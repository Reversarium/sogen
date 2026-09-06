"""Capture REV-426 fixtures and verify them through the offline core adapter."""
import argparse
import ctypes as C
from ctypes import wintypes as W
import datetime
import hashlib
import json
import os
from pathlib import Path
import platform
import statistics
import struct
import subprocess
import time

FIXTURES = ["hello-x64-351.vmp.exe", "hello-x64-381.vmp.exe", "hello-x64-396.vmp.exe"]


def sha(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def process_metrics(proc):
    kernel = C.WinDLL("kernel32", use_last_error=True)
    kernel.GetProcessTimes.argtypes = [W.HANDLE, *([C.POINTER(W.FILETIME)] * 4)]
    kernel.GetProcessTimes.restype = W.BOOL
    times = [W.FILETIME() for _ in range(4)]
    if not kernel.GetProcessTimes(int(proc._handle), *[C.byref(t) for t in times]):
        raise C.WinError(C.get_last_error())

    class Memory(C.Structure):
        _fields_ = [("cb", W.DWORD), ("PageFaultCount", W.DWORD)] + [
            (name, C.c_size_t) for name in (
                "PeakWorkingSetSize", "WorkingSetSize", "QuotaPeakPagedPoolUsage",
                "QuotaPagedPoolUsage", "QuotaPeakNonPagedPoolUsage",
                "QuotaNonPagedPoolUsage", "PagefileUsage", "PeakPagefileUsage",
                "PrivateUsage")
        ]

    info = Memory(cb=C.sizeof(Memory))
    psapi = C.WinDLL("psapi", use_last_error=True)
    psapi.GetProcessMemoryInfo.argtypes = [W.HANDLE, C.POINTER(Memory), W.DWORD]
    psapi.GetProcessMemoryInfo.restype = W.BOOL
    if not psapi.GetProcessMemoryInfo(int(proc._handle), C.byref(info), C.sizeof(info)):
        raise C.WinError(C.get_last_error())
    seconds = lambda t: ((t.dwHighDateTime << 32) | t.dwLowDateTime) / 1e7
    return dict(kernel_cpu_s=seconds(times[2]), user_cpu_s=seconds(times[3]),
                peak_working_set_bytes=info.PeakWorkingSetSize,
                peak_commit_bytes=info.PeakPagefileUsage)


def run(command, log, timeout, cwd):
    begin = time.perf_counter()
    with log.open("wb") as output:
        proc = subprocess.Popen(command, cwd=cwd, stdout=output,
                                stderr=subprocess.STDOUT,
                                creationflags=subprocess.CREATE_NO_WINDOW)
        try:
            code = proc.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait()
            raise RuntimeError(f"Timed out: {log}")
        result = dict(command=command, exit_code=code,
                      process_wall_s=time.perf_counter() - begin,
                      **process_metrics(proc))
    if code:
        raise RuntimeError(f"Exit {code}: {log}")
    return result


def metadata(path):
    with path.open("rb") as stream:
        def integer(fmt):
            return struct.unpack("<" + fmt, stream.read(struct.calcsize("<" + fmt)))[0]

        def string():
            return stream.read(integer("I")).decode("utf-8")

        def blob():
            return stream.read(integer("Q"))

        if stream.read(8) != b"RVSNAP01" or integer("I") != 1:
            raise ValueError("Unsupported snapshot file")
        machine, start = integer("I"), integer("Q")
        counts = [integer("I") for _ in range(3)]
        modules = []
        for _ in range(counts[0]):
            module = dict(id=integer("I"), load_base=integer("Q"),
                          size=integer("Q"), name=string())
            headers = blob()
            if headers[:2] != b"MZ":
                raise ValueError(f"Missing original PE metadata: {module['name']}")
            module["pe_header_bytes"] = len(headers)
            module["pe_headers"] = headers.hex()
            modules.append(module)
        registers = [dict(name=string(), bytes=blob().hex()) for _ in range(counts[1])]
        regions = []
        for _ in range(counts[2]):
            region = dict(start=integer("Q"), size=integer("Q"),
                          permissions=integer("I"), captured_bytes=integer("Q"))
            region["file_offset"] = stream.tell()
            stream.seek(region["captured_bytes"], 1)
            regions.append(region)
        if stream.tell() != path.stat().st_size:
            raise ValueError("Unexpected file size")
    return dict(machine=machine, start_address=start, modules=modules,
                registers=registers, regions=regions)


def read_memory(path, meta, address, size):
    result = bytearray()
    with path.open("rb") as stream:
        for region in meta["regions"]:
            offset = address - region["start"]
            if 0 <= offset < region["size"]:
                count = min(size - len(result), region["size"] - offset)
                if offset + count > region["captured_bytes"]:
                    raise ValueError(f"Required bytes unavailable at {address:#x}")
                stream.seek(region["file_offset"] + offset)
                result += stream.read(count)
                address += count
                if len(result) == size:
                    return bytes(result)
    raise ValueError(f"Required mapping missing at {address:#x}")


def validate(path, meta, capture, imported, events):
    for key in ("start_address", "modules", "registers"):
        if meta[key] != imported[key]:
            raise ValueError(f"Adapter changed {key}")
    expected_regions = [{k: v for k, v in region.items() if k != "file_offset"}
                        for region in meta["regions"]]
    actual_regions = [{k: v for k, v in region.items() if k != "fnv1a64"}
                      for region in imported["regions"]]
    if expected_regions != actual_regions:
        raise ValueError("Adapter changed mappings or permissions")
    for key in ("mapped_bytes", "captured_bytes", "memory_fnv1a64"):
        if capture[key] != imported[key]:
            raise ValueError(f"Memory round-trip failed: {key}")
    if capture["file_bytes"] != path.stat().st_size:
        raise ValueError("File size differs from capture")
    for key in ("modules", "registers", "regions"):
        if capture[key] != len(imported[key]):
            raise ValueError(f"Record count differs: {key}")
    registers = {r["name"]: bytes.fromhex(r["bytes"]) for r in meta["registers"]}
    required = ["rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp", "rsp",
                "rip", "rflags", "fsbase", "gsbase", "mxcsr"] + [f"r{i}" for i in range(8, 16)]
    if any(name not in registers for name in required):
        raise ValueError("Required entry context missing")
    value = lambda name: int.from_bytes(registers[name], "little")
    if value("rip") != meta["start_address"]:
        raise ValueError("Entry RIP mismatch")
    read_memory(path, meta, value("rsp"), 8)
    for name in ("fsbase", "gsbase"):
        if value(name):
            read_memory(path, meta, value(name), 8)
    missing = [r for r in meta["regions"] if r["captured_bytes"] != r["size"]]
    for region in missing:
        for module in meta["modules"]:
            if (region["start"] < module["load_base"] + module["size"]
                    and module["load_base"] < region["start"] + region["size"]):
                raise ValueError(f"Required module bytes missing: {module['name']}")
    candidates = [e for e in events if e["event"] == "candidate"]
    results = [e for e in events if e["event"] == "result"]
    if len(candidates) != 1 or len(results) != 1 or results[0]["status"] != "unique_candidate":
        raise ValueError("No unique successful handoff")
    candidate = candidates[0]
    if int(candidate["address"], 16) != meta["start_address"]:
        raise ValueError("Start differs from observed handoff")
    expected = bytes.fromhex(candidate["bytes"])
    if read_memory(path, meta, meta["start_address"], len(expected)) != expected:
        raise ValueError("OEP bytes differ from live observation")
    return dict(oep_rva=candidate["rva"], observed_blocks=results[0]["observed_blocks"],
                missing_regions=missing, all_exported_memory_verified=True,
                all_exported_registers_verified=True, offline_import=True)



def fixed_base_reason(module):
    headers = bytes.fromhex(module["pe_headers"])
    nt = struct.unpack_from("<I", headers, 60)[0]
    characteristics = struct.unpack_from("<H", headers, nt + 22)[0]
    optional = nt + 24
    dll_characteristics = struct.unpack_from("<H", headers, optional + 70)[0]
    reloc_rva, reloc_size = struct.unpack_from("<II", headers, optional + 112 + 5 * 8)
    if characteristics & 1:
        return "PE relocations stripped"
    if not reloc_rva or not reloc_size:
        return "PE base-relocation directory absent"
    if not (characteristics & 0x2000 or dll_characteristics & 0x40):
        return "Sogen requires DLL or DYNAMIC_BASE for automatic relocation"
    return None


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--analyzer", type=Path, required=True)
    parser.add_argument("--inspector", type=Path, required=True)
    parser.add_argument("--emulation-root", type=Path, required=True)
    parser.add_argument("--fixtures-dir", type=Path, required=True)
    parser.add_argument("--fixtures", nargs="+", default=FIXTURES)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--timeout", type=float, default=900)
    parser.add_argument("--native-repeats", type=int, default=3)
    args = parser.parse_args()
    if args.native_repeats < 1:
        parser.error("--native-repeats must be positive")
    if os.name != "nt":
        parser.error("Native fixture measurements require Windows")
    for name in ("analyzer", "inspector", "emulation_root", "fixtures_dir", "output"):
        setattr(args, name, getattr(args, name).resolve())
    args.output.mkdir(parents=True, exist_ok=False)
    summary = dict(utc=datetime.datetime.now(datetime.timezone.utc).isoformat(),
                   platform=platform.platform(), cpu=platform.processor(),
                   tool_sha256={str(p): sha(p) for p in
                                (args.analyzer, args.analyzer.parent / "unicorn-emulator.dll",
                                 args.inspector)},
                   fixtures=[], passed=False)
    try:
        for name in args.fixtures:
            fixture = args.fixtures_dir / name
            folder = args.output / fixture.stem
            folder.mkdir()
            native = [run([str(fixture)], folder / f"native-{i}.log",
                          args.timeout, fixture.parent)
                      for i in range(args.native_repeats)]
            expected = (folder / "native-0.log").read_bytes().replace(b"\r\n", b"\n")
            if not expected or any((folder / f"native-{i}.log").read_bytes().replace(b"\r\n", b"\n")
                                   != expected for i in range(args.native_repeats)):
                raise ValueError("Native output is empty or inconsistent")
            record = dict(fixture=name, fixture_sha256=sha(fixture), native=native,
                          native_median_s=statistics.median(r["process_wall_s"] for r in native),
                          captures=[])
            summary["fixtures"].append(record)
            normal = None
            for layout in ("normal", "relocated"):
                path = folder / f"{layout}.rvs"
                oep = folder / f"{layout}.oep.jsonl"
                guest = folder / f"{layout}.stdout"
                command = [str(args.analyzer), "-s", "--backend", "unicorn",
                           "--no-inst-precision", "--reproducible", "--oep-report", str(oep),
                           "--runtime-snapshot", str(path), "--stdout", str(guest)]
                if normal:
                    for module in normal["modules"]:
                        if fixed_base_reason(module) is None:
                            command += ["--reserve-range", hex(module["load_base"]), hex(module["size"])]
                command += ["-e", str(args.emulation_root), "-p", "c:/oep-fixture.exe",
                            str(fixture), "c:/oep-fixture.exe"]
                execution = run(command, folder / f"{layout}.log", args.timeout, args.analyzer.parent)
                if guest.read_bytes().replace(b"\r\n", b"\n") != expected:
                    raise ValueError(f"Guest output differs: {fixture.name}/{layout}")
                capture = json.loads(Path(str(path) + ".json").read_text())
                import_log = folder / f"{layout}.import.json"
                importer = run([str(args.inspector), str(path)], import_log,
                               args.timeout, args.inspector.parent)
                imported = json.loads(import_log.read_text())
                meta = metadata(path)
                events = [json.loads(line) for line in oep.read_text().splitlines()]
                checks = validate(path, meta, capture, imported, events)
                result = dict(layout=layout, snapshot=str(path), snapshot_sha256=sha(path),
                              execution=execution, capture=capture, importer=importer,
                              import_metrics={k: imported[k] for k in
                                              ("file_read_ms", "import_ms", "verify_ms")},
                              modules=[{k: v for k, v in m.items() if k != "pe_headers"} for m in meta["modules"]],
                              checks=checks)
                record["captures"].append(result)
                if normal is None:
                    normal = meta
                    record["fixed_modules"] = {m["name"]: reason for m in meta["modules"]
                                               if (reason := fixed_base_reason(m))}
                else:
                    old = {m["name"]: m for m in normal["modules"]}
                    if set(old) != {m["name"] for m in meta["modules"]}:
                        raise ValueError("Loaded module identities changed")
                    moved = []
                    for module in meta["modules"]:
                        module_name = module["name"]
                        changed = module["load_base"] != old[module_name]["load_base"]
                        if module_name not in record["fixed_modules"] and not changed:
                            raise ValueError(f"A reserved module did not move: {module_name}")
                        if changed:
                            moved.append(module_name)
                    if not moved:
                        raise ValueError("The second layout did not move any module")
                    record["moved_modules"] = moved
                    if checks["oep_rva"] != record["captures"][0]["checks"]["oep_rva"]:
                        raise ValueError("OEP RVA changed across layouts")
                print(f"{name}/{layout}: execution={capture['execution_ms']/1000:.3f}s "
                      f"capture={capture['capture_ms']:.1f}ms file={capture['file_bytes']} PASS",
                      flush=True)
        summary["passed"] = True
    finally:
        (args.output / "summary.json").write_text(json.dumps(summary, indent=2) + "\n")
    print(args.output / "summary.json", flush=True)


if __name__ == "__main__":
    main()
