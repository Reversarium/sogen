"""Run baseline-independent OEP detection, then compare its reports with a baseline."""

import argparse
import concurrent.futures
import hashlib
import json
from pathlib import Path
import struct
import subprocess
import time


def pe_entry(path):
    data = path.read_bytes()
    pe = struct.unpack_from("<I", data, 0x3C)[0]
    if data[pe : pe + 4] != b"PE\0\0":
        raise ValueError(f"Not a PE file: {path}")
    count, optional_size = struct.unpack_from("<H12xH", data, pe + 6)
    optional = pe + 24
    if struct.unpack_from("<H", data, optional)[0] != 0x20B:
        raise ValueError("Verification requires PE32+")
    entry = struct.unpack_from("<I", data, optional + 16)[0]
    for index in range(count):
        section = optional + optional_size + index * 40
        virtual_size, rva, raw_size, raw = struct.unpack_from("<IIII", data, section + 8)
        if rva <= entry < rva + min(virtual_size, raw_size):
            offset = raw + entry - rva
            return entry, data[offset : offset + 64]
    raise ValueError(f"Entry bytes are not file backed: {path}")


def run_fixture(args, fixture):
    report = args.output / (fixture.stem + ".jsonl")
    log = args.output / (fixture.stem + ".log")
    command = [
        str(args.analyzer), "-s", "--no-inst-precision", "--reproducible",
        "--oep-report", str(report), "-e", str(args.emulation_root),
        "-p", "c:/oep-fixture.exe", str(fixture), "c:/oep-fixture.exe",
    ]
    started = time.monotonic()
    outcome = {"fixture": fixture.name, "sha256": hashlib.sha256(fixture.read_bytes()).hexdigest()}
    try:
        with log.open("wb") as output:
            result = subprocess.run(command, cwd=args.analyzer.parent, stdout=output,
                                    stderr=subprocess.STDOUT, timeout=args.timeout, check=False)
        events = [json.loads(line) for line in report.read_text().splitlines()]
        outcome.update(exit_code=result.returncode, events=events, output=log.read_text(errors="replace"))
    except (subprocess.TimeoutExpired, OSError, ValueError) as error:
        outcome["error"] = str(error)
    outcome["seconds"] = round(time.monotonic() - started, 3)
    return outcome


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("fixture_directory", type=Path)
    parser.add_argument("--analyzer", type=Path, required=True)
    parser.add_argument("--emulation-root", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--baseline", default="hello-x64.exe")
    parser.add_argument("--jobs", type=int, default=2)
    parser.add_argument("--timeout", type=float, default=600)
    args = parser.parse_args()
    for name in ("fixture_directory", "analyzer", "emulation_root", "output"):
        setattr(args, name, getattr(args, name).resolve())
    args.output.mkdir(parents=True, exist_ok=True)
    baseline = args.fixture_directory / args.baseline
    protected = sorted(args.fixture_directory.glob("*.vmp.exe"))
    if not protected:
        parser.error("No protected *.vmp.exe fixtures")
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.jobs) as pool:
        outcomes = list(pool.map(lambda fixture: run_fixture(args, fixture), [baseline, *protected]))
    expected_rva, expected_bytes = pe_entry(baseline)
    for index, outcome in enumerate(outcomes):
        events = outcome.get("events", [])
        entries = [e for e in events if e["event"] == "entry"]
        candidates = [e for e in events if e["event"] == "candidate"]
        result = next((e for e in events if e["event"] == "result"), {})
        passed = outcome.get("exit_code") == 0 and len(entries) == 1
        if index == 0:
            passed = passed and result.get("status") == "no_candidate" and not candidates
            passed = passed and int(entries[0]["rva"], 16) == expected_rva
        else:
            passed = passed and result.get("status") == "unique_candidate" and len(candidates) == 1
            if len(candidates) == 1:
                candidate = candidates[0]
                byte_match = bool(candidate["bytes"]) and bytes.fromhex(candidate["bytes"])[:16] == expected_bytes[:16]
                outcome["baseline_entry_prefix_matches"] = byte_match
                outcome["baseline_64_bytes_match"] = bool(candidate["bytes"]) and bytes.fromhex(candidate["bytes"]) == expected_bytes
                passed = passed and candidate["rva"] is not None and int(candidate["rva"], 16) == expected_rva and byte_match
        outcome["output_matches_baseline"] = outcome.get("output") == outcomes[0].get("output")
        passed = bool(passed and outcome["output_matches_baseline"])
        outcome["passed"] = passed
        print(f"{outcome['fixture']}: {'PASS' if passed else 'FAIL'} ({outcome['seconds']}s)", flush=True)
    summary = {"baseline_rva": hex(expected_rva), "passed": all(o["passed"] for o in outcomes), "fixtures": outcomes}
    (args.output / "summary.json").write_text(json.dumps(summary, indent=2) + "\n")
    return 0 if summary["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
