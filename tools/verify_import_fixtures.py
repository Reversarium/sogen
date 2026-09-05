"""Verify import recovery against a separate baseline and fresh native/sogen runs."""

import argparse
import hashlib
import json
from pathlib import Path
import platform
import statistics
import subprocess
import time

from capture_import_fixtures import capture
from recover_imports import imports_from_file, rebuild, recover


def read_events(directory):
    return [json.loads(line) for line in (directory / "trace.jsonl").read_text().splitlines()]


def api_sequence(events):
    return [(event["module"].lower(), event["name"]) for event in events if event["event"] == "api"]


def native_runs(path, repeat=3):
    results = []
    for _ in range(repeat):
        started = time.monotonic()
        process = subprocess.run([str(path)], capture_output=True, timeout=20,
                                 creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0), check=False)
        results.append(dict(exit_code=process.returncode, stdout_hex=process.stdout.hex(),
                            stderr_hex=process.stderr.hex(), seconds=round(time.monotonic() - started, 6)))
    return results


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("fixture_directory", type=Path)
    parser.add_argument("--baseline", default="hello-x64.exe")
    parser.add_argument("--analyzer", type=Path, required=True)
    parser.add_argument("--emulation-root", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--reuse-captures", action="store_true")
    args = parser.parse_args()
    for name in ("fixture_directory", "analyzer", "emulation_root", "output"):
        setattr(args, name, getattr(args, name).resolve())
    args.output.mkdir(parents=True, exist_ok=True)
    baseline = args.fixture_directory / args.baseline
    baseline_imports = {(item["module"], item["name"]) for item in imports_from_file(baseline)}
    baseline_native = native_runs(baseline)
    if any(run["exit_code"] != 0 or run["stdout_hex"] != baseline_native[0]["stdout_hex"]
           or run["stderr_hex"] for run in baseline_native):
        raise RuntimeError("Baseline native behavior is not stable")
    baseline_capture_dir = args.output / "baseline"
    baseline_capture = capture(args.analyzer, args.emulation_root, baseline, baseline_capture_dir, True)
    if not baseline_capture["passed"]:
        raise RuntimeError("Baseline capture failed")
    baseline_apis = api_sequence(read_events(baseline_capture_dir))
    summary = dict(
        schema=1, system=platform.platform(), python=platform.python_version(),
        analyzer_sha256=hashlib.sha256(args.analyzer.read_bytes()).hexdigest(),
        unicorn_sha256=hashlib.sha256((args.analyzer.parent / "unicorn-emulator.dll").read_bytes()).hexdigest(),
        baseline=dict(name=baseline.name, sha256=hashlib.sha256(baseline.read_bytes()).hexdigest(),
                      imports=sorted(baseline_imports), apis=baseline_apis, native_runs=baseline_native),
        fixtures=[])
    protected = sorted(args.fixture_directory.glob("*.vmp.exe"))
    if not protected:
        raise RuntimeError("No protected fixtures")
    for fixture in protected:
        directory = args.output / "capture" / fixture.stem
        if args.reuse_captures:
            captured = json.loads((directory / "capture.json").read_text())
            if captured["sha256"] != hashlib.sha256(fixture.read_bytes()).hexdigest():
                raise RuntimeError("Reused capture fixture hash mismatch")
            if captured.get("analyzer_sha256") != summary["analyzer_sha256"] or captured.get("unicorn_sha256") != summary["unicorn_sha256"]:
                raise RuntimeError("Reused capture backend/analyzer hash mismatch")
            if captured.get("from_entry") is not False:
                raise RuntimeError("Protected fixture capture did not use handoff detection")
        else:
            captured = capture(args.analyzer, args.emulation_root, fixture, directory)
        if not captured["passed"]:
            raise RuntimeError(f"Protected trace failed: {fixture.name}")
        events = read_events(directory)
        image = (directory / "image.bin").read_bytes()
        started = time.monotonic()
        report = recover(events, image)
        binary = rebuild(image, report)
        recovery_seconds = round(time.monotonic() - started, 6)
        output = args.output / "rebuilt" / (fixture.stem + ".repaired.exe")
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_bytes(binary)
        output.with_suffix(".imports.json").write_text(json.dumps(report, indent=2) + "\n")
        import_inventory = imports_from_file(output)
        imports = {(item["module"], item["name"]) for item in import_inventory}
        runs = native_runs(output)
        replay_directory = args.output / "replay" / fixture.stem
        replay = capture(args.analyzer, args.emulation_root, output, replay_directory, True)
        replay_apis = api_sequence(read_events(replay_directory)) if replay["passed"] else []
        checks = dict(
            retained_import_slots_preserved=all(item in import_inventory for item in report["retained_imports"]),
            baseline_imports_recovered=baseline_imports <= imports,
            native_output_matches_baseline=all(run["exit_code"] == 0 and
                run["stdout_hex"] == baseline_native[0]["stdout_hex"] and not run["stderr_hex"] for run in runs),
            fresh_sogen_execution_passed=replay["passed"],
            fresh_api_sequence_matches_baseline=replay_apis == baseline_apis,
            fresh_sogen_stdout_matches_baseline=(replay_directory / "stdout.bin").read_bytes()
                == (baseline_capture_dir / "stdout.bin").read_bytes())
        item = dict(
            fixture=fixture.name, input_sha256=captured["sha256"],
            capture_analyzer_sha256=captured["analyzer_sha256"], capture_unicorn_sha256=captured["unicorn_sha256"],
            capture_seconds=captured["seconds"], recovery_seconds=recovery_seconds,
            trace_result=report["trace_result"], image_size=len(image), entry_rva=report["entry_rva"],
            repaired_sites=[{key: value for key, value in repair.items()
                            if key not in ("original", "replacement", "target")} for repair in report["repairs"]],
            imports=sorted(imports), additional_imports=sorted(imports - baseline_imports),
            recovered_imports=report["rebuilt_imports"], retained_imports=report["retained_imports"],
            unresolved_transitions=report["unresolved_transitions"],
            output_sha256=report["output_sha256"], output_size=len(binary),
            native_runs=runs, native_median_seconds=statistics.median(run["seconds"] for run in runs),
            replay_seconds=replay["seconds"], replay_apis=replay_apis, checks=checks, passed=all(checks.values()))
        summary["fixtures"].append(item)
        print(f"{fixture.name}: {'PASS' if item['passed'] else 'FAIL'} â€” "
              f"{len(report['repairs'])} repairs; native + fresh sogen verified", flush=True)
    summary["passed"] = all(item["passed"] for item in summary["fixtures"])
    (args.output / "verification.json").write_text(json.dumps(summary, indent=2) + "\n")
    return 0 if summary["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
