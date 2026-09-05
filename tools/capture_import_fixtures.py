"""Capture import recovery evidence on controlled x64 fixtures, serially."""

import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import time


def capture(analyzer, root, fixture, output, from_entry=False, timeout=600):
    output.mkdir(parents=True, exist_ok=True)
    command = [
        str(analyzer), "-s", "--no-inst-precision", "--reproducible",
        "--import-trace", str(output), "--stdout", str(output / "stdout.bin"),
        "-e", str(root), "-p", "c:/iat-fixture.exe", str(fixture),
    ]
    if from_entry:
        command.append("--import-from-entry")
    else:
        command.extend(["--oep-report", str(output / "oep.jsonl")])
    command.append("c:/iat-fixture.exe")
    started = time.monotonic()
    result = {"fixture": fixture.name, "sha256": hashlib.sha256(fixture.read_bytes()).hexdigest(),
              "command": command, "from_entry": from_entry,
              "analyzer_sha256": hashlib.sha256(analyzer.read_bytes()).hexdigest(),
              "unicorn_sha256": hashlib.sha256((analyzer.parent / "unicorn-emulator.dll").read_bytes()).hexdigest()}
    try:
        with (output / "analyzer.log").open("wb") as log:
            completed = subprocess.run(command, cwd=analyzer.parent, stdout=log,
                                       stderr=subprocess.STDOUT, timeout=timeout, check=False)
        result["exit_code"] = completed.returncode
        if (output / "trace.jsonl").exists():
            with (output / "trace.jsonl").open() as trace:
                for line in trace:
                    event = json.loads(line)
                    if event["event"] == "result":
                        result["trace_result"] = event
        result["passed"] = (
            result["exit_code"] == 0
            and result.get("trace_result", {}).get("completed", False)
            and result.get("trace_result", {}).get("candidate_count") == 1)
    except (OSError, ValueError, subprocess.TimeoutExpired) as error:
        result.update(passed=False, error=str(error))
    result["seconds"] = round(time.monotonic() - started, 3)
    (output / "capture.json").write_text(json.dumps(result, indent=2) + "\n")
    print(f"{fixture.name}: {'PASS' if result['passed'] else 'FAIL'} ({result['seconds']}s)", flush=True)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("fixtures", type=Path, nargs="+")
    parser.add_argument("--analyzer", type=Path, required=True)
    parser.add_argument("--emulation-root", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--from-entry", action="store_true")
    parser.add_argument("--timeout", type=float, default=600)
    args = parser.parse_args()
    results = [capture(args.analyzer.resolve(), args.emulation_root.resolve(), fixture.resolve(),
                       args.output.resolve() / fixture.stem, args.from_entry, args.timeout)
               for fixture in args.fixtures]
    return 0 if all(result["passed"] for result in results) else 1


if __name__ == "__main__":
    raise SystemExit(main())
