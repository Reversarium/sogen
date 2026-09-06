# Export an offline OEP snapshot

REV-426 connects the established OEP detector to Reversarium core.

1. Run the existing OEP detector.
2. At its first candidate callback, capture the current memory and registers
   before executing that instruction. Write a temporary file.
3. Continue the program. Publish the snapshot only when execution succeeds and
   the detector reports one candidate. Otherwise fail and remove the temporary
   capture.
4. After sogen exits, load the file through core and verify its contents.

This adds no section-name or protector-version test to OEP detection. The
exporter relies on the detector's existing handoff decision; it does not
independently prove that decision for every protector. Caller-saved registers,
including R10 and R11, are captured as observed at the handoff.

## Capture profile: sogen-x64-v1

- One x64 vCPU, captured synchronously in the active CPU callback.
- All committed guest mappings, including anonymous allocations and mappings
  without read permission. Reserved-only ranges and host-only reservations are
  excluded.
- Device-backed mappings remain mapped but have unavailable bytes. Reading them
  can invoke device callbacks. Failed ordinary reads are split to 4 KiB pages
  so readable neighboring pages are retained.
- R/W/X permissions are retained. Windows guard and copy-on-write attributes
  are outside the current core contract.
- Context includes available GPRs, RIP, flags, segment selectors, FS/GS bases,
  physical x87 state and environment, vector state, MXCSR, control/debug
  registers, XCR0, and GDTR/IDTR base and limit. Only the widest available
  vector view is stored. Unsupported values are listed in the JSON report;
  they are never replaced with zero.
- The profile does not capture indexed MSRs or hidden TR/LDTR state. It is an
  analysis snapshot, not a complete CPU checkpoint for replay.
- Module IDs, runtime bases, image sizes, names, and original file PE headers
  accompany runtime memory. Original headers are metadata, never a fallback
  for missing memory. An unreadable source header is recorded as absent.

The versioned `RVSNAP01` binary format is read by
`Reversarium/core/tools/runtime-snapshot/snapshot_file.cc`. Architectural
register names are stored instead of core's build-dependent register IDs.
An adjacent `capture.rvs.json` report records timings, counts, missing registers,
and an FNV-1a 64-bit checksum of captured memory bytes in file order. The runner
compares that checksum with core's memory readback to check the transfer. The
fixture runner also records SHA-256 hashes of the complete files and tools.

## One capture

Run from the built artifact directory, with an existing emulator root:

```powershell
.\analyzer.exe -s --backend unicorn --no-inst-precision --reproducible `
  --oep-report D:/captures/sample.oep.jsonl `
  --runtime-snapshot D:/captures/sample.rvs `
  --stdout D:/captures/sample.stdout `
  -e D:/RE/REProjects/sogen-root `
  -p c:/sample.exe D:/fixtures/sample.exe c:/sample.exe
```

The output directory must exist. Existing snapshot, pending capture or report
files are rejected. For an unprotected control only, `--snapshot-at-entry`
explicitly selects the PE entry without OEP detection.

## Reproduce the fixture experiment

Build core's test-enabled configuration and sogen's release preset first.
These tests use the local REV-412 binaries; no binaries or dumps are committed.

```powershell
python tools/capture_runtime_snapshots.py `
  --analyzer build/release/artifacts/analyzer.exe `
  --inspector D:/RE/REProjects/core/build/ninja-debug/reversarium_snapshot_inspect.exe `
  --emulation-root D:/RE/REProjects/sogen-root `
  --fixtures-dir D:/RE/REProjects/.tmp/REV-412-OEP `
  --output D:/RE/REProjects/.tmp/REV-426-results-final
```

`--fixtures-dir` locates the binaries. `--fixtures` optionally selects filenames
inside that directory; omitting it runs the three VMP fixtures listed in `--help`.
For example, add `--fixtures hello-x64-396.vmp.exe` to run only the 3.9.6 fixture.

The runner creates a new `--output` directory so results from different runs
cannot overwrite or mix with each other. Each fixture gets:

1. Three native executions to measure host runtime. Their median reduces timing
   noise. Set `--native-repeats 1` to skip the timing repeats.
2. One sogen capture at the normal load addresses, followed by offline import.
3. One capture/import with changed module addresses to expose assumptions about
   fixed load bases. Before loading, the runner reserves each relocatable module's
   first-run range so sogen's loader must choose another address and relocate it.

Modules whose PE headers require a fixed base remain there and are recorded as
exceptions. These repeated runs validate the implementation; exporting one
snapshot only requires the single analyzer run shown above.

Each run records the exact command, tool and fixture hashes, exit status, peak
working set/commit, OEP evidence, and output comparison. After the emulator
exits, the offline inspector checks every exported memory byte. The runner
also compares all registers, module metadata and mappings, checks OEP bytes
against the live callback evidence, and requires available entry stack and
FS/GS-base memory. Missing bytes inside a module fail the experiment.
Both runs must identify the same OEP RVA, and every module selected for
relocation must move. Fixed-base exceptions are reported by module and reason.

## Timing boundaries

- Native/process wall time: process launch through exit, including startup and
  teardown. Native results use the median of three runs.
- Sogen execution: `run_emulation`, including the OEP callback and capture.
- Handoff: from emulation start to capture entry.
- Capture/export: context reads, header metadata, memory reads, hashing and file
  write/close. It excludes the subsequent uniqueness check and final rename.
- Import: file parsing and core construction are timed separately. Full
  readback/hash verification has its own timing.
- Peak memory: Windows process peak working set and peak commit. This is not
  a measurement of the exporter's incremental allocation.

Capture streams memory in at most 64 KiB buffers; its work is linear in bytes
captured. There is one capture, not one file per block. Import owns one copy of
captured memory. The existing OEP detector and guest execution can still
dominate total time.

## Fixture measurements

Measured 2026-09-05 on Windows 11 build 26200, Ryzen 9 9950X3D2.
Sogen: MSVC RelWithDebInfo, Unicorn, reproducible mode, instruction precision
disabled. Core inspector: MSVC Debug. Runs were serial, after this task's
builds/tests. Each layout has one capture; native timings are medians of three runs.

Pairs below are normal / relocated layout. Sogen process wall time includes
startup and teardown; emulation time includes capture.

| VMP | Native wall ms | Sogen wall s | Emulation s | Capture ms | File MiB |
| --- | ---: | ---: | ---: | ---: | ---: |
| 3.5.1 | 71.6 | 6.856 / 6.853 | 6.737 / 6.734 | 50.0 / 48.4 | 41.42 |
| 3.8.1 | 1116.0 | 95.970 / 94.837 | 95.731 / 94.574 | 87.3 / 92.1 | 76.14 |
| 3.9.6 | 905.7 | 113.003 / 112.471 | 112.824 / 112.294 | 87.2 / 86.5 | 74.47 |

Core timings separate parsing from snapshot construction and full readback.
Peak working sets are process peaks; they do not measure incremental capture allocation.

| VMP | Parse ms | Core construction ms | Verify ms | Sogen peak MiB | Inspector peak MiB |
| --- | ---: | ---: | ---: | ---: | ---: |
| 3.5.1 | 29.56 / 29.19 | 0.258 / 0.263 | 70.3 / 70.1 | 81.2 / 80.9 | 46.6 / 46.6 |
| 3.8.1 | 54.59 / 55.97 | 0.314 / 0.317 | 130.2 / 130.5 | 309.1 / 307.1 | 81.7 / 81.7 |
| 3.9.6 | 56.04 / 52.10 | 0.315 / 0.305 | 129.8 / 127.2 | 229.7 / 234.1 | 80.0 / 80.0 |

| VMP | OEP RVA | Observed blocks (normal) | Regions | Relocated modules |
| --- | ---: | ---: | ---: | --- |
| 3.5.1 | 0x1000 | 105,508,593 | 699 | EXE + 4 DLLs |
| 3.8.1 | 0x1000 | 1,241,556,074 | 1259 | 4 DLLs |
| 3.9.6 | 0x1000 | 1,408,429,258 | 1232 | 4 DLLs |

All six captures pass offline memory, register, PE-header and mapping checks.
Each contains 5 modules and 91 register values. K0–K7 are unavailable in
this Unicorn build. The only unavailable memory is the 4 KiB device-backed
shared-data page at 0x7ffe0000; module, stack and FS/GS-base checks pass.

The 3.8.1 and 3.9.6 executables have IMAGE_FILE_RELOCS_STRIPPED and no
base-relocation directory. Their image bases remain fixed; all four DLL
bases change. Forcing the 3.8.1 executable away from its preferred base
was rejected by the loader before execution, which led to the explicit
fixed-module policy in the runner.

Local raw measurements, commands and SHA-256 identities are in
D:/RE/REProjects/.tmp/REV-426-verified-matrix.json; it combines the completed
3.5.1 runs from REV-426-results-final with the 3.8.1/3.9.6 runs from
REV-426-results-relocatable. The default runner command reproduces all three.
Snapshots and guest binaries remain local.

Validation: 3 capture regression tests, the emulated native test-sample smoke
test, baseline entry capture/offline import, output-collision rejection and
absent-handoff rejection pass. Core validation covers 1,277 enabled tests
after the final targeted parser/generator recheck; one existing test is disabled.
The full tidy preset stops on pre-existing readability-redundant-typename
errors in platform/port.hpp and platform/process.hpp. Clang-tidy checks
on changed lines pass.
