# REV-423: tested import recovery in sogen

The same algorithm recovered the three baseline application imports in all three REV-412 fixtures. The rebuilt executables print exactly `Hello, world!\r\n` and exit 0 under native Windows. Fresh sogen runs also reproduce the baseline's API sequence and output.

The recovery inputs are the protected executable, sogen's Windows environment, and execution evidence. The baseline is supplied only to the separate verifier. There are no VMProtect version checks, expected RVAs, section-name tests, or wrapper byte signatures in the recovery code.

1. **Run the existing OEP detector. Stop at its first candidate, but keep auditing the complete run.** At the stop, check that the CPU's instruction pointer still equals the candidate. Save the mapped executable before executing that instruction. A completed run must report exactly one handoff candidate before recovery accepts the trace. This preserves REV-412's ambiguity handling and prevents a partially observed unpacking run from producing an accepted repair.

2. **Install instruction and memory-write tracing, then resume from that exact instruction.** The trace records executed instruction boundaries, bytes, registers, stack contents, and writes. Installing hooks after translation exposed a Unicorn cache issue: previously translated blocks retained their old instrumentation. The backend now invalidates cached translations before resuming after memory-hook installation. The regression test warms a block, adds hooks, and checks both its instructions and its write.

3. **Wait for execution to leave the main image and reach an exact named export in a loaded DLL.** For example, the fixtures reach `kernel32.dll!GetStdHandle`. Verify the address/name pair against the module's export metadata. An arbitrary address inside a DLL is insufficient. Record the API-entry state before its first instruction executes. The identity recovered is an importable export at the observed destination; runtime addresses alone cannot establish the original spelling through aliases or forwarders.

4. **Read the API's return address and use it to locate the caller window.** Let the return address be `C`. Look for an actually executed instruction boundary at `C-5` or `C-6`, with a contiguous instruction sequence ending in a native `CALL`. These widths come from the supported replacement encodings. The window is accepted only after the following state and write checks pass.

   This handles both shapes seen in the fixtures: a five-byte call whose wrapper advances the return address over one skipped byte, and a one-byte push followed by a five-byte call whose wrapper removes that extra save. No particular pushed register or wrapper instruction sequence is required. Bytes after the call can be consumed only when the trace shows they were never executed.

5. **Compare the state before that whole window with the state at API entry.** Require:
   - API RSP equals the window's initial RSP minus eight.
   - The API return address is exactly `C`, the replacement's continuation.
   - RCX, RDX, R8, and R9 retain the caller's argument values.
   - RBX, RBP, RSI, RDI, and R12-R15 retain their values.
   - XMM0-XMM3 and XMM6-XMM15 retain their values.
   - The captured caller stack agrees after accounting for the pushed return address.

   The register checks follow the [Windows x64 calling convention](https://learn.microsoft.com/en-us/cpp/build/x64-calling-convention). The collector records all GPRs and all sixteen XMM registers, so the report also shows stronger equality when observed. For all nine baseline application calls, every GPR except RSP and every XMM register matched. Each comparison covered the remaining 192 bytes of the caller's stack.

6. **Reject wrappers with observable work beyond private stack scratch.** Every recorded write between the window and API entry must lie in the same thread's allocated stack, entirely below the window's initial RSP. This protects the caller's arguments, caller frame, globals, and pointed-to data. Reject intervening foreign transitions and direct system transitions. Account conservatively for fixed-width vector writes, and reject variable-size processor-state saves that the write model does not cover.

   This check is necessary because reaching the right API with the right registers can still hide a global write. Stack scratch and return-slot adjustment are permitted because the replacement recreates the validated API-entry stack.

7. **Require consistent observations before committing any patch.** Reject changing API identities, changing site bytes, overlapping repairs, entry into the middle of a replacement, and sites that have both an accepted and an unresolved observation. Retain unresolved transitions in the report. The shortest equivalent window is chosen when more than one supported width qualifies.

8. **Build loader-managed imports and patch the accepted windows.** Preserve existing ordinary import descriptors and their original IAT locations, including a separate lookup table that lets the loader rebind their entries. Append a `.sogen` section containing the recovered DLL/function names, import lookup tables, and new IAT entries. A six-byte window becomes `CALL [RIP+IAT]`. A five-byte window calls a new thunk that tail-jumps through its IAT entry. Thus the loader supplies fresh API addresses on every launch; emulation-session DLL addresses are never embedded in the new IAT. These structures follow the [PE import format](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#import-directory-table).

9. **Write the mapped sections back into a PE and set its entry to the detected handoff.** Keep their RVAs and permissions, recompute raw offsets and image/header sizes, and update the import/IAT directories. Remove stale certificate, debug-file-offset, and bound-import directories. The current standalone writer rejects TLS, delay-import, and CLR initialization, and rejects existing import descriptors without a usable separate lookup table. It does not silently remove those initialization requirements.

10. **Validate from a fresh load.** The separate verifier reads the baseline's import inventory, checks that its imports were recovered and ordinary IAT slots retained, runs each rebuilt executable natively three times, and then starts it in a fresh sogen process from the PE entry. Compare native output/status and fresh-emulator API sequence/output with the baseline. The original unpacker's process state is absent from these fresh runs.

The invariant supporting a repair is **an observed native call window that reaches a verified export with the same API inputs, the required call stack and continuation, and no recorded writes outside private stack scratch**. It is evidence for the observed executions. Branches or inputs that were not exercised remain unproven.

| Fixture | Application calls recovered | Additional transparent cleanup call | Existing IAT entries retained | Native + fresh sogen |
| --- | ---: | --- | ---: | --- |
| VMP 3.5.1 | 3/3 | None observed | 12 | Pass |
| VMP 3.8.1 | 3/3 | HeapFree | 8 | Pass |
| VMP 3.9.6 | 3/3 | HeapFree | 1 | Pass |

The application imports are GetStdHandle, WriteFile, and ExitProcess. Their recovered window RVAs are 0x1011, 0x1035, and 0x103D in each fixture; these are outputs of the experiment. The main-image instruction counts after the handoff were 62, 624, and 803 respectively, including protector cleanup activity.

The newer fixtures also produce four critical-section helper transitions and one unnamed return into ntdll during termination. The helper calls change their inputs before reaching the API, so the original calls fail the transparent-call check and remain unchanged. The unnamed transition does not establish an import. All five observations remain visible in each report.

Recorded serial capture times were 7.831, 103.823, and 120.698 seconds. Recovery plus PE rebuilding took 0.015, 0.091, and 0.081 seconds. Warm native medians over three runs were approximately 0.015, 0.029, and 0.028 seconds. These are single-host experiment measurements, not a controlled performance comparison.

The current scope is observed native call windows in the mapped main executable on x64 Unicorn. Unexecuted protected imports, data imports, tail-jump-only sites, imports entirely inside virtualized execution, private executable allocations, and transformations requiring wider replacements need additional analysis. Existing ordinary imports are retained, but this experiment does not certify complete import recovery for arbitrary programs or all protectors.

Implementation and reproduction:

```powershell
cmake --build --preset=release --target analyzer unicorn-emulator windows-emulator-test
py -3.13 -m unittest discover -s tools -p test_import_recovery.py
build/release/artifacts/windows-emulator-test.exe --gtest_filter=DynamicHooks.*:EntryHandoff.*

py -3.13 tools/verify_import_fixtures.py D:/RE/REProjects/.tmp/REV-412-OEP --analyzer D:/RE/REProjects/sogen/build/release/artifacts/analyzer.exe --emulation-root D:/RE/REProjects/sogen-root --output D:/RE/REProjects/.tmp/REV-423-IAT/review
```

Use `--reuse-captures` to repeat recovery and fresh execution without repeating unpacking; fixture, analyzer, and backend hashes are checked before reuse. Individual captures can be processed with `tools/recover_imports.py CAPTURE_DIRECTORY --output REPAIRED.exe`.

The raw images, protected executables, full traces, and repaired binaries remain local. [import-fixtures.json](import-fixtures.json) contains compact validation evidence. Sixteen synthetic recovery tests cover acceptance and rejection rules; the C++ dynamic-hook regression and five existing OEP tests pass. The repository smoke sample also passes. The repository-wide tidy build is blocked by existing redundant-`typename` errors in `platform/port.hpp:83` and `platform/process.hpp:1261,1272`. All changed C++ files and headers pass targeted tidy.
