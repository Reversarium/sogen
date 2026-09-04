# OEP detection tested on REV-412 fixtures

The same detector finds RVA `0x1000` in the supplied VMProtect 3.5.1, 3.8.1, and 3.9.6 executables. It takes only the protected executable. The baseline is used afterward by the verification script, never by the detector.

1. **Stop observing startup until the executable's PE entry point executes.** Capture that thread's RSP (`S0`), the eight bytes at `[S0]`, RBX/RBP/RSI/RDI/R12–R15, and XMM6–XMM15 before the entry instruction. This anchors the comparison to the actual entry invocation, after earlier Windows startup activity. The hook does not look for a prologue or a saved-RBP instruction.

2. **Observe executed basic blocks on that same thread and require RSP to leave `S0`.** This prevents reporting the initial entry context as a discovery. Other threads cannot satisfy the condition. A nested call normally has its own stack frame and therefore fails the later RSP comparison.

3. **At every subsequent block boundary, first compare RSP with `S0`.** If different, continue. This is a native sogen block callback, not a debugger break after every instruction. On a match, read the full saved comparison state. These fixtures each have exactly one post-entry block boundary with `RSP == S0`, despite many intermediate VM transitions.

4. **Require the return slot, all eight nonvolatile GPRs, and XMM6–XMM15 to match the entry snapshot.** Equal RSP alone is insufficient: a reused stack address, a different continuation, or a partially restored register context must fail. Volatile GPRs and flags are deliberately excluded; the experiment showed that they differ at the verified OEP. This is an entry-frame restoration condition, not equality of the entire machine state.

5. **Record the current block address before its first instruction executes.** Also record the previous executed block, matching state, and 64 destination bytes. Do not require a particular predecessor instruction, a section name, membership in the original image, an RVA, or a byte signature. Multiple distinct matches remain multiple candidates; the first one is not silently selected.

6. **Complete the run and classify the evidence.** One distinct match becomes `unique_candidate`; multiple matches become `ambiguous`; zero becomes `no_candidate`. An unsuccessful or interrupted run becomes `incomplete`, even if it emitted candidates earlier. An entry point that never executed becomes `entry_not_reached` after a successful run. This implementation audits the run; it does not stop the guest at the first candidate.

7. **Validate independently against the baseline in the fixture test.** Only after the protected runs finish, read the baseline PE entry RVA and entry bytes. Require one candidate at that RVA and a matching 16-byte entry prefix, successful guest exit, and output equal to the baseline. Record whether all 64 bytes match separately. Later bytes differ in these protected fixtures, so full function byte identity is not an acceptance requirement. The unprotected baseline must report its PE entry and no additional handoff.

The operative assumption is specific: the loader hands off to a native entry boundary after restoring this entry-frame state. It does not require a native `push rbp` at the protected entry, and does not assume every VM exit is that handoff. The supplied runs establish a unique matching boundary for these three files; they do not establish uniqueness for all possible programs.

A unique context match alone cannot prove that the destination belongs to the original program. A protector can construct a decoy with the same state. A returning entry function or intermediate tail transfers can also create multiple matches. The tool preserves that uncertainty through candidate terminology and explicit ambiguity. It does not fall back to `.text`, first-executed sections, API names, or instruction signatures.

If the original entry itself is virtualized into the unpacker's VM, the original native entry boundary may never execute. VMProtect explicitly documents that a virtualized entry and unpacker can share the same interpreter ([VMProtect manual](https://vmpsoft.com/vmprotect/user-manual/working-with-vmprotect/)). This detector does not recover a virtual instruction pointer or reconstruct a removed native entry. A missing native candidate is unresolved, not a guessed OEP. All three supplied fixtures do execute the verified native boundary at RVA `0x1000`.

Run one protected file:

```powershell
build/release/artifacts/analyzer.exe -s --no-inst-precision --reproducible `
  --oep-report candidate.jsonl -e D:/RE/REProjects/sogen-root `
  -p c:/sample.exe D:/RE/REProjects/.tmp/REV-412-OEP/hello-x64-396.vmp.exe `
  c:/sample.exe
```

Reproduce the fixture check:

```powershell
py -3.13 tools/verify_oep_fixtures.py D:/RE/REProjects/.tmp/REV-412-OEP `
  --analyzer build/release/artifacts/analyzer.exe `
  --emulation-root D:/RE/REProjects/sogen-root `
  --output D:/RE/REProjects/.tmp/REV-412-OEP/results/verified --jobs 3
```

The JSONL contains `entry`, zero or more `candidate` events, then `result`. Addresses and register values are hex strings. `rva` is null for an address outside the main image; that is reporting metadata, not a rejection condition. `previous_block` is a block address, not the exact predecessor instruction. The nonvolatile GPR array order is RBX, RBP, RSI, RDI, R12, R13, R14, R15. SIMD entries contain the low and high 64-bit halves. `unique_candidate` requires a completed successful run and means uniqueness under this predicate, not universal semantic proof.

Implementation: `src/windows-analyzer/oep_detector.cpp` installs the hooks and writes evidence; `entry_handoff_tracker.hpp` holds the comparison state and candidate set. The fixture checker uses only Python's standard library. The tested backend is Unicorn with one vCPU and x64 EXEs. DLL entry invocations, virtual entry recovery, and other backends are not validated by these fixtures.

The regression tests use distinct nonzero register values and reject partial GPR/SIMD restoration, a changed return slot, another thread, initial-entry/reentry matches, and premature matches before stack departure. They also accept a matching destination outside the original image and retain ambiguity across distinct destinations. These are state-machine tests; they do not claim that the protected binaries were run with perturbed registers.

Validation records are in `oep-fixtures.json`. Release build, fixture verification, and the existing test-sample smoke test passed. The required full tidy build was attempted and failed on unchanged platform headers (`platform/port.hpp:83`, `platform/process.hpp:1261,1272`, redundant `typename`). New detector and test files, plus the changed lines in analyzer main, pass targeted clang-tidy with the repository checks; the existing analyzer main also has pre-existing unchecked-container-access diagnostics. No unrelated source was changed to suppress these failures.
