---
name: recover-windows-x64-rva
description: "Recover authorized Windows x64 behavior from user-supplied runtime traces using concrete backward slicing, optional-for-hypothesis Triton replay/taint/path solving, multi-trace comparison, recursive callee recovery, and clearly labeled C++ artifacts without compiling candidates. Use when trace files from frida-instr-trace unidbg AssemblyCodeDumper-style text output, the bundled pintrace-jsonl/2.0 toolchain, or C:\\project\\intel-pin UnidbgTrace binary/unidbg-text output are available for VMP/obfuscated exports, self-decrypting LoadLibrary/DllMain DLLs, interactive console protocols, algorithms, callbacks, failures, exceptions, and side effects. Source code, if user-supplied for testing, is validation-only and never recovery evidence."
---

# Recover Windows x64 RVA Logic

Work entirely offline. Initial target tracing is done by a human or upstream workflow; once trace files are supplied, the AI owns downstream analysis: format detection, integrity checks, normalization, replay, slicing, Triton-assisted proof when available, hypothesis management, and recovered C++ artifacts. Treat user-supplied runtime traces as the primary evidence. Recover observable behavior, not original source spelling. Never claim whole-program recovery outside the traced and tested interval.

This skill supports two output levels:

- `verified`: behavior tied to target bytes, raw trace records, replay/slice/taint/path evidence, or direct external-event observations.
- `hypothesis`: AI-inferred behavior that best explains the available traces but is not fully proven. Hypotheses are allowed and useful; they must be labeled as such, include confidence and rationale, and never be promoted to `verified` or `complete` without evidence.

Assume the normal case is binary-only. If source code appears in the workspace, treat it as a user-provided validation oracle only when the user explicitly says so; never read it to infer behavior, fill gaps, or justify the recovered logic.

## Enforce Evidence Independence

Treat source code, debug symbols, prior reconstructions, and unprotected builds as unavailable unless the user explicitly supplied them as evidence before recovery. A reconstruction written from the current hypothesis is a candidate, never an oracle or required trace source.

If a source oracle is supplied for testing, keep it completely separate from recovery evidence:

- do not inspect it until the candidate exists;
- do not mine it for branch structure, constants, or control flow;
- do not cite it as proof of any recovered behavior;
- use it only for black-box differential validation of the candidate.

Prefer trace evidence from one protected EXE. Do not launch, instrument, attach to, or otherwise trace a target yourself unless the user explicitly asks for trace capture in the current request. Default to consuming trace files already produced by the user or an upstream tracing workflow, then perform the downstream analysis without asking the user to manually inspect routine trace details.

Accepted trace inputs:

- bundled toolchain `pintrace-jsonl/2.0` instruction JSONL plus optional external-call JSONL;
- `C:\project\intel-pin` UnidbgTrace binary pair: `<prefix>.events.bin` plus `<prefix>.meta.bin`;
- `C:\project\intel-pin` UnidbgTrace rendered text from `trace_to_text.py` when the binary pair is unavailable;
- `frida-instr-trace` UTF-8 unidbg `AssemblyCodeDumper`-style text output from `frida-rva-trace` / `native\veh-injector`, including lines shaped as `[module 0xRVA] [bytes] 0xVA: "instruction" ...`.

Use a twin only when provenance and independent equivalence evidence predate the reconstruction. Record both hashes and the proof. Never silently substitute a hand-written candidate twin. If the main behavioral trunk is recoverable from evidence or a trace-supported hypothesis, generate it first and list the remaining gaps as `unknown`. Only stop without C++ when even a useful hypothesis cannot be supported.

For self-decrypting DLLs whose code decrypts in `DllMain` during `LoadLibrary`, or whose `DllMain` owns the interactive prompts, read [references/self-decrypting-dllmain.md](references/self-decrypting-dllmain.md) before classifying supplied routing evidence or requesting a replacement trace.

Read [references/rva-boundaries.md](references/rva-boundaries.md) before interpreting or requesting trace RVA boundaries.

## Establish The Case

Accept user-supplied traces by default. A bare executable/RVA request is a request for trace requirements or analysis planning unless the user explicitly asks this skill to capture a trace.

For trace-backed cases, ask for or infer, when present: trace paths, matching external-call paths, target/module path and SHA-256, module base, selected RVA window, input seeds, and the trace schema. If some metadata is absent, proceed with best-effort analysis and record the missing fields as `unknown` or `hypothesis_blocker`. Validate trace integrity as far as the files allow, hash every supplied trace, and state whether conclusions are `verified` from raw trace records or `hypothesis` from trace patterns.

When the user supplies caller RVAs, recover the call ABI from trace records at that caller when available, then discover callee entry and reachable returns from runtime evidence. Reject ASLR VAs as RVA boundaries unless the trace schema explicitly identifies them as runtime VAs with a module base.

Do not create a direct capture case, run `CREATE_RVA_CASE.cmd`, run `RUN_CASE.cmd`, start Pin, attach Pin, start Frida/Stalker, or build an execution harness unless explicitly requested. It is allowed and expected to run offline trace analyzers, converters, validators, digest builders, Triton replay scripts, slicers, and artifact writers against supplied files. If trace evidence is insufficient, emit a precise missing-trace request: format, module, RVA window, input transcript/arguments, and fields needed for the blocked claim.

Do not accept metadata-only JSONL as proof. Metadata-only traces may still seed a `hypothesis` artifact, but verified claims require instruction records or independently observed external events. Prefer schema v2 evidence PASS, zero required failures, contiguous instruction records, both boundaries, scalar pre-state, instruction bytes, reliable memory post-state, external effects, and accepted memory loss; if any field is missing, continue only with downgraded confidence and list the gap.

For a metadata-only, stalled, or incomplete trace supplied by the user, classify the likely cause from available trace metadata and logs. Do not retry capture yourself. Request a replacement trace or routing evidence when needed, such as runtime bytes, module load timing, owner-thread status, or a debugger/Pin replay that records the missing sink.

## Capture Behavior and the Critical Branches

Analyze supplied runs for success, repeats, one-field mutations, boundary lengths, invalid inputs, aliases, callback behavior, resource failure, exceptions, and crashes as applicable. Treat dangerous-call coverage as a trace request to the upstream capture workflow, not as an instruction to execute the target yourself.

If the supplied trace set is missing routine branch coverage, propose concrete additional inputs or transcripts for the upstream capture workflow. Do not build or run cheap ABI probes unless the user explicitly asks for local execution.

For interactive console targets, request an upstream trace whose harness owns stdin/stdout and writes the whole transcript programmatically. Treat the transcript as atomic: menu selector, submenu payloads, explicit exit token, and final pause-dismiss key. Ask upstream capture to preserve output as bytes when UTF-8 decoding is unreliable.

Expect to iterate across multiple concrete inputs and multiple traces. The default recovery loop is: ingest user-supplied traces, normalize their schema, replay when available, taint and slice from branches/sinks/stores when practical, emit or update a C++ hypothesis, parse that hypothesis for branch/data obligations, solve alternate predicates or choose cheap boundary inputs, request new upstream traces when needed, merge evidence, and repeat. A first matching path is enough to deliver a labeled `hypothesis` or `trunk` artifact, but not enough to claim complete behavior when branch behavior, error handling, or callback order is still unverified.

Maintain a branch manifest while exploring. For every executed or statically reachable conditional branch that affects the recovered logic or sink behavior, record the RVA, condition, controlling input, true-edge runs, false-edge runs, next RVAs, and observable effects. Uncovered edges become `unknown` items in the gap list instead of blocking trunk delivery. Include branches controlling cleanup, allocation, callback order, output-length sentinels, error codes, exceptions, and early returns.

Recover callees by default. Starting from the requested RVA window, follow observed direct calls, indirect calls with resolved runtime targets, returns, tail jumps, and helper chunks that materially affect inputs, branches, stores, external calls, or return values. Emit recovered C++ for the wrapper and reachable subfunctions together in one artifact unless the user explicitly asks for one function only. Name unresolved callees as `sub_<rva>` and include a body when trace evidence or a strong hypothesis exists; otherwise emit a stub with `unknown` behavior and a gap entry. Wrapper-only output is incomplete if a traced callee owns the real algorithm or sink.

Read [references/trace-recovery.md](references/trace-recovery.md) before naming an algorithm and [references/vmp-trace-analysis.md](references/vmp-trace-analysis.md) for VMP normalization or crypto/protocol hypotheses.

## Use Triton When Available

Binary-analysis Triton is required for `verified` symbolic claims and `complete` gate claims, but it is not a blocker for best-effort or hypothesis C++ generation. Run when available:

```cmd
python scripts\check_triton.py
```

Use the Python interpreter that passes this semantic, taint, and solver check. A successful import, disassembly, snapshot probe, concrete slicer, or candidate test does not count as `verified` recovery validation. If Triton is unavailable, still generate a clearly labeled `hypothesis` C++ artifact from traces and static/dynamic reasoning, then report that verified symbolic proof is missing. Never download Triton during an offline case.

For verified claims, select each concrete sink, build a byte-accurate backward slice, then replay a focused real-trace window in Triton. Require exact agreement for the processed next PCs, reliable writes, and the sinks used to justify the verified part of the algorithmic claim. For hypothesis claims, Triton disagreement, missing snapshots, or unavailable symbolic proof should downgrade confidence rather than suppress the C++ output. Apply taint from confirmed sources and solve key uncovered path predicates when possible; otherwise explain the guessed predicate and what trace would confirm it. Prefer focused windows for branch obligations discovered from supplied traces; avoid full-loop Triton replay until a recurrence or segment proof is ready. Request independent runs when needed to separate the main trunk from edge behavior.

Read [references/dynamic-slicing-triton.md](references/dynamic-slicing-triton.md) before replay. A runtime snapshot may be decoded with `scripts\triton_snapshot_probe.py`, but its report explicitly is not replay evidence because it lacks concrete execution state.

## Offline Bundle

Read [references/toolchain-usage.md](references/toolchain-usage.md) before ingesting `frida-instr-trace` text traces, bundled JSONL traces, `C:\project\intel-pin` UnidbgTrace binary/text traces, Triton replay reports, or recovery validation manifests.

Use these fixed bundle paths:

- `.runtime\triton-py314` for Triton/Python
- `toolchain\pin` for `pin.exe` and the selected Pin runtime
- `toolchain\trace` for the selected tracer/helper DLLs

Repository-copy note for `C:\project\frida-trace`: this checked-in skill copy intentionally omits generated `.runtime`, the full Pin SDK under `toolchain\pin`, `_toolchain_stage`, caches, logs, and backup DLLs. Treat missing runtime/toolchain components as unavailable rather than as a setup failure. The native trace input for this repository is `frida-instr-trace` text produced by `native\veh-injector` / `frida-rva-trace`; request stronger external traces only when the missing machine state is required for verified claims.

The reusable cross-sample layer is the skill itself, `references/`, `runtime/replay/`, `scripts/`, `templates/`, `tests/`, `vendor/`, and the skill-local `.runtime\triton-py314` environment after it passes `scripts/check_triton.py`. These may be packaged and installed offline.

Pin and trace helpers are reusable only when their version, trace schema, switches, and required DLLs are fixed and recorded. Package them as an optional upstream toolchain component; keep per-sample traces, recovered candidates, logs, ASTs, and source oracles outside the reusable bundle.

To build a portable offline bundle:

```cmd
python scripts\package_offline_bundle.py --output C:\path\recover-windows-x64-rva-offline.zip
```

To include fixed Pin or trace tools:

```cmd
python scripts\package_offline_bundle.py --output C:\path\recover-windows-x64-rva-offline.zip --pin-root C:\pin --pin-tool C:\tools\tracer\MyPinTool.dll
```

To validate a bundled installation:

```cmd
python scripts\check_offline_bundle.py
```

## Stage The First Candidate

Emit the best-supported C++ early. If verified evidence closes the main behavioral trunk, label the corresponding statements `verified`. If the trace pattern strongly suggests missing constants, loops, predicates, or callees but proof is incomplete, include them as `hypothesis` with confidence and rationale instead of omitting them. The C++ is an evidence/hypothesis artifact, not a compiled candidate binary.

The first delivery must:

- include an actual recovered `.cpp` artifact path; a report, trace summary, or prose-only answer is incomplete;
- preserve every verified ABI rule, sink, callback order, and error/exception path already proven;
- recover observed reachable subfunctions in the same `.cpp` artifact, or include stubs and gap entries for unresolved callees;
- keep all remaining gaps explicitly labeled `unknown`, and all AI guesses explicitly labeled `hypothesis`;
- include a short gap list and the exact trace/branch items still open;
- include a `cpp_evidence_map` tying every emitted branch, store, formula, call, return, error, and exception behavior to raw target trace IDs plus Triton replay/taint/slice/path evidence when available, or to a `hypothesis` rationale when proof is missing.

After delivering the trunk or hypothesis C++, summarize which subfunctions are verified, inferred, guessed, or still unknown. If more precision is needed, request specific additional upstream traces with exact format, module/RVA window, and input requirements.

## Validate Evidence Against The Original

Validate the recovered C++ by evidence mapping, not by compiling it. The validation surface for verified claims is the original target trace set, strict Triton concrete replay when available, taint and backward slices, path predicates and solver results, branch-edge manifest, sink inventory, exception/unwind inventory, and the `cpp_evidence_map`. Hypothesis claims may rely on AI reasoning over trace patterns and static structure, but must stay labeled `hypothesis` until confirmed by a user-supplied trace. Solver-produced inputs and AI-guessed inputs are trace requests, not evidence, until the upstream workflow executes them on the original target and supplies the resulting trace.

Do not search for, invoke, or report missing C/C++ compilers such as `cl.exe`, `clang++`, or `g++`. Do not compile recovered C++, create candidate binaries, or run target-vs-candidate differential validation as part of this skill. If the user later asks to compile or test the artifact, treat that as a separate task outside the recovery evidence gate and never promote its result to recovery evidence.

Read [references/completeness-validation.md](references/completeness-validation.md), then run:

```cmd
python scripts\validate_recovery_gate.py path\to\recovery_gate.json
```

Use `claim=hypothesis` in prose/artifact metadata for best-effort C++ that includes AI guesses. Use `claim=trunk` for a key-algorithm artifact with explicit `unknown` gaps and enough evidence for the main path. Use `claim=complete` only when every branch, sink, failure, exception, and machine-state domain is closed or solver-proven infeasible. Only a PASS may authorize the strongest verified claim for the current evidence set; a failed or skipped gate does not block hypothesis delivery.

## Generate Through A Plugin

After the current evidence gate passes, implement a case plugin only when existing case infrastructure is already present and an automated artifact writer is useful. For hypothesis-only cases, a lightweight local writer is acceptable if it emits C++, evidence map, hypotheses, and gaps. Preserve ABI, widths, signedness, alias behavior, callback order, allocation/cleanup, state transitions, error returns, exceptions, and crash behavior. Keep unsupported helpers and uncovered behavior as `unknown`, not silently deleted.

Read [references/plugin-artifacts.md](references/plugin-artifacts.md). Route supplied-trace and replay failures using [references/failure-routing.md](references/failure-routing.md); when requesting replacement upstream traces, ask for one variable to change at a time and retain failed evidence.

## Deliver

Report case ID when present, target hashes when known, exact RVA intervals or trace-selected windows, arguments/input seeds, branch-edge coverage, trace metrics, Triton interpreter/version and replay report hashes when available, provenance losses, recovered callee list, and `verified/inferred/hypothesis/unknown` findings. Deliver evidence-listed or hypothesis-listed artifacts with SHA-256 values. When only the main trunk or a hypothesis is ready, deliver the combined wrapper-plus-subfunctions C++ plus the gap list. Never describe source as complete while a required gate or branch edge is missing.
