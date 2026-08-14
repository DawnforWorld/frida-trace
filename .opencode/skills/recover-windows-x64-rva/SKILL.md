---
name: recover-windows-x64-rva
description: "Recover authorized Windows x64 behavior from this repository's frida-instr-trace text output. Use when native\\veh-injector / frida-rva-trace trace files are available for RVA windows, algorithms, branches, callees, failures, exceptions, and side effects. Source code, if supplied for testing, is validation-only and never recovery evidence."
---

# Recover Windows x64 RVA Logic

Work offline from supplied `frida-instr-trace` text traces produced by this repository.

Treat trace records as the primary evidence. Recover observable behavior inside the traced RVA interval, not original source spelling or whole-program intent.

Accepted trace input:

- UTF-8 unidbg `AssemblyCodeDumper`-style text emitted by `native\veh-injector` / `frida-rva-trace`.

Read these references before analysis:

- [Trace Format](references/frida-instr-trace.md)
- [RVA Boundaries](references/rva-boundaries.md)
- [Recovery Workflow](references/trace-recovery.md)

## Evidence Rules

- Hash every supplied trace before analysis.
- Record, when present: trace path, target/module path and SHA-256, selected module, module base, start RVA, inclusive stop RVA, command-line arguments, stdin transcript, trigger point, `--target-only`, and `--flush`.
- If metadata is missing, proceed best-effort and mark fields as `unknown` rather than inventing them.
- Use the bracketed module RVA as the selected-module offset. Treat absolute VAs as ASLR-dependent unless the trace or arithmetic from consistent module RVA/VA pairs proves a base.
- Treat instruction bytes, decoded instruction text, register tokens, memory effective addresses, and external target hints as trace evidence.
- Memory entries record effective address and size only. They do not prove memory byte values.
- Missing post-register tokens do not prove unchanged state.
- No strict symbolic or complete claim may rely on memory bytes, extended registers, exact flags transitions, or API argument logs unless the user supplies separate evidence for those fields.

## Recovery Scope

Deliver one of these claim levels:

- `verified`: behavior directly tied to raw trace rows, instruction bytes, observed control flow, register observations, external target hints, or user-supplied side-effect observations.
- `hypothesis`: inferred behavior that best explains the trace but depends on missing bytes, unobserved branches, omitted state, or AI reasoning. Label confidence and rationale.

Do not promote a hypothesis to verified without additional trace evidence.

Recover callees by default when the trace shows direct calls, resolved indirect calls, returns, tail jumps, or helper chunks that materially affect inputs, branches, stores, external calls, or return values. Emit unresolved callees as `unknown` stubs with gap entries.

## Source Independence

If source code, debug symbols, previous reconstructions, or unprotected builds appear in the workspace, do not read them to infer behavior unless the user explicitly supplied them as recovery evidence before analysis. If source is supplied only for testing, keep it separate:

- do not inspect it until a candidate recovery exists;
- do not mine it for branches, constants, or control flow;
- do not cite it as proof;
- use it only for black-box differential validation if the user asks.

## Deliverables

When a useful trunk or hypothesis exists, deliver an actual recovered `.cpp` artifact path plus a short report containing:

- trace paths and SHA-256 values;
- selected module and RVA interval;
- arguments/transcript/trigger metadata when known;
- branch-edge coverage and unknown edges;
- recovered subfunction list;
- `verified`, `hypothesis`, and `unknown` findings;
- `cpp_evidence_map` tying each branch, store, formula, call, return, error, exception, and side effect in the C++ to trace rows or a labeled hypothesis rationale;
- gaps blocking stronger claims.

The recovered C++ is an evidence/hypothesis artifact. Do not compile candidates, do not search for compilers, and do not claim complete behavior while branch edges, sinks, exceptions, or state domains remain uncovered.
