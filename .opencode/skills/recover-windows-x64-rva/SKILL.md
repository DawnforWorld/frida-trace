---
name: recover-windows-x64-rva
description: "Recover authorized Windows x64 data-flow from frida-instr-trace traces, authorized sample binaries, and Triton/angr-assisted taint/slicing for RVA windows, algorithms, branches, callees, failures, exceptions, inputs, outputs, and side effects. Use when native\\veh-injector / frida-rva-trace trace files or sample inputs are available and the goal is C++ reconstruction from trace plus binary evidence."
---

# Recover Windows x64 RVA Logic

Work offline from supplied `frida-instr-trace` text traces and any authorized sample binaries or outputs provided by the user.

Treat trace records as the primary evidence. Use Triton, angr, or comparable analysis only to refine hypotheses through taint tracking, backward slicing, path constraints, CFG recovery, and AST simplification. The main objective is to recover how input bytes, registers, memory, and state flow into outputs, comparisons, stores, returns, and emitted buffers. Recover observable behavior inside the traced RVA interval, not original source spelling or whole-program intent.

Accepted trace input:

- UTF-8 unidbg `AssemblyCodeDumper`-style text emitted by `native\veh-injector` / `frida-rva-trace`.

Read these references before analysis:

- [Trace Format](references/frida-instr-trace.md)
- [RVA Boundaries](references/rva-boundaries.md)
- [Recovery Workflow](references/trace-recovery.md)

## Evidence Rules

- Hash every supplied trace before analysis.
- Hash every supplied sample binary or auxiliary artifact before analysis.
- Record, when present: trace path, target/module path and SHA-256, sample binary path and SHA-256, selected module, module base, start RVA, inclusive stop RVA, command-line arguments, stdin transcript, trigger point, `--target-only`, and `--flush`.
- If metadata is missing, proceed best-effort and mark fields as `unknown` rather than inventing them.
- Use the bracketed module RVA as the selected-module offset. Treat absolute VAs as ASLR-dependent unless the trace or arithmetic from consistent module RVA/VA pairs proves a base.
- Treat instruction bytes, decoded instruction text, register tokens, memory effective addresses, and external target hints as trace evidence.
- Memory entries record effective address and size only. They do not prove memory byte values.
- Missing post-register tokens do not prove unchanged state.
- No strict symbolic or complete claim may rely on memory bytes, extended registers, exact flags transitions, or API argument logs unless the user supplies separate evidence for those fields.
- Triton/angr expressions, taint flows, and path constraints are support evidence, not proof, until they line up with trace rows or user-supplied observed I/O.

## Recovery Scope

Deliver one of these claim levels:

- `verified`: behavior directly tied to raw trace rows, instruction bytes, observed control flow, register observations, external target hints, or user-supplied side-effect observations.
- `hypothesis`: inferred behavior that best explains the trace but depends on missing bytes, unobserved branches, omitted state, or AI reasoning. Label confidence and rationale.

Do not promote a hypothesis to verified without additional trace evidence.

Recover callees by default when the trace shows direct calls, resolved indirect calls, returns, tail jumps, or helper chunks that materially affect inputs, branches, stores, external calls, or return values. Emit unresolved callees as `unknown` stubs with gap entries.

## Data-Flow Workflow

When a useful trace exists and the user also supplies a sample binary, input corpus, or observed outputs:

1. Identify sources: stdin, file reads, network reads, command-line arguments, shared memory, decrypted buffers, and persisted state.
2. Identify sinks: comparisons, branches, writes, returns, encoders, decoders, checksums, decryptors, and output buffers.
3. Use Triton to taint source bytes and propagate influence through registers, memory, and flags.
4. Use angr to recover surrounding CFG shape, prune infeasible paths, and confirm which predicates control the sink.
5. Perform backward slicing from sink to source until the minimum data-flow chain is stable.
6. Simplify the recovered expressions into readable C++-style formulas that explain the observed output.
7. Validate the candidate flow against trace rows and any supplied sample input/output pairs.

Preferred uses:

- Triton: taint source discovery, register/memory influence tracking, simplification of arithmetic and bitwise expressions, branch predicate recovery, input-to-output dependency chains.
- angr: function boundary recovery, path predicate extraction, CFG/call graph building, pruning impossible branches, locating loops and dispatchers that affect the data flow.
- Multiple traces: confirm edge coverage and distinguish verified behavior from path-specific hypotheses.

## Source Independence

If source code, debug symbols, previous reconstructions, or unprotected builds appear in the workspace, do not read them to infer behavior unless the user explicitly supplied them as recovery evidence before analysis. If source is supplied only for testing, keep it separate:

- do not inspect it until a candidate recovery exists;
- do not mine it for branches, constants, or control flow;
- do not cite it as proof;
- use it only for black-box differential validation if the user asks.

If the user supplies only a sample binary and no source, it may be used as analysis evidence together with trace-derived state, but the final claims must still separate observed rows from tool-derived hypotheses.

## Deliverables

When a useful trunk or hypothesis exists, deliver an actual recovered `.cpp` artifact path plus a short report containing:

- trace paths and SHA-256 values;
- selected module and RVA interval;
- arguments/transcript/trigger metadata when known;
- branch-edge coverage and unknown edges;
- recovered subfunction list;
- `verified`, `hypothesis`, and `unknown` findings;
- `cpp_evidence_map` tying each branch, store, formula, call, return, error, exception, input source, and output sink in the C++ to trace rows or a labeled hypothesis rationale;
- tool notes for any Triton/angr assumptions, taint sources, path predicates, and simplification steps;
- gaps blocking stronger claims.

The recovered C++ is an evidence/hypothesis artifact. Do not compile candidates, do not search for compilers, and do not claim complete behavior while branch edges, sinks, exceptions, or state domains remain uncovered.
