---
name: recover-windows-x64-rva
description: "Recover authorized Windows x64 data-flow from one or more frida-instr-trace traces, authorized sample binaries, and Triton/angr-assisted taint/slicing for RVA windows, algorithms, branches, callees, failures, exceptions, inputs, outputs, and side effects. Use when native\\veh-injector / frida-rva-trace trace files or sample inputs are available and the goal is C++ reconstruction from trace families plus binary evidence."
---

# Recover Windows x64 RVA Logic

Work offline from supplied `frida-instr-trace` text traces and any authorized sample binaries or outputs provided by the user.

Treat trace records as the primary evidence. Use Triton and angr as first-class analysis tools when the supplied artifacts are sufficient: Triton for concrete/symbolic execution, taint propagation, AST extraction, and AST simplification; angr for CFG recovery, call graph expansion, VEX-level slicing, symbolic exploration, and path predicate recovery. Tool output refines hypotheses and candidate formulas, but verified claims still require trace rows or user-supplied I/O evidence. The main objective is to recover how input bytes, registers, memory, and state flow into outputs, comparisons, stores, returns, and emitted buffers. Recover observable behavior inside the traced RVA interval, not original source spelling or whole-program intent. Prefer multiple traces over a single trace whenever the algorithm contains loops, table lookups, path-specific branches, or lane/state permutations.

Accepted trace input:

- UTF-8 unidbg `AssemblyCodeDumper`-style text emitted by `native\veh-injector` / `frida-rva-trace`.

Read these references before analysis:

- [Trace Format](references/frida-instr-trace.md)
- [RVA Boundaries](references/rva-boundaries.md)
- [Recovery Workflow](references/trace-recovery.md)

## Evidence Rules

- Hash every supplied trace before analysis.
- When multiple traces are supplied, record the trace family, note which traces share the same module/RVA window, and use cross-trace agreement to separate invariant logic from path-dependent logic.
- Hash every supplied sample binary or auxiliary artifact before analysis.
- Record, when present: trace path, target/module path and SHA-256, sample binary path and SHA-256, selected module, module base, start RVA, inclusive stop RVA, command-line arguments, stdin transcript, trigger point, `--target-only`, and `--flush`.
- If metadata is missing, proceed best-effort and mark fields as `unknown` rather than inventing them.
- Use the bracketed module RVA as the selected-module offset. Treat absolute VAs as ASLR-dependent unless the trace or arithmetic from consistent module RVA/VA pairs proves a base.
- Treat instruction bytes, decoded instruction text, register tokens, memory effective addresses, and external target hints as trace evidence.
- Memory entries record effective address and size only. They do not prove memory byte values.
- Missing post-register tokens do not prove unchanged state.
- No strict symbolic or complete claim may rely on memory bytes, extended registers, exact flags transitions, or API argument logs unless the user supplies separate evidence for those fields.
- Triton/angr expressions, taint flows, and path constraints are support evidence, not proof, until they line up with trace rows or user-supplied observed I/O.
- If multiple traces disagree, prefer the intersection of behaviors that repeat across traces for verified claims, and label the differences as path-dependent hypotheses.
- Do not hard-code a value observed in one trace as an algorithm. If only one path is available, emit a named stub or formula hole with the observed value as a test vector, not as the implementation.

## Tool Requirements

Use tools when they can materially improve recovery quality:

- Use Triton for instruction-level data flow: seed symbolic variables for input bytes, mark source memory/registers tainted, replay the traced instruction path when bytes and memory evidence are available, collect ASTs for sink registers/memory, simplify expressions, and emit bit-vector formulas for output bytes or dwords.
- Use angr for binary-wide structure: recover CFG around the RVA window, identify function boundaries and callees, lift basic blocks to VEX, recover reaching definitions/backward slices, derive path predicates for branches, and explore alternate feasible edges that are missing from a trace.
- Use both together when possible: angr identifies candidate blocks/edges and state boundaries; Triton reconstructs precise per-instruction source-to-sink expressions on concrete traced paths.
- If Triton or angr cannot run in the environment, ask the user to provide or install the missing tool when it is required; otherwise state the gap explicitly and continue with trace-only recovery. Do not add these tools to this project's runtime dependencies and do not pretend tool-derived evidence exists.
- Tool scripts should be small, reproducible, and tied to the exact binary SHA-256, module base/RVA window, trace file hash, and selected input/output pair.

Required tool outputs when used:

- source definitions: input bytes, API read buffers, argv bytes, decrypted buffers, or state words;
- sink definitions: compare operands, branch predicates, output stores, return values, emitted buffers, or checksum/hash words;
- dependency map: which source bits influence each sink bit;
- simplified formula: Triton AST or equivalent bit-vector expression reduced into readable operations;
- validation notes: which trace rows and sample I/O confirm or contradict the formula.

## Recovery Scope

Deliver one of these claim levels:

- `verified`: behavior directly tied to raw trace rows, instruction bytes, observed control flow, register observations, external target hints, or user-supplied side-effect observations.
- `hypothesis`: inferred behavior that best explains the trace but depends on missing bytes, unobserved branches, omitted state, or AI reasoning. Label confidence and rationale.

Do not promote a hypothesis to verified without additional trace evidence.

Recover callees by default when the trace shows direct calls, resolved indirect calls, returns, tail jumps, or helper chunks that materially affect inputs, branches, stores, external calls, or return values. Emit unresolved callees as `unknown` stubs with gap entries.

## Data-Flow Workflow

When one or more useful traces exist and the user also supplies a sample binary, input corpus, or observed outputs:

1. Cluster traces by module, RVA interval, and observed input/output shape.
2. Align common entry, loop, branch, call, and sink RVAs across traces.
3. Identify sources: stdin, file reads, network reads, command-line arguments, shared memory, decrypted buffers, and persisted state.
4. Identify sinks: comparisons, branches, writes, returns, encoders, decoders, checksums, decryptors, and output buffers.
5. Use Triton to taint source bytes and propagate influence through registers, memory, and flags on each trace.
6. Use angr to recover surrounding CFG shape, prune infeasible paths, and confirm which predicates control the sink.
7. Use Triton ASTs to recover bit-level expressions from source bits to sink bits, especially for arithmetic/bitwise code, rotations, table indices, and mixed flag/data dependencies.
8. Use angr reaching definitions or backward slicing to confirm that the Triton source set is complete and no unmodeled state source is missing.
9. Perform backward slicing from sink to source and compare the slice across traces until the minimum data-flow chain is stable.
10. Simplify the recovered expressions into readable C++-style formulas that explain the observed output.
11. Validate candidate formulas against all supplied traces and any sample input/output pairs.
12. When a trace-specific lane, branch, or table index differs, isolate the invariant subexpression and record the varying term as a path-dependent component.
13. Replace stubs only after a formula explains at least the trace where it was observed and does not contradict other supplied traces.

Preferred uses:

- Triton: taint source discovery, register/memory influence tracking, concrete-path symbolic execution, AST extraction, AST simplification, branch predicate recovery, and input-to-output bit dependency chains.
- angr: function boundary recovery, CFG/call graph building, VEX IR inspection, reaching definitions, backward slicing, path predicate extraction, pruning impossible branches, and locating loops and dispatchers that affect the data flow.
- Multiple traces: confirm edge coverage, derive invariant formulas, isolate path-dependent terms, and distinguish verified behavior from path-specific hypotheses.

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
- cross-trace evidence notes showing which formulas are invariant, which terms vary by path, and which trace pair(s) established the distinction;
- tool notes for any Triton/angr assumptions, scripts used, taint sources, path predicates, ASTs, simplified formulas, source-bit to sink-bit dependencies, and validation steps;
- gaps blocking stronger claims.

The recovered C++ is an evidence/hypothesis artifact. Do not compile candidates, do not search for compilers, and do not claim complete behavior while branch edges, sinks, exceptions, or state domains remain uncovered.
