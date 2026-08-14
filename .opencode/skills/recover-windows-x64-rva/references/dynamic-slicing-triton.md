# Mandatory Dynamic Slicing And Triton Proof

## Separate But Require The Stages

Concrete backward slicing identifies executed definitions that reach a sink. Triton taint confirms influence from selected source bytes. Triton symbolic execution produces exact ASTs and path predicates. Concrete replay checks that Triton's semantics agree with the captured execution. A complete recovery requires all four; none substitutes for another.

## Fail-Closed Preconditions

Require one selected thread, contiguous records, exact instruction bytes/addresses, full scalar pre-state, reliable memory reads/writes, both focused boundaries, and zero loss. If the interval uses XMM/YMM/ZMM, x87, opmask, MXCSR, FS/GS, cross-thread, self-modifying, or external state, that state must be present in the supplied trace or listed as a missing-trace requirement.

Reject the focused window if any required state is absent. Do not seed absent state with zeros or repeatedly overwrite divergent state from trace records.

Choose each sink at an exact sequence number. Record its kind, address/register, width, bytes/bits, owning call/return, and expected side effects.

## Concrete Byte-Versioned Slice

Normalize each instruction into register slices, flag uses/defs, concrete memory-byte versions, address dependencies, observed control edge, and tested external-call models. x86 aliases must be exact: EAX clears upper RAX, AL defines only eight bits, and ADC/SBB/CMOVcc/SETcc consume flags.

Scan backward from sink versions to the last writer of each required version. Add data/address uses, then add controlling predicates whose alternate edge prevents or replaces a selected definition. Leaves at the start boundary remain unclassified until trace evidence identifies them.

Do not physically remove instructions needed to preserve machine semantics. Select a focused contiguous window and replay every instruction in it.

## Per-Function Triton Script

Write a Python analyzer for every recovered function. It must directly call the binary-analysis Triton API:

- TritonContext with ARCH.X86_64;
- setConcreteRegisterValue and setConcreteMemoryAreaValue for boundary state;
- symbolizeMemory or symbolizeRegister only for proven ABI sources;
- taintMemory or taintRegister for the same sources;
- Instruction plus processing for every record;
- getRegisterAst or getMemoryAst for each sink;
- getPathConstraints for every controlling branch;
- simplify on unrolled sink and predicate ASTs;
- isSat and getModel for equivalence checks and alternate edges.

The final gate statically audits these calls and validates the script hash against its runtime report. A script that only parses a report, evaluates a guessed formula, or invokes a candidate implementation fails.

## Exact Replay Loop

At the first record, restore all captured state and install/symbolize sources. For each instruction in sequence:

1. Assert its address and bytes.
2. Supply only concrete memory not already defined or symbolically derived.
3. Process the actual bytes through Triton.
4. Assert the next PC equals the recorded next PC.
5. Assert every reliable write-after byte.
6. Assert non-symbolic registers/memory have not drifted.
7. Record path constraints before any permitted model boundary.

Opaque external returns, concrete resynchronization, unsupported instructions, solver timeouts, AST failures, or state drift block completion.

An audited scalar-SSE2 semantic extension is not a concrete resynchronization. For each modeled instruction, require an exact Z3 IEEE-754 formula, MXCSR mode, result bits, sticky exception flags, post-XMM/MXCSR equality, and a Triton symbolic carrier whose hash is tied to that formula. The shadow formula must be included in the sink/path slice and solver query. Any arithmetic or comparison opcode outside the extension remains a hard unsupported failure.

## Win64 External Boundary Model

When crossing a captured external call or callback return, do not mark the next record as a new first instruction and do not reload the whole trace state. Model only the state the Windows x64 ABI permits the callee to change:

- Volatile GPRs: RAX, RCX, RDX, R8, R9, R10, R11, RFLAGS, and the call/return RIP/RSP transfer.
- Volatile SIMD: XMM0 through XMM5.
- MXCSR status flags bits 0..5 may change; MXCSR control bits 6..15, including DAZ, masks, rounding, and FTZ, must be preserved.
- Nonvolatile GPRs RBX, RBP, RSI, RDI, R12 through R15 and nonvolatile XMM6 through XMM15 must be compared against the trace and kept symbolic if they carried symbolic state.
- Memory writes by the external call are admissible only when captured as explicit side effects; symbolic memory may not be overwritten by a modeled boundary.

Every external return value consumed by the function must be explicitly named, symbolized, tainted, and tied to the external event sequence. If preserving those symbols creates a large loop expression, prove the loop by segmented replay plus an induction or recurrence summary. The segment report must still replay real instructions with Triton, include the entry/exit symbolic state, verify nonvolatile preservation at each callback boundary, and prove the recurrence step with solver equivalence. A long unrolled AST is useful evidence, but it is not required when a stronger segmented proof closes the same branch and sink obligations.

## Taint And Symbolic Sink Proof

For every applicable sink, require both Triton taint and a symbolic AST dependency on named source variables. Constant error returns may be data-untainted, but their controlling predicate must be source-dependent and explicitly linked to the sink.

Unroll each sink AST. Simplify it with Triton. Prove raw and simplified AST equivalence by asking whether their bit-vector inequality is satisfiable. Save both AST files, lengths, variable IDs, and SHA-256 values.

## Branch Closure

For every path constraint, combine each candidate edge with the prior path prefix. Solve every edge. For a satisfiable unobserved edge, save the model and request an original-target trace for that input. An unsatisfiable edge is accepted only with predicate/prefix AST hashes and a successful solver result.

Repeat analysis as user-supplied traces arrive until every branch edge is observed or solver-proven infeasible. Solver-generated inputs are hypotheses until represented by an original-target trace.

## Required Reports

The generic replay report must be pintrace-triton-replay/1.1 and record strict configuration, counters, source variables, taint, sink ASTs, simplified ASTs, branch alternatives, models, exact replay results, and failure examples.

The per-function script must emit rva-recovery-triton-case/1.0 with:

- its own SHA-256;
- processed instruction count and exact-state assertions;
- each sink's concrete value, taint, symbolic variables, raw/simplified AST hashes, and equivalence result;
- each branch's predicate hashes, alternate satisfiability/model, and supplied target trace run ID when available;
- floating machine-state proof when floating instructions execute;
- zero unsupported state, resynchronization, and external provenance loss.
