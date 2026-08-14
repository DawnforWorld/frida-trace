# Triton Capability Map And Mandatory Routing

## Official Scope

Authoritative sources checked for this skill:

- https://triton-library.github.io/
- https://triton-library.github.io/documentation/doxygen/
- https://triton-library.github.io/documentation/doxygen/py_TritonContext_page.html
- https://triton-library.github.io/documentation/doxygen/py_AstContext_page.html

The official site describes Triton as a dynamic binary analysis library with dynamic symbolic execution, dynamic taint analysis, ISA-semantic ASTs, expression synthesis, SMT simplification, LLVM/Z3 lifting, Z3/Bitwuzla solver interfaces, and C++/Python APIs. It lists x86, x86-64, ARM32, AArch64, and RISC-V 32/64 semantics.

The site also discusses snapshot and corpus-scheduling components in its Pin-era/framework and TritonDSE material. The locked core Python binding exposes no standalone snapshot or corpus scheduler object. This workflow therefore captures hash-bound machine snapshots in the tracer, restores them through Triton's concrete-state APIs, and implements the coverage queue in the case analyzer. Do not mislabel either upper layer as a `TritonContext` method.

The installed locked binding is the operational authority. Run scripts/audit_triton_capabilities.py and retain its report. It records the official feature inventory, enumerates every callable TritonContext/AstContext method (including explicitly unrouted methods), supported architectures, solvers, modes, callbacks, API counts, and the binding-file SHA-256. Missing a required capability blocks recovery.

The binding's x64 instruction table currently returns `FAULT_UD` for scalar `ADDSD`, `SUBSD`, `MULSD`, `DIVSD`, `CVTDQ2PD`, and `COMISD`. The audited `runtime/replay/sse2_ieee.py` adapter is the only route for these instructions. It is a semantic extension around Triton, not a concrete overwrite: Z3 IEEE-754 operations under the recorded MXCSR mode calculate exact result bits, exception flags are checked against the trace, and a hash-bound Z3 FPA formula is retained beside the Triton symbolic carrier. Branch solving must use the shadow FPA predicate and produce a missing-trace request for any satisfiable unobserved model.

## Capability Routing

| Capability | Core APIs | Required recovery use |
|---|---|---|
| Architecture/disassembly | setArchitecture, disassembly, getAllRegisters | Decode exact bytes and establish the machine-state contract. |
| Concrete emulation | processing/buildSemantics, concrete register/memory APIs | Replay every instruction and assert PC/write/state agreement. |
| Dynamic symbolic execution | symbolizeMemory/Register, symbolic expressions, register/memory ASTs | Build source-to-sink formulas from actual instruction semantics. |
| Path exploration/coverage | getPathConstraints, getPathPredicate, getPredicatesToReachAddress, push/pop | Negate frontier edges, solve models, request upstream traces for satisfiable models, and close coverage when those traces are supplied. |
| Dynamic taint analysis | taintMemory/Register, taintAssignment/Union, taint queries | Track data and pointer influence from ABI sources to sinks. |
| Backward slicing | sliceExpressions | Recover the symbolic-expression dependency slice for every sink. |
| AST representation/transforms | getAstContext, unroll, duplicate, search, Z3 bridge | Normalize, inspect, hash, and cross-check sink/path formulas. |
| SMT simplification | simplify with solver padding; optional LLVM pass | Reduce formulas and prove simplified/raw equivalence. |
| Solver/models | isSat, getModel(s), evaluateAstViaSolver, solver/time/memory controls | Prove infeasible edges, generate inputs, enumerate diverse models, and enforce timeouts. |
| Expression synthesis | synthesize | Attempt concise semantics for MBA/handler formulas; validate synthesized AST equivalence before use. |
| Lifting/export | liftToSMT/Python/LLVM/Dot | Save independently inspectable formulas/graphs/IR for each verified sink. |
| Callbacks | add/remove/clearCallback | Supply audited lazy concrete state and symbolic simplification hooks; log each callback effect. |
| Analysis modes | setMode/isModeEnabled | Record exact optimization, symbolization, PC, memory, and taint-through-pointer policies. |
| Concretization control | concretize memory/register APIs | Allow only explicit modeled boundaries; every provenance loss is a blocker for completeness. |

Triton core exposes path predicates and models. A full corpus scheduler and target executor are an upper layer; the official site lists TritonDSE separately. This skill implements that layer in the case-specific analyzer rather than claiming processing() alone provides coverage.

## Mandatory Coverage Loop

For each seed target trace:

1. Replay it exactly and record its edge/path hash.
2. Enumerate path constraints in execution order.
3. Combine an alternate edge with the prior path prefix.
4. Use DTA and sliceExpressions to discard constraints unrelated to the selected source/sink only when control dependence proves that removal sound.
5. Solve the alternate with isSat/getModel; use getModels for diverse frontier inputs where aliases may hide classes.
6. Create an upstream trace request for each satisfiable model not already represented in the supplied trace set.
7. When a supplied model trace does not reach the intended edge, retain it as a solver/trace mismatch.
8. Add new edges/sinks as traces arrive and repeat analysis until every manifest edge is observed or unsatisfiable.

Report instruction, basic-block, edge, branch-edge, return, error-outcome, and sink coverage. A percentage alone is insufficient; the uncovered set must be empty for the declared complete domain.

## Mandatory DTA And Backward Slice

Taint proven ABI source bytes/registers and enable TAINT_THROUGH_POINTERS only when address influence is part of the claim. At each sink record tainted registers, memory, and symbolic expressions. Then call sliceExpressions on the sink SymbolicExpression.

Save:

- sink expression ID;
- all sliced expression IDs and origins;
- taint source IDs;
- concrete sequence/RVA mappings;
- controlling path constraints;
- slice hash and exported Dot graph.

Taint is an influence over-approximation and does not supply an exact formula. The symbolic slice and exact replay must agree with it.

## Simplification, Synthesis, And Lifting

For every symbolic sink and controlling predicate:

1. unroll the AST;
2. simplify with solver padding;
3. optionally run the LLVM simplifier and expression synthesizer for obfuscated/MBA formulas;
4. prove raw vs simplified/synthesized inequality unsatisfiable;
5. export SMT, Python, LLVM, and Dot when supported;
6. hash every export.

Never translate a simplified or synthesized expression into C++ before the equivalence query passes and original-target traces cover its path. If coverage is still missing, emit an `unknown` obligation instead of a guessed concrete expression.

## Case Capability Ledger

Every per-function case report must contain one entry for every capability group from the audit report. Mark it used with artifact/evidence paths, or not_applicable with a concrete scope reason. Concrete emulation, DSE, path exploration, DTA, backward slicing, AST, simplification, solver, and exact state control are always required. Synthesis/lifting/callback-specific mechanisms may be inapplicable, but omission without a ledger entry fails the gate.
