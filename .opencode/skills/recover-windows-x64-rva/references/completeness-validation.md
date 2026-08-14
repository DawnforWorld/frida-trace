# Completeness And Behavioral Equivalence

## Define The Claim Domain

Perfect recovery from finitely many traces is impossible for an unrestricted program. State the input domain, reachable machine state, callback/external contract, thread model, and environment assumptions. A complete claim is valid only for that declared domain.

Use exhaustive execution for a finite tractable domain. For a larger or infinite domain, partition it by every recovered path predicate, prove bounded-loop invariants and external models, and use solver equivalence for each partition. Fuzzing and random differential tests are falsification tools, not universal proofs.

## Branch And Exit Closure

Inventory static conditional instructions plus dynamic/synthetic predicates introduced by indirect control flow. For each branch record both edges as:

- observed, with target run IDs; or
- infeasible, with a Triton predicate, prior-path constraint, unsatisfiable result, and AST hash.

Cover every return, validation error, allocation failure, callback failure, loop zero/one/exhaustion path, numeric exceptional case, crash/exception, and output-sentinel behavior. Any unknown blocks a complete claim.

## Evidence-Backed C++ Gate

Do not require compiling the recovered C++ artifact. Validate it by mapping source statements back to original-target evidence:

- every emitted branch maps to a branch manifest item plus a Triton path predicate;
- every emitted store, return, callback, error, exception, or formula maps to a sink, trace run, focused replay, taint/slice report, and AST or concrete-value evidence;
- every `unknown` item remains abstract and must not publish guessed constants or representative behavior;
- every solver-generated input is represented by a user-supplied original-target trace before it is promoted from hypothesis to evidence.

Use `claim=trunk` for a useful key-algorithm artifact with explicit gaps. Use `claim=complete` only when every domain below is closed or solver-proven infeasible.

## No Candidate Compilation

Candidate compilation, candidate binaries, target-vs-candidate differential execution, and mutation tests are outside this skill's recovery gate. Do not look for a C/C++ compiler and do not use compiled-candidate behavior as proof. If the user asks for compilation later, run it as a separate engineering task and keep any failures as hypotheses that require original-target trace/Triton evidence before changing recovered semantics.

## Staging And Publication

Recovered C++ may exist in a staging directory as soon as the main trunk has evidence. Publish it as `trunk` only with a gap list and `verified/inferred/unknown` manifest. Publish it as `complete` only after the recovery gate passes with no unknown branch, sink, failure, exception, or machine-state item.
