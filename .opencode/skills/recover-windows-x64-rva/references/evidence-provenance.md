# Evidence Provenance And Oracle Separation

## Admissible Semantic Sources

The supplied executable is the default semantic source. Record its SHA-256 before any experiment. A trace must identify the executable that produced it, its hash, arguments, input hashes, RVA interval, module base, tracer version, and capture time.

An independent twin is admissible only when all of these are documented:

- it existed before recovery began;
- it was not compiled from candidate or recovered code;
- its origin and hash are known;
- independent artifacts establish equivalence for the exact function/ABI scope;
- target observations still validate every recovered branch and sink.

A matching export name, RVA, disassembly shape, or a few equal outputs does not prove twin equivalence.

## Forbidden Circular Evidence

Never use any of the following as target truth:

- a C++ candidate written during recovery;
- an executable built from that candidate;
- a hand-written semantic twin based on the current hypothesis;
- test vectors generated only by the candidate;
- a decompiler output treated as executable truth;
- source code revealed for grading before the candidate is frozen.

Candidate artifacts must have hashes disjoint from all semantic-source hashes. Differential tests execute the target and candidate as separate subjects; the candidate never supplies expected values.

## Sealed Source Oracle

When source exists only for evaluating the skill, keep it sealed. Freeze the candidate C++, build flags, executable hash, tests, recovery manifest, and evidence hashes first. Only then may the source be revealed for post-recovery scoring. Oracle differences are lessons for the workflow, not retroactive trace evidence.

## Meaning Of PASS

An evidence-engine PASS proves only the checks named in that evidence file, such as schema, boundaries, sequence continuity, or artifact hashes. It does not prove:

- target/twin semantic equivalence;
- branch completeness;
- absence of unobserved error behavior;
- correct source-level types or names;
- candidate equivalence.

Those are separate proof obligations in the recovery gate.
