# Trace Recovery Workflow

## Analysis Order

1. Hash the raw trace file.
2. Parse rows into module, RVA, VA, bytes, instruction text, memory effective addresses, register tokens, post-register changes, and external target hints.
3. Confirm the first and last rows against the requested start/stop semantics when metadata is available.
4. Build a dynamic path digest: unique instructions, branches, calls, returns, external targets, memory address touches, and register observations.
5. Recover the entry ABI from caller setup and the first rows when available.
6. Follow observed direct calls, resolved indirect calls, tail jumps, helper chunks, and returns that materially affect the recovered behavior.
7. Slice backward from visible sinks using registers, effective addresses, comparisons, calls, returns, and branch outcomes present in the trace.
8. Compare multiple traces when available before naming input-dependent behavior.
9. Emit C++ with an evidence map and explicit `unknown` gaps.

## Branch Manifest

For every executed conditional branch that affects recovered logic, record:

- branch RVA;
- observed condition instruction text;
- taken and fallthrough targets when inferable from adjacent rows;
- controlling registers or memory effective addresses;
- traces covering each edge;
- observable effect of the edge.

Uncovered edges become `unknown` items rather than guessed verified behavior.
