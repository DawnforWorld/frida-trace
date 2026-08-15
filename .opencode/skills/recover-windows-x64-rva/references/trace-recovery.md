# Trace Recovery Workflow

## Analysis Order

1. Hash the raw trace file.
2. Parse rows into module, RVA, VA, bytes, instruction text, memory effective addresses, register tokens, post-register changes, and external target hints.
3. Confirm the first and last rows against the requested start/stop semantics when metadata is available.
4. Build a dynamic path digest: unique instructions, branches, calls, returns, external targets, memory address touches, and register observations.
5. Recover the entry ABI from caller setup and the first trace rows when available.
6. Follow observed direct calls, resolved indirect calls, tail jumps, helper chunks, and returns that materially affect the recovered behavior.
7. Slice backward from visible sinks using registers, effective addresses, comparisons, calls, returns, and branch outcomes present in the trace.
8. Compare multiple traces when available before naming input-dependent behavior.
9. Recover memory values from trace instruction semantics and register pre/post state before declaring gaps.
10. Detect Capstone, Triton, and angr. Every detected tool must be used on trace-row bytes/state: Capstone decoding, Triton replay/taint/AST, and angr VEX/dependency analysis. Document concrete failed attempts when trace state is insufficient.
11. Write one Simplified Chinese Markdown semantic-analysis report containing tool results and reduced C++ code blocks with Chinese explanatory trace-RVA comments and explicit `unknown` gaps. Preserve exact technical identifiers and canonical enums, but do not leave English narrative text in the report. Do not emit separate C++ or auxiliary artifacts.

## Branch Manifest

For every executed conditional branch that affects recovered logic, record:

- branch RVA;
- observed condition instruction text;
- taken and fallthrough targets when inferable from adjacent rows;
- controlling registers or memory effective addresses;
- traces covering each edge;
- observable effect of the edge.

Uncovered edges become `unknown` items rather than guessed verified behavior.
