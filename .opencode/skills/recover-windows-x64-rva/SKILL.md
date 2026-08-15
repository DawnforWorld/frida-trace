---
name: recover-windows-x64-rva
description: "Analyze authorized Windows x64 frida-instr-trace text files only: recover memory values from instruction/register pre-post state, identify sources and sinks, backward-slice data flow, and use detected Capstone/Triton/angr tooling only on bytes contained in the trace. Use when native\\veh-injector or frida-rva-trace text traces are supplied. The only persistent output is one professional Simplified Chinese Markdown data-flow report, including partial, blocked, and no-signal outcomes."
---

# Trace-Only Windows x64 Data-Flow Report

Analyze supplied `frida-instr-trace` text files as the sole analysis input. Recover the narrowest trace-supported relation between observed input sources and output sinks. The goal is a professional data-flow report, not source reconstruction or binary decompilation.

## Strict Input Boundary

Accepted analysis input:

- UTF-8 unidbg `AssemblyCodeDumper`-style text emitted by `native\veh-injector` / `frida-rva-trace`.
- Multiple files from the same trace family.
- Capture metadata only when it is embedded in the trace text or encoded in the supplied trace filename/path; otherwise mark it `unknown`.

Forbidden analysis input:

- PE/ELF/Mach-O binaries, DLLs, firmware, memory dumps, source code, PDB/debug symbols, disassembler databases, or decompiler output.
- IDA/Ghidra/Binary Ninja/radare2 MCP analysis, binary bytes read outside trace rows, or static tables recovered from a binary.
- Existing recovered C++/JSON/Markdown artifacts, previous hypotheses, challenge writeups, known flags, or external sample I/O not present in the trace.
- Internet searches or third-party descriptions of the target.

If forbidden artifacts exist in the workspace or are supplied alongside traces, do not inspect them. State in the report that they were intentionally excluded by the trace-only contract.

The trace's instruction bytes, decoded instruction text, effective addresses, register tokens, post-register changes, external target hints, and observed control-flow sequence are the complete evidence domain.

## Strict Output Boundary

The only persistent artifact this skill may create is one Markdown report:

```text
<trace-family-or-module>.<start-rva>_<stop-rva>.data_flow_report.md
```

Do not create or modify:

- C/C++ source files;
- JSON manifests or evidence maps;
- replay, parser, or extraction scripts in the workspace;
- AST exports, CSV files, databases, patched traces, IDB comments, or auxiliary reports.

Temporary in-memory computation or temporary files outside the workspace may be used when required by a tool, but they are not deliverables. The final response should link the single report and summarize its outcome without duplicating the full report.

## Mandatory Report Language

The Markdown report must be written in Simplified Chinese. This requirement applies to the title, metadata labels, section headings, prose, table headings and descriptions, findings, blockers, validation notes, tool-use notes, and explanatory C++ comments.

Keep exact technical evidence unchanged where translation would reduce precision: file and module names, paths, hashes, RVAs/VAs, register names, instruction text, API/tool names, code identifiers, formulas, and the canonical outcome/claim enums such as `partial` and `derived_exact`. Surrounding explanations and labels must still be Chinese. Do not leave English narrative paragraphs, English section titles, or English data-flow diagrams in the deliverable.

## Required References

Read before analysis:

- [Trace Format](references/frida-instr-trace.md)
- [RVA Boundaries](references/rva-boundaries.md)
- [Recovery Workflow](references/trace-recovery.md)
- [Derived Memory Recovery](references/derived-memory-recovery.md)
- [Data-Flow Report](references/data-flow-report.md)

## Evidence Rules

- Hash every supplied trace before analysis and include its SHA-256 and line count in the report.
- Use bracketed module RVA as the selected-module offset. Treat runtime VAs as ASLR-dependent.
- Mark unavailable metadata as `unknown`; never infer capture settings without evidence.
- Keep trace observations, exact algebraic derivations, hypotheses, unknowns, and contradictions separate.
- Do not hard-code one observed value as a general algorithm. Scope every formula to its observed path or trace family.
- Missing post-register tokens do not prove unchanged state.
- External target names are control-transfer hints, not API argument or return-value logs.
- A formula is closed only when every in-slice register, memory byte, table value, and path predicate is trace-observed or exactly derived from trace evidence.

Claim levels:

- `verified`: directly present in trace rows.
- `derived_exact`: uniquely solved from trace instruction semantics, register pre/post state, byte-level propagation, or deterministic trace replay; include equation and rows.
- `hypothesis`: plausible but depends on an unobserved value, branch, state, or non-unique inference.
- `unknown`: no unique value or dependency can be established.
- `contradiction`: supplied traces disagree; preserve both observations.

## Memory-Value Recovery

Memory entries print effective address and size, but many values are exactly recoverable. Follow [Derived Memory Recovery](references/derived-memory-recovery.md) before declaring a gap.

At minimum handle:

- direct loads from destination post-state;
- direct stores from source pre-state or immediates;
- invertible `xor/add/sub` memory operands from destination pre/post state;
- uniquely invertible multiplication at the correct bit width;
- read-modify-write memory using a byte-addressed little-endian ledger;
- prior-store/later-load propagation with overlap invalidation;
- scalar-defined SIMD copy chains;
- implicit `push/pop/call/ret` stack effects;
- branch and `setcc` constraints from `cmp/test` without overclaiming complete values.

Every recovered value recorded in the report must include method, trace row, RVA, address, size, equation, confidence, and cross-check when available.

Report coverage counts for total memory operands, each exact recovery class, constraint-only values, unknown values, unknown values in the final slice, and cross-check pass/fail totals.

## Trace-Only Tool Policy

Allowed:

- text parsing, hashing, indexing, and arithmetic over trace rows;
- Capstone decoding of instruction bytes embedded in trace rows;
- Triton concrete/symbolic execution using only the executed instruction bytes, order, register observations, and memory values present in or derived from the trace;
- angr/pyvex lifting, block modeling, reaching-definition analysis, and dependency checks using only instruction bytes and executed block order reconstructed from trace rows; create shellcode/blob projects in memory or temporary storage only, never a project from the target binary;
- standard bit-vector or SMT simplification over expressions derived only from trace evidence.

Forbidden:

- IDA or any disassembler MCP;
- angr project/CFG creation from a target binary or any code/data source outside trace rows;
- reading target binary sections, imports, tables, or code not present in trace rows;
- using static decompilation to fill trace gaps.

At the start of analysis, detect whether Capstone, Triton, and angr are available and record versions or import errors. Tool use is mandatory when detected:

- If Capstone is available, decode representative and ambiguous trace instruction bytes, especially memory direction/width, implicit stack operands, and SIMD copies.
- If Triton is available, perform concrete replay on the selected source-to-sink slice, symbolize trace-identified inputs, extract sink ASTs or taint dependencies, and compare replayed concrete state with trace observations.
- If angr is available, lift trace-reconstructed blocks to VEX and use at least one structural analysis relevant to the slice, such as block effects, reaching definitions, dependency confirmation, or path-predicate support.

Do not claim tool use merely because an import succeeded. The report must state the exact trace rows/bytes supplied to each tool, analysis performed, result, mismatches, and limitations. If a detected tool cannot process the trace because rows or state are insufficient, make a concrete attempt and document the failure point; do not silently skip it. Seed only trace-identified source bytes or registers. Tool failure never cancels report generation.

## Workflow

1. Discover only the supplied trace files; do not inspect neighboring target artifacts.
2. Hash traces and stream-index module, RVA, VA, bytes, instruction, memory operands, register pre/post tokens, and external hints.
3. Cluster traces by module, RVA interval, path shape, and observed source/sink shape.
4. Establish an explicit input/output contract from trace evidence. If impossible, classify `blocked` or `no-signal` and continue to report generation.
5. Build source, sink, call, return, branch, and loop manifests.
6. Build the byte-addressed derived-memory ledger and coverage statistics.
7. Backward-slice each sink to candidate sources, retaining data definitions, address calculations, path predicates, table indices, loop counters, and relevant calls.
8. Separate unknown memory outside the slice from unknown memory that blocks the slice.
9. Compare traces to identify invariant logic, path-specific terms, and contradictions.
10. Detect Capstone, Triton, and angr. Use every detected tool under the trace-only policy and capture versions, inputs, results, mismatches, and limitations for the report.
11. Use Triton sink AST/taint results and angr VEX/dependency results to refine or challenge the manual slice; trace rows remain authoritative.
12. Express recovered semantics directly inside the Markdown report using formulas, tables, and a mandatory fenced C++ section. Every important C++ statement must have an adjacent trace-RVA comment. Do not create a separate source file.
13. Validate every candidate relation against every supplied trace and against detected-tool replay/lift results.
14. Write exactly one professional Simplified Chinese Markdown report, regardless of outcome.
15. Run the report quality gate before responding.

## Mandatory Outcome Report

Every analysis must finish with one on-disk Markdown report. Valid outcomes:

- `complete`: the selected observed path has a closed source-to-sink relation and no unresolved in-slice dependency.
- `partial`: useful data flow was recovered, but one or more named in-slice terms remain unresolved.
- `blocked`: parsing, evidence, or required trace state prevents meaningful recovery.
- `no-signal`: requested module, RVA, source, sink, or dependency is absent from the trace.

Use [Data-Flow Report](references/data-flow-report.md) exactly. The report must include:

- outcome and claim scope;
- trace paths, hashes, line counts, module/base/RVA metadata;
- input/output contract;
- path, branch, call, source, and sink inventory;
- memory-recovery methods, equations, coverage, cross-checks, and in-slice unknowns;
- minimal source-to-sink chain;
- Capstone/Triton/angr availability, versions, exact trace-only use, outputs, mismatches, and limitations;
- formulas, predicates, constants, and mandatory reduced C++ with adjacent trace-RVA comments for inputs, assignments, loops, branches, table accesses, calls, formula holes, and sinks;
- per-trace validation and contradictions;
- separate verified, derived-exact, hypothesis, unknown, and contradiction findings;
- blockers and the minimum additional trace evidence required;
- reproducibility details that do not create another persistent artifact.
- Simplified Chinese presentation throughout, while preserving exact technical identifiers and canonical enums.

Failure is not permission to omit the report. A blocked or no-signal report must show what was searched, what was attempted, the exact evidence boundary, and the smallest corrected capture or additional trace needed.

## Final Quality Gate

Before concluding, verify:

- exactly one new persistent analysis artifact exists: the Markdown report;
- the report is linked in the final response;
- all evidence comes from supplied trace text;
- no binary, IDA/MCP, source, previous recovery, or external I/O was used;
- memory recovery statistics and representative equations are present;
- the report contains reduced C++ and every important statement cites its trace RVA;
- every supplied trace appears in validation;
- every detected Capstone/Triton/angr tool was actually used and documented, or has a documented concrete failure attempt;
- every in-slice unknown has a named blocker and minimum-next-trace requirement;
- claims do not exceed observed path coverage;
- report prose, headings, tables, findings, blockers, validation notes, tool notes, data-flow diagrams, and explanatory C++ comments are in Simplified Chinese;
- no separate C++, JSON, script, or evidence-map artifact was emitted.
