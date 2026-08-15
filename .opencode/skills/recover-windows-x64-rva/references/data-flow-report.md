# Mandatory Trace-Only Semantic Analysis Report

Every trace-analysis attempt must produce exactly one professional Markdown report on disk, regardless of success. No separate C++, JSON, script, evidence map, or auxiliary report may be emitted.

## Mandatory Report Language

The report must be written in Simplified Chinese. Translate all titles, metadata labels, section headings, prose, table headings and descriptions, findings, blockers, validation notes, tool notes, data-flow diagrams, and explanatory C++ comments into Chinese.

Preserve exact technical identifiers where translation would reduce precision: paths, filenames, module names, hashes, RVA/VA values, registers, assembly text, API/tool names, code identifiers, formulas, and canonical enums such as `complete`, `partial`, `blocked`, `no-signal`, `verified`, and `derived_exact`. These identifiers do not make an otherwise Chinese report non-compliant. English narrative text does.

Recommended filename:

```text
<trace-family-or-module>.<start-rva>_<stop-rva>.data_flow_report.md
```

## Required Header

```markdown
# <目标> 纯 Trace 语义分析报告

- 分析结果：complete | partial | blocked | no-signal
- 结论范围：已观测路径 | trace 族 | 分段的已观测路径
- 主要证据：仅使用所提供的 trace 文本
- 分析工具：解析器 / 基于 trace 字节的 Capstone / 基于 trace 路径的 Triton / 基于 trace 字节的 angr VEX / 不可用
- 明确排除的证据：二进制、IDA/MCP、源码、PDB、既有恢复产物、外部样例输入输出
```

## Required Sections

### 1. 执行摘要

State what was requested, what was recovered, the strongest trace-supported input-to-output relation, and the most important limitation.

### 2. Trace 完整性与范围

For every supplied trace include:

- path;
- SHA-256;
- line count;
- module name, module base when derivable, start RVA, inclusive stop RVA;
- first and last relevant rows;
- capture metadata embedded in the trace, with unavailable fields marked `unknown`.

Explicitly state that neighboring binaries, source, IDA databases, previous reports, and external samples were not read.

### 3. 分析契约

Define from trace evidence:

- input source registers or memory ranges;
- input length and observed values when recoverable;
- output stores, return registers, compare operands, or emitted buffers;
- requested and observed RVA scope;
- completion criteria.

If no source or sink can be established, explain the searched evidence and classify `blocked` or `no-signal`.

### 4. Trace 与路径清单

Include relevant calls, returns, loops, external transfers, branch edges, controlling predicates, per-trace path differences, and unobserved edges.

### 5. 内存值恢复

Follow `derived-memory-recovery.md`. Include:

- a method table with representative rows, RVAs, effective addresses, widths, equations, values, and confidence;
- counts for direct loads, direct stores, invertible ALU recovery, propagation/copies, constraints, unknowns, and in-slice unknowns;
- byte ranges or objects reconstructed;
- SIMD copy and implicit-stack treatment;
- independent cross-check pass/fail totals.

Do not state only that memory values are missing. Name the exact operand and explain why all trace-only recovery methods fail to determine it uniquely.

### 6. 源到汇数据流

Show the minimal chain, for example:

```text
输入字节
 -> 规范化缓冲区
 -> 混合字
 -> 状态/密钥调度
 -> 比较累加器
 -> 路径谓词
 -> 输出 store 与返回值
```

For each stage list key RVAs, variables, constants, and claim level.

### 7. 必需的工具辅助分析

Report availability and version for Capstone, Triton, and angr. Every detected tool must have an actual trace-only analysis entry:

```text
工具 | 版本 | 使用的 trace 记录/RVA/字节 | 操作 | 结果 | 不一致/限制
```

Required when detected:

- Capstone: decode ambiguous or representative memory/SIMD/implicit-stack instructions from trace bytes.
- Triton: replay the selected slice, symbolize trace inputs, extract sink AST/taint dependencies, and compare concrete replay state with trace rows.
- angr: lift trace-reconstructed block bytes to VEX and perform a structural dependency, reaching-definition, block-effect, or path-predicate check relevant to the sink.

If a detected tool fails, include the attempted trace input, exception/failure point, affected claim, and fallback. A version/import check alone does not count as use.

### 8. 归约后的 C++ 语义

This section is mandatory for every outcome. Put the recovered semantics directly in fenced C++ code blocks inside the report. Do not create a separate `.cpp` file.

Requirements:

- Reduce the trace to readable semantic operations; do not dump millions of instructions.
- Preserve exact bit widths, wraparound, rotations, signedness, byte order, and path predicates.
- Every important input read, output write, assignment, table access, loop, branch, call boundary, and formula hole must have an adjacent comment containing the corresponding trace RVA and concise assembly or role.
- When one statement combines several instructions, list the RVA span and the key instruction sequence.
- When behavior differs by trace path, use explicit `if`/`switch` branches and identify the controlling branch RVA.
- Unknown in-slice behavior must be represented by a named function or expression hole, never an empty unexplained block.
- A formula hole comment must state the exact blocking RVA, missing trace state, affected outputs, and observed test-vector value when available.
- If analysis is `blocked` or `no-signal`, include the smallest honest C++ skeleton showing the established ABI/source/sink boundary and named unknowns.

Required comment style:

```cpp
// Trace RVA 0x4778：mov al, byte ptr [r9 + rdx] - 读取源字节。
std::uint8_t byte = input[index];

// Trace RVA 0x2a4e：xor r8d, dword ptr [rsi + r9*4 + 0x1c]。
// 派生精确：mixed_word = r8d_before ^ r8d_after。
accumulator ^= key.mixed_words[word_index];

// Trace RVA 0x3260：or edi, ecx - 累积不匹配位。
mismatch |= difference;

// 公式缺口，Trace RVA 0x3e5d..0x4014：
// 缺少可唯一恢复的索引字节；影响 compressed[2]。
state = unknown_vm_step(state, input, path_state);

// Trace RVA 0x32de：mov dword ptr [r12], r9d - 输出 sink。
*encoded_result = encoded;
```

The code must state its scope in a leading comment:

```cpp
// 范围：仅对所提供的已观测路径精确；未实现未观测边。
```

### 9. 表达式与路径谓词

After the C++ block, summarize source variables, sink variables, constants, simplified expressions, controlling RVAs, and named formula holes. Keep observed-path constants separate from general formulas.

### 10. 验证

Provide a table:

```text
trace | 观测输入 | 路径 | 观测 sink | C++/公式预测 | 结果
```

Validate every supplied trace. Include internal memory cross-checks, contradictions, and unexplained differences.

Also validate manual formulas against Triton replay and angr-lifted effects when those tools are detected. Trace observations remain authoritative when a tool model disagrees; document the disagreement.

### 11. 按结论级别分类的发现

Use separate flat lists:

- `Verified`
- `Derived exact`
- `Hypothesis`
- `Unknown`
- `Contradiction`

Do not merge these categories.

### 12. 阻塞项与所需的最小后续 Trace 证据

For every unresolved in-slice dependency specify:

- exact trace RVA, variable, address, and affected sink;
- why current rows are insufficient;
- trace-only recovery already attempted;
- smallest additional trace path, register observation, memory-defining row, or branch sample needed.

Do not request a binary or static-analysis artifact.

### 13. 可复现性

Document trace hashes, parsing rules, equations, Capstone/Triton/angr versions and trace-only operations, source/sink definitions, and validation procedure directly in the report. Do not create a separate script or manifest.

## Outcome-Specific Requirements

### Complete

Include a closed observed-path C++ relation, validation for all traces, and zero unresolved in-slice dependencies.

### Partial

Include useful reduced C++, every named formula hole with RVA, the recovered prefix/suffix, and affected outputs.

### Blocked

Still include trace hashes, parsing results, attempted memory recovery, exact failure row, a minimal C++ boundary skeleton, and minimum next trace evidence.

### No-Signal

Show that the requested source/sink/module/RVA was searched, include a minimal C++ interface with named unknown source/sink, and state the corrected trace boundary or trigger needed.

## Final Quality Gate

Before finishing, verify:

- exactly one persistent artifact was created: this Markdown report;
- outcome and observed-path scope are explicit;
- every input/output claim cites trace RVA evidence;
- memory recovery metrics and equations are present;
- the report contains reduced C++ with adjacent trace-RVA comments;
- formula holes identify blocking RVAs and affected sinks;
- all traces are validated;
- every detected Capstone/Triton/angr tool was actually used on trace-derived bytes/state and documented, or has a documented failed attempt;
- claim levels remain separate;
- no binary/static/previous-recovery evidence was used;
- all narrative text, headings, table labels, data-flow diagrams, findings, blockers, validation/tool notes, and explanatory C++ comments are in Simplified Chinese;
- no separate C++, JSON, script, AST export, or evidence map was emitted;
- the final chat response links this report and does not overclaim beyond it.
