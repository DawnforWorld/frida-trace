# RVA Boundary Reference

## Boundary Semantics

`start_rva` activates tracing only when that exact selected-module instruction executes. The selected module is the main executable by default, or the module named by the trace tool's module selector. `end_rva` is inclusive and stops tracing only when that exact instruction executes.

Choose a start before argument preparation and an end after the call/result transfer when recovering one call. For a whole local function, use an entry instruction and a return-path instruction known to execute for the chosen input. If a function has multiple returns, request separate upstream traces or choose a reachable caller instruction after the function returns.

RVA is `runtime_address - selected_module_base`. Never store an ASLR-dependent VA as a trace boundary. For DLL targets, record both the process executable and the selected DLL path/name/hash when available. If the DLL is delay-loaded, the upstream tracer must wait for its image-load event before resolving `base + RVA`; a run where the module never loads is a valid negative capture, not evidence about the function body.

## Trace Request Shape

When a boundary is missing or wrong, request a new upstream trace rather than creating or running a capture case yourself. Include:

- target/module path and hash when known;
- selected module name, `start_rva`, and inclusive `end_rva`;
- exact arguments, stdin transcript, file inputs, or environment needed to reach the interval;
- required trace family: `frida-instr-trace` text, bundled `pintrace-jsonl/2.0`, `intel-pin` binary pair, or `intel-pin` unidbg text;
- required evidence fields, such as scalar pre/post registers, instruction bytes, memory values, or external-call records.

For example, request: bundled JSONL for `target.exe`, selected main module, `start_rva=0x1400`, `end_rva=0x1488`, args `--mode test`, external calls enabled, and at least 128 bytes per memory operand.

## Protected/Twin Cases

The protected program's supplied traces may include IMAGE_LOAD/BEFORE_EXIT snapshots. A twin may supply semantic trace evidence only after the provenance gate proves that it existed independently of the recovery and is equivalent for the selected ABI/behavior scope. A candidate-built twin is forbidden. Runtime-vs-twin differences remain unresolved evidence until protected-target observations validate every recovered sink and branch.

## Important Fields

| Field | Meaning |
|---|---|
| arguments/transcript | Inputs needed to reach the interval; keep menu transcripts atomic. |
| selected module | DLL or non-main module name; RVAs are relative to this module and tracing starts only after it is loaded. |
| dependency list | DLL/data dependencies that upstream capture must place beside the target. |
| repeat request | Capture multiple start/end intervals rather than only the first, when loop behavior matters. |
| timeout | Target timeout used by upstream capture. |
| minimum instructions | Nonempty-trace gate for the requested interval. |
| memory byte limit | Requested memory bytes per operand, usually 64 first and up to 256 for memory-heavy sinks. |

Prefer structured manifests for complex quoting or transcripts so later analysis can tie each trace to exact inputs.

## Multi-Trace Runs

Use consistent names for each supplied run. Each named run should identify arguments/transcript, target hash, output paths, boundary, and capture limits. Evidence rules may select a run with `trace: mutation` or an equivalent run ID.

Keep the same boundary and executable hash when comparing input mutations. If the path no longer reaches the end RVA, record that as path-dependent behavior rather than forcing PASS.
