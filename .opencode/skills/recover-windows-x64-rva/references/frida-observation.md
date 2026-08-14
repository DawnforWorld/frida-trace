# Frida Observation Evidence

Use this reference when the user supplies Frida, Stalker, hardware-breakpoint, or debugger routing logs, or when the user explicitly asks for capture work. By default, initial runtime observation is upstream work; the AI consumes the resulting records and turns gaps into precise trace requests.

## Role In The Workflow

Frida-style records are optional routing and observation evidence. They are useful for:

- DLL or plugin module load timing before export/RVA selection;
- self-decrypting DLLs whose target RVA bytes are rewritten during `DllMain`;
- module base, export address, export RVA, thread ID, entry/leave timing, and normal vs exceptional return;
- function-level arguments, return channels, callback counts, callback argument order, and crash/exception hints;
- deciding which concrete inputs should be requested as Pin/debug traces and replayed by the AI.

Ordinary Frida hooks are not enough for final recovery evidence because they usually do not capture instruction bytes, reliable memory read/write versions, full flags, next PC for every instruction, or replayable concrete machine state. Treat ordinary hook output as `routing_evidence` unless a later supplied Pin/debug trace plus AI-run replay/proof closes the same sink, branch, or exception behavior.

`frida-instr-trace` is a special case: its Stalker output is an accepted instruction trace family when supplied as unidbg `AssemblyCodeDumper`-style text. Use [toolchain-usage.md](toolchain-usage.md) for its parser rules and evidence limits. It may support trace-backed hypotheses and path/branch/callee recovery, but claims requiring memory bytes, complete machine state, or strict Triton replay still need stronger supplied evidence.

## Analysis Order

1. Parse the supplied Frida/routing records.
2. Extract `module_name`, `module_base`, `export_va`, `export_rva`, enter/leave events, exception hints, callback order, and concrete inputs.
3. Convert useful observations into missing-trace queue entries with selected module/RVA and input requirements.
4. When a matching Pin/debug trace is supplied, replay the focused window with Triton when available before claiming recovered behavior.

## What Records Should Contain

Each Frida/routing record should include:

- process path, PID, target hash when available;
- module name, full path when available, base, size, and SHA-256 if the file exists;
- export name, VA, RVA, and hook installation time;
- enter/leave event, thread ID, elapsed time, integer argument registers, stack argument addresses if decoded, return register, and exception/detach state;
- callback order and callback argument bits when callback hooks are installed;
- whether XMM/floating arguments were captured reliably. If XMM values are null or missing, mark them `unknown`.

Never infer floating-point ABI behavior from missing Frida XMM fields. Require Pin extended registers, debugger state, or another supplied exact-state trace instead.

## Requesting Better Routing Evidence

For self-decrypting `DllMain` cases, ask upstream capture to avoid patching target bytes until runtime byte polling proves the code has stabilized. Prefer non-patching Stalker callouts, hardware breakpoints, or debugger traces for integrity-sensitive code.

For protected DLL routing evidence, request:

- first decrypted bytes at `base + start_rva`;
- the menu/prompt or transcript state that precedes the target path;
- callouts only for exact start/end RVAs, discovered callee entry, and return edge when possible;
- `callsite_rva` from the stack at callee entry when it proves `start_rva` returned to the inclusive `end_rva`.

Large full-module per-instruction Stalker logs are routing evidence only when no narrower option exists; prefer focused Pin/debug traces for final proof.
