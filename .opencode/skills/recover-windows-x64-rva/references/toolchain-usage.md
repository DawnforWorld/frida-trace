# Fixed Offline Toolchain Usage

Use this reference whenever the skill ingests trace files or runs offline analysis tools. Prefer package-relative paths; avoid hard-coded host paths. Do not run target capture tools, start Pin, attach Pin, or drive target execution unless the user explicitly asks for trace capture in the current request. Do run offline converters, validators, digesters, replay scripts, slicers, and artifact writers against supplied trace files when they help the analysis.

## Fixed paths

From the skill root:

| Component | Path | Role |
|---|---|---|
| Triton Python | `.runtime\triton-py314\Scripts\python.exe` | Run all Triton, validation, and packaging Python scripts. |
| Triton replay | `runtime\replay\triton_replay.py` | Replay `pintrace-jsonl/2.0` traces with concrete execution, taint, ASTs, and branch solving. |
| Pin runtime | `toolchain\pin\pin.exe` | Optional upstream capture tool; do not run by default during analysis. |
| Pin tracer | `toolchain\trace\MyPinTool.dll` | Optional upstream emitter for JSONL instruction trace and external-event logs. |
| Bundle check | `scripts\check_offline_bundle.py` | Verify fixed paths and Triton preflight. |
| Triton preflight | `scripts\check_triton.py` | Verify binary-analysis Triton, Z3, taint, solver, AST, and path APIs. |
| Capabilities audit | `scripts\audit_triton_capabilities.py` | Record installed Triton API/capability surface. |
| Gate validator | `scripts\validate_recovery_gate.py` | Validate recovery evidence manifest before strongest claims. |

Repository-copy note for `C:\project\frida-trace`: this checked-in skill copy intentionally omits generated `.runtime`, the full Pin SDK under `toolchain\pin`, `_toolchain_stage`, caches, logs, and backup DLLs. Treat missing components as unavailable instead of recapturing or failing the case setup. The native trace input for this repository is `frida-instr-trace` text produced by `native\veh-injector` / `frida-rva-trace`.

## Accepted Trace Inputs

The default analysis input is one of these user-supplied trace families:

| Family | Files | Use |
|---|---|---|
| Bundled JSONL | `trace.jsonl` plus optional `trace.external.jsonl` | Preferred when strict `pintrace-jsonl/2.0` replay and external-call events are needed. |
| `intel-pin` binary | `<prefix>.events.bin` plus `<prefix>.meta.bin` | Preferred for large traces; binary capture is authoritative for `UnidbgTrace` version 1. |
| `intel-pin` text | `<prefix>.txt` rendered by `trace_to_text.py` | Best-effort analysis format when binary files are unavailable. |
| `frida-instr-trace` text | UTF-8 trace text from `frida-rva-trace` / `native\veh-injector` | Native input for this workflow when the upstream capture is produced by `C:\project\frida-trace`. |

For all formats, hash the raw supplied files before analysis and record missing metadata as `unknown` or `hypothesis_blocker` instead of recapturing. The AI should do routine parsing and conversion itself; for example, render an `intel-pin` binary pair with `trace_to_text.py` for inspection while keeping the binary pair as the authoritative evidence.

## Bundled JSONL Trace

`pintrace-jsonl/2.0` is the bundled schema described by `toolchain\trace\TRACE_FORMAT.md`. It contains metadata records, instruction records, scalar and extended register state, memory before/after bytes when captured, flow records, and optional external-call JSONL.

Strict Triton replay currently expects this family. Metadata-only JSONL is not proof of behavior.

## Frida Instr Trace Text

`C:\project\frida-trace` produces UTF-8 unidbg `AssemblyCodeDumper`-style text. Treat it as an accepted instruction trace family named `frida-instr-trace`.

Lines are shaped like:

```text
[Test.vmp.exe                     0x0000000000001133] [488b4f08                      ] 0x0000000140001133: "mov rcx, qword ptr [rdi + 8]" (r 0x6d65f8 8) rdi=0x6d65f0 => rcx=0x6d6649 ; module.function
```

Field interpretation:

- The first bracket contains module name and module-relative RVA.
- The second bracket contains instruction bytes as hex.
- The absolute runtime VA follows the byte bracket.
- Quoted text is the decoded instruction.
- `(r address size)`, `(w address size)`, and `(rw address size)` describe memory effective addresses and sizes only.
- Register tokens before `=>` are read/pre-state values captured for the instruction.
- Register tokens after `=>` are observed post-state changes when available; absence does not prove unchanged state.
- A trailing `; module.function` names an external transfer target when the agent resolved one.

Compatibility rules:

- Hash the raw text and record the producing command, target/module identity, RVA window, trigger point, `--target-only`, and `--flush` when available.
- Use the bracketed module RVA as the selected-module offset. Treat the absolute VA as ASLR-dependent unless a module base is supplied or inferable from `VA - RVA` for that module in the same run.
- The format is replayable for path, instruction bytes, register read/write observations, effective memory addresses, and external target hints, but it is weaker than bundled JSONL for strict proof.
- It does not record memory bytes, full scalar pre-state for every register, extended registers, exact flags transitions, or separate external-call argument logs. Downgrade claims depending on those fields to `hypothesis` or request bundled JSONL/debug evidence.
- Strict Triton replay currently requires `pintrace-jsonl/2.0`; do not claim Triton-verified behavior from this text alone unless a separate converter/replay report supplies the missing concrete state.

## Intel-Pin UnidbgTrace

`C:\project\intel-pin` produces UnidbgTrace version 1 in two related forms.

Binary files:

- `<prefix>.events.bin` begins with magic `UTREVT1`, version `1`, then fixed-size event records.
- `<prefix>.meta.bin` begins with magic `UTRMET1`, version `1`, then lazy metadata records.
- Event records contain sequence, metadata ID, dynamic IP, owner thread ID, pre-instruction GPR/RFLAGS values, and up to four memory effective addresses.
- Metadata records contain metadata ID, IP, image base, read/write register masks, instruction bytes, module name, disassembly, and up to four memory operand descriptors.
- Event N+1 supplies post-register values for event N. The inclusive stop event has unavailable post-register values.

Rendered text from `trace_to_text.py` has lines shaped like:

```text
#0 | tid=1234 | module.dll+0x1133 | ip=0x7ff600001133 | bytes=488b4f08 | mov rcx, qword ptr [rdi+8] | read=[rdi=0x...] | write=[rcx=0x...] | mem=[r8@0x...]
```

Compatibility rules:

- Treat the binary pair as stronger evidence than rendered text because the binary preserves exact record structure.
- Use `module+offset` as the RVA when `imageBase` is present; use `<anonymous>@ip` only as runtime VA evidence.
- Use `read=[...]` and `write=[...]` masks to recover register dependencies. For binary traces, compute writes from the successor event registers.
- Memory evidence is weaker than bundled JSONL because UnidbgTrace records memory effective addresses and sizes, not memory before/after bytes.
- Extended state such as XMM, MXCSR, x87, and opmask is absent from first-version UnidbgTrace. Downgrade floating/SIMD-dependent claims unless another supplied trace records that state.
- External-call event logs are not part of UnidbgTrace version 1; infer calls from instruction flow and request bundled JSONL/external logs if exact API arguments or side effects are required.

## Pin Tracer Command

The commands below are documentation for the upstream capture workflow. The skill should not run them unless the user explicitly asks for trace capture.

Run from the case work directory:

```cmd
<skill>\toolchain\pin\pin.exe ^
  -t <skill>\toolchain\trace\MyPinTool.dll ^
  [-module plugin.dll] ^
  -start 0xSTART ^
  -end 0xEND ^
  -once 1 ^
  -maxmem 64 ^
  -external 1 ^
  -external-o trace.external.jsonl ^
  -o trace.jsonl ^
  -- target.exe [target args...]
```

For interactive console targets that must be fed after startup, launch the target separately with inherited pipes or a pseudo-console, then attach Pin to the live PID:

```cmd
<skill>\toolchain\pin\pin.exe ^
  -pid <target-pid> ^
  -t <skill>\toolchain\trace\MyPinTool.dll ^
  [-module plugin.dll] ^
  -start 0xSTART ^
  -end 0xEND ^
  -once 1 ^
  -external 1 ^
  -external-o trace.external.jsonl ^
  -o trace.jsonl
```

Use a full transcript, not stepwise typing, and include the final dismiss key when the target prints a pause prompt.

For DLLs whose `DllMain` performs the interaction during `LoadLibrary`, the host process remains inside `LoadLibrary` until the transcript exits the DLL. Drive stdin/stdout from the harness, not the shell. A valid transcript must include the menu selector, any payload lines, the DLL exit token, and any host pause-dismiss key.

Supported tracer switches used by this workflow:

| Switch | Meaning |
|---|---|
| `-module name.dll` | Select a DLL or non-main module; omit it to trace the main executable. |
| `-start 0xRVA` | Start tracing when selected module executes this RVA. |
| `-end 0xRVA` | Inclusive stop RVA. |
| `-once 1` | Stop after the first captured interval. |
| `-repeat 1` | Capture repeated intervals when supported by the bundled tracer. |
| `-maxmem N` | Capture up to N bytes per memory operand; use 64 first, 256 for memory-heavy sinks. |
| `-external 1` | Emit external call/return events when supported. |
| `-external-o path` | External-event JSONL path. |
| `-o path` | Main instruction JSONL path. |

Actual bundled tracer behavior:

- Treat main-module tracing as the default and DLL selected-module RVA tracing as supported by this bundle.
- If the DLL is delay-loaded, start the target first, wait for the loader condition in the CreateProcess harness, then attach Pin to the live PID with `-module`.
- If an attach run reports metadata plus `instructions: 0`, the trace started but the chosen RVA window never executed. Recheck the transcript and the module/RVA pair before suspecting the toolchain.
- If a self-decrypting DLL is mapped with zero/encrypted bytes and later rewrites the selected RVA in `DllMain`, a selected-DLL Pin run may stall or stay metadata-only even with the right transcript. Record first-seen and decrypted runtime bytes, then route through [self-decrypting-dllmain.md](self-decrypting-dllmain.md).
- Require trace schema `pintrace-jsonl/2.0` for strict Triton replay.

## Triton replay command

Use the packaged Python:

```cmd
<skill>\.runtime\triton-py314\Scripts\python.exe ^
  <skill>\runtime\replay\triton_replay.py ^
  trace.jsonl ^
  --image target.exe ^
  --output triton_report.json ^
  --strict ^
  --model-external ^
  --solve-branches ^
  --track-dataflow ^
  --ast-dir asts ^
  --source-register rcx:0xVALUE:name
```

Common source declarations:

| Option | Use |
|---|---|
| `--source-register reg:value:name` | Symbolize and taint an ABI register source. |
| `--source-memory address:hex:name` | Symbolize and taint ABI memory bytes. |
| `--input address:hex` | Override argv-style input discovery. |
| `--concrete-input` | Seed input concretely without symbolization. |
| `--goal seq:register:value` | Solve a post-instruction register goal. |
| `--memory-goal seq:address:size[:value]` | Solve a memory sink goal. |

Strict success requires:

- processed instruction count reaches the intended end;
- unsupported instructions are zero;
- PC/write/register/memory divergences are zero;
- memory drops are zero or explicitly accepted outside the claimed sink;
- branch solver failures are zero when `--solve-branches` is used;
- SSE2 floating events, if any, have exact result bits and MXCSR agreement.

## Validation commands

Preflight:

```cmd
<skill>\.runtime\triton-py314\Scripts\python.exe <skill>\scripts\check_triton.py
```

Offline bundle check:

```cmd
<skill>\.runtime\triton-py314\Scripts\python.exe <skill>\scripts\check_offline_bundle.py
```

Capability audit:

```cmd
<skill>\.runtime\triton-py314\Scripts\python.exe <skill>\scripts\audit_triton_capabilities.py --output triton-capabilities.json
```

Recovery gate:

```cmd
<skill>\.runtime\triton-py314\Scripts\python.exe <skill>\scripts\validate_recovery_gate.py recovery_gate.json --output recovery_gate.validation.json
```

Do not validate recovered C++ by looking for `cl.exe`, `clang++`, `g++`, or any other compiler. The recovery gate is evidence mapping plus Triton/debug trace proof, not candidate compilation.

## What is sample-specific

Never package these into the reusable toolchain by default:

- target binaries;
- runtime traces;
- trace logs and AST directories;
- cheap ABI probe source/exe;
- recovered candidate C++;
- source oracle or source-derived binaries.
