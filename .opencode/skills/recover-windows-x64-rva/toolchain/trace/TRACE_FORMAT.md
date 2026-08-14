# PinTrace JSONL 2.0

`MyPinTool` currently supports Windows x64 targets only. It emits one JSON
object per line. The schema identifier is
`pintrace-jsonl/2.0`; `pintrace-jsonl-2.0.schema.json` describes each record.
JSONL is intentionally used for both files and byte streams so an offline
replayer and a live IPC consumer receive the same records.

Version 2.0 is the only accepted recovery format. Recapture older traces. This
keeps strict replay fail-closed and prevents optional state from being mistaken
for complete machine-state evidence.

## Record order

1. One `metadata` record is written after the main image is loaded.
2. Zero or more `instruction` records follow.
3. One `summary` record is written at normal Pin shutdown.

`seq` is the serialized process-wide event order. `thread_seq` is the order for
one Pin thread. A trace without a `summary` record is incomplete, usually due
to termination or an output transport failure.

## Address and byte conventions

- All addresses and RVAs are lowercase, zero-padded, 64-bit hexadecimal
  strings. Keeping addresses as strings avoids JSON number precision loss.
- `addr` and `flow.next` are runtime virtual addresses.
- `rva`, `flow.next_rva`, and the selection values are relative to the selected
  target module base. By default the target module is the main executable; with
  `-module name.dll`, it is the first loaded module whose basename or full path
  matches that value. Use RVAs when comparing ASLR-enabled runs.
- Byte strings are lowercase hexadecimal in increasing-address order. For
  example, bytes at addresses `p..p+3` containing `78 56 34 12` are written as
  `78563412`. Consumers may interpret that byte array as little-endian when an
  instruction loads it as an integer.
- Instruction `bytes` are the bytes decoded by Pin. `size` is the decoded
  instruction length.

## Metadata

- `module.base` and `module.high` define the inclusive selected-module range
  used by this tracer. `module.target_is_main_executable=false` means the trace
  is for a DLL or other non-main image.
- `selection.requested_module` is the `-module` knob value. An empty string
  means the main executable. `selection.resolved_module` is the basename that
  was actually loaded and selected.
- `selection.start_rva=0` means tracing begins at the first executed
  selected-module instruction on a thread.
- `selection.end_rva=0` means tracing continues until process exit.
- With `selection.once=true`, a thread does not begin a second interval after
  it reaches `end_rva`.
- `capture` states the timing and byte ordering used by instruction records.

## Instruction state

`mnemonic` and `category` are Pin/XED instruction classification strings. They
are meant for filtering and triage; `bytes` and `disasm` remain the replay
source of truth.

`regs` is the complete scalar register state immediately before the
instruction. It includes the 16 x86-64 general-purpose registers, `rflags`, and
the FS/GS bases.

`extended_regs` is always emitted. It
contains `xmm.xmm0` through `xmm.xmm15` as 16-byte increasing-address hex
strings plus `mxcsr` as a 64-bit hex string. This state is mandatory evidence
for strict Triton replay of SSE/SSE2 floating-point intervals. x87 and opmask
registers are still not captured in this tracer; a replayer must reject an
interval that depends on unmodelled x87/opmask state unless it obtains that
state elsewhere.

Instruction records always contain `post_regs`, the scalar register state at
Pin's post-instruction point when Pin provides one; otherwise it is `null`.

`post_extended_regs` is always present and contains post-instruction XMM/MXCSR
state when Pin provides post-state; otherwise the field is `null`.

`rflags_semantics` is mandatory on every instruction. Its XED-derived
`read_mask`, `written_mask`, and `undefined_mask` are architectural RFLAGS bit
masks. Strict replay propagates undefined bits until a defined write replaces
them, rejects any read of an undefined bit, and compares every remaining bit.

Each `memory` item represents a Pin memory operand:

- `operand` is Pin's zero-based memory-operand index.
- `region` is `main` when `addr` belongs to the selected target module,
  otherwise `other`. The value is kept as `main` for schema compatibility.
- `rva` is the memory address relative to the selected target-module base when
  `region=main`; otherwise it is `null`.
- `access` is `r`, `w`, or `rw`.
- `before` is captured at `IPOINT_BEFORE` for reads and writes.
- A write has `after` and `after_captured`. `after=null` means Pin did not offer
  a reliable post-instruction instrumentation point.
- `*_captured` gives the actual byte count returned by `PIN_SafeCopy`.
- `truncated=true` means `before` does not contain the operand's full declared
  size, either because of `-maxmem` or a partial safe copy.
- `memory_dropped` reports operands omitted because a fixed safety limit was
  reached. A symbolic replayer should treat a nonzero value as a coverage gap.

`sync` is one of:

- `trace_start`: this is the first record in a selected interval.
- `external_return`: the previous traced control-flow instruction entered code
  outside the main image, and this is the next main-image instruction.
- `null`: ordinary consecutive execution.

## Flow

`flow.kind` is `fallthrough`, `branch`, `jump`, `call`, `return`, or `syscall`.
For conditional branches, `taken` is a Boolean and `next` is the observed edge.
For non-branch instructions where a branch decision is meaningless, `taken`
is `null`. `direct_target` is present only when Pin decoded a static target.

`flow.external` identifies the destination module and symbol when a
control-flow instruction leaves the main image. Symbol may be empty when Pin
cannot resolve it. Only main-image instructions are traced, so external code is
represented by the later `external_return` synchronization record.

`flow.post_state=false` means finalization had to run before the instruction.
In that case write-after values are unavailable and `flow.next` may only be a
fallthrough estimate. Consumers must not use that record for strict post-state
validation.

## Triton replay contract

This JSONL schema supports a focused Triton adapter, but the recovery kit does
not bundle the Triton runtime. Use this contract only when Triton is already
available in the authorized offline environment. The default concrete evidence
workflow does not require it, and an offline run must not download it.

For one selected thread:

1. Create an x86-64 Triton context and map the instruction bytes at their
   runtime addresses.
2. At `trace_start`, load `regs` and concrete memory required by the first
   instruction. Symbolize the chosen input bytes after their concrete seed is
   installed.
3. At ordinary records, keep Triton's symbolic register and memory expressions.
   Use the logged pre-state to detect divergence; do not overwrite symbolic
   expressions with every concrete snapshot.
4. Before a concrete memory read that Triton has not modelled, inject the
   logged `before` bytes. Never replace bytes whose symbolic provenance must be
   preserved.
5. At `external_return`, model the external routine or explicitly resynchronize
   its concrete register and memory side effects. Resynchronization
   concretizes affected expressions, so record that boundary as a loss of
   symbolic provenance.
6. Process the instruction, then compare Triton's next PC and concrete writes
   with `flow.next` and `memory.after` whenever `flow.post_state=true`.
7. Use Triton's branch AST/path constraint from the processed instruction.
   Negate a selected constraint and solve it to generate a candidate input.

An offline file and a live stream produce equivalent Triton ASTs and path
constraints only when the consumer sees the same ordered records, initializes
the same symbolic variables, uses the same external-call models, and applies
the same synchronization policy. Offline replay is deterministic and easier
to debug. Live replay can change future inputs or execution state, but IPC
latency, backpressure, process scheduling, and target timing become part of the
experiment.

## Commands

Build x64 Release with VS2022:

```powershell
.\Build.ps1
```

Trace the main executable RVA interval:

```powershell
.\Run-Trace.ps1 -Target C:\path\app.exe -StartRva 0x1133 -EndRva 0x113c -Output C:\trace\run.jsonl
```

Trace a DLL RVA interval after it is loaded:

```powershell
pin.exe -t MyPinTool.dll -module plugin.dll -start 0x1133 -end 0x113c -o C:\trace\dll-run.jsonl -- C:\path\app.exe
```

The tracer installs image-load callbacks before the program starts. If
`plugin.dll` is delay-loaded with `LoadLibrary`, no metadata or instruction
records are written until that module appears. If the module never loads, the
summary has zero instructions and the recovery case must treat the boundary as
not reached.

Pass target command-line arguments after Pin's `--` separator through
`-TargetArgs`. For the current sample:

```powershell
    .\Run-Trace.ps1 -Target C:\path\Test.vmp_nocomplexity.exe -StartRva 0x1133 -EndRva 0x113c -Output C:\trace\hello.jsonl -TargetArgs hello
```

For floating-point recovery, `extended_regs` is mandatory. A trace without it
is invalid 2.0 evidence.

Validate every JSON line and the main invariants:

```powershell
.\Validate-Trace.ps1 -Path C:\trace\run.jsonl
```

Build and run the deterministic branch/memory regression fixture:

```powershell
.\Smoke-Test.ps1
```

Run the contract test for the trace format itself:

```powershell
.\Contract-Test.ps1
```

The contract test is the TDD guardrail for this tracer. It builds the smoke
fixture, records a 2.0 trace, validates the JSONL stream, and
asserts that the fields needed by offline replay are present and coherent.

The tested transport in version 2.0 is a regular file. A consumer can tail only
complete newline-terminated records; `-flush 1` minimizes latency and a larger
value reduces overhead. A dedicated named-pipe writer is not implemented, and
`-Output` must not be pointed at `\\.\pipe\...` in this version.
