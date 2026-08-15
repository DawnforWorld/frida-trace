# Derived Memory Recovery From Trace Rows

The trace prints memory effective address and operand size, not a separate memory-value field. Recover concrete or symbolic values by combining the trace row with x64 instruction semantics and observed register pre/post state.

This process is mandatory before classifying an in-slice memory value as missing.

## Memory Ledger

Maintain a byte-addressed, little-endian memory ledger. Each entry should contain:

```json
{
  "trace": "trace.txt",
  "line": 1234,
  "rva": "0x2a4e",
  "instruction": "xor r8d, dword ptr [rsi+r9*4+0x1c]",
  "access": "read",
  "address": "0x14fd2c",
  "size": 4,
  "method": "invertible_alu",
  "equation": "mem32 = r8d_before XOR r8d_after",
  "value": "0x034c3fd8",
  "confidence": "exact",
  "cross_check": "later load/store or none"
}
```

Split multi-byte values into bytes in the ledger so overlapping and unaligned accesses compose correctly. Track the full originating equation separately for readability.

## Exact Recovery Classes

### Direct loads

For `mov`, `movzx`, `movsx`, `movsxd`, and equivalent scalar loads, the destination post-state reveals the loaded value after applying the instruction's extension rule.

Examples:

```text
mov eax, dword ptr [p]       -> mem32 = eax_after
movzx eax, byte ptr [p]      -> mem8  = eax_after & 0xff
movsx eax, byte ptr [p]      -> mem8  = eax_after & 0xff
```

For partial-register destinations, use the written width. Respect x64 zero-extension when a 32-bit GPR is written.

### Direct stores

For scalar stores, the source pre-state or immediate is the written value at the operand width.

```text
mov dword ptr [p], r9d       -> mem32_after = r9_before & 0xffffffff
mov byte ptr [p], 0x41       -> mem8_after  = 0x41
```

### Invertible ALU reads

When the destination register pre-state and post-state are both observed, solve the memory operand modulo its width.

```text
xor reg, [mem]  -> mem = before XOR after
add reg, [mem]  -> mem = after - before mod 2^width
sub reg, [mem]  -> mem = before - after mod 2^width
```

For `imul reg,[mem],k`, solve modulo `2^width`. The memory value is unique only when `k` is invertible modulo `2^width` (for powers of two, `k` must be odd). Otherwise record the candidate congruence, not a fabricated exact value.

For shifts, rotates, AND, OR, multiplication, division, carry-dependent operations, and flag-dependent instructions, mark exact only when the mapping is uniquely invertible with all required inputs known.

### Read-modify-write memory destinations

For instructions such as `xor [mem],reg`, `add [mem],reg`, `inc [mem]`, or `xchg`, recover the before value from the current ledger or a prior/later exact anchor, then execute the operation to obtain the after value.

Never assume an uninitialized before value. Record separate read-before and write-after entries.

### Later reload and store-forward recovery

A later exact load can anchor an earlier write when no intervening overlapping write exists. A prior exact store can supply a later read. Track byte-range overlap and invalidate overwritten bytes precisely.

Cross-check values whenever the same bytes are independently exposed by another instruction form.

### Copies and SIMD transfers

Untracked XMM/YMM state is not automatically a gap. Follow copy chains:

```text
scalar stores -> source memory -> movups xmm -> movups destination memory
```

If the vector register is only loaded and copied without an intervening vector transform, propagate the source bytes exactly. If vector arithmetic, shuffles, blends, masking, or partial-lane writes occur, decode the instruction bytes with Capstone and model the lane semantics; otherwise mark affected bytes unknown.

Be alert for collector access-direction errors on SIMD stores. Determine direction from instruction semantics, not only the rendered `(r)/(w)` marker.

### Implicit stack memory

Model implicit stack effects even when no memory token is printed:

```text
push src  -> write src at rsp_after
pop dst   -> read dst_after from rsp_before
call      -> write return address at rsp_after
ret       -> read return address from rsp_before
```

Track stack pointer width and ordering exactly.

## Constraint-Only Values

`cmp [mem],x`, `test [mem],x`, conditional branches, and `setcc` may constrain memory without revealing it uniquely.

Examples:

- equality branch taken after `cmp [mem], 5` proves `mem == 5`;
- equality branch not taken proves only `mem != 5`;
- `test [mem],mask` plus branch usually proves masked bits, not the complete value.

Record constraints separately from exact values. Promote a constraint to exact only when its solution is unique at the operand width or another row anchors the value.

## Register and Width Rules

- Normalize aliases (`al/ah/ax/eax/rax`, `r8b/r8w/r8d/r8`) while retaining the accessed bit range.
- A write to a 32-bit GPR zeroes the upper 32 bits.
- Writes to 8-bit or 16-bit aliases preserve unaffected bits.
- Arithmetic wraps modulo `2^operand_width`.
- Use signed interpretation only for instructions whose semantics require it; stored bytes remain bit-vectors.
- Treat missing post-state as unknown unless the instruction semantics and another observation uniquely determine it.

## Address and Overlap Rules

- Use the trace's effective address as primary evidence.
- Split every value into byte cells and merge reads from contiguous known bytes.
- Handle unaligned accesses and partial overwrites.
- Keep ASLR-dependent absolute addresses separate from module RVAs.
- Distinguish stack instances and repeated calls even when the same relative stack offsets are reused.

## Decoder and Tool Use

- The trace instruction bytes and row are primary evidence.
- Use Capstone to verify operand direction, width, implicit operands, register aliases, and SIMD lane semantics.
- Use Triton after populating exact constants and symbolic source bytes in the ledger. Do not symbolize every unknown byte when trace algebra can recover it first.
- When angr is detected, lift blocks reconstructed from trace-row bytes and use VEX effects/reaching definitions to cross-check the ledger and slice. Do not load a target binary.
- Do not use IDA, a target binary, source code, or previous recovery artifacts. If a value cannot be recovered from the trace ledger or trace-only tool replay, keep it unknown.

## Coverage Metrics

Report at least:

```text
total memory operands
exact direct loads
exact direct stores
exact invertible-ALU recoveries
exact propagated/copy recoveries
constraint-only operands
unknown operands
unknown operands in final source-to-sink slice
independent cross-check count and pass/fail count
```

Unknown operands outside the final slice do not block a selected output formula. Any unknown operand inside the slice must appear in the report as a named formula hole or blocker.
