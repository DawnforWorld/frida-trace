# Exact Floating-Point Recovery

## Machine State Is Part Of The Input

For x64 floating code, require a supplied trace that records every state component the executed instructions can read:

- XMM/YMM/ZMM operands and results;
- x87 stack, control word, status word, and tag word;
- MXCSR rounding mode, exception masks/flags, FTZ, and DAZ;
- memory operands as exact bytes;
- compiler/runtime helper effects and floating environment changes.

The base Pin JSONL scalar state does not contain these fields. Extend each instruction record with an `extended_regs` object whose keys use Triton register names and whose values are full-width hexadecimal bits, for example `xmm0` and `mxcsr`. The strict adapter restores and compares those values exactly.

A replay encountering SSE/AVX without the required `extended_regs` values must fail. The locked Triton binding exposes vector registers and MXCSR, but not complete x87 control/status/tag or AVX-512 opmask state; those paths remain blocked even if a debugger prints partial values. Extend the PinTool/binding or use another exact supported instruction boundary. Never initialize missing floating state to zero.

## Compare Bits, Not Tolerances

Record float as 8 hex digits and double as 16 hex digits in memory byte order plus interpreted class. Exact equivalence distinguishes:

- +0 and -0;
- subnormal and normal boundaries;
- adjacent values around every comparison threshold;
- maximum finite values and overflow;
- +Inf and -Inf;
- quiet/signaling NaNs, sign, payload, and quieting behavior;
- invalid, divide-by-zero, overflow, underflow, and inexact flags.

Do not use epsilon, ULP tolerance, decimal formatting, ordinary ==, or JSON floating numbers for the complete gate. `scripts/compare_behavior.py` rejects JSON floats and requires `{"kind":"f32","bits":"........"}` or `{"kind":"f64","bits":"................"}` with exact hexadecimal widths.

## Prove Operations And Paths

The case-specific Triton script must:

1. restore the exact floating environment and register bits;
2. replay the actual instruction bytes;
3. assert next PCs and reliable writes;
4. extract sink and comparison ASTs;
5. unroll and simplify each AST;
6. ask the solver whether raw and simplified ASTs can differ;
7. negate ordered/unordered comparison predicates and generate models;
8. request original-target traces for those models.

If Triton does not implement an executed floating opcode or its environmental semantics, mark the path unknown. A hand-written real-number formula is not an acceptable substitute for IEEE-754 instruction semantics.

For the locked binding's audited scalar SSE2 gap, use `runtime/replay/sse2_ieee.py`. It performs the operation in Z3's IEEE-754 `Float64` sort with the MXCSR rounding mode, applies DAZ/FTZ, derives invalid/denormal/divide-by-zero/overflow/underflow/inexact sticky flags, and compares the resulting 64/128-bit value and MXCSR against the trace. The symbolic result is carried in Triton only as an explicitly named opaque variable; the hash-bound Z3 FPA formula is the authoritative semantic definition and must be included in every backward slice and branch query. This route is valid only for the audited opcode set and represented exception-mask behavior. It does not permit tolerances or generic concrete state overwrite.

## Required Boundary Matrix

Select relevant values from:

- both signed zeros;
- minimum/maximum subnormal;
- minimum normal and adjacent representable values;
- values immediately below/at/above each threshold using nextafter;
- maximum finite and adjacent overflow-producing operands;
- both infinities;
- multiple quiet NaN payloads and signaling NaN where the ABI permits;
- every reachable rounding mode and FTZ/DAZ combination.

Also cover loop exhaustion, nonpositive refinement/count values, integer-to-floating conversion boundaries, callback-produced exceptional values, and intermediate overflow. Record callback order and raw argument bits.

When emitting C++, record source-level obligations for strict IEEE-754 behavior and link each one to exact target bits, MXCSR/x87 state, Triton ASTs, and any Z3 FPA shadow formulas. Do not validate floating recovery by compiling the candidate. Compilation and compiler-flag review are separate engineering tasks outside this recovery skill.
