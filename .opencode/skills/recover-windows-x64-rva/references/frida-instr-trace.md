# Frida Instr Trace Format

This project emits a single supported trace family: UTF-8 unidbg `AssemblyCodeDumper`-style text from `native\veh-injector` / `frida-rva-trace`.

Example row:

```text
[Test.vmp.exe                     0x0000000000001133] [488b4f08                      ] 0x0000000140001133: "mov rcx, qword ptr [rdi + 8]" (r 0x6d65f8 8) rdi=0x6d65f0 => rcx=0x6d6649 ; module.function
```

Field interpretation:

- First bracket: module name and module-relative RVA.
- Second bracket: instruction bytes as hex.
- Absolute VA: runtime instruction address after the byte bracket.
- Quoted text: decoded instruction.
- `(r address size)`, `(w address size)`, `(rw address size)`: memory effective address and operand size only.
- Register tokens before `=>`: observed read/pre-state register values for that instruction.
- Register tokens after `=>`: observed post-state register changes when available.
- Trailing `; module.function`: external transfer target resolved by the agent.

Evidence limits:

- Memory values are not printed as a separate field. Many are nevertheless uniquely recoverable from the decoded instruction and scalar register observations: destination post-state for loads, source pre-state for stores, or inversion of operations such as XOR/add/sub. Treat these as derived evidence and record the equation and width.
- Memory-only comparisons, non-invertible operations, and vector accesses without a traceable scalar or memory definition do not reveal a unique value.
- Apply [Derived Memory Recovery](derived-memory-recovery.md) before declaring a memory value unavailable.
- Full scalar state for every register is not guaranteed.
- Extended registers, x87, opmask, MXCSR, and exact floating-point state are not recorded.
- Exact flags transitions are not guaranteed.
- External target names are hints about control transfer, not API argument logs.
- Absence of a register after `=>` does not prove the register was unchanged.

Use this format as the sole evidence input for path reconstruction, branch/callee discovery, register flow, effective-address reasoning, memory-value derivation, and external target inventory. Claims depending on missing state must stay `hypothesis` or become explicit missing-trace requests.
