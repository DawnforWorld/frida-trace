# RVA Boundaries

`frida-instr-trace` uses module-relative RVAs:

```text
absolute = module.base + rva
```

Boundary semantics match this repository's launcher and agent:

- `--start-rva` is inclusive.
- `--start-rva 0` means the first observed instruction inside the start module.
- `--end-rva` / `--stop-rva` is inclusive; the stop instruction is written to the trace.
- `--end-rva 0` means trace until process exit or user stop.
- `--start-module` and `--stop-module` may differ from `--module`.
- Stop RVA does not need to be numerically greater than start RVA; execution flow determines whether it is reached.
- The default owner thread is the thread that hit the VEH trigger. Other threads are not recovery evidence unless the trace clearly records them.

Reject ASLR runtime VAs as RVA boundaries unless a module base is supplied and the RVA is explicitly computed from it.
