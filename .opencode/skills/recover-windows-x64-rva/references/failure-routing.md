# Supplied Trace Failure Routing

| Symptom | Classification | Next action |
|---|---|---|
| Pin does not create metadata | launch/injection/tool failure | Ask upstream to check x64 PE/harness, relative tool paths, dependencies, arguments, and console exit code. |
| Metadata exists, instruction count is zero | boundary not hit or anti-instrumentation | Ask upstream to verify sample hash/RVA and input path; use a twin only after independent-provenance proof. |
| Selected-DLL Pin trace is metadata-only and the host stops at pre-LoadLibrary output | self-decrypting `DllMain` routing failure | Request no-Pin transcript evidence, module bytes before/after `DllMain` decryption, then a prompt-gated Stalker/hardware-breakpoint/debug trace. |
| DLL module is visible but target RVA bytes are zero/encrypted | self-decrypting or delayed runtime code materialization | Request first-seen and decrypted bytes, plus a trace captured only after bytes stabilize. |
| Frida `Interceptor.attach` misses or changes behavior in protected DLL | patch overwritten or integrity-sensitive code | Request a non-patching trace using Stalker callouts, hardware breakpoints, or another read-only debugger trace. |
| Full-module Stalker stalls during `DllMain` or produces huge logs | observation too invasive | Request a narrower trace after the prompt, exact RVA/callee/return callouts, or hardware breakpoint trace. |
| Interactive DLL never returns to host after `LoadLibrary` | transcript incomplete or prompt not driven | Treat menu selector, payload, DLL exit token, and final pause-dismiss key as one transcript; capture stdout as bytes. |
| Start record exists, end record absent | incomplete interval | Ask upstream to check that end is an exact executed instruction, inspect tail/early exit, and adjust only the boundary or input. |
| Summary absent | incomplete trace | Preserve log; classify crash, forced termination, timeout, or output failure. |
| Sequence discontinuity | corrupt/incomplete stream | Reject trace and request a replacement. |
| Memory dropped/truncated | capture gap | Request raised `max_memory_bytes` up to 256, a narrower interval, or independent evidence for the missing external effect. |
| Protected process exits under debugger/Pin | anti-debug/integrity | Do not patch by default. Request read-only capture, hardware-assisted observation, or an independently proven twin. |
| Runtime bytes differ from twin | rewrite/virtualization or version mismatch | Reject semantic substitution until target-vs-twin equivalence is independently proven for the selected scope. |
| Triton import/preflight fails | missing or wrong runtime | Run only offline preflight/bootstrap for analysis; never download dependencies during a case. |
| Triton replay diverges/resynchronizes | incomplete state or semantics | Request a trace with more complete state, request a narrower window, or model the exact effect; do not overwrite the divergence. |
| SIMD/x87/MXCSR state absent | incomplete floating trace | Request an extended Pin/debugger trace; do not initialize missing state. |
| Branch edge remains unknown | incomplete behavior | Negate the Triton predicate, solve, and request an original-target trace for the model, or retain unknown. |
| Optional candidate falsification fails | hypothesis mismatch | Request an original-target trace/Triton report for the exact input before changing recovered behavior. |
| Output differs across repeats | nondeterminism/state | Request repeat and controlled-mutation runs; locate random/time/external sources from supplied evidence. |
| Plugin vectors fail | algorithm hypothesis wrong/incomplete | Stop source generation; revisit mode, padding, coverage, endianness, state initialization, and caller/callee ownership. |

Never repair a failed required check by changing it to advisory without a documented evidence reason. Never use one failed anti-debug experiment as algorithm evidence. Do not terminate or manage target process trees unless the user explicitly asked for capture work.
