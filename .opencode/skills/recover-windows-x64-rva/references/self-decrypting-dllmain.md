# Self-Decrypting LoadLibrary/DllMain DLLs

Use this reference when the selected RVA is inside a DLL loaded by `LoadLibrary*`, the DLL decrypts or rewrites code during `DllMain`, or `DllMain` itself performs interactive console I/O before `LoadLibrary` returns.

## Recognition

Typical signals:

- the host prints a pre-load marker such as `before`, calls `LoadLibrary`, and does not print the post-load marker until the DLL interaction exits;
- the selected DLL appears in Toolhelp/module enumeration while bytes at the target RVA are `00`, encrypted, or otherwise not executable-looking;
- later, still inside `DllMain`, the same `base + RVA` bytes change into valid code and the user transcript can hit the RVA;
- Pin selected-module runs produce metadata-only traces or stall at the host pre-load marker, while ordinary no-Pin execution with the same transcript completes.

Treat `before` plus no later prompt as ambiguous: it may be a real prompt waiting through direct console I/O, a pipe issue, or instrumentation perturbing loader/DllMain execution. Prove which one with byte-level stdout capture and normal no-Pin transcript runs.

## Upstream Harness Requirements

When requesting a replacement trace for this shape, ask upstream capture to use one controlling harness for process lifetime and I/O:

1. Create the host process suspended with inherited stdin/stdout/stderr pipes or a pseudo-console.
2. Attach observation before resuming: Frida, debugger, or another read-only module/byte observer.
3. Resume the main thread.
4. Wait for the DLL module base with Toolhelp or loader hooks.
5. Poll `base + target_rva` bytes until the requested window has decrypted/replaced bytes. Record both first-seen bytes and decrypted bytes.
6. Wait for the prompt that precedes the user-controlled path, if one exists.
7. Start the least-invasive routing trace only after decryption and prompt readiness.
8. Write the full transcript at once or in deterministic prompt-gated chunks.
9. Include the exit token that returns from `DllMain` and any final host pause-dismiss key.

Never treat manual typing as the primary evidence path when pipes or a pseudo-console can drive the same transcript.

## I/O Discipline

Own stdout as bytes:

- search for prompt bytes in the target code page, not only UTF-8 text;
- keep a rolling tail buffer so prompts split across reads are still detected;
- mirror stdout to a binary artifact such as `console.stdout.bin`;
- store the exact transcript bytes, including `\r\n`, exit token, and final dismiss key;
- if a target uses direct console APIs and pipes fail, switch to a pseudo-console or user-approved UI automation harness, but still record the transcript contract.

For menu-driven protocol cases, one transcript is one semantic input. Do not send only the first menu selector and then wonder why the host never exits; `LoadLibrary` cannot return until `DllMain` returns.

## Pin Routing Pitfall

Pin can be valid in principle and still fail for this shape:

- selecting the self-decrypting DLL may make Pin observe/cache/instrument the zeroed or encrypted mapping before `DllMain` rewrites it;
- `-smc_strict` may not recover this if the protected loader, code cache, or anti-instrumentation behavior prevents a clean selected-module interval;
- attaching after `LoadLibrary` returns is too late when the target RVA executes inside `DllMain`;
- attaching while `DllMain` is blocked on input may still be too late if the selected-module code was already rewritten and Pin did not own that thread state.

When this happens, classify Pin output carefully:

- metadata file absent: launch/injection/tool failure;
- metadata-only selected-DLL trace and target stuck at pre-load output: likely self-decrypt/DllMain routing failure;
- metadata-only trace but no-Pin transcript completes and runtime bytes decrypt: use supplied read-only fallback evidence to prove route, then request a debugger/hardware-breakpoint trace if final replay is required.

Do not keep changing command-line syntax after a clean no-Pin transcript and runtime byte polling prove the issue is self-decrypt timing.

## Read-Only Fallbacks

Request non-patching methods from upstream capture:

- Toolhelp/module polling plus `ReadProcessMemory` snapshots for first-seen and decrypted bytes;
- Frida Stalker focused callouts for exact RVAs, call targets, and returns after the prompt is visible;
- hardware breakpoints on `base + start_rva` and single-step/debugger trace through the inclusive end window;
- full-module Stalker only as a last resort and only after the prompt is reached, because it can add millions of events and perturb protected code.

Avoid ordinary `Interceptor.attach` on protected bytes unless no safer option exists. Early hooks may be overwritten by self-decryption; late patching can trip integrity checks or change behavior.

## Evidence Classification

Use labels consistently:

- runtime byte snapshots are evidence for decrypted code bytes and branch/call targets;
- focused Stalker or debugger hits are routing evidence for `start -> callee -> return/end`;
- full strict Pin/debugger instruction records plus Triton replay are required for verified sink formulas and complete claims;
- when only the route and console-visible behavior are closed, emit trunk C++ with helper bodies marked `inferred` or `unknown`.

Even when Pin fails, still emit the best-supported C++ trunk if the main behavior is recoverable. The C++ must include `cpp_evidence_map`, explicit gaps, and provenance losses.
