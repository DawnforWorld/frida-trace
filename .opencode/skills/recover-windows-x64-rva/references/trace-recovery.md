# Trace-to-Algorithm Recovery

## Evidence Order

1. Confirm target hash, arguments, module base, RVA selection, metadata, summary, and zero/accepted memory loss.
2. Recover the entry ABI from register preparation and the start record.
3. List direct/internal calls and external calls in sequence.
4. Identify observable sources: input buffers, files, environment, clocks, random APIs, key/IV/nonce material.
5. Identify sinks: changed output memory, comparison branches, console/file/network writes, returned containers, and error codes.
6. Slice backward from each sink using register and memory addresses in the raw records.
7. Compare independent runs before assigning semantic names.

## Digest Fields

`trace_digest.json` is a bounded index, not replacement evidence:

- `entry_contract`: first instruction plus scalar pre/post registers;
- `calls`: source/target, external symbol, and RCX/RDX/R8/R9;
- `branches`: taken counts and observed next RVAs;
- `changed_writes`: concrete before/after bytes for writes with reliable post-state;
- `top_memory_pages`: likely stack/image/other pages ranked by activity;
- `external.events`: call arguments, RAX, candidate memory, and changed memory;
- `unique_instructions`: first-seen disassembly and hit counts;
- `path_sha256`: dynamic path signature;
- `comparisons`: path/RVA/call differences between named runs.

If a digest section is truncated, query the raw JSONL by sequence number or RVA. Never infer absence from a truncated digest.

## Experiment Matrix

| Run | Purpose |
|---|---|
| primary | Establish successful baseline and output bytes. |
| repeat | Detect random/time/process-dependent data. |
| input_mutation | Locate input-dependent state and avalanche behavior. |
| key_or_state_mutation | Separate key/state from plaintext/message fields. |
| length_edge | Recover block size, padding, bounds, and errors. |
| invalid_input | Recover validation and failure branches. |

Use concrete output agreement across at least two relevant runs. For standard crypto, also check published vectors. For proprietary transforms, implement an independent reference and compare every observed output byte.

## Coverage Requests

The default workflow consumes user-supplied trace files. Do not execute the target, build probes, start Pin, attach Pin, start Frida/Stalker, or recapture traces unless the user explicitly asks for capture work in the current request. After trace files are supplied, run the downstream analysis yourself: identify the schema, convert renderable formats, hash and validate records, build digests, replay supported traces, slice sinks/branches, run Triton when available, and emit the recovered C++ plus evidence map.

When coverage is missing after analysis, produce a precise upstream trace request instead of running the target yourself. Each request should include:

- trace format: `frida-instr-trace` text, `pintrace-jsonl/2.0`, `intel-pin` binary pair, or `intel-pin` unidbg text;
- target/module identity and hash when known;
- selected module, start RVA, inclusive stop RVA, and whether the interval should follow calls into other modules;
- command-line arguments, stdin transcript, file inputs, callback setup, or environmental inputs needed to reach the edge;
- the blocked claim: branch edge, sink, output bytes, error path, exception path, callback order, or callee behavior;
- required fields, such as instruction bytes, pre-registers, memory operand addresses/sizes, memory bytes, external-call records, or module-base metadata.

Suggest discriminating inputs for upstream capture:

1. zero, one, two, odd, negative, and max signed counts;
2. null pointers and null output/error pointers in isolated children;
3. key/length/block/padding boundaries and sentinel-preservation cases;
4. callback functions that return identity, constant, NaN, infinity, max finite, signed zero, and side-effect counters;
5. callback order probes that store every argument bit before returning;
6. allocation-size and overflow cases that may change C++ EH vs SEH behavior;
7. aliasing and overlap cases only after the ordinary domain is stable.

For interactive menu-driven console targets, request the whole script as one atomic transcript:

- include every menu choice in order;
- include the submenu payload string(s);
- include the final exit token such as `0`;
- if the binary prints a `press any key` style pause, append one extra keypress or the run will look hung even when the semantic path already finished.

If the target opens console windows or reads through direct console APIs, ask the upstream tracer to use a `CreateProcessW` harness with inherited pipes or a pseudo-console. Manual typing is too brittle for repeatable trace recovery.

Classify every supplied run:

- `match`: keep as regression coverage.
- `candidate_mismatch`: treat it only as a hypothesis that the C++ artifact is missing behavior; request an original-target trace for the exact input, then run replay/proof yourself before changing recovered semantics.
- `subject_divergence`: request an upstream rerun plus hash/provenance confirmation before interpreting.
- `crash_or_exception`: record code/type, side effects before transfer, and unwind evidence requirements.

Do not let proposed inputs replace trace evidence. Use them only to define high-value RVAs, sinks, and concrete upstream capture requests.

## Missing-Trace Queue

The AI is responsible for downstream analysis and for proposing the next trace, not running target capture. Build a missing-trace queue from:

- candidate mismatches found during evidence mapping;
- loader/attach observations supplied with the trace package;
- unknown branch edges from Triton path constraints;
- unobserved validation failures, null pointers, signed/unsigned length boundaries, overflow boundaries, aliasing cases, callback return classes, and floating special values;
- missing sinks such as error stores, sentinel preservation, callback order, exception transfer, and side effects before failure;
- optional candidate falsification failures, if supplied by the user, that identify a likely missing guard or ordering rule.

Queue entries must record the function, selected module, RVA window, source predicate/hash or trace evidence, proposed concrete inputs/transcript, expected sink/edge, requested format, and required fields. Prefer cheap and discriminating traces first:

1. Null and invalid pointer guards.
2. Zero/one/min/max length and count boundaries.
3. Error-code and sentinel-preservation cases.
4. Floating signed zero, infinities, quiet/signaling NaNs, max finite, subnormal, and tolerance boundaries.
5. Callback return classes and callback side effects.
6. Short loop base cases.
7. Large loops only after a recurrence hypothesis is ready to test.

For menu-driven protocol cases, queue transcript variants as one input contract instead of one prompt at a time. A common shape is: selector -> payload string -> explicit exit token -> final dismiss key. Missing the last token often produces a false hang and no trace records.

After the user supplies a new trace, hash the raw trace, run strict concrete replay when the schema supports it, run the smallest symbolic proof window that explains the new edge or sink, and update the branch matrix. A solver model that is not represented by a user-supplied original-target trace remains a hypothesis, not evidence.

If a supplied trace contains metadata only or a summary such as `instructions: 0`, treat it as a routing failure: the transcript did not reach the chosen RVA window, the selected module was wrong, or the function was not actually executed. Do not feed such a run into Triton as proof of behavior.

## Cost Control

Use a staged budget:

- Request only traces that can change the algorithm, branch manifest, sink model, callback order, or exception/error behavior.
- Prefer one focused trace request over broad recapture.
- Keep supplied transcript and PID/loader timing in the case evidence when the upstream capture provides them.
- Triton should replay the smallest contiguous window that proves the sink, branch predicate, callback boundary, or exception state.
- Large loops require segmentation, recurrence summaries, or representative base/step/exit traces before symbolic replay.
- Stop a slow replay and narrow the window when it exceeds the value of the uncovered behavior; report the edge as `unknown` rather than blocking main-trunk delivery.

## C++ Reconstruction Rules

- Reconstruct behavior and ABI boundaries, not original source spelling.
- Preserve exact widths, signedness when proven, byte order, lengths, and state update order.
- Preserve evaluation/callback order, local-copy aliasing behavior, allocation/failure ownership, sentinels, exceptions, and crashes.
- Preserve floating values and arguments by IEEE-754 bits plus MXCSR/x87 behavior; do not validate with tolerances.
- Keep caller-owned padding/allocation/serialization outside the recovered callee.
- Keep an untraced helper abstract or explicitly unknown.
- Include a `cpp_evidence_map` that ties every emitted branch, store, formula, call, return, error, and exception behavior to trace/Triton evidence.
- Do not require compiling or executing the recovered C++.
- Do not invent rejection or null guards for unsupported/unobserved inputs; keep them unknown and block completeness.
