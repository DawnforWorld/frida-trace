# VMP and Obfuscated Trace Analysis

## Decision Order

1. Fix the sample hash, RVA window, arguments, trace schema, and successful path.
2. Inspect external calls, output sinks, random sources, and copy/fill operations.
3. Group observable fields by address, length, repetition, and mutation behavior.
4. Test standard primitive and protocol hypotheses against exact bytes.
5. Require one formula to explain independent runs.
6. Use a concrete backward slice, then mandatory strict Triton replay, taint, simplified sink ASTs, and alternate-path solving.
7. Reconstruct evidence-mapped C++, close important branches/errors with original-target traces and Triton, then publish as `trunk` with explicit gaps or as `complete` only if no unknown remains.

Prefer sinks and external effects over raw VM handler volume. Useful searches include candidate constant reads, candidate key-buffer writes, bytewise output calls, `memcpy`/`memmove` assembly chains, `memset` around fixed-size blocks, and external calls whose sequence stays stable across mutations.

## Field Grouping

Common lengths are hypotheses, never names:

- 16 bytes: block, IV, nonce, short tag, or MD5-sized value;
- 20 bytes: SHA-1-sized or truncated value;
- 32 bytes: SHA-256/HMAC-sized value or 256-bit key;
- 48 bytes: composite or TLS-like material;
- 64 bytes: SHA-256 block, HMAC pad region, or message block.

Temporarily name fields `field_0`, `field_1`, and so on. Promote a name only when source, sink, coverage, and exact formula agree.

## Crypto and Protocol Hypotheses

For each candidate field, ask:

1. Is it emitted, compared, or stored repeatedly at a stable boundary?
2. Does its length and block behavior fit a primitive?
3. Are label strings or domain separators read into the covered data?
4. Can message, key, IV, nonce, and tag roles be separated by controlled mutation?
5. Does an independent implementation reproduce every byte?
6. Does the same formula work on another run and an edge length?

Test plausible HMAC, SHA, AES mode, padding, IV coverage, tag coverage, byte order, and serialization rules. A previous protocol recovery, for example, produced this hypothesis chain:

```text
master_secret = HMAC-SHA256(pre_master, client_random || server_random)
enc_key       = HMAC-SHA256(master_secret, client_random || server_random)
mac_key       = HMAC-SHA256(master_secret, "MAC")
tag           = HMAC-SHA256(mac_key, iv || ciphertext)
```

Treat that chain only as an example of staged hypothesis testing. Never reuse it as evidence for another sample.

## Multi-Trace Tests

- Same input repeated: locate random, time, process, and state dependencies.
- One-byte message mutation: measure propagation and field coverage.
- Key/IV/nonce mutation: separate state roles.
- Length edges: recover blocks, padding, bounds, and allocation ownership.
- Invalid input: recover validation, comparison, return, and tamper paths.

Compare path hashes, call sequences, changed writes, and final sink bytes. A changed path is behavioral evidence, not automatically a failed experiment.
Require exact byte agreement across multiple traces before promoting one formula to `verified`.

## VM Noise Reduction

Group repeated handler RVAs, dispatcher edges, virtual-register storage, and constant-pool reads. Keep concrete sequence numbers so every normalized operation maps back to raw evidence. Do not assume handler identity from one opcode pattern. If self-modifying bytes or protected/twin bytes differ, distinguish virtualization and runtime rewriting from an RVA error.

If only trace artifacts are available, use analyze-only mode and require known sample hashes, arguments, module base, boundary semantics, metadata, summary, memory-loss status, and all machine state required by Triton. Metadata-only JSONL is not an instruction trace.

## Reconstruction and Confidence

Preserve field order, widths, byte order, state update order, caller/callee ownership, receiver checks, and observed failures. Keep untraced helper bodies abstract.

Use these labels consistently:

- `verified`: exact trace bytes plus independent implementation or vector agree;
- `inferred`: structure or source-like naming is well supported but not directly observed;
- `unknown`: unexecuted path, unmodeled effect, or insufficient evidence.

Deliver a comparison showing field layout, formulas, helper coverage, error paths, and agreement for every captured run.
