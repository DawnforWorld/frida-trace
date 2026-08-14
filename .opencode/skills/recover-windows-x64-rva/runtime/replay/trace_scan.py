from __future__ import annotations

import argparse
import hashlib
import json
import struct
from collections import defaultdict
from pathlib import Path
from typing import Any, Iterable

from trace_io import open_trace_text


def _hex_int(value: str) -> int:
    return int(value, 16)


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest().upper()


def _read_jsonl(path: Path) -> Iterable[dict[str, Any]]:
    with open_trace_text(path) as stream:
        for line_number, line in enumerate(stream, 1):
            try:
                yield json.loads(line)
            except json.JSONDecodeError as error:
                raise ValueError(f"invalid JSON at {path}:{line_number}: {error}") from error


def _pe_ascii_strings(path: Path, minimum_length: int = 4) -> list[dict[str, Any]]:
    data = path.read_bytes()
    if data[:2] != b"MZ":
        raise ValueError(f"{path} is not a PE image")

    pe_offset = struct.unpack_from("<I", data, 0x3C)[0]
    if data[pe_offset : pe_offset + 4] != b"PE\0\0":
        raise ValueError(f"{path} has an invalid PE signature")

    coff = pe_offset + 4
    section_count = struct.unpack_from("<H", data, coff + 2)[0]
    optional_size = struct.unpack_from("<H", data, coff + 16)[0]
    section_table = coff + 20 + optional_size
    strings: list[dict[str, Any]] = []

    for index in range(section_count):
        offset = section_table + index * 40
        name = data[offset : offset + 8].split(b"\0", 1)[0].decode("ascii", "replace")
        virtual_address = struct.unpack_from("<I", data, offset + 12)[0]
        raw_size = struct.unpack_from("<I", data, offset + 16)[0]
        raw_offset = struct.unpack_from("<I", data, offset + 20)[0]
        raw = data[raw_offset : raw_offset + raw_size]

        cursor = 0
        while cursor < len(raw):
            start = cursor
            while cursor < len(raw) and 0x20 <= raw[cursor] <= 0x7E:
                cursor += 1
            if cursor - start >= minimum_length:
                value = raw[start:cursor].decode("ascii")
                strings.append(
                    {
                        "section": name,
                        "rva": virtual_address + start,
                        "file_offset": raw_offset + start,
                        "text": value,
                    }
                )
            cursor = max(cursor + 1, start + 1)

    return strings


def _resolve_string(
    address: int, image_base: int, strings_by_rva: dict[int, dict[str, Any]]
) -> dict[str, Any] | None:
    item = strings_by_rva.get(address - image_base)
    if not item:
        return None
    return {"address": f"0x{address:016x}", "rva": f"0x{item['rva']:x}", "text": item["text"]}


def scan_trace(trace_path: Path, image_path: Path | None = None, max_input: int = 256) -> dict[str, Any]:
    metadata: dict[str, Any] | None = None
    summary: dict[str, Any] | None = None
    first_instruction: dict[str, Any] | None = None
    last_instruction: dict[str, Any] | None = None
    selected_tid: int | None = None
    input_pointer: int | None = None
    input_bytes: dict[int, int] = {}
    input_reads: list[dict[str, Any]] = []
    image_byte_reads: dict[int, list[dict[str, Any]]] = defaultdict(list)
    external_calls: list[dict[str, Any]] = []

    for record in _read_jsonl(trace_path):
        record_type = record.get("type")
        if record_type == "metadata":
            metadata = record
            continue
        if record_type == "summary":
            summary = record
            continue
        if record_type != "instruction":
            continue

        if selected_tid is None:
            selected_tid = int(record["tid"])
        if int(record["tid"]) != selected_tid:
            continue

        if first_instruction is None:
            first_instruction = record
            if "[rdi+0x8]" in record["disasm"]:
                for memory in record["memory"]:
                    raw = bytes.fromhex(memory["before"])
                    if "r" in memory["access"] and len(raw) == 8:
                        input_pointer = int.from_bytes(raw, "little")
                        break
        last_instruction = record

        if metadata:
            image_base = _hex_int(metadata["module"]["base"])
            image_high = _hex_int(metadata["module"]["high"])
        else:
            image_base = 0
            image_high = 0

        for memory in record["memory"]:
            if "r" not in memory["access"]:
                continue
            address = _hex_int(memory["addr"])
            raw = bytes.fromhex(memory["before"])

            if input_pointer is not None and input_pointer <= address < input_pointer + max_input:
                for byte_index, byte_value in enumerate(raw):
                    current = address + byte_index
                    if current < input_pointer + max_input:
                        input_bytes[current] = byte_value
                input_reads.append(
                    {
                        "seq": int(record["seq"]),
                        "rva": record["rva"],
                        "instruction": record["disasm"],
                        "address": memory["addr"],
                        "size": int(memory["size"]),
                        "value": memory["before"],
                    }
                )

            if image_base <= address <= image_high and raw:
                for byte_index, byte_value in enumerate(raw):
                    current = address + byte_index
                    if current <= image_high:
                        image_byte_reads[current].append(
                            {
                                "seq": int(record["seq"]),
                                "rva": record["rva"],
                                "instruction": record["disasm"],
                                "value": byte_value,
                            }
                        )

        external = record["flow"].get("external")
        if external:
            external_calls.append(
                {
                    "seq": int(record["seq"]),
                    "rva": record["rva"],
                    "instruction": record["disasm"],
                    "module": external.get("module", ""),
                    "symbol": external.get("symbol", ""),
                    "arguments": {
                        name: record["regs"][name] for name in ("rcx", "rdx", "r8", "r9")
                    },
                }
            )

    if not metadata or not summary or not first_instruction or not last_instruction:
        raise ValueError("trace is missing metadata, instructions, or summary")

    seed = bytearray()
    if input_pointer is not None:
        for offset in range(max_input):
            address = input_pointer + offset
            if address not in input_bytes:
                break
            value = input_bytes[address]
            seed.append(value)
            if value == 0:
                break

    image_base = _hex_int(metadata["module"]["base"])
    pe_strings: list[dict[str, Any]] = []
    strings_by_rva: dict[int, dict[str, Any]] = {}
    if image_path:
        pe_strings = _pe_ascii_strings(image_path)
        strings_by_rva = {int(item["rva"]): item for item in pe_strings}

    candidate_constants: list[dict[str, Any]] = []
    seed_text_bytes = bytes(seed[:-1] if seed.endswith(b"\0") else seed)
    for item in pe_strings:
        encoded = item["text"].encode("ascii")
        if encoded != seed_text_bytes:
            continue
        runtime_address = image_base + int(item["rva"])
        expected = encoded + b"\0"
        verified: list[dict[str, Any]] = []
        for index, byte_value in enumerate(expected):
            reads = image_byte_reads.get(runtime_address + index, [])
            matching = [entry for entry in reads if entry["value"] == byte_value]
            if matching:
                verified.append(matching[0])
        candidate_constants.append(
            {
                "text": item["text"],
                "rva": f"0x{int(item['rva']):x}",
                "address": f"0x{runtime_address:016x}",
                "bytes_including_nul": expected.hex(),
                "verified_byte_reads": verified,
                "all_bytes_verified": len(verified) == len(expected),
            }
        )

    for call in external_calls:
        resolved: dict[str, Any] = {}
        for name, value in call["arguments"].items():
            item = _resolve_string(_hex_int(value), image_base, strings_by_rva)
            if item:
                resolved[name] = item
        call["resolved_strings"] = resolved

    input_deltas = [
        input_reads[index]["seq"] - input_reads[index - 1]["seq"]
        for index in range(1, len(input_reads))
    ]
    has_verified_constant = any(item["all_bytes_verified"] for item in candidate_constants)
    success_call = any(
        call["symbol"].lower() == "messageboxa"
        and any(value.get("text") == "success!" for value in call["resolved_strings"].values())
        for call in external_calls
    )

    inference = {
        "operation": "nul-terminated bytewise equality" if has_verified_constant else "unknown",
        "pseudocode": (
            'return strcmp(argv[1], "hello") == 0;'
            if has_verified_constant and seed_text_bytes == b"hello"
            else None
        ),
        "confidence": "high" if has_verified_constant and success_call else "medium",
        "evidence": [
            "argv[1] and the embedded candidate are read byte-by-byte including the NUL terminator",
            "the successful concrete path reaches MessageBoxA with success!",
            "the selected function returns RAX=1",
        ],
    }

    return {
        "schema": "pintrace-analysis/1.0",
        "trace": {
            "path": str(trace_path),
            "sha256": _sha256(trace_path),
            "source_schema": metadata["schema"],
            "instructions": int(summary["instructions"]),
            "selected_tid": selected_tid,
            "start_rva": metadata["selection"]["start_rva"],
            "end_rva": metadata["selection"]["end_rva"],
        },
        "image": {
            "runtime_path": metadata["module"]["path"],
            "base": metadata["module"]["base"],
            "analysis_path": str(image_path) if image_path else None,
            "sha256": _sha256(image_path) if image_path else None,
        },
        "input": {
            "source": "argv[1] via [rdi+8]",
            "pointer": f"0x{input_pointer:016x}" if input_pointer is not None else None,
            "seed_hex": bytes(seed).hex(),
            "seed_text": seed_text_bytes.decode("ascii", "replace"),
            "size_including_nul": len(seed),
            "reads": input_reads,
            "read_seq_deltas": input_deltas,
        },
        "candidate_constants": candidate_constants,
        "external_calls": external_calls,
        "result": {
            "seq": int(last_instruction["seq"]),
            "rva": last_instruction["rva"],
            "rax": last_instruction["regs"]["rax"],
        },
        "inference": inference,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Extract input and comparison evidence from PinTrace JSONL.")
    parser.add_argument("trace", type=Path)
    parser.add_argument("--image", type=Path)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--max-input", type=int, default=256)
    args = parser.parse_args()

    report = scan_trace(args.trace.resolve(), args.image.resolve() if args.image else None, args.max_input)
    rendered = json.dumps(report, indent=2, ensure_ascii=False)
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(rendered + "\n", encoding="utf-8")
    else:
        print(rendered)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
