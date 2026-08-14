#!/usr/bin/env python3
"""Emit a hash-bound Windows x64 PE unwind / exception inventory."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import struct
from dataclasses import dataclass
from pathlib import Path
from typing import Any


SCHEMA = "pe-unwind-inventory/1.1"
UNW_FLAG_EHANDLER = 0x1
UNW_FLAG_UHANDLER = 0x2
UNW_FLAG_CHAININFO = 0x4


@dataclass(frozen=True)
class Section:
    name: str
    va: int
    virtual_size: int
    raw_size: int
    raw_ptr: int


@dataclass(frozen=True)
class SnapshotRegion:
    path: Path
    phase: str
    base: int
    start_rva: int
    data: bytes


def u16(data: bytes, offset: int) -> int:
    return struct.unpack_from("<H", data, offset)[0]


def u32(data: bytes, offset: int) -> int:
    return struct.unpack_from("<I", data, offset)[0]


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest().upper()


def parse_int(value: str) -> int:
    return int(value, 0)


def parse_function_arg(raw: str) -> dict[str, Any]:
    if "=" in raw:
        name, interval = raw.split("=", 1)
    else:
        name, interval = raw, raw
    if ":" in interval:
        start, end = interval.split(":", 1)
        start_rva = parse_int(start)
        end_rva = parse_int(end)
        if end_rva <= start_rva:
            raise ValueError(f"invalid function interval {raw!r}")
    else:
        start_rva = parse_int(interval)
        end_rva = None
    return {"name": name, "entry_rva": start_rva, "end_rva": end_rva}


def rva_to_offset(rva: int, sections: list[Section]) -> int | None:
    for section in sections:
        size = max(section.virtual_size, section.raw_size)
        if section.va <= rva < section.va + size:
            delta = rva - section.va
            if delta < section.raw_size:
                return section.raw_ptr + delta
    return None


def parse_snapshot(path: Path, phase: str) -> SnapshotRegion:
    pattern = re.compile(
        rf"^{re.escape(phase)} base=(0x[0-9a-fA-F]+) "
        r"start_rva=(0x[0-9a-fA-F]+) end_rva=(0x[0-9a-fA-F]+) "
        r"copied=(0x[0-9a-fA-F]+) data=([0-9a-fA-F]*)$"
    )
    matches: list[SnapshotRegion] = []
    with path.open("r", encoding="ascii", errors="strict") as stream:
        for raw_line in stream:
            match = pattern.match(raw_line.rstrip("\r\n"))
            if not match:
                continue
            base = int(match.group(1), 16)
            start_rva = int(match.group(2), 16)
            end_rva = int(match.group(3), 16)
            copied = int(match.group(4), 16)
            captured = bytes.fromhex(match.group(5))
            if len(captured) != copied:
                raise ValueError(
                    f"snapshot {phase} byte count mismatch: copied={copied} data={len(captured)}"
                )
            if copied != end_rva - start_rva + 1:
                raise ValueError(f"snapshot {phase} RVA range is not fully captured")
            matches.append(SnapshotRegion(path, phase, base, start_rva, captured))
    if len(matches) != 1:
        raise ValueError(f"snapshot must contain exactly one {phase} record, found {len(matches)}")
    return matches[0]


def read_rva(
    image: bytes,
    sections: list[Section],
    rva: int,
    size: int,
    snapshot: SnapshotRegion | None,
) -> tuple[bytes, str] | None:
    if snapshot and snapshot.start_rva <= rva:
        offset = rva - snapshot.start_rva
        if offset + size <= len(snapshot.data):
            return snapshot.data[offset:offset + size], "snapshot"
    offset = rva_to_offset(rva, sections)
    if offset is not None and offset + size <= len(image):
        return image[offset:offset + size], "pe_raw"
    return None


def read_c_string(data: bytes, offset: int, limit: int = 256) -> str:
    end = offset
    maximum = min(len(data), offset + limit)
    while end < maximum and data[end] != 0:
        end += 1
    return data[offset:end].decode("ascii", errors="replace")


def parse_pe(data: bytes) -> dict[str, Any]:
    if len(data) < 0x100 or data[:2] != b"MZ":
        raise ValueError("not a PE/MZ image")
    pe_offset = u32(data, 0x3C)
    if data[pe_offset:pe_offset + 4] != b"PE\0\0":
        raise ValueError("PE signature not found")
    coff = pe_offset + 4
    machine = u16(data, coff)
    section_count = u16(data, coff + 2)
    optional_size = u16(data, coff + 16)
    optional = coff + 20
    magic = u16(data, optional)
    if magic == 0x20B:
        image_base = struct.unpack_from("<Q", data, optional + 24)[0]
        data_directory = optional + 112
        pe_kind = "PE32+"
    elif magic == 0x10B:
        image_base = u32(data, optional + 28)
        data_directory = optional + 96
        pe_kind = "PE32"
    else:
        raise ValueError(f"unknown optional-header magic 0x{magic:X}")
    exception_rva = u32(data, data_directory + 3 * 8)
    exception_size = u32(data, data_directory + 3 * 8 + 4)
    sections: list[Section] = []
    section_table = optional + optional_size
    for index in range(section_count):
        offset = section_table + index * 40
        name = read_c_string(data, offset, 8)
        virtual_size = u32(data, offset + 8)
        va = u32(data, offset + 12)
        raw_size = u32(data, offset + 16)
        raw_ptr = u32(data, offset + 20)
        sections.append(Section(name, va, virtual_size, raw_size, raw_ptr))
    return {
        "machine": f"0x{machine:04X}",
        "pe_kind": pe_kind,
        "image_base": f"0x{image_base:X}",
        "exception_rva": exception_rva,
        "exception_size": exception_size,
        "sections": sections,
    }


def parse_runtime_functions(
    data: bytes,
    sections: list[Section],
    exception_rva: int,
    exception_size: int,
    snapshot: SnapshotRegion | None,
) -> tuple[list[dict[str, int]], str]:
    if exception_rva == 0 or exception_size == 0:
        return [], "absent"
    mapped = read_rva(data, sections, exception_rva, exception_size, snapshot)
    if mapped is None:
        raise ValueError("exception directory RVA does not map to captured memory or PE raw data")
    directory, mapping_mode = mapped
    count = exception_size // 12
    functions = []
    for index in range(count):
        row = index * 12
        begin = u32(directory, row)
        end = u32(directory, row + 4)
        unwind = u32(directory, row + 8)
        if begin == 0 and end == 0 and unwind == 0:
            continue
        functions.append({"begin_rva": begin, "end_rva": end, "unwind_rva": unwind})
    return functions, mapping_mode


def parse_unwind_info(
    data: bytes,
    sections: list[Section],
    unwind_rva: int,
    snapshot: SnapshotRegion | None,
    depth: int = 0,
) -> dict[str, Any]:
    if depth > 8:
        return {"unwind_rva": f"0x{unwind_rva:X}", "parsed": False, "error": "chain recursion limit"}
    mapped_header = read_rva(data, sections, unwind_rva, 4, snapshot)
    if mapped_header is None:
        return {"unwind_rva": f"0x{unwind_rva:X}", "parsed": False, "error": "unwind RVA unmapped"}
    header, mapping_mode = mapped_header
    version_flags = header[0]
    version = version_flags & 0x7
    flags = version_flags >> 3
    if version not in (1, 2):
        return {
            "unwind_rva": f"0x{unwind_rva:X}",
            "parsed": False,
            "mapping_mode": mapping_mode,
            "error": f"invalid UNWIND_INFO version {version}",
        }
    prolog_size = header[1]
    code_count = header[2]
    frame = header[3]
    frame_register = frame & 0x0F
    frame_offset = frame >> 4
    mapped_codes = read_rva(data, sections, unwind_rva + 4, code_count * 2, snapshot)
    if mapped_codes is None:
        return {"unwind_rva": f"0x{unwind_rva:X}", "parsed": False, "error": "unwind codes unmapped"}
    code_bytes, code_mapping = mapped_codes
    if code_mapping != mapping_mode:
        return {"unwind_rva": f"0x{unwind_rva:X}", "parsed": False, "error": "split unwind mapping source"}
    codes = []
    for index in range(code_count):
        item = index * 2
        op = code_bytes[item + 1] & 0x0F
        info = code_bytes[item + 1] >> 4
        codes.append({"code_offset": code_bytes[item], "unwind_op": op, "op_info": info})
    trailer_rva = unwind_rva + 4 + ((code_count + 1) & ~1) * 2
    result: dict[str, Any] = {
        "unwind_rva": f"0x{unwind_rva:X}",
        "parsed": True,
        "mapping_mode": mapping_mode,
        "version": version,
        "flags": flags,
        "prolog_size": prolog_size,
        "frame_register": frame_register,
        "frame_offset": frame_offset,
        "codes": codes,
    }
    if flags & UNW_FLAG_CHAININFO:
        mapped_chain = read_rva(data, sections, trailer_rva, 12, snapshot)
        if mapped_chain is not None:
            trailer, trailer_mapping = mapped_chain
            if trailer_mapping != mapping_mode:
                result["parsed"] = False
                result["error"] = "split chained unwind mapping source"
                return result
            chained = {
                "begin_rva": u32(trailer, 0),
                "end_rva": u32(trailer, 4),
                "unwind_rva": u32(trailer, 8),
            }
            result["chained_runtime_function"] = {
                "begin_rva": f"0x{chained['begin_rva']:X}",
                "end_rva": f"0x{chained['end_rva']:X}",
                "unwind_rva": f"0x{chained['unwind_rva']:X}",
                "unwind_info": parse_unwind_info(data, sections, chained["unwind_rva"], snapshot, depth + 1),
            }
        else:
            result["parsed"] = False
            result["error"] = "chained runtime function past EOF"
    elif flags & (UNW_FLAG_EHANDLER | UNW_FLAG_UHANDLER):
        mapped_handler = read_rva(data, sections, trailer_rva, 4, snapshot)
        if mapped_handler is not None:
            handler_bytes, handler_mapping = mapped_handler
            if handler_mapping != mapping_mode:
                result["parsed"] = False
                result["error"] = "split handler unwind mapping source"
                return result
            handler_rva = u32(handler_bytes, 0)
            result["handler_rva"] = f"0x{handler_rva:X}"
            result["handler_flags"] = {
                "exception_handler": bool(flags & UNW_FLAG_EHANDLER),
                "termination_handler": bool(flags & UNW_FLAG_UHANDLER),
            }
            handler_data_rva = trailer_rva + 4
            result["handler_data_rva"] = f"0x{handler_data_rva:X}"
            identify_handler(
                result,
                data,
                sections,
                handler_rva,
                handler_data_rva,
                snapshot,
            )
        else:
            result["parsed"] = False
            result["error"] = "handler RVA past EOF"
    return result


def _matches_gs_handler_check(code: bytes) -> bool:
    """Match the stable x64 __GSHandlerCheck wrapper around its rel32 call."""
    return (
        len(code) >= 29
        and code[:14] == bytes.fromhex("4883ec284d8b4138488bca498bd1")
        and code[14] == 0xE8
        and code[19:29] == bytes.fromhex("b8010000004883c428c3")
    )


def identify_handler(
    unwind: dict[str, Any],
    data: bytes,
    sections: list[Section],
    handler_rva: int,
    handler_data_rva: int,
    snapshot: SnapshotRegion | None,
) -> None:
    mapped_code = read_rva(data, sections, handler_rva, 29, snapshot)
    if mapped_code is None or not _matches_gs_handler_check(mapped_code[0]):
        unwind["handler_identification"] = {
            "status": "unknown",
            "reason": "handler bytes do not match an audited signature",
        }
        unwind["language_specific_data_parsed"] = False
        return

    mapped_data = read_rva(data, sections, handler_data_rva, 4, snapshot)
    if mapped_data is None:
        unwind["handler_symbol"] = "__GSHandlerCheck"
        unwind["handler_identification"] = {
            "status": "identified",
            "method": "exact x64 wrapper signature with rel32 wildcard",
        }
        unwind["language_specific_data_parsed"] = False
        return

    encoded = u32(mapped_data[0], 0)
    cookie_offset = encoded & ~0x7
    aligned_frame = bool(encoded & 0x4)
    handler_data: dict[str, Any] = {
        "schema": "msvc-gs-handler-data/1.0",
        "mapping_mode": mapped_data[1],
        "encoded_offset_and_flags": f"0x{encoded:08X}",
        "cookie_offset": cookie_offset,
        "flags": {
            "unknown_bit_0": bool(encoded & 0x1),
            "unknown_bit_1": bool(encoded & 0x2),
            "aligned_frame": aligned_frame,
        },
        "size": 4,
    }
    if encoded & 0x3:
        handler_data["parsed"] = False
        handler_data["error"] = "unrecognized __GSHandlerCheck flag bits"
    elif aligned_frame:
        mapped_alignment = read_rva(data, sections, handler_data_rva + 4, 8, snapshot)
        if mapped_alignment is None or mapped_alignment[1] != mapped_data[1]:
            handler_data["parsed"] = False
            handler_data["error"] = "aligned-frame GS data is unmapped or split"
        else:
            handler_data["aligned_base_offset"] = struct.unpack_from(
                "<i", mapped_alignment[0], 0
            )[0]
            handler_data["alignment"] = u32(mapped_alignment[0], 4)
            handler_data["size"] = 12
            handler_data["parsed"] = True
    else:
        handler_data["parsed"] = True

    unwind["handler_symbol"] = "__GSHandlerCheck"
    unwind["handler_kind"] = "gs_cookie_check_only"
    unwind["handler_identification"] = {
        "status": "identified",
        "method": "exact x64 wrapper signature with rel32 wildcard",
    }
    unwind["handler_data"] = handler_data
    unwind["language_specific_data_parsed"] = handler_data.get("parsed") is True


def find_runtime_function(functions: list[dict[str, int]], rva: int) -> dict[str, int] | None:
    for function in functions:
        if function["begin_rva"] <= rva < function["end_rva"]:
            return function
    return None


def runtime_functions_for_interval(
    functions: list[dict[str, int]], start_rva: int, end_rva: int
) -> list[dict[str, int]]:
    return [
        function
        for function in functions
        if function["begin_rva"] < end_rva and start_rva < function["end_rva"]
    ]


def interval_gaps(
    fragments: list[dict[str, int]], start_rva: int, end_rva: int
) -> list[dict[str, str]]:
    gaps = []
    cursor = start_rva
    for fragment in sorted(fragments, key=lambda item: item["begin_rva"]):
        begin = max(start_rva, fragment["begin_rva"])
        end = min(end_rva, fragment["end_rva"])
        if begin > cursor:
            gaps.append({"start_rva": f"0x{cursor:X}", "end_rva": f"0x{begin:X}"})
        cursor = max(cursor, end)
    if cursor < end_rva:
        gaps.append({"start_rva": f"0x{cursor:X}", "end_rva": f"0x{end_rva:X}"})
    return gaps


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--image", required=True, type=Path)
    parser.add_argument("--snapshot", type=Path, help="SnapshotTool log containing loaded RVA bytes")
    parser.add_argument("--snapshot-phase", default="BEFORE_EXIT")
    parser.add_argument(
        "--function",
        action="append",
        default=[],
        help="name=0xSTART:0xEND (END exclusive), name=0xENTRY, or bare RVA; repeatable",
    )
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()

    data = args.image.read_bytes()
    errors: list[str] = []
    try:
        snapshot = parse_snapshot(args.snapshot, args.snapshot_phase) if args.snapshot else None
        pe = parse_pe(data)
        runtime_functions, exception_mapping = parse_runtime_functions(
            data,
            pe["sections"],
            pe["exception_rva"],
            pe["exception_size"],
            snapshot,
        )
    except Exception as error:
        result = {
            "schema": SCHEMA,
            "passed": False,
            "target": {"path": str(args.image), "sha256": sha256(args.image)},
            "errors": [str(error)],
        }
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
        print(json.dumps(result, indent=2), end="\n")
        return 2

    parsed_unwind: dict[int, dict[str, Any]] = {}
    for function in runtime_functions:
        unwind_rva = function["unwind_rva"]
        if unwind_rva not in parsed_unwind:
            parsed_unwind[unwind_rva] = parse_unwind_info(
                data, pe["sections"], unwind_rva, snapshot
            )

    requested = [parse_function_arg(raw) for raw in args.function]
    function_reports = []
    for requested_function in requested:
        entry_rva = int(requested_function["entry_rva"])
        end_rva = requested_function.get("end_rva")
        runtime = find_runtime_function(runtime_functions, entry_rva)
        mapped = runtime is not None
        interval_fragments = (
            runtime_functions_for_interval(runtime_functions, entry_rva, int(end_rva))
            if end_rva is not None
            else ([runtime] if runtime else [])
        )
        gaps = interval_gaps(interval_fragments, entry_rva, int(end_rva)) if end_rva is not None else []
        fragments = []
        for fragment in interval_fragments:
            unwind = parsed_unwind.get(fragment["unwind_rva"])
            fragments.append(
                {
                    "begin_rva": f"0x{fragment['begin_rva']:X}",
                    "end_rva": f"0x{fragment['end_rva']:X}",
                    "unwind_rva": f"0x{fragment['unwind_rva']:X}",
                    "unwind_info": unwind,
                }
            )
        unknown_unwind = any(
            not (isinstance(item["unwind_info"], dict) and item["unwind_info"].get("parsed") is True)
            for item in fragments
        ) or not fragments
        unknown_handlers = any(
            isinstance(item["unwind_info"], dict)
            and item["unwind_info"].get("handler_rva")
            and not item["unwind_info"].get("handler_symbol")
            for item in fragments
        )
        unknown_lsd = any(
            isinstance(item["unwind_info"], dict)
            and item["unwind_info"].get("language_specific_data_parsed") is False
            for item in fragments
        )
        interval_complete = end_rva is not None and not gaps
        function_reports.append(
            {
                "name": requested_function["name"],
                "entry_rva": f"0x{entry_rva:X}",
                "end_rva": f"0x{int(end_rva):X}" if end_rva is not None else None,
                "function_covered": mapped and (interval_complete if end_rva is not None else True),
                "runtime_function_mapped": mapped,
                "runtime_function": (
                    {
                        "begin_rva": f"0x{runtime['begin_rva']:X}",
                        "end_rva": f"0x{runtime['end_rva']:X}",
                        "unwind_rva": f"0x{runtime['unwind_rva']:X}",
                    }
                    if runtime
                    else None
                ),
                "runtime_fragments": fragments,
                "interval_gaps": gaps,
                "unknown_unwind_info": unknown_unwind,
                "unknown_handlers": unknown_handlers,
                "unknown_language_specific_data": unknown_lsd,
            }
        )

    serialized_runtime = [
        {
            "begin_rva": f"0x{function['begin_rva']:X}",
            "end_rva": f"0x{function['end_rva']:X}",
            "unwind_rva": f"0x{function['unwind_rva']:X}",
        }
        for function in runtime_functions
    ]
    passed = not errors and all(
        item["function_covered"]
        and item["runtime_function_mapped"]
        and not item["unknown_unwind_info"]
        and not item["unknown_handlers"]
        and not item["unknown_language_specific_data"]
        for item in function_reports
    )
    result = {
        "schema": SCHEMA,
        "passed": passed,
        "target": {"path": str(args.image), "sha256": sha256(args.image)},
        "snapshot": (
            {
                "path": str(snapshot.path),
                "sha256": sha256(snapshot.path),
                "phase": snapshot.phase,
                "base": f"0x{snapshot.base:X}",
                "start_rva": f"0x{snapshot.start_rva:X}",
                "end_rva": f"0x{snapshot.start_rva + len(snapshot.data) - 1:X}",
            }
            if snapshot
            else None
        ),
        "pe": {
            "machine": pe["machine"],
            "kind": pe["pe_kind"],
            "image_base": pe["image_base"],
        },
        "exception_directory": {
            "parsed": True,
            "rva": f"0x{pe['exception_rva']:X}",
            "size": pe["exception_size"],
            "runtime_function_count": len(runtime_functions),
            "mapping_mode": exception_mapping,
        },
        "runtime_functions": serialized_runtime,
        "functions": function_reports,
        "errors": errors,
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(result, indent=2), end="\n")
    return 0 if passed else 2


if __name__ == "__main__":
    raise SystemExit(main())
