from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
import time
from pathlib import Path
from typing import Any

try:
    from triton import AST_NODE, ARCH, CPUSIZE, EXCEPTION, MODE, Instruction, MemoryAccess, TritonContext
except ImportError as error:
    raise SystemExit(
        "triton-library is missing; run scripts\\bootstrap_triton.py with Windows CPython 3.14"
    ) from error

from trace_scan import scan_trace
from trace_io import open_trace_text
from sse2_ieee import model_sse2_instruction


REGISTER_MAP = {
    "rax": "rax",
    "rbx": "rbx",
    "rcx": "rcx",
    "rdx": "rdx",
    "rsi": "rsi",
    "rdi": "rdi",
    "rbp": "rbp",
    "rsp": "rsp",
    "r8": "r8",
    "r9": "r9",
    "r10": "r10",
    "r11": "r11",
    "r12": "r12",
    "r13": "r13",
    "r14": "r14",
    "r15": "r15",
    "rflags": "eflags",
}

FLAG_REGISTERS = (
    "cf",
    "pf",
    "af",
    "zf",
    "sf",
    "tf",
    "if",
    "df",
    "of",
    "nt",
    "rf",
    "ac",
    "vif",
    "vip",
    "id",
)

RFLAGS_ARCHITECTURAL_MASK = 0x0000FFFFFFFFFFFF
VOLATILE_GPRS = ("rax", "rcx", "rdx", "r8", "r9", "r10", "r11", "eflags", "rip")
VOLATILE_TRACE_GPRS = {"rax", "rcx", "rdx", "r8", "r9", "r10", "r11", "rflags"}
MODELED_BOUNDARY_TRACE_GPRS = VOLATILE_TRACE_GPRS | {"rsp"}
MODELED_BOUNDARY_TRITON_REGISTERS = VOLATILE_GPRS + ("rsp",)
VOLATILE_VECTORS = tuple(f"xmm{index}" for index in range(6))
MXCSR_STATUS_MASK = 0x003F
MXCSR_CONTROL_MASK = 0xFFC0


def _value(value: str) -> int:
    return int(value, 16)


def _vector_value(value: str) -> int:
    return int.from_bytes(bytes.fromhex(value), "little")


def _extended_snapshot_items(snapshot: dict[str, Any]) -> dict[str, int]:
    if set(snapshot) != {"mxcsr", "xmm"} or not isinstance(snapshot["xmm"], dict):
        raise ValueError("pintrace-jsonl/2.0 requires extended_regs={mxcsr,xmm}")
    xmm = snapshot["xmm"]
    required = {f"xmm{index}" for index in range(16)}
    if set(xmm) != required:
        raise ValueError("pintrace-jsonl/2.0 requires xmm0-xmm15")
    items = {"mxcsr": _value(snapshot["mxcsr"])}
    items.update({name: _vector_value(xmm[name]) for name in sorted(required)})
    return items


def _flag_semantics(event: dict[str, Any]) -> tuple[int, int, int]:
    semantics = event.get("rflags_semantics")
    if not isinstance(semantics, dict):
        raise ValueError("pintrace-jsonl/2.0 requires rflags_semantics")
    try:
        return (
            _value(semantics["read_mask"]),
            _value(semantics["written_mask"]),
            _value(semantics["undefined_mask"]),
        )
    except (KeyError, TypeError, ValueError) as error:
        raise ValueError("invalid pintrace-jsonl/2.0 rflags_semantics") from error


def _parse_input(value: str) -> tuple[int, bytes]:
    try:
        address_text, hex_bytes = value.split(":", 1)
        return int(address_text, 0), bytes.fromhex(hex_bytes)
    except (ValueError, TypeError) as error:
        raise argparse.ArgumentTypeError("input must be ADDRESS:HEXBYTES") from error


def _parse_goal(value: str) -> tuple[int, str, int]:
    try:
        seq_text, register, target_text = value.split(":", 2)
        return int(seq_text, 0), register.lower(), int(target_text, 0)
    except (ValueError, TypeError) as error:
        raise argparse.ArgumentTypeError("goal must be SEQ:REGISTER:VALUE") from error


def _parse_memory_goal(value: str) -> tuple[int, int, int, int | None]:
    try:
        parts = value.split(":")
        if len(parts) not in (3, 4):
            raise ValueError
        seq_text, address_text, size_text = parts[:3]
        target = int(parts[3], 0) if len(parts) == 4 else None
        size = int(size_text, 0)
        if size not in (1, 2, 4, 8, 16, 32, 64):
            raise ValueError
        if target is not None and not 0 <= target < (1 << (size * 8)):
            raise ValueError
        return int(seq_text, 0), int(address_text, 0), size, target
    except (ValueError, TypeError) as error:
        raise argparse.ArgumentTypeError(
            "memory goal must be SEQ:ADDRESS:SIZE[:VALUE]"
        ) from error


def _parse_source_register(value: str) -> tuple[str, int, str]:
    try:
        register, raw_value, name = value.split(":", 2)
        return register.lower(), int(raw_value, 0), name
    except (ValueError, TypeError) as error:
        raise argparse.ArgumentTypeError(
            "source-register must be REGISTER:VALUE:NAME"
        ) from error


def _parse_source_memory(value: str) -> tuple[int, bytes, str]:
    try:
        address, raw_bytes, name = value.split(":", 2)
        return int(address, 0), bytes.fromhex(raw_bytes), name
    except (ValueError, TypeError) as error:
        raise argparse.ArgumentTypeError(
            "source-memory must be ADDRESS:HEXBYTES:NAME"
        ) from error


def _pc_field(path_constraint: Any, name: str, default: Any = None) -> Any:
    method = getattr(path_constraint, name, None)
    return method() if method else default


def _ast_variable_ids(node: Any) -> set[int]:
    variables: set[int] = set()
    visited: set[tuple[int, int]] = set()
    pending = [node]
    while pending:
        current = pending.pop()
        node_type = int(current.getType())
        if node_type == AST_NODE.REFERENCE:
            node_key = (node_type, current.getSymbolicExpression().getId())
        elif node_type == AST_NODE.VARIABLE:
            node_key = (node_type, current.getSymbolicVariable().getId())
        else:
            node_key = (node_type, int(current.getHash()))
        if node_key in visited:
            continue
        visited.add(node_key)
        if node_type == AST_NODE.VARIABLE:
            variables.add(current.getSymbolicVariable().getId())
        elif node_type == AST_NODE.REFERENCE:
            pending.append(current.getSymbolicExpression().getAst())
        else:
            pending.extend(current.getChildren())
    return variables


def _sync_registers(
    context: TritonContext,
    snapshot: dict[str, str],
    first: bool,
    strict: bool,
    counters: dict[str, int],
    examples: list[dict[str, Any]],
    event: dict[str, Any],
    previous_undefined_mask: int,
    modeled_boundary: bool = False,
) -> None:
    current_read_mask, _, _ = _flag_semantics(event)
    if not first and current_read_mask & previous_undefined_mask:
        raise RuntimeError(
            f"undefined RFLAGS dependency at seq {event['seq']} RVA {event['rva']} "
            f"({event['disasm']}): read=0x{current_read_mask:x} "
            f"previous_undefined=0x{previous_undefined_mask:x}"
        )
    for trace_name, triton_name in REGISTER_MAP.items():
        register = getattr(context.registers, triton_name)
        expected = _value(snapshot[trace_name])
        actual = context.getConcreteRegisterValue(register)
        if first:
            if context.isRegisterSymbolized(register):
                if actual != expected:
                    raise RuntimeError(
                        f"explicit source {trace_name} seed does not match first trace state"
                    )
            else:
                context.setConcreteRegisterValue(register, expected)
            continue

        symbolic = context.isRegisterSymbolized(register)
        if trace_name == "rflags":
            symbolic = any(context.isRegisterSymbolized(getattr(context.registers, name))
                           for name in FLAG_REGISTERS if hasattr(context.registers, name))

        if modeled_boundary and trace_name in MODELED_BOUNDARY_TRACE_GPRS:
            if actual != expected:
                counters["modeled_external_register_updates"] += 1
            context.setConcreteRegisterValue(register, expected)
            continue
        if modeled_boundary:
            counters["modeled_external_nonvolatile_register_checks"] += 1
        if symbolic:
            diverged = actual != expected
            if trace_name == "rflags":
                reliable_mask = RFLAGS_ARCHITECTURAL_MASK & ~previous_undefined_mask
                diverged = bool((actual ^ expected) & reliable_mask)
            if diverged:
                counters["symbolic_register_divergences"] += 1
                if len(examples) < 20:
                    examples.append(
                        {
                            "kind": "symbolic_register",
                            "register": trace_name,
                            "expected": f"0x{expected:x}",
                            "actual": f"0x{actual:x}",
                        }
                    )
                if strict:
                    raise RuntimeError(
                        f"symbolic {trace_name} diverged at seq {event['seq']} "
                        f"RVA {event['rva']}: expected 0x{expected:x}, got 0x{actual:x}"
                    )
        else:
            compare_mask = (
                RFLAGS_ARCHITECTURAL_MASK & ~previous_undefined_mask
                if trace_name == "rflags"
                else (1 << 64) - 1
            )
            if ((actual ^ expected) & compare_mask) != 0:
                counters["concrete_register_resyncs"] += 1
                if len(examples) < 20:
                    examples.append(
                        {
                            "kind": "concrete_register",
                            "register": trace_name,
                            "expected": f"0x{expected:x}",
                            "actual": f"0x{actual:x}",
                        }
                    )
                if strict:
                    raise RuntimeError(
                        f"concrete {trace_name} diverged at seq {event['seq']} "
                        f"RVA {event['rva']}: expected 0x{expected:x}, got 0x{actual:x}"
                    )
            if trace_name != "rflags" or compare_mask == RFLAGS_ARCHITECTURAL_MASK:
                context.setConcreteRegisterValue(register, expected)


def _sync_memory(
    context: TritonContext,
    event: dict[str, Any],
    strict: bool,
    counters: dict[str, int],
    examples: list[dict[str, Any]],
    modeled_boundary: bool = False,
) -> None:
    for memory in event["memory"]:
        address = _value(memory["addr"])
        expected = bytes.fromhex(memory["before"])
        for offset, byte_value in enumerate(expected):
            current = address + offset
            access = MemoryAccess(current, CPUSIZE.BYTE)
            if context.isMemorySymbolized(access):
                actual = context.getConcreteMemoryValue(access)
                if actual != byte_value:
                    counters["symbolic_memory_divergences"] += 1
                    if len(examples) < 20:
                        examples.append(
                            {
                                "kind": "symbolic_memory",
                                "address": f"0x{current:x}",
                                "expected": f"0x{byte_value:02x}",
                                "actual": f"0x{actual:02x}",
                            }
                        )
                    if strict:
                        raise RuntimeError(
                            f"symbolic memory 0x{current:x} diverged: expected {byte_value:02x}, got {actual:02x}"
                        )
            else:
                if modeled_boundary:
                    if context.isMemorySymbolized(access):
                        actual = context.getConcreteMemoryValue(access)
                        if actual != byte_value:
                            raise RuntimeError(
                                f"modeled external boundary changed symbolic memory 0x{current:x}"
                            )
                    else:
                        context.setConcreteMemoryValue(access, byte_value)
                    continue
                if context.isConcreteMemoryValueDefined(current, 1):
                    actual = context.getConcreteMemoryValue(access)
                    if actual != byte_value:
                        counters["concrete_memory_resyncs"] += 1
                        if len(examples) < 20:
                            examples.append(
                                {
                                    "kind": "concrete_memory",
                                    "address": f"0x{current:x}",
                                    "expected": f"0x{byte_value:02x}",
                                    "actual": f"0x{actual:02x}",
                                }
                            )
                        if strict:
                            raise RuntimeError(
                                f"concrete memory 0x{current:x} diverged: "
                                f"expected {byte_value:02x}, got {actual:02x}"
                            )
                context.setConcreteMemoryValue(access, byte_value)


def _verify_writes(
    context: TritonContext,
    event: dict[str, Any],
    strict: bool,
    counters: dict[str, int],
    examples: list[dict[str, Any]],
) -> None:
    if not event["flow"]["post_state"]:
        return
    for memory in event["memory"]:
        if "w" not in memory["access"] or memory.get("after") is None:
            continue
        address = _value(memory["addr"])
        expected = bytes.fromhex(memory["after"])
        actual = bytes(context.getConcreteMemoryAreaValue(address, len(expected)))
        if actual != expected:
            counters["write_divergences"] += 1
            if len(examples) < 20:
                examples.append(
                    {
                        "kind": "write",
                        "seq": event["seq"],
                        "rva": event["rva"],
                        "address": memory["addr"],
                        "expected": expected.hex(),
                        "actual": actual.hex(),
                    }
                )
            if strict:
                raise RuntimeError(
                    f"write divergence at seq {event['seq']} address {memory['addr']}"
                )


def _input_carriers(
    context: TritonContext,
    input_variable_ids: set[int],
    input_address: int,
    input_size: int,
    dependency_cache: dict[int, set[int]],
) -> tuple[set[int], list[str]]:
    variables: set[int] = set()
    carriers: list[str] = []

    for register_id, expression in context.getSymbolicRegisters().items():
        expression_id = expression.getId()
        dependencies = dependency_cache.get(expression_id)
        if dependencies is None:
            dependencies = _ast_variable_ids(expression.getAst())
            dependency_cache[expression_id] = dependencies
        dependencies = dependencies.intersection(input_variable_ids)
        if dependencies:
            variables.update(dependencies)
            carriers.append(context.getRegister(register_id).getName())

    for address, expression in context.getSymbolicMemory().items():
        if input_address <= address < input_address + input_size:
            continue
        expression_id = expression.getId()
        dependencies = dependency_cache.get(expression_id)
        if dependencies is None:
            dependencies = _ast_variable_ids(expression.getAst())
            dependency_cache[expression_id] = dependencies
        dependencies = dependencies.intersection(input_variable_ids)
        if dependencies:
            variables.update(dependencies)
            carriers.append(f"mem@0x{address:x}")

    return variables, carriers


def _taint_carriers(context: TritonContext) -> list[str]:
    carriers = [
        register.getName() for register in context.getTaintedRegisters()
    ]
    carriers.extend(
        f"mem@0x{int(address):x}" for address in context.getTaintedMemory()
    )
    return sorted(set(carriers))


UNCAPTURED_STATE_TOKENS = (
    "xmm",
    "ymm",
    "zmm",
    "mxcsr",
    "st(",
    "st0",
    "st1",
    "st2",
    "st3",
    "st4",
    "st5",
    "st6",
    "st7",
)


def _uses_uncaptured_state(disassembly: str) -> bool:
    lowered = disassembly.lower()
    if any(token in lowered for token in UNCAPTURED_STATE_TOKENS):
        return True
    words = lowered.replace(",", " ").replace("[", " ").replace("]", " ").split()
    return any(word in {f"k{index}" for index in range(8)} for word in words)


def _uncaptured_state_reason(
    context: TritonContext, event: dict[str, Any]
) -> str | None:
    disassembly = event["disasm"].lower()
    vector_names = set(re.findall(r"\b(?:xmm|ymm|zmm)\d+\b", disassembly))
    opmask_names = set(re.findall(r"\bk[0-7]\b", disassembly))
    uses_x87 = any(
        token in disassembly
        for token in ("st(", "st0", "st1", "st2", "st3", "st4", "st5", "st6", "st7")
    )
    if opmask_names:
        return "Triton binding does not expose AVX-512 opmask state"
    if uses_x87:
        return "Triton binding does not expose complete x87 control/status/tag state"
    if not vector_names and "mxcsr" not in disassembly:
        return None
    extended = event.get("extended_regs")
    if not isinstance(extended, dict):
        return "trace lacks extended_regs for vector/MXCSR semantics"
    flat_extended = _extended_snapshot_items(extended)
    missing = sorted(
        name
        for name in vector_names | {"mxcsr"}
        if name not in flat_extended or not hasattr(context.registers, name)
    )
    if missing:
        return f"trace/Triton lacks extended register state: {', '.join(missing)}"
    return None


def _sync_extended_registers(
    context: TritonContext,
    event: dict[str, Any],
    first: bool,
    strict: bool,
    counters: dict[str, int],
    examples: list[dict[str, Any]],
    modeled_boundary: bool = False,
) -> None:
    snapshot = event.get("extended_regs")
    if not isinstance(snapshot, dict):
        return
    for name, expected in _extended_snapshot_items(snapshot).items():
        if not hasattr(context.registers, name):
            if strict:
                raise RuntimeError(f"Triton has no register for extended state {name}")
            continue
        register = getattr(context.registers, name)
        actual = context.getConcreteRegisterValue(register)
        if first:
            if context.isRegisterSymbolized(register):
                if actual != expected:
                    raise RuntimeError(
                        f"explicit extended source {name} seed does not match first trace state"
                    )
            else:
                context.setConcreteRegisterValue(register, expected)
            continue
        if modeled_boundary and name == "mxcsr":
            if (actual ^ expected) & MXCSR_CONTROL_MASK:
                counters["extended_register_resyncs"] += 1
                if len(examples) < 20:
                    examples.append(
                        {
                            "kind": "mxcsr_control",
                            "register": name,
                            "expected": f"0x{expected:x}",
                            "actual": f"0x{actual:x}",
                            "control_mask": f"0x{MXCSR_CONTROL_MASK:x}",
                        }
                    )
                if strict:
                    raise RuntimeError(
                        f"MXCSR control bits diverged across modeled external boundary at seq {event['seq']}"
                    )
            if (actual ^ expected) & MXCSR_STATUS_MASK:
                counters["modeled_external_mxcsr_status_updates"] += 1
            context.setConcreteRegisterValue(register, expected)
            continue
        if modeled_boundary and name in VOLATILE_VECTORS:
            if actual != expected:
                counters["modeled_external_vector_updates"] += 1
            context.setConcreteRegisterValue(register, expected)
            continue
        if modeled_boundary:
            counters["modeled_external_nonvolatile_vector_checks"] += 1
        if context.isRegisterSymbolized(register):
            if actual != expected:
                counters["symbolic_register_divergences"] += 1
                if strict:
                    raise RuntimeError(
                        f"symbolic extended register {name} diverged"
                    )
            continue
        if actual != expected:
            counters["extended_register_resyncs"] += 1
            if len(examples) < 20:
                examples.append(
                    {
                        "kind": "extended_register",
                        "register": name,
                        "expected": f"0x{expected:x}",
                        "actual": f"0x{actual:x}",
                    }
                )
            if strict:
                raise RuntimeError(f"extended register {name} diverged")
        context.setConcreteRegisterValue(register, expected)


def _solve_input_model(
    context: TritonContext,
    predicate: Any,
    input_variables: list[Any],
    seed: bytes,
) -> dict[str, Any]:
    result: dict[str, Any] = {"sat": bool(context.isSat(predicate))}
    if not result["sat"]:
        return result
    model = context.getModel(predicate)
    solved = bytearray(seed)
    for index, variable in enumerate(input_variables):
        if variable.getId() in model:
            solved[index] = model[variable.getId()].getValue()
    result["model_hex"] = bytes(solved).hex()
    return result


def _logical_or(ast: Any, nodes: list[Any]) -> Any:
    if not nodes:
        raise ValueError("logical OR requires at least one node")
    return nodes[0] if len(nodes) == 1 else ast.lor(nodes)


def _simplify_ast(
    context: TritonContext,
    node: Any,
    ast_dir: Path | None,
    stem: str,
) -> dict[str, Any]:
    ast = context.getAstContext()
    raw = ast.unroll(node)
    simplified = context.simplify(raw, True, False)
    raw_text = str(raw)
    simplified_text = str(simplified)
    distinct = ast.distinct(raw, simplified)
    equivalent = not bool(context.isSat(distinct))
    if not equivalent:
        raise RuntimeError("Triton simplification changed AST semantics")
    result: dict[str, Any] = {
        "raw_ast_length": len(raw_text),
        "simplified_ast_length": len(simplified_text),
        "raw_ast_sha256": hashlib.sha256(raw_text.encode("utf-8")).hexdigest().upper(),
        "simplified_ast_sha256": hashlib.sha256(
            simplified_text.encode("utf-8")
        ).hexdigest().upper(),
        "simplification_equivalent": equivalent,
        "raw_ast_preview": raw_text[:500],
        "simplified_ast_preview": simplified_text[:500],
    }
    if ast_dir:
        ast_dir.mkdir(parents=True, exist_ok=True)
        raw_path = ast_dir / f"{stem}.raw.smt2"
        simplified_path = ast_dir / f"{stem}.simplified.smt2"
        raw_path.write_text(raw_text + "\n", encoding="utf-8")
        simplified_path.write_text(simplified_text + "\n", encoding="utf-8")
        result["raw_ast_path"] = str(raw_path)
        result["simplified_ast_path"] = str(simplified_path)
    return result


def _slice_summary(context: TritonContext, expression: Any) -> dict[str, Any]:
    sliced = context.sliceExpressions(expression)
    serialized = "\n".join(
        f"{expression_id}:{symbolic_expression}"
        for expression_id, symbolic_expression in sorted(sliced.items())
    )
    return {
        "expression_ids": sorted(int(expression_id) for expression_id in sliced),
        "tainted_expression_ids": sorted(
            int(expression_id)
            for expression_id, symbolic_expression in sliced.items()
            if symbolic_expression.isTainted()
        ),
        "expression_count": len(sliced),
        "slice_sha256": hashlib.sha256(serialized.encode("utf-8")).hexdigest().upper(),
    }


def _memory_slice_summary(
    context: TritonContext, address: int, size: int
) -> dict[str, Any] | None:
    expressions: dict[int, Any] = {}
    for current in range(address, address + size):
        expression = context.getSymbolicMemory(current)
        if expression is not None:
            expressions.update(context.sliceExpressions(expression))
    if not expressions:
        return None
    serialized = "\n".join(
        f"{expression_id}:{symbolic_expression}"
        for expression_id, symbolic_expression in sorted(expressions.items())
    )
    return {
        "expression_ids": sorted(int(expression_id) for expression_id in expressions),
        "tainted_expression_ids": sorted(
            int(expression_id)
            for expression_id, symbolic_expression in expressions.items()
            if symbolic_expression.isTainted()
        ),
        "expression_count": len(expressions),
        "slice_sha256": hashlib.sha256(serialized.encode("utf-8")).hexdigest().upper(),
    }


def replay(args: argparse.Namespace) -> dict[str, Any]:
    if not hasattr(args, "concrete_input"):
        args.concrete_input = False
    if args.strict and args.through_external:
        raise RuntimeError(
            "strict replay cannot cross opaque external calls; split the window or add a tested model"
        )
    trace_path = args.trace.resolve()
    image_path = args.image.resolve() if args.image else None
    scan = scan_trace(trace_path, image_path)
    if scan["trace"]["source_schema"] != "pintrace-jsonl/2.0":
        raise RuntimeError(
            "strict latest replay requires a supplied pintrace-jsonl/2.0 trace"
        )

    if args.input:
        input_address, seed = args.input
    else:
        pointer = scan["input"]["pointer"]
        seed_hex = scan["input"]["seed_hex"]
        if not pointer or not seed_hex:
            if not args.source_register and not args.source_memory:
                raise RuntimeError("could not discover argv[1]; provide --input ADDRESS:HEXBYTES or explicit sources")
            input_address, seed = 0x1000, b"\x00"
        else:
            input_address = int(pointer, 16)
            seed = bytes.fromhex(seed_hex)

    input_reads = scan["input"]["reads"]
    default_start = min((int(item["seq"]) for item in input_reads), default=1)
    start_seq = args.start_seq or default_start
    selected_tid = int(scan["trace"]["selected_tid"])

    context = TritonContext(ARCH.X86_64)
    context.setMode(MODE.AST_OPTIMIZATIONS, True)
    context.setMode(MODE.CONSTANT_FOLDING, True)
    context.setMode(MODE.CONCRETIZE_UNDEFINED_REGISTERS, True)
    context.setMode(MODE.ONLY_ON_SYMBOLIZED, True)
    context.setMode(MODE.PC_TRACKING_SYMBOLIC, True)
    context.setMode(MODE.SYMBOLIZE_LOAD, True)
    context.setMode(MODE.SYMBOLIZE_STORE, True)
    context.setSolverTimeout(args.solver_timeout)

    context.setConcreteMemoryAreaValue(input_address, seed)
    input_variables = []
    source_variables = []
    if not args.concrete_input:
        for index, byte_value in enumerate(seed):
            access = MemoryAccess(input_address + index, CPUSIZE.BYTE)
            variable = context.symbolizeMemory(access, f"argv1_{index}")
            context.setConcreteVariableValue(variable, byte_value)
            context.taintMemory(access)
            input_variables.append(variable)
    for register_name, value, name in args.source_register:
        register = getattr(context.registers, register_name)
        context.setConcreteRegisterValue(register, value)
        variable = context.symbolizeRegister(register, name)
        context.setConcreteVariableValue(variable, value)
        context.taintRegister(register)
        source_variables.append((variable, value, register_name))
    for address, source_bytes, name in args.source_memory:
        context.setConcreteMemoryAreaValue(address, source_bytes)
        for index, byte_value in enumerate(source_bytes):
            access = MemoryAccess(address + index, CPUSIZE.BYTE)
            variable = context.symbolizeMemory(access, f"{name}_{index}")
            context.setConcreteVariableValue(variable, byte_value)
            context.taintMemory(access)
            source_variables.append((variable, byte_value, f"0x{address + index:x}"))
    input_variable_ids = {
        variable.getId() for variable in input_variables
    } | {variable.getId() for variable, _, _ in source_variables}

    counters = {
        "processed": 0,
        "skipped_before_start": 0,
        "unsupported_instructions": 0,
        "modeled_floating_instructions": 0,
        "floating_model_failures": 0,
        "modeled_external_boundaries": 0,
        "modeled_external_register_updates": 0,
        "modeled_external_vector_updates": 0,
        "modeled_external_mxcsr_status_updates": 0,
        "modeled_external_nonvolatile_register_checks": 0,
        "modeled_external_nonvolatile_vector_checks": 0,
        "pc_divergences": 0,
        "symbolic_register_divergences": 0,
        "symbolic_memory_divergences": 0,
        "concrete_register_resyncs": 0,
        "concrete_memory_resyncs": 0,
        "extended_register_resyncs": 0,
        "write_divergences": 0,
        "external_syncs": 0,
        "path_constraints": 0,
        "input_dependent_constraints": 0,
        "symbolic_pc_events": 0,
        "synthetic_pc_constraints": 0,
        "uncaptured_state_instructions": 0,
        "branch_solver_failures": 0,
        "simplification_failures": 0,
    }
    divergence_examples: list[dict[str, Any]] = []
    unsupported_examples: list[dict[str, Any]] = []
    floating_model_events: list[dict[str, Any]] = []
    input_constraints: list[dict[str, Any]] = []
    branch_constraints: list[dict[str, Any]] = []
    goal_results: list[dict[str, Any]] = []
    goal_nodes: list[Any | None] = []
    goals_by_seq: dict[int, list[tuple[str, int]]] = {}
    for goal_seq, goal_register, goal_value in args.goal:
        goals_by_seq.setdefault(goal_seq, []).append((goal_register, goal_value))
    memory_goals_by_seq: dict[int, list[tuple[int, int, int | None]]] = {}
    for goal_seq, goal_address, goal_size, goal_value in args.memory_goal:
        memory_goals_by_seq.setdefault(goal_seq, []).append(
            (goal_address, goal_size, goal_value)
        )
    dataflow_transitions: list[dict[str, Any]] = []
    dependency_cache: dict[int, set[int]] = {}
    previous_active_variables: set[int] = set()
    previous_carriers: set[str] = set()
    previous_taint_carriers: set[str] = set()
    first = True
    stop_reason = "end_of_trace"
    started_at = time.monotonic()
    last_seq = 0
    last_rva: str | None = None
    undefined_flag_state_mask = 0

    with open_trace_text(trace_path) as stream:
        for line in stream:
            event = json.loads(line)
            if event.get("type") != "instruction" or int(event["tid"]) != selected_tid:
                continue
            seq = int(event["seq"])
            if seq < start_seq:
                counters["skipped_before_start"] += 1
                continue
            if args.max_instructions and counters["processed"] >= args.max_instructions:
                stop_reason = "max_instructions"
                break
            if args.stop_seq and seq > args.stop_seq:
                stop_reason = "stop_seq"
                break
            if args.stop_at_external and event["flow"].get("external"):
                stop_reason = "external_call"
                break

            modeled_boundary = bool(
                args.model_external and event.get("sync") == "external_return"
            )
            if modeled_boundary:
                for name in MODELED_BOUNDARY_TRITON_REGISTERS + VOLATILE_VECTORS:
                    if hasattr(context.registers, name):
                        context.concretizeRegister(getattr(context.registers, name))
            if event.get("sync") == "external_return":
                counters["external_syncs"] += 1
                if modeled_boundary:
                    counters["external_syncs"] -= 1
                    counters["modeled_external_boundaries"] += 1

            _sync_registers(
                context,
                event["regs"],
                first,
                args.strict,
                counters,
                divergence_examples,
                event,
                undefined_flag_state_mask,
                modeled_boundary,
            )
            _sync_extended_registers(
                context,
                event,
                first,
                args.strict,
                counters,
                divergence_examples,
                modeled_boundary,
            )
            _sync_memory(
                context,
                event,
                args.strict,
                counters,
                divergence_examples,
                modeled_boundary,
            )
            if modeled_boundary:
                for register_name in args.external_return_register:
                    register = getattr(context.registers, register_name)
                    expected = (
                        _extended_snapshot_items(event["extended_regs"])[register_name]
                        if register_name.startswith("xmm")
                        else _value(event["regs"][register_name])
                    )
                    variable = context.symbolizeRegister(
                        register,
                        f"external_seq_{seq}_{register_name}",
                    )
                    context.setConcreteVariableValue(variable, expected)
                    context.taintRegister(register)
                    source_variables.append((variable, expected, f"external:{seq}:{register_name}"))
                    input_variable_ids.add(variable.getId())

            context.setConcreteRegisterValue(context.registers.rip, _value(event["addr"]))
            uncaptured_reason = _uncaptured_state_reason(context, event)
            if uncaptured_reason:
                counters["uncaptured_state_instructions"] += 1
                unsupported_examples.append(
                    {
                        "seq": seq,
                        "rva": event["rva"],
                        "instruction": event["disasm"],
                        "fault": uncaptured_reason,
                    }
                )
                if args.strict:
                    raise RuntimeError(
                        f"uncaptured machine state at seq {seq}: "
                        f"{event['disasm']} ({uncaptured_reason})"
                    )
            instruction = Instruction(bytes.fromhex(event["bytes"]))
            instruction.setAddress(_value(event["addr"]))
            before_constraints = len(context.getPathConstraints())
            path_prefix = context.getPathPredicate()
            fault = context.processing(instruction)
            modeled_floating = None
            if fault != EXCEPTION.NO_FAULT:
                try:
                    modeled_floating = model_sse2_instruction(context, event)
                except Exception as error:
                    counters["floating_model_failures"] += 1
                    if len(unsupported_examples) < 50:
                        unsupported_examples.append(
                            {
                                "seq": seq,
                                "rva": event["rva"],
                                "instruction": event["disasm"],
                                "fault": "floating-model-error",
                                "detail": str(error),
                            }
                        )
                    if args.strict:
                        raise RuntimeError(
                            f"exact SSE2 model failed at seq {seq}: {event['disasm']}: {error}"
                        ) from error
                if modeled_floating is not None:
                    counters["modeled_floating_instructions"] += 1
                    floating_model_events.append(modeled_floating)
                    fault = EXCEPTION.NO_FAULT
            if fault != EXCEPTION.NO_FAULT:
                counters["unsupported_instructions"] += 1
                if len(unsupported_examples) < 50:
                    unsupported_examples.append(
                        {
                            "seq": seq,
                            "rva": event["rva"],
                            "instruction": event["disasm"],
                            "fault": int(fault),
                        }
                    )
                if args.strict:
                    raise RuntimeError(
                        f"Triton fault {int(fault)} at seq {seq}: {event['disasm']}"
                    )
            _, written_flag_mask, instruction_undefined_mask = _flag_semantics(event)
            undefined_flag_state_mask = (
                (undefined_flag_state_mask & ~written_flag_mask)
                | instruction_undefined_mask
            )

            actual_pc = context.getConcreteRegisterValue(context.registers.rip)
            expected_pc = _value(event["flow"]["next"])
            if actual_pc != expected_pc:
                counters["pc_divergences"] += 1
                if len(divergence_examples) < 20:
                    divergence_examples.append(
                        {
                            "kind": "pc",
                            "seq": seq,
                            "rva": event["rva"],
                            "instruction": event["disasm"],
                            "expected": f"0x{expected_pc:x}",
                            "actual": f"0x{actual_pc:x}",
                        }
                    )
                if args.strict:
                    raise RuntimeError(f"symbolic PC diverged at seq {seq}")

            _verify_writes(context, event, args.strict, counters, divergence_examples)

            if args.track_dataflow:
                active_variables, carriers = _input_carriers(
                    context,
                    input_variable_ids,
                    input_address,
                    len(seed),
                    dependency_cache,
                )
                carrier_set = set(carriers)
                taint_carrier_set = set(_taint_carriers(context))
                if (
                    active_variables != previous_active_variables
                    or carrier_set != previous_carriers
                    or taint_carrier_set != previous_taint_carriers
                ) and len(dataflow_transitions) < 2000:
                    dataflow_transitions.append(
                        {
                            "seq": seq,
                            "rva": event["rva"],
                            "instruction": event["disasm"],
                            "before_variables": sorted(previous_active_variables),
                            "after_variables": sorted(active_variables),
                            "before_carriers": sorted(previous_carriers)[:100],
                            "after_carriers": sorted(carrier_set)[:100],
                            "before_taint_carriers": sorted(previous_taint_carriers)[:100],
                            "after_taint_carriers": sorted(taint_carrier_set)[:100],
                        }
                    )
                previous_active_variables = active_variables
                previous_carriers = carrier_set
                previous_taint_carriers = taint_carrier_set

            path_constraints = context.getPathConstraints()
            automatic_input_constraint = False
            for path_constraint in path_constraints[before_constraints:]:
                counters["path_constraints"] += 1
                predicate = path_constraint.getTakenPredicate()
                variable_ids = _ast_variable_ids(predicate)
                input_ids = sorted(variable_ids.intersection(input_variable_ids))
                if input_ids:
                    automatic_input_constraint = True
                    counters["input_dependent_constraints"] += 1
                try:
                    predicate_ast = _simplify_ast(
                        context,
                        predicate,
                        args.ast_dir,
                        f"constraint_{seq}_{event['rva']}",
                    )
                except Exception as error:
                    counters["simplification_failures"] += 1
                    if args.strict:
                        raise RuntimeError(
                            f"could not simplify branch predicate at seq {seq}: {error}"
                        ) from error
                    predicate_ast = {"simplification_error": str(error)}

                item = {
                    "seq": seq,
                    "rva": event["rva"],
                    "instruction": event["disasm"],
                    "source": _pc_field(path_constraint, "getSourceAddress"),
                    "destination": _pc_field(path_constraint, "getTakenAddress"),
                    "variables": input_ids,
                    "ast_length": len(str(predicate)),
                }
                item.update(predicate_ast)
                ast = context.getAstContext()
                alternatives = []
                prefix = path_prefix
                prefix_unrolled = ast.unroll(prefix)
                prefix_sha256 = hashlib.sha256(
                    str(prefix_unrolled).encode("utf-8")
                ).hexdigest().upper()
                taken_predicate = None
                for branch in path_constraint.getBranchConstraints():
                    branch_predicate = branch["constraint"]
                    branch_unrolled = ast.unroll(branch_predicate)
                    branch_variables = sorted(
                        _ast_variable_ids(branch_predicate).intersection(input_variable_ids)
                    )
                    alternative = {
                        "is_taken": bool(branch["isTaken"]),
                        "source": branch["srcAddr"],
                        "destination": branch["dstAddr"],
                        "variables": branch_variables,
                        "predicate_sha256": hashlib.sha256(
                            str(branch_unrolled).encode("utf-8")
                        ).hexdigest().upper(),
                        "path_prefix_sha256": prefix_sha256,
                    }
                    if args.solve_branches:
                        try:
                            alternative.update(
                                _solve_input_model(
                                    context,
                                    ast.land([prefix, branch_predicate]),
                                    input_variables,
                                    seed,
                                )
                            )
                        except Exception as error:
                            counters["branch_solver_failures"] += 1
                            alternative["solver_error"] = str(error)
                            if args.strict:
                                raise RuntimeError(
                                    f"could not solve branch at seq {seq}: {error}"
                                ) from error
                    alternatives.append(alternative)
                    if branch["isTaken"]:
                        taken_predicate = branch_predicate
                if taken_predicate is None:
                    raise RuntimeError(f"Triton path constraint at seq {seq} has no taken edge")
                # Every sibling edge is solved against the same pre-branch prefix.
                # Only the observed edge is appended for subsequent constraints.
                prefix = ast.land([prefix, taken_predicate])
                item["alternatives"] = alternatives
                item["observed_next"] = expected_pc
                branch_constraints.append(item)
                path_prefix = prefix
                if input_ids:
                    input_constraints.append(item)

            rip_expression = context.getSymbolicRegister(context.registers.rip)
            if rip_expression is not None:
                rip_variables = _ast_variable_ids(rip_expression.getAst()).intersection(
                    input_variable_ids
                )
                if rip_variables:
                    counters["symbolic_pc_events"] += 1
                    if not automatic_input_constraint:
                        ast = context.getAstContext()
                        predicate = ast.equal(rip_expression.getAst(), ast.bv(expected_pc, 64))
                        context.pushPathConstraint(predicate)
                        counters["path_constraints"] += 1
                        counters["input_dependent_constraints"] += 1
                        counters["synthetic_pc_constraints"] += 1
                        item = {
                            "kind": "observed_symbolic_pc",
                            "seq": seq,
                            "rva": event["rva"],
                            "instruction": event["disasm"],
                            "source": _value(event["addr"]),
                            "destination": expected_pc,
                            "variables": sorted(rip_variables),
                            "ast_length": len(str(predicate)),
                        }
                        input_constraints.append(item)
                        if args.ast_dir:
                            args.ast_dir.mkdir(parents=True, exist_ok=True)
                            ast_path = args.ast_dir / f"constraint_{seq}_{event['rva']}.smt2"
                            ast_path.write_text(str(predicate) + "\n", encoding="utf-8")
                            item["ast_path"] = str(ast_path)

            for goal_register, goal_value in goals_by_seq.get(seq, []):
                if not hasattr(context.registers, goal_register):
                    raise RuntimeError(f"unknown Triton register in goal: {goal_register}")
                register = getattr(context.registers, goal_register)
                expression = context.getSymbolicRegister(register)
                register_ast = context.getRegisterAst(register)
                dependencies = sorted(
                    _ast_variable_ids(register_ast).intersection(input_variable_ids)
                )
                goal_item: dict[str, Any] = {
                    "kind": "register",
                    "seq": seq,
                    "rva": event["rva"],
                    "instruction": event["disasm"],
                    "register": goal_register,
                    "target": f"0x{goal_value:x}",
                    "concrete_value": f"0x{context.getConcreteRegisterValue(register):x}",
                    "bit_size": register.getBitSize(),
                    "symbolic": bool(dependencies),
                    "tainted": context.isRegisterTainted(register),
                    "input_variables": dependencies,
                }
                if expression is not None:
                    goal_item["expression_id"] = expression.getId()
                    goal_item["backward_slice"] = _slice_summary(context, expression)
                if dependencies:
                    try:
                        goal_item.update(
                            _simplify_ast(
                                context,
                                register_ast,
                                args.ast_dir,
                                f"goal_{seq}_{goal_register}",
                            )
                        )
                    except Exception as error:
                        counters["simplification_failures"] += 1
                        if args.strict:
                            raise RuntimeError(
                                f"could not simplify register sink at seq {seq}: {error}"
                            ) from error
                        goal_item["simplification_error"] = str(error)
                    if args.ast_dir:
                        args.ast_dir.mkdir(parents=True, exist_ok=True)
                        ast_path = args.ast_dir / f"goal_{seq}_{goal_register}.smt2"
                        expanded_ast = context.getAstContext().unroll(register_ast)
                        ast_path.write_text(str(expanded_ast) + "\n", encoding="utf-8")
                        goal_item["ast_path"] = str(ast_path)
                goal_results.append(goal_item)
                goal_nodes.append(register_ast if dependencies else None)

            for goal_address, goal_size, requested_value in memory_goals_by_seq.get(seq, []):
                access = MemoryAccess(goal_address, goal_size)
                memory_ast = context.getMemoryAst(access)
                concrete_value = context.getConcreteMemoryValue(access)
                dependencies = sorted(
                    _ast_variable_ids(memory_ast).intersection(input_variable_ids)
                )
                goal_value = concrete_value if requested_value is None else requested_value
                goal_item = {
                    "kind": "memory",
                    "seq": seq,
                    "rva": event["rva"],
                    "instruction": event["disasm"],
                    "address": f"0x{goal_address:016x}",
                    "size": goal_size,
                    "target_source": "observed" if requested_value is None else "explicit",
                    "target": f"0x{goal_value:x}",
                    "concrete_value": f"0x{concrete_value:x}",
                    "bit_size": goal_size * 8,
                    "symbolic": bool(dependencies),
                    "tainted": context.isMemoryTainted(access),
                    "input_variables": dependencies,
                }
                try:
                    goal_item.update(
                        _simplify_ast(
                            context,
                            memory_ast,
                            args.ast_dir,
                            f"goal_{seq}_mem_{goal_address:x}_{goal_size}",
                        )
                    )
                except Exception as error:
                    counters["simplification_failures"] += 1
                    if args.strict:
                        raise RuntimeError(
                            f"could not simplify memory sink at seq {seq}: {error}"
                        ) from error
                    goal_item["simplification_error"] = str(error)
                memory_slice = _memory_slice_summary(
                    context, goal_address, goal_size
                )
                if memory_slice is not None:
                    goal_item["backward_slice"] = memory_slice
                if args.ast_dir:
                    args.ast_dir.mkdir(parents=True, exist_ok=True)
                    ast_path = args.ast_dir / f"goal_{seq}_mem_{goal_address:x}_{goal_size}.smt2"
                    expanded_ast = context.getAstContext().unroll(memory_ast)
                    ast_path.write_text(str(expanded_ast) + "\n", encoding="utf-8")
                    goal_item["ast_path"] = str(ast_path)
                goal_results.append(goal_item)
                goal_nodes.append(memory_ast)

            counters["processed"] += 1
            last_seq = seq
            last_rva = event["rva"]
            first = False
            if args.progress and counters["processed"] % args.progress == 0:
                elapsed = time.monotonic() - started_at
                rate = counters["processed"] / elapsed if elapsed else 0.0
                print(
                    f"[replay] seq={seq} processed={counters['processed']} "
                    f"constraints={counters['input_dependent_constraints']} rate={rate:.0f}/s",
                    file=sys.stderr,
                    flush=True,
                )

    solver: dict[str, Any] = {"attempted": False}
    if not args.no_solve and counters["input_dependent_constraints"]:
        solver["attempted"] = True
        try:
            predicate = context.getPathPredicate()
            solver["path_predicate_ast_length"] = len(str(predicate))
            solver["path_is_sat"] = bool(context.isSat(predicate))
            model = context.getModel(predicate)
            solved = bytearray(seed)
            for index, variable in enumerate(input_variables):
                if variable.getId() in model:
                    solved[index] = model[variable.getId()].getValue()
            solver["path_model_hex"] = bytes(solved).hex()
            solver["path_model_text"] = bytes(solved).rstrip(b"\0").decode("ascii", "replace")

            ast = context.getAstContext()
            live_ids = _ast_variable_ids(predicate)
            alternatives = [
                ast.distinct(ast.variable(variable), ast.bv(seed[index], 8))
                for index, variable in enumerate(input_variables)
                if variable.getId() in live_ids
            ]
            if alternatives:
                alternate_query = ast.land([predicate, _logical_or(ast, alternatives)])
                solver["different_input_same_path_is_sat"] = bool(context.isSat(alternate_query))
            else:
                solver["different_input_same_path_is_sat"] = False
            if solver["different_input_same_path_is_sat"]:
                alternate_model = context.getModel(alternate_query)
                alternate = bytearray(seed)
                for index, variable in enumerate(input_variables):
                    if variable.getId() in alternate_model:
                        alternate[index] = alternate_model[variable.getId()].getValue()
                solver["alternate_model_hex"] = bytes(alternate).hex()
        except Exception as error:  # Triton exposes solver failures as runtime exceptions.
            solver["error"] = str(error)

    for goal, goal_ast in zip(goal_results, goal_nodes):
        goal_solver: dict[str, Any] = {"attempted": False}
        goal["solver"] = goal_solver
        if args.no_solve or not goal.get("symbolic") or goal_ast is None:
            continue
        goal_solver["attempted"] = True
        try:
            ast = context.getAstContext()
            target = int(goal["target"], 16)
            query = ast.equal(
                goal_ast, ast.bv(target, int(goal["bit_size"]))
            )
            goal_solver["query_ast_length"] = len(str(query))
            goal_solver["is_sat"] = bool(context.isSat(query))
            if goal_solver["is_sat"]:
                model = context.getModel(query)
                solved = bytearray(seed)
                for index, variable in enumerate(input_variables):
                    if variable.getId() in model:
                        solved[index] = model[variable.getId()].getValue()
                goal_solver["model_hex"] = bytes(solved).hex()
                goal_solver["model_text"] = bytes(solved).rstrip(b"\0").decode(
                    "ascii", "replace"
                )

                alternatives = [
                    ast.distinct(ast.variable(variable), ast.bv(solved[index], 8))
                    for index, variable in enumerate(input_variables)
                    if variable.getId() in _ast_variable_ids(query)
                ]
                if alternatives:
                    alternate_query = ast.land([query, _logical_or(ast, alternatives)])
                    goal_solver["different_input_same_goal_is_sat"] = bool(
                        context.isSat(alternate_query)
                    )
                else:
                    goal_solver["different_input_same_goal_is_sat"] = False
                if goal_solver["different_input_same_goal_is_sat"]:
                    alternate_model = context.getModel(alternate_query)
                    alternate = bytearray(solved)
                    for index, variable in enumerate(input_variables):
                        if variable.getId() in alternate_model:
                            alternate[index] = alternate_model[variable.getId()].getValue()
                    goal_solver["alternate_model_hex"] = bytes(alternate).hex()

                dependent_ids = set(goal.get("input_variables", []))
                dependent_alternatives = [
                    ast.distinct(ast.variable(variable), ast.bv(solved[index], 8))
                    for index, variable in enumerate(input_variables)
                    if variable.getId() in dependent_ids
                ]
                if dependent_alternatives:
                    dependent_difference = (
                        dependent_alternatives[0]
                        if len(dependent_alternatives) == 1
                        else ast.lor(dependent_alternatives)
                    )
                    dependent_query = ast.land(
                        [query, dependent_difference]
                    )
                    goal_solver["different_dependent_input_same_goal_is_sat"] = bool(
                        context.isSat(dependent_query)
                    )
        except Exception as error:
            goal_solver["error"] = str(error)

    combined_goal_solver: dict[str, Any] = {"attempted": False}
    symbolic_goals = [
        (goal, goal_ast)
        for goal, goal_ast in zip(goal_results, goal_nodes)
        if goal.get("symbolic") and goal_ast is not None
    ]
    if not args.no_solve and len(symbolic_goals) > 1:
        combined_goal_solver["attempted"] = True
        try:
            ast = context.getAstContext()
            predicates = [
                ast.equal(
                    goal_ast,
                    ast.bv(int(goal["target"], 16), int(goal["bit_size"])),
                )
                for goal, goal_ast in symbolic_goals
            ]
            query = ast.land(predicates)
            combined_goal_solver["goal_count"] = len(predicates)
            combined_goal_solver["is_sat"] = bool(context.isSat(query))
            if combined_goal_solver["is_sat"]:
                model = context.getModel(query)
                solved = bytearray(seed)
                for index, variable in enumerate(input_variables):
                    if variable.getId() in model:
                        solved[index] = model[variable.getId()].getValue()
                combined_goal_solver["model_hex"] = bytes(solved).hex()
                combined_goal_solver["model_text"] = bytes(solved).rstrip(b"\0").decode(
                    "ascii", "replace"
                )
                alternatives = [
                    ast.distinct(ast.variable(variable), ast.bv(solved[index], 8))
                    for index, variable in enumerate(input_variables)
                    if variable.getId() in _ast_variable_ids(query)
                ]
                if alternatives:
                    alternate_query = ast.land([query, _logical_or(ast, alternatives)])
                    combined_goal_solver["different_input_same_goals_is_sat"] = bool(
                        context.isSat(alternate_query)
                    )
                else:
                    combined_goal_solver["different_input_same_goals_is_sat"] = False
                if combined_goal_solver["different_input_same_goals_is_sat"]:
                    alternate_model = context.getModel(alternate_query)
                    alternate = bytearray(solved)
                    for index, variable in enumerate(input_variables):
                        if variable.getId() in alternate_model:
                            alternate[index] = alternate_model[variable.getId()].getValue()
                    combined_goal_solver["alternate_model_hex"] = bytes(alternate).hex()
        except Exception as error:
            combined_goal_solver["error"] = str(error)

    final_symbolic_registers = []
    for register_id, expression in context.getSymbolicRegisters().items():
        register = context.getRegister(register_id)
        final_symbolic_registers.append(
            {
                "register": register.getName(),
                "expression_id": expression.getId(),
                "ast_preview": str(expression.getAst())[:500],
                "input_variables": sorted(
                    _ast_variable_ids(expression.getAst()).intersection(input_variable_ids)
                ),
            }
        )
    final_symbolic_memory = []
    for address, expression in context.getSymbolicMemory().items():
        dependencies = sorted(
            _ast_variable_ids(expression.getAst()).intersection(input_variable_ids)
        )
        if dependencies:
            final_symbolic_memory.append(
                {
                    "address": f"0x{address:016x}",
                    "expression_id": expression.getId(),
                    "input_variables": dependencies,
                }
            )

    return {
        "schema": "pintrace-triton-replay/1.1",
        "trace": str(trace_path),
        "selected_tid": selected_tid,
        "configuration": {
            "strict": bool(args.strict),
            "solve_branches": bool(args.solve_branches),
            "track_dataflow": bool(args.track_dataflow),
            "through_external": bool(args.through_external),
            "model_external": bool(args.model_external),
            "concrete_input": bool(args.concrete_input),
            "explicit_source_count": len(source_variables),
            "solver_timeout": int(args.solver_timeout),
        },
        "input": {
            "address": f"0x{input_address:016x}",
            "seed_hex": seed.hex(),
            "seed_text": seed.rstrip(b"\0").decode("ascii", "replace"),
            "variables": [
                {"id": variable.getId(), "name": variable.getName(), "seed": seed[index]}
                for index, variable in enumerate(input_variables)
            ],
            "explicit_sources": [
                {
                    "id": variable.getId(),
                    "name": variable.getName(),
                    "value": f"0x{value:x}",
                    "location": location,
                }
                for variable, value, location in source_variables
            ],
        },
        "range": {
            "start_seq": start_seq,
            "last_seq": last_seq,
            "last_rva": last_rva,
            "stop_reason": stop_reason,
        },
        "counters": counters,
        "input_constraints": input_constraints,
        "branch_constraints": branch_constraints,
        "goals": goal_results,
        "taint": {
            "source_byte_count": len(seed),
            "tainted_goal_indices": [
                index for index, goal in enumerate(goal_results) if goal.get("tainted")
            ],
            "tainted_goal_count": sum(
                1 for goal in goal_results if goal.get("tainted")
            ),
        },
        "combined_goal_solver": combined_goal_solver,
        "dataflow_transitions": dataflow_transitions,
        "final_symbolic_state": {
            "registers": final_symbolic_registers,
            "input_dependent_memory": final_symbolic_memory,
            "symbolic_expression_count": len(context.getSymbolicExpressions()),
        },
        "solver": solver,
        "divergence_examples": divergence_examples,
        "unsupported_examples": unsupported_examples,
        "external_model": {
            "enabled": bool(args.model_external),
            "boundary_count": counters["modeled_external_boundaries"],
            "contract": "pintrace external event return state, hash-bound per event",
        },
        "floating_model": {
            "schema": "triton-sse2-ieee-model/1.0",
            "events": floating_model_events,
            "event_count": len(floating_model_events),
        },
        "elapsed_seconds": round(time.monotonic() - started_at, 3),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Trace-guided Triton replay for pintrace-jsonl/2.0.")
    parser.add_argument("trace", type=Path)
    parser.add_argument("--image", type=Path)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--input", type=_parse_input, help="override argv[1] as ADDRESS:HEXBYTES")
    parser.add_argument(
        "--concrete-input",
        action="store_true",
        help="seed --input bytes concretely without symbolizing or tainting them",
    )
    parser.add_argument(
        "--source-register",
        action="append",
        type=_parse_source_register,
        default=[],
        help="symbolize and taint REGISTER:VALUE:NAME",
    )
    parser.add_argument(
        "--source-memory",
        action="append",
        type=_parse_source_memory,
        default=[],
        help="symbolize and taint ADDRESS:HEXBYTES:NAME",
    )
    parser.add_argument("--start-seq", type=int)
    parser.add_argument("--stop-seq", type=int)
    parser.add_argument("--max-instructions", type=int, default=0)
    parser.add_argument("--progress", type=int, default=10000)
    parser.add_argument("--solver-timeout", type=int, default=60000, help="solver timeout in milliseconds")
    parser.add_argument("--strict", action="store_true")
    parser.add_argument("--no-solve", action="store_true")
    parser.add_argument(
        "--solve-branches",
        action="store_true",
        help="solve every observed and alternate path edge from the prior path prefix",
    )
    parser.add_argument("--through-external", action="store_true")
    parser.add_argument(
        "--model-external",
        action="store_true",
        help="cross captured external returns as explicit modeled boundaries",
    )
    parser.add_argument(
        "--external-return-register",
        action="append",
        default=[],
        help="symbolize and taint a modeled external return register, e.g. xmm0",
    )
    parser.add_argument("--ast-dir", type=Path)
    parser.add_argument("--track-dataflow", action="store_true")
    parser.add_argument(
        "--goal",
        action="append",
        type=_parse_goal,
        default=[],
        help="solve a post-instruction register value as SEQ:REGISTER:VALUE",
    )
    parser.add_argument(
        "--memory-goal",
        action="append",
        type=_parse_memory_goal,
        default=[],
        help=(
            "solve a post-instruction memory value as SEQ:ADDRESS:SIZE[:VALUE]; "
            "omitting VALUE uses the observed seed value"
        ),
    )
    args = parser.parse_args()
    args.stop_at_external = not args.through_external and not args.model_external

    report = replay(args)
    rendered = json.dumps(report, indent=2, ensure_ascii=False)
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(rendered + "\n", encoding="utf-8")
    else:
        print(rendered)

    counters = report["counters"]
    fail_closed_counters = (
        "unsupported_instructions",
        "uncaptured_state_instructions",
        "pc_divergences",
        "symbolic_register_divergences",
        "symbolic_memory_divergences",
        "concrete_register_resyncs",
        "concrete_memory_resyncs",
        "extended_register_resyncs",
        "write_divergences",
        "external_syncs",
        "branch_solver_failures",
        "simplification_failures",
    )
    if any(int(counters.get(name, 0)) for name in fail_closed_counters):
        return 2
    if args.strict and report["range"]["stop_reason"] in {
        "max_instructions",
        "external_call",
        "error",
        "incomplete",
    }:
        return 2
    if args.strict and (
        report["solver"].get("error")
        or report["combined_goal_solver"].get("error")
        or any(goal.get("solver", {}).get("error") for goal in report["goals"])
    ):
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
