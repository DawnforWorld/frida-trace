from __future__ import annotations

import hashlib
import re
import struct
from fractions import Fraction
from typing import Any

import z3
from triton import AST_NODE, CPUSIZE, MemoryAccess


SCHEMA = "triton-sse2-ieee-model/1.0"
_SCALAR_BINARY = {"addsd", "subsd", "mulsd", "divsd"}


def _xmm_value(snapshot: dict[str, Any], name: str) -> int:
    return int.from_bytes(bytes.fromhex(snapshot["xmm"][name]), "little")


def _f64_parts(bits: int) -> tuple[int, int, int]:
    return bits >> 63, (bits >> 52) & 0x7FF, bits & ((1 << 52) - 1)


def _is_nan(bits: int) -> bool:
    _, exponent, fraction = _f64_parts(bits)
    return exponent == 0x7FF and fraction != 0


def _is_snan(bits: int) -> bool:
    return _is_nan(bits) and (bits & (1 << 51)) == 0


def _is_inf(bits: int) -> bool:
    _, exponent, fraction = _f64_parts(bits)
    return exponent == 0x7FF and fraction == 0


def _is_zero(bits: int) -> bool:
    return bits & 0x7FFFFFFFFFFFFFFF == 0


def _is_subnormal(bits: int) -> bool:
    _, exponent, fraction = _f64_parts(bits)
    return exponent == 0 and fraction != 0


def _quiet_nan(bits: int) -> int:
    return bits | (1 << 51)


def _propagated_nan(left: int, right: int) -> int:
    if _is_snan(left):
        return _quiet_nan(left)
    if _is_snan(right):
        return _quiet_nan(right)
    if _is_nan(left):
        return left
    if _is_nan(right):
        return right
    return 0xFFF8000000000000


def _fraction(bits: int) -> Fraction:
    sign, exponent, significand = _f64_parts(bits)
    if exponent == 0:
        value = Fraction(significand, 1 << 1074)
    else:
        value = Fraction((1 << 52) | significand, 1 << 52)
        shift = exponent - 1023
        value = value * (1 << shift) if shift >= 0 else value / (1 << -shift)
    return -value if sign else value


def _rounding_mode(mxcsr: int) -> Any:
    return (z3.RNE(), z3.RTN(), z3.RTP(), z3.RTZ())[(mxcsr >> 13) & 3]


def _daz(bits: int, mxcsr: int) -> int:
    if mxcsr & (1 << 6) and _is_subnormal(bits):
        return bits & (1 << 63)
    return bits


def _z3_f64(bits: int) -> Any:
    return z3.fpBVToFP(z3.BitVecVal(bits, 64), z3.Float64())


def _ast_has_variable(node: Any) -> bool:
    seen: set[tuple[int, int]] = set()
    pending = [node]
    while pending:
        current = pending.pop()
        node_type = int(current.getType())
        if node_type == AST_NODE.REFERENCE:
            key = (node_type, current.getSymbolicExpression().getId())
        else:
            key = (node_type, int(current.getHash()))
        if key in seen:
            continue
        seen.add(key)
        if node_type == AST_NODE.VARIABLE:
            return True
        if node_type == AST_NODE.REFERENCE:
            pending.append(current.getSymbolicExpression().getAst())
        else:
            pending.extend(current.getChildren())
    return False


def _z3_scalar_result(mnemonic: str, left: int, right: int, mxcsr: int) -> int:
    if _is_nan(left) or _is_nan(right):
        return _propagated_nan(left, right)
    invalid = (
        mnemonic in {"addsd", "subsd"} and _is_inf(left) and _is_inf(right)
        and ((left ^ right) >> 63) == (1 if mnemonic == "addsd" else 0)
    ) or (
        mnemonic == "mulsd" and ((_is_zero(left) and _is_inf(right)) or (_is_inf(left) and _is_zero(right)))
    ) or (
        mnemonic == "divsd" and ((_is_zero(left) and _is_zero(right)) or (_is_inf(left) and _is_inf(right)))
    )
    if invalid:
        return 0xFFF8000000000000
    lhs = _z3_f64(left)
    rhs = _z3_f64(right)
    operation = {
        "addsd": z3.fpAdd,
        "subsd": z3.fpSub,
        "mulsd": z3.fpMul,
        "divsd": z3.fpDiv,
    }[mnemonic]
    result = z3.simplify(z3.fpToIEEEBV(operation(_rounding_mode(mxcsr), lhs, rhs)))
    if not z3.is_bv_value(result):
        raise RuntimeError(f"Z3 did not reduce concrete {mnemonic} to IEEE bits")
    return result.as_long()


def _exception_flags(mnemonic: str, left: int, right: int, result: int, mxcsr: int) -> int:
    flags = 0
    if _is_subnormal(left) or _is_subnormal(right):
        flags |= 1 << 1
    invalid = _is_snan(left) or _is_snan(right)
    if mnemonic in {"addsd", "subsd"}:
        invalid |= _is_inf(left) and _is_inf(right) and (
            ((left ^ right) >> 63) == (1 if mnemonic == "addsd" else 0)
        )
    elif mnemonic == "mulsd":
        invalid |= (_is_zero(left) and _is_inf(right)) or (_is_inf(left) and _is_zero(right))
    elif mnemonic == "divsd":
        invalid |= (_is_zero(left) and _is_zero(right)) or (_is_inf(left) and _is_inf(right))
        if not invalid and not _is_nan(left) and not _is_nan(right) and not _is_zero(left) and _is_zero(right):
            flags |= 1 << 2
    if invalid:
        flags |= 1
        return flags
    if _is_nan(left) or _is_nan(right) or _is_inf(left) or _is_inf(right):
        return flags

    lhs = _fraction(left)
    rhs = _fraction(right)
    exact = {
        "addsd": lambda: lhs + rhs,
        "subsd": lambda: lhs - rhs,
        "mulsd": lambda: lhs * rhs,
        "divsd": lambda: lhs / rhs,
    }[mnemonic]()
    maximum = _fraction(0x7FEFFFFFFFFFFFFF)
    overflow = abs(exact) > maximum
    if overflow:
        flags |= (1 << 3) | (1 << 5)
        return flags
    rounded = _fraction(result) if not _is_inf(result) else None
    inexact = rounded is None or rounded != exact
    tiny = _is_subnormal(result) or _is_zero(result)
    if inexact:
        flags |= 1 << 5
        if tiny:
            flags |= 1 << 4
    return flags


def _source_bits(event: dict[str, Any], operand: str) -> int:
    operand = operand.strip()
    if re.fullmatch(r"xmm\d+", operand):
        return _xmm_value(event["extended_regs"], operand) & ((1 << 64) - 1)
    for memory in event.get("memory", []):
        if "r" in memory.get("access", ""):
            before = bytes.fromhex(memory["before"])
            if len(before) >= 8:
                return int.from_bytes(before[:8], "little")
    raise RuntimeError(f"cannot resolve SSE2 source operand {operand!r}")


def _source_ast(context: Any, event: dict[str, Any], operand: str) -> tuple[Any, bool, bool]:
    ast = context.getAstContext()
    operand = operand.strip()
    if re.fullmatch(r"xmm\d+", operand):
        register = getattr(context.registers, operand)
        node = ast.extract(63, 0, context.getRegisterAst(register))
        return (
            node,
            context.isRegisterSymbolized(register) or _ast_has_variable(node),
            context.isRegisterTainted(register),
        )
    for memory in event.get("memory", []):
        if "r" in memory.get("access", ""):
            address = int(memory["addr"], 16)
            access = MemoryAccess(address, CPUSIZE.QWORD)
            node = context.getMemoryAst(access)
            return (
                node,
                context.isMemorySymbolized(access) or _ast_has_variable(node),
                context.isMemoryTainted(access),
            )
    raise RuntimeError(f"cannot resolve symbolic SSE2 source operand {operand!r}")


def _fp_formula(context: Any, mnemonic: str, left_ast: Any, right_ast: Any, mxcsr: int) -> tuple[str, str]:
    ast = context.getAstContext()
    left = ast.tritonToZ3(left_ast)
    right = ast.tritonToZ3(right_ast)
    left = z3.BitVecRef(left.as_ast(), left.ctx)
    right = z3.BitVecRef(right.as_ast(), right.ctx)
    operation = {
        "addsd": z3.fpAdd,
        "subsd": z3.fpSub,
        "mulsd": z3.fpMul,
        "divsd": z3.fpDiv,
    }[mnemonic]
    formula = z3.fpToIEEEBV(
        operation(
            _rounding_mode(mxcsr),
            z3.fpBVToFP(left, z3.Float64()),
            z3.fpBVToFP(right, z3.Float64()),
        )
    )
    text = formula.sexpr()
    return text, hashlib.sha256(text.encode("utf-8")).hexdigest().upper()


def _assign_xmm(context: Any, name: str, value: int, symbolic: bool, tainted: bool, seq: int) -> None:
    register = getattr(context.registers, name)
    if symbolic:
        parent = context.getParentRegister(register)
        variable = context.symbolizeRegister(parent, f"sse2_seq_{seq}_{name}")
        context.setConcreteVariableValue(variable, value)
    else:
        context.setConcreteRegisterValue(register, value)
    context.setTaintRegister(register, tainted)


def _assign_flag(context: Any, name: str, node: Any, tainted: bool, seq: int) -> None:
    register = getattr(context.registers, name)
    expression = context.newSymbolicExpression(node, f"modeled COMISD {name} seq {seq}")
    context.assignSymbolicExpressionToRegister(expression, register)
    context.setTaintRegister(register, tainted)


def _compare_flag_nodes(context: Any, left: Any, right: Any) -> dict[str, Any]:
    ast = context.getAstContext()
    zero64 = ast.bv(0, 64)
    exp_mask = ast.bv(0x7FF, 11)
    frac_zero = ast.bv(0, 52)
    left_nan = ast.land([
        ast.equal(ast.extract(62, 52, left), exp_mask),
        ast.distinct(ast.extract(51, 0, left), frac_zero),
    ])
    right_nan = ast.land([
        ast.equal(ast.extract(62, 52, right), exp_mask),
        ast.distinct(ast.extract(51, 0, right), frac_zero),
    ])
    unordered = ast.lor([left_nan, right_nan])
    left_zero = ast.equal(left & ast.bv(0x7FFFFFFFFFFFFFFF, 64), zero64)
    right_zero = ast.equal(right & ast.bv(0x7FFFFFFFFFFFFFFF, 64), zero64)
    equal = ast.lor([ast.equal(left, right), ast.land([left_zero, right_zero])])
    left_sign = ast.extract(63, 63, left)
    right_sign = ast.extract(63, 63, right)
    signs_differ = ast.distinct(left_sign, right_sign)
    negative_left = ast.equal(left_sign, ast.bv(1, 1))
    same_sign_less = ast.ite(negative_left, ast.bvugt(left, right), ast.bvult(left, right))
    less = ast.ite(signs_differ, ast.land([negative_left, ast.lnot(ast.land([left_zero, right_zero]))]), same_sign_less)
    one = ast.bv(1, 1)
    zero = ast.bv(0, 1)
    return {
        "zf": ast.ite(ast.lor([unordered, equal]), one, zero),
        "pf": ast.ite(unordered, one, zero),
        "cf": ast.ite(ast.lor([unordered, less]), one, zero),
        "of": zero,
        "sf": zero,
        "af": zero,
    }


def model_sse2_instruction(context: Any, event: dict[str, Any]) -> dict[str, Any] | None:
    disassembly = event["disasm"].lower()
    match = re.fullmatch(r"([a-z0-9]+)\s+([^,]+),\s*(.+)", disassembly)
    if not match:
        return None
    mnemonic, destination, source = match.groups()
    if mnemonic not in _SCALAR_BINARY | {"cvtdq2pd", "comisd"}:
        return None

    seq = int(event["seq"])
    mxcsr_before = int(event["extended_regs"]["mxcsr"], 16)
    mxcsr_expected = int(event["post_extended_regs"]["mxcsr"], 16)
    expected_pc = int(event["flow"]["next"], 16)
    evidence: dict[str, Any] = {
        "schema": SCHEMA,
        "seq": seq,
        "rva": event["rva"],
        "instruction": event["disasm"],
        "mxcsr_before": f"0x{mxcsr_before:08X}",
    }

    if mnemonic in _SCALAR_BINARY:
        left = _xmm_value(event["extended_regs"], destination) & ((1 << 64) - 1)
        right = _source_bits(event, source)
        left_effective = _daz(left, mxcsr_before)
        right_effective = _daz(right, mxcsr_before)
        result = _z3_scalar_result(mnemonic, left_effective, right_effective, mxcsr_before)
        flags = _exception_flags(mnemonic, left, right, result, mxcsr_before)
        if mxcsr_before & (1 << 15) and _is_subnormal(result):
            result &= 1 << 63
            flags |= (1 << 4) | (1 << 5)
        unmasked = flags & ~((mxcsr_before >> 7) & 0x3F)
        if unmasked:
            raise RuntimeError(f"unmasked SSE2 exception at seq {seq} is not represented as a normal post-state")
        mxcsr_after = mxcsr_before | flags
        destination_before = _xmm_value(event["extended_regs"], destination)
        destination_after = (destination_before & (~((1 << 64) - 1))) | result
        expected_after = _xmm_value(event["post_extended_regs"], destination)
        if destination_after != expected_after:
            raise RuntimeError(
                f"IEEE model mismatch at seq {seq}: expected XMM 0x{expected_after:032X}, modeled 0x{destination_after:032X}"
            )
        left_ast, left_symbolic, left_tainted = _source_ast(context, event, destination)
        right_ast, right_symbolic, right_tainted = _source_ast(context, event, source)
        formula, formula_hash = _fp_formula(context, mnemonic, left_ast, right_ast, mxcsr_before)
        _assign_xmm(
            context,
            destination,
            destination_after,
            left_symbolic or right_symbolic,
            left_tainted or right_tainted,
            seq,
        )
        evidence.update(
            {
                "operand_bits": [f"0x{left:016X}", f"0x{right:016X}"],
                "result_bits": f"0x{result:016X}",
                "z3_fpa_formula": formula,
                "z3_fpa_formula_sha256": formula_hash,
                "triton_bridge": "opaque result variable with hash-bound Z3 FPA definition",
                "exception_flags": f"0x{flags:02X}",
            }
        )
    elif mnemonic == "cvtdq2pd":
        source_value = _xmm_value(event["extended_regs"], source)
        first = struct.unpack("<i", (source_value & 0xFFFFFFFF).to_bytes(4, "little"))[0]
        second = struct.unpack("<i", ((source_value >> 32) & 0xFFFFFFFF).to_bytes(4, "little"))[0]
        first_bits = struct.unpack("<Q", struct.pack("<d", float(first)))[0]
        second_bits = struct.unpack("<Q", struct.pack("<d", float(second)))[0]
        destination_after = first_bits | (second_bits << 64)
        expected_after = _xmm_value(event["post_extended_regs"], destination)
        if destination_after != expected_after:
            raise RuntimeError(f"CVTDQ2PD model mismatch at seq {seq}")
        source_register = getattr(context.registers, source)
        _assign_xmm(
            context,
            destination,
            destination_after,
            context.isRegisterSymbolized(source_register),
            context.isRegisterTainted(source_register),
            seq,
        )
        evidence.update(
            {
                "signed_inputs": [first, second],
                "result_bits": f"0x{destination_after:032X}",
                "triton_bridge": "opaque result variable with exact signed-int32 conversion provenance",
            }
        )
        mxcsr_after = mxcsr_before
    else:
        left = _xmm_value(event["extended_regs"], destination) & ((1 << 64) - 1)
        right = _source_bits(event, source)
        unordered = _is_nan(left) or _is_nan(right)
        if unordered:
            zf = pf = cf = 1
        else:
            lhs = _fraction(left) if not _is_inf(left) else (-float("inf") if left >> 63 else float("inf"))
            rhs = _fraction(right) if not _is_inf(right) else (-float("inf") if right >> 63 else float("inf"))
            zf, pf, cf = int(lhs == rhs), 0, int(lhs < rhs)
        flags = 1 if unordered else 0
        if flags and not (mxcsr_before & (1 << 7)):
            raise RuntimeError(f"unmasked COMISD invalid exception at seq {seq}")
        mxcsr_after = mxcsr_before | flags
        left_ast, left_symbolic, left_tainted = _source_ast(context, event, destination)
        right_ast, right_symbolic, right_tainted = _source_ast(context, event, source)
        flag_nodes = _compare_flag_nodes(context, left_ast, right_ast)
        for name, node in flag_nodes.items():
            _assign_flag(context, name, node, left_tainted or right_tainted, seq)
        actual = {
            name: context.getConcreteRegisterValue(getattr(context.registers, name))
            for name in ("zf", "pf", "cf", "of", "sf", "af")
        }
        expected = {"zf": zf, "pf": pf, "cf": cf, "of": 0, "sf": 0, "af": 0}
        if actual != expected:
            raise RuntimeError(f"COMISD symbolic flag model mismatch at seq {seq}: {actual} != {expected}")
        evidence.update(
            {
                "operand_bits": [f"0x{left:016X}", f"0x{right:016X}"],
                "flags": expected,
                "symbolic_compare": left_symbolic or right_symbolic,
                "triton_compare_ast": "exact IEEE ordered/unordered bit-vector predicate",
            }
        )

    if mxcsr_after != mxcsr_expected:
        raise RuntimeError(
            f"MXCSR model mismatch at seq {seq}: expected 0x{mxcsr_expected:08X}, modeled 0x{mxcsr_after:08X}"
        )
    context.setConcreteRegisterValue(context.registers.mxcsr, mxcsr_after)
    context.setConcreteRegisterValue(context.registers.rip, expected_pc)
    evidence["mxcsr_after"] = f"0x{mxcsr_after:08X}"
    evidence["concrete_exact_match"] = True
    return evidence
