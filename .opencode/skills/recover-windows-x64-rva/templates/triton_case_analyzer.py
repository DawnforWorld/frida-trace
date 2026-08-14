#!/usr/bin/env python3
"""Per-function Triton analyzer scaffold. Copy into the case and specialize."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

from triton import ARCH, CPUSIZE, EXCEPTION, Instruction, MemoryAccess, TritonContext


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


def sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest().upper()


def restore_boundary(
    context: TritonContext,
    registers: dict[str, int],
    memory: list[tuple[int, bytes]],
) -> None:
    for trace_name, triton_name in REGISTER_MAP.items():
        context.setConcreteRegisterValue(
            getattr(context.registers, triton_name),
            registers[trace_name],
        )
    for address, value in memory:
        context.setConcreteMemoryAreaValue(address, value)


def install_memory_source(
    context: TritonContext,
    address: int,
    value: bytes,
    name: str,
) -> list[Any]:
    context.setConcreteMemoryAreaValue(address, value)
    variables = []
    for index, byte in enumerate(value):
        access = MemoryAccess(address + index, CPUSIZE.BYTE)
        variable = context.symbolizeMemory(access, f"{name}_{index}")
        context.setConcreteVariableValue(variable, byte)
        context.taintMemory(access)
        variables.append(variable)
    return variables


def install_register_source(
    context: TritonContext,
    register: Any,
    value: int,
    name: str,
) -> Any:
    context.setConcreteRegisterValue(register, value)
    variable = context.symbolizeRegister(register, name)
    context.setConcreteVariableValue(variable, value)
    context.taintRegister(register)
    return variable


def replay_exact(context: TritonContext, records: list[dict[str, Any]]) -> None:
    for record in records:
        if record.get("sync") == "external_return":
            raise RuntimeError("opaque external resynchronization is forbidden")
        context.setConcreteRegisterValue(context.registers.rip, int(record["addr"], 16))
        for operand in record["memory"]:
            address = int(operand["addr"], 16)
            before = bytes.fromhex(operand["before"])
            for offset, byte in enumerate(before):
                access = MemoryAccess(address + offset, CPUSIZE.BYTE)
                if not context.isConcreteMemoryValueDefined(address + offset, 1):
                    context.setConcreteMemoryValue(access, byte)
        instruction = Instruction(bytes.fromhex(record["bytes"]))
        instruction.setAddress(int(record["addr"], 16))
        fault = context.processing(instruction)
        if fault != EXCEPTION.NO_FAULT:
            raise RuntimeError(f"Triton fault at sequence {record['seq']}: {int(fault)}")
        actual_pc = context.getConcreteRegisterValue(context.registers.rip)
        expected_pc = int(record["flow"]["next"], 16)
        if actual_pc != expected_pc:
            raise RuntimeError(f"next-PC mismatch at sequence {record['seq']}")
        if record["flow"]["post_state"]:
            for operand in record["memory"]:
                if "w" not in operand["access"] or operand.get("after") is None:
                    continue
                address = int(operand["addr"], 16)
                expected = bytes.fromhex(operand["after"])
                actual = bytes(context.getConcreteMemoryAreaValue(address, len(expected)))
                if actual != expected:
                    raise RuntimeError(f"write mismatch at sequence {record['seq']}")


def prove_sink_ast(
    context: TritonContext,
    sink_ast: Any,
    tainted: bool,
) -> dict[str, Any]:
    ast = context.getAstContext()
    raw = ast.unroll(sink_ast)
    simplified = context.simplify(raw, True, False)
    equivalent = not context.isSat(ast.distinct(raw, simplified))
    if not equivalent:
        raise RuntimeError("simplified sink AST is not equivalent")
    synthesized = context.synthesize(raw)
    synthesis_equivalent = not context.isSat(ast.distinct(raw, synthesized))
    if not synthesis_equivalent:
        raise RuntimeError("synthesized sink AST is not equivalent")
    llvm = context.liftToLLVM(raw)
    dot = context.liftToDot(raw)
    return {
        "tainted": tainted,
        "symbolic": True,
        "raw_ast_sha256": sha256_text(str(raw)),
        "simplified_ast_sha256": sha256_text(str(simplified)),
        "simplification_equivalent": True,
        "synthesized_ast_sha256": sha256_text(str(synthesized)),
        "synthesis_equivalent": True,
        "llvm_sha256": sha256_text(llvm),
        "dot_sha256": sha256_text(dot),
    }


def prove_register_sink(context: TritonContext, register: Any) -> dict[str, Any]:
    result = prove_sink_ast(
        context,
        context.getRegisterAst(register),
        context.isRegisterTainted(register),
    )
    expression = context.getSymbolicRegister(register)
    if expression is None:
        raise RuntimeError(f"register sink {register.getName()} has no symbolic expression")
    result["smt_sha256"] = sha256_text(context.liftToSMT(expression))
    result["python_sha256"] = sha256_text(context.liftToPython(expression))
    sliced = context.sliceExpressions(expression)
    result["slice_expression_ids"] = sorted(sliced)
    result["tainted_slice_expression_ids"] = sorted(
        expression_id
        for expression_id, symbolic_expression in sliced.items()
        if symbolic_expression.isTainted()
    )
    result["slice_sha256"] = sha256_text(
        "\n".join(f"{key}:{value}" for key, value in sorted(sliced.items()))
    )
    return result


def prove_memory_sink(context: TritonContext, address: int, size: int) -> dict[str, Any]:
    access = MemoryAccess(address, size)
    result = prove_sink_ast(
        context,
        context.getMemoryAst(access),
        context.isMemoryTainted(access),
    )
    sliced = {}
    for current in range(address, address + size):
        expression = context.getSymbolicMemory(current)
        if expression is not None:
            sliced.update(context.sliceExpressions(expression))
    result["slice_expression_ids"] = sorted(sliced)
    result["tainted_slice_expression_ids"] = sorted(
        expression_id
        for expression_id, symbolic_expression in sliced.items()
        if symbolic_expression.isTainted()
    )
    result["slice_sha256"] = sha256_text(
        "\n".join(f"{key}:{value}" for key, value in sorted(sliced.items()))
    )
    return result


def solve_alternate_edges(
    context: TritonContext,
    prior_path: Any,
    input_variables: list[Any],
    seed: bytes,
) -> list[dict[str, Any]]:
    ast = context.getAstContext()
    results = []
    context.getPathPredicate()
    prefix = prior_path
    for path in context.getPathConstraints():
        taken_predicate = None
        prefix_sha256 = sha256_text(str(ast.unroll(prefix)))
        for edge in path.getBranchConstraints():
            predicate = edge["constraint"]
            query = ast.land([prefix, predicate])
            sat = bool(context.isSat(query))
            item = {
                "is_taken": bool(edge["isTaken"]),
                "destination": edge["dstAddr"],
                "sat": sat,
                "predicate_sha256": sha256_text(str(ast.unroll(predicate))),
                "path_prefix_sha256": prefix_sha256,
            }
            if sat:
                model = context.getModel(query)
                item["model_count"] = len(context.getModels(query, 2))
                generated = bytearray(seed)
                for index, variable in enumerate(input_variables):
                    if variable.getId() in model:
                        generated[index] = model[variable.getId()].getValue()
                item["model_hex"] = bytes(generated).hex()
            results.append(item)
            if edge["isTaken"]:
                taken_predicate = predicate
        if taken_predicate is None:
            raise RuntimeError("Triton path constraint has no observed edge")
        prefix = ast.land([prefix, taken_predicate])
    return results


def predicates_to_reach(context: TritonContext, address: int) -> list[Any]:
    """Query a real case-specific reachability address; never use a dummy RVA."""
    return context.getPredicatesToReachAddress(address)


def build_capability_artifacts(
    context: TritonContext,
    node: Any,
    destination: Any,
    source: Any,
) -> dict[str, Any]:
    ast = context.getAstContext()
    unrolled = ast.unroll(node)
    duplicated = ast.duplicate(unrolled)
    matches = ast.search(duplicated, duplicated.getType())
    z3_node = ast.tritonToZ3(duplicated)
    round_trip = ast.z3ToTriton(z3_node)
    context.pushPathConstraint(context.getPathPredicate(), "capability audit")
    context.popPathConstraint()
    context.taintAssignment(destination, source)
    context.taintUnion(destination, source)
    tainted_memory = context.getTaintedMemory()
    tainted_registers = context.getTaintedRegisters()
    # Concretization is allowed only at a separately proven model boundary.
    context.concretizeMemory(0)
    context.concretizeRegister(context.registers.rax)
    return {
        "round_trip_sha256": sha256_text(str(round_trip)),
        "match_count": len(matches),
        "tainted_memory": list(tainted_memory),
        "tainted_registers": [register.getName() for register in tainted_registers],
    }


def main() -> int:
    # The AI must replace this guard with case-specific trace loading, exact
    # ABI sources/sinks, floating-state restoration, branch IDs, supplied
    # target trace IDs, AST artifact writes, and rva-recovery-triton-case/1.0.
    raise SystemExit("specialize this analyzer for the selected function")


if __name__ == "__main__":
    raise SystemExit(main())
