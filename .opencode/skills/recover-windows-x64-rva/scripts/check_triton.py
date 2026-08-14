#!/usr/bin/env python3
"""Fail-closed preflight for the binary-analysis Triton Python API."""

from __future__ import annotations

import argparse
import hashlib
import importlib.metadata
import json
import platform
import sys
from pathlib import Path


SCHEMA = "rva-recovery-triton-preflight/1.0"
EXPECTED_PACKAGE = "triton-library"
EXPECTED_VERSION = "1.0.0rc4"
EXPECTED_Z3_VERSION = "4.13.3.0"


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest().upper()


def run_preflight() -> dict[str, object]:
    checks: list[dict[str, object]] = []

    def check(name: str, passed: bool, detail: str) -> None:
        checks.append({"name": name, "passed": bool(passed), "detail": detail})
        if not passed:
            raise RuntimeError(f"{name}: {detail}")

    check("platform", sys.platform == "win32", f"sys.platform={sys.platform}")
    check(
        "cpython_3_14",
        sys.implementation.name == "cpython" and sys.version_info[:2] == (3, 14),
        f"implementation={sys.implementation.name} version={platform.python_version()}",
    )
    check(
        "amd64",
        platform.machine().lower() in {"amd64", "x86_64"},
        f"machine={platform.machine()}",
    )

    try:
        from triton import (
            ARCH,
            AST_NODE,
            CALLBACK,
            CPUSIZE,
            EXCEPTION,
            Instruction,
            MemoryAccess,
            MODE,
            SOLVER,
            TritonContext,
        )
    except Exception as error:
        raise RuntimeError(f"binary-analysis Triton import failed: {error}") from error

    version = importlib.metadata.version(EXPECTED_PACKAGE)
    check("package_version", version == EXPECTED_VERSION, f"version={version}")
    z3_version = importlib.metadata.version("z3-solver")
    check(
        "z3_package_version",
        z3_version == EXPECTED_Z3_VERSION,
        f"version={z3_version}",
    )

    import triton

    module_path = Path(triton.__file__).resolve()
    check(
        "binary_analysis_api",
        all(hasattr(triton, name) for name in ("TritonContext", "ARCH", "Instruction")),
        f"module={module_path}",
    )

    context = TritonContext(ARCH.X86_64)
    decoded = Instruction(0x0FF0, b"\x90")
    context.disassembly(decoded)
    check(
        "architecture_and_disassembly",
        decoded.getDisassembly() == "nop" and len(context.getAllRegisters()) > 0,
        f"instruction={decoded.getDisassembly()} registers={len(context.getAllRegisters())}",
    )
    semantic_instruction = Instruction(0x0FF1, b"\x48\x83\xc0\x01")
    context.disassembly(semantic_instruction)
    context.setConcreteRegisterValue(context.registers.rax, 5)
    variable = context.symbolizeRegister(context.registers.rax, "preflight_rax")
    context.taintRegister(context.registers.rax)
    fault = context.buildSemantics(semantic_instruction)
    check("build_semantics", fault == EXCEPTION.NO_FAULT, f"fault={int(fault)}")
    instruction = Instruction(0x1000, b"\x48\x83\xc0\x01")
    fault = context.processing(instruction)
    check("instruction_processing", fault == EXCEPTION.NO_FAULT, f"fault={int(fault)}")
    check(
        "concrete_semantics",
        context.getConcreteRegisterValue(context.registers.rax) == 7,
        f"rax={context.getConcreteRegisterValue(context.registers.rax)}",
    )
    check(
        "taint_propagation",
        context.isRegisterTainted(context.registers.rax),
        "symbolized input taint must reach the result register",
    )

    result_ast = context.getRegisterAst(context.registers.rax)
    ast = context.getAstContext()
    query = ast.equal(result_ast, ast.bv(8, 64))
    model = context.getModel(query)
    check(
        "symbolic_solver",
        context.isSat(query) and variable.getId() in model and model[variable.getId()].getValue() == 6,
        "solver must recover input 6 for result 8",
    )
    expression = context.getSymbolicRegister(context.registers.rax)
    sliced = context.sliceExpressions(expression)
    check(
        "backward_slice",
        expression.getId() in sliced
        and any(item.isTainted() for item in sliced.values()),
        f"slice_expression_count={len(sliced)}",
    )
    raw = ast.unroll(result_ast)
    simplified = context.simplify(raw, True, False)
    check(
        "ast_simplification",
        not context.isSat(ast.distinct(raw, simplified)),
        "raw and simplified ASTs must be equivalent",
    )
    synthesized = context.synthesize(raw)
    check(
        "expression_synthesis",
        synthesized is not None
        and not context.isSat(ast.distinct(raw, synthesized)),
        "synthesized and raw ASTs must be equivalent",
    )
    exports = {
        "smt": context.liftToSMT(expression),
        "python": context.liftToPython(expression),
        "llvm": context.liftToLLVM(raw),
        "dot": context.liftToDot(raw),
    }
    check(
        "lifting",
        all(isinstance(value, str) and value for value in exports.values()),
        ", ".join(f"{name}={len(value)}" for name, value in exports.items()),
    )
    z3_node = ast.tritonToZ3(raw)
    round_trip = ast.z3ToTriton(z3_node)
    check(
        "z3_ast_bridge",
        not context.isSat(ast.distinct(raw, round_trip)),
        "Triton -> Z3 -> Triton AST must be equivalent",
    )
    duplicated = ast.duplicate(raw)
    variables_found = ast.search(duplicated, AST_NODE.VARIABLE)
    check(
        "ast_duplicate_search",
        bool(variables_found) and not context.isSat(ast.distinct(raw, duplicated)),
        f"variable_nodes={len(variables_found)}",
    )

    solver_results = {}
    for solver_name in ("Z3", "BITWUZLA"):
        solver = getattr(SOLVER, solver_name)
        context.setSolver(solver)
        context.setSolverTimeout(10_000)
        context.setSolverMemoryLimit(256)
        solver_results[solver_name] = context.evaluateAstViaSolver(ast.bv(0x42, 8))
    context.setSolver(SOLVER.Z3)
    check(
        "solver_interfaces_and_limits",
        solver_results == {"Z3": 0x42, "BITWUZLA": 0x42},
        f"results={solver_results}",
    )

    taint_context = TritonContext(ARCH.X86_64)
    taint_context.taintRegister(taint_context.registers.rax)
    assigned = taint_context.taintAssignment(
        taint_context.registers.rbx, taint_context.registers.rax
    )
    unioned = taint_context.taintUnion(
        taint_context.registers.rcx, taint_context.registers.rbx
    )
    tainted_names = {
        register.getName() for register in taint_context.getTaintedRegisters()
    }
    check(
        "dta_assignment_union",
        assigned and unioned and {"rax", "rbx", "rcx"}.issubset(tainted_names),
        f"tainted={sorted(tainted_names)}",
    )

    concretize_context = TritonContext(ARCH.X86_64)
    concretize_context.setConcreteRegisterValue(concretize_context.registers.rax, 1)
    concretize_context.symbolizeRegister(concretize_context.registers.rax, "concrete_rax")
    memory = MemoryAccess(0x3000, CPUSIZE.BYTE)
    concretize_context.setConcreteMemoryValue(memory, 2)
    concretize_context.symbolizeMemory(memory, "concrete_mem")
    concretize_context.concretizeRegister(concretize_context.registers.rax)
    concretize_context.concretizeMemory(memory)
    individual_ok = not concretize_context.isRegisterSymbolized(
        concretize_context.registers.rax
    ) and not concretize_context.isMemorySymbolized(memory)
    concretize_context.symbolizeRegister(concretize_context.registers.rax, "all_rax")
    concretize_context.symbolizeMemory(memory, "all_mem")
    concretize_context.concretizeAllRegister()
    concretize_context.concretizeAllMemory()
    check(
        "concretization_control",
        individual_ok
        and not concretize_context.isRegisterSymbolized(concretize_context.registers.rax)
        and not concretize_context.isMemorySymbolized(memory),
        "individual and global concretization succeeded",
    )

    path_context = TritonContext(ARCH.X86_64)
    path_context.setMode(MODE.PC_TRACKING_SYMBOLIC, True)
    path_context.setConcreteRegisterValue(path_context.registers.rax, 1)
    path_variable = path_context.symbolizeRegister(path_context.registers.rax, "path_rax")
    path_context.taintRegister(path_context.registers.rax)
    path_context.processing(Instruction(0x2000, b"\x48\x83\xf8\x00"))
    path_context.processing(Instruction(0x2004, b"\x75\x05"))
    constraints = path_context.getPathConstraints()
    alternatives = constraints[0].getBranchConstraints() if constraints else []
    alternate = next((edge for edge in alternatives if not edge["isTaken"]), None)
    alternate_model = (
        path_context.getModel(alternate["constraint"]) if alternate else {}
    )
    multiple_models = (
        path_context.getModels(alternate["constraint"], 2) if alternate else []
    )
    reach_predicates = path_context.getPredicatesToReachAddress(0x200B)
    original_path_count = len(path_context.getPathConstraints())
    path_context.pushPathConstraint(path_context.getPathPredicate(), "preflight")
    pushed_path_count = len(path_context.getPathConstraints())
    path_context.popPathConstraint()
    check(
        "path_exploration",
        bool(
            alternate
            and alternate_model
            and multiple_models
            and path_variable.getId() in alternate_model
            and isinstance(reach_predicates, list)
            and pushed_path_count == original_path_count + 1
            and len(path_context.getPathConstraints()) == original_path_count
        ),
        f"constraints={len(constraints)} alternatives={len(alternatives)}",
    )
    check(
        "analysis_modes",
        path_context.isModeEnabled(MODE.PC_TRACKING_SYMBOLIC),
        "PC_TRACKING_SYMBOLIC must be active",
    )

    def simplification_callback(_context: object, node: object) -> object:
        return node

    context.addCallback(CALLBACK.SYMBOLIC_SIMPLIFICATION, simplification_callback)
    context.removeCallback(CALLBACK.SYMBOLIC_SIMPLIFICATION, simplification_callback)
    context.addCallback(CALLBACK.SYMBOLIC_SIMPLIFICATION, simplification_callback)
    context.clearCallbacks()
    check("callbacks", True, "callback registration/removal/clear succeeded")

    mode_context = TritonContext(ARCH.X86_64)
    mode_context.setMode(MODE.PC_TRACKING_SYMBOLIC, True)
    mode_context.clearModes()
    check(
        "mode_clear",
        not mode_context.isModeEnabled(MODE.PC_TRACKING_SYMBOLIC),
        "setMode/isModeEnabled/clearModes succeeded",
    )

    return {
        "schema": SCHEMA,
        "passed": all(bool(item["passed"]) for item in checks),
        "python": sys.executable,
        "python_version": platform.python_version(),
        "triton_package": EXPECTED_PACKAGE,
        "triton_version": version,
        "z3_version": z3_version,
        "triton_module": str(module_path),
        "triton_module_sha256": sha256(module_path),
        "checks": checks,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    try:
        report = run_preflight()
    except Exception as error:
        report = {"schema": SCHEMA, "passed": False, "error": str(error)}

    rendered = json.dumps(report, indent=2, ensure_ascii=False) + "\n"
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(rendered, encoding="utf-8")
    print(rendered, end="")
    return 0 if report.get("passed") is True else 2


if __name__ == "__main__":
    raise SystemExit(main())
