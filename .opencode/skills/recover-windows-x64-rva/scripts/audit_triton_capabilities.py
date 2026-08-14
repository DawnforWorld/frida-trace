#!/usr/bin/env python3
"""Audit official Triton capabilities exposed by the locked Python binding."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

import triton
from triton import ARCH, CALLBACK, MODE, SOLVER, TritonContext


SCHEMA = "rva-recovery-triton-capabilities/1.0"
OFFICIAL_SOURCES = [
    "https://triton-library.github.io/",
    "https://triton-library.github.io/documentation/doxygen/",
    "https://triton-library.github.io/documentation/doxygen/py_TritonContext_page.html",
    "https://triton-library.github.io/documentation/doxygen/py_AstContext_page.html",
]
OFFICIAL_FEATURE_INVENTORY = {
    "dynamic_binary_analysis": [
        "concrete_emulation",
        "dynamic_symbolic_execution",
        "dynamic_taint_analysis",
        "path_constraint_management",
        "solver_backed_path_exploration",
    ],
    "program_representation": [
        "architecture_semantics",
        "disassembly",
        "symbolic_expressions",
        "architecture_independent_ast",
        "backward_symbolic_slicing",
    ],
    "formula_transformation": [
        "ast_unrolling",
        "solver_and_llvm_simplification",
        "expression_synthesis",
        "triton_z3_ast_conversion",
    ],
    "solver_and_lifting": [
        "z3",
        "bitwuzla",
        "smt_models",
        "smt_python_llvm_dot_lifting",
    ],
    "instrumentation_control": [
        "callbacks",
        "analysis_modes",
        "symbolization_and_concretization",
        "concrete_state_callbacks",
    ],
    "interfaces_and_isa": [
        "cpp_api",
        "python_api",
        "x86",
        "x86_64",
        "arm32",
        "aarch64",
        "riscv32",
        "riscv64",
        "linux",
        "windows",
        "macos",
    ],
    "ecosystem_and_state": [
        "tritondse_corpus_scheduling_upper_layer",
        "snapshot_restore_via_capture_and_concrete_state_apis",
    ],
}
GROUPS = {
    "architecture_and_disassembly": [
        "setArchitecture",
        "getArchitecture",
        "disassembly",
        "getAllRegisters",
    ],
    "concrete_emulation": [
        "processing",
        "buildSemantics",
        "setConcreteRegisterValue",
        "setConcreteMemoryAreaValue",
        "getConcreteRegisterValue",
        "getConcreteMemoryAreaValue",
    ],
    "dynamic_symbolic_execution": [
        "symbolizeMemory",
        "symbolizeRegister",
        "getSymbolicExpressions",
        "getRegisterAst",
        "getMemoryAst",
    ],
    "path_exploration_and_coverage": [
        "getPathConstraints",
        "getPathPredicate",
        "pushPathConstraint",
        "popPathConstraint",
        "getPredicatesToReachAddress",
    ],
    "dynamic_taint_analysis": [
        "taintMemory",
        "taintRegister",
        "taintAssignment",
        "taintUnion",
        "getTaintedMemory",
        "getTaintedRegisters",
    ],
    "backward_slicing": ["sliceExpressions"],
    "ast_and_simplification": ["getAstContext", "simplify"],
    "solver_and_models": [
        "isSat",
        "getModel",
        "getModels",
        "evaluateAstViaSolver",
        "setSolver",
        "setSolverTimeout",
        "setSolverMemoryLimit",
    ],
    "expression_synthesis": ["synthesize"],
    "lifting_and_export": [
        "liftToDot",
        "liftToLLVM",
        "liftToPython",
        "liftToSMT",
    ],
    "callbacks": ["addCallback", "removeCallback", "clearCallbacks"],
    "analysis_modes": ["setMode", "isModeEnabled", "clearModes"],
    "concretization_control": [
        "concretizeMemory",
        "concretizeRegister",
        "concretizeAllMemory",
        "concretizeAllRegister",
    ],
}
AST_GROUP = ["unroll", "tritonToZ3", "z3ToTriton", "search", "duplicate"]


def enum_names(value: object) -> list[str]:
    return sorted(name for name in dir(value) if not name.startswith("_"))


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()

    context = TritonContext(ARCH.X86_64)
    ast_context = context.getAstContext()
    groups = {}
    for name, methods in GROUPS.items():
        missing = [method for method in methods if not callable(getattr(context, method, None))]
        groups[name] = {
            "passed": not missing,
            "methods": methods,
            "missing": missing,
        }
    ast_missing = [
        method for method in AST_GROUP if not callable(getattr(ast_context, method, None))
    ]
    groups["ast_transform_and_z3_bridge"] = {
        "passed": not ast_missing,
        "methods": AST_GROUP,
        "missing": ast_missing,
    }

    context_methods = sorted(
        name
        for name in dir(context)
        if not name.startswith("_") and callable(getattr(context, name, None))
    )
    ast_methods = sorted(
        name
        for name in dir(ast_context)
        if not name.startswith("_") and callable(getattr(ast_context, name, None))
    )
    routed_context_methods = {
        method for methods in GROUPS.values() for method in methods
    }
    routed_ast_methods = set(AST_GROUP)

    module = Path(triton.__file__).resolve()
    binding = module.with_name("triton.pyi")
    report = {
        "schema": SCHEMA,
        "passed": all(group["passed"] for group in groups.values()),
        "official_sources": OFFICIAL_SOURCES,
        "official_feature_inventory": OFFICIAL_FEATURE_INVENTORY,
        "module": str(module),
        "binding": str(binding),
        "binding_sha256": (
            hashlib.sha256(binding.read_bytes()).hexdigest().upper()
            if binding.is_file()
            else None
        ),
        "architectures": enum_names(ARCH),
        "solvers": enum_names(SOLVER),
        "modes": enum_names(MODE),
        "callbacks": enum_names(CALLBACK),
        "groups": groups,
        "runtime_api_counts": {
            "triton_context": len(context_methods),
            "ast_context": len(ast_methods),
        },
        "triton_context_methods": context_methods,
        "ast_context_methods": ast_methods,
        "routed_context_methods": sorted(routed_context_methods),
        "routed_ast_methods": sorted(routed_ast_methods),
        "unrouted_context_methods": sorted(
            set(context_methods) - routed_context_methods
        ),
        "unrouted_ast_methods": sorted(set(ast_methods) - routed_ast_methods),
    }
    rendered = json.dumps(report, indent=2, ensure_ascii=False) + "\n"
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(rendered, encoding="utf-8")
    print(rendered, end="")
    return 0 if report["passed"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
