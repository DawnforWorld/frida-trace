#!/usr/bin/env python3
"""Validate the evidence contract before a recovered C++ file is publishable."""

from __future__ import annotations

import argparse
import ast as pyast
import hashlib
import json
from pathlib import Path
from typing import Any

from validate_coverage import validate as validate_coverage_report


SCHEMA = "rva-recovery-gate/1.0"
VALIDATION_SCHEMA = "rva-recovery-gate-validation/1.0"
BAD_STOP_REASONS = {"max_instructions", "external_call", "error", "incomplete"}
ZERO_COUNTERS = (
    "unsupported_instructions",
    "floating_model_failures",
    "pc_divergences",
    "symbolic_register_divergences",
    "symbolic_memory_divergences",
    "write_divergences",
    "concrete_register_resyncs",
    "concrete_memory_resyncs",
    "extended_register_resyncs",
    "external_syncs",
    "uncaptured_state_instructions",
    "simplification_failures",
)
FLOAT_CLASSES = {
    "positive_zero",
    "negative_zero",
    "min_subnormal",
    "max_subnormal",
    "min_normal",
    "max_finite",
    "positive_infinity",
    "negative_infinity",
    "quiet_nan",
    "signaling_nan",
    "below_threshold",
    "at_threshold",
    "above_threshold",
}
FLOAT_EXCEPTIONS = {"invalid", "divide_by_zero", "overflow", "underflow", "inexact"}
COMPLETENESS_DOMAINS = {
    "abi_and_calling_convention",
    "input_domain_and_aliasing",
    "normal_returns_and_output_bits",
    "memory_side_effects_and_ownership",
    "control_flow_and_loop_exits",
    "external_calls_and_callbacks",
    "errors_exceptions_and_crashes",
    "floating_point_and_machine_state",
    "environment_assumptions",
}
EXCEPTION_KINDS = {
    "none",
    "seh",
    "cxx_exception",
    "process_exit",
    "access_violation",
    "illegal_instruction",
    "integer_divide_by_zero",
    "floating_point_exception",
    "stack_overflow",
    "abort",
    "unknown_crash",
}
CAPABILITY_GROUPS = {
    "architecture_and_disassembly",
    "concrete_emulation",
    "dynamic_symbolic_execution",
    "path_exploration_and_coverage",
    "dynamic_taint_analysis",
    "backward_slicing",
    "ast_and_simplification",
    "solver_and_models",
    "expression_synthesis",
    "lifting_and_export",
    "callbacks",
    "analysis_modes",
    "concretization_control",
    "ast_transform_and_z3_bridge",
}
ALWAYS_USED_CAPABILITIES = {
    "architecture_and_disassembly",
    "concrete_emulation",
    "dynamic_symbolic_execution",
    "path_exploration_and_coverage",
    "dynamic_taint_analysis",
    "backward_slicing",
    "ast_and_simplification",
    "solver_and_models",
    "analysis_modes",
    "concretization_control",
    "ast_transform_and_z3_bridge",
}


def file_hash(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest().upper()


def load_json(path: Path, errors: list[str]) -> dict[str, Any] | None:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except Exception as error:
        errors.append(f"cannot read JSON {path}: {error}")
        return None
    if not isinstance(value, dict):
        errors.append(f"JSON root is not an object: {path}")
        return None
    return value


def require(condition: bool, message: str, errors: list[str]) -> None:
    if not condition:
        errors.append(message)


def resolve_case_path(case_dir: Path, raw: Any, errors: list[str], label: str) -> Path | None:
    require(isinstance(raw, str) and raw.strip() != "", f"{label}: path is required", errors)
    if not isinstance(raw, str) or not raw.strip():
        return None
    path = Path(raw)
    if not path.is_absolute():
        path = case_dir / path
    path = path.resolve()
    require(path.is_file(), f"{label}: file does not exist: {path}", errors)
    return path if path.is_file() else None


def validate_hash(case_dir: Path, item: dict[str, Any], errors: list[str], label: str) -> Path | None:
    path = resolve_case_path(case_dir, item.get("path"), errors, label)
    expected = item.get("sha256")
    require(isinstance(expected, str) and len(expected) == 64, f"{label}: SHA-256 is required", errors)
    if path and isinstance(expected, str) and len(expected) == 64:
        actual = file_hash(path)
        require(actual == expected.upper(), f"{label}: SHA-256 mismatch ({actual})", errors)
    return path


def validate_provenance(case_dir: Path, manifest: dict[str, Any], errors: list[str]) -> set[str]:
    provenance = manifest.get("provenance")
    require(isinstance(provenance, dict), "provenance object is required", errors)
    if not isinstance(provenance, dict):
        return set()

    target = provenance.get("target")
    require(isinstance(target, dict), "provenance.target is required", errors)
    source_ids: set[str] = set()
    if isinstance(target, dict):
        validate_hash(case_dir, target, errors, "provenance.target")
        source_ids.add("target")

    sources = provenance.get("semantic_sources")
    require(isinstance(sources, list) and sources, "semantic_sources must be non-empty", errors)
    source_hashes: set[str] = set()
    if isinstance(sources, list):
        for index, source in enumerate(sources):
            label = f"semantic_sources[{index}]"
            require(isinstance(source, dict), f"{label}: object required", errors)
            if not isinstance(source, dict):
                continue
            source_id = source.get("id")
            role = source.get("role")
            require(isinstance(source_id, str) and source_id, f"{label}: id required", errors)
            require(role in {"target", "independent_twin"}, f"{label}: invalid role", errors)
            require(source.get("candidate_model") is False, f"{label}: candidate_model must be false", errors)
            require(source.get("created_before_recovery") is True, f"{label}: pre-recovery provenance required", errors)
            if role == "independent_twin":
                proof = source.get("independence_proof")
                require(isinstance(proof, dict), f"{label}: independence_proof required for a twin", errors)
                if isinstance(proof, dict):
                    require(isinstance(proof.get("method"), str) and proof.get("method"), f"{label}: proof method required", errors)
                    require(isinstance(proof.get("artifacts"), list) and proof.get("artifacts"), f"{label}: proof artifacts required", errors)
            validate_hash(case_dir, source, errors, label)
            if isinstance(source_id, str):
                source_ids.add(source_id)
            if isinstance(source.get("sha256"), str):
                source_hashes.add(source["sha256"].upper())

    oracle = provenance.get("sealed_source_oracle")
    require(isinstance(oracle, dict), "sealed_source_oracle is required", errors)
    if isinstance(oracle, dict):
        require(oracle.get("used_for_recovery") is False, "source oracle must not be used for recovery", errors)
        require(oracle.get("revealed_after_freeze") is True, "source oracle must be sealed until freeze", errors)

    candidates = provenance.get("candidate_artifacts", [])
    require(isinstance(candidates, list), "candidate_artifacts must be a list", errors)
    if isinstance(candidates, list):
        for index, candidate in enumerate(candidates):
            label = f"candidate_artifacts[{index}]"
            require(isinstance(candidate, dict), f"{label}: object required", errors)
            if not isinstance(candidate, dict):
                continue
            candidate_hash = candidate.get("sha256")
            require(
                isinstance(candidate_hash, str) and candidate_hash.upper() not in source_hashes,
                f"{label}: candidate may not be an evidence source",
                errors,
            )

    traces = provenance.get("trace_artifacts")
    require(isinstance(traces, list) and traces, "trace_artifacts must be non-empty", errors)
    if isinstance(traces, list):
        for index, trace in enumerate(traces):
            label = f"trace_artifacts[{index}]"
            require(isinstance(trace, dict), f"{label}: object required", errors)
            if not isinstance(trace, dict):
                continue
            require(trace.get("source_id") in source_ids, f"{label}: source_id is not a semantic source", errors)
            validate_hash(case_dir, trace, errors, label)
    return source_ids


def validate_replay(case_dir: Path, replay: dict[str, Any], errors: list[str]) -> dict[str, Any] | None:
    label = f"Triton replay {replay.get('id', '<unnamed>')}"
    require(replay.get("strict") is True, f"{label}: strict=true is required", errors)
    require(replay.get("full_window") is True, f"{label}: full_window=true is required", errors)
    path = resolve_case_path(case_dir, replay.get("report"), errors, label)
    if not path:
        return None
    report = load_json(path, errors)
    if not report:
        return None
    require(report.get("schema") == "pintrace-triton-replay/1.1", f"{label}: bundled 1.1 replay report required", errors)
    configuration = report.get("configuration")
    require(
        isinstance(configuration, dict) and configuration.get("strict") is True,
        f"{label}: report was not strict",
        errors,
    )
    if isinstance(configuration, dict):
        require(configuration.get("solve_branches") is True, f"{label}: branch solving was not enabled", errors)
        require(configuration.get("track_dataflow") is True, f"{label}: DTA data-flow tracking was not enabled", errors)
        require(configuration.get("through_external") is False, f"{label}: external resynchronization is forbidden", errors)
    counters = report.get("counters")
    require(isinstance(counters, dict), f"{label}: counters missing", errors)
    if isinstance(counters, dict):
        require(int(counters.get("processed", 0)) > 0, f"{label}: no instructions processed", errors)
        for counter in ZERO_COUNTERS:
            require(int(counters.get(counter, 0)) == 0, f"{label}: {counter} is nonzero", errors)
        require(int(counters.get("branch_solver_failures", 0)) == 0, f"{label}: branch solver failure", errors)
        if int(counters.get("modeled_external_boundaries", 0)):
            require(
                isinstance(configuration, dict) and configuration.get("model_external") is True,
                f"{label}: modeled external boundaries were not explicitly enabled",
                errors,
            )
            external_model = report.get("external_model")
            require(
                isinstance(external_model, dict)
                and external_model.get("enabled") is True
                and int(external_model.get("boundary_count", -1))
                == int(counters.get("modeled_external_boundaries", 0)),
                f"{label}: external boundary model inventory mismatch",
                errors,
            )
    range_info = report.get("range")
    require(isinstance(range_info, dict), f"{label}: range missing", errors)
    if isinstance(range_info, dict):
        require(range_info.get("stop_reason") not in BAD_STOP_REASONS, f"{label}: replay stopped early", errors)
    require(isinstance(report.get("branch_constraints"), list), f"{label}: branch_constraints missing", errors)
    require(isinstance(report.get("taint"), dict), f"{label}: taint result missing", errors)
    require(
        isinstance(report.get("solver"), dict) and not report["solver"].get("error"),
        f"{label}: solver result missing or errored",
        errors,
    )
    return report


def validate_case_analyzer(
    case_dir: Path,
    analyzer: Any,
    sink_ids: set[str],
    taint_required: set[str],
    branch_ids: set[str],
    floating_used: bool,
    errors: list[str],
    label: str,
) -> None:
    require(isinstance(analyzer, dict), f"{label}: case_analyzer is required", errors)
    if not isinstance(analyzer, dict):
        return
    script = validate_hash(case_dir, analyzer, errors, f"{label}.script")
    if not script:
        return
    try:
        tree = pyast.parse(script.read_text(encoding="utf-8"), filename=str(script))
    except Exception as error:
        errors.append(f"{label}: cannot parse case analyzer: {error}")
        return
    names = {
        node.func.id
        for node in pyast.walk(tree)
        if isinstance(node, pyast.Call) and isinstance(node.func, pyast.Name)
    }
    methods = {
        node.func.attr
        for node in pyast.walk(tree)
        if isinstance(node, pyast.Call) and isinstance(node.func, pyast.Attribute)
    }
    require("TritonContext" in names, f"{label}: analyzer must instantiate TritonContext", errors)
    required_methods = {
        "setConcreteRegisterValue",
        "setConcreteMemoryAreaValue",
        "processing",
        "sliceExpressions",
        "simplify",
        "getPathConstraints",
        "getPathPredicate",
        "getPredicatesToReachAddress",
        "pushPathConstraint",
        "popPathConstraint",
        "isSat",
        "getModel",
        "getModels",
        "taintAssignment",
        "taintUnion",
        "getTaintedMemory",
        "getTaintedRegisters",
        "concretizeMemory",
        "concretizeRegister",
        "unroll",
        "tritonToZ3",
        "z3ToTriton",
        "duplicate",
        "search",
    }
    for method in required_methods:
        require(method in methods, f"{label}: analyzer does not call Triton.{method}()", errors)
    require(
        bool({"symbolizeMemory", "symbolizeRegister"}.intersection(methods)),
        f"{label}: analyzer does not symbolize a proven source",
        errors,
    )
    require(
        bool({"taintMemory", "taintRegister"}.intersection(methods)),
        f"{label}: analyzer does not use Triton taint",
        errors,
    )
    require(
        bool({"getMemoryAst", "getRegisterAst"}.intersection(methods)),
        f"{label}: analyzer does not extract a sink AST",
        errors,
    )

    report_path = resolve_case_path(
        case_dir,
        analyzer.get("report"),
        errors,
        f"{label}.report",
    )
    if not report_path:
        return
    report = load_json(report_path, errors)
    if not report:
        return
    script_digest = file_hash(script)
    require(report.get("schema") == "rva-recovery-triton-case/1.0", f"{label}: invalid case report schema", errors)
    require(report.get("passed") is True, f"{label}: case analyzer did not pass", errors)
    require(report.get("script_sha256") == script_digest, f"{label}: report/script hash mismatch", errors)
    ledger = report.get("capability_ledger")
    require(isinstance(ledger, dict), f"{label}: capability ledger missing", errors)
    if isinstance(ledger, dict):
        require(set(ledger) == CAPABILITY_GROUPS, f"{label}: capability ledger is incomplete", errors)
        for group in CAPABILITY_GROUPS:
            item = ledger.get(group)
            require(isinstance(item, dict), f"{label}: capability {group} entry missing", errors)
            if not isinstance(item, dict):
                continue
            status = item.get("status")
            if group in ALWAYS_USED_CAPABILITIES:
                require(status == "used", f"{label}: capability {group} must be used", errors)
            else:
                require(status in {"used", "not_applicable"}, f"{label}: capability {group} status invalid", errors)
            if status == "used":
                artifacts = item.get("artifacts")
                require(
                    isinstance(artifacts, list) and artifacts,
                    f"{label}: capability {group} lacks artifacts",
                    errors,
                )
                if isinstance(artifacts, list):
                    for artifact in artifacts:
                        resolve_case_path(
                            case_dir,
                            artifact,
                            errors,
                            f"{label}.capability.{group}",
                        )
            elif status == "not_applicable":
                require(item.get("reason"), f"{label}: capability {group} needs a scope reason", errors)
        optional_api = {
            "expression_synthesis": {"synthesize"},
            "lifting_and_export": {"liftToSMT", "liftToPython", "liftToLLVM", "liftToDot"},
            "callbacks": {"addCallback", "removeCallback", "clearCallbacks"},
        }
        for group, required_api in optional_api.items():
            item = ledger.get(group)
            if isinstance(item, dict) and item.get("status") == "used":
                for method in required_api:
                    require(method in methods, f"{label}: used capability {group} does not call Triton.{method}()", errors)
    exact = report.get("exact_replay")
    require(isinstance(exact, dict), f"{label}: exact_replay result missing", errors)
    if isinstance(exact, dict):
        require(int(exact.get("processed_instructions", 0)) > 0, f"{label}: no instructions emulated", errors)
        for field in ("all_next_pcs_match", "all_reliable_writes_match", "full_window"):
            require(exact.get(field) is True, f"{label}: {field} must be true", errors)
        for field in (
            "unsupported_state_count",
            "external_provenance_loss_count",
            "resynchronization_count",
        ):
            require(int(exact.get(field, -1)) == 0, f"{label}: {field} must be zero", errors)
    if floating_used:
        fp = report.get("floating_point")
        require(isinstance(fp, dict), f"{label}: floating-point replay proof missing", errors)
        if isinstance(fp, dict):
            for field in (
                "vector_state_restored",
                "mxcsr_restored",
                "x87_state_restored",
                "environment_matches",
                "bit_exact",
            ):
                require(fp.get(field) is True, f"{label}: floating proof {field} must be true", errors)

    sink_results = report.get("sinks")
    require(isinstance(sink_results, list), f"{label}: sink AST results missing", errors)
    by_sink = {
        item.get("id"): item
        for item in sink_results
        if isinstance(item, dict) and isinstance(item.get("id"), str)
    } if isinstance(sink_results, list) else {}
    require(sink_ids.issubset(by_sink), f"{label}: not every sink has an AST result", errors)
    for sink_id in sink_ids:
        item = by_sink.get(sink_id)
        if not isinstance(item, dict):
            continue
        require(item.get("concrete_match") is True, f"{label}: sink {sink_id} concrete mismatch", errors)
        require(item.get("simplification_equivalent") is True, f"{label}: sink {sink_id} AST simplification is unproven", errors)
        for field in ("raw_ast_sha256", "simplified_ast_sha256"):
            require(
                isinstance(item.get(field), str) and len(item[field]) == 64,
                f"{label}: sink {sink_id} lacks {field}",
                errors,
            )
        require(
            isinstance(item.get("slice_sha256"), str)
            and len(item["slice_sha256"]) == 64
            and isinstance(item.get("slice_expression_ids"), list)
            and item.get("slice_expression_ids"),
            f"{label}: sink {sink_id} lacks Triton backward slice",
            errors,
        )
        if sink_id in taint_required:
            require(item.get("tainted") is True, f"{label}: sink {sink_id} is not tainted", errors)
            require(item.get("symbolic") is True, f"{label}: sink {sink_id} has no symbolic source", errors)
            require(
                isinstance(item.get("tainted_slice_expression_ids"), list)
                and item.get("tainted_slice_expression_ids"),
                f"{label}: sink {sink_id} has no taint-backed reverse slice",
                errors,
            )

    branch_results = report.get("branches")
    require(isinstance(branch_results, list), f"{label}: branch AST results missing", errors)
    by_branch = {
        item.get("id"): item
        for item in branch_results
        if isinstance(item, dict) and isinstance(item.get("id"), str)
    } if isinstance(branch_results, list) else {}
    require(branch_ids.issubset(by_branch), f"{label}: not every branch has a symbolic result", errors)
    for branch_id in branch_ids:
        item = by_branch.get(branch_id)
        if not isinstance(item, dict):
            continue
        require(item.get("simplification_equivalent") is True, f"{label}: branch {branch_id} predicate simplification is unproven", errors)
        for field in ("raw_ast_sha256", "simplified_ast_sha256"):
            require(
                isinstance(item.get(field), str) and len(item[field]) == 64,
                f"{label}: branch {branch_id} lacks {field}",
                errors,
            )
        alternates = item.get("alternate_edges")
        require(isinstance(alternates, list) and alternates, f"{label}: branch {branch_id} was not negated/solved", errors)
        if isinstance(alternates, list):
            for edge in alternates:
                if isinstance(edge, dict) and edge.get("sat") is True:
                    require(edge.get("model_hex"), f"{label}: feasible branch {branch_id} lacks a model", errors)
                    require(edge.get("target_run_id"), f"{label}: feasible branch {branch_id} model lacks a supplied target trace", errors)


def validate_floating_point(function: dict[str, Any], errors: list[str], label: str) -> None:
    floating = function.get("floating_point")
    require(isinstance(floating, dict), f"{label}: floating_point declaration required", errors)
    if not isinstance(floating, dict):
        return
    require(isinstance(floating.get("used"), bool), f"{label}: floating_point.used must be Boolean", errors)
    if floating.get("used") is not True:
        require(floating.get("absence_evidence"), f"{label}: floating-point absence needs trace evidence", errors)
        return
    require(floating.get("comparison") == "ieee754_bits", f"{label}: floating comparison must be bit-exact", errors)
    require(floating.get("tolerance_used") is False, f"{label}: floating tolerance is forbidden", errors)
    state = floating.get("state_capture")
    require(isinstance(state, dict), f"{label}: floating state_capture required", errors)
    if isinstance(state, dict):
        for field in ("vector_registers", "mxcsr", "x87_control", "x87_status", "x87_tags"):
            require(state.get(field) is True, f"{label}: floating state {field} is not captured", errors)
    matrix = floating.get("class_matrix")
    require(isinstance(matrix, dict), f"{label}: floating class_matrix required", errors)
    if isinstance(matrix, dict):
        require(FLOAT_CLASSES.issubset(matrix), f"{label}: floating boundary classes are incomplete", errors)
        for name in FLOAT_CLASSES:
            require(matrix.get(name), f"{label}: floating class {name} has no target run/proof", errors)
    exceptions = floating.get("exception_matrix")
    require(isinstance(exceptions, dict), f"{label}: floating exception_matrix required", errors)
    if isinstance(exceptions, dict):
        require(FLOAT_EXCEPTIONS.issubset(exceptions), f"{label}: floating exception classes are incomplete", errors)
        for name in FLOAT_EXCEPTIONS:
            require(exceptions.get(name), f"{label}: floating exception {name} has no target run/proof", errors)
    require(
        isinstance(floating.get("reachable_rounding_modes"), list)
        and floating.get("reachable_rounding_modes"),
        f"{label}: reachable rounding modes must be proven",
        errors,
    )
    obligations = floating.get("source_obligations")
    require(isinstance(obligations, list) and obligations, f"{label}: floating source obligations required", errors)
    if isinstance(obligations, list):
        for index, obligation in enumerate(obligations):
            item_label = f"{label}.floating_point.source_obligations[{index}]"
            require(isinstance(obligation, dict), f"{item_label}: object required", errors)
            if not isinstance(obligation, dict):
                continue
            require(isinstance(obligation.get("cpp_ref"), str) and obligation.get("cpp_ref"), f"{item_label}: cpp_ref required", errors)
            require(isinstance(obligation.get("triton_ast_sha256"), str) and len(obligation.get("triton_ast_sha256", "")) == 64, f"{item_label}: Triton AST hash required", errors)
            require(obligation.get("ieee754_bits_exact") is True, f"{item_label}: bit-exact floating obligation required", errors)


def validate_completeness_contract(function: dict[str, Any], errors: list[str], label: str, claim: str) -> None:
    contract = function.get("completeness_contract")
    require(isinstance(contract, dict), f"{label}: completeness_contract required", errors)
    if not isinstance(contract, dict):
        return
    if claim == "complete":
        require(contract.get("complete") is True, f"{label}: completeness_contract.complete must be true", errors)
    else:
        require(isinstance(contract.get("complete"), bool), f"{label}: completeness_contract.complete must be Boolean", errors)
    require(
        contract.get("definition") == "recover-function-behavior/1.0",
        f"{label}: completeness definition must be recover-function-behavior/1.0",
        errors,
    )
    domains = contract.get("domains")
    require(isinstance(domains, dict), f"{label}: completeness domains required", errors)
    if isinstance(domains, dict):
        require(
            COMPLETENESS_DOMAINS.issubset(domains),
            f"{label}: completeness domains are incomplete",
            errors,
        )
        for domain in COMPLETENESS_DOMAINS:
            item = domains.get(domain)
            require(isinstance(item, dict), f"{label}: completeness domain {domain} missing", errors)
            if not isinstance(item, dict):
                continue
            allowed_status = {"complete"} if claim == "complete" else {"complete", "partial", "unknown"}
            require(item.get("status") in allowed_status, f"{label}: completeness domain {domain} has invalid status", errors)
            require(
                isinstance(item.get("evidence"), list) and item.get("evidence"),
                f"{label}: completeness domain {domain} lacks evidence",
                errors,
            )
            if claim == "complete":
                require(not item.get("unknown"), f"{label}: completeness domain {domain} still has unknowns", errors)
    machine_state = contract.get("machine_state_domain")
    require(isinstance(machine_state, dict), f"{label}: machine_state_domain required", errors)
    if isinstance(machine_state, dict):
        for field in ("registers", "stack", "flags", "memory", "external_state"):
            require(machine_state.get(field) in {"captured", "proven_irrelevant"}, f"{label}: machine state {field} unresolved", errors)
    assumptions = contract.get("environment_assumptions")
    require(isinstance(assumptions, list), f"{label}: environment assumptions list required", errors)
    for assumption in assumptions if isinstance(assumptions, list) else []:
        require(isinstance(assumption, dict), f"{label}: malformed environment assumption", errors)
        if isinstance(assumption, dict):
            require(isinstance(assumption.get("name"), str) and assumption.get("name"), f"{label}: assumption name required", errors)
            require(assumption.get("validated") is True, f"{label}: assumption {assumption.get('name', '<unnamed>')} not validated", errors)


def validate_exception_inventory(case_dir: Path, function: dict[str, Any], errors: list[str], label: str) -> None:
    inventory = function.get("exception_inventory")
    require(isinstance(inventory, dict), f"{label}: exception_inventory required", errors)
    if not isinstance(inventory, dict):
        return
    require(inventory.get("complete") is True, f"{label}: exception_inventory.complete must be true", errors)

    pe_unwind = inventory.get("pe_unwind")
    require(isinstance(pe_unwind, dict), f"{label}: pe_unwind inventory required", errors)
    if isinstance(pe_unwind, dict):
        report_path = validate_hash(case_dir, pe_unwind, errors, f"{label}.exception_inventory.pe_unwind")
        if report_path:
            report = load_json(report_path, errors)
            require(
                bool(
                    report
                    and report.get("schema") == "pe-unwind-inventory/1.1"
                    and report.get("passed") is True
                ),
                f"{label}: PE unwind inventory report did not pass",
                errors,
            )
            if report and isinstance(report.get("functions"), list):
                report_functions = {
                    item.get("name"): item
                    for item in report["functions"]
                    if isinstance(item, dict) and isinstance(item.get("name"), str)
                }
                report_item = report_functions.get(function.get("name"))
                require(isinstance(report_item, dict), f"{label}: PE unwind report lacks this function", errors)
                if isinstance(report_item, dict):
                    for field in ("function_covered", "runtime_function_mapped"):
                        require(report_item.get(field) is True, f"{label}: PE unwind report {field} is not true", errors)
                    for field in ("unknown_unwind_info", "unknown_handlers", "unknown_language_specific_data"):
                        require(report_item.get(field) is False, f"{label}: PE unwind report {field} is not false", errors)
        for field in ("exception_directory_parsed", "function_covered", "runtime_function_mapped"):
            require(pe_unwind.get(field) is True, f"{label}: pe_unwind {field} must be true", errors)
        for field in ("unknown_unwind_info", "unknown_handlers", "unknown_language_specific_data"):
            require(pe_unwind.get(field) is False, f"{label}: pe_unwind {field} must be false", errors)

    cxx_eh = inventory.get("cxx_eh")
    require(isinstance(cxx_eh, dict), f"{label}: cxx_eh inventory required", errors)
    if isinstance(cxx_eh, dict):
        require(cxx_eh.get("status") in {"not_present", "parsed"}, f"{label}: C++ EH metadata is unknown", errors)
        if cxx_eh.get("status") == "parsed":
            require(isinstance(cxx_eh.get("frame_handler"), str) and cxx_eh.get("frame_handler"), f"{label}: C++ frame handler required", errors)
            require(isinstance(cxx_eh.get("func_info"), dict), f"{label}: C++ FuncInfo required", errors)
            require(isinstance(cxx_eh.get("try_blocks"), list), f"{label}: C++ try block map required", errors)
            require(isinstance(cxx_eh.get("unwind_map"), list), f"{label}: C++ unwind map required", errors)

    seh = inventory.get("seh")
    require(isinstance(seh, dict), f"{label}: SEH inventory required", errors)
    if isinstance(seh, dict):
        require(seh.get("status") in {"not_present", "parsed"}, f"{label}: SEH handler metadata is unknown", errors)
        if seh.get("status") == "parsed":
            require(isinstance(seh.get("handlers"), list) and seh.get("handlers"), f"{label}: SEH handlers required", errors)

    runtime_matrix = inventory.get("runtime_exception_matrix")
    require(isinstance(runtime_matrix, list), f"{label}: runtime_exception_matrix required", errors)
    if isinstance(runtime_matrix, list):
        if not runtime_matrix:
            require(inventory.get("no_runtime_exceptions_proven") is True, f"{label}: empty exception matrix needs proof", errors)
        for index, outcome in enumerate(runtime_matrix):
            outcome_label = f"{label}.exception[{index}]"
            require(isinstance(outcome, dict), f"{outcome_label}: object required", errors)
            if not isinstance(outcome, dict):
                continue
            require(outcome.get("kind") in EXCEPTION_KINDS, f"{outcome_label}: invalid exception kind", errors)
            require(isinstance(outcome.get("target_run_id"), str) and outcome.get("target_run_id"), f"{outcome_label}: target run required", errors)
            require(isinstance(outcome.get("trace_run_id"), str) and outcome.get("trace_run_id"), f"{outcome_label}: trace run required", errors)
            require(isinstance(outcome.get("replay_id"), str) and outcome.get("replay_id"), f"{outcome_label}: Triton replay required", errors)
            require(outcome.get("side_effects_compared") is True, f"{outcome_label}: side effects before exception not compared", errors)
            if outcome.get("kind") == "cxx_exception":
                require(isinstance(outcome.get("throw_type"), str) and outcome.get("throw_type"), f"{outcome_label}: C++ throw type required", errors)
            elif outcome.get("kind") not in {"none", "process_exit"}:
                require(isinstance(outcome.get("exception_code"), str) and outcome.get("exception_code"), f"{outcome_label}: exception code required", errors)


def validate_cpp_evidence_map(function: dict[str, Any], sink_ids: set[str], branch_ids: set[str], errors: list[str], label: str) -> None:
    evidence_map = function.get("cpp_evidence_map")
    require(isinstance(evidence_map, list) and evidence_map, f"{label}: cpp_evidence_map required", errors)
    if not isinstance(evidence_map, list):
        return
    mapped_sinks: set[str] = set()
    mapped_branches: set[str] = set()
    for index, item in enumerate(evidence_map):
        item_label = f"{label}.cpp_evidence_map[{index}]"
        require(isinstance(item, dict), f"{item_label}: object required", errors)
        if not isinstance(item, dict):
            continue
        require(item.get("kind") in {"branch", "store", "formula", "call", "return", "error", "exception", "abi"}, f"{item_label}: invalid kind", errors)
        require(item.get("status") in {"verified", "inferred", "unknown"}, f"{item_label}: invalid status", errors)
        require(isinstance(item.get("cpp_ref"), str) and item.get("cpp_ref"), f"{item_label}: cpp_ref required", errors)
        if isinstance(item.get("sink_id"), str):
            mapped_sinks.add(item["sink_id"])
        if isinstance(item.get("branch_id"), str):
            mapped_branches.add(item["branch_id"])
        if item.get("status") == "verified":
            require(isinstance(item.get("trace_run_id"), str) and item.get("trace_run_id"), f"{item_label}: verified item needs trace_run_id", errors)
            require(isinstance(item.get("replay_id"), str) and item.get("replay_id"), f"{item_label}: verified item needs replay_id", errors)
            require(isinstance(item.get("evidence"), list) and item.get("evidence"), f"{item_label}: verified item needs evidence", errors)
        if item.get("status") == "unknown":
            require("concrete_value" not in item, f"{item_label}: unknown item may not publish a guessed concrete_value", errors)
    require(sink_ids.issubset(mapped_sinks), f"{label}: every sink needs a C++ evidence map entry", errors)
    require(branch_ids.issubset(mapped_branches), f"{label}: every branch needs a C++ evidence map entry", errors)


def validate_functions(case_dir: Path, manifest: dict[str, Any], errors: list[str], claim: str) -> None:
    functions = manifest.get("functions")
    require(isinstance(functions, list) and functions, "functions must be non-empty", errors)
    if not isinstance(functions, list):
        return
    for index, function in enumerate(functions):
        label = f"functions[{index}]"
        require(isinstance(function, dict), f"{label}: object required", errors)
        if not isinstance(function, dict):
            continue
        require(isinstance(function.get("name"), str) and function.get("name"), f"{label}: name required", errors)
        require(isinstance(function.get("sinks"), list) and function.get("sinks"), f"{label}: sink inventory required", errors)
        unknown = function.get("unknown", [])
        if claim == "complete":
            require(isinstance(unknown, list) and not unknown, f"{label}: unknown behavior remains", errors)
        else:
            require(isinstance(unknown, list), f"{label}: unknown must be a list", errors)
        validate_completeness_contract(function, errors, label, claim)
        validate_exception_inventory(case_dir, function, errors, label)
        validate_floating_point(function, errors, label)

        branch_inventory = function.get("branch_inventory")
        branch_complete_required = claim == "complete"
        require(
            isinstance(branch_inventory, dict)
            and (branch_inventory.get("complete") is True or not branch_complete_required),
            f"{label}: branch inventory required",
            errors,
        )
        branches = branch_inventory.get("branches", []) if isinstance(branch_inventory, dict) else []
        require(isinstance(branches, list), f"{label}: branches must be a list", errors)
        branch_ids: set[str] = set()
        observed_runs: set[str] = set()
        if isinstance(branches, list):
            for branch_index, branch in enumerate(branches):
                branch_label = f"{label}.branch[{branch_index}]"
                require(isinstance(branch, dict), f"{branch_label}: object required", errors)
                if not isinstance(branch, dict):
                    continue
                branch_id = branch.get("id")
                require(isinstance(branch_id, str) and branch_id, f"{branch_label}: id required", errors)
                if isinstance(branch_id, str):
                    branch_ids.add(branch_id)
                for edge_name in ("taken", "not_taken"):
                    edge = branch.get(edge_name)
                    require(isinstance(edge, dict), f"{branch_label}.{edge_name}: edge required", errors)
                    if not isinstance(edge, dict):
                        continue
                    status = edge.get("status")
                    require(
                        status in ({"observed", "infeasible"} if claim == "complete" else {"observed", "infeasible", "unknown"}),
                        f"{branch_label}.{edge_name}: unknown edge is forbidden",
                        errors,
                    )
                    runs = edge.get("runs", [])
                    if status == "observed":
                        require(
                            isinstance(runs, list) and runs,
                            f"{branch_label}.{edge_name}: observed edge needs runs",
                            errors,
                        )
                        if isinstance(runs, list):
                            observed_runs.update(str(run) for run in runs)
                    elif status == "infeasible":
                        require(
                            isinstance(edge.get("proof"), dict),
                            f"{branch_label}.{edge_name}: infeasibility proof required",
                            errors,
                        )

        error_inventory = function.get("error_inventory")
        error_complete_required = claim == "complete"
        require(
            isinstance(error_inventory, dict)
            and (error_inventory.get("complete") is True or not error_complete_required),
            f"{label}: error inventory required",
            errors,
        )
        if isinstance(error_inventory, dict):
            outcomes = error_inventory.get("outcomes")
            require(isinstance(outcomes, list), f"{label}: error outcomes must be a list", errors)
            if not outcomes:
                require(
                    error_inventory.get("no_errors_proven") is True,
                    f"{label}: empty error inventory needs proof",
                    errors,
                )

        triton = function.get("triton")
        require(isinstance(triton, dict), f"{label}: Triton section required", errors)
        if not isinstance(triton, dict):
            continue
        capability_path = resolve_case_path(
            case_dir,
            triton.get("capability_audit"),
            errors,
            f"{label}.triton.capability_audit",
        )
        if capability_path:
            capability = load_json(capability_path, errors)
            require(
                bool(
                    capability
                    and capability.get("schema")
                    == "rva-recovery-triton-capabilities/1.0"
                    and capability.get("passed") is True
                    and isinstance(capability.get("groups"), dict)
                    and CAPABILITY_GROUPS.issubset(capability["groups"])
                    and all(
                        capability["groups"][group].get("passed") is True
                        for group in CAPABILITY_GROUPS
                    )
                ),
                f"{label}: Triton capability audit did not pass",
                errors,
            )
        coverage_path = resolve_case_path(
            case_dir,
            triton.get("coverage_report"),
            errors,
            f"{label}.triton.coverage_report",
        )
        if coverage_path:
            coverage = load_json(coverage_path, errors)
            if coverage:
                for coverage_error in validate_coverage_report(coverage):
                    errors.append(f"{label}.triton.coverage_report: {coverage_error}")
                require(
                    coverage.get("function") == function.get("name"),
                    f"{label}: coverage report function mismatch",
                    errors,
                )
                covered_branch_ids = {
                    item.get("id")
                    for item in coverage.get("branches", [])
                    if isinstance(item, dict)
                }
                require(
                    branch_ids == covered_branch_ids,
                    f"{label}: coverage report branch inventory mismatch",
                    errors,
                )
        preflight = resolve_case_path(case_dir, triton.get("preflight"), errors, f"{label}.triton.preflight")
        if preflight:
            report = load_json(preflight, errors)
            require(
                bool(
                    report
                    and report.get("schema") == "rva-recovery-triton-preflight/1.0"
                    and report.get("passed") is True
                ),
                f"{label}: Triton preflight did not pass",
                errors,
            )
        replays = triton.get("replays")
        require(isinstance(replays, list) and replays, f"{label}: focused Triton replay required", errors)
        replay_reports: dict[str, dict[str, Any]] = {}
        if isinstance(replays, list):
            for replay in replays:
                if not isinstance(replay, dict):
                    require(False, f"{label}: malformed replay entry", errors)
                    continue
                report = validate_replay(case_dir, replay, errors)
                if report and isinstance(replay.get("id"), str):
                    replay_reports[replay["id"]] = report

        sinks = function.get("sinks", [])
        sink_ids = {
            sink.get("id")
            for sink in sinks
            if isinstance(sink, dict) and isinstance(sink.get("id"), str)
        }
        required_taint = {
            sink.get("id")
            for sink in sinks
            if isinstance(sink, dict) and sink.get("taint_required", True)
        }
        validate_case_analyzer(
            case_dir,
            triton.get("case_analyzer"),
            sink_ids,
            required_taint,
            branch_ids,
            bool(
                isinstance(function.get("floating_point"), dict)
                and function["floating_point"].get("used") is True
            ),
            errors,
            f"{label}.triton.case_analyzer",
        )
        validate_cpp_evidence_map(function, sink_ids, branch_ids, errors, label)
        taint_items = triton.get("taint")
        require(isinstance(taint_items, list), f"{label}: taint manifest required", errors)
        tainted_sinks: set[str] = set()
        if isinstance(taint_items, list):
            for item in taint_items:
                if not isinstance(item, dict):
                    continue
                sink_id = item.get("sink_id")
                replay = replay_reports.get(str(item.get("replay_id")))
                goal_index = item.get("goal_index")
                require(isinstance(sink_id, str), f"{label}: taint sink_id required", errors)
                require(
                    replay is not None and isinstance(goal_index, int),
                    f"{label}: taint must reference a replay goal",
                    errors,
                )
                if replay is not None and isinstance(goal_index, int):
                    goals = replay.get("goals", [])
                    goal = goals[goal_index] if 0 <= goal_index < len(goals) else None
                    require(
                        isinstance(goal, dict) and goal.get("tainted") is True,
                        f"{label}: Triton taint did not reach sink {sink_id}",
                        errors,
                    )
                    backward_slice = (
                        goal.get("backward_slice")
                        if isinstance(goal, dict)
                        else None
                    )
                    require(
                        isinstance(backward_slice, dict)
                        and backward_slice.get("tainted_expression_ids"),
                        f"{label}: sink {sink_id} lacks a taint-backed Triton slice",
                        errors,
                    )
                    if isinstance(goal, dict) and goal.get("tainted") is True:
                        tainted_sinks.add(str(sink_id))
        require(
            required_taint.issubset(tainted_sinks),
            f"{label}: not all taint-required sinks are proven",
            errors,
        )

        paths = triton.get("paths")
        require(isinstance(paths, list), f"{label}: symbolic path manifest required", errors)
        path_branch_ids = (
            {path.get("branch_id") for path in paths if isinstance(path, dict)}
            if isinstance(paths, list)
            else set()
        )
        require(
            branch_ids.issubset(path_branch_ids),
            f"{label}: every branch needs a Triton predicate/path result",
            errors,
        )
        for path_item in paths if isinstance(paths, list) else []:
            if not isinstance(path_item, dict):
                continue
            replay = replay_reports.get(str(path_item.get("replay_id")))
            constraint_index = path_item.get("constraint_index")
            require(
                replay is not None and isinstance(constraint_index, int),
                f"{label}: path entry must reference a replay constraint",
                errors,
            )
            if replay is None or not isinstance(constraint_index, int):
                continue
            constraints = replay.get("branch_constraints", [])
            constraint = constraints[constraint_index] if 0 <= constraint_index < len(constraints) else None
            require(isinstance(constraint, dict), f"{label}: invalid branch constraint reference", errors)
            if isinstance(constraint, dict):
                require(
                    isinstance(constraint.get("alternatives"), list),
                    f"{label}: branch alternatives missing",
                    errors,
                )
                require(
                    isinstance(path_item.get("alternate_runs"), list),
                    f"{label}: alternate target runs missing",
                    errors,
                )


def validate_gate(manifest_path: Path) -> dict[str, Any]:
    errors: list[str] = []
    manifest = load_json(manifest_path, errors)
    if manifest is None:
        return {"schema": VALIDATION_SCHEMA, "passed": False, "errors": errors}
    require(manifest.get("schema") == SCHEMA, "manifest schema must be rva-recovery-gate/1.0", errors)
    claim = manifest.get("claim")
    require(claim in {"complete", "trunk"}, "claim must be complete or trunk", errors)
    source_ids = validate_provenance(manifest_path.parent.resolve(), manifest, errors)
    validate_functions(manifest_path.parent.resolve(), manifest, errors, str(claim))
    return {
        "schema": VALIDATION_SCHEMA,
        "passed": not errors,
        "source_ids": sorted(source_ids),
        "errors": errors,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("manifest", type=Path)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    result = validate_gate(args.manifest.resolve())
    rendered = json.dumps(result, indent=2, ensure_ascii=False) + "\n"
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(rendered, encoding="utf-8")
    print(rendered, end="")
    return 0 if result["passed"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
