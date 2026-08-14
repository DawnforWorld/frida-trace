#!/usr/bin/env python3
"""Validate Triton-guided target path and behavioral coverage closure."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any


SCHEMA = "rva-triton-coverage/1.0"
VALIDATION_SCHEMA = "rva-triton-coverage-validation/1.0"


def validate(report: dict[str, Any]) -> list[str]:
    errors = []
    if report.get("schema") != SCHEMA:
        errors.append(f"schema must be {SCHEMA}")
    if report.get("passed") is not True:
        errors.append("coverage producer did not pass")
    if report.get("queue_exhausted") is not True:
        errors.append("path exploration queue is not exhausted")
    if not isinstance(report.get("runs"), list) or not report["runs"]:
        errors.append("target runs are missing")
    branches = report.get("branches")
    if not isinstance(branches, list):
        errors.append("branch inventory is missing")
        branches = []
    edge_count = 0
    observed_count = 0
    infeasible_count = 0
    for branch in branches:
        if not isinstance(branch, dict) or not branch.get("id"):
            errors.append("malformed branch entry")
            continue
        edges = branch.get("edges")
        if not isinstance(edges, dict) or set(edges) != {"taken", "not_taken"}:
            errors.append(f"branch {branch.get('id')} must contain both edges")
            continue
        for name, edge in edges.items():
            edge_count += 1
            if not isinstance(edge, dict):
                errors.append(f"branch {branch['id']} edge {name} is malformed")
                continue
            status = edge.get("status")
            if status == "observed":
                observed_count += 1
                if not edge.get("target_run_ids"):
                    errors.append(f"branch {branch['id']} edge {name} lacks target runs")
            elif status == "infeasible":
                infeasible_count += 1
                proof = edge.get("triton_proof")
                if not isinstance(proof, dict) or proof.get("sat") is not False:
                    errors.append(f"branch {branch['id']} edge {name} lacks UNSAT proof")
                elif not proof.get("predicate_sha256") or not proof.get("path_prefix_sha256"):
                    errors.append(f"branch {branch['id']} edge {name} lacks AST hashes")
            else:
                errors.append(f"branch {branch['id']} edge {name} remains unknown")
    metrics = report.get("metrics")
    if not isinstance(metrics, dict):
        errors.append("coverage metrics are missing")
    else:
        expected = {
            "branch_edge_total": edge_count,
            "branch_edge_observed": observed_count,
            "branch_edge_infeasible": infeasible_count,
        }
        for key, value in expected.items():
            if metrics.get(key) != value:
                errors.append(f"metric {key} must equal {value}")
        for key in (
            "instruction_total",
            "instruction_covered",
            "basic_block_total",
            "basic_block_covered",
            "return_total",
            "return_covered",
            "error_outcome_total",
            "error_outcome_covered",
            "sink_total",
            "sink_covered",
        ):
            if not isinstance(metrics.get(key), int) or metrics[key] < 0:
                errors.append(f"metric {key} is missing or invalid")
        for total, covered in (
            ("instruction_total", "instruction_covered"),
            ("basic_block_total", "basic_block_covered"),
            ("return_total", "return_covered"),
            ("error_outcome_total", "error_outcome_covered"),
            ("sink_total", "sink_covered"),
        ):
            if isinstance(metrics.get(total), int) and metrics.get(covered) != metrics[total]:
                errors.append(f"{covered} does not close {total}")
    for key in (
        "uncovered_edges",
        "uncovered_returns",
        "uncovered_error_outcomes",
        "uncovered_sinks",
    ):
        if report.get(key) != []:
            errors.append(f"{key} must be an empty list")
    return errors


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("report", type=Path)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    try:
        report = json.loads(args.report.read_text(encoding="utf-8"))
        if not isinstance(report, dict):
            raise ValueError("report root must be an object")
        errors = validate(report)
    except Exception as error:
        errors = [str(error)]
    result = {
        "schema": VALIDATION_SCHEMA,
        "passed": not errors,
        "errors": errors,
    }
    rendered = json.dumps(result, indent=2, ensure_ascii=False) + "\n"
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(rendered, encoding="utf-8")
    print(rendered, end="")
    return 0 if result["passed"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
