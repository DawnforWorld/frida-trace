from __future__ import annotations

import sys
import hashlib
import json
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
sys.path.insert(0, str(ROOT / "runtime" / "replay"))

from compare_behavior import differences, validate_exact_encoding
from triton import ARCH, TritonContext
from triton_replay import _uncaptured_state_reason, _uses_uncaptured_state
from validate_coverage import validate as validate_coverage
from validate_recovery_gate import validate_gate
from validate_recovery_gate import CAPABILITY_GROUPS, ALWAYS_USED_CAPABILITIES, COMPLETENESS_DOMAINS


class ToolingTests(unittest.TestCase):
    def test_ieee_bits_are_not_tolerated(self) -> None:
        target = {"return": {"kind": "f64", "bits": "0000000000000000"}}
        candidate = {"return": {"kind": "f64", "bits": "8000000000000000"}}
        result = differences(target, candidate)
        self.assertEqual(result[0]["path"], "observations.return.bits")
        with self.assertRaisesRegex(ValueError, "JSON floating number"):
            validate_exact_encoding({"return": 0.0})
        with self.assertRaisesRegex(ValueError, "16 hexadecimal digits"):
            validate_exact_encoding({"return": {"kind": "f64", "bits": "0"}})

    def test_uncaptured_floating_state_is_detected(self) -> None:
        self.assertTrue(_uses_uncaptured_state("movsd xmm0, qword ptr [rax]"))
        self.assertTrue(_uses_uncaptured_state("fld st(0)"))
        self.assertTrue(_uses_uncaptured_state("kmovw k1, eax"))
        self.assertFalse(_uses_uncaptured_state("add rax, rbx"))
        context = TritonContext(ARCH.X86_64)
        self.assertIsNotNone(
            _uncaptured_state_reason(
                context,
                {"disasm": "movsd xmm0, qword ptr [rax]"},
            )
        )
        self.assertIsNone(
            _uncaptured_state_reason(
                context,
                {
                    "disasm": "movsd xmm0, qword ptr [rax]",
                    "extended_regs": {
                        "mxcsr": "0x00001f80",
                        "xmm": {
                            **{
                                f"xmm{index}": "00000000000000000000000000000000"
                                for index in range(16)
                            }
                        },
                    },
                },
            )
        )

    def test_unknown_coverage_edge_fails(self) -> None:
        report = {
            "schema": "rva-triton-coverage/1.0",
            "passed": True,
            "queue_exhausted": True,
            "runs": [{"id": "seed"}],
            "branches": [
                {
                    "id": "b0",
                    "edges": {
                        "taken": {"status": "observed", "target_run_ids": ["seed"]},
                        "not_taken": {"status": "unknown"},
                    },
                }
            ],
            "metrics": {
                "branch_edge_total": 2,
                "branch_edge_observed": 1,
                "branch_edge_infeasible": 0,
                "instruction_total": 1,
                "instruction_covered": 1,
                "basic_block_total": 1,
                "basic_block_covered": 1,
                "return_total": 1,
                "return_covered": 1,
                "error_outcome_total": 0,
                "error_outcome_covered": 0,
                "sink_total": 1,
                "sink_covered": 1,
            },
            "uncovered_edges": ["b0:not_taken"],
            "uncovered_returns": [],
            "uncovered_error_outcomes": [],
            "uncovered_sinks": [],
        }
        self.assertTrue(validate_coverage(report))

    def test_example_manifest_cannot_pass(self) -> None:
        result = validate_gate(ROOT / "templates" / "recovery-gate.example.json")
        self.assertFalse(result["passed"])
        self.assertTrue(result["errors"])

    def test_complete_synthetic_gate_can_pass(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            case = Path(temporary)

            def write_bytes(name: str, value: bytes) -> tuple[str, str]:
                path = case / name
                path.write_bytes(value)
                return name, hashlib.sha256(value).hexdigest().upper()

            def write_json(name: str, value: object) -> str:
                (case / name).write_text(json.dumps(value), encoding="utf-8")
                return name

            target_path, target_hash = write_bytes("target.exe", b"target")
            candidate_path, candidate_hash = write_bytes("candidate.exe", b"candidate")
            trace_path, trace_hash = write_bytes("trace.jsonl", b"trace")
            preflight = write_json(
                "preflight.json",
                {
                    "schema": "rva-recovery-triton-preflight/1.0",
                    "passed": True,
                },
            )
            capabilities = write_json(
                "capabilities.json",
                {
                    "schema": "rva-recovery-triton-capabilities/1.0",
                    "passed": True,
                    "groups": {
                        group: {"passed": True} for group in CAPABILITY_GROUPS
                    },
                },
            )
            coverage = write_json(
                "coverage.json",
                {
                    "schema": "rva-triton-coverage/1.0",
                    "passed": True,
                    "queue_exhausted": True,
                    "function": "f",
                    "runs": [{"id": "primary"}],
                    "branches": [],
                    "metrics": {
                        "branch_edge_total": 0,
                        "branch_edge_observed": 0,
                        "branch_edge_infeasible": 0,
                        "instruction_total": 1,
                        "instruction_covered": 1,
                        "basic_block_total": 1,
                        "basic_block_covered": 1,
                        "return_total": 1,
                        "return_covered": 1,
                        "error_outcome_total": 0,
                        "error_outcome_covered": 0,
                        "sink_total": 1,
                        "sink_covered": 1,
                    },
                    "uncovered_edges": [],
                    "uncovered_returns": [],
                    "uncovered_error_outcomes": [],
                    "uncovered_sinks": [],
                },
            )
            replay = write_json(
                "replay.json",
                {
                    "schema": "pintrace-triton-replay/1.1",
                    "configuration": {
                        "strict": True,
                        "solve_branches": True,
                        "track_dataflow": True,
                        "through_external": False,
                    },
                    "counters": {
                        "processed": 1,
                        "branch_solver_failures": 0,
                        **{name: 0 for name in (
                            "unsupported_instructions",
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
                        )},
                    },
                    "range": {"stop_reason": "end_of_trace"},
                    "branch_constraints": [],
                    "goals": [
                        {
                            "tainted": True,
                            "backward_slice": {
                                "tainted_expression_ids": [1],
                            },
                        }
                    ],
                    "taint": {"tainted_goal_count": 1},
                    "solver": {},
                },
            )
            analyzer_source = """
from triton import TritonContext
def analyze(ctx, reg, mem, inst, node):
    TritonContext()
    ctx.setConcreteRegisterValue(reg, 0)
    ctx.setConcreteMemoryAreaValue(0, b'x')
    ctx.processing(inst)
    ctx.sliceExpressions(node)
    ctx.simplify(node)
    ctx.getPathConstraints()
    ctx.getPathPredicate()
    ctx.getPredicatesToReachAddress(0)
    ctx.pushPathConstraint(node)
    ctx.popPathConstraint()
    ctx.isSat(node)
    ctx.getModel(node)
    ctx.getModels(node, 2)
    ctx.symbolizeMemory(mem)
    ctx.taintMemory(mem)
    ctx.taintAssignment(reg, mem)
    ctx.taintUnion(reg, mem)
    ctx.getTaintedMemory()
    ctx.getTaintedRegisters()
    ctx.concretizeMemory(mem)
    ctx.concretizeRegister(reg)
    ctx.getMemoryAst(mem)
    ast = ctx.getAstContext()
    ast.unroll(node)
    ast.tritonToZ3(node)
    ast.z3ToTriton(node)
    ast.duplicate(node)
    ast.search(node, 0)
"""
            analyzer_path = case / "analyzer.py"
            analyzer_path.write_text(analyzer_source, encoding="utf-8")
            analyzer_hash = hashlib.sha256(analyzer_path.read_bytes()).hexdigest().upper()
            ledger = {
                group: (
                    {"status": "used", "artifacts": ["case.json"]}
                    if group in ALWAYS_USED_CAPABILITIES
                    else {"status": "not_applicable", "reason": "branchless fixture"}
                )
                for group in CAPABILITY_GROUPS
            }
            case_report = write_json(
                "case.json",
                {
                    "schema": "rva-recovery-triton-case/1.0",
                    "passed": True,
                    "script_sha256": analyzer_hash,
                    "capability_ledger": ledger,
                    "exact_replay": {
                        "processed_instructions": 1,
                        "all_next_pcs_match": True,
                        "all_reliable_writes_match": True,
                        "full_window": True,
                        "unsupported_state_count": 0,
                        "external_provenance_loss_count": 0,
                        "resynchronization_count": 0,
                    },
                    "sinks": [
                        {
                            "id": "return",
                            "concrete_match": True,
                            "simplification_equivalent": True,
                            "raw_ast_sha256": "A" * 64,
                            "simplified_ast_sha256": "B" * 64,
                            "slice_sha256": "C" * 64,
                            "slice_expression_ids": [1],
                            "tainted_slice_expression_ids": [1],
                            "tainted": True,
                            "symbolic": True,
                        }
                    ],
                    "branches": [],
                },
            )
            pe_unwind = write_json(
                "pe-unwind.json",
                {
                    "schema": "pe-unwind-inventory/1.1",
                    "passed": True,
                    "target": {"sha256": target_hash},
                    "exception_directory": {"parsed": True},
                    "functions": [
                        {
                            "name": "f",
                            "entry_rva": "0x1000",
                            "function_covered": True,
                            "runtime_function_mapped": True,
                            "unknown_unwind_info": False,
                            "unknown_handlers": False,
                            "unknown_language_specific_data": False,
                        }
                    ],
                },
            )
            pe_unwind_hash = hashlib.sha256((case / pe_unwind).read_bytes()).hexdigest().upper()
            manifest = {
                "schema": "rva-recovery-gate/1.0",
                "claim": "complete",
                "provenance": {
                    "target": {"path": target_path, "sha256": target_hash},
                    "semantic_sources": [
                        {
                            "id": "target",
                            "role": "target",
                            "path": target_path,
                            "sha256": target_hash,
                            "candidate_model": False,
                            "created_before_recovery": True,
                        }
                    ],
                    "trace_artifacts": [
                        {
                            "path": trace_path,
                            "sha256": trace_hash,
                            "source_id": "target",
                        }
                    ],
                    "candidate_artifacts": [
                        {"path": candidate_path, "sha256": candidate_hash}
                    ],
                    "sealed_source_oracle": {
                        "used_for_recovery": False,
                        "revealed_after_freeze": True,
                    },
                },
                "functions": [
                    {
                        "name": "f",
                        "unknown": [],
                        "completeness_contract": {
                            "definition": "recover-function-behavior/1.0",
                            "complete": True,
                            "domains": {
                                domain: {
                                    "status": "complete",
                                    "evidence": ["fixture"],
                                    "unknown": [],
                                }
                                for domain in COMPLETENESS_DOMAINS
                            },
                            "machine_state_domain": {
                                "registers": "captured",
                                "stack": "captured",
                                "flags": "captured",
                                "memory": "captured",
                                "external_state": "captured",
                            },
                            "environment_assumptions": [
                                {
                                    "name": "fixture",
                                    "validated": True,
                                }
                            ],
                        },
                        "exception_inventory": {
                            "complete": True,
                            "pe_unwind": {
                                "path": pe_unwind,
                                "sha256": pe_unwind_hash,
                                "exception_directory_parsed": True,
                                "function_covered": True,
                                "runtime_function_mapped": True,
                                "unknown_unwind_info": False,
                                "unknown_handlers": False,
                                "unknown_language_specific_data": False,
                            },
                            "cxx_eh": {"status": "not_present"},
                            "seh": {"status": "not_present"},
                            "runtime_exception_matrix": [],
                            "no_runtime_exceptions_proven": True,
                        },
                        "floating_point": {
                            "used": False,
                            "absence_evidence": "instruction inventory",
                        },
                        "sinks": [
                            {
                                "id": "return",
                                "kind": "register",
                                "taint_required": True,
                            }
                        ],
                        "branch_inventory": {
                            "complete": True,
                            "branches": [],
                        },
                        "error_inventory": {
                            "complete": True,
                            "outcomes": [],
                            "no_errors_proven": True,
                        },
                        "triton": {
                            "preflight": preflight,
                            "capability_audit": capabilities,
                            "coverage_report": coverage,
                            "case_analyzer": {
                                "path": "analyzer.py",
                                "sha256": analyzer_hash,
                                "report": case_report,
                            },
                            "replays": [
                                {
                                    "id": "replay",
                                    "report": replay,
                                    "strict": True,
                                    "full_window": True,
                                }
                            ],
                            "taint": [
                                {
                                    "sink_id": "return",
                                    "replay_id": "replay",
                                    "goal_index": 0,
                                }
                            ],
                            "paths": [],
                        },
                        "cpp_evidence_map": [
                            {
                                "kind": "return",
                                "status": "verified",
                                "cpp_ref": "return rax",
                                "sink_id": "return",
                                "trace_run_id": "primary",
                                "replay_id": "replay",
                                "evidence": ["fixture"],
                            }
                        ],
                    }
                ],
            }
            manifest_path = case / "gate.json"
            manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
            result = validate_gate(manifest_path)
            self.assertTrue(result["passed"], result["errors"])

            replay_path = case / replay
            replay_document = json.loads(replay_path.read_text(encoding="utf-8"))
            replay_document["configuration"]["track_dataflow"] = False
            replay_path.write_text(json.dumps(replay_document), encoding="utf-8")
            result = validate_gate(manifest_path)
            self.assertFalse(result["passed"])
            self.assertTrue(
                any("DTA data-flow tracking" in error for error in result["errors"]),
                result["errors"],
            )


if __name__ == "__main__":
    unittest.main()
