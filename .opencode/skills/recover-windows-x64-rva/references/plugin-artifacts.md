# Plugin and Artifact Contract

After evidence-only PASS, when an automated artifact writer is useful:

```cmd
CREATE_CASE.cmd case_id --add-plugin
```

Implement `API_VERSION = 1` and `analyze(context)` in `cases\case_id\plugin.py`.

```python
API_VERSION = 1

def analyze(context):
    passed = verify_all_captured_runs(context)
    cpp = build_behavior_equivalent_cpp(context) if passed else ""
    return {
        "name": "local-transform/1.0",
        "checks": [
            {
                "name": "independent_vectors",
                "passed": passed,
                "required": True,
                "detail": "captured runs and independent reference agree",
            }
        ],
        "data": {"boundary": "selected RVA interval"},
        "findings": {
            "verified": ["exact behavior supported by trace and vectors"],
            "inferred": ["source-like names and local types"],
            "unknown": ["unexecuted branches and original symbols"],
        },
        "report_markdown": "## Local transform\n\nEvidence-backed conclusion.\n",
        "artifacts": [
            {
                "name": "recovered_cpp",
                "path": "output/recovered_case_id.cpp",
                "content": cpp,
                "encoding": "utf-8",
            }
        ],
    }
```

The plugin may read package-local references and `context` but must not mutate the sample, snapshot, or raw trace. Return artifact content to the engine; do not write it directly. The engine writes artifacts only after every required core/plugin check and `scripts/validate_recovery_gate.py` pass and records each artifact hash.

Use `context["traces"]` for multi-run validation, `context["core"]` for anchors/calls/ranges, `context["snapshots"]` for runtime bytes, and `context["hashes"]` for provenance. Include hashes of the case-specific Triton scripts, preflight/replay/case reports, AST artifacts, branch manifests, and `cpp_evidence_map`. The digest is an index; validate final conclusions against raw original-target records and Triton replay evidence.
