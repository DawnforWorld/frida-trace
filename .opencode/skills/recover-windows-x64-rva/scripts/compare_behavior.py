#!/usr/bin/env python3
"""Compare target and candidate harness observations with zero tolerance."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
from pathlib import Path
from typing import Any


INPUT_SCHEMA = "rva-behavior-run/1.0"
OUTPUT_SCHEMA = "rva-behavior-differential/1.0"
REQUIRED_OBSERVATIONS = {
    "return",
    "outputs",
    "memory_side_effects",
    "callbacks",
    "error_channels",
    "sentinels",
    "termination",
    "floating_environment",
}
IEEE_BITS = {"f32": 8, "f64": 16}


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest().upper()


def validate_exact_encoding(value: Any, path: str = "observations") -> None:
    if isinstance(value, float):
        raise ValueError(
            f"{path} is a JSON floating number; encode IEEE-754 values as raw hex bits"
        )
    if isinstance(value, dict):
        kind = value.get("kind")
        if kind in IEEE_BITS:
            bits = value.get("bits")
            width = IEEE_BITS[kind]
            if not isinstance(bits, str) or re.fullmatch(
                rf"[0-9A-Fa-f]{{{width}}}", bits
            ) is None:
                raise ValueError(
                    f"{path}.bits must be exactly {width} hexadecimal digits for {kind}"
                )
        for key, item in value.items():
            validate_exact_encoding(item, f"{path}.{key}")
    elif isinstance(value, list):
        for index, item in enumerate(value):
            validate_exact_encoding(item, f"{path}[{index}]")


def load(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict) or value.get("schema") != INPUT_SCHEMA:
        raise ValueError(f"{path} is not {INPUT_SCHEMA}")
    observations = value.get("observations")
    if not isinstance(observations, dict):
        raise ValueError(f"{path} has no observations object")
    missing = REQUIRED_OBSERVATIONS - set(observations)
    extra = set(observations) - REQUIRED_OBSERVATIONS
    if missing or extra:
        raise ValueError(f"{path} observation keys differ: missing={sorted(missing)} extra={sorted(extra)}")
    validate_exact_encoding(observations)
    return value


def differences(left: Any, right: Any, path: str = "observations") -> list[dict[str, Any]]:
    if type(left) is not type(right):
        return [{"path": path, "target": left, "candidate": right, "reason": "type"}]
    if isinstance(left, dict):
        result: list[dict[str, Any]] = []
        for key in sorted(set(left) | set(right)):
            if key not in left or key not in right:
                result.append(
                    {
                        "path": f"{path}.{key}",
                        "target": left.get(key, "<missing>"),
                        "candidate": right.get(key, "<missing>"),
                        "reason": "missing",
                    }
                )
            else:
                result.extend(differences(left[key], right[key], f"{path}.{key}"))
        return result
    if isinstance(left, list):
        result = []
        if len(left) != len(right):
            result.append(
                {
                    "path": f"{path}.length",
                    "target": len(left),
                    "candidate": len(right),
                    "reason": "length",
                }
            )
        for index, (left_item, right_item) in enumerate(zip(left, right)):
            result.extend(differences(left_item, right_item, f"{path}[{index}]"))
        return result
    if left != right:
        return [{"path": path, "target": left, "candidate": right, "reason": "value"}]
    return []


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("target", type=Path)
    parser.add_argument("candidate", type=Path)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()

    try:
        target = load(args.target.resolve())
        candidate = load(args.candidate.resolve())
        errors = []
        for field in ("run_id", "function", "input_sha256"):
            if target.get(field) != candidate.get(field):
                errors.append(
                    {
                        "path": field,
                        "target": target.get(field),
                        "candidate": candidate.get(field),
                        "reason": "identity",
                    }
                )
        errors.extend(differences(target["observations"], candidate["observations"]))
        result = {
            "schema": OUTPUT_SCHEMA,
            "passed": not errors,
            "comparison": "exact_structural_and_bitwise",
            "tolerance_used": False,
            "target": str(args.target.resolve()),
            "target_sha256": sha256(args.target.resolve()),
            "candidate": str(args.candidate.resolve()),
            "candidate_sha256": sha256(args.candidate.resolve()),
            "difference_count": len(errors),
            "differences": errors[:1000],
        }
    except Exception as error:
        result = {
            "schema": OUTPUT_SCHEMA,
            "passed": False,
            "comparison": "exact_structural_and_bitwise",
            "tolerance_used": False,
            "error": str(error),
        }

    rendered = json.dumps(result, indent=2, ensure_ascii=False) + "\n"
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(rendered, encoding="utf-8")
    print(rendered, end="")
    return 0 if result["passed"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
