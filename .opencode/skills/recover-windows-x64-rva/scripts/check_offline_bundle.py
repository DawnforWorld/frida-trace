#!/usr/bin/env python3
"""Validate the fixed offline toolchain layout for this skill."""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
from pathlib import Path


SCHEMA = "rva-recovery-offline-toolchain-check/1.0"


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest().upper()


def file_record(path: Path) -> dict[str, object]:
    return {
        "path": str(path),
        "exists": path.is_file(),
        "sha256": sha256(path) if path.is_file() else None,
        "size": path.stat().st_size if path.is_file() else None,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--skill-root", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--output", type=Path)
    parser.add_argument("--skip-triton-run", action="store_true")
    args = parser.parse_args()

    skill_root = args.skill_root.resolve()
    triton_python = skill_root / ".runtime" / "triton-py314" / "Scripts" / "python.exe"
    pin_exe = skill_root / "toolchain" / "pin" / "pin.exe"
    trace_tool = skill_root / "toolchain" / "trace" / "MyPinTool.dll"

    report: dict[str, object] = {
        "schema": SCHEMA,
        "skill_root": str(skill_root),
        "fixed_paths": {
            "triton_python": file_record(triton_python),
            "pin_exe": file_record(pin_exe),
            "trace_tool": file_record(trace_tool),
        },
        "triton_preflight": {"attempted": False},
        "frida_preflight": {"attempted": False},
    }

    passed = triton_python.is_file() and pin_exe.is_file() and trace_tool.is_file()
    if triton_python.is_file() and not args.skip_triton_run:
        result = subprocess.run(
            [
                str(triton_python),
                str(skill_root / "scripts" / "check_triton.py"),
            ],
            text=True,
            capture_output=True,
        )
        report["triton_preflight"] = {
            "attempted": True,
            "returncode": result.returncode,
            "stdout": result.stdout,
            "stderr": result.stderr,
        }
        passed = passed and result.returncode == 0

        frida_result = subprocess.run(
            [
                str(triton_python),
                "-c",
                "import frida, json; print(json.dumps({'version': frida.__version__, 'module': frida.__file__}))",
            ],
            text=True,
            capture_output=True,
        )
        report["frida_preflight"] = {
            "attempted": True,
            "returncode": frida_result.returncode,
            "stdout": frida_result.stdout,
            "stderr": frida_result.stderr,
        }
        passed = passed and frida_result.returncode == 0

    report["passed"] = passed
    rendered = json.dumps(report, indent=2, ensure_ascii=False) + "\n"
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(rendered, encoding="utf-8")
    print(rendered, end="")
    return 0 if passed else 2


if __name__ == "__main__":
    raise SystemExit(main())
