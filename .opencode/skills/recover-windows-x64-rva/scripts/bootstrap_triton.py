#!/usr/bin/env python3
"""Create the skill-local, offline Triton CPython environment."""

from __future__ import annotations

import argparse
import hashlib
import json
import platform
import subprocess
import sys
import venv
from pathlib import Path


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest().upper()


def main() -> int:
    skill_root = Path(__file__).resolve().parents[1]
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--env-dir", type=Path, default=skill_root / ".runtime" / "triton-py314")
    parser.add_argument("--rebuild", action="store_true")
    args = parser.parse_args()

    if sys.platform != "win32" or sys.implementation.name != "cpython":
        raise SystemExit("bootstrap requires 64-bit Windows CPython")
    if sys.version_info[:2] != (3, 14) or platform.machine().lower() not in {"amd64", "x86_64"}:
        raise SystemExit(
            f"bootstrap requires CPython 3.14 AMD64, got {platform.python_version()} {platform.machine()}"
        )

    lock_path = skill_root / "vendor" / "runtime-lock.json"
    lock = json.loads(lock_path.read_text(encoding="utf-8"))
    if (
        lock.get("schema") != "rva-recovery-triton-runtime-lock/1.0"
        or lock.get("platform") != "win_amd64"
        or lock.get("implementation") != "cpython"
        or lock.get("python") != "3.14"
        or lock.get("abi") != "cp314"
    ):
        raise SystemExit(f"invalid runtime lock: {lock_path}")
    packages = lock.get("packages")
    if not isinstance(packages, list) or not packages:
        raise SystemExit(f"runtime lock has no packages: {lock_path}")

    wheels = []
    for package in packages:
        wheel_name = package.get("file")
        expected_hash = package.get("sha256")
        if not isinstance(wheel_name, str) or not isinstance(expected_hash, str):
            raise SystemExit(f"invalid package entry in runtime lock: {package!r}")
        wheel = skill_root / "vendor" / wheel_name
        if not wheel.is_file():
            raise SystemExit(f"vendored wheel is missing: {wheel}")
        actual_hash = sha256(wheel)
        if actual_hash != expected_hash:
            raise SystemExit(
                f"vendored wheel hash mismatch for {wheel_name}: {actual_hash}"
            )
        wheels.append((wheel, actual_hash))

    env_dir = args.env_dir.resolve()
    env_python = env_dir / "Scripts" / "python.exe"

    def install_wheels() -> None:
        subprocess.run(
            [
                str(env_python),
                "-m",
                "pip",
                "install",
                "--disable-pip-version-check",
                "--no-index",
                "--no-deps",
                "--upgrade",
                *[str(wheel) for wheel, _ in wheels],
            ],
            check=True,
        )

    if env_python.exists() and not args.rebuild:
        install_wheels()
        preflight = env_dir / "triton-preflight.json"
        capabilities = env_dir / "triton-capabilities.json"
        preflight_result = subprocess.run(
            [
                str(env_python),
                str(skill_root / "scripts" / "check_triton.py"),
                "--output",
                str(preflight),
            ],
            text=True,
            capture_output=True,
        )
        capability_result = subprocess.run(
            [
                str(env_python),
                str(skill_root / "scripts" / "audit_triton_capabilities.py"),
                "--output",
                str(capabilities),
            ],
            text=True,
            capture_output=True,
        )
        if preflight_result.returncode == 0 and capability_result.returncode == 0:
            print(preflight_result.stdout, end="")
            print(capability_result.stdout, end="")
            return 0
        raise SystemExit(
            f"existing environment failed Triton audit; rerun with --rebuild\n"
            f"{preflight_result.stdout}{preflight_result.stderr}"
            f"{capability_result.stdout}{capability_result.stderr}"
        )

    venv.EnvBuilder(with_pip=True, clear=args.rebuild).create(env_dir)
    install_wheels()
    preflight = env_dir / "triton-preflight.json"
    subprocess.run(
        [str(env_python), str(skill_root / "scripts" / "check_triton.py"), "--output", str(preflight)],
        check=True,
    )
    capabilities = env_dir / "triton-capabilities.json"
    subprocess.run(
        [
            str(env_python),
            str(skill_root / "scripts" / "audit_triton_capabilities.py"),
            "--output",
            str(capabilities),
        ],
        check=True,
    )
    print(
        json.dumps(
            {
                "schema": "rva-recovery-triton-bootstrap/1.0",
                "passed": True,
                "python": str(env_python),
                "wheels": [
                    {"path": str(wheel), "sha256": actual_hash}
                    for wheel, actual_hash in wheels
                ],
                "preflight": str(preflight),
                "capabilities": str(capabilities),
            },
            indent=2,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
