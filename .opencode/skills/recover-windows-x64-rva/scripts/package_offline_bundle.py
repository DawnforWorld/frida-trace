#!/usr/bin/env python3
"""Build an offline-ready bundle for the recover-windows-x64-rva skill.

The default output is a self-contained skill directory that can be copied into
the Codex skills folder on another machine. Optional Pin and tracer roots can
be mirrored into a toolchain subdirectory when the user has fixed versions.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import tempfile
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable


SKILL_TOP_LEVEL = (
    "SKILL.md",
    "agents",
    "references",
    "runtime",
    "scripts",
    "templates",
    "tests",
    "vendor",
    ".runtime",
)

DEFAULT_PIN_ROOT = Path(
    r"C:\project\vmp\dump\vmp_v8_满血_instance10\VMP_Offline_Recovery_Kit_20260803_FINAL\runtime\pin"
)
DEFAULT_PIN_TOOL = Path(
    r"C:\project\vmp\dump\vmp_v8_满血_instance10\VMP_Offline_Recovery_Kit_20260803_FINAL\tools\tracer\MyPinTool.dll"
)
DEFAULT_TRACE_ROOT = Path(
    r"C:\project\vmp\dump\vmp_v8_满血_instance10\VMP_Offline_Recovery_Kit_20260803_FINAL\tools\tracer"
)


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest().upper()


def copy_entry(source: Path, destination: Path) -> int:
    if source.is_dir():
        shutil.copytree(source, destination)
        count = 0
        for path in destination.rglob("*"):
            if path.is_file():
                count += 1
        return count
    destination.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(source, destination)
    return 1


def copy_tree(source_root: Path, destination_root: Path, entries: Iterable[str]) -> list[dict[str, object]]:
    records: list[dict[str, object]] = []
    for name in entries:
        source = source_root / name
        if not source.exists():
            continue
        destination = destination_root / name
        copied_files = copy_entry(source, destination)
        records.append(
            {
                "name": name,
                "source": str(source),
                "destination": str(destination),
                "kind": "directory" if source.is_dir() else "file",
                "sha256": sha256(source) if source.is_file() else None,
                "copied_files": copied_files,
            }
        )
    return records


def mirror_root(source: Path, destination: Path, label: str) -> dict[str, object]:
    if not source.exists():
        raise FileNotFoundError(source)
    if destination.exists():
        shutil.rmtree(destination)
    files = copy_entry(source, destination)
    return {
        "label": label,
        "source": str(source),
        "destination": str(destination),
        "kind": "directory" if source.is_dir() else "file",
        "file_count": files,
    }


def write_bootstrap(bundle_root: Path) -> None:
    cmd = bundle_root / "bootstrap_bundle.cmd"
    cmd.write_text(
        "@echo off\r\n"
        "setlocal\r\n"
        "set \"BUNDLE_ROOT=%~dp0\"\r\n"
        "\"%BUNDLE_ROOT%\\.runtime\\triton-py314\\Scripts\\python.exe\" "
        "\"%BUNDLE_ROOT%\\scripts\\bootstrap_triton.py\" %*\r\n",
        encoding="utf-8",
    )


def write_bundle_check(bundle_root: Path) -> None:
    cmd = bundle_root / "check_bundle.cmd"
    cmd.write_text(
        "@echo off\r\n"
        "setlocal\r\n"
        "set \"BUNDLE_ROOT=%~dp0\"\r\n"
        "\"%BUNDLE_ROOT%\\.runtime\\triton-py314\\Scripts\\python.exe\" "
        "\"%BUNDLE_ROOT%\\scripts\\check_offline_bundle.py\" %*\r\n",
        encoding="utf-8",
    )


def zip_bundle(source_root: Path, zip_path: Path) -> None:
    with zipfile.ZipFile(zip_path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for path in sorted(source_root.rglob("*")):
            if path.is_dir():
                continue
            arcname = (Path(source_root.name) / path.relative_to(source_root)).as_posix()
            zf.write(path, arcname)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True, type=Path, help="bundle directory or .zip file")
    parser.add_argument("--zip", action="store_true", help="force zip output even if --output has no .zip suffix")
    parser.add_argument("--pin-root", type=Path, help="optional fixed Pin root to mirror into toolchain/pin")
    parser.add_argument("--pin-tool", type=Path, help="optional fixed Pin tool DLL to mirror into toolchain/pin-tool")
    parser.add_argument("--trace-root", type=Path, help="optional fixed trace helper root to mirror into toolchain/trace")
    parser.add_argument("--no-default-toolchain", action="store_true", help="do not auto-include the validated local toolchain")
    args = parser.parse_args()

    skill_root = Path(__file__).resolve().parents[1]
    output = args.output.resolve()
    zip_mode = args.zip or output.suffix.lower() == ".zip"

    with tempfile.TemporaryDirectory(prefix="recover-windows-x64-rva-bundle-") as temp_dir:
        stage_root = Path(temp_dir) / skill_root.name
        stage_root.mkdir(parents=True, exist_ok=True)

        included = copy_tree(skill_root, stage_root, SKILL_TOP_LEVEL)
        write_bootstrap(stage_root)
        write_bundle_check(stage_root)

        toolchain_records: list[dict[str, object]] = []
        toolchain_root = stage_root / "toolchain"
        pin_root = args.pin_root or (None if args.no_default_toolchain else DEFAULT_PIN_ROOT)
        pin_tool = args.pin_tool or (None if args.no_default_toolchain else DEFAULT_PIN_TOOL)
        trace_root = args.trace_root or (None if args.no_default_toolchain else DEFAULT_TRACE_ROOT)
        if pin_root and pin_root.exists():
            toolchain_records.append(
                mirror_root(pin_root.resolve(), toolchain_root / "pin", "pin_root")
            )
        if pin_tool and pin_tool.is_file():
            destination = toolchain_root / "pin-tool" / pin_tool.name
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(pin_tool.resolve(), destination)
            toolchain_records.append(
                {
                    "label": "pin_tool",
                    "source": str(pin_tool.resolve()),
                    "destination": str(destination),
                    "kind": "file",
                    "sha256": sha256(pin_tool.resolve()),
                }
            )
        if trace_root and trace_root.exists():
            toolchain_records.append(
                mirror_root(trace_root.resolve(), toolchain_root / "trace", "trace_root")
            )

        manifest = {
            "schema": "rva-recovery-offline-bundle/1.0",
            "created_utc": datetime.now(timezone.utc).isoformat(),
            "skill_root": str(skill_root),
            "bundle_name": skill_root.name,
            "bundle_type": "zip" if zip_mode else "directory",
            "generic_skill_entries": included,
            "toolchain_entries": toolchain_records,
            "notes": [
                "Source code is excluded from the bundle by design.",
                "Trace/probe artifacts are sample-specific and should be kept outside the bundle.",
                "Pin and trace helpers are included by default from the validated local roots when available.",
            ],
        }
        (stage_root / "bundle_manifest.json").write_text(
            json.dumps(manifest, indent=2, ensure_ascii=False) + "\n",
            encoding="utf-8",
        )

        if zip_mode:
            if output.exists():
                output.unlink()
            output.parent.mkdir(parents=True, exist_ok=True)
            zip_bundle(stage_root, output)
        else:
            if output.exists():
                shutil.rmtree(output)
            shutil.copytree(stage_root, output)

    print(
        json.dumps(
            {
                "schema": "rva-recovery-offline-bundle-build/1.0",
                "passed": True,
                "output": str(output),
                "zip": zip_mode,
            },
            indent=2,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
