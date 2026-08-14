from __future__ import annotations

import io
import shutil
import subprocess
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator, TextIO


def zstd_executable() -> str | None:
    return shutil.which("zstd") or shutil.which("zstd.exe")


@contextmanager
def open_trace_text(path: Path) -> Iterator[TextIO]:
    if path.suffix.lower() != ".zst":
        with path.open("r", encoding="utf-8") as stream:
            yield stream
        return

    executable = zstd_executable()
    if not executable:
        raise RuntimeError(
            f"{path} is Zstandard-compressed, but zstd.exe is not available on PATH"
        )

    process = subprocess.Popen(
        [executable, "-q", "-d", "-c", "--", str(path)],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    assert process.stdout is not None
    assert process.stderr is not None
    stream = io.TextIOWrapper(process.stdout, encoding="utf-8")
    completed = False
    try:
        yield stream
        completed = process.poll() is not None
    finally:
        stream.close()
        if process.poll() is None:
            process.terminate()
        stderr = process.stderr.read().decode("utf-8", "replace").strip()
        return_code = process.wait()
        process.stderr.close()
        if completed and return_code != 0:
            detail = f": {stderr}" if stderr else ""
            raise RuntimeError(f"zstd failed with exit code {return_code}{detail}")
