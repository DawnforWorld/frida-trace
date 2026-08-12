from __future__ import annotations

import argparse
import ctypes
import ctypes.wintypes
import signal
import sys
import threading
from pathlib import Path
from typing import Any

import frida

from .unidbg_text import UnidbgTextWriter


PACKAGE_ROOT = Path(__file__).resolve().parent
AGENT_PATH = PACKAGE_ROOT / "agent" / "rva_trace.js"


class CliError(RuntimeError):
    pass


def parse_int(value: str) -> int:
    try:
        parsed = int(value, 0)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(f"invalid integer/RVA: {value!r}") from exc
    if parsed < 0:
        raise argparse.ArgumentTypeError("RVA must be >= 0")
    return parsed


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Attach to the process prepared by the native VEH launcher and "
            "trace instructions between two module RVAs."
        )
    )
    parser.add_argument("--pid", required=True, type=int, help="Native launcher target process id")
    parser.add_argument("--module", required=True, help="Target module name")
    parser.add_argument("--start-module", help="Start boundary module; defaults to --module")
    parser.add_argument("--stop-module", help="Stop boundary module; defaults to --module")
    parser.add_argument("--start-rva", default=0, type=parse_int, help="Inclusive start RVA; 0 means first instruction in start module")
    parser.add_argument("--end-rva", "--stop-rva", dest="end_rva", default=0, type=parse_int, help="Inclusive stop RVA; 0 means process exit")
    parser.add_argument(
        "--target-only",
        type=int,
        choices=(0, 1),
        default=1,
        help="Record only target/boundary modules (1) or cross-module owner-thread flow (0)",
    )
    parser.add_argument("--out", default="traces/trace.txt", help="Unidbg-style text output path")
    parser.add_argument("--thread-id", type=int, help="Only stalk this OS thread id")
    parser.add_argument(
        "--gate-address",
        help="Install an Interceptor gate at this address and start Stalker from its onEnter callback",
    )
    parser.add_argument(
        "--flush",
        type=int,
        default=1024,
        help="Trace rows buffered per message; 0 uses the full 16384-row buffer",
    )
    parser.add_argument(
        "--ready-event",
        help="Windows named event to signal after the Frida agent and Stalker are ready",
    )
    return parser.parse_args()


def signal_named_event(name: str) -> None:
    if sys.platform != "win32":
        raise CliError("--ready-event is only supported on Windows")

    EVENT_MODIFY_STATE = 0x0002
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.OpenEventW.argtypes = [ctypes.wintypes.DWORD, ctypes.wintypes.BOOL, ctypes.wintypes.LPCWSTR]
    kernel32.OpenEventW.restype = ctypes.wintypes.HANDLE
    kernel32.SetEvent.argtypes = [ctypes.wintypes.HANDLE]
    kernel32.SetEvent.restype = ctypes.wintypes.BOOL
    kernel32.CloseHandle.argtypes = [ctypes.wintypes.HANDLE]
    kernel32.CloseHandle.restype = ctypes.wintypes.BOOL

    event = kernel32.OpenEventW(EVENT_MODIFY_STATE, False, name)
    if not event:
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        if not kernel32.SetEvent(event):
            raise ctypes.WinError(ctypes.get_last_error())
    finally:
        kernel32.CloseHandle(event)


def main() -> int:
    args = parse_args()
    if args.pid <= 0:
        raise CliError("--pid must be > 0")
    if args.start_module is None:
        args.start_module = args.module
    if args.stop_module is None:
        args.stop_module = args.module

    if args.flush < 0:
        raise CliError("--flush must be >= 0")
    requested_out = Path(args.out).expanduser().resolve()

    device = frida.get_local_device()
    pid = args.pid
    session: frida.core.Session | None = None
    script: frida.core.Script | None = None
    text_writer = UnidbgTextWriter(requested_out)
    done = threading.Event()
    stopping = threading.Event()
    stats = {"rows": 0}

    def stop_requested(_signum: int | None = None, _frame: object | None = None) -> None:
        stopping.set()
        done.set()

    signal.signal(signal.SIGINT, stop_requested)
    signal.signal(signal.SIGTERM, stop_requested)

    def on_detached(reason: str, crash: object | None = None) -> None:
        print(f"detached: {reason}")
        if crash is not None:
            print(f"crash: {crash}", file=sys.stderr)
        if stats["rows"] == 0:
            print("no trace rows captured; start RVA was not observed before detach")
        done.set()

    def on_message(message: dict[str, Any], data: bytes | None) -> None:
        if message["type"] == "error":
            print(message.get("stack", message), file=sys.stderr)
            done.set()
            return

        if message["type"] != "send":
            print(f"frida message: {message}")
            return

        payload = message.get("payload", {})
        event_type = payload.get("type")

        if event_type == "trace":
            items = payload["items"]
            for item in items:
                text_writer.write(item)
            stats["rows"] += len(items)
            return

        if event_type == "ready":
            print(
                "module ready: "
                f"{payload['module']} base={payload['base']} "
                f"start={payload['startAddress']} end={payload['endAddress']}"
            )
            return

        if event_type == "waiting-module":
            print(f"waiting for module: {payload['module']}")
            return

        if event_type == "stalking-thread":
            print(f"stalking thread: {payload['threadId']}")
            return

        if event_type == "recording-started":
            print(
                "recording started: "
                f"tid={payload['threadId']} address={payload['address']} rva={payload['rva']}"
            )
            return

        if event_type == "done":
            print(
                "recording stopped: "
                f"tid={payload.get('threadId')} address={payload.get('address')} "
                f"rows={payload.get('count')} reason={payload.get('reason')}"
            )
            done.set()
            return

        if event_type == "agent-error":
            print(payload.get("message", payload), file=sys.stderr)
            done.set()
            return

        print(f"agent: {payload}")

    try:
        session = device.attach(pid)
        session.on("detached", on_detached)

        agent_source = AGENT_PATH.read_text(encoding="utf-8")
        script = session.create_script(agent_source)
        script.on("message", on_message)
        script.load()

        print(f"attached: pid={pid}")
        print(f"writing unidbg text: {requested_out}")

        script.exports_sync.start(
            {
                "moduleName": args.module,
                "startModuleName": args.start_module,
                "stopModuleName": args.stop_module,
                "startRva": args.start_rva,
                "endRva": args.end_rva,
                "targetOnly": args.target_only == 1,
                "threadId": args.thread_id,
                "gateAddress": args.gate_address,
                "flushEvery": 16384 if args.flush == 0 else args.flush,
            }
        )

        if args.ready_event:
            signal_named_event(args.ready_event)
            print(f"signaled ready event: {args.ready_event}")

        print("attached process is ready; press Ctrl+C to stop waiting")

        while not done.wait(0.25):
            pass

    except KeyboardInterrupt:
        stopping.set()
    except CliError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    except frida.ProcessNotFoundError as exc:
        print(f"frida process error: {exc}", file=sys.stderr)
        return 3
    except frida.TransportError as exc:
        print(f"frida transport error: {exc}", file=sys.stderr)
        return 4
    except Exception as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    finally:
        if script is not None:
            try:
                script.exports_sync.stop()
            except Exception:
                pass
        if session is not None:
            try:
                session.detach()
            except Exception:
                pass
        text_writer.close()

    if stopping.is_set():
        print("stopped by request before end RVA was observed")
    print(f"saved {stats['rows']} instruction rows")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
