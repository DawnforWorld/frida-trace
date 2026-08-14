from __future__ import annotations

import argparse
import json
from pathlib import Path

from trace_io import open_trace_text


def main() -> int:
    parser = argparse.ArgumentParser(description="Extract a compact sequence window from a PinTrace.")
    parser.add_argument("trace", type=Path)
    parser.add_argument("--start", type=int, required=True)
    parser.add_argument("--end", type=int, required=True)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    if args.start < 1 or args.end < args.start:
        parser.error("expected 1 <= start <= end")

    records = []
    with open_trace_text(args.trace.resolve()) as stream:
        for line in stream:
            if '"type":"instruction"' not in line:
                continue
            event = json.loads(line)
            seq = int(event["seq"])
            if seq < args.start:
                continue
            if seq > args.end:
                break
            records.append(
                {
                    "seq": seq,
                    "rva": event["rva"],
                    "bytes": event["bytes"],
                    "disasm": event["disasm"],
                    "sync": event.get("sync"),
                    "regs": event["regs"],
                    "memory": event["memory"],
                    "flow": event["flow"],
                }
            )

    serialized = json.dumps(records, indent=2)
    if args.output:
        args.output.write_text(serialized + "\n", encoding="utf-8")
    else:
        print(serialized)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
