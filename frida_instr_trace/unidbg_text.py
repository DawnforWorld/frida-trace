from __future__ import annotations

from pathlib import Path


REGISTER_NAMES = (
    "rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp", "rsp",
    "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15", "rflags",
)
MEMORY_READ = 1


def integer(value: object) -> int:
    if value is None:
        return 0
    if isinstance(value, int):
        return value
    return int(str(value), 0)


class UnidbgTextWriter:
    """Stream x64 trace rows using unidbg's AssemblyCodeDumper line shape."""

    def __init__(self, path: Path) -> None:
        self.path = path
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.output = self.path.open("w", encoding="utf-8", newline="\n")

    def write(self, row: dict[str, object]) -> None:
        address = integer(row.get("address"))
        image_base = integer(row.get("imageBase"))
        module = str(row.get("module", "<anonymous>"))
        location = (
            f"[{module:<32} 0x{address - image_base:016x}]"
            if image_base else f"[{'<anonymous>':<32} 0x{address:016x}]"
        )
        instruction_bytes = bytes.fromhex(str(row.get("bytes", ""))).hex()
        line = f'{location} [{instruction_bytes:<30}] 0x{address:016x}: "{row.get("instruction", "")}"'

        for item in row.get("memory", []):
            if not isinstance(item, dict):
                continue
            flags = integer(item.get("flags"))
            access = "rw" if flags == 3 else "r" if flags & MEMORY_READ else "w"
            line += f" ({access} 0x{integer(item.get('address')):x} {integer(item.get('size'))})"

        registers = row.get("registers", {})
        if not isinstance(registers, dict):
            registers = {}
        reads = _masked_registers(integer(row.get("readMask")), registers)
        if reads:
            line += " " + " ".join(reads)

        changes = row.get("registerChanges", {})
        if not isinstance(changes, dict):
            changes = {}
        writes = _changed_registers(integer(row.get("writeMask")), registers, changes)
        if writes:
            line += " => " + " ".join(writes)

        external_target = row.get("externalTarget")
        if external_target:
            line += f" ; {external_target}"
        self.output.write(line + "\n")

    def close(self) -> None:
        if not self.output.closed:
            self.output.flush()
            self.output.close()


def _masked_registers(mask: int, registers: dict[str, object]) -> list[str]:
    return [
        f"{name}=0x{integer(registers.get(name)):x}"
        for index, name in enumerate(REGISTER_NAMES)
        if mask & (1 << index) and name in registers
    ]


def _changed_registers(
    mask: int,
    registers: dict[str, object],
    changes: dict[str, object],
) -> list[str]:
    result: list[str] = []
    for index, name in enumerate(REGISTER_NAMES):
        if not mask & (1 << index):
            continue
        change = changes.get(name)
        if change is not None and "->" in str(change):
            value = str(change).rsplit("->", 1)[1]
        elif name in registers:
            value = str(registers[name])
        else:
            continue
        result.append(f"{name}=0x{integer(value):x}")
    return result
