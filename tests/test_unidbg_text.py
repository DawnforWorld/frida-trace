import tempfile
import unittest
from pathlib import Path

from frida_instr_trace import unidbg_text as trace


class UnidbgTextTest(unittest.TestCase):
    def test_upstream_style_text_writer(self):
        with tempfile.TemporaryDirectory() as directory:
            output_path = Path(directory) / "capture.txt"
            output_path.write_text("old trace\n", encoding="utf-8")
            writer = trace.UnidbgTextWriter(output_path)
            writer.write({
                "module": "fixture.exe",
                "address": "0x140001000",
                "imageBase": "0x140000000",
                "bytes": "48 89 c3",
                "instruction": "mov rbx, rax",
                "registers": {"rax": "0x10", "rbx": "0x20"},
                "registerChanges": {"rbx": "0x20->0x10"},
                "readMask": 1 << 0,
                "writeMask": 1 << 1,
                "memory": [{"size": 8, "flags": trace.MEMORY_READ, "address": "0x2000"}],
            })
            writer.close()

            line = output_path.read_text(encoding="utf-8").strip()
            self.assertNotIn("old trace", line)
            self.assertEqual(
                line,
                '[fixture.exe                      0x0000000000001000] '
                '[4889c3                        ] 0x0000000140001000: '
                '"mov rbx, rax" (r 0x2000 8) rax=0x10 => rbx=0x10',
            )


if __name__ == "__main__":
    unittest.main()
