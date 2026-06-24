"""Tests for function-start trampoline peeling (unwindy.trampolines).

Synthetic fixtures cover the local / cross-section / chained / import / negative
cases (neither bundled sample emits a local jump trampoline), and both bundled
samples are pinned -- they are deliberately distinct release builds: ``b325...``
has exactly one ``jmp [rip]`` import stub, ``602314...`` has none.
"""

from __future__ import annotations

import struct
import unittest
from pathlib import Path

from tests._pebuilder import (
    CODE_PERMS,
    RDATA_PERMS,
    PEBuilder,
    encode_runtime_function,
    encode_unwind_info,
)
from unwindy.analyzer import analyze
from unwindy.pe import PEFile

SAMPLES = Path(__file__).resolve().parents[1] / "samples"
SMALL = SAMPLES / "b325e5a8da4f8bea2db9fc118f6a6f237731d734.bin"
BIG = SAMPLES / "602314161f55e2ca2affab8c516437148c079dd8.bin"

PDATA_RVA = 0x30000
XDATA_RVA = 0x40000


def e9(src, dst):
    return b"\xe9" + struct.pack("<i", dst - (src + 5))


def eb(src, dst):
    return b"\xeb" + struct.pack("<b", dst - (src + 2))


def ff25(src, slot):
    return b"\xff\x25" + struct.pack("<i", slot - (src + 6))


def code_section(name, rva, size, patches):
    buf = bytearray(b"\xcc" * size)
    for at, data in patches:
        buf[at - rva : at - rva + len(data)] = data
    return (name, rva, bytes(buf), CODE_PERMS)


def build(code_sections, funcs):
    """``code_sections``: ``(name, rva, bytes, perms)``.  ``funcs``: ``(begin,
    end, unwind_rva, unwind_bytes)`` -> .pdata + .xdata."""
    pb = PEBuilder()
    for name, rva, data, perms in code_sections:
        pb.add_section(name, rva, data, perms)
    xdata = bytearray()
    for _b, _e, urva, ub in funcs:
        off = urva - XDATA_RVA
        if off + len(ub) > len(xdata):
            xdata.extend(b"\x00" * (off + len(ub) - len(xdata)))
        xdata[off : off + len(ub)] = ub
    pb.add_section(".xdata", XDATA_RVA, bytes(xdata), RDATA_PERMS)
    rfs = b"".join(encode_runtime_function(b, e, u) for b, e, u, _ in funcs)
    pb.add_section(".pdata", PDATA_RVA, rfs, RDATA_PERMS)
    pb.set_exception_dir(PDATA_RVA, len(rfs))
    return PEFile(pb.build())


U = encode_unwind_info(prolog=0)  # trivial leaf unwind info


class SyntheticTrampolineTests(unittest.TestCase):
    def test_local_same_section(self):
        text = code_section(".text", 0x1000, 0x2000, [(0x1000, e9(0x1000, 0x1500))])
        pe = build([text], [(0x1000, 0x1006, XDATA_RVA, U), (0x1500, 0x1600, XDATA_RVA + 8, U)])
        a = analyze(pe)
        t = a.functions[0].trampoline
        self.assertIsNotNone(t)
        self.assertEqual(t.kind, "local")
        self.assertEqual(t.real_start, 0x1500)
        self.assertEqual(t.hops, 1)
        self.assertFalse(t.crosses_segment)
        self.assertEqual(t.real_start_index, 1)
        # The real function itself is not a trampoline.
        self.assertIsNone(a.functions[1].trampoline)

    def test_cross_section_transition(self):
        text = code_section(".text", 0x1000, 0x2000, [(0x1000, e9(0x1000, 0x6000))])
        text2 = code_section(".code2", 0x6000, 0x1000, [])
        pe = build(
            [text, text2],
            [(0x1000, 0x1006, XDATA_RVA, U), (0x6000, 0x6100, XDATA_RVA + 8, U)],
        )
        a = analyze(pe)
        t = a.functions[0].trampoline
        self.assertEqual(t.kind, "local")
        self.assertEqual(t.real_start, 0x6000)
        self.assertTrue(t.crosses_segment)
        self.assertEqual(t.transition_rva, 0x6000)

    def test_chained_trampolines(self):
        text = code_section(
            ".text",
            0x1000,
            0x2000,
            [(0x1000, e9(0x1000, 0x1100)), (0x1100, e9(0x1100, 0x1500))],
        )
        pe = build([text], [(0x1000, 0x1006, XDATA_RVA, U), (0x1500, 0x1600, XDATA_RVA + 8, U)])
        a = analyze(pe)
        t = a.functions[0].trampoline
        self.assertEqual(t.chain, [0x1000, 0x1100, 0x1500])
        self.assertEqual(t.hops, 2)
        self.assertEqual(t.real_start, 0x1500)

    def test_short_jump_trampoline(self):
        text = code_section(".text", 0x1000, 0x2000, [(0x1000, eb(0x1000, 0x1040))])
        pe = build([text], [(0x1000, 0x1002, XDATA_RVA, U), (0x1040, 0x1100, XDATA_RVA + 8, U)])
        a = analyze(pe)
        t = a.functions[0].trampoline
        self.assertEqual(t.kind, "local")
        self.assertEqual(t.real_start, 0x1040)

    def test_intra_function_jump_is_not_a_trampoline(self):
        # eb forward jump that stays inside the function == ordinary control flow.
        text = code_section(".text", 0x1000, 0x2000, [(0x1000, eb(0x1000, 0x1010))])
        pe = build([text], [(0x1000, 0x1100, XDATA_RVA, U)])
        a = analyze(pe)
        self.assertIsNone(a.functions[0].trampoline)

    def test_import_stub(self):
        text = code_section(".text", 0x1000, 0x2000, [(0x1000, ff25(0x1000, 0x50000))])
        pe = build([text], [(0x1000, 0x1006, XDATA_RVA, U)])
        a = analyze(pe)
        t = a.functions[0].trampoline
        self.assertEqual(t.kind, "import")
        self.assertEqual(t.import_slot, 0x50000)
        self.assertIsNone(t.import_target)  # no import table in this fixture

    def test_plain_function_has_no_trampoline(self):
        text = code_section(".text", 0x1000, 0x2000, [])  # all 0xCC
        pe = build([text], [(0x1000, 0x1100, XDATA_RVA, U)])
        a = analyze(pe)
        self.assertIsNone(a.functions[0].trampoline)


class SampleTrampolineTests(unittest.TestCase):
    def test_small_sample_single_import_stub(self):
        a = analyze(PEFile.from_path(str(SMALL)))
        tramps = [f for f in a.functions if f.trampoline]
        self.assertEqual(len(tramps), 1)
        t = tramps[0].trampoline
        self.assertEqual(tramps[0].index, 901)
        self.assertEqual(t.kind, "import")
        self.assertEqual(t.import_slot, 0x70020)

    def test_big_sample_has_no_trampolines(self):
        a = analyze(PEFile.from_path(str(BIG)))
        self.assertEqual([f for f in a.functions if f.trampoline], [])


if __name__ == "__main__":
    unittest.main()
