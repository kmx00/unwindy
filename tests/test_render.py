"""Tests for address/section labeling and the cross-section column."""

from __future__ import annotations

import unittest

from tests._pebuilder import (
    CODE_PERMS,
    RDATA_PERMS,
    PEBuilder,
    encode_runtime_function,
    encode_unwind_info,
)
from unwindy.pe import PEFile
from unwindy.render import addr_label, func_section_info, function_row, xsect_label
from unwindy.unwind import RuntimeFunction


def _pe(rf: bytes) -> PEFile:
    u = encode_unwind_info(prolog=0)
    b = PEBuilder()
    # .text spans rva 0x1000..0x3000 (size 0x2000)
    b.add_section(".text", 0x1000, b"\xcc" * 0x2000, CODE_PERMS)
    b.add_section(".pdata", 0x3000, rf, RDATA_PERMS)
    b.add_section(".xdata", 0x4000, u, RDATA_PERMS)
    b.set_exception_dir(0x3000, len(rf))
    return PEFile(b.build())


class LabelTests(unittest.TestCase):
    def test_addr_label_rva_and_va(self):
        pe = _pe(encode_runtime_function(0x1100, 0x1200, 0x4000))
        self.assertEqual(addr_label(pe, 0x1100, use_va=False), ".text:0x1100")
        self.assertEqual(addr_label(pe, 0x1100, use_va=True), ".text:0x140001100")

    def test_addr_label_unmapped(self):
        pe = _pe(encode_runtime_function(0x1100, 0x1200, 0x4000))
        self.assertTrue(addr_label(pe, 0x7FFFFFF, use_va=False).startswith("??:"))

    def test_same_section_not_flagged(self):
        pe = _pe(encode_runtime_function(0x1100, 0x1200, 0x4000))
        f = RuntimeFunction(0x1100, 0x1200, 0x4000, index=0)
        begin_sec, end_sec, crosses = func_section_info(pe, f)
        self.assertEqual((begin_sec, end_sec, crosses), (".text", ".text", False))
        self.assertEqual(xsect_label(pe, f), "-")

    def test_cross_section_flagged(self):
        # begin in .text (..0x3000), last byte (end-1=0x3007) in .pdata.
        pe = _pe(encode_runtime_function(0x2FF0, 0x3008, 0x4000))
        f = RuntimeFunction(0x2FF0, 0x3008, 0x4000, index=0)
        begin_sec, end_sec, crosses = func_section_info(pe, f)
        self.assertEqual((begin_sec, end_sec, crosses), (".text", ".pdata", True))
        self.assertEqual(xsect_label(pe, f), ".text->.pdata")

    def test_function_row_carries_section_labels(self):
        pe = _pe(encode_runtime_function(0x1100, 0x1200, 0x4000))
        f = RuntimeFunction(0x1100, 0x1200, 0x4000, index=0)
        row = [str(c) for c in function_row(pe, f, use_va=False)]
        self.assertIn(".text:0x1100", row)
        self.assertIn(".text:0x1200", row)


if __name__ == "__main__":
    unittest.main()
