"""Tests for the directory/section-level analyzer."""

from __future__ import annotations

import unittest
from pathlib import Path

from tests._pebuilder import (
    CODE_PERMS,
    RDATA_PERMS,
    PEBuilder,
    alloc_small,
    encode_runtime_function,
    encode_unwind_info,
    push_nonvol,
    save_nonvol,
    simple_image,
)
from unwindy.analyzer import analyze
from unwindy.errors import UnwindFormatError
from unwindy.pe import PEFile

SAMPLE = Path(__file__).resolve().parents[1] / "samples" / (
    "b325e5a8da4f8bea2db9fc118f6a6f237731d734.bin"
)


def _build(funcs_and_unwind):
    """funcs_and_unwind: list of (begin, end, unwind_rva, unwind_bytes).

    All unwind blobs are concatenated into .xdata starting at 0x4000; caller
    supplies the rva each blob will actually live at.
    """
    # Place each unwind blob at its declared rva inside one .xdata section.
    base = 0x4000
    xdata = bytearray()
    for begin, end, urva, ublob in funcs_and_unwind:
        off = urva - base
        if off + len(ublob) > len(xdata):
            xdata.extend(b"\x00" * (off + len(ublob) - len(xdata)))
        xdata[off : off + len(ublob)] = ublob
    rfs = b"".join(
        encode_runtime_function(b, e, u) for b, e, u, _ in funcs_and_unwind
    )
    b = PEBuilder()
    b.add_section(".text", 0x1000, b"\xcc" * 0x2000, CODE_PERMS)
    b.add_section(".pdata", 0x3000, rfs, RDATA_PERMS)
    b.add_section(".xdata", base, bytes(xdata), RDATA_PERMS)
    b.set_exception_dir(0x3000, len(rfs))
    return PEFile(b.build())


class SampleAnalysisTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.pe = PEFile.from_path(str(SAMPLE))
        cls.analysis = analyze(cls.pe)

    def test_function_count(self):
        self.assertEqual(len(self.analysis.functions), 919)

    def test_chained_and_handlers(self):
        self.assertEqual(self.analysis.chained_count, 252)
        self.assertEqual(self.analysis.handler_count, 143)

    def test_no_warnings_on_clean_compiler_output(self):
        self.assertEqual(len(self.analysis.diagnostics.warnings), 0)
        self.assertEqual(len(self.analysis.diagnostics.errors), 0)

    def test_op_histogram_matches_known(self):
        hist = self.analysis.op_histogram()
        self.assertEqual(hist["UWOP_PUSH_NONVOL"], 1214)
        self.assertEqual(hist["UWOP_ALLOC_SMALL"], 510)
        self.assertEqual(hist["UWOP_SAVE_NONVOL"], 500)
        self.assertEqual(hist["UWOP_SAVE_XMM128"], 363)
        self.assertEqual(hist["UWOP_ALLOC_LARGE"], 105)


class SyntheticAnalysisTests(unittest.TestCase):
    def test_clean_two_functions(self):
        u1 = encode_unwind_info(prolog=4, code_words=alloc_small(4, 0x20))
        u2 = encode_unwind_info(prolog=2, code_words=push_nonvol(2, 3))
        pe = _build(
            [
                (0x1000, 0x1100, 0x4000, u1),
                (0x1100, 0x1200, 0x4040, u2),
            ]
        )
        a = analyze(pe)
        self.assertEqual(len(a.functions), 2)
        self.assertEqual(len(a.diagnostics.warnings), 0)

    def test_unsorted_pdata_warns(self):
        u = encode_unwind_info(prolog=0)
        pe = _build(
            [
                (0x1200, 0x1300, 0x4000, u),
                (0x1000, 0x1100, 0x4040, u),  # begins before the previous
            ]
        )
        a = analyze(pe)
        self.assertTrue(any(d.code == "pdata.unsorted" for d in a.diagnostics.warnings))

    def test_overlap_warns(self):
        u = encode_unwind_info(prolog=0)
        pe = _build(
            [
                (0x1000, 0x1200, 0x4000, u),
                (0x1100, 0x1300, 0x4040, u),  # overlaps the first
            ]
        )
        a = analyze(pe)
        self.assertTrue(any(d.code == "pdata.overlap" for d in a.diagnostics.warnings))

    def test_bad_range_strict_raises(self):
        u = encode_unwind_info(prolog=0)
        pe = _build([(0x1200, 0x1000, 0x4000, u)])  # end < begin
        with self.assertRaises(UnwindFormatError):
            analyze(pe, strict=True)

    def test_bad_range_lenient_records_error(self):
        u = encode_unwind_info(prolog=0)
        pe = _build([(0x1200, 0x1000, 0x4000, u)])
        a = analyze(pe, strict=False)
        self.assertTrue(any(d.code == "pdata.bad_range" for d in a.diagnostics.errors))

    def test_size_not_multiple_of_12_warns(self):
        u = encode_unwind_info(prolog=0)
        rf = encode_runtime_function(0x1000, 0x1100, 0x4000)
        b = PEBuilder()
        b.add_section(".text", 0x1000, b"\xcc" * 0x2000, CODE_PERMS)
        b.add_section(".pdata", 0x3000, rf + b"\x00\x00\x00", RDATA_PERMS)
        b.add_section(".xdata", 0x4000, u, RDATA_PERMS)
        b.set_exception_dir(0x3000, len(rf) + 3)  # not a multiple of 12
        a = analyze(PEFile(b.build()))
        self.assertTrue(
            any(d.code == "pdata.size_misaligned" for d in a.diagnostics.warnings)
        )

    def test_absent_exception_dir(self):
        b = PEBuilder()
        b.add_section(".text", 0x1000, b"\xcc" * 0x2000, CODE_PERMS)
        a = analyze(PEFile(b.build()))
        self.assertEqual(len(a.functions), 0)
        self.assertTrue(any(d.code == "pdata.absent" for d in a.diagnostics.items))


if __name__ == "__main__":
    unittest.main()
