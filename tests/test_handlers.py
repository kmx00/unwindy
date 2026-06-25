"""Tests for language-specific handler-data decoding (unwindy.handlers).

Three layers:

* Pure decoder tests build a synthetic PE with crafted ``.xdata`` and call the
  byte-level decoders directly.  These are the only coverage for the GS and
  FH3 ``FuncInfo`` formats, which neither bundled sample exercises.
* Structural-classification tests run the whole ``analyze`` pipeline against
  unnamed (statically-linked) handlers and assert the recognized kind.
* Real-sample tests pin the decode of the bundled ``b325...`` image, whose C++
  EH is emitted as ``__CxxFrameHandler4`` (FH4) plus ``__C_specific_handler``
  scope tables.
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
from unwindy.errors import DiagnosticBag
from unwindy.handlers import (
    decode_fh4,
    decode_funcinfo3,
    decode_gs_data,
    decode_scope_table,
)
from unwindy.pe import PEFile

SAMPLE = Path(__file__).resolve().parents[1] / "samples" / (
    "b325e5a8da4f8bea2db9fc118f6a6f237731d734.bin"
)

XBASE = 0x4000


# --- crafted-payload encoders -----------------------------------------------


def enc_scope(records):
    out = struct.pack("<I", len(records))
    for begin, end, handler, target in records:
        out += struct.pack("<IIII", begin, end, handler, target)
    return out


def enc_gs(cookie, *, eh=False, uh=False, has_align=False, base=0, align=0):
    value = (cookie & ~7) | (1 if eh else 0) | (2 if uh else 0) | (4 if has_align else 0)
    out = struct.pack("<I", value)
    if has_align:
        out += struct.pack("<ii", base, align)
    return out


def enc_fh3(
    *,
    magic,
    max_state=0,
    disp_unwind=0,
    n_try=0,
    disp_try=0,
    n_ip=0,
    disp_ip=0,
    unwind_help=-2,
    es_type=0,
    eh_flags=0,
    bbt=0,
):
    raw_magic = (magic & 0x1FFFFFFF) | ((bbt & 7) << 29)
    out = struct.pack(
        "<IiIIIIIi",
        raw_magic,
        max_state,
        disp_unwind,
        n_try,
        disp_try,
        n_ip,
        disp_ip,
        unwind_help,
    )
    if magic >= 0x19930521:
        out += struct.pack("<i", es_type)
    if magic >= 0x19930522:
        out += struct.pack("<i", eh_flags)
    return out


def enc_tryblock(try_low, try_high, catch_high, n_catches, disp_handler):
    return struct.pack("<iiiII", try_low, try_high, catch_high, n_catches, disp_handler)


def enc_catch(adjectives, disp_type, disp_catch_obj, disp_handler, disp_frame):
    return struct.pack("<IIiII", adjectives, disp_type, disp_catch_obj, disp_handler, disp_frame)


# --- synthetic image builder ------------------------------------------------


def build_image(funcs=(), blobs=()):
    """``funcs``: ``(begin, end, unwind_rva, unwind_bytes)`` placed in .pdata +
    .xdata.  ``blobs``: extra ``(rva, bytes)`` placed in .xdata (FuncInfo etc.)."""
    xdata = bytearray()

    def place(rva, data):
        off = rva - XBASE
        if off + len(data) > len(xdata):
            xdata.extend(b"\x00" * (off + len(data) - len(xdata)))
        xdata[off : off + len(data)] = data

    for begin, end, urva, ublob in funcs:
        place(urva, ublob)
    for rva, data in blobs:
        place(rva, data)
    rfs = b"".join(encode_runtime_function(b, e, u) for b, e, u, _ in funcs)
    pb = PEBuilder()
    pb.add_section(".text", 0x1000, b"\xcc" * 0x2000, CODE_PERMS)
    pb.add_section(".pdata", 0x3000, rfs, RDATA_PERMS)
    pb.add_section(".xdata", XBASE, bytes(xdata), RDATA_PERMS)
    pb.set_exception_dir(0x3000, len(rfs))
    return PEFile(pb.build())


def only_xdata(blob, rva=XBASE):
    """Build an image whose .xdata holds ``blob`` at ``rva`` (no .pdata)."""
    pb = PEBuilder()
    pb.add_section(".text", 0x1000, b"\xcc" * 0x2000, CODE_PERMS)
    pad = b"\x00" * (rva - XBASE)
    pb.add_section(".xdata", XBASE, pad + blob, RDATA_PERMS)
    return PEFile(pb.build())


# --- pure decoder tests -----------------------------------------------------


class ScopeTableTests(unittest.TestCase):
    def test_classifies_except_finally_and_execute(self):
        records = [
            (0x1010, 0x1020, 0x1900, 0x1030),  # __except with filter
            (0x1040, 0x1050, 1, 0x1060),        # __except EXECUTE_HANDLER (filter==1)
            (0x1070, 0x1080, 0x1908, 0),        # __finally (target==0)
        ]
        pe = only_xdata(enc_scope(records))
        bag = DiagnosticBag()
        recs, consumed = decode_scope_table(pe, XBASE, 0x1000, 0x1100, bag, "t")
        self.assertEqual(consumed, 4 + 3 * 16)
        self.assertEqual([r.kind for r in recs], [
            "except (filter)",
            "except (EXECUTE_HANDLER)",
            "finally",
        ])
        self.assertEqual(recs[0].handler, 0x1900)
        self.assertEqual(recs[0].target, 0x1030)
        self.assertEqual(recs[2].target, 0)
        self.assertEqual(len(bag.warnings), 0)

    def test_out_of_bounds_record_warns(self):
        pe = only_xdata(enc_scope([(0x2000, 0x2010, 0x1900, 0x2020)]))
        bag = DiagnosticBag()
        recs, _ = decode_scope_table(pe, XBASE, 0x1000, 0x1100, bag, "t")
        self.assertEqual(len(recs), 1)
        self.assertTrue(any(d.code == "handler.scope_oob" for d in bag.warnings))

    def test_classify_rejects_non_scope(self):
        # A huge bogus count must not be mistaken for a scope table.
        pe = only_xdata(struct.pack("<I", 0xDEAD) + b"\x00" * 32)
        recs, consumed = decode_scope_table(
            pe, XBASE, 0x1000, 0x1100, DiagnosticBag(), "t", classify=True
        )
        self.assertIsNone(recs)
        self.assertEqual(consumed, 0)

    def test_truncated_table_warns_and_clamps(self):
        # Count claims far more records than the section's raw data can hold.
        blob = struct.pack("<I", 1000) + struct.pack("<IIII", 0x1010, 0x1020, 0x1900, 0)
        pe = only_xdata(blob)
        bag = DiagnosticBag()
        recs, _ = decode_scope_table(pe, XBASE, 0x1000, 0x1100, bag, "t")
        self.assertTrue(any(d.code == "handler.scope_truncated" for d in bag.warnings))
        self.assertLess(len(recs), 1000)


class GsDataTests(unittest.TestCase):
    def test_cookie_offset_and_flags(self):
        pe = only_xdata(enc_gs(0x58, uh=True))
        gs = decode_gs_data(pe, XBASE)
        self.assertEqual(gs.cookie_offset, 0x58)
        self.assertTrue(gs.uhandler)
        self.assertFalse(gs.ehandler)
        self.assertFalse(gs.has_alignment)
        self.assertEqual(gs.size, 4)

    def test_aligned_form(self):
        pe = only_xdata(enc_gs(0x80, eh=True, has_align=True, base=0x20, align=0x10))
        gs = decode_gs_data(pe, XBASE)
        self.assertTrue(gs.ehandler)
        self.assertTrue(gs.has_alignment)
        self.assertEqual(gs.cookie_offset, 0x80)
        self.assertEqual(gs.aligned_base_offset, 0x20)
        self.assertEqual(gs.alignment, 0x10)
        self.assertEqual(gs.size, 12)


class FuncInfo3Tests(unittest.TestCase):
    def test_full_funcinfo_with_try_and_catches(self):
        fi_rva, try_rva, harr_rva = 0x4100, 0x4200, 0x4300
        catches = enc_catch(0x40, 0x4400, 0x30, 0x1500, 0x60) + enc_catch(
            0, 0, 0, 0x1600, 0x60  # catch(...) -- type_rva == 0
        )
        tryblock = enc_tryblock(0, 2, 2, 2, harr_rva)
        fi = enc_fh3(
            magic=0x19930522,
            max_state=3,
            disp_unwind=0x4500,
            n_try=1,
            disp_try=try_rva,
            n_ip=4,
            disp_ip=0x4600,
            unwind_help=-2,
            es_type=0,
            eh_flags=0x1,
        )
        pe = build_image(blobs=[(fi_rva, fi), (try_rva, tryblock), (harr_rva, catches)])
        info = decode_funcinfo3(pe, fi_rva, DiagnosticBag(), "t")
        self.assertEqual(info.version, 3)
        self.assertEqual(info.max_state, 3)
        self.assertEqual(info.n_try_blocks, 1)
        self.assertEqual(info.eh_flags, 0x1)
        self.assertEqual(len(info.try_blocks), 1)
        tb = info.try_blocks[0]
        self.assertEqual((tb.try_low, tb.try_high, tb.catch_high), (0, 2, 2))
        self.assertEqual(len(tb.catches), 2)
        self.assertEqual(tb.catches[0].type_rva, 0x4400)
        self.assertEqual(tb.catches[0].handler_rva, 0x1500)
        self.assertEqual(tb.catches[1].type_rva, 0)  # catch(...)

    def test_magic_versions_gate_trailing_fields(self):
        # 0x19930520 has neither ESTypeList nor EHFlags.
        pe = only_xdata(enc_fh3(magic=0x19930520, max_state=1))
        info = decode_funcinfo3(pe, XBASE, DiagnosticBag(), "t")
        self.assertEqual(info.version, 1)
        self.assertEqual(info.es_type_list_rva, 0)
        self.assertEqual(info.eh_flags, 0)

    def test_unknown_magic_warns(self):
        pe = only_xdata(enc_fh3(magic=0x12345678))
        bag = DiagnosticBag()
        info = decode_funcinfo3(pe, XBASE, bag, "t")
        self.assertEqual(info.version, 0)
        self.assertTrue(any(d.code == "handler.cxx_magic" for d in bag.warnings))


class Fh4HeaderTests(unittest.TestCase):
    def test_header_flag_decode(self):
        pe = only_xdata(bytes([0x28]))
        fh4 = decode_fh4(pe, XBASE, DiagnosticBag(), "t")
        self.assertEqual(fh4.flag_names(), ["UnwindMap", "EHs"])
        self.assertTrue(fh4.has_unwind_map and fh4.has_ehs)
        self.assertFalse(fh4.is_catch)

    def test_noexcept_and_reserved_bit(self):
        bag = DiagnosticBag()
        pe = only_xdata(bytes([0x60]))
        fh4 = decode_fh4(pe, XBASE, bag, "t")
        self.assertEqual(fh4.flag_names(), ["EHs", "NoExcept"])
        self.assertEqual(len(bag.warnings), 0)
        pe2 = only_xdata(bytes([0x80]))  # reserved high bit set
        decode_fh4(pe2, XBASE, bag, "t")
        self.assertTrue(any(d.code == "handler.fh4_header" for d in bag.warnings))


# --- structural classification through analyze() ----------------------------


def _ui_with_handler(handler_rva, lang_data):
    return encode_unwind_info(
        prolog=4, flags=0x1, handler_rva=handler_rva, lang_data=lang_data
    )


class StructuralClassificationTests(unittest.TestCase):
    def _decode_one(self, lang_data, blobs=()):
        # Handler routine at 0x1900 is outside the function range -> unnamed.
        ub = _ui_with_handler(0x1900, lang_data)
        pe = build_image([(0x1000, 0x1100, XBASE, ub)], blobs=blobs)
        a = analyze(pe)
        return a, a.functions[0].unwind_info.handler_data

    def test_scope_table_structural(self):
        lang = enc_scope([(0x1010, 0x1080, 0x1500, 0x1090)])
        a, hd = self._decode_one(lang)
        self.assertEqual(hd.kind, "scope")
        self.assertEqual(len(hd.scope_records), 1)
        self.assertEqual(hd.scope_records[0].kind, "except (filter)")
        self.assertEqual(len(a.diagnostics.warnings), 0)

    def test_fh3_structural(self):
        fi_rva = 0x4100
        lang = struct.pack("<I", fi_rva)
        fi = enc_fh3(magic=0x19930522, max_state=2, n_try=0)
        a, hd = self._decode_one(lang, blobs=[(fi_rva, fi)])
        self.assertEqual(hd.kind, "cxx3")
        self.assertIsNotNone(hd.cxx)
        self.assertEqual(hd.cxx.version, 3)

    def test_fh4_structural(self):
        fi_rva = 0x4100
        lang = struct.pack("<I", fi_rva)
        a, hd = self._decode_one(lang, blobs=[(fi_rva, bytes([0x28]))])
        self.assertEqual(hd.kind, "cxx4")
        self.assertIsNotNone(hd.fh4)
        self.assertEqual(hd.fh4.flag_names(), ["UnwindMap", "EHs"])

    def test_unrecognized_is_quiet(self):
        lang = struct.pack("<I", 0xDEAD) + b"\x00" * 8
        a, hd = self._decode_one(lang)
        self.assertEqual(hd.kind, "unknown")
        self.assertTrue(hd.notes)
        # An unrecognized payload must not emit a decode-failure warning.
        self.assertFalse(any(d.code == "handler.decode_failed" for d in a.diagnostics))


# --- real bundled sample ----------------------------------------------------


class SampleHandlerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.pe = PEFile.from_path(str(SAMPLE))
        cls.analysis = analyze(cls.pe)
        cls.by_index = {f.index: f for f in cls.analysis.functions}

    def _hd(self, index):
        return self.by_index[index].unwind_info.handler_data

    def test_handler_kind_distribution(self):
        counts = {}
        for f in self.analysis.functions:
            ui = f.unwind_info
            if ui and ui.handler_data:
                counts[ui.handler_data.kind] = counts.get(ui.handler_data.kind, 0) + 1
        self.assertEqual(counts, {"scope": 4, "cxx4": 28, "gs+cxx4": 4, "unknown": 107})

    def test_no_handler_decode_warnings(self):
        self.assertFalse(
            any(d.code.startswith("handler.") for d in self.analysis.diagnostics)
        )

    def test_c_specific_scope_execute_handler(self):
        hd = self._hd(250)
        self.assertEqual(hd.kind, "scope")
        self.assertEqual(hd.routine_name, "__C_specific_handler")
        self.assertEqual(len(hd.scope_records), 1)
        s = hd.scope_records[0]
        self.assertEqual(s.kind, "except (EXECUTE_HANDLER)")
        self.assertEqual((s.begin, s.end, s.handler, s.target), (0xF0C4, 0xF0CD, 1, 0xF0CD))

    def test_c_specific_scope_two_filter_regions(self):
        hd = self._hd(866)
        self.assertEqual(hd.kind, "scope")
        self.assertEqual(len(hd.scope_records), 2)
        self.assertTrue(all(s.kind == "except (filter)" for s in hd.scope_records))
        self.assertEqual(hd.scope_records[0].handler, 0x56F10)

    def test_cxxframehandler4_named_and_fh4_decoded(self):
        hd = self._hd(6)
        self.assertEqual(hd.kind, "cxx4")
        self.assertEqual(hd.routine_name, "__CxxFrameHandler4")
        self.assertEqual(hd.dll, "VCRUNTIME140_1.dll")
        self.assertIsNotNone(hd.fh4)
        self.assertEqual(hd.fh4.header, 0x28)

    def test_gs_wrapped_cxx4(self):
        hd = self._hd(235)
        self.assertEqual(hd.kind, "gs+cxx4")
        self.assertEqual(hd.wraps, "__CxxFrameHandler4")
        self.assertIsNotNone(hd.gs)
        self.assertEqual(hd.gs.cookie_offset, 0x50)
        self.assertTrue(hd.gs.uhandler)
        self.assertIsNotNone(hd.fh4)

    def test_unrecognized_local_handler(self):
        hd = self._hd(170)
        self.assertEqual(hd.kind, "unknown")
        self.assertIsNone(hd.routine_name)
        self.assertTrue(hd.raw_head)


if __name__ == "__main__":
    unittest.main()
