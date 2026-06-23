"""Tests for the x64 unwind decoder."""

from __future__ import annotations

import unittest

from tests._pebuilder import (
    CODE_PERMS,
    RDATA_PERMS,
    PEBuilder,
    alloc_large,
    alloc_small,
    encode_runtime_function,
    encode_unwind_info,
    push_machframe,
    push_nonvol,
    raw_slot,
    save_nonvol,
    save_nonvol_far,
    save_xmm128,
    save_xmm128_far,
    set_fpreg,
)
from unwindy.errors import DiagnosticBag, UnwindFormatError
from unwindy.unwind import UnwindFlag, UnwindOp, parse_unwind_info

XDATA_RVA = 0x4000


def _pe_with_xdata(blob: bytes) -> "PEFile":
    from unwindy.pe import PEFile

    b = PEBuilder()
    b.add_section(".text", 0x1000, b"\xcc" * 0x2000, CODE_PERMS)
    b.add_section(".xdata", XDATA_RVA, blob, RDATA_PERMS)
    return PEFile(b.build())


def _parse(blob: bytes, rva: int = XDATA_RVA):
    pe = _pe_with_xdata(blob)
    bag = DiagnosticBag()
    info = parse_unwind_info(pe, rva, bag)
    return info, bag


class SingleOpTests(unittest.TestCase):
    def test_push_nonvol(self):
        info, bag = _parse(encode_unwind_info(prolog=2, code_words=push_nonvol(2, 5)))
        (c,) = info.codes
        self.assertEqual(c.op_enum, UnwindOp.PUSH_NONVOL)
        self.assertEqual(c.register, "rbp")
        self.assertEqual(c.description, "push rbp")
        self.assertEqual(info.fixed_stack_alloc, 8)

    def test_alloc_small(self):
        info, _ = _parse(encode_unwind_info(prolog=4, code_words=alloc_small(4, 0x40)))
        (c,) = info.codes
        self.assertEqual(c.op_enum, UnwindOp.ALLOC_SMALL)
        self.assertEqual(c.alloc_size, 0x40)
        self.assertEqual(info.fixed_stack_alloc, 0x40)

    def test_alloc_large_scaled(self):
        info, _ = _parse(
            encode_unwind_info(prolog=7, code_words=alloc_large(7, 0x2000))
        )
        (c,) = info.codes
        self.assertEqual(c.op_enum, UnwindOp.ALLOC_LARGE)
        self.assertEqual(c.op_info, 0)
        self.assertEqual(c.node_count, 2)
        self.assertEqual(c.alloc_size, 0x2000)

    def test_alloc_large_unscaled(self):
        info, _ = _parse(
            encode_unwind_info(prolog=7, code_words=alloc_large(7, 0x123456))
        )
        (c,) = info.codes
        self.assertEqual(c.op_info, 1)
        self.assertEqual(c.node_count, 3)
        self.assertEqual(c.alloc_size, 0x123456)

    def test_save_nonvol(self):
        info, _ = _parse(
            encode_unwind_info(prolog=9, code_words=save_nonvol(9, 3, 0x48))
        )
        (c,) = info.codes
        self.assertEqual(c.op_enum, UnwindOp.SAVE_NONVOL)
        self.assertEqual(c.register, "rbx")
        self.assertEqual(c.save_offset, 0x48)
        self.assertEqual(info.fixed_stack_alloc, 0)  # save does not move rsp

    def test_save_nonvol_far(self):
        info, _ = _parse(
            encode_unwind_info(prolog=9, code_words=save_nonvol_far(9, 6, 0x1FFF8))
        )
        (c,) = info.codes
        self.assertEqual(c.op_enum, UnwindOp.SAVE_NONVOL_FAR)
        self.assertEqual(c.register, "rsi")
        self.assertEqual(c.save_offset, 0x1FFF8)
        self.assertEqual(c.node_count, 3)

    def test_save_xmm128(self):
        info, _ = _parse(
            encode_unwind_info(prolog=12, code_words=save_xmm128(12, 7, 0x60))
        )
        (c,) = info.codes
        self.assertEqual(c.op_enum, UnwindOp.SAVE_XMM128)
        self.assertEqual(c.register, "xmm7")
        self.assertEqual(c.save_offset, 0x60)

    def test_save_xmm128_far(self):
        info, _ = _parse(
            encode_unwind_info(prolog=12, code_words=save_xmm128_far(12, 7, 0x12340))
        )
        (c,) = info.codes
        self.assertEqual(c.op_enum, UnwindOp.SAVE_XMM128_FAR)
        self.assertEqual(c.save_offset, 0x12340)

    def test_push_machframe(self):
        info, _ = _parse(
            encode_unwind_info(prolog=1, code_words=push_machframe(1, True))
        )
        (c,) = info.codes
        self.assertEqual(c.op_enum, UnwindOp.PUSH_MACHFRAME)
        self.assertTrue(c.has_error_code)
        self.assertEqual(info.fixed_stack_alloc, 48)


class FramePointerTests(unittest.TestCase):
    def test_set_fpreg_ok(self):
        info, _ = _parse(
            encode_unwind_info(
                prolog=5,
                frame_register=5,  # rbp
                frame_offset=2,  # *16 = 0x20
                code_words=set_fpreg(5),
            )
        )
        (c,) = info.codes
        self.assertEqual(c.op_enum, UnwindOp.SET_FPREG)
        self.assertEqual(info.frame_register_name, "rbp")
        self.assertEqual(info.frame_offset_bytes, 0x20)

    def test_set_fpreg_without_frame_register_raises(self):
        with self.assertRaises(UnwindFormatError):
            _parse(
                encode_unwind_info(
                    prolog=5, frame_register=0, code_words=set_fpreg(5)
                )
            )

    def test_frame_register_rsp_warns(self):
        # frame_register=4 (rsp) with a SET_FPREG is parseable but suspicious.
        _, bag = _parse(
            encode_unwind_info(
                prolog=5, frame_register=4, frame_offset=1, code_words=set_fpreg(5)
            )
        )
        self.assertTrue(any(d.code == "unwind.frame_reg_rsp" for d in bag.warnings))

    def test_frame_register_declared_unused_warns(self):
        _, bag = _parse(
            encode_unwind_info(prolog=2, frame_register=5, code_words=push_nonvol(2, 5))
        )
        self.assertTrue(any(d.code == "unwind.frame_reg_unused" for d in bag.warnings))


class StructuralTests(unittest.TestCase):
    def test_multiple_codes_in_prolog_order(self):
        codes = alloc_small(9, 0x28) + push_nonvol(5, 7) + push_nonvol(4, 6) + push_nonvol(3, 5) + push_nonvol(2, 3)
        info, bag = _parse(encode_unwind_info(prolog=9, code_words=codes))
        self.assertEqual(len(info.codes), 5)
        self.assertEqual(info.count_of_codes, 5)  # alloc_small(1) + 4 pushes(4) = 5 slots
        self.assertEqual(info.fixed_stack_alloc, 0x28 + 4 * 8)
        self.assertEqual(len(bag.warnings), 0)

    def test_overrun_raises(self):
        # claim a save_nonvol (needs 2 slots) but only declare 1 slot.
        blob = encode_unwind_info(
            prolog=9, code_words=[save_nonvol(9, 3, 0x48)[0]], count_override=1
        )
        with self.assertRaises(UnwindFormatError):
            _parse(blob)

    def test_unknown_opcode_raises(self):
        with self.assertRaises(UnwindFormatError):
            _parse(encode_unwind_info(prolog=1, code_words=raw_slot(1, 11, 0)))

    def test_invalid_version_raises(self):
        with self.assertRaises(UnwindFormatError):
            _parse(encode_unwind_info(version=0))
        with self.assertRaises(UnwindFormatError):
            _parse(encode_unwind_info(version=5))

    def test_version3_warns_but_parses(self):
        info, bag = _parse(encode_unwind_info(version=3, prolog=2, code_words=push_nonvol(2, 3)))
        self.assertEqual(info.version, 3)
        self.assertTrue(any(d.code == "unwind.version3" for d in bag.warnings))

    def test_reserved_flag_warns(self):
        _, bag = _parse(encode_unwind_info(flags=0x8))  # bit beyond the 3 defined
        self.assertTrue(any(d.code == "unwind.reserved_flags" for d in bag.warnings))

    def test_misaligned_warns(self):
        info, bag = _parse(b"\x00\x00" + encode_unwind_info(prolog=2, code_words=push_nonvol(2, 3)), rva=XDATA_RVA + 2)
        self.assertTrue(any(d.code == "unwind.misaligned" for d in bag.warnings))

    def test_code_after_prolog_warns(self):
        # CodeOffset 0x20 but prolog only 0x04.
        _, bag = _parse(encode_unwind_info(prolog=4, code_words=push_nonvol(0x20, 3)))
        self.assertTrue(any(d.code == "unwind.code_after_prolog" for d in bag.warnings))


class HandlerAndChainTests(unittest.TestCase):
    def test_handler(self):
        blob = encode_unwind_info(
            prolog=2,
            flags=UnwindFlag.EHANDLER,
            code_words=push_nonvol(2, 3),
            handler_rva=0x1500,
            lang_data=b"\xaa\xbb\xcc\xdd",
        )
        info, _ = _parse(blob)
        self.assertTrue(info.has_handler)
        self.assertEqual(info.handler_rva, 0x1500)
        self.assertEqual(info.handler_kind, "exception")
        self.assertIsNotNone(info.language_data_rva)

    def test_both_handler_kinds(self):
        blob = encode_unwind_info(
            prolog=0,
            flags=UnwindFlag.EHANDLER | UnwindFlag.UHANDLER,
            handler_rva=0x1500,
        )
        info, _ = _parse(blob)
        self.assertEqual(info.handler_kind, "exception+termination")

    def test_chain_resolution(self):
        # parent at 0x4000, child at 0x4040 chaining back to parent.
        parent = encode_unwind_info(prolog=6, code_words=push_nonvol(6, 3) + push_nonvol(5, 5))
        pad = b"\x00" * (0x40 - len(parent))
        child = encode_unwind_info(
            prolog=4,
            flags=UnwindFlag.CHAININFO,
            code_words=push_nonvol(4, 6),
            chain=(0x1200, 0x1300, XDATA_RVA),  # -> parent unwind
        )
        blob = parent + pad + child
        pe = _pe_with_xdata(blob)
        bag = DiagnosticBag()
        info = parse_unwind_info(pe, XDATA_RVA + 0x40, bag)
        self.assertTrue(info.is_chained)
        self.assertIsNotNone(info.chained_function)
        self.assertIsNotNone(info.chained_function.unwind_info)
        self.assertEqual(info.chained_function.unwind_info.size_of_prolog, 6)

    def test_chain_cycle_raises(self):
        # unwind chains to a RUNTIME_FUNCTION whose unwind is itself.
        blob = encode_unwind_info(
            prolog=0,
            flags=UnwindFlag.CHAININFO,
            chain=(0x1000, 0x1100, XDATA_RVA),
        )
        with self.assertRaises(UnwindFormatError):
            _parse(blob)


if __name__ == "__main__":
    unittest.main()
