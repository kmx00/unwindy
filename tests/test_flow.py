"""Tests for the forwarding-flow tracer and its rendering."""

from __future__ import annotations

import unittest
from pathlib import Path

from unwindy.analyzer import analyze
from unwindy.flow import iced_available, trace_flow
from unwindy.pe import PEFile
from unwindy.render import render_flow_lines

SAMPLES = Path(__file__).resolve().parents[1] / "samples"
SAMPLE_DISPATCH = SAMPLES / "602314161f55e2ca2affab8c516437148c079dd8.bin"
SAMPLE_IMPORT = SAMPLES / "b325e5a8da4f8bea2db9fc118f6a6f237731d734.bin"


def _load(path):
    pe = PEFile.from_path(str(path))
    an = analyze(pe, strict=False)
    begins = {f.begin_address: f.index for f in an.functions}
    return pe, an, begins


@unittest.skipUnless(iced_available(), "iced-x86 not installed")
class DispatchTraceTests(unittest.TestCase):
    """The large sample forwards .text stubs into another section."""

    @classmethod
    def setUpClass(cls):
        cls.pe, cls.an, cls.begins = _load(SAMPLE_DISPATCH)

    def test_chain_follows_tail_dispatch_across_sections(self):
        # func #0 begins at .text:0x1020 with a real prolog, then jmps into
        # the forwarding section, which `call`s a resolver and `jmp rax`.
        self.assertEqual(self.an.functions[0].begin_address, 0x1020)
        tr = trace_flow(self.pe, 0x1020, self.begins)
        self.assertEqual(tr.chain, [0x1020, 0x135E0E8, 0x135D340])
        self.assertEqual(tr.stop, "known-begin")
        self.assertTrue(tr.crosses_section)
        self.assertTrue(tr.forwards)

    def test_destination_is_a_known_begin(self):
        tr = trace_flow(self.pe, 0x1020, self.begins)
        dest = tr.destination
        self.assertIsNotNone(dest)
        self.assertEqual(dest.start, 0x135D340)
        self.assertEqual(dest.func_index, self.begins[0x135D340])
        # the landed-on RVA really is another function's begin
        self.assertIn(0x135D340, self.begins)

    def test_first_hop_is_jmp_second_is_call_dispatch(self):
        tr = trace_flow(self.pe, 0x1020, self.begins)
        self.assertEqual(tr.hops[0].edge, "jmp")
        self.assertEqual(tr.hops[0].edge_target, 0x135E0E8)
        self.assertEqual(tr.hops[1].edge, "call")
        self.assertEqual(tr.hops[1].edge_target, 0x135D340)

    def test_block_instructions_decode(self):
        tr = trace_flow(self.pe, 0x1020, self.begins)
        first = tr.hops[0].insns
        self.assertEqual(first[0].text, "mov [rsp+0x10], edx")
        self.assertEqual(first[-1].kind, "jmp")
        self.assertEqual(first[-1].target, 0x135E0E8)

    def test_normal_function_does_not_forward(self):
        # 0x8000 is a real function body, not a forwarding stub.
        self.assertIn(0x8000, self.begins)
        tr = trace_flow(self.pe, 0x8000, self.begins)
        self.assertFalse(tr.forwards)
        self.assertEqual(tr.chain, [0x8000])
        self.assertGreater(len(tr.hops[0].insns), 0)

    def test_render_marks_jumpable_hop_green(self):
        tr = trace_flow(self.pe, 0x1020, self.begins)
        lines = render_flow_lines(
            self.pe, tr, use_va=False, begins=self.begins, max_insns=4
        )
        # the arrow summary leads
        self.assertTrue(lines[0].text.lstrip().startswith("flow:"))
        self.assertIn(" -> ", lines[0].text)
        jumpers = [ln for ln in lines if ln.jump_rva is not None]
        self.assertEqual([j.jump_rva for j in jumpers], [0x135D340])
        self.assertEqual(jumpers[0].color, "green")

    def test_render_caps_long_destination_block(self):
        tr = trace_flow(self.pe, 0x1020, self.begins)
        lines = render_flow_lines(
            self.pe, tr, use_va=False, begins=self.begins, max_insns=4
        )
        self.assertTrue(any("more)" in ln.text for ln in lines))


@unittest.skipUnless(iced_available(), "iced-x86 not installed")
class ImportStubTraceTests(unittest.TestCase):
    def test_jmp_rip_import_stub_stops_at_import(self):
        pe, an, begins = _load(SAMPLE_IMPORT)
        f = an.functions[901]  # the lone `jmp [rip]` import stub
        self.assertEqual(f.begin_address, 0x55780)
        tr = trace_flow(pe, f.begin_address, begins, an.import_resolver)
        self.assertEqual(tr.stop, "import")
        self.assertEqual(tr.import_slot, 0x70020)
        self.assertEqual(len(tr.hops), 1)
        self.assertEqual(tr.hops[0].insns[-1].kind, "ijmp")


class IcedAvailabilityTests(unittest.TestCase):
    def test_degrades_without_iced(self):
        # Force the no-iced path by patching the module flag.
        import unwindy.flow as flow

        saved = flow._iced
        try:
            flow._iced = None
            pe = PEFile.from_path(str(SAMPLE_DISPATCH))
            tr = flow.trace_flow(pe, 0x1020, {})
            self.assertEqual(tr.stop, "no-iced")
            self.assertEqual(tr.hops, [])
            lines = render_flow_lines(pe, tr)
            self.assertEqual(len(lines), 1)
            self.assertIn("iced-x86", lines[0].text)
        finally:
            flow._iced = saved


if __name__ == "__main__":
    unittest.main()
