"""Tests for the interactive TUI logic (no real terminal involved)."""

from __future__ import annotations

import os
import unittest
from pathlib import Path

from unwindy.tui import (
    BACKTAB,
    DOWN,
    END,
    ENTER,
    ESC,
    HOME,
    PGDN,
    PGUP,
    TAB,
    UP,
    SHIFT_ENTER,
    TuiApp,
    _decode_byte,
    _decode_posix_seq,
    ansi_truncate,
    plain_truncate,
)

SAMPLES = Path(__file__).resolve().parents[1] / "samples"
SAMPLE = SAMPLES / "b325e5a8da4f8bea2db9fc118f6a6f237731d734.bin"
SAMPLE2 = SAMPLES / "602314161f55e2ca2affab8c516437148c079dd8.bin"


def _app(files=None, **kw):
    files = files or [str(SAMPLE)]
    return TuiApp(
        files,
        manage_terminal=False,
        get_size=lambda: (120, 30),
        **kw,
    )


class TruncationTests(unittest.TestCase):
    def test_plain_truncate(self):
        self.assertEqual(plain_truncate("hello", 3), "hel")
        self.assertEqual(plain_truncate("hi", 10), "hi")
        self.assertEqual(plain_truncate("hi", 0), "")

    def test_ansi_truncate_counts_visible_only(self):
        colored = "\x1b[31mABCDEF\x1b[0m"
        out = ansi_truncate(colored, 3)
        # visible content limited to 3 chars, escapes preserved, reset appended
        self.assertIn("ABC", out)
        self.assertNotIn("DEF", out)
        self.assertTrue(out.endswith("\x1b[0m"))


class SingleFileTests(unittest.TestCase):
    def test_starts_in_list_with_section_labels(self):
        a = _app()
        self.assertEqual(a.mode, TuiApp.MODE_LIST)
        frame = a.render_frame(120, 30)
        self.assertIn("begin", frame)
        self.assertIn("ops", frame)
        self.assertIn("x-sect", frame)
        self.assertIn(".text:0x", frame)
        self.assertIn("push", frame)  # ops digest content

    def test_navigation(self):
        a = _app()
        a.render_frame(120, 30)  # establishes page size
        self.assertEqual(a.sel, 0)
        a.handle_key("DOWN")
        a.handle_key("DOWN")
        self.assertEqual(a.sel, 2)
        a.handle_key("UP")
        self.assertEqual(a.sel, 1)
        last = len(a.entry().functions) - 1
        a.handle_key("END")
        self.assertEqual(a.sel, last)
        a.handle_key("HOME")
        self.assertEqual(a.sel, 0)
        a.render_frame(120, 30)
        a.handle_key("PGDN")
        self.assertGreater(a.sel, 0)

    def test_selection_scrolls_viewport(self):
        a = _app()
        a.render_frame(120, 30)
        a.handle_key("END")
        a.render_frame(120, 30)
        self.assertGreater(a.top, 0)  # viewport followed the selection

    def test_enter_opens_detail_and_steps(self):
        a = _app()
        a.render_frame(120, 30)
        a.handle_key("DOWN")
        a.handle_key("DOWN")  # function #2 (a chained one)
        a.handle_key("ENTER")
        self.assertEqual(a.mode, TuiApp.MODE_TEXT)
        self.assertEqual(a.text_kind, "detail")
        self.assertTrue(any("Function #2" in ln for ln in a.text_lines))
        a.handle_key("RIGHT")  # next function
        self.assertEqual(a.sel, 3)
        a.handle_key("LEFT")  # previous
        self.assertEqual(a.sel, 2)
        a.handle_key("ESC")
        self.assertEqual(a.mode, TuiApp.MODE_LIST)

    def test_detail_scrolls(self):
        a = _app()
        a.render_frame(120, 30)
        a.handle_key("ENTER")
        a.render_frame(120, 8)  # small viewport
        before = a.text_scroll
        a.handle_key("DOWN")
        self.assertGreaterEqual(a.text_scroll, before)

    def test_warnings_view(self):
        a = _app()
        a.handle_key("w")
        self.assertEqual(a.mode, TuiApp.MODE_TEXT)
        self.assertEqual(a.text_kind, "warnings")
        a.render_frame(120, 30)

    def test_help_view(self):
        a = _app()
        a.handle_key("?")
        self.assertEqual(a.text_kind, "help")

    def test_toggle_va(self):
        a = _app()
        rva_frame = a.render_frame(120, 30)
        self.assertIn(".text:0x", rva_frame)
        self.assertNotIn("0x14000", rva_frame)
        a.handle_key("v")
        va_frame = a.render_frame(120, 30)
        self.assertIn("0x14000", va_frame)  # image base prefix

    def test_esc_and_q_quit_single_file(self):
        self.assertFalse(_app().handle_key("ESC"))
        self.assertFalse(_app().handle_key("q"))


class SortModeTests(unittest.TestCase):
    SIZE_COL = 3  # index of the "size" column in FUNC_COLUMNS

    def test_enter_and_leave_sort_mode(self):
        a = _app()
        a.render_frame(120, 30)
        a.handle_key("s")
        self.assertTrue(a.sort_mode)
        a.handle_key("ESC")
        self.assertFalse(a.sort_mode)

    def test_tab_moves_cursor_and_sort_by_size(self):
        a = _app()
        a.render_frame(120, 30)
        a.handle_key("s")
        for _ in range(self.SIZE_COL):
            a.handle_key(TAB)
        self.assertEqual(a.sort_cursor, self.SIZE_COL)
        a.handle_key(ENTER)  # sort ascending by size
        self.assertEqual(a.sort_applied, self.SIZE_COL)
        self.assertFalse(a.sort_desc)
        sizes = [f.size for f in a.entry().functions]
        self.assertEqual(sizes, sorted(sizes))
        self.assertEqual(a.sel, 0)  # jumped to top
        a.handle_key(ENTER)  # toggle to descending
        self.assertTrue(a.sort_desc)
        sizes = [f.size for f in a.entry().functions]
        self.assertEqual(sizes, sorted(sizes, reverse=True))

    def test_backtab_wraps_and_force_dir(self):
        a = _app()
        a.render_frame(120, 30)
        a.handle_key("s")
        a.handle_key(BACKTAB)  # wrap to last column
        from unwindy.render import FUNC_COLUMNS

        self.assertEqual(a.sort_cursor, len(FUNC_COLUMNS) - 1)
        # 'a' / 'd' force ascending / descending on the cursor column
        a.sort_cursor = self.SIZE_COL
        a.handle_key("d")
        self.assertTrue(a.sort_desc)
        self.assertEqual(a.sort_applied, self.SIZE_COL)
        a.handle_key("a")
        self.assertFalse(a.sort_desc)

    def test_sort_persists_across_files(self):
        a = _app(files=[str(SAMPLE), str(SAMPLE2)])
        a.handle_key(ENTER)  # open first file
        a.render_frame(120, 30)
        a.handle_key("s")
        for _ in range(self.SIZE_COL):
            a.handle_key(TAB)
        a.handle_key(ENTER)
        a.handle_key(ENTER)  # size desc
        a.handle_key(ESC)
        a.handle_key(ESC)  # back to picker
        self.assertEqual(a.mode, TuiApp.MODE_FILES)
        a.handle_key(DOWN)
        a.handle_key(ENTER)  # open second file
        sizes = [f.size for f in a.entry().functions]
        self.assertEqual(sizes, sorted(sizes, reverse=True))


class MultiFileTests(unittest.TestCase):
    def test_picker_lists_all(self):
        a = _app(files=[str(SAMPLE), str(SAMPLE2)])
        self.assertEqual(a.mode, TuiApp.MODE_FILES)
        frame = a.render_frame(120, 30)
        self.assertIn(os.path.basename(str(SAMPLE)), frame)
        self.assertIn(os.path.basename(str(SAMPLE2)), frame)

    def test_open_and_back(self):
        a = _app(files=[str(SAMPLE), str(SAMPLE2)])
        a.handle_key("DOWN")
        self.assertEqual(a.file_sel, 1)
        a.handle_key("ENTER")
        self.assertEqual(a.mode, TuiApp.MODE_LIST)
        self.assertEqual(a.cur, 1)
        frame = a.render_frame(120, 30)
        self.assertIn(os.path.basename(str(SAMPLE2)), frame)
        a.handle_key("ESC")  # back to picker, not quit
        self.assertEqual(a.mode, TuiApp.MODE_FILES)

    def test_lazy_load(self):
        a = _app(files=[str(SAMPLE), str(SAMPLE2)])
        self.assertFalse(a.entries[1].loaded)
        a.handle_key("DOWN")
        a.handle_key("ENTER")
        self.assertTrue(a.entries[1].loaded)


class RunLoopTests(unittest.TestCase):
    def test_scripted_run_terminates(self):
        keys = iter(["DOWN", "DOWN", "ENTER", "DOWN", "ESC", "w", "ESC", "q"])
        frames = []
        a = TuiApp(
            [str(SAMPLE)],
            manage_terminal=False,
            get_size=lambda: (100, 24),
            read_key=lambda: next(keys),
            write=frames.append,
        )
        a.run()
        self.assertGreaterEqual(len(frames), 6)
        # every frame repositions the cursor to home
        self.assertTrue(all(f.startswith("\x1b[H") for f in frames))


class KeyDecodeTests(unittest.TestCase):
    def test_posix_csi_arrows(self):
        self.assertEqual(_decode_posix_seq(b"[A"), UP)
        self.assertEqual(_decode_posix_seq(b"[B"), DOWN)
        self.assertEqual(_decode_posix_seq(b"[H"), HOME)
        self.assertEqual(_decode_posix_seq(b"[F"), END)

    def test_posix_application_mode(self):
        self.assertEqual(_decode_posix_seq(b"OA"), UP)

    def test_posix_tilde_sequences(self):
        self.assertEqual(_decode_posix_seq(b"[5~"), PGUP)
        self.assertEqual(_decode_posix_seq(b"[6~"), PGDN)
        self.assertEqual(_decode_posix_seq(b"[1~"), HOME)
        self.assertEqual(_decode_posix_seq(b"[4~"), END)

    def test_decode_byte(self):
        self.assertEqual(_decode_byte(13), ENTER)
        self.assertEqual(_decode_byte(10), ENTER)
        self.assertEqual(_decode_byte(27), ESC)
        self.assertEqual(_decode_byte(3), "q")  # Ctrl-C -> quit
        self.assertEqual(_decode_byte(ord("v")), "v")

    def test_posix_shift_enter_csi_u(self):
        self.assertEqual(_decode_posix_seq(b"[13;2u"), SHIFT_ENTER)
        self.assertEqual(_decode_posix_seq(b"[13;1u"), ENTER)
        self.assertEqual(_decode_posix_seq(b"[13u"), ENTER)

    def test_posix_shift_enter_modify_other_keys(self):
        self.assertEqual(_decode_posix_seq(b"[27;2;13~"), SHIFT_ENTER)
        self.assertEqual(_decode_posix_seq(b"[27;1;13~"), ENTER)
        # arrows and tilde nav keys still decode after the new branch
        self.assertEqual(_decode_posix_seq(b"[A"), UP)
        self.assertEqual(_decode_posix_seq(b"[5~"), PGUP)


def _iced_ok():
    from unwindy.flow import iced_available
    return iced_available()


@unittest.skipUnless(SAMPLE2.exists() and _iced_ok(), "needs sample + iced-x86")
class FlowExpandTests(unittest.TestCase):
    """Inline forwarding-flow expansion over the large sample."""

    def _open(self):
        a = _app(files=[str(SAMPLE2)])
        a.render_frame(140, 40)
        return a

    def test_x_expands_and_inserts_flow_rows(self):
        a = self._open()
        self.assertEqual(a.entry().functions[0].begin_address, 0x1020)
        base = len(a._visual_rows())
        a.handle_key("x")
        self.assertIn(0, a.expanded)
        vrows = a._visual_rows()
        self.assertGreater(len(vrows), base)
        # a summary row and a jumpable destination row appear under func 0
        own = [r for r in vrows if r[0] == 0 and r[1] >= 0]
        self.assertTrue(any(r[2].lstrip().startswith("flow:") for r in own))
        self.assertTrue(any(r[4] is not None for r in own))

    def test_shift_enter_also_expands(self):
        a = self._open()
        a.handle_key(SHIFT_ENTER)
        self.assertIn(0, a.expanded)
        a.handle_key(SHIFT_ENTER)  # toggles back
        self.assertNotIn(0, a.expanded)

    def test_enter_on_jumpable_row_navigates_to_begin(self):
        a = self._open()
        a.handle_key("x")
        # walk down onto the green jumpable hop
        for _ in range(40):
            vrows = a._visual_rows()
            vi = a._vindex(vrows)
            if vrows[vi][1] >= 0 and vrows[vi][4] is not None:
                break
            a.handle_key("DOWN")
        vrows = a._visual_rows()
        target = vrows[a._vindex(vrows)][4]
        self.assertIsNotNone(target)
        a.handle_key("ENTER")
        self.assertEqual(a.sel, target)
        self.assertEqual(a.flow_idx, -1)
        self.assertEqual(a.entry().functions[a.sel].begin_address, 0x135D340)

    def test_collapse_removes_flow_rows(self):
        a = self._open()
        a.handle_key("x")
        self.assertIn(0, a.expanded)
        a.sel, a.flow_idx = 0, -1
        a.handle_key("x")
        self.assertNotIn(0, a.expanded)
        # only function rows remain (flow_idx == -1 for every row)
        self.assertTrue(all(r[1] == -1 for r in a._visual_rows()))

    def test_sort_clears_expansion(self):
        a = self._open()
        a.handle_key("x")
        self.assertTrue(a.expanded)
        a.handle_key("s")  # entering sort mode clears inline expansions
        self.assertFalse(a.expanded)


if __name__ == "__main__":
    unittest.main()
