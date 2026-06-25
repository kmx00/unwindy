"""A slim, dependency-free interactive terminal UI.

No ``curses`` (so it works identically on Windows and Linux): raw key input via
``termios``/``tty`` on POSIX and ``msvcrt`` on Windows, rendering with ANSI
escapes on the alternate screen buffer.

The interaction logic (state + frame composition) is deliberately separated from
terminal control so it can be unit-tested without a real TTY: inject ``read_key``
/ ``get_size`` / ``write`` and set ``manage_terminal=False``.
"""

from __future__ import annotations

import os
import sys
from typing import Callable, Dict, List, Optional, Sequence, Tuple

from ..analyzer import Analysis, analyze
from ..errors import UnwindyError
from ..flow import trace_flow
from ..pe import PEFile
from ..render import (
    FUNC_ALIGNS,
    FUNC_COLUMN_TABLE,
    FUNC_COLUMNS,
    Painter,
    _enable_windows_vt,
    function_row,
    func_section_info,
    render_diagnostics,
    render_flow_lines,
    render_function_detail,
)
from ..unwind import RuntimeFunction
from .keys import (
    BACKSPACE,
    BACKTAB,
    DOWN,
    END,
    ENTER,
    ESC,
    HOME,
    LEFT,
    PGDN,
    PGUP,
    RIGHT,
    SHIFT_ENTER,
    TAB,
    UP,
    make_key_reader,
)
from .text import ansi_truncate, pad, plain_truncate


# --- file entry / analysis cache --------------------------------------------


class _Entry:
    def __init__(self, path: str) -> None:
        self.path = path
        self.loaded = False
        self.error: Optional[str] = None
        self.pe: Optional[PEFile] = None
        self.analysis: Optional[Analysis] = None
        self.functions: List[RuntimeFunction] = []
        self._rows_cache: Dict[bool, Tuple[str, List[str], List[bool]]] = {}
        # forwarding-flow caches (lazily populated on expand)
        self.flow_cache: Dict[int, object] = {}
        self.flow_lines_cache: Dict[Tuple[int, bool], list] = {}
        self._begins: Optional[Dict[int, Optional[int]]] = None
        self._begin_pos: Optional[Dict[int, int]] = None
        try:
            self.size = os.path.getsize(path)
        except OSError:
            self.size = 0

    def load(self) -> None:
        if self.loaded:
            return
        self.loaded = True
        try:
            self.pe = PEFile.from_path(self.path)
            # TUI is exploratory: never abort on a single bad entry.
            self.analysis = analyze(self.pe, strict=False)
            self.functions = list(self.analysis.functions)
        except (UnwindyError, OSError, ValueError) as exc:
            self.error = f"{type(exc).__name__}: {exc}"

    def rows(
        self, use_va: bool
    ) -> Tuple[str, List[str], List[bool], List[int]]:
        if use_va in self._rows_cache:
            return self._rows_cache[use_va]
        result = _compose_rows(self.pe, self.functions, use_va)
        self._rows_cache[use_va] = result
        return result

    # -- forwarding-flow expansion -------------------------------------------

    def begins_map(self) -> Dict[int, Optional[int]]:
        """begin RVA -> .pdata index (stable across re-sorts)."""
        if self._begins is None:
            self._begins = {f.begin_address: f.index for f in self.functions}
        return self._begins

    def begin_pos(self) -> Dict[int, int]:
        """begin RVA -> current list position (invalidated on sort)."""
        if self._begin_pos is None:
            self._begin_pos = {
                f.begin_address: i for i, f in enumerate(self.functions)
            }
        return self._begin_pos

    def flow_trace(self, begin: int):
        tr = self.flow_cache.get(begin)
        if tr is None:
            resolver = self.analysis.import_resolver if self.analysis else None
            tr = trace_flow(self.pe, begin, self.begins_map(), resolver)
            self.flow_cache[begin] = tr
        return tr

    def flow_lines(self, begin: int, use_va: bool) -> list:
        key = (begin, use_va)
        out = self.flow_lines_cache.get(key)
        if out is None:
            out = render_flow_lines(
                self.pe, self.flow_trace(begin),
                use_va=use_va, begins=self.begins_map(),
            )
            self.flow_lines_cache[key] = out
        return out

    def invalidate_positions(self) -> None:
        """Drop position-derived caches after the function order changes."""
        self._begin_pos = None


def _compose_rows(
    pe: Optional[PEFile], functions: Sequence[RuntimeFunction], use_va: bool
) -> Tuple[str, List[str], List[bool], List[int]]:
    cols = len(FUNC_COLUMNS)
    raw = [[str(c) for c in function_row(pe, f, use_va=use_va)] for f in functions]
    widths = [len(h) for h in FUNC_COLUMNS]
    for r in raw:
        for i in range(cols):
            widths[i] = max(widths[i], len(r[i]))

    def cell(s: str, i: int) -> str:
        return s.rjust(widths[i]) if FUNC_ALIGNS[i] == "r" else s.ljust(widths[i])

    sep = "  "
    header = sep.join(cell(FUNC_COLUMNS[i], i) for i in range(cols))
    rows = [sep.join(cell(r[i], i) for i in range(cols)) for r in raw]
    meta = [func_section_info(pe, f)[2] for f in functions]
    return header, rows, meta, widths


# --- the app ----------------------------------------------------------------


class TuiApp:
    MODE_FILES = "files"
    MODE_LIST = "list"
    MODE_TEXT = "text"

    def __init__(
        self,
        files: Sequence[str],
        *,
        use_va: bool = False,
        read_key: Optional[Callable[[], str]] = None,
        get_size: Optional[Callable[[], Tuple[int, int]]] = None,
        write: Optional[Callable[[str], None]] = None,
        manage_terminal: bool = True,
    ) -> None:
        if not files:
            raise ValueError("TuiApp requires at least one file")
        self.entries = [_Entry(p) for p in files]
        self.use_va = use_va
        self.painter = Painter(True)
        self._reader = None
        self._read_key = read_key
        self._get_size = get_size or (lambda: _terminal_size())
        self._write = write or _stdout_write
        self.manage_terminal = manage_terminal

        # selection state
        self.file_sel = 0
        self.file_top = 0
        self.sel = 0
        self.top = 0
        self.page = 1
        # inline forwarding-flow expansion
        self.expanded: set = set()   # function positions shown expanded
        self.flow_idx = -1           # sub-row under sel (-1 == the function row)

        # text view state
        self.text_lines: List[str] = []
        self.text_title = ""
        self.text_scroll = 0
        self.text_kind = ""  # 'detail' | 'warnings' | 'help' | 'error'

        # interactive column-sort state
        self.sort_mode = False
        self.sort_cursor = 0          # column the Tab cursor is on
        self.sort_applied: Optional[int] = None  # column currently sorted by
        self.sort_desc = False

        if len(self.entries) > 1:
            self.mode = self.MODE_FILES
            self.cur = -1
        else:
            self.mode = self.MODE_LIST
            self.cur = 0
            self.entries[0].load()

    # -- helpers --------------------------------------------------------------

    def entry(self) -> _Entry:
        return self.entries[self.cur]

    def _clamp(self, value: int, lo: int, hi: int) -> int:
        return max(lo, min(value, hi))

    def _ensure_visible(self, sel: int, top: int, count: int, page: int) -> int:
        if sel < top:
            top = sel
        elif sel >= top + page:
            top = sel - page + 1
        return self._clamp(top, 0, max(0, count - page))

    # -- public-ish API (used by run() and tests) ----------------------------

    def render_frame(self, cols: int, rows: int) -> str:
        if self.mode == self.MODE_FILES:
            lines = self._lines_files(cols, rows)
        elif self.mode == self.MODE_TEXT:
            lines = self._lines_text(cols, rows)
        else:
            lines = self._lines_list(cols, rows)
        body = [(lines[i] if i < len(lines) else "") + "\x1b[K" for i in range(rows)]
        return "\x1b[H" + "\r\n".join(body) + "\x1b[J"

    def handle_key(self, key: str) -> bool:
        """Return False to quit."""
        if self.mode == self.MODE_FILES:
            return self._handle_files(key)
        if self.mode == self.MODE_TEXT:
            return self._handle_text(key)
        return self._handle_list(key)

    # -- run loop -------------------------------------------------------------

    def run(self) -> None:
        self._enter()
        try:
            while True:
                cols, rows = self._get_size()
                self._write(self.render_frame(cols, rows))
                key = self._next_key()
                if not self.handle_key(key):
                    break
        finally:
            self._leave()

    def _next_key(self) -> str:
        if self._read_key is not None:
            return self._read_key()
        assert self._reader is not None
        return self._reader.read_key()

    def _enter(self) -> None:
        if not self.manage_terminal:
            return
        _enable_windows_vt()
        if self._read_key is None:
            self._reader = make_key_reader()
            self._reader.__enter__()
        self._write("\x1b[?1049h\x1b[?25l\x1b[2J")

    def _leave(self) -> None:
        if not self.manage_terminal:
            return
        self._write("\x1b[?25h\x1b[?1049l")
        if self._reader is not None:
            self._reader.__exit__(None, None, None)
            self._reader = None

    # -- FILES mode -----------------------------------------------------------

    def _lines_files(self, cols: int, rows: int) -> List[str]:
        p = self.painter
        names = [os.path.basename(e.path) for e in self.entries]
        namew = min(72, max(len("file"), max(len(n) for n in names)))
        lines = [self._bar(f" unwindy  -  {len(self.entries)} binaries ", cols)]
        cols_hdr = (
            f"  {'#':>3}  {'file':<{namew}}  {'size':>9}  {'funcs':>7}  warnings"
        )
        lines.append(p.bold(plain_truncate(cols_hdr, cols)))
        body_h = max(1, rows - 3)
        self.page = body_h
        self.file_top = self._ensure_visible(
            self.file_sel, self.file_top, len(self.entries), body_h
        )
        for i in range(body_h):
            idx = self.file_top + i
            if idx >= len(self.entries):
                lines.append("")
                continue
            e = self.entries[idx]
            name = names[idx]
            size = _human(e.size)
            if e.loaded and e.error:
                funcs = "err"
                warns = "!"
            elif e.loaded:
                funcs = str(len(e.functions))
                warns = str(len(e.analysis.diagnostics.warnings)) if e.analysis else "0"
            else:
                funcs = "-"
                warns = "-"
            row = f"  {idx:>3}  {name:<{namew}}  {size:>9}  {funcs:>7}  {warns}"
            row = plain_truncate(row, cols)
            if idx == self.file_sel:
                lines.append(p.reverse(pad(row, cols)))
            elif e.loaded and e.error:
                lines.append(p.red(row))
            else:
                lines.append(row)
        lines.append(
            self._bar(" up/down move   enter open   q quit ", cols)
        )
        return lines

    def _handle_files(self, key: str) -> bool:
        n = len(self.entries)
        if key in (UP, "k"):
            self.file_sel = self._clamp(self.file_sel - 1, 0, n - 1)
        elif key in (DOWN, "j"):
            self.file_sel = self._clamp(self.file_sel + 1, 0, n - 1)
        elif key == PGUP:
            self.file_sel = self._clamp(self.file_sel - self.page, 0, n - 1)
        elif key == PGDN:
            self.file_sel = self._clamp(self.file_sel + self.page, 0, n - 1)
        elif key in (HOME, "g"):
            self.file_sel = 0
        elif key in (END, "G"):
            self.file_sel = n - 1
        elif key == ENTER:
            self._open_file(self.file_sel)
        elif key in ("q", ESC):
            return False
        return True

    def _open_file(self, idx: int) -> None:
        self.cur = idx
        e = self.entry()
        e.load()
        self.sel = 0
        self.top = 0
        self.flow_idx = -1
        self.expanded.clear()
        self.sort_mode = False
        if e.error:
            self._open_text("error", f"Error loading {os.path.basename(e.path)}",
                            [self.painter.red(e.error)])
        else:
            self.mode = self.MODE_LIST
            if self.sort_applied is not None:
                self._sort_current()

    # -- LIST mode ------------------------------------------------------------

    def _lines_list(self, cols: int, rows: int) -> List[str]:
        p = self.painter
        e = self.entry()
        header, rowstrs, meta, widths = e.rows(self.use_va)
        nfun = len(rowstrs)
        warns = len(e.analysis.diagnostics.warnings) if e.analysis else 0
        errs = len(e.analysis.diagnostics.errors) if e.analysis else 0
        name = os.path.basename(e.path)
        pos = f"{self.sel + 1}/{nfun}" if nfun else "0/0"
        warn_txt = ""
        if warns or errs:
            warn_txt = f"   ! {warns}w {errs}e"
        sort_txt = ""
        if self.sort_applied is not None:
            arrow = "desc" if self.sort_desc else "asc"
            sort_txt = f"   sort:{FUNC_COLUMNS[self.sort_applied]} {arrow}"
        title = (
            f" {name}   {pos}   {'VA' if self.use_va else 'RVA'}{warn_txt}{sort_txt} "
        )
        lines = [self._bar(title, cols)]
        lines.append(self._header_line(widths, cols))
        body_h = max(1, rows - 3)
        self.page = body_h
        if nfun == 0:
            lines.append(p.yellow("  (no functions in this image)"))
            for _ in range(body_h - 1):
                lines.append("")
        else:
            self.sel = self._clamp(self.sel, 0, nfun - 1)
            vrows = self._visual_rows()
            vi = self._vindex(vrows)
            self.top = self._ensure_visible(vi, self.top, len(vrows), body_h)
            for i in range(body_h):
                idx = self.top + i
                if idx >= len(vrows):
                    lines.append("")
                    continue
                _, _, text, color, _ = vrows[idx]
                s = plain_truncate(text, cols)
                if idx == vi:
                    lines.append(p.reverse(pad(s, cols)))
                elif color:
                    lines.append(p.wrap(s, color))
                else:
                    lines.append(s)
        if self.sort_mode:
            footer = (
                f" SORT  tab/<-/-> column   enter sort (toggle asc/desc)   "
                f"esc done   [{FUNC_COLUMNS[self.sort_cursor]}] "
            )
        else:
            back = "back" if len(self.entries) > 1 else "quit"
            footer = (
                f" up/down  enter inspect/jump  x expand flow  s sort  "
                f"w warn  v va/rva  esc {back}  q quit "
            )
        lines.append(self._bar(footer, cols))
        return lines

    def _header_line(self, widths: List[int], cols: int) -> str:
        p = self.painter
        sep = "  "
        parts = []
        for i, name in enumerate(FUNC_COLUMNS):
            cell = name.rjust(widths[i]) if FUNC_ALIGNS[i] == "r" else name.ljust(widths[i])
            if self.sort_mode and i == self.sort_cursor:
                cell = p.reverse(cell)
            elif self.sort_applied == i:
                cell = p.wrap(cell, "green", "bold")
            else:
                cell = p.bold(cell)
            parts.append(cell)
        return ansi_truncate(sep.join(parts), cols)

    def _handle_list(self, key: str) -> bool:
        if self.sort_mode:
            return self._handle_sort(key)
        e = self.entry()
        n = len(e.functions)
        if n == 0:
            if key == "q":
                return False
            if key in (ESC, LEFT):
                return self._leave_list()
            if key == "w":
                self._open_warnings()
            elif key in ("h", "?"):
                self._open_help()
            elif key == "v":
                self.use_va = not self.use_va
            return True
        vrows = self._visual_rows()
        vi = self._vindex(vrows)
        if key in (UP, "k"):
            self._move_cursor(vrows, vi - 1)
        elif key in (DOWN, "j"):
            self._move_cursor(vrows, vi + 1)
        elif key == PGUP:
            self._move_cursor(vrows, vi - self.page)
        elif key == PGDN:
            self._move_cursor(vrows, vi + self.page)
        elif key in (HOME, "g"):
            self._move_cursor(vrows, 0)
        elif key in (END, "G"):
            self._move_cursor(vrows, len(vrows) - 1)
        elif key == ENTER:
            self._activate_row(vrows, vi)
        elif key in (SHIFT_ENTER, "x"):
            self._toggle_expand()
        elif key in ("s", TAB):
            self.expanded.clear()
            self.flow_idx = -1
            self.sort_mode = True
            if self.sort_applied is not None:
                self.sort_cursor = self.sort_applied
        elif key == "w":
            self._open_warnings()
        elif key in ("h", "?"):
            self._open_help()
        elif key == "v":
            self.use_va = not self.use_va
        elif key == "q":
            return False
        elif key in (ESC, LEFT):
            return self._leave_list()
        return True

    # -- visual-row model (function rows + inline flow expansions) -----------

    def _visual_rows(self) -> List[Tuple[int, int, str, str, Optional[int]]]:
        """Flatten functions and any expanded flow into renderable rows.

        Each row is ``(func_pos, flow_idx, text, color, jump_pos)``; ``flow_idx``
        is ``-1`` for a function row, and ``jump_pos`` is the destination list
        position when a flow row lands on another function's begin."""
        e = self.entry()
        _, rowstrs, meta, _ = e.rows(self.use_va)
        out: List[Tuple[int, int, str, str, Optional[int]]] = []
        for p in range(len(rowstrs)):
            out.append((p, -1, rowstrs[p], "red" if meta[p] else "", None))
            if p in self.expanded:
                begin = e.functions[p].begin_address
                for k, fl in enumerate(e.flow_lines(begin, self.use_va)):
                    jump_pos = (
                        e.begin_pos().get(fl.jump_rva)
                        if fl.jump_rva is not None
                        else None
                    )
                    out.append((p, k, fl.text, fl.color, jump_pos))
        return out

    def _vindex(self, vrows) -> int:
        for i, (p, fi, *_rest) in enumerate(vrows):
            if p == self.sel and fi == self.flow_idx:
                return i
        # selection moved onto a now-collapsed row: fall back to its func row.
        self.flow_idx = -1
        for i, (p, fi, *_rest) in enumerate(vrows):
            if p == self.sel and fi == -1:
                return i
        return 0

    def _move_cursor(self, vrows, new_i: int) -> None:
        new_i = self._clamp(new_i, 0, len(vrows) - 1)
        p, fi = vrows[new_i][0], vrows[new_i][1]
        self.sel = p
        self.flow_idx = fi

    def _activate_row(self, vrows, vi: int) -> None:
        _, fi, _text, _color, jump_pos = vrows[vi]
        if fi >= 0 and jump_pos is not None:  # jump to the landed function
            self.sel = jump_pos
            self.flow_idx = -1
            return
        self._open_detail()  # function row or non-jumpable flow row

    def _toggle_expand(self) -> None:
        e = self.entry()
        if not e.functions:
            return
        p = self.sel
        if p in self.expanded:
            self.expanded.discard(p)
        else:
            self.expanded.add(p)
        self.flow_idx = -1  # land back on the function row either way

    def _leave_list(self) -> bool:
        if len(self.entries) > 1:
            self.mode = self.MODE_FILES
            return True
        return False

    def _handle_sort(self, key: str) -> bool:
        ncols = len(FUNC_COLUMNS)
        if key in (TAB, RIGHT, "l"):
            self.sort_cursor = (self.sort_cursor + 1) % ncols
        elif key in (BACKTAB, LEFT, "h"):
            self.sort_cursor = (self.sort_cursor - 1) % ncols
        elif key in (ENTER, " "):
            if self.sort_applied == self.sort_cursor:
                self.sort_desc = not self.sort_desc
            else:
                self.sort_applied = self.sort_cursor
                self.sort_desc = False
            self._sort_current()
        elif key == "a":
            self.sort_applied = self.sort_cursor
            self.sort_desc = False
            self._sort_current()
        elif key == "d":
            self.sort_applied = self.sort_cursor
            self.sort_desc = True
            self._sort_current()
        elif key in (UP, "k"):
            self.sel = self._clamp(self.sel - 1, 0, max(0, len(self.entry().functions) - 1))
            self.flow_idx = -1
        elif key in (DOWN, "j"):
            self.sel = self._clamp(self.sel + 1, 0, max(0, len(self.entry().functions) - 1))
            self.flow_idx = -1
        elif key in (ESC, "s", "q"):
            self.sort_mode = False
        return True

    def _sort_keyfn(self, col: int, pe):
        sort_key = FUNC_COLUMN_TABLE[col].sort_key
        return lambda f: sort_key(pe, f)

    def _sort_current(self) -> None:
        e = self.entry()
        if e.pe is None or self.sort_applied is None or not e.functions:
            return
        e.functions.sort(key=self._sort_keyfn(self.sort_applied, e.pe),
                         reverse=self.sort_desc)
        e._rows_cache.clear()
        e.invalidate_positions()  # list order changed; begin->pos is stale
        self.expanded.clear()
        self.flow_idx = -1
        # Surface the extremes: a fresh sort jumps to the top of the list.
        self.sel = 0
        self.top = 0

    # -- TEXT mode (detail / warnings / help / error) ------------------------

    def _open_text(self, kind: str, title: str, lines: List[str]) -> None:
        self.text_kind = kind
        self.text_title = title
        self.text_lines = lines
        self.text_scroll = 0
        self.mode = self.MODE_TEXT

    def _open_detail(self) -> None:
        e = self.entry()
        f = e.functions[self.sel]
        text = render_function_detail(e.pe, f, self.painter, use_va=self.use_va)
        idx = "?" if f.index is None else f.index
        self._open_text(
            "detail",
            f" function #{idx}   ({self.sel + 1}/{len(e.functions)}) ",
            text.split("\n"),
        )

    def _open_warnings(self) -> None:
        e = self.entry()
        diags = list(e.analysis.diagnostics) if e.analysis else []
        text = render_diagnostics(diags, self.painter)
        self._open_text("warnings", " diagnostics ", text.split("\n"))

    def _open_help(self) -> None:
        self._open_text("help", " help ", _HELP_LINES)

    def _lines_text(self, cols: int, rows: int) -> List[str]:
        p = self.painter
        lines = [self._bar(self.text_title, cols)]
        body_h = max(1, rows - 2)
        self.page = body_h
        total = len(self.text_lines)
        self.text_scroll = self._clamp(
            self.text_scroll, 0, max(0, total - body_h)
        )
        for i in range(body_h):
            idx = self.text_scroll + i
            if idx >= total:
                lines.append("")
            else:
                lines.append(ansi_truncate(self.text_lines[idx], cols))
        nav = ""
        if self.text_kind == "detail":
            nav = "left/right prev/next   "
        more = ""
        if total > body_h:
            more = f"   [{self.text_scroll + 1}-{min(total, self.text_scroll + body_h)}/{total}]"
        lines.append(self._bar(f" up/down scroll   {nav}esc back   q back{more} ", cols))
        return lines

    def _handle_text(self, key: str) -> bool:
        total = len(self.text_lines)
        if key in (UP, "k"):
            self.text_scroll = self._clamp(self.text_scroll - 1, 0, max(0, total - 1))
        elif key in (DOWN, "j"):
            self.text_scroll = self._clamp(self.text_scroll + 1, 0, max(0, total - 1))
        elif key == PGUP:
            self.text_scroll = self._clamp(
                self.text_scroll - self.page, 0, max(0, total - 1)
            )
        elif key == PGDN:
            self.text_scroll = self._clamp(
                self.text_scroll + self.page, 0, max(0, total - 1)
            )
        elif key in (HOME, "g"):
            self.text_scroll = 0
        elif key in (END, "G"):
            self.text_scroll = max(0, total - 1)
        elif key == LEFT and self.text_kind == "detail":
            self._step_detail(-1)
        elif key == RIGHT and self.text_kind == "detail":
            self._step_detail(1)
        elif key in (ESC, ENTER, BACKSPACE, "q"):
            self.mode = self.MODE_LIST
        return True

    def _step_detail(self, delta: int) -> None:
        e = self.entry()
        n = len(e.functions)
        if not n:
            return
        self.sel = self._clamp(self.sel + delta, 0, n - 1)
        self.flow_idx = -1
        self._open_detail()

    # -- chrome ---------------------------------------------------------------

    def _bar(self, text: str, cols: int) -> str:
        return self.painter.reverse(pad(plain_truncate(text, cols), cols))


_HELP_LINES = [
    "unwindy interactive viewer",
    "",
    "  Lists every RUNTIME_FUNCTION in the PE64 exception directory.",
    "  Addresses are shown as  section:0xADDRESS  (begin and end).",
    "  The 'ops' column digests the prolog, e.g.  4push sub 0x28 3xmm.",
    "  The 'x-sect' column flags a function whose body spans two sections",
    "  (shown as A->B and highlighted in red).",
    "",
    "navigation",
    "  up / down (or k / j)    move selection",
    "  PgUp / PgDn             move a page",
    "  Home / End (or g / G)   jump to first / last",
    "  Enter                   inspect the selected function in full detail",
    "  Left / Right            (in detail) previous / next function",
    "",
    "forwarding flow",
    "  x  (or Shift+Enter*)    expand/collapse the code-flow trace of a func",
    "                          -- decodes each block and follows the jmp/",
    "                          tail-dispatch chain across sections, e.g.",
    "                          .text:0x1020 -> .grfn10:.. -> .grfn10:..",
    "  Enter (on a green hop)  jump to the function that hop lands on",
    "  * Shift+Enter is honored only on terminals that report it; the",
    "    standard Windows console cannot, so use 'x' there.",
    "  w                       view diagnostics (warnings / errors)",
    "  v                       toggle between RVA and virtual address",
    "  h or ?                  this help",
    "  Esc                     back (to file list) / quit",
    "  q                       quit",
    "",
    "sort mode  (press 's' or Tab in the list)",
    "  Tab / Left / Right      move between columns",
    "  Enter                   sort by the column (press again to flip asc/desc)",
    "  a / d                   force ascending / descending",
    "  Esc or s                leave sort mode (the sort is kept)",
]


# --- terminal plumbing ------------------------------------------------------


def _terminal_size() -> Tuple[int, int]:
    import shutil

    size = shutil.get_terminal_size(fallback=(100, 30))
    return max(20, size.columns), max(6, size.lines)


def _stdout_write(text: str) -> None:
    sys.stdout.write(text)
    sys.stdout.flush()


def _human(n: int) -> str:
    size = float(n)
    for unit in ("B", "K", "M", "G"):
        if size < 1024 or unit == "G":
            return f"{size:.0f}B" if unit == "B" else f"{size:.1f}{unit}"
        size /= 1024
    return f"{size:.0f}"


def run_tui(files: Sequence[str], *, use_va: bool = False) -> int:
    if not sys.stdin.isatty() or not sys.stdout.isatty():
        sys.stderr.write(
            "unwindy: --tui requires an interactive terminal "
            "(stdin/stdout must be a TTY)\n"
        )
        return 2
    app = TuiApp(files, use_va=use_va)
    app.run()
    return 0
