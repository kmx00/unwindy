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

from .analyzer import Analysis, analyze
from .errors import UnwindyError
from .pe import PEFile
from .render import (
    FUNC_COLUMNS,
    Painter,
    _enable_windows_vt,
    function_row,
    func_section_info,
    render_diagnostics,
    render_function_detail,
)
from .unwind import RuntimeFunction

# Key tokens returned by the readers.
UP, DOWN, LEFT, RIGHT = "UP", "DOWN", "LEFT", "RIGHT"
PGUP, PGDN, HOME, END = "PGUP", "PGDN", "HOME", "END"
ENTER, ESC, BACKSPACE = "ENTER", "ESC", "BACKSPACE"

_ALIGNS = ["r", "l", "l", "r", "r", "r", "l", "r", "l", "l"]


# --- ANSI-aware string helpers ----------------------------------------------


def plain_truncate(s: str, width: int) -> str:
    if width <= 0:
        return ""
    return s if len(s) <= width else s[:width]


def pad(s: str, width: int) -> str:
    return s + " " * (width - len(s)) if len(s) < width else s


def ansi_truncate(s: str, width: int) -> str:
    """Truncate to ``width`` *visible* columns, preserving ANSI escapes."""
    if width <= 0:
        return ""
    out: List[str] = []
    vis = 0
    i = 0
    n = len(s)
    saw_escape = False
    while i < n:
        ch = s[i]
        if ch == "\x1b":
            j = i + 1
            if j < n and s[j] == "[":
                j += 1
                while j < n and not ("@" <= s[j] <= "~"):
                    j += 1
                if j < n:
                    j += 1
            else:
                j = min(n, i + 2)
            out.append(s[i:j])
            saw_escape = True
            i = j
            continue
        if vis >= width:
            break
        out.append(ch)
        vis += 1
        i += 1
    res = "".join(out)
    if saw_escape and not res.endswith("\x1b[0m"):
        res += "\x1b[0m"
    return res


# --- key readers ------------------------------------------------------------


class _PosixKeyReader:
    def __init__(self) -> None:
        import termios  # noqa: F401  (import-time availability check)

        self._fd = sys.stdin.fileno()
        self._old = None

    def __enter__(self) -> "_PosixKeyReader":
        import termios
        import tty

        self._old = termios.tcgetattr(self._fd)
        tty.setraw(self._fd)
        return self

    def __exit__(self, *exc) -> None:
        import termios

        if self._old is not None:
            termios.tcsetattr(self._fd, termios.TCSADRAIN, self._old)

    def read_key(self) -> str:
        data = os.read(self._fd, 1)
        if not data:
            return ESC
        ch = data
        if ch == b"\x1b":
            import select

            r, _, _ = select.select([self._fd], [], [], 0.02)
            if not r:
                return ESC
            seq = os.read(self._fd, 5)
            return _decode_posix_seq(seq)
        return _decode_byte(ch[0])


def _decode_posix_seq(seq: bytes) -> str:
    text = seq.decode("latin-1", "replace")
    if text[:1] == "[" or text[:1] == "O":
        body = text[1:]
        simple = {
            "A": UP, "B": DOWN, "C": RIGHT, "D": LEFT,
            "H": HOME, "F": END,
        }
        if body[:1] in simple:
            return simple[body[:1]]
        # \x1b[<num>~
        num = ""
        for c in body:
            if c.isdigit():
                num += c
            else:
                break
        mapping = {"1": HOME, "7": HOME, "4": END, "8": END, "5": PGUP, "6": PGDN}
        return mapping.get(num, ESC)
    return ESC


def _decode_byte(b: int) -> str:
    if b in (13, 10):
        return ENTER
    if b in (127, 8):
        return BACKSPACE
    if b == 3:  # Ctrl-C
        return "q"
    if b == 27:
        return ESC
    return chr(b)


class _WindowsKeyReader:
    def __enter__(self) -> "_WindowsKeyReader":
        return self

    def __exit__(self, *exc) -> None:
        pass

    def read_key(self) -> str:
        import msvcrt

        ch = msvcrt.getwch()
        if ch in ("\x00", "\xe0"):  # special key prefix
            code = msvcrt.getwch()
            mapping = {
                "H": UP, "P": DOWN, "K": LEFT, "M": RIGHT,
                "I": PGUP, "Q": PGDN, "G": HOME, "O": END,
            }
            return mapping.get(code, ESC)
        if ch in ("\r", "\n"):
            return ENTER
        if ch in ("\x08",):
            return BACKSPACE
        if ch == "\x03":
            return "q"
        if ch == "\x1b":
            return ESC
        return ch


def make_key_reader():
    if os.name == "nt":
        return _WindowsKeyReader()
    return _PosixKeyReader()


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

    def rows(self, use_va: bool) -> Tuple[str, List[str], List[bool]]:
        if use_va in self._rows_cache:
            return self._rows_cache[use_va]
        result = _compose_rows(self.pe, self.functions, use_va)
        self._rows_cache[use_va] = result
        return result


def _compose_rows(
    pe: Optional[PEFile], functions: Sequence[RuntimeFunction], use_va: bool
) -> Tuple[str, List[str], List[bool]]:
    cols = len(FUNC_COLUMNS)
    raw = [[str(c) for c in function_row(pe, f, use_va=use_va)] for f in functions]
    widths = [len(h) for h in FUNC_COLUMNS]
    for r in raw:
        for i in range(cols):
            widths[i] = max(widths[i], len(r[i]))

    def cell(s: str, i: int) -> str:
        return s.rjust(widths[i]) if _ALIGNS[i] == "r" else s.ljust(widths[i])

    sep = "  "
    header = sep.join(cell(FUNC_COLUMNS[i], i) for i in range(cols))
    rows = [sep.join(cell(r[i], i) for i in range(cols)) for r in raw]
    meta = [func_section_info(pe, f)[2] for f in functions]
    return header, rows, meta


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

        # text view state
        self.text_lines: List[str] = []
        self.text_title = ""
        self.text_scroll = 0
        self.text_kind = ""  # 'detail' | 'warnings' | 'help' | 'error'

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
        if e.error:
            self._open_text("error", f"Error loading {os.path.basename(e.path)}",
                            [self.painter.red(e.error)])
        else:
            self.mode = self.MODE_LIST

    # -- LIST mode ------------------------------------------------------------

    def _lines_list(self, cols: int, rows: int) -> List[str]:
        p = self.painter
        e = self.entry()
        header, rowstrs, meta = e.rows(self.use_va)
        nfun = len(rowstrs)
        warns = len(e.analysis.diagnostics.warnings) if e.analysis else 0
        errs = len(e.analysis.diagnostics.errors) if e.analysis else 0
        name = os.path.basename(e.path)
        pos = f"{self.sel + 1}/{nfun}" if nfun else "0/0"
        warn_txt = ""
        if warns or errs:
            warn_txt = f"   ! {warns}w {errs}e"
        title = f" {name}   {pos}   {'VA' if self.use_va else 'RVA'}{warn_txt} "
        lines = [self._bar(title, cols)]
        lines.append(p.bold(plain_truncate(header, cols)))
        body_h = max(1, rows - 3)
        self.page = body_h
        if nfun == 0:
            lines.append(p.yellow("  (no functions in this image)"))
            for _ in range(body_h - 1):
                lines.append("")
        else:
            self.sel = self._clamp(self.sel, 0, nfun - 1)
            self.top = self._ensure_visible(self.sel, self.top, nfun, body_h)
            for i in range(body_h):
                idx = self.top + i
                if idx >= nfun:
                    lines.append("")
                    continue
                s = plain_truncate(rowstrs[idx], cols)
                if idx == self.sel:
                    lines.append(p.reverse(pad(s, cols)))
                elif meta[idx]:
                    lines.append(p.red(s))
                else:
                    lines.append(s)
        back = "back" if len(self.entries) > 1 else "quit"
        lines.append(
            self._bar(
                f" up/down  PgUp/PgDn  enter inspect  w warnings  v va/rva  "
                f"esc {back}  q quit ",
                cols,
            )
        )
        return lines

    def _handle_list(self, key: str) -> bool:
        e = self.entry()
        n = len(e.functions)
        if key in (UP, "k"):
            self.sel = self._clamp(self.sel - 1, 0, max(0, n - 1))
        elif key in (DOWN, "j"):
            self.sel = self._clamp(self.sel + 1, 0, max(0, n - 1))
        elif key == PGUP:
            self.sel = self._clamp(self.sel - self.page, 0, max(0, n - 1))
        elif key == PGDN:
            self.sel = self._clamp(self.sel + self.page, 0, max(0, n - 1))
        elif key in (HOME, "g"):
            self.sel = 0
        elif key in (END, "G"):
            self.sel = max(0, n - 1)
        elif key == ENTER and n:
            self._open_detail()
        elif key == "w":
            self._open_warnings()
        elif key in ("h", "?"):
            self._open_help()
        elif key == "v":
            self.use_va = not self.use_va
        elif key == "q":
            return False
        elif key in (ESC, LEFT):
            if len(self.entries) > 1:
                self.mode = self.MODE_FILES
            else:
                return False
        return True

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
        self._open_detail()

    # -- chrome ---------------------------------------------------------------

    def _bar(self, text: str, cols: int) -> str:
        return self.painter.reverse(pad(plain_truncate(text, cols), cols))


_HELP_LINES = [
    "unwindy interactive viewer",
    "",
    "  Lists every RUNTIME_FUNCTION in the PE64 exception directory.",
    "  Addresses are shown as  section:0xADDRESS  (begin and end).",
    "  The 'x-sect' column flags a function whose body spans two sections",
    "  (shown as A->B and highlighted in red).",
    "",
    "navigation",
    "  up / down (or k / j)    move selection",
    "  PgUp / PgDn             move a page",
    "  Home / End (or g / G)   jump to first / last",
    "  Enter                   inspect the selected function in full detail",
    "  Left / Right            (in detail) previous / next function",
    "  w                       view diagnostics (warnings / errors)",
    "  v                       toggle between RVA and virtual address",
    "  h or ?                  this help",
    "  Esc                     back (to file list) / quit",
    "  q                       quit",
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
