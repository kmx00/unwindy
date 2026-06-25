"""Raw keyboard input + key decoding for the TUI.

No ``curses`` and no third-party packages: raw bytes via ``msvcrt`` on Windows
and ``termios``/``tty`` on POSIX, normalised to the small set of key tokens the
app reasons about. The token constants are the canonical names; both the readers
and :mod:`unwindy.tui.app` import them from here.
"""

from __future__ import annotations

import os
import sys

# Key tokens returned by the readers.
UP, DOWN, LEFT, RIGHT = "UP", "DOWN", "LEFT", "RIGHT"
PGUP, PGDN, HOME, END = "PGUP", "PGDN", "HOME", "END"
ENTER, ESC, BACKSPACE = "ENTER", "ESC", "BACKSPACE"
TAB, BACKTAB = "TAB", "BACKTAB"
SHIFT_ENTER = "SHIFT_ENTER"


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
            seq = os.read(self._fd, 10)
            return _decode_posix_seq(seq)
        return _decode_byte(ch[0])


def _decode_posix_seq(seq: bytes) -> str:
    text = seq.decode("latin-1", "replace")
    if text[:1] == "[" or text[:1] == "O":
        body = text[1:]
        simple = {
            "A": UP, "B": DOWN, "C": RIGHT, "D": LEFT,
            "H": HOME, "F": END, "Z": BACKTAB,
        }
        if body[:1] in simple:
            return simple[body[:1]]
        # Enter with modifiers: kitty/fixterms CSI-u (\x1b[13;2u) and xterm
        # modifyOtherKeys (\x1b[27;2;13~).  Any modifier on Return -> SHIFT_ENTER.
        if body[-1:] == "u":
            return _decode_modified_enter(body[:-1], code_first=True)
        if body[-1:] == "~" and ";" in body:
            return _decode_modified_enter(body[:-1], code_first=False)
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


def _decode_modified_enter(body: str, *, code_first: bool) -> str:
    """Decode a CSI ``code;mod u`` / ``27;mod;code ~`` Return key sequence."""
    parts = body.split(";")
    try:
        if code_first:  # code ; mod
            code = int(parts[0])
            mod = int(parts[1]) if len(parts) > 1 else 1
        else:  # 27 ; mod ; code
            if len(parts) != 3 or parts[0] != "27":
                return ESC
            mod = int(parts[1])
            code = int(parts[2])
    except (ValueError, IndexError):
        return ESC
    if code not in (10, 13):
        return ESC
    return SHIFT_ENTER if mod >= 2 else ENTER


def _decode_byte(b: int) -> str:
    if b in (13, 10):
        return ENTER
    if b == 9:
        return TAB
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
                "\x0f": BACKTAB,
            }
            return mapping.get(code, ESC)
        if ch in ("\r", "\n"):
            return ENTER
        if ch == "\t":
            return TAB
        if ch == "\x08":
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
