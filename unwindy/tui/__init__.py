"""Interactive terminal UI.

A slim, dependency-free TUI split across three modules:

* :mod:`~unwindy.tui.keys` -- raw key input and decoding (no curses).
* :mod:`~unwindy.tui.text` -- ANSI-aware truncation/padding helpers.
* :mod:`~unwindy.tui.app`  -- the ``TuiApp`` state machine and run loop.

The names re-exported here are the package's public surface (and what the tests
import as ``unwindy.tui.*``).
"""

from __future__ import annotations

from .app import TuiApp, run_tui
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
    _decode_byte,
    _decode_modified_enter,
    _decode_posix_seq,
    make_key_reader,
)
from .text import ansi_truncate, pad, plain_truncate

__all__ = [
    "TuiApp",
    "run_tui",
    "make_key_reader",
    "ansi_truncate",
    "pad",
    "plain_truncate",
    "UP", "DOWN", "LEFT", "RIGHT",
    "PGUP", "PGDN", "HOME", "END",
    "ENTER", "ESC", "BACKSPACE", "TAB", "BACKTAB", "SHIFT_ENTER",
]
