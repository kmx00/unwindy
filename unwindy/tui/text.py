"""ANSI-aware string helpers for the TUI: width-correct truncation and padding.

Escape sequences are zero-width, so plain ``len``-based truncation would corrupt
coloured rows. ``ansi_truncate`` counts only visible columns and keeps escapes
intact (re-appending a reset when it cut inside a styled run)."""

from __future__ import annotations

from typing import List


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
