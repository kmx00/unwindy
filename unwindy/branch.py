"""Decode the handful of x86-64 branch encodings unwindy follows off-disk.

Pure standard library (no iced-x86): these primitives run inside the
dependency-free analysis core -- start-trampoline peeling and handler-thunk
resolution -- where adopting a disassembler would be overkill.  The richer
interactive flow view in :mod:`unwindy.flow` uses iced-x86 instead.

Three forms are recognised, all read from a clamped 6-byte window so they are
safe to probe at any RVA:

* ``e9 rel32`` / ``eb rel8``   -- a near *jump* to local code.
* ``e8 rel32``                 -- a near *call* (only where calls are wanted).
* ``ff 25 disp32``             -- ``jmp qword [rip+disp32]`` import stub.
"""

from __future__ import annotations

import struct
from typing import Optional, Tuple

from .pe import PEFile


def _i8(b: bytes) -> int:
    return struct.unpack("<b", b)[0]


def _i32(b: bytes) -> int:
    return struct.unpack("<i", b)[0]


def follow_jump(pe: PEFile, rva: int) -> Tuple[Optional[str], Optional[int]]:
    """Classify a *jump* at ``rva``.

    Returns ``("rel", target_rva)`` for ``jmp rel8``/``rel32``,
    ``("import", iat_slot_rva)`` for ``jmp qword [rip+disp32]``, or
    ``(None, None)`` otherwise.  An ``e8`` *call* is deliberately not a jump.
    """
    b = pe.read_clamped(rva, 6)
    if len(b) >= 5 and b[0] == 0xE9:  # jmp rel32
        return "rel", rva + 5 + _i32(b[1:5])
    if len(b) >= 2 and b[0] == 0xEB:  # jmp rel8
        return "rel", rva + 2 + _i8(b[1:2])
    if len(b) >= 6 and b[0] == 0xFF and b[1] == 0x25:  # jmp qword [rip+disp32]
        return "import", rva + 6 + _i32(b[2:6])
    return None, None


def direct_call_or_jump(pe: PEFile, rva: int) -> Tuple[Optional[str], Optional[int]]:
    """Classify a *direct* call or jump at ``rva`` (for body scanning).

    Returns ``("rel", target_rva)`` for ``e8`` call / ``e9`` jmp rel32,
    ``("import", iat_slot_rva)`` for ``ff 25`` ``jmp [rip]``, else
    ``(None, None)``.
    """
    b = pe.read_clamped(rva, 6)
    if len(b) >= 5 and b[0] in (0xE8, 0xE9):  # call/jmp rel32
        return "rel", rva + 5 + _i32(b[1:5])
    if len(b) >= 6 and b[0] == 0xFF and b[1] == 0x25:  # jmp qword [rip+disp32]
        return "import", rva + 6 + _i32(b[2:6])
    return None, None
