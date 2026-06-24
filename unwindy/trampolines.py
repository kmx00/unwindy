"""Peel function-start trampolines down to the real entry point.

Some ``RUNTIME_FUNCTION``s begin at a *trampoline*: a lone ``jmp`` that forwards
to the actual function body.  These show up as incremental-link thunks, ICF /
identical-COMDAT folding stubs, guard/retpoline stubs, tail-call-only wrappers,
and import stubs.  When the real body lives in a different section ("segment"),
that jump is exactly where execution crosses the boundary.

``peel_start`` follows the ``jmp`` chain (``e9``/``eb`` near jumps, ``ff 25``
``jmp [rip]`` import stubs) to the real start, records any segment transition,
and links to the real start's own ``RUNTIME_FUNCTION`` when there is one.  Only
the unambiguous trampoline encodings are followed; an intra-function jump (a jump
that stays inside the function's own ``[begin, end)``) is ordinary control flow
and is never treated as a trampoline.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple

from .handlers import ImportResolver
from .pe import PEFile
from .unwind import RuntimeFunction

MAX_TRAMPOLINE_HOPS = 16


def _i8(b: bytes) -> int:
    return struct.unpack("<b", b)[0]


def _i32(b: bytes) -> int:
    return struct.unpack("<i", b)[0]


@dataclass
class StartTrampoline:
    """A function start that forwards through one or more ``jmp`` stubs."""

    begin: int
    chain: List[int]  # [begin, hop1, ...]; last entry is the local landing site
    real_start: int  # final local RVA reached (== last jmp site for imports)
    kind: str  # 'local' | 'import'
    import_slot: Optional[int] = None  # IAT slot RVA for 'import'
    import_target: Optional[Tuple[str, str]] = None  # (dll, symbol) if resolved
    crosses_segment: bool = False
    transition_rva: Optional[int] = None  # first hop landing in another section
    real_start_index: Optional[int] = None  # pdata index of the real start, if any

    @property
    def hops(self) -> int:
        return max(0, len(self.chain) - 1)

    def import_name(self) -> Optional[str]:
        if self.import_target is None:
            return None
        return f"{self.import_target[0]}!{self.import_target[1]}"

    def to_dict(self) -> dict:
        return {
            "begin": self.begin,
            "kind": self.kind,
            "chain": list(self.chain),
            "real_start": self.real_start,
            "real_start_index": self.real_start_index,
            "import_slot": self.import_slot,
            "import": self.import_name(),
            "crosses_segment": self.crosses_segment,
            "transition_rva": self.transition_rva,
        }


def _jmp_target(pe: PEFile, rva: int) -> Tuple[Optional[str], Optional[int]]:
    """Classify the instruction at ``rva`` as a followable jump.

    Returns ``('local', target_rva)`` for ``jmp rel8/rel32``, ``('import',
    iat_slot_rva)`` for ``jmp qword [rip+disp]``, or ``(None, None)`` otherwise.
    """
    b = pe.read_clamped(rva, 6)
    if len(b) >= 5 and b[0] == 0xE9:  # jmp rel32
        return "local", rva + 5 + _i32(b[1:5])
    if len(b) >= 2 and b[0] == 0xEB:  # jmp rel8
        return "local", rva + 2 + _i8(b[1:2])
    if len(b) >= 6 and b[0] == 0xFF and b[1] == 0x25:  # jmp qword [rip+disp]
        return "import", rva + 6 + _i32(b[2:6])
    return None, None


def peel_start(
    pe: PEFile,
    func: RuntimeFunction,
    resolver: ImportResolver,
    begins: Dict[int, Optional[int]],
) -> Optional[StartTrampoline]:
    """Return the trampoline for ``func`` if its start forwards elsewhere."""
    begin = func.begin_address
    kind0, target0 = _jmp_target(pe, begin)
    if kind0 is None:
        return None
    # A jump that stays inside the function is ordinary control flow.
    if kind0 == "local" and func.begin_address <= target0 < func.end_address:
        return None

    seg0 = pe.section_name(begin)

    if kind0 == "import":
        return StartTrampoline(
            begin=begin,
            chain=[begin],
            real_start=begin,
            kind="import",
            import_slot=target0,
            import_target=resolver.name_at_slot(target0),
        )

    chain = [begin]
    seen = {begin}
    transition: Optional[int] = None
    cur = begin
    for _ in range(MAX_TRAMPOLINE_HOPS):
        kind, target = _jmp_target(pe, cur)
        if kind == "import":  # chain ends at an import stub
            return StartTrampoline(
                begin=begin,
                chain=chain,
                real_start=cur,
                kind="import",
                import_slot=target,
                import_target=resolver.name_at_slot(target),
                crosses_segment=transition is not None,
                transition_rva=transition,
            )
        if kind != "local":
            break
        if target in seen or pe.section_for_rva(target) is None:
            break
        chain.append(target)
        seen.add(target)
        if transition is None and pe.section_name(target) != seg0:
            transition = target
        cur = target
        if target in begins:  # reached a real RUNTIME_FUNCTION entry
            break

    real = chain[-1]
    return StartTrampoline(
        begin=begin,
        chain=chain,
        real_start=real,
        kind="local",
        crosses_segment=transition is not None,
        transition_rva=transition,
        real_start_index=begins.get(real),
    )


def annotate_trampolines(
    pe: PEFile, functions: List[RuntimeFunction], resolver: ImportResolver
) -> None:
    """Attach a :class:`StartTrampoline` to every function whose start forwards."""
    begins: Dict[int, Optional[int]] = {f.begin_address: f.index for f in functions}
    for f in functions:
        f.trampoline = peel_start(pe, f, resolver, begins)
