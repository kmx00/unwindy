"""Trace where a function's control flow forwards to, block by block.

Many compiler/linker artifacts begin a ``RUNTIME_FUNCTION`` at a short block
that, after a tiny prolog, jumps or tail-dispatches into another section
(incremental-link thunks, guard/ICF stubs, the packed ``.grfn*`` forwarders in
some images).  Such a function is *not* a start trampoline -- its first
instruction is real code, not a lone ``jmp`` -- so :mod:`unwindy.trampolines`
never peels it.

``trace_flow`` decodes each basic block, follows the block's *primary* outgoing
edge, and stops at the first real destination::

    .text:0x1020  ->  .grfn10:0x135e0e8  ->  .grfn10:0x135d340

The primary edge is a direct ``jmp`` target, or -- for the ``call X; jmp reg``
tail-dispatch pattern -- the ``call`` target ``X`` (where execution actually
goes).  ``call`` does not end a block (control returns); only ``jmp``/``jcc``/
``ret``/``int``/invalid do.  The walk stops when it reaches another function's
known begin (a jumpable destination), an import thunk, an indirect branch it
cannot follow, a ``ret``, a cycle, or the hop limit.

Disassembly uses iced-x86 -- the project's one decoding dependency.  It is
imported lazily so the pure-stdlib PE/unwind core still imports without it;
when it is missing, :func:`trace_flow` returns a trace whose ``stop`` is
``"no-iced"`` and the UI degrades gracefully.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple

from .pe import PEFile

try:  # the one allowed third-party dep, used only for disassembly
    import iced_x86 as _iced
except Exception:  # pragma: no cover - exercised only where the wheel is absent
    _iced = None

MAX_FLOW_HOPS = 24
MAX_BLOCK_INSNS = 64
MAX_INSN_LEN = 15  # x64 instructions are at most 15 bytes


def iced_available() -> bool:
    """True when iced-x86 is importable and flow tracing is possible."""
    return _iced is not None


# --- model ------------------------------------------------------------------


@dataclass
class FlowInsn:
    """One decoded instruction inside a traced block."""

    rva: int
    length: int
    raw: bytes
    text: str  # iced Intel-syntax rendering, e.g. "jmp 0x135e0e8"
    kind: str  # 'seq'|'call'|'icall'|'jmp'|'jcc'|'ijmp'|'ret'|'int'|'bad'
    target: Optional[int] = None  # direct branch/call target RVA
    import_slot: Optional[int] = None  # IAT slot RVA for a [rip] jmp/call
    import_name: Optional[str] = None  # "dll!symbol" if the slot resolved


@dataclass
class FlowHop:
    """A basic block visited while tracing."""

    start: int
    section: str
    insns: List[FlowInsn]
    func_index: Optional[int]  # pdata index when 'start' is a known begin
    edge: str = ""  # 'jmp'|'call' -- how the trace leaves to the next hop
    edge_target: Optional[int] = None  # the followed successor RVA


@dataclass
class FlowTrace:
    """The forwarding chain rooted at a function's begin."""

    begin: int
    hops: List[FlowHop]
    stop: str
    crosses_section: bool = False
    import_slot: Optional[int] = None
    import_name: Optional[str] = None

    @property
    def chain(self) -> List[int]:
        """Block-start RVAs in flow order (the arrow chain)."""
        return [h.start for h in self.hops]

    @property
    def forwards(self) -> bool:
        """True when control leaves the first block (more than one hop)."""
        return len(self.hops) > 1

    @property
    def destination(self) -> Optional[FlowHop]:
        """The final hop reached, if the trace got anywhere."""
        return self.hops[-1] if self.hops else None


# --- decoding ---------------------------------------------------------------

# iced FlowControl -> our coarse instruction kind (built once, when iced is
# present).  Block decode stops after a terminator kind; calls do not end a block.
if _iced is not None:
    _FC = _iced.FlowControl
    _KIND: Dict[int, str] = {
        _FC.NEXT: "seq",
        _FC.CALL: "call",
        _FC.INDIRECT_CALL: "icall",
        _FC.UNCONDITIONAL_BRANCH: "jmp",
        _FC.CONDITIONAL_BRANCH: "jcc",
        _FC.INDIRECT_BRANCH: "ijmp",
        _FC.RETURN: "ret",
        _FC.INTERRUPT: "int",
        _FC.EXCEPTION: "bad",
    }
else:  # pragma: no cover - exercised only where the wheel is absent
    _KIND = {}
_TERMINATORS = frozenset({"jmp", "jcc", "ijmp", "ret", "int", "bad"})

_FORMATTER = None


def _formatter():
    global _FORMATTER
    if _FORMATTER is None:
        f = _iced.Formatter(_iced.FormatterSyntax.INTEL)
        f.leading_zeros = False
        f.branch_leading_zeros = False
        f.uppercase_hex = False
        f.hex_prefix = "0x"
        f.hex_suffix = ""
        f.space_after_operand_separator = True
        _FORMATTER = f
    return _FORMATTER


def _decode_block(
    pe: PEFile, start: int, resolver, max_insns: int
) -> Optional[List[FlowInsn]]:
    """Linearly decode the block at ``start`` up to its first terminator.

    Returns ``None`` when ``start`` is not backed by readable bytes."""
    data = pe.read_clamped(start, max_insns * MAX_INSN_LEN)
    if not data:
        return None
    fmt = _formatter()
    rip_reg = _iced.Register.RIP
    dec = _iced.Decoder(64, data, ip=start)
    out: List[FlowInsn] = []
    for ins in dec:
        off = ins.ip - start
        raw = data[off : off + ins.len]
        if ins.is_invalid:
            out.append(FlowInsn(ins.ip, max(ins.len, 1), raw, "(bad)", "bad"))
            break
        kind = _KIND.get(ins.flow_control, "bad")
        fi = FlowInsn(ins.ip, ins.len, raw, fmt.format(ins), kind)
        if kind in ("jmp", "jcc", "call"):
            fi.target = ins.near_branch_target
        elif kind in ("ijmp", "icall") and ins.memory_base == rip_reg:
            fi.import_slot = ins.memory_displacement
            if resolver is not None:
                nm = resolver.name_at_slot(fi.import_slot)
                if nm is not None:
                    fi.import_name = f"{nm[0]}!{nm[1]}"
        out.append(fi)
        if kind in _TERMINATORS or len(out) >= max_insns:
            break
    return out


def _last_direct_call(insns: List[FlowInsn]) -> Optional[int]:
    for fi in reversed(insns):
        if fi.kind == "call" and fi.target is not None:
            return fi.target
    return None


def trace_flow(
    pe: PEFile,
    begin: int,
    begins: Dict[int, Optional[int]],
    resolver=None,
    *,
    max_hops: int = MAX_FLOW_HOPS,
    max_insns: int = MAX_BLOCK_INSNS,
) -> FlowTrace:
    """Trace the forwarding chain starting at ``begin``.

    ``begins`` maps a function begin RVA to its ``.pdata`` index; a hop landing
    on one (other than the start) is a real destination and ends the trace.
    ``resolver`` (an :class:`~unwindy.handlers.ImportResolver`) names IAT slots
    reached through ``jmp/call [rip]`` thunks.
    """
    if _iced is None:
        return FlowTrace(begin, [], "no-iced")
    hops: List[FlowHop] = []
    visited = set()
    seg0 = pe.section_name(begin)
    crosses = False
    cur = begin
    stop = "fallthrough"
    imp_slot: Optional[int] = None
    imp_name: Optional[str] = None

    for _ in range(max_hops):
        if cur in visited:
            stop = "cycle"
            break
        visited.add(cur)

        insns = _decode_block(pe, cur, resolver, max_insns)
        if not insns:
            stop = "unmapped"
            break

        sec = pe.section_name(cur)
        if sec != seg0:
            crosses = True
        fidx = begins.get(cur)
        hop = FlowHop(cur, sec, insns, fidx)
        hops.append(hop)

        # Reaching another function's begin is a real, jumpable destination.
        if cur != begin and fidx is not None:
            stop = "known-begin"
            break

        term = insns[-1]
        nxt: Optional[int] = None
        if term.kind == "jmp" and term.target is not None:
            nxt = term.target
            hop.edge = "jmp"
        elif term.kind == "ijmp":
            if term.import_slot is not None:  # jmp [rip] import stub
                imp_slot, imp_name = term.import_slot, term.import_name
                stop = "import"
                break
            # tail-dispatch: `call resolver; jmp reg` -> follow the resolver.
            callt = _last_direct_call(insns)
            if callt is not None:
                nxt = callt
                hop.edge = "call"
            else:
                stop = "indirect"
                break
        elif term.kind == "jcc":
            stop = "conditional"
            break
        elif term.kind == "ret":
            stop = "ret"
            break
        elif term.kind == "int":
            stop = "int"
            break
        elif term.kind == "bad":
            stop = "bad"
            break
        else:  # ran past max_insns without a terminator: ordinary body
            stop = "fallthrough"
            break

        if nxt is None or pe.section_for_rva(nxt) is None:
            hop.edge = ""
            stop = "unmapped"
            break
        hop.edge_target = nxt
        cur = nxt
    else:
        stop = "limit"

    return FlowTrace(begin, hops, stop, crosses, imp_slot, imp_name)
