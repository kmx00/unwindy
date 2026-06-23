"""Decode language-specific exception-handler data referenced by UNWIND_INFO.

When an ``UNWIND_INFO`` carries the ``EHANDLER``/``UHANDLER`` flag, the trailing
ULONG is the RVA of a *language-specific* handler routine and the bytes that
follow it (the "language-specific data", a.k.a. LSDA) describe how that routine
behaves.  This module identifies the handler routine -- following import thunks
and naming the well-known MSVC CRT handlers -- and decodes the payloads they
consume:

* ``__C_specific_handler``          -> a ``SCOPE_TABLE`` of
                                       ``__try``/``__except``/``__finally`` regions.
* ``__GSHandlerCheck``              -> ``GS_HANDLER_DATA`` (stack-cookie location).
* ``__GSHandlerCheck_SEH``          -> a scope table followed by GS data.
* ``__GSHandlerCheck_EH``/``_EH4``  -> a C++ ``FuncInfo`` RVA followed by GS data.
* ``__CxxFrameHandler``/``2``/``3`` -> MSVC C++ ``FuncInfo`` (the classic "FH3").
* ``__CxxFrameHandler4``            -> the compact "FH4" ``FuncInfo`` (header decoded).

Identification is deterministic (via the import table and one-hop thunk
following) and decoding is structurally validated against the owning function's
bounds, so it still works when the handler is statically linked and unnamed.
Anything that does not validate is reported as such -- never guessed.
"""

from __future__ import annotations

import bisect
import struct
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

from .errors import DiagnosticBag
from .pe import PEFile, PEFormatError
from .unwind import RuntimeFunction, UnwindInfo

# --- recognized CRT handler names -------------------------------------------

C_SCOPE_HANDLERS = frozenset(
    {"__C_specific_handler", "_C_specific_handler", "__C_specific_handler_noexcept"}
)
CXX_FH3_HANDLERS = frozenset(
    {"__CxxFrameHandler", "__CxxFrameHandler2", "__CxxFrameHandler3"}
)
CXX_FH4_HANDLERS = frozenset({"__CxxFrameHandler4"})
GS_PLAIN = "__GSHandlerCheck"
GS_SEH = "__GSHandlerCheck_SEH"
GS_EH_FH3 = "__GSHandlerCheck_EH"
GS_EH_FH4 = "__GSHandlerCheck_EH4"
RECOGNIZED_LANG_HANDLERS = C_SCOPE_HANDLERS | CXX_FH3_HANDLERS | CXX_FH4_HANDLERS

IMPORT_DIRECTORY_INDEX = 1

# magicNumber (low 29 bits) -> FH3 "version"; gates the optional trailing fields.
FH3_MAGICS = {0x19930520: 1, 0x19930521: 2, 0x19930522: 3}
MAGIC_MASK = 0x1FFFFFFF

MAX_SCOPE_RECORDS = 0x4000
MAX_TRY_BLOCKS = 0x4000
MAX_CATCHES = 0x1000

EXECUTE_HANDLER = 1  # SCOPE_TABLE HandlerAddress meaning EXCEPTION_EXECUTE_HANDLER


def _i32(b: bytes) -> int:
    return struct.unpack("<i", b)[0]


def _u32(b: bytes) -> int:
    return struct.unpack("<I", b)[0]


# --- decoded structures -----------------------------------------------------


@dataclass
class ScopeRecord:
    """One ``__try`` region from a ``__C_specific_handler`` scope table."""

    begin: int
    end: int
    handler: int  # __except filter RVA, 1 (EXECUTE_HANDLER), or __finally routine RVA
    target: int  # __except body RVA, 0 for __finally
    kind: str

    def to_dict(self) -> dict:
        return {
            "begin": self.begin,
            "end": self.end,
            "handler": self.handler,
            "target": self.target,
            "kind": self.kind,
        }


@dataclass
class GsData:
    """``GS_HANDLER_DATA`` -- locates the stack security cookie."""

    cookie_offset: int
    ehandler: bool
    uhandler: bool
    has_alignment: bool
    aligned_base_offset: Optional[int]
    alignment: Optional[int]
    size: int

    def to_dict(self) -> dict:
        return {
            "cookie_offset": self.cookie_offset,
            "ehandler": self.ehandler,
            "uhandler": self.uhandler,
            "has_alignment": self.has_alignment,
            "aligned_base_offset": self.aligned_base_offset,
            "alignment": self.alignment,
        }


@dataclass
class CxxCatch:
    """A ``HandlerType`` entry: one ``catch`` clause."""

    adjectives: int
    type_rva: int  # TypeDescriptor RVA, 0 == catch(...)
    catch_object_offset: int
    handler_rva: int  # catch funclet RVA
    frame_offset: int  # dispFrame (x64)

    def to_dict(self) -> dict:
        return {
            "adjectives": self.adjectives,
            "type_rva": self.type_rva,
            "catch_object_offset": self.catch_object_offset,
            "handler_rva": self.handler_rva,
            "frame_offset": self.frame_offset,
        }


@dataclass
class CxxTryBlock:
    """A ``TryBlockMapEntry``: a ``try`` and its ``catch`` clauses (by state)."""

    try_low: int
    try_high: int
    catch_high: int
    n_catches: int
    handler_array_rva: int
    catches: List[CxxCatch] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "try_low": self.try_low,
            "try_high": self.try_high,
            "catch_high": self.catch_high,
            "n_catches": self.n_catches,
            "handler_array_rva": self.handler_array_rva,
            "catches": [c.to_dict() for c in self.catches],
        }


@dataclass
class CxxFuncInfo:
    """MSVC C++ ``FuncInfo`` (FH3) for ``__CxxFrameHandler``/2/3."""

    funcinfo_rva: int
    magic: int  # raw magicNumber dword (with bbt bits)
    version: int  # 1/2/3, or 0 if the magic is unrecognized
    bbt_flags: int
    max_state: int
    unwind_map_rva: int
    try_block_map_rva: int
    n_try_blocks: int
    ip_to_state_map_rva: int
    n_ip_entries: int
    unwind_help_offset: int
    es_type_list_rva: int  # 0 unless magic >= 0x19930521
    eh_flags: int  # 0 unless magic >= 0x19930522
    try_blocks: List[CxxTryBlock] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "funcinfo_rva": self.funcinfo_rva,
            "magic": self.magic,
            "version": self.version,
            "bbt_flags": self.bbt_flags,
            "max_state": self.max_state,
            "unwind_map_rva": self.unwind_map_rva,
            "try_block_map_rva": self.try_block_map_rva,
            "n_try_blocks": self.n_try_blocks,
            "ip_to_state_map_rva": self.ip_to_state_map_rva,
            "n_ip_entries": self.n_ip_entries,
            "unwind_help_offset": self.unwind_help_offset,
            "es_type_list_rva": self.es_type_list_rva,
            "eh_flags": self.eh_flags,
            "try_blocks": [t.to_dict() for t in self.try_blocks],
        }


@dataclass
class Fh4Info:
    """The compact "FH4" ``FuncInfo`` header for ``__CxxFrameHandler4``.

    The full FH4 body is a variable-length, compressed-integer encoding of the
    state/IP maps; only the well-defined ``FuncInfoHeader`` byte is decoded here.
    """

    funcinfo_rva: int
    header: int
    is_catch: bool
    is_separated: bool
    bbt: bool
    has_unwind_map: bool
    has_try_block_map: bool
    has_ehs: bool
    no_except: bool

    def flag_names(self) -> List[str]:
        bits = [
            ("isCatch", self.is_catch),
            ("isSeparated", self.is_separated),
            ("BBT", self.bbt),
            ("UnwindMap", self.has_unwind_map),
            ("TryBlockMap", self.has_try_block_map),
            ("EHs", self.has_ehs),
            ("NoExcept", self.no_except),
        ]
        return [name for name, on in bits if on]

    def to_dict(self) -> dict:
        return {
            "funcinfo_rva": self.funcinfo_rva,
            "header": self.header,
            "flags": self.flag_names(),
        }


@dataclass
class HandlerData:
    """Everything decoded about one UNWIND_INFO's language-specific handler."""

    handler_rva: int
    routine_rva: int  # final routine after following thunks
    routine_name: Optional[str]  # recognized import name, if any
    dll: Optional[str]
    routine_section: str
    wraps: Optional[str]  # underlying handler when a local GS-check wrapper
    lsda_rva: int
    kind: str  # scope|gs|gs+scope|cxx3|cxx4|gs+cxx3|gs+cxx4|unknown
    scope_records: List[ScopeRecord] = field(default_factory=list)
    gs: Optional[GsData] = None
    cxx: Optional[CxxFuncInfo] = None
    fh4: Optional[Fh4Info] = None
    raw_head: bytes = b""
    notes: List[str] = field(default_factory=list)

    def routine_label(self) -> str:
        if self.routine_name:
            return self.routine_name
        if self.wraps:
            return f"GScheck->{self.wraps}"
        return f"local@{self.routine_rva:#x}"

    def tag(self) -> str:
        """Compact one-token label for the function table / list view."""
        n = len(self.scope_records)
        return {
            "scope": f"scope[{n}]",
            "gs+scope": f"gs+scope[{n}]",
            "cxx3": "cxx3",
            "cxx4": "cxx4",
            "gs+cxx3": "gs+cxx3",
            "gs+cxx4": "gs+cxx4",
            "gs": "gs",
        }.get(self.kind, "?")

    def to_dict(self) -> dict:
        return {
            "handler_rva": self.handler_rva,
            "routine_rva": self.routine_rva,
            "routine_name": self.routine_name,
            "dll": self.dll,
            "routine_section": self.routine_section,
            "wraps": self.wraps,
            "lsda_rva": self.lsda_rva,
            "kind": self.kind,
            "scopes": [s.to_dict() for s in self.scope_records],
            "gs": self.gs.to_dict() if self.gs else None,
            "cxx_funcinfo": self.cxx.to_dict() if self.cxx else None,
            "fh4": self.fh4.to_dict() if self.fh4 else None,
            "raw_head": self.raw_head.hex(),
            "notes": list(self.notes),
        }


# --- import-table resolution ------------------------------------------------


class ImportResolver:
    """Maps an IAT slot RVA to the ``(dll, symbol)`` it imports.

    Used to name handler routines reached through ``jmp [rip+disp]`` thunks. A
    malformed import table degrades to an empty map rather than raising."""

    def __init__(self, pe: PEFile) -> None:
        self.pe = pe
        self.slot_to_name: Dict[int, Tuple[str, str]] = {}
        self._build()

    def _build(self) -> None:
        pe = self.pe
        if IMPORT_DIRECTORY_INDEX >= len(pe.data_directories):
            return
        idir = pe.data_directories[IMPORT_DIRECTORY_INDEX]
        if not idir.present:
            return
        base = idir.virtual_address
        try:
            for i in range(0, 100000):
                desc = pe.read_at_rva(base + i * 20, 20)
                oft, _td, _fwd, name_rva, first_thunk = struct.unpack("<IIIII", desc)
                if oft == 0 and name_rva == 0 and first_thunk == 0:
                    break
                dll = pe.read_cstr(name_rva) if name_rva else "?"
                array = oft or first_thunk
                for j in range(0, 100000):
                    entry = struct.unpack("<Q", pe.read_at_rva(array + j * 8, 8))[0]
                    if entry == 0:
                        break
                    slot = first_thunk + j * 8
                    if entry & (1 << 63):
                        name = f"#{entry & 0xFFFF}"  # import by ordinal
                    else:
                        name = pe.read_cstr((entry & 0x7FFFFFFF) + 2)  # skip Hint
                    self.slot_to_name[slot] = (dll, name)
        except (PEFormatError, struct.error):
            # Best effort: keep whatever we resolved before the malformed entry.
            pass

    def name_at_slot(self, slot_rva: int) -> Optional[Tuple[str, str]]:
        return self.slot_to_name.get(slot_rva)


def _import_thunk_target(pe: PEFile, rva: int, resolver: ImportResolver):
    """If ``rva`` is a ``jmp/call qword [rip+disp]`` import thunk, return its
    ``(dll, name)``; otherwise ``None``."""
    b = pe.read_clamped(rva, 6)
    if len(b) >= 6 and b[0] == 0xFF and b[1] == 0x25:
        slot = rva + 6 + _i32(b[2:6])
        return resolver.name_at_slot(slot)
    return None


def resolve_routine(
    pe: PEFile, handler_rva: int, resolver: ImportResolver, *, extent_of=None, max_hops: int = 6
) -> Tuple[int, Optional[str], Optional[str], Optional[str]]:
    """Follow ``jmp rel32`` / ``jmp [rip]`` thunks from ``handler_rva``.

    Returns ``(routine_rva, name, dll, wraps)`` where ``name``/``dll`` come from
    the import table when the routine is an imported CRT handler, and ``wraps``
    names the underlying handler when the routine is a statically-linked
    ``__GSHandlerCheck_*`` cookie-check wrapper.
    """
    cur = handler_rva
    for _ in range(max_hops):
        b = pe.read_clamped(cur, 6)
        if len(b) >= 6 and b[0] == 0xFF and b[1] == 0x25:  # jmp qword [rip+disp]
            slot = cur + 6 + _i32(b[2:6])
            named = resolver.name_at_slot(slot)
            if named:
                return cur, named[1], named[0], None
            return cur, None, None, None
        if len(b) >= 5 and b[0] == 0xE9:  # jmp rel32
            cur = cur + 5 + _i32(b[1:5])
            continue
        break
    return cur, None, None, _scan_wrapper(pe, cur, resolver, extent_of)


def _scan_wrapper(
    pe: PEFile, rva: int, resolver: ImportResolver, extent_of=None
) -> Optional[str]:
    """A statically-linked ``__GSHandlerCheck_*`` routine checks the stack cookie
    then tail-calls the real language handler. Scan the routine body -- bounded
    to its own ``.pdata`` extent so the scan never bleeds into a neighbouring
    function -- for a direct ``call``/``jmp`` that lands (optionally through one
    import thunk) on a recognized handler, and return that handler's name."""
    if extent_of is None:
        return None
    ext = extent_of(rva)
    if ext is None:
        return None
    window = min(ext[1] - rva, 0x2000)
    body = pe.read_clamped(rva, window)
    n = len(body)
    i = 0
    while i + 6 <= n:
        op = body[i]
        if op in (0xE8, 0xE9):  # call/jmp rel32
            target = rva + i + 5 + _i32(body[i + 1 : i + 5])
            named = _import_thunk_target(pe, target, resolver)
            if named and named[1] in RECOGNIZED_LANG_HANDLERS:
                return named[1]
        elif op == 0xFF and body[i + 1] == 0x25:  # call/jmp qword [rip+disp]
            slot = rva + i + 6 + _i32(body[i + 2 : i + 6])
            named = resolver.name_at_slot(slot)
            if named and named[1] in RECOGNIZED_LANG_HANDLERS:
                return named[1]
        i += 1
    return None


# --- payload decoders -------------------------------------------------------


def _scope_kind(handler: int, target: int) -> str:
    if target == 0:
        return "finally"
    if handler == EXECUTE_HANDLER:
        return "except (EXECUTE_HANDLER)"
    return "except (filter)"


def decode_scope_table(
    pe: PEFile,
    table_rva: int,
    begin: int,
    end: int,
    bag: DiagnosticBag,
    where: str,
    *,
    classify: bool = False,
) -> Tuple[Optional[List[ScopeRecord]], int]:
    """Decode a ``SCOPE_TABLE`` (count + 4-DWORD records) at ``table_rva``.

    Returns ``(records, bytes_consumed)``. With ``classify`` the table must
    validate cleanly against ``[begin, end)`` or ``(None, 0)`` is returned (used
    to recognize statically-linked scope tables without a handler name). Without
    it the records are returned best-effort and anomalies are warned loudly.
    """
    head = pe.read_clamped(table_rva, 4)
    if len(head) < 4:
        return None, 0
    count = _u32(head)
    if count == 0 or count > MAX_SCOPE_RECORDS:
        if classify:
            return None, 0
        bag.warn(
            "handler.scope_count",
            f"scope-table count {count:#x} is out of range",
            where,
        )
        return [], 4
    need = count * 16
    blob = pe.read_clamped(table_rva + 4, need)
    if len(blob) < need:
        if classify:
            return None, 0
        bag.warn(
            "handler.scope_truncated",
            f"scope table claims {count} records but only "
            f"{len(blob) // 16} fit before the section ends",
            where,
        )
        count = len(blob) // 16
    consumed = 4 + count * 16
    records: List[ScopeRecord] = []
    for i in range(count):
        b, e, h, t = struct.unpack_from("<IIII", blob, i * 16)
        in_func = begin <= b < end and begin < e <= end
        ordered = b < e
        target_ok = t == 0 or begin <= t < end
        if classify and not (in_func and ordered and target_ok):
            return None, 0
        if not classify:
            if not ordered:
                bag.warn(
                    "handler.scope_range",
                    f"scope[{i}] begin {b:#x} >= end {e:#x}",
                    where,
                )
            if not in_func:
                bag.warn(
                    "handler.scope_oob",
                    f"scope[{i}] [{b:#x},{e:#x}) lies outside function "
                    f"[{begin:#x},{end:#x})",
                    where,
                )
            if not target_ok:
                bag.warn(
                    "handler.scope_target",
                    f"scope[{i}] jump target {t:#x} lies outside function "
                    f"[{begin:#x},{end:#x})",
                    where,
                )
        records.append(ScopeRecord(b, e, h, t, _scope_kind(h, t)))
    return records, consumed


def decode_gs_data(pe: PEFile, rva: int, bag: DiagnosticBag, where: str) -> GsData:
    """Decode ``GS_HANDLER_DATA``: a cookie offset whose low 3 bits flag
    EHandler/UHandler/HasAlignment, with two extra ints when aligned."""
    value = _u32(pe.read_at_rva(rva, 4))
    ehandler = bool(value & 1)
    uhandler = bool(value & 2)
    has_alignment = bool(value & 4)
    cookie_offset = value & ~7
    aligned_base = alignment = None
    size = 4
    if has_alignment:
        more = pe.read_at_rva(rva + 4, 8)
        aligned_base = _i32(more[0:4])
        alignment = _i32(more[4:8])
        size = 12
    return GsData(
        cookie_offset, ehandler, uhandler, has_alignment, aligned_base, alignment, size
    )


def decode_funcinfo3(
    pe: PEFile, fi_rva: int, bag: DiagnosticBag, where: str
) -> CxxFuncInfo:
    """Decode the fixed-layout MSVC C++ ``FuncInfo`` (FH3) and expand its
    try-block / catch maps."""
    head = pe.read_at_rva(fi_rva, 32)
    raw_magic = _u32(head[0:4])
    magic = raw_magic & MAGIC_MASK
    bbt_flags = (raw_magic >> 29) & 0x7
    version = FH3_MAGICS.get(magic, 0)
    if version == 0:
        bag.warn(
            "handler.cxx_magic",
            f"unexpected C++ FuncInfo magic {raw_magic:#x} at {fi_rva:#x}",
            where,
        )
    max_state = _i32(head[4:8])
    unwind_map_rva = _u32(head[8:12])
    n_try = _u32(head[12:16])
    try_map_rva = _u32(head[16:20])
    n_ip = _u32(head[20:24])
    ip_map_rva = _u32(head[24:28])
    unwind_help = _i32(head[28:32])
    es_type = eh_flags = 0
    off = fi_rva + 32
    if magic >= 0x19930521:
        es_type = _u32(pe.read_at_rva(off, 4))
        off += 4
    if magic >= 0x19930522:
        eh_flags = _i32(pe.read_at_rva(off, 4))
        off += 4

    info = CxxFuncInfo(
        funcinfo_rva=fi_rva,
        magic=raw_magic,
        version=version,
        bbt_flags=bbt_flags,
        max_state=max_state,
        unwind_map_rva=unwind_map_rva,
        try_block_map_rva=try_map_rva,
        n_try_blocks=n_try,
        ip_to_state_map_rva=ip_map_rva,
        n_ip_entries=n_ip,
        unwind_help_offset=unwind_help,
        es_type_list_rva=es_type,
        eh_flags=eh_flags,
    )

    if try_map_rva and 0 < n_try <= MAX_TRY_BLOCKS:
        for i in range(n_try):
            tl, th, ch, ncat, harr = struct.unpack(
                "<iiiII", pe.read_at_rva(try_map_rva + i * 20, 20)
            )
            block = CxxTryBlock(tl, th, ch, ncat, harr)
            if harr and 0 < ncat <= MAX_CATCHES:
                for j in range(ncat):
                    adj, dtype, dcatch, dhand, dframe = struct.unpack(
                        "<IIiII", pe.read_at_rva(harr + j * 20, 20)
                    )
                    block.catches.append(
                        CxxCatch(adj, dtype, dcatch, dhand, dframe)
                    )
            info.try_blocks.append(block)
    elif n_try > MAX_TRY_BLOCKS:
        bag.warn(
            "handler.cxx_trycount",
            f"C++ FuncInfo nTryBlocks {n_try:#x} is implausibly large",
            where,
        )
    return info


def decode_fh4(pe: PEFile, fi_rva: int, bag: DiagnosticBag, where: str) -> Fh4Info:
    """Decode the FH4 ``FuncInfoHeader`` byte. The reserved high bit must be 0."""
    header = pe.read_at_rva(fi_rva, 1)[0]
    if header & 0x80:
        bag.warn(
            "handler.fh4_header",
            f"FH4 FuncInfoHeader {header:#04x} has the reserved bit set",
            where,
        )
    return Fh4Info(
        funcinfo_rva=fi_rva,
        header=header,
        is_catch=bool(header & 0x01),
        is_separated=bool(header & 0x02),
        bbt=bool(header & 0x04),
        has_unwind_map=bool(header & 0x08),
        has_try_block_map=bool(header & 0x10),
        has_ehs=bool(header & 0x20),
        no_except=bool(header & 0x40),
    )


# --- dispatch ---------------------------------------------------------------


def _classify_structural(
    pe: PEFile,
    begin: int,
    end: int,
    lsda: int,
    hd: HandlerData,
    bag: DiagnosticBag,
    where: str,
) -> None:
    """Recognize the LSDA shape of an unnamed (statically-linked) handler."""
    records, _ = decode_scope_table(pe, lsda, begin, end, bag, where, classify=True)
    if records:
        hd.scope_records = records
        hd.kind = "scope"
        hd.notes.append("classified structurally as a scope table")
        return
    head = pe.read_clamped(lsda, 4)
    if len(head) < 4:
        hd.notes.append("language-specific data not recognized")
        return
    d0 = _u32(head)
    sec = pe.section_for_rva(d0) if d0 else None
    if sec is not None:
        magic_bytes = pe.read_clamped(d0, 4)
        magic = (_u32(magic_bytes) & MAGIC_MASK) if len(magic_bytes) == 4 else 0
        if magic in FH3_MAGICS:
            hd.cxx = decode_funcinfo3(pe, d0, bag, where)
            hd.kind = "cxx3"
            hd.notes.append("classified structurally via FuncInfo magic")
            return
        head_byte = pe.read_clamped(d0, 1)
        if not sec.is_executable and head_byte and not (head_byte[0] & 0x80):
            hd.fh4 = decode_fh4(pe, d0, bag, where)
            hd.kind = "cxx4"
            hd.notes.append("classified structurally as compact FH4 (tentative)")
            return
    hd.notes.append("language-specific data not recognized")


def _dispatch(
    pe: PEFile,
    begin: int,
    end: int,
    lsda: int,
    hd: HandlerData,
    bag: DiagnosticBag,
    where: str,
) -> None:
    name = hd.routine_name
    wraps = hd.wraps

    # Statically-linked GS-check wrapper: [FuncInfo RVA | scope table] + GS data.
    if wraps is not None:
        if wraps in CXX_FH4_HANDLERS:
            hd.fh4 = decode_fh4(pe, _u32(pe.read_at_rva(lsda, 4)), bag, where)
            hd.gs = decode_gs_data(pe, lsda + 4, bag, where)
            hd.kind = "gs+cxx4"
            return
        if wraps in CXX_FH3_HANDLERS:
            hd.cxx = decode_funcinfo3(pe, _u32(pe.read_at_rva(lsda, 4)), bag, where)
            hd.gs = decode_gs_data(pe, lsda + 4, bag, where)
            hd.kind = "gs+cxx3"
            return
        if wraps in C_SCOPE_HANDLERS:
            records, consumed = decode_scope_table(pe, lsda, begin, end, bag, where)
            hd.scope_records = records or []
            hd.gs = decode_gs_data(pe, lsda + consumed, bag, where)
            hd.kind = "gs+scope"
            return

    if name in C_SCOPE_HANDLERS:
        records, _ = decode_scope_table(pe, lsda, begin, end, bag, where)
        hd.scope_records = records or []
        hd.kind = "scope"
        return
    if name in CXX_FH4_HANDLERS:
        hd.fh4 = decode_fh4(pe, _u32(pe.read_at_rva(lsda, 4)), bag, where)
        hd.kind = "cxx4"
        return
    if name in CXX_FH3_HANDLERS:
        hd.cxx = decode_funcinfo3(pe, _u32(pe.read_at_rva(lsda, 4)), bag, where)
        hd.kind = "cxx3"
        return
    if name == GS_PLAIN:
        hd.gs = decode_gs_data(pe, lsda, bag, where)
        hd.kind = "gs"
        return
    if name == GS_SEH:
        records, consumed = decode_scope_table(pe, lsda, begin, end, bag, where)
        hd.scope_records = records or []
        hd.gs = decode_gs_data(pe, lsda + consumed, bag, where)
        hd.kind = "gs+scope"
        return
    if name == GS_EH_FH3:
        hd.cxx = decode_funcinfo3(pe, _u32(pe.read_at_rva(lsda, 4)), bag, where)
        hd.gs = decode_gs_data(pe, lsda + 4, bag, where)
        hd.kind = "gs+cxx3"
        return
    if name == GS_EH_FH4:
        hd.fh4 = decode_fh4(pe, _u32(pe.read_at_rva(lsda, 4)), bag, where)
        hd.gs = decode_gs_data(pe, lsda + 4, bag, where)
        hd.kind = "gs+cxx4"
        return

    _classify_structural(pe, begin, end, lsda, hd, bag, where)


def decode_handler_data(
    pe: PEFile,
    begin: int,
    end: int,
    ui: UnwindInfo,
    resolver: ImportResolver,
    bag: DiagnosticBag,
    where: str,
    *,
    extent_of=None,
    route_cache: Optional[Dict[int, Tuple[int, Optional[str], Optional[str], Optional[str]]]] = None,
) -> Optional[HandlerData]:
    """Identify and decode the language-specific handler of one ``UnwindInfo``."""
    handler_rva = ui.handler_rva
    lsda = ui.language_data_rva
    if handler_rva is None or lsda is None:
        return None
    if route_cache is not None and handler_rva in route_cache:
        routine_rva, name, dll, wraps = route_cache[handler_rva]
    else:
        routine_rva, name, dll, wraps = resolve_routine(
            pe, handler_rva, resolver, extent_of=extent_of
        )
        if route_cache is not None:
            route_cache[handler_rva] = (routine_rva, name, dll, wraps)
    hd = HandlerData(
        handler_rva=handler_rva,
        routine_rva=routine_rva,
        routine_name=name,
        dll=dll,
        routine_section=pe.section_name(routine_rva),
        wraps=wraps,
        lsda_rva=lsda,
        kind="unknown",
        raw_head=pe.read_clamped(lsda, 48),
    )
    try:
        _dispatch(pe, begin, end, lsda, hd, bag, where)
    except (PEFormatError, struct.error) as exc:
        bag.warn(
            "handler.decode_failed",
            f"failed to decode language-specific handler data: {exc}",
            where,
        )
        hd.notes.append(f"decode error: {exc}")
    return hd


def decode_handlers(
    pe: PEFile, functions: List[RuntimeFunction], bag: DiagnosticBag
) -> ImportResolver:
    """Decode handler data for every function (and each link in its unwind chain)
    that carries a handler, attaching results to the owning ``UnwindInfo``."""
    resolver = ImportResolver(pe)

    ranges = sorted(
        (f.begin_address, f.end_address)
        for f in functions
        if f.end_address > f.begin_address
    )
    begins = [r[0] for r in ranges]

    def extent_of(rva: int) -> Optional[Tuple[int, int]]:
        idx = bisect.bisect_right(begins, rva) - 1
        if 0 <= idx < len(ranges):
            b, e = ranges[idx]
            if b <= rva < e:
                return (b, e)
        return None

    route_cache: Dict[int, Tuple[int, Optional[str], Optional[str], Optional[str]]] = {}
    for f in functions:
        begin, end = f.begin_address, f.end_address
        ui: Optional[UnwindInfo] = f.unwind_info
        guard = 0
        while ui is not None and guard < 64:
            guard += 1
            if ui.handler_rva is not None and ui.language_data_rva is not None:
                ui.handler_data = decode_handler_data(
                    pe, begin, end, ui, resolver, bag, f"unwind@{ui.rva:#x}",
                    extent_of=extent_of, route_cache=route_cache,
                )
            child = ui.chained_function
            if child is not None:
                begin, end = child.begin_address, child.end_address
                ui = child.unwind_info
            else:
                ui = None
    return resolver
