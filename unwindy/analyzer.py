"""High-level analysis: enumerate ``.pdata``, resolve unwind info, and collect
loud warnings about anything suspicious at the directory/section level.
"""

from __future__ import annotations

import struct
from collections import Counter
from dataclasses import dataclass, field
from typing import List, Optional

from .errors import DiagnosticBag, UnwindFormatError
from .pe import DataDirectory, PEFile
from .unwind import RuntimeFunction, UnwindInfo, parse_unwind_info

RUNTIME_FUNCTION_SIZE = 12


@dataclass
class Analysis:
    pe: PEFile
    exception_dir: DataDirectory
    functions: List[RuntimeFunction] = field(default_factory=list)
    diagnostics: DiagnosticBag = field(default_factory=DiagnosticBag)
    strict: bool = True

    # -- aggregate statistics -------------------------------------------------

    @property
    def chained_count(self) -> int:
        return sum(
            1 for f in self.functions if f.unwind_info and f.unwind_info.is_chained
        )

    @property
    def handler_count(self) -> int:
        return sum(
            1 for f in self.functions if f.unwind_info and f.unwind_info.has_handler
        )

    def op_histogram(self) -> Counter:
        """Per-op tally over each function's own unwind codes.

        Chained parents are independent ``.pdata`` entries counted on their own,
        so the chain is not walked here (that would double-count)."""
        hist: Counter = Counter()
        for f in self.functions:
            if f.unwind_info is None:
                continue
            for c in f.unwind_info.codes:
                op = c.op_enum
                hist[op.uwop_name if op is not None else f"UWOP_{c.op:#x}?"] += 1
        return hist

    def version_histogram(self) -> Counter:
        hist: Counter = Counter()
        for f in self.functions:
            if f.unwind_info:
                hist[f.unwind_info.version] += 1
        return hist

    @staticmethod
    def _walk_unwind(ui: Optional[UnwindInfo]):
        while ui is not None:
            yield ui
            ui = ui.chained_function.unwind_info if ui.chained_function else None


def analyze(pe: PEFile, *, strict: bool = True) -> Analysis:
    """Parse every ``RUNTIME_FUNCTION`` and its unwind chain.

    In ``strict`` mode (default) spec violations raise; otherwise they become
    loud ``ERROR`` diagnostics and parsing continues.
    """
    bag = DiagnosticBag()
    ed = pe.exception_directory
    analysis = Analysis(pe=pe, exception_dir=ed, diagnostics=bag, strict=strict)

    if not ed.present:
        bag.info(
            "pdata.absent",
            "image has no exception directory; there is no x64 unwind data",
        )
        return analysis

    sec = pe.section_for_rva(ed.virtual_address)
    if sec is None:
        _fail(
            bag,
            strict,
            "pdata.unmapped",
            f"exception directory RVA {ed.virtual_address:#x} is not mapped by "
            f"any section",
        )
    else:
        if sec.name != ".pdata":
            bag.warn(
                "pdata.section",
                f"exception directory lives in section {sec.name!r}, "
                f"not the conventional '.pdata'",
            )
        if sec.is_executable or sec.is_writable:
            bag.warn(
                "pdata.section_perms",
                f"exception directory section {sec.name!r} is "
                f"{'executable' if sec.is_executable else ''}"
                f"{'/writable' if sec.is_writable else ''}; expected read-only",
            )

    if ed.size % RUNTIME_FUNCTION_SIZE:
        bag.warn(
            "pdata.size_misaligned",
            f"exception directory size {ed.size:#x} is not a multiple of "
            f"{RUNTIME_FUNCTION_SIZE} (RUNTIME_FUNCTION); trailing bytes ignored",
        )

    count = ed.size // RUNTIME_FUNCTION_SIZE
    raw = pe.read_at_rva(ed.virtual_address, count * RUNTIME_FUNCTION_SIZE)

    prev_begin = -1
    for i in range(count):
        begin, end, uia = struct.unpack_from("<III", raw, i * RUNTIME_FUNCTION_SIZE)
        where = f"pdata[{i}]"

        if begin == 0 and end == 0 and uia == 0:
            bag.warn("pdata.null_entry", "all-zero RUNTIME_FUNCTION entry", where)
            continue

        rf = RuntimeFunction(
            begin_address=begin,
            end_address=end,
            unwind_info_address=uia,
            index=i,
        )

        if begin < prev_begin:
            bag.warn(
                "pdata.unsorted",
                f"BeginAddress {begin:#x} < previous {prev_begin:#x}; .pdata "
                f"must be sorted ascending for the OS binary search",
                where,
            )
        prev_begin = begin

        if end <= begin:
            _fail(
                bag,
                strict,
                "pdata.bad_range",
                f"BeginAddress {begin:#x} >= EndAddress {end:#x}",
                where,
            )

        bsec = pe.section_for_rva(begin)
        if bsec is None:
            bag.warn(
                "pdata.begin_unmapped",
                f"function BeginAddress {begin:#x} is not mapped by any section",
                where,
            )
        elif not bsec.is_executable:
            bag.warn(
                "pdata.begin_not_exec",
                f"function begins in non-executable section {bsec.name!r}",
                where,
            )
        if bsec is not None and end > begin and not bsec.contains_rva(end - 1):
            bag.warn(
                "pdata.span_crosses_section",
                f"function [{begin:#x},{end:#x}) extends past section "
                f"{bsec.name!r}",
                where,
            )

        usec = pe.section_for_rva(uia)
        if usec is None:
            bag.warn(
                "pdata.unwind_unmapped",
                f"UnwindInfoAddress {uia:#x} is not mapped by any section",
                where,
            )
        elif usec.is_executable:
            bag.warn(
                "pdata.unwind_in_code",
                f"UNWIND_INFO at {uia:#x} lives in executable section "
                f"{usec.name!r}",
                where,
            )

        try:
            rf.unwind_info = parse_unwind_info(pe, uia, bag)
        except UnwindFormatError as exc:
            if strict:
                raise
            bag.error("unwind.parse_failed", str(exc), where)

        analysis.functions.append(rf)

    _check_overlaps(analysis.functions, bag)
    _check_handlers_mapped(pe, analysis.functions, bag)
    return analysis


def _fail(
    bag: DiagnosticBag,
    strict: bool,
    code: str,
    message: str,
    where: Optional[str] = None,
) -> None:
    if strict:
        loc = f"{where}: " if where else ""
        raise UnwindFormatError(f"{loc}{message}")
    bag.error(code, message, where)


def _check_overlaps(functions: List[RuntimeFunction], bag: DiagnosticBag) -> None:
    valid = [f for f in functions if f.end_address > f.begin_address]
    ordered = sorted(valid, key=lambda f: f.begin_address)
    for prev, cur in zip(ordered, ordered[1:]):
        if cur.begin_address < prev.end_address:
            bag.warn(
                "pdata.overlap",
                f"function [{cur.begin_address:#x},{cur.end_address:#x}) overlaps "
                f"[{prev.begin_address:#x},{prev.end_address:#x})",
                f"pdata[{cur.index}]",
            )


def _check_handlers_mapped(
    pe: PEFile, functions: List[RuntimeFunction], bag: DiagnosticBag
) -> None:
    for f in functions:
        ui = f.unwind_info
        if ui is not None and ui.handler_rva:
            hsec = pe.section_for_rva(ui.handler_rva)
            if hsec is None:
                bag.warn(
                    "unwind.handler_unmapped",
                    f"handler RVA {ui.handler_rva:#x} is not mapped by any "
                    f"section",
                    f"unwind@{ui.rva:#x}",
                )
            elif not hsec.is_executable:
                bag.warn(
                    "unwind.handler_not_exec",
                    f"handler RVA {ui.handler_rva:#x} points into "
                    f"non-executable section {hsec.name!r}",
                    f"unwind@{ui.rva:#x}",
                )
