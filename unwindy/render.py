"""Text rendering: ANSI-colored tables, summaries and rich per-function detail.

Pure standard library. Color auto-enables on a TTY (and is honored on modern
Windows terminals) and respects ``NO_COLOR``/``--no-color``.
"""

from __future__ import annotations

import os
import sys
from typing import Callable, List, Optional, Sequence

from .analyzer import Analysis
from .errors import Diagnostic, Severity
from .pe import PEFile
from .unwind import RuntimeFunction, UnwindInfo, UnwindOp
from .handlers import HandlerData


# --- color ------------------------------------------------------------------


class Painter:
    """Tiny ANSI helper. Padding must be applied *before* coloring so column
    widths stay correct (escape codes are zero-width)."""

    CODES = {
        "reset": "0",
        "bold": "1",
        "dim": "2",
        "red": "31",
        "green": "32",
        "yellow": "33",
        "blue": "34",
        "magenta": "35",
        "cyan": "36",
        "gray": "90",
        "brred": "91",
        "brgreen": "92",
        "bryellow": "93",
        "reverse": "7",
    }

    def __init__(self, enabled: bool) -> None:
        self.enabled = enabled

    def wrap(self, text: str, *names: str) -> str:
        if not self.enabled or not names:
            return text
        codes = ";".join(self.CODES[n] for n in names)
        return f"\x1b[{codes}m{text}\x1b[0m"

    def bold(self, t: str) -> str:
        return self.wrap(t, "bold")

    def dim(self, t: str) -> str:
        return self.wrap(t, "dim")

    def red(self, t: str) -> str:
        return self.wrap(t, "red")

    def green(self, t: str) -> str:
        return self.wrap(t, "green")

    def yellow(self, t: str) -> str:
        return self.wrap(t, "yellow")

    def cyan(self, t: str) -> str:
        return self.wrap(t, "cyan")

    def magenta(self, t: str) -> str:
        return self.wrap(t, "magenta")

    def gray(self, t: str) -> str:
        return self.wrap(t, "gray")

    def reverse(self, t: str) -> str:
        return self.wrap(t, "reverse")


def _enable_windows_vt() -> None:
    if os.name != "nt":
        return
    try:  # pragma: no cover - platform specific
        import ctypes

        kernel32 = ctypes.windll.kernel32
        handle = kernel32.GetStdHandle(-11)  # STD_OUTPUT_HANDLE
        mode = ctypes.c_uint32()
        if kernel32.GetConsoleMode(handle, ctypes.byref(mode)):
            kernel32.SetConsoleMode(handle, mode.value | 0x0004)
    except Exception:
        pass


def make_painter(force: Optional[bool] = None) -> Painter:
    if force is True:
        _enable_windows_vt()
        return Painter(True)
    if force is False:
        return Painter(False)
    enabled = (
        sys.stdout.isatty()
        and os.environ.get("NO_COLOR") is None
        and os.environ.get("TERM") != "dumb"
    )
    if enabled:
        _enable_windows_vt()
    return Painter(enabled)


# --- generic table ----------------------------------------------------------


def format_table(
    headers: Sequence[str],
    rows: Sequence[Sequence[object]],
    aligns: Optional[Sequence[str]] = None,
    painter: Optional[Painter] = None,
    col_color: Optional[Sequence[Optional[Callable[[str, object], str]]]] = None,
    gap: int = 2,
) -> str:
    cols = len(headers)
    aligns = list(aligns) if aligns else ["l"] * cols
    widths = [len(str(h)) for h in headers]
    str_rows = [[str(c) for c in r] for r in rows]
    for r in str_rows:
        for i in range(cols):
            widths[i] = max(widths[i], len(r[i]))

    sep = " " * gap

    def pad(s: str, w: int, a: str) -> str:
        return s.rjust(w) if a == "r" else s.ljust(w)

    out: List[str] = []
    hcells = [pad(str(headers[i]), widths[i], aligns[i]) for i in range(cols)]
    if painter:
        hcells = [painter.bold(painter.cyan(c)) for c in hcells]
    out.append(sep.join(hcells))
    rule = sep.join(
        (painter.dim("-" * widths[i]) if painter else "-" * widths[i])
        for i in range(cols)
    )
    out.append(rule)
    for ri, r in enumerate(str_rows):
        cells = [pad(r[i], widths[i], aligns[i]) for i in range(cols)]
        if col_color:
            for i in range(cols):
                fn = col_color[i] if i < len(col_color) else None
                if fn is not None:
                    cells[i] = fn(cells[i], rows[ri][i])
        out.append(sep.join(cells))
    return "\n".join(out)


# --- summaries --------------------------------------------------------------


def render_image_summary(analysis: Analysis, painter: Painter) -> str:
    pe = analysis.pe
    ed = analysis.exception_dir
    p = painter
    lines = [p.bold(p.cyan("Image"))]

    def kv(k: str, v: str) -> str:
        return f"  {p.gray(k + ':'):<28} {v}"

    src = pe.source or "<memory>"
    lines.append(kv("file", src))
    lines.append(kv("machine", "AMD64 (x64)"))
    lines.append(kv("type", "DLL" if pe.is_dll else "EXE/driver"))
    lines.append(kv("image base", f"{pe.image_base:#018x}"))
    lines.append(kv("entry point", f"rva {pe.address_of_entry_point:#x}"))
    lines.append(kv("size of image", f"{pe.size_of_image:#x}"))
    lines.append(kv("sections", str(pe.number_of_sections)))
    if ed.present:
        count = ed.size // 12
        lines.append(
            kv(
                "exception dir",
                f"rva {ed.virtual_address:#x} size {ed.size:#x} "
                f"({count} RUNTIME_FUNCTION)",
            )
        )
    else:
        lines.append(kv("exception dir", p.yellow("absent")))
    lines.append(kv("functions parsed", str(len(analysis.functions))))
    lines.append(
        kv(
            "chained / handlers",
            f"{analysis.chained_count} chained, {analysis.handler_count} handlers",
        )
    )
    return "\n".join(lines)


def render_sections(pe: PEFile, painter: Painter) -> str:
    headers = ["#", "name", "rva", "vsize", "raw", "rawsize", "perms"]
    rows = []
    for s in pe.sections:
        perms = "".join(
            [
                "r" if s.is_readable else "-",
                "w" if s.is_writable else "-",
                "x" if s.is_executable else "-",
            ]
        )
        rows.append(
            [
                s.index,
                s.name,
                f"{s.virtual_address:#x}",
                f"{s.virtual_size:#x}",
                f"{s.raw_ptr:#x}",
                f"{s.raw_size:#x}",
                perms,
            ]
        )
    aligns = ["r", "l", "r", "r", "r", "r", "l"]
    return format_table(headers, rows, aligns, painter)


def render_stats(analysis: Analysis, painter: Painter) -> str:
    p = painter
    out = [p.bold(p.cyan("Statistics"))]
    vh = analysis.version_histogram()
    out.append("  versions: " + ", ".join(f"v{k}={vh[k]}" for k in sorted(vh)))
    out.append(
        f"  chained: {analysis.chained_count}    handlers: {analysis.handler_count}"
    )
    hist = analysis.op_histogram()
    if hist:
        out.append(p.gray("  unwind operations:"))
        width = max(len(k) for k in hist)
        for op, cnt in sorted(hist.items(), key=lambda kv: (-kv[1], kv[0])):
            bar = "#" * min(40, cnt * 40 // max(hist.values()))
            out.append(f"    {op.ljust(width)}  {cnt:>6}  {p.dim(bar)}")
    return "\n".join(out)


# --- diagnostics ------------------------------------------------------------


def render_diagnostics(diags: Sequence[Diagnostic], painter: Painter) -> str:
    p = painter
    warns = [d for d in diags if d.severity == Severity.WARNING]
    errs = [d for d in diags if d.severity == Severity.ERROR]
    if not warns and not errs:
        return p.green("No warnings: exception data conforms to spec.")
    out: List[str] = []
    if errs:
        out.append(p.bold(p.red(f"ERRORS ({len(errs)})")))
        for d in errs:
            loc = p.gray(f" @ {d.where}") if d.where else ""
            out.append(f"  {p.red('x')} {p.bold(d.code)}: {d.message}{loc}")
    if warns:
        out.append(p.bold(p.yellow(f"WARNINGS ({len(warns)})")))
        for d in warns:
            loc = p.gray(f" @ {d.where}") if d.where else ""
            out.append(f"  {p.yellow('!')} {p.bold(d.code)}: {d.message}{loc}")
    return "\n".join(out)


# --- function table ---------------------------------------------------------

FUNC_COLUMNS = [
    "#", "begin", "end", "size", "prolog", "codes", "ops", "flags", "stack",
    "x-sect", "handler",
]


def addr_label(pe: PEFile, rva: int, *, use_va: bool) -> str:
    """Render an address as ``section:0xRVA`` (or VA when ``use_va``)."""
    name = pe.section_name(rva)
    value = pe.image_base + rva if use_va else rva
    return f"{name}:{value:#x}"


def func_section_info(pe: PEFile, f: RuntimeFunction):
    """Return ``(begin_section, end_section, crosses)``.

    The end section is taken from the function's *last* byte (``end - 1``) so a
    function that merely abuts the next section is not mis-flagged."""
    begin_sec = pe.section_name(f.begin_address)
    last = f.end_address - 1 if f.end_address > f.begin_address else f.begin_address
    end_sec = pe.section_name(last)
    return begin_sec, end_sec, begin_sec != end_sec


def xsect_label(pe: PEFile, f: RuntimeFunction) -> str:
    begin_sec, end_sec, crosses = func_section_info(pe, f)
    return f"{begin_sec}->{end_sec}" if crosses else "-"


def _flags_label(ui: Optional[UnwindInfo]) -> str:
    if ui is None:
        return "-"
    parts = []
    if ui.is_chained:
        parts.append("CHAIN")
    if ui.has_exception_handler:
        parts.append("EH")
    if ui.has_termination_handler:
        parts.append("UH")
    return "+".join(parts) if parts else "."


def unwind_summary(ui: Optional[UnwindInfo]) -> str:
    """Compact one-line digest of the prolog operations and sizes."""
    if ui is None:
        return "-"
    pushes = alloc = saves = xmms = 0
    fp = None
    mframe = False
    for c in ui.codes:
        op = c.op_enum
        if op is UnwindOp.PUSH_NONVOL:
            pushes += 1
        elif op in (UnwindOp.ALLOC_SMALL, UnwindOp.ALLOC_LARGE):
            alloc += c.alloc_size or 0
        elif op in (UnwindOp.SAVE_NONVOL, UnwindOp.SAVE_NONVOL_FAR):
            saves += 1
        elif op in (UnwindOp.SAVE_XMM128, UnwindOp.SAVE_XMM128_FAR):
            xmms += 1
        elif op is UnwindOp.SET_FPREG:
            fp = ui.frame_register_name
        elif op is UnwindOp.PUSH_MACHFRAME:
            mframe = True
    parts: List[str] = []
    if pushes:
        parts.append(f"{pushes}push")
    if alloc:
        parts.append(f"sub {alloc:#x}")
    if saves:
        parts.append(f"{saves}sav")
    if xmms:
        parts.append(f"{xmms}xmm")
    if fp:
        parts.append(f"fp:{fp}")
    if mframe:
        parts.append("mframe")
    return " ".join(parts) if parts else "."


def function_row(pe: PEFile, f: RuntimeFunction, *, use_va: bool) -> List[object]:
    ui = f.unwind_info
    handler = "-"
    if ui and ui.handler_data is not None:
        handler = ui.handler_data.tag()
    elif ui and ui.handler_rva:
        handler = addr_label(pe, ui.handler_rva, use_va=use_va)
    return [
        "-" if f.index is None else f.index,
        addr_label(pe, f.begin_address, use_va=use_va),
        addr_label(pe, f.end_address, use_va=use_va),
        f"{f.size:#x}",
        f"{ui.size_of_prolog:#x}" if ui else "-",
        ui.count_of_codes if ui else "-",
        unwind_summary(ui),
        _flags_label(ui),
        f"{ui.fixed_stack_alloc:#x}" if ui else "-",
        xsect_label(pe, f),
        handler,
    ]


def render_function_table(
    pe: PEFile,
    functions: Sequence[RuntimeFunction],
    painter: Painter,
    *,
    use_va: bool = False,
) -> str:
    p = painter

    def color_flags(padded: str, raw: object) -> str:
        s = str(raw)
        if "CHAIN" in s:
            return p.magenta(padded)
        if "EH" in s or "UH" in s:
            return p.yellow(padded)
        return p.dim(padded) if s == "." else padded

    def color_handler(padded: str, raw: object) -> str:
        return p.dim(padded) if str(raw) == "-" else p.yellow(padded)

    def color_xsect(padded: str, raw: object) -> str:
        return p.dim(padded) if str(raw) == "-" else p.red(padded)

    def color_ops(padded: str, raw: object) -> str:
        return p.dim(padded) if str(raw) in ("-", ".") else p.gray(padded)

    rows = [function_row(pe, f, use_va=use_va) for f in functions]
    #         #    begin end  size prol code ops        flags        stack xsect handler
    aligns = ["r", "l", "l", "r", "r", "r", "l", "l", "r", "l", "l"]
    col_color = [None, None, None, None, None, None, color_ops, color_flags,
                 None, color_xsect, color_handler]
    return format_table(FUNC_COLUMNS, rows, aligns, p, col_color)


# --- per-function detail ----------------------------------------------------

_OP_COLOR = {
    UnwindOp.PUSH_NONVOL: "green",
    UnwindOp.ALLOC_SMALL: "yellow",
    UnwindOp.ALLOC_LARGE: "yellow",
    UnwindOp.SET_FPREG: "magenta",
    UnwindOp.SAVE_NONVOL: "cyan",
    UnwindOp.SAVE_NONVOL_FAR: "cyan",
    UnwindOp.SAVE_XMM128: "blue",
    UnwindOp.SAVE_XMM128_FAR: "blue",
    UnwindOp.PUSH_MACHFRAME: "red",
}


def _render_handler_data(
    pe: PEFile, hd: HandlerData, p: Painter, indent: str, use_va: bool
) -> List[str]:
    """Render the decoded language-specific handler payload."""

    def a(rva: int) -> str:
        return addr_label(pe, rva, use_va=use_va)

    out: List[str] = []
    head = indent + p.gray(f"  language-specific data @ rva {hd.lsda_rva:#x}  kind={hd.kind}")
    if hd.dll:
        head += p.gray(f"  ({hd.routine_name} from {hd.dll})")
    elif hd.wraps:
        head += p.gray(f"  (GS cookie check wrapping {hd.wraps})")
    out.append(head)

    if hd.scope_records:
        out.append(indent + p.cyan(f"  scope table: {len(hd.scope_records)} region(s)"))
        for i, s in enumerate(hd.scope_records):
            if s.kind == "finally":
                desc = f"__finally  handler {a(s.handler)}"
            elif s.kind == "except (EXECUTE_HANDLER)":
                desc = f"__except (EXECUTE_HANDLER)  -> {a(s.target)}"
            else:
                desc = f"__except  filter {a(s.handler)}  -> {a(s.target)}"
            out.append(
                indent + f"    [{i}] try [{a(s.begin)}, {a(s.end)})  " + p.yellow(desc)
            )

    if hd.gs is not None:
        g = hd.gs
        flags = "+".join(
            n for n, on in (("EHANDLER", g.ehandler), ("UHANDLER", g.uhandler)) if on
        ) or "none"
        extra = (
            f"  aligned-base {g.aligned_base_offset:#x} align {g.alignment:#x}"
            if g.has_alignment
            else ""
        )
        out.append(
            indent
            + p.magenta("  GS cookie: ")
            + f"@ frame+{g.cookie_offset:#x}  flags {flags}{extra}"
        )

    if hd.cxx is not None:
        c = hd.cxx
        out.append(
            indent
            + p.green("  C++ FuncInfo ")
            + f"@ rva {c.funcinfo_rva:#x}  magic {c.magic:#x} (v{c.version})  "
            + f"maxState {c.max_state}  tryBlocks {c.n_try_blocks}"
        )
        for i, tb in enumerate(c.try_blocks):
            out.append(
                indent
                + f"    try[{i}] states [{tb.try_low}..{tb.try_high}] "
                + f"catchHigh {tb.catch_high}  {tb.n_catches} catch(es)"
            )
            for cat in tb.catches:
                tname = "catch(...)" if cat.type_rva == 0 else f"type {a(cat.type_rva)}"
                out.append(
                    indent
                    + f"      {tname}  -> handler {a(cat.handler_rva)}  "
                    + f"obj@frame+{cat.catch_object_offset:#x}"
                )

    if hd.fh4 is not None:
        f4 = hd.fh4
        names = ", ".join(f4.flag_names()) or "none"
        out.append(
            indent
            + p.green("  C++ FuncInfo (FH4) ")
            + f"@ rva {f4.funcinfo_rva:#x}  header {f4.header:#04x} [{names}]"
        )
        out.append(indent + p.dim("    compact FH4 layout; state/IP maps not expanded"))

    if hd.kind == "unknown":
        out.append(indent + p.dim(f"  unrecognized handler data; raw {hd.raw_head[:16].hex()}"))
    if hd.notes:
        out.append(indent + p.dim("  note: " + "; ".join(hd.notes)))
    return out


def _render_unwind_info(
    pe: PEFile, ui: UnwindInfo, painter: Painter, indent: str, use_va: bool
) -> List[str]:
    p = painter
    out: List[str] = []
    flags = " | ".join(ui.flag_names())
    out.append(
        indent
        + p.gray("UNWIND_INFO ")
        + f"@ rva {ui.rva:#x}  v{ui.version}  "
        + p.bold(flags)
    )
    frame = "none"
    if ui.frame_register:
        frame = f"{ui.frame_register_name} + {ui.frame_offset_bytes:#x}"
    out.append(
        indent
        + f"  prolog={ui.size_of_prolog:#x}  codes={ui.count_of_codes}  "
        + f"frame={frame}  fixed-alloc={ui.fixed_stack_alloc:#x}"
    )

    if ui.codes:
        out.append(indent + p.gray("  unwind codes (reverse-prolog / unwind order):"))
        for c in ui.codes:
            op = c.op_enum
            mn = c.mnemonic
            if op is not None and op in _OP_COLOR:
                mn = p.wrap(mn.ljust(20), _OP_COLOR[op])
            else:
                mn = mn.ljust(20)
            out.append(
                indent
                + f"    +{c.code_offset:#04x}  {mn}  {c.description}"
            )

    if ui.handler_rva is not None:
        hsec = pe.section_for_rva(ui.handler_rva)
        secname = hsec.name if hsec else "?"
        va = f" (va {pe.image_base + ui.handler_rva:#x})" if use_va else ""
        hd = ui.handler_data
        label = hd.routine_label() if hd is not None else (ui.handler_kind or "?")
        out.append(
            indent
            + p.yellow("  handler: ")
            + f"{label}  routine rva {ui.handler_rva:#x}{va} "
            + p.gray(f"[{secname}]")
        )
        if hd is not None:
            out.extend(_render_handler_data(pe, hd, p, indent + "  ", use_va))
        elif ui.language_data_rva is not None:
            out.append(
                indent
                + p.gray(f"  language-specific data rva {ui.language_data_rva:#x}")
            )

    if ui.chained_function is not None:
        child = ui.chained_function
        begin_lbl = addr_label(pe, child.begin_address, use_va=use_va)
        end_lbl = addr_label(pe, child.end_address, use_va=use_va)
        out.append(
            indent
            + p.magenta("  chained -> ")
            + f"[{begin_lbl}, {end_lbl}) "
            + p.gray(f"unwind@{child.unwind_info_address:#x}")
        )
        if child.unwind_info is not None:
            out.extend(
                _render_unwind_info(
                    pe, child.unwind_info, painter, indent + "    ", use_va
                )
            )
    return out


def render_function_detail(
    pe: PEFile, f: RuntimeFunction, painter: Painter, *, use_va: bool = False
) -> str:
    p = painter
    idx = "?" if f.index is None else f.index
    begin_lbl = addr_label(pe, f.begin_address, use_va=use_va)
    end_lbl = addr_label(pe, f.end_address, use_va=use_va)
    begin_sec, end_sec, crosses = func_section_info(pe, f)
    xsect = p.red(f"  CROSS-SECTION {begin_sec}->{end_sec}") if crosses else ""
    header = (
        p.bold(p.cyan(f"Function #{idx}"))
        + f"  [{begin_lbl}, {end_lbl})  "
        + p.gray(f"size={f.size:#x}  unwind@{f.unwind_info_address:#x}")
        + xsect
    )
    out = [header]
    if f.unwind_info is None:
        out.append("  " + p.red("<unwind info failed to parse>"))
        return "\n".join(out)
    out.extend(_render_unwind_info(pe, f.unwind_info, painter, "  ", use_va))
    return "\n".join(out)
