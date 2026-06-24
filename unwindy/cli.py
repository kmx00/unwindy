"""Command-line front end for unwindy."""

from __future__ import annotations

import argparse
import json
import os
import sys
from typing import List, Optional, Sequence

from . import __version__
from .analyzer import Analysis, analyze
from .errors import PEFormatError, UnwindyError
from .pe import PEFile
from .render import (
    make_painter,
    render_diagnostics,
    render_function_detail,
    render_function_table,
    render_image_summary,
    render_sections,
    render_stats,
)
from .unwind import RuntimeFunction, UnwindInfo

SORT_KEYS = {
    "index": lambda f: (f.index if f.index is not None else -1),
    "begin": lambda f: f.begin_address,
    "end": lambda f: f.end_address,
    "size": lambda f: f.size,
    "prolog": lambda f: (f.unwind_info.size_of_prolog if f.unwind_info else -1),
    "codes": lambda f: (f.unwind_info.count_of_codes if f.unwind_info else -1),
    "alloc": lambda f: (f.unwind_info.fixed_stack_alloc if f.unwind_info else -1),
    "handler": lambda f: (1 if f.unwind_info and f.unwind_info.has_handler else 0),
    "chained": lambda f: (1 if f.unwind_info and f.unwind_info.is_chained else 0),
}


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="unwindy",
        description="View x64 (PE64) exception/unwind information in rich detail.",
    )
    p.add_argument(
        "path",
        nargs="*",
        help="one or more PE64 images, or directories scanned for *.bin",
    )
    p.add_argument("--version", action="version", version=f"unwindy {__version__}")

    view = p.add_argument_group("views")
    view.add_argument(
        "-d", "--detail", nargs="*", metavar="IDX", default=None,
        help="show full per-function detail (all, or only the given .pdata indices)",
    )
    view.add_argument("-t", "--table", action="store_true", help="function table (default)")
    view.add_argument("-S", "--sections", action="store_true", help="show section table")
    view.add_argument("-s", "--stats", action="store_true", help="show statistics")
    view.add_argument("--summary-only", action="store_true", help="image summary only")
    view.add_argument("--json", action="store_true", help="emit machine-readable JSON")
    tui = view.add_mutually_exclusive_group()
    tui.add_argument(
        "-i", "--tui", dest="tui", action="store_true", default=None,
        help="interactive scrollable terminal UI (default when run in a TTY)",
    )
    tui.add_argument(
        "--no-tui", dest="tui", action="store_false",
        help="never launch the interactive UI; print to stdout instead",
    )

    filt = p.add_argument_group("filtering / sorting")
    filt.add_argument("--sort", choices=sorted(SORT_KEYS), default="index")
    filt.add_argument("-r", "--reverse", action="store_true", help="reverse sort order")
    filt.add_argument("--limit", type=int, default=None, help="cap rows/detail shown")
    filt.add_argument("--only-handlers", action="store_true", help="only functions with a handler")
    filt.add_argument("--only-chained", action="store_true", help="only chained functions")
    filt.add_argument("--min-size", type=lambda s: int(s, 0), default=None, help="minimum function size")
    filt.add_argument("--has-op", metavar="UWOP", default=None, help="only functions using this UWOP (e.g. SET_FPREG)")

    out = p.add_argument_group("output")
    out.add_argument("--va", action="store_true", help="show virtual addresses (image base + rva)")
    color = out.add_mutually_exclusive_group()
    color.add_argument("--color", dest="color", action="store_true", default=None)
    color.add_argument("--no-color", dest="color", action="store_false")
    out.add_argument("-q", "--quiet", action="store_true", help="suppress the image summary header")
    out.add_argument("--lenient", action="store_true", help="downgrade spec violations to errors instead of raising")
    out.add_argument("--fail-on-warn", action="store_true", help="exit non-zero if any warning/error was reported")
    return p


def _matches(f: RuntimeFunction, args: argparse.Namespace) -> bool:
    ui = f.unwind_info
    if args.only_handlers and not (ui and ui.has_handler):
        return False
    if args.only_chained and not (ui and ui.is_chained):
        return False
    if args.min_size is not None and f.size < args.min_size:
        return False
    if args.has_op:
        want = args.has_op.upper()
        if not want.startswith("UWOP_"):
            want = "UWOP_" + want
        found = False
        for level in Analysis._walk_unwind(ui):
            for c in level.codes:
                op = c.op_enum
                if op is not None and op.uwop_name == want:
                    found = True
                    break
            if found:
                break
        if not found:
            return False
    return True


def select_functions(
    analysis: Analysis, args: argparse.Namespace
) -> List[RuntimeFunction]:
    funcs = [f for f in analysis.functions if _matches(f, args)]
    funcs.sort(key=SORT_KEYS[args.sort], reverse=args.reverse)
    if args.limit is not None:
        funcs = funcs[: args.limit]
    return funcs


# --- JSON serialization -----------------------------------------------------


def _unwind_to_dict(pe: PEFile, ui: Optional[UnwindInfo]) -> Optional[dict]:
    if ui is None:
        return None
    d = {
        "rva": ui.rva,
        "version": ui.version,
        "flags": ui.flag_names(),
        "size_of_prolog": ui.size_of_prolog,
        "count_of_codes": ui.count_of_codes,
        "frame_register": ui.frame_register_name,
        "frame_offset": ui.frame_offset_bytes,
        "fixed_stack_alloc": ui.fixed_stack_alloc,
        "struct_size": ui.struct_size,
        "codes": [
            {
                "code_offset": c.code_offset,
                "op": c.mnemonic,
                "op_info": c.op_info,
                "node_count": c.node_count,
                "register": c.register,
                "alloc_size": c.alloc_size,
                "save_offset": c.save_offset,
                "frame_offset": c.frame_offset,
                "has_error_code": c.has_error_code,
                "text": c.description,
            }
            for c in ui.codes
        ],
        "handler_rva": ui.handler_rva,
        "handler_kind": ui.handler_kind,
        "language_data_rva": ui.language_data_rva,
        "handler_data": ui.handler_data.to_dict() if ui.handler_data is not None else None,
    }
    if ui.chained_function is not None:
        d["chained"] = _func_to_dict(pe, ui.chained_function)
    return d


def _func_to_dict(pe: PEFile, f: RuntimeFunction) -> dict:
    from .render import func_section_info

    begin_sec, end_sec, crosses = func_section_info(pe, f)
    return {
        "index": f.index,
        "begin_rva": f.begin_address,
        "end_rva": f.end_address,
        "begin_va": pe.image_base + f.begin_address,
        "begin_section": begin_sec,
        "end_section": end_sec,
        "crosses_section": crosses,
        "size": f.size,
        "unwind_info_address": f.unwind_info_address,
        "unwind_info": _unwind_to_dict(pe, f.unwind_info),
        "trampoline": f.trampoline.to_dict() if f.trampoline is not None else None,
    }


def build_json(analysis: Analysis, functions: Sequence[RuntimeFunction]) -> dict:
    pe = analysis.pe
    ed = analysis.exception_dir
    return {
        "file": pe.source,
        "machine": "AMD64",
        "is_dll": pe.is_dll,
        "image_base": pe.image_base,
        "entry_point_rva": pe.address_of_entry_point,
        "size_of_image": pe.size_of_image,
        "exception_directory": {
            "rva": ed.virtual_address,
            "size": ed.size,
            "count": ed.size // 12,
        },
        "sections": [
            {
                "index": s.index,
                "name": s.name,
                "rva": s.virtual_address,
                "virtual_size": s.virtual_size,
                "raw_ptr": s.raw_ptr,
                "raw_size": s.raw_size,
                "characteristics": s.characteristics,
                "executable": s.is_executable,
                "readable": s.is_readable,
                "writable": s.is_writable,
            }
            for s in pe.sections
        ],
        "diagnostics": [
            {
                "severity": str(d.severity),
                "code": d.code,
                "message": d.message,
                "where": d.where,
            }
            for d in analysis.diagnostics
        ],
        "stats": {
            "function_count": len(analysis.functions),
            "shown": len(functions),
            "chained": analysis.chained_count,
            "handlers": analysis.handler_count,
            "ops": dict(analysis.op_histogram()),
        },
        "functions": [_func_to_dict(pe, f) for f in functions],
    }


# --- main -------------------------------------------------------------------


def _collect_files(paths: Sequence[str]) -> List[str]:
    """Expand directories to their ``*.bin`` members; keep files as given.

    Order is preserved and duplicates removed."""
    import glob

    out: List[str] = []
    seen = set()
    for pth in paths:
        if os.path.isdir(pth):
            members = sorted(glob.glob(os.path.join(pth, "*.bin")))
        else:
            members = [pth]
        for m in members:
            if m not in seen:
                seen.add(m)
                out.append(m)
    return out


def _load(path: str, args: argparse.Namespace):
    """Return ``(pe, analysis)`` or print an error and return ``(None, None)``."""
    try:
        pe = PEFile.from_path(path)
    except FileNotFoundError:
        print(f"unwindy: cannot open {path!r}: no such file", file=sys.stderr)
        return None, None
    except OSError as exc:
        print(f"unwindy: cannot read {path!r}: {exc}", file=sys.stderr)
        return None, None
    except PEFormatError as exc:
        print(f"unwindy: {path}: not a valid PE64: {exc}", file=sys.stderr)
        return None, None
    try:
        analysis = analyze(pe, strict=not args.lenient)
    except UnwindyError as exc:
        print(f"unwindy: {path}: spec violation: {exc}", file=sys.stderr)
        print(
            "unwindy: re-run with --lenient to keep going and list every issue.",
            file=sys.stderr,
        )
        return None, None
    return pe, analysis


def run(argv: Optional[Sequence[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    if not args.path:
        build_parser().error("at least one PE64 path (or directory) is required")

    files = _collect_files(args.path)
    if not files:
        print("unwindy: no input files (no *.bin found in given directories)",
              file=sys.stderr)
        return 2

    explicit_view = (
        args.json or args.sections or args.stats or args.summary_only
        or args.table or args.detail is not None
    )
    want_tui = args.tui is True or (
        args.tui is None and not explicit_view
        and sys.stdout.isatty() and sys.stdin.isatty()
    )
    if want_tui:
        from .tui import run_tui

        # Defer hard parse errors to the UI: it loads each file leniently.
        return run_tui(files, use_va=args.va)

    if args.json:
        return _run_json(files, args)
    return _run_static(files, args)


def _run_json(files: Sequence[str], args: argparse.Namespace) -> int:
    docs = []
    code = 0
    for path in files:
        pe, analysis = _load(path, args)
        if pe is None:
            code = max(code, 2)
            continue
        functions = select_functions(analysis, args)
        docs.append(build_json(analysis, functions))
        code = max(code, _exit_code(analysis, args))
    payload = docs if len(files) > 1 else (docs[0] if docs else {})
    json.dump(payload, sys.stdout, indent=2)
    sys.stdout.write("\n")
    return code


def _run_static(files: Sequence[str], args: argparse.Namespace) -> int:
    painter = make_painter(args.color)
    code = 0
    multi = len(files) > 1
    sep = ""
    for path in files:
        pe, analysis = _load(path, args)
        if pe is None:
            code = max(code, 2)
            continue
        if multi:
            print(sep + painter.bold(painter.cyan(f"==> {path} <==")))
        sep = "\n"
        functions = select_functions(analysis, args)
        print("\n\n".join(_render_blocks(pe, analysis, functions, args, painter)))
        code = max(code, _exit_code(analysis, args))
    return code


def _render_blocks(
    pe: PEFile,
    analysis: Analysis,
    functions: Sequence[RuntimeFunction],
    args: argparse.Namespace,
    painter,
) -> List[str]:
    blocks: List[str] = []
    if not args.quiet:
        blocks.append(render_image_summary(analysis, painter))
    blocks.append(render_diagnostics(list(analysis.diagnostics), painter))

    if args.summary_only:
        pass
    elif args.sections:
        blocks.append(render_sections(pe, painter))
    elif args.stats:
        blocks.append(render_stats(analysis, painter))
    elif args.detail is not None:
        wanted = _detail_subset(functions, args.detail)
        if not wanted:
            blocks.append(painter.yellow("No functions match the given selection."))
        for f in wanted:
            blocks.append(render_function_detail(pe, f, painter, use_va=args.va))
    else:
        if functions:
            blocks.append(render_function_table(pe, functions, painter, use_va=args.va))
            if len(functions) < len(analysis.functions):
                blocks.append(
                    painter.gray(
                        f"({len(functions)} of {len(analysis.functions)} functions "
                        f"shown)"
                    )
                )
        else:
            blocks.append(painter.yellow("No functions to show."))
    return [b for b in blocks if b]


def _detail_subset(
    functions: Sequence[RuntimeFunction], detail: Sequence[str]
) -> List[RuntimeFunction]:
    if not detail:
        return list(functions)
    wanted_idx = set()
    for tok in detail:
        try:
            wanted_idx.add(int(tok, 0))
        except ValueError:
            continue
    return [f for f in functions if f.index in wanted_idx]


def _exit_code(analysis: Analysis, args: argparse.Namespace) -> int:
    if args.fail_on_warn and len(analysis.diagnostics) and (
        analysis.diagnostics.warnings or analysis.diagnostics.errors
    ):
        return 1
    return 0


def main(argv: Optional[Sequence[str]] = None) -> int:
    try:
        return run(argv)
    except KeyboardInterrupt:  # pragma: no cover
        print("interrupted", file=sys.stderr)
        return 130


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
