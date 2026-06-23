# current status, checkboxes

## v0.0.1 - DONE

Slim, zero-dependency PE64 x64 exception/unwind viewer. Pure stdlib runtime;
tests run under `unittest` with no installs.

### Core parser
- [x] PE64 reader (`unwindy/pe.py`): DOS/NT headers, optional header, section
      table, data directories, RVA->offset translation. Rejects non-x64,
      non-PE32+, truncated images.
- [x] Unwind decoder (`unwindy/unwind.py`): `RUNTIME_FUNCTION`, `UNWIND_INFO`,
      all UWOP codes with operand decode + human-readable text.
- [x] Chaining (`UNW_FLAG_CHAININFO`) resolved recursively with cycle + depth
      guards.
- [x] Handlers (`UNW_FLAG_EHANDLER` / `UNW_FLAG_UHANDLER`): handler RVA +
      language-specific data RVA.
- [x] Analyzer (`unwindy/analyzer.py`): directory/section-level validation,
      diagnostics, aggregate stats.

### Conformance
- [x] Hard spec violations raise (`PEFormatError` / `UnwindFormatError`).
- [x] `--lenient` downgrades violations to loud errors and continues.
- [x] Suspicious traits warned loudly: unsorted/overlapping `.pdata`, bad
      directory size, misaligned/exec-section unwind info, reserved flags,
      code-after-prolog, frame-register anomalies, unmapped/non-exec handlers.

### Interface
- [x] Color text renderer (`unwindy/render.py`), ANSI, Windows VT enabled,
      `NO_COLOR` honored.
- [x] CLI (`unwindy/cli.py`): table / detail / sections / stats / JSON views;
      sort, filter (`--only-handlers`, `--only-chained`, `--has-op`,
      `--min-size`), `--limit`, `--va`, `--fail-on-warn`.
- [x] `python -m unwindy` entry + `unwindy` console script.

### Verification
- [x] 60 unit tests (`tests/`), all passing.
- [x] Validated against bundled sample
      `b325e5a8da4f8bea2db9fc118f6a6f237731d734.bin`:
      919 RUNTIME_FUNCTION, 252 chained, 143 handlers, 0 warnings.
      Op counts cross-checked against an independent raw scan.

## Backlog / extra credit
- [ ] Decode language-specific handler payloads (`__C_specific_handler` scope
      tables, `__GSHandlerCheck`, MSVC C++ `FuncInfo`).
- [ ] Interactive TUI (curses) for browse/sort.
- [ ] Full v3 unwind support once the spec is published (currently v3 parses
      best-effort using the v2 layout with a warning).
- [ ] More sample binaries (DLLs, drivers, frame-pointer-heavy, v2 epilog).
