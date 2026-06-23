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

## v0.0.2 - DONE

Interactive terminal UI + section-aware addressing + multi-file support.

### TUI (`unwindy/tui.py`)
- [x] Slim cross-platform TUI with **no** `curses`/third-party deps: raw key
      input via `msvcrt` (Windows) / `termios`+`tty` (POSIX), ANSI rendering on
      the alternate screen. Interaction logic decoupled from terminal I/O so it
      is unit-tested without a real TTY.
- [x] Paginated, scrollable function list (up/down, PgUp/PgDn, Home/End).
- [x] `Enter` opens a fully scrollable per-function detail view; `Left`/`Right`
      step to the previous/next function; `w` diagnostics, `h`/`?` help,
      `v` toggles RVA<->VA.
- [x] Multi-file picker: pass several files or a directory; `*.bin` is scanned,
      each image analyzed lazily and cached; `Esc` returns to the picker.
- [x] Launches by default on a TTY; `-i/--tui` forces it, `--no-tui` disables.

### Section-aware output
- [x] Begin/end/handler addresses labelled as `section:0xADDRESS` across the
      table, detail and TUI (`addr_label`, `PEFile.section_name`).
- [x] New `x-sect` column / `crosses_section` JSON field flagging functions whose
      body spans two sections (`begin_section`->`end_section`), highlighted red.

### CLI
- [x] Accepts multiple paths and directories; static views iterate per file with
      banners; `--json` emits an array for many files.

### Verification
- [x] 84 unit tests, all passing (added TUI logic/navigation/run-loop, key
      decoders, address/section labelling, multi-file picker).
- [x] Second sample `602314161f55e2ca2affab8c516437148c079dd8.bin` (19.8 MB,
      2861 functions, packed `.grfn*` sections): parses in ~0.6 s and the
      relocated exception directory is loudly warned (`pdata.section`).

## Backlog / extra credit
- [ ] Decode language-specific handler payloads (`__C_specific_handler` scope
      tables, `__GSHandlerCheck`, MSVC C++ `FuncInfo`).
- [ ] In-TUI search / sort toggles.
- [ ] Full v3 unwind support once the spec is published (currently v3 parses
      best-effort using the v2 layout with a warning).
- [ ] More sample binaries (frame-pointer-heavy, v2 epilog, drivers).
