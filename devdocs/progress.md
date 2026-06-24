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

## v0.0.3 - DONE

Interactive column sorting + richer unwind/size column.

- [x] `ops` column (table + TUI): compact prolog digest with sizes, e.g.
      `4push sub 0x28 3xmm`, `1push sub 0x70 1sav` (`render.unwind_summary`).
- [x] TUI **sort mode** (`s`/`Tab`): `Tab`/`<-`/`->` move a column cursor,
      `Enter` sorts by it and toggles asc/desc, `a`/`d` force a direction; the
      active column is highlighted, the applied sort shown in the title bar, and
      a fresh sort jumps to the top. Every column is sortable; the chosen sort
      persists across files in the picker.
- [x] 91 unit tests, all passing (added `unwind_summary` + TUI sort-mode tests).

## v0.0.4 - DONE

Decode language-specific exception-handler payloads (`unwindy/handlers.py`).

### Handler identification
- [x] Import-table parser (`ImportResolver`) maps IAT slots -> `(dll, symbol)`.
- [x] Handler routine named by following `jmp [rip]` / `jmp rel32` thunks to the
      imported CRT handler; statically-linked `__GSHandlerCheck_*` wrappers are
      named by the handler they tail-call (body scan bounded to the routine's own
      `.pdata` extent, so it never bleeds into a neighbour).

### Payload decoders (validated against the owning function's bounds)
- [x] `__C_specific_handler` **scope tables**: count + records, each classified
      `__except (filter)` / `__except (EXECUTE_HANDLER)` / `__finally`; loud
      warnings on out-of-range / truncated tables.
- [x] `__GSHandlerCheck` **`GS_HANDLER_DATA`**: cookie offset, EHANDLER/UHANDLER/
      alignment flags, aligned-base/alignment.
- [x] MSVC C++ **`FuncInfo`** (FH3): magic/version, maxState, unwind/try-block/
      ip-to-state maps, with try-block + catch (`HandlerType`) expansion.
- [x] **`__CxxFrameHandler4`**: compact FH4 `FuncInfoHeader` flags (state/IP maps
      noted, not expanded).
- [x] Structural fallback classifies statically-linked, unnamed handlers; any
      payload matching no known shape is reported raw, never guessed.

### Surfacing
- [x] Rich per-function detail (CLI + TUI), a compact tag in the function-table
      `handler` column (e.g. `scope[2]`, `cxx4`, `gs+cxx4`), and a full
      `handler_data` object in `--json`.

### Verification
- [x] 113 unit tests, all passing (+22): byte-level decoders for scope/GS/FH3/FH4
      (the GS and FH3 formats are covered by synthetic `_pebuilder` fixtures, as
      neither bundled sample emits them), structural classification through
      `analyze`, and real-sample assertions.
- [x] Bundled `b325...` sample decodes to 4 `__C_specific_handler` scope tables,
      28 `__CxxFrameHandler4` (FH4), 4 GS-wrapped FH4, 107 unrecognized local
      handlers, with **0** warnings.

## v0.0.5 - DONE

Peel function-start trampolines to the real entry point (`unwindy/trampolines.py`).

- [x] Detect when a `RUNTIME_FUNCTION` begins at a forwarding stub and follow the
      `jmp` chain: `e9`/`eb` near jumps to local code, `ff 25` `jmp [rip]` import
      stubs (named via the import table). An intra-function jump (target inside
      the function's own `[begin, end)`) is ordinary control flow, never a
      trampoline; `e8` `call` tails are not mistaken for jumps.
- [x] Record the peeled `real_start`, the full hop chain, the real start's own
      pdata index, and any **segment transition** (the first hop landing in a
      different section), with a cycle/hop guard.
- [x] Surfaced as a `real-start` function-table column (CLI + TUI, sortable), a
      `trampoline:` line in the detail view, and a `trampoline` object in JSON.
- [x] 131 unit tests, all passing (+9): synthetic local / cross-section / chained
      / short-jump / import / intra-function / plain fixtures, plus both samples
      (`b325...` has exactly one `jmp [rip]` import stub at func #901 -> IAT slot
      `0x70020`; `602314...` has none).

## Backlog / extra credit
- [x] Decode language-specific handler payloads (`__C_specific_handler` scope
      tables, `__GSHandlerCheck`, MSVC C++ `FuncInfo`).  *(v0.0.4)*
- [ ] In-TUI text search / filtering.
- [ ] Full v3 unwind support once the spec is published (currently v3 parses
      best-effort using the v2 layout with a warning).
- [ ] More sample binaries (frame-pointer-heavy, v2 epilog, drivers).
