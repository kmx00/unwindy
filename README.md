# unwindy

A slim CLI **and interactive TUI** for inspecting x64 (PE64) exception/unwind
information. It decodes the `.pdata` `RUNTIME_FUNCTION` table and every
`UNWIND_INFO` / `UNWIND_CODE` (UWOP) record, resolves chained unwind info,
surfaces language-specific handlers, and loudly warns about anything off — while
raising on data that violates the spec.

**Zero hard dependencies** — the PE/unwind core is pure Python standard library.
The interactive forwarding-flow view adds
[`iced-x86`](https://pypi.org/project/iced-x86/) for disassembly as an optional
extra (`pip install unwindy[flow]`), imported lazily. Linux, Windows, macOS —
any CPython ≥ 3.9.

## Why

Reverse-engineering and crash-analysis workflows constantly need to answer
"what does the prolog of this function do, and who handles its exceptions?"
unwindy reads the PE straight off disk, validates it, and prints the answer.

## Install / run

No install required. Point it at one binary, several, or a directory of `*.bin`:

```sh
python -m unwindy path/to/binary.exe      # one image
python -m unwindy samples/                 # every *.bin in a directory
python -m unwindy a.dll b.exe c.bin        # several at once
```

Run interactively (the default when stdout is a terminal):

```sh
python -m unwindy samples/                 # opens the TUI
```

Or install the console script:

```sh
pip install -e .            # core (zero dependencies)
pip install -e ".[flow]"    # + iced-x86 for the interactive flow view
unwindy path/to/binary.exe
```

## Interactive TUI

When you run unwindy in a terminal it launches a slim, scrollable terminal UI
(no `curses`, no third-party packages -- raw `msvcrt` on Windows, `termios` on
POSIX, ANSI everywhere). Pass `-i`/`--tui` to force it, `--no-tui` to never use
it.

* **File picker** -- when given more than one binary (or a directory), pick which
  image to inspect; each is analyzed lazily on open.
* **Function list** -- paginated and scrollable over every `RUNTIME_FUNCTION`.
  Begin/end are shown as `section:0xADDRESS`. An **`ops`** column digests the
  prolog (e.g. `4push sub 0x28 3xmm`), an **`x-sect`** column flags (in red,
  as `A->B`) any function whose body spans two sections, and a **`real-start`**
  column peels function-start trampolines to the real entry point.
* **Sort mode** -- press `s` (or `Tab`) to enter an interactive column sorter:
  `Tab`/`<-`/`->` move between columns, `Enter` sorts by the highlighted column
  and toggles ascending/descending; the active sort is shown in the title bar.
* **Inspect** -- `Enter` opens the full decoded detail (prolog unwind codes,
  handler, and the resolved chain), itself scrollable; `Left`/`Right` step to the
  previous/next function.
* **Forwarding flow** -- press **`x`** (or `Shift+Enter`*) to expand a function
  in place and follow where its code actually goes: each basic block is
  disassembled and the `jmp` / tail-dispatch chain is traced across sections to
  its destination. Hops that land on a known function are shown in green; `Enter`
  jumps to them. (*Use `x` on the Windows console, which can't report
  `Shift+Enter`.)

```
  up / down (k / j)     move          Enter       inspect / jump to green hop
  PgUp / PgDn           page          Left/Right  prev/next (in detail)
  Home / End (g / G)    jump          s           sort mode (Tab + Enter)
  x  (Shift+Enter)      expand flow   w           diagnostics (warnings/errors)
  v                     RVA <-> VA    h or ?      help        q  quit
  Esc                   back / quit
```

## Non-interactive usage

```
unwindy [paths...] [view] [filters] [output]

views
  (default)            function table (or the TUI when attached to a terminal)
  -i, --tui            force the interactive UI;  --no-tui forces plain output
  -d, --detail [IDX..] full per-function detail (all, or specific .pdata indices)
  -S, --sections       section table
  -s, --stats          version / op histograms
  --summary-only       image summary only
  --json               machine-readable JSON (an array when given many files)

filtering / sorting
  --sort {index,begin,end,size,prolog,codes,alloc,handler,chained}
  -r, --reverse
  --limit N
  --only-handlers      functions with a language-specific handler
  --only-chained       functions using UNW_FLAG_CHAININFO
  --min-size N
  --has-op UWOP        e.g. --has-op SET_FPREG

output
  --va                 show virtual addresses (image base + rva)
  --color / --no-color
  -q, --quiet          drop the image summary header
  --lenient            downgrade spec violations to errors instead of raising
  --fail-on-warn       exit non-zero if any warning/error was reported
```

### Examples

```sh
# Overview + first functions (force plain output)
python -m unwindy app.exe --no-tui --limit 20

# Full detail of one function (with its chained parent and handler)
python -m unwindy app.exe --no-tui -d 42

# Every function that establishes a frame pointer, largest first
python -m unwindy app.exe --no-tui --has-op SET_FPREG --sort size -r

# Pipe structured data somewhere
python -m unwindy app.exe --json --only-handlers > handlers.json
```

## What it decodes

* **PE64 headers** — DOS/NT, optional header, section table, data directories.
  Rejects non-x64 (`Machine != 0x8664`), non-PE32+ images, and truncation.
* **`RUNTIME_FUNCTION`** — begin/end RVA, size, unwind-info pointer.
* **`UNWIND_INFO`** — version, flags, prolog size, frame register/offset.
* **All UWOP codes** — `PUSH_NONVOL`, `ALLOC_SMALL`, `ALLOC_LARGE` (scaled and
  unscaled), `SET_FPREG`, `SAVE_NONVOL[_FAR]`, `SAVE_XMM128[_FAR]`,
  `PUSH_MACHFRAME`, plus version-2 `EPILOG` / `SPARE_CODE`. Each is rendered as a
  human-readable instruction (e.g. `sub rsp, 0x28`, `mov [rsp+0x48], rbx`).
* **Chaining** — `UNW_FLAG_CHAININFO` is followed recursively, with cycle and
  depth protection.
* **Language-specific handlers** — the handler routine is *named* by following
  its import thunk (e.g. `__C_specific_handler`, `__CxxFrameHandler4`) or, for a
  statically-linked `__GSHandlerCheck_*` cookie-check wrapper, by the handler it
  wraps. The trailing payload is then decoded and validated against the function:
  - `__C_specific_handler` **scope tables** — every `__try` region classified as
    `__except (filter)`, `__except (EXECUTE_HANDLER)`, or `__finally`, with its
    filter / body / handler addresses.
  - `__GSHandlerCheck` **`GS_HANDLER_DATA`** — stack-cookie frame offset,
    EHANDLER/UHANDLER/alignment flags, and aligned-base/alignment fields.
  - **MSVC C++ `FuncInfo`** (FH3) — magic/version, state count, and the expanded
    try-block / catch maps (catch type, handler funclet, frame offset).
  - **`__CxxFrameHandler4`** — the compact FH4 `FuncInfoHeader` flags; its
    variable-length state/IP maps are noted but not expanded.
  Payloads that match no known shape are reported with their raw leading bytes,
  never guessed.
* **Start trampolines** — when a function begins at a forwarding stub (an
  incremental-link / ICF / guard thunk, a tail-call-only wrapper, or a
  `jmp [rip]` import stub), the `jmp` chain is peeled to the real entry point.
  The `real-start` column / `trampoline` JSON field show the peeled RVA, and any
  **segment transition** (the hop that lands in a different section) is flagged.
* **Forwarding flow** (TUI, `iced-x86`) — when a function's *real* prolog
  tail-jumps or tail-dispatches into another stub, the `jmp`/`call` chain is
  disassembled and traced block by block to its destination, across sections.
  Interactive-only; not part of `--json`.
* **Section context** — every begin/end/handler address is labelled with its
  containing section (`section:0xADDRESS`), and functions whose body spans two
  sections are flagged (`x-sect` column / `crosses_section` in JSON).

## Conformance: raise vs. warn

Two tiers, by design:

* **Hard spec violations raise** (`PEFormatError` / `UnwindFormatError`):
  bad magic, non-x64 machine, unknown UWOP, an unwind code that overruns
  `CountOfCodes`, `SET_FPREG` with no frame register, invalid `UNWIND_INFO`
  version, chain cycles, `BeginAddress >= EndAddress`. Use `--lenient` to turn
  these into loud errors and keep going.
* **Suspicious-but-parseable traits warn** (and are printed in red/yellow):
  unsorted or overlapping `.pdata`, `.pdata` size not a multiple of 12,
  misaligned `UNWIND_INFO`, unwind info in an executable section, handler RVA
  outside an executable section, reserved flag bits, code offsets beyond the
  prolog, frame register declared but never set, and more.

## Library API

```python
from unwindy import PEFile, analyze

pe = PEFile.from_path("app.exe")
analysis = analyze(pe)                 # strict=True by default

print(analysis.chained_count, analysis.handler_count)
for func in analysis.functions:
    ui = func.unwind_info
    for code in ui.codes:
        print(hex(code.code_offset), code.mnemonic, code.description)

for diag in analysis.diagnostics:
    print(diag)                        # severity, code, message, location
```

## Development

```sh
python -m unittest discover -s tests -p 'test_*.py' -v   # full suite
pip install ".[flow]"                                    # run the flow tests too
```

CI (GitHub Actions) runs the suite on Linux and Windows, builds an installable
wheel, and produces standalone PyInstaller binaries for both platforms.

Tests are pure `unittest` (no third-party runner), exercising the real samples
plus synthetic images (`tests/_pebuilder.py`) that cover every UWOP, the handler
payloads, trampolines, malformation paths, and the TUI logic.

## References

* [x64 exception handling](https://learn.microsoft.com/en-us/cpp/build/exception-handling-x64)
* x64 unwind information v3 (forward-looking; decoded best-effort as v2 today)

## License

Proprietary — Copyright (c) 2026 kmx00. **All rights reserved.** This software
is provided for viewing only; no use, copying, modification, or redistribution
is permitted. Contact the author (kmx00) for permission. See [LICENSE](LICENSE).
