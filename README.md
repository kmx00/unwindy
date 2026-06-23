# unwindy

A slim, **zero-dependency** CLI for inspecting x64 (PE64) exception / unwind
information in rich detail. It decodes the `.pdata` `RUNTIME_FUNCTION` table and
every `UNWIND_INFO` / `UNWIND_CODE` (UWOP) record, resolves chained unwind info,
surfaces language-specific handlers, and loudly warns about anything that looks
off — while raising on data that violates the spec.

Pure Python standard library. No `lief`, no `pefile`, no `rich`. Runs on Linux
and Windows with any CPython ≥ 3.9.

## Why

Reverse-engineering and crash-analysis workflows constantly need to answer
"what does the prolog of this function do, and who handles its exceptions?"
unwindy reads the PE straight off disk, validates it, and prints the answer.

## Install / run

No install required:

```sh
python -m unwindy path/to/binary.exe
```

Or install the console script:

```sh
pip install -e .
unwindy path/to/binary.exe
```

## Usage

```
unwindy [path] [view] [filters] [output]

views
  (default)            function table
  -d, --detail [IDX..] full per-function detail (all, or specific .pdata indices)
  -S, --sections       section table
  -s, --stats          version / op histograms
  --summary-only       image summary only
  --json               machine-readable JSON

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
# Overview + first functions
python -m unwindy app.exe --limit 20

# Full detail of one function (with its chained parent and handler)
python -m unwindy app.exe -d 42

# Every function that establishes a frame pointer, largest first
python -m unwindy app.exe --has-op SET_FPREG --sort size -r

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
* **Handlers** — `UNW_FLAG_EHANDLER` / `UNW_FLAG_UHANDLER` handler RVA and the
  RVA of the trailing language-specific data.

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
bash scripts/dev.sh          # run tests + a smoke analysis of the sample
python -m unittest discover -s tests -p 'test_*.py' -v
```

Tests are pure `unittest` (no third-party runner) and cover both the bundled
real-world sample and synthetic images built in `tests/_pebuilder.py` that
exercise every UWOP, chaining, handlers, and each malformation path.

## References

* [x64 exception handling](https://learn.microsoft.com/en-us/cpp/build/exception-handling-x64)
* x64 unwind information v3 (forward-looking; decoded best-effort as v2 today)
