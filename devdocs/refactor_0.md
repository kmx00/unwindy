# refactor_0 — slim-down + correctness review

Scope: full read of `unwindy/` at v0.0.6 (4,669 LoC / 12 modules, +2,071 LoC tests).
Goal: cut duplication and coupling, tighten cohesion, keep behaviour identical
(138 tests are the contract). Ordered by value/risk; each item cites evidence.

## Verdict

The core is genuinely good: `pe.py`, `unwind.py`, `errors.py` are tight,
spec-accurate, and well-documented; the raise-vs-warn contract is honoured
consistently. The bloat is **not** in the parser — it's in three cross-cutting
seams that each got hand-rolled per module: **column metadata**, **branch/thunk
decoding**, and **`to_dict` serialization**. Fixing those three is most of the
slim-down. `tui.py` (994 LoC) is the one module that is simply too big and mixes
concerns.

Rough recoverable: ~250–400 LoC net, plus removal of 3 silent-drift hazards.

---

## P1 — high value, low risk

### 1. Unify column metadata (kills a silent-drift hazard)
The function-table schema is described **four times, in parallel lists keyed by
position**, across two files:
- `render.py:267` `FUNC_COLUMNS` (names)
- `render.py:~413` `aligns` + `~414` `col_color`
- `render.py:357` `function_row` (value order)
- `tui.py:40` `_ALIGNS` (verbatim copy of `aligns`)
- `tui.py:689` `_sort_keyfn` — a 12-branch `if col == N` ladder of magic indices.

Add/reorder a column and you must touch five spots in lockstep or it breaks
*silently* (wrong alignment, wrong sort key, no error). 

**Proposal:** one `Column` descriptor table (name, align, `value(pe,f,use_va)`,
optional `color`, optional `sort_key`) in `render.py`; `function_row`,
`render_function_table`, `_compose_rows`, `_header_line`, and `_sort_keyfn` all
derive from it. Deletes `_ALIGNS`, the second `aligns`, and the entire
`_sort_keyfn` ladder (~40 LoC) in favour of `col.sort_key`.
Risk: low — pure internal restructure, covered by sort tests.

### 2. Consolidate hand-rolled branch decoding
The `e9`/`eb` near-jump and `ff 25` `jmp [rip]` encodings are re-implemented in
**three** places:
- `trampolines.py:75` `_jmp_target`
- `handlers.py:341` `_import_thunk_target`, `:351` `resolve_routine`, `:377`
  `_scan_wrapper`
- `flow.py` (now via iced-x86)

Four copies of the same byte patterns drift independently. 

**Proposal:** a tiny `branch.py` exposing `classify_branch(pe, rva) ->
(kind, target|slot)` for the 2–3 encodings, reused by trampolines + handlers.
Keep it pure-stdlib (do **not** route the core through iced — see "Leave alone")
so `analyze()` stays dependency-free; iced remains flow-only. Removes ~30 LoC of
duplicated opcode literals and one class of bugs.

### 3. Collapse `to_dict` boilerplate
Eight near-identical `to_dict()` methods (`handlers.py`: ScopeRecord, GsData,
CxxCatch, CxxTryBlock, CxxFuncInfo, Fh4Info, HandlerData; `trampolines.py`:
StartTrampoline) plus `cli.py:130` `_unwind_to_dict`/`:168` `_func_to_dict`.
Most are mechanical field mirrors. 

**Proposal:** a small `serialize.py` helper (`as_jsonable(obj)` over
`dataclasses.fields`, with a hook for the few custom bits — `raw_head.hex()`,
`import_name()`, `flag_names()`). Keep the handful of computed fields as explicit
overrides; drop the rest. ~80–120 LoC removed. Risk: medium — JSON shape is a
public surface; assert byte-for-byte equality against current `--json` output in
a test before/after.

---

## P2 — cohesion / structure

### 4. Decompose `tui.py` (994 LoC, three responsibilities in one file)
Currently holds: terminal/key I/O (`_PosixKeyReader`/`_WindowsKeyReader`,
decoders), the `_Entry` analysis cache, and the `TuiApp` state machine + the new
visual-row/flow plumbing. 

**Proposal:** split into `tui/keys.py` (readers + `_decode_*`), `tui/app.py`
(`TuiApp`), and keep `_Entry` near the app or in `tui/cache.py`. The visual-row
model (`_visual_rows`/`_vindex`/`_move_cursor`) is the densest part — give it a
short docstring on the (sel, flow_idx) invariant so the next maintainer isn't
reverse-engineering it. No LoC saved, big readability win. Risk: low (imports
only); the TUI tests run headless and will catch breakage.

### 5. Data-drive the handler `_dispatch` ladder
`handlers.py:653` `_dispatch` + `:614` `_classify_structural`: the GS-wrapper
branch (`gs+cxx4`/`gs+cxx3`/`gs+scope`) and the plain branch repeat the same
"read FuncInfo RVA → decode → maybe GS at +4" sequences. 

**Proposal:** a table `name -> (kind, decode_fn, gs_at)` so the 8 branches become
2 lookups. Modest (~25 LoC) and clarifies the FH3/FH4/scope/GS matrix. Risk:
medium — exercised only partly by real samples; lean on the synthetic
`_pebuilder` fixtures.

### 6. JSON ↔ detail ↔ flow parity gap
The flow feature is TUI-only: `--json` (`cli.build_json`) and the static detail
view (`render.render_function_detail`) expose **trampolines but not flow**. If
flow is a first-class capability it should appear in both (a `flow` object in
JSON, a `flow:` block in detail). Decide: promote flow to a real output, or
document it as interactive-only. Either way, note it so the omission is a choice.

---

## P3 — minor / hygiene

- `handlers.py:497` `decode_gs_data(pe, rva, bag, where)` — `bag` and `where`
  are unused. Drop them (and at the 4 call sites) or actually warn on a
  bad/oversized cookie offset.
- `cli.py:169` `_func_to_dict` does a function-local `from .render import
  func_section_info` to dodge an import cycle — a smell. After P1, move
  `func_section_info` to a neutral home (it's pure `pe`+`f` logic; belongs in
  `pe.py` or a new `sections.py`) and import normally.
- `errors.py` `DiagnosticBag.warnings`/`errors` rescan `items` on every access
  (`by_severity`). Fine at current scale; if ever hot, cache counts. Leave for now.
- `flow.py` `_KIND` is a module global populated lazily by `_build_kind_table()`.
  Works, but a frozen module-level dict built once behind `iced_available()`
  would read cleaner than mutate-on-first-call.
- Version string lives in two places (`pyproject.toml` and `__init__.__version__`)
  — keep them in sync or read one from the other.

---

## Leave alone (looks refactorable, isn't)

- **Do not push the core onto iced-x86.** `analyze()`/`trampolines`/`handlers`
  are intentionally pure-stdlib and dependency-free; iced is lazily imported and
  flow-only. Item 2 unifies the *stdlib* decoders, it does not adopt iced in the
  core.
- **`unwind.py` `_decode_codes`** — the long UWOP `if/elif` chain looks like a
  table candidate, but each arm has distinct slot-count/operand math and bespoke
  diagnostics. A table would obscure more than it saves. Keep as is.
- **The dataclass field lists themselves** — verbose but they *are* the decoded
  record shapes; only the `to_dict` mirror (item 3) is boilerplate.

---

## Suggested order

1. Item 1 (columns) — unblocks `tui.py` cleanup, removes the worst drift hazard.
2. Item 2 (branch decoding) — small, isolated, immediate dedup.
3. Item 4 (split `tui.py`) — now that columns are centralized.
4. Item 3 (serialization) — gated behind a `--json` golden-output test.
5. Items 5/6/P3 as capacity allows.

Each step: keep `python -m unittest discover` green; for item 3 add a
golden-JSON snapshot test of both samples *first*, then refactor under it.
