"""Golden-output safety net for the refactor branch.

Locks the *observable* output of the JSON serializer and the function-table /
detail renderers so the slim-down refactors (column unification, serialization
consolidation) provably change nothing a consumer can see.

Full JSON for the samples is large, so it is guarded by a sha256 hash; a small,
diffable slice of the b325 JSON is also committed for human inspection.

Regenerate after an *intended* output change:

    python tests/test_golden.py --generate
"""

from __future__ import annotations

import hashlib
import json
import sys
import unittest
from pathlib import Path

from unwindy.analyzer import analyze
from unwindy.cli import build_json
from unwindy.pe import PEFile
from unwindy.render import Painter, render_function_detail, render_function_table

ROOT = Path(__file__).resolve().parents[1]
SAMPLES = ROOT / "samples"
GOLDEN = Path(__file__).resolve().parent / "golden"
S1 = SAMPLES / "b325e5a8da4f8bea2db9fc118f6a6f237731d734.bin"
S2 = SAMPLES / "602314161f55e2ca2affab8c516437148c079dd8.bin"


def _analyze(path: Path):
    pe = PEFile.from_path(str(path))
    return pe, analyze(pe, strict=False)


def _json_canon(pe, an) -> str:
    return json.dumps(build_json(an, an.functions), sort_keys=True, separators=(",", ":"))


def _table_canon(pe, an) -> str:
    return render_function_table(pe, an.functions[:60], Painter(False), use_va=False)


def _detail_sel(an):
    sel = [
        f
        for f in an.functions
        if f.unwind_info and (f.unwind_info.handler_data or f.unwind_info.is_chained)
    ][:10]
    return sel or an.functions[:10]


def _detail_canon(pe, an) -> str:
    return "\n".join(
        render_function_detail(pe, f, Painter(False), use_va=False)
        for f in _detail_sel(an)
    )


def _sha(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _all_hashes() -> dict:
    out = {}
    for label, path in (("b325", S1), ("602", S2)):
        pe, an = _analyze(path)
        out[f"json_{label}"] = _sha(_json_canon(pe, an))
        out[f"table_{label}"] = _sha(_table_canon(pe, an))
        out[f"detail_{label}"] = _sha(_detail_canon(pe, an))
    return out


def _generate() -> None:
    GOLDEN.mkdir(exist_ok=True)
    (GOLDEN / "hashes.json").write_text(
        json.dumps(_all_hashes(), indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    pe, an = _analyze(S1)
    slice_doc = build_json(an, an.functions[:12])
    (GOLDEN / "b325_first12.json").write_text(
        json.dumps(slice_doc, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    print(f"wrote golden fixtures to {GOLDEN}")


class GoldenOutputTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.expected = json.loads((GOLDEN / "hashes.json").read_text(encoding="utf-8"))

    def test_json_unchanged(self):
        for label, path in (("b325", S1), ("602", S2)):
            pe, an = _analyze(path)
            self.assertEqual(_sha(_json_canon(pe, an)), self.expected[f"json_{label}"],
                             f"--json output changed for {label}")

    def test_table_unchanged(self):
        for label, path in (("b325", S1), ("602", S2)):
            pe, an = _analyze(path)
            self.assertEqual(_sha(_table_canon(pe, an)), self.expected[f"table_{label}"],
                             f"function-table render changed for {label}")

    def test_detail_unchanged(self):
        for label, path in (("b325", S1), ("602", S2)):
            pe, an = _analyze(path)
            self.assertEqual(_sha(_detail_canon(pe, an)), self.expected[f"detail_{label}"],
                             f"detail render changed for {label}")

    def test_b325_first12_slice_matches(self):
        pe, an = _analyze(S1)
        got = build_json(an, an.functions[:12])
        want = json.loads((GOLDEN / "b325_first12.json").read_text(encoding="utf-8"))
        self.assertEqual(got, want)


if __name__ == "__main__":
    if "--generate" in sys.argv:
        _generate()
    else:
        unittest.main()
