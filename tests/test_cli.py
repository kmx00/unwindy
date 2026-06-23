"""Tests for the command-line front end."""

from __future__ import annotations

import io
import json
import os
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path

from tests._pebuilder import (
    CODE_PERMS,
    RDATA_PERMS,
    PEBuilder,
    encode_runtime_function,
    encode_unwind_info,
)
from unwindy.cli import main

SAMPLE = Path(__file__).resolve().parents[1] / "samples" / (
    "b325e5a8da4f8bea2db9fc118f6a6f237731d734.bin"
)


def _run(*argv):
    out, err = io.StringIO(), io.StringIO()
    with redirect_stdout(out), redirect_stderr(err):
        code = main(["--no-color", *argv])
    return code, out.getvalue(), err.getvalue()


class CliTests(unittest.TestCase):
    def test_default_table(self):
        code, out, _ = _run(str(SAMPLE), "--limit", "5")
        self.assertEqual(code, 0)
        self.assertIn("Image", out)
        self.assertIn("RUNTIME_FUNCTION", out)
        self.assertIn("No warnings", out)

    def test_stats(self):
        code, out, _ = _run(str(SAMPLE), "-s")
        self.assertEqual(code, 0)
        self.assertIn("UWOP_PUSH_NONVOL", out)

    def test_sections(self):
        code, out, _ = _run(str(SAMPLE), "-S", "-q")
        self.assertEqual(code, 0)
        self.assertIn(".pdata", out)
        self.assertIn(".text", out)

    def test_detail_specific_index(self):
        code, out, _ = _run(str(SAMPLE), "-d", "2")
        self.assertEqual(code, 0)
        self.assertIn("Function #2", out)
        self.assertIn("chained ->", out)

    def test_json_is_valid_and_complete(self):
        code, out, _ = _run(str(SAMPLE), "--json", "--limit", "3")
        self.assertEqual(code, 0)
        doc = json.loads(out)
        self.assertEqual(doc["machine"], "AMD64")
        self.assertEqual(doc["stats"]["function_count"], 919)
        self.assertEqual(len(doc["functions"]), 3)
        self.assertEqual(doc["exception_directory"]["count"], 919)
        # every shown function carries decoded unwind info
        for f in doc["functions"]:
            self.assertIn("unwind_info", f)

    def test_filter_only_handlers(self):
        code, out, _ = _run(str(SAMPLE), "--json", "--only-handlers")
        doc = json.loads(out)
        self.assertEqual(len(doc["functions"]), 143)
        for f in doc["functions"]:
            self.assertIsNotNone(f["unwind_info"]["handler_kind"])

    def test_filter_only_chained(self):
        code, out, _ = _run(str(SAMPLE), "--json", "--only-chained")
        doc = json.loads(out)
        self.assertEqual(len(doc["functions"]), 252)

    def test_has_op_filter(self):
        code, out, _ = _run(str(SAMPLE), "--json", "--has-op", "SAVE_XMM128")
        doc = json.loads(out)
        self.assertTrue(len(doc["functions"]) > 0)
        self.assertTrue(len(doc["functions"]) < 919)

    def test_sort_by_size_desc(self):
        code, out, _ = _run(str(SAMPLE), "--json", "--sort", "size", "-r", "--limit", "5")
        doc = json.loads(out)
        sizes = [f["size"] for f in doc["functions"]]
        self.assertEqual(sizes, sorted(sizes, reverse=True))

    def test_missing_file_exit_code(self):
        code, _, err = _run("does-not-exist.bin")
        self.assertEqual(code, 2)
        self.assertIn("no such file", err)

    def test_not_a_pe_exit_code(self):
        bad = Path(__file__)  # this .py file is not a PE
        code, _, err = _run(str(bad))
        self.assertEqual(code, 2)

class WarnAndColorTests(unittest.TestCase):
    def _write_warning_image(self) -> str:
        # Two functions whose .pdata is unsorted -> a warning, not a hard error.
        u = encode_unwind_info(prolog=0)
        rfs = encode_runtime_function(0x1200, 0x1300, 0x4000) + encode_runtime_function(
            0x1000, 0x1100, 0x4000
        )
        b = PEBuilder()
        b.add_section(".text", 0x1000, b"\xcc" * 0x2000, CODE_PERMS)
        b.add_section(".pdata", 0x3000, rfs, RDATA_PERMS)
        b.add_section(".xdata", 0x4000, u, RDATA_PERMS)
        b.set_exception_dir(0x3000, len(rfs))
        fd, path = tempfile.mkstemp(suffix=".bin")
        with os.fdopen(fd, "wb") as fh:
            fh.write(b.build())
        return path

    def test_fail_on_warn_exit_code(self):
        path = self._write_warning_image()
        try:
            code, out, _ = _run(path, "--fail-on-warn")
            self.assertEqual(code, 1)
            self.assertIn("WARNINGS", out)
            self.assertIn("pdata.unsorted", out)
            # without the flag the same image exits 0
            code2, _, _ = _run(path)
            self.assertEqual(code2, 0)
        finally:
            os.unlink(path)

    def test_forced_color_emits_ansi(self):
        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            main(["--color", str(SAMPLE), "-q", "-S"])
        self.assertIn("\x1b[", out.getvalue())



if __name__ == "__main__":
    unittest.main()
