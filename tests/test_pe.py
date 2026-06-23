"""Tests for the PE64 reader."""

from __future__ import annotations

import struct
import unittest
from pathlib import Path

from tests._pebuilder import CODE_PERMS, RDATA_PERMS, PEBuilder, simple_image
from unwindy.errors import PEFormatError
from unwindy.pe import IMAGE_DIRECTORY_ENTRY_EXCEPTION, PEFile

SAMPLE = Path(__file__).resolve().parents[1] / "samples" / (
    "b325e5a8da4f8bea2db9fc118f6a6f237731d734.bin"
)


class SamplePETests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.pe = PEFile.from_path(str(SAMPLE))

    def test_basic_header_fields(self):
        self.assertEqual(self.pe.machine, 0x8664)
        self.assertEqual(self.pe.image_base, 0x140000000)
        self.assertEqual(self.pe.number_of_sections, 8)
        self.assertFalse(self.pe.is_dll)

    def test_exception_directory_present(self):
        ed = self.pe.exception_directory
        self.assertEqual(ed.index, IMAGE_DIRECTORY_ENTRY_EXCEPTION)
        self.assertEqual(ed.virtual_address, 0x69000)
        self.assertEqual(ed.size, 0x2B14)
        self.assertTrue(ed.present)

    def test_section_lookup_and_perms(self):
        text = self.pe.section_for_rva(0x1000)
        self.assertEqual(text.name, ".text")
        self.assertTrue(text.is_executable)
        self.assertTrue(text.is_readable)
        self.assertFalse(text.is_writable)

    def test_rva_translation_roundtrip(self):
        ed = self.pe.exception_directory
        off = self.pe.rva_to_offset(ed.virtual_address)
        # First RUNTIME_FUNCTION begin we verified manually.
        begin = struct.unpack_from("<I", self.pe.data, off)[0]
        self.assertEqual(begin, 0x5710)

    def test_read_at_rva_bounds(self):
        with self.assertRaises(PEFormatError):
            # Way past the image.
            self.pe.read_at_rva(0x7FFFFFFF, 4)


class MalformedPETests(unittest.TestCase):
    def _valid(self) -> bytes:
        return simple_image(b"\x00" * 12, b"\x01\x00\x00\x00")

    def test_too_small(self):
        with self.assertRaises(PEFormatError):
            PEFile(b"MZ")

    def test_bad_dos_magic(self):
        data = bytearray(self._valid())
        data[0:2] = b"XX"
        with self.assertRaises(PEFormatError):
            PEFile(bytes(data))

    def test_bad_pe_signature(self):
        data = bytearray(self._valid())
        e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
        struct.pack_into("<I", data, e_lfanew, 0xDEADBEEF)
        with self.assertRaises(PEFormatError):
            PEFile(bytes(data))

    def test_non_x64_machine_rejected(self):
        b = PEBuilder(machine=0x014C)  # i386
        b.add_section(".text", 0x1000, b"\xcc" * 0x100, CODE_PERMS)
        with self.assertRaises(PEFormatError):
            PEFile(b.build())

    def test_pe32_magic_rejected(self):
        b = PEBuilder(opt_magic=0x10B)  # PE32, not PE32+
        b.add_section(".text", 0x1000, b"\xcc" * 0x100, CODE_PERMS)
        with self.assertRaises(PEFormatError):
            PEFile(b.build())

    def test_uninitialized_tail_not_readable(self):
        b = PEBuilder()
        # virtual_size larger than raw data -> tail has no file bytes.
        b.add_section(".text", 0x1000, b"\xcc" * 0x10, CODE_PERMS, virtual_size=0x1000)
        pe = PEFile(b.build())
        with self.assertRaises(PEFormatError):
            pe.read_at_rva(0x1FF0, 4)


if __name__ == "__main__":
    unittest.main()
