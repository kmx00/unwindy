"""Minimal, dependency-free PE64 reader.

Only what unwindy needs: DOS/NT headers, the section table, RVA translation and
the exception data directory. Anything that is not a well-formed x64 PE raises
:class:`~unwindy.errors.PEFormatError` immediately.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass
from typing import List, Optional

from .errors import PEFormatError

# --- constants ---------------------------------------------------------------

DOS_MAGIC = 0x5A4D  # 'MZ'
PE_SIGNATURE = 0x00004550  # 'PE\0\0'
IMAGE_FILE_MACHINE_AMD64 = 0x8664
IMAGE_NT_OPTIONAL_HDR64_MAGIC = 0x20B

IMAGE_FILE_HEADER_SIZE = 20
SECTION_HEADER_SIZE = 40

IMAGE_DIRECTORY_ENTRY_EXCEPTION = 3
DATA_DIRECTORY_NAMES = [
    "Export",
    "Import",
    "Resource",
    "Exception",
    "Security",
    "BaseReloc",
    "Debug",
    "Architecture",
    "GlobalPtr",
    "TLS",
    "LoadConfig",
    "BoundImport",
    "IAT",
    "DelayImport",
    "CLRRuntime",
    "Reserved",
]

# Section characteristics
IMAGE_SCN_CNT_CODE = 0x00000020
IMAGE_SCN_MEM_EXECUTE = 0x20000000
IMAGE_SCN_MEM_READ = 0x40000000
IMAGE_SCN_MEM_WRITE = 0x80000000

# File characteristics
IMAGE_FILE_DLL = 0x2000
IMAGE_FILE_EXECUTABLE_IMAGE = 0x0002


@dataclass(frozen=True)
class DataDirectory:
    index: int
    name: str
    virtual_address: int
    size: int

    @property
    def present(self) -> bool:
        return self.virtual_address != 0 and self.size != 0


@dataclass(frozen=True)
class Section:
    index: int
    name: str
    raw_name: bytes
    virtual_address: int
    virtual_size: int
    raw_size: int
    raw_ptr: int
    characteristics: int

    @property
    def virtual_end(self) -> int:
        return self.virtual_address + max(self.virtual_size, self.raw_size)

    def contains_rva(self, rva: int) -> bool:
        return self.virtual_address <= rva < self.virtual_end

    @property
    def is_executable(self) -> bool:
        return bool(self.characteristics & IMAGE_SCN_MEM_EXECUTE)

    @property
    def is_readable(self) -> bool:
        return bool(self.characteristics & IMAGE_SCN_MEM_READ)

    @property
    def is_writable(self) -> bool:
        return bool(self.characteristics & IMAGE_SCN_MEM_WRITE)

    @property
    def is_code(self) -> bool:
        return bool(self.characteristics & IMAGE_SCN_CNT_CODE)


class PEFile:
    """A parsed PE64 image, read straight off disk.

    The constructor performs strict structural validation; on any deviation it
    raises :class:`PEFormatError`.
    """

    def __init__(self, data: bytes, *, source: Optional[str] = None) -> None:
        self.data = data
        self.source = source
        self._parse()

    # -- construction helpers -------------------------------------------------

    @classmethod
    def from_path(cls, path: str) -> "PEFile":
        with open(path, "rb") as fh:
            return cls(fh.read(), source=path)

    def _u16(self, off: int) -> int:
        self._need(off, 2)
        return struct.unpack_from("<H", self.data, off)[0]

    def _u32(self, off: int) -> int:
        self._need(off, 4)
        return struct.unpack_from("<I", self.data, off)[0]

    def _u64(self, off: int) -> int:
        self._need(off, 8)
        return struct.unpack_from("<Q", self.data, off)[0]

    def _need(self, off: int, length: int) -> None:
        if off < 0 or off + length > len(self.data):
            raise PEFormatError(
                f"truncated image: need {length} bytes at offset {off:#x}, "
                f"have {len(self.data)}"
            )

    # -- parsing --------------------------------------------------------------

    def _parse(self) -> None:
        if len(self.data) < 0x40:
            raise PEFormatError("file too small to be a PE image")
        if self._u16(0) != DOS_MAGIC:
            raise PEFormatError("missing 'MZ' DOS signature")

        self.e_lfanew = self._u32(0x3C)
        if self._u32(self.e_lfanew) != PE_SIGNATURE:
            raise PEFormatError(
                f"missing 'PE\\0\\0' signature at e_lfanew={self.e_lfanew:#x}"
            )

        fh_off = self.e_lfanew + 4
        (
            self.machine,
            self.number_of_sections,
            self.time_date_stamp,
            _psym,
            _nsym,
            self.size_of_optional_header,
            self.file_characteristics,
        ) = struct.unpack_from("<HHIIIHH", self.data, fh_off)

        if self.machine != IMAGE_FILE_MACHINE_AMD64:
            raise PEFormatError(
                f"unsupported machine {self.machine:#06x}; only x64 "
                f"(AMD64, 0x8664) PE images are supported"
            )

        opt_off = fh_off + IMAGE_FILE_HEADER_SIZE
        self.optional_header_offset = opt_off
        if self.size_of_optional_header < 112:
            raise PEFormatError(
                f"optional header too small ({self.size_of_optional_header} bytes)"
            )

        magic = self._u16(opt_off)
        if magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC:
            raise PEFormatError(
                f"optional header magic {magic:#06x} is not PE32+ (0x20b); "
                f"not a 64-bit image"
            )

        self.address_of_entry_point = self._u32(opt_off + 16)
        self.image_base = self._u64(opt_off + 24)
        self.section_alignment = self._u32(opt_off + 32)
        self.file_alignment = self._u32(opt_off + 36)
        self.size_of_image = self._u32(opt_off + 56)
        self.size_of_headers = self._u32(opt_off + 60)
        self.subsystem = self._u16(opt_off + 68)
        self.dll_characteristics = self._u16(opt_off + 70)
        self.number_of_rva_and_sizes = self._u32(opt_off + 108)

        self._parse_data_directories(opt_off + 112)
        self._parse_sections(opt_off + self.size_of_optional_header)

    def _parse_data_directories(self, off: int) -> None:
        count = self.number_of_rva_and_sizes
        if count > 16:
            # Spec caps this at 16; trust the array but only read 16.
            count = 16
        dirs: List[DataDirectory] = []
        for i in range(count):
            va, size = struct.unpack_from("<II", self.data, off + i * 8)
            name = DATA_DIRECTORY_NAMES[i] if i < len(DATA_DIRECTORY_NAMES) else str(i)
            dirs.append(DataDirectory(i, name, va, size))
        self.data_directories = dirs

    def _parse_sections(self, off: int) -> None:
        sections: List[Section] = []
        for i in range(self.number_of_sections):
            base = off + i * SECTION_HEADER_SIZE
            self._need(base, SECTION_HEADER_SIZE)
            raw_name = self.data[base : base + 8]
            name = raw_name.rstrip(b"\x00").decode("latin-1", "replace")
            vsize, vaddr, rsize, rptr = struct.unpack_from("<IIII", self.data, base + 8)
            chars = struct.unpack_from("<I", self.data, base + 36)[0]
            sections.append(
                Section(i, name, raw_name, vaddr, vsize, rsize, rptr, chars)
            )
        self.sections = sections

    # -- RVA helpers ----------------------------------------------------------

    def section_for_rva(self, rva: int) -> Optional[Section]:
        for sec in self.sections:
            if sec.contains_rva(rva):
                return sec
        return None

    def section_name(self, rva: int, default: str = "??") -> str:
        sec = self.section_for_rva(rva)
        return sec.name if sec is not None else default

    def rva_to_offset(self, rva: int) -> int:
        """Translate an RVA to a file offset, raising if it is not backed by
        on-disk bytes."""
        sec = self.section_for_rva(rva)
        if sec is not None:
            delta = rva - sec.virtual_address
            if delta >= sec.raw_size:
                raise PEFormatError(
                    f"rva {rva:#x} falls in uninitialized tail of section "
                    f"{sec.name!r}; no file bytes present"
                )
            off = sec.raw_ptr + delta
            self._need(off, 1)
            return off
        if rva < self.size_of_headers:
            # Header region maps 1:1 with the file.
            return rva
        raise PEFormatError(f"rva {rva:#x} is not mapped by any section")

    def read_at_rva(self, rva: int, length: int) -> bytes:
        """Read ``length`` bytes starting at ``rva``; the whole span must live in
        a single section's raw data."""
        off = self.rva_to_offset(rva)
        sec = self.section_for_rva(rva)
        if sec is not None:
            avail = sec.raw_ptr + sec.raw_size - off
            if length > avail:
                raise PEFormatError(
                    f"read of {length} bytes at rva {rva:#x} overruns section "
                    f"{sec.name!r}"
                )
        self._need(off, length)
        return self.data[off : off + length]

    def rva_to_va(self, rva: int) -> int:
        return self.image_base + rva

    @property
    def is_dll(self) -> bool:
        return bool(self.file_characteristics & IMAGE_FILE_DLL)

    @property
    def exception_directory(self) -> DataDirectory:
        if IMAGE_DIRECTORY_ENTRY_EXCEPTION >= len(self.data_directories):
            return DataDirectory(
                IMAGE_DIRECTORY_ENTRY_EXCEPTION, "Exception", 0, 0
            )
        return self.data_directories[IMAGE_DIRECTORY_ENTRY_EXCEPTION]
