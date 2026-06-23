"""Minimal synthetic PE64 + UNWIND_INFO builder for deterministic tests.

Produces just enough of a well-formed x64 PE image for :mod:`unwindy` to parse,
with full control over the section table, the exception directory and the
contents of every ``RUNTIME_FUNCTION`` / ``UNWIND_INFO``.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass
from typing import List, Optional, Sequence, Tuple

IMAGE_SCN_CNT_CODE = 0x00000020
IMAGE_SCN_MEM_EXECUTE = 0x20000000
IMAGE_SCN_MEM_READ = 0x40000000
IMAGE_SCN_MEM_WRITE = 0x80000000

CODE_PERMS = IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ
RDATA_PERMS = IMAGE_SCN_MEM_READ

FILE_ALIGN = 0x200
SECT_ALIGN = 0x1000
IMAGE_BASE = 0x140000000


def _align(value: int, alignment: int) -> int:
    return (value + alignment - 1) // alignment * alignment


# --- unwind-code slot encoders ---------------------------------------------
# Each returns a list of u16 slot words.


def push_nonvol(off: int, reg: int) -> List[int]:
    return [off | (0 << 8) | (reg << 12)]


def alloc_small(off: int, size: int) -> List[int]:
    assert 8 <= size <= 128 and size % 8 == 0
    info = (size // 8) - 1
    return [off | (2 << 8) | (info << 12)]


def alloc_large(off: int, size: int) -> List[int]:
    if size % 8 == 0 and size < 512 * 1024:
        return [off | (1 << 8) | (0 << 12), size // 8]
    return [off | (1 << 8) | (1 << 12), size & 0xFFFF, (size >> 16) & 0xFFFF]


def set_fpreg(off: int) -> List[int]:
    return [off | (3 << 8) | (0 << 12)]


def save_nonvol(off: int, reg: int, offset: int) -> List[int]:
    return [off | (4 << 8) | (reg << 12), offset // 8]


def save_nonvol_far(off: int, reg: int, offset: int) -> List[int]:
    return [off | (5 << 8) | (reg << 12), offset & 0xFFFF, (offset >> 16) & 0xFFFF]


def save_xmm128(off: int, reg: int, offset: int) -> List[int]:
    return [off | (8 << 8) | (reg << 12), offset // 16]


def save_xmm128_far(off: int, reg: int, offset: int) -> List[int]:
    return [off | (9 << 8) | (reg << 12), offset & 0xFFFF, (offset >> 16) & 0xFFFF]


def push_machframe(off: int, error_code: bool) -> List[int]:
    return [off | (10 << 8) | ((1 if error_code else 0) << 12)]


def raw_slot(off: int, op: int, info: int) -> List[int]:
    return [off | ((op & 0xF) << 8) | ((info & 0xF) << 12)]


def encode_unwind_info(
    *,
    version: int = 1,
    flags: int = 0,
    prolog: int = 0,
    frame_register: int = 0,
    frame_offset: int = 0,
    code_words: Sequence[int] = (),
    count_override: Optional[int] = None,
    handler_rva: Optional[int] = None,
    chain: Optional[Tuple[int, int, int]] = None,
    lang_data: bytes = b"",
) -> bytes:
    code_words = list(code_words)
    count = count_override if count_override is not None else len(code_words)
    frame = (frame_register & 0xF) | ((frame_offset & 0xF) << 4)
    hdr = bytes(
        [
            (version & 0x7) | ((flags & 0x1F) << 3),
            prolog & 0xFF,
            count & 0xFF,
            frame,
        ]
    )
    body = b"".join(struct.pack("<H", w & 0xFFFF) for w in code_words)
    if len(code_words) % 2:
        body += b"\x00\x00"
    tail = b""
    if chain is not None:
        tail = struct.pack("<III", *chain)
    elif handler_rva is not None:
        tail = struct.pack("<I", handler_rva) + lang_data
    return hdr + body + tail


def encode_runtime_function(begin: int, end: int, unwind: int) -> bytes:
    return struct.pack("<III", begin, end, unwind)


@dataclass
class _Sect:
    name: str
    rva: int
    data: bytes
    chars: int
    virtual_size: Optional[int] = None


class PEBuilder:
    """Assemble a synthetic PE64 image."""

    def __init__(self, *, machine: int = 0x8664, opt_magic: int = 0x20B) -> None:
        self.sections: List[_Sect] = []
        self.exc_rva = 0
        self.exc_size = 0
        self.machine = machine
        self.opt_magic = opt_magic
        self.number_of_rva_and_sizes = 16

    def add_section(
        self,
        name: str,
        rva: int,
        data: bytes,
        chars: int,
        *,
        virtual_size: Optional[int] = None,
    ) -> "PEBuilder":
        self.sections.append(_Sect(name, rva, data, chars, virtual_size))
        return self

    def set_exception_dir(self, rva: int, size: int) -> "PEBuilder":
        self.exc_rva = rva
        self.exc_size = size
        return self

    def build(self) -> bytes:
        e_lfanew = 0x80
        n = len(self.sections)
        opt_size = 240
        headers_end = e_lfanew + 4 + 20 + opt_size + 40 * n
        size_of_headers = _align(headers_end, FILE_ALIGN)

        # Assign raw pointers sequentially.
        raw_ptr = size_of_headers
        raw_ptrs: List[int] = []
        for s in self.sections:
            raw_ptrs.append(raw_ptr)
            raw_ptr += _align(len(s.data), FILE_ALIGN)
        total_raw = raw_ptr

        size_of_image = SECT_ALIGN
        for s in self.sections:
            vsize = s.virtual_size if s.virtual_size is not None else len(s.data)
            size_of_image = max(size_of_image, _align(s.rva + vsize, SECT_ALIGN))

        buf = bytearray(total_raw)

        # DOS header
        buf[0:2] = b"MZ"
        struct.pack_into("<I", buf, 0x3C, e_lfanew)

        # NT signature + file header
        struct.pack_into("<I", buf, e_lfanew, 0x00004550)
        fh = e_lfanew + 4
        struct.pack_into(
            "<HHIIIHH",
            buf,
            fh,
            self.machine,  # Machine
            n,  # NumberOfSections
            0,  # TimeDateStamp
            0,  # PointerToSymbolTable
            0,  # NumberOfSymbols
            opt_size,  # SizeOfOptionalHeader
            0x22,  # Characteristics (EXECUTABLE | LARGE_ADDRESS_AWARE)
        )

        opt = fh + 20
        struct.pack_into("<H", buf, opt, self.opt_magic)  # Magic
        struct.pack_into("<I", buf, opt + 16, 0x1000)  # AddressOfEntryPoint
        struct.pack_into("<I", buf, opt + 20, 0x1000)  # BaseOfCode
        struct.pack_into("<Q", buf, opt + 24, IMAGE_BASE)  # ImageBase
        struct.pack_into("<I", buf, opt + 32, SECT_ALIGN)  # SectionAlignment
        struct.pack_into("<I", buf, opt + 36, FILE_ALIGN)  # FileAlignment
        struct.pack_into("<I", buf, opt + 56, size_of_image)  # SizeOfImage
        struct.pack_into("<I", buf, opt + 60, size_of_headers)  # SizeOfHeaders
        struct.pack_into("<H", buf, opt + 68, 3)  # Subsystem = console
        struct.pack_into(
            "<I", buf, opt + 108, self.number_of_rva_and_sizes
        )  # NumberOfRvaAndSizes

        # Data directory [3] = exception
        dd = opt + 112
        struct.pack_into("<II", buf, dd + 3 * 8, self.exc_rva, self.exc_size)

        # Section headers
        sh = opt + opt_size
        for i, s in enumerate(self.sections):
            base = sh + i * 40
            raw_name = s.name.encode("latin-1")[:8].ljust(8, b"\x00")
            buf[base : base + 8] = raw_name
            vsize = s.virtual_size if s.virtual_size is not None else len(s.data)
            struct.pack_into(
                "<IIII",
                buf,
                base + 8,
                vsize,  # VirtualSize
                s.rva,  # VirtualAddress
                _align(len(s.data), FILE_ALIGN),  # SizeOfRawData
                raw_ptrs[i],  # PointerToRawData
            )
            struct.pack_into("<I", buf, base + 36, s.chars)

        # Section raw data
        for i, s in enumerate(self.sections):
            buf[raw_ptrs[i] : raw_ptrs[i] + len(s.data)] = s.data

        return bytes(buf)


def simple_image(
    runtime_functions: bytes,
    xdata: bytes,
    *,
    xdata_rva: int = 0x4000,
    text_size: int = 0x2000,
) -> bytes:
    """Build an image with .text/.pdata/.xdata laid out canonically.

    ``runtime_functions`` are placed in .pdata at rva 0x3000; ``xdata`` is placed
    in .xdata (read-only) at ``xdata_rva``. The exception directory points at the
    whole .pdata blob.
    """
    b = PEBuilder()
    b.add_section(".text", 0x1000, b"\xcc" * text_size, CODE_PERMS)
    b.add_section(".pdata", 0x3000, runtime_functions, RDATA_PERMS)
    b.add_section(".xdata", xdata_rva, xdata, RDATA_PERMS)
    b.set_exception_dir(0x3000, len(runtime_functions))
    return b.build()
