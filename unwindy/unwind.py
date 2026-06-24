"""x64 unwind-information model and decoder.

Implements the structures from the Microsoft x64 exception-handling spec:
``RUNTIME_FUNCTION``, ``UNWIND_INFO`` and the ``UNWIND_CODE`` (UWOP) array,
including chained unwind info and language-specific handler pointers.

Strict violations raise :class:`~unwindy.errors.UnwindFormatError`. Merely
suspicious traits are recorded on the supplied :class:`DiagnosticBag`.
"""

from __future__ import annotations

import enum
import struct
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, List, Optional, Set

from .errors import DiagnosticBag, UnwindFormatError
from .pe import PEFile

if TYPE_CHECKING:
    from .handlers import HandlerData
    from .trampolines import StartTrampoline

# General-purpose register encoding shared by OpInfo and FrameRegister.
GP_REGISTERS = (
    "rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi",
    "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15",
)
XMM_REGISTERS = tuple(f"xmm{i}" for i in range(16))

MAX_CHAIN_DEPTH = 32


class UnwindOp(enum.IntEnum):
    PUSH_NONVOL = 0
    ALLOC_LARGE = 1
    ALLOC_SMALL = 2
    SET_FPREG = 3
    SAVE_NONVOL = 4
    SAVE_NONVOL_FAR = 5
    EPILOG = 6  # version >= 2 (legacy SAVE_XMM in v1, deprecated)
    SPARE_CODE = 7  # version >= 2 (legacy SAVE_XMM_FAR in v1, deprecated)
    SAVE_XMM128 = 8
    SAVE_XMM128_FAR = 9
    PUSH_MACHFRAME = 10

    @property
    def uwop_name(self) -> str:
        return "UWOP_" + self.name


class UnwindFlag(enum.IntFlag):
    EHANDLER = 0x1  # has language-specific exception handler
    UHANDLER = 0x2  # has language-specific termination handler
    CHAININFO = 0x4  # this info chains to another RUNTIME_FUNCTION


def _align2(count: int) -> int:
    """Unwind-code slots are padded to an even count for 4-byte alignment of the
    trailing handler/chain ULONG."""
    return (count + 1) & ~1


@dataclass
class UnwindCode:
    """A single decoded UWOP node (possibly spanning several 2-byte slots)."""

    slot_index: int
    code_offset: int
    op: int
    op_info: int
    node_count: int
    raw: bytes
    register: Optional[str] = None
    alloc_size: Optional[int] = None
    save_offset: Optional[int] = None
    frame_offset: Optional[int] = None
    has_error_code: Optional[bool] = None
    description: str = ""

    @property
    def op_enum(self) -> Optional[UnwindOp]:
        try:
            return UnwindOp(self.op)
        except ValueError:
            return None

    @property
    def mnemonic(self) -> str:
        op = self.op_enum
        return op.uwop_name if op is not None else f"UWOP_{self.op:#x}?"


@dataclass
class RuntimeFunction:
    """A ``.pdata`` ``RUNTIME_FUNCTION`` (12 bytes) plus its resolved unwind."""

    begin_address: int
    end_address: int
    unwind_info_address: int
    index: Optional[int] = None  # position in .pdata; None for chained parents
    unwind_info: Optional["UnwindInfo"] = None
    trampoline: Optional["StartTrampoline"] = None

    @property
    def size(self) -> int:
        return self.end_address - self.begin_address


@dataclass
class UnwindInfo:
    rva: int
    version: int
    flags: int
    size_of_prolog: int
    count_of_codes: int
    frame_register: int
    frame_offset: int  # raw nibble; bytes = frame_offset * 16
    codes: List[UnwindCode] = field(default_factory=list)
    handler_rva: Optional[int] = None
    language_data_rva: Optional[int] = None
    chained_function: Optional[RuntimeFunction] = None
    struct_size: int = 0
    handler_data: Optional["HandlerData"] = None

    # -- flag helpers ---------------------------------------------------------

    @property
    def is_chained(self) -> bool:
        return bool(self.flags & UnwindFlag.CHAININFO)

    @property
    def has_exception_handler(self) -> bool:
        return bool(self.flags & UnwindFlag.EHANDLER)

    @property
    def has_termination_handler(self) -> bool:
        return bool(self.flags & UnwindFlag.UHANDLER)

    @property
    def has_handler(self) -> bool:
        return self.handler_rva is not None

    @property
    def handler_kind(self) -> Optional[str]:
        e = self.has_exception_handler
        u = self.has_termination_handler
        if e and u:
            return "exception+termination"
        if e:
            return "exception"
        if u:
            return "termination"
        return None

    def flag_names(self) -> List[str]:
        names = [f.name for f in UnwindFlag if self.flags & f]
        if not names:
            names = ["NHANDLER"]
        reserved = self.flags & ~0x7
        if reserved:
            names.append(f"RESERVED({reserved:#x})")
        return names

    # -- frame / stack helpers ------------------------------------------------

    @property
    def frame_register_name(self) -> Optional[str]:
        return GP_REGISTERS[self.frame_register] if self.frame_register else None

    @property
    def frame_offset_bytes(self) -> int:
        return self.frame_offset * 16

    @property
    def fixed_stack_alloc(self) -> int:
        """Total bytes the prolog subtracts from RSP: pushes + allocations +
        machine frame. Excludes chained-parent contributions."""
        total = 0
        for c in self.codes:
            op = c.op_enum
            if op is UnwindOp.PUSH_NONVOL:
                total += 8
            elif op in (UnwindOp.ALLOC_SMALL, UnwindOp.ALLOC_LARGE):
                total += c.alloc_size or 0
            elif op is UnwindOp.PUSH_MACHFRAME:
                total += 48 if c.has_error_code else 40
        return total


# --- decoding ---------------------------------------------------------------


def _decode_codes(
    words: List[int],
    count: int,
    version: int,
    frame_register: int,
    frame_offset: int,
    bag: DiagnosticBag,
    where: str,
) -> List[UnwindCode]:
    codes: List[UnwindCode] = []
    i = 0
    while i < count:
        w = words[i]
        code_offset = w & 0xFF
        op = (w >> 8) & 0xF
        info = (w >> 12) & 0xF

        def need(nodes: int) -> None:
            if i + nodes > count:
                raise UnwindFormatError(
                    f"{where}: UWOP {op:#x} at slot {i} needs {nodes} slots but "
                    f"only {count - i} remain (CountOfCodes={count})"
                )

        op_enum: Optional[UnwindOp]
        try:
            op_enum = UnwindOp(op)
        except ValueError:
            op_enum = None

        register: Optional[str] = None
        alloc_size: Optional[int] = None
        save_offset: Optional[int] = None
        frame_off: Optional[int] = None
        has_error_code: Optional[bool] = None
        desc: str = ""

        if op_enum is UnwindOp.PUSH_NONVOL:
            need(1)
            nodes = 1
            register = GP_REGISTERS[info]
            desc = f"push {register}"
        elif op_enum is UnwindOp.ALLOC_LARGE:
            if info == 0:
                need(2)
                nodes = 2
                alloc_size = words[i + 1] * 8
            elif info == 1:
                need(3)
                nodes = 3
                alloc_size = words[i + 1] | (words[i + 2] << 16)
            else:
                raise UnwindFormatError(
                    f"{where}: UWOP_ALLOC_LARGE has invalid OpInfo {info} "
                    f"(expected 0 or 1)"
                )
            desc = f"sub rsp, {alloc_size:#x}"
        elif op_enum is UnwindOp.ALLOC_SMALL:
            need(1)
            nodes = 1
            alloc_size = info * 8 + 8
            desc = f"sub rsp, {alloc_size:#x}"
        elif op_enum is UnwindOp.SET_FPREG:
            need(1)
            nodes = 1
            frame_off = frame_offset * 16
            fpreg = GP_REGISTERS[frame_register] if frame_register else "<unset>"
            desc = f"lea {fpreg}, [rsp+{frame_off:#x}]  (set frame pointer)"
        elif op_enum is UnwindOp.SAVE_NONVOL:
            need(2)
            nodes = 2
            register = GP_REGISTERS[info]
            save_offset = words[i + 1] * 8
            desc = f"mov [rsp+{save_offset:#x}], {register}"
        elif op_enum is UnwindOp.SAVE_NONVOL_FAR:
            need(3)
            nodes = 3
            register = GP_REGISTERS[info]
            save_offset = words[i + 1] | (words[i + 2] << 16)
            desc = f"mov [rsp+{save_offset:#x}], {register}"
        elif op_enum is UnwindOp.SAVE_XMM128:
            need(2)
            nodes = 2
            register = XMM_REGISTERS[info]
            save_offset = words[i + 1] * 16
            desc = f"movaps [rsp+{save_offset:#x}], {register}"
        elif op_enum is UnwindOp.SAVE_XMM128_FAR:
            need(3)
            nodes = 3
            register = XMM_REGISTERS[info]
            save_offset = words[i + 1] | (words[i + 2] << 16)
            desc = f"movaps [rsp+{save_offset:#x}], {register}"
        elif op_enum is UnwindOp.PUSH_MACHFRAME:
            need(1)
            nodes = 1
            if info not in (0, 1):
                bag.warn(
                    "unwind.machframe_opinfo",
                    f"UWOP_PUSH_MACHFRAME OpInfo {info} is not 0 or 1",
                    where,
                )
            has_error_code = info == 1
            extra = " with error code" if has_error_code else ""
            desc = f"push machine frame{extra}"
        elif op_enum is UnwindOp.EPILOG:
            need(2)
            nodes = 2
            if version < 2:
                bag.warn(
                    "unwind.legacy_op6",
                    "UWOP code 6 in a version-1 record (deprecated UWOP_SAVE_XMM)",
                    where,
                )
            desc = (
                f"epilog marker (offset_low={code_offset:#x}, info={info}, "
                f"data={words[i + 1]:#06x})"
            )
        elif op_enum is UnwindOp.SPARE_CODE:
            need(3)
            nodes = 3
            bag.warn(
                "unwind.spare_code",
                f"UWOP code 7 (reserved/spare) encountered (version {version})",
                where,
            )
            desc = "spare/reserved code"
        else:
            raise UnwindFormatError(
                f"{where}: unknown UWOP code {op:#x} at slot {i}"
            )

        raw = struct.pack(f"<{nodes}H", *words[i : i + nodes])
        codes.append(
            UnwindCode(
                slot_index=i,
                code_offset=code_offset,
                op=op,
                op_info=info,
                node_count=nodes,
                raw=raw,
                register=register,
                alloc_size=alloc_size,
                save_offset=save_offset,
                frame_offset=frame_off,
                has_error_code=has_error_code,
                description=desc,
            )
        )
        i += nodes
    return codes


def parse_unwind_info(
    pe: PEFile,
    rva: int,
    bag: DiagnosticBag,
    *,
    depth: int = 0,
    visited: Optional[Set[int]] = None,
) -> UnwindInfo:
    """Parse the ``UNWIND_INFO`` at ``rva`` and resolve any chain.

    Raises :class:`UnwindFormatError` on spec violations; records suspicious
    traits on ``bag``.
    """
    if visited is None:
        visited = set()
    where = f"unwind@{rva:#x}"

    if rva in visited:
        raise UnwindFormatError(
            f"{where}: cycle detected in chained unwind information"
        )
    if depth > MAX_CHAIN_DEPTH:
        raise UnwindFormatError(
            f"{where}: chained unwind depth exceeds {MAX_CHAIN_DEPTH}"
        )
    visited.add(rva)

    if rva & 0x3:
        bag.warn(
            "unwind.misaligned",
            f"UNWIND_INFO RVA {rva:#x} is not 4-byte aligned",
            where,
        )

    header = pe.read_at_rva(rva, 4)
    version_flags, size_of_prolog, count_of_codes, frame = struct.unpack(
        "<BBBB", header
    )
    version = version_flags & 0x7
    flags = version_flags >> 3
    frame_register = frame & 0xF
    frame_offset = frame >> 4

    if version == 0 or version > 3:
        raise UnwindFormatError(
            f"{where}: unsupported UNWIND_INFO version {version}"
        )
    if version == 3:
        bag.warn(
            "unwind.version3",
            "UNWIND_INFO version 3 is not formally published; decoding "
            "best-effort using the version-2 layout",
            where,
        )

    reserved = flags & ~0x7
    if reserved:
        bag.warn(
            "unwind.reserved_flags",
            f"reserved UNWIND_INFO flag bits set: {reserved:#x}",
            where,
        )

    # Read the (padded) unwind-code array.
    slot_count = _align2(count_of_codes)
    if slot_count:
        code_bytes = pe.read_at_rva(rva + 4, slot_count * 2)
        words = list(struct.unpack(f"<{slot_count}H", code_bytes))
    else:
        words = []

    codes = _decode_codes(
        words, count_of_codes, version, frame_register, frame_offset, bag, where
    )

    info = UnwindInfo(
        rva=rva,
        version=version,
        flags=flags,
        size_of_prolog=size_of_prolog,
        count_of_codes=count_of_codes,
        frame_register=frame_register,
        frame_offset=frame_offset,
        codes=codes,
    )

    # Semantic checks on frame-pointer usage.
    has_set_fpreg = any(c.op_enum is UnwindOp.SET_FPREG for c in codes)
    if has_set_fpreg and frame_register == 0:
        raise UnwindFormatError(
            f"{where}: UWOP_SET_FPREG present but FrameRegister is 0"
        )
    if frame_register == 4:  # rsp
        bag.warn(
            "unwind.frame_reg_rsp",
            "FrameRegister is rsp (4), which cannot be a frame pointer",
            where,
        )
    if frame_register != 0 and not has_set_fpreg and not (flags & UnwindFlag.CHAININFO):
        bag.warn(
            "unwind.frame_reg_unused",
            f"FrameRegister {GP_REGISTERS[frame_register]} declared but no "
            f"UWOP_SET_FPREG establishes it",
            where,
        )

    # Code offsets must fall inside the prolog.
    for c in codes:
        if c.code_offset > size_of_prolog:
            bag.warn(
                "unwind.code_after_prolog",
                f"{c.mnemonic} CodeOffset {c.code_offset:#x} exceeds "
                f"SizeOfProlog {size_of_prolog:#x}",
                where,
            )

    tail_rva = rva + 4 + slot_count * 2
    info.struct_size = 4 + slot_count * 2

    if flags & UnwindFlag.CHAININFO:
        if flags & (UnwindFlag.EHANDLER | UnwindFlag.UHANDLER):
            bag.warn(
                "unwind.chain_with_handler",
                "CHAININFO set together with a handler flag; the trailing slot "
                "is interpreted as a chained RUNTIME_FUNCTION",
                where,
            )
        rf_bytes = pe.read_at_rva(tail_rva, 12)
        begin, end, child_unwind = struct.unpack("<III", rf_bytes)
        info.struct_size += 12
        child = RuntimeFunction(
            begin_address=begin,
            end_address=end,
            unwind_info_address=child_unwind,
        )
        child.unwind_info = parse_unwind_info(
            pe, child_unwind, bag, depth=depth + 1, visited=visited
        )
        info.chained_function = child
    elif flags & (UnwindFlag.EHANDLER | UnwindFlag.UHANDLER):
        handler_bytes = pe.read_at_rva(tail_rva, 4)
        info.handler_rva = struct.unpack("<I", handler_bytes)[0]
        info.language_data_rva = tail_rva + 4
        info.struct_size += 4
        if info.handler_rva == 0:
            bag.warn(
                "unwind.null_handler",
                "handler flag set but handler RVA is 0",
                where,
            )

    return info
