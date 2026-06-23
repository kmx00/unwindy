"""unwindy - a slim, dependency-free PE64 x64 exception/unwind viewer.

Public API::

    from unwindy import PEFile, analyze

    pe = PEFile.from_path("foo.exe")
    analysis = analyze(pe)
    for func in analysis.functions:
        ...
"""

from __future__ import annotations

from .analyzer import Analysis, analyze
from .errors import (
    Diagnostic,
    DiagnosticBag,
    PEFormatError,
    Severity,
    UnwindFormatError,
    UnwindyError,
)
from .handlers import (
    CxxFuncInfo,
    Fh4Info,
    GsData,
    HandlerData,
    ImportResolver,
    ScopeRecord,
    decode_handlers,
)
from .pe import DataDirectory, PEFile, Section
from .unwind import (
    RuntimeFunction,
    UnwindCode,
    UnwindFlag,
    UnwindInfo,
    UnwindOp,
    parse_unwind_info,
)

__version__ = "0.0.4"

__all__ = [
    "__version__",
    "Analysis",
    "analyze",
    "PEFile",
    "Section",
    "DataDirectory",
    "RuntimeFunction",
    "UnwindInfo",
    "UnwindCode",
    "UnwindOp",
    "UnwindFlag",
    "parse_unwind_info",
    "HandlerData",
    "ScopeRecord",
    "GsData",
    "CxxFuncInfo",
    "Fh4Info",
    "ImportResolver",
    "decode_handlers",
    "Diagnostic",
    "DiagnosticBag",
    "Severity",
    "UnwindyError",
    "PEFormatError",
    "UnwindFormatError",
]
