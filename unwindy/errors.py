"""Error types and diagnostic collection for unwindy.

Two tiers, matching the project contract:

* Hard non-conformance with the PE / x64-unwind spec raises an exception
  (:class:`PEFormatError` or :class:`UnwindFormatError`).
* Suspicious-but-parseable traits are recorded as :class:`Diagnostic` objects
  (severity ``WARNING``) and surfaced loudly by the front end.
"""

from __future__ import annotations

import enum
from dataclasses import dataclass, field
from typing import List, Optional


class UnwindyError(Exception):
    """Base class for every error unwindy raises."""


class PEFormatError(UnwindyError):
    """The input is not a well-formed PE64 image we can trust."""


class UnwindFormatError(UnwindyError):
    """The exception/unwind data violates the x64 unwind specification."""


class Severity(enum.IntEnum):
    INFO = 0
    WARNING = 1
    ERROR = 2

    def __str__(self) -> str:  # pragma: no cover - trivial
        return self.name


@dataclass(frozen=True)
class Diagnostic:
    """A single non-fatal finding about the binary.

    ``code`` is a short stable identifier (e.g. ``"pdata.unsorted"``) so callers
    can filter/aggregate; ``where`` is a human pointer (RVA, index, ...).
    """

    severity: Severity
    code: str
    message: str
    where: Optional[str] = None

    def __str__(self) -> str:
        loc = f" @ {self.where}" if self.where else ""
        return f"[{self.severity}] {self.code}: {self.message}{loc}"


@dataclass
class DiagnosticBag:
    """Accumulates diagnostics during parsing/analysis."""

    items: List[Diagnostic] = field(default_factory=list)

    def add(
        self,
        severity: Severity,
        code: str,
        message: str,
        where: Optional[str] = None,
    ) -> Diagnostic:
        diag = Diagnostic(severity, code, message, where)
        self.items.append(diag)
        return diag

    def warn(self, code: str, message: str, where: Optional[str] = None) -> Diagnostic:
        return self.add(Severity.WARNING, code, message, where)

    def info(self, code: str, message: str, where: Optional[str] = None) -> Diagnostic:
        return self.add(Severity.INFO, code, message, where)

    def error(self, code: str, message: str, where: Optional[str] = None) -> Diagnostic:
        return self.add(Severity.ERROR, code, message, where)

    def by_severity(self, severity: Severity) -> List[Diagnostic]:
        return [d for d in self.items if d.severity == severity]

    @property
    def warnings(self) -> List[Diagnostic]:
        return self.by_severity(Severity.WARNING)

    @property
    def errors(self) -> List[Diagnostic]:
        return self.by_severity(Severity.ERROR)

    def __len__(self) -> int:
        return len(self.items)

    def __iter__(self):
        return iter(self.items)
