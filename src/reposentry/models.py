from __future__ import annotations

from dataclasses import asdict, dataclass
from enum import StrEnum
from typing import Any


class Severity(StrEnum):
    INFO = "info"
    REVIEW = "review"
    WARNING = "warning"


@dataclass(frozen=True)
class Finding:
    rule_id: str
    severity: Severity
    title: str
    path: str
    line: int | None
    evidence: str
    recommendation: str

    def as_dict(self) -> dict[str, Any]:
        return {**asdict(self), "severity": self.severity.value}


@dataclass(frozen=True)
class RepositoryStats:
    files_scanned: int
    files_skipped: int
    bytes_scanned: int
    languages: dict[str, int]


@dataclass(frozen=True)
class Report:
    root: str
    stats: RepositoryStats
    findings: tuple[Finding, ...]

    def as_dict(self) -> dict[str, Any]:
        return {
            "root": self.root,
            "stats": asdict(self.stats),
            "findings": [finding.as_dict() for finding in self.findings],
            "disclaimer": "Static indicators require human review. RepoSentry never executes scanned code and does not determine whether software is malware.",
        }
