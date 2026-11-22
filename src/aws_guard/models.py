"""The Finding data model shared by every check."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import IntEnum


class Severity(IntEnum):
    """Same four levels AWS Security Hub uses. Higher number = worse."""

    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    def __str__(self) -> str:
        return self.name


@dataclass
class Finding:
    check: str  # our id, e.g. "s3_bucket_public"
    control: str | None  # AWS Security Hub FSBP control id, e.g. "S3.8" (None for cost-only checks)
    service: str  # "s3", "ec2", "iam", "rds"
    severity: Severity
    resource: str  # bucket name, volume id, user name...
    region: str
    title: str  # one line: what is wrong
    fix: str  # one line: how to fix it
    category: str = "security"  # "security" or "cost"
    monthly_cost: float | None = None  # estimated USD per month wasted, where it makes sense

    def to_dict(self) -> dict:
        d = asdict(self)
        d["severity"] = self.severity.name
        return d


@dataclass
class ScanResult:
    region: str
    account: str | None
    findings: list[Finding] = field(default_factory=list)
    skipped: list[str] = field(default_factory=list)  # checks we couldn't run (e.g. AccessDenied)

    def sorted(self) -> list[Finding]:
        """Worst first, then biggest saving."""
        return sorted(
            self.findings, key=lambda f: (-f.severity, -(f.monthly_cost or 0), f.service, f.resource)
        )
