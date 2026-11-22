"""Turns findings into a score out of 100 and a plain-English summary."""

from __future__ import annotations

from .models import Finding, Severity

# How many points each finding costs. One critical issue matters more than several low ones.
PENALTY = {Severity.CRITICAL: 20, Severity.HIGH: 10, Severity.MEDIUM: 4, Severity.LOW: 1}


def score(findings: list[Finding]) -> int:
    return max(0, 100 - sum(PENALTY[f.severity] for f in findings if f.category == "security"))


def grade(points: int) -> str:
    if points >= 90:
        return "Good"
    if points >= 70:
        return "Needs attention"
    if points >= 40:
        return "At risk"
    return "Critical"


def counts(findings: list[Finding]) -> dict[str, int]:
    out = {s.name: 0 for s in sorted(Severity, reverse=True)}
    for f in findings:
        out[f.severity.name] += 1
    return out


def summary(findings: list[Finding]) -> str:
    """A short, deterministic summary — no AI needed."""
    if not findings:
        return "No issues found by the checks that ran. Nice."
    c = counts(findings)
    waste = sum(f.monthly_cost or 0 for f in findings)
    worst = sorted(findings, key=lambda f: -f.severity)[0]
    parts = []
    serious = c["CRITICAL"] + c["HIGH"]
    if serious:
        parts.append(f"{serious} serious issue{'s' if serious != 1 else ''} to fix first")
    else:
        parts.append("no critical or high-severity issues")
    parts.append(f"{c['MEDIUM']} medium and {c['LOW']} low")
    text = f"Found {len(findings)} findings: " + ", ".join(parts) + "."
    text += f" Start with: {worst.title.lower()} ({worst.resource})."
    if waste:
        text += f" About ${waste:,.2f}/month is being spent on resources that aren't doing anything."
    return text
