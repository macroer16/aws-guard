"""Output: a rich table in the terminal, report.html and findings.json."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

from jinja2 import Environment, PackageLoader, select_autoescape
from rich.console import Console
from rich.table import Table

from . import __version__
from .models import ScanResult, Severity
from .scoring import counts, grade, score, summary

COLOURS = {
    Severity.CRITICAL: "bold white on red",
    Severity.HIGH: "bold red",
    Severity.MEDIUM: "yellow",
    Severity.LOW: "cyan",
}


def print_terminal(result: ScanResult, console: Console | None = None) -> None:
    console = console or Console()
    findings = result.sorted()
    pts = score(findings)
    console.print()
    console.print(
        f"[bold]aws-guard[/] · region [bold]{result.region}[/]"
        + (f" · account …{result.account[-4:]}" if result.account else "")
    )
    table = Table(show_lines=False, header_style="bold", expand=True)
    for col, kw in [
        ("Severity", {"no_wrap": True}),
        ("Control", {"no_wrap": True}),
        ("Resource", {}),
        ("Finding", {}),
        ("$/month", {"justify": "right", "no_wrap": True}),
    ]:
        table.add_column(col, **kw)
    for f in findings:
        table.add_row(
            f"[{COLOURS[f.severity]}] {f.severity.name} [/]",
            f.control or "—",
            f.resource,
            f.title,
            f"{f.monthly_cost:,.2f}" if f.monthly_cost else "",
        )
    console.print(table)
    c = counts(findings)
    waste = sum(f.monthly_cost or 0 for f in findings)
    console.print(
        f"Score [bold]{pts}/100[/] ({grade(pts)}) · "
        + " · ".join(f"{k.lower()} {v}" for k, v in c.items())
        + (f" · ~${waste:,.2f}/month waste" if waste else "")
    )
    console.print(summary(findings), style="dim")
    for s in result.skipped:
        console.print(f"[yellow]skipped[/] {s}")


def write_reports(result: ScanResult, out_dir: Path, ai_text: str | None = None) -> tuple[Path, Path]:
    out_dir.mkdir(parents=True, exist_ok=True)
    findings = result.sorted()
    env = Environment(loader=PackageLoader("aws_guard", "templates"), autoescape=select_autoescape())
    html = env.get_template("report.html.j2").render(
        result=result,
        findings=findings,
        score=score(findings),
        grade=grade(score(findings)),
        counts=counts(findings),
        summary=summary(findings),
        ai_text=ai_text,
        waste=sum(f.monthly_cost or 0 for f in findings),
        generated=datetime.now(UTC).strftime("%d %b %Y, %H:%M UTC"),
        version=__version__,
    )
    html_path = out_dir / "report.html"
    html_path.write_text(html, encoding="utf-8")
    json_path = out_dir / "findings.json"
    json_path.write_text(
        json.dumps(
            {
                "region": result.region,
                "score": score(findings),
                "findings": [f.to_dict() for f in findings],
                "skipped": result.skipped,
            },
            indent=2,
        ),
        encoding="utf-8",
    )
    return html_path, json_path
