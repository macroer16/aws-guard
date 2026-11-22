"""Command-line entry point: `aws-guard --region eu-west-2 --output reports/`."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from rich.console import Console

from . import __version__
from .checks import CHECKS
from .models import Severity
from .report import print_terminal, write_reports
from .scanner import scan


def parse(argv: list[str] | None = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(prog="aws-guard", description="Read-only AWS security and cost scanner.")
    p.add_argument(
        "--region", default=None, help="AWS region to scan (default: your profile's region, or eu-west-2)"
    )
    p.add_argument("--profile", default=None, help="AWS named profile from ~/.aws/credentials")
    p.add_argument(
        "--output", type=Path, default=Path("aws-guard-report"), help="folder for report.html + findings.json"
    )
    p.add_argument("--checks", default=None, help=f"comma-separated subset: {','.join(CHECKS)}")
    p.add_argument(
        "--ai", action="store_true", help="add a short AI summary (sends anonymised findings only)"
    )
    p.add_argument("--demo", action="store_true", help="scan a fake account full of mistakes (no AWS needed)")
    p.add_argument(
        "--fail-on",
        choices=[s.name.lower() for s in Severity],
        default=None,
        help="exit with code 1 if any finding is at or above this severity (useful in CI)",
    )
    p.add_argument("--version", action="version", version=f"aws-guard {__version__}")
    return p.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse(argv)
    console = Console()
    only = args.checks.split(",") if args.checks else None

    if args.demo:
        from .demo import demo_session

        region = args.region or "eu-west-2"
        with demo_session(region) as session:
            result = scan(session, region, only)
    else:
        import boto3

        session = boto3.Session(profile_name=args.profile, region_name=args.region)
        region = session.region_name or "eu-west-2"
        result = scan(session, region, only)

    print_terminal(result, console)
    ai_text = None
    if args.ai:
        from .ai import summarise

        ai_text = summarise(result.sorted())
        console.print(f"\n[bold]AI summary[/]\n{ai_text}")
    html, js = write_reports(result, args.output, ai_text)
    console.print(f"\nReport: [link=file://{html.resolve()}]{html}[/] · data: {js}")

    if args.fail_on:
        threshold = Severity[args.fail_on.upper()]
        if any(f.severity >= threshold for f in result.findings):
            return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
