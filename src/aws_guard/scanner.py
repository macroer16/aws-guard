"""Runs the checks and collects the results. A check that fails (e.g. AccessDenied) is skipped, not fatal."""

from __future__ import annotations

from botocore.exceptions import BotoCoreError, ClientError

from .checks import CHECKS
from .models import ScanResult


def scan(session, region: str, only: list[str] | None = None) -> ScanResult:
    try:
        account = session.client("sts", region_name=region).get_caller_identity()["Account"]
    except (ClientError, BotoCoreError):
        account = None
    result = ScanResult(region=region, account=account)
    for name, run in CHECKS.items():
        if only and name not in only:
            continue
        try:
            result.findings.extend(run(session, region))
        except (ClientError, BotoCoreError) as e:
            result.skipped.append(f"{name}: {e}")
    return result
