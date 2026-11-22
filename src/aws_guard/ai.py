"""Optional AI summary (--ai). Sends ONLY anonymised findings to the Claude API.

No account IDs, bucket names, instance IDs or user names ever leave your machine: every resource is
replaced with a placeholder like "resource-3" before anything is sent.
"""

from __future__ import annotations

import os

from .models import Finding


def anonymise(findings: list[Finding]) -> list[dict]:
    names: dict[str, str] = {}
    out = []
    for f in findings:
        alias = names.setdefault(f.resource, f"resource-{len(names) + 1}")
        out.append(
            {
                "severity": f.severity.name,
                "control": f.control,
                "service": f.service,
                "issue": f.title,
                "fix": f.fix,
                "resource": alias,
                "monthly_cost_usd": f.monthly_cost,
            }
        )
    return out


def summarise(findings: list[Finding]) -> str:
    try:
        import anthropic
    except ImportError as e:
        raise SystemExit("The --ai flag needs the 'anthropic' package: pip install 'aws-guard[ai]'") from e
    if not os.environ.get("ANTHROPIC_API_KEY"):
        raise SystemExit("Set ANTHROPIC_API_KEY to use --ai.")
    client = anthropic.Anthropic()
    msg = client.messages.create(
        model=os.environ.get("AWS_GUARD_MODEL", "claude-sonnet-5-5"),
        max_tokens=400,
        messages=[
            {
                "role": "user",
                "content": (
                    "You are reviewing an AWS security scan for a small team. In under 120 words of plain English, "
                    "say how worried they should be, the 3 things to fix first and why, and any money being wasted. "
                    f"Findings (anonymised JSON): {anonymise(findings)}"
                ),
            }
        ],
    )
    return "".join(block.text for block in msg.content if getattr(block, "type", "") == "text")
