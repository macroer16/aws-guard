"""IAM: root MFA and keys, users without MFA, old access keys."""

from __future__ import annotations

from datetime import UTC, datetime

from botocore.exceptions import ClientError

from ..models import Finding, Severity

MAX_KEY_AGE_DAYS = 90


def run(session, region: str) -> list[Finding]:
    iam = session.client("iam", region_name=region)
    findings: list[Finding] = []

    summary = iam.get_account_summary()["SummaryMap"]
    if not summary.get("AccountMFAEnabled"):
        findings.append(
            Finding(
                "iam_root_mfa_off",
                "IAM.9",
                "iam",
                Severity.CRITICAL,
                "root account",
                "global",
                "Root account has no MFA",
                "Sign in as root and add an MFA device (a hardware key or authenticator app).",
            )
        )
    if summary.get("AccountAccessKeysPresent"):
        findings.append(
            Finding(
                "iam_root_access_key",
                "IAM.4",
                "iam",
                Severity.CRITICAL,
                "root account",
                "global",
                "Root account has an access key",
                "Delete the root access key. Use IAM users or roles for programmatic access.",
            )
        )

    now = datetime.now(UTC)
    for page in iam.get_paginator("list_users").paginate():
        for user in page["Users"]:
            name = user["UserName"]
            try:
                iam.get_login_profile(UserName=name)
                has_console = True
            except ClientError:
                has_console = False
            if has_console and not iam.list_mfa_devices(UserName=name)["MFADevices"]:
                findings.append(
                    Finding(
                        "iam_user_no_mfa",
                        "IAM.5",
                        "iam",
                        Severity.MEDIUM,
                        name,
                        "global",
                        "Console user has no MFA",
                        "Require MFA for this user (and add a policy that denies actions without MFA).",
                    )
                )
            for key in iam.list_access_keys(UserName=name)["AccessKeyMetadata"]:
                age = (now - key["CreateDate"]).days
                if key["Status"] == "Active" and age > MAX_KEY_AGE_DAYS:
                    findings.append(
                        Finding(
                            "iam_old_access_key",
                            "IAM.3",
                            "iam",
                            Severity.MEDIUM,
                            f"{name} / …{key['AccessKeyId'][-4:]}",
                            "global",
                            f"Access key is {age} days old",
                            "Create a new key, switch your apps to it, then deactivate and delete the old one.",
                        )
                    )
    return findings
