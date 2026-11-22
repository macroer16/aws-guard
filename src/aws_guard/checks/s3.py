"""S3: public buckets, Block Public Access, default encryption."""

from __future__ import annotations

from botocore.exceptions import ClientError

from ..models import Finding, Severity

PUBLIC_GROUPS = (
    "http://acs.amazonaws.com/groups/global/AllUsers",
    "http://acs.amazonaws.com/groups/global/AuthenticatedUsers",
)


def _account_bpa_on(session, region: str) -> bool:
    """True if Block Public Access is fully on for the whole account (then per-bucket settings matter less)."""
    try:
        account = session.client("sts", region_name=region).get_caller_identity()["Account"]
        cfg = session.client("s3control", region_name=region).get_public_access_block(AccountId=account)[
            "PublicAccessBlockConfiguration"
        ]
        return all(cfg.values())
    except ClientError:
        return False


def run(session, region: str) -> list[Finding]:
    s3 = session.client("s3", region_name=region)
    findings: list[Finding] = []
    account_bpa = _account_bpa_on(session, region)

    for bucket in s3.list_buckets().get("Buckets", []):
        name = bucket["Name"]

        def add(severity, control, title, fix, check, name=name):
            findings.append(Finding(check, control, "s3", severity, name, region, title, fix))

        # 1. Is the bucket public through its policy?
        try:
            if s3.get_bucket_policy_status(Bucket=name)["PolicyStatus"]["IsPublic"]:
                add(
                    Severity.CRITICAL,
                    "S3.8",
                    "Bucket is public through its bucket policy",
                    "Remove the public statement from the bucket policy and turn on Block Public Access.",
                    "s3_bucket_public_policy",
                )
        except ClientError:
            pass  # no policy at all

        # 2. Is it public through its ACL (the older way)?
        try:
            grants = s3.get_bucket_acl(Bucket=name).get("Grants", [])
            if any(g.get("Grantee", {}).get("URI") in PUBLIC_GROUPS for g in grants):
                add(
                    Severity.CRITICAL,
                    "S3.2",
                    "Bucket ACL grants access to everyone",
                    "Set the bucket ACL to private (or set Object Ownership to 'Bucket owner enforced').",
                    "s3_bucket_public_acl",
                )
        except ClientError:
            pass

        # 3. Block Public Access settings on the bucket.
        if not account_bpa:
            try:
                cfg = s3.get_public_access_block(Bucket=name)["PublicAccessBlockConfiguration"]
                off = [k for k, v in cfg.items() if not v]
            except ClientError:
                off = ["all"]
            if off:
                add(
                    Severity.MEDIUM,
                    "S3.1",
                    "Block Public Access is not fully turned on",
                    "Turn on all four Block Public Access settings (bucket or account level).",
                    "s3_block_public_access_off",
                )

        # 4. Default encryption. New buckets get SSE-S3 automatically since Jan 2023, so this is rare.
        try:
            s3.get_bucket_encryption(Bucket=name)
        except ClientError as e:
            if e.response["Error"]["Code"] == "ServerSideEncryptionConfigurationNotFoundError":
                add(
                    Severity.LOW,
                    None,
                    "No default encryption configured",
                    "Set default encryption to SSE-S3 or SSE-KMS.",
                    "s3_no_default_encryption",
                )
    return findings
