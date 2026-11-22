"""EBS: unencrypted volumes, unattached volumes still billing, default encryption."""

from __future__ import annotations

from ..models import Finding, Severity
from ..pricing import ebs_monthly


def run(session, region: str) -> list[Finding]:
    ec2 = session.client("ec2", region_name=region)
    findings: list[Finding] = []

    if not ec2.get_ebs_encryption_by_default().get("EbsEncryptionByDefault", False):
        findings.append(
            Finding(
                "ebs_default_encryption_off",
                "EC2.7",
                "ec2",
                Severity.MEDIUM,
                f"account ({region})",
                region,
                "EBS encryption by default is off",
                "EC2 console → Settings → EBS encryption → 'Always encrypt new EBS volumes'.",
            )
        )

    for page in ec2.get_paginator("describe_volumes").paginate():
        for v in page["Volumes"]:
            vid, size, vtype = v["VolumeId"], v["Size"], v.get("VolumeType", "gp2")
            attached = bool(v.get("Attachments"))
            if attached and not v.get("Encrypted"):
                findings.append(
                    Finding(
                        "ebs_volume_unencrypted",
                        "EC2.3",
                        "ec2",
                        Severity.MEDIUM,
                        vid,
                        region,
                        "Attached EBS volume is not encrypted",
                        "Snapshot it, copy the snapshot with encryption on, and swap in a volume made from the copy.",
                    )
                )
            if v["State"] == "available":  # created but not attached to anything
                findings.append(
                    Finding(
                        "ebs_volume_unattached",
                        None,
                        "ec2",
                        Severity.LOW,
                        vid,
                        region,
                        f"Unattached {size} GB {vtype} volume is still billing",
                        "Snapshot it if you might need the data, then delete the volume.",
                        category="cost",
                        monthly_cost=ebs_monthly(size, vtype),
                    )
                )
    return findings
