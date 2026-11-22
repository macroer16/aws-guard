"""RDS: backups, Multi-AZ, public access, encryption."""

from __future__ import annotations

from ..models import Finding, Severity

MIN_RETENTION_DAYS = 7


def run(session, region: str) -> list[Finding]:
    rds = session.client("rds", region_name=region)
    findings: list[Finding] = []
    for page in rds.get_paginator("describe_db_instances").paginate():
        for db in page["DBInstances"]:
            name = db["DBInstanceIdentifier"]
            retention = db.get("BackupRetentionPeriod", 0)
            if retention == 0:
                findings.append(
                    Finding(
                        "rds_no_backups",
                        "RDS.11",
                        "rds",
                        Severity.MEDIUM,
                        name,
                        region,
                        "Automated backups are turned off",
                        "Set the backup retention period to at least 7 days.",
                    )
                )
            elif retention < MIN_RETENTION_DAYS:
                findings.append(
                    Finding(
                        "rds_short_retention",
                        None,
                        "rds",
                        Severity.LOW,
                        name,
                        region,
                        f"Backups are only kept for {retention} day(s)",
                        "Raise the backup retention period to 7 days or more.",
                    )
                )
            if not db.get("MultiAZ"):
                findings.append(
                    Finding(
                        "rds_single_az",
                        "RDS.5",
                        "rds",
                        Severity.MEDIUM,
                        name,
                        region,
                        "Database runs in a single Availability Zone",
                        "Enable Multi-AZ for production databases so a zone outage doesn't take it down.",
                    )
                )
            if db.get("PubliclyAccessible"):
                findings.append(
                    Finding(
                        "rds_public",
                        "RDS.2",
                        "rds",
                        Severity.CRITICAL,
                        name,
                        region,
                        "Database is publicly accessible",
                        "Set PubliclyAccessible to false and reach it from inside the VPC.",
                    )
                )
            if not db.get("StorageEncrypted"):
                findings.append(
                    Finding(
                        "rds_unencrypted",
                        "RDS.3",
                        "rds",
                        Severity.MEDIUM,
                        name,
                        region,
                        "Database storage is not encrypted",
                        "Snapshot, copy the snapshot with encryption, and restore from the encrypted copy.",
                    )
                )
    return findings
