"""Every check module exposes run(session, region) -> list[Finding].

Checks only call read-only APIs: List*, Describe*, Get*.
"""

from . import ebs, ec2, iam, rds, s3, security_groups

CHECKS = {
    "s3": s3.run,
    "ebs": ebs.run,
    "ec2": ec2.run,
    "security_groups": security_groups.run,
    "iam": iam.run,
    "rds": rds.run,
}
