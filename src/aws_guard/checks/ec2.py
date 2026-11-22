"""EC2: stopped instances still paying for disks, old generations, IMDSv2."""

from __future__ import annotations

from ..models import Finding, Severity
from ..pricing import ebs_monthly

# Instance families that have a newer, cheaper generation available.
OLD_FAMILIES = {"t1", "t2", "m1", "m2", "m3", "m4", "c1", "c3", "c4", "r3", "r4", "i2", "d2", "g2", "x1"}


def run(session, region: str) -> list[Finding]:
    ec2 = session.client("ec2", region_name=region)
    findings: list[Finding] = []

    # Volume sizes so we can price the disks of stopped instances.
    volumes = {}
    for page in ec2.get_paginator("describe_volumes").paginate():
        for v in page["Volumes"]:
            volumes[v["VolumeId"]] = (v["Size"], v.get("VolumeType", "gp2"))

    for page in ec2.get_paginator("describe_instances").paginate():
        for res in page["Reservations"]:
            for i in res["Instances"]:
                iid, itype, state = i["InstanceId"], i["InstanceType"], i["State"]["Name"]
                if state == "terminated":
                    continue

                if state == "stopped":
                    cost = sum(
                        ebs_monthly(*volumes[m["Ebs"]["VolumeId"]])
                        for m in i.get("BlockDeviceMappings", [])
                        if "Ebs" in m and m["Ebs"]["VolumeId"] in volumes
                    )
                    findings.append(
                        Finding(
                            "ec2_stopped_instance",
                            "EC2.4",
                            "ec2",
                            Severity.MEDIUM,
                            iid,
                            region,
                            "Stopped instance is still paying for its disks",
                            "If it's no longer needed, snapshot the volumes and terminate it.",
                            category="cost",
                            monthly_cost=round(cost, 2) or None,
                        )
                    )

                family = itype.split(".")[0]
                if family in OLD_FAMILIES:
                    findings.append(
                        Finding(
                            "ec2_old_generation",
                            None,
                            "ec2",
                            Severity.LOW,
                            iid,
                            region,
                            f"Old-generation instance type ({itype})",
                            "Move to the current generation (e.g. t3/t4g, m7g) — usually faster and cheaper.",
                            category="cost",
                        )
                    )

                if state == "running" and i.get("MetadataOptions", {}).get("HttpTokens") != "required":
                    findings.append(
                        Finding(
                            "ec2_imdsv1_allowed",
                            "EC2.8",
                            "ec2",
                            Severity.HIGH,
                            iid,
                            region,
                            "Instance still allows IMDSv1",
                            "Require IMDSv2: modify-instance-metadata-options --http-tokens required.",
                        )
                    )
    return findings
