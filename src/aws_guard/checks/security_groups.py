"""Security groups open to the whole internet on dangerous ports."""

from __future__ import annotations

from ..models import Finding, Severity

OPEN = ("0.0.0.0/0", "::/0")
# Database and admin ports that should never be open to the internet (from AWS control EC2.19).
HIGH_RISK = {
    20,
    21,
    23,
    25,
    110,
    135,
    143,
    445,
    1433,
    1434,
    3000,
    3306,
    4333,
    5000,
    5432,
    5500,
    5601,
    8080,
    8088,
    8888,
    9200,
    9300,
    27017,
}


def _is_open(rule: dict) -> bool:
    return any(r.get("CidrIp") in OPEN for r in rule.get("IpRanges", [])) or any(
        r.get("CidrIpv6") in OPEN for r in rule.get("Ipv6Ranges", [])
    )


def _covers(rule: dict, port: int) -> bool:
    if rule.get("IpProtocol") == "-1":
        return True
    lo, hi = rule.get("FromPort"), rule.get("ToPort")
    return lo is not None and hi is not None and lo <= port <= hi


def run(session, region: str) -> list[Finding]:
    ec2 = session.client("ec2", region_name=region)
    findings: list[Finding] = []
    for page in ec2.get_paginator("describe_security_groups").paginate():
        for sg in page["SecurityGroups"]:
            gid = f"{sg['GroupId']} ({sg.get('GroupName', '')})"
            for rule in sg.get("IpPermissions", []):
                if not _is_open(rule):
                    continue
                if rule.get("IpProtocol") == "-1":
                    findings.append(
                        Finding(
                            "sg_all_traffic_open",
                            "EC2.19",
                            "ec2",
                            Severity.CRITICAL,
                            gid,
                            region,
                            "All ports are open to the internet",
                            "Delete this rule and allow only the ports you need, from known IP ranges.",
                        )
                    )
                    continue
                if _covers(rule, 22):
                    findings.append(
                        Finding(
                            "sg_ssh_open",
                            "EC2.13",
                            "ec2",
                            Severity.HIGH,
                            gid,
                            region,
                            "SSH (22) is open to the internet",
                            "Limit SSH to your own IP, or use SSM Session Manager and close port 22.",
                        )
                    )
                if _covers(rule, 3389):
                    findings.append(
                        Finding(
                            "sg_rdp_open",
                            "EC2.14",
                            "ec2",
                            Severity.HIGH,
                            gid,
                            region,
                            "RDP (3389) is open to the internet",
                            "Limit RDP to your own IP, or use Fleet Manager / a bastion host.",
                        )
                    )
                risky = sorted(p for p in HIGH_RISK if _covers(rule, p))
                if risky:
                    findings.append(
                        Finding(
                            "sg_high_risk_port_open",
                            "EC2.19",
                            "ec2",
                            Severity.CRITICAL,
                            gid,
                            region,
                            f"High-risk port(s) open to the internet: {', '.join(map(str, risky[:5]))}",
                            "Close these ports to 0.0.0.0/0; databases should only be reachable inside the VPC.",
                        )
                    )
    return findings
