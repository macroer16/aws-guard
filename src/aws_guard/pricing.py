"""Rough monthly prices used for cost estimates.

These are AWS list prices for us-east-1 (USD per GB-month for EBS). Other regions cost a bit more,
so treat every figure as an estimate. Source: https://aws.amazon.com/ebs/pricing/
"""

EBS_GB_MONTH = {
    "gp3": 0.08,
    "gp2": 0.10,
    "io1": 0.125,
    "io2": 0.125,
    "st1": 0.045,
    "sc1": 0.015,
    "standard": 0.05,
}


def ebs_monthly(size_gb: int, volume_type: str) -> float:
    return round(size_gb * EBS_GB_MONTH.get(volume_type, 0.10), 2)
