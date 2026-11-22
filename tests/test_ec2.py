from datetime import UTC, datetime, timedelta

from conftest import REGION, ids

from aws_guard.checks import ebs, ec2, iam, security_groups


def _ami(c):
    return c.describe_images(Owners=["amazon"])["Images"][0]["ImageId"]


def test_unattached_volume_priced(session):
    c = session.client("ec2")
    c.create_volume(AvailabilityZone=f"{REGION}a", Size=100, VolumeType="gp3", Encrypted=True)
    found = [f for f in ebs.run(session, REGION) if f.check == "ebs_volume_unattached"]
    assert len(found) == 1 and found[0].monthly_cost == 8.0 and found[0].category == "cost"


def test_default_encryption_off_then_on(session):
    c = session.client("ec2")
    assert "ebs_default_encryption_off" in ids(ebs.run(session, REGION))
    c.enable_ebs_encryption_by_default()
    assert "ebs_default_encryption_off" not in ids(ebs.run(session, REGION))


def test_ssh_open_is_high_and_restricted_is_clean(session):
    c = session.client("ec2")
    open_sg = c.create_security_group(GroupName="open", Description="x")["GroupId"]
    c.authorize_security_group_ingress(
        GroupId=open_sg,
        IpPermissions=[
            {"IpProtocol": "tcp", "FromPort": 22, "ToPort": 22, "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}
        ],
    )
    safe_sg = c.create_security_group(GroupName="safe", Description="x")["GroupId"]
    c.authorize_security_group_ingress(
        GroupId=safe_sg,
        IpPermissions=[
            {"IpProtocol": "tcp", "FromPort": 22, "ToPort": 22, "IpRanges": [{"CidrIp": "203.0.113.7/32"}]}
        ],
    )
    found = security_groups.run(session, REGION)
    ssh = [f for f in found if f.check == "sg_ssh_open"]
    assert len(ssh) == 1 and open_sg in ssh[0].resource and ssh[0].control == "EC2.13"


def test_all_traffic_open_is_critical(session):
    c = session.client("ec2")
    sg = c.create_security_group(GroupName="wide", Description="x")["GroupId"]
    c.authorize_security_group_ingress(
        GroupId=sg, IpPermissions=[{"IpProtocol": "-1", "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}]
    )
    assert "sg_all_traffic_open" in ids(security_groups.run(session, REGION))


def test_stopped_old_instance(session):
    c = session.client("ec2")
    i = c.run_instances(ImageId=_ami(c), MinCount=1, MaxCount=1, InstanceType="m4.large")["Instances"][0]
    c.stop_instances(InstanceIds=[i["InstanceId"]])
    found = ids(ec2.run(session, REGION))
    assert "ec2_stopped_instance" in found and "ec2_old_generation" in found


def test_imdsv2_required_is_clean(session):
    c = session.client("ec2")
    i = c.run_instances(ImageId=_ami(c), MinCount=1, MaxCount=1, InstanceType="t3.micro")["Instances"][0]
    c.modify_instance_metadata_options(InstanceId=i["InstanceId"], HttpTokens="required")
    assert "ec2_imdsv1_allowed" not in ids(ec2.run(session, REGION))


def test_iam_user_without_mfa_and_old_key(session, monkeypatch):
    c = session.client("iam")
    c.create_user(UserName="sam")
    c.create_login_profile(UserName="sam", Password="Example-only-1!")
    c.create_access_key(UserName="sam")
    # Pretend it's 100 days in the future so the key counts as old.
    future = datetime.now(UTC) + timedelta(days=100)
    monkeypatch.setattr(iam, "datetime", type("D", (), {"now": staticmethod(lambda tz=None: future)}))
    found = ids(iam.run(session, REGION))
    assert "iam_user_no_mfa" in found and "iam_old_access_key" in found
