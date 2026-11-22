"""--demo: builds a fake AWS account full of common mistakes (using moto) and scans it.

Lets anyone try aws-guard without an AWS account.
"""

from __future__ import annotations

import json
import os
from contextlib import contextmanager


@contextmanager
def demo_session(region: str):
    try:
        from moto import mock_aws
    except ImportError as e:
        raise SystemExit("Demo mode needs moto: pip install 'aws-guard[demo]'") from e
    import boto3

    for k in ("AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY"):
        os.environ[k] = "testing"  # fake credentials for the in-memory mock only
    with mock_aws():
        session = boto3.Session(region_name=region)
        seed(session, region)
        yield session


def seed(session, region: str) -> None:
    s3 = session.client("s3", region_name=region)
    loc = {"CreateBucketConfiguration": {"LocationConstraint": region}} if region != "us-east-1" else {}
    s3.create_bucket(Bucket="acme-public-assets", **loc)
    s3.put_bucket_policy(
        Bucket="acme-public-assets",
        Policy=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Principal": "*",
                        "Action": "s3:GetObject",
                        "Resource": "arn:aws:s3:::acme-public-assets/*",
                    }
                ],
            }
        ),
    )
    s3.create_bucket(Bucket="acme-backups", **loc)
    s3.put_public_access_block(
        Bucket="acme-backups",
        PublicAccessBlockConfiguration={
            "BlockPublicAcls": True,
            "IgnorePublicAcls": True,
            "BlockPublicPolicy": True,
            "RestrictPublicBuckets": True,
        },
    )

    ec2 = session.client("ec2", region_name=region)
    az = f"{region}a"
    ec2.create_volume(AvailabilityZone=az, Size=200, VolumeType="gp2")  # forgotten, unattached
    ec2.create_volume(AvailabilityZone=az, Size=50, VolumeType="gp3", Encrypted=True)
    ami = ec2.describe_images(Owners=["amazon"])["Images"][0]["ImageId"]
    web = ec2.run_instances(ImageId=ami, MinCount=1, MaxCount=1, InstanceType="t2.micro")["Instances"][0]
    old = ec2.run_instances(ImageId=ami, MinCount=1, MaxCount=1, InstanceType="m4.large")["Instances"][0]
    ec2.stop_instances(InstanceIds=[old["InstanceId"]])
    ec2.modify_instance_metadata_options(InstanceId=web["InstanceId"], HttpTokens="optional")
    sg = ec2.create_security_group(GroupName="web-debug", Description="temporary")["GroupId"]
    ec2.authorize_security_group_ingress(
        GroupId=sg,
        IpPermissions=[
            {"IpProtocol": "tcp", "FromPort": 22, "ToPort": 22, "IpRanges": [{"CidrIp": "0.0.0.0/0"}]},
            {"IpProtocol": "tcp", "FromPort": 3306, "ToPort": 3306, "IpRanges": [{"CidrIp": "0.0.0.0/0"}]},
        ],
    )

    iam = session.client("iam", region_name=region)
    iam.create_user(UserName="intern-sam")
    iam.create_login_profile(UserName="intern-sam", Password="Example-only-1!")
    iam.create_access_key(UserName="intern-sam")

    rds = session.client("rds", region_name=region)
    rds.create_db_instance(
        DBInstanceIdentifier="orders-db",
        DBInstanceClass="db.t3.micro",
        Engine="postgres",
        MasterUsername="app",
        MasterUserPassword="example-only",
        AllocatedStorage=20,
        BackupRetentionPeriod=0,
        MultiAZ=False,
        PubliclyAccessible=True,
        StorageEncrypted=False,
    )
