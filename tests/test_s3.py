import json

from conftest import REGION, ids

from aws_guard.checks import s3

LOC = {"CreateBucketConfiguration": {"LocationConstraint": REGION}}
ALL_ON = {
    "BlockPublicAcls": True,
    "IgnorePublicAcls": True,
    "BlockPublicPolicy": True,
    "RestrictPublicBuckets": True,
}


def test_private_locked_bucket_is_clean(session):
    c = session.client("s3")
    c.create_bucket(Bucket="safe", **LOC)
    c.put_public_access_block(Bucket="safe", PublicAccessBlockConfiguration=ALL_ON)
    c.put_bucket_encryption(
        Bucket="safe",
        ServerSideEncryptionConfiguration={
            "Rules": [{"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "AES256"}}]
        },
    )
    assert s3.run(session, REGION) == []


def test_public_policy_is_critical(session):
    c = session.client("s3")
    c.create_bucket(Bucket="leaky", **LOC)
    c.put_bucket_policy(
        Bucket="leaky",
        Policy=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Principal": "*",
                        "Action": "s3:GetObject",
                        "Resource": "arn:aws:s3:::leaky/*",
                    }
                ],
            }
        ),
    )
    found = s3.run(session, REGION)
    assert "s3_bucket_public_policy" in ids(found)
    assert any(f.control == "S3.8" and f.severity.name == "CRITICAL" for f in found)


def test_public_acl_detected(session):
    c = session.client("s3")
    c.create_bucket(Bucket="old-style", ACL="public-read", **LOC)
    assert "s3_bucket_public_acl" in ids(s3.run(session, REGION))


def test_block_public_access_missing(session):
    session.client("s3").create_bucket(Bucket="no-bpa", **LOC)
    assert "s3_block_public_access_off" in ids(s3.run(session, REGION))
