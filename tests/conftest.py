import os

import boto3
import pytest
from moto import mock_aws

REGION = "eu-west-2"


@pytest.fixture
def session():
    """A boto3 session against an empty, in-memory fake AWS account."""
    os.environ["AWS_ACCESS_KEY_ID"] = "testing"
    os.environ["AWS_SECRET_ACCESS_KEY"] = "testing"
    with mock_aws():
        yield boto3.Session(region_name=REGION)


def ids(findings):
    return sorted(f.check for f in findings)
