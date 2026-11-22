from conftest import REGION, ids

from aws_guard.checks import rds


def _db(session, **kw):
    session.client("rds").create_db_instance(
        DBInstanceIdentifier=kw.pop("name", "db"),
        DBInstanceClass="db.t3.micro",
        Engine="postgres",
        MasterUsername="app",
        MasterUserPassword="example-only",
        AllocatedStorage=20,
        **kw,
    )


def test_risky_database(session):
    _db(session, BackupRetentionPeriod=0, MultiAZ=False, PubliclyAccessible=True, StorageEncrypted=False)
    assert ids(rds.run(session, REGION)) == [
        "rds_no_backups",
        "rds_public",
        "rds_single_az",
        "rds_unencrypted",
    ]


def test_well_configured_database(session):
    _db(session, BackupRetentionPeriod=14, MultiAZ=True, PubliclyAccessible=False, StorageEncrypted=True)
    assert rds.run(session, REGION) == []
