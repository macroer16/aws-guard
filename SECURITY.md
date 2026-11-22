# Security

aws-guard is built to be safe to run against a real account.

## What it can access

- **Read-only API calls only**: `List*`, `Describe*` and `Get*` on S3, EC2/EBS, IAM, RDS and STS.
  It never creates, changes, deletes, starts or stops anything. You can check: search the code for any
  call that isn't a list/describe/get — there are none.
- **Metadata only**: settings like "is this bucket public?" or "is this volume encrypted?".
  It does **not** read S3 objects, database contents or anything inside your instances.

## Credentials

- aws-guard never asks for, stores or prints credentials. It uses the standard AWS credential chain
  (environment variables, `~/.aws/credentials` profiles, SSO, or an instance role) via boto3.
- Run it as a dedicated **read-only** IAM user or role. Attach the AWS managed policies
  **SecurityAudit** and **ViewOnlyAccess**, or the minimal policy in [`iam-policy.json`](iam-policy.json).
- Never commit access keys. The `.gitignore` excludes `.env` and report folders.

## Where results go

- Results are written only to your machine: `report.html` and `findings.json` in the output folder.
  The account ID is shortened to its last 4 digits in reports.
- **`--ai` is off by default.** If you turn it on, only anonymised findings are sent to the Claude API:
  every bucket, instance, volume and user name is replaced with a placeholder like `resource-3`, and no
  account ID is sent. See `src/aws_guard/ai.py` and the test `test_anonymise_hides_resource_names`.

## Reporting a problem

Please email Victorbenson419@gmail.com rather than opening a public issue.
