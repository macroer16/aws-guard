# Research

Before writing code I looked at how existing tools find and present AWS risks.

## Tools studied

- **Devopsly** (main model) — read-only AWS monitoring. Checks public/unencrypted S3, unencrypted EBS, databases without
  backups, single-AZ databases, unattached volumes and stopped instances still billing, and old instance types. Ranks
  fixes by severity and estimated monthly saving; deterministic checks find the issues and AI only writes the summary.
  Credentials stay out of the AI's reach.
- **Prowler** (open source) — hundreds of checks mapped to compliance frameworks (CIS, PCI, HIPAA); checks named
  `service_resource_issue`; severity per check; HTML/CSV/JSON output; can fail a CI pipeline on severity.
- **AWS Security Hub — Foundational Security Best Practices (FSBP)** — AWS's own control IDs and severities,
  e.g. EC2.13 (SSH open, HIGH), IAM.9 (root MFA, CRITICAL), S3.8 (public bucket, HIGH), RDS.11 (backups, MEDIUM).
- **ScoutSuite / Trusted Advisor** — multi-service read-only audits, findings grouped by service.

## What aws-guard copies

| Idea | From | In aws-guard |
| --- | --- | --- |
| Read-only, metadata only | Devopsly | Only List/Describe/Get calls; see SECURITY.md |
| Rank by severity, then money | Devopsly | Table and report sorted worst-first, then biggest saving |
| Map to a real standard | Prowler, Security Hub | Every security check shows its FSBP control ID and uses AWS's severity |
| Check naming | Prowler | `s3_bucket_public_policy`, `sg_ssh_open`, `iam_root_mfa_off` … |
| AI explains, code decides | Devopsly | Findings come from deterministic checks; `--ai` only summarises anonymised findings |
| Machine-readable output + CI gate | Prowler | `findings.json` and `--fail-on high` |

## Checks

| Check | Control | Severity |
| --- | --- | --- |
| Bucket public via policy | S3.8 | CRITICAL |
| Bucket ACL grants everyone | S3.2 | CRITICAL |
| Block Public Access not fully on | S3.1 | MEDIUM |
| No default bucket encryption | — | LOW |
| EBS encryption by default off | EC2.7 | MEDIUM |
| Attached EBS volume unencrypted | EC2.3 | MEDIUM |
| Unattached EBS volume still billing | cost | LOW + $/month |
| Stopped instance still paying for disks | EC2.4 | MEDIUM + $/month |
| Old-generation instance type | cost | LOW |
| IMDSv1 allowed | EC2.8 | HIGH |
| All traffic open to the internet | EC2.19 | CRITICAL |
| High-risk port (DB/admin) open | EC2.19 | CRITICAL |
| SSH open to 0.0.0.0/0 | EC2.13 | HIGH |
| RDP open to 0.0.0.0/0 | EC2.14 | HIGH |
| Root account without MFA | IAM.9 | CRITICAL |
| Root access key exists | IAM.4 | CRITICAL |
| Console user without MFA | IAM.5 | MEDIUM |
| Access key older than 90 days | IAM.3 | MEDIUM |
| RDS automated backups off | RDS.11 | MEDIUM |
| RDS single-AZ | RDS.5 | MEDIUM |
| RDS publicly accessible | RDS.2 | CRITICAL |
| RDS storage unencrypted | RDS.3 | MEDIUM |

## Score

Start at 100 and subtract 20 per critical, 10 per high, 4 per medium and 1 per low security finding (cost-only findings
don't affect the score). 90+ Good · 70+ Needs attention · 40+ At risk · below 40 Critical.
