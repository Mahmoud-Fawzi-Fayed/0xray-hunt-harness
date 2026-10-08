---
name: hunt-cloud-misconfig
description: "Hunt cloud / infrastructure misconfigurations. AWS: public S3 buckets (s3:GetObject anonymous), permissive bucket policies (PutObject public-write), exposed CloudFront origin, public Lambda function URL, public RDS snapshot, IAM credentials in JS bundles, AWS metadata accessible via SSRF. GCP: public GCS buckets, exposed Cloud Run services, leaked service account JSON. Azure: public blob containers, exposed Function App. (Kubernetes/Docker exposure is owned by hunt-k8s; CI/CD pipeline attacks by hunt-cicd; post-credential IAM escalation by cloud-iam-deep.) Detection: targeted naming from recon, certificate transparency, JS bundle secret extraction, known service ports. Validate: actual data read / write / RCE. Use when hunting cloud-native storage and compute misconfig (S3/GCS/Blob, IMDS-via-SSRF, serverless, public managed services)."
---

# HUNT-CLOUD — storage, serverless, metadata, identity pools

Proof is an object, a role, or an unauthenticated invoke. A bucket name that returns `AccessDenied` is not a public bucket. Link-local metadata is only reachable **from the target** (SSRF or a shell you already have) — requesting `169.254.169.254` from your laptop proves nothing.

## Decision tree

| Signal | Test once | Hit looks like |
|---|---|---|
| `*.s3.amazonaws.com`, `s3.amazonaws.com/<bucket>`, website endpoint, CNAME to S3 | `GET /?list-type=2&max-keys=5` unsigned, then one key you saw in HTML/JS | `ListBucketResult`, or a private object body |
| `storage.googleapis.com`, `*.storage.googleapis.com` | `GET /storage/v1/b/BUCKET/o` and one object URL | JSON object list or file bytes |
| `*.blob.core.windows.net` | `GET /CONTAINER?restype=container&comp=list` | `<EnumerationResults>` or a blob |
| `*.lambda-url.*.on.aws`, `*.run.app`, `*.azurewebsites.net`, `*.cloudfunctions.net` | One unauthenticated invoke of the URL in JS | Data or an action that should require auth |
| `identityPoolId` / `guestRoleArn` / Cognito in JS (incl. CloudWatch RUM) | `get-id` then `get-credentials-for-identity` | STS creds whose policy allows more than the intended API |
| Leaked `AKIA` / service-account JSON | `sts get-caller-identity` or the GCP token info endpoint | A real account id. Then one read |
| SSRF already confirmed | One IMDS URL with the required header (`hunt-ssrf`) | Role name or token body |

`NoSuchBucket` / `NoSuchBucket` XML on a hostname the app still uses is a takeover lead (`hunt-subdomain`), not data exposure. `AllAccessDisabled` and `AccessDenied` mean you do not have a list; try keys the site already references (`/static/`, `/uploads/`, source maps).

## Storage

```bash
# S3 — virtual-hosted and path-style. Follow a 301 to the region endpoint; do not ignore PermanentRedirect.
curl -s "https://$BUCKET.s3.amazonaws.com/?list-type=2&max-keys=5"
curl -s "https://s3.amazonaws.com/$BUCKET/?list-type=2&max-keys=5"
aws s3 ls "s3://$BUCKET" --no-sign-request

# GCS
curl -s "https://storage.googleapis.com/storage/v1/b/$BUCKET/o?maxResults=5"
curl -sI "https://storage.googleapis.com/$BUCKET/$KEY"

# Azure Blob
curl -s "https://$ACCOUNT.blob.core.windows.net/$CONTAINER?restype=container&comp=list&maxresults=5"
```

Name guesses come from the program: the hostname, `<project>-prod`, `<project>-backup`, `<project>-logs`, `<project>-tfstate`, the CNAME target, and names in JS. A handful of informed names, not a cloud-wide brute.

**Write** (only if the engagement allows): one object `marker-<rand>.txt`, `GET` it back unsigned, stop. Do not `PutBucketAcl`, do not delete, do not sync a bucket down. Listing plus a sensitive key (backup, `.env`, `tfstate`, PII export) is the usual High/Critical. A public marketing-image bucket the site already hotlinks is informational.

Authenticated-users-only (`Any Authenticated AWS Principal`) still exposes data to every AWS account. Say that explicitly if `AllUsers` is closed but a second account you own can read.

## Serverless and admin panels

Lambda function URL with `AuthType NONE`, Cloud Run without IAM invoker, Azure Function or Firebase function anonymous: send the application's normal JSON once. Impact is the data or the privileged effect, not a `200` health check.

Known unauth services, one request each, only on in-scope hosts: `GET /_cat/indices` (OpenSearch/Elastic), `GET /v2/_catalog` (registry), Jenkins/Grafana login is **not** a finding (`hunt-cicd`, `hunt-k8s`). `/server-status` and `phpinfo` go to `hunt-source-leak`.

## IMDS (via SSRF or a foothold, never from your host)

```text
http://169.254.169.254/latest/meta-data/iam/security-credentials/
http://169.254.169.254/latest/api/token     # IMDSv2: PUT, header X-aws-ec2-metadata-token-ttl-seconds
http://169.254.170.2$AWS_CONTAINER_CREDENTIALS_RELATIVE_URI    # ECS
http://169.254.170.23/v1/credentials        # EKS pod identity, when advertised
http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token
http://169.254.169.254/metadata/instance?api-version=2021-02-01   # Azure, header Metadata: true
```

A 401/403 body from the metadata IP is proof of **reach**. Credential impact starts when the token or role keys come back. Header requirements and bypasses: `hunt-ssrf`. Hop-limit 1 blocks IMDSv2 through an extra proxy; a browser or a client on the instance itself still reaches it. Hand live keys to `cloud-iam-deep` for read-only enumeration — do not create users or change policy.

## Cognito identity pools and CloudWatch RUM

`identityPoolId` (`region:uuid`) and `guestRoleArn` in page JS are public by design. The role policy is the boundary. RUM snippets (`cwr`, `aws-rum-web`, `dataplane.rum.<region>.amazonaws.com`) are one place they appear.

```bash
aws cognito-identity get-id --identity-pool-id "$POOL" --region "$REGION" --no-sign-request
aws cognito-identity get-credentials-for-identity --identity-id "$ID" --region "$REGION" --no-sign-request
aws sts get-caller-identity
```

Then **one** read the role should not have (`s3 ls` of a bucket you did not author, `secretsmanager list-secrets`, `dynamodb list-tables`). If the only allowed action is `rum:PutRumEvents` on that app monitor, it is informational — do not file it as cloud takeover. Do not flood `PutRumEvents`, do not use the endpoint as a covert channel, and do not claim dashboard XSS unless the console actually rendered your marker as HTML.

| Proven policy | Severity |
|---|---|
| Unauth STS and a wildcard or multi-service write/read on production | Critical |
| Unauth read of secrets, objects, or parameters | High |
| Only `rum:PutRumEvents` on its own monitor | Informational |
| Self-hosted `cwr.js` on a dangling subdomain you can claim | Depends on the takeover (`hunt-subdomain`) — JS on the app origin is XSS |

## Validation

- Unsigned `GET` of a non-public object, or STS `get-caller-identity` plus one extra API read.
- Unique marker for any write, fetched from a second unauthenticated client.
- Metadata: the token body, not a timeout.
- Do not modify cloud state, do not snapshot, do not invoke delete APIs. A lab emulator (LocalStack or similar) is not evidence — only the in-scope account is.

## Chains

- Public bucket object is a `.env` or `tfstate` → live key → `cloud-iam-deep` read-only.
- Dangling bucket CNAME → `hunt-subdomain`.
- SSRF + IMDSv1 or header-capable IMDSv2 → role creds.
- Over-broad Cognito guest role → same as a leaked key.
- Function URL unauth → `hunt-idor` or `hunt-ssrf` inside the function.

## Rails

- In-scope accounts and hostnames only. No bucket-name brute force, no credential stuffing, no destructive ACL changes, no telemetry flood.
- Draft only — do not submit.

## Before you report — dedup gate

```bash
python3 engine/dedup.py check --program <program> --class cloud --url "<endpoint>" --title "<title>"
```

`NOVEL` → `/validate`. `LIKELY_DUP` → stop unless the bucket, role, or a fix bypass is a concrete differentiator.

Cross-refs: `hunt-ssrf`, `hunt-k8s`, `hunt-cicd`, `cloud-iam-deep`, `hunt-subdomain`, `hunt-baas`, `hunt-source-leak`, `triage-validation`.
