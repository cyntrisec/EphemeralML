# AWS Site Inventory Report — 2026-02-21

**Scope:** Read-only discovery for `cyntrisec.com` (marketing) and `ephemeralml.cyntrisec.com` (technical).

---

## 1. Identity / Account Context

| Field | Value |
|-------|-------|
| Account ID | `272493677165` |
| IAM User | `EphemeralML-Deployer` |
| ARN | `arn:aws:iam::272493677165:user/EphemeralML-Deployer` |
| Region (config) | `us-east-1` |
| AWS_PROFILE | Not set (default profile) |
| AWS_REGION | Not set (uses config-file `us-east-1`) |

### IAM Permissions (Attached Policies)

| Policy | ARN |
|--------|-----|
| AmazonS3FullAccess | `arn:aws:iam::aws:policy/AmazonS3FullAccess` |
| AmazonEC2FullAccess | `arn:aws:iam::aws:policy/AmazonEC2FullAccess` |
| IAMFullAccess | `arn:aws:iam::aws:policy/IAMFullAccess` |
| AWSKeyManagementServicePowerUser | `arn:aws:iam::aws:policy/AWSKeyManagementServicePowerUser` |
| AmazonSSMFullAccess | `arn:aws:iam::aws:policy/AmazonSSMFullAccess` |
| EC2InstanceConnect | `arn:aws:iam::aws:policy/EC2InstanceConnect` |

**Inline policy:** `AllowInstanceConnectUbuntu`

### Missing Permissions (Blocked This Audit)

| Service | Action Attempted | Result |
|---------|-----------------|--------|
| CloudFront | `cloudfront:ListDistributions` | **AccessDenied** |
| CloudFront | `cloudfront:GetDistribution` | **AccessDenied** |
| Route53 | `route53:ListHostedZones` | **AccessDenied** |
| ACM | `acm:ListCertificates` | **AccessDenied** |

> **Impact:** CloudFront distribution details, Route53 record sets, and ACM certificate ARNs could not be directly queried. Partial information was recovered from S3 bucket policies and external DNS/TLS probing.

---

## 2. S3 Inventory

### All Buckets in Account (14 total)

| Bucket | Created | Purpose |
|--------|---------|---------|
| `cyntrisec-frontend-prod` | 2025-11-01 | **Marketing site** (cyntrisec.com) — CloudFront origin |
| `ai-assurance-cyntrisec-com` | 2026-01-01 | Older/alternate site with S3 website hosting enabled |
| `cyntrisec-mail` | 2025-11-13 | SES incoming email storage |
| `ephemeral-ml-models-272493677165` | 2026-01-26 | ML models (encrypted + plaintext MiniLM) |
| `ephemeral-ml-models-demo` | 2026-01-28 | Demo ML models (MiniLM, BERT-base, MiniLM-L12) |
| `ephemeral-ml-models-1769608207` | 2026-01-28 | ML models (test + large bench model) |
| `ephemeral-ml-temp-*` (4 buckets) | 2026-01-28 | Temporary benchmark/proxy artifacts |
| `canisharethisfile.com` | 2025-12-29 | Separate project (S3 website hosting) |
| `can-i-share-this-file-terraform-state-*` (2) | 2025-12 | Terraform state for canisharethisfile |

### Bucket: `cyntrisec-frontend-prod` (Marketing Site)

| Property | Value |
|----------|-------|
| Region | `us-east-1` (LocationConstraint: null) |
| S3 Website Hosting | **Not configured** (NoSuchWebsiteConfiguration) |
| Public Access Block | **All blocked** (BlockPublicAcls, IgnorePublicAcls, BlockPublicPolicy, RestrictPublicBuckets = true) |
| Policy Status | **Not public** (served via CloudFront OAC only) |
| Encryption | AES256 (SSE-S3), BucketKeyEnabled=true |
| Versioning | **Not enabled** |
| Logging | **Not enabled** |
| CORS | Not configured |
| Tags | None |

**Bucket Policy:**
```json
{
  "Version": "2008-10-17",
  "Id": "PolicyForCloudFrontPrivateContent",
  "Statement": [{
    "Sid": "AllowCloudFrontServicePrincipal",
    "Effect": "Allow",
    "Principal": {"Service": "cloudfront.amazonaws.com"},
    "Action": "s3:GetObject",
    "Resource": "arn:aws:s3:::cyntrisec-frontend-prod/*",
    "Condition": {
      "ArnLike": {
        "AWS:SourceArn": "arn:aws:cloudfront::272493677165:distribution/E3I9161DAHSC79"
      }
    }
  }]
}
```

**Objects (10 files):**

| Date | Size | Key |
|------|------|-----|
| 2026-02-17 | 11,924 B | `index.html` |
| 2026-02-17 | 8,205 B | `style.css` |
| 2026-02-17 | 2,224 B | `llms.txt` |
| 2026-01-19 | 84 B | `robots.txt` |
| 2026-01-18 | 787,965 B | `assets/favicon.png` |
| 2026-01-18 | 369,192 B | `assets/logo-dark.png` |
| 2026-01-18 | 16,934 B | `assets/logo.png` |
| 2026-02-17 | 7,943 B | `backup/index.html.bak` |
| 2026-02-17 | 1,136 B | `backup/llms.txt.bak` |
| 2026-02-17 | 5,996 B | `backup/style.css.bak` |

### Bucket: `ai-assurance-cyntrisec-com` (Alternate/Old Site)

| Property | Value |
|----------|-------|
| Region | `us-east-1` |
| S3 Website Hosting | **Enabled** (IndexDocument: `index.html`, ErrorDocument: `404.html`) |
| Public Access Block | **All disabled** (fully public) |
| Policy Status | **Public** |
| Encryption | AES256 (SSE-S3), BucketKeyEnabled=false |
| Versioning | Not enabled |
| Logging | Not enabled |
| Tags | None |
| S3 Website Endpoint | `http://ai-assurance-cyntrisec-com.s3-website-us-east-1.amazonaws.com` |

**Bucket Policy:**
```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Sid": "PublicReadGetObject",
    "Effect": "Allow",
    "Principal": "*",
    "Action": "s3:GetObject",
    "Resource": "arn:aws:s3:::ai-assurance-cyntrisec-com/*"
  }]
}
```

**Objects (5 files):**

| Date | Size | Key |
|------|------|-----|
| 2026-01-02 | 30,132 B | `index.html` |
| 2026-01-02 | 20,988 B | `assets/css/styles.css` |
| 2026-01-02 | 98 B | `assets/images/.gitkeep` |
| 2026-01-02 | 543 B | `favicon.svg` |
| 2026-01-02 | 2,321 B | `404.html` |

> **Note:** This bucket has S3 website hosting enabled and is publicly accessible at its S3 endpoint, but no DNS record points `ai-assurance.cyntrisec.com` to it. It appears to be an older/unused site. Last modified 2026-01-02.

---

## 3. CloudFront Inventory

**Direct CloudFront API access is blocked** (missing `cloudfront:*` permissions on EphemeralML-Deployer).

### Recovered Information

From the `cyntrisec-frontend-prod` bucket policy and HTTP response headers:

| Property | Value |
|----------|-------|
| Distribution ID | `E3I9161DAHSC79` |
| Origin | `cyntrisec-frontend-prod` (S3, via OAC) |
| Default Root Object | `index.html` (inferred from behavior) |
| TLS Certificate | Amazon RSA 2048 M01 (SANs: `cyntrisec.com`, `*.cyntrisec.com`) |
| HSTS | `max-age=31536000; includeSubDomains` |
| IPv6 | Enabled (AAAA records: `2600:9000:21f8:*`) |
| Edge POP observed | `TLV50-C1` |

**Aliases served by this distribution:**
- `cyntrisec.com` (confirmed via HTTP headers)
- `www.cyntrisec.com` (confirmed via HTTP headers, same content and CloudFront headers)

**ephemeralml.cyntrisec.com is NOT served by CloudFront.** It is a CNAME to GitHub Pages (see Section 4).

---

## 4. Route53 DNS

**Direct Route53 API access is blocked** (missing `route53:*` permissions on EphemeralML-Deployer).

### External DNS Discovery

**Nameservers for cyntrisec.com:**
```
ns-1446.awsdns-52.org.
ns-464.awsdns-58.com.
ns-533.awsdns-02.net.
ns-1890.awsdns-44.co.uk.
```

> DNS is hosted on AWS Route53.

### Record Mapping

| Domain | Type | Value | Destination |
|--------|------|-------|-------------|
| `cyntrisec.com` | A | `13.226.2.{79,84,106,121}` | CloudFront `E3I9161DAHSC79` |
| `cyntrisec.com` | AAAA | `2600:9000:21f8:*` (8 IPs) | CloudFront `E3I9161DAHSC79` |
| `www.cyntrisec.com` | A | `13.226.2.{79,84,106,121}` | CloudFront `E3I9161DAHSC79` (same dist) |
| `ephemeralml.cyntrisec.com` | CNAME | `tsyrulb.github.io.` | **GitHub Pages** |
| `ephemeralml.cyntrisec.com` | A (resolved) | `185.199.{108-111}.153` | GitHub Pages IPs |
| `cyntrisec.com` | MX | `1 smtp.google.com.` | Google Workspace email |
| `cyntrisec.com` | TXT | `v=spf1 include:_spf.google.com ~all` | SPF for Google |
| `cyntrisec.com` | TXT | `google-site-verification=bNHMd6L...` | Google ownership |
| `_dmarc.cyntrisec.com` | TXT | **(NOT FOUND)** | **Missing DMARC record** |

---

## 5. ACM Certificates

**Direct ACM API access is blocked** (missing `acm:*` permissions on EphemeralML-Deployer).

### TLS Certificate Discovery (via openssl s_client)

#### cyntrisec.com (CloudFront)

| Field | Value |
|-------|-------|
| Subject CN | `cyntrisec.com` |
| Issuer | `C=US, O=Amazon, CN=Amazon RSA 2048 M01` |
| SANs | `DNS:cyntrisec.com`, `DNS:*.cyntrisec.com` |
| Not Before | 2025-11-01 00:00:00 UTC |
| Not After | **2026-11-30 23:59:59 UTC** |
| Status | Valid (expires in ~9 months) |

> Wildcard cert (`*.cyntrisec.com`) covers all subdomains including `www.cyntrisec.com`. This is an ACM-managed certificate (Amazon-issued, used by CloudFront distribution `E3I9161DAHSC79`).

#### ephemeralml.cyntrisec.com (GitHub Pages)

| Field | Value |
|-------|-------|
| Subject CN | `ephemeralml.cyntrisec.com` |
| Issuer | `C=US, O=Let's Encrypt, CN=R12` |
| SANs | `DNS:ephemeralml.cyntrisec.com` |
| Not Before | 2025-12-29 00:54:17 UTC |
| Not After | **2026-03-29 00:54:16 UTC** |
| Status | Valid (expires in ~36 days, auto-renewed by GitHub) |

---

## 6. Complete Domain-to-Infrastructure Mapping

### cyntrisec.com (Marketing Site)

```
User Browser
  |
  +-- DNS: cyntrisec.com -> Route53 (A/AAAA alias)
  |         -> CloudFront 13.226.2.x / 2600:9000:*
  |
  +-- TLS: ACM wildcard cert (*.cyntrisec.com, Amazon RSA 2048 M01)
  |         Expires: 2026-11-30
  |
  +-- CDN: CloudFront Distribution E3I9161DAHSC79
  |         HSTS: max-age=31536000; includeSubDomains
  |
  +-- Origin: S3 bucket "cyntrisec-frontend-prod" (us-east-1)
              Access: OAC only (no public access, no S3 website hosting)
              Files: index.html, style.css, llms.txt, robots.txt, assets/*
```

### www.cyntrisec.com

```
Same as cyntrisec.com -- same CloudFront distribution, same S3 origin.
DNS resolves to identical CloudFront IPs. Serves identical content.
```

### ephemeralml.cyntrisec.com (Technical Site)

```
User Browser
  |
  +-- DNS: ephemeralml.cyntrisec.com -> Route53 CNAME
  |         -> tsyrulb.github.io. -> 185.199.{108-111}.153
  |
  +-- TLS: Let's Encrypt cert (auto-managed by GitHub)
  |         Expires: 2026-03-29 (auto-renewed)
  |
  +-- Origin: GitHub Pages (tsyrulb.github.io)
              NOT hosted in AWS at all
```

### ai-assurance-cyntrisec-com (Orphaned)

```
S3 website hosting enabled at:
  http://ai-assurance-cyntrisec-com.s3-website-us-east-1.amazonaws.com

No DNS record points to it. Publicly accessible. Last updated 2026-01-02.
Status: ORPHANED -- appears to be an earlier version of the marketing site.
```

---

## 7. Findings and Gaps

### Issues Found

| # | Severity | Finding | Detail |
|---|----------|---------|--------|
| 1 | **HIGH** | IAM permissions missing for full audit | EphemeralML-Deployer lacks CloudFront, Route53, ACM permissions. Cannot view or manage CDN, DNS, or certificates via CLI. |
| 2 | **MEDIUM** | Missing DMARC DNS record | `_dmarc.cyntrisec.com` TXT record does not exist. Email spoofing protection is incomplete (SPF exists but DMARC does not). |
| 3 | **MEDIUM** | Orphaned public S3 bucket | `ai-assurance-cyntrisec-com` is publicly accessible with `Principal: *`, has S3 website hosting enabled, but no DNS points to it. Stale content from 2026-01-02. |
| 4 | **LOW** | No S3 versioning on marketing bucket | `cyntrisec-frontend-prod` has no versioning. Accidental overwrites or deletions are unrecoverable. |
| 5 | **LOW** | No S3 access logging on either web bucket | Neither `cyntrisec-frontend-prod` nor `ai-assurance-cyntrisec-com` has access logging enabled. |
| 6 | **LOW** | Backup files in production bucket | `backup/index.html.bak`, `backup/llms.txt.bak`, `backup/style.css.bak` are in the production S3 bucket. These are accessible via CloudFront. |
| 7 | **LOW** | No bucket tags | Neither web-hosting bucket has tags for cost allocation or environment tracking. |
| 8 | **INFO** | ephemeralml site is outside AWS | `ephemeralml.cyntrisec.com` is served entirely from GitHub Pages. Only the DNS CNAME in Route53 is AWS-managed. |
| 9 | **INFO** | 5 temp/test model buckets | `ephemeral-ml-temp-*` and `ephemeral-ml-models-1769608207` appear to be leftover test resources. |

### What Is Healthy

- **cyntrisec.com** is live, served via CloudFront + S3 OAC (best practice, no direct public S3 access)
- **www.cyntrisec.com** resolves and serves same content as apex domain
- **HSTS** is enabled with `includeSubDomains` and 1-year max-age
- **TLS certificates** are valid: ACM wildcard (9 months remaining), Let's Encrypt (36 days, auto-renewed)
- **S3 encryption** at rest (AES256/SSE-S3) on both web buckets
- **IPv6** is enabled on CloudFront
- **SPF** record is properly configured for Google Workspace

### What Is Missing

- CloudFront, Route53, ACM permissions for the `EphemeralML-Deployer` IAM user
- DMARC DNS record for email authentication
- S3 versioning on the marketing bucket
- S3 access logging on web buckets
- Cleanup of orphaned `ai-assurance-cyntrisec-com` bucket

---

## 8. Ready-to-Deploy Checklist (Commands -- DO NOT EXECUTE)

### Fix 1: Add missing IAM permissions

```bash
# Attach read-only policies for CloudFront, Route53, ACM
aws iam attach-user-policy \
  --user-name EphemeralML-Deployer \
  --policy-arn arn:aws:iam::aws:policy/CloudFrontReadOnlyAccess

aws iam attach-user-policy \
  --user-name EphemeralML-Deployer \
  --policy-arn arn:aws:iam::aws:policy/AmazonRoute53ReadOnlyAccess

aws iam attach-user-policy \
  --user-name EphemeralML-Deployer \
  --policy-arn arn:aws:iam::aws:policy/AWSCertificateManagerReadOnly
```

### Fix 2: Add DMARC record (requires Route53 access)

```bash
# After getting Route53 access, find the hosted zone ID:
aws route53 list-hosted-zones --query "HostedZones[?Name=='cyntrisec.com.'].Id" --output text

# Then add DMARC record:
aws route53 change-resource-record-sets \
  --hosted-zone-id <ZONE_ID> \
  --change-batch '{
    "Changes": [{
      "Action": "CREATE",
      "ResourceRecordSet": {
        "Name": "_dmarc.cyntrisec.com",
        "Type": "TXT",
        "TTL": 3600,
        "ResourceRecords": [{"Value": "\"v=DMARC1; p=quarantine; rua=mailto:dmarc@cyntrisec.com; pct=100\""}]
      }
    }]
  }'
```

### Fix 3: Clean up orphaned public bucket

```bash
# Option A: Delete the orphaned bucket
aws s3 rb s3://ai-assurance-cyntrisec-com --force

# Option B: If keeping, at minimum block public access
aws s3api put-public-access-block \
  --bucket ai-assurance-cyntrisec-com \
  --public-access-block-configuration \
    BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true
```

### Fix 4: Enable versioning on marketing bucket

```bash
aws s3api put-bucket-versioning \
  --bucket cyntrisec-frontend-prod \
  --versioning-configuration Status=Enabled
```

### Fix 5: Enable S3 access logging

```bash
# Create a logging bucket first, or use an existing one
aws s3api put-bucket-logging \
  --bucket cyntrisec-frontend-prod \
  --bucket-logging-status '{
    "LoggingEnabled": {
      "TargetBucket": "cyntrisec-frontend-prod",
      "TargetPrefix": "access-logs/"
    }
  }'
```

### Fix 6: Remove backup files from production

```bash
aws s3 rm s3://cyntrisec-frontend-prod/backup/ --recursive
```

### Fix 7: Clean up temp/test model buckets

```bash
# Review and delete if no longer needed:
aws s3 rb s3://ephemeral-ml-temp-1769625858 --force
aws s3 rb s3://ephemeral-ml-temp-1769625866 --force
aws s3 rb s3://ephemeral-ml-temp-1769630351 --force
aws s3 rb s3://ephemeral-ml-temp-1769632078 --force
aws s3 rb s3://ephemeral-ml-temp-1769632280 --force
```

---

## 9. Blockers

| Blocker | Impact | Resolution |
|---------|--------|------------|
| Missing CloudFront permissions | Cannot inspect distribution config, cache behaviors, custom error pages, WAF associations | Attach `CloudFrontReadOnlyAccess` or `CloudFrontFullAccess` |
| Missing Route53 permissions | Cannot view/confirm DNS records, cannot add DMARC | Attach `AmazonRoute53ReadOnlyAccess` or `AmazonRoute53FullAccess` |
| Missing ACM permissions | Cannot confirm certificate ARN, renewal status, or validation method | Attach `AWSCertificateManagerReadOnly` |
| GitHub Pages dependency | ephemeralml.cyntrisec.com is hosted outside AWS; TLS cert renewal depends on GitHub automation | Consider migrating to S3+CloudFront for unified management, or accept external dependency |

---

*Report generated 2026-02-21 by read-only AWS inventory scan.*
*IAM principal: `arn:aws:iam::272493677165:user/EphemeralML-Deployer`*
