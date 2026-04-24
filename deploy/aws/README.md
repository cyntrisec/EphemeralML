# Cyntrisec AWS Deployment Templates

Three CloudFormation templates will eventually live here. Each runs in a
**different trust domain**. Mixing them — deploying a Cyntrisec-operated
template in a customer account, or a customer-deployed template in a
Cyntrisec account — breaks the architectural boundary the
[HIPAA Position Memo](../../../startup-plans/05-legal/hipaa-position-memo-byoc-default-architecture-2026-04-23.md)
and [MSA Security Addendum](../../../startup-plans/05-legal/pilot-contract-pack-v0-1-2026-04-23.md)
rest on.

## Templates

### `cyntrisec-pilot.yaml` — **Customer-deployed**

- **Deploy in:** the customer's own AWS account
- **Purpose:** stand up a Phase 1 BYOC pilot host in the customer's account
- **What it creates:** EC2 Nitro host + customer-managed KMS key + S3 evidence
  bucket + least-privilege IAM role + SSH security group + SSM config parameters
- **Contract:**
  [byoc-phase-1-cloudformation-output-contract-2026-04-23.md](../../../startup-plans/10-operations/byoc-phase-1-cloudformation-output-contract-2026-04-23.md)
- **Trust story:** Customer owns everything. Cyntrisec has no IAM principal
  on any resource. Customer Data never leaves the customer's account.

### `release-signing-bootstrap.yaml` — **Cyntrisec-operated (release account)**

- **Deploy in:** a dedicated Cyntrisec AWS account (production signing authority)
- **Purpose:** provision the signing substrate for Phase 1 artifacts
- **What it creates:**
  - GitHub Actions OIDC identity provider (conditional)
  - `alias/cyntrisec-release-signing` — asymmetric KMS CMK (ECC_NIST_P256, SIGN_VERIFY)
  - `alias/cyntrisec-eval-signing` — distinct asymmetric KMS CMK for eval
  - IAM role `cyntrisec-gha-release-signer` — trusted by OIDC, bound to
    `byoc-pilot-release.yml` + tag pattern `pilot-v*`
  - IAM role `cyntrisec-gha-eval-signer` — trusted by OIDC, bound to
    `byoc-eval-release.yml` + branch `main`
  - Pilot release S3 bucket + eval release S3 bucket (write-only-from-role)
- **Contract:**
  [byoc-phase-1-supply-chain-posture-spec-2026-04-23.md](../../../startup-plans/10-operations/byoc-phase-1-supply-chain-posture-spec-2026-04-23.md)
- **Trust story:** Cyntrisec operates the signing keys; GitHub Actions is the
  only principal that can use them, via OIDC with `workflow_ref`-pinned trust.
  No customer account has any trust relationship with this account.
- **Cost:** ~$2/month steady-state (2 × KMS CMK × $1)

### `eval-endpoint-bootstrap.yaml` — **Cyntrisec-operated (eval account, separate from release)**

- **Deploy in:** a dedicated Cyntrisec AWS account (`cyntrisec-eval-prod`),
  separate from the release account and separate from every customer account
- **Purpose:** stand up the account-level scaffolding for `demo.cyntrisec.com`
  per Day 9 spec
- **What it creates:** EC2 Nitro host + IAM role + EBS-encryption KMS key +
  CloudWatch log group + security group (443 public, 22 admin)
- **What it does NOT create:** EIF image, PII filter (Presidio), session
  store (Redis), API service, CloudFront distribution, Route 53 records —
  all either software-level or deferred to separate ChangeSets
- **Contract:**
  [byoc-phase-1-eval-endpoint-spec-2026-04-23.md](../../../startup-plans/10-operations/byoc-phase-1-eval-endpoint-spec-2026-04-23.md)
- **Trust story:** Separate account = blast-radius isolation. Compromise of
  the eval endpoint cannot reach pilot customers or the production signing
  account because no cross-account trust exists.
- **Cost:** ~$10/month idle (EBS + KMS + logs), ~$136/month running.
  Day 9 auto-shutdown on 72h idle keeps steady-state near the idle number.

## Deployment order (when AWS access is available)

### Release account setup

```bash
# One-time account prep
aws cloudformation create-stack \
  --stack-name cyntrisec-release-signing \
  --template-body file://deploy/aws/release-signing-bootstrap.yaml \
  --capabilities CAPABILITY_NAMED_IAM \
  --region us-east-1 \
  --parameters \
    ParameterKey=GitHubOrg,ParameterValue=cyntrisec \
    ParameterKey=GitHubRepo,ParameterValue=ephemeralml

aws cloudformation wait stack-create-complete --stack-name cyntrisec-release-signing
aws cloudformation describe-stacks --stack-name cyntrisec-release-signing \
  --query 'Stacks[0].Outputs'
```

Post-deploy:
1. Copy `ProductionSignerRoleArn` into GitHub repo secret `AWS_RELEASE_ROLE_ARN`
2. Copy `EvalSignerRoleArn` into repo secret `AWS_EVAL_ROLE_ARN`
3. Export production + eval public keys via `aws kms get-public-key` and
   store them in the Cyntrisec release artifact path so `ephemeralml-doctor`
   and `ephemeralml-verify` can embed them at build time

### Eval account setup (separate AWS account)

```bash
# Assumes this runs under the eval-account credentials, not the release-account
aws cloudformation create-stack \
  --stack-name cyntrisec-eval-endpoint \
  --template-body file://deploy/aws/eval-endpoint-bootstrap.yaml \
  --capabilities CAPABILITY_NAMED_IAM \
  --region us-east-1 \
  --parameters \
    ParameterKey=KeyPairName,ParameterValue=<your-keypair> \
    ParameterKey=VpcId,ParameterValue=<your-vpc> \
    ParameterKey=SubnetId,ParameterValue=<your-public-subnet> \
    ParameterKey=AllowedAdminCIDR,ParameterValue=<your-office-ip>/32
```

Post-deploy:
1. Create CloudFront distribution + ACM cert for `demo.cyntrisec.com` + `api.demo.cyntrisec.com`
2. Route 53 record mapping
3. SSH or SSM to the host and pull the eval EIF + API service + Presidio from the eval release bucket
4. Wire the auto-stop-on-idle CloudWatch alarm

### Customer pilot deploy (customer's own account)

Customer follows the admin quickstart independently — no Cyntrisec involvement
in the customer's AWS account.

## Validation

All templates validated in CI via:

```bash
cfn-lint deploy/aws/*.yaml
cfn_nag_scan --input-path deploy/aws/
```

Current status: all three pass cfn-lint exit 0 + cfn-nag 0 failures / 0 warnings
(with inline rationale on intentional exceptions like asymmetric-CMK rotation,
explicit role naming, and the `PutMetricData` resource-level API constraint).

## What to change if the trust boundary changes

If at any future point Cyntrisec needs to take action inside a customer's
AWS account (a capability this boundary currently forbids), that change
is a HIPAA Position Memo flip condition F5 — the memo's three-part
structure describes what happens operationally before any such IAM grant
can be accepted.

Do not provision cross-account trust between these accounts without
revisiting the memo, the contract pack's Support Boundary Clause, and the
BYOC trust disclosure.
