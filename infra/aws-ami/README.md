# Cyntrisec AWS Pilot AMI

Private pilots use a customer-launched CloudFormation stack plus a private
shared Cyntrisec AMI. Marketplace can wrap this later, but the reliable install
unit is the AMI.

## Release Model

The EIF is a fixed release artifact. Treat these as one release unit:

- AMI ID
- `/opt/cyntrisec/eif/ephemeralml-pilot.eif`
- Nitro EIF PCR0 / PCR1 / PCR2 measurements
- CloudFormation KMS `RecipientAttestation` parameters
- verifier expected-measurement policy

Do not fetch a different EIF at boot for a real pilot. The EIF file SHA-384 is
only an inventory hash; it is not the KMS `ImageSha384` / PCR0 value.

## Build A Release Bundle

Use a prebuilt EIF plus captured Nitro measurements:

```bash
scripts/aws/build_release_bundle.sh   --version v0.2.9-aws-pilot.1   --eif /path/to/ephemeralml-pilot.eif   --measurements-json /path/to/ephemeralml-pilot.measurements.json
```

Or build the EIF from the AWS PoC enclave Dockerfile:

```bash
scripts/aws/build_release_bundle.sh   --version v0.2.9-aws-pilot.1   --build-eif   --model-dir /path/to/model-stage
```

The bundle is written to:

```text
dist/aws-ami/cyntrisec-aws-pilot-<version>/
```

The script prints the exact CloudFormation values to use:

```text
cfn_EnclaveImageSha384: <PCR0 / ImageSha384>
cfn_EnclavePcr1Sha384: <PCR1>
cfn_EnclavePcr2Sha384: <PCR2>
```

## Build The AMI

The AMI snapshot must be encrypted with a customer-managed KMS key if it will be
shared to a pilot customer's AWS account. AWS-managed `aws/ebs` keys cannot be
shared cross-account.

```bash
packer init infra/aws-ami/packer
packer build   -var region=us-east-1   -var ami_name=cyntrisec-aws-pilot-v0.2.9-aws-pilot.1   -var ebs_kms_key_id=arn:aws:kms:us-east-1:123456789012:key/...   -var release_bundle=dist/aws-ami/cyntrisec-aws-pilot-v0.2.9-aws-pilot.1   infra/aws-ami/packer
```

## Share With A Pilot Customer

```bash
aws ec2 modify-image-attribute   --region us-east-1   --image-id ami-...   --launch-permission "Add=[{UserId=111122223333}]"
```

Also update the customer-managed KMS key policy for the AMI snapshot so the pilot
customer account can use it to launch instances. Do not bake customer secrets
into the AMI.

## Launch With Quick Create

Use `infra/aws-native-poc/cyntrisec-aws-poc.yaml` and set:

- `CyntrisecAmiId=ami-...`
- `EnclaveImageSha384=<cfn_EnclaveImageSha384 from release bundle>`
- `EnclavePcr1Sha384=<cfn_EnclavePcr1Sha384 from release bundle>`
- `EnclavePcr2Sha384=<cfn_EnclavePcr2Sha384 from release bundle>`
- optional `SplunkHecEndpoint`
- optional `SplunkHecSecretArn`

CloudFormation still owns IAM, KMS, S3, security groups, SSM config, and the EC2
instance. The AMI removes the fragile runtime installation from first boot.

## Operator Smoke Test

After `CREATE_COMPLETE`, run the `DoctorCommand` and `SmokeTestCommand` stack
outputs. For private pilots the smoke test is intentionally operator-run rather
than a CloudFormation custom resource.
