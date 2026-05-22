//! Per-inference receipt bundle assembly.
//!
//! This module owns the auditor-facing artifact. It builds a deterministic
//! tar.gz bundle from in-enclave receipt/evidence bytes, then writes it through
//! the generic `EgressClient` boundary. AWS SDK and vsock details stay outside
//! this module.

use std::collections::BTreeMap;
use std::fmt;
use std::io::Cursor;
use std::sync::Arc;

use base64::Engine as _;
use ephemeral_ml_common::air_receipt::parse_air_v1;
use ephemeral_ml_common::{
    default_verification_limitations, EgressClient, EgressError, EvidenceBundleSummary, FileDigest,
    InferenceHandlerOutput, Limitation, PolicySummary, ReceiptEvidenceSummary, ReportCheck,
    ReportCheckStatus, ReportStatus, ReportType, S3PutObjectRequest, VerificationReportV1,
    VerifierSummary, VERIFICATION_REPORT_V1,
};
use flate2::Compression;
use flate2::GzBuilder;
use sha2::{Digest, Sha256};
use tar::{Builder, Header};

pub type BundleEmitResult<T> = std::result::Result<T, BundleEmitError>;

pub const BUNDLE_CONTENT_TYPE: &str = "application/gzip";
pub const AIR_CBOR: &str = "air.cbor";
pub const ATTESTATION_CBOR: &str = "attestation.cbor";
pub const POLICY_JSON: &str = "cyntrisec-policy.json";
pub const MODEL_MANIFEST_JSON: &str = "model-manifest.json";
pub const RUNTIME_PASSPORT_JSON: &str = "runtime-passport.json";
pub const VERIFICATION_REPORT_JSON: &str = "verification-report.json";
pub const AWS_NITRO_ATTESTATION_CBOR: &str = "vendor-evidence/aws-nitro-attestation.cbor";
pub const SHA256SUMS: &str = "SHA256SUMS";

pub const BUNDLE_FILE_ORDER: [&str; 7] = [
    AIR_CBOR,
    ATTESTATION_CBOR,
    POLICY_JSON,
    MODEL_MANIFEST_JSON,
    RUNTIME_PASSPORT_JSON,
    VERIFICATION_REPORT_JSON,
    AWS_NITRO_ATTESTATION_CBOR,
];

#[derive(Clone, Debug)]
pub struct BundleAssemblerConfig {
    pub bucket: String,
    pub key_prefix: Option<String>,
    pub tenant_id: String,
    pub session_id: String,
    pub policy_json: Vec<u8>,
    pub runtime_passport_json: Vec<u8>,
    pub fallback_model_manifest_json: Option<Vec<u8>>,
    pub kms_key_arn: Option<String>,
}

#[derive(Clone)]
pub struct BundleAssembler {
    egress: Arc<dyn EgressClient>,
    config: BundleAssemblerConfig,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BundleEmission {
    pub bundle_url: String,
    pub bundle_sha256: String,
    pub bucket: String,
    pub key: String,
    pub etag: String,
    pub version_id: Option<String>,
    pub files: Vec<FileDigest>,
}

#[derive(Debug)]
pub enum BundleEmitError {
    MissingArtifact(&'static str),
    InvalidBase64 {
        artifact: &'static str,
        reason: String,
    },
    Serialization(String),
    Io(std::io::Error),
    Egress(EgressError),
}

impl fmt::Display for BundleEmitError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingArtifact(name) => write!(f, "missing required bundle artifact: {name}"),
            Self::InvalidBase64 { artifact, reason } => {
                write!(f, "invalid base64 for {artifact}: {reason}")
            }
            Self::Serialization(err) => write!(f, "bundle serialization failed: {err}"),
            Self::Io(err) => write!(f, "bundle I/O failed: {err}"),
            Self::Egress(err) => write!(f, "bundle egress failed: {err}"),
        }
    }
}

impl std::error::Error for BundleEmitError {}

impl From<std::io::Error> for BundleEmitError {
    fn from(err: std::io::Error) -> Self {
        Self::Io(err)
    }
}

impl BundleAssembler {
    pub fn new(egress: Arc<dyn EgressClient>, config: BundleAssemblerConfig) -> Self {
        Self { egress, config }
    }

    pub async fn emit(&self, output: &InferenceHandlerOutput) -> BundleEmitResult<BundleEmission> {
        let timestamp = output.receipt.execution_timestamp;
        let files = self.bundle_files(output)?;
        let sha256sums = sha256sums(&files);

        let mut tar_files = files.clone();
        tar_files.push((SHA256SUMS.to_string(), sha256sums.into_bytes()));
        let bundle_bytes = build_tar_gz(&tar_files)?;
        let bundle_sha256 = sha256_hex(&bundle_bytes);
        let key = self.bundle_key(timestamp, output.receipt.sequence_number);
        let bundle_url = format!("s3://{}/{}", self.config.bucket, key);

        let mut metadata = BTreeMap::new();
        metadata.insert("bundle-sha256".to_string(), bundle_sha256.clone());
        metadata.insert(
            "air-receipt-sha256".to_string(),
            sha256_hex(file_bytes(&files, AIR_CBOR)?),
        );
        metadata.insert("receipt-id".to_string(), output.receipt.receipt_id.clone());

        let s3 = self
            .egress
            .s3_put_object(S3PutObjectRequest {
                bucket: self.config.bucket.clone(),
                key: key.clone(),
                body: bundle_bytes,
                content_type: Some(BUNDLE_CONTENT_TYPE.to_string()),
                kms_key_arn: self.config.kms_key_arn.clone(),
                metadata: Some(metadata),
            })
            .await
            .map_err(BundleEmitError::Egress)?;

        Ok(BundleEmission {
            bundle_url,
            bundle_sha256,
            bucket: self.config.bucket.clone(),
            key,
            etag: s3.etag,
            version_id: s3.version_id,
            files: file_digests(&tar_files),
        })
    }

    fn bundle_files(
        &self,
        output: &InferenceHandlerOutput,
    ) -> BundleEmitResult<Vec<(String, Vec<u8>)>> {
        let air_cbor = decode_b64_required(output.air_v1_receipt_b64.as_deref(), AIR_CBOR)?;
        let attestation_cbor =
            decode_b64_required(output.boot_attestation_b64.as_deref(), ATTESTATION_CBOR)?;
        let model_manifest_json = match output.model_manifest_json.as_ref() {
            Some(json) => json.as_bytes().to_vec(),
            None => self
                .config
                .fallback_model_manifest_json
                .clone()
                .ok_or(BundleEmitError::MissingArtifact(MODEL_MANIFEST_JSON))?,
        };

        let verification_report_json = self.verification_report_json(
            output,
            &air_cbor,
            &attestation_cbor,
            &model_manifest_json,
        )?;

        Ok(vec![
            (AIR_CBOR.to_string(), air_cbor),
            (ATTESTATION_CBOR.to_string(), attestation_cbor.clone()),
            (POLICY_JSON.to_string(), self.config.policy_json.clone()),
            (MODEL_MANIFEST_JSON.to_string(), model_manifest_json),
            (
                RUNTIME_PASSPORT_JSON.to_string(),
                self.config.runtime_passport_json.clone(),
            ),
            (
                VERIFICATION_REPORT_JSON.to_string(),
                verification_report_json,
            ),
            (AWS_NITRO_ATTESTATION_CBOR.to_string(), attestation_cbor),
        ])
    }

    fn verification_report_json(
        &self,
        output: &InferenceHandlerOutput,
        air_cbor: &[u8],
        attestation_cbor: &[u8],
        model_manifest_json: &[u8],
    ) -> BundleEmitResult<Vec<u8>> {
        let now = output.receipt.execution_timestamp;
        let air_sha256 = sha256_hex(air_cbor);
        let attestation_sha256 = sha256_hex(attestation_cbor);
        let manifest_sha256 = sha256_hex(model_manifest_json);
        let parsed_air = parse_air_v1(air_cbor).ok();
        let mut report = VerificationReportV1 {
            schema_version: VERIFICATION_REPORT_V1.to_string(),
            report_id: format!("vrpt_{}", output.receipt.receipt_id),
            report_type: ReportType::ExecutionReport,
            created_at: now,
            verified_at: now,
            expires_at: None,
            verifier: VerifierSummary {
                name: "cyntrisec-enclave-bundle-emitter".to_string(),
                version: env!("CARGO_PKG_VERSION").to_string(),
                git_commit: None,
            },
            policy: PolicySummary {
                policy_id: "cyntrisec-worker-policy".to_string(),
                policy_version: output.receipt.policy_version.clone(),
                expected_security_mode: Some("production".to_string()),
                max_age_secs: None,
                expected_model_id: Some(output.receipt.model_id.clone()),
                expected_model_hash: parsed_air
                    .as_ref()
                    .map(|air| hex::encode(air.claims.model_hash)),
                require_tee_provenance: true,
                require_runtime_passport: true,
                require_cloud_correlation: false,
            },
            overall_status: ReportStatus::Pass,
            assurance_level: "air_receipt_bundle".to_string(),
            receipt: Some(ReceiptEvidenceSummary {
                receipt_id: Some(output.receipt.receipt_id.clone()),
                receipt_sha256: Some(air_sha256.clone()),
                model_id: Some(output.receipt.model_id.clone()),
                model_version: Some(output.receipt.model_version.clone()),
                model_hash: parsed_air
                    .as_ref()
                    .map(|air| hex::encode(air.claims.model_hash)),
                model_hash_scheme: output.air_v1_model_hash_scheme.clone(),
                request_hash: Some(hex::encode(output.receipt.request_hash)),
                response_hash: Some(hex::encode(output.receipt.response_hash)),
                attestation_doc_hash: Some(hex::encode(output.receipt.attestation_doc_hash)),
                issued_at: Some(output.receipt.execution_timestamp),
                security_mode: Some("gateway_only".to_string()),
                platform: output.receipt.attestation_source.clone(),
            }),
            runtime_passport_ref: None,
            evidence_bundle: Some(EvidenceBundleSummary {
                bundle_type: "cyntrisec-inference-receipt-bundle".to_string(),
                bundle_format_version: "1".to_string(),
                uri: None,
                manifest_sha256: Some(manifest_sha256.clone()),
                sha256sums_sha256: None,
                bundle_sha256: None,
                files: vec![],
            }),
            cloud_correlation: None,
            checks: vec![
                ReportCheck {
                    id: "air_receipt_present".to_string(),
                    label: "AIR receipt present".to_string(),
                    layer: "receipt".to_string(),
                    status: ReportCheckStatus::Pass,
                    detail: Some(format!("sha256:{air_sha256}")),
                    evidence_ref: Some(AIR_CBOR.to_string()),
                },
                ReportCheck {
                    id: "attestation_present".to_string(),
                    label: "Platform attestation present".to_string(),
                    layer: "platform".to_string(),
                    status: ReportCheckStatus::Pass,
                    detail: Some(format!("sha256:{attestation_sha256}")),
                    evidence_ref: Some(ATTESTATION_CBOR.to_string()),
                },
                ReportCheck {
                    id: "model_manifest_present".to_string(),
                    label: "Model manifest present".to_string(),
                    layer: "model".to_string(),
                    status: ReportCheckStatus::Pass,
                    detail: Some(format!("sha256:{manifest_sha256}")),
                    evidence_ref: Some(MODEL_MANIFEST_JSON.to_string()),
                },
            ],
            warnings: vec![],
            limitations: bundle_report_limitations(),
            report_sha256: None,
        };
        report
            .finalize_report_sha256()
            .map_err(|err| BundleEmitError::Serialization(err.to_string()))?;
        serde_json::to_vec_pretty(&report)
            .map_err(|err| BundleEmitError::Serialization(err.to_string()))
    }

    fn bundle_key(&self, timestamp: u64, sequence_number: u64) -> String {
        let (year, month, day, hour) = utc_ymdh(timestamp);
        let leaf = format!(
            "tenant={}/date={year:04}/{month:02}/{day:02}/hour={hour:02}/{}/{}.bundle.tar.gz",
            sanitize_key_component(&self.config.tenant_id),
            sanitize_key_component(&self.config.session_id),
            sequence_number
        );
        match self
            .config
            .key_prefix
            .as_deref()
            .map(|prefix| prefix.trim_matches('/'))
        {
            Some("") | None => leaf,
            Some(prefix) => format!("{prefix}/{leaf}"),
        }
    }
}

fn bundle_report_limitations() -> Vec<Limitation> {
    let mut limitations = default_verification_limitations();
    limitations.push(Limitation {
        code: "enclave_generated_summary".to_string(),
        message: "verification-report.json is an in-enclave summary bundled with evidence; external verifier decisions should recompute checks from the raw bundle files.".to_string(),
    });
    limitations
}

fn decode_b64_required(value: Option<&str>, artifact: &'static str) -> BundleEmitResult<Vec<u8>> {
    let value = value.ok_or(BundleEmitError::MissingArtifact(artifact))?;
    base64::engine::general_purpose::STANDARD
        .decode(value.as_bytes())
        .map_err(|err| BundleEmitError::InvalidBase64 {
            artifact,
            reason: err.to_string(),
        })
}

fn build_tar_gz(files: &[(String, Vec<u8>)]) -> BundleEmitResult<Vec<u8>> {
    let encoder = GzBuilder::new()
        .mtime(0)
        .write(Vec::new(), Compression::default());
    let mut builder = Builder::new(encoder);
    for (name, bytes) in files {
        let mut header = Header::new_gnu();
        header.set_path(name)?;
        header.set_size(bytes.len() as u64);
        header.set_mode(0o644);
        header.set_uid(0);
        header.set_gid(0);
        header.set_mtime(0);
        header.set_cksum();
        builder.append(&header, Cursor::new(bytes))?;
    }
    let encoder = builder.into_inner()?;
    encoder.finish().map_err(BundleEmitError::Io)
}

fn sha256sums(files: &[(String, Vec<u8>)]) -> String {
    let mut out = String::new();
    for (name, bytes) in files {
        out.push_str(&sha256_hex(bytes));
        out.push_str("  ");
        out.push_str(name);
        out.push('\n');
    }
    out
}

fn file_digests(files: &[(String, Vec<u8>)]) -> Vec<FileDigest> {
    files
        .iter()
        .map(|(name, bytes)| FileDigest {
            name: name.clone(),
            sha256: sha256_hex(bytes),
        })
        .collect()
}

fn file_bytes<'a>(
    files: &'a [(String, Vec<u8>)],
    name: &'static str,
) -> BundleEmitResult<&'a [u8]> {
    files
        .iter()
        .find(|(file, _)| file == name)
        .map(|(_, bytes)| bytes.as_slice())
        .ok_or(BundleEmitError::MissingArtifact(name))
}

fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn sanitize_key_component(value: &str) -> String {
    value
        .chars()
        .map(|ch| match ch {
            'a'..='z' | 'A'..='Z' | '0'..='9' | '-' | '_' | '.' => ch,
            _ => '-',
        })
        .collect()
}

fn utc_ymdh(timestamp: u64) -> (i64, u32, u32, u32) {
    let days = (timestamp / 86_400) as i64;
    let hour = ((timestamp % 86_400) / 3_600) as u32;
    let (year, month, day) = civil_from_days(days);
    (year, month, day, hour)
}

fn civil_from_days(days_since_epoch: i64) -> (i64, u32, u32) {
    let z = days_since_epoch + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let mut year = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = mp + if mp < 10 { 3 } else { -9 };
    if month <= 2 {
        year += 1;
    }
    (year, month as u32, day as u32)
}

#[cfg(all(test, feature = "mock"))]
mod tests {
    use super::*;
    use std::io::Read;

    use ephemeral_ml_common::air_receipt::{build_air_v1, AirReceiptClaims};
    use ephemeral_ml_common::egress_client::mock::MockEgressClient;
    use ephemeral_ml_common::{
        AttestationReceipt, EnclaveMeasurements, ModelManifest, ReceiptSigningKey, SecurityMode,
    };
    use flate2::read::GzDecoder;

    fn test_output() -> InferenceHandlerOutput {
        let key = ReceiptSigningKey::generate().unwrap();
        let mut receipt = AttestationReceipt::new(
            uuid::Uuid::new_v4().to_string(),
            1,
            SecurityMode::GatewayOnly,
            EnclaveMeasurements::new(vec![0; 48], vec![1; 48], vec![2; 48]),
            [0xAA; 32],
            [0xBB; 32],
            [0xCC; 32],
            "v1".to_string(),
            42,
            "bundle-model".to_string(),
            "v1".to_string(),
            7,
            16,
        );
        receipt.execution_timestamp = 1_700_000_000;
        receipt.attestation_source = Some("nitro-pcr".to_string());
        receipt.sign(&key).unwrap();

        let model_hash = [0xDD; 32];
        let air_claims = AirReceiptClaims::from_legacy_with_scheme(
            &receipt,
            "issuer.test".to_string(),
            model_hash,
            Some("sha256-single".to_string()),
        )
        .unwrap();
        let air_cbor = build_air_v1(&air_claims, &key).unwrap();
        let manifest = ModelManifest {
            model_id: "bundle-model".to_string(),
            version: "v1".to_string(),
            model_hash: model_hash.to_vec(),
            hash_algorithm: "sha256".to_string(),
            key_id: "alias/model".to_string(),
            tokenizer_hash: None,
            config_hash: None,
            gcs_uris: BTreeMap::new(),
            created_at: "2026-05-12T00:00:00Z".to_string(),
            model_identity: None,
            signature: vec![0; 64],
        };

        InferenceHandlerOutput {
            output_tensor: vec![1.0, 2.0],
            receipt,
            generated_text: Some("ok".to_string()),
            boot_attestation_b64: Some(
                base64::engine::general_purpose::STANDARD.encode(b"attestation-cbor"),
            ),
            model_manifest_json: Some(serde_json::to_string(&manifest).unwrap()),
            air_v1_receipt_b64: Some(base64::engine::general_purpose::STANDARD.encode(air_cbor)),
            air_v1_model_hash_scheme: Some("sha256-single".to_string()),
            model_identity_coverage: None,
            bundle_url: None,
            bundle_sha256: None,
            benchmark: None,
        }
    }

    fn assembler(egress: Arc<dyn EgressClient>) -> BundleAssembler {
        BundleAssembler::new(
            egress,
            BundleAssemblerConfig {
                bucket: "customer-evidence".to_string(),
                key_prefix: Some("bundles".to_string()),
                tenant_id: "tenant-a".to_string(),
                session_id: "session-1".to_string(),
                policy_json: br#"{"PCR0":"00"}"#.to_vec(),
                runtime_passport_json: br#"{"schema_version":"1","passport_id":"rpass-test"}"#
                    .to_vec(),
                fallback_model_manifest_json: None,
                kms_key_arn: Some("arn:aws:kms:us-east-1:111122223333:key/evidence".to_string()),
            },
        )
    }

    fn unpack_bundle(bytes: &[u8]) -> Vec<(String, Vec<u8>)> {
        let decoder = GzDecoder::new(Cursor::new(bytes));
        let mut archive = tar::Archive::new(decoder);
        let mut files = Vec::new();
        for entry in archive.entries().unwrap() {
            let mut entry = entry.unwrap();
            let name = entry.path().unwrap().to_string_lossy().to_string();
            let mut bytes = Vec::new();
            entry.read_to_end(&mut bytes).unwrap();
            files.push((name, bytes));
        }
        files
    }

    fn find_file<'a>(files: &'a [(String, Vec<u8>)], name: &str) -> &'a [u8] {
        files
            .iter()
            .find(|(path, _)| path == name)
            .map(|(_, bytes)| bytes.as_slice())
            .unwrap()
    }

    #[tokio::test]
    async fn bundle_emit_uploads_tar_gz_with_expected_files_and_sums() {
        let egress = Arc::new(MockEgressClient::default());
        let emission = assembler(egress.clone())
            .emit(&test_output())
            .await
            .unwrap();
        let requests = egress.s3_requests.lock().unwrap();
        assert_eq!(requests.len(), 1);
        let req = &requests[0];
        assert_eq!(req.bucket, "customer-evidence");
        assert_eq!(req.content_type.as_deref(), Some(BUNDLE_CONTENT_TYPE));
        assert_eq!(
            req.key,
            "bundles/tenant=tenant-a/date=2023/11/14/hour=22/session-1/42.bundle.tar.gz"
        );
        assert_eq!(
            emission.bundle_url,
            format!("s3://customer-evidence/{}", req.key)
        );
        assert_eq!(emission.bundle_sha256, sha256_hex(&req.body));

        let files = unpack_bundle(&req.body);
        let expected = [
            AIR_CBOR,
            ATTESTATION_CBOR,
            POLICY_JSON,
            MODEL_MANIFEST_JSON,
            RUNTIME_PASSPORT_JSON,
            VERIFICATION_REPORT_JSON,
            AWS_NITRO_ATTESTATION_CBOR,
            SHA256SUMS,
        ];
        assert_eq!(
            files
                .iter()
                .map(|(name, _)| name.as_str())
                .collect::<Vec<_>>(),
            expected
        );
        assert!(parse_air_v1(find_file(&files, AIR_CBOR)).is_ok());
        assert_eq!(find_file(&files, ATTESTATION_CBOR), b"attestation-cbor");
        assert_eq!(
            find_file(&files, AWS_NITRO_ATTESTATION_CBOR),
            b"attestation-cbor"
        );
        let _: ModelManifest =
            serde_json::from_slice(find_file(&files, MODEL_MANIFEST_JSON)).unwrap();
        let _: VerificationReportV1 =
            serde_json::from_slice(find_file(&files, VERIFICATION_REPORT_JSON)).unwrap();

        let sums = String::from_utf8(find_file(&files, SHA256SUMS).to_vec()).unwrap();
        for name in BUNDLE_FILE_ORDER {
            let line = format!("{}  {name}\n", sha256_hex(find_file(&files, name)));
            assert!(sums.contains(&line), "missing SHA256SUMS line for {name}");
        }
    }

    #[test]
    fn utc_key_date_conversion_handles_known_timestamp() {
        assert_eq!(utc_ymdh(1_700_000_000), (2023, 11, 14, 22));
    }
}
