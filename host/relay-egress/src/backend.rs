use std::future::Future;
use std::pin::Pin;

use aws_sdk_kms::Client as KmsClient;
use aws_sdk_s3::primitives::ByteStream;
use aws_sdk_s3::types::ServerSideEncryption;
use aws_sdk_s3::Client as S3Client;
use ephemeral_ml_common::{
    EgressError, KmsDecryptRequest, S3PutObjectRequest, S3PutObjectResponse,
};

pub type AwsBackendFuture<'a, T> =
    Pin<Box<dyn Future<Output = Result<T, AwsBackendError>> + Send + 'a>>;

pub trait AwsBackend: Send + Sync {
    fn kms_decrypt<'a>(&'a self, req: KmsDecryptRequest) -> AwsBackendFuture<'a, Vec<u8>>;

    fn s3_put_object<'a>(
        &'a self,
        req: S3PutObjectRequest,
    ) -> AwsBackendFuture<'a, PutObjectResult>;
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PutObjectResult {
    pub etag: String,
    pub version_id: Option<String>,
}

impl From<PutObjectResult> for S3PutObjectResponse {
    fn from(value: PutObjectResult) -> Self {
        Self {
            etag: value.etag,
            version_id: value.version_id,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AwsBackendError {
    pub code: String,
    pub message: String,
    pub aws_request_id: Option<String>,
}

impl AwsBackendError {
    pub fn new(code: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            code: code.into(),
            message: message.into(),
            aws_request_id: None,
        }
    }

    pub fn with_aws_request_id(mut self, aws_request_id: impl Into<String>) -> Self {
        self.aws_request_id = Some(aws_request_id.into());
        self
    }

    pub fn to_egress_error(&self) -> EgressError {
        let mut err = EgressError::new(self.code.clone(), self.message.clone());
        if let Some(request_id) = &self.aws_request_id {
            err = err.with_aws_request_id(request_id.clone());
        }
        err
    }

    pub fn kms_access_denied(message: impl Into<String>) -> Self {
        Self::new("kms.access_denied", message)
    }

    pub fn kms_invalid_ciphertext(message: impl Into<String>) -> Self {
        Self::new("kms.invalid_ciphertext", message)
    }

    pub fn kms_attestation_mismatch(message: impl Into<String>) -> Self {
        Self::new("kms.attestation_mismatch", message)
    }

    pub fn s3_access_denied(message: impl Into<String>) -> Self {
        Self::new("s3.access_denied", message)
    }

    pub fn s3_no_such_bucket(message: impl Into<String>) -> Self {
        Self::new("s3.no_such_bucket", message)
    }

    pub fn s3_kms_key_disabled(message: impl Into<String>) -> Self {
        Self::new("s3.kms_key_disabled", message)
    }
}

#[derive(Clone)]
pub struct AwsSdkBackend {
    kms: KmsClient,
    s3: S3Client,
}

impl AwsSdkBackend {
    pub fn new(config: &aws_config::SdkConfig) -> Self {
        Self {
            kms: KmsClient::new(config),
            s3: S3Client::new(config),
        }
    }
}

impl AwsBackend for AwsSdkBackend {
    fn kms_decrypt<'a>(&'a self, req: KmsDecryptRequest) -> AwsBackendFuture<'a, Vec<u8>> {
        Box::pin(async move {
            let mut builder = self
                .kms
                .decrypt()
                .key_id(req.key_arn)
                .ciphertext_blob(aws_sdk_kms::primitives::Blob::new(req.ciphertext));

            if let Some(ctx) = req.encryption_context {
                for (key, value) in ctx {
                    builder = builder.encryption_context(key, value);
                }
            }

            let output = builder
                .send()
                .await
                .map_err(|err| classify_kms_error(format!("{err:?}")))?;
            output
                .plaintext()
                .map(|blob| blob.as_ref().to_vec())
                .ok_or_else(|| {
                    AwsBackendError::kms_invalid_ciphertext(
                        "KMS Decrypt response did not include plaintext",
                    )
                })
        })
    }

    fn s3_put_object<'a>(
        &'a self,
        req: S3PutObjectRequest,
    ) -> AwsBackendFuture<'a, PutObjectResult> {
        Box::pin(async move {
            let mut builder = self
                .s3
                .put_object()
                .bucket(req.bucket)
                .key(req.key)
                .body(ByteStream::from(req.body));

            if let Some(content_type) = req.content_type {
                builder = builder.content_type(content_type);
            }
            if let Some(kms_key_arn) = req.kms_key_arn {
                builder = builder
                    .server_side_encryption(ServerSideEncryption::AwsKms)
                    .ssekms_key_id(kms_key_arn);
            }
            if let Some(metadata) = req.metadata {
                for (key, value) in metadata {
                    builder = builder.metadata(key, value);
                }
            }

            let output = builder
                .send()
                .await
                .map_err(|err| classify_s3_error(format!("{err:?}")))?;
            Ok(PutObjectResult {
                etag: output.e_tag().unwrap_or_default().to_string(),
                version_id: output.version_id().map(ToOwned::to_owned),
            })
        })
    }
}

fn classify_kms_error(debug: String) -> AwsBackendError {
    if contains_any(&debug, &["AccessDenied", "NotAuthorized", "Unauthorized"]) {
        AwsBackendError::kms_access_denied(debug)
    } else if contains_any(&debug, &["InvalidCiphertext", "IncorrectKey"]) {
        AwsBackendError::kms_invalid_ciphertext(debug)
    } else if contains_any(&debug, &["Attestation", "Recipient", "PCR"]) {
        AwsBackendError::kms_attestation_mismatch(debug)
    } else {
        AwsBackendError::new("kms.error", debug)
    }
}

fn classify_s3_error(debug: String) -> AwsBackendError {
    if contains_any(&debug, &["NoSuchBucket"]) {
        AwsBackendError::s3_no_such_bucket(debug)
    } else if contains_any(
        &debug,
        &["KMS.Disabled", "KMSInvalidState", "DisabledException"],
    ) {
        AwsBackendError::s3_kms_key_disabled(debug)
    } else if contains_any(&debug, &["AccessDenied", "NotAuthorized", "Unauthorized"]) {
        AwsBackendError::s3_access_denied(debug)
    } else {
        AwsBackendError::new("s3.error", debug)
    }
}

fn contains_any(haystack: &str, needles: &[&str]) -> bool {
    needles.iter().any(|needle| haystack.contains(needle))
}
