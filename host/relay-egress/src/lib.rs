pub mod backend;
pub mod config;

use std::collections::HashSet;
use std::fmt;
use std::io;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use backend::AwsBackend;
use ephemeral_ml_common::{
    EgressError, EgressOkResponse, EgressRequest, EgressResponse, KmsDecryptResponse,
};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::Semaphore;
use tokio_vsock::VsockListener;

pub const DEFAULT_SHUTDOWN_GRACE: Duration = Duration::from_secs(30);

pub type EgressRelayResult<T> = Result<T, EgressRelayError>;

#[derive(Debug)]
pub enum EgressRelayError {
    Io(io::Error),
    IdleTimeout(Duration),
    RequestTooLarge { limit: usize },
    ShutdownGraceExceeded { active_connections: usize },
}

impl fmt::Display for EgressRelayError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(err) => write!(f, "I/O error: {err}"),
            Self::IdleTimeout(timeout) => {
                write!(
                    f,
                    "egress request idle timeout after {}s",
                    timeout.as_secs()
                )
            }
            Self::RequestTooLarge { limit } => {
                write!(f, "egress request exceeded max_request_bytes={limit}")
            }
            Self::ShutdownGraceExceeded { active_connections } => write!(
                f,
                "shutdown grace exceeded with {active_connections} active connection(s)"
            ),
        }
    }
}

impl std::error::Error for EgressRelayError {}

impl From<io::Error> for EgressRelayError {
    fn from(value: io::Error) -> Self {
        Self::Io(value)
    }
}

#[derive(Clone, Debug, Default)]
pub struct EgressAllowlist {
    pub allowed_buckets: HashSet<String>,
    pub allowed_kms_keys: HashSet<String>,
}

impl EgressAllowlist {
    pub fn new(allowed_buckets: HashSet<String>, allowed_kms_keys: HashSet<String>) -> Self {
        Self {
            allowed_buckets,
            allowed_kms_keys,
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub struct EgressServerConfig {
    pub max_request_bytes: usize,
    pub max_concurrent: usize,
    pub idle_timeout: Duration,
    pub shutdown_grace: Duration,
}

impl EgressServerConfig {
    pub fn new(max_request_bytes: usize, max_concurrent: usize, idle_timeout: Duration) -> Self {
        Self {
            max_request_bytes,
            max_concurrent,
            idle_timeout,
            shutdown_grace: DEFAULT_SHUTDOWN_GRACE,
        }
    }
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct EgressRunStats {
    pub accepted_connections: u64,
    pub refused_connections: u64,
}

pub async fn run_vsock_listener<S>(
    listener: VsockListener,
    backend: Arc<dyn AwsBackend>,
    allowlist: EgressAllowlist,
    config: EgressServerConfig,
    shutdown: S,
) -> EgressRelayResult<EgressRunStats>
where
    S: std::future::Future<Output = ()> + Send,
{
    let semaphore = Arc::new(Semaphore::new(config.max_concurrent));
    let connection_ids = Arc::new(AtomicU64::new(1));
    let accepted = Arc::new(AtomicU64::new(0));
    let refused = Arc::new(AtomicU64::new(0));

    tokio::pin!(shutdown);
    loop {
        tokio::select! {
            biased;
            _ = &mut shutdown => {
                break;
            }
            accept_result = listener.accept() => {
                let (stream, addr) = accept_result.map_err(EgressRelayError::Io)?;
                let connection_id = connection_ids.fetch_add(1, Ordering::Relaxed);

                let permit = match semaphore.clone().try_acquire_owned() {
                    Ok(permit) => permit,
                    Err(_) => {
                        refused.fetch_add(1, Ordering::Relaxed);
                        tracing::warn!(
                            connection_id,
                            cid = addr.cid(),
                            max_concurrent = config.max_concurrent,
                            "egress connection refused: capacity reached"
                        );
                        drop(stream);
                        continue;
                    }
                };

                accepted.fetch_add(1, Ordering::Relaxed);
                let backend = backend.clone();
                let allowlist = allowlist.clone();
                let idle_timeout = config.idle_timeout;
                let max_request_bytes = config.max_request_bytes;
                tokio::spawn(async move {
                    let _permit = permit;
                    tracing::info!(connection_id, cid = addr.cid(), "egress connection accepted");
                    if let Err(err) = handle_stream(
                        stream,
                        backend,
                        allowlist,
                        max_request_bytes,
                        idle_timeout,
                    ).await {
                        tracing::warn!(
                            connection_id,
                            cid = addr.cid(),
                            error = %err,
                            "egress connection closed with error"
                        );
                    }
                });
            }
        }
    }

    drop(listener);
    let active_connections = config
        .max_concurrent
        .saturating_sub(semaphore.available_permits());
    if active_connections > 0 {
        match tokio::time::timeout(config.shutdown_grace, async {
            loop {
                if semaphore.available_permits() == config.max_concurrent {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        })
        .await
        {
            Ok(()) => {}
            Err(_) => {
                let active_connections = config
                    .max_concurrent
                    .saturating_sub(semaphore.available_permits());
                return Err(EgressRelayError::ShutdownGraceExceeded { active_connections });
            }
        }
    }

    Ok(EgressRunStats {
        accepted_connections: accepted.load(Ordering::Relaxed),
        refused_connections: refused.load(Ordering::Relaxed),
    })
}

pub async fn handle_stream<S>(
    mut stream: S,
    backend: Arc<dyn AwsBackend>,
    allowlist: EgressAllowlist,
    max_request_bytes: usize,
    idle_timeout: Duration,
) -> EgressRelayResult<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    tokio::time::timeout(idle_timeout, async {
        let request_bytes = read_to_end_capped(&mut stream, max_request_bytes).await?;
        let response = handle_request_bytes(&request_bytes, backend, &allowlist).await;
        let response_bytes = response.to_cbor().map_err(|err| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("EgressResponse encoding failed: {err}"),
            )
        })?;
        stream.write_all(&response_bytes).await?;
        stream.shutdown().await?;
        Ok(())
    })
    .await
    .map_err(|_| EgressRelayError::IdleTimeout(idle_timeout))?
}

pub async fn handle_request_bytes(
    request_bytes: &[u8],
    backend: Arc<dyn AwsBackend>,
    allowlist: &EgressAllowlist,
) -> EgressResponse {
    match EgressRequest::from_cbor(request_bytes) {
        Ok(request) => handle_request(request, backend, allowlist).await,
        Err(err) => EgressResponse::Err(EgressError::new(
            "egress.protocol",
            format!("failed to decode EgressRequest: {err}"),
        )),
    }
}

pub async fn handle_request(
    request: EgressRequest,
    backend: Arc<dyn AwsBackend>,
    allowlist: &EgressAllowlist,
) -> EgressResponse {
    match request {
        EgressRequest::KmsDecrypt(req) => {
            if !allowlist.allowed_kms_keys.contains(&req.key_arn) {
                return EgressResponse::Err(EgressError::new(
                    "kms.access_denied",
                    "key arn not in allowlist",
                ));
            }

            match backend.kms_decrypt(req).await {
                Ok(plaintext) => {
                    EgressResponse::Ok(EgressOkResponse::KmsDecrypt(KmsDecryptResponse {
                        plaintext,
                    }))
                }
                Err(err) => EgressResponse::Err(err.to_egress_error()),
            }
        }
        EgressRequest::S3PutObject(req) => {
            if !allowlist.allowed_buckets.contains(&req.bucket) {
                return EgressResponse::Err(EgressError::new(
                    "s3.access_denied",
                    "bucket not in allowlist",
                ));
            }
            if let Some(kms_key_arn) = &req.kms_key_arn {
                if !allowlist.allowed_kms_keys.contains(kms_key_arn) {
                    return EgressResponse::Err(EgressError::new(
                        "s3.access_denied",
                        "SSE-KMS key arn not in allowlist",
                    ));
                }
            }

            match backend.s3_put_object(req).await {
                Ok(result) => EgressResponse::Ok(EgressOkResponse::S3PutObject(result.into())),
                Err(err) => EgressResponse::Err(err.to_egress_error()),
            }
        }
    }
}

async fn read_to_end_capped<S>(
    stream: &mut S,
    max_request_bytes: usize,
) -> EgressRelayResult<Vec<u8>>
where
    S: AsyncRead + Unpin,
{
    let mut out = Vec::new();
    let mut buf = [0u8; 8192];
    loop {
        let n = stream.read(&mut buf).await.map_err(EgressRelayError::Io)?;
        if n == 0 {
            break;
        }
        if out.len().saturating_add(n) > max_request_bytes {
            return Err(EgressRelayError::RequestTooLarge {
                limit: max_request_bytes,
            });
        }
        out.extend_from_slice(&buf[..n]);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::sync::Arc;

    use backend::{AwsBackendError, AwsBackendFuture, PutObjectResult};
    use ephemeral_ml_common::{
        EgressOkResponse, KmsDecryptRequest, S3PutObjectRequest, S3PutObjectResponse,
    };

    use super::*;

    #[derive(Clone)]
    struct TestBackend {
        kms_result: Result<Vec<u8>, AwsBackendError>,
        s3_result: Result<PutObjectResult, AwsBackendError>,
    }

    impl Default for TestBackend {
        fn default() -> Self {
            Self {
                kms_result: Ok(b"plaintext".to_vec()),
                s3_result: Ok(PutObjectResult {
                    etag: "\"etag\"".to_string(),
                    version_id: Some("v1".to_string()),
                }),
            }
        }
    }

    impl AwsBackend for TestBackend {
        fn kms_decrypt<'a>(&'a self, _req: KmsDecryptRequest) -> AwsBackendFuture<'a, Vec<u8>> {
            Box::pin(async move { self.kms_result.clone() })
        }

        fn s3_put_object<'a>(
            &'a self,
            _req: S3PutObjectRequest,
        ) -> AwsBackendFuture<'a, PutObjectResult> {
            Box::pin(async move { self.s3_result.clone() })
        }
    }

    fn allowlist() -> EgressAllowlist {
        EgressAllowlist::new(
            HashSet::from(["customer-evidence".to_string()]),
            HashSet::from([
                "arn:aws:kms:us-east-1:111122223333:key/model".to_string(),
                "arn:aws:kms:us-east-1:111122223333:key/evidence".to_string(),
            ]),
        )
    }

    fn kms_request(key_arn: &str) -> EgressRequest {
        let mut ctx = BTreeMap::new();
        ctx.insert("tenant".to_string(), "tenant-a".to_string());
        EgressRequest::KmsDecrypt(KmsDecryptRequest {
            ciphertext: b"ciphertext".to_vec(),
            key_arn: key_arn.to_string(),
            encryption_context: Some(ctx),
        })
    }

    fn s3_request(bucket: &str, kms_key_arn: Option<&str>) -> EgressRequest {
        EgressRequest::S3PutObject(S3PutObjectRequest {
            bucket: bucket.to_string(),
            key: "bundles/one.bundle.tar.gz".to_string(),
            body: b"bundle".to_vec(),
            content_type: Some("application/gzip".to_string()),
            kms_key_arn: kms_key_arn.map(ToOwned::to_owned),
            metadata: None,
        })
    }

    #[tokio::test]
    async fn kms_decrypt_allowed_key_dispatches_to_backend() {
        let response = handle_request(
            kms_request("arn:aws:kms:us-east-1:111122223333:key/model"),
            Arc::new(TestBackend::default()),
            &allowlist(),
        )
        .await;

        assert_eq!(
            response,
            EgressResponse::Ok(EgressOkResponse::KmsDecrypt(KmsDecryptResponse {
                plaintext: b"plaintext".to_vec()
            }))
        );
    }

    #[tokio::test]
    async fn kms_decrypt_rejects_key_outside_allowlist() {
        let response = handle_request(
            kms_request("arn:aws:kms:us-east-1:111122223333:key/other"),
            Arc::new(TestBackend::default()),
            &allowlist(),
        )
        .await;

        assert_eq!(
            response,
            EgressResponse::Err(EgressError::new(
                "kms.access_denied",
                "key arn not in allowlist"
            ))
        );
    }

    #[tokio::test]
    async fn s3_put_allowed_bucket_and_kms_key_dispatches_to_backend() {
        let response = handle_request(
            s3_request(
                "customer-evidence",
                Some("arn:aws:kms:us-east-1:111122223333:key/evidence"),
            ),
            Arc::new(TestBackend::default()),
            &allowlist(),
        )
        .await;

        assert_eq!(
            response,
            EgressResponse::Ok(EgressOkResponse::S3PutObject(S3PutObjectResponse {
                etag: "\"etag\"".to_string(),
                version_id: Some("v1".to_string())
            }))
        );
    }

    #[tokio::test]
    async fn s3_put_rejects_bucket_outside_allowlist() {
        let response = handle_request(
            s3_request(
                "other-bucket",
                Some("arn:aws:kms:us-east-1:111122223333:key/evidence"),
            ),
            Arc::new(TestBackend::default()),
            &allowlist(),
        )
        .await;

        assert_eq!(
            response,
            EgressResponse::Err(EgressError::new(
                "s3.access_denied",
                "bucket not in allowlist"
            ))
        );
    }

    #[tokio::test]
    async fn s3_put_rejects_sse_kms_key_outside_allowlist() {
        let response = handle_request(
            s3_request(
                "customer-evidence",
                Some("arn:aws:kms:us-east-1:111122223333:key/other"),
            ),
            Arc::new(TestBackend::default()),
            &allowlist(),
        )
        .await;

        assert_eq!(
            response,
            EgressResponse::Err(EgressError::new(
                "s3.access_denied",
                "SSE-KMS key arn not in allowlist"
            ))
        );
    }

    #[tokio::test]
    async fn cbor_request_round_trip_through_stream_handler() {
        let request = s3_request("customer-evidence", None);
        let request_bytes = request.to_cbor().unwrap();
        let (mut client, server) = tokio::io::duplex(4096);

        let server_task = tokio::spawn(handle_stream(
            server,
            Arc::new(TestBackend::default()),
            allowlist(),
            4096,
            Duration::from_secs(1),
        ));

        client.write_all(&request_bytes).await.unwrap();
        client.shutdown().await.unwrap();

        let mut response_bytes = Vec::new();
        client.read_to_end(&mut response_bytes).await.unwrap();
        server_task.await.unwrap().unwrap();

        let response = EgressResponse::from_cbor(&response_bytes).unwrap();
        assert!(matches!(
            response,
            EgressResponse::Ok(EgressOkResponse::S3PutObject(_))
        ));
    }

    #[tokio::test]
    async fn backend_error_maps_to_egress_error() {
        let backend = TestBackend {
            kms_result: Err(AwsBackendError::kms_invalid_ciphertext("bad ciphertext")
                .with_aws_request_id("req-123")),
            s3_result: Ok(PutObjectResult {
                etag: "\"etag\"".to_string(),
                version_id: None,
            }),
        };
        let response = handle_request(
            kms_request("arn:aws:kms:us-east-1:111122223333:key/model"),
            Arc::new(backend),
            &allowlist(),
        )
        .await;

        assert_eq!(
            response,
            EgressResponse::Err(
                EgressError::new("kms.invalid_ciphertext", "bad ciphertext")
                    .with_aws_request_id("req-123")
            )
        );
    }
}
