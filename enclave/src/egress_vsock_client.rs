//! Enclave-side client for the parent egress helper.
//!
//! The v1 protocol uses one connection per request. The caller writes one
//! versioned CBOR `EgressRequest`, shuts down the write half, reads one
//! versioned CBOR `EgressResponse`, then closes the connection.

use std::time::Duration;

#[cfg(feature = "production")]
use ephemeral_ml_common::{
    EgressClient, EgressOkResponse, KmsDecryptRequest, S3PutObjectRequest, S3PutObjectResponse,
};
use ephemeral_ml_common::{EgressError, EgressRequest, EgressResponse};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

pub const DEFAULT_MAX_EGRESS_RESPONSE_BYTES: usize = 100 * 1024 * 1024;

pub async fn send_request_over_stream<S>(
    stream: S,
    request: EgressRequest,
    max_response_bytes: usize,
    request_timeout: Duration,
) -> Result<EgressResponse, EgressError>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    tokio::time::timeout(
        request_timeout,
        send_request_over_stream_inner(stream, request, max_response_bytes),
    )
    .await
    .map_err(|_| EgressError::new("egress.timeout", "egress request timed out"))?
}

async fn send_request_over_stream_inner<S>(
    mut stream: S,
    request: EgressRequest,
    max_response_bytes: usize,
) -> Result<EgressResponse, EgressError>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    let request_bytes = request.to_cbor().map_err(|err| {
        EgressError::new(
            "egress.protocol",
            format!("failed to encode EgressRequest: {err}"),
        )
    })?;
    stream.write_all(&request_bytes).await.map_err(|err| {
        EgressError::new(
            "egress.transport_unreachable",
            format!("failed to write egress request: {err}"),
        )
    })?;
    stream.shutdown().await.map_err(|err| {
        EgressError::new(
            "egress.transport_unreachable",
            format!("failed to close egress request stream: {err}"),
        )
    })?;

    let response_bytes = read_to_end_capped(&mut stream, max_response_bytes).await?;
    EgressResponse::from_cbor(&response_bytes).map_err(|err| {
        EgressError::new(
            "egress.protocol",
            format!("failed to decode EgressResponse: {err}"),
        )
    })
}

async fn read_to_end_capped<S>(
    stream: &mut S,
    max_response_bytes: usize,
) -> Result<Vec<u8>, EgressError>
where
    S: AsyncRead + Unpin,
{
    let mut out = Vec::new();
    let mut buf = [0u8; 8192];
    loop {
        let n = stream.read(&mut buf).await.map_err(|err| {
            EgressError::new(
                "egress.transport_unreachable",
                format!("failed to read egress response: {err}"),
            )
        })?;
        if n == 0 {
            break;
        }
        if out.len().saturating_add(n) > max_response_bytes {
            return Err(EgressError::new(
                "egress.response_too_large",
                format!("egress response exceeded max_response_bytes={max_response_bytes}"),
            ));
        }
        out.extend_from_slice(&buf[..n]);
    }
    Ok(out)
}

#[cfg(feature = "production")]
#[derive(Clone, Debug)]
pub struct VsockEgressClient {
    parent_cid: u32,
    egress_port: u32,
    request_timeout: Duration,
    max_response_bytes: usize,
}

#[cfg(feature = "production")]
impl VsockEgressClient {
    pub fn new(parent_cid: u32, egress_port: u32, request_timeout: Duration) -> Self {
        Self {
            parent_cid,
            egress_port,
            request_timeout,
            max_response_bytes: DEFAULT_MAX_EGRESS_RESPONSE_BYTES,
        }
    }

    pub fn with_max_response_bytes(mut self, max_response_bytes: usize) -> Self {
        self.max_response_bytes = max_response_bytes;
        self
    }

    async fn send(&self, request: EgressRequest) -> Result<EgressResponse, EgressError> {
        let stream = tokio_vsock::VsockStream::connect(tokio_vsock::VsockAddr::new(
            self.parent_cid,
            self.egress_port,
        ))
        .await
        .map_err(|err| {
            EgressError::new(
                "egress.transport_unreachable",
                format!(
                    "failed to connect to parent egress vsock cid={} port={}: {}",
                    self.parent_cid, self.egress_port, err
                ),
            )
        })?;
        send_request_over_stream(
            stream,
            request,
            self.max_response_bytes,
            self.request_timeout,
        )
        .await
    }
}

#[cfg(feature = "production")]
#[async_trait::async_trait]
impl EgressClient for VsockEgressClient {
    async fn kms_decrypt(&self, req: KmsDecryptRequest) -> Result<Vec<u8>, EgressError> {
        match self.send(EgressRequest::KmsDecrypt(req)).await? {
            EgressResponse::Ok(EgressOkResponse::KmsDecrypt(resp)) => Ok(resp.plaintext),
            EgressResponse::Ok(other) => Err(EgressError::new(
                "egress.protocol",
                format!("unexpected egress response for KMS decrypt: {other:?}"),
            )),
            EgressResponse::Err(err) => Err(err),
        }
    }

    async fn s3_put_object(
        &self,
        req: S3PutObjectRequest,
    ) -> Result<S3PutObjectResponse, EgressError> {
        match self.send(EgressRequest::S3PutObject(req)).await? {
            EgressResponse::Ok(EgressOkResponse::S3PutObject(resp)) => Ok(resp),
            EgressResponse::Ok(other) => Err(EgressError::new(
                "egress.protocol",
                format!("unexpected egress response for S3 PutObject: {other:?}"),
            )),
            EgressResponse::Err(err) => Err(err),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use ephemeral_ml_common::{EgressOkResponse, KmsDecryptRequest, S3PutObjectRequest};

    use super::*;

    #[tokio::test]
    async fn request_response_round_trip_over_duplex_stream() {
        let (client_stream, mut host_stream) = tokio::io::duplex(4096);
        let host = tokio::spawn(async move {
            let mut request_bytes = Vec::new();
            host_stream.read_to_end(&mut request_bytes).await.unwrap();
            let request = EgressRequest::from_cbor(&request_bytes).unwrap();
            assert!(matches!(request, EgressRequest::KmsDecrypt(_)));

            let response = EgressResponse::Ok(EgressOkResponse::KmsDecrypt(
                ephemeral_ml_common::KmsDecryptResponse {
                    plaintext: b"plaintext".to_vec(),
                },
            ));
            host_stream
                .write_all(&response.to_cbor().unwrap())
                .await
                .unwrap();
            host_stream.shutdown().await.unwrap();
        });

        let mut ctx = BTreeMap::new();
        ctx.insert("tenant".to_string(), "tenant-a".to_string());
        let response = send_request_over_stream(
            client_stream,
            EgressRequest::KmsDecrypt(KmsDecryptRequest {
                ciphertext: b"ciphertext".to_vec(),
                key_arn: "arn:aws:kms:us-east-1:111122223333:key/model".to_string(),
                encryption_context: Some(ctx),
            }),
            4096,
            Duration::from_secs(1),
        )
        .await
        .unwrap();

        host.await.unwrap();
        assert_eq!(
            response,
            EgressResponse::Ok(EgressOkResponse::KmsDecrypt(
                ephemeral_ml_common::KmsDecryptResponse {
                    plaintext: b"plaintext".to_vec()
                }
            ))
        );
    }

    #[tokio::test]
    async fn oversized_response_is_rejected() {
        let (client_stream, mut host_stream) = tokio::io::duplex(4096);
        let host = tokio::spawn(async move {
            let mut request_bytes = Vec::new();
            host_stream.read_to_end(&mut request_bytes).await.unwrap();
            host_stream.write_all(b"too large").await.unwrap();
            host_stream.shutdown().await.unwrap();
        });

        let err = send_request_over_stream(
            client_stream,
            EgressRequest::S3PutObject(S3PutObjectRequest {
                bucket: "customer-evidence".to_string(),
                key: "bundles/one.bundle.tar.gz".to_string(),
                body: b"bundle".to_vec(),
                content_type: None,
                kms_key_arn: None,
                metadata: None,
            }),
            4,
            Duration::from_secs(1),
        )
        .await
        .unwrap_err();

        host.await.unwrap();
        assert_eq!(err.code, "egress.response_too_large");
    }
}
