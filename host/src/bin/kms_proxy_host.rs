use anyhow::{Context, Result};
use aws_config::BehaviorVersion;
use ephemeral_ml_common::{
    audit::{AuditLogRequest, AuditLogResponse},
    storage_protocol::{StorageRequest, StorageResponse},
    KmsProxyErrorCode, KmsProxyRequestEnvelope, KmsProxyResponseEnvelope, KmsResponse, MessageType,
    VSockMessage,
};
use ephemeral_ml_host::aws_proxy::AWSApiProxy;
#[cfg(feature = "production")]
use ephemeral_ml_host::storage::S3WeightStorage;
use ephemeral_ml_host::storage::WeightStorage;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tracing::{error, info, warn};
use tracing_subscriber::{fmt, EnvFilter};

#[cfg(feature = "production")]
use tokio_vsock::VsockListener;

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize logging
    fmt()
        .with_env_filter(EnvFilter::from_default_env().add_directive(tracing::Level::INFO.into()))
        .init();

    // Configuration from environment variables with sensible defaults
    let s3_bucket = std::env::var("EPHEMERALML_S3_BUCKET")
        .unwrap_or_else(|_| "ephemeral-ml-models-demo".to_string());
    let vsock_port: u32 = std::env::var("EPHEMERALML_VSOCK_PORT")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(8082);
    let tcp_port: u16 = std::env::var("EPHEMERALML_VSOCK_PORT")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(8082);
    let cid = 3;
    #[cfg(not(feature = "production"))]
    let _ = (cid, vsock_port);
    #[cfg(feature = "production")]
    let _ = tcp_port;

    let config = aws_config::load_defaults(BehaviorVersion::latest()).await;
    let proxy = AWSApiProxy::new(&config);
    let s3_client = aws_sdk_s3::Client::new(&config);
    #[cfg(feature = "production")]
    let storage = S3WeightStorage::new(s3_client, s3_bucket.clone());
    #[cfg(not(feature = "production"))]
    let _ = s3_client;
    #[cfg(not(feature = "production"))]
    let storage = ephemeral_ml_host::storage::InMemoryWeightStorage::new();

    info!(
        message = "kms-proxy-host starting",
        event = "startup",
        s3_bucket = %s3_bucket,
        vsock_port = vsock_port,
        tcp_port = tcp_port
    );

    #[cfg(feature = "production")]
    {
        info!(
            message = "initialized with real AWS clients",
            event = "init",
            mode = "production"
        );
        let mut listener =
            VsockListener::bind(cid, vsock_port).context("Failed to bind VSock listener")?;
        info!(
            message = "listening",
            event = "listen",
            transport = "vsock",
            port = vsock_port
        );

        loop {
            match listener.accept().await {
                Ok((stream, addr)) => {
                    info!(
                        message = "accepted connection",
                        event = "accept",
                        transport = "vsock",
                        cid = addr.cid()
                    );
                    let proxy = proxy.clone();
                    let storage = storage.clone();
                    tokio::spawn(async move {
                        if let Err(e) = handle_connection(stream, proxy, storage).await {
                            warn!(message = "connection error", event = "conn_error", transport = "vsock", error = %e);
                        }
                    });
                }
                Err(e) => {
                    error!(message = "accept error", event = "accept_error", transport = "vsock", error = %e);
                }
            }
        }
    }

    #[cfg(not(feature = "production"))]
    {
        use tokio::net::TcpListener;
        info!(
            message = "initialized with mock AWS clients",
            event = "init",
            mode = "mock"
        );
        let listener = TcpListener::bind(format!("0.0.0.0:{}", tcp_port))
            .await
            .context("Failed to bind TCP listener")?;
        info!(
            message = "listening",
            event = "listen",
            transport = "tcp",
            port = tcp_port
        );

        loop {
            match listener.accept().await {
                Ok((stream, _addr)) => {
                    info!(
                        message = "accepted connection",
                        event = "accept",
                        transport = "tcp"
                    );
                    let proxy = proxy.clone();
                    let storage = storage.clone();
                    tokio::spawn(async move {
                        if let Err(e) = handle_connection(stream, proxy, storage).await {
                            warn!(message = "connection error", event = "conn_error", transport = "tcp", error = %e);
                        }
                    });
                }
                Err(e) => {
                    error!(message = "accept error", event = "accept_error", transport = "tcp", error = %e);
                }
            }
        }
    }
    #[allow(unreachable_code)]
    Ok(())
}

trait AsyncStream: AsyncReadExt + AsyncWriteExt + Unpin + Send {}
impl<T: AsyncReadExt + AsyncWriteExt + Unpin + Send> AsyncStream for T {}

async fn handle_connection<S: AsyncStream + 'static>(
    mut stream: S,
    proxy: AWSApiProxy,
    storage: impl WeightStorage + Clone + 'static,
) -> Result<()> {
    loop {
        let mut len_buf = [0u8; 4];
        if stream.read_exact(&mut len_buf).await.is_err() {
            break; // Connection closed
        }
        let total_len = u32::from_be_bytes(len_buf) as usize;

        info!(
            event = "frame_header",
            len_prefix = ?len_buf,
            total_len = total_len,
            "received frame header"
        );

        if total_len > ephemeral_ml_common::vsock::MAX_MESSAGE_SIZE + 100 {
            return Err(anyhow::anyhow!("Message too large"));
        }

        let mut body = vec![0u8; total_len];
        stream.read_exact(&mut body).await?;

        // Debug: log first 64 bytes of body
        let preview_len = body.len().min(64);
        info!(
            event = "frame_body",
            body_len = body.len(),
            body_preview = ?&body[..preview_len],
            body_str = ?String::from_utf8_lossy(&body[..preview_len]),
            "received frame body"
        );

        let mut full_buf = Vec::with_capacity(4 + total_len);
        full_buf.extend_from_slice(&len_buf);
        full_buf.extend_from_slice(&body);

        let msg = VSockMessage::decode(&full_buf)?;

        info!(
            event = "frame_decoded",
            msg_type = ?msg.msg_type,
            sequence = msg.sequence,
            payload_len = msg.payload.len(),
            "decoded VSockMessage"
        );

        match msg.msg_type {
            MessageType::KmsProxy => {
                info!(event = "kms_request_raw", payload_len = msg.payload.len());
                let req_env: KmsProxyRequestEnvelope = serde_json::from_slice(&msg.payload).map_err(|e| {
                    error!(event = "kms_parse_error", error = %e, payload = ?String::from_utf8_lossy(&msg.payload));
                    e
                })?;

                info!(
                    event = "kms_request",
                    request_id = %req_env.request_id,
                    trace_id = ?req_env.trace_id,
                    "processing KMS request"
                );

                let kms_result = match req_env.request {
                    ephemeral_ml_common::KmsRequest::Decrypt {
                        ciphertext_blob,
                        key_id,
                        encryption_context,
                        grant_tokens,
                        recipient,
                    } => {
                        proxy
                            .decrypt(
                                ciphertext_blob,
                                key_id,
                                encryption_context,
                                grant_tokens,
                                recipient,
                            )
                            .await
                    }
                    ephemeral_ml_common::KmsRequest::GenerateDataKey {
                        key_id,
                        key_spec,
                        encryption_context,
                        recipient,
                    } => {
                        proxy
                            .generate_data_key(
                                key_id,
                                key_spec,
                                encryption_context,
                                None,
                                recipient,
                            )
                            .await
                    }
                };

                let response_env = match kms_result {
                    Ok((resp, aws_req_id)) => KmsProxyResponseEnvelope {
                        request_id: req_env.request_id,
                        trace_id: req_env.trace_id,
                        kms_request_id: aws_req_id,
                        response: resp,
                    },
                    Err(e) => {
                        error!(event = "kms_error", error = %e, "KMS operation failed");
                        KmsProxyResponseEnvelope {
                            request_id: req_env.request_id,
                            trace_id: req_env.trace_id,
                            kms_request_id: None,
                            response: KmsResponse::Error {
                                code: KmsProxyErrorCode::Internal,
                                message: e.to_string(),
                            },
                        }
                    }
                };

                let resp_payload = serde_json::to_vec(&response_env)?;
                let resp_msg =
                    VSockMessage::new(MessageType::KmsProxy, msg.sequence, resp_payload)?;
                stream.write_all(&resp_msg.encode()).await?;
            }
            MessageType::Storage => {
                info!(
                    event = "storage_request_raw",
                    payload_len = msg.payload.len()
                );
                // Use CBOR for Storage channel - binary-efficient encoding for large payloads
                let req: StorageRequest = serde_cbor::from_slice(&msg.payload).map_err(|e| {
                    error!(event = "storage_parse_error", error = %e);
                    e
                })?;
                info!(event = "storage_request", model_id = %req.model_id, "fetching model data");

                let resp = match storage.retrieve(&req.model_id).await {
                    Ok(data) => StorageResponse::Data {
                        payload: data,
                        is_last: true,
                    },
                    Err(e) => {
                        let err_msg: String = e.to_string();
                        StorageResponse::Error { message: err_msg }
                    }
                };

                // Use CBOR for Storage channel - binary-efficient encoding for large payloads
                let resp_payload = serde_cbor::to_vec(&resp)?;
                let resp_msg = VSockMessage::new(MessageType::Storage, msg.sequence, resp_payload)?;
                stream.write_all(&resp_msg.encode()).await?;
            }
            MessageType::Audit => {
                info!(event = "audit_request_raw", payload_len = msg.payload.len());
                let req: AuditLogRequest = serde_json::from_slice(&msg.payload).map_err(|e| {
                    error!(event = "audit_parse_error", error = %e, payload = ?String::from_utf8_lossy(&msg.payload));
                    e
                })?;

                info!(
                    event = "audit_log",
                    event_type = ?req.entry.event_type,
                    severity = ?req.entry.severity,
                    session_id = ?req.entry.session_id,
                    is_metric = %req.entry.is_metric,
                    details = ?req.entry.details,
                    "[AUDIT] received from enclave"
                );

                let log_entry = serde_json::to_string(&req.entry)? + "\n";
                let log_file = if req.entry.is_metric {
                    "/tmp/metrics.log"
                } else {
                    "/tmp/audit.log"
                };

                use std::fs::OpenOptions;
                use std::io::Write;
                if let Ok(mut file) = OpenOptions::new().create(true).append(true).open(log_file) {
                    let _ = file.write_all(log_entry.as_bytes());
                }

                let resp = AuditLogResponse {
                    success: true,
                    error: None,
                };
                let resp_payload = serde_json::to_vec(&resp)?;
                let resp_msg = VSockMessage::new(MessageType::Audit, msg.sequence, resp_payload)?;
                stream.write_all(&resp_msg.encode()).await?;
            }
            _ => {
                return Err(anyhow::anyhow!("Unsupported message type"));
            }
        }
    }

    Ok(())
}
