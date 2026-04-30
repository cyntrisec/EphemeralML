use anyhow::{Context, Result};
use aws_config::BehaviorVersion;
use ephemeral_ml_common::{
    audit::{AuditLogRequest, AuditLogResponse},
    storage_protocol::{StorageRequest, StorageResponse},
    transport_types::simple_frame::{self, TAG_AUDIT, TAG_KMS, TAG_STORAGE},
    KmsProxyErrorCode, KmsProxyRequestEnvelope, KmsProxyResponseEnvelope, KmsResponse,
};
use ephemeral_ml_host::aws_proxy::AWSApiProxy;
#[cfg(feature = "production")]
use ephemeral_ml_host::storage::S3WeightStorage;
use ephemeral_ml_host::storage::WeightStorage;
use std::time::Instant;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::time::{timeout, Duration};
use tracing::{error, info, warn};
use tracing_subscriber::{fmt, EnvFilter};

#[cfg(feature = "production")]
use tokio_vsock::{VsockAddr, VsockListener, VMADDR_CID_ANY};

const STORAGE_CHUNK_SIZE: usize = 16 * 1024 * 1024;
const DEFAULT_AWS_KMS_TIMEOUT_SECS: u64 = 30;

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
    let tcp_port: u16 = std::env::var("EPHEMERALML_TCP_PORT")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(8082);
    #[cfg(not(feature = "production"))]
    let _ = vsock_port;
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
        let listener = VsockListener::bind(VsockAddr::new(VMADDR_CID_ANY, vsock_port))
            .context("Failed to bind VSock listener")?;
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
        // Read tagged frame using simple_frame
        let (tag, payload) = match simple_frame::read_frame(&mut stream).await {
            Ok(frame) => frame,
            Err(_) => break, // Connection closed
        };

        info!(
            event = "frame_received",
            tag = tag,
            payload_len = payload.len(),
            "received simple_frame"
        );

        match tag {
            TAG_KMS => {
                info!(event = "kms_request_raw", payload_len = payload.len());
                let req_env: KmsProxyRequestEnvelope =
                    serde_json::from_slice(&payload).map_err(|e| {
                        error!(event = "kms_parse_error", error = %e);
                        e
                    })?;

                info!(
                    event = "kms_request",
                    request_id = %req_env.request_id,
                    trace_id = ?req_env.trace_id,
                    "processing KMS request"
                );

                let kms_timeout = std::env::var("EPHEMERALML_KMS_PROXY_AWS_TIMEOUT_SECS")
                    .ok()
                    .and_then(|v| v.parse::<u64>().ok())
                    .unwrap_or(DEFAULT_AWS_KMS_TIMEOUT_SECS);
                let kms_started = Instant::now();

                let timed_kms_result = match req_env.request {
                    ephemeral_ml_common::KmsRequest::Decrypt {
                        ciphertext_blob,
                        key_id,
                        encryption_context,
                        grant_tokens,
                        recipient,
                    } => {
                        maybe_dump_recipient(&req_env.request_id, recipient.as_deref());
                        timeout(
                            Duration::from_secs(kms_timeout),
                            proxy.decrypt(
                                ciphertext_blob,
                                key_id,
                                encryption_context,
                                grant_tokens,
                                recipient,
                            ),
                        )
                        .await
                    }
                    ephemeral_ml_common::KmsRequest::GenerateDataKey {
                        key_id,
                        key_spec,
                        encryption_context,
                        recipient,
                    } => {
                        maybe_dump_recipient(&req_env.request_id, recipient.as_deref());
                        timeout(
                            Duration::from_secs(kms_timeout),
                            proxy.generate_data_key(
                                key_id,
                                key_spec,
                                encryption_context,
                                None,
                                recipient,
                            ),
                        )
                        .await
                    }
                };
                let kms_result = match timed_kms_result {
                    Ok(result) => result,
                    Err(_) => {
                        warn!(
                            event = "kms_timeout",
                            request_id = %req_env.request_id,
                            timeout_secs = kms_timeout,
                            elapsed_ms = kms_started.elapsed().as_millis() as u64,
                            "KMS operation timed out"
                        );
                        Err(ephemeral_ml_host::HostError::Host(
                            ephemeral_ml_common::EphemeralError::KmsError(
                                "KMS operation timed out".to_string(),
                            ),
                        ))
                    }
                };
                info!(
                    event = "kms_request_complete",
                    request_id = %req_env.request_id,
                    elapsed_ms = kms_started.elapsed().as_millis() as u64,
                    success = kms_result.is_ok()
                );

                let response_env = match kms_result {
                    Ok((resp, aws_req_id)) => KmsProxyResponseEnvelope {
                        request_id: req_env.request_id,
                        trace_id: req_env.trace_id,
                        kms_request_id: aws_req_id,
                        response: resp,
                    },
                    Err(e) => {
                        // Log full error on host only — never forward details to enclave
                        error!(event = "kms_error", error = %e, "KMS operation failed");
                        KmsProxyResponseEnvelope {
                            request_id: req_env.request_id,
                            trace_id: req_env.trace_id,
                            kms_request_id: None,
                            response: KmsResponse::Error {
                                code: KmsProxyErrorCode::Internal,
                                message: "KMS operation failed".to_string(),
                            },
                        }
                    }
                };

                let resp_payload = serde_json::to_vec(&response_env)?;
                simple_frame::write_frame(&mut stream, TAG_KMS, &resp_payload)
                    .await
                    .map_err(|e| anyhow::anyhow!("write_frame error: {}", e))?;
            }
            TAG_STORAGE => {
                info!(event = "storage_request_raw", payload_len = payload.len());
                let req: StorageRequest =
                    ephemeral_ml_common::cbor::from_slice(&payload).map_err(|e| {
                        error!(event = "storage_parse_error", error = %e);
                        e
                    })?;
                info!(event = "storage_request", model_id = %req.model_id, "fetching model data");

                match storage.retrieve(&req.model_id).await {
                    Ok(data) => {
                        let total_len = data.len();
                        let mut part_count = 0usize;
                        if data.is_empty() {
                            let resp = StorageResponse::Data {
                                payload: Vec::new(),
                                is_last: true,
                            };
                            let resp_payload = ephemeral_ml_common::cbor::to_vec(&resp)?;
                            simple_frame::write_frame(&mut stream, TAG_STORAGE, &resp_payload)
                                .await
                                .map_err(|e| anyhow::anyhow!("write_frame error: {}", e))?;
                        } else {
                            for (idx, chunk) in data.chunks(STORAGE_CHUNK_SIZE).enumerate() {
                                let is_last = (idx + 1) * STORAGE_CHUNK_SIZE >= total_len;
                                let resp = StorageResponse::Data {
                                    payload: chunk.to_vec(),
                                    is_last,
                                };
                                let resp_payload = ephemeral_ml_common::cbor::to_vec(&resp)?;
                                info!(
                                    event = "storage_response_chunk",
                                    model_id = %req.model_id,
                                    part_index = idx,
                                    payload_len = chunk.len(),
                                    total_len = total_len,
                                    is_last = is_last
                                );
                                simple_frame::write_frame(&mut stream, TAG_STORAGE, &resp_payload)
                                    .await
                                    .map_err(|e| anyhow::anyhow!("write_frame error: {}", e))?;
                                part_count += 1;
                            }
                        }
                        info!(
                            event = "storage_response_complete",
                            model_id = %req.model_id,
                            total_len = total_len,
                            part_count = part_count
                        );
                    }
                    Err(e) => {
                        let resp = StorageResponse::Error {
                            message: e.to_string(),
                        };
                        let resp_payload = ephemeral_ml_common::cbor::to_vec(&resp)?;
                        simple_frame::write_frame(&mut stream, TAG_STORAGE, &resp_payload)
                            .await
                            .map_err(|e| anyhow::anyhow!("write_frame error: {}", e))?;
                    }
                }
            }
            TAG_AUDIT => {
                info!(event = "audit_request_raw", payload_len = payload.len());

                // Reject oversized audit payloads (max 64 KB)
                const MAX_AUDIT_PAYLOAD: usize = 65_536;
                if payload.len() > MAX_AUDIT_PAYLOAD {
                    warn!(
                        event = "audit_rejected",
                        payload_len = payload.len(),
                        "Audit entry too large, rejecting"
                    );
                    let resp = AuditLogResponse {
                        success: false,
                        error: Some("Audit entry too large".to_string()),
                    };
                    let resp_payload = serde_json::to_vec(&resp)?;
                    simple_frame::write_frame(&mut stream, TAG_AUDIT, &resp_payload)
                        .await
                        .map_err(|e| anyhow::anyhow!("write_frame error: {}", e))?;
                    continue;
                }

                let req: AuditLogRequest = serde_json::from_slice(&payload).map_err(|e| {
                    error!(event = "audit_parse_error", error = %e);
                    e
                })?;

                // Sanitize: enforce field size limits
                const MAX_DETAIL_KEYS: usize = 20;
                const MAX_DETAIL_KEY_LEN: usize = 64;
                const MAX_DETAIL_VALUE_LEN: usize = 1024;
                const MAX_SESSION_ID_LEN: usize = 128;

                let details_valid = req.entry.details.len() <= MAX_DETAIL_KEYS
                    && req.entry.details.keys().all(|k| {
                        k.len() <= MAX_DETAIL_KEY_LEN
                            && k.chars()
                                .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '.')
                    })
                    && req
                        .entry
                        .details
                        .values()
                        .all(|v| v.to_string().len() <= MAX_DETAIL_VALUE_LEN);

                let session_id_valid = req
                    .entry
                    .session_id
                    .as_ref()
                    .is_none_or(|s| s.len() <= MAX_SESSION_ID_LEN);

                if !details_valid || !session_id_valid {
                    warn!(
                        event = "audit_sanitization_failed",
                        details_count = req.entry.details.len(),
                        "Audit entry failed field validation"
                    );
                    let resp = AuditLogResponse {
                        success: false,
                        error: Some("Audit entry failed field validation".to_string()),
                    };
                    let resp_payload = serde_json::to_vec(&resp)?;
                    simple_frame::write_frame(&mut stream, TAG_AUDIT, &resp_payload)
                        .await
                        .map_err(|e| anyhow::anyhow!("write_frame error: {}", e))?;
                    continue;
                }

                info!(
                    event = "audit_log",
                    event_type = ?req.entry.event_type,
                    severity = ?req.entry.severity,
                    session_id = ?req.entry.session_id,
                    is_metric = %req.entry.is_metric,
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
                simple_frame::write_frame(&mut stream, TAG_AUDIT, &resp_payload)
                    .await
                    .map_err(|e| anyhow::anyhow!("write_frame error: {}", e))?;
            }
            _ => {
                return Err(anyhow::anyhow!("Unsupported tag: 0x{:02x}", tag));
            }
        }
    }

    Ok(())
}

fn maybe_dump_recipient(request_id: &str, recipient: Option<&[u8]>) {
    let Some(recipient) = recipient else {
        return;
    };
    let Ok(dir) = std::env::var("EPHEMERALML_KMS_PROXY_DUMP_DIR") else {
        return;
    };
    if dir.trim().is_empty() {
        return;
    }
    if let Err(e) = std::fs::create_dir_all(&dir) {
        warn!(event = "kms_recipient_dump_failed", error = %e, "failed to create dump dir");
        return;
    }
    let safe_request_id: String = request_id
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || *c == '-')
        .collect();
    let path = std::path::Path::new(&dir).join(format!("recipient-{safe_request_id}.cbor"));
    match std::fs::write(&path, recipient) {
        Ok(()) => info!(event = "kms_recipient_dumped", path = %path.display()),
        Err(e) => warn!(event = "kms_recipient_dump_failed", error = %e),
    }
}
