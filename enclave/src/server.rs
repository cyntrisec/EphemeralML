use confidential_ml_pipeline::{PipelineError, StageConfig, StageExecutor, StageRuntime};
use zeroize::Zeroize;

/// Maximum retries for accepting control connections.
/// Health checks, port scanners, and other non-handshake TCP connections
/// are tolerated and retried.
const MAX_ACCEPT_RETRIES: usize = 50;

/// Base delay for exponential backoff between accept retries (milliseconds).
const ACCEPT_RETRY_BASE_DELAY_MS: u64 = 100;

/// Maximum delay between accept retries (milliseconds).
const ACCEPT_RETRY_MAX_DELAY_MS: u64 = 5000;

/// Maximum size for inference input payloads (16 MB).
const MAX_INPUT_PAYLOAD_SIZE: usize = 16 * 1024 * 1024;

/// Maximum length for model_id strings.
const MAX_MODEL_ID_LEN: usize = 128;

// --- Direct mode types (matching client's InferenceHandlerInput/Output) ---

/// Default max tokens for generation.
const DEFAULT_MAX_TOKENS: usize = 256;
/// Hard cap on max_tokens to prevent runaway generation.
const MAX_TOKENS_LIMIT: usize = 4096;
/// Default sampling temperature.
const DEFAULT_TEMPERATURE: f64 = 0.7;
/// Default top-p (nucleus) sampling threshold.
const DEFAULT_TOP_P: f64 = 0.9;

#[derive(serde::Deserialize)]
struct DirectInferenceRequest {
    model_id: String,
    input_data: Vec<u8>,
    #[allow(dead_code)]
    input_shape: Option<Vec<usize>>,
    /// When true, use autoregressive text generation instead of embeddings/logits.
    #[serde(default)]
    generate: bool,
    /// Maximum number of tokens to generate (only used when generate=true).
    /// Accepts null or absent — defaults to 256, capped at 4096.
    #[serde(default)]
    max_tokens: Option<usize>,
    /// Sampling temperature (only used when generate=true).
    /// Accepts null or absent — defaults to 0.7.
    #[serde(default)]
    temperature: Option<f64>,
    /// Top-p (nucleus) sampling threshold (only used when generate=true).
    /// Accepts null or absent — defaults to 0.9.
    #[serde(default)]
    top_p: Option<f64>,
}

#[derive(serde::Serialize)]
struct DirectInferenceResponse {
    output_tensor: Vec<f32>,
    receipt: ephemeral_ml_common::AttestationReceipt,
    /// Generated text (only present when generate=true).
    #[serde(skip_serializing_if = "Option::is_none")]
    generated_text: Option<String>,
    /// Base64-encoded boot attestation document (raw TEE quote bytes).
    /// Present when the server has boot attestation evidence to provide.
    #[serde(skip_serializing_if = "Option::is_none")]
    boot_attestation_b64: Option<String>,
    /// Model manifest JSON string.
    /// Present when the server loaded a signed model manifest.
    #[serde(skip_serializing_if = "Option::is_none")]
    model_manifest_json: Option<String>,
}

/// Accept a single client SecureChannel on `listen_addr` and serve inference
/// requests directly — no pipeline orchestrator needed.
///
/// Intended for GCP smoke / E2E testing where a client connects with
/// `SecureChannel::connect_with_attestation()` on a single port.
#[allow(clippy::too_many_arguments)]
pub async fn run_direct_tcp<A: crate::AttestationProvider + Send + Sync>(
    engine: crate::CandleInferenceEngine,
    attestation_provider: A,
    receipt_key: ephemeral_ml_common::ReceiptSigningKey,
    listen_addr: &str,
    transport_provider: &(dyn confidential_ml_transport::AttestationProvider + Sync),
    transport_verifier: &(dyn confidential_ml_transport::AttestationVerifier + Sync),
    boot_attestation_hash: [u8; 32],
    boot_attestation_bytes: Option<std::sync::Arc<Vec<u8>>>,
    model_manifest_json: Option<std::sync::Arc<String>>,
) -> std::result::Result<(), Box<dyn std::error::Error + Send + Sync>> {
    use bytes::Bytes;
    use confidential_ml_transport::session::channel::Message;
    use confidential_ml_transport::{SecureChannel, SessionConfig};
    use ephemeral_ml_common::transport_types::ConnectionState;
    use sha2::{Digest, Sha256};

    let listener = tokio::net::TcpListener::bind(listen_addr).await?;
    println!("[direct] Listening on {}", listen_addr);

    // Accept-retry loop: tolerate malformed connections (health checks, probes)
    let mut channel = {
        let mut last_err = None;
        let mut result = None;
        for attempt in 0..MAX_ACCEPT_RETRIES {
            let (stream, peer) = listener.accept().await?;
            stream.set_nodelay(true).ok();

            let config = SessionConfig::default();
            match SecureChannel::accept_with_attestation(
                stream,
                transport_provider,
                transport_verifier,
                config,
            )
            .await
            {
                Ok(ch) => {
                    println!("[direct] Secure channel established with {}", peer);
                    result = Some(ch);
                    break;
                }
                Err(e) => {
                    eprintln!(
                        "[direct] Malformed connection from {} (attempt {}/{}): {}",
                        peer,
                        attempt + 1,
                        MAX_ACCEPT_RETRIES,
                        e,
                    );
                    last_err = Some(e);
                    // Exponential backoff to limit resource exhaustion from rapid probes
                    let delay = std::cmp::min(
                        ACCEPT_RETRY_BASE_DELAY_MS * (1 << attempt.min(6)),
                        ACCEPT_RETRY_MAX_DELAY_MS,
                    );
                    tokio::time::sleep(std::time::Duration::from_millis(delay)).await;
                }
            }
        }
        match result {
            Some(ch) => ch,
            None => {
                return Err(format!(
                    "max accept retries exhausted: {}",
                    last_err.map(|e| e.to_string()).unwrap_or_default()
                )
                .into());
            }
        }
    };

    // Build ConnectionState for receipt generation.
    // boot_attestation_hash binds receipts to hardware attestation evidence.
    // In GCP mode: SHA-256 of the raw TDX quote generated at boot.
    // In mock mode: SHA-256 of the mock attestation document (pre-computed
    // at boot to match what the transport layer will produce).
    // In production (Nitro): set during NSM attestation.
    let attestation_hash = boot_attestation_hash;
    let receipt_pk = receipt_key.public_key_bytes();
    let session_id = hex::encode(Sha256::digest(receipt_pk));
    let mut state = ConnectionState::new(
        session_id,
        receipt_key,
        attestation_hash,
        "direct-client".to_string(),
        1,
    );

    println!("[direct] Ready for inference requests");

    // Request loop
    loop {
        let msg = match channel.recv().await {
            Ok(m) => m,
            Err(e) => {
                println!("[direct] Channel closed: {}", e);
                break;
            }
        };

        match msg {
            Message::Data(bytes) => {
                match handle_direct_request(
                    &bytes,
                    &engine,
                    &attestation_provider,
                    &mut state,
                    boot_attestation_bytes.as_deref(),
                    model_manifest_json.as_deref(),
                ) {
                    Ok(result) => {
                        channel.send(Bytes::from(result.response_json)).await?;
                        println!(
                            "[direct] Response sent: {} floats, {}ms, seq={}",
                            result.n_floats, result.exec_ms, result.sequence,
                        );
                    }
                    Err(e) => {
                        eprintln!("[direct] Request failed: {}", e);
                        // Send redacted error back to client to avoid leaking
                        // internal details (file paths, stack traces).
                        let err_json = serde_json::json!({"error": "Inference request failed"});
                        let err_bytes = serde_json::to_vec(&err_json).unwrap_or_default();
                        if let Err(send_err) = channel.send(Bytes::from(err_bytes)).await {
                            eprintln!("[direct] Failed to send error response: {}", send_err);
                            break;
                        }
                    }
                }
            }
            Message::Shutdown => {
                println!("[direct] Client initiated shutdown");
                break;
            }
            Message::Heartbeat => {}
            other => {
                eprintln!("[direct] Unexpected message: {:?}", other);
            }
        }
    }

    Ok(())
}

/// Successful result from a direct-mode inference request.
struct DirectResult {
    response_json: Vec<u8>,
    n_floats: usize,
    exec_ms: u64,
    sequence: u64,
}

/// Process a single direct-mode inference request.
fn handle_direct_request<A: crate::AttestationProvider>(
    bytes: &[u8],
    engine: &crate::CandleInferenceEngine,
    attestation_provider: &A,
    state: &mut ephemeral_ml_common::transport_types::ConnectionState,
    boot_attestation_bytes: Option<&Vec<u8>>,
    model_manifest_json: Option<&String>,
) -> std::result::Result<DirectResult, Box<dyn std::error::Error + Send + Sync>> {
    let request: DirectInferenceRequest =
        serde_json::from_slice(bytes).map_err(|e| format!("Bad request JSON: {}", e))?;

    // Validate model_id: alphanumeric, hyphens, underscores, dots only
    if request.model_id.len() > MAX_MODEL_ID_LEN
        || !request
            .model_id
            .chars()
            .all(|c| c.is_alphanumeric() || c == '-' || c == '_' || c == '.')
    {
        return Err(format!(
            "Invalid model_id: must be <= {} chars, alphanumeric/hyphens/underscores/dots",
            MAX_MODEL_ID_LEN
        )
        .into());
    }

    // Enforce input payload size limit to prevent OOM in constrained enclave
    if request.input_data.len() > MAX_INPUT_PAYLOAD_SIZE {
        return Err(format!(
            "Input payload too large: {} bytes (max {})",
            request.input_data.len(),
            MAX_INPUT_PAYLOAD_SIZE
        )
        .into());
    }

    println!(
        "[direct] Inference request: model_id={}, input_len={}, generate={}",
        request.model_id,
        request.input_data.len(),
        request.generate,
    );

    let start = std::time::Instant::now();

    let (output_tensor, generated_text) = if request.generate {
        // Resolve defaults for optional generation parameters
        let max_tokens = request
            .max_tokens
            .unwrap_or(DEFAULT_MAX_TOKENS)
            .min(MAX_TOKENS_LIMIT);
        let temperature = request.temperature.unwrap_or(DEFAULT_TEMPERATURE);
        let top_p = request.top_p.unwrap_or(DEFAULT_TOP_P);

        // Validate generation parameters
        if temperature < 0.0 {
            return Err(format!("temperature must be >= 0, got {}", temperature).into());
        }
        if !(0.0..=1.0).contains(&top_p) {
            return Err(format!("top_p must be in [0.0, 1.0], got {}", top_p).into());
        }

        // Text generation mode
        let gen_output = engine.execute_by_id_generate(
            &request.model_id,
            &request.input_data,
            max_tokens,
            temperature,
            top_p,
        )?;
        // Store token IDs as f32 for receipt hash verification
        let token_floats: Vec<f32> = gen_output.token_ids.iter().map(|&id| id as f32).collect();
        (token_floats, Some(gen_output.text))
    } else {
        // Embedding / raw logits mode
        let output = engine.execute_by_id(&request.model_id, &request.input_data)?;
        (output, None)
    };

    let exec_ms = start.elapsed().as_millis() as u64;

    // Compute response bytes for receipt hash
    let mut output_bytes: Vec<u8> = output_tensor.iter().flat_map(|f| f.to_le_bytes()).collect();

    // Resolve receipt model_id: prefer manifest (authoritative) over client request.
    // When a signed manifest is loaded (GCS/GCS-KMS flow), the manifest's model_id
    // is the ground truth. In local/non-manifest mode, use the client request's value.
    let (receipt_model_id, receipt_model_version) = if let Some(manifest_json) = model_manifest_json
    {
        match serde_json::from_str::<ephemeral_ml_common::ModelManifest>(manifest_json) {
            Ok(m) => (m.model_id, m.version),
            Err(_) => (request.model_id.clone(), "1.0".to_string()),
        }
    } else {
        (request.model_id.clone(), "1.0".to_string())
    };

    // Build and sign receipt.
    // Hash the full request bytes (not just input_data) so the client can verify
    // SHA256(serialized_request) == receipt.request_hash.
    state.model_id = receipt_model_id.clone();
    let mut receipt = crate::receipt::ReceiptBuilder::build(
        state,
        attestation_provider,
        bytes,
        &output_bytes,
        receipt_model_id,
        receipt_model_version,
        exec_ms,
        0,
    )?;
    output_bytes.zeroize();

    // Record destroy evidence for the cleanup actions taken during this request.
    receipt.destroy_evidence = Some(ephemeral_ml_common::DestroyEvidence {
        timestamp: ephemeral_ml_common::current_timestamp(),
        actions: vec![
            ephemeral_ml_common::DestroyAction {
                target: "output_bytes".to_string(),
                mechanism: "explicit_zeroize".to_string(),
            },
            ephemeral_ml_common::DestroyAction {
                target: "output_tensor".to_string(),
                mechanism: "explicit_zeroize".to_string(),
            },
            ephemeral_ml_common::DestroyAction {
                target: "generated_text".to_string(),
                mechanism: "explicit_zeroize".to_string(),
            },
            ephemeral_ml_common::DestroyAction {
                target: "session_dek".to_string(),
                mechanism: "drop_on_scope_exit".to_string(),
            },
            ephemeral_ml_common::DestroyAction {
                target: "ephemeral_keypair".to_string(),
                mechanism: "drop_on_scope_exit".to_string(),
            },
        ],
    });

    receipt.sign(&state.receipt_signing_key)?;

    let seq = receipt.sequence_number;
    let n_floats = output_tensor.len();
    use base64::Engine as _;
    let response = DirectInferenceResponse {
        output_tensor,
        receipt,
        generated_text,
        boot_attestation_b64: boot_attestation_bytes
            .map(|b| base64::engine::general_purpose::STANDARD.encode(b)),
        model_manifest_json: model_manifest_json.cloned(),
    };
    let response_json = serde_json::to_vec(&response)?;

    // Zeroize sensitive inference buffers before they are dropped.
    // output_bytes was already consumed above; zeroize the response struct's
    // owned copies of output_tensor and generated_text.
    let mut response = response;
    response.output_tensor.zeroize();
    if let Some(ref mut text) = response.generated_text {
        text.zeroize();
    }

    Ok(DirectResult {
        response_json,
        n_floats,
        exec_ms,
        sequence: seq,
    })
}

/// Start a pipeline stage worker using TCP with accept-retry resilience.
///
/// Binds control and data_in listeners, then runs an accept-retry loop
/// for the control phase to tolerate malformed connections (e.g. Docker
/// health checks or load-balancer probes). Once a real orchestrator
/// connection completes the handshake, proceeds to the data phase.
pub async fn run_stage_tcp<E: StageExecutor + 'static>(
    executor: E,
    config: StageConfig,
    control_addr: &str,
    data_in_addr: &str,
    data_out_addr: std::net::SocketAddr,
    provider: &(dyn confidential_ml_transport::AttestationProvider + Sync),
    verifier: &(dyn confidential_ml_transport::AttestationVerifier + Sync),
) -> std::result::Result<(), PipelineError> {
    let ctrl_listener = tokio::net::TcpListener::bind(control_addr)
        .await
        .map_err(|e| PipelineError::Transport(confidential_ml_transport::Error::Io(e)))?;
    let din_listener = tokio::net::TcpListener::bind(data_in_addr)
        .await
        .map_err(|e| PipelineError::Transport(confidential_ml_transport::Error::Io(e)))?;

    // Clone retry policy before config is moved into the runtime.
    let retry_policy = config.tcp_retry_policy.clone();
    let mut runtime = StageRuntime::new(executor, config);

    // Accept-retry loop: tolerate malformed connections (TCP health checks,
    // port scanners, load-balancer probes) that fail during SecureChannel
    // handshake. Only transport/IO errors trigger retry; protocol/stage
    // errors propagate immediately.
    let control_result = {
        let mut last_err = None;
        let mut result = None;
        for attempt in 0..MAX_ACCEPT_RETRIES {
            let (ctrl_stream, ctrl_peer) =
                ctrl_listener.accept().await.map_err(PipelineError::Io)?;
            ctrl_stream.set_nodelay(true).ok();

            match runtime
                .run_control_phase(ctrl_stream, provider, verifier)
                .await
            {
                Ok(r) => {
                    result = Some(r);
                    break;
                }
                Err(e @ PipelineError::Transport(_) | e @ PipelineError::Io(_)) => {
                    eprintln!(
                        "[server] Malformed connection from {} (attempt {}/{}): {}",
                        ctrl_peer,
                        attempt + 1,
                        MAX_ACCEPT_RETRIES,
                        e,
                    );
                    last_err = Some(e);
                    // Exponential backoff to limit resource exhaustion
                    let delay = std::cmp::min(
                        ACCEPT_RETRY_BASE_DELAY_MS * (1 << attempt.min(6)),
                        ACCEPT_RETRY_MAX_DELAY_MS,
                    );
                    tokio::time::sleep(std::time::Duration::from_millis(delay)).await;
                }
                Err(e) => return Err(e),
            }
        }
        match result {
            Some(r) => r,
            None => {
                return Err(last_err.unwrap_or_else(|| {
                    PipelineError::Protocol("max control-accept retries exhausted".to_string())
                }))
            }
        }
    };

    // Data phase: accept data_in and connect data_out concurrently.
    let (din_stream, dout_stream) = tokio::try_join!(
        async {
            let (stream, _peer) = din_listener.accept().await.map_err(PipelineError::Io)?;
            stream.set_nodelay(true).ok();
            Ok(stream)
        },
        confidential_ml_pipeline::tcp::connect_tcp_retry(data_out_addr, &retry_policy),
    )?;

    runtime
        .run_data_phase(
            control_result.control,
            din_stream,
            dout_stream,
            provider,
            verifier,
        )
        .await
}
