use confidential_ml_pipeline::{PipelineError, StageConfig, StageExecutor, StageRuntime};

/// Maximum retries for accepting control connections.
/// Health checks, port scanners, and other non-handshake TCP connections
/// are tolerated and retried.
const MAX_ACCEPT_RETRIES: usize = 50;

// --- Direct mode types (matching client's InferenceHandlerInput/Output) ---

#[derive(serde::Deserialize)]
struct DirectInferenceRequest {
    model_id: String,
    input_data: Vec<u8>,
    #[allow(dead_code)]
    input_shape: Option<Vec<usize>>,
}

#[derive(serde::Serialize)]
struct DirectInferenceResponse {
    output_tensor: Vec<f32>,
    receipt: ephemeral_ml_common::AttestationReceipt,
}

/// Accept a single client SecureChannel on `listen_addr` and serve inference
/// requests directly — no pipeline orchestrator needed.
///
/// Intended for GCP smoke / E2E testing where a client connects with
/// `SecureChannel::connect_with_attestation()` on a single port.
pub async fn run_direct_tcp<A: crate::AttestationProvider + Send + Sync>(
    engine: crate::CandleInferenceEngine,
    attestation_provider: A,
    receipt_key: ephemeral_ml_common::ReceiptSigningKey,
    listen_addr: &str,
    transport_provider: &(dyn confidential_ml_transport::AttestationProvider + Sync),
    transport_verifier: &(dyn confidential_ml_transport::AttestationVerifier + Sync),
    boot_attestation_hash: [u8; 32],
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
                match handle_direct_request(&bytes, &engine, &attestation_provider, &mut state) {
                    Ok(result) => {
                        channel.send(Bytes::from(result.response_json)).await?;
                        println!(
                            "[direct] Response sent: {} floats, {}ms, seq={}",
                            result.n_floats, result.exec_ms, result.sequence,
                        );
                    }
                    Err(e) => {
                        eprintln!("[direct] Request failed: {}", e);
                        // Send error back to client as a JSON object so the
                        // channel stays open for subsequent requests.
                        let err_json = serde_json::json!({"error": e.to_string()});
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
) -> std::result::Result<DirectResult, Box<dyn std::error::Error + Send + Sync>> {
    let request: DirectInferenceRequest =
        serde_json::from_slice(bytes).map_err(|e| format!("Bad request JSON: {}", e))?;

    println!(
        "[direct] Inference request: model_id={}, input_len={}",
        request.model_id,
        request.input_data.len()
    );

    let start = std::time::Instant::now();
    let output = engine.execute_by_id(&request.model_id, &request.input_data)?;
    let exec_ms = start.elapsed().as_millis() as u64;

    // Compute response bytes for receipt hash
    let output_bytes: Vec<u8> = output.iter().flat_map(|f| f.to_le_bytes()).collect();

    // Build and sign receipt
    state.model_id = request.model_id.clone();
    let mut receipt = crate::receipt::ReceiptBuilder::build(
        state,
        attestation_provider,
        &request.input_data,
        &output_bytes,
        request.model_id.clone(),
        "1.0".to_string(),
        exec_ms,
        0,
    )?;
    receipt.sign(&state.receipt_signing_key)?;

    let seq = receipt.sequence_number;
    let n_floats = output.len();
    let response = DirectInferenceResponse {
        output_tensor: output,
        receipt,
    };
    let response_json = serde_json::to_vec(&response)?;
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
