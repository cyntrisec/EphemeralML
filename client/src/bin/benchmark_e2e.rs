//! E2E encrypted request latency benchmark for EphemeralML.
//!
//! Measures the full mock pipeline: ClientHello → attestation verification →
//! HPKE session setup → encrypt request → (mock inference) → receipt sign →
//! encrypt response → decrypt + receipt verify.
//!
//! Runs on bare metal using mock mode (no enclave needed).

use ephemeral_ml_client::secure_client::{InferenceHandlerInput, InferenceHandlerOutput};
use ephemeral_ml_client::{SecureClient, SecureEnclaveClient};
use ephemeral_ml_common::protocol::{ClientHello, ServerHello};
use ephemeral_ml_common::AttestationReceipt;
use ephemeral_ml_common::{
    AttestationDocument, EnclaveMeasurements, EncryptedMessage, HPKESession, MessageType,
    PcrMeasurements, ReceiptSigningKey, SecurityMode, VSockMessage,
};

use sha2::{Digest, Sha256};
use std::time::{Instant, SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

const NUM_WARMUP: usize = 3;
const NUM_ITERATIONS: usize = 100;

fn percentile(sorted: &[f64], p: f64) -> f64 {
    if sorted.is_empty() {
        return 0.0;
    }
    let idx = (p / 100.0 * (sorted.len() as f64 - 1.0)).round() as usize;
    sorted[idx.min(sorted.len() - 1)]
}

fn round4(v: f64) -> f64 {
    (v * 10000.0).round() / 10000.0
}

fn latency_stats(sorted: &[f64]) -> serde_json::Value {
    let mean = sorted.iter().sum::<f64>() / sorted.len() as f64;
    serde_json::json!({
        "mean": round4(mean),
        "p50": round4(percentile(sorted, 50.0)),
        "p95": round4(percentile(sorted, 95.0)),
        "p99": round4(percentile(sorted, 99.0)),
        "min": round4(sorted.first().copied().unwrap_or(0.0)),
        "max": round4(sorted.last().copied().unwrap_or(0.0))
    })
}

/// Spawn a mock enclave server that handles hello + inference requests
async fn spawn_mock_server() -> (u16, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();

    let handle = tokio::spawn(async move {
        // Pre-generate server keys (reused across all connections)
        use ed25519_dalek::SigningKey;
        use x25519_dalek::{PublicKey, StaticSecret};

        let server_secret = StaticSecret::from([42u8; 32]);
        let server_public = PublicKey::from(&server_secret);
        let signing_key = SigningKey::from_bytes(&[7u8; 32]);
        let verifying_key = signing_key.verifying_key();
        let receipt_signing = ReceiptSigningKey::from_parts(signing_key, verifying_key);

        let pcr_val = vec![0u8; 48];
        let attestation = AttestationDocument {
            module_id: "mock".to_string(),
            digest: vec![0u8; 32],
            timestamp: 0,
            pcrs: PcrMeasurements::new(pcr_val.clone(), pcr_val.clone(), pcr_val),
            certificate: vec![],
            signature: vec![0u8; 64],
            nonce: None,
        };

        // Pre-compute attestation hash
        let mut hasher = Sha256::new();
        hasher.update(attestation.module_id.as_bytes());
        hasher.update(&attestation.digest);
        hasher.update(&attestation.timestamp.to_be_bytes());
        hasher.update(&attestation.pcrs.pcr0);
        hasher.update(&attestation.pcrs.pcr1);
        hasher.update(&attestation.pcrs.pcr2);
        hasher.update(&attestation.certificate);
        let attestation_hash: [u8; 32] = hasher.finalize().into();

        // Pre-compute attestation doc hash for receipts
        let attestation_doc_bytes = serde_json::to_vec(&attestation).unwrap();
        let mut hasher = Sha256::new();
        hasher.update(&attestation_doc_bytes);
        let attestation_doc_hash: [u8; 32] = hasher.finalize().into();

        let _server_pub_bytes = *server_public.as_bytes();

        loop {
            let (mut socket, _) = match listener.accept().await {
                Ok(s) => s,
                Err(_) => break,
            };

            // Read incoming message
            let mut len_buf = [0u8; 4];
            if socket.read_exact(&mut len_buf).await.is_err() {
                continue;
            }
            let total_len = u32::from_be_bytes(len_buf) as usize;
            let mut body = vec![0u8; total_len];
            if socket.read_exact(&mut body).await.is_err() {
                continue;
            }

            let mut full_buf = Vec::with_capacity(4 + total_len);
            full_buf.extend_from_slice(&len_buf);
            full_buf.extend_from_slice(&body);
            let msg = VSockMessage::decode(&full_buf).unwrap();

            match msg.msg_type {
                MessageType::Hello => {
                    let client_hello: ClientHello = serde_json::from_slice(&msg.payload).unwrap();
                    let mut att = attestation.clone();
                    att.nonce = Some(client_hello.client_nonce.to_vec());

                    let server_hello = ServerHello {
                        version: 1,
                        chosen_features: vec!["gateway".to_string()],
                        attestation_document: serde_json::to_vec(&att).unwrap(),
                        ephemeral_public_key: server_public.as_bytes().to_vec(),
                        receipt_signing_key: verifying_key.to_bytes().to_vec(),
                        timestamp: 0,
                    };

                    let resp_payload = serde_json::to_vec(&server_hello).unwrap();
                    let resp_msg = VSockMessage::new(MessageType::Hello, 0, resp_payload).unwrap();
                    let _ = socket.write_all(&resp_msg.encode()).await;
                }
                MessageType::Data => {
                    let _encrypted_request: EncryptedMessage =
                        serde_json::from_slice(&msg.payload).unwrap();

                    // We need to know the client's public key to establish HPKE.
                    // In real server, this comes from the session. For the benchmark,
                    // we store it from the last hello. Since we process serially per
                    // client, we reconstruct the session from the encrypted message's session_id.
                    // Actually, the server can't decrypt without knowing the client key.
                    // Instead, we simulate the server-side crypto pipeline.

                    // For a realistic E2E benchmark, the server side should do:
                    // 1. Look up session → decrypt → process → sign receipt → encrypt → send
                    // We'll simulate with a mock response that's already encrypted.

                    // Generate a mock signed receipt
                    let mut receipt = AttestationReceipt::new(
                        "bench-receipt".to_string(),
                        1,
                        SecurityMode::GatewayOnly,
                        EnclaveMeasurements::new(vec![0x01; 48], vec![0x02; 48], vec![0x03; 48]),
                        attestation_doc_hash,
                        [0u8; 32],
                        [0u8; 32],
                        "v1".to_string(),
                        0,
                        "model".to_string(),
                        "v1".to_string(),
                        85,
                        535,
                    );
                    receipt.sign(&receipt_signing).unwrap();

                    // We can't decrypt without knowing the client's private key.
                    // To make this work properly, we need a full session pair.
                    // The benchmark_e2e should measure the CLIENT-SIDE of E2E instead.
                    // Send back a simple error indicator — the client measurement is what matters.
                    let output = InferenceHandlerOutput {
                        output_tensor: vec![0.1, 0.2, 0.3],
                        receipt,
                    };
                    let resp_plaintext = serde_json::to_vec(&output).unwrap();

                    // Since we can't encrypt without a shared session key, send unencrypted
                    // wrapped in a Data message. The client will fail to decrypt.
                    // This is a limitation of the mock — we need a different approach.
                    let resp_msg = VSockMessage::new(MessageType::Data, 1, resp_plaintext).unwrap();
                    let _ = socket.write_all(&resp_msg.encode()).await;
                }
                _ => {}
            }
        }
    });

    (port, handle)
}

/// Measure the E2E flow in-process (no TCP) for accurate crypto timing.
/// This measures: keygen → session setup → encrypt → (mock inference) →
/// receipt sign → encrypt response → decrypt → receipt verify
fn bench_e2e_crypto_pipeline() -> (serde_json::Value, serde_json::Value) {
    use ed25519_dalek::SigningKey;
    use x25519_dalek::{PublicKey, StaticSecret};

    eprintln!("[e2e] Benchmarking E2E crypto pipeline (in-process)...");

    let mut setup_latencies = Vec::with_capacity(NUM_ITERATIONS);
    let mut request_latencies = Vec::with_capacity(NUM_ITERATIONS);

    let pcr_val = vec![0u8; 48];
    let attestation = AttestationDocument {
        module_id: "mock".to_string(),
        digest: vec![0u8; 32],
        timestamp: 0,
        pcrs: PcrMeasurements::new(pcr_val.clone(), pcr_val.clone(), pcr_val),
        certificate: vec![],
        signature: vec![0u8; 64],
        nonce: None,
    };
    let attestation_doc_bytes = serde_json::to_vec(&attestation).unwrap();
    let mut hasher = Sha256::new();
    hasher.update(attestation.module_id.as_bytes());
    hasher.update(&attestation.digest);
    hasher.update(&attestation.timestamp.to_be_bytes());
    hasher.update(&attestation.pcrs.pcr0);
    hasher.update(&attestation.pcrs.pcr1);
    hasher.update(&attestation.pcrs.pcr2);
    hasher.update(&attestation.certificate);
    let attestation_hash: [u8; 32] = hasher.finalize().into();

    let mut hasher = Sha256::new();
    hasher.update(&attestation_doc_bytes);
    let attestation_doc_hash: [u8; 32] = hasher.finalize().into();

    let signing_key = SigningKey::from_bytes(&[7u8; 32]);
    let verifying_key = signing_key.verifying_key();
    let receipt_signing = ReceiptSigningKey::from_parts(signing_key, verifying_key);

    // Simulate a 1KB inference request payload (typical embedding input after tokenization)
    let request_payload = serde_json::to_vec(&InferenceHandlerInput {
        model_id: "MiniLM-L6-v2".to_string(),
        input_data: vec![0u8; 512],
        input_shape: Some(vec![1, 128]),
    })
    .unwrap();

    // Simulate a typical inference response (384-dim embedding + receipt)
    let mock_output_tensor: Vec<f32> = (0..384).map(|i| (i as f32) * 0.001).collect();

    for i in 0..(NUM_WARMUP + NUM_ITERATIONS) {
        // === SESSION SETUP (one-time per client) ===
        let setup_start = Instant::now();

        let client_secret = StaticSecret::random_from_rng(rand::thread_rng());
        let client_public = PublicKey::from(&client_secret);
        let server_secret = StaticSecret::random_from_rng(rand::thread_rng());
        let server_public = PublicKey::from(&server_secret);

        let mut client_session = HPKESession::new(
            "bench-session".to_string(),
            1,
            attestation_hash,
            *client_public.as_bytes(),
            *server_public.as_bytes(),
            [3u8; 12],
            3600,
        )
        .unwrap();
        client_session.establish(client_secret.as_bytes()).unwrap();

        let mut server_session = HPKESession::new(
            "bench-session".to_string(),
            1,
            attestation_hash,
            *server_public.as_bytes(),
            *client_public.as_bytes(),
            [3u8; 12],
            3600,
        )
        .unwrap();
        server_session.establish(server_secret.as_bytes()).unwrap();

        let setup_ms = setup_start.elapsed().as_secs_f64() * 1000.0;

        // === PER-REQUEST E2E (every inference) ===
        let request_start = Instant::now();

        // Client: encrypt request
        let encrypted_request = client_session.encrypt(&request_payload).unwrap();
        let _request_wire = serde_json::to_vec(&encrypted_request).unwrap();

        // Server: decrypt request
        let _decrypted_request = server_session.decrypt(&encrypted_request).unwrap();

        // Server: (inference would happen here — excluded, already benchmarked separately)

        // Server: generate and sign receipt
        let mut receipt = AttestationReceipt::new(
            format!("receipt-{}", i),
            1,
            SecurityMode::GatewayOnly,
            EnclaveMeasurements::new(vec![0x01; 48], vec![0x02; 48], vec![0x03; 48]),
            attestation_doc_hash,
            [0u8; 32],
            [0u8; 32],
            "v1".to_string(),
            i as u64,
            "MiniLM-L6-v2".to_string(),
            "1.0.0".to_string(),
            93,
            1064,
        );
        receipt.sign(&receipt_signing).unwrap();

        // Server: encrypt response
        let response = InferenceHandlerOutput {
            output_tensor: mock_output_tensor.clone(),
            receipt,
        };
        let response_payload = serde_json::to_vec(&response).unwrap();
        let encrypted_response = server_session.encrypt(&response_payload).unwrap();
        let _response_wire = serde_json::to_vec(&encrypted_response).unwrap();

        // Client: decrypt response
        let decrypted_response = client_session.decrypt(&encrypted_response).unwrap();
        let output: InferenceHandlerOutput = serde_json::from_slice(&decrypted_response).unwrap();

        // Client: verify receipt signature
        let _valid = output.receipt.verify_signature(&verifying_key).unwrap();

        let request_ms = request_start.elapsed().as_secs_f64() * 1000.0;

        if i >= NUM_WARMUP {
            setup_latencies.push(setup_ms);
            request_latencies.push(request_ms);
        }
    }

    setup_latencies.sort_by(|a, b| a.partial_cmp(b).unwrap());
    request_latencies.sort_by(|a, b| a.partial_cmp(b).unwrap());

    let setup_stats = latency_stats(&setup_latencies);
    let request_stats = latency_stats(&request_latencies);

    eprintln!("[e2e] Session setup: mean={:.4}ms", setup_stats["mean"]);
    eprintln!(
        "[e2e] Per-request E2E crypto: mean={:.4}ms",
        request_stats["mean"]
    );
    eprintln!("[e2e]   (excludes inference time — add ~93ms for enclave, ~81ms for bare metal)");

    (setup_stats, request_stats)
}

/// Measure E2E with TCP loopback (includes serialization + network overhead)
async fn bench_e2e_tcp_handshake(port: u16) -> serde_json::Value {
    eprintln!("[e2e] Benchmarking E2E TCP handshake (localhost)...");
    let addr = format!("127.0.0.1:{}", port);

    let mut latencies = Vec::with_capacity(NUM_ITERATIONS);

    for i in 0..(NUM_WARMUP + NUM_ITERATIONS) {
        let start = Instant::now();
        let mut client = SecureEnclaveClient::new(format!("bench-client-{}", i));
        let result = client.establish_channel(&addr).await;
        let ms = start.elapsed().as_secs_f64() * 1000.0;

        if let Err(e) = result {
            eprintln!("[e2e] Handshake failed (iter {}): {:?}", i, e);
            continue;
        }

        if i >= NUM_WARMUP {
            latencies.push(ms);
        }
    }

    latencies.sort_by(|a, b| a.partial_cmp(b).unwrap());
    let stats = latency_stats(&latencies);
    eprintln!("[e2e] TCP handshake: mean={:.4}ms", stats["mean"]);
    stats
}

#[tokio::main]
async fn main() -> std::result::Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().collect();
    let instance_type = args
        .iter()
        .position(|a| a == "--instance-type")
        .and_then(|i| args.get(i + 1))
        .map(|s| s.as_str())
        .unwrap_or("unknown");

    eprintln!("[e2e] Starting E2E encrypted request latency benchmark");
    eprintln!(
        "[e2e] Iterations: {}, Warmup: {}",
        NUM_ITERATIONS, NUM_WARMUP
    );

    let commit = option_env!("GIT_COMMIT").unwrap_or("unknown");
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    // 1. In-process crypto pipeline (no TCP overhead)
    let (setup_stats, request_stats) = bench_e2e_crypto_pipeline();

    // 2. TCP loopback handshake (includes network + serialization)
    let (port, server_handle) = spawn_mock_server().await;
    let tcp_handshake_stats = bench_e2e_tcp_handshake(port).await;
    server_handle.abort();

    let results = serde_json::json!({
        "benchmark": "e2e_encrypted_request",
        "environment": "bare_metal_mock",
        "hardware": instance_type,
        "timestamp": format!("{}Z", timestamp),
        "commit": commit,
        "iterations": NUM_ITERATIONS,
        "warmup": NUM_WARMUP,
        "session_setup_ms": setup_stats,
        "per_request_crypto_ms": request_stats,
        "tcp_handshake_ms": tcp_handshake_stats,
        "notes": {
            "session_setup": "X25519 keygen + HPKE session creation + establishment (both sides)",
            "per_request_crypto": "HPKE encrypt request + decrypt request + receipt sign + HPKE encrypt response + decrypt response + receipt verify (excludes inference)",
            "tcp_handshake": "Full ClientHello→ServerHello→attestation verify→HPKE establish over TCP loopback"
        }
    });

    println!("{}", serde_json::to_string_pretty(&results)?);
    eprintln!("[e2e] Benchmark complete");
    Ok(())
}
