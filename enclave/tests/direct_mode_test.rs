//! Integration tests for direct mode (--direct) server.
//!
//! Tests the single-port SecureChannel server that bypasses pipeline orchestration.
//! Run with: cargo test --features mock --test direct_mode_test

#![cfg(feature = "mock")]

use bytes::Bytes;
use confidential_ml_transport::session::channel::Message;
use confidential_ml_transport::{MockProvider, MockVerifier, SecureChannel, SessionConfig};
use ephemeral_ml_common::{AttestationReceipt, ReceiptSigningKey};
use ephemeral_ml_enclave::candle_engine::CandleInferenceEngine;
use ephemeral_ml_enclave::mock::MockAttestationProvider;
use ephemeral_ml_enclave::server::run_direct_tcp;
use serde::{Deserialize, Serialize};
use std::path::Path;

/// Wire-format types matching client's InferenceHandlerInput/Output.
#[derive(Serialize)]
struct InferenceRequest {
    model_id: String,
    input_data: Vec<u8>,
    input_shape: Option<Vec<usize>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    generate: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    max_tokens: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    temperature: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    top_p: Option<f64>,
}

#[derive(Deserialize)]
struct InferenceResponse {
    output_tensor: Vec<f32>,
    receipt: AttestationReceipt,
    generated_text: Option<String>,
}

/// Helper: create an engine with MiniLM loaded. Returns None if test assets missing.
fn create_engine_with_model(model_id: &str) -> Option<CandleInferenceEngine> {
    let config_path = "../test_assets/minilm/config.json";
    let weights_path = "../test_assets/minilm/model.safetensors";
    let tokenizer_path = "../test_assets/minilm/tokenizer.json";

    if !Path::new(config_path).exists()
        || !Path::new(weights_path).exists()
        || !Path::new(tokenizer_path).exists()
    {
        return None;
    }

    let engine = CandleInferenceEngine::new().expect("Failed to create engine");
    let config = std::fs::read(config_path).unwrap();
    let weights = std::fs::read(weights_path).unwrap();
    let tokenizer = std::fs::read(tokenizer_path).unwrap();
    engine
        .register_model(model_id, &config, &weights, &tokenizer)
        .unwrap();
    Some(engine)
}

#[tokio::test]
async fn direct_mode_happy_path() {
    let model_id = "stage-0";
    let engine = match create_engine_with_model(model_id) {
        Some(e) => e,
        None => {
            println!("Skipping test: model assets not found");
            return;
        }
    };

    let receipt_key = ReceiptSigningKey::generate().unwrap();
    let receipt_pk = receipt_key.public_key_bytes();
    let mock_provider = MockAttestationProvider::new();

    // Bind to OS-assigned port
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    drop(listener); // Release so run_direct_tcp can bind

    let addr_str = addr.to_string();

    // Spawn direct-mode server
    let server_handle = tokio::spawn(async move {
        let transport_provider = MockProvider::new();
        let transport_verifier = MockVerifier::new();
        run_direct_tcp(
            engine,
            mock_provider,
            receipt_key,
            &addr_str,
            &transport_provider,
            &transport_verifier,
            [0u8; 32],
        )
        .await
    });

    // Give server a moment to bind
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    // Connect client
    let stream = tokio::net::TcpStream::connect(addr).await.unwrap();
    let client_provider = MockProvider::new();
    let client_verifier = MockVerifier::new();
    let config = SessionConfig::default();

    let mut channel =
        SecureChannel::connect_with_attestation(stream, &client_provider, &client_verifier, config)
            .await
            .unwrap();

    // Extract server's receipt signing key from peer attestation
    let server_pk = channel
        .peer_attestation()
        .and_then(|a| a.user_data.as_ref())
        .and_then(|ud| {
            ephemeral_ml_common::transport_types::EphemeralUserData::from_cbor(ud)
                .ok()
                .map(|d| d.receipt_signing_key)
        });

    // Send inference request
    let request = InferenceRequest {
        model_id: model_id.to_string(),
        input_data: b"Hello, direct mode!".to_vec(),
        input_shape: None,
        generate: None,
        max_tokens: None,
        temperature: None,
        top_p: None,
    };
    let request_bytes = serde_json::to_vec(&request).unwrap();
    channel.send(Bytes::from(request_bytes)).await.unwrap();

    // Receive response
    let msg = channel.recv().await.unwrap();
    let response_bytes = match msg {
        Message::Data(data) => data,
        other => panic!("Expected Data, got {:?}", other),
    };

    let response: InferenceResponse = serde_json::from_slice(&response_bytes).unwrap();

    // Verify output: MiniLM produces 384-dim embeddings
    assert_eq!(response.output_tensor.len(), 384);
    let sum: f32 = response.output_tensor.iter().map(|x| x.abs()).sum();
    assert!(sum > 0.0, "Embeddings should be non-zero");

    // Verify receipt is signed
    assert!(
        response.receipt.signature.is_some(),
        "Receipt must be signed"
    );
    assert_eq!(response.receipt.model_id, model_id);
    assert_eq!(response.receipt.sequence_number, 0);
    assert_eq!(response.receipt.protocol_version, 1);

    // Verify receipt signature if we got the server's public key
    if let Some(pk_bytes) = server_pk {
        assert_eq!(
            pk_bytes, receipt_pk,
            "Server should advertise its receipt key"
        );
        let vk = ed25519_dalek::VerifyingKey::from_bytes(&pk_bytes).unwrap();
        assert!(
            response.receipt.verify_signature(&vk).unwrap(),
            "Receipt signature must verify"
        );
    }

    // Verify response hash binding
    {
        use sha2::{Digest, Sha256};
        let output_bytes: Vec<u8> = response
            .output_tensor
            .iter()
            .flat_map(|f| f.to_le_bytes())
            .collect();
        let expected_hash: [u8; 32] = Sha256::digest(&output_bytes).into();
        assert_eq!(
            response.receipt.response_hash, expected_hash,
            "Receipt response_hash must match output data"
        );
    }

    // Shutdown
    channel.shutdown().await.ok();
    // Server should exit cleanly after channel closes
    let _ = tokio::time::timeout(std::time::Duration::from_secs(2), server_handle).await;
}

#[tokio::test]
async fn direct_mode_malformed_json_no_crash() {
    let model_id = "stage-0";
    let engine = match create_engine_with_model(model_id) {
        Some(e) => e,
        None => {
            println!("Skipping test: model assets not found");
            return;
        }
    };

    let receipt_key = ReceiptSigningKey::generate().unwrap();
    let mock_provider = MockAttestationProvider::new();

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    drop(listener);

    let addr_str = addr.to_string();

    let server_handle = tokio::spawn(async move {
        let transport_provider = MockProvider::new();
        let transport_verifier = MockVerifier::new();
        run_direct_tcp(
            engine,
            mock_provider,
            receipt_key,
            &addr_str,
            &transport_provider,
            &transport_verifier,
            [0u8; 32],
        )
        .await
    });

    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    let stream = tokio::net::TcpStream::connect(addr).await.unwrap();
    let client_provider = MockProvider::new();
    let client_verifier = MockVerifier::new();
    let config = SessionConfig::default();

    let mut channel =
        SecureChannel::connect_with_attestation(stream, &client_provider, &client_verifier, config)
            .await
            .unwrap();

    // Send malformed JSON — server should NOT crash
    channel
        .send(Bytes::from_static(b"this is not json"))
        .await
        .unwrap();

    // Server should send back an error response (not close the channel)
    let msg = channel.recv().await.unwrap();
    let error_bytes = match msg {
        Message::Data(data) => data,
        other => panic!("Expected error Data response, got {:?}", other),
    };

    // Error response should contain an "error" field
    let error_obj: serde_json::Value = serde_json::from_slice(&error_bytes).unwrap();
    assert!(
        error_obj.get("error").is_some(),
        "Error response should have 'error' field, got: {}",
        error_obj
    );

    // Now send a VALID request — server should still work after the bad one
    let request = InferenceRequest {
        model_id: model_id.to_string(),
        input_data: b"Recovery test".to_vec(),
        input_shape: None,
        generate: None,
        max_tokens: None,
        temperature: None,
        top_p: None,
    };
    let request_bytes = serde_json::to_vec(&request).unwrap();
    channel.send(Bytes::from(request_bytes)).await.unwrap();

    let msg = channel.recv().await.unwrap();
    let response_bytes = match msg {
        Message::Data(data) => data,
        other => panic!("Expected Data after recovery, got {:?}", other),
    };

    let response: InferenceResponse = serde_json::from_slice(&response_bytes).unwrap();
    assert_eq!(response.output_tensor.len(), 384);
    assert!(response.receipt.signature.is_some());
    // Sequence should be 0 (first successful inference — failed requests don't increment)
    assert_eq!(response.receipt.sequence_number, 0);

    channel.shutdown().await.ok();
    let _ = tokio::time::timeout(std::time::Duration::from_secs(2), server_handle).await;
}

/// Helper: spawn a direct-mode server and connect a client channel.
/// Returns (channel, server_handle). Skips test if model assets are missing.
async fn setup_direct_server(
    model_id: &str,
) -> Option<(
    SecureChannel<tokio::net::TcpStream>,
    tokio::task::JoinHandle<Result<(), Box<dyn std::error::Error + Send + Sync>>>,
)> {
    let engine = create_engine_with_model(model_id)?;
    let receipt_key = ReceiptSigningKey::generate().unwrap();
    let mock_provider = MockAttestationProvider::new();

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    drop(listener);

    let addr_str = addr.to_string();
    let server_handle = tokio::spawn(async move {
        let transport_provider = MockProvider::new();
        let transport_verifier = MockVerifier::new();
        run_direct_tcp(
            engine,
            mock_provider,
            receipt_key,
            &addr_str,
            &transport_provider,
            &transport_verifier,
            [0u8; 32],
        )
        .await
    });

    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    let stream = tokio::net::TcpStream::connect(addr).await.unwrap();
    let client_provider = MockProvider::new();
    let client_verifier = MockVerifier::new();
    let config = SessionConfig::default();
    let channel =
        SecureChannel::connect_with_attestation(stream, &client_provider, &client_verifier, config)
            .await
            .unwrap();

    Some((channel, server_handle))
}

#[tokio::test]
async fn direct_mode_generate_on_bert_returns_error() {
    let model_id = "stage-0";
    let (mut channel, server_handle) = match setup_direct_server(model_id).await {
        Some(v) => v,
        None => {
            println!("Skipping test: model assets not found");
            return;
        }
    };

    // Request text generation on BERT model — should get an error response, not a crash
    let request = InferenceRequest {
        model_id: model_id.to_string(),
        input_data: b"Generate something".to_vec(),
        input_shape: None,
        generate: Some(true),
        max_tokens: Some(10),
        temperature: None,
        top_p: None,
    };
    let request_bytes = serde_json::to_vec(&request).unwrap();
    channel.send(Bytes::from(request_bytes)).await.unwrap();

    let msg = channel.recv().await.unwrap();
    let response_bytes = match msg {
        Message::Data(data) => data,
        other => panic!("Expected Data response, got {:?}", other),
    };

    // Should be an error response
    let error_obj: serde_json::Value = serde_json::from_slice(&response_bytes).unwrap();
    assert!(
        error_obj.get("error").is_some(),
        "BERT generate should return error, got: {}",
        error_obj
    );

    channel.shutdown().await.ok();
    let _ = tokio::time::timeout(std::time::Duration::from_secs(2), server_handle).await;
}

#[tokio::test]
async fn direct_mode_invalid_top_p_returns_error() {
    let model_id = "stage-0";
    let (mut channel, server_handle) = match setup_direct_server(model_id).await {
        Some(v) => v,
        None => {
            println!("Skipping test: model assets not found");
            return;
        }
    };

    // Request with invalid top_p > 1.0 — should get validation error
    let request = InferenceRequest {
        model_id: model_id.to_string(),
        input_data: b"Invalid params".to_vec(),
        input_shape: None,
        generate: Some(true),
        max_tokens: Some(10),
        temperature: Some(0.7),
        top_p: Some(1.5), // invalid
    };
    let request_bytes = serde_json::to_vec(&request).unwrap();
    channel.send(Bytes::from(request_bytes)).await.unwrap();

    let msg = channel.recv().await.unwrap();
    let response_bytes = match msg {
        Message::Data(data) => data,
        other => panic!("Expected Data response, got {:?}", other),
    };

    let error_obj: serde_json::Value = serde_json::from_slice(&response_bytes).unwrap();
    assert!(
        error_obj.get("error").is_some(),
        "Invalid top_p should return error, got: {}",
        error_obj
    );

    channel.shutdown().await.ok();
    let _ = tokio::time::timeout(std::time::Duration::from_secs(2), server_handle).await;
}

#[tokio::test]
async fn direct_mode_absent_generate_params_use_defaults() {
    let model_id = "stage-0";
    let (mut channel, server_handle) = match setup_direct_server(model_id).await {
        Some(v) => v,
        None => {
            println!("Skipping test: model assets not found");
            return;
        }
    };

    // Send embedding request with generate=false (default), omitting generation params.
    // This verifies null/absent fields don't cause deserialization errors.
    let request = InferenceRequest {
        model_id: model_id.to_string(),
        input_data: b"Testing defaults".to_vec(),
        input_shape: None,
        generate: None,
        max_tokens: None,
        temperature: None,
        top_p: None,
    };
    let request_bytes = serde_json::to_vec(&request).unwrap();
    channel.send(Bytes::from(request_bytes)).await.unwrap();

    let msg = channel.recv().await.unwrap();
    let response_bytes = match msg {
        Message::Data(data) => data,
        other => panic!("Expected Data, got {:?}", other),
    };

    let response: InferenceResponse = serde_json::from_slice(&response_bytes).unwrap();
    // Should succeed as an embedding request (384-dim from MiniLM)
    assert_eq!(response.output_tensor.len(), 384);
    assert!(response.generated_text.is_none());
    assert!(response.receipt.signature.is_some());

    channel.shutdown().await.ok();
    let _ = tokio::time::timeout(std::time::Duration::from_secs(2), server_handle).await;
}
