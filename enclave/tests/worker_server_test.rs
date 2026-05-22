//! Worker protocol integration tests over loopback TCP.

#![cfg(feature = "mock")]

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use bytes::Bytes;
use confidential_ml_transport::{
    Message, MockProvider, MockVerifier, SecureChannel, SessionConfig,
};
use ephemeral_ml_common::{
    AttestationReceipt, EnclaveMeasurements, InferenceHandlerInput, InferenceHandlerOutput,
    SecurityMode, WorkerAttestationUserData, WorkerInferenceError, WorkerResponse,
};
use ephemeral_ml_enclave::worker_server::{InferenceHandler, WorkerServer};

struct CannedHandler;

#[async_trait]
impl InferenceHandler for CannedHandler {
    async fn handle(
        &self,
        input: InferenceHandlerInput,
    ) -> Result<InferenceHandlerOutput, WorkerInferenceError> {
        Ok(InferenceHandlerOutput {
            output_tensor: input.input_data.iter().map(|b| *b as f32).collect(),
            receipt: AttestationReceipt::new(
                "tcp-receipt".to_string(),
                1,
                SecurityMode::GatewayOnly,
                EnclaveMeasurements::new(vec![0; 48], vec![1; 48], vec![2; 48]),
                [0; 32],
                [1; 32],
                [2; 32],
                "v1".to_string(),
                0,
                input.model_id,
                "v1".to_string(),
                0,
                0,
            ),
            generated_text: None,
            boot_attestation_b64: None,
            model_manifest_json: None,
            air_v1_receipt_b64: None,
            air_v1_model_hash_scheme: None,
            model_identity_coverage: None,
            bundle_url: None,
            bundle_sha256: None,
            benchmark: None,
        })
    }
}

fn request() -> InferenceHandlerInput {
    InferenceHandlerInput {
        model_id: "tcp-model".to_string(),
        input_data: vec![4, 5, 6],
        input_shape: Some(vec![3]),
        generate: false,
        max_tokens: None,
        temperature: None,
        top_p: None,
        benchmark_mode: None,
        eat_nonce: None,
    }
}

#[tokio::test]
async fn worker_server_tcp_roundtrip_exposes_worker_user_data() {
    let listener = match tokio::net::TcpListener::bind("127.0.0.1:0").await {
        Ok(listener) => listener,
        Err(err) if err.kind() == std::io::ErrorKind::PermissionDenied => {
            eprintln!(
                "skipping worker_server_tcp_roundtrip_exposes_worker_user_data: loopback bind not permitted: {err}"
            );
            return;
        }
        Err(err) => panic!("failed to bind loopback listener: {err}"),
    };
    let addr = listener.local_addr().unwrap();

    let server = WorkerServer::with_worker_identity(
        Arc::new(CannedHandler),
        Arc::new(MockProvider::new()),
        Arc::new(MockVerifier::new()),
        [9; 32],
        "tcp-model",
        [10; 32],
        SessionConfig::development(),
    )
    .unwrap();

    let server_task = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        server.accept_stream(stream).await
    });

    let stream = tokio::net::TcpStream::connect(addr).await.unwrap();
    let mut channel = SecureChannel::connect_with_attestation(
        stream,
        &MockProvider::new(),
        &MockVerifier::new(),
        SessionConfig::development(),
    )
    .await
    .unwrap();

    let user_data = channel
        .peer_attestation()
        .and_then(|attestation| attestation.user_data.as_deref())
        .expect("server attestation should include worker user_data");
    let decoded = WorkerAttestationUserData::from_cbor(user_data).unwrap();
    assert_eq!(decoded.receipt_signing_pubkey, [9; 32]);
    assert_eq!(decoded.model_id, "tcp-model");
    assert_eq!(decoded.model_hash, [10; 32]);

    channel
        .send(Bytes::from(serde_json::to_vec(&request()).unwrap()))
        .await
        .unwrap();
    let response = match channel.recv().await.unwrap() {
        Message::Data(data) => serde_json::from_slice::<WorkerResponse>(&data).unwrap(),
        other => panic!("expected Data response, got {other:?}"),
    };
    match response {
        WorkerResponse::Ok(output) => assert_eq!(output.output_tensor, vec![4.0, 5.0, 6.0]),
        WorkerResponse::Err(err) => panic!("unexpected worker error: {err:?}"),
    }

    channel.shutdown().await.unwrap();
    let result = tokio::time::timeout(Duration::from_secs(2), server_task)
        .await
        .unwrap()
        .unwrap();
    assert!(result.is_ok());
}
