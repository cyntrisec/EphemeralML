//! Integration test: single-stage pipeline with EphemeralML receipt generation.
//!
//! Proves the full pipeline round-trip:
//!   orchestrator → stage control → stage data → executor → receipt → output

#![cfg(all(feature = "mock"))]

use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::time::Duration;

use async_trait::async_trait;
use bytes::Bytes;
use confidential_ml_pipeline::tcp;
use confidential_ml_pipeline::{
    ActivationDType, ActivationSpec, ForwardOutput, OrchestratorConfig, PortSpec, ShardManifest,
    StageConfig, StageEndpoint, StageError, StageExecutor, StageSpec,
};
use confidential_ml_transport::{DType, MockProvider, MockVerifier, OwnedTensor};
use ephemeral_ml_common::{AttestationReceipt, ReceiptSigningKey};
use ephemeral_ml_enclave::mock::MockAttestationProvider;
use ephemeral_ml_enclave::receipt::ReceiptBuilder;

use ephemeral_ml_common::transport_types::ConnectionState;

/// Test executor that mimics EphemeralStageExecutor but without needing a real model.
/// Returns dummy output + signed receipt tensor.
struct ReceiptTestExecutor {
    provider: MockAttestationProvider,
    state: std::sync::Mutex<ConnectionState>,
    model_id: String,
}

impl ReceiptTestExecutor {
    fn new(provider: MockAttestationProvider, receipt_key: ReceiptSigningKey) -> Self {
        let receipt_pk = receipt_key.public_key_bytes();
        let session_id = hex::encode(&receipt_pk[..16]);
        let attestation_hash = {
            use sha2::{Digest, Sha256};
            let hash: [u8; 32] = Sha256::digest(&receipt_pk).into();
            hash
        };
        let state = ConnectionState::new(
            session_id,
            receipt_key,
            attestation_hash,
            "test-pipeline".to_string(),
            1,
        );
        Self {
            provider,
            state: std::sync::Mutex::new(state),
            model_id: String::new(),
        }
    }
}

#[async_trait]
impl StageExecutor for ReceiptTestExecutor {
    async fn init(&mut self, spec: &StageSpec) -> Result<(), StageError> {
        self.model_id = format!("test-stage-{}", spec.stage_idx);
        Ok(())
    }

    async fn forward(
        &self,
        request_id: u64,
        micro_batch: u32,
        inputs: Vec<OwnedTensor>,
    ) -> Result<ForwardOutput, StageError> {
        if inputs.is_empty() {
            return Err(StageError::ForwardFailed {
                request_id,
                micro_batch,
                reason: "No input tensors".to_string(),
            });
        }

        let input_bytes = inputs[0].data.as_ref();

        // Dummy output: echo the input as-is
        let output_bytes = input_bytes.to_vec();
        let output_tensor = OwnedTensor {
            name: "output".to_string(),
            dtype: DType::U8,
            shape: vec![output_bytes.len() as u32],
            data: Bytes::from(output_bytes.clone()),
        };

        // Build and sign receipt
        let receipt = {
            let mut state = self.state.lock().map_err(|_| StageError::ForwardFailed {
                request_id,
                micro_batch,
                reason: "State lock poisoned".to_string(),
            })?;

            let mut receipt = ReceiptBuilder::build(
                &mut state,
                &self.provider,
                input_bytes,
                &output_bytes,
                self.model_id.clone(),
                "v1.0".to_string(),
                0,
                0,
            )
            .map_err(|e| StageError::ForwardFailed {
                request_id,
                micro_batch,
                reason: format!("Receipt build failed: {}", e),
            })?;

            receipt
                .sign(&state.receipt_signing_key)
                .map_err(|e| StageError::ForwardFailed {
                    request_id,
                    micro_batch,
                    reason: format!("Receipt sign failed: {}", e),
                })?;

            receipt
        };

        let receipt_bytes =
            serde_json::to_vec(&receipt).map_err(|e| StageError::ForwardFailed {
                request_id,
                micro_batch,
                reason: format!("Receipt serialize failed: {}", e),
            })?;

        let receipt_tensor = OwnedTensor {
            name: "__receipt__".to_string(),
            dtype: DType::U8,
            shape: vec![receipt_bytes.len() as u32],
            data: Bytes::from(receipt_bytes),
        };

        Ok(ForwardOutput {
            tensors: vec![output_tensor, receipt_tensor],
        })
    }
}

#[tokio::test]
async fn single_stage_pipeline_with_receipts() {
    let localhost: SocketAddr = "127.0.0.1:0".parse().unwrap();

    // 1. Bind stage listeners (OS-assigned ports)
    let (s0_ctrl_lis, s0_ctrl_addr, s0_din_lis, s0_din_addr) =
        tcp::bind_stage_listeners(localhost, localhost)
            .await
            .unwrap();

    // 2. Bind orchestrator data_out listener
    let orch_dout_lis = tokio::net::TcpListener::bind(localhost).await.unwrap();
    let orch_dout_addr = orch_dout_lis.local_addr().unwrap();

    // 3. Build manifest with actual bound addresses
    let manifest = ShardManifest {
        model_name: "receipt-test".into(),
        model_version: "1.0".into(),
        total_layers: 4,
        stages: vec![StageSpec {
            stage_idx: 0,
            layer_start: 0,
            layer_end: 4,
            weight_hashes: vec![],
            expected_measurements: BTreeMap::new(),
            endpoint: StageEndpoint {
                control: PortSpec::Tcp {
                    addr: s0_ctrl_addr.to_string(),
                },
                data_in: PortSpec::Tcp {
                    addr: s0_din_addr.to_string(),
                },
                data_out: PortSpec::Tcp {
                    addr: "0.0.0.0:0".to_string(),
                },
            },
        }],
        activation_spec: ActivationSpec {
            dtype: ActivationDType::F32,
            hidden_dim: 384,
            max_seq_len: 512,
        },
    };

    // 4. Spawn stage worker task
    let s0_handle = tokio::spawn(async move {
        let mock_provider = MockAttestationProvider::new();
        let receipt_key = ReceiptSigningKey::generate().unwrap();

        let executor = ReceiptTestExecutor::new(mock_provider, receipt_key);

        let stage_provider = MockProvider::new();
        let stage_verifier = MockVerifier::new();

        tcp::run_stage_with_listeners(
            executor,
            StageConfig::default(),
            s0_ctrl_lis,
            s0_din_lis,
            orch_dout_addr,
            &stage_provider,
            &stage_verifier,
        )
        .await
        .expect("stage 0 failed");
    });

    // Give stage a moment to accept
    tokio::time::sleep(Duration::from_millis(50)).await;

    // 5. Initialize orchestrator
    let verifier = MockVerifier::new();
    let provider = MockProvider::new();

    let mut orch = tcp::init_orchestrator_tcp(
        OrchestratorConfig::default(),
        manifest,
        orch_dout_lis,
        &verifier,
        &provider,
    )
    .await
    .expect("orchestrator init failed");

    // 6. Health check
    orch.health_check().await.expect("health check failed");

    // 7. Run inference with test input
    let input = vec![vec![OwnedTensor {
        name: "input".to_string(),
        dtype: DType::U8,
        shape: vec![5],
        data: Bytes::from_static(b"hello"),
    }]];

    let result = orch.infer(input, 16).await.expect("inference failed");

    // 8. Verify output structure
    assert_eq!(result.outputs.len(), 1, "expected 1 micro-batch");
    let tensors = &result.outputs[0];
    assert!(tensors.len() >= 2, "expected at least output + receipt tensors");

    // 9. Find and verify receipt tensor
    let receipt_tensor = tensors
        .iter()
        .find(|t| t.name == "__receipt__")
        .expect("no __receipt__ tensor in output");

    let receipt: AttestationReceipt =
        serde_json::from_slice(&receipt_tensor.data).expect("failed to deserialize receipt");

    assert!(!receipt.receipt_id.is_empty(), "receipt_id should not be empty");
    assert_eq!(receipt.sequence_number, 0, "first request should have seq=0");
    assert_eq!(receipt.model_id, "test-stage-0");
    assert_eq!(receipt.model_version, "v1.0");
    assert!(receipt.signature.is_some(), "receipt should be signed");

    // 10. Verify output tensor echoed input
    let output_tensor = tensors
        .iter()
        .find(|t| t.name == "output")
        .expect("no output tensor");
    assert_eq!(output_tensor.data.as_ref(), b"hello");

    // 11. Shutdown
    orch.shutdown().await.expect("shutdown failed");
    s0_handle.await.unwrap();
}
