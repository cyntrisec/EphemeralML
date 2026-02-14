use async_trait::async_trait;
use confidential_ml_pipeline::{ForwardOutput, StageError, StageExecutor, StageSpec};
use confidential_ml_transport::OwnedTensor;

use crate::attestation::AttestationProvider;
use crate::candle_engine::CandleInferenceEngine;
use crate::receipt::ReceiptBuilder;
use ephemeral_ml_common::transport_types::ConnectionState;
use ephemeral_ml_common::ReceiptSigningKey;

use std::sync::Mutex;

/// Implements `StageExecutor` for EphemeralML inference with receipt generation.
///
/// Wraps `CandleInferenceEngine` and produces an `__receipt__` tensor alongside
/// the inference output so the orchestrator can extract compliance artifacts.
pub struct EphemeralStageExecutor<A: AttestationProvider> {
    engine: CandleInferenceEngine,
    attestation_provider: A,
    model_id: String,
    /// Mutable connection state behind a mutex for receipt sequence tracking.
    state: Mutex<ConnectionState>,
}

impl<A: AttestationProvider> EphemeralStageExecutor<A> {
    pub fn new(engine: CandleInferenceEngine, provider: A, receipt_key: ReceiptSigningKey) -> Self {
        let receipt_pk = receipt_key.public_key_bytes();
        let session_id = hex::encode(&receipt_pk[..16]);
        let attestation_hash = {
            use sha2::{Digest, Sha256};
            let hash: [u8; 32] = Sha256::digest(receipt_pk).into();
            hash
        };
        let state = ConnectionState::new(
            session_id,
            receipt_key,
            attestation_hash,
            "pipeline".to_string(),
            1,
        );

        Self {
            engine,
            attestation_provider: provider,
            model_id: String::new(),
            state: Mutex::new(state),
        }
    }
}

#[async_trait]
impl<A: AttestationProvider + Send + Sync> StageExecutor for EphemeralStageExecutor<A> {
    async fn init(&mut self, spec: &StageSpec) -> std::result::Result<(), StageError> {
        self.model_id = format!("stage-{}", spec.stage_idx);
        Ok(())
    }

    async fn forward(
        &self,
        request_id: u64,
        micro_batch: u32,
        inputs: Vec<OwnedTensor>,
    ) -> std::result::Result<ForwardOutput, StageError> {
        if inputs.is_empty() {
            return Err(StageError::ForwardFailed {
                request_id,
                micro_batch,
                reason: "No input tensors".to_string(),
            });
        }

        // Separate receipt tensors (from previous stages) from data tensors
        let mut prev_receipt_tensors: Vec<OwnedTensor> = Vec::new();
        let mut data_tensors: Vec<&OwnedTensor> = Vec::new();
        for tensor in &inputs {
            if tensor.name.starts_with("__receipt__") {
                prev_receipt_tensors.push(tensor.clone());
            } else {
                data_tensors.push(tensor);
            }
        }

        if data_tensors.is_empty() {
            return Err(StageError::ForwardFailed {
                request_id,
                micro_batch,
                reason: "No data input tensors (only receipts)".to_string(),
            });
        }

        let input_bytes = data_tensors[0].data.as_ref();

        // Execute inference via CandleInferenceEngine
        let infer_start = std::time::Instant::now();
        let output = self
            .engine
            .execute_by_id(&self.model_id, input_bytes)
            .map_err(|e| StageError::ForwardFailed {
                request_id,
                micro_batch,
                reason: format!("Inference failed: {}", e),
            })?;
        let infer_ms = infer_start.elapsed().as_millis() as u64;

        // Encode output as f32 bytes
        let output_bytes: Vec<u8> = output.iter().flat_map(|f| f.to_le_bytes()).collect();

        let output_tensor = OwnedTensor {
            name: "output".to_string(),
            dtype: confidential_ml_transport::DType::F32,
            shape: vec![output.len() as u32],
            data: bytes::Bytes::from(output_bytes.clone()),
        };

        // Compute previous_receipt_hash for receipt chaining.
        // Hash the most recent previous receipt's CBOR to chain stages.
        let previous_receipt_hash: Option<[u8; 32]> = if !prev_receipt_tensors.is_empty() {
            use sha2::{Digest, Sha256};
            // Use the last receipt tensor (highest stage index)
            let last_receipt = &prev_receipt_tensors[prev_receipt_tensors.len() - 1];
            Some(Sha256::digest(&last_receipt.data).into())
        } else {
            None
        };

        // Build and sign receipt (needs mutable access to state for sequence counter)
        let receipt = {
            let mut state = self.state.lock().map_err(|_| StageError::ForwardFailed {
                request_id,
                micro_batch,
                reason: "State lock poisoned".to_string(),
            })?;

            let mut receipt = ReceiptBuilder::build(
                &mut state,
                &self.attestation_provider,
                input_bytes,
                &output_bytes,
                self.model_id.clone(),
                "1.0".to_string(),
                infer_ms,
                0,
            )
            .map_err(|e| StageError::ForwardFailed {
                request_id,
                micro_batch,
                reason: format!("Receipt build failed: {}", e),
            })?;

            // Set chain hash linking to previous stage's receipt
            receipt.previous_receipt_hash = previous_receipt_hash;

            receipt
                .sign(&state.receipt_signing_key)
                .map_err(|e| StageError::ForwardFailed {
                    request_id,
                    micro_batch,
                    reason: format!("Receipt sign failed: {}", e),
                })?;

            receipt
        };

        // Serialize receipt as canonical CBOR for deterministic encoding.
        // CBOR with serde_cbor produces deterministic output (sorted keys, no indefinite lengths).
        let receipt_bytes =
            serde_cbor::to_vec(&receipt).map_err(|e| StageError::ForwardFailed {
                request_id,
                micro_batch,
                reason: format!("Receipt serialize failed: {}", e),
            })?;

        // Verify determinism: re-decode and re-encode must produce identical bytes
        #[cfg(debug_assertions)]
        {
            let decoded: serde_cbor::Value =
                serde_cbor::from_slice(&receipt_bytes).expect("CBOR round-trip decode failed");
            let re_encoded = serde_cbor::to_vec(&decoded).expect("CBOR round-trip encode failed");
            assert_eq!(
                receipt_bytes, re_encoded,
                "CBOR encoding is not deterministic"
            );
        }

        let receipt_tensor = OwnedTensor {
            name: "__receipt__".to_string(),
            dtype: confidential_ml_transport::DType::U8,
            shape: vec![receipt_bytes.len() as u32],
            data: bytes::Bytes::from(receipt_bytes),
        };

        // Build output: [output_tensor, ...forwarded_prev_receipts_renamed, this_receipt]
        let mut out_tensors = vec![output_tensor];

        // Forward previous receipts with stage-indexed names
        for (i, mut prev) in prev_receipt_tensors.into_iter().enumerate() {
            prev.name = format!("__receipt__stage{}", i);
            out_tensors.push(prev);
        }

        out_tensors.push(receipt_tensor);

        Ok(ForwardOutput {
            tensors: out_tensors,
        })
    }
}

#[cfg(all(test, feature = "mock"))]
mod tests {
    use super::*;
    use crate::attestation::DefaultAttestationProvider;

    #[tokio::test]
    async fn test_stage_executor_forward() {
        let engine = CandleInferenceEngine::new().unwrap();
        let provider = DefaultAttestationProvider::new().unwrap();
        let receipt_key = ReceiptSigningKey::generate().unwrap();

        let mut executor = EphemeralStageExecutor::new(engine, provider, receipt_key);

        let spec = StageSpec {
            stage_idx: 0,
            layer_start: 0,
            layer_end: 1,
            weight_hashes: vec![],
            expected_measurements: std::collections::BTreeMap::new(),
            endpoint: confidential_ml_pipeline::StageEndpoint {
                control: confidential_ml_pipeline::PortSpec::Tcp {
                    addr: "127.0.0.1:9000".to_string(),
                },
                data_in: confidential_ml_pipeline::PortSpec::Tcp {
                    addr: "127.0.0.1:9001".to_string(),
                },
                data_out: confidential_ml_pipeline::PortSpec::Tcp {
                    addr: "127.0.0.1:9002".to_string(),
                },
            },
        };

        executor.init(&spec).await.unwrap();

        // Test with empty input
        let result = executor.forward(1, 0, vec![]).await;
        assert!(result.is_err());

        // Test with input (will fail because no model registered for "stage-0")
        let input = OwnedTensor {
            name: "input".to_string(),
            dtype: confidential_ml_transport::DType::U8,
            shape: vec![5],
            data: bytes::Bytes::from_static(b"hello"),
        };
        let result = executor.forward(1, 0, vec![input]).await;
        assert!(result.is_err()); // Expected: model not loaded
    }
}
