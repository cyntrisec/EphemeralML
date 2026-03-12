use crate::{AttestationProvider, Result};
use ephemeral_ml_common::transport_types::ConnectionState;
use ephemeral_ml_common::{AttestationReceipt, EnclaveMeasurements, SecurityMode};
use sha2::{Digest, Sha256};

pub struct ReceiptBuilder;

impl ReceiptBuilder {
    #[allow(clippy::too_many_arguments)]
    pub fn build<A: AttestationProvider>(
        state: &mut ConnectionState,
        provider: &A,
        request_plaintext: &[u8],
        response_plaintext: &[u8],
        model_id: String,
        model_version: String,
        execution_time_ms: u64,
        memory_peak_mb: u64,
    ) -> Result<AttestationReceipt> {
        // 1. Calculate Hashes
        let request_hash: [u8; 32] = Sha256::digest(request_plaintext).into();
        let response_hash: [u8; 32] = Sha256::digest(response_plaintext).into();

        // 2. Get PCRs / TDX measurements
        let pcrs = provider.get_pcr_measurements()?;
        let enclave_measurements = match provider.measurement_type() {
            "tdx-mrtd-rtmr" => EnclaveMeasurements::new_tdx(pcrs.pcr0, pcrs.pcr1, pcrs.pcr2),
            _ => EnclaveMeasurements::new(pcrs.pcr0, pcrs.pcr1, pcrs.pcr2),
        };

        // 3. Create Receipt
        let sequence = state.next_seq();
        let mut receipt = AttestationReceipt::new(
            uuid::Uuid::new_v4().to_string(),
            state.protocol_version,
            SecurityMode::GatewayOnly,
            enclave_measurements,
            state.attestation_hash,
            request_hash,
            response_hash,
            "v1-default".to_string(),
            sequence,
            model_id,
            model_version,
            execution_time_ms,
            memory_peak_mb,
        );

        if let Some(source) = provider.attestation_source() {
            receipt = receipt.with_attestation_source(source.to_string());
        }

        Ok(receipt)
    }
}

#[cfg(all(test, feature = "mock"))]
mod tests {
    use super::ReceiptBuilder;
    use crate::mock::MockAttestationProvider;
    use ephemeral_ml_common::transport_types::ConnectionState;
    use ephemeral_ml_common::ReceiptSigningKey;

    #[test]
    fn receipt_builder_sets_mock_attestation_source() {
        let provider = MockAttestationProvider::new();
        let mut state = ConnectionState {
            attestation_hash: [7u8; 32],
            receipt_signing_key: ReceiptSigningKey::generate().unwrap(),
            session_id: "test-session".into(),
            client_id: "test-client".into(),
            next_sequence: 0,
            protocol_version: 1,
            model_id: "model".into(),
        };

        let receipt = ReceiptBuilder::build(
            &mut state,
            &provider,
            b"request",
            b"response",
            "model".into(),
            "1.0".into(),
            10,
            0,
        )
        .unwrap();

        assert_eq!(receipt.attestation_source.as_deref(), Some("mock"));
    }
}
