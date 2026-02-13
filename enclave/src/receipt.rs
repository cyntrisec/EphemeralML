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
        let receipt = AttestationReceipt::new(
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

        Ok(receipt)
    }
}
