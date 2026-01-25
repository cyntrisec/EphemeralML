use crate::{Result, EnclaveError, EphemeralError, AttestationProvider};
use crate::session_manager::EnclaveSession;
use ephemeral_ml_common::{AttestationReceipt, EnclaveMeasurements, SecurityMode};
use sha2::{Sha256, Digest};

pub struct ReceiptBuilder;

impl ReceiptBuilder {
    pub fn build<A: AttestationProvider>(
        session: &EnclaveSession,
        provider: &A,
        request_plaintext: &[u8],
        response_plaintext: &[u8],
        model_id: String,
        model_version: String,
        execution_time_ms: u64,
        memory_peak_mb: u64,
    ) -> Result<AttestationReceipt> {
        // 1. Calculate Hashes
        let mut hasher = Sha256::new();
        hasher.update(request_plaintext);
        let request_hash = hasher.finalize().into();

        let mut hasher = Sha256::new();
        hasher.update(response_plaintext);
        let response_hash = hasher.finalize().into();

        // 2. Get PCRs
        // In a real system, we might cache these or get them from the session context if immutable
        let pcrs = provider.get_pcr_measurements()?;
        let enclave_measurements = EnclaveMeasurements::new(pcrs.pcr0, pcrs.pcr1, pcrs.pcr2);

        // 3. Create Receipt
        let receipt = AttestationReceipt::new(
            uuid::Uuid::new_v4().to_string(),
            session.hpke.protocol_version,
            SecurityMode::GatewayOnly,
            enclave_measurements,
            session.attestation_hash,
            request_hash,
            response_hash,
            "v1-default".to_string(), // Policy version
            session.hpke.get_next_sequence(),
            model_id,
            model_version,
            execution_time_ms,
            memory_peak_mb,
        );

        Ok(receipt)
    }
}
