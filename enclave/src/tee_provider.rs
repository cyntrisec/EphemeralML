//! Generic TEE attestation provider for platform-native attestation.
//!
//! Currently supports Intel TDX via configfs-tsm (GCP Confidential VMs, bare-metal).
//! The same `TeeAttestationProvider` trait adapter pattern can be extended to
//! AMD SEV-SNP or future TEE platforms without changing the pipeline or receipt code.
//!
//! # Wire format
//!
//! Because TDX quotes only carry 64 bytes of REPORTDATA (used for `pk || nonce`),
//! there is no in-quote user_data field like AWS Nitro's COSE_Sign1 payload.
//! We wrap the attestation in a CBOR envelope so the receipt signing key can travel
//! alongside the hardware quote:
//!
//! ```cbor
//! {
//!   "platform": "tdx",
//!   "tdx_wire": <bytes>,     // TDX_V1 marker + raw quote (cml-transport format)
//!   "user_data": <bytes>,    // CBOR-encoded EphemeralUserData
//! }
//! ```

use crate::attestation::{AttestationProvider, AttestationUserData, EphemeralKeyPair};
use crate::Result;
use ephemeral_ml_common::{AttestationDocument, PcrMeasurements};

use hpke::{aead::ChaCha20Poly1305, kem::X25519HkdfSha256, Deserializable, OpModeR};
use serde::{Deserialize, Serialize};

use std::sync::atomic::{AtomicU64, Ordering};
use zeroize::ZeroizeOnDrop;

use crate::error::{EnclaveError, EphemeralError};

/// Global counter for unique configfs-tsm report entry names.
static TSM_ENTRY_COUNTER: AtomicU64 = AtomicU64::new(0);

// TDX quote body layout constants (matching cml-transport/src/attestation/tdx.rs).
const HEADER_SIZE: usize = 48;
const BODY_SIZE_V4: usize = 584;
const MRTD_OFFSET: usize = 136;
const MEASUREMENT_SIZE: usize = 48;
const RTMR0_OFFSET: usize = 328;
const REPORTDATA_OFFSET: usize = 520;

/// CBOR envelope that wraps a TDX quote alongside EphemeralML user_data.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct TeeAttestationEnvelope {
    pub platform: String,
    #[serde(with = "serde_bytes")]
    pub tdx_wire: Vec<u8>,
    #[serde(with = "serde_bytes")]
    pub user_data: Vec<u8>,
}

impl TeeAttestationEnvelope {
    /// Decode envelope from CBOR bytes.
    pub fn from_cbor(bytes: &[u8]) -> std::result::Result<Self, String> {
        serde_cbor::from_slice(bytes).map_err(|e| format!("envelope decode failed: {}", e))
    }

    /// Encode envelope to CBOR bytes.
    pub fn to_cbor(&self) -> std::result::Result<Vec<u8>, String> {
        serde_cbor::to_vec(self).map_err(|e| format!("envelope encode failed: {}", e))
    }
}

/// Generic TEE attestation provider.
///
/// Uses Intel TDX via configfs-tsm when running inside a TDX Trust Domain.
/// For local/mock testing, use `TeeAttestationProvider::synthetic()` which
/// generates valid-looking quotes signed with ephemeral keys.
#[derive(ZeroizeOnDrop)]
pub struct TeeAttestationProvider {
    #[zeroize(skip)]
    tsm_path: Option<std::path::PathBuf>,
    hpke_keypair: EphemeralKeyPair,
}

impl TeeAttestationProvider {
    /// Create a provider that uses real configfs-tsm (for TDX Trust Domains).
    pub fn new() -> Result<Self> {
        let tsm_path = std::path::PathBuf::from("/sys/kernel/config/tsm/report");
        if !tsm_path.exists() {
            return Err(EnclaveError::Enclave(EphemeralError::AttestationError(
                "configfs-tsm not available: /sys/kernel/config/tsm/report does not exist. \
                 Not running inside a TDX Trust Domain?"
                    .to_string(),
            )));
        }
        Ok(Self {
            tsm_path: Some(tsm_path),
            hpke_keypair: EphemeralKeyPair::generate(),
        })
    }

    /// Create a provider with a custom configfs-tsm path (for testing).
    pub fn with_tsm_path(path: std::path::PathBuf) -> Result<Self> {
        if !path.exists() {
            return Err(EnclaveError::Enclave(EphemeralError::AttestationError(
                format!("configfs-tsm path does not exist: {}", path.display()),
            )));
        }
        Ok(Self {
            tsm_path: Some(path),
            hpke_keypair: EphemeralKeyPair::generate(),
        })
    }

    /// Create a synthetic provider for testing (no configfs-tsm needed).
    ///
    /// Uses `cml-transport`'s `build_synthetic_tdx_quote()` under the `tdx` feature
    /// to produce structurally valid, ECDSA-signed TDX quotes without hardware.
    pub fn synthetic() -> Self {
        Self {
            tsm_path: None,
            hpke_keypair: EphemeralKeyPair::generate(),
        }
    }

    /// Generate a TDX quote via configfs-tsm or synthetic builder.
    fn generate_quote(&self, report_data: &[u8; 64]) -> Result<Vec<u8>> {
        if let Some(ref tsm_path) = self.tsm_path {
            self.generate_configfs_quote(tsm_path, report_data)
        } else {
            self.generate_synthetic_quote(report_data)
        }
    }

    /// Real configfs-tsm quote generation.
    fn generate_configfs_quote(
        &self,
        tsm_path: &std::path::Path,
        report_data: &[u8; 64],
    ) -> Result<Vec<u8>> {
        use std::fs;

        let entry_name = format!(
            "eml_{}_{}",
            std::process::id(),
            TSM_ENTRY_COUNTER.fetch_add(1, Ordering::Relaxed)
        );
        let entry_path = tsm_path.join(&entry_name);

        // Clean up any stale entry from a previous run.
        let _ = fs::remove_dir_all(&entry_path);

        fs::create_dir(&entry_path).map_err(|e| {
            EnclaveError::Enclave(EphemeralError::AttestationError(format!(
                "failed to create tsm report entry {}: {}",
                entry_path.display(),
                e
            )))
        })?;

        fs::write(entry_path.join("inblob"), report_data).map_err(|e| {
            let _ = fs::remove_dir_all(&entry_path);
            EnclaveError::Enclave(EphemeralError::AttestationError(format!(
                "failed to write inblob: {}",
                e
            )))
        })?;

        let quote = fs::read(entry_path.join("outblob")).map_err(|e| {
            let _ = fs::remove_dir_all(&entry_path);
            EnclaveError::Enclave(EphemeralError::AttestationError(format!(
                "failed to read outblob: {}",
                e
            )))
        })?;

        let _ = fs::remove_dir_all(&entry_path);
        Ok(quote)
    }

    /// Synthetic quote for testing (uses cml-transport's builder).
    #[cfg(feature = "tdx")]
    fn generate_synthetic_quote(&self, report_data: &[u8; 64]) -> Result<Vec<u8>> {
        let mrtd = [0xAA; 48];
        let rtmrs = [[0xBB; 48], [0xCC; 48], [0xDD; 48], [0xEE; 48]];
        Ok(
            confidential_ml_transport::attestation::tdx::build_synthetic_tdx_quote(
                *report_data,
                mrtd,
                rtmrs,
            ),
        )
    }

    #[cfg(not(feature = "tdx"))]
    fn generate_synthetic_quote(&self, _report_data: &[u8; 64]) -> Result<Vec<u8>> {
        Err(EnclaveError::Enclave(EphemeralError::AttestationError(
            "Synthetic TDX quotes require the `tdx` feature".to_string(),
        )))
    }

    /// Encode a raw TDX quote into cml-transport's wire format.
    fn encode_tdx_wire(quote: &[u8]) -> Vec<u8> {
        let mut wire = Vec::with_capacity(12 + 4 + quote.len());
        wire.extend_from_slice(b"TDX_V1\0\0\0\0\0\0");
        wire.extend_from_slice(&(quote.len() as u32).to_le_bytes());
        wire.extend_from_slice(quote);
        wire
    }

    /// Parse measurements from a raw TDX quote.
    ///
    /// Maps TDX registers to EphemeralML's PcrMeasurements:
    /// - MRTD  (48 bytes) → pcr0 (enclave/TD image measurement)
    /// - RTMR0 (48 bytes) → pcr1 (kernel/firmware measurement)
    /// - RTMR1 (48 bytes) → pcr2 (application measurement)
    pub fn parse_measurements(quote: &[u8]) -> Result<PcrMeasurements> {
        if quote.len() < HEADER_SIZE + BODY_SIZE_V4 {
            return Err(EnclaveError::Enclave(EphemeralError::AttestationError(
                format!(
                    "TDX quote too short: need at least {} bytes, got {}",
                    HEADER_SIZE + BODY_SIZE_V4,
                    quote.len()
                ),
            )));
        }

        let body = &quote[HEADER_SIZE..];

        let mrtd = body[MRTD_OFFSET..MRTD_OFFSET + MEASUREMENT_SIZE].to_vec();
        let rtmr0 = body[RTMR0_OFFSET..RTMR0_OFFSET + MEASUREMENT_SIZE].to_vec();
        let rtmr1 =
            body[RTMR0_OFFSET + MEASUREMENT_SIZE..RTMR0_OFFSET + 2 * MEASUREMENT_SIZE].to_vec();

        Ok(PcrMeasurements::new(mrtd, rtmr0, rtmr1))
    }

    /// Extract REPORTDATA from a raw TDX quote.
    pub fn parse_reportdata(quote: &[u8]) -> Result<[u8; 64]> {
        if quote.len() < HEADER_SIZE + BODY_SIZE_V4 {
            return Err(EnclaveError::Enclave(EphemeralError::AttestationError(
                "TDX quote too short for REPORTDATA".to_string(),
            )));
        }

        let body = &quote[HEADER_SIZE..];
        let mut reportdata = [0u8; 64];
        reportdata.copy_from_slice(&body[REPORTDATA_OFFSET..REPORTDATA_OFFSET + 64]);
        Ok(reportdata)
    }
}

impl AttestationProvider for TeeAttestationProvider {
    fn generate_attestation(
        &self,
        nonce: &[u8],
        receipt_public_key: [u8; 32],
    ) -> Result<AttestationDocument> {
        // Build REPORTDATA: pk[0..32] || nonce[32..64]
        // Nonce must be exactly 32 bytes for canonical session binding.
        if nonce.len() != 32 {
            return Err(EnclaveError::Enclave(EphemeralError::ValidationError(
                format!("TDX nonce must be exactly 32 bytes, got {}", nonce.len()),
            )));
        }
        let mut report_data = [0u8; 64];
        report_data[..32].copy_from_slice(&self.hpke_keypair.public_key);
        report_data[32..64].copy_from_slice(nonce);

        // Generate TDX quote
        let raw_quote = self.generate_quote(&report_data)?;
        let measurements = Self::parse_measurements(&raw_quote)?;

        // Encode as cml-transport wire format
        let tdx_wire = Self::encode_tdx_wire(&raw_quote);

        // Build EphemeralUserData (same structure as Nitro, for portability)
        let user_data = AttestationUserData {
            hpke_public_key: self.hpke_keypair.public_key,
            receipt_signing_key: receipt_public_key,
            protocol_version: 1,
            supported_features: vec!["gateway".to_string()],
        };
        let user_data_bytes = serde_json::to_vec(&user_data).map_err(|e| {
            EnclaveError::Enclave(EphemeralError::SerializationError(e.to_string()))
        })?;

        // Wrap in CBOR envelope (TDX wire + user_data)
        let envelope = TeeAttestationEnvelope {
            platform: "tdx".to_string(),
            tdx_wire,
            user_data: user_data_bytes,
        };
        let envelope_bytes = envelope.to_cbor().map_err(|e| {
            EnclaveError::Enclave(EphemeralError::SerializationError(e.to_string()))
        })?;

        Ok(AttestationDocument {
            module_id: "tdx-cvm".to_string(),
            digest: vec![],
            timestamp: ephemeral_ml_common::current_timestamp(),
            pcrs: measurements,
            certificate: vec![],
            signature: envelope_bytes,
            nonce: Some(nonce.to_vec()),
        })
    }

    fn get_pcr_measurements(&self) -> Result<PcrMeasurements> {
        // Generate a quote with dummy REPORTDATA just to read current measurements.
        let report_data = [0u8; 64];
        let quote = self.generate_quote(&report_data)?;
        Self::parse_measurements(&quote)
    }

    fn get_hpke_public_key(&self) -> [u8; 32] {
        self.hpke_keypair.public_key
    }

    fn get_hpke_private_key(&self) -> [u8; 32] {
        self.hpke_keypair.private_key
    }

    fn decrypt_hpke(&self, ciphertext: &[u8]) -> Result<Vec<u8>> {
        if ciphertext.len() < 32 {
            return Err(EnclaveError::Enclave(EphemeralError::DecryptionError(
                "Ciphertext too short".to_string(),
            )));
        }

        let (encapped_key_bytes, cipher_text) = ciphertext.split_at(32);

        let kem_priv =
            <X25519HkdfSha256 as hpke::Kem>::PrivateKey::from_bytes(&self.hpke_keypair.private_key)
                .map_err(|e| {
                    EnclaveError::Enclave(EphemeralError::DecryptionError(format!(
                        "Invalid private key: {}",
                        e
                    )))
                })?;

        let encapped_key = <X25519HkdfSha256 as hpke::Kem>::EncappedKey::from_bytes(
            encapped_key_bytes,
        )
        .map_err(|e| {
            EnclaveError::Enclave(EphemeralError::DecryptionError(format!(
                "Invalid encapped key: {}",
                e
            )))
        })?;

        let mut receiver_ctx = hpke::setup_receiver::<
            ChaCha20Poly1305,
            hpke::kdf::HkdfSha256,
            X25519HkdfSha256,
        >(&OpModeR::Base, &kem_priv, &encapped_key, b"KMS_DEK")
        .map_err(|e| {
            EnclaveError::Enclave(EphemeralError::DecryptionError(format!(
                "HPKE setup failed: {}",
                e
            )))
        })?;

        let plaintext = receiver_ctx.open(cipher_text, b"").map_err(|e| {
            EnclaveError::Enclave(EphemeralError::DecryptionError(format!(
                "HPKE open failed: {}",
                e
            )))
        })?;

        Ok(plaintext)
    }

    fn decrypt_kms(&self, _ciphertext: &[u8]) -> Result<Vec<u8>> {
        // TDX Confidential VMs call Cloud KMS directly (no RSA RecipientInfo flow).
        Err(EnclaveError::Enclave(EphemeralError::KmsError(
            "KMS decrypt not available for TDX/GCP. Use GcpKmsClient directly.".to_string(),
        )))
    }

    fn measurement_type(&self) -> &str {
        "tdx-mrtd-rtmr"
    }
}

impl TeeAttestationProvider {
    /// Generate a transport-level attestation binding a handshake DH public key.
    ///
    /// Unlike `generate_attestation()` which puts the HPKE key in REPORTDATA[0..32],
    /// this puts the caller-supplied `handshake_pk` there. This is what
    /// cml-transport's handshake expects: the attestation must bind the same DH
    /// public key that was sent in the Hello message.
    ///
    /// The HPKE key is still included in the `user_data` envelope for the
    /// application layer to use.
    pub fn generate_transport_attestation(
        &self,
        nonce: &[u8],
        handshake_pk: &[u8; 32],
        receipt_public_key: [u8; 32],
    ) -> Result<AttestationDocument> {
        if nonce.len() != 32 {
            return Err(EnclaveError::Enclave(EphemeralError::ValidationError(
                format!("TDX nonce must be exactly 32 bytes, got {}", nonce.len()),
            )));
        }
        let mut report_data = [0u8; 64];
        report_data[..32].copy_from_slice(handshake_pk);
        report_data[32..64].copy_from_slice(nonce);

        let raw_quote = self.generate_quote(&report_data)?;
        let measurements = Self::parse_measurements(&raw_quote)?;
        let tdx_wire = Self::encode_tdx_wire(&raw_quote);

        let user_data = AttestationUserData {
            hpke_public_key: self.hpke_keypair.public_key,
            receipt_signing_key: receipt_public_key,
            protocol_version: 1,
            supported_features: vec!["gateway".to_string()],
        };
        let user_data_bytes = serde_json::to_vec(&user_data).map_err(|e| {
            EnclaveError::Enclave(EphemeralError::SerializationError(e.to_string()))
        })?;

        let envelope = TeeAttestationEnvelope {
            platform: "tdx".to_string(),
            tdx_wire,
            user_data: user_data_bytes,
        };
        let envelope_bytes = envelope.to_cbor().map_err(|e| {
            EnclaveError::Enclave(EphemeralError::SerializationError(e.to_string()))
        })?;

        Ok(AttestationDocument {
            module_id: "tdx-cvm".to_string(),
            digest: vec![],
            timestamp: ephemeral_ml_common::current_timestamp(),
            pcrs: measurements,
            certificate: vec![],
            signature: envelope_bytes,
            nonce: Some(nonce.to_vec()),
        })
    }
}

/// Bridge from `TeeAttestationProvider` to cml-transport's `AttestationProvider`.
///
/// Extracts the TDX wire bytes from the CBOR envelope and passes them to
/// cml-transport for the secure channel handshake.
pub struct TeeAttestationBridge {
    inner: TeeAttestationProvider,
    receipt_public_key: [u8; 32],
}

impl TeeAttestationBridge {
    pub fn new(inner: TeeAttestationProvider, receipt_public_key: [u8; 32]) -> Self {
        Self {
            inner,
            receipt_public_key,
        }
    }

    pub fn inner(&self) -> &TeeAttestationProvider {
        &self.inner
    }
}

#[async_trait::async_trait]
impl confidential_ml_transport::AttestationProvider for TeeAttestationBridge {
    async fn attest(
        &self,
        _user_data: Option<&[u8]>,
        nonce: Option<&[u8]>,
        public_key: Option<&[u8]>,
    ) -> std::result::Result<
        confidential_ml_transport::attestation::types::AttestationDocument,
        confidential_ml_transport::error::AttestError,
    > {
        let nonce_bytes = nonce.unwrap_or(&[]);

        // The handshake passes the DH public key as `public_key`. We must bind
        // it in REPORTDATA[0..32] so the peer's verifier can confirm the
        // attestation matches the Hello message's DH key.
        let doc = if let Some(pk) = public_key {
            let mut handshake_pk = [0u8; 32];
            if pk.len() == 32 {
                handshake_pk.copy_from_slice(pk);
            }
            self.inner
                .generate_transport_attestation(nonce_bytes, &handshake_pk, self.receipt_public_key)
                .map_err(|e| {
                    confidential_ml_transport::error::AttestError::GenerationFailed(format!(
                        "TEE attestation failed: {}",
                        e
                    ))
                })?
        } else {
            // Fallback: no DH key provided, use HPKE key (boot-time attestation).
            self.inner
                .generate_attestation(nonce_bytes, self.receipt_public_key)
                .map_err(|e| {
                    confidential_ml_transport::error::AttestError::GenerationFailed(format!(
                        "TEE attestation failed: {}",
                        e
                    ))
                })?
        };

        // Pass the full CBOR envelope (tdx_wire + user_data) to the transport layer.
        // The client's TdxEnvelopeVerifierBridge will decode the envelope, verify
        // the TDX wire via TdxVerifier, and extract user_data (receipt signing key).
        Ok(confidential_ml_transport::attestation::types::AttestationDocument::new(doc.signature))
    }
}

/// Print TDX measurement summary to stdout (for smoke testing).
pub fn print_tdx_measurements(quote: &[u8]) -> Result<()> {
    let measurements = TeeAttestationProvider::parse_measurements(quote)?;
    let reportdata = TeeAttestationProvider::parse_reportdata(quote)?;

    println!("========================================");
    println!("  TDX Quote Measurements");
    println!("========================================");
    println!("  MRTD  (pcr0): {}", hex::encode(&measurements.pcr0[..24]));
    println!("  RTMR0 (pcr1): {}", hex::encode(&measurements.pcr1[..24]));
    println!("  RTMR1 (pcr2): {}", hex::encode(&measurements.pcr2[..24]));
    println!("  REPORTDATA:");
    println!("    pk[0..32]:    {}", hex::encode(&reportdata[..32]));
    println!("    nonce[32..64]:{}", hex::encode(&reportdata[32..64]));
    println!("  Quote size:     {} bytes", quote.len());
    println!("========================================");

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_synthetic_provider_creation() {
        let provider = TeeAttestationProvider::synthetic();
        assert!(provider.tsm_path.is_none());
        assert_ne!(provider.hpke_keypair.public_key, [0u8; 32]);
    }

    #[test]
    fn test_envelope_roundtrip() {
        let envelope = TeeAttestationEnvelope {
            platform: "tdx".to_string(),
            tdx_wire: vec![1, 2, 3, 4],
            user_data: vec![5, 6, 7, 8],
        };

        let cbor = envelope.to_cbor().unwrap();
        let decoded = TeeAttestationEnvelope::from_cbor(&cbor).unwrap();

        assert_eq!(decoded.platform, "tdx");
        assert_eq!(decoded.tdx_wire, vec![1, 2, 3, 4]);
        assert_eq!(decoded.user_data, vec![5, 6, 7, 8]);
    }

    #[cfg(feature = "tdx")]
    #[test]
    fn test_synthetic_attestation_generation() {
        let provider = TeeAttestationProvider::synthetic();
        let receipt_key = [42u8; 32];
        let nonce = [0xAB; 32];

        let doc = provider.generate_attestation(&nonce, receipt_key).unwrap();

        assert_eq!(doc.module_id, "tdx-cvm");
        assert_eq!(doc.nonce, Some(nonce.to_vec()));

        // Parse the envelope
        let envelope = TeeAttestationEnvelope::from_cbor(&doc.signature).unwrap();
        assert_eq!(envelope.platform, "tdx");

        // Verify user_data contains our keys
        let ud: AttestationUserData = serde_json::from_slice(&envelope.user_data).unwrap();
        assert_eq!(ud.receipt_signing_key, receipt_key);
        assert_eq!(ud.hpke_public_key, provider.hpke_keypair.public_key);

        // Verify measurements are non-empty
        assert_eq!(doc.pcrs.pcr0.len(), 48);
        assert_eq!(doc.pcrs.pcr1.len(), 48);
        assert_eq!(doc.pcrs.pcr2.len(), 48);
    }

    #[cfg(feature = "tdx")]
    #[test]
    fn test_synthetic_quote_measurements() {
        let provider = TeeAttestationProvider::synthetic();
        let nonce = [0u8; 32];
        let doc = provider.generate_attestation(&nonce, [0u8; 32]).unwrap();

        // MRTD should be 0xAA (our synthetic constant)
        assert!(doc.pcrs.pcr0.iter().all(|&b| b == 0xAA));
        // RTMR0 should be 0xBB
        assert!(doc.pcrs.pcr1.iter().all(|&b| b == 0xBB));
        // RTMR1 should be 0xCC
        assert!(doc.pcrs.pcr2.iter().all(|&b| b == 0xCC));
    }

    #[cfg(feature = "tdx")]
    #[test]
    fn test_reportdata_binding() {
        let provider = TeeAttestationProvider::synthetic();
        let nonce = [0x42; 32];
        let receipt_key = [0x99; 32];

        let doc = provider.generate_attestation(&nonce, receipt_key).unwrap();

        // Extract TDX wire, decode raw quote, check REPORTDATA
        let envelope = TeeAttestationEnvelope::from_cbor(&doc.signature).unwrap();

        // Skip TDX_V1 marker (12 bytes) + size (4 bytes) to get raw quote
        let raw_quote = &envelope.tdx_wire[16..];
        let reportdata = TeeAttestationProvider::parse_reportdata(raw_quote).unwrap();

        // REPORTDATA[0..32] should be HPKE public key
        assert_eq!(&reportdata[..32], &provider.hpke_keypair.public_key);
        // REPORTDATA[32..64] should be nonce
        assert_eq!(&reportdata[32..64], &nonce);
    }

    #[cfg(feature = "tdx")]
    #[test]
    fn test_tdx_wire_format_compatibility() {
        let provider = TeeAttestationProvider::synthetic();
        let doc = provider
            .generate_attestation(&[0u8; 32], [0u8; 32])
            .unwrap();

        let envelope = TeeAttestationEnvelope::from_cbor(&doc.signature).unwrap();

        // Wire format should start with TDX_V1 marker
        assert_eq!(&envelope.tdx_wire[..6], b"TDX_V1");
        assert_eq!(&envelope.tdx_wire[6..12], &[0u8; 6]);

        // Parse size
        let quote_size = u32::from_le_bytes(envelope.tdx_wire[12..16].try_into().unwrap()) as usize;
        assert_eq!(envelope.tdx_wire.len(), 16 + quote_size);
    }
}
