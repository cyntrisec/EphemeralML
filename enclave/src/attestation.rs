use crate::Result;
use serde::{Deserialize, Serialize};
use zeroize::ZeroizeOnDrop;

// Re-export common types
pub use ephemeral_ml_common::{current_timestamp, AttestationDocument, PcrMeasurements};

#[cfg(feature = "production")]
use crate::{EnclaveError, EphemeralError};
#[cfg(feature = "production")]
use aws_nitro_enclaves_nsm_api as nsm;
#[cfg(feature = "production")]
use hpke::{aead::ChaCha20Poly1305, kem::X25519HkdfSha256, Deserializable, OpModeR};
#[cfg(feature = "production")]
use rsa::pkcs8::EncodePublicKey;
#[cfg(feature = "production")]
use rsa::{Oaep, RsaPrivateKey};
#[cfg(feature = "production")]
use serde_bytes::ByteBuf;
#[cfg(feature = "production")]
use sha2::Sha256;

/// Attestation document user data structure for key binding
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct AttestationUserData {
    pub hpke_public_key: [u8; 32],     // X25519 public key for HPKE
    pub receipt_signing_key: [u8; 32], // Ed25519 public key for receipts
    pub protocol_version: u32,         // Fixed to 1 for v1
    pub supported_features: Vec<String>,
}

/// Ephemeral key pair for session establishment (X25519)
///
/// Private key material is zeroized on drop to prevent key leakage.
/// A new keypair MUST be generated per session for forward secrecy.
#[derive(Clone, Debug, ZeroizeOnDrop)]
pub struct EphemeralKeyPair {
    #[zeroize(skip)]
    pub public_key: [u8; 32],
    pub private_key: [u8; 32],
}

impl EphemeralKeyPair {
    /// Generate a new ephemeral key pair
    pub fn generate() -> Self {
        use rand::rngs::OsRng;
        use x25519_dalek::{PublicKey, StaticSecret};

        let secret = StaticSecret::random_from_rng(OsRng);
        let public = PublicKey::from(&secret);

        Self {
            public_key: *public.as_bytes(),
            private_key: *secret.as_bytes(),
        }
    }
}

/// Trait for attestation functionality
pub trait AttestationProvider: Send + Sync {
    /// Generate an attestation document with the given nonce.
    /// `receipt_public_key` is the Ed25519 public key bytes for the per-session
    /// receipt signing key, embedded in the attestation user_data so the client
    /// can extract it for receipt verification.
    fn generate_attestation(
        &self,
        nonce: &[u8],
        receipt_public_key: [u8; 32],
    ) -> Result<AttestationDocument>;

    /// Get current PCR measurements
    fn get_pcr_measurements(&self) -> Result<PcrMeasurements>;

    /// Get the HPKE public key for session establishment
    fn get_hpke_public_key(&self) -> [u8; 32];

    /// Get the HPKE private key (Sensitive!)
    fn get_hpke_private_key(&self) -> [u8; 32];

    /// Generate a fresh ephemeral keypair for a single session.
    ///
    /// Each session MUST use a unique ephemeral keypair to provide forward secrecy.
    /// The returned keypair should be used for exactly one HPKE session and then dropped
    /// (triggering ZeroizeOnDrop on the private key).
    fn generate_ephemeral_keypair(&self) -> EphemeralKeyPair {
        EphemeralKeyPair::generate()
    }

    /// Decrypt ciphertext encrypted with the enclave's HPKE public key
    fn decrypt_hpke(&self, ciphertext: &[u8]) -> Result<Vec<u8>>;

    /// Decrypt ciphertext returned by AWS KMS (RecipientInfo flow)
    fn decrypt_kms(&self, ciphertext: &[u8]) -> Result<Vec<u8>>;
}

/// NSM client for production attestation document generation
#[cfg(feature = "production")]
#[derive(Clone)]
pub struct NSMAttestationProvider {
    hpke_keypair: EphemeralKeyPair,
    kms_keypair: RsaPrivateKey,
}

#[cfg(feature = "production")]
impl NSMAttestationProvider {
    /// Create a new NSM attestation provider with ephemeral keys
    pub fn new() -> Result<Self> {
        let mut rng = rand::thread_rng();
        let kms_keypair = RsaPrivateKey::new(&mut rng, 2048).map_err(|e| {
            EnclaveError::Enclave(EphemeralError::Internal(format!(
                "RSA keygen failed: {}",
                e
            )))
        })?;

        Ok(Self {
            hpke_keypair: EphemeralKeyPair::generate(),
            kms_keypair,
        })
    }

    /// Generate attestation document using NSM API
    fn generate_nsm_attestation(&self, nonce: &[u8], user_data: &[u8]) -> Result<Vec<u8>> {
        let nsm_fd = nsm::driver::nsm_init();
        if nsm_fd < 0 {
            return Err(EnclaveError::Enclave(EphemeralError::AttestationError(
                "Failed to initialize NSM driver".to_string(),
            )));
        }

        // Export RSA public key as SPKI DER for KMS
        let kms_pub_key = self.kms_keypair.to_public_key();
        let kms_pub_der = kms_pub_key.to_public_key_der().map_err(|e| {
            EnclaveError::Enclave(EphemeralError::Internal(format!(
                "RSA export failed: {}",
                e
            )))
        })?;

        let request = nsm::api::Request::Attestation {
            user_data: Some(ByteBuf::from(user_data.to_vec())),
            nonce: Some(ByteBuf::from(nonce.to_vec())),
            public_key: Some(ByteBuf::from(kms_pub_der.as_bytes().to_vec())),
        };

        let response = nsm::driver::nsm_process_request(nsm_fd, request);
        nsm::driver::nsm_exit(nsm_fd);

        match response {
            nsm::api::Response::Attestation { document } => Ok(document),
            nsm::api::Response::Error(err) => Err(EnclaveError::Enclave(
                EphemeralError::AttestationError(format!("NSM attestation error: {:?}", err)),
            )),
            _ => Err(EnclaveError::Enclave(EphemeralError::AttestationError(
                "Unexpected NSM response type".to_string(),
            ))),
        }
    }

    /// Extract PCR measurements from NSM
    fn get_nsm_measurements(&self) -> Result<PcrMeasurements> {
        let nsm_fd = nsm::driver::nsm_init();
        if nsm_fd < 0 {
            return Err(EnclaveError::Enclave(EphemeralError::AttestationError(
                "Failed to initialize NSM driver".to_string(),
            )));
        }

        let mut pcr_values = Vec::new();
        for i in 0..3 {
            let request = nsm::api::Request::DescribePCR { index: i };
            let response = nsm::driver::nsm_process_request(nsm_fd, request);
            match response {
                nsm::api::Response::DescribePCR { data, .. } => {
                    pcr_values.push(data);
                }
                _ => {
                    nsm::driver::nsm_exit(nsm_fd);
                    return Err(EnclaveError::Enclave(EphemeralError::AttestationError(
                        format!("Failed to describe PCR {}", i),
                    )));
                }
            }
        }

        nsm::driver::nsm_exit(nsm_fd);

        Ok(PcrMeasurements::new(
            pcr_values[0].clone(),
            pcr_values[1].clone(),
            pcr_values[2].clone(),
        ))
    }
}

#[cfg(feature = "production")]
impl AttestationProvider for NSMAttestationProvider {
    fn generate_attestation(
        &self,
        nonce: &[u8],
        receipt_public_key: [u8; 32],
    ) -> Result<AttestationDocument> {
        // Create user data with embedded keys
        let user_data = AttestationUserData {
            hpke_public_key: self.hpke_keypair.public_key,
            receipt_signing_key: receipt_public_key,
            protocol_version: 1,
            supported_features: vec!["gateway".to_string()], // v1 only supports Gateway mode
        };

        let user_data_bytes = serde_json::to_vec(&user_data).map_err(|e| {
            EnclaveError::Enclave(EphemeralError::SerializationError(e.to_string()))
        })?;

        // Generate attestation document using NSM
        let attestation_doc_bytes = self.generate_nsm_attestation(nonce, &user_data_bytes)?;

        // Get PCR measurements
        let pcrs = self.get_pcr_measurements()?;

        // Store the raw COSE_Sign1 bytes directly in `signature`.
        // The client verifier will parse the COSE_Sign1 structure (a CBOR array,
        // not a map) to verify the signature and extract the payload.
        // The other fields on AttestationDocument are placeholders — the real
        // data lives inside the COSE_Sign1 payload.
        Ok(AttestationDocument {
            module_id: "nitro-enclave".to_string(),
            digest: vec![],
            timestamp: current_timestamp(),
            pcrs,
            certificate: vec![],
            signature: attestation_doc_bytes,
            nonce: Some(nonce.to_vec()),
        })
    }

    fn get_pcr_measurements(&self) -> Result<PcrMeasurements> {
        self.get_nsm_measurements()
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

    fn decrypt_kms(&self, ciphertext: &[u8]) -> Result<Vec<u8>> {
        let padding = Oaep::new::<Sha256>();
        self.kms_keypair
            .decrypt_blinded(&mut rand::thread_rng(), padding, ciphertext)
            .map_err(|e| {
                EnclaveError::Enclave(EphemeralError::DecryptionError(format!(
                    "KMS decryption failed: {}",
                    e
                )))
            })
    }
}

/// Default attestation provider that uses mock in development, NSM in production
#[derive(Clone)]
pub struct DefaultAttestationProvider {
    #[cfg(feature = "production")]
    nsm_provider: NSMAttestationProvider,
    #[cfg(not(feature = "production"))]
    mock_provider: crate::mock::MockAttestationProvider,
}

impl DefaultAttestationProvider {
    pub fn new() -> Result<Self> {
        Ok(Self {
            #[cfg(feature = "production")]
            nsm_provider: NSMAttestationProvider::new()?,
            #[cfg(not(feature = "production"))]
            mock_provider: crate::mock::MockAttestationProvider::new(),
        })
    }
}

impl AttestationProvider for DefaultAttestationProvider {
    fn generate_attestation(
        &self,
        nonce: &[u8],
        receipt_public_key: [u8; 32],
    ) -> Result<AttestationDocument> {
        #[cfg(feature = "production")]
        {
            self.nsm_provider
                .generate_attestation(nonce, receipt_public_key)
        }

        #[cfg(not(feature = "production"))]
        {
            self.mock_provider
                .generate_attestation(nonce, receipt_public_key)
        }
    }

    fn get_pcr_measurements(&self) -> Result<PcrMeasurements> {
        #[cfg(feature = "production")]
        {
            self.nsm_provider.get_pcr_measurements()
        }

        #[cfg(not(feature = "production"))]
        {
            self.mock_provider.get_pcr_measurements()
        }
    }

    fn get_hpke_public_key(&self) -> [u8; 32] {
        #[cfg(feature = "production")]
        {
            self.nsm_provider.get_hpke_public_key()
        }

        #[cfg(not(feature = "production"))]
        {
            self.mock_provider.get_hpke_public_key()
        }
    }

    fn get_hpke_private_key(&self) -> [u8; 32] {
        #[cfg(feature = "production")]
        {
            self.nsm_provider.get_hpke_private_key()
        }

        #[cfg(not(feature = "production"))]
        {
            self.mock_provider.get_hpke_private_key()
        }
    }

    fn decrypt_hpke(&self, ciphertext: &[u8]) -> Result<Vec<u8>> {
        #[cfg(feature = "production")]
        {
            self.nsm_provider.decrypt_hpke(ciphertext)
        }

        #[cfg(not(feature = "production"))]
        {
            self.mock_provider.decrypt_hpke(ciphertext)
        }
    }

    fn decrypt_kms(&self, ciphertext: &[u8]) -> Result<Vec<u8>> {
        #[cfg(feature = "production")]
        {
            self.nsm_provider.decrypt_kms(ciphertext)
        }

        #[cfg(not(feature = "production"))]
        {
            self.mock_provider.decrypt_kms(ciphertext)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mock::MockAttestationProvider;

    #[test]
    fn test_ephemeral_key_generation() {
        let keypair1 = EphemeralKeyPair::generate();
        let keypair2 = EphemeralKeyPair::generate();

        // Keys should be different
        assert_ne!(keypair1.public_key, keypair2.public_key);
        assert_ne!(keypair1.private_key, keypair2.private_key);

        // Keys should be 32 bytes
        assert_eq!(keypair1.public_key.len(), 32);
        assert_eq!(keypair1.private_key.len(), 32);
    }

    #[test]
    fn test_attestation_user_data_serialization() {
        let user_data = AttestationUserData {
            hpke_public_key: [1u8; 32],
            receipt_signing_key: [2u8; 32],
            protocol_version: 1,
            supported_features: vec!["gateway".to_string()],
        };

        let serialized = serde_json::to_vec(&user_data).unwrap();
        let deserialized: AttestationUserData = serde_json::from_slice(&serialized).unwrap();

        assert_eq!(user_data.hpke_public_key, deserialized.hpke_public_key);
        assert_eq!(
            user_data.receipt_signing_key,
            deserialized.receipt_signing_key
        );
        assert_eq!(user_data.protocol_version, deserialized.protocol_version);
        assert_eq!(
            user_data.supported_features,
            deserialized.supported_features
        );
    }

    #[test]
    fn test_default_attestation_provider_mock_mode() {
        let provider = DefaultAttestationProvider::new().unwrap();
        let nonce = b"test_nonce_12345678901234567890";
        let receipt_pk = [42u8; 32];

        // Should work in mock mode
        let attestation = provider.generate_attestation(nonce, receipt_pk).unwrap();
        assert_eq!(attestation.module_id, "mock-enclave");
        assert_eq!(attestation.nonce, Some(nonce.to_vec()));

        // Should get PCR measurements
        let pcrs = provider.get_pcr_measurements().unwrap();
        assert!(pcrs.is_valid());

        // Should get HPKE key
        let hpke_key = provider.get_hpke_public_key();
        assert_eq!(hpke_key.len(), 32);
    }

    #[test]
    fn test_mock_attestation_provider_with_keys() {
        let provider = MockAttestationProvider::new();
        let nonce = b"test_nonce_12345678901234567890";
        let receipt_pk = [42u8; 32];

        let attestation = provider.generate_attestation(nonce, receipt_pk).unwrap();

        // Verify attestation contains expected fields
        assert_eq!(attestation.module_id, "mock-enclave");
        assert_eq!(attestation.nonce, Some(nonce.to_vec()));
        assert!(attestation.pcrs.is_valid());

        // Verify HPKE key is accessible and non-zero
        let hpke_key = provider.get_hpke_public_key();
        assert_ne!(hpke_key, [0u8; 32]);
    }

    #[test]
    fn test_mock_attestation_provider_invalid() {
        let provider = MockAttestationProvider::with_invalid_attestation();
        let nonce = b"test_nonce_12345678901234567890";

        // Should fail when configured to fail
        let result = provider.generate_attestation(nonce, [0u8; 32]);
        assert!(result.is_err());
    }
}
