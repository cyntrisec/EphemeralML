use crate::{
    current_timestamp, AttestationProvider, EnclaveError, EphemeralError, Result,
};
pub use ephemeral_ml_common::{AttestationDocument, PcrMeasurements};
use rsa::{pkcs8::EncodePublicKey, Oaep, RsaPrivateKey};
use sha2::{Digest, Sha256};

use zeroize::ZeroizeOnDrop;

/// Mock key pair for testing
#[derive(Clone, Debug, ZeroizeOnDrop)]
pub struct MockKeyPair {
    #[zeroize(skip)]
    pub public_key: [u8; 32],
    pub private_key: [u8; 32],
}

impl MockKeyPair {
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

/// Mock attestation provider for local development
#[derive(Clone)]
pub struct MockAttestationProvider {
    pub valid_attestation: bool,
    pub hpke_keypair: MockKeyPair,
    pub kms_keypair: RsaPrivateKey,
}

impl MockAttestationProvider {
    pub fn new() -> Self {
        let mut rng = rand::thread_rng();
        let kms_keypair = RsaPrivateKey::new(&mut rng, 2048).expect("RSA keygen failed");

        Self {
            valid_attestation: true,
            hpke_keypair: MockKeyPair::generate(),
            kms_keypair,
        }
    }

    pub fn with_invalid_attestation() -> Self {
        let mut rng = rand::thread_rng();
        let kms_keypair = RsaPrivateKey::new(&mut rng, 2048).expect("RSA keygen failed");

        Self {
            valid_attestation: false,
            hpke_keypair: MockKeyPair::generate(),
            kms_keypair,
        }
    }

    pub fn new_copy(&self) -> Self {
        Self {
            valid_attestation: self.valid_attestation,
            hpke_keypair: self.hpke_keypair.clone(),
            kms_keypair: self.kms_keypair.clone(),
        }
    }

    /// Generate mock attestation document with embedded keys
    pub fn generate_attestation_with_keys(
        &self,
        nonce: &[u8],
        receipt_public_key: [u8; 32],
    ) -> Result<AttestationDocument> {
        if !self.valid_attestation {
            return Err(EnclaveError::Enclave(EphemeralError::AttestationError(
                "Mock attestation configured to fail".to_string(),
            )));
        }

        #[derive(serde::Serialize, serde::Deserialize, Clone, Debug)]
        struct MockAttestationUserData {
            hpke_public_key: [u8; 32],
            receipt_signing_key: [u8; 32],
            protocol_version: u32,
            supported_features: Vec<String>,
        }

        let user_data = MockAttestationUserData {
            hpke_public_key: self.hpke_keypair.public_key,
            receipt_signing_key: receipt_public_key,
            protocol_version: 1,
            supported_features: vec!["gateway".to_string()],
        };

        let user_data_bytes = serde_json::to_vec(&user_data).map_err(|e| {
            EnclaveError::Enclave(EphemeralError::SerializationError(e.to_string()))
        })?;

        let mut hasher = Sha256::new();
        hasher.update(b"mock_enclave_image");
        hasher.update(nonce);
        hasher.update(&user_data_bytes);
        let digest_bytes = hasher.finalize();

        let mut digest = vec![0u8; 48];
        digest[..32].copy_from_slice(&digest_bytes);

        let pcr_hex = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f";
        let pcr0_bytes = hex::decode(pcr_hex).unwrap_or_else(|_| vec![0x01; 48]);
        let pcr1_bytes = pcr0_bytes.clone();
        let pcr2_bytes = pcr0_bytes.clone();

        let kms_pub_key = self.kms_keypair.to_public_key();
        let kms_pub_der = kms_pub_key.to_public_key_der().expect("RSA export failed");

        use std::collections::BTreeMap;
        let mut map = BTreeMap::new();
        map.insert(
            serde_cbor::Value::Text("module_id".to_string()),
            serde_cbor::Value::Text("mock-enclave".to_string()),
        );
        map.insert(
            serde_cbor::Value::Text("user_data".to_string()),
            serde_cbor::Value::Bytes(user_data_bytes),
        );
        map.insert(
            serde_cbor::Value::Text("public_key".to_string()),
            serde_cbor::Value::Bytes(kms_pub_der.as_bytes().to_vec()),
        );

        let mut pcrs_map = BTreeMap::new();
        pcrs_map.insert(
            serde_cbor::Value::Integer(0),
            serde_cbor::Value::Bytes(pcr0_bytes.clone()),
        );
        pcrs_map.insert(
            serde_cbor::Value::Integer(1),
            serde_cbor::Value::Bytes(pcr1_bytes.clone()),
        );
        pcrs_map.insert(
            serde_cbor::Value::Integer(2),
            serde_cbor::Value::Bytes(pcr2_bytes.clone()),
        );
        map.insert(
            serde_cbor::Value::Text("pcrs".to_string()),
            serde_cbor::Value::Map(pcrs_map),
        );

        let signature_bytes = serde_cbor::to_vec(&serde_cbor::Value::Map(map)).map_err(|e| {
            EnclaveError::Enclave(EphemeralError::SerializationError(e.to_string()))
        })?;

        Ok(AttestationDocument {
            module_id: "mock-enclave".to_string(),
            digest,
            timestamp: current_timestamp(),
            pcrs: PcrMeasurements {
                pcr0: pcr0_bytes,
                pcr1: pcr1_bytes,
                pcr2: pcr2_bytes,
            },
            certificate: b"mock_certificate".to_vec(),
            signature: signature_bytes,
            nonce: Some(nonce.to_vec()),
        })
    }
}

impl Default for MockAttestationProvider {
    fn default() -> Self {
        Self::new()
    }
}

impl AttestationProvider for MockAttestationProvider {
    fn generate_attestation(
        &self,
        nonce: &[u8],
        receipt_public_key: [u8; 32],
    ) -> Result<AttestationDocument> {
        self.generate_attestation_with_keys(nonce, receipt_public_key)
    }

    fn get_pcr_measurements(&self) -> Result<PcrMeasurements> {
        let pcr_hex = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f";
        Ok(PcrMeasurements {
            pcr0: hex::decode(pcr_hex).unwrap_or_else(|_| vec![0x01; 48]),
            pcr1: hex::decode(pcr_hex).unwrap_or_else(|_| vec![0x02; 48]),
            pcr2: hex::decode(pcr_hex).unwrap_or_else(|_| vec![0x03; 48]),
        })
    }

    fn get_hpke_public_key(&self) -> [u8; 32] {
        self.hpke_keypair.public_key
    }

    fn get_hpke_private_key(&self) -> [u8; 32] {
        self.hpke_keypair.private_key
    }

    fn decrypt_hpke(&self, ciphertext: &[u8]) -> Result<Vec<u8>> {
        use hpke::{aead::ChaCha20Poly1305, kem::X25519HkdfSha256, Deserializable, OpModeR};

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
        match self
            .kms_keypair
            .decrypt_blinded(&mut rand::thread_rng(), padding, ciphertext)
        {
            Ok(pt) => Ok(pt),
            Err(_) => self.decrypt_hpke(ciphertext),
        }
    }
}

