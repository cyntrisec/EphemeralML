//! Trust Evidence Bundle — canonical output of all cryptographic bindings
//! produced during boot and first inference.
//!
//! This provides a single structured log line per session that captures:
//! - Quote hash (SHA-256 of the raw TDX/Nitro attestation quote)
//! - HPKE public key (session key bound in REPORTDATA)
//! - Model hash (SHA-256 of decrypted model weights)
//! - Receipt signing key (Ed25519 public key for receipt verification)
//! - Receipt hash (SHA-256 of the first signed receipt)
//!
//! This is the "proof bundle" artifact for compliance and audit.

use sha2::{Digest, Sha256};

/// Trust evidence bundle emitted at boot and after first inference.
pub struct TrustEvidenceBundle {
    /// SHA-256 of the raw attestation quote.
    pub quote_hash: [u8; 32],
    /// HPKE session public key (bound in attestation REPORTDATA).
    pub hpke_public_key: [u8; 32],
    /// SHA-256 of the decrypted model weights (pre-registration).
    pub model_hash: Option<[u8; 32]>,
    /// Model identifier (e.g. "stage-0").
    pub model_id: String,
    /// Ed25519 receipt signing public key.
    pub receipt_signing_key: [u8; 32],
    /// SHA-256 of the first receipt (set after first inference).
    pub receipt_hash: Option<[u8; 32]>,
    /// Cloud KMS key resource name (if applicable).
    pub kms_key_id: Option<String>,
    /// Platform identifier.
    pub platform: String,
}

impl TrustEvidenceBundle {
    /// Create a bundle from boot-time evidence.
    ///
    /// `raw_quote` is the raw TDX/Nitro attestation quote bytes.
    /// `model_weights` is the decrypted model weights (optional, for hash).
    pub fn from_boot(
        raw_quote: &[u8],
        hpke_public_key: [u8; 32],
        receipt_signing_key: [u8; 32],
        model_id: &str,
        model_weights: Option<&[u8]>,
        kms_key_id: Option<String>,
        platform: &str,
    ) -> Self {
        let quote_hash: [u8; 32] = Sha256::digest(raw_quote).into();
        let model_hash = model_weights.map(|w| Sha256::digest(w).into());

        Self {
            quote_hash,
            hpke_public_key,
            model_hash,
            model_id: model_id.to_string(),
            receipt_signing_key,
            receipt_hash: None,
            kms_key_id,
            platform: platform.to_string(),
        }
    }

    /// Record the first receipt hash.
    pub fn set_receipt_hash(&mut self, receipt_bytes: &[u8]) {
        self.receipt_hash = Some(Sha256::digest(receipt_bytes).into());
    }

    /// Print the trust evidence bundle in a canonical format.
    pub fn print(&self) {
        println!("========================================");
        println!("  TRUST EVIDENCE BUNDLE");
        println!("========================================");
        println!("  Platform:           {}", self.platform);
        println!("  Model ID:           {}", self.model_id);
        println!("  Quote Hash:         {}", hex::encode(self.quote_hash));
        println!(
            "  HPKE Public Key:    {}",
            &hex::encode(self.hpke_public_key)[..32]
        );
        println!(
            "  Receipt Sign Key:   {}",
            &hex::encode(self.receipt_signing_key)[..32]
        );
        if let Some(ref model_hash) = self.model_hash {
            println!("  Model Hash:         {}", hex::encode(model_hash));
        }
        if let Some(ref receipt_hash) = self.receipt_hash {
            println!("  Receipt Hash:       {}", hex::encode(receipt_hash));
        }
        if let Some(ref key_id) = self.kms_key_id {
            println!("  KMS Key ID:         {}", key_id);
        }
        println!("========================================");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bundle_from_boot_computes_hashes() {
        let raw_quote = b"fake-tdx-quote-bytes-for-test";
        let hpke_key = [0x11; 32];
        let receipt_key = [0x22; 32];
        let model_weights = b"fake-model-weights";

        let bundle = TrustEvidenceBundle::from_boot(
            raw_quote,
            hpke_key,
            receipt_key,
            "stage-0",
            Some(model_weights),
            Some("projects/p/locations/l/keyRings/kr/cryptoKeys/k".to_string()),
            "tdx",
        );

        let expected_quote_hash: [u8; 32] = Sha256::digest(raw_quote).into();
        let expected_model_hash: [u8; 32] = Sha256::digest(model_weights).into();

        assert_eq!(bundle.quote_hash, expected_quote_hash);
        assert_eq!(bundle.model_hash, Some(expected_model_hash));
        assert_eq!(bundle.hpke_public_key, hpke_key);
        assert_eq!(bundle.receipt_signing_key, receipt_key);
        assert_eq!(bundle.model_id, "stage-0");
        assert_eq!(bundle.platform, "tdx");
        assert!(bundle.receipt_hash.is_none());
        assert!(bundle.kms_key_id.is_some());
    }

    #[test]
    fn bundle_receipt_hash_update() {
        let mut bundle = TrustEvidenceBundle::from_boot(
            b"quote", [0; 32], [0; 32], "stage-0", None, None, "tdx",
        );

        assert!(bundle.receipt_hash.is_none());

        bundle.set_receipt_hash(b"receipt-bytes");
        assert!(bundle.receipt_hash.is_some());

        let expected: [u8; 32] = Sha256::digest(b"receipt-bytes").into();
        assert_eq!(bundle.receipt_hash.unwrap(), expected);
    }

    #[test]
    fn bundle_print_does_not_panic() {
        let bundle = TrustEvidenceBundle::from_boot(
            b"quote",
            [0xAA; 32],
            [0xBB; 32],
            "stage-0",
            Some(b"weights"),
            None,
            "tdx",
        );
        // Just verify it doesn't panic
        bundle.print();
    }
}
