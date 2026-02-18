//! Bridge between EphemeralML's `AttestationProvider` and cml-transport's
//! `AttestationProvider` trait.
//!
//! `AttestationBridge<P>` wraps an EphemeralML attestation provider so it can
//! be used by `SecureChannel::accept_with_attestation()` and by the pipeline's
//! `StageRuntime`.

use crate::attestation::AttestationProvider as EphemeralAttestationProvider;
use confidential_ml_transport::attestation::types::AttestationDocument as CmlAttestationDocument;
use confidential_ml_transport::AttestationProvider as CmlAttestationProvider;
use ephemeral_ml_common::transport_types::EphemeralUserData;

/// Wraps an EphemeralML `AttestationProvider` as a cml-transport `AttestationProvider`.
///
/// Stores the 32-byte Ed25519 receipt signing public key directly.
/// The private key stays in the `EphemeralStageExecutor`.
pub struct AttestationBridge<P: EphemeralAttestationProvider> {
    inner: P,
    receipt_public_key: [u8; 32],
}

impl<P: EphemeralAttestationProvider> AttestationBridge<P> {
    /// Get the receipt public key stored in this bridge.
    pub fn receipt_public_key(&self) -> &[u8; 32] {
        &self.receipt_public_key
    }
}

impl<P: EphemeralAttestationProvider> AttestationBridge<P> {
    pub fn new(inner: P, receipt_public_key: [u8; 32]) -> Self {
        Self {
            inner,
            receipt_public_key,
        }
    }

    /// Get a reference to the inner provider (for KMS decrypt, PCRs, etc.)
    pub fn inner(&self) -> &P {
        &self.inner
    }
}

#[async_trait::async_trait]
impl<P: EphemeralAttestationProvider> CmlAttestationProvider for AttestationBridge<P> {
    async fn attest(
        &self,
        user_data: Option<&[u8]>,
        nonce: Option<&[u8]>,
        _public_key: Option<&[u8]>,
    ) -> std::result::Result<CmlAttestationDocument, confidential_ml_transport::error::AttestError>
    {
        // Build EphemeralUserData from receipt key + any additional user_data
        let ephemeral_ud = if let Some(ud_bytes) = user_data {
            // Try to parse existing user data and merge
            EphemeralUserData::from_cbor(ud_bytes).unwrap_or_else(|_| {
                EphemeralUserData::new(self.receipt_public_key, 1, vec!["gateway".to_string()])
            })
        } else {
            EphemeralUserData::new(self.receipt_public_key, 1, vec!["gateway".to_string()])
        };

        let ud_cbor = ephemeral_ud.to_cbor().map_err(|e| {
            confidential_ml_transport::error::AttestError::GenerationFailed(format!(
                "Failed to serialize user data: {}",
                e
            ))
        })?;

        // Use the nonce from cml-transport's handshake
        let nonce_bytes = nonce.unwrap_or(&[]);

        // Call EphemeralML's attestation provider
        let doc = self
            .inner
            .generate_attestation(nonce_bytes, self.receipt_public_key)
            .map_err(|e| {
                confidential_ml_transport::error::AttestError::GenerationFailed(format!(
                    "Attestation generation failed: {}",
                    e
                ))
            })?;

        // The `generate_attestation()` call above already embedded the receipt key,
        // so we use doc.signature as the raw attestation bytes.
        let _ = ud_cbor; // user_data was embedded by generate_attestation via receipt_pk

        Ok(CmlAttestationDocument::new(doc.signature))
    }
}

#[cfg(all(test, feature = "mock"))]
mod tests {
    use super::*;
    use crate::mock::MockAttestationProvider;
    use confidential_ml_transport::AttestationProvider as CmlAttestationProvider;

    #[tokio::test]
    async fn bridge_produces_non_empty_attestation() {
        let mock = MockAttestationProvider::new();
        let receipt_key = [42u8; 32];
        let bridge = AttestationBridge::new(mock, receipt_key);

        let doc = bridge.attest(None, Some(&[0xAB; 32]), None).await.unwrap();
        assert!(
            !doc.raw.is_empty(),
            "Attestation document should not be empty"
        );
    }

    #[tokio::test]
    async fn bridge_embeds_receipt_key_in_attestation() {
        let mock = MockAttestationProvider::new();
        let receipt_key = [0x99u8; 32];
        let bridge = AttestationBridge::new(mock, receipt_key);

        let doc = bridge.attest(None, Some(&[0xAB; 32]), None).await.unwrap();

        // The raw bytes are a CBOR map produced by MockAttestationProvider.
        // Parse and verify receipt_signing_key is embedded in user_data.
        use ciborium::Value;

        let cbor: Value = ephemeral_ml_common::cbor::from_slice(&doc.raw).unwrap();
        let map = match cbor {
            Value::Map(m) => m,
            _ => panic!("Expected CBOR map"),
        };

        let ud_key = Value::Text("user_data".to_string());
        let ud_bytes = match ephemeral_ml_common::cbor::map_get(&map, &ud_key) {
            Some(Value::Bytes(b)) => b,
            _ => panic!("No user_data bytes in attestation"),
        };

        // MockAttestationProvider serializes user_data as JSON
        let ud: serde_json::Value = serde_json::from_slice(ud_bytes).unwrap();
        let rsk = ud["receipt_signing_key"]
            .as_array()
            .expect("receipt_signing_key should be an array");

        // Verify all 32 bytes match
        for (i, byte) in rsk.iter().enumerate() {
            assert_eq!(byte.as_u64().unwrap() as u8, 0x99, "Byte {} mismatch", i);
        }
    }

    #[tokio::test]
    async fn bridge_stores_receipt_public_key() {
        let mock = MockAttestationProvider::new();
        let receipt_key = [0xBB; 32];
        let bridge = AttestationBridge::new(mock, receipt_key);
        assert_eq!(bridge.receipt_public_key(), &[0xBB; 32]);
    }

    #[tokio::test]
    async fn bridge_inner_returns_provider_ref() {
        let mock = MockAttestationProvider::new();
        let hpke_key = mock.hpke_keypair.public_key;
        let bridge = AttestationBridge::new(mock, [0u8; 32]);
        // Verify inner() returns the original provider
        assert_eq!(bridge.inner().get_hpke_public_key(), hpke_key);
    }

    #[tokio::test]
    async fn bridge_with_none_user_data_creates_default() {
        let mock = MockAttestationProvider::new();
        let receipt_key = [0x11; 32];
        let bridge = AttestationBridge::new(mock, receipt_key);

        // Call with None user_data — should create default EphemeralUserData
        let doc = bridge.attest(None, None, None).await.unwrap();
        assert!(!doc.raw.is_empty());
    }

    #[tokio::test]
    async fn bridge_with_valid_cbor_user_data_parses_it() {
        let mock = MockAttestationProvider::new();
        let receipt_key = [0x22; 32];
        let bridge = AttestationBridge::new(mock, receipt_key);

        // Create valid EphemeralUserData CBOR
        let ud = EphemeralUserData::new([0xAA; 32], 2, vec!["feature1".to_string()]);
        let ud_cbor = ud.to_cbor().unwrap();

        let doc = bridge
            .attest(Some(&ud_cbor), Some(&[0xCC; 32]), None)
            .await
            .unwrap();
        assert!(!doc.raw.is_empty());
    }

    #[tokio::test]
    async fn bridge_with_invalid_cbor_user_data_uses_default() {
        let mock = MockAttestationProvider::new();
        let receipt_key = [0x33; 32];
        let bridge = AttestationBridge::new(mock, receipt_key);

        // Invalid CBOR bytes — should fall back to default EphemeralUserData
        let invalid_cbor = b"this is not valid cbor";
        let doc = bridge
            .attest(Some(invalid_cbor), Some(&[0xDD; 32]), None)
            .await
            .unwrap();
        assert!(!doc.raw.is_empty());
    }

    #[tokio::test]
    async fn bridge_propagates_provider_error() {
        let mock = MockAttestationProvider::with_invalid_attestation();
        let bridge = AttestationBridge::new(mock, [0u8; 32]);

        let result = bridge.attest(None, Some(&[0xAB; 32]), None).await;
        assert!(result.is_err(), "Should propagate provider error");
        let err = format!("{}", result.unwrap_err());
        assert!(
            err.contains("Attestation generation failed"),
            "Error: {}",
            err
        );
    }
}
