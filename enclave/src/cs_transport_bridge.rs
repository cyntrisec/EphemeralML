//! Confidential Space transport attestation bridge.
//!
//! Implements `cml-transport::AttestationProvider` using the CS Launcher JWT
//! instead of configfs-tsm TDX quotes. This enables transport-level attestation
//! in CS containers where configfs-tsm is not exposed.
//!
//! The Launcher JWT is hardware-backed: the Confidential Space attestation
//! service verifies the TDX quote before issuing the token. This bridge wraps
//! the JWT in a `CsTransportAttestation` envelope (deterministic CBOR) that
//! binds the JWT to the SecureChannel handshake via nonce and DH public key.
//!
//! Requires feature: `gcp`

use crate::cs_token_client::CsTokenClient;
use ephemeral_ml_common::CsTransportAttestation;

/// Bridge from CS Launcher JWT attestation to cml-transport's `AttestationProvider`.
///
/// Used when running in Confidential Space without configfs-tsm access.
/// Each `attest()` call fetches a fresh Launcher JWT with the handshake nonce
/// bound via `eat_nonce`, packages it in a `CsTransportAttestation` envelope,
/// and returns the CBOR-encoded envelope as the attestation document.
pub struct CsTransportAttestationBridge {
    token_client: CsTokenClient,
    receipt_public_key: [u8; 32],
    wip_audience: String,
}

impl CsTransportAttestationBridge {
    /// Create a new CS transport attestation bridge.
    ///
    /// # Arguments
    /// * `receipt_public_key` — Ed25519 public key for receipt signing (32 bytes)
    /// * `wip_audience` — Workload Identity Pool audience for the Launcher JWT
    pub fn new(receipt_public_key: [u8; 32], wip_audience: String) -> Self {
        Self {
            token_client: CsTokenClient::new(),
            receipt_public_key,
            wip_audience,
        }
    }

    /// Create with a custom token client (for testing).
    #[cfg(test)]
    pub fn with_token_client(
        token_client: CsTokenClient,
        receipt_public_key: [u8; 32],
        wip_audience: String,
    ) -> Self {
        Self {
            token_client,
            receipt_public_key,
            wip_audience,
        }
    }
}

#[async_trait::async_trait]
impl confidential_ml_transport::AttestationProvider for CsTransportAttestationBridge {
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
        let handshake_pk = public_key.unwrap_or(&[]);

        // Build eat_nonce: hex-encode the handshake nonce for the Launcher.
        // The nonce binds this JWT to the specific SecureChannel handshake session.
        let nonce_hex = hex::encode(nonce_bytes);
        let nonces = if nonce_hex.is_empty() {
            vec![]
        } else {
            vec![nonce_hex]
        };

        // Fetch a fresh Launcher JWT with the handshake nonce bound.
        let jwt = self
            .token_client
            .get_token(&self.wip_audience, nonces)
            .await
            .map_err(|e| {
                confidential_ml_transport::error::AttestError::GenerationFailed(format!(
                    "CS Launcher JWT fetch failed: {}",
                    e
                ))
            })?;

        // Package as CsTransportAttestation envelope.
        let envelope = CsTransportAttestation::new(
            jwt,
            self.receipt_public_key,
            handshake_pk.to_vec(),
            nonce_bytes.to_vec(),
        );

        // Validate structure before encoding.
        envelope.validate_structure().map_err(|e| {
            confidential_ml_transport::error::AttestError::GenerationFailed(format!(
                "CS transport attestation envelope validation failed: {}",
                e
            ))
        })?;

        // Encode as deterministic CBOR.
        let cbor = envelope.to_cbor_deterministic().map_err(|e| {
            confidential_ml_transport::error::AttestError::GenerationFailed(format!(
                "CS transport attestation CBOR encoding failed: {}",
                e
            ))
        })?;

        Ok(confidential_ml_transport::attestation::types::AttestationDocument::new(cbor))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use confidential_ml_transport::AttestationProvider;

    /// Helper: build a synthetic JWT for testing.
    fn make_test_jwt(nonces: &[&str]) -> String {
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;
        use base64::Engine;

        let header = URL_SAFE_NO_PAD.encode(b"{\"alg\":\"RS256\",\"typ\":\"JWT\"}");

        let nonce_json = if nonces.len() == 1 {
            format!("\"{}\"", nonces[0])
        } else {
            let items: Vec<String> = nonces.iter().map(|n| format!("\"{}\"", n)).collect();
            format!("[{}]", items.join(","))
        };

        let claims = format!(
            "{{\"aud\":\"test-audience\",\"eat_nonce\":{},\"iss\":\"https://confidentialcomputing.googleapis.com\",\"exp\":9999999999}}",
            nonce_json
        );
        let payload = URL_SAFE_NO_PAD.encode(claims.as_bytes());
        let sig = URL_SAFE_NO_PAD.encode(b"fake-signature");

        format!("{}.{}.{}", header, payload, sig)
    }

    /// Start a mock Launcher socket that returns a fixed JWT.
    async fn start_mock_launcher(socket_path: &str, jwt: &str) -> tokio::task::JoinHandle<()> {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::UnixListener;

        let listener = UnixListener::bind(socket_path).unwrap();
        let jwt = jwt.to_string();

        tokio::spawn(async move {
            if let Ok((mut stream, _)) = listener.accept().await {
                let mut buf = vec![0u8; 8192];
                let _ = stream.read(&mut buf).await;

                let response = format!(
                    "HTTP/1.1 200 OK\r\n\
                     Content-Type: text/plain\r\n\
                     Content-Length: {}\r\n\
                     Connection: close\r\n\
                     \r\n\
                     {}",
                    jwt.len(),
                    jwt
                );
                let _ = stream.write_all(response.as_bytes()).await;
            }
        })
    }

    #[tokio::test]
    async fn test_cs_bridge_produces_valid_envelope() {
        let dir = std::env::temp_dir().join(format!("cs_bridge_{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        let socket_path = dir.join("launcher.sock");
        let socket_str = socket_path.to_str().unwrap();

        let test_nonce = b"test-handshake-nonce-32bytes!!!!";
        let nonce_hex = hex::encode(test_nonce);
        let jwt = make_test_jwt(&[&nonce_hex]);

        let _server = start_mock_launcher(socket_str, &jwt).await;
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        let bridge = CsTransportAttestationBridge::with_token_client(
            CsTokenClient::with_socket_path(socket_str),
            [0xAA; 32],
            "test-audience".to_string(),
        );

        let handshake_pk = [0xBB; 32];
        let doc = bridge
            .attest(None, Some(test_nonce), Some(&handshake_pk))
            .await
            .unwrap();

        // Decode the envelope
        let envelope = CsTransportAttestation::from_cbor(&doc.raw).unwrap();
        assert_eq!(envelope.platform, "cs-tdx");
        assert_eq!(envelope.receipt_signing_key, vec![0xAA; 32]);
        assert_eq!(envelope.handshake_public_key, vec![0xBB; 32]);
        assert_eq!(envelope.nonce, test_nonce.to_vec());
        assert_eq!(envelope.protocol_version, 1);
        assert_eq!(envelope.launcher_jwt, jwt);

        // Validate structure
        envelope.validate_structure().unwrap();

        // Cleanup
        let _ = std::fs::remove_file(&socket_path);
        let _ = std::fs::remove_dir(&dir);
    }

    #[tokio::test]
    async fn test_cs_bridge_fails_without_socket() {
        let bridge = CsTransportAttestationBridge::with_token_client(
            CsTokenClient::with_socket_path("/nonexistent/launcher.sock"),
            [0xAA; 32],
            "test-audience".to_string(),
        );

        let result = bridge.attest(None, Some(&[0; 32]), Some(&[0; 32])).await;
        assert!(result.is_err());
        let err = format!("{:?}", result.unwrap_err());
        assert!(
            err.contains("CS Launcher JWT fetch failed"),
            "Error: {}",
            err
        );
    }
}
