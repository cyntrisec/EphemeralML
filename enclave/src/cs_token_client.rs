//! Confidential Space attestation token client.
//!
//! Talks to the Launcher agent via a Unix domain socket at
//! `/run/container_launcher/teeserver.sock` to obtain OIDC attestation
//! tokens with `eat_nonce` session binding.
//!
//! These tokens carry Confidential Space identity claims (container image
//! digest, GCE project ID, instance zone, etc.) that are not available
//! through the Cloud Attestation API path.
//!
//! Requires feature: `gcp`

use crate::{EnclaveError, EphemeralError, Result};
use serde::{Deserialize, Serialize};

/// Default Launcher socket path.
const DEFAULT_SOCKET_PATH: &str = "/run/container_launcher/teeserver.sock";

/// Token request endpoint (HTTP over Unix socket).
const TOKEN_PATH: &str = "/v1/token";

/// Confidential Space attestation token client.
///
/// Communicates with the Launcher agent over a Unix domain socket to
/// obtain OIDC tokens with session-binding nonces (`eat_nonce`).
pub struct CsTokenClient {
    socket_path: String,
}

/// Token request body sent to the Launcher.
#[derive(Serialize)]
struct TokenRequest<'a> {
    audience: &'a str,
    token_type: &'a str,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    nonces: Vec<String>,
}

/// Parsed (unverified) JWT claims from the attestation token.
///
/// The enclave does not verify the JWT signature — it trusts the local
/// Launcher socket. The relying party (client) verifies the full JWT.
#[derive(Deserialize, Debug, Clone)]
pub struct CsTokenClaims {
    /// Audience the token was requested for.
    pub aud: String,
    /// Session-binding nonces (mirrored from request).
    /// CS Launcher may return a single string or an array of strings.
    #[serde(default, deserialize_with = "deserialize_string_or_vec")]
    pub eat_nonce: Vec<String>,
    /// Token issuer (https://confidentialcomputing.googleapis.com).
    #[serde(default)]
    pub iss: String,
    /// Subject (instance resource URI).
    #[serde(default)]
    pub sub: String,
    /// Token expiry (Unix seconds).
    #[serde(default)]
    pub exp: u64,
    /// Token issued-at (Unix seconds).
    #[serde(default)]
    pub iat: u64,
    /// Software name (CONFIDENTIAL_SPACE).
    #[serde(default)]
    pub swname: String,
    /// Software version.
    #[serde(default)]
    pub swversion: Vec<String>,
    /// Container image reference submods (if present).
    #[serde(default)]
    pub submods: serde_json::Value,
}

impl Default for CsTokenClient {
    fn default() -> Self {
        Self::new()
    }
}

impl CsTokenClient {
    /// Create a client using the default Launcher socket path.
    pub fn new() -> Self {
        Self {
            socket_path: DEFAULT_SOCKET_PATH.to_string(),
        }
    }

    /// Create a client with a custom socket path (for testing).
    pub fn with_socket_path(path: &str) -> Self {
        Self {
            socket_path: path.to_string(),
        }
    }

    /// Request an OIDC attestation token from the Launcher.
    ///
    /// - `audience`: relying party identifier (max 512 bytes).
    /// - `nonces`: session-binding nonces (up to 6, each 10–74 bytes).
    ///
    /// Returns the raw JWT string.
    pub async fn get_token(&self, audience: &str, nonces: Vec<String>) -> Result<String> {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::UnixStream;

        let stream = UnixStream::connect(&self.socket_path).await.map_err(|e| {
            EnclaveError::Enclave(EphemeralError::NetworkError(format!(
                "Failed to connect to Launcher socket at {}: {}",
                self.socket_path, e
            )))
        })?;

        let request = TokenRequest {
            audience,
            token_type: "OIDC",
            nonces,
        };

        let body = serde_json::to_vec(&request).map_err(|e| {
            EnclaveError::Enclave(EphemeralError::SerializationError(format!(
                "Token request serialization: {}",
                e
            )))
        })?;

        // Build HTTP/1.1 request manually (avoids adding hyper/unix-connector dep).
        let http_request = format!(
            "POST {} HTTP/1.1\r\n\
             Host: localhost\r\n\
             Content-Type: application/json\r\n\
             Content-Length: {}\r\n\
             Connection: close\r\n\
             \r\n",
            TOKEN_PATH,
            body.len(),
        );

        let (mut reader, mut writer) = stream.into_split();

        writer
            .write_all(http_request.as_bytes())
            .await
            .map_err(|e| {
                EnclaveError::Enclave(EphemeralError::NetworkError(format!(
                    "Failed to write HTTP request: {}",
                    e
                )))
            })?;
        writer.write_all(&body).await.map_err(|e| {
            EnclaveError::Enclave(EphemeralError::NetworkError(format!(
                "Failed to write request body: {}",
                e
            )))
        })?;
        writer.shutdown().await.map_err(|e| {
            EnclaveError::Enclave(EphemeralError::NetworkError(format!(
                "Failed to shutdown write half: {}",
                e
            )))
        })?;

        // Read the full HTTP response.
        let mut response_buf = Vec::with_capacity(8192);
        reader.read_to_end(&mut response_buf).await.map_err(|e| {
            EnclaveError::Enclave(EphemeralError::NetworkError(format!(
                "Failed to read Launcher response: {}",
                e
            )))
        })?;

        let response_str = String::from_utf8(response_buf).map_err(|e| {
            EnclaveError::Enclave(EphemeralError::SerializationError(format!(
                "Launcher response is not UTF-8: {}",
                e
            )))
        })?;

        // Parse HTTP response: split headers from body at \r\n\r\n.
        let (headers, body) = response_str.split_once("\r\n\r\n").ok_or_else(|| {
            EnclaveError::Enclave(EphemeralError::NetworkError(format!(
                "Malformed HTTP response from Launcher: no header/body separator. Response: {}",
                &response_str[..response_str.len().min(200)]
            )))
        })?;

        // Check for HTTP 200 status.
        let status_line = headers.lines().next().unwrap_or("");
        if !status_line.contains("200") {
            return Err(EnclaveError::Enclave(EphemeralError::NetworkError(
                format!(
                    "Launcher returned non-200: {}. Body: {}",
                    status_line,
                    &body[..body.len().min(500)]
                ),
            )));
        }

        let token = body.trim().to_string();
        if token.is_empty() {
            return Err(EnclaveError::Enclave(EphemeralError::NetworkError(
                "Launcher returned empty token".to_string(),
            )));
        }

        Ok(token)
    }

    /// Decode JWT claims without signature verification.
    ///
    /// SAFETY: This function does NOT verify the JWT signature. It is only safe
    /// for informational/logging use because the token comes from the local
    /// Launcher socket (trusted path). Do NOT use these claims for security
    /// decisions (access control, key release, policy enforcement).
    /// The relying party (client) must verify the full JWT via Google's OIDC keys.
    pub fn parse_claims(token: &str) -> Result<CsTokenClaims> {
        // JWT format: header.payload.signature
        let parts: Vec<&str> = token.split('.').collect();
        if parts.len() != 3 {
            return Err(EnclaveError::Enclave(EphemeralError::ValidationError(
                format!("Invalid JWT: expected 3 parts, got {}", parts.len()),
            )));
        }

        // Decode payload (second part), base64url without padding.
        let payload = base64_url_decode(parts[1])?;

        let claims: CsTokenClaims = serde_json::from_slice(&payload).map_err(|e| {
            EnclaveError::Enclave(EphemeralError::SerializationError(format!(
                "JWT claims parse failed: {}",
                e
            )))
        })?;

        // Warn on expired tokens. We don't hard-fail here because this function
        // is informational-only (see doc comment), but downstream code should be
        // aware of stale tokens.
        if claims.exp > 0 {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
            if now >= claims.exp {
                eprintln!(
                    "[cs_token] WARNING: Launcher token expired (exp={}, now={})",
                    claims.exp, now
                );
            }
        }

        Ok(claims)
    }
}

/// Deserialize a JSON value that may be a single string or an array of strings.
/// CS Launcher returns `"eat_nonce": "single-string"` (string) while the spec
/// allows `"eat_nonce": ["a", "b"]` (array).
fn deserialize_string_or_vec<'de, D>(deserializer: D) -> std::result::Result<Vec<String>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    use serde::de;

    struct StringOrVec;

    impl<'de> de::Visitor<'de> for StringOrVec {
        type Value = Vec<String>;

        fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
            formatter.write_str("a string or an array of strings")
        }

        fn visit_str<E: de::Error>(self, v: &str) -> std::result::Result<Vec<String>, E> {
            Ok(vec![v.to_string()])
        }

        fn visit_seq<A: de::SeqAccess<'de>>(
            self,
            mut seq: A,
        ) -> std::result::Result<Vec<String>, A::Error> {
            let mut vec = Vec::new();
            while let Some(s) = seq.next_element()? {
                vec.push(s);
            }
            Ok(vec)
        }
    }

    deserializer.deserialize_any(StringOrVec)
}

/// Base64url decode (no padding), as used in JWT.
fn base64_url_decode(input: &str) -> Result<Vec<u8>> {
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine;

    URL_SAFE_NO_PAD.decode(input).map_err(|e| {
        EnclaveError::Enclave(EphemeralError::SerializationError(format!(
            "Base64url decode failed: {}",
            e
        )))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_synthetic_jwt_claims() {
        // Build a synthetic JWT: header.payload.signature
        let header = base64_url_encode(b"{\"alg\":\"RS256\",\"typ\":\"JWT\"}");
        let claims = serde_json::json!({
            "aud": "test-audience",
            "eat_nonce": ["nonce-abc123", "nonce-def456"],
            "iss": "https://confidentialcomputing.googleapis.com",
            "sub": "projects/12345/zones/us-central1-a/instances/test-vm",
            "exp": 1721330075u64,
            "iat": 1721326475u64,
            "swname": "CONFIDENTIAL_SPACE",
            "swversion": ["240500"],
        });
        let payload = base64_url_encode(serde_json::to_string(&claims).unwrap().as_bytes());
        let signature = base64_url_encode(b"fake-signature");

        let jwt = format!("{}.{}.{}", header, payload, signature);

        let parsed = CsTokenClient::parse_claims(&jwt).unwrap();
        assert_eq!(parsed.aud, "test-audience");
        assert_eq!(parsed.eat_nonce, vec!["nonce-abc123", "nonce-def456"]);
        assert_eq!(parsed.iss, "https://confidentialcomputing.googleapis.com");
        assert_eq!(parsed.swname, "CONFIDENTIAL_SPACE");
        assert_eq!(parsed.exp, 1721330075);
    }

    #[test]
    fn parse_claims_rejects_invalid_jwt() {
        assert!(CsTokenClient::parse_claims("not-a-jwt").is_err());
        assert!(CsTokenClient::parse_claims("a.b").is_err());
    }

    #[test]
    fn parse_claims_string_eat_nonce() {
        // CS Launcher returns eat_nonce as a single string, not an array.
        let header = base64_url_encode(b"{\"alg\":\"RS256\",\"typ\":\"JWT\"}");
        let claims = serde_json::json!({
            "aud": "test-audience",
            "eat_nonce": "single-nonce-value",
            "iss": "https://confidentialcomputing.googleapis.com",
        });
        let payload = base64_url_encode(serde_json::to_string(&claims).unwrap().as_bytes());
        let signature = base64_url_encode(b"fake-signature");

        let jwt = format!("{}.{}.{}", header, payload, signature);

        let parsed = CsTokenClient::parse_claims(&jwt).unwrap();
        assert_eq!(parsed.aud, "test-audience");
        assert_eq!(parsed.eat_nonce, vec!["single-nonce-value"]);
        assert_eq!(parsed.iss, "https://confidentialcomputing.googleapis.com");
    }

    #[test]
    fn parse_claims_handles_missing_optional_fields() {
        let header = base64_url_encode(b"{\"alg\":\"RS256\"}");
        let claims = serde_json::json!({"aud": "x"});
        let payload = base64_url_encode(serde_json::to_string(&claims).unwrap().as_bytes());
        let sig = base64_url_encode(b"s");

        let jwt = format!("{}.{}.{}", header, payload, sig);
        let parsed = CsTokenClient::parse_claims(&jwt).unwrap();
        assert_eq!(parsed.aud, "x");
        assert!(parsed.eat_nonce.is_empty());
        assert_eq!(parsed.exp, 0);
    }

    #[tokio::test]
    async fn get_token_fails_when_socket_missing() {
        let client = CsTokenClient::with_socket_path("/nonexistent/socket.sock");
        let result = client.get_token("audience", vec![]).await;
        assert!(result.is_err());
        let err = format!("{:?}", result.unwrap_err());
        assert!(err.contains("Failed to connect"), "Error: {}", err);
    }

    // --- Mock Unix socket round-trip tests ---

    /// Start a mock Launcher socket server that returns a JWT.
    async fn mock_launcher_socket(
        socket_path: &str,
        status: u16,
        body: &str,
    ) -> tokio::task::JoinHandle<()> {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::UnixListener;

        let listener = UnixListener::bind(socket_path).unwrap();
        let body = body.to_string();

        tokio::spawn(async move {
            if let Ok((mut stream, _)) = listener.accept().await {
                // Read the request (HTTP/1.1 over Unix socket)
                let mut buf = vec![0u8; 8192];
                let _ = stream.read(&mut buf).await;

                let status_text = match status {
                    200 => "OK",
                    400 => "Bad Request",
                    500 => "Internal Server Error",
                    _ => "Error",
                };

                let response = format!(
                    "HTTP/1.1 {} {}\r\n\
                     Content-Type: text/plain\r\n\
                     Content-Length: {}\r\n\
                     Connection: close\r\n\
                     \r\n\
                     {}",
                    status,
                    status_text,
                    body.len(),
                    body
                );
                let _ = stream.write_all(response.as_bytes()).await;
            }
        })
    }

    #[tokio::test]
    async fn get_token_round_trip_success() {
        let dir = std::env::temp_dir().join(format!("cs_test_{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        let socket_path = dir.join("launcher.sock");
        let socket_str = socket_path.to_str().unwrap();

        // Create a synthetic JWT
        let header = base64_url_encode(b"{\"alg\":\"RS256\",\"typ\":\"JWT\"}");
        let claims = serde_json::json!({
            "aud": "test-audience",
            "eat_nonce": ["nonce-1"],
            "iss": "https://confidentialcomputing.googleapis.com",
            "exp": 9999999999u64,
            "iat": 1000000000u64,
            "swname": "CONFIDENTIAL_SPACE",
        });
        let payload = base64_url_encode(serde_json::to_string(&claims).unwrap().as_bytes());
        let sig = base64_url_encode(b"fake-sig");
        let jwt = format!("{}.{}.{}", header, payload, sig);

        let _server = mock_launcher_socket(socket_str, 200, &jwt).await;
        // Small delay to ensure server is listening
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        let client = CsTokenClient::with_socket_path(socket_str);
        let token = client
            .get_token("test-audience", vec!["nonce-1".to_string()])
            .await
            .unwrap();

        assert_eq!(token, jwt);

        // Parse and verify claims
        let parsed = CsTokenClient::parse_claims(&token).unwrap();
        assert_eq!(parsed.aud, "test-audience");
        assert_eq!(parsed.eat_nonce, vec!["nonce-1"]);
        assert_eq!(parsed.swname, "CONFIDENTIAL_SPACE");

        // Cleanup
        let _ = std::fs::remove_file(&socket_path);
        let _ = std::fs::remove_dir(&dir);
    }

    #[tokio::test]
    async fn get_token_non_200_response() {
        let dir = std::env::temp_dir().join(format!("cs_test_err_{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        let socket_path = dir.join("launcher_err.sock");
        let socket_str = socket_path.to_str().unwrap();

        let _server = mock_launcher_socket(socket_str, 400, "invalid audience parameter").await;
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        let client = CsTokenClient::with_socket_path(socket_str);
        let result = client.get_token("bad-audience", vec![]).await;
        assert!(result.is_err());
        let err = format!("{:?}", result.unwrap_err());
        assert!(
            err.contains("non-200") || err.contains("400"),
            "Error: {}",
            err
        );

        let _ = std::fs::remove_file(&socket_path);
        let _ = std::fs::remove_dir(&dir);
    }

    #[tokio::test]
    async fn get_token_empty_body_response() {
        let dir = std::env::temp_dir().join(format!("cs_test_empty_{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        let socket_path = dir.join("launcher_empty.sock");
        let socket_str = socket_path.to_str().unwrap();

        let _server = mock_launcher_socket(socket_str, 200, "").await;
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        let client = CsTokenClient::with_socket_path(socket_str);
        let result = client.get_token("audience", vec![]).await;
        assert!(result.is_err());
        let err = format!("{:?}", result.unwrap_err());
        assert!(err.contains("empty token"), "Error: {}", err);

        let _ = std::fs::remove_file(&socket_path);
        let _ = std::fs::remove_dir(&dir);
    }

    /// Helper: base64url encode without padding.
    fn base64_url_encode(input: &[u8]) -> String {
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;
        use base64::Engine;
        URL_SAFE_NO_PAD.encode(input)
    }
}
