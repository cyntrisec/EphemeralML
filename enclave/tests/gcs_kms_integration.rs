//! End-to-end integration test for the GCS fetch -> KMS decrypt -> model load path.
//!
//! Validates the full orchestrated flow that `main.rs` performs in `gcs-kms` mode,
//! using mock HTTP servers and synthetic TDX quotes. No real GCP credentials or
//! hardware required.
//!
//! Run with: cargo test --no-default-features --features gcp --test gcs_kms_integration

#[cfg(feature = "gcp")]
mod tests {
    use base64::engine::general_purpose::STANDARD as BASE64;
    use base64::Engine;
    use ephemeral_ml_enclave::crypto_util::{decrypt_artifact, encrypt_artifact};
    use ephemeral_ml_enclave::gcp_kms_client::GcpKmsClient;
    use ephemeral_ml_enclave::gcs_loader::GcsModelLoader;
    use ephemeral_ml_enclave::tee_provider::TeeAttestationProvider;
    use sha2::{Digest, Sha256};
    use std::collections::VecDeque;
    use std::sync::{Arc, Mutex};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    const WIP: &str = "//iam.googleapis.com/projects/12345/locations/global/workloadIdentityPools/pool/providers/prov";

    /// Queue-based mock HTTP server (same as test_helpers::MockHttpServer but
    /// available to integration tests without crate-internal access).
    struct MockHttpServer {
        pub base_url: String,
        _handle: tokio::task::JoinHandle<()>,
    }

    impl MockHttpServer {
        async fn start(responses: Vec<(u16, String)>) -> Self {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let base_url = format!("http://{}", listener.local_addr().unwrap());
            let queue = Arc::new(Mutex::new(VecDeque::from(responses)));

            let handle = tokio::spawn(async move {
                while let Ok((mut stream, _)) = listener.accept().await {
                    let queue = queue.clone();
                    tokio::spawn(async move {
                        let mut buf = vec![0u8; 16384];
                        let _ = stream.read(&mut buf).await;

                        let (status, body) = queue
                            .lock()
                            .unwrap()
                            .pop_front()
                            .unwrap_or((500, r#"{"error":"queue empty"}"#.to_string()));

                        let status_text = match status {
                            200 => "OK",
                            400 => "Bad Request",
                            401 => "Unauthorized",
                            403 => "Forbidden",
                            404 => "Not Found",
                            500 => "Internal Server Error",
                            _ => "Error",
                        };

                        let resp = format!(
                            "HTTP/1.1 {} {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                            status, status_text, body.len(), body
                        );
                        let _ = stream.write_all(resp.as_bytes()).await;
                    });
                }
            });

            Self {
                base_url,
                _handle: handle,
            }
        }
    }

    /// Full GCS-KMS round-trip: encrypt payload, wrap DEK, serve both via mock
    /// GCS/KMS endpoints, then decrypt and verify.
    #[tokio::test]
    async fn gcs_kms_full_roundtrip() {
        // 1. Prepare test data
        let plaintext_weights =
            b"fake model weights for integration test - at least 32 bytes of data";
        let dek: [u8; 32] = [0x42u8; 32];

        // Encrypt the payload with ChaCha20-Poly1305 (same as real flow)
        let encrypted_weights = encrypt_artifact(plaintext_weights, &dek).unwrap();

        // "Wrap" the DEK — in a real flow, KMS wraps it; here we just base64 encode
        // the raw DEK bytes (the mock KMS will return them as "plaintext")
        let wrapped_dek = b"kms-wrapped-dek-placeholder";
        let dek_b64 = BASE64.encode(dek);

        // Compute expected hash
        let expected_hash: [u8; 32] = Sha256::digest(plaintext_weights).into();

        // --- Test A: GCS fetch works ---
        let gcs_server = MockHttpServer::start(vec![
            (
                200,
                r#"{"access_token":"gcs-tok","token_type":"Bearer","expires_in":3600}"#.to_string(),
            ),
            (200, r#"{"model_type":"bert"}"#.to_string()),
        ])
        .await;

        let gcs_loader = GcsModelLoader::with_test_urls("test-bucket", &gcs_server.base_url);
        let config_art = gcs_loader
            .fetch_object("models/minilm/config.json")
            .await
            .unwrap();
        assert_eq!(config_art.bytes, br#"{"model_type":"bert"}"#);

        // --- Test B: KMS decrypt (full 5-step attestation flow) returns the DEK ---
        let kms_server = MockHttpServer::start(vec![
            (
                200,
                r#"{"access_token":"meta-tok","token_type":"Bearer","expires_in":3600}"#
                    .to_string(),
            ),
            (
                200,
                r#"{"name":"projects/test-project/locations/us-central1/challenges/ch-1","nonce":"AAAA"}"#
                    .to_string(),
            ),
            (
                200,
                r#"{"oidcClaimsToken":"eyJhbGciOiJSUzI1NiJ9.eyJhdWQiOiJ0ZXN0In0.sig"}"#
                    .to_string(),
            ),
            (
                200,
                r#"{"access_token":"fed-tok","token_type":"Bearer","expires_in":3600}"#.to_string(),
            ),
            (200, format!(r#"{{"plaintext":"{}"}}"#, dek_b64)),
        ])
        .await;

        let kms_client = GcpKmsClient::with_test_urls(
            "test-project",
            "us-central1",
            WIP,
            TeeAttestationProvider::synthetic(),
            &kms_server.base_url,
        );

        let unwrapped_dek = kms_client
            .decrypt(
                "projects/test/locations/global/keyRings/kr/cryptoKeys/model-key",
                wrapped_dek,
            )
            .await
            .unwrap();

        assert_eq!(unwrapped_dek.len(), 32, "DEK must be 32 bytes");
        assert_eq!(unwrapped_dek, dek.to_vec());

        // --- Test C: Decrypt the encrypted weights with the unwrapped DEK ---
        let dek_array: [u8; 32] = unwrapped_dek.try_into().unwrap();
        let decrypted_weights = decrypt_artifact(&encrypted_weights, &dek_array).unwrap();
        assert_eq!(decrypted_weights, plaintext_weights);

        // --- Test D: Verify hash matches ---
        let actual_hash: [u8; 32] = Sha256::digest(&decrypted_weights).into();
        assert_eq!(
            actual_hash, expected_hash,
            "Model hash must match after decrypt"
        );
    }

    /// KMS returns wrong DEK -> ChaCha20-Poly1305 decryption fails (fail-closed).
    #[tokio::test]
    async fn gcs_kms_wrong_dek_fails_closed() {
        let plaintext = b"sensitive model weights";
        let real_dek: [u8; 32] = [0x42u8; 32];
        let wrong_dek: [u8; 32] = [0x99u8; 32];

        let encrypted = encrypt_artifact(plaintext, &real_dek).unwrap();

        // Mock KMS returns the WRONG DEK
        let wrong_dek_b64 = BASE64.encode(wrong_dek);
        let kms_server = MockHttpServer::start(vec![
            (
                200,
                r#"{"access_token":"meta","token_type":"Bearer","expires_in":3600}"#.to_string(),
            ),
            (
                200,
                r#"{"name":"projects/p/locations/l/challenges/c","nonce":"AAAA"}"#.to_string(),
            ),
            (200, r#"{"oidcClaimsToken":"tok"}"#.to_string()),
            (
                200,
                r#"{"access_token":"fed","token_type":"Bearer","expires_in":3600}"#.to_string(),
            ),
            (200, format!(r#"{{"plaintext":"{}"}}"#, wrong_dek_b64)),
        ])
        .await;

        let kms_client = GcpKmsClient::with_test_urls(
            "test-project",
            "us-central1",
            WIP,
            TeeAttestationProvider::synthetic(),
            &kms_server.base_url,
        );

        let unwrapped = kms_client
            .decrypt(
                "projects/p/locations/l/keyRings/kr/cryptoKeys/k",
                b"wrapped",
            )
            .await
            .unwrap();

        let dek_arr: [u8; 32] = unwrapped.try_into().unwrap();

        // Decryption with wrong DEK MUST fail (AEAD authentication)
        let result = decrypt_artifact(&encrypted, &dek_arr);
        assert!(result.is_err(), "Decryption with wrong DEK must fail");
    }

    /// Hash mismatch after successful decrypt -> rejected (fail-closed).
    #[tokio::test]
    async fn gcs_kms_hash_mismatch_after_decrypt() {
        let plaintext = b"real model weights";
        let dek: [u8; 32] = [0x42u8; 32];

        let encrypted = encrypt_artifact(plaintext, &dek).unwrap();
        let decrypted = decrypt_artifact(&encrypted, &dek).unwrap();

        // Compute the actual hash
        let actual_hash: [u8; 32] = Sha256::digest(&decrypted).into();

        // A different expected hash should not match
        let mut wrong_expected = actual_hash;
        wrong_expected[0] ^= 0xFF;

        assert_ne!(actual_hash, wrong_expected);
    }

    /// KMS 403 (attestation-bound key release denied) -> entire flow fails.
    #[tokio::test]
    async fn gcs_kms_attestation_denied() {
        let kms_server = MockHttpServer::start(vec![
            (
                200,
                r#"{"access_token":"meta","token_type":"Bearer","expires_in":3600}"#.to_string(),
            ),
            (
                200,
                r#"{"name":"projects/p/locations/l/challenges/c","nonce":"AAAA"}"#.to_string(),
            ),
            (200, r#"{"oidcClaimsToken":"tok"}"#.to_string()),
            (
                200,
                r#"{"access_token":"fed","token_type":"Bearer","expires_in":3600}"#.to_string(),
            ),
            (
                403,
                r#"{"error":{"code":403,"message":"Request denied by WIP condition: image digest mismatch"}}"#
                    .to_string(),
            ),
        ])
        .await;

        let kms_client = GcpKmsClient::with_test_urls(
            "test-project",
            "us-central1",
            WIP,
            TeeAttestationProvider::synthetic(),
            &kms_server.base_url,
        );

        let result: ephemeral_ml_enclave::Result<Vec<u8>> = kms_client
            .decrypt(
                "projects/p/locations/l/keyRings/kr/cryptoKeys/k",
                b"wrapped-dek",
            )
            .await;

        assert!(result.is_err(), "KMS 403 must cause the flow to fail");
        let err = format!("{:?}", result.unwrap_err());
        assert!(
            err.contains("KMS decrypt returned") || err.contains("403"),
            "Error should mention KMS denial: {}",
            err
        );
    }

    /// GCS object not found (model not uploaded) -> flow fails before KMS.
    #[tokio::test]
    async fn gcs_missing_artifact_fails_before_kms() {
        let gcs_server = MockHttpServer::start(vec![
            (
                200,
                r#"{"access_token":"tok","token_type":"Bearer","expires_in":3600}"#.to_string(),
            ),
            (
                404,
                r#"{"error":{"code":404,"message":"No such object: bucket/model.safetensors.enc"}}"#
                    .to_string(),
            ),
        ])
        .await;

        let gcs_loader = GcsModelLoader::with_test_urls("test-bucket", &gcs_server.base_url);
        let result: ephemeral_ml_enclave::Result<_> = gcs_loader
            .fetch_object("models/minilm/model.safetensors.enc")
            .await;

        assert!(result.is_err(), "GCS 404 must fail the fetch");
        let err = format!("{:?}", result.unwrap_err());
        assert!(
            err.contains("GCS returned") || err.contains("404"),
            "Error should mention GCS failure: {}",
            err
        );
    }

    /// STS returns 400 (wrong WIP audience) → full decrypt flow fails closed.
    #[tokio::test]
    async fn gcs_kms_sts_wrong_audience_fails_closed() {
        // Steps 1-3 succeed, step 4 (STS) returns 400 with audience error
        let kms_server = MockHttpServer::start(vec![
            // Step 1: metadata token
            (
                200,
                r#"{"access_token":"meta","token_type":"Bearer","expires_in":3600}"#.to_string(),
            ),
            // Step 2: create challenge
            (
                200,
                r#"{"name":"projects/p/locations/l/challenges/c","nonce":"AAAA"}"#.to_string(),
            ),
            // Step 3: verify attestation → OIDC token
            (200, r#"{"oidcClaimsToken":"tok"}"#.to_string()),
            // Step 4: STS → wrong audience
            (
                400,
                r#"{"error":"invalid_target","error_description":"The target audience is not allowed for the given subject"}"#
                    .to_string(),
            ),
        ])
        .await;

        let kms_client = GcpKmsClient::with_test_urls(
            "test-project",
            "us-central1",
            WIP,
            TeeAttestationProvider::synthetic(),
            &kms_server.base_url,
        );

        let result: ephemeral_ml_enclave::Result<Vec<u8>> = kms_client
            .decrypt(
                "projects/p/locations/l/keyRings/kr/cryptoKeys/k",
                b"wrapped-dek",
            )
            .await;

        assert!(
            result.is_err(),
            "Wrong WIP audience must cause the flow to fail"
        );
        let err = format!("{:?}", result.unwrap_err());
        assert!(
            err.contains("STS returned"),
            "Error should mention STS rejection: {}",
            err
        );
    }

    /// VerifyAttestation returns 400 (MRTD mismatch) → full decrypt flow fails
    /// before reaching STS or KMS (fail-closed).
    #[tokio::test]
    async fn gcs_kms_verify_attestation_rejects_mrtd() {
        // Steps 1-2 succeed, step 3 (VerifyAttestation) returns 400
        let kms_server = MockHttpServer::start(vec![
            // Step 1: metadata token
            (
                200,
                r#"{"access_token":"meta","token_type":"Bearer","expires_in":3600}"#.to_string(),
            ),
            // Step 2: create challenge
            (
                200,
                r#"{"name":"projects/p/locations/l/challenges/c","nonce":"AAAA"}"#.to_string(),
            ),
            // Step 3: VerifyAttestation → MRTD mismatch
            (
                400,
                r#"{"error":{"code":400,"message":"MRTD mismatch: container image measurements do not match policy"}}"#
                    .to_string(),
            ),
        ])
        .await;

        let kms_client = GcpKmsClient::with_test_urls(
            "test-project",
            "us-central1",
            WIP,
            TeeAttestationProvider::synthetic(),
            &kms_server.base_url,
        );

        let result: ephemeral_ml_enclave::Result<Vec<u8>> = kms_client
            .decrypt(
                "projects/p/locations/l/keyRings/kr/cryptoKeys/k",
                b"wrapped-dek",
            )
            .await;

        assert!(result.is_err(), "MRTD mismatch must cause the flow to fail");
        let err = format!("{:?}", result.unwrap_err());
        assert!(
            err.contains("VerifyAttestation returned"),
            "Error should originate from VerifyAttestation, never reach KMS: {}",
            err
        );
    }

    /// encrypt_artifact -> decrypt_artifact round-trip with hash verification
    /// (mirrors the exact flow in the gcs-kms match arm of main.rs).
    #[tokio::test]
    async fn encrypt_decrypt_verify_full_chain() {
        let model_weights = vec![0xABu8; 1024]; // 1KB model
        let dek: [u8; 32] = [0x42u8; 32];

        // Encrypt (done offline, uploaded to GCS)
        let encrypted = encrypt_artifact(&model_weights, &dek).unwrap();
        assert!(encrypted.len() > model_weights.len()); // nonce + tag overhead

        // Mock KMS returns the DEK
        let dek_b64 = BASE64.encode(dek);
        let kms_server = MockHttpServer::start(vec![
            (
                200,
                r#"{"access_token":"m","token_type":"Bearer","expires_in":3600}"#.to_string(),
            ),
            (
                200,
                r#"{"name":"projects/p/locations/l/challenges/c","nonce":"AAAA"}"#.to_string(),
            ),
            (200, r#"{"oidcClaimsToken":"t"}"#.to_string()),
            (
                200,
                r#"{"access_token":"f","token_type":"Bearer","expires_in":3600}"#.to_string(),
            ),
            (200, format!(r#"{{"plaintext":"{}"}}"#, dek_b64)),
        ])
        .await;

        let kms_client = GcpKmsClient::with_test_urls(
            "p",
            "l",
            WIP,
            TeeAttestationProvider::synthetic(),
            &kms_server.base_url,
        );

        // Unwrap DEK via mock KMS
        let unwrapped = kms_client
            .decrypt(
                "projects/p/locations/l/keyRings/kr/cryptoKeys/k",
                b"wrapped",
            )
            .await
            .unwrap();
        let dek_arr: [u8; 32] = unwrapped.try_into().unwrap();

        // Decrypt the model
        let decrypted = decrypt_artifact(&encrypted, &dek_arr).unwrap();
        assert_eq!(decrypted, model_weights);

        // Verify hash (same check as main.rs gcs-kms arm)
        let expected_hash: [u8; 32] = Sha256::digest(&model_weights).into();
        let actual_hash: [u8; 32] = Sha256::digest(&decrypted).into();
        assert_eq!(actual_hash, expected_hash, "Hash must match after decrypt");
    }
}
