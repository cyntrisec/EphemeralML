//! Shared cryptographic utilities for model decryption.
//!
//! Used by both the AWS model loader (via KMS proxy) and the GCP model
//! loader (via GcpKmsClient) to decrypt ChaCha20-Poly1305 encrypted
//! model artifacts.

use crate::{EnclaveError, EphemeralError, Result};
use chacha20poly1305::aead::Aead;
use chacha20poly1305::{ChaCha20Poly1305, Key, KeyInit, Nonce};
use sha2::{Digest, Sha256};

/// Encrypt a plaintext artifact with ChaCha20-Poly1305.
///
/// Output format: `nonce (12 bytes) || ciphertext+tag`.
/// This is the inverse of `decrypt_artifact()`.
pub fn encrypt_artifact(plaintext: &[u8], dek: &[u8; 32]) -> Result<Vec<u8>> {
    use rand::RngCore;

    let key: &Key = dek.into();
    let cipher = ChaCha20Poly1305::new(key);

    let mut nonce_bytes = [0u8; 12];
    rand::rngs::OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ciphertext = cipher.encrypt(nonce, plaintext).map_err(|e| {
        EnclaveError::Enclave(EphemeralError::EncryptionError(format!(
            "ChaCha20-Poly1305 encryption failed: {}",
            e
        )))
    })?;

    let mut result = nonce_bytes.to_vec();
    result.extend_from_slice(&ciphertext);
    Ok(result)
}

/// Decrypt a ChaCha20-Poly1305 encrypted artifact.
///
/// The artifact format is: `nonce (12 bytes) || ciphertext+tag`.
/// Returns the decrypted plaintext bytes.
pub fn decrypt_artifact(encrypted: &[u8], dek: &[u8; 32]) -> Result<Vec<u8>> {
    if encrypted.len() < 12 + 16 {
        return Err(EnclaveError::Enclave(EphemeralError::DecryptionError(
            "Encrypted artifact too short (need at least nonce + tag)".to_string(),
        )));
    }

    let (nonce_bytes, ciphertext) = encrypted.split_at(12);
    let key: &Key = dek.into();
    let cipher = ChaCha20Poly1305::new(key);
    let nonce = Nonce::from_slice(nonce_bytes);

    cipher.decrypt(nonce, ciphertext).map_err(|e| {
        EnclaveError::Enclave(EphemeralError::DecryptionError(format!(
            "ChaCha20-Poly1305 decryption failed: {}",
            e
        )))
    })
}

/// Decrypt an artifact and verify its SHA-256 hash.
///
/// Returns the plaintext if the hash matches. Errors if it doesn't.
pub fn decrypt_and_verify(
    encrypted: &[u8],
    dek: &[u8; 32],
    expected_sha256: &[u8; 32],
) -> Result<Vec<u8>> {
    let plaintext = decrypt_artifact(encrypted, dek)?;

    let mut hasher = Sha256::new();
    hasher.update(&plaintext);
    let actual_hash: [u8; 32] = hasher.finalize().into();

    if actual_hash != *expected_sha256 {
        return Err(EnclaveError::Enclave(EphemeralError::DecryptionError(
            format!(
                "Hash mismatch after decryption: expected {}, got {}",
                hex::encode(expected_sha256),
                hex::encode(actual_hash),
            ),
        )));
    }

    Ok(plaintext)
}

#[cfg(test)]
mod tests {
    use super::*;
    use chacha20poly1305::aead::Aead;
    use rand::rngs::OsRng;
    use rand::RngCore;

    fn encrypt_test_data(plaintext: &[u8], dek: &[u8; 32]) -> Vec<u8> {
        let key: &Key = dek.into();
        let cipher = ChaCha20Poly1305::new(key);
        let mut nonce_bytes = [0u8; 12];
        OsRng.fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);
        let ciphertext = cipher.encrypt(nonce, plaintext).unwrap();
        let mut result = nonce_bytes.to_vec();
        result.extend_from_slice(&ciphertext);
        result
    }

    #[test]
    fn decrypt_roundtrip() {
        let dek = [0x42u8; 32];
        let plaintext = b"hello world model weights";
        let encrypted = encrypt_test_data(plaintext, &dek);
        let decrypted = decrypt_artifact(&encrypted, &dek).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn decrypt_and_verify_ok() {
        let dek = [0x42u8; 32];
        let plaintext = b"model weights data";
        let encrypted = encrypt_test_data(plaintext, &dek);

        let mut hasher = Sha256::new();
        hasher.update(plaintext);
        let expected_hash: [u8; 32] = hasher.finalize().into();

        let result = decrypt_and_verify(&encrypted, &dek, &expected_hash).unwrap();
        assert_eq!(result, plaintext);
    }

    #[test]
    fn decrypt_and_verify_hash_mismatch() {
        let dek = [0x42u8; 32];
        let plaintext = b"model weights data";
        let encrypted = encrypt_test_data(plaintext, &dek);

        let wrong_hash = [0xFF; 32];
        let result = decrypt_and_verify(&encrypted, &dek, &wrong_hash);
        assert!(result.is_err());
    }

    #[test]
    fn decrypt_wrong_key() {
        let dek = [0x42u8; 32];
        let wrong_dek = [0x99u8; 32];
        let plaintext = b"secret data";
        let encrypted = encrypt_test_data(plaintext, &dek);
        let result = decrypt_artifact(&encrypted, &wrong_dek);
        assert!(result.is_err());
    }

    #[test]
    fn decrypt_too_short() {
        let dek = [0x42u8; 32];
        let result = decrypt_artifact(&[0u8; 10], &dek);
        assert!(result.is_err());
        let err = format!("{:?}", result.unwrap_err());
        assert!(err.contains("too short"), "Error: {}", err);
    }

    // --- Negative / edge-case tests ---

    #[test]
    fn decrypt_tampered_ciphertext() {
        let dek = [0x42u8; 32];
        let plaintext = b"sensitive model weights";
        let mut encrypted = encrypt_test_data(plaintext, &dek);

        // Flip a bit in the ciphertext portion (after the 12-byte nonce)
        encrypted[15] ^= 0x01;

        let result = decrypt_artifact(&encrypted, &dek);
        assert!(result.is_err(), "Tampered ciphertext should fail AEAD");
    }

    #[test]
    fn decrypt_tampered_nonce() {
        let dek = [0x42u8; 32];
        let plaintext = b"sensitive model weights";
        let mut encrypted = encrypt_test_data(plaintext, &dek);

        // Flip a bit in the nonce (first 12 bytes)
        encrypted[0] ^= 0x01;

        let result = decrypt_artifact(&encrypted, &dek);
        assert!(result.is_err(), "Tampered nonce should fail AEAD");
    }

    #[test]
    fn decrypt_exact_minimum_size() {
        // Minimum valid: 12 (nonce) + 16 (tag) = 28 bytes, 0 bytes plaintext
        let dek = [0x42u8; 32];
        let plaintext = b""; // empty
        let encrypted = encrypt_test_data(plaintext, &dek);

        // Should be exactly 28 bytes (12 nonce + 16 tag)
        assert_eq!(encrypted.len(), 28);

        let result = decrypt_artifact(&encrypted, &dek).unwrap();
        assert!(result.is_empty());
    }

    #[test]
    fn decrypt_just_below_minimum_size() {
        let dek = [0x42u8; 32];
        // 27 bytes: below minimum of 28 (12 nonce + 16 tag)
        let result = decrypt_artifact(&[0u8; 27], &dek);
        assert!(result.is_err());
    }

    #[test]
    fn decrypt_large_payload_roundtrip() {
        let dek = [0x42u8; 32];
        // 1 MB payload — realistic model shard size
        let plaintext = vec![0xABu8; 1_000_000];
        let encrypted = encrypt_test_data(&plaintext, &dek);
        let decrypted = decrypt_artifact(&encrypted, &dek).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn decrypt_and_verify_tampered_after_decrypt() {
        // Data that decrypts fine but whose hash doesn't match
        let dek = [0x42u8; 32];
        let plaintext = b"the real data";
        let encrypted = encrypt_test_data(plaintext, &dek);

        // Hash of different data
        let mut hasher = Sha256::new();
        hasher.update(b"different data");
        let wrong_hash: [u8; 32] = hasher.finalize().into();

        let result = decrypt_and_verify(&encrypted, &dek, &wrong_hash);
        assert!(result.is_err());
        let err = format!("{:?}", result.unwrap_err());
        assert!(err.contains("Hash mismatch"), "Error: {}", err);
    }

    #[test]
    fn encrypt_artifact_roundtrip() {
        let dek = [0x42u8; 32];
        let plaintext = b"model weights to encrypt";
        let encrypted = super::encrypt_artifact(plaintext, &dek).unwrap();

        // Should be nonce (12) + plaintext + tag (16)
        assert_eq!(encrypted.len(), 12 + plaintext.len() + 16);

        let decrypted = decrypt_artifact(&encrypted, &dek).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn encrypt_artifact_empty_plaintext() {
        let dek = [0x42u8; 32];
        let encrypted = super::encrypt_artifact(b"", &dek).unwrap();
        assert_eq!(encrypted.len(), 12 + 16); // nonce + tag only
        let decrypted = decrypt_artifact(&encrypted, &dek).unwrap();
        assert!(decrypted.is_empty());
    }

    /// Simulates the KMS deny case: model encrypted with real DEK,
    /// attacker tries to decrypt with wrong DEK — AEAD rejects.
    #[test]
    fn encrypt_artifact_wrong_key_denied() {
        let real_dek = [0x42u8; 32];
        let wrong_dek = [0x99u8; 32];
        let model_weights = b"sensitive model weights that must be protected";

        let encrypted = super::encrypt_artifact(model_weights, &real_dek).unwrap();

        // Correct key succeeds
        let decrypted = decrypt_artifact(&encrypted, &real_dek).unwrap();
        assert_eq!(decrypted, model_weights);

        // Wrong key fails — AEAD authentication rejects
        let result = decrypt_artifact(&encrypted, &wrong_dek);
        assert!(result.is_err(), "Decryption with wrong DEK must fail");
    }

    #[test]
    fn encrypt_artifact_different_calls_produce_different_nonces() {
        let dek = [0x42u8; 32];
        let plaintext = b"same data";
        let enc1 = super::encrypt_artifact(plaintext, &dek).unwrap();
        let enc2 = super::encrypt_artifact(plaintext, &dek).unwrap();

        // Nonces (first 12 bytes) should differ
        assert_ne!(&enc1[..12], &enc2[..12]);

        // Both should decrypt to the same plaintext
        assert_eq!(decrypt_artifact(&enc1, &dek).unwrap(), plaintext);
        assert_eq!(decrypt_artifact(&enc2, &dek).unwrap(), plaintext);
    }

    #[test]
    fn decrypt_two_different_keys_produce_different_results() {
        let dek1 = [0x11u8; 32];
        let dek2 = [0x22u8; 32];
        let plaintext = b"data";

        let enc1 = encrypt_test_data(plaintext, &dek1);
        let enc2 = encrypt_test_data(plaintext, &dek2);

        // Both decrypt with their own key
        assert_eq!(decrypt_artifact(&enc1, &dek1).unwrap(), plaintext);
        assert_eq!(decrypt_artifact(&enc2, &dek2).unwrap(), plaintext);

        // Neither decrypts with the other's key
        assert!(decrypt_artifact(&enc1, &dek2).is_err());
        assert!(decrypt_artifact(&enc2, &dek1).is_err());
    }
}
