//! Shared cryptographic utilities for model decryption.
//!
//! Used by both the AWS model loader (via KMS proxy) and the GCP model
//! loader (via GcpKmsClient) to decrypt ChaCha20-Poly1305 encrypted
//! model artifacts.

use crate::{EnclaveError, EphemeralError, Result};
use chacha20poly1305::aead::Aead;
use chacha20poly1305::{ChaCha20Poly1305, Key, KeyInit, Nonce};
use sha2::{Digest, Sha256};

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
    }
}
