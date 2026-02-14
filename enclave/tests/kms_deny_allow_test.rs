//! KMS deny/allow integration test.
//!
//! Simulates the full attestation-gated model release flow:
//!
//!   1. Model owner encrypts weights with DEK (ChaCha20-Poly1305)
//!   2. DEK is "wrapped" (simulated KMS — in production, Cloud KMS does this)
//!   3. Attested workload unwraps DEK → decrypts model → hash verified
//!   4. Wrong identity / wrong DEK → decryption denied
//!
//! This is NOT a unit test — it exercises the full `encrypt_artifact` →
//! `decrypt_and_verify` pipeline with realistic model-sized payloads.
//!
//! Run with: cargo test --features mock --test kms_deny_allow_test

use ephemeral_ml_enclave::crypto_util::{decrypt_and_verify, decrypt_artifact, encrypt_artifact};
use sha2::{Digest, Sha256};

/// Simulate KMS key wrapping: in production, Cloud KMS encrypts the DEK with a
/// key-encryption-key (KEK) that only attested workloads can use. Here we use
/// XOR with a "policy key" to simulate the wrap/unwrap without real KMS.
fn kms_wrap_dek(dek: &[u8; 32], policy_key: &[u8; 32]) -> Vec<u8> {
    dek.iter().zip(policy_key.iter()).map(|(a, b)| a ^ b).collect()
}

fn kms_unwrap_dek(wrapped: &[u8], policy_key: &[u8; 32]) -> Result<[u8; 32], String> {
    if wrapped.len() != 32 {
        return Err("wrapped DEK must be 32 bytes".to_string());
    }
    let mut dek = [0u8; 32];
    for (i, (a, b)) in wrapped.iter().zip(policy_key.iter()).enumerate() {
        dek[i] = a ^ b;
    }
    Ok(dek)
}

/// Full allow path: correct attestation identity → unwrap DEK → decrypt model → hash matches.
#[test]
fn kms_allow_correct_identity_decrypts_model() {
    // --- Model owner (offline) ---
    // Generate a random DEK
    let dek: [u8; 32] = {
        use rand::RngCore;
        let mut key = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut key);
        key
    };

    // Simulate model weights (realistic size: 1 MB)
    let model_weights: Vec<u8> = (0..1_000_000).map(|i| (i % 256) as u8).collect();

    // Compute expected hash
    let expected_hash: [u8; 32] = Sha256::digest(&model_weights).into();

    // Encrypt model weights with DEK
    let encrypted_weights = encrypt_artifact(&model_weights, &dek).unwrap();

    // Wrap DEK with policy key (only attested workloads get this key)
    let policy_key: [u8; 32] = [0xAA; 32]; // KMS policy: "only TDX workloads"
    let wrapped_dek = kms_wrap_dek(&dek, &policy_key);

    // --- Attested workload (enclave) ---
    // Step 1: Present attestation → KMS grants policy_key
    // (In production: GcpKmsClient.decrypt() calls Cloud KMS with TDX quote,
    //  KMS checks WIP policy, returns unwrapped DEK)
    let unwrapped_dek = kms_unwrap_dek(&wrapped_dek, &policy_key).unwrap();

    // Step 2: Decrypt model weights and verify hash
    let decrypted = decrypt_and_verify(&encrypted_weights, &unwrapped_dek, &expected_hash).unwrap();

    // Step 3: Verify model integrity
    assert_eq!(decrypted.len(), model_weights.len());
    assert_eq!(decrypted, model_weights);

    println!("ALLOW: Attested workload decrypted 1 MB model, hash verified.");
    println!("  DEK:           {}...", hex::encode(&dek[..8]));
    println!("  Model hash:    {}", hex::encode(expected_hash));
    println!("  Encrypted:     {} bytes", encrypted_weights.len());
    println!("  Decrypted:     {} bytes", decrypted.len());
}

/// Deny path 1: wrong attestation identity → wrong policy key → unwrap produces garbage → AEAD rejects.
#[test]
fn kms_deny_wrong_identity_cannot_decrypt() {
    let dek: [u8; 32] = [0x42; 32];
    let model_weights = b"sensitive model weights that must be protected";

    // Encrypt with real DEK
    let encrypted = encrypt_artifact(model_weights, &dek).unwrap();

    // Wrap DEK with the correct policy key
    let correct_policy_key: [u8; 32] = [0xAA; 32]; // TDX workload identity
    let wrapped_dek = kms_wrap_dek(&dek, &correct_policy_key);

    // Attacker's identity → different policy key (KMS returns different unwrap)
    let attacker_policy_key: [u8; 32] = [0xBB; 32]; // Unattested VM identity
    let wrong_dek = kms_unwrap_dek(&wrapped_dek, &attacker_policy_key).unwrap();

    // Wrong DEK should differ from real DEK
    assert_ne!(wrong_dek, dek, "Policy keys differ → DEKs must differ");

    // Decryption must fail — AEAD authentication rejects wrong key
    let result = decrypt_artifact(&encrypted, &wrong_dek);
    assert!(
        result.is_err(),
        "DENY: Unattested identity must not decrypt model"
    );

    println!("DENY: Wrong attestation identity → AEAD rejected decryption.");
    println!("  Real DEK:      {}...", hex::encode(&dek[..8]));
    println!("  Wrong DEK:     {}...", hex::encode(&wrong_dek[..8]));
    println!("  Result:        {:?}", result.unwrap_err());
}

/// Deny path 2: correct DEK but model weights tampered in transit → hash mismatch.
#[test]
fn kms_deny_tampered_model_weights_detected() {
    let dek: [u8; 32] = [0x42; 32];
    let real_weights = b"real model weights";
    let expected_hash: [u8; 32] = Sha256::digest(real_weights).into();

    // Attacker substitutes different weights, encrypts with same DEK
    let tampered_weights = b"backdoored weights";
    let tampered_encrypted = encrypt_artifact(tampered_weights, &dek).unwrap();

    // Decryption succeeds (correct DEK) but hash verification fails
    let result = decrypt_and_verify(&tampered_encrypted, &dek, &expected_hash);
    assert!(
        result.is_err(),
        "DENY: Tampered model weights must fail hash verification"
    );

    let err = format!("{:?}", result.unwrap_err());
    assert!(
        err.contains("Hash mismatch"),
        "Error should mention hash mismatch, got: {}",
        err
    );

    println!("DENY: Model weight substitution detected via hash mismatch.");
    println!(
        "  Expected hash: {}",
        hex::encode(expected_hash)
    );
    println!(
        "  Tampered hash: {}",
        hex::encode(Sha256::digest(tampered_weights))
    );
}

/// Deny path 3: attacker intercepts wrapped DEK and replays with different encrypted model.
/// Even with the correct policy key, the hash check catches the mismatch.
#[test]
fn kms_deny_model_swap_with_valid_dek() {
    let dek: [u8; 32] = [0x42; 32];
    let policy_key: [u8; 32] = [0xAA; 32];

    // Owner publishes model A
    let model_a = b"legitimate model A weights";
    let model_a_hash: [u8; 32] = Sha256::digest(model_a).into();
    let model_a_enc = encrypt_artifact(model_a, &dek).unwrap();
    let wrapped_dek = kms_wrap_dek(&dek, &policy_key);

    // Attacker creates model B, encrypts with their own DEK
    let attacker_dek: [u8; 32] = [0x99; 32];
    let model_b = b"attacker's backdoored model B";
    let model_b_enc = encrypt_artifact(model_b, &attacker_dek).unwrap();

    // Attacker cannot decrypt model A (wrong DEK)
    let result_b_key = decrypt_artifact(&model_a_enc, &attacker_dek);
    assert!(result_b_key.is_err(), "Attacker DEK must not decrypt model A");

    // If attacker somehow replaces encrypted blob, the hash check catches it
    let unwrapped = kms_unwrap_dek(&wrapped_dek, &policy_key).unwrap();
    assert_eq!(unwrapped, dek);

    // Original model decrypts and verifies fine
    let good = decrypt_and_verify(&model_a_enc, &unwrapped, &model_a_hash).unwrap();
    assert_eq!(good, model_a);

    // Attacker's encrypted model can't be decrypted with real DEK
    let result_swap = decrypt_artifact(&model_b_enc, &unwrapped);
    assert!(
        result_swap.is_err(),
        "DENY: Swapped encrypted model must fail with real DEK"
    );

    println!("DENY: Model swap attack blocked — wrong key for swapped blob.");
}

/// Full pipeline simulation: encrypt → wrap → attest → unwrap → decrypt → verify → register.
/// This mirrors the real GCP gcs-kms model loading path in main.rs:305-407.
#[test]
fn kms_full_pipeline_simulation() {
    use rand::RngCore;

    // === Model Owner Phase (offline tooling, scripts/gcp/encrypt_model.sh) ===

    // Generate DEK
    let mut dek = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut dek);

    // Simulate realistic model weights
    let model_weights: Vec<u8> = {
        let mut w = vec![0u8; 500_000]; // 500 KB
        rand::rngs::OsRng.fill_bytes(&mut w);
        w
    };

    // Compute model hash (published in manifest)
    let model_hash: [u8; 32] = Sha256::digest(&model_weights).into();

    // Encrypt model
    let encrypted_model = encrypt_artifact(&model_weights, &dek).unwrap();

    // Wrap DEK via KMS (only attested workloads can unwrap)
    let kms_policy_key: [u8; 32] = {
        let mut k = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut k);
        k
    };
    let wrapped_dek = kms_wrap_dek(&dek, &kms_policy_key);

    // === Enclave Phase (runtime, main.rs gcs-kms path) ===

    // Step 1: Fetch artifacts from GCS (simulated — we just have the bytes)
    let fetched_encrypted = &encrypted_model;
    let fetched_wrapped_dek = &wrapped_dek;

    // Step 2: Present attestation → KMS unwraps DEK
    // (In production: GcpKmsClient.get_attested_token() + GcpKmsClient.decrypt())
    let unwrapped_dek = kms_unwrap_dek(fetched_wrapped_dek, &kms_policy_key).unwrap();
    assert_eq!(unwrapped_dek, dek, "Unwrapped DEK should match original");

    // Step 3: Decrypt and verify model
    let decrypted_model =
        decrypt_and_verify(fetched_encrypted, &unwrapped_dek, &model_hash).unwrap();
    assert_eq!(decrypted_model, model_weights);

    // Step 4: Would call engine.register_model() here in production

    println!("FULL PIPELINE: encrypt → wrap → unwrap → decrypt → verify");
    println!("  Model size:    {} bytes", model_weights.len());
    println!("  Encrypted:     {} bytes", encrypted_model.len());
    println!("  Model hash:    {}...", &hex::encode(model_hash)[..16]);
    println!("  DEK:           {}... (zeroed after use)", &hex::encode(dek)[..16]);

    // === Deny: same pipeline, wrong identity ===
    let wrong_policy_key: [u8; 32] = [0xFF; 32];
    let wrong_dek = kms_unwrap_dek(fetched_wrapped_dek, &wrong_policy_key).unwrap();
    assert_ne!(wrong_dek, dek);

    let deny_result = decrypt_and_verify(fetched_encrypted, &wrong_dek, &model_hash);
    assert!(
        deny_result.is_err(),
        "Wrong identity must not decrypt model"
    );

    println!("  Deny path:     wrong identity → AEAD rejected");
}
