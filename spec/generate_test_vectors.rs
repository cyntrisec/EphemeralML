//! Standalone binary that generates deterministic test vectors for the
//! EphemeralML Attested Execution Receipt (AER) specification.
//!
//! Run with:
//!     cargo run --bin generate-test-vectors
//!
//! Outputs CBOR (`.cbor`), JSON (`.json`), and public-key (`.pubkey`) files
//! into `spec/test-vectors/`.

use ed25519_dalek::SigningKey;
use ephemeral_ml_common::{
    current_timestamp, AttestationReceipt, EnclaveMeasurements, ReceiptSigningKey, SecurityMode,
};
use std::fs;
use std::path::Path;

/// Directory where test vector files are written.
const OUTPUT_DIR: &str = "spec/test-vectors";

/// Deterministic signing key (key A).
fn deterministic_key_a() -> (SigningKey, ReceiptSigningKey) {
    let sk = SigningKey::from_bytes(&[0x01; 32]);
    let vk = sk.verifying_key();
    let rsk = ReceiptSigningKey::from_parts(sk.clone(), vk);
    (sk, rsk)
}

/// Deterministic signing key (key B) -- used for wrong-key test.
fn deterministic_key_b() -> (SigningKey, ReceiptSigningKey) {
    let sk = SigningKey::from_bytes(&[0x02; 32]);
    let vk = sk.verifying_key();
    let rsk = ReceiptSigningKey::from_parts(sk.clone(), vk);
    (sk, rsk)
}

/// Build a baseline receipt with the given id, model_id, measurements, and timestamp.
fn build_receipt(
    receipt_id: &str,
    model_id: &str,
    measurements: EnclaveMeasurements,
    timestamp: u64,
) -> AttestationReceipt {
    let mut r = AttestationReceipt::new(
        receipt_id.to_string(),
        1,                          // protocol_version
        SecurityMode::GatewayOnly,
        measurements,
        [0xAA; 32],                 // attestation_doc_hash
        [0xBB; 32],                 // request_hash
        [0xCC; 32],                 // response_hash
        "policy-v1".to_string(),
        1,                          // sequence_number
        model_id.to_string(),
        "v1.0.0".to_string(),
        150,                        // execution_time_ms
        256,                        // memory_peak_mb
    );
    r.execution_timestamp = timestamp;
    r
}

/// Serialize a receipt to CBOR bytes.
fn to_cbor(receipt: &AttestationReceipt) -> Vec<u8> {
    ephemeral_ml_common::cbor::to_vec(receipt).expect("CBOR serialization failed")
}

/// Serialize a receipt to pretty JSON bytes.
fn to_json(receipt: &AttestationReceipt) -> Vec<u8> {
    serde_json::to_vec_pretty(receipt).expect("JSON serialization failed")
}

/// Write CBOR + JSON files (and optionally a `.pubkey` file) for the given
/// test vector name.
fn write_vector(name: &str, receipt: &AttestationReceipt, pubkey: Option<&[u8; 32]>) {
    let dir = Path::new(OUTPUT_DIR);

    let cbor_path = dir.join(format!("{}.cbor", name));
    let json_path = dir.join(format!("{}.json", name));

    fs::write(&cbor_path, to_cbor(receipt)).expect("failed to write CBOR");
    fs::write(&json_path, to_json(receipt)).expect("failed to write JSON");

    println!("  {}.cbor  ({} bytes)", name, fs::metadata(&cbor_path).unwrap().len());
    println!("  {}.json  ({} bytes)", name, fs::metadata(&json_path).unwrap().len());

    if let Some(pk) = pubkey {
        let pk_path = dir.join(format!("{}.pubkey", name));
        fs::write(&pk_path, pk).expect("failed to write pubkey");
        println!("  {}.pubkey (32 bytes)", name);
    }
}

fn main() {
    // Ensure output directory exists.
    fs::create_dir_all(OUTPUT_DIR).expect("failed to create output directory");

    let now = current_timestamp();
    let (_sk_a, rsk_a) = deterministic_key_a();
    let (_sk_b, rsk_b) = deterministic_key_b();

    println!("Generating EphemeralML receipt test vectors...\n");

    // -----------------------------------------------------------------------
    // 1. valid-receipt-nitro
    // -----------------------------------------------------------------------
    {
        let name = "valid-receipt-nitro";
        println!("[{}]", name);
        let measurements = EnclaveMeasurements::new(
            vec![0x11; 48],
            vec![0x22; 48],
            vec![0x33; 48],
        );
        let mut receipt = build_receipt("receipt-nitro-001", "minilm-l6-v2", measurements, now);
        receipt.sign(&rsk_a).expect("signing failed");
        write_vector(name, &receipt, Some(&rsk_a.public_key_bytes()));
    }

    // -----------------------------------------------------------------------
    // 2. valid-receipt-tdx
    // -----------------------------------------------------------------------
    {
        let name = "valid-receipt-tdx";
        println!("[{}]", name);
        let measurements = EnclaveMeasurements::new_tdx(
            vec![0x44; 48],
            vec![0x55; 48],
            vec![0x66; 48],
        );
        let mut receipt = build_receipt("receipt-tdx-001", "minilm-l6-v2", measurements, now);
        receipt.sign(&rsk_a).expect("signing failed");
        write_vector(name, &receipt, Some(&rsk_a.public_key_bytes()));
    }

    // -----------------------------------------------------------------------
    // 3. tampered-receipt-id
    // -----------------------------------------------------------------------
    {
        let name = "tampered-receipt-id";
        println!("[{}]", name);
        let measurements = EnclaveMeasurements::new(
            vec![0x11; 48],
            vec![0x22; 48],
            vec![0x33; 48],
        );
        let mut receipt = build_receipt("receipt-original-id", "minilm-l6-v2", measurements, now);
        receipt.sign(&rsk_a).expect("signing failed");
        // Mutate receipt_id AFTER signing -- signature should fail verification.
        receipt.receipt_id = "receipt-TAMPERED-id".to_string();
        write_vector(name, &receipt, Some(&rsk_a.public_key_bytes()));
    }

    // -----------------------------------------------------------------------
    // 4. tampered-model-id
    // -----------------------------------------------------------------------
    {
        let name = "tampered-model-id";
        println!("[{}]", name);
        let measurements = EnclaveMeasurements::new(
            vec![0x11; 48],
            vec![0x22; 48],
            vec![0x33; 48],
        );
        let mut receipt = build_receipt("receipt-model-001", "minilm-l6-v2", measurements, now);
        receipt.sign(&rsk_a).expect("signing failed");
        // Mutate model_id AFTER signing.
        receipt.model_id = "evil-model-v9".to_string();
        write_vector(name, &receipt, Some(&rsk_a.public_key_bytes()));
    }

    // -----------------------------------------------------------------------
    // 5. wrong-key-receipt
    // -----------------------------------------------------------------------
    {
        let name = "wrong-key-receipt";
        println!("[{}]", name);
        let measurements = EnclaveMeasurements::new(
            vec![0x11; 48],
            vec![0x22; 48],
            vec![0x33; 48],
        );
        let mut receipt = build_receipt("receipt-wrongkey-001", "minilm-l6-v2", measurements, now);
        // Sign with key A ...
        receipt.sign(&rsk_a).expect("signing failed");
        // ... but ship key B's public key. Verification must fail.
        write_vector(name, &receipt, Some(&rsk_b.public_key_bytes()));
    }

    // -----------------------------------------------------------------------
    // 6. stale-receipt
    // -----------------------------------------------------------------------
    {
        let name = "stale-receipt";
        println!("[{}]", name);
        let measurements = EnclaveMeasurements::new(
            vec![0x11; 48],
            vec![0x22; 48],
            vec![0x33; 48],
        );
        let stale_ts = now.saturating_sub(7200); // 2 hours ago
        let mut receipt = build_receipt("receipt-stale-001", "minilm-l6-v2", measurements, stale_ts);
        receipt.sign(&rsk_a).expect("signing failed");
        write_vector(name, &receipt, Some(&rsk_a.public_key_bytes()));
    }

    // -----------------------------------------------------------------------
    // 7. future-receipt
    // -----------------------------------------------------------------------
    {
        let name = "future-receipt";
        println!("[{}]", name);
        let measurements = EnclaveMeasurements::new(
            vec![0x11; 48],
            vec![0x22; 48],
            vec![0x33; 48],
        );
        let future_ts = now + 3600; // 1 hour from now
        let mut receipt = build_receipt("receipt-future-001", "minilm-l6-v2", measurements, future_ts);
        receipt.sign(&rsk_a).expect("signing failed");
        write_vector(name, &receipt, Some(&rsk_a.public_key_bytes()));
    }

    // -----------------------------------------------------------------------
    // 8. short-measurements
    // -----------------------------------------------------------------------
    {
        let name = "short-measurements";
        println!("[{}]", name);
        // 32-byte measurements instead of the expected 48
        let measurements = EnclaveMeasurements::new(
            vec![0x11; 32],
            vec![0x22; 32],
            vec![0x33; 32],
        );
        let mut receipt = build_receipt("receipt-short-001", "minilm-l6-v2", measurements, now);
        receipt.sign(&rsk_a).expect("signing failed");
        write_vector(name, &receipt, Some(&rsk_a.public_key_bytes()));
    }

    // -----------------------------------------------------------------------
    // 9. pipeline-chained
    // -----------------------------------------------------------------------
    {
        let name = "pipeline-chained";
        println!("[{}]", name);
        let measurements = EnclaveMeasurements::new(
            vec![0x11; 48],
            vec![0x22; 48],
            vec![0x33; 48],
        );
        let mut receipt = build_receipt("receipt-pipeline-001", "minilm-l6-v2", measurements, now);
        receipt.previous_receipt_hash = Some([0xAB; 32]);
        receipt.sign(&rsk_a).expect("signing failed");
        write_vector(name, &receipt, Some(&rsk_a.public_key_bytes()));
    }

    println!("\nDone. {} test vectors written to {}/", 9, OUTPUT_DIR);
}
