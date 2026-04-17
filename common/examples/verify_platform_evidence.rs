//! One-shot Phase 1 E2E validator.
//!
//! Usage:
//!     cargo run -p ephemeral-ml-common --example verify_platform_evidence -- \
//!         <bundle.cbor> <expected_hash_hex> <receipt_signing_key_hex> \
//!         <base_attestation_hash_hex>
//!
//! Called against artifacts captured from a real GCP CS TDX enclave boot:
//!   bundle.cbor             - scp'd from /tmp/ephemeralml-platform-evidence.cbor
//!   expected_hash_hex       - platform_evidence_hash from enclave `info!` log
//!   receipt_signing_key_hex - receipt_pk (hex) from enclave boot log
//!   base_attestation_hash_hex - boot_attestation_hash (hex) from enclave log
//!
//! Prints the decoded bundle on success, exits non-zero on binding mismatch.

use ephemeral_ml_common::PlatformEvidenceBundle;
use std::env;
use std::fs;
use std::process::ExitCode;

fn parse_hash(label: &str, s: &str) -> [u8; 32] {
    let bytes = hex::decode(s.trim()).unwrap_or_else(|e| {
        eprintln!("ERROR: {} must be 32-byte hex: {}", label, e);
        std::process::exit(2);
    });
    bytes.try_into().unwrap_or_else(|b: Vec<u8>| {
        eprintln!("ERROR: {} must be 32 bytes, got {}", label, b.len());
        std::process::exit(2);
    })
}

fn main() -> ExitCode {
    let args: Vec<String> = env::args().collect();
    if args.len() != 5 {
        eprintln!(
            "usage: {} <bundle.cbor> <expected_hash_hex> <receipt_signing_key_hex> <base_attestation_hash_hex>",
            args[0]
        );
        return ExitCode::from(2);
    }

    let bundle_path = &args[1];
    let bundle_bytes = fs::read(bundle_path).unwrap_or_else(|e| {
        eprintln!("ERROR: failed to read {}: {}", bundle_path, e);
        std::process::exit(2);
    });
    let expected_hash = parse_hash("expected_hash", &args[2]);
    let expected_signing_key = parse_hash("receipt_signing_key", &args[3]);
    let expected_attestation_hash = parse_hash("base_attestation_hash", &args[4]);

    println!("Bundle file:              {} ({} bytes)", bundle_path, bundle_bytes.len());
    println!("Expected bundle hash:     {}", hex::encode(expected_hash));
    println!("Expected signing key:     {}", hex::encode(expected_signing_key));
    println!("Expected attest hash:     {}", hex::encode(expected_attestation_hash));

    match PlatformEvidenceBundle::verify_binding(
        &bundle_bytes,
        &expected_hash,
        &expected_signing_key,
        &expected_attestation_hash,
    ) {
        Ok(bundle) => {
            println!();
            println!("BINDING VERIFIED");
            println!("  platform_profile:       {}", bundle.platform_profile);
            println!("  generated_at:           {}", bundle.generated_at);
            println!("  binding.model_id:       {}", bundle.binding.model_id);
            if let Some(h) = bundle.binding.model_hash {
                println!("  binding.model_hash:     {}", hex::encode(h));
            }
            if let Some(k) = bundle.binding.hpke_public_key {
                println!("  binding.hpke_pk:        {}", hex::encode(k));
            }
            if let Some(cpu) = &bundle.cpu {
                println!("  cpu.tee_type:           {}", cpu.tee_type);
                println!("  cpu.measurement_type:   {}", cpu.measurement_type);
                println!("  cpu.measurements:       {} entries", cpu.measurements.len());
            }
            if let Some(cloud) = &bundle.cloud {
                println!("  cloud.source:           {}", cloud.attestation_source);
            }
            println!("  verifier.cpu:           {}", bundle.verifier.cpu_verifier);
            println!("  verifier.policy:        {}", bundle.verifier.policy_version);
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!();
            eprintln!("BINDING REJECTED: {}", e);
            ExitCode::from(1)
        }
    }
}
