//! CLI for EphemeralML compliance operations.
//!
//! Subcommands:
//! - `verify`: Load a bundle, evaluate policy, print result.
//! - `collect`: Collect evidence files into a bundle.
//! - `export`: Evaluate, sign, and export a bundle.
//!
//! Exit codes: 0 = compliant, 1 = non-compliant, 2 = error.

use std::process;

use clap::{Parser, Subcommand};

use ephemeral_ml_common::receipt_signing::AttestationReceipt;
use ephemeral_ml_compliance::controls::baseline::baseline_registry;
use ephemeral_ml_compliance::controls::hipaa::hipaa_registry;
use ephemeral_ml_compliance::evidence::collector::EvidenceBundleCollector;
use ephemeral_ml_compliance::evidence::schema::validate_bundle;
use ephemeral_ml_compliance::export::json_export;
use ephemeral_ml_compliance::export::signing::{sign_bundle, verify_bundle_signature};
use ephemeral_ml_compliance::export::BundleExporter;
use ephemeral_ml_compliance::policy::profiles::profile_by_name;
use ephemeral_ml_compliance::policy::PolicyEngine;

#[derive(Parser)]
#[command(
    name = "ephemeralml-compliance",
    about = "EphemeralML compliance toolkit"
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Verify a compliance bundle against a profile.
    Verify {
        /// Path to the bundle JSON file.
        bundle: String,
        /// Compliance profile name (baseline or hipaa).
        #[arg(long, default_value = "baseline")]
        profile: String,
        /// Hex-encoded Ed25519 public key for receipt signature verification (32 bytes = 64 hex chars).
        #[arg(long)]
        public_key: String,
        /// Hex-encoded Ed25519 public key for verifying the export bundle signature (optional).
        /// If provided and the input is a SignedEvidenceBundle, its signature is verified first.
        #[arg(long)]
        bundle_public_key: Option<String>,
    },
    /// Collect evidence files into a bundle.
    Collect {
        /// Path to the CBOR-encoded receipt file.
        #[arg(long)]
        receipt: String,
        /// Path to the CBOR-encoded attestation document (optional).
        #[arg(long)]
        attestation: Option<String>,
        /// Output path for the bundle JSON.
        #[arg(long)]
        output: String,
    },
    /// Evaluate policy, sign, and export a bundle.
    Export {
        /// Path to the bundle JSON file.
        #[arg(long)]
        bundle: String,
        /// Compliance profile name (baseline or hipaa).
        #[arg(long, default_value = "baseline")]
        profile: String,
        /// Hex-encoded Ed25519 public key for receipt signature verification (32 bytes = 64 hex chars).
        #[arg(long)]
        receipt_public_key: String,
        /// Hex-encoded Ed25519 signing key for bundle signing (32 bytes = 64 hex chars).
        #[arg(long)]
        signing_key: String,
        /// Output path for the signed bundle JSON.
        #[arg(long)]
        output: String,
    },
}

fn main() {
    let cli = Cli::parse();

    let exit_code = match cli.command {
        Commands::Verify {
            bundle,
            profile,
            public_key,
            bundle_public_key,
        } => run_verify(&bundle, &profile, &public_key, bundle_public_key.as_deref()),
        Commands::Collect {
            receipt,
            attestation,
            output,
        } => run_collect(&receipt, attestation.as_deref(), &output),
        Commands::Export {
            bundle,
            profile,
            receipt_public_key,
            signing_key,
            output,
        } => run_export(
            &bundle,
            &profile,
            &receipt_public_key,
            &signing_key,
            &output,
        ),
    };

    process::exit(exit_code);
}

fn run_verify(
    bundle_path: &str,
    profile_name: &str,
    public_key_hex: &str,
    bundle_public_key_hex: Option<&str>,
) -> i32 {
    // Parse optional bundle public key for export signature verification
    let bundle_public_key = if let Some(bpk_hex) = bundle_public_key_hex {
        let bpk_bytes = match hex::decode(bpk_hex) {
            Ok(b) if b.len() == 32 => b,
            Ok(b) => {
                eprintln!("Error: bundle public key must be 32 bytes, got {}", b.len());
                return 2;
            }
            Err(e) => {
                eprintln!("Error: invalid hex for bundle public key: {}", e);
                return 2;
            }
        };
        let mut bpk_array = [0u8; 32];
        bpk_array.copy_from_slice(&bpk_bytes);
        match ed25519_dalek::VerifyingKey::from_bytes(&bpk_array) {
            Ok(pk) => Some(pk),
            Err(e) => {
                eprintln!("Error: invalid Ed25519 bundle public key: {}", e);
                return 2;
            }
        }
    } else {
        None
    };

    // Parse public key
    let pk_bytes = match hex::decode(public_key_hex) {
        Ok(b) if b.len() == 32 => b,
        Ok(b) => {
            eprintln!("Error: public key must be 32 bytes, got {}", b.len());
            return 2;
        }
        Err(e) => {
            eprintln!("Error: invalid hex for public key: {}", e);
            return 2;
        }
    };
    let mut pk_array = [0u8; 32];
    pk_array.copy_from_slice(&pk_bytes);
    let public_key = match ed25519_dalek::VerifyingKey::from_bytes(&pk_array) {
        Ok(pk) => pk,
        Err(e) => {
            eprintln!("Error: invalid Ed25519 public key: {}", e);
            return 2;
        }
    };

    // Load bundle — accept both EvidenceBundle and SignedEvidenceBundle formats (Fix 7)
    let bundle_json = match std::fs::read_to_string(bundle_path) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("Error: cannot read bundle file '{}': {}", bundle_path, e);
            return 2;
        }
    };
    let bundle: ephemeral_ml_compliance::evidence::EvidenceBundle = if let Ok(signed) =
        serde_json::from_str::<ephemeral_ml_compliance::export::SignedEvidenceBundle>(&bundle_json)
    {
        // If --bundle-public-key provided, verify the export signature before trusting the bundle
        if let Some(ref bpk) = bundle_public_key {
            match verify_bundle_signature(&signed, bpk) {
                Ok(true) => {
                    eprintln!("Bundle export signature verified.");
                }
                Ok(false) => {
                    eprintln!("Error: bundle export signature verification failed");
                    return 2;
                }
                Err(e) => {
                    eprintln!("Error: bundle export signature check failed: {}", e);
                    return 2;
                }
            }
        }
        signed.bundle
    } else {
        match serde_json::from_str(&bundle_json) {
            Ok(b) => b,
            Err(e) => {
                eprintln!("Error: cannot parse bundle JSON: {}", e);
                return 2;
            }
        }
    };

    // Validate bundle schema + hash integrity (Fix 6)
    if let Err(e) = validate_bundle(&bundle) {
        eprintln!("Error: bundle schema validation failed: {}", e);
        return 2;
    }

    // v0.1: enforce exactly one receipt per bundle (Fix 5)
    let receipt_items: Vec<_> = bundle
        .items
        .iter()
        .filter(|i| i.evidence_type == ephemeral_ml_compliance::evidence::EvidenceType::Receipt)
        .collect();

    if receipt_items.is_empty() {
        eprintln!("Error: no Receipt evidence item found in bundle");
        return 2;
    }
    if receipt_items.len() > 1 {
        eprintln!(
            "Error: v0.1 bundles must contain exactly one receipt, found {}",
            receipt_items.len()
        );
        return 2;
    }

    let receipt_item = receipt_items[0];
    let receipt: AttestationReceipt = match ephemeral_ml_common::cbor::from_slice(&receipt_item.data) {
        Ok(r) => r,
        Err(_) => match serde_json::from_slice(&receipt_item.data) {
            Ok(r) => r,
            Err(e) => {
                eprintln!("Error: cannot deserialize receipt: {}", e);
                return 2;
            }
        },
    };

    // Load profile
    let profile = match profile_by_name(profile_name) {
        Some(p) => p,
        None => {
            eprintln!(
                "Error: unknown profile '{}'. Use 'baseline' or 'hipaa'.",
                profile_name
            );
            return 2;
        }
    };

    // Evaluate
    let engine = PolicyEngine;
    let result = match engine.evaluate(&bundle, &receipt, &public_key, &profile) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("Error: policy evaluation failed: {}", e);
            return 2;
        }
    };

    // Print result
    match serde_json::to_string_pretty(&result) {
        Ok(json) => println!("{}", json),
        Err(e) => {
            eprintln!("Error: cannot serialize result: {}", e);
            return 2;
        }
    }

    if result.compliant {
        0
    } else {
        1
    }
}

fn run_collect(receipt_path: &str, attestation_path: Option<&str>, output_path: &str) -> i32 {
    let mut collector = EvidenceBundleCollector::new();

    // Add receipt
    let receipt_data = match std::fs::read(receipt_path) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("Error: cannot read receipt '{}': {}", receipt_path, e);
            return 2;
        }
    };
    let receipt_id = match collector.add_receipt(&receipt_data) {
        Ok(id) => id,
        Err(e) => {
            eprintln!("Error: cannot add receipt: {}", e);
            return 2;
        }
    };

    // Add attestation if provided
    if let Some(att_path) = attestation_path {
        let att_data = match std::fs::read(att_path) {
            Ok(d) => d,
            Err(e) => {
                eprintln!("Error: cannot read attestation '{}': {}", att_path, e);
                return 2;
            }
        };
        let att_id = match collector.add_attestation(&att_data) {
            Ok(id) => id,
            Err(e) => {
                eprintln!("Error: cannot add attestation: {}", e);
                return 2;
            }
        };
        collector.add_binding(&receipt_id, &att_id, "signing-key-attestation", None);
    }

    // Build
    let bundle = match collector.build() {
        Ok(b) => b,
        Err(e) => {
            eprintln!("Error: cannot build bundle: {}", e);
            return 2;
        }
    };

    // Write
    let json = match serde_json::to_string_pretty(&bundle) {
        Ok(j) => j,
        Err(e) => {
            eprintln!("Error: cannot serialize bundle: {}", e);
            return 2;
        }
    };
    if let Err(e) = std::fs::write(output_path, &json) {
        eprintln!("Error: cannot write '{}': {}", output_path, e);
        return 2;
    }

    eprintln!("Bundle written to {}", output_path);
    0
}

fn run_export(
    bundle_path: &str,
    profile_name: &str,
    receipt_public_key_hex: &str,
    signing_key_hex: &str,
    output_path: &str,
) -> i32 {
    // Parse receipt public key — used for receipt signature verification (SIG-001)
    let rpk_bytes = match hex::decode(receipt_public_key_hex) {
        Ok(b) if b.len() == 32 => b,
        Ok(b) => {
            eprintln!(
                "Error: receipt public key must be 32 bytes, got {}",
                b.len()
            );
            return 2;
        }
        Err(e) => {
            eprintln!("Error: invalid hex for receipt public key: {}", e);
            return 2;
        }
    };
    let mut rpk_array = [0u8; 32];
    rpk_array.copy_from_slice(&rpk_bytes);
    let receipt_public_key = match ed25519_dalek::VerifyingKey::from_bytes(&rpk_array) {
        Ok(pk) => pk,
        Err(e) => {
            eprintln!("Error: invalid Ed25519 receipt public key: {}", e);
            return 2;
        }
    };

    // Parse bundle signing key — used ONLY for signing the exported bundle
    let sk_bytes = match hex::decode(signing_key_hex) {
        Ok(b) if b.len() == 32 => b,
        Ok(b) => {
            eprintln!("Error: signing key must be 32 bytes, got {}", b.len());
            return 2;
        }
        Err(e) => {
            eprintln!("Error: invalid hex for signing key: {}", e);
            return 2;
        }
    };
    let mut sk_array = [0u8; 32];
    sk_array.copy_from_slice(&sk_bytes);
    let signing_key = ed25519_dalek::SigningKey::from_bytes(&sk_array);

    // Load bundle
    let bundle_json = match std::fs::read_to_string(bundle_path) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("Error: cannot read bundle '{}': {}", bundle_path, e);
            return 2;
        }
    };
    let bundle: ephemeral_ml_compliance::evidence::EvidenceBundle =
        match serde_json::from_str(&bundle_json) {
            Ok(b) => b,
            Err(e) => {
                eprintln!("Error: cannot parse bundle JSON: {}", e);
                return 2;
            }
        };

    // Validate bundle schema + hash integrity (Fix 6)
    if let Err(e) = validate_bundle(&bundle) {
        eprintln!("Error: bundle schema validation failed: {}", e);
        return 2;
    }

    // v0.1: enforce exactly one receipt per bundle (Fix 5)
    let receipt_items: Vec<_> = bundle
        .items
        .iter()
        .filter(|i| i.evidence_type == ephemeral_ml_compliance::evidence::EvidenceType::Receipt)
        .collect();

    if receipt_items.is_empty() {
        eprintln!("Error: no Receipt evidence item found in bundle");
        return 2;
    }
    if receipt_items.len() > 1 {
        eprintln!(
            "Error: v0.1 bundles must contain exactly one receipt, found {}",
            receipt_items.len()
        );
        return 2;
    }

    let receipt_item = receipt_items[0];
    let receipt: AttestationReceipt = match ephemeral_ml_common::cbor::from_slice(&receipt_item.data) {
        Ok(r) => r,
        Err(_) => match serde_json::from_slice(&receipt_item.data) {
            Ok(r) => r,
            Err(e) => {
                eprintln!("Error: cannot deserialize receipt: {}", e);
                return 2;
            }
        },
    };

    // Load profile
    let profile = match profile_by_name(profile_name) {
        Some(p) => p,
        None => {
            eprintln!(
                "Error: unknown profile '{}'. Use 'baseline' or 'hipaa'.",
                profile_name
            );
            return 2;
        }
    };

    // Evaluate policy using receipt's public key (Fix 1: separate from bundle signing key)
    let engine = PolicyEngine;
    let policy_result = match engine.evaluate(&bundle, &receipt, &receipt_public_key, &profile) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("Error: policy evaluation failed: {}", e);
            return 2;
        }
    };

    // Evaluate controls
    let control_results = match profile_name {
        "hipaa" => {
            let registry = hipaa_registry();
            registry.evaluate(&policy_result)
        }
        _ => {
            let registry = baseline_registry();
            registry.evaluate(&policy_result)
        }
    };

    // Export
    let exporter = BundleExporter::new(bundle, policy_result.clone(), control_results);
    let mut signed_bundle = match exporter.export() {
        Ok(b) => b,
        Err(e) => {
            eprintln!("Error: export failed: {}", e);
            return 2;
        }
    };

    // Sign bundle with the bundle signing key (separate from receipt key)
    if let Err(e) = sign_bundle(&mut signed_bundle, &signing_key) {
        eprintln!("Error: signing failed: {}", e);
        return 2;
    }

    // Write
    let output_json = match json_export::to_json(&signed_bundle) {
        Ok(j) => j,
        Err(e) => {
            eprintln!("Error: cannot serialize signed bundle: {}", e);
            return 2;
        }
    };
    if let Err(e) = std::fs::write(output_path, &output_json) {
        eprintln!("Error: cannot write '{}': {}", output_path, e);
        return 2;
    }

    eprintln!("Signed bundle written to {}", output_path);

    if policy_result.compliant {
        0
    } else {
        1
    }
}
