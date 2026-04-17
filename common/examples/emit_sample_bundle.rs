//! Emit a sample PlatformEvidenceBundle + its hash + binding inputs.
//! Used to smoke-test verify_platform_evidence locally before running against
//! real GCP enclave artifacts.

use ephemeral_ml_common::{
    CloudEvidenceSummary, CpuEvidenceSummary, EvidenceBinding, EvidenceVerifierSummary,
    MeasurementEntry, PlatformEvidenceBundle, PLATFORM_EVIDENCE_V1,
};
use std::fs;

fn main() {
    let bundle = PlatformEvidenceBundle {
        version: PLATFORM_EVIDENCE_V1,
        platform_profile: "gcp-cs-tdx".to_string(),
        generated_at: 1_744_500_000,
        binding: EvidenceBinding {
            receipt_signing_key: [0x11; 32],
            hpke_public_key: Some([0x22; 32]),
            model_id: "minilm".to_string(),
            model_hash: Some([0x33; 32]),
            base_attestation_hash: [0x44; 32],
        },
        cpu: Some(CpuEvidenceSummary {
            tee_type: "tdx".to_string(),
            measurement_type: "tdx-mrtd-rtmr".to_string(),
            measurements: vec![MeasurementEntry {
                index: 0,
                value: vec![0xAA; 48],
            }],
        }),
        gpu: None,
        cloud: Some(CloudEvidenceSummary {
            attestation_source: "cs-tdx".to_string(),
            launcher_jwt_sha256: None,
            image_digest: None,
            project_id: None,
            zone: None,
        }),
        verifier: EvidenceVerifierSummary {
            cpu_verifier: "cml-transport-tdx".to_string(),
            gpu_verifier: None,
            policy_version: "v1-default".to_string(),
        },
    };

    let bytes = bundle.to_cbor_deterministic().expect("encode");
    let hash = bundle.document_hash().expect("hash");

    let path = "/tmp/sample-platform-evidence.cbor";
    fs::write(path, &bytes).expect("write");

    println!("bundle_path={}", path);
    println!("bundle_bytes={}", bytes.len());
    println!("hash={}", hex::encode(hash));
    println!(
        "receipt_signing_key={}",
        hex::encode(bundle.binding.receipt_signing_key)
    );
    println!(
        "base_attestation_hash={}",
        hex::encode(bundle.binding.base_attestation_hash)
    );
}
