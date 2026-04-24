/// Shared metadata for a verification check shown in CLI and web surfaces.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VerificationCheckMeta {
    pub label: &'static str,
    pub layer: Option<&'static str>,
}

/// Canonical metadata for legacy receipt verification checks.
pub fn legacy_check_meta(id: &str) -> Option<VerificationCheckMeta> {
    let meta = match id {
        "signature" => VerificationCheckMeta {
            label: "Signature (Ed25519)",
            layer: Some("crypto"),
        },
        "model_match" => VerificationCheckMeta {
            label: "Model ID match",
            layer: Some("policy"),
        },
        "measurement_type" => VerificationCheckMeta {
            label: "Measurement type",
            layer: Some("policy"),
        },
        "timestamp_fresh" => VerificationCheckMeta {
            label: "Timestamp freshness",
            layer: Some("policy"),
        },
        "measurements_present" => VerificationCheckMeta {
            label: "Measurements present",
            layer: Some("claim"),
        },
        "attestation_source" => VerificationCheckMeta {
            label: "Attestation source",
            layer: Some("policy"),
        },
        "image_digest" => VerificationCheckMeta {
            label: "Image digest",
            layer: Some("policy"),
        },
        "destroy_evidence" => VerificationCheckMeta {
            label: "Destroy evidence",
            layer: Some("policy"),
        },
        _ => return None,
    };
    Some(meta)
}

/// Canonical metadata for AIR v1 verification checks.
pub fn air_check_meta(name: &str) -> VerificationCheckMeta {
    match name {
        "SIZE" => VerificationCheckMeta {
            label: "Receipt size limit",
            layer: Some("parse"),
        },
        "COSE_DECODE" => VerificationCheckMeta {
            label: "COSE envelope",
            layer: Some("parse"),
        },
        "ALG" => VerificationCheckMeta {
            label: "Algorithm header",
            layer: Some("parse"),
        },
        "CONTENT_TYPE" => VerificationCheckMeta {
            label: "Content type",
            layer: Some("parse"),
        },
        "PAYLOAD" => VerificationCheckMeta {
            label: "Payload present",
            layer: Some("parse"),
        },
        "CLAIMS_DECODE" => VerificationCheckMeta {
            label: "Claims structure",
            layer: Some("parse"),
        },
        "EAT_PROFILE" => VerificationCheckMeta {
            label: "AIR v1 profile",
            layer: Some("parse"),
        },
        "SIG" => VerificationCheckMeta {
            label: "Signature (Ed25519)",
            layer: Some("crypto"),
        },
        "CTI" => VerificationCheckMeta {
            label: "Receipt ID valid",
            layer: Some("claim"),
        },
        "MHASH_PRESENT" => VerificationCheckMeta {
            label: "Model hash non-zero",
            layer: Some("claim"),
        },
        "MEAS" => VerificationCheckMeta {
            label: "Measurements present",
            layer: Some("claim"),
        },
        "MTYPE" => VerificationCheckMeta {
            label: "Measurement type valid",
            layer: Some("claim"),
        },
        "MHASH_SCHEME" => VerificationCheckMeta {
            label: "Model hash scheme",
            layer: Some("claim"),
        },
        "SECURITY_MODE" => VerificationCheckMeta {
            label: "Security mode valid",
            layer: Some("claim"),
        },
        "FRESH" => VerificationCheckMeta {
            label: "Timestamp freshness",
            layer: Some("policy"),
        },
        "MHASH" => VerificationCheckMeta {
            label: "Model hash match",
            layer: Some("policy"),
        },
        "RHASH" => VerificationCheckMeta {
            label: "Request hash match",
            layer: Some("policy"),
        },
        "OHASH" => VerificationCheckMeta {
            label: "Response hash match",
            layer: Some("policy"),
        },
        "MODEL" => VerificationCheckMeta {
            label: "Model ID match",
            layer: Some("policy"),
        },
        "SECURITY_MODE_POLICY" => VerificationCheckMeta {
            label: "Security mode policy",
            layer: Some("policy"),
        },
        "PLATFORM" => VerificationCheckMeta {
            label: "Platform match",
            layer: Some("policy"),
        },
        "NONCE" => VerificationCheckMeta {
            label: "Nonce match",
            layer: Some("policy"),
        },
        "REPLAY" => VerificationCheckMeta {
            label: "Replay detection",
            layer: Some("policy"),
        },
        _ if name.starts_with("CLAIM_") => VerificationCheckMeta {
            label: "Required claim present",
            layer: Some("claim"),
        },
        _ if name.starts_with("HASH_") => VerificationCheckMeta {
            label: "Hash field valid",
            layer: Some("claim"),
        },
        _ => VerificationCheckMeta {
            label: "Verification check",
            layer: Some("policy"),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn legacy_check_metadata_is_stable() {
        let meta = legacy_check_meta("signature").unwrap();
        assert_eq!(meta.label, "Signature (Ed25519)");
        assert_eq!(meta.layer, Some("crypto"));
    }

    #[test]
    fn legacy_destroy_evidence_metadata_exists() {
        let meta = legacy_check_meta("destroy_evidence").unwrap();
        assert_eq!(meta.label, "Destroy evidence");
        assert_eq!(meta.layer, Some("policy"));
    }

    #[test]
    fn air_check_metadata_is_human_readable() {
        let meta = air_check_meta("COSE_DECODE");
        assert_eq!(meta.label, "COSE envelope");
        assert_eq!(meta.layer, Some("parse"));
    }

    #[test]
    fn air_claim_prefix_uses_shared_metadata() {
        let meta = air_check_meta("CLAIM_MODEL_HASH");
        assert_eq!(meta.label, "Required claim present");
        assert_eq!(meta.layer, Some("claim"));
    }

    #[test]
    fn unknown_air_check_falls_back_to_generic_metadata() {
        let meta = air_check_meta("SOMETHING_NEW");
        assert_eq!(meta.label, "Verification check");
        assert_eq!(meta.layer, Some("policy"));
    }
}
