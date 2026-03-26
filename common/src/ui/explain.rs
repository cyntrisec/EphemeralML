use crate::receipt_verify::CheckStatus;

/// Explanation for a failed verification check.
pub struct CheckExplanation {
    pub why: &'static str,
    pub fix: &'static str,
}

/// Return an explanation for a legacy check if it failed.
///
/// Returns `None` for `Pass` and `Skip` statuses — only `Fail` gets an explanation.
pub fn explain_check(name: &str, status: &CheckStatus) -> Option<CheckExplanation> {
    if !matches!(status, CheckStatus::Fail) {
        return None;
    }
    explain_by_name(name)
}

/// Return an explanation for any check name (AIR v1 or legacy) if it failed.
///
/// The `failed` flag should be true only for checks with Fail status.
pub fn explain_failed(name: &str, failed: bool) -> Option<CheckExplanation> {
    if !failed {
        return None;
    }
    explain_by_name(name)
}

/// Shared explanation lookup covering both legacy and AIR v1 check names.
fn explain_by_name(name: &str) -> Option<CheckExplanation> {
    let explanation = match name {
        // ── Legacy check names ──────────────────────────────────────
        "signature" => CheckExplanation {
            why: "The Ed25519 signature does not match the provided public key.",
            fix: "Verify you are using the correct public key (--public-key or --public-key-file).",
        },
        "model_match" => CheckExplanation {
            why: "The receipt's model_id does not match the expected model.",
            fix: "Check that --expected-model matches the model ID in the receipt.",
        },
        "measurement_type" => CheckExplanation {
            why: "The receipt's measurement type does not match the expected platform.",
            fix: "Check --measurement-type (e.g. nitro-pcr, tdx-mrtd-rtmr, or any).",
        },
        "timestamp_fresh" => CheckExplanation {
            why: "The receipt timestamp is either too old or in the future.",
            fix: "Increase --max-age or set to 0 to skip. Check system clock sync.",
        },
        "measurements_present" => CheckExplanation {
            why: "The enclave measurement fields are missing or the wrong length (expected 48 bytes / SHA-384).",
            fix: "This usually indicates a mock receipt or a corrupted receipt file.",
        },
        "attestation_source" => CheckExplanation {
            why: "The receipt's attestation_source does not match the expected value.",
            fix: "Check --expected-attestation-source (e.g. cs-tdx, tdx, nitro).",
        },
        "image_digest" => CheckExplanation {
            why: "The container image digest in the receipt does not match the expected value.",
            fix: "Check --expected-image-digest matches the deployed container digest.",
        },
        "destroy_evidence" => CheckExplanation {
            why: "The receipt is missing destroy evidence or does not list any recorded destroy actions.",
            fix: "Re-run with receipt generation that records cleanup actions, or omit --require-destroy-event to skip this policy check.",
        },

        // ── AIR v1 check names (Layer 1: Parse) ────────────────────
        "SIZE" => CheckExplanation {
            why: "The receipt exceeds the maximum allowed size (64 KB).",
            fix: "Check for padding or unexpected data appended to the receipt file.",
        },
        "COSE_DECODE" => CheckExplanation {
            why: "The receipt is not a valid COSE_Sign1 envelope.",
            fix: "Ensure the file is a valid CBOR-encoded COSE_Sign1 with tag 18.",
        },
        "ALG" => CheckExplanation {
            why: "The COSE protected header is missing or has the wrong algorithm (expected EdDSA).",
            fix: "The receipt must be signed with EdDSA (Ed25519). Check the signing implementation.",
        },
        "CONTENT_TYPE" => CheckExplanation {
            why: "The COSE protected header has the wrong or missing content type (expected CWT).",
            fix: "The receipt payload must be tagged as CWT (CBOR Web Token).",
        },
        "PAYLOAD" => CheckExplanation {
            why: "The COSE_Sign1 envelope has no payload or the payload is empty.",
            fix: "The receipt must contain a non-empty CWT payload with AIR v1 claims.",
        },
        "CLAIMS_DECODE" => CheckExplanation {
            why: "The receipt payload could not be decoded as a valid CBOR claims map.",
            fix: "The payload must be a valid CBOR map with integer keys per the AIR v1 spec.",
        },
        "EAT_PROFILE" => CheckExplanation {
            why: "The eat_profile claim does not match the AIR v1 profile URI.",
            fix: "The receipt must include eat_profile matching the expected AIR v1 identifier.",
        },

        // ── AIR v1 check names (Layer 2: Crypto) ───────────────────
        "SIG" => CheckExplanation {
            why: "The Ed25519 signature does not match the provided public key.",
            fix: "Verify you are using the correct public key for this receipt.",
        },

        // ── AIR v1 check names (Layer 3: Claim validation) ─────────
        "CTI" => CheckExplanation {
            why: "The receipt ID (cti) is invalid — wrong length or all zeros.",
            fix: "The receipt must contain a valid 16-byte UUID v4 as the cti claim.",
        },
        "MHASH_PRESENT" => CheckExplanation {
            why: "The model_hash claim is all zeros.",
            fix: "The signing workload must compute and include a non-zero SHA-256 model hash.",
        },
        "MEAS" => CheckExplanation {
            why: "The enclave measurements are missing or the wrong length (expected 48 bytes each).",
            fix: "This indicates a corrupted receipt or a mock workload that did not produce real measurements.",
        },
        "MTYPE" => CheckExplanation {
            why: "The measurement_type is not a recognized value.",
            fix: "Expected values: nitro-pcr or tdx-mrtd-rtmr.",
        },
        "MHASH_SCHEME" => CheckExplanation {
            why: "The model_hash_scheme value is not in the allowed set.",
            fix: "Allowed values: sha256-single, sha256-concat, sha256-manifest.",
        },

        // ── AIR v1 check names (Layer 4: Policy) ───────────────────
        "FRESH" => CheckExplanation {
            why: "The receipt timestamp is stale or in the future.",
            fix: "CLI: increase --max-age or set to 0 to skip. API: increase max_age_secs. Check system clock sync.",
        },
        "MHASH" => CheckExplanation {
            why: "The model_hash in the receipt does not match the expected value.",
            fix: "This check is enforced via policy when an expected model hash is configured.",
        },
        "MODEL" => CheckExplanation {
            why: "The model_id in the receipt does not match the expected value.",
            fix: "CLI: check --expected-model. API: check expected_model in the request.",
        },
        "PLATFORM" => CheckExplanation {
            why: "The measurement_type does not match the expected platform.",
            fix: "CLI: check --measurement-type (e.g. nitro-pcr, tdx-mrtd-rtmr, or any). API: check measurement_type in the request.",
        },
        "NONCE" => CheckExplanation {
            why: "The eat_nonce in the receipt does not match the expected challenge nonce.",
            fix: "Verify the nonce you provided at request time matches.",
        },
        "REPLAY" => CheckExplanation {
            why: "This receipt ID (cti) has been seen before — possible replay.",
            fix: "Each receipt should have a unique cti. Check for duplicate submissions.",
        },

        _ => return None,
    };

    Some(explanation)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pass_returns_none() {
        assert!(explain_check("signature", &CheckStatus::Pass).is_none());
    }

    #[test]
    fn skip_returns_none() {
        assert!(explain_check("model_match", &CheckStatus::Skip).is_none());
    }

    #[test]
    fn fail_returns_explanation() {
        let exp = explain_check("signature", &CheckStatus::Fail).unwrap();
        assert!(!exp.why.is_empty());
        assert!(!exp.fix.is_empty());
    }

    #[test]
    fn all_legacy_checks_covered() {
        let names = [
            "signature",
            "model_match",
            "measurement_type",
            "timestamp_fresh",
            "measurements_present",
            "attestation_source",
            "image_digest",
            "destroy_evidence",
        ];
        for name in &names {
            let exp = explain_check(name, &CheckStatus::Fail);
            assert!(exp.is_some(), "Missing explanation for check: {}", name);
        }
    }

    #[test]
    fn all_air_v1_checks_covered() {
        let names = [
            "SIZE",
            "COSE_DECODE",
            "ALG",
            "CONTENT_TYPE",
            "PAYLOAD",
            "CLAIMS_DECODE",
            "EAT_PROFILE",
            "SIG",
            "CTI",
            "MHASH_PRESENT",
            "MEAS",
            "MTYPE",
            "MHASH_SCHEME",
            "FRESH",
            "MHASH",
            "MODEL",
            "PLATFORM",
            "NONCE",
            "REPLAY",
        ];
        for name in &names {
            let exp = explain_failed(name, true);
            assert!(exp.is_some(), "Missing explanation for AIR check: {}", name);
        }
    }

    #[test]
    fn explain_failed_respects_flag() {
        assert!(explain_failed("SIG", true).is_some());
        assert!(explain_failed("SIG", false).is_none());
    }

    #[test]
    fn unknown_check_returns_none() {
        assert!(explain_check("nonexistent", &CheckStatus::Fail).is_none());
        assert!(explain_failed("nonexistent", true).is_none());
    }
}
