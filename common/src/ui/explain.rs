use crate::receipt_verify::CheckStatus;

/// Explanation for a failed verification check.
pub struct CheckExplanation {
    pub why: &'static str,
    pub fix: &'static str,
}

/// Return an explanation for a check if it failed.
///
/// Returns `None` for `Pass` and `Skip` statuses — only `Fail` gets an explanation.
pub fn explain_check(name: &str, status: &CheckStatus) -> Option<CheckExplanation> {
    if !matches!(status, CheckStatus::Fail) {
        return None;
    }

    let explanation = match name {
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
    fn all_seven_checks_covered() {
        let names = [
            "signature",
            "model_match",
            "measurement_type",
            "timestamp_fresh",
            "measurements_present",
            "attestation_source",
            "image_digest",
        ];
        for name in &names {
            let exp = explain_check(name, &CheckStatus::Fail);
            assert!(exp.is_some(), "Missing explanation for check: {}", name);
        }
    }

    #[test]
    fn unknown_check_returns_none() {
        assert!(explain_check("nonexistent", &CheckStatus::Fail).is_none());
    }
}
