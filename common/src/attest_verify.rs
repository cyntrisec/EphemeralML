//! Attestation trust chain verification — structured error codes (M2)
//!
//! Four trust layers, parallel to the AIR v1 receipt verifier:
//!
//! 1. **T1_PARSE** — evidence shape/parsing (quote structure, version, fields)
//! 2. **T2_CRYPTO** — signatures over evidence (ECDSA, RSA, COSE)
//! 3. **T3_CHAIN** — cert chain, collateral, trust anchors, freshness, revocation
//! 4. **T4_POLICY** — measurements, audience, nonce, TCB acceptance level
//!
//! Separate from `AirCheckCode` (receipt format) — these codes cover
//! platform attestation verification.
//!
//! See `spec/internal/m2-trust-matrix.md` for the full test matrix.

use serde::{Deserialize, Serialize};

// ── Attestation failure codes ────────────────────────────────────────

/// Structured failure code for attestation trust verification.
///
/// Codes are stable identifiers for the M2 trust matrix.
/// Naming: `{PLATFORM}_{LAYER_HINT}_{FAILURE}`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum AttestCheckCode {
    // ── TDX DCAP: T1_PARSE ──────────────────────────────────────
    /// TDX quote bytes could not be parsed
    TdxQuoteParseFailed,
    /// TDX quote version or type is unsupported
    TdxQuoteUnsupportedFormat,

    // ── TDX DCAP: T2_CRYPTO ─────────────────────────────────────
    /// TDX quote ECDSA signature verification failed
    TdxQuoteSigInvalid,
    /// REPORTDATA does not match expected public key binding
    TdxReportdataBindingMismatch,

    // ── TDX DCAP: T3_CHAIN ──────────────────────────────────────
    /// DCAP collateral bundle missing (no TCB/QE/PCK)
    TdxCollateralMissing,
    /// DCAP collateral expired (nextUpdate passed)
    TdxCollateralStale,
    /// PCK certificate chain invalid (wrong issuer/root)
    TdxPckChainInvalid,
    /// QE identity signature verification failed
    TdxQeIdentityInvalid,
    /// TCB info signature verification failed
    TdxTcbInfoInvalid,
    /// FMSPC mismatch between quote and collateral
    TdxFmspcMismatch,
    /// PCK certificate revoked during validity window
    TdxPckRevoked,

    // ── TDX DCAP: T4_POLICY ─────────────────────────────────────
    /// TCB status unacceptable under current policy (OutOfDate, ConfigurationNeeded)
    TdxTcbStatusUnacceptable,
    /// TCB status is Revoked (always fail)
    TdxTcbRevoked,
    /// MRTD measurement does not match pinned value
    TdxMrtdMismatch,
    /// RTMR measurement does not match pinned value
    TdxRtmrMismatch,
    /// Nonce in quote does not match expected session nonce
    TdxNonceMismatch,
    /// Collateral not yet valid or clock skew issue
    TdxCollateralTimeInvalid,

    // ── GCP Confidential Space JWT: T2_CRYPTO ───────────────────
    /// JWT RS256 signature verification failed
    CsjwtSigInvalid,

    // ── GCP Confidential Space JWT: T3_CHAIN ────────────────────
    /// kid from JWT header not found in JWKS
    CsjwtKidNotFound,
    /// JWKS key type or algorithm mismatch
    CsjwtJwksKeyInvalid,

    // ── GCP Confidential Space JWT: T4_POLICY ───────────────────
    /// aud claim missing when audience pinning required
    CsjwtAudMissing,
    /// aud claim does not match expected audience
    CsjwtAudMismatch,
    /// iss claim does not match expected issuer
    CsjwtIssMismatch,
    /// JWT exp claim indicates token is expired
    CsjwtExpired,
    /// JWT nbf/iat indicates token is not yet valid
    CsjwtTimeInvalid,
    /// Nonce in JWT does not match expected session nonce
    CsjwtNonceMismatch,
    /// Enclave-side unverified stub path active in production mode
    CsjwtUnverifiedStubForbidden,

    // ── AWS Nitro: T2_CRYPTO ────────────────────────────────────
    /// COSE attestation document signature invalid
    NitroDocSigInvalid,

    // ── AWS Nitro: T3_CHAIN ─────────────────────────────────────
    /// Certificate chain invalid or root pin mismatch
    NitroCertChainInvalid,
    /// Certificate expired or not yet valid
    NitroCertTimeInvalid,
    /// Certificate revoked (CRL/OCSP check)
    NitroCertRevoked,

    // ── AWS Nitro: T4_POLICY ────────────────────────────────────
    /// PCR measurement mismatch (pcr0/pcr1/pcr2/pcr8)
    NitroMeasurementMismatch,
    /// Public key in attestation doc does not match receipt signing key
    NitroPubkeyBindingMismatch,
    /// Nonce mismatch
    NitroNonceMismatch,

    // ── Cross-cutting policy ────────────────────────────────────
    /// Measurement pinning disabled in strict mode
    PolicyMeasurementPinningDisabled,
    /// Audience pinning required but not configured
    PolicyAudiencePinRequired,
    /// Trust anchor not available
    TrustAnchorMissing,
    /// Revocation checking required but unavailable
    RevocationCheckUnavailable,
}

impl std::fmt::Display for AttestCheckCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            // TDX
            Self::TdxQuoteParseFailed => write!(f, "TDX_QUOTE_PARSE_FAILED"),
            Self::TdxQuoteUnsupportedFormat => write!(f, "TDX_QUOTE_UNSUPPORTED_FORMAT"),
            Self::TdxQuoteSigInvalid => write!(f, "TDX_QUOTE_SIG_INVALID"),
            Self::TdxReportdataBindingMismatch => write!(f, "TDX_REPORTDATA_BINDING_MISMATCH"),
            Self::TdxCollateralMissing => write!(f, "TDX_COLLATERAL_MISSING"),
            Self::TdxCollateralStale => write!(f, "TDX_COLLATERAL_STALE"),
            Self::TdxPckChainInvalid => write!(f, "TDX_PCK_CHAIN_INVALID"),
            Self::TdxQeIdentityInvalid => write!(f, "TDX_QE_IDENTITY_INVALID"),
            Self::TdxTcbInfoInvalid => write!(f, "TDX_TCB_INFO_INVALID"),
            Self::TdxFmspcMismatch => write!(f, "TDX_FMSPC_MISMATCH"),
            Self::TdxPckRevoked => write!(f, "TDX_PCK_REVOKED"),
            Self::TdxTcbStatusUnacceptable => write!(f, "TDX_TCB_STATUS_UNACCEPTABLE"),
            Self::TdxTcbRevoked => write!(f, "TDX_TCB_REVOKED"),
            Self::TdxMrtdMismatch => write!(f, "TDX_MRTD_MISMATCH"),
            Self::TdxRtmrMismatch => write!(f, "TDX_RTMR_MISMATCH"),
            Self::TdxNonceMismatch => write!(f, "TDX_NONCE_MISMATCH"),
            Self::TdxCollateralTimeInvalid => write!(f, "TDX_COLLATERAL_TIME_INVALID"),
            // CS JWT
            Self::CsjwtSigInvalid => write!(f, "CSJWT_SIG_INVALID"),
            Self::CsjwtKidNotFound => write!(f, "CSJWT_KID_NOT_FOUND"),
            Self::CsjwtJwksKeyInvalid => write!(f, "CSJWT_JWKS_KEY_INVALID"),
            Self::CsjwtAudMissing => write!(f, "CSJWT_AUD_MISSING"),
            Self::CsjwtAudMismatch => write!(f, "CSJWT_AUD_MISMATCH"),
            Self::CsjwtIssMismatch => write!(f, "CSJWT_ISS_MISMATCH"),
            Self::CsjwtExpired => write!(f, "CSJWT_EXPIRED"),
            Self::CsjwtTimeInvalid => write!(f, "CSJWT_TIME_INVALID"),
            Self::CsjwtNonceMismatch => write!(f, "CSJWT_NONCE_MISMATCH"),
            Self::CsjwtUnverifiedStubForbidden => write!(f, "CSJWT_UNVERIFIED_STUB_FORBIDDEN"),
            // Nitro
            Self::NitroDocSigInvalid => write!(f, "NITRO_DOC_SIG_INVALID"),
            Self::NitroCertChainInvalid => write!(f, "NITRO_CERT_CHAIN_INVALID"),
            Self::NitroCertTimeInvalid => write!(f, "NITRO_CERT_TIME_INVALID"),
            Self::NitroCertRevoked => write!(f, "NITRO_CERT_REVOKED"),
            Self::NitroMeasurementMismatch => write!(f, "NITRO_MEASUREMENT_MISMATCH"),
            Self::NitroPubkeyBindingMismatch => write!(f, "NITRO_PUBKEY_BINDING_MISMATCH"),
            Self::NitroNonceMismatch => write!(f, "NITRO_NONCE_MISMATCH"),
            // Cross-cutting
            Self::PolicyMeasurementPinningDisabled => {
                write!(f, "POLICY_MEASUREMENT_PINNING_DISABLED")
            }
            Self::PolicyAudiencePinRequired => write!(f, "POLICY_AUDIENCE_PIN_REQUIRED"),
            Self::TrustAnchorMissing => write!(f, "TRUST_ANCHOR_MISSING"),
            Self::RevocationCheckUnavailable => write!(f, "REVOCATION_CHECK_UNAVAILABLE"),
        }
    }
}

// ── Warning codes (non-fatal) ────────────────────────────────────────

/// Non-fatal warning codes for dangerous-but-configured states.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum VerifyWarningCode {
    /// Measurement pinning bypassed in dev mode
    MeasurementPinningBypassed,
    /// Revocation checking not performed (optional mode)
    RevocationUnchecked,
    /// Audience pinning not configured (optional mode)
    AudiencePinningSkipped,
}

impl std::fmt::Display for VerifyWarningCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MeasurementPinningBypassed => write!(f, "WARN_MEASUREMENT_PINNING_BYPASSED"),
            Self::RevocationUnchecked => write!(f, "WARN_REVOCATION_UNCHECKED"),
            Self::AudiencePinningSkipped => write!(f, "WARN_AUDIENCE_PINNING_SKIPPED"),
        }
    }
}

// ── Check result ─────────────────────────────────────────────────────

/// Outcome of a single attestation verification check.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum AttestCheckStatus {
    Pass,
    Fail,
    Skip,
}

impl std::fmt::Display for AttestCheckStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Pass => write!(f, "PASS"),
            Self::Fail => write!(f, "FAIL"),
            Self::Skip => write!(f, "SKIP"),
        }
    }
}

/// A single named attestation check with its outcome.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttestCheck {
    /// Check name (e.g., "TDX_QUOTE_SIG", "CS_JWT_AUD")
    pub name: &'static str,
    /// Trust layer: "T1_PARSE", "T2_CRYPTO", "T3_CHAIN", "T4_POLICY"
    pub layer: &'static str,
    pub status: AttestCheckStatus,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub code: Option<AttestCheckCode>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

impl AttestCheck {
    pub fn pass(name: &'static str, layer: &'static str) -> Self {
        Self {
            name,
            layer,
            status: AttestCheckStatus::Pass,
            code: None,
            detail: None,
        }
    }

    pub fn fail(
        name: &'static str,
        layer: &'static str,
        code: AttestCheckCode,
        detail: impl Into<String>,
    ) -> Self {
        Self {
            name,
            layer,
            status: AttestCheckStatus::Fail,
            code: Some(code),
            detail: Some(detail.into()),
        }
    }

    pub fn skip(name: &'static str, layer: &'static str) -> Self {
        Self {
            name,
            layer,
            status: AttestCheckStatus::Skip,
            code: None,
            detail: None,
        }
    }
}

// ── Full attestation verification result ─────────────────────────────

/// Complete attestation verification result across all trust layers.
#[derive(Debug, Clone, Serialize)]
pub struct AttestVerifyResult {
    /// Overall verdict: true only if all non-skipped checks pass.
    pub verified: bool,
    /// Platform identifier: "tdx-dcap", "nitro-nsm", "cs-jwt"
    pub platform: String,
    /// Individual check outcomes, ordered by layer.
    pub checks: Vec<AttestCheck>,
    /// Non-fatal warnings.
    pub warnings: Vec<VerifyWarningCode>,
}

impl AttestVerifyResult {
    /// Get all failure codes.
    pub fn failures(&self) -> Vec<&AttestCheckCode> {
        self.checks.iter().filter_map(|c| c.code.as_ref()).collect()
    }

    /// Check if a specific failure code is present.
    pub fn has_failure(&self, code: &AttestCheckCode) -> bool {
        self.checks.iter().any(|c| c.code.as_ref() == Some(code))
    }

    /// Check if a specific warning is present.
    pub fn has_warning(&self, code: &VerifyWarningCode) -> bool {
        self.warnings.contains(code)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_attest_check_code_display() {
        assert_eq!(
            AttestCheckCode::TdxQuoteParseFailed.to_string(),
            "TDX_QUOTE_PARSE_FAILED"
        );
        assert_eq!(
            AttestCheckCode::CsjwtSigInvalid.to_string(),
            "CSJWT_SIG_INVALID"
        );
        assert_eq!(
            AttestCheckCode::NitroDocSigInvalid.to_string(),
            "NITRO_DOC_SIG_INVALID"
        );
        assert_eq!(
            AttestCheckCode::PolicyMeasurementPinningDisabled.to_string(),
            "POLICY_MEASUREMENT_PINNING_DISABLED"
        );
    }

    #[test]
    fn test_warning_code_display() {
        assert_eq!(
            VerifyWarningCode::MeasurementPinningBypassed.to_string(),
            "WARN_MEASUREMENT_PINNING_BYPASSED"
        );
        assert_eq!(
            VerifyWarningCode::RevocationUnchecked.to_string(),
            "WARN_REVOCATION_UNCHECKED"
        );
    }

    #[test]
    fn test_attest_check_constructors() {
        let pass = AttestCheck::pass("TDX_QUOTE_SIG", "T2_CRYPTO");
        assert_eq!(pass.status, AttestCheckStatus::Pass);
        assert!(pass.code.is_none());

        let fail = AttestCheck::fail(
            "TDX_QUOTE_SIG",
            "T2_CRYPTO",
            AttestCheckCode::TdxQuoteSigInvalid,
            "ECDSA P256 verification failed",
        );
        assert_eq!(fail.status, AttestCheckStatus::Fail);
        assert_eq!(fail.code, Some(AttestCheckCode::TdxQuoteSigInvalid));

        let skip = AttestCheck::skip("TDX_COLLATERAL", "T3_CHAIN");
        assert_eq!(skip.status, AttestCheckStatus::Skip);
    }

    #[test]
    fn test_attest_verify_result() {
        let result = AttestVerifyResult {
            verified: false,
            platform: "tdx-dcap".to_string(),
            checks: vec![
                AttestCheck::pass("TDX_QUOTE_PARSE", "T1_PARSE"),
                AttestCheck::fail(
                    "TDX_QUOTE_SIG",
                    "T2_CRYPTO",
                    AttestCheckCode::TdxQuoteSigInvalid,
                    "signature mismatch",
                ),
                AttestCheck::skip("TDX_COLLATERAL", "T3_CHAIN"),
            ],
            warnings: vec![VerifyWarningCode::RevocationUnchecked],
        };

        assert!(!result.verified);
        assert!(result.has_failure(&AttestCheckCode::TdxQuoteSigInvalid));
        assert!(!result.has_failure(&AttestCheckCode::TdxMrtdMismatch));
        assert!(result.has_warning(&VerifyWarningCode::RevocationUnchecked));
        assert_eq!(result.failures().len(), 1);
    }

    #[test]
    fn test_all_codes_serializable() {
        // Ensure all codes survive JSON roundtrip
        let codes = vec![
            AttestCheckCode::TdxQuoteParseFailed,
            AttestCheckCode::TdxQuoteSigInvalid,
            AttestCheckCode::TdxCollateralMissing,
            AttestCheckCode::TdxTcbRevoked,
            AttestCheckCode::CsjwtSigInvalid,
            AttestCheckCode::CsjwtAudMismatch,
            AttestCheckCode::NitroDocSigInvalid,
            AttestCheckCode::NitroCertRevoked,
            AttestCheckCode::PolicyMeasurementPinningDisabled,
            AttestCheckCode::TrustAnchorMissing,
        ];
        for code in &codes {
            let json = serde_json::to_string(code).unwrap();
            let back: AttestCheckCode = serde_json::from_str(&json).unwrap();
            assert_eq!(*code, back);
        }
    }
}
