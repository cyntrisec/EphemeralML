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

impl AttestCheckCode {
    /// Parse a code string (e.g., `"TDX_QUOTE_PARSE_FAILED"`) into the typed enum.
    ///
    /// This is the primary bridge between `confidential-ml-transport`'s
    /// `TdxVerifyError::code()` strings and EphemeralML's structured codes.
    /// Using stable strings avoids a direct type dependency on the transport
    /// crate's TDX feature flag.
    pub fn from_code_str(code: &str) -> Option<Self> {
        match code {
            // TDX DCAP
            "TDX_QUOTE_PARSE_FAILED" => Some(Self::TdxQuoteParseFailed),
            "TDX_QUOTE_UNSUPPORTED_FORMAT" => Some(Self::TdxQuoteUnsupportedFormat),
            "TDX_QUOTE_SIG_INVALID" => Some(Self::TdxQuoteSigInvalid),
            "TDX_REPORTDATA_BINDING_MISMATCH" => Some(Self::TdxReportdataBindingMismatch),
            "TDX_COLLATERAL_MISSING" => Some(Self::TdxCollateralMissing),
            "TDX_COLLATERAL_STALE" => Some(Self::TdxCollateralStale),
            "TDX_PCK_CHAIN_INVALID" => Some(Self::TdxPckChainInvalid),
            "TDX_QE_IDENTITY_INVALID" => Some(Self::TdxQeIdentityInvalid),
            "TDX_TCB_INFO_INVALID" => Some(Self::TdxTcbInfoInvalid),
            "TDX_FMSPC_MISMATCH" => Some(Self::TdxFmspcMismatch),
            "TDX_PCK_REVOKED" => Some(Self::TdxPckRevoked),
            "TDX_TCB_STATUS_UNACCEPTABLE" => Some(Self::TdxTcbStatusUnacceptable),
            "TDX_TCB_REVOKED" => Some(Self::TdxTcbRevoked),
            "TDX_MRTD_MISMATCH" => Some(Self::TdxMrtdMismatch),
            "TDX_RTMR_MISMATCH" => Some(Self::TdxRtmrMismatch),
            "TDX_NONCE_MISMATCH" => Some(Self::TdxNonceMismatch),
            "TDX_COLLATERAL_TIME_INVALID" => Some(Self::TdxCollateralTimeInvalid),
            // CS JWT
            "CSJWT_SIG_INVALID" => Some(Self::CsjwtSigInvalid),
            "CSJWT_KID_NOT_FOUND" => Some(Self::CsjwtKidNotFound),
            "CSJWT_JWKS_KEY_INVALID" => Some(Self::CsjwtJwksKeyInvalid),
            "CSJWT_AUD_MISSING" => Some(Self::CsjwtAudMissing),
            "CSJWT_AUD_MISMATCH" => Some(Self::CsjwtAudMismatch),
            "CSJWT_ISS_MISMATCH" => Some(Self::CsjwtIssMismatch),
            "CSJWT_EXPIRED" => Some(Self::CsjwtExpired),
            "CSJWT_TIME_INVALID" => Some(Self::CsjwtTimeInvalid),
            "CSJWT_NONCE_MISMATCH" => Some(Self::CsjwtNonceMismatch),
            "CSJWT_UNVERIFIED_STUB_FORBIDDEN" => Some(Self::CsjwtUnverifiedStubForbidden),
            // Nitro
            "NITRO_DOC_SIG_INVALID" => Some(Self::NitroDocSigInvalid),
            "NITRO_CERT_CHAIN_INVALID" => Some(Self::NitroCertChainInvalid),
            "NITRO_CERT_TIME_INVALID" => Some(Self::NitroCertTimeInvalid),
            "NITRO_CERT_REVOKED" => Some(Self::NitroCertRevoked),
            "NITRO_MEASUREMENT_MISMATCH" => Some(Self::NitroMeasurementMismatch),
            "NITRO_PUBKEY_BINDING_MISMATCH" => Some(Self::NitroPubkeyBindingMismatch),
            "NITRO_NONCE_MISMATCH" => Some(Self::NitroNonceMismatch),
            // Cross-cutting
            "POLICY_MEASUREMENT_PINNING_DISABLED" => Some(Self::PolicyMeasurementPinningDisabled),
            "POLICY_AUDIENCE_PIN_REQUIRED" => Some(Self::PolicyAudiencePinRequired),
            "TRUST_ANCHOR_MISSING" => Some(Self::TrustAnchorMissing),
            "REVOCATION_CHECK_UNAVAILABLE" => Some(Self::RevocationCheckUnavailable),
            _ => None,
        }
    }

    /// Returns the M2 trust layer for this code.
    pub fn layer(&self) -> &'static str {
        match self {
            // T1_PARSE
            Self::TdxQuoteParseFailed | Self::TdxQuoteUnsupportedFormat => "T1_PARSE",
            // T2_CRYPTO
            Self::TdxQuoteSigInvalid
            | Self::TdxReportdataBindingMismatch
            | Self::CsjwtSigInvalid
            | Self::NitroDocSigInvalid => "T2_CRYPTO",
            // T3_CHAIN
            Self::TdxCollateralMissing
            | Self::TdxCollateralStale
            | Self::TdxPckChainInvalid
            | Self::TdxQeIdentityInvalid
            | Self::TdxTcbInfoInvalid
            | Self::TdxFmspcMismatch
            | Self::TdxPckRevoked
            | Self::CsjwtKidNotFound
            | Self::CsjwtJwksKeyInvalid
            | Self::NitroCertChainInvalid
            | Self::NitroCertTimeInvalid
            | Self::NitroCertRevoked
            | Self::TrustAnchorMissing
            | Self::RevocationCheckUnavailable => "T3_CHAIN",
            // T4_POLICY
            Self::TdxTcbStatusUnacceptable
            | Self::TdxTcbRevoked
            | Self::TdxMrtdMismatch
            | Self::TdxRtmrMismatch
            | Self::TdxNonceMismatch
            | Self::TdxCollateralTimeInvalid
            | Self::CsjwtAudMissing
            | Self::CsjwtAudMismatch
            | Self::CsjwtIssMismatch
            | Self::CsjwtExpired
            | Self::CsjwtTimeInvalid
            | Self::CsjwtNonceMismatch
            | Self::CsjwtUnverifiedStubForbidden
            | Self::NitroMeasurementMismatch
            | Self::NitroPubkeyBindingMismatch
            | Self::NitroNonceMismatch
            | Self::PolicyMeasurementPinningDisabled
            | Self::PolicyAudiencePinRequired => "T4_POLICY",
        }
    }
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

// ── GCP CS JWT structured errors ─────────────────────────────────────

/// Structured error codes for GCP Confidential Space JWT verification.
///
/// Each variant maps to a test case in the M2 trust verification matrix
/// (section: "GCP Confidential Space JWT Matrix").
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CsJwtVerifyError {
    // -- T2_CRYPTO --
    /// CSJWT-CRYPTO-001: JWT RS256 signature verification failed.
    SigInvalid(String),

    // -- T3_CHAIN --
    /// CSJWT-CHAIN-001: kid from JWT header not found in JWKS.
    KidNotFound(String),
    /// CSJWT-CHAIN-002: JWKS key type or algorithm mismatch.
    JwksKeyInvalid(String),

    // -- T4_POLICY --
    /// CSJWT-POL-001: aud claim missing when audience pinning is required.
    AudMissing,
    /// CSJWT-POL-002: aud claim does not match expected audience.
    AudMismatch { expected: String, actual: String },
    /// CSJWT-POL-003: iss claim does not match expected issuer.
    IssMismatch { expected: String, actual: String },
    /// CSJWT-POL-004: JWT has expired (exp claim).
    Expired(String),
    /// CSJWT-POL-005: JWT nbf/iat indicates token is not yet valid.
    TimeInvalid(String),
    /// CSJWT-POL-006: Nonce in JWT does not match expected session nonce.
    NonceMismatch { expected: String, actual: String },
    /// CSJWT-POL-007: Enclave-side unverified stub path active in production.
    UnverifiedStubForbidden,
}

impl CsJwtVerifyError {
    /// Returns the M2 matrix code string for this error.
    pub fn code(&self) -> &'static str {
        match self {
            Self::SigInvalid(_) => "CSJWT_SIG_INVALID",
            Self::KidNotFound(_) => "CSJWT_KID_NOT_FOUND",
            Self::JwksKeyInvalid(_) => "CSJWT_JWKS_KEY_INVALID",
            Self::AudMissing => "CSJWT_AUD_MISSING",
            Self::AudMismatch { .. } => "CSJWT_AUD_MISMATCH",
            Self::IssMismatch { .. } => "CSJWT_ISS_MISMATCH",
            Self::Expired(_) => "CSJWT_EXPIRED",
            Self::TimeInvalid(_) => "CSJWT_TIME_INVALID",
            Self::NonceMismatch { .. } => "CSJWT_NONCE_MISMATCH",
            Self::UnverifiedStubForbidden => "CSJWT_UNVERIFIED_STUB_FORBIDDEN",
        }
    }

    /// Returns the M2 trust layer for this error.
    pub fn layer(&self) -> &'static str {
        match self {
            Self::SigInvalid(_) => "T2_CRYPTO",
            Self::KidNotFound(_) | Self::JwksKeyInvalid(_) => "T3_CHAIN",
            Self::AudMissing
            | Self::AudMismatch { .. }
            | Self::IssMismatch { .. }
            | Self::Expired(_)
            | Self::TimeInvalid(_)
            | Self::NonceMismatch { .. }
            | Self::UnverifiedStubForbidden => "T4_POLICY",
        }
    }
}

impl std::fmt::Display for CsJwtVerifyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::SigInvalid(msg) => write!(f, "CSJWT_SIG_INVALID: {msg}"),
            Self::KidNotFound(kid) => write!(f, "CSJWT_KID_NOT_FOUND: kid={kid}"),
            Self::JwksKeyInvalid(msg) => write!(f, "CSJWT_JWKS_KEY_INVALID: {msg}"),
            Self::AudMissing => write!(f, "CSJWT_AUD_MISSING"),
            Self::AudMismatch { expected, actual } => {
                write!(f, "CSJWT_AUD_MISMATCH: expected {expected}, got {actual}")
            }
            Self::IssMismatch { expected, actual } => {
                write!(f, "CSJWT_ISS_MISMATCH: expected {expected}, got {actual}")
            }
            Self::Expired(msg) => write!(f, "CSJWT_EXPIRED: {msg}"),
            Self::TimeInvalid(msg) => write!(f, "CSJWT_TIME_INVALID: {msg}"),
            Self::NonceMismatch { expected, actual } => {
                write!(f, "CSJWT_NONCE_MISMATCH: expected {expected}, got {actual}")
            }
            Self::UnverifiedStubForbidden => {
                write!(f, "CSJWT_UNVERIFIED_STUB_FORBIDDEN")
            }
        }
    }
}

impl std::error::Error for CsJwtVerifyError {}

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

    /// Build a TDX DCAP verification result from a `TdxVerifyError::code()` string.
    ///
    /// Populates the check list with pass/fail/skip entries for each trust layer
    /// based on which layer the error belongs to.
    ///
    /// Returns `None` if the code string is not a recognized TDX code.
    pub fn from_tdx_error(error_code: &str, detail: &str) -> Option<Self> {
        let code = AttestCheckCode::from_code_str(error_code)?;
        let layer = code.layer();

        // Build checks list: layers before the failure passed, the failure
        // layer failed, layers after it were skipped.
        let layer_order = ["T1_PARSE", "T2_CRYPTO", "T3_CHAIN", "T4_POLICY"];
        let fail_idx = layer_order.iter().position(|&l| l == layer)?;

        let check_names = [
            ("TDX_QUOTE_PARSE", "T1_PARSE"),
            ("TDX_QUOTE_SIG", "T2_CRYPTO"),
            ("TDX_COLLATERAL", "T3_CHAIN"),
            ("TDX_POLICY", "T4_POLICY"),
        ];

        let mut checks = Vec::with_capacity(4);
        for (i, &(name, check_layer)) in check_names.iter().enumerate() {
            if i < fail_idx {
                checks.push(AttestCheck::pass(name, check_layer));
            } else if i == fail_idx {
                checks.push(AttestCheck::fail(name, check_layer, code.clone(), detail));
            } else {
                checks.push(AttestCheck::skip(name, check_layer));
            }
        }

        Some(Self {
            verified: false,
            platform: "tdx-dcap".to_string(),
            checks,
            warnings: vec![],
        })
    }

    /// Build a passing TDX DCAP verification result.
    pub fn tdx_pass() -> Self {
        Self {
            verified: true,
            platform: "tdx-dcap".to_string(),
            checks: vec![
                AttestCheck::pass("TDX_QUOTE_PARSE", "T1_PARSE"),
                AttestCheck::pass("TDX_QUOTE_SIG", "T2_CRYPTO"),
                AttestCheck::pass("TDX_COLLATERAL", "T3_CHAIN"),
                AttestCheck::pass("TDX_POLICY", "T4_POLICY"),
            ],
            warnings: vec![],
        }
    }

    /// Build a passing TDX DCAP result with T3_CHAIN skipped (no collateral).
    ///
    /// **Caution:** This should only be used in dev/test mode. In strict/prod
    /// paths, missing collateral should fail (use `from_tdx_error` with
    /// `TDX_COLLATERAL_MISSING` instead). The `RevocationUnchecked` warning
    /// makes this visible in logs and verification results.
    pub fn tdx_pass_no_collateral() -> Self {
        Self {
            verified: true,
            platform: "tdx-dcap".to_string(),
            checks: vec![
                AttestCheck::pass("TDX_QUOTE_PARSE", "T1_PARSE"),
                AttestCheck::pass("TDX_QUOTE_SIG", "T2_CRYPTO"),
                AttestCheck::skip("TDX_COLLATERAL", "T3_CHAIN"),
                AttestCheck::pass("TDX_POLICY", "T4_POLICY"),
            ],
            warnings: vec![VerifyWarningCode::RevocationUnchecked],
        }
    }

    /// Build a CS JWT verification result from a `CsJwtVerifyError`.
    ///
    /// Populates the check list with pass/fail/skip entries for each trust
    /// layer based on which layer the error belongs to.
    /// CS JWT has no T1_PARSE layer (JWT is always parseable at this point),
    /// so the check list starts at T2_CRYPTO.
    pub fn from_csjwt_error(err: &CsJwtVerifyError) -> Self {
        let code = AttestCheckCode::from_code_str(err.code())
            .expect("CsJwtVerifyError::code() must map to a valid AttestCheckCode");
        let layer = err.layer();
        let detail = err.to_string();

        // CS JWT check layers (no T1_PARSE — JWT structure is validated earlier).
        let check_names = [
            ("CSJWT_SIG", "T2_CRYPTO"),
            ("CSJWT_CHAIN", "T3_CHAIN"),
            ("CSJWT_POLICY", "T4_POLICY"),
        ];
        let layer_order = ["T2_CRYPTO", "T3_CHAIN", "T4_POLICY"];
        let fail_idx = layer_order
            .iter()
            .position(|&l| l == layer)
            .expect("CsJwtVerifyError::layer() must be a valid layer");

        let mut checks = Vec::with_capacity(3);
        for (i, &(name, check_layer)) in check_names.iter().enumerate() {
            if i < fail_idx {
                checks.push(AttestCheck::pass(name, check_layer));
            } else if i == fail_idx {
                checks.push(AttestCheck::fail(name, check_layer, code.clone(), &detail));
            } else {
                checks.push(AttestCheck::skip(name, check_layer));
            }
        }

        Self {
            verified: false,
            platform: "cs-jwt".to_string(),
            checks,
            warnings: vec![],
        }
    }

    /// Build a passing CS JWT verification result.
    pub fn csjwt_pass() -> Self {
        Self {
            verified: true,
            platform: "cs-jwt".to_string(),
            checks: vec![
                AttestCheck::pass("CSJWT_SIG", "T2_CRYPTO"),
                AttestCheck::pass("CSJWT_CHAIN", "T3_CHAIN"),
                AttestCheck::pass("CSJWT_POLICY", "T4_POLICY"),
            ],
            warnings: vec![],
        }
    }

    /// Build a passing CS JWT result with audience pinning skipped (dev mode).
    ///
    /// **Caution:** This should only be used in dev/test mode. In production,
    /// audience pinning must be mandatory (`CSJWT_AUD_MISSING` should fail).
    pub fn csjwt_pass_no_audience_pin() -> Self {
        Self {
            verified: true,
            platform: "cs-jwt".to_string(),
            checks: vec![
                AttestCheck::pass("CSJWT_SIG", "T2_CRYPTO"),
                AttestCheck::pass("CSJWT_CHAIN", "T3_CHAIN"),
                AttestCheck::pass("CSJWT_POLICY", "T4_POLICY"),
            ],
            warnings: vec![VerifyWarningCode::AudiencePinningSkipped],
        }
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

    // ── from_code_str roundtrip tests ─────────────────────────────

    #[test]
    fn test_from_code_str_all_tdx_codes() {
        let tdx_codes = [
            (
                "TDX_QUOTE_PARSE_FAILED",
                AttestCheckCode::TdxQuoteParseFailed,
                "T1_PARSE",
            ),
            (
                "TDX_QUOTE_UNSUPPORTED_FORMAT",
                AttestCheckCode::TdxQuoteUnsupportedFormat,
                "T1_PARSE",
            ),
            (
                "TDX_QUOTE_SIG_INVALID",
                AttestCheckCode::TdxQuoteSigInvalid,
                "T2_CRYPTO",
            ),
            (
                "TDX_REPORTDATA_BINDING_MISMATCH",
                AttestCheckCode::TdxReportdataBindingMismatch,
                "T2_CRYPTO",
            ),
            (
                "TDX_COLLATERAL_MISSING",
                AttestCheckCode::TdxCollateralMissing,
                "T3_CHAIN",
            ),
            (
                "TDX_COLLATERAL_STALE",
                AttestCheckCode::TdxCollateralStale,
                "T3_CHAIN",
            ),
            (
                "TDX_PCK_CHAIN_INVALID",
                AttestCheckCode::TdxPckChainInvalid,
                "T3_CHAIN",
            ),
            (
                "TDX_QE_IDENTITY_INVALID",
                AttestCheckCode::TdxQeIdentityInvalid,
                "T3_CHAIN",
            ),
            (
                "TDX_TCB_INFO_INVALID",
                AttestCheckCode::TdxTcbInfoInvalid,
                "T3_CHAIN",
            ),
            (
                "TDX_FMSPC_MISMATCH",
                AttestCheckCode::TdxFmspcMismatch,
                "T3_CHAIN",
            ),
            (
                "TDX_PCK_REVOKED",
                AttestCheckCode::TdxPckRevoked,
                "T3_CHAIN",
            ),
            (
                "TDX_TCB_STATUS_UNACCEPTABLE",
                AttestCheckCode::TdxTcbStatusUnacceptable,
                "T4_POLICY",
            ),
            (
                "TDX_TCB_REVOKED",
                AttestCheckCode::TdxTcbRevoked,
                "T4_POLICY",
            ),
            (
                "TDX_MRTD_MISMATCH",
                AttestCheckCode::TdxMrtdMismatch,
                "T4_POLICY",
            ),
            (
                "TDX_RTMR_MISMATCH",
                AttestCheckCode::TdxRtmrMismatch,
                "T4_POLICY",
            ),
            (
                "TDX_NONCE_MISMATCH",
                AttestCheckCode::TdxNonceMismatch,
                "T4_POLICY",
            ),
            (
                "TDX_COLLATERAL_TIME_INVALID",
                AttestCheckCode::TdxCollateralTimeInvalid,
                "T4_POLICY",
            ),
        ];

        for (code_str, expected_variant, expected_layer) in &tdx_codes {
            let parsed = AttestCheckCode::from_code_str(code_str);
            assert_eq!(
                parsed.as_ref(),
                Some(expected_variant),
                "from_code_str({code_str}) mismatch"
            );
            // Verify layer() is consistent.
            assert_eq!(
                parsed.unwrap().layer(),
                *expected_layer,
                "layer mismatch for {code_str}"
            );
        }
    }

    #[test]
    fn test_from_code_str_display_roundtrip() {
        // Every variant's Display string must roundtrip through from_code_str.
        let all_variants = vec![
            AttestCheckCode::TdxQuoteParseFailed,
            AttestCheckCode::TdxQuoteUnsupportedFormat,
            AttestCheckCode::TdxQuoteSigInvalid,
            AttestCheckCode::TdxReportdataBindingMismatch,
            AttestCheckCode::TdxCollateralMissing,
            AttestCheckCode::TdxCollateralStale,
            AttestCheckCode::TdxPckChainInvalid,
            AttestCheckCode::TdxQeIdentityInvalid,
            AttestCheckCode::TdxTcbInfoInvalid,
            AttestCheckCode::TdxFmspcMismatch,
            AttestCheckCode::TdxPckRevoked,
            AttestCheckCode::TdxTcbStatusUnacceptable,
            AttestCheckCode::TdxTcbRevoked,
            AttestCheckCode::TdxMrtdMismatch,
            AttestCheckCode::TdxRtmrMismatch,
            AttestCheckCode::TdxNonceMismatch,
            AttestCheckCode::TdxCollateralTimeInvalid,
            AttestCheckCode::CsjwtSigInvalid,
            AttestCheckCode::CsjwtKidNotFound,
            AttestCheckCode::CsjwtJwksKeyInvalid,
            AttestCheckCode::CsjwtAudMissing,
            AttestCheckCode::CsjwtAudMismatch,
            AttestCheckCode::CsjwtIssMismatch,
            AttestCheckCode::CsjwtExpired,
            AttestCheckCode::CsjwtTimeInvalid,
            AttestCheckCode::CsjwtNonceMismatch,
            AttestCheckCode::CsjwtUnverifiedStubForbidden,
            AttestCheckCode::NitroDocSigInvalid,
            AttestCheckCode::NitroCertChainInvalid,
            AttestCheckCode::NitroCertTimeInvalid,
            AttestCheckCode::NitroCertRevoked,
            AttestCheckCode::NitroMeasurementMismatch,
            AttestCheckCode::NitroPubkeyBindingMismatch,
            AttestCheckCode::NitroNonceMismatch,
            AttestCheckCode::PolicyMeasurementPinningDisabled,
            AttestCheckCode::PolicyAudiencePinRequired,
            AttestCheckCode::TrustAnchorMissing,
            AttestCheckCode::RevocationCheckUnavailable,
        ];

        for variant in &all_variants {
            let code_str = variant.to_string();
            let roundtrip = AttestCheckCode::from_code_str(&code_str);
            assert_eq!(
                roundtrip.as_ref(),
                Some(variant),
                "Display→from_code_str roundtrip failed for {code_str}"
            );
        }
    }

    #[test]
    fn test_from_code_str_unknown_returns_none() {
        assert_eq!(AttestCheckCode::from_code_str("UNKNOWN_CODE"), None);
        assert_eq!(AttestCheckCode::from_code_str(""), None);
        assert_eq!(
            AttestCheckCode::from_code_str("tdx_quote_parse_failed"),
            None
        );
    }

    // ── from_tdx_error builder tests ──────────────────────────────

    #[test]
    fn test_from_tdx_error_t1_failure() {
        let result =
            AttestVerifyResult::from_tdx_error("TDX_QUOTE_PARSE_FAILED", "corrupt bytes").unwrap();
        assert!(!result.verified);
        assert_eq!(result.platform, "tdx-dcap");
        assert_eq!(result.checks.len(), 4);
        // T1 failed, T2/T3/T4 skipped.
        assert_eq!(result.checks[0].status, AttestCheckStatus::Fail);
        assert_eq!(
            result.checks[0].code,
            Some(AttestCheckCode::TdxQuoteParseFailed)
        );
        assert_eq!(result.checks[1].status, AttestCheckStatus::Skip);
        assert_eq!(result.checks[2].status, AttestCheckStatus::Skip);
        assert_eq!(result.checks[3].status, AttestCheckStatus::Skip);
    }

    #[test]
    fn test_from_tdx_error_t2_failure() {
        let result =
            AttestVerifyResult::from_tdx_error("TDX_QUOTE_SIG_INVALID", "ECDSA failed").unwrap();
        // T1 passed, T2 failed, T3/T4 skipped.
        assert_eq!(result.checks[0].status, AttestCheckStatus::Pass);
        assert_eq!(result.checks[1].status, AttestCheckStatus::Fail);
        assert_eq!(
            result.checks[1].code,
            Some(AttestCheckCode::TdxQuoteSigInvalid)
        );
        assert_eq!(result.checks[2].status, AttestCheckStatus::Skip);
        assert_eq!(result.checks[3].status, AttestCheckStatus::Skip);
    }

    #[test]
    fn test_from_tdx_error_t3_failure() {
        let result =
            AttestVerifyResult::from_tdx_error("TDX_PCK_REVOKED", "serial 42 revoked").unwrap();
        // T1/T2 passed, T3 failed, T4 skipped.
        assert_eq!(result.checks[0].status, AttestCheckStatus::Pass);
        assert_eq!(result.checks[1].status, AttestCheckStatus::Pass);
        assert_eq!(result.checks[2].status, AttestCheckStatus::Fail);
        assert_eq!(result.checks[2].code, Some(AttestCheckCode::TdxPckRevoked));
        assert_eq!(result.checks[3].status, AttestCheckStatus::Skip);
    }

    #[test]
    fn test_from_tdx_error_t4_failure() {
        let result =
            AttestVerifyResult::from_tdx_error("TDX_MRTD_MISMATCH", "expected aa, got bb").unwrap();
        // T1/T2/T3 passed, T4 failed.
        assert_eq!(result.checks[0].status, AttestCheckStatus::Pass);
        assert_eq!(result.checks[1].status, AttestCheckStatus::Pass);
        assert_eq!(result.checks[2].status, AttestCheckStatus::Pass);
        assert_eq!(result.checks[3].status, AttestCheckStatus::Fail);
        assert_eq!(
            result.checks[3].code,
            Some(AttestCheckCode::TdxMrtdMismatch)
        );
    }

    #[test]
    fn test_from_tdx_error_unknown_returns_none() {
        assert!(AttestVerifyResult::from_tdx_error("BOGUS", "test").is_none());
    }

    #[test]
    fn test_tdx_pass_result() {
        let result = AttestVerifyResult::tdx_pass();
        assert!(result.verified);
        assert_eq!(result.platform, "tdx-dcap");
        assert_eq!(result.checks.len(), 4);
        assert!(result
            .checks
            .iter()
            .all(|c| c.status == AttestCheckStatus::Pass));
        assert!(result.warnings.is_empty());
    }

    #[test]
    fn test_tdx_pass_no_collateral_result() {
        let result = AttestVerifyResult::tdx_pass_no_collateral();
        assert!(result.verified);
        assert_eq!(result.checks[0].status, AttestCheckStatus::Pass);
        assert_eq!(result.checks[1].status, AttestCheckStatus::Pass);
        assert_eq!(result.checks[2].status, AttestCheckStatus::Skip);
        assert_eq!(result.checks[3].status, AttestCheckStatus::Pass);
        // Must emit a warning — no silent pass for skipped collateral.
        assert!(result.has_warning(&VerifyWarningCode::RevocationUnchecked));
    }

    #[test]
    fn test_from_tdx_error_failures_list() {
        let result = AttestVerifyResult::from_tdx_error("TDX_COLLATERAL_STALE", "expired").unwrap();
        let failures = result.failures();
        assert_eq!(failures.len(), 1);
        assert_eq!(*failures[0], AttestCheckCode::TdxCollateralStale);
    }

    // ── CsJwtVerifyError tests ────────────────────────────────────

    #[test]
    fn test_csjwt_error_code_and_layer() {
        let cases: Vec<(CsJwtVerifyError, &str, &str)> = vec![
            (
                CsJwtVerifyError::SigInvalid("bad sig".into()),
                "CSJWT_SIG_INVALID",
                "T2_CRYPTO",
            ),
            (
                CsJwtVerifyError::KidNotFound("abc123".into()),
                "CSJWT_KID_NOT_FOUND",
                "T3_CHAIN",
            ),
            (
                CsJwtVerifyError::JwksKeyInvalid("wrong alg".into()),
                "CSJWT_JWKS_KEY_INVALID",
                "T3_CHAIN",
            ),
            (
                CsJwtVerifyError::AudMissing,
                "CSJWT_AUD_MISSING",
                "T4_POLICY",
            ),
            (
                CsJwtVerifyError::AudMismatch {
                    expected: "aud1".into(),
                    actual: "aud2".into(),
                },
                "CSJWT_AUD_MISMATCH",
                "T4_POLICY",
            ),
            (
                CsJwtVerifyError::IssMismatch {
                    expected: "iss1".into(),
                    actual: "iss2".into(),
                },
                "CSJWT_ISS_MISMATCH",
                "T4_POLICY",
            ),
            (
                CsJwtVerifyError::Expired("token expired at...".into()),
                "CSJWT_EXPIRED",
                "T4_POLICY",
            ),
            (
                CsJwtVerifyError::TimeInvalid("nbf in future".into()),
                "CSJWT_TIME_INVALID",
                "T4_POLICY",
            ),
            (
                CsJwtVerifyError::NonceMismatch {
                    expected: "aabb".into(),
                    actual: "ccdd".into(),
                },
                "CSJWT_NONCE_MISMATCH",
                "T4_POLICY",
            ),
            (
                CsJwtVerifyError::UnverifiedStubForbidden,
                "CSJWT_UNVERIFIED_STUB_FORBIDDEN",
                "T4_POLICY",
            ),
        ];

        for (err, expected_code, expected_layer) in &cases {
            assert_eq!(err.code(), *expected_code, "code mismatch for {err:?}");
            assert_eq!(err.layer(), *expected_layer, "layer mismatch for {err:?}");
            // Display should start with the code string.
            let display = err.to_string();
            assert!(
                display.starts_with(expected_code),
                "Display for {err:?} should start with {expected_code}: got {display}"
            );
            // Code must roundtrip through from_code_str.
            let check_code = AttestCheckCode::from_code_str(expected_code);
            assert!(
                check_code.is_some(),
                "{expected_code} must map to AttestCheckCode"
            );
        }
    }

    // ── CSJWT-CRYPTO-001: JWT signature invalid → T2 failure ──────

    #[test]
    fn test_csjwt_crypto_001_sig_invalid() {
        let err = CsJwtVerifyError::SigInvalid("RS256 verification failed".into());
        let result = AttestVerifyResult::from_csjwt_error(&err);
        assert!(!result.verified);
        assert_eq!(result.platform, "cs-jwt");
        assert_eq!(result.checks.len(), 3);
        // T2 failed, T3/T4 skipped.
        assert_eq!(result.checks[0].status, AttestCheckStatus::Fail);
        assert_eq!(
            result.checks[0].code,
            Some(AttestCheckCode::CsjwtSigInvalid)
        );
        assert_eq!(result.checks[1].status, AttestCheckStatus::Skip);
        assert_eq!(result.checks[2].status, AttestCheckStatus::Skip);
    }

    // ── CSJWT-CHAIN-001: kid not found → T3 failure ──────────────

    #[test]
    fn test_csjwt_chain_001_kid_not_found() {
        let err = CsJwtVerifyError::KidNotFound("unknown-kid-123".into());
        let result = AttestVerifyResult::from_csjwt_error(&err);
        // T2 passed, T3 failed, T4 skipped.
        assert_eq!(result.checks[0].status, AttestCheckStatus::Pass);
        assert_eq!(result.checks[1].status, AttestCheckStatus::Fail);
        assert_eq!(
            result.checks[1].code,
            Some(AttestCheckCode::CsjwtKidNotFound)
        );
        assert_eq!(result.checks[2].status, AttestCheckStatus::Skip);
    }

    // ── CSJWT-POL-001: aud missing in strict mode ────────────────

    #[test]
    fn test_csjwt_pol_001_aud_missing() {
        let err = CsJwtVerifyError::AudMissing;
        let result = AttestVerifyResult::from_csjwt_error(&err);
        // T2/T3 passed, T4 failed.
        assert_eq!(result.checks[0].status, AttestCheckStatus::Pass);
        assert_eq!(result.checks[1].status, AttestCheckStatus::Pass);
        assert_eq!(result.checks[2].status, AttestCheckStatus::Fail);
        assert_eq!(
            result.checks[2].code,
            Some(AttestCheckCode::CsjwtAudMissing)
        );
    }

    // ── CSJWT-POL-002: wrong aud ─────────────────────────────────

    #[test]
    fn test_csjwt_pol_002_aud_mismatch() {
        let err = CsJwtVerifyError::AudMismatch {
            expected: "https://myservice.example.com".into(),
            actual: "https://other.example.com".into(),
        };
        let result = AttestVerifyResult::from_csjwt_error(&err);
        assert_eq!(result.checks[2].status, AttestCheckStatus::Fail);
        assert_eq!(
            result.checks[2].code,
            Some(AttestCheckCode::CsjwtAudMismatch)
        );
    }

    // ── CSJWT-POL-003: wrong issuer ──────────────────────────────

    #[test]
    fn test_csjwt_pol_003_iss_mismatch() {
        let err = CsJwtVerifyError::IssMismatch {
            expected: "https://confidentialcomputing.googleapis.com".into(),
            actual: "https://attacker.example.com".into(),
        };
        let result = AttestVerifyResult::from_csjwt_error(&err);
        assert_eq!(result.checks[2].status, AttestCheckStatus::Fail);
        assert_eq!(
            result.checks[2].code,
            Some(AttestCheckCode::CsjwtIssMismatch)
        );
    }

    // ── CSJWT-POL-004: token expired ─────────────────────────────

    #[test]
    fn test_csjwt_pol_004_expired() {
        let err = CsJwtVerifyError::Expired("expired at 1700000000".into());
        let result = AttestVerifyResult::from_csjwt_error(&err);
        assert_eq!(result.checks[2].status, AttestCheckStatus::Fail);
        assert_eq!(result.checks[2].code, Some(AttestCheckCode::CsjwtExpired));
    }

    // ── CSJWT-POL-006: nonce mismatch ────────────────────────────

    #[test]
    fn test_csjwt_pol_006_nonce_mismatch() {
        let err = CsJwtVerifyError::NonceMismatch {
            expected: "aabbccdd".into(),
            actual: "11223344".into(),
        };
        let result = AttestVerifyResult::from_csjwt_error(&err);
        assert_eq!(result.checks[2].status, AttestCheckStatus::Fail);
        assert_eq!(
            result.checks[2].code,
            Some(AttestCheckCode::CsjwtNonceMismatch)
        );
    }

    // ── CSJWT-POL-007: stub forbidden in prod ────────────────────

    #[test]
    fn test_csjwt_pol_007_stub_forbidden() {
        let err = CsJwtVerifyError::UnverifiedStubForbidden;
        let result = AttestVerifyResult::from_csjwt_error(&err);
        assert_eq!(result.checks[2].status, AttestCheckStatus::Fail);
        assert_eq!(
            result.checks[2].code,
            Some(AttestCheckCode::CsjwtUnverifiedStubForbidden)
        );
    }

    // ── CS JWT positive paths ────────────────────────────────────

    #[test]
    fn test_csjwt_pass_result() {
        let result = AttestVerifyResult::csjwt_pass();
        assert!(result.verified);
        assert_eq!(result.platform, "cs-jwt");
        assert_eq!(result.checks.len(), 3);
        assert!(result
            .checks
            .iter()
            .all(|c| c.status == AttestCheckStatus::Pass));
        assert!(result.warnings.is_empty());
    }

    #[test]
    fn test_csjwt_pass_no_audience_pin() {
        let result = AttestVerifyResult::csjwt_pass_no_audience_pin();
        assert!(result.verified);
        assert_eq!(result.checks.len(), 3);
        assert!(result
            .checks
            .iter()
            .all(|c| c.status == AttestCheckStatus::Pass));
        // Must emit a warning — no silent audience skip.
        assert!(result.has_warning(&VerifyWarningCode::AudiencePinningSkipped));
    }
}
