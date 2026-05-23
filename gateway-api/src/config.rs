//! Gateway/proxy configuration from environment variables and CLI args.

use clap::{Parser, ValueEnum};
use serde::Serialize;
use std::ffi::OsString;
use std::path::PathBuf;

const ENV_ALIASES: &[(&str, &[&str])] = &[
    (
        "EPHEMERALML_BACKEND_ADDR",
        &[
            "CYNTRISEC_BACKEND_ADDR",
            "CYNTRISEC_WORKER_ADDR",
            "CYNTRISEC_WORKER",
        ],
    ),
    ("EPHEMERALML_DEFAULT_MODEL", &["CYNTRISEC_DEFAULT_MODEL"]),
    ("EPHEMERALML_API_KEY", &["CYNTRISEC_API_KEY"]),
    (
        "EPHEMERALML_GATEWAY_HOST",
        &["CYNTRISEC_PROXY_HOST", "CYNTRISEC_GATEWAY_HOST"],
    ),
    (
        "EPHEMERALML_GATEWAY_PORT",
        &["CYNTRISEC_PROXY_PORT", "CYNTRISEC_GATEWAY_PORT"],
    ),
    (
        "EPHEMERALML_REQUEST_TIMEOUT_SECS",
        &["CYNTRISEC_REQUEST_TIMEOUT_SECS"],
    ),
    (
        "EPHEMERALML_INCLUDE_METADATA_JSON",
        &["CYNTRISEC_INCLUDE_METADATA_JSON"],
    ),
    (
        "EPHEMERALML_RECEIPT_HEADER_FULL",
        &["CYNTRISEC_RECEIPT_HEADER_FULL"],
    ),
    (
        "EPHEMERALML_MODEL_CAPABILITIES",
        &["CYNTRISEC_MODEL_CAPABILITIES"],
    ),
    (
        "EPHEMERALML_EMBEDDING_BACKEND_ADDR",
        &["CYNTRISEC_EMBEDDING_BACKEND_ADDR"],
    ),
    (
        "EPHEMERALML_EMBEDDING_MODEL",
        &["CYNTRISEC_EMBEDDING_MODEL"],
    ),
    (
        "EPHEMERALML_MAX_CONCURRENT_REQUESTS",
        &["CYNTRISEC_MAX_CONCURRENT_REQUESTS"],
    ),
    (
        "EPHEMERALML_RATE_LIMIT_PER_IP",
        &["CYNTRISEC_RATE_LIMIT_PER_IP"],
    ),
    (
        "EPHEMERALML_RATE_LIMIT_GLOBAL",
        &["CYNTRISEC_RATE_LIMIT_GLOBAL"],
    ),
    (
        "EPHEMERALML_TRUST_PROXY_HEADERS",
        &["CYNTRISEC_TRUST_PROXY_HEADERS"],
    ),
    (
        "EPHEMERALML_RECONNECT_ENABLED",
        &["CYNTRISEC_RECONNECT_ENABLED"],
    ),
    (
        "EPHEMERALML_RECONNECT_BACKOFF_BASE_MS",
        &["CYNTRISEC_RECONNECT_BACKOFF_BASE_MS"],
    ),
    (
        "EPHEMERALML_RECONNECT_BACKOFF_CAP_MS",
        &["CYNTRISEC_RECONNECT_BACKOFF_CAP_MS"],
    ),
    (
        "EPHEMERALML_RECONNECT_HEALTH_INTERVAL_SECS",
        &["CYNTRISEC_RECONNECT_HEALTH_INTERVAL_SECS"],
    ),
];

/// Install CYNTRISEC_* environment aliases before clap parses `EPHEMERALML_*`.
///
/// Existing EPHEMERALML_* values keep precedence for backward compatibility.
pub fn install_env_aliases() {
    for (legacy, aliases) in ENV_ALIASES {
        if std::env::var_os(legacy).is_some() {
            continue;
        }
        if let Some((alias, value)) = first_env_value(aliases) {
            let value = normalize_alias_value(legacy, alias, value);
            std::env::set_var(legacy, value);
        }
    }
}

/// Install local-proxy defaults before Clap parses env vars.
///
/// `cyntrisec-proxy` is intentionally localhost-only by default. If a customer
/// needs another process namespace, they should run the proxy as a sidecar in
/// the same pod/task/service boundary as the application, not expose it as a
/// public network service.
pub fn install_local_proxy_defaults() {
    set_env_default("EPHEMERALML_GATEWAY_HOST", "127.0.0.1");
    set_env_default("EPHEMERALML_GATEWAY_PORT", "4000");
    set_env_default("CYNTRISEC_PREFLIGHT_REQUIRED", "true");
}

fn set_env_default(name: &str, value: &str) {
    if std::env::var_os(name).is_none() {
        std::env::set_var(name, value);
    }
}

fn first_env_value<'a>(names: &'a [&'a str]) -> Option<(&'a str, OsString)> {
    names
        .iter()
        .find_map(|name| std::env::var_os(name).map(|value| (*name, value)))
}

fn normalize_alias_value(legacy: &str, alias: &str, value: OsString) -> OsString {
    if legacy == "EPHEMERALML_BACKEND_ADDR" && alias == "CYNTRISEC_WORKER" {
        if let Some(value_str) = value.to_str() {
            if let Some(stripped) = value_str.strip_prefix("tcp://") {
                return OsString::from(stripped);
            }
        }
    }
    value
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, Serialize, ValueEnum)]
#[serde(rename_all = "snake_case")]
pub enum WorkerChannelKind {
    Http,
    Secure,
}

#[derive(Parser, Clone, Debug)]
#[command(
    name = "cyntrisec-proxy",
    visible_alias = "ephemeralml-gateway",
    about = "OpenAI-compatible local proxy/gateway for Cyntrisec confidential inference"
)]
pub struct GatewayConfig {
    /// Cyntrisec worker/backend address (host:port) for the secure enclave channel.
    #[arg(long, env = "EPHEMERALML_BACKEND_ADDR")]
    pub backend_addr: String,

    /// Default model ID when the client sends a model name that doesn't match
    /// the backend's internal model ID (maps OpenAI model names to backend IDs).
    #[arg(long, env = "EPHEMERALML_DEFAULT_MODEL", default_value = "stage-0")]
    pub default_model: String,

    /// Optional bearer token for gateway authentication.
    /// When set, all inference endpoints require `Authorization: Bearer <key>`.
    #[arg(long, env = "EPHEMERALML_API_KEY")]
    pub api_key: Option<String>,

    /// Gateway listen host.
    #[arg(long, env = "EPHEMERALML_GATEWAY_HOST", default_value = "0.0.0.0")]
    pub host: String,

    /// Gateway listen port.
    #[arg(long, env = "EPHEMERALML_GATEWAY_PORT", default_value = "8090")]
    pub port: u16,

    /// Per-request timeout in seconds for backend inference calls.
    #[arg(long, env = "EPHEMERALML_REQUEST_TIMEOUT_SECS", default_value = "120")]
    pub request_timeout_secs: u64,

    /// Include `_ephemeralml` metadata object in JSON response bodies.
    /// Default: only headers. Set to `1` or `true` to enable.
    #[arg(long, env = "EPHEMERALML_INCLUDE_METADATA_JSON")]
    pub include_metadata_json: bool,

    /// Include full AIR v1 receipt in receipt-b64 headers.
    /// Off by default — large receipts can break proxies/load balancers with
    /// header-size limits (typically 4-8 KB). When disabled, only
    /// receipt presence/hash headers are sent. Full receipt is always
    /// available via JSON metadata when metadata JSON is enabled.
    #[arg(long, env = "EPHEMERALML_RECEIPT_HEADER_FULL")]
    pub receipt_header_full: bool,

    /// Comma-separated model capabilities: "chat", "embeddings", or
    /// "chat,embeddings". Controls which endpoints are active. `/v1/embeddings`
    /// returns 400 unless "embeddings" is listed.
    #[arg(long, env = "EPHEMERALML_MODEL_CAPABILITIES", default_value = "chat")]
    pub model_capabilities: String,

    /// Optional dedicated embedding backend address (host:port).
    /// When set, `/v1/embeddings` routes to this backend instead of the main one.
    #[arg(long, env = "EPHEMERALML_EMBEDDING_BACKEND_ADDR")]
    pub embedding_backend_addr: Option<String>,

    /// Model ID for the embedding backend. Required when `EPHEMERALML_EMBEDDING_BACKEND_ADDR` is set.
    #[arg(long, env = "EPHEMERALML_EMBEDDING_MODEL")]
    pub embedding_model: Option<String>,

    /// Maximum concurrent inference requests the gateway will process
    /// simultaneously. Requests exceeding this limit receive HTTP 503.
    #[arg(
        long,
        env = "EPHEMERALML_MAX_CONCURRENT_REQUESTS",
        default_value = "50"
    )]
    pub max_concurrent_requests: usize,

    /// Per-IP rate limit: maximum requests per minute from a single IP.
    /// Set to 0 to disable per-IP rate limiting.
    #[arg(long, env = "EPHEMERALML_RATE_LIMIT_PER_IP", default_value = "60")]
    pub rate_limit_per_ip: u32,

    /// Global rate limit: maximum requests per minute across all clients.
    /// Set to 0 to disable global rate limiting.
    #[arg(long, env = "EPHEMERALML_RATE_LIMIT_GLOBAL", default_value = "0")]
    pub rate_limit_global: u32,

    /// Trust `X-Forwarded-For` / `X-Real-Ip` for client IP extraction.
    /// Off by default. Enable only behind a trusted proxy that overwrites
    /// these headers; otherwise clients can spoof rate-limit identity.
    #[arg(long, env = "EPHEMERALML_TRUST_PROXY_HEADERS", default_value = "false")]
    pub trust_proxy_headers: bool,

    /// Allowed browser CORS origins for the gateway.
    ///
    /// Empty means no cross-origin browser access. Repeat the flag or use a
    /// comma-separated EPHEMERALML_CORS_ORIGINS value for browser clients.
    #[arg(
        long = "cors-origin",
        env = "EPHEMERALML_CORS_ORIGINS",
        value_delimiter = ','
    )]
    pub cors_origins: Vec<String>,

    /// Enable background reconnect loop with exponential backoff.
    /// When true, a background task monitors connectivity and reconnects
    /// automatically when a backend disconnects.
    #[arg(long, env = "EPHEMERALML_RECONNECT_ENABLED", default_value = "true")]
    pub reconnect_enabled: bool,

    /// Base delay in milliseconds for exponential backoff on reconnect.
    #[arg(
        long,
        env = "EPHEMERALML_RECONNECT_BACKOFF_BASE_MS",
        default_value = "100"
    )]
    pub reconnect_backoff_base_ms: u64,

    /// Maximum delay in milliseconds for exponential backoff on reconnect.
    #[arg(
        long,
        env = "EPHEMERALML_RECONNECT_BACKOFF_CAP_MS",
        default_value = "30000"
    )]
    pub reconnect_backoff_cap_ms: u64,

    /// Interval in seconds between TCP liveness probes when connected.
    /// Each probe attempts a TCP connect to the backend; if it fails, the
    /// gateway marks the backend disconnected and starts reconnecting.
    #[arg(
        long,
        env = "EPHEMERALML_RECONNECT_HEALTH_INTERVAL_SECS",
        default_value = "5"
    )]
    pub reconnect_health_interval_secs: u64,

    /// Worker-channel implementation. Defaults to `http` until the AWS host
    /// relay and enclave worker direct path are available.
    #[arg(
        long,
        env = "CYNTRISEC_WORKER_CHANNEL",
        value_enum,
        default_value = "http"
    )]
    pub worker_channel_kind: WorkerChannelKind,

    /// Pinned Cyntrisec policy file loaded by the local proxy preflight.
    #[arg(long, env = "CYNTRISEC_POLICY_PATH")]
    pub preflight_policy_path: Option<PathBuf>,

    /// Pinned model manifest loaded by the local proxy preflight.
    #[arg(long, env = "CYNTRISEC_MANIFEST_PATH")]
    pub preflight_manifest_path: Option<PathBuf>,

    /// Require local-proxy preflight to load pinned policy/manifest inputs and
    /// verify worker attestation before accepting prompts.
    #[arg(long, env = "CYNTRISEC_PREFLIGHT_REQUIRED", default_value = "false")]
    pub preflight_required: bool,
}

impl GatewayConfig {
    /// Check whether a capability (e.g. "chat", "embeddings") is present in
    /// the comma-separated `model_capabilities` string.
    pub fn has_capability(&self, cap: &str) -> bool {
        self.model_capabilities
            .split(',')
            .any(|c| c.trim().eq_ignore_ascii_case(cap))
    }

    /// Validate config consistency at startup. Returns an error message if the
    /// configuration is invalid.
    pub fn validate(&self) -> Result<(), String> {
        // Require explicit embedding model when a dedicated backend is configured
        // to prevent duplicate IDs in /v1/models.
        if self.embedding_backend_addr.is_some() && self.embedding_model.is_none() {
            return Err(
                "EPHEMERALML_EMBEDDING_BACKEND_ADDR is set but EPHEMERALML_EMBEDDING_MODEL is \
                 not. A dedicated embedding backend requires an explicit model ID to avoid \
                 duplicate entries in /v1/models. Set EPHEMERALML_EMBEDDING_MODEL to the \
                 embedding model's identifier."
                    .to_string(),
            );
        }

        // Reject embedding model ID that duplicates the default model — would
        // produce ambiguous /v1/models output.
        if let Some(ref emb_model) = self.embedding_model {
            if self.embedding_backend_addr.is_some() && emb_model == &self.default_model {
                return Err(format!(
                    "EPHEMERALML_EMBEDDING_MODEL ('{}') must differ from \
                     EPHEMERALML_DEFAULT_MODEL when a dedicated embedding backend is configured. \
                     Use a distinct model ID to avoid duplicate entries in /v1/models.",
                    emb_model
                ));
            }
        }

        // Reject unknown capability tokens.
        for cap in self.model_capabilities.split(',') {
            let cap = cap.trim().to_lowercase();
            if !cap.is_empty() && cap != "chat" && cap != "embeddings" {
                return Err(format!(
                    "Unknown capability '{cap}' in EPHEMERALML_MODEL_CAPABILITIES. \
                     Valid values: chat, embeddings"
                ));
            }
        }

        // Embedding model without a backend address is a no-op — warn.
        if self.embedding_model.is_some() && self.embedding_backend_addr.is_none() {
            tracing::warn!(
                "EPHEMERALML_EMBEDDING_MODEL is set but EPHEMERALML_EMBEDDING_BACKEND_ADDR is \
                 not — the embedding model ID will be ignored"
            );
        }

        // Embedding backend configured but embeddings capability not enabled — dead config.
        if self.embedding_backend_addr.is_some() && !self.has_capability("embeddings") {
            tracing::warn!(
                "EPHEMERALML_EMBEDDING_BACKEND_ADDR is set but 'embeddings' capability is not \
                 enabled — the embedding backend will not be used. Add 'embeddings' to \
                 EPHEMERALML_MODEL_CAPABILITIES."
            );
        }

        // Reconnect backoff base exceeds cap — cap will always apply.
        if self.reconnect_backoff_base_ms > self.reconnect_backoff_cap_ms {
            tracing::warn!(
                base_ms = self.reconnect_backoff_base_ms,
                cap_ms = self.reconnect_backoff_cap_ms,
                "EPHEMERALML_RECONNECT_BACKOFF_BASE_MS exceeds \
                 EPHEMERALML_RECONNECT_BACKOFF_CAP_MS — backoff will be capped at {cap_ms}ms",
                cap_ms = self.reconnect_backoff_cap_ms
            );
        }

        // No capabilities active at all — gateway will reject all inference requests.
        if !self.has_capability("chat") && !self.has_capability("embeddings") {
            tracing::warn!(
                "No capabilities enabled in EPHEMERALML_MODEL_CAPABILITIES — all inference \
                 endpoints will return 400. Set capabilities to 'chat', 'embeddings', or \
                 'chat,embeddings'."
            );
        }

        if self.trust_proxy_headers {
            tracing::warn!(
                "EPHEMERALML_TRUST_PROXY_HEADERS is enabled -- only do this behind a trusted \
                 proxy/load balancer that overwrites forwarding headers"
            );
        }

        // Reject empty api_key. An empty string is treated as "no auth" by
        // auth_middleware (Some("") matches `_ => return next.run`), which is
        // almost always an env-var typo rather than an intentional config.
        // Unset the variable to opt into the unauthenticated path explicitly.
        if let Some(ref key) = self.api_key {
            if key.is_empty() {
                return Err(
                    "EPHEMERALML_API_KEY is set but empty. Either set a non-empty bearer token, \
                     or unset the variable entirely to run without authentication."
                        .to_string(),
                );
            }
        }

        for origin in &self.cors_origins {
            if origin == "*" {
                return Err(
                    "EPHEMERALML_CORS_ORIGINS does not accept '*'. Use concrete browser origins."
                        .to_string(),
                );
            }
            axum::http::HeaderValue::from_str(origin).map_err(|_| {
                format!(
                    "Invalid CORS origin '{origin}'. Use a concrete origin such as \
                     https://app.example.com; wildcards are not accepted."
                )
            })?;
        }

        if self.preflight_required {
            if self.preflight_policy_path.is_none() {
                return Err(
                    "CYNTRISEC_PREFLIGHT_REQUIRED is true but CYNTRISEC_POLICY_PATH is not set"
                        .to_string(),
                );
            }
            if self.preflight_manifest_path.is_none() {
                return Err(
                    "CYNTRISEC_PREFLIGHT_REQUIRED is true but CYNTRISEC_MANIFEST_PATH is not set"
                        .to_string(),
                );
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalize_strips_tcp_prefix_for_worker_alias() {
        let value = normalize_alias_value(
            "EPHEMERALML_BACKEND_ADDR",
            "CYNTRISEC_WORKER",
            OsString::from("tcp://1.2.3.4:443"),
        );
        assert_eq!(value, OsString::from("1.2.3.4:443"));
    }

    #[test]
    fn normalize_keeps_tcp_prefix_for_other_backend_aliases() {
        let value = normalize_alias_value(
            "EPHEMERALML_BACKEND_ADDR",
            "CYNTRISEC_BACKEND_ADDR",
            OsString::from("tcp://1.2.3.4:443"),
        );
        assert_eq!(value, OsString::from("tcp://1.2.3.4:443"));
    }
}
