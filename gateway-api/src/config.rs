//! Gateway configuration from environment variables and CLI args.

use clap::Parser;

#[derive(Parser, Clone, Debug)]
#[command(
    name = "ephemeralml-gateway",
    about = "OpenAI-compatible gateway for EphemeralML"
)]
pub struct GatewayConfig {
    /// EphemeralML backend address (host:port) for the secure enclave channel.
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

    /// Include full AIR v1 receipt in `x-ephemeralml-air-receipt-b64` header.
    /// Off by default — large receipts can break proxies/load balancers with
    /// header-size limits (typically 4-8 KB). When disabled, only
    /// `x-ephemeralml-receipt-present` and `x-ephemeralml-receipt-sha256` are
    /// sent. Full receipt is always available via JSON metadata when
    /// `EPHEMERALML_INCLUDE_METADATA_JSON=true`.
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

        Ok(())
    }
}
