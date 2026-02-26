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
}
