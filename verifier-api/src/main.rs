use clap::Parser;
use tracing_subscriber::EnvFilter;

#[derive(Parser)]
#[command(
    name = "ephemeralml-verifier",
    about = "Cyntrisec Trust Center — Receipt Verification API"
)]
struct Args {
    /// Listen address
    #[arg(long, default_value = "0.0.0.0")]
    host: String,
    /// Listen port
    #[arg(long, default_value = "8080")]
    port: u16,
    /// Allowed CORS origins (repeatable). If omitted, all origins are allowed.
    #[arg(long = "cors-origin")]
    cors_origins: Vec<String>,
    /// API key for authenticating verify requests.
    /// Can also be set via EPHEMERALML_VERIFIER_API_KEY env var.
    #[arg(long, env = "EPHEMERALML_VERIFIER_API_KEY")]
    api_key: Option<String>,
    /// Deployment mode: "public-trust-center" or "secured-api".
    ///
    /// public-trust-center: No API key required. Strong rate limiting.
    ///                      Designed for public internet-facing verification.
    ///
    /// secured-api:         API key required. For internal or enterprise use.
    #[arg(long, env = "EPHEMERALML_VERIFIER_MODE")]
    mode: Option<String>,
    /// Disable API key authentication (legacy flag, prefer --mode).
    /// WARNING: Do not use in production internet-facing deployments.
    #[arg(long, env = "EPHEMERALML_VERIFIER_NO_AUTH")]
    insecure_no_auth: bool,
    /// Maximum requests per minute per IP. Default: 60. Set to 0 to disable.
    #[arg(long, env = "EPHEMERALML_VERIFIER_RATE_LIMIT", default_value = "60")]
    rate_limit: u32,
    /// Allow fully permissive CORS when auth is enabled and no --cors-origin
    /// is specified. Not recommended for production.
    #[arg(long)]
    allow_permissive_cors: bool,
}

#[tokio::main]
async fn main() {
    let args = Args::parse();

    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    // --- Mode resolution ---
    let service_mode = resolve_mode(&args);

    let (api_key, rate_limit) = match &service_mode {
        ephemeralml_verifier_api::ServiceMode::PublicTrustCenter => {
            tracing::info!("╔══════════════════════════════════════════════╗");
            tracing::info!("║  CYNTRISEC TRUST CENTER — PUBLIC MODE       ║");
            tracing::info!("║  No API key required for verification.      ║");
            tracing::info!("║  Rate limiting active.                      ║");
            tracing::info!("╚══════════════════════════════════════════════╝");
            // Force rate limiting in public mode (minimum 30 rpm if user set 0).
            let rpm = if args.rate_limit == 0 {
                tracing::warn!("Rate limit 0 not allowed in public-trust-center mode, defaulting to 60");
                60
            } else {
                args.rate_limit
            };
            (None, rpm)
        }
        ephemeralml_verifier_api::ServiceMode::SecuredApi => {
            let key = args.api_key.clone().unwrap_or_else(|| {
                eprintln!(
                    "Error: --mode secured-api requires --api-key or EPHEMERALML_VERIFIER_API_KEY."
                );
                std::process::exit(1);
            });
            if key.len() < 16 {
                tracing::warn!(
                    "API key is shorter than 16 characters — consider using a stronger key"
                );
            }
            tracing::info!("Cyntrisec Trust Center — Secured API mode");
            tracing::info!("API key authentication enabled");
            (Some(key), args.rate_limit)
        }
    };

    // --- CORS validation ---
    if args.cors_origins.is_empty() {
        if api_key.is_some() && !args.allow_permissive_cors {
            eprintln!(
                "Error: Auth is enabled but no --cors-origin specified.\n\
                 \n\
                 Either:\n\
                 1. Specify allowed origins:  --cors-origin https://your-app.example.com\n\
                 2. Explicitly allow permissive CORS:  --allow-permissive-cors\n\
                 \n\
                 Fully permissive CORS with auth enabled is not recommended."
            );
            std::process::exit(1);
        }
        if service_mode == ephemeralml_verifier_api::ServiceMode::PublicTrustCenter {
            tracing::info!("CORS: permissive (public trust center mode)");
        } else {
            tracing::warn!("No --cors-origin specified; CORS is fully permissive");
        }
    } else {
        tracing::info!("CORS allowed origins: {:?}", args.cors_origins);
    }

    // --- Rate limit ---
    if rate_limit == 0 {
        tracing::warn!("Rate limiting is disabled (--rate-limit 0)");
    } else {
        tracing::info!("Rate limit: {} requests/minute per IP", rate_limit);
    }

    let config = ephemeralml_verifier_api::ServerConfig {
        mode: service_mode,
        api_key,
        requests_per_minute: rate_limit,
        cors_origins: args.cors_origins,
    };

    let app = ephemeralml_verifier_api::build_router_with_config(&config);

    let addr = format!("{}:{}", args.host, args.port);
    tracing::info!("Listening on {}", addr);

    let listener = tokio::net::TcpListener::bind(&addr).await.unwrap();
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
    )
    .await
    .unwrap();
}

/// Resolve the service mode from CLI args.
///
/// Priority: --mode > --insecure-no-auth (legacy) > --api-key > error.
fn resolve_mode(args: &Args) -> ephemeralml_verifier_api::ServiceMode {
    if let Some(mode_str) = &args.mode {
        match mode_str.as_str() {
            "public-trust-center" => ephemeralml_verifier_api::ServiceMode::PublicTrustCenter,
            "secured-api" => ephemeralml_verifier_api::ServiceMode::SecuredApi,
            other => {
                eprintln!(
                    "Error: Unknown mode '{}'.\n\
                     Valid modes: public-trust-center, secured-api",
                    other
                );
                std::process::exit(1);
            }
        }
    } else if args.insecure_no_auth {
        // Legacy flag — map to public-trust-center for backward compat.
        tracing::warn!("--insecure-no-auth is deprecated. Use --mode public-trust-center instead.");
        ephemeralml_verifier_api::ServiceMode::PublicTrustCenter
    } else if args.api_key.is_some() {
        ephemeralml_verifier_api::ServiceMode::SecuredApi
    } else {
        eprintln!(
            "Error: No mode configured. Either:\n\
             \n\
             1. Public trust center:  --mode public-trust-center\n\
             2. Secured API:          --mode secured-api --api-key <KEY>\n\
             3. Legacy (deprecated):  --insecure-no-auth"
        );
        std::process::exit(1);
    }
}
