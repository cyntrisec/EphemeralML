use clap::Parser;
use tracing_subscriber::EnvFilter;

#[derive(Parser)]
#[command(
    name = "ephemeralml-verifier",
    about = "EphemeralML Hosted Receipt Verification API"
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
    /// Disable API key authentication. Required when no --api-key is set.
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

    // --- Auth validation ---
    let api_key = match (&args.api_key, args.insecure_no_auth) {
        (Some(key), _) => {
            if key.len() < 16 {
                tracing::warn!(
                    "API key is shorter than 16 characters — consider using a stronger key"
                );
            }
            tracing::info!("API key authentication enabled");
            Some(key.clone())
        }
        (None, true) => {
            tracing::warn!("========================================");
            tracing::warn!("  AUTH DISABLED (--insecure-no-auth)");
            tracing::warn!("  Do NOT expose this to the internet!");
            tracing::warn!("========================================");
            None
        }
        (None, false) => {
            eprintln!(
                "Error: No API key configured. Either:\n\
                 \n\
                 1. Set an API key:  --api-key <KEY>  or  EPHEMERALML_VERIFIER_API_KEY=<KEY>\n\
                 2. Explicitly disable auth:  --insecure-no-auth\n\
                 \n\
                 This is required to prevent accidental unauthenticated deployments."
            );
            std::process::exit(1);
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
        tracing::warn!("No --cors-origin specified; CORS is fully permissive");
    } else {
        tracing::info!("CORS allowed origins: {:?}", args.cors_origins);
    }

    // --- Rate limit ---
    if args.rate_limit == 0 {
        tracing::warn!("Rate limiting is disabled (--rate-limit 0)");
    } else {
        tracing::info!("Rate limit: {} requests/minute per IP", args.rate_limit);
    }

    let config = ephemeralml_verifier_api::ServerConfig {
        api_key,
        requests_per_minute: args.rate_limit,
        cors_origins: args.cors_origins,
    };

    let app = ephemeralml_verifier_api::build_router_with_config(&config);

    let addr = format!("{}:{}", args.host, args.port);
    tracing::info!("EphemeralML Verifier API listening on {}", addr);

    let listener = tokio::net::TcpListener::bind(&addr).await.unwrap();
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
    )
    .await
    .unwrap();
}
