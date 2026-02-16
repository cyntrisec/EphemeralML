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
}

#[tokio::main]
async fn main() {
    let args = Args::parse();

    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    let app = if args.cors_origins.is_empty() {
        tracing::warn!("No --cors-origin specified; CORS is fully permissive");
        ephemeralml_verifier_api::build_router()
    } else {
        tracing::info!("CORS allowed origins: {:?}", args.cors_origins);
        ephemeralml_verifier_api::build_router_with_origins(&args.cors_origins)
    };

    let addr = format!("{}:{}", args.host, args.port);
    tracing::info!("EphemeralML Verifier API listening on {}", addr);

    let listener = tokio::net::TcpListener::bind(&addr).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}
