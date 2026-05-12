//! Local OpenAI-compatible proxy for Cyntrisec workers.
//!
//! The default bind address is intentionally `127.0.0.1:4000`. Loopback keeps
//! the plaintext OpenAI API surface on the customer's machine; deployments that
//! need another process namespace should run this binary as a sidecar in the
//! same Kubernetes pod, ECS task, or systemd boundary as the application.

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    ephemeralml_gateway::runtime::run_local_proxy().await
}
