#[tokio::main]
async fn main() -> anyhow::Result<()> {
    ephemeralml_gateway::runtime::run_gateway().await
}
