use confidential_ml_pipeline::{StageConfig, StageExecutor};

/// Start a pipeline stage worker using TCP (mock mode).
///
/// Binds control and data_in listeners, then runs the pipeline's
/// `StageRuntime` which handles all connection management and message routing.
pub async fn run_stage_tcp<E: StageExecutor + 'static>(
    executor: E,
    config: StageConfig,
    control_addr: &str,
    data_in_addr: &str,
    data_out_addr: std::net::SocketAddr,
    provider: &(dyn confidential_ml_transport::AttestationProvider + Sync),
    verifier: &(dyn confidential_ml_transport::AttestationVerifier + Sync),
) -> std::result::Result<(), confidential_ml_pipeline::PipelineError> {
    let ctrl_listener = tokio::net::TcpListener::bind(control_addr)
        .await
        .map_err(|e| {
            confidential_ml_pipeline::PipelineError::Transport(
                confidential_ml_transport::Error::Io(e),
            )
        })?;
    let din_listener = tokio::net::TcpListener::bind(data_in_addr)
        .await
        .map_err(|e| {
            confidential_ml_pipeline::PipelineError::Transport(
                confidential_ml_transport::Error::Io(e),
            )
        })?;

    confidential_ml_pipeline::tcp::run_stage_with_listeners(
        executor,
        config,
        ctrl_listener,
        din_listener,
        data_out_addr,
        provider,
        verifier,
    )
    .await
}
