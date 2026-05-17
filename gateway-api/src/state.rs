//! Shared application state — holds the backend client behind a Mutex.

use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{Mutex, Notify, Semaphore};

use ephemeral_ml_client::SecureEnclaveClient;

use crate::config::{GatewayConfig, WorkerChannelKind};
use crate::rate_limit::RateLimiter;
use crate::worker::{
    expected_measurements_from_policy_path, HttpBackendChannel, SecureChannelWorker, WorkerChannel,
};

/// Shared state accessible from all Axum handlers via `State<AppState>`.
#[derive(Clone)]
pub struct AppState {
    pub client: Arc<Mutex<SecureEnclaveClient>>,
    pub worker_channel: Arc<dyn WorkerChannel>,
    pub config: Arc<GatewayConfig>,
    /// Set to `true` once `establish_channel` succeeds.
    pub connected: Arc<std::sync::atomic::AtomicBool>,
    /// Optional dedicated embedding backend client.
    pub embedding_client: Option<Arc<Mutex<SecureEnclaveClient>>>,
    pub embedding_worker_channel: Option<Arc<dyn WorkerChannel>>,
    /// Set to `true` once the embedding backend channel is established.
    pub embedding_connected: Arc<std::sync::atomic::AtomicBool>,
    /// Wakes the background reconnect loop for the main backend.
    pub reconnect_notify: Arc<Notify>,
    /// Wakes the background reconnect loop for the embedding backend.
    pub embedding_reconnect_notify: Arc<Notify>,
    /// Concurrency semaphore — limits the number of in-flight inference requests.
    pub concurrency_semaphore: Arc<Semaphore>,
    /// Per-IP rate limiter.
    pub rate_limiter: Arc<RateLimiter>,
}

impl AppState {
    pub fn new(
        client: SecureEnclaveClient,
        config: GatewayConfig,
        embedding_client: Option<SecureEnclaveClient>,
    ) -> Self {
        let max_concurrent = config.max_concurrent_requests;
        let rate_limit_per_ip = config.rate_limit_per_ip;
        let rate_limit_global = config.rate_limit_global;
        let request_timeout = Duration::from_secs(config.request_timeout_secs);
        let client = Arc::new(Mutex::new(client));
        let connected = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let reconnect_notify = Arc::new(Notify::new());
        let worker_channel = build_worker_channel(
            config.worker_channel_kind,
            client.clone(),
            config.backend_addr.clone(),
            connected.clone(),
            reconnect_notify.clone(),
            request_timeout,
            expected_measurements_from_policy_path(config.preflight_policy_path.as_deref()),
        );

        let embedding_connected = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let embedding_reconnect_notify = Arc::new(Notify::new());
        let embedding_client = embedding_client.map(|c| Arc::new(Mutex::new(c)));
        let embedding_worker_channel = embedding_client.as_ref().map(|client| {
            build_worker_channel(
                config.worker_channel_kind,
                client.clone(),
                config
                    .embedding_backend_addr
                    .clone()
                    .unwrap_or_else(|| config.backend_addr.clone()),
                embedding_connected.clone(),
                embedding_reconnect_notify.clone(),
                request_timeout,
                expected_measurements_from_policy_path(config.preflight_policy_path.as_deref()),
            )
        });

        Self {
            client,
            worker_channel,
            config: Arc::new(config),
            connected,
            embedding_client,
            embedding_worker_channel,
            embedding_connected,
            reconnect_notify,
            embedding_reconnect_notify,
            concurrency_semaphore: Arc::new(Semaphore::new(max_concurrent)),
            rate_limiter: Arc::new(RateLimiter::new(rate_limit_per_ip, rate_limit_global)),
        }
    }
}

fn build_worker_channel(
    kind: WorkerChannelKind,
    client: Arc<Mutex<SecureEnclaveClient>>,
    backend_addr: String,
    connected: Arc<std::sync::atomic::AtomicBool>,
    reconnect_notify: Arc<Notify>,
    request_timeout: Duration,
    expected_measurements: Result<confidential_ml_transport::ExpectedMeasurements, String>,
) -> Arc<dyn WorkerChannel> {
    match kind {
        WorkerChannelKind::Http => Arc::new(HttpBackendChannel::new(
            client,
            backend_addr,
            connected,
            reconnect_notify,
            request_timeout,
        )),
        WorkerChannelKind::Secure => Arc::new(SecureChannelWorker::new(
            client,
            backend_addr,
            connected,
            reconnect_notify,
            request_timeout,
            expected_measurements,
        )),
    }
}
