//! Shared application state — holds the backend client behind a Mutex.

use std::sync::Arc;
use tokio::sync::Mutex;

use ephemeral_ml_client::{SecureClient, SecureEnclaveClient};

use crate::config::GatewayConfig;

/// Shared state accessible from all Axum handlers via `State<AppState>`.
#[derive(Clone)]
pub struct AppState {
    pub client: Arc<Mutex<SecureEnclaveClient>>,
    pub config: Arc<GatewayConfig>,
    /// Set to `true` once `establish_channel` succeeds.
    pub connected: Arc<std::sync::atomic::AtomicBool>,
}

impl AppState {
    pub fn new(client: SecureEnclaveClient, config: GatewayConfig) -> Self {
        Self {
            client: Arc::new(Mutex::new(client)),
            config: Arc::new(config),
            connected: Arc::new(std::sync::atomic::AtomicBool::new(false)),
        }
    }

    /// Ensure the backend channel is established. Connects lazily on first call.
    /// Subsequent calls are no-ops if already connected.
    pub async fn ensure_connected(&self) -> Result<(), String> {
        use std::sync::atomic::Ordering;
        if self.connected.load(Ordering::Acquire) {
            return Ok(());
        }
        let mut client = self.client.lock().await;
        // Double-check after acquiring lock
        if self.connected.load(Ordering::Acquire) {
            return Ok(());
        }
        client
            .establish_channel(&self.config.backend_addr)
            .await
            .map_err(|e| format!("Backend handshake failed: {e}"))?;
        self.connected.store(true, Ordering::Release);
        tracing::info!(
            backend = %self.config.backend_addr,
            "Secure channel established with backend"
        );
        Ok(())
    }
}
