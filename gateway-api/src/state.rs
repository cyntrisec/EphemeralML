//! Shared application state — holds the backend client behind a Mutex.

use std::sync::Arc;
use tokio::sync::{Mutex, Notify};

use ephemeral_ml_client::{SecureClient, SecureEnclaveClient};

use crate::config::GatewayConfig;
use crate::reconnect::CONNECT_TIMEOUT;

/// Shared state accessible from all Axum handlers via `State<AppState>`.
#[derive(Clone)]
pub struct AppState {
    pub client: Arc<Mutex<SecureEnclaveClient>>,
    pub config: Arc<GatewayConfig>,
    /// Set to `true` once `establish_channel` succeeds.
    pub connected: Arc<std::sync::atomic::AtomicBool>,
    /// Optional dedicated embedding backend client.
    pub embedding_client: Option<Arc<Mutex<SecureEnclaveClient>>>,
    /// Set to `true` once the embedding backend channel is established.
    pub embedding_connected: Arc<std::sync::atomic::AtomicBool>,
    /// Wakes the background reconnect loop for the main backend.
    pub reconnect_notify: Arc<Notify>,
    /// Wakes the background reconnect loop for the embedding backend.
    pub embedding_reconnect_notify: Arc<Notify>,
}

impl AppState {
    pub fn new(
        client: SecureEnclaveClient,
        config: GatewayConfig,
        embedding_client: Option<SecureEnclaveClient>,
    ) -> Self {
        Self {
            client: Arc::new(Mutex::new(client)),
            config: Arc::new(config),
            connected: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            embedding_client: embedding_client.map(|c| Arc::new(Mutex::new(c))),
            embedding_connected: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            reconnect_notify: Arc::new(Notify::new()),
            embedding_reconnect_notify: Arc::new(Notify::new()),
        }
    }

    /// Ensure the backend channel is established. Connects lazily on first call.
    /// Subsequent calls are no-ops if already connected. The connect attempt is
    /// bounded by `CONNECT_TIMEOUT` to avoid holding the mutex indefinitely.
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
        tokio::time::timeout(
            CONNECT_TIMEOUT,
            client.establish_channel(&self.config.backend_addr),
        )
        .await
        .map_err(|_| {
            format!(
                "Backend handshake timed out after {}s",
                CONNECT_TIMEOUT.as_secs()
            )
        })?
        .map_err(|e| format!("Backend handshake failed: {e}"))?;
        self.connected.store(true, Ordering::Release);
        tracing::info!(
            backend = %self.config.backend_addr,
            "Secure channel established with backend"
        );
        Ok(())
    }

    /// Ensure the embedding backend channel is established (when a dedicated
    /// embedding backend is configured). Mirrors `ensure_connected()`.
    pub async fn ensure_embedding_connected(&self) -> Result<(), String> {
        use std::sync::atomic::Ordering;
        let emb_client = self
            .embedding_client
            .as_ref()
            .ok_or_else(|| "No embedding backend configured".to_string())?;
        let emb_addr = self
            .config
            .embedding_backend_addr
            .as_deref()
            .ok_or_else(|| "No embedding backend address configured".to_string())?;

        if self.embedding_connected.load(Ordering::Acquire) {
            return Ok(());
        }
        let mut client = emb_client.lock().await;
        if self.embedding_connected.load(Ordering::Acquire) {
            return Ok(());
        }
        tokio::time::timeout(
            CONNECT_TIMEOUT,
            client.establish_channel(emb_addr),
        )
        .await
        .map_err(|_| {
            format!(
                "Embedding backend handshake timed out after {}s",
                CONNECT_TIMEOUT.as_secs()
            )
        })?
        .map_err(|e| format!("Embedding backend handshake failed: {e}"))?;
        self.embedding_connected.store(true, Ordering::Release);
        tracing::info!(
            backend = %emb_addr,
            "Secure channel established with embedding backend"
        );
        Ok(())
    }
}
