pub mod error;
pub mod aws_proxy;
pub mod kms_proxy_server;
pub mod retry;
pub mod limits;
pub mod rate_limit;
pub mod proxy;
pub mod storage;
pub mod spy;

#[cfg(feature = "mock")]
pub mod mock;

// Re-export common types and host-specific types
pub use ephemeral_ml_common::*;
pub use error::{HostError, Result};
pub use proxy::VSockProxy;
pub use storage::WeightStorage;

/// Core trait for host proxy operations
pub trait HostProxy: Send + Sync {
    /// Forward encrypted payload to enclave
    fn forward_to_enclave(&self, payload: &[u8]) -> Result<Vec<u8>>;
}

/// Target structure for blind relay operations
pub struct BlindRelay;

impl BlindRelay {
    pub fn new() -> Self {
        Self
    }
}

impl HostProxy for BlindRelay {
    fn forward_to_enclave(&self, _payload: &[u8]) -> Result<Vec<u8>> {
        // Core relay logic would go here. For now, it's a blind relay.
        // In mock mode, this might just echo or return success.
        Ok(vec![]) 
    }
}
