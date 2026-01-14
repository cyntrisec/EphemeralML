pub mod error;
pub mod proxy;
pub mod aws_proxy;
pub mod storage;

#[cfg(feature = "mock")]
pub mod mock;

// Re-export common types and host-specific types
pub use ephemeral_ml_common::*;
pub use error::{HostError, Result};
pub use proxy::VSockProxy;
pub use storage::WeightStorage;