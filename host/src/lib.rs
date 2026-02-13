// Prevent accidentally building with conflicting features enabled.
#[cfg(all(feature = "mock", feature = "production"))]
compile_error!(
    "Features `mock` and `production` are mutually exclusive. \
     Build with: --no-default-features --features production"
);
#[cfg(all(feature = "mock", feature = "gcp"))]
compile_error!(
    "Features `mock` and `gcp` are mutually exclusive. \
     Build with: --no-default-features --features gcp"
);
#[cfg(all(feature = "production", feature = "gcp"))]
compile_error!(
    "Features `production` and `gcp` are mutually exclusive. \
     Build with: --no-default-features --features gcp"
);

pub mod aws_proxy;
pub mod circuit_breaker;
pub mod error;
pub mod kms_proxy_server;
pub mod limits;
pub mod metrics;
pub mod otel;
pub mod rate_limit;
pub mod retry;
pub mod storage;

#[cfg(feature = "mock")]
pub mod mock;

// Re-export common types and host-specific types
pub use ephemeral_ml_common::*;
pub use error::{HostError, Result};
pub use storage::WeightStorage;
