use std::net::SocketAddr;
use std::time::Duration;

use clap::{Parser, ValueEnum};

#[derive(Copy, Clone, Debug, Eq, PartialEq, ValueEnum)]
pub enum LogFormat {
    Json,
    Pretty,
}

#[derive(Clone, Debug, Parser)]
#[command(name = "cyntrisec-relay")]
#[command(about = "TCP-to-vsock byte relay for Cyntrisec workers")]
pub struct RelayConfig {
    #[arg(long, env = "CYNTRISEC_RELAY_TCP_BIND", default_value = "0.0.0.0:443")]
    pub tcp_bind: SocketAddr,

    #[arg(long, env = "CYNTRISEC_RELAY_VSOCK_CID", default_value_t = 16)]
    pub vsock_cid: u32,

    #[arg(long, env = "CYNTRISEC_RELAY_VSOCK_PORT", default_value_t = 5000)]
    pub vsock_port: u32,

    #[arg(long, env = "CYNTRISEC_RELAY_MAX_CONN", default_value_t = 1024)]
    pub max_connections: usize,

    #[arg(long, env = "CYNTRISEC_RELAY_IDLE_SECS", default_value_t = 300)]
    pub idle_timeout_secs: u64,

    #[arg(long, env = "CYNTRISEC_RELAY_LOG_FORMAT", value_enum, default_value_t = LogFormat::Json)]
    pub log_format: LogFormat,
}

impl RelayConfig {
    pub fn idle_timeout(&self) -> Duration {
        Duration::from_secs(self.idle_timeout_secs)
    }
}
