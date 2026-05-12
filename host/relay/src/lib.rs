pub mod config;

use std::fmt;
use std::future::Future;
use std::io;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Semaphore;

pub const DEFAULT_SHUTDOWN_GRACE: Duration = Duration::from_secs(30);

pub type RelayResult<T> = Result<T, RelayError>;

#[derive(Debug)]
pub enum RelayError {
    Io(io::Error),
    IdleTimeout(Duration),
    ShutdownGraceExceeded { active_connections: usize },
}

impl fmt::Display for RelayError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RelayError::Io(e) => write!(f, "I/O error: {e}"),
            RelayError::IdleTimeout(timeout) => {
                write!(
                    f,
                    "relay connection idle timeout after {}s",
                    timeout.as_secs()
                )
            }
            RelayError::ShutdownGraceExceeded { active_connections } => write!(
                f,
                "shutdown grace exceeded with {active_connections} active connection(s)"
            ),
        }
    }
}

impl std::error::Error for RelayError {}

impl From<io::Error> for RelayError {
    fn from(value: io::Error) -> Self {
        RelayError::Io(value)
    }
}

#[derive(Clone, Copy, Debug)]
pub struct RelayServerConfig {
    pub max_connections: usize,
    pub idle_timeout: Duration,
    pub shutdown_grace: Duration,
}

impl RelayServerConfig {
    pub fn new(max_connections: usize, idle_timeout: Duration) -> Self {
        Self {
            max_connections,
            idle_timeout,
            shutdown_grace: DEFAULT_SHUTDOWN_GRACE,
        }
    }
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct RelayRunStats {
    pub accepted_connections: u64,
    pub refused_connections: u64,
}

pub async fn relay_connection<U>(
    inbound: TcpStream,
    upstream: U,
    idle_timeout: Duration,
) -> RelayResult<(u64, u64)>
where
    U: AsyncRead + AsyncWrite + Unpin + Send,
{
    relay_streams(inbound, upstream, idle_timeout).await
}

pub async fn relay_streams<A, B>(
    mut inbound: A,
    mut upstream: B,
    idle_timeout: Duration,
) -> RelayResult<(u64, u64)>
where
    A: AsyncRead + AsyncWrite + Unpin + Send,
    B: AsyncRead + AsyncWrite + Unpin + Send,
{
    tokio::time::timeout(
        idle_timeout,
        tokio::io::copy_bidirectional(&mut inbound, &mut upstream),
    )
    .await
    .map_err(|_| RelayError::IdleTimeout(idle_timeout))?
    .map_err(RelayError::Io)
}

pub async fn run_listener_with_connector<C, Fut, U, S>(
    listener: TcpListener,
    connector: C,
    config: RelayServerConfig,
    shutdown: S,
) -> RelayResult<RelayRunStats>
where
    C: Fn() -> Fut + Send + Sync + 'static,
    Fut: Future<Output = io::Result<U>> + Send + 'static,
    U: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    S: Future<Output = ()> + Send,
{
    let connector = Arc::new(connector);
    let semaphore = Arc::new(Semaphore::new(config.max_connections));
    let connection_ids = Arc::new(AtomicU64::new(1));
    let accepted = Arc::new(AtomicU64::new(0));
    let refused = Arc::new(AtomicU64::new(0));

    tokio::pin!(shutdown);
    loop {
        tokio::select! {
            biased;
            _ = &mut shutdown => {
                break;
            }
            accept_result = listener.accept() => {
                let (inbound, peer_addr) = accept_result.map_err(RelayError::Io)?;
                let connection_id = connection_ids.fetch_add(1, Ordering::Relaxed);

                let permit = match semaphore.clone().try_acquire_owned() {
                    Ok(permit) => permit,
                    Err(_) => {
                        refused.fetch_add(1, Ordering::Relaxed);
                        tracing::warn!(
                            connection_id,
                            peer_addr = %peer_addr,
                            max_connections = config.max_connections,
                            "relay connection refused: capacity reached"
                        );
                        drop(inbound);
                        continue;
                    }
                };

                accepted.fetch_add(1, Ordering::Relaxed);
                let connector = connector.clone();
                let idle_timeout = config.idle_timeout;
                tokio::spawn(async move {
                    let _permit = permit;
                    if let Err(err) = handle_connection(
                        connection_id,
                        peer_addr,
                        inbound,
                        connector,
                        idle_timeout,
                    ).await {
                        tracing::warn!(
                            connection_id,
                            peer_addr = %peer_addr,
                            error = %err,
                            "relay connection closed with error"
                        );
                    }
                });
            }
        }
    }

    drop(listener);
    let active_connections = config
        .max_connections
        .saturating_sub(semaphore.available_permits());
    if active_connections > 0 {
        match tokio::time::timeout(config.shutdown_grace, async {
            loop {
                if semaphore.available_permits() == config.max_connections {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        })
        .await
        {
            Ok(()) => {}
            Err(_) => {
                let active_connections = config
                    .max_connections
                    .saturating_sub(semaphore.available_permits());
                return Err(RelayError::ShutdownGraceExceeded { active_connections });
            }
        }
    }

    Ok(RelayRunStats {
        accepted_connections: accepted.load(Ordering::Relaxed),
        refused_connections: refused.load(Ordering::Relaxed),
    })
}

async fn handle_connection<C, Fut, U>(
    connection_id: u64,
    peer_addr: SocketAddr,
    inbound: TcpStream,
    connector: Arc<C>,
    idle_timeout: Duration,
) -> RelayResult<()>
where
    C: Fn() -> Fut + Send + Sync + 'static,
    Fut: Future<Output = io::Result<U>> + Send + 'static,
    U: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    tracing::info!(
        connection_id,
        peer_addr = %peer_addr,
        "relay connection accepted"
    );

    let upstream = match connector().await {
        Ok(stream) => stream,
        Err(err) => {
            tracing::warn!(
                connection_id,
                peer_addr = %peer_addr,
                error = %err,
                "relay upstream dial failed"
            );
            return Err(RelayError::Io(err));
        }
    };

    let (client_to_worker, worker_to_client) =
        relay_connection(inbound, upstream, idle_timeout).await?;
    tracing::info!(
        connection_id,
        peer_addr = %peer_addr,
        client_to_worker,
        worker_to_client,
        "relay connection completed"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[tokio::test]
    async fn relay_streams_copies_both_directions() {
        let (mut client, inbound) = tokio::io::duplex(64);
        let (upstream, mut worker) = tokio::io::duplex(64);

        let relay = tokio::spawn(relay_streams(inbound, upstream, Duration::from_secs(1)));

        client.write_all(b"hello").await.unwrap();
        client.shutdown().await.unwrap();
        let mut from_client = vec![0; 5];
        worker.read_exact(&mut from_client).await.unwrap();
        assert_eq!(&from_client, b"hello");

        worker.write_all(b"world").await.unwrap();
        worker.shutdown().await.unwrap();
        let mut from_worker = Vec::new();
        client.read_to_end(&mut from_worker).await.unwrap();
        assert_eq!(&from_worker, b"world");

        let stats = relay.await.unwrap().unwrap();
        assert_eq!(stats, (5, 5));
    }

    #[tokio::test]
    async fn relay_streams_times_out_idle_connections() {
        let (_client, inbound) = tokio::io::duplex(64);
        let (upstream, _worker) = tokio::io::duplex(64);

        let err = relay_streams(inbound, upstream, Duration::from_millis(10))
            .await
            .unwrap_err();
        assert!(matches!(err, RelayError::IdleTimeout(_)));
    }
}
