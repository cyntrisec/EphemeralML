use std::io;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use cyntrisec_relay::{run_listener_with_connector, RelayServerConfig};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::oneshot;

#[tokio::test]
async fn tcp_relay_handles_half_close() {
    let Some(upstream_listener) = bind_loopback("tcp_relay_handles_half_close").await else {
        return;
    };
    let upstream_addr = upstream_listener.local_addr().unwrap();
    let Some(relay_listener) = bind_loopback("tcp_relay_handles_half_close").await else {
        return;
    };
    let relay_addr = relay_listener.local_addr().unwrap();
    let upstream_task = tokio::spawn(async move {
        let (mut stream, _) = upstream_listener.accept().await.unwrap();
        let mut received = Vec::new();
        stream.read_to_end(&mut received).await.unwrap();
        assert_eq!(received, b"hello");
        stream.write_all(b"world").await.unwrap();
        stream.shutdown().await.unwrap();
    });

    let (shutdown_tx, shutdown_rx) = oneshot::channel();
    let relay_task = tokio::spawn(run_listener_with_connector(
        relay_listener,
        move || async move { TcpStream::connect(upstream_addr).await },
        RelayServerConfig {
            max_connections: 8,
            idle_timeout: Duration::from_secs(1),
            shutdown_grace: Duration::from_secs(1),
        },
        async move {
            let _ = shutdown_rx.await;
        },
    ));

    let mut client = TcpStream::connect(relay_addr).await.unwrap();
    client.write_all(b"hello").await.unwrap();
    client.shutdown().await.unwrap();
    let mut response = Vec::new();
    client.read_to_end(&mut response).await.unwrap();
    assert_eq!(response, b"world");

    shutdown_tx.send(()).unwrap();
    let stats = relay_task.await.unwrap().unwrap();
    assert_eq!(stats.accepted_connections, 1);
    assert_eq!(stats.refused_connections, 0);
    upstream_task.await.unwrap();
}

#[tokio::test]
async fn tcp_relay_refuses_connections_at_capacity() {
    let Some(upstream_listener) = bind_loopback("tcp_relay_refuses_connections_at_capacity").await
    else {
        return;
    };
    let upstream_addr = upstream_listener.local_addr().unwrap();
    let Some(relay_listener) = bind_loopback("tcp_relay_refuses_connections_at_capacity").await
    else {
        return;
    };
    let relay_addr = relay_listener.local_addr().unwrap();
    let connector_count = Arc::new(AtomicUsize::new(0));
    let accepted_count = Arc::new(AtomicUsize::new(0));
    let accepted_count_task = accepted_count.clone();
    let upstream_task = tokio::spawn(async move {
        let (mut stream, _) = upstream_listener.accept().await.unwrap();
        accepted_count_task.fetch_add(1, Ordering::SeqCst);
        let mut one = [0u8; 1];
        let _ = stream.read(&mut one).await;
    });

    let (shutdown_tx, shutdown_rx) = oneshot::channel();
    let connector_count_closure = connector_count.clone();
    let relay_task = tokio::spawn(run_listener_with_connector(
        relay_listener,
        move || {
            let connector_count = connector_count_closure.clone();
            async move {
                connector_count.fetch_add(1, Ordering::SeqCst);
                TcpStream::connect(upstream_addr).await
            }
        },
        RelayServerConfig {
            max_connections: 1,
            idle_timeout: Duration::from_secs(5),
            shutdown_grace: Duration::from_secs(1),
        },
        async move {
            let _ = shutdown_rx.await;
        },
    ));

    let mut first = TcpStream::connect(relay_addr).await.unwrap();
    wait_for(|| accepted_count.load(Ordering::SeqCst) == 1).await;

    let mut second = TcpStream::connect(relay_addr).await.unwrap();
    second.write_all(b"x").await.unwrap();
    let mut buf = [0u8; 1];
    let read = tokio::time::timeout(Duration::from_secs(1), second.read(&mut buf))
        .await
        .unwrap();
    match read {
        Ok(0) => {}
        Err(err) if err.kind() == io::ErrorKind::ConnectionReset => {}
        other => panic!("expected refused connection to close or reset, got {other:?}"),
    }
    assert_eq!(connector_count.load(Ordering::SeqCst), 1);

    first.write_all(b"q").await.unwrap();
    first.shutdown().await.unwrap();
    upstream_task.await.unwrap();
    shutdown_tx.send(()).unwrap();
    let stats = relay_task.await.unwrap().unwrap();
    assert_eq!(stats.accepted_connections, 1);
    assert_eq!(stats.refused_connections, 1);
}

#[tokio::test]
async fn tcp_relay_closes_idle_connections() {
    let Some(upstream_listener) = bind_loopback("tcp_relay_closes_idle_connections").await else {
        return;
    };
    let upstream_addr = upstream_listener.local_addr().unwrap();
    let Some(relay_listener) = bind_loopback("tcp_relay_closes_idle_connections").await else {
        return;
    };
    let relay_addr = relay_listener.local_addr().unwrap();
    let upstream_task = tokio::spawn(async move {
        let (_stream, _) = upstream_listener.accept().await.unwrap();
        tokio::time::sleep(Duration::from_secs(2)).await;
    });

    let (shutdown_tx, shutdown_rx) = oneshot::channel();
    let relay_task = tokio::spawn(run_listener_with_connector(
        relay_listener,
        move || async move { TcpStream::connect(upstream_addr).await },
        RelayServerConfig {
            max_connections: 8,
            idle_timeout: Duration::from_millis(25),
            shutdown_grace: Duration::from_secs(1),
        },
        async move {
            let _ = shutdown_rx.await;
        },
    ));

    let mut client = TcpStream::connect(relay_addr).await.unwrap();
    let mut buf = [0u8; 1];
    let read = tokio::time::timeout(Duration::from_secs(1), client.read(&mut buf))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(read, 0);

    shutdown_tx.send(()).unwrap();
    let stats = relay_task.await.unwrap().unwrap();
    assert_eq!(stats.accepted_connections, 1);
    upstream_task.await.unwrap();
}

async fn wait_for(predicate: impl Fn() -> bool) {
    let started = std::time::Instant::now();
    while !predicate() {
        assert!(
            started.elapsed() < Duration::from_secs(1),
            "condition did not become true"
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

async fn bind_loopback(test_name: &str) -> Option<TcpListener> {
    match TcpListener::bind("127.0.0.1:0").await {
        Ok(listener) => Some(listener),
        Err(err) if err.kind() == io::ErrorKind::PermissionDenied => {
            eprintln!("skipping {test_name}: loopback bind not permitted: {err}");
            None
        }
        Err(err) => panic!("failed to bind loopback for {test_name}: {err}"),
    }
}
