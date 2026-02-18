use axum::extract::{Request, State};
use axum::http::StatusCode;
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use axum::Json;
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Instant;
use tokio::sync::Mutex;

use crate::api_types::ErrorResponse;
use crate::AppState;

/// Per-IP sliding window rate limiter.
///
/// Tracks request counts per IP within a 60-second window.
/// When the limit is exceeded, returns 429 Too Many Requests.
#[derive(Clone)]
pub struct RateLimiter {
    requests_per_minute: u32,
    clients: Arc<Mutex<HashMap<IpAddr, WindowEntry>>>,
}

struct WindowEntry {
    count: u32,
    window_start: Instant,
}

impl RateLimiter {
    pub fn new(requests_per_minute: u32) -> Self {
        Self {
            requests_per_minute,
            clients: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Check if the given IP is within the rate limit.
    pub async fn check(&self, ip: IpAddr) -> bool {
        let mut clients = self.clients.lock().await;
        let now = Instant::now();

        let entry = clients.entry(ip).or_insert(WindowEntry {
            count: 0,
            window_start: now,
        });

        if now.duration_since(entry.window_start) > std::time::Duration::from_secs(60) {
            entry.count = 1;
            entry.window_start = now;
            true
        } else {
            entry.count += 1;
            entry.count <= self.requests_per_minute
        }
    }

    /// Periodically clean up expired entries to prevent unbounded memory growth.
    pub fn spawn_cleanup_task(&self) {
        let clients = self.clients.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(300));
            loop {
                interval.tick().await;
                let mut map = clients.lock().await;
                let now = Instant::now();
                map.retain(|_, entry| {
                    now.duration_since(entry.window_start) < std::time::Duration::from_secs(120)
                });
            }
        });
    }
}

/// Extract client IP from request extensions (ConnectInfo) or fall back to 0.0.0.0.
fn extract_ip(request: &Request) -> IpAddr {
    request
        .extensions()
        .get::<axum::extract::ConnectInfo<std::net::SocketAddr>>()
        .map(|ci| ci.0.ip())
        .unwrap_or(IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED))
}

/// Rate limiting middleware.
///
/// Skips rate limiting for health checks.
pub async fn rate_limit_middleware(
    State(state): State<AppState>,
    request: Request,
    next: Next,
) -> Response {
    let limiter = match &state.rate_limiter {
        Some(l) => l,
        None => return next.run(request).await,
    };

    // Skip rate limiting for health endpoint
    if request.uri().path() == "/health" {
        return next.run(request).await;
    }

    let ip = extract_ip(&request);

    if limiter.check(ip).await {
        next.run(request).await
    } else {
        (
            StatusCode::TOO_MANY_REQUESTS,
            Json(ErrorResponse {
                error: "Rate limit exceeded. Try again later.".to_string(),
            }),
        )
            .into_response()
    }
}
