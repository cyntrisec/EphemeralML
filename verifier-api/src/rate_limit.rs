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

/// Extract client IP from ConnectInfo unless proxy headers are explicitly trusted.
fn extract_ip(request: &Request) -> IpAddr {
    extract_ip_with_proxy_trust(request, trust_proxy_headers_enabled())
}

fn trust_proxy_headers_enabled() -> bool {
    matches!(
        std::env::var("TRUST_PROXY_HEADERS").as_deref(),
        Ok("1") | Ok("true") | Ok("yes")
    )
}

fn extract_ip_with_proxy_trust(request: &Request, trust_proxy_headers: bool) -> IpAddr {
    if trust_proxy_headers {
        if let Some(xff) = request.headers().get("x-forwarded-for") {
            if let Ok(val) = xff.to_str() {
                // The leftmost IP is the original client; only trust it when a
                // deployment-level proxy strips client-supplied XFF.
                if let Some(first_ip) = val.split(',').next() {
                    if let Ok(ip) = first_ip.trim().parse::<IpAddr>() {
                        return ip;
                    }
                }
            }
        }
    }
    // Fallback: direct connection IP
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

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use std::net::{Ipv4Addr, SocketAddr};

    fn request_with_connect_ip(ip: IpAddr) -> Request {
        let mut request = Request::builder()
            .header("x-forwarded-for", "203.0.113.10, 198.51.100.20")
            .body(Body::empty())
            .unwrap();
        request
            .extensions_mut()
            .insert(axum::extract::ConnectInfo(SocketAddr::new(ip, 443)));
        request
    }

    #[test]
    fn ignores_x_forwarded_for_unless_proxy_headers_are_trusted() {
        let connect_ip = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 55));
        let request = request_with_connect_ip(connect_ip);

        assert_eq!(extract_ip_with_proxy_trust(&request, false), connect_ip);
    }

    #[test]
    fn uses_x_forwarded_for_when_proxy_headers_are_trusted() {
        let connect_ip = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 55));
        let request = request_with_connect_ip(connect_ip);

        assert_eq!(
            extract_ip_with_proxy_trust(&request, true),
            IpAddr::V4(Ipv4Addr::new(203, 0, 113, 10))
        );
    }
}
