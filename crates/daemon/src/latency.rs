//! TCP-connect latency probing for dot selection.
//!
//! ICMP ping requires raw sockets (elevated privileges on Linux/macOS), so we
//! measure round-trip time with a TCP connect to the dot's API port instead.

use std::time::{Duration, Instant};

/// Default timeout for a single probe attempt.
pub const DEFAULT_PROBE_TIMEOUT: Duration = Duration::from_secs(3);

/// Default API port when the dot does not advertise one.
pub const DEFAULT_API_PORT: u16 = 443;

/// Probe latency to a host using TCP connect timing.
///
/// Returns `Some(rtt)` on a successful connect within `timeout`, or `None` if
/// the connect fails or times out.
pub async fn probe_tcp_latency(host: &str, port: u16, timeout: Duration) -> Option<Duration> {
    let addr = format!("{host}:{port}");
    let start = Instant::now();
    match tokio::time::timeout(timeout, tokio::net::TcpStream::connect(&addr)).await {
        Ok(Ok(_stream)) => Some(start.elapsed()),
        _ => None,
    }
}
