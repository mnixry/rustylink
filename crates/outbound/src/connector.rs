//! Hyper connector built on the outbound [`Dialer`] and [`Resolver`].
//!
//! [`HyperConnector`] implements [`tower::Service<http::Uri>`], producing
//! `TokioIo<TcpStream>` connections bound to the physical outbound interface.
//! It resolves hostnames via the interface-bound [`Resolver`] (not
//! `lookup_host`), making it immune to TUN routing state.

use std::{
    future::Future,
    pin::Pin,
    task::{Context, Poll},
};

use hyper_util::rt::TokioIo;
use snafu::prelude::*;
use tokio::net::TcpStream;

use crate::{Dialer, Resolver};

// ---------------------------------------------------------------------------
// Error
// ---------------------------------------------------------------------------

#[derive(Debug, Snafu)]
pub enum Error {
    #[snafu(display("URI has no host"))]
    MissingHost,

    #[snafu(display("unsupported URI scheme `{scheme}`"))]
    UnsupportedScheme { scheme: String },

    #[snafu(display("failed to resolve `{host}`: {source}"))]
    Resolve {
        host: String,
        source: crate::resolver::Error,
    },

    #[snafu(display("no addresses resolved for `{host}`"))]
    NoAddress { host: String },

    #[snafu(display("failed to connect to `{host}`: {source}"))]
    Connect {
        host: String,
        source: crate::dialer::Error,
    },
}

pub type Result<T, E = Error> = std::result::Result<T, E>;

// ---------------------------------------------------------------------------
// URI parsing
// ---------------------------------------------------------------------------

/// Parse a URI into (host, port), applying default ports by scheme.
pub fn parse_uri_host_port(uri: &http::Uri) -> Result<(String, u16)> {
    let host = uri.host().context(MissingHostSnafu)?.to_string();
    let port = uri.port_u16().unwrap_or_else(|| match uri.scheme_str() {
        Some("https") => 443,
        _ => 80,
    });
    let scheme = uri.scheme_str().unwrap_or("http");
    if scheme != "http" && scheme != "https" {
        return UnsupportedSchemeSnafu {
            scheme: scheme.to_string(),
        }
        .fail();
    }
    Ok((host, port))
}

// ---------------------------------------------------------------------------
// HyperConnector
// ---------------------------------------------------------------------------

/// A [`tower::Service<http::Uri>`] that produces `TokioIo<TcpStream>`
/// connections through the outbound [`Dialer`], with DNS resolved via
/// the interface-bound [`Resolver`].
#[derive(Clone, Debug)]
pub struct HyperConnector {
    dialer: Dialer,
    resolver: Resolver,
}

impl HyperConnector {
    /// Create a new connector with the given dialer and resolver.
    #[must_use]
    pub fn new(dialer: Dialer, resolver: Resolver) -> Self {
        Self { dialer, resolver }
    }

    async fn connect_to(
        dialer: Dialer, resolver: Resolver, uri: http::Uri,
    ) -> Result<TokioIo<TcpStream>> {
        let (host, port) = parse_uri_host_port(&uri)?;

        let addrs = resolver
            .resolve_host(&host, port)
            .await
            .context(ResolveSnafu { host: host.clone() })?;

        if addrs.is_empty() {
            return NoAddressSnafu { host }.fail();
        }

        let mut last_err = None;
        for addr in &addrs {
            match dialer.connect_tcp(*addr).await {
                Ok(stream) => return Ok(TokioIo::new(stream)),
                Err(e) => {
                    tracing::debug!(%addr, %e, "connect attempt failed, trying next");
                    last_err = Some(e);
                }
            }
        }

        Err(Error::Connect {
            host,
            // last_err is always Some here because addrs was non-empty and all
            // iterations failed.
            source: last_err.expect("at least one address was tried"),
        })
    }
}

impl tower::Service<http::Uri> for HyperConnector {
    type Response = TokioIo<TcpStream>;
    type Error = Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response>> + Send>>;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, uri: http::Uri) -> Self::Future {
        let dialer = self.dialer.clone();
        let resolver = self.resolver.clone();
        Box::pin(Self::connect_to(dialer, resolver, uri))
    }
}

// ---------------------------------------------------------------------------
// Unit tests (pure logic only — hyper integration test in tests/integration.rs)
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_uri_http_default_port() {
        let uri: http::Uri = "http://example.com/path".parse().unwrap();
        let (host, port) = parse_uri_host_port(&uri).unwrap();
        assert_eq!(host, "example.com");
        assert_eq!(port, 80);
    }

    #[test]
    fn parse_uri_https_default_port() {
        let uri: http::Uri = "https://example.com/path".parse().unwrap();
        let (host, port) = parse_uri_host_port(&uri).unwrap();
        assert_eq!(host, "example.com");
        assert_eq!(port, 443);
    }

    #[test]
    fn parse_uri_explicit_port() {
        let uri: http::Uri = "http://example.com:8080/path".parse().unwrap();
        let (host, port) = parse_uri_host_port(&uri).unwrap();
        assert_eq!(host, "example.com");
        assert_eq!(port, 8080);
    }

    #[test]
    fn parse_uri_missing_host() {
        let uri: http::Uri = "/just-a-path".parse().unwrap();
        assert!(parse_uri_host_port(&uri).is_err());
    }

    #[test]
    fn parse_uri_unsupported_scheme() {
        let uri: http::Uri = "ftp://example.com".parse().unwrap();
        let err = parse_uri_host_port(&uri).unwrap_err();
        assert!(matches!(err, Error::UnsupportedScheme { .. }));
    }
}
