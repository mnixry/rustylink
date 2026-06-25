//! Integration tests for `rustylink-outbound` — require loopback networking.
//!
//! These tests are separated from inline unit tests because they create real
//! sockets and may fail in a nix sandbox without networking (especially IPv6).

use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};

use rustylink_outbound::{Dialer, HyperConnector, NetworkSnapshot, OutboundInterface, Resolver};

// ---------------------------------------------------------------------------
// Dialer integration tests
// ---------------------------------------------------------------------------

#[tokio::test]
async fn connect_tcp_loopback_round_trip() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind listener");
    let addr = listener.local_addr().expect("local addr");

    let dialer = Dialer::default();
    let stream = dialer.connect_tcp(addr).await.expect("connect");

    // Verify TCP_NODELAY is set.
    assert!(stream.nodelay().expect("get nodelay"));
}

#[tokio::test]
async fn bind_udp_to_loopback_skips_iface_bind() {
    // Binding to a loopback DNS server should work even with a (nonexistent)
    // interface configured -- because should_bind(127.x) returns false and
    // skips the setsockopt.
    let dialer = Dialer::new(Some(OutboundInterface {
        name: "nonexistent0".to_string(),
        index: 99999,
        gateway_v4: None,
        gateway_v6: None,
    }));
    let server = SocketAddr::from((Ipv4Addr::LOCALHOST, 53));
    let _socket = dialer.bind_udp_to(server).expect("bind for loopback DNS");
}

#[tokio::test]
async fn bind_udp_pair_shares_port() {
    let dialer = Dialer::default();
    let (v4, v6) = dialer
        .bind_udp_pair(Ipv4Addr::UNSPECIFIED, Ipv6Addr::UNSPECIFIED, 0)
        .expect("bind pair");
    let port_v4 = v4.local_addr().expect("v4 addr").port();
    let port_v6 = v6.local_addr().expect("v6 addr").port();
    assert_eq!(port_v4, port_v6);
    assert_ne!(port_v4, 0);
}

#[tokio::test]
async fn bind_udp_round_trip() {
    let dialer = Dialer::default();
    let sock_a = dialer
        .bind_udp(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
        .expect("bind a");
    let sock_b = dialer
        .bind_udp(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
        .expect("bind b");
    let addr_b = sock_b.local_addr().expect("b addr");

    sock_a.send_to(b"hello", addr_b).await.expect("send");
    let mut buf = [0u8; 16];
    let (len, from) = sock_b.recv_from(&mut buf).await.expect("recv");
    assert_eq!(&buf[..len], b"hello");
    assert_eq!(from.ip(), Ipv4Addr::LOCALHOST);
}

// ---------------------------------------------------------------------------
// Snapshot integration test
// ---------------------------------------------------------------------------

#[tokio::test]
async fn snapshot_capture_runs_without_panic() {
    // On CI without a network, this may return an empty snapshot -- that's fine.
    let _snap = NetworkSnapshot::capture().await;
}

// ---------------------------------------------------------------------------
// HyperConnector integration test
// ---------------------------------------------------------------------------

#[tokio::test]
async fn hyper_connector_loopback_integration() {
    use http_body_util::{BodyExt, Full};
    use hyper::{
        Request, Response, body::Bytes, server::conn::http1 as server_http1, service::service_fn,
    };
    use hyper_util::rt::TokioIo;
    use tower::Service;

    // Start a minimal HTTP server on loopback.
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let addr = listener.local_addr().expect("addr");

    let server_task = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.expect("accept");
        let io = TokioIo::new(stream);
        let _ = server_http1::Builder::new()
            .serve_connection(
                io,
                service_fn(|_req: Request<hyper::body::Incoming>| async {
                    Ok::<_, std::convert::Infallible>(Response::new(Full::new(Bytes::from(
                        "hello from outbound test",
                    ))))
                }),
            )
            .await;
    });

    // Build a connector with an IP-literal URI (no DNS needed).
    let dialer = Dialer::default();
    let resolver = Resolver::new(dialer.clone(), vec![]);
    let mut connector = HyperConnector::new(dialer, resolver);

    let uri: http::Uri = format!("http://127.0.0.1:{}/test", addr.port())
        .parse()
        .unwrap();

    let io = connector.call(uri).await.expect("connect");

    // Drive an HTTP/1 request over the connection.
    let (mut sender, conn) = hyper::client::conn::http1::handshake(io)
        .await
        .expect("handshake");
    tokio::spawn(conn);

    let req = Request::get(format!("http://127.0.0.1:{}/test", addr.port()))
        .body(Full::<Bytes>::new(Bytes::new()))
        .unwrap();
    let resp = sender.send_request(req).await.expect("request");
    assert_eq!(resp.status(), 200);

    let body = resp.into_body().collect().await.expect("body").to_bytes();
    assert_eq!(body.as_ref(), b"hello from outbound test");

    drop(sender);
    let _ = tokio::time::timeout(std::time::Duration::from_secs(5), server_task).await;
}
