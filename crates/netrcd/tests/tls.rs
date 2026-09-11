//! Loopback TLS tests with a real (static-curl) executor: a local
//! rustls server with a self-signed rcgen certificate stands in for
//! the upstream. Covers the trust path end to end: CA-verified
//! success without pins, and fail-closed pin mismatch (the
//! "possible MITM" case).

use std::io::Write as _;
use std::sync::Arc;

use netrcd::exec::{ExecError, Executor, OutboundRequest, RealExecutor};
use netrcd::policy::Method;

/// Serve one HTTPS request: read whatever the client sends, answer
/// with a minimal 200. Blocks until one request is served.
fn serve_one(
    listener: std::net::TcpListener,
    config: Arc<rustls::ServerConfig>,
    body: std::sync::Arc<std::sync::Mutex<Option<Vec<u8>>>>,
    status_line: std::sync::Arc<std::sync::Mutex<Option<String>>>,
) {
    let (stream, _) = listener.accept().expect("accept");
    let mut conn = rustls::ServerConnection::new(config).expect("server conn");
    let mut stream = stream;
    let _ = conn.complete_io(&mut stream);
    let mut tls = conn;
    let _ = tls.read_tls(&mut stream);
    let _ = tls.write_tls(&mut stream);
    let _ = tls.process_new_packets();
    let body = body.lock().unwrap().clone().unwrap_or_else(|| b"ok".to_vec());
    let status = status_line
        .lock()
        .unwrap()
        .clone()
        .unwrap_or_else(|| "HTTP/1.1 200 OK\r\nConnection: close\r\n".into());
    let head = format!("{status}Content-Length: {}\r\n", body.len());
    let mut response = head.into_bytes();
    response.extend_from_slice(b"\r\n");
    response.extend_from_slice(&body);
    let _ = tls.writer().write_all(&response);
    let _ = tls.write_tls(&mut stream);
}

struct TestPeer {
    cert_pem: String,
    port: u16,
    _dir: tempfile::TempDir,
    body_override: std::sync::Arc<std::sync::Mutex<Option<Vec<u8>>>>,
    status_override: std::sync::Arc<std::sync::Mutex<Option<String>>>,
}

/// Stand up a loopback TLS listener with a fresh self-signed cert for
/// 127.0.0.1. Returns the CA PEM (to trust) and the port.
fn spawn_peer() -> TestPeer {
    let cert = rcgen::generate_simple_self_signed(vec!["127.0.0.1".to_string()])
        .expect("generate cert");
    let cert_der = cert.cert.der().clone();
    let key_der = cert.key_pair.serialize_der();
    let cert_pem = cert.cert.pem().to_string();

    let config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(
            vec![cert_der],
            rustls::pki_types::PrivateKeyDer::Pkcs8(rustls::pki_types::PrivatePkcs8KeyDer::from(
                key_der,
            )),
        )
        .expect("server config");

    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
    let port = listener.local_addr().unwrap().port();
    let body: std::sync::Arc<std::sync::Mutex<Option<Vec<u8>>>> = Default::default();
    let status: std::sync::Arc<std::sync::Mutex<Option<String>>> = Default::default();
    let (b2, s2) = (Arc::clone(&body), Arc::clone(&status));
    std::thread::spawn(move || serve_one(listener, Arc::new(config), b2, s2));

    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("ca.pem"), &cert_pem).unwrap();
    TestPeer { cert_pem, port, _dir: dir, body_override: body, status_override: status }
}

fn outbound(port: u16, pins: Vec<String>) -> OutboundRequest {
    OutboundRequest {
        url: format!("https://127.0.0.1:{port}/zen"),
        method: Method::Get,
        headers: vec![("Authorization".into(), "Bearer sekrit".into())],
        body: None,
        pins,
        timeout: std::time::Duration::from_secs(10),
        max_rsp: 1 << 20,
    }
}

#[test]
fn ca_verified_request_without_pins_succeeds() {
    let peer = spawn_peer();
    let exec = RealExecutor {
        ca_path: Some(peer._dir.path().join("ca.pem")),
    };
    let resp = exec.execute(&outbound(peer.port, vec![])).expect("request should succeed");
    assert_eq!(resp.status, 200);
    assert_eq!(resp.body, b"ok");
}

#[test]
fn wrong_pin_fails_closed_as_pin_mismatch() {
    let peer = spawn_peer();
    let exec = RealExecutor {
        ca_path: Some(peer._dir.path().join("ca.pem")),
    };
    // A structurally valid pin (32 bytes) for the WRONG key: even
    // with the CA trusted, the pin check must kill the handshake.
    let wrong = "sha256//AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
    let err = exec
        .execute(&outbound(peer.port, vec![wrong.to_string()]))
        .expect_err("pin mismatch must fail closed");
    assert_eq!(err, ExecError::PinMismatch, "{err:?}");
}

#[test]
fn untrusted_ca_without_pins_fails_closed() {
    let peer = spawn_peer();
    // System store (no ca_path): the self-signed peer is not trusted.
    let exec = RealExecutor { ca_path: None };
    let err = exec.execute(&outbound(peer.port, vec![])).expect_err("must fail");
    assert!(
        matches!(err, ExecError::Tls(_) | ExecError::Io(_)),
        "{err:?}"
    );
    let _ = &peer.cert_pem; // keep the peer alive through the request
}


#[test]
fn response_truncation_flags_and_caps() {
    let peer = spawn_peer();
    *peer.body_override.lock().unwrap() = Some(vec![b'x'; 4096]);
    let exec = RealExecutor {
        ca_path: Some(peer._dir.path().join("ca.pem")),
    };
    let mut req = outbound(peer.port, vec![]);
    req.max_rsp = 1024; // policy cap far below the body
    let resp = exec.execute(&req).expect("request succeeds");
    assert!(resp.truncated, "must be flagged");
    assert_eq!(resp.body.len(), 1024, "capped at max_rsp");
}

#[test]
fn redirects_are_not_followed() {
    let peer = spawn_peer();
    // The peer answers 302 to a different host. Following it would
    // carry the Authorization header cross-origin; curl must hand us
    // the 302 as-is.
    *peer.status_override.lock().unwrap() =
        Some("HTTP/1.1 302 Found\r\nLocation: https://127.0.0.1:1/evil\r\n".into());
    let exec = RealExecutor {
        ca_path: Some(peer._dir.path().join("ca.pem")),
    };
    let resp = exec.execute(&outbound(peer.port, vec![])).expect("request succeeds");
    assert_eq!(resp.status, 302);
}
