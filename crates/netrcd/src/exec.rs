//! Outbound execution: the only place credentials touch the network.
//! Static curl+openssl (deterministic linkage), SPKI pinning via
//! `CURLOPT_PINNEDPUBLICKEY` (any-of against the presented chain),
//! response capping per machine policy.

use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;
use std::time::Duration;

use crate::policy::Method;

/// Everything the policy layer decided, fully resolved: destination,
/// headers (including the rendered credential), pins, limits.
#[derive(Debug, Clone)]
pub struct OutboundRequest {
    pub url: String,
    pub method: Method,
    pub headers: Vec<(String, String)>,
    pub body: Option<Vec<u8>>,
    /// `sha256//…` pins, any-of.
    pub pins: Vec<String>,
    pub timeout: Duration,
    pub max_rsp: usize,
}

#[derive(Debug, Clone)]
pub struct UpstreamResponse {
    pub status: u16,
    pub headers: std::collections::BTreeMap<String, String>,
    pub body: Vec<u8>,
    pub truncated: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExecError {
    PinMismatch,
    Tls(String),
    Io(String),
}

pub trait Executor: Send + Sync {
    fn execute(&self, req: &OutboundRequest) -> Result<UpstreamResponse, ExecError>;
}

/// libcurl executor. `ca_path` exists for the loopback TLS tests;
/// production leaves it None (system store) — pins are the real gate.
pub struct RealExecutor {
    pub ca_path: Option<std::path::PathBuf>,
}

struct Collector {
    headers: Vec<u8>,
    body: Vec<u8>,
    max: usize,
    truncated: bool,
}

impl curl::easy::Handler for Collector {
    fn write(&mut self, data: &[u8]) -> Result<usize, curl::easy::WriteError> {
        if self.body.len() + data.len() > self.max {
            let room = self.max.saturating_sub(self.body.len());
            self.body.extend_from_slice(&data[..room]);
            self.truncated = true;
            // Swallow the rest so libcurl does not treat this as a
            // hard write error; we report truncation ourselves.
            return Ok(data.len());
        }
        self.body.extend_from_slice(data);
        Ok(data.len())
    }
    fn header(&mut self, data: &[u8]) -> bool {
        if self.headers.len() < 64 << 10 {
            self.headers.extend_from_slice(data);
        }
        true
    }
}

impl Executor for RealExecutor {
    fn execute(&self, req: &OutboundRequest) -> Result<UpstreamResponse, ExecError> {
        let mut easy = curl::easy::Easy2::new(Collector {
            headers: Vec::new(),
            body: Vec::new(),
            max: req.max_rsp,
            truncated: false,
        });
        let setup = |easy: &mut curl::easy::Easy2<Collector>| -> Result<(), curl::Error> {
            easy.url(&req.url)?;
            if req.method != Method::Get {
                easy.custom_request(req.method.name())?;
            }
            if let Some(body) = &req.body {
                easy.post_fields_copy(body)?;
            }
            let mut list = curl::easy::List::new();
            for (name, value) in &req.headers {
                list.append(&format!("{name}: {value}"))?;
            }
            easy.http_headers(list)?;
            if !req.pins.is_empty() {
                easy.pinned_public_key(&req.pins.join(";"))?;
            }
            if let Some(ca) = &self.ca_path {
                easy.cainfo(ca)?;
            }
            easy.timeout(req.timeout)?;
            easy.connect_timeout(req.timeout.min(Duration::from_secs(10)))?;
            // Redirects are not followed: a redirect could carry the
            // Authorization header to a different host. If a site
            // needs redirects, allow the final URL in a rule instead.
            easy.follow_location(false)?;
            Ok(())
        };
        setup(&mut easy).map_err(|e| ExecError::Io(e.to_string()))?;
        easy.perform().map_err(classify_curl_error)?;
        let status = easy.response_code().map_err(|e| ExecError::Io(e.to_string()))?;
        let coll = easy.get_ref();
        let headers = parse_header_block(&String::from_utf8_lossy(&coll.headers));
        Ok(UpstreamResponse {
            status: status as u16,
            headers,
            body: coll.body.clone(),
            truncated: coll.truncated,
        })
    }
}

/// Map libcurl failures: CURLE_SSL_PINNEDPUBKEYNOTMATCH (90) is the
/// "possible MITM or CA rotation" case; CURLE_PEER_FAILED_VERIFICATION
/// (60) covers generic trust failures.
fn classify_curl_error(e: curl::Error) -> ExecError {
    const CURLE_PEER_FAILED_VERIFICATION: u32 = 60;
    const CURLE_SSL_PINNEDPUBKEYNOTMATCH: u32 = 90;
    match e.code() {
        CURLE_SSL_PINNEDPUBKEYNOTMATCH => ExecError::PinMismatch,
        CURLE_PEER_FAILED_VERIFICATION => ExecError::Tls(e.to_string()),
        _ => ExecError::Io(e.to_string()),
    }
}

/// Parse a raw HTTP header block (status line + headers, possibly with
/// digest continuation lines) into name → value (later duplicates win).
fn parse_header_block(raw: &str) -> std::collections::BTreeMap<String, String> {
    let mut map = std::collections::BTreeMap::new();
    for line in raw.lines() {
        if line.is_empty() || !line.contains(':') || line.starts_with("HTTP/") {
            continue;
        }
        if line.starts_with(' ') || line.starts_with('\t') {
            continue; // continuation of a folded header: skipped, not guessed
        }
        let Some((name, value)) = line.split_once(':') else { continue };
        map.insert(name.trim().to_string(), value.trim().to_string());
    }
    map
}

/// The client side of the socket, shared by `nrq` and tests: one JSON
/// line in, one JSON line out.
pub fn request_over_socket(
    socket: &std::path::Path,
    req: &crate::wire::WireRequest,
) -> Result<crate::wire::WireResponse, String> {
    let mut stream = UnixStream::connect(socket).map_err(|e| format!("connect {}: {e}", socket.display()))?;
    stream
        .set_read_timeout(Some(Duration::from_secs(300)))
        .map_err(|e| e.to_string())?;
    let line = serde_json::to_string(req).map_err(|e| e.to_string())?;
    stream
        .write_all(format!("{line}\n").as_bytes())
        .map_err(|e| format!("send: {e}"))?;
    let mut reader = BufReader::new(stream);
    let mut response = String::new();
    reader
        .read_line(&mut response)
        .map_err(|e| format!("recv: {e}"))?;
    if response.is_empty() {
        return Err("connection closed without a response".into());
    }
    serde_json::from_str(response.trim())
        .map_err(|e| format!("malformed response frame: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn header_block_parses_names_and_skips_status_and_folds() {
        let raw = "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nX-Long: part one\r\n  continued\r\nX-Dup: first\r\nX-Dup: second\r\n\r\n";
        let h = parse_header_block(raw);
        assert_eq!(h.get("Content-Type").unwrap(), "application/json");
        assert_eq!(h.get("X-Dup").unwrap(), "second", "later duplicates win");
        assert!(h.get("X-Long").map(|v| v.as_str()) == Some("part one"));
    }
}
