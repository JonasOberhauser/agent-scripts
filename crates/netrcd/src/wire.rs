//! The socket protocol: one JSON line per request, one JSON line per
//! response, one request per connection. Typed on both ends; malformed
//! frames never reach adjudication.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

use crate::policy::Method;
use crate::policy::method_names_with_any;
use crate::Request;

/// Cap a single wire line (the request body rides inside the JSON).
/// A hostile client can exceed it only to be disconnected.
pub const WIRE_MAX: usize = 16 << 20;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WireRequest {
    pub op: String,
    pub machine: String,
    pub method: String,
    pub url: String,
    #[serde(default)]
    pub headers: BTreeMap<String, String>,
    #[serde(default)]
    pub body: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ErrorCode {
    /// The frame could not be parsed or validated.
    BadRequest,
    /// `op` is not "request".
    UnknownOp,
    /// No profile loaded for the machine (or its profile was refused).
    UnknownMachine,
    /// Known machine, but no grant rule matched.
    NotAllowed,
    /// Machine has no netrc credential.
    NoCredentials,
    TooLarge,
    RateLimited,
    /// The TLS peer failed SPKI pin verification: possible MITM, or a
    /// site CA rotation.
    PinMismatch,
    UpstreamTls,
    Upstream,
    Internal,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "op")]
pub enum WireResponse {
    #[serde(rename = "response")]
    Response {
        status: u16,
        #[serde(default)]
        headers: BTreeMap<String, String>,
        body: String,
        #[serde(default)]
        truncated: bool,
    },
    #[serde(rename = "error")]
    Error { code: ErrorCode, detail: String },
}

impl WireResponse {
    pub fn error(code: ErrorCode, detail: impl Into<String>) -> WireResponse {
        WireResponse::Error { code, detail: detail.into() }
    }
}

/// Validate a wire frame into a typed [`Request`]. Every failure is a
/// `BadRequest` whose detail names the problem and the valid shapes.
pub fn validate(req: &WireRequest) -> Result<Request, WireResponse> {
    if req.op != "request" {
        return Err(WireResponse::error(
            ErrorCode::UnknownOp,
            format!("op {:?} unknown — only \"request\" exists", req.op),
        ));
    }
    let method = Method::parse(req.method.trim()).ok_or_else(|| {
        WireResponse::error(
            ErrorCode::BadRequest,
            format!(
                "method {:?} unknown — expected one of {}",
                req.method,
                method_names_with_any()
            ),
        )
    })?;
    let url = req.url.trim().to_string();
    if !url.starts_with('/') {
        return Err(WireResponse::error(
            ErrorCode::BadRequest,
            "url must be an absolute path starting with '/' (host comes from the machine)",
        ));
    }
    if url.len() > 8192 || url.bytes().any(|b| b <= b' ' || b == 0x7f) {
        return Err(WireResponse::error(
            ErrorCode::BadRequest,
            "url is malformed (too long, or contains whitespace/control bytes)",
        ));
    }
    // Path normalization is REFUSED, not canonicalized: `..`, `.` and
    // empty segments (from `//`) are where allowlist matching leaks.
    let path = url.split('?').next().unwrap_or("");
    for seg in path.split('/') {
        if seg == ".." || seg == "." {
            return Err(WireResponse::error(
                ErrorCode::BadRequest,
                "url path contains '.' or '..' segments — refusing",
            ));
        }
    }
    if url.contains("//") {
        return Err(WireResponse::error(
            ErrorCode::BadRequest,
            "url path contains '//' — refusing",
        ));
    }
    let headers = req
        .headers
        .iter()
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect::<Vec<_>>();
    let body = req.body.as_ref().map(|b| b.as_bytes().to_vec());
    Ok(Request {
        machine: req.machine.trim().to_ascii_lowercase(),
        method,
        url,
        headers,
        body,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn frame() -> WireRequest {
        WireRequest {
            op: "request".into(),
            machine: "GitHub.com".into(),
            method: "GET".into(),
            url: "/zen".into(),
            headers: BTreeMap::new(),
            body: None,
        }
    }

    #[test]
    fn valid_frame_normalizes_machine_case() {
        let req = validate(&frame()).unwrap();
        assert_eq!(req.machine, "github.com");
    }

    #[test]
    fn pony_method_is_rejected_with_the_vocabulary() {
        let mut f = frame();
        f.method = "pony".into();
        let err = validate(&f).unwrap_err();
        match err {
            WireResponse::Error { code, detail } => {
                assert_eq!(code, ErrorCode::BadRequest);
                assert!(detail.contains("GET") && detail.contains("OPTIONS"), "{detail}");
            }
            _ => panic!(),
        }
    }

    #[test]
    fn unknown_op_is_rejected() {
        let mut f = frame();
        f.op = "fetch".into();
        assert!(matches!(validate(&f), Err(WireResponse::Error { code: ErrorCode::UnknownOp, .. })));
    }

    #[test]
    fn url_shapes_fail_closed() {
        for bad in ["zen", "https://x.com/zen", "/a//b", "/a/../b", "/a/./b"] {
            let mut f = frame();
            f.url = bad.into();
            assert!(validate(&f).is_err(), "{bad} must be refused");
        }
        let mut f = frame();
        f.url = "/zen?a=b&c=d".into();
        assert_eq!(validate(&f).unwrap().url, "/zen?a=b&c=d");
    }
}
