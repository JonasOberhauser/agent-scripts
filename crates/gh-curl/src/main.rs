//! `gh-curl` — a single-purpose HTTP client for the GitHub API, shaped for
//! the fuse-gatekeeper secret model.
//!
//! The binary is designed to be the ONLY package the gatekeeper whitelists
//! for the token file (`~/.netrc` → `/fuse/...`). It therefore:
//!
//! * speaks HTTP **in-process** via libcurl (the `curl` crate) — no child
//!   curl process, no shell, no pass-through of curl syntax: the local-file
//!   vectors of the curl CLI (`-d @file`, `-T`, `--config @…`, `file://`)
//!   structurally do not exist here;
//! * parses the netrc itself and mirrors libcurl's matching rule exactly:
//!   credentials flow only to a URL host that **exactly (case-insensitively)
//!   matches a `machine` entry** of the netrc. Subdomains do not match; a
//!   `default` entry (which would catch every host) is rejected — the file
//!   fails closed rather than widening the allowlist;
//! * authenticates as `Authorization: Bearer <password>` (GitHub PAT
//!   semantics; the API rejects netrc's HTTP Basic form);
//! * never writes, prints, or logs the token: it appears only inside the
//!   Authorization header of an HTTPS request to an allowlisted host.
//!
//! Usage (a curated subset of curl's flags; every value is literal):
//!
//! ```text
//! gh-curl [-X METHOD] [-H 'Header: value']... [-d DATA]... [-i] URL
//! ```
//!
//! * `-X`   — request method (default: GET; POST when `-d` is given)
//! * `-H`   — request header (repeatable; replaces libcurl defaults)
//! * `-d`   — request body (repeatable, joined with `&`; a leading `@` is
//!   LITERAL text, never a file read)
//! * `-i`   — include response status line and headers in the output
//!
//! The netrc path is `$GH_CURL_NETRC` if set, else `$HOME/.netrc`. An
//! unreadable or malformed netrc is a hard error (the gatekeeper denying
//! the read surfaces here as a fail-closed exit).

use std::io::Write;
use std::process::ExitCode;

/// One parsed netrc machine entry.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Machine {
    name: String,
    login: String,
    password: String,
}

// ── netrc parsing (strict subset, fail closed) ──────────────────

/// Tokenizer state shared by the parser: words split on whitespace, values
/// optionally single- or double-quoted.
fn next_token(line: &str) -> Option<(String, &str)> {
    let rest = line.trim_start();
    if rest.is_empty() {
        return None;
    }
    let quote = rest.chars().next().filter(|c| *c == '"' || *c == '\'');
    let (tok, rest) = match quote {
        Some(q) => {
            let end = rest[1..].find(q)? + 1;
            (rest[1..end].to_string(), &rest[end + 1..])
        }
        None => {
            let end = rest.find(char::is_whitespace).unwrap_or(rest.len());
            (rest[..end].to_string(), &rest[end..])
        }
    };
    Some((tok, rest))
}

/// Validate a finished entry and store it. Entries are delimited by
/// `machine` tokens (they may span lines), so flushing happens only when
/// the next `machine` starts or at EOF.
fn finish_entry(entry: Option<Machine>, out: &mut Vec<Machine>) -> Result<(), String> {
    if let Some(m) = entry {
        if m.login.is_empty() || m.password.is_empty() {
            return Err(format!(
                "machine `{}` is missing its {} — a partial entry changes \
                 what the allowlist grants",
                m.name,
                if m.login.is_empty() { "login" } else { "password" }
            ));
        }
        out.push(m);
    }
    Ok(())
}

fn parse_netrc(text: &str) -> Result<Vec<Machine>, String> {
    let mut machines = Vec::new();
    let mut current: Option<Machine> = None;

    for (lineno, raw) in text.lines().enumerate() {
        let mut rest = raw;
        while let Some((tok, tail)) = next_token(rest) {
            rest = tail;
            match tok.as_str() {
                "machine" => {
                    finish_entry(current.take(), &mut machines)?;
                    let (name, tail) = next_token(rest)
                        .ok_or_else(|| format!("line {}: machine entry without a name", lineno + 1))?;
                    rest = tail;
                    if name.eq_ignore_ascii_case("default") {
                        return Err(format!(
                            "line {}: `default` entry refused — it would allow \
                             credentials for EVERY host",
                            lineno + 1
                        ));
                    }
                    current = Some(Machine {
                        name,
                        login: String::new(),
                        password: String::new(),
                    });
                }
                "login" => {
                    let m = current.as_mut().ok_or_else(|| {
                        format!("line {}: `login` outside any machine entry", lineno + 1)
                    })?;
                    let (v, tail) = next_token(rest)
                        .ok_or_else(|| format!("line {}: login without a value", lineno + 1))?;
                    rest = tail;
                    m.login = v;
                }
                "password" => {
                    let m = current.as_mut().ok_or_else(|| {
                        format!("line {}: `password` outside any machine entry", lineno + 1)
                    })?;
                    let (v, tail) = next_token(rest)
                        .ok_or_else(|| format!("line {}: password without a value", lineno + 1))?;
                    rest = tail;
                    m.password = v;
                }
                "default" => {
                    return Err(format!(
                        "line {}: `default` entry refused — it would allow \
                         credentials for EVERY host",
                        lineno + 1
                    ));
                }
                kw => {
                    return Err(format!(
                        "line {}: unsupported keyword `{kw}` — refusing to guess",
                        lineno + 1
                    ));
                }
            }
        }
    }
    finish_entry(current.take(), &mut machines)?;
    Ok(machines)
}

/// Load and parse the netrc file. Fail closed with an actionable message.
fn load_netrc() -> Result<Vec<Machine>, String> {
    let path = std::env::var_os("GH_CURL_NETRC")
        .map(std::path::PathBuf::from)
        .or_else(|| {
            std::env::var_os("HOME").map(|h| std::path::PathBuf::from(h).join(".netrc"))
        })
        .ok_or_else(|| "no netrc path: set GH_CURL_NETRC or HOME".to_string())?;
    let text = std::fs::read_to_string(&path)
        .map_err(|e| format!("cannot read {}: {e} — fail closed", path.display()))?;
    let machines = parse_netrc(&text)?;
    if machines.is_empty() {
        return Err(format!("{} contains no machine entries", path.display()));
    }
    Ok(machines)
}

// ── URL validation (mirrors libcurl's exact-host netrc rule) ─────

/// Validate the request URL against the netrc-derived allowlist.
///
/// Rules: `https` only; no userinfo; default port (443) only; the host must
/// exactly (case-insensitively) match a `machine` entry — subdomains do NOT
/// match, exactly like libcurl's netrc lookup.
fn validate_url<'a>(raw: &str, machines: &'a [Machine]) -> Result<(url::Url, &'a Machine), String> {
    let url = url::Url::parse(raw).map_err(|e| format!("not a valid URL: {e}"))?;
    if url.scheme() != "https" {
        return Err(format!("scheme `{}` refused — https only", url.scheme()));
    }
    if !url.username().is_empty() || url.password().is_some() {
        return Err("userinfo in the URL refused".to_string());
    }
    if url.port().is_some() {
        return Err("explicit port refused — default (443) only".to_string());
    }
    let Some(host) = url.host_str() else {
        return Err("URL has no host".to_string());
    };
    match machines.iter().find(|m| m.name.eq_ignore_ascii_case(host)) {
        Some(m) => Ok((url, m)),
        None => Err(format!(
            "host `{host}` is not a machine entry of the netrc — refused"
        )),
    }
}

// ── request ──────────────────────────────────────────────────────

/// The parsed command line. Every value is a literal string; nothing is
/// interpreted as a filename.
#[derive(Debug, Default, PartialEq)]
struct Request {
    method: Option<String>,
    headers: Vec<String>,
    data: Vec<Vec<u8>>,
    include_headers: bool,
    url: String,
}

const USAGE: &str = "usage: gh-curl [-X METHOD] [-H 'Header: value']... [-d DATA]... [-i] URL";

fn parse_args<I: IntoIterator<Item = String>>(args: I) -> Result<Request, String> {
    let mut req = Request::default();
    let mut it = args.into_iter().peekable();
    while let Some(arg) = it.next() {
        match arg.as_str() {
            "-X" | "--request" => {
                let v = it.next().ok_or("-X needs a METHOD")?;
                req.method = Some(v.to_ascii_uppercase());
            }
            "-H" | "--header" => {
                let v = it.next().ok_or("-H needs a 'Header: value'")?;
                if !v.contains(':') {
                    return Err(format!("-H value must contain ':' — got {v:?}"));
                }
                req.headers.push(v);
            }
            "-d" | "--data" => {
                let v = it.next().ok_or("-d needs DATA (a literal string)")?;
                req.data.push(v.into_bytes());
            }
            "-i" | "--include" => req.include_headers = true,
            _ if arg.starts_with('-') => {
                return Err(format!("unknown flag {arg:?} — no curl pass-through: {USAGE}"));
            }
            _ => {
                if !req.url.is_empty() {
                    return Err("multiple URLs given — exactly one is allowed".to_string());
                }
                req.url = arg;
            }
        }
    }
    if req.url.is_empty() {
        return Err(USAGE.to_string());
    }
    Ok(req)
}

/// Collects the response: header chunks (incl. the status line) and body.
struct Collector {
    headers: Vec<u8>,
    body: Vec<u8>,
}

impl curl::easy::Handler for Collector {
    fn write(&mut self, data: &[u8]) -> Result<usize, curl::easy::WriteError> {
        self.body.extend_from_slice(data);
        Ok(data.len())
    }
    fn header(&mut self, data: &[u8]) -> bool {
        self.headers.extend_from_slice(data);
        true
    }
}

/// Join repeated `-d` payloads the way curl's form mode does: `&`.
fn join_data(data: &[Vec<u8>]) -> Option<Vec<u8>> {
    if data.is_empty() {
        return None;
    }
    let mut joined = Vec::new();
    for (i, part) in data.iter().enumerate() {
        if i > 0 {
            joined.push(b'&');
        }
        joined.extend_from_slice(part);
    }
    Some(joined)
}

/// Perform the request. Returns the HTTP status code.
///
/// The token's only journey: netrc → Authorization header → TLS to the
/// allowlisted host. It is never part of any error message.
fn perform(req: &Request, url: &url::Url, token: &str) -> Result<u32, String> {
    let mut easy = curl::easy::Easy2::new(Collector { headers: Vec::new(), body: Vec::new() });
    easy.url(url.as_str()).map_err(|e| format!("request setup: {e}"))?;
    easy.connect_timeout(std::time::Duration::from_secs(10)).ok();
    easy.timeout(std::time::Duration::from_secs(120)).ok();

    let mut list = curl::easy::List::new();
    list.append(&format!("Authorization: Bearer {token}"))
        .map_err(|e| format!("request setup: {e}"))?;
    for h in &req.headers {
        list.append(h).map_err(|e| format!("bad header {h:?}: {e}"))?;
    }
    easy.http_headers(list).map_err(|e| format!("request setup: {e}"))?;

    let body = join_data(&req.data);
    match (&req.method, &body) {
        (Some(m), Some(b)) => {
            easy.custom_request(m).map_err(|e| format!("request setup: {e}"))?;
            easy.post_fields_copy(b).map_err(|e| format!("request setup: {e}"))?;
        }
        (Some(m), None) => {
            easy.custom_request(m).map_err(|e| format!("request setup: {e}"))?;
        }
        (None, Some(b)) => {
            easy.post_fields_copy(b).map_err(|e| format!("request setup: {e}"))?;
        }
        (None, None) => {}
    }

    easy.perform().map_err(|e| format!("request failed: {e}"))?;
    let status = easy.response_code().map_err(|e| format!("no response: {e}"))?;
    let resp = easy.get_ref();

    let out = std::io::stdout();
    let mut out = out.lock();
    if req.include_headers {
        let _ = out.write_all(&resp.headers);
    }
    let _ = out.write_all(&resp.body);
    let _ = out.flush();
    Ok(status)
}

fn main() -> ExitCode {
    let req = match parse_args(std::env::args().skip(1)) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("gh-curl: {e}");
            return ExitCode::from(2);
        }
    };
    let machines = match load_netrc() {
        Ok(m) => m,
        Err(e) => {
            eprintln!("gh-curl: {e}");
            return ExitCode::from(3);
        }
    };
    let (url, machine) = match validate_url(&req.url, &machines) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("gh-curl: {e}");
            return ExitCode::from(2);
        }
    };
    match perform(&req, &url, &machine.password) {
        Ok(_) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("gh-curl: {e}");
            ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn machines(list: &[(&str, &str, &str)]) -> Vec<Machine> {
        list.iter()
            .map(|&(n, l, p)| Machine {
                name: n.to_string(),
                login: l.to_string(),
                password: p.to_string(),
            })
            .collect()
    }

    // ── netrc parsing ────────────────────────────────────────────

    #[test]
    fn parses_machine_login_password() {
        let m = parse_netrc("machine github.com\nlogin token\npassword ghp_secret\n").unwrap();
        assert_eq!(
            m,
            vec![Machine {
                name: "github.com".into(),
                login: "token".into(),
                password: "ghp_secret".into(),
            }]
        );
    }

    #[test]
    fn parses_single_line_and_multiple_machines() {
        let text = "machine github.com login token password ghp_a\n \
                    machine api.github.com login token password ghp_b\n";
        let m = parse_netrc(text).unwrap();
        assert_eq!(m.len(), 2);
        assert_eq!(m[0].password, "ghp_a");
        assert_eq!(m[1].password, "ghp_b");
    }

    #[test]
    fn parses_quoted_values() {
        let m = parse_netrc("machine \"github.com\" password 'ghp s p'\nlogin t\n").unwrap();
        assert_eq!(m[0].password, "ghp s p");
    }

    #[test]
    fn default_entry_fails_closed() {
        let err = parse_netrc("machine github.com login t password p\ndefault login t password p\n")
            .unwrap_err();
        assert!(err.contains("default") && err.contains("EVERY host"), "{err}");
    }

    #[test]
    fn missing_password_fails_closed() {
        let err = parse_netrc("machine github.com\nlogin token\n").unwrap_err();
        assert!(err.contains("missing"), "{err}");
    }

    #[test]
    fn unknown_keyword_fails_closed() {
        let err = parse_netrc("machine github.com login t password p\naccount x\n").unwrap_err();
        assert!(err.contains("account"), "{err}");
    }

    #[test]
    fn empty_file_is_an_error_at_load_but_ok_at_parse() {
        assert!(parse_netrc("").unwrap().is_empty());
    }

    #[test]
    fn keyword_outside_machine_fails() {
        let err = parse_netrc("login orphan\n").unwrap_err();
        assert!(err.contains("outside"), "{err}");
    }

    // ── URL validation ───────────────────────────────────────────

    fn gh_machines() -> Vec<Machine> {
        machines(&[("github.com", "token", "ghp_x"), ("api.github.com", "token", "ghp_y")])
    }

    #[test]
    fn exact_machine_match_is_allowed() {
        let ms = gh_machines();
        assert!(validate_url("https://api.github.com/repos/x/y", &ms).is_ok());
        assert!(validate_url("https://github.com/owner/repo", &ms).is_ok());
    }

    #[test]
    fn host_match_is_case_insensitive_via_url_normalization() {
        let ms = gh_machines();
        assert!(validate_url("HTTPS://API.GitHub.Com/zen", &ms).is_ok());
    }

    #[test]
    fn subdomains_do_not_match() {
        // libcurl's netrc lookup is exact-host: evil.github.com must NOT be
        // authorized by a github.com entry.
        let ms = machines(&[("github.com", "token", "ghp_x")]);
        assert!(validate_url("https://api.github.com/zen", &ms).is_err());
        assert!(validate_url("https://evil.github.com/x", &ms).is_err());
    }

    #[test]
    fn unknown_host_refused() {
        let ms = gh_machines();
        assert!(validate_url("https://evil.com/x", &ms).is_err());
    }

    #[test]
    fn http_and_file_refused() {
        let ms = gh_machines();
        assert!(validate_url("http://api.github.com/x", &ms).is_err());
        assert!(validate_url("file:///root/.netrc", &ms).is_err());
    }

    #[test]
    fn userinfo_and_port_refused() {
        let ms = gh_machines();
        assert!(validate_url("https://x:@api.github.com/", &ms).is_err());
        assert!(validate_url("https://api.github.com:8443/x", &ms).is_err());
    }

    // ── argument parsing ─────────────────────────────────────────

    fn args(list: &[&str]) -> Vec<String> {
        list.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn plain_url_defaults_to_get() {
        let r = parse_args(args(&["https://api.github.com/zen"])).unwrap();
        assert_eq!(r.method, None);
        assert_eq!(r.url, "https://api.github.com/zen");
    }

    #[test]
    fn method_headers_data_include_parse() {
        let r = parse_args(args(&[
            "-X",
            "patch",
            "-H",
            "Content-Type: application/json",
            "-d",
            r#"{"k":1}"#,
            "-i",
            "https://api.github.com/x",
        ]))
        .unwrap();
        assert_eq!(r.method.as_deref(), Some("PATCH"));
        assert_eq!(r.headers, vec!["Content-Type: application/json"]);
        assert_eq!(r.data, vec![br#"{"k":1}"#.to_vec()]);
        assert!(r.include_headers);
    }

    #[test]
    fn repeated_data_joins_with_ampersand() {
        let r = parse_args(args(&["-d", "a=1", "-d", "b=2", "https://api.github.com/"])).unwrap();
        assert_eq!(join_data(&r.data).unwrap(), b"a=1&b=2".to_vec());
    }

    #[test]
    fn leading_at_is_literal_not_a_file() {
        // The curl CLI would read @file — here it is a plain string, and the
        // request would send the literal characters "@/root/.netrc".
        let r = parse_args(args(&["-d", "@/root/.netrc", "https://api.github.com/"])).unwrap();
        assert_eq!(r.data, vec![b"@/root/.netrc".to_vec()]);
    }

    #[test]
    fn curl_only_flags_refused() {
        for flag in ["-T", "--upload-file", "-K", "--config", "-o", "--output", "-s"] {
            assert!(parse_args(args(&[flag])).is_err(), "{flag} must be refused");
        }
    }

    #[test]
    fn multiple_urls_and_missing_values_refused() {
        assert!(parse_args(args(&["https://a.io/", "https://b.io/"])).is_err());
        assert!(parse_args(args(&["-X"])).is_err());
        assert!(parse_args(args(&["-d"])).is_err());
        assert!(parse_args(args(&[])).is_err());
    }

    // ── live request path (needs egress; harmless without a token) ──

    /// Full-path smoke test against the real API: a Bearer header with a
    /// dummy token must reach api.github.com and come back as HTTP 401 —
    /// proving URL validation, header injection and the libcurl pipeline.
    /// Run with `cargo test -p gh-curl -- --ignored`.
    #[test]
    #[ignore = "needs network egress to api.github.com"]
    fn live_request_with_dummy_token_gets_401() {
        let dir = tempfile_env();
        // Scope the env var for this test's netrc lookup.
        std::env::set_var("GH_CURL_NETRC", &dir);
        let ms = load_netrc().unwrap();
        let (url, machine) = validate_url("https://api.github.com/zen", &ms).unwrap();
        assert_eq!(machine.password, "dummy-not-a-token");
        let req = parse_args(args(&["https://api.github.com/zen"])).unwrap();
        let status = perform(&req, &url, &machine.password).unwrap();
        assert_eq!(status, 401, "dummy Bearer token must be rejected by GitHub");
        std::env::remove_var("GH_CURL_NETRC");
    }

    fn tempfile_env() -> String {
        let dir = std::env::temp_dir().join(format!("gh-curl-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let file = dir.join("netrc");
        std::fs::write(
            &file,
            "machine api.github.com\nlogin token\npassword dummy-not-a-token\n",
        )
        .unwrap();
        file.to_string_lossy().into_owned()
    }
}
