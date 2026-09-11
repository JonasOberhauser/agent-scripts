//! The policy language: typed TOML structs, validated and compiled
//! (regexes, pins, templates) at load time — a value that exists is
//! well-formed.
//!
//! Two layers with disjoint vocabularies, enforced by distinct types:
//!
//! * **profiles** (shareable facts about a site): `auth`, `pins`,
//!   fixed `headers`
//! * **grants** (user-level permits): `allow` rules, `rate`,
//!   `max_req`, `max_rsp`, `timeout`
//!
//! ```toml
//! # profiles.d/github.com.toml
//! [[machine]]
//! name = "github.com"
//! auth = "bearer"
//! pins = ["sha256//ZSa…", "sha256//S2L…"]
//!
//!   [machine.headers]
//!   "X-GitHub-Api-Version" = "2022-11-28"
//!
//! # config.d/github.com.toml
//! [[machine]]
//! name = "github.com"
//! rate = "30/min"
//!
//!   [[machine.allow]]
//!   method = "POST"
//!   url = '/v1/chat/completions'
//!   headers = ['Content-Type: application/json']
//!   body = ['\{"model":"gpt-4o[^"]*"']
//! ```

use std::time::Duration;

use serde::Deserialize;

// ── wire-independent primitives ─────────────────────────────────

/// HTTP methods the policy can name. Closed vocabulary: a typo dies
/// at load with the full valid list, never at request time.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Method {
    Get,
    Post,
    Put,
    Patch,
    Delete,
    Head,
    Options,
}

pub const METHODS: &[(&str, Method)] = &[
    ("GET", Method::Get),
    ("POST", Method::Post),
    ("PUT", Method::Put),
    ("PATCH", Method::Patch),
    ("DELETE", Method::Delete),
    ("HEAD", Method::Head),
    ("OPTIONS", Method::Options),
];

impl Method {
    pub fn parse(s: &str) -> Option<Method> {
        METHODS
            .iter()
            .find(|(n, _)| *n == s)
            .map(|(_, m)| *m)
    }

    pub fn name(self) -> &'static str {
        METHODS
            .iter()
            .find(|(_, m)| *m == self)
            .map(|(n, _)| *n)
            .unwrap()
    }
}

pub fn method_names_with_any() -> String {
    let mut names: Vec<&str> = METHODS.iter().map(|(n, _)| *n).collect();
    names.push("*");
    names.join(", ")
}

/// How the credential is presented — the client-side "translation"
/// of a netrc entry into the site's auth scheme. Config may format
/// (fixed template over `{login}`/`{password}`), never compute.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Auth {
    /// `Authorization: Basic base64(login:password)`
    Basic,
    /// `Authorization: Bearer password`
    Bearer,
    /// Arbitrary fixed header: `Header { name, template }` rendered
    /// with `{login}`/`{password}`.
    Header { name: String, template: String },
}

impl Auth {
    /// Parse the `auth` value: `basic`, `bearer`, or
    /// `header: <Name>: <template>`.
    pub fn parse(raw: &str) -> Result<Auth, String> {
        let raw = raw.trim();
        match raw {
            "basic" => Ok(Auth::Basic),
            "bearer" => Ok(Auth::Bearer),
            _ => {
                let Some(rest) = raw.strip_prefix("header:") else {
                    return Err(format!(
                        "auth must be `basic`, `bearer`, or `header: <Name>: <template>` — got {raw:?}"
                    ));
                };
                let rest = rest.trim_start();
                let Some((name, template)) = rest.split_once(':') else {
                    return Err(format!(
                        "header auth needs `header: <Name>: <template>` — got {raw:?}"
                    ));
                };
                let name = name.trim();
                let template = template.trim();
                if name.is_empty() || !name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-') {
                    return Err(format!("header name {name:?} is not a valid token"));
                }
                validate_template(template)?;
                Ok(Auth::Header {
                    name: name.to_string(),
                    template: template.to_string(),
                })
            }
        }
    }

    /// The header names this auth OWNS: client-supplied headers with
    /// these names are dropped, netrcd's values always win.
    pub fn owned_headers(&self) -> Vec<String> {
        match self {
            Auth::Basic | Auth::Bearer => vec!["authorization".into()],
            Auth::Header { name, .. } => vec![name.to_ascii_lowercase()],
        }
    }

    /// Render the Authorization/header value. The credential's only
    /// journey: netrc → this string → TLS.
    pub fn render(&self, login: &str, password: &str) -> (String, String) {
        match self {
            Auth::Basic => {
                use base64::Engine as _;
                let value = base64::engine::general_purpose::STANDARD
                    .encode(format!("{login}:{password}"));
                ("Authorization".into(), value)
            }
            Auth::Bearer => ("Authorization".into(), format!("Bearer {password}")),
            Auth::Header { name, template } => {
                (name.clone(), render_template(template, login, password))
            }
        }
    }
}

/// Only `{login}` and `{password}` are valid placeholders; anything
/// else in braces is a typo that must fail closed.
pub fn validate_template(template: &str) -> Result<(), String> {
    let mut rest = template;
    while let Some(start) = rest.find('{') {
        let after = &rest[start + 1..];
        let Some(end) = after.find('}') else {
            return Err(format!("template {template:?} has an unclosed '{{'"));
        };
        let token = &after[..end];
        if token != "login" && token != "password" {
            return Err(format!(
                "template placeholder {{{token}}} unknown — only {{login}} and {{password}} are defined"
            ));
        }
        rest = &after[end + 1..];
    }
    Ok(())
}

pub fn render_template(template: &str, login: &str, password: &str) -> String {
    template.replace("{login}", login).replace("{password}", password)
}

// ── raw TOML shapes (serde) ──────────────────────────────────────

/// Values keep their spans so validation and merge diagnostics can
/// name `file:line`.
pub type Spanned = toml::Spanned<String>;

pub fn deser_machine_name(s: &str) -> Result<String, String> {
    let name = s.trim().to_ascii_lowercase();
    if name.is_empty() || name.contains(char::is_whitespace) {
        return Err(format!("machine name {s:?} is not a hostname"));
    }
    Ok(name)
}

/// One profile entry as written in a TOML file. `deny_unknown_fields`
/// makes typos load errors instead of silent ignores, and confines the
/// profile vocabulary to facts.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProfileFile {
    #[serde(default)]
    pub machine: Vec<ProfileMachine>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProfileMachine {
    pub name: Spanned,
    pub auth: Option<Spanned>,
    #[serde(default)]
    pub pins: Vec<Spanned>,
    #[serde(default)]
    pub headers: std::collections::BTreeMap<String, Spanned>,
}

/// One grant entry. The grant vocabulary is permits only: putting a
/// fact key (`auth`, `pins`) here is a load error.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GrantFile {
    #[serde(default)]
    pub machine: Vec<GrantMachine>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GrantMachine {
    pub name: Spanned,
    #[serde(default)]
    pub allow: Vec<AllowRuleRaw>,
    pub rate: Option<Spanned>,
    pub max_req: Option<Spanned>,
    pub max_rsp: Option<Spanned>,
    pub timeout: Option<Spanned>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AllowRuleRaw {
    pub method: Spanned,
    pub url: Spanned,
    #[serde(default)]
    pub headers: Vec<Spanned>,
    #[serde(default)]
    pub body: Vec<Spanned>,
}

/// The plain (unspanned) shape a raw rule is lowered into before
/// compilation.
#[derive(Debug, Clone)]
pub struct AllowRule {
    pub method: String,
    pub url: String,
    pub headers: Vec<String>,
    pub body: Vec<String>,
}

// ── compiled (validated) shapes ─────────────────────────────────

/// A compiled allow rule: method matcher + auto-anchored url regex +
/// conjunctive header/body matchers.
#[derive(Debug, Clone)]
pub struct CompiledRule {
    pub any_method: bool,
    pub method: Method,
    pub url: regex::Regex,
    pub headers: Vec<regex::Regex>,
    pub body: Vec<regex::Regex>,
}

/// Per-machine rate limit: `count` requests per `window`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rate {
    pub count: u32,
    pub window: Duration,
}

impl Rate {
    pub fn parse(raw: &str) -> Result<Rate, String> {
        let Some((count, unit)) = raw.trim().split_once('/') else {
            return Err(format!("rate must look like `30/min` — got {raw:?}"));
        };
        let count: u32 = count
            .trim()
            .parse()
            .map_err(|_| format!("rate count in {raw:?} is not a number"))?;
        let window = match unit.trim() {
            "s" | "sec" | "second" | "seconds" => Duration::from_secs(1),
            "min" | "minute" | "minutes" => Duration::from_secs(60),
            "h" | "hour" | "hours" => Duration::from_secs(3600),
            u => return Err(format!("rate unit {u:?} unknown (s, min, h)")),
        };
        if count == 0 {
            return Err(format!("rate {raw:?} allows nothing — remove the rule instead"));
        }
        Ok(Rate { count, window })
    }
}

/// Byte size with units: `1 MiB`, `512 KiB`, `1024`.
pub fn parse_size(raw: &str) -> Result<usize, String> {
    let raw = raw.trim();
    let (num, mult) = match raw
        .strip_suffix("GiB")
        .map(|n| (n, 1 << 30))
        .or_else(|| raw.strip_suffix("MiB").map(|n| (n, 1 << 20)))
        .or_else(|| raw.strip_suffix("KiB").map(|n| (n, 1 << 10)))
        .or_else(|| raw.strip_suffix('B').map(|n| (n, 1)))
    {
        Some(v) => v,
        None => (raw, 1),
    };
    let n: usize = num
        .trim()
        .parse()
        .map_err(|_| format!("size {raw:?} is not a number"))?;
    Ok(n * mult)
}

pub fn parse_timeout(raw: &str) -> Result<Duration, String> {
    let raw = raw.trim();
    let (n, unit) = raw
        .strip_suffix("ms")
        .map(|n| (n, 1u64))
        .or_else(|| raw.strip_suffix('s').map(|n| (n, 1000)))
        .ok_or_else(|| format!("timeout must look like `30s` or `500ms` — got {raw:?}"))?;
    let n: u64 = n
        .trim()
        .parse()
        .map_err(|_| format!("timeout value in {raw:?} is not a number"))?;
    if n == 0 {
        return Err(format!("timeout {raw:?} is zero"));
    }
    Ok(Duration::from_millis(n * unit))
}

/// A normalized `sha256//BASE64` SPKI pin, as libcurl expects it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Pin(pub String);

pub fn parse_pin(raw: &str) -> Result<Pin, String> {
    let Some(b64) = raw.strip_prefix("sha256//") else {
        return Err(format!("pin must be `sha256//<base64>` — got {raw:?}"));
    };
    use base64::Engine as _;
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(b64.trim())
        .map_err(|e| format!("pin {raw:?} is not base64: {e}"))?;
    if bytes.len() != 32 {
        return Err(format!(
            "pin {raw:?} decodes to {} bytes — a sha256 SPKI pin is 32",
            bytes.len()
        ));
    }
    Ok(Pin(format!("sha256//{}", b64.trim())))
}

/// Compile an allow rule: method against the closed vocabulary,
/// url/header/body regexes auto-anchored (`^(?:…)$` — unanchored
/// patterns are the classic allowlist bypass).
pub fn compile_rule(rule: &AllowRule) -> Result<CompiledRule, String> {
    let method_raw = rule.method.trim();
    let (any_method, method) = if method_raw == "*" {
        (true, Method::Get)
    } else {
        let m = Method::parse(method_raw).ok_or_else(|| {
            format!(
                "method {method_raw:?} unknown — expected one of {}",
                method_names_with_any()
            )
        })?;
        (false, m)
    };
    // The URL is matched as a WHOLE (auto-anchored): partial-path
    // matches are the classic allowlist bypass. Header/body matchers
    // use find semantics — the interesting part of a body is rarely
    // the whole body — and authors anchor explicitly with ^…$ when
    // they want exact matches.
    let url = compile_anchored(&rule.url)?;
    let mut headers = Vec::new();
    for h in &rule.headers {
        headers.push(compile_plain(h)?);
    }
    let mut body = Vec::new();
    for b in &rule.body {
        body.push(compile_plain(b)?);
    }
    Ok(CompiledRule {
        any_method,
        method,
        url,
        headers,
        body,
    })
}

/// Compile with the auto-anchor wrapper. The `regex` crate is
/// linear-time (no ReDoS) and has no lookaround — permits must be
/// expressed positively.
pub fn compile_anchored(pattern: &str) -> Result<regex::Regex, String> {
    regex::Regex::new(&format!("^(?:{pattern})$"))
        .map_err(|e| format!("regex {pattern:?} does not compile: {e}"))
}

/// Compile a find-semantics matcher (header/body).
pub fn compile_plain(pattern: &str) -> Result<regex::Regex, String> {
    regex::Regex::new(pattern).map_err(|e| format!("regex {pattern:?} does not compile: {e}"))
}

/// A fully validated machine profile: facts only.
#[derive(Debug, Clone)]
pub struct ValidProfile {
    pub name: String,
    pub auth: Auth,
    pub pins: Vec<Pin>,
    pub headers: Vec<(String, String)>,
}

/// A fully validated machine grant: permits only.
#[derive(Debug, Clone)]
pub struct ValidGrant {
    pub name: String,
    pub allows: Vec<CompiledRule>,
    pub rate: Option<Rate>,
    pub max_req: usize,
    pub max_rsp: usize,
    pub timeout: Duration,
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine as _;

    #[test]
    fn method_vocabulary_is_closed() {
        assert!(Method::parse("GET").is_some());
        assert!(Method::parse("get").is_none(), "case-sensitive, like HTTP");
        assert!(Method::parse("pony").is_none());
    }

    #[test]
    fn auth_parses_all_forms() {
        assert_eq!(Auth::parse("basic").unwrap(), Auth::Basic);
        assert_eq!(Auth::parse("bearer").unwrap(), Auth::Bearer);
        match Auth::parse("header: X-Api-Key: {password}").unwrap() {
            Auth::Header { name, template } => {
                assert_eq!(name, "X-Api-Key");
                assert_eq!(template, "{password}");
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn auth_rejects_garbage() {
        assert!(Auth::parse("digest").unwrap_err().contains("basic"));
        assert!(Auth::parse("header: NoColon").unwrap_err().contains("template"));
        assert!(Auth::parse("header: X: {token}").unwrap_err().contains("placeholder"));
    }

    #[test]
    fn auth_render_journeys() {
        assert_eq!(
            Auth::Basic.render("u", "p"),
            ("Authorization".into(), "dTpw".into())
        );
        assert_eq!(
            Auth::Bearer.render("u", "s3cret"),
            ("Authorization".into(), "Bearer s3cret".into())
        );
        assert_eq!(
            Auth::Header {
                name: "X-Key".into(),
                template: "{login}.{password}".into()
            }
            .render("u", "p"),
            ("X-Key".into(), "u.p".into())
        );
    }

    #[test]
    fn owned_headers_guide_the_drop_rule() {
        assert_eq!(
            Auth::Bearer.owned_headers(),
            vec!["authorization".to_string()]
        );
        assert_eq!(
            Auth::Header {
                name: "X-Key".into(),
                template: "{password}".into()
            }
            .owned_headers(),
            vec!["x-key".to_string()]
        );
    }

    #[test]
    fn pins_must_be_sha256_base64_32_bytes() {
        assert!(parse_pin("sha256//AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=").is_ok());
        assert!(parse_pin("sha256//short").is_err());
        assert!(parse_pin("pin-sha256:xyz").is_err());
        // 31 bytes of zeros
        let bad = base64::engine::general_purpose::STANDARD.encode([0u8; 31]);
        assert!(parse_pin(&format!("sha256//{bad}")).unwrap_err().contains("32"));
    }

    #[test]
    fn rules_compile_anchored() {
        let rule = AllowRule {
            method: "POST".into(),
            url: "/v1/chat".into(),
            headers: vec!["Content-Type: application/json".into()],
            body: vec![],
        };
        let c = compile_rule(&rule).unwrap();
        assert!(c.url.is_match("/v1/chat"));
        assert!(!c.url.is_match("/v1/chat/extra"), "auto-anchor holds");
    }

    #[test]
    fn unanchored_look_is_impossible_and_pony_dies() {
        let err = compile_rule(&AllowRule {
            method: "pony".into(),
            url: "/x".into(),
            headers: vec![],
            body: vec![],
        })
        .unwrap_err();
        assert!(err.contains("GET") && err.contains("OPTIONS") && err.contains('*'), "{err}");
        assert!(compile_rule(&AllowRule {
            method: "GET".into(),
            url: "(".into(),
            headers: vec![],
            body: vec![],
        })
        .unwrap_err()
        .contains("does not compile"));
    }

    #[test]
    fn units_parse() {
        assert_eq!(parse_size("1 MiB").unwrap(), 1 << 20);
        assert_eq!(parse_size("512").unwrap(), 512);
        assert_eq!(Rate::parse("30/min").unwrap().count, 30);
        assert!(Rate::parse("30/fortnight").unwrap_err().contains("unit"));
        assert_eq!(parse_timeout("500ms").unwrap(), Duration::from_millis(500));
        assert_eq!(parse_timeout("30s").unwrap(), Duration::from_secs(30));
    }
}
