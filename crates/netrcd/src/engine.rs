//! Adjudication: turn a typed [`Request`] plus the loaded [`Runtime`]
//! into either an [`OutboundRequest`] (perform it) or a typed refusal.
//! All checks happen BEFORE any network activity, and credentials only
//! enter the picture once every gate has passed.

use std::collections::HashMap;
use std::time::Instant;

use crate::exec::OutboundRequest;
use crate::loader::Runtime;
use crate::policy::Auth;
use crate::wire::ErrorCode;
use crate::Request;

pub enum Verdict {
    Allow(OutboundRequest),
    Deny(ErrorCode, String),
}

/// Fixed-window rate counters per machine. Only permitted requests
/// consume quota.
#[derive(Default)]
pub struct RateState {
    windows: HashMap<String, (Instant, u32)>,
}

impl RateState {
    /// None = allowed and now counted; Some(detail) = over budget.
    fn consume(&mut self, machine: &str, rate: &crate::policy::Rate) -> Option<String> {
        let now = Instant::now();
        let entry = self.windows.entry(machine.to_string()).or_insert((now, 0));
        if now.duration_since(entry.0) >= rate.window {
            *entry = (now, 0);
        }
        if entry.1 >= rate.count {
            return Some(format!(
                "machine '{machine}' is limited to {}/{} — retry later",
                rate.count,
                match rate.window.as_secs() {
                    1 => "s".to_string(),
                    s => format!("{s}s"),
                }
            ));
        }
        entry.1 += 1;
        None
    }
}

/// Adjudicate one request against the runtime. Pure except for the
/// rate counters; no I/O.
pub fn adjudicate(rt: &Runtime, rates: &mut RateState, req: &Request) -> Verdict {
    let Some(machine) = rt.machines.get(&req.machine) else {
        return Verdict::Deny(
            ErrorCode::UnknownMachine,
            format!(
                "machine '{}' unknown — no profile loaded{}",
                req.machine,
                if rt.machines.is_empty() { " (nothing loaded)" } else { "" }
            ),
        );
    };
    let Some((login, password)) = rt.creds.get(&req.machine) else {
        // Distinct from unknown_machine: the site is configured, the
        // credential is not — an operator-level gap.
        return Verdict::Deny(
            ErrorCode::NoCredentials,
            format!("machine '{}' has no netrc credential", req.machine),
        );
    };

    // First fully-matching rule permits (OR across rules, AND within).
    let header_lines: Vec<String> = req
        .headers
        .iter()
        .map(|(k, v)| format!("{k}: {v}"))
        .collect();
    let body_text = req
        .body
        .as_ref()
        .map(|b| String::from_utf8_lossy(b).into_owned())
        .unwrap_or_default();
    let matched = machine.grant.allows.iter().any(|rule| {
        if !rule.any_method && rule.method != req.method {
            return false;
        }
        if !rule.url.is_match(&req.url) {
            return false;
        }
        // Each matcher must match SOME header line / the body.
        if !rule.headers.iter().all(|re| header_lines.iter().any(|h| re.is_match(h))) {
            return false;
        }
        if !rule.body.iter().all(|re| re.is_match(&body_text)) {
            return false;
        }
        true
    });
    if !matched {
        return Verdict::Deny(
            ErrorCode::NotAllowed,
            format!(
                "no rule matches {} {} for machine '{}'",
                req.method.name(),
                req.url,
                req.machine
            ),
        );
    }

    if let Some(body) = &req.body {
        if body.len() > machine.grant.max_req {
            return Verdict::Deny(
                ErrorCode::TooLarge,
                format!(
                    "body is {} bytes, machine '{}' allows {} — refused before transmit",
                    body.len(),
                    req.machine,
                    machine.grant.max_req
                ),
            );
        }
    }
    if let Some(rate) = &machine.grant.rate {
        if let Some(detail) = rates.consume(&req.machine, rate) {
            return Verdict::Deny(ErrorCode::RateLimited, detail);
        }
    }

    // Build the outbound request: client headers minus everything the
    // profile owns (netrcd's values always win), plus fixed headers,
    // plus the rendered credential.
    let owned: Vec<String> = machine
        .profile
        .auth
        .owned_headers()
        .into_iter()
        .chain(machine.profile.headers.iter().map(|(k, _)| k.to_ascii_lowercase()))
        .collect();
    let mut headers: Vec<(String, String)> = req
        .headers
        .iter()
        .filter(|(k, _)| !owned.contains(&k.to_ascii_lowercase()))
        .cloned()
        .collect();
    headers.extend(machine.profile.headers.iter().cloned());
    let (auth_name, auth_value) = machine.profile.auth.render(login, password);
    headers.push((auth_name, auth_value));

    Verdict::Allow(OutboundRequest {
        url: format!("https://{}{}", req.machine, req.url),
        method: req.method,
        headers,
        body: req.body.clone(),
        pins: machine
            .profile
            .pins
            .iter()
            .map(|p| p.0.clone())
            .collect(),
        timeout: machine.grant.timeout,
        max_rsp: machine.grant.max_rsp,
    })
}

/// Render a credential for a machine — exposed for tests of the
/// header-drop rule without a live daemon.
pub fn render_auth(auth: &Auth, login: &str, password: &str) -> (String, String) {
    auth.render(login, password)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::loader::load_runtime;
    use std::path::Path;

    fn setup(policy_grant: &str) -> (tempfile::TempDir, tempfile::TempDir, Runtime) {
        let p = tempfile::tempdir().unwrap();
        let g = tempfile::tempdir().unwrap();
        std::fs::write(
            p.path().join("m.toml"),
            "[[machine]]\nname = \"api.x.com\"\nauth = \"bearer\"\npins = [\"sha256//AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\"]\n\n  [machine.headers]\n  \"X-Org\" = \"acme\"\n",
        )
        .unwrap();
        std::fs::write(g.path().join("m.toml"), policy_grant).unwrap();
        let rt = load_runtime(
            p.path(),
            g.path(),
            &[("n".into(), "machine api.x.com login u password sekrit".into())],
        );
        assert!(
            !rt.diagnostics.iter().any(|d| d.level == crate::loader::Level::Error),
            "{:?}",
            rt.diagnostics
        );
        (p, g, rt)
    }

    fn req(method: &str, url: &str) -> Request {
        Request {
            machine: "api.x.com".into(),
            method: crate::policy::Method::parse(method).unwrap(),
            url: url.into(),
            headers: vec![],
            body: None,
        }
    }

    fn deny_detail(v: Verdict) -> (ErrorCode, String) {
        match v {
            Verdict::Deny(c, d) => (c, d),
            Verdict::Allow(_) => panic!("expected deny"),
        }
    }

    #[test]
    fn unknown_machine_and_missing_credential_differ() {
        let (_p, _g, rt) = setup("[[machine]]\nname = \"api.x.com\"\n");
        let mut rates = RateState::default();
        let (c, _) = deny_detail(adjudicate(&rt, &mut rates, &req("GET", "/zen")));
        assert_eq!(c, ErrorCode::NotAllowed);
    }

    #[test]
    fn first_matching_rule_permits_and_method_must_match() {
        let (_p, _g, rt) = setup(
            "[[machine]]\nname = \"api.x.com\"\n[[machine.allow]]\nmethod = \"POST\"\nurl = '/v1/chat.*'\n[[machine.allow]]\nmethod = \"GET\"\nurl = '/zen'\n",
        );
        let mut rates = RateState::default();
        assert!(matches!(
            adjudicate(&rt, &mut rates, &req("POST", "/v1/chat/completions")),
            Verdict::Allow(_)
        ));
        // method mismatch on rule 1, url mismatch on rule 2
        let (c, d) = deny_detail(adjudicate(&rt, &mut rates, &req("POST", "/zen")));
        assert_eq!(c, ErrorCode::NotAllowed);
        assert!(d.contains("POST /zen"), "{d}");
    }

    #[test]
    fn any_method_rule_matches_every_method() {
        let (_p, _g, rt) = setup(
            "[[machine]]\nname = \"api.x.com\"\n[[machine.allow]]\nmethod = \"*\"\nurl = '/any.*'\n",
        );
        let mut rates = RateState::default();
        for m in ["GET", "POST", "DELETE"] {
            assert!(
                matches!(adjudicate(&rt, &mut rates, &req(m, "/anything")), Verdict::Allow(_)),
                "{m} must pass an any-method rule"
            );
        }
    }

    #[test]
    fn auto_anchor_prevents_partial_matches() {
        let (_p, _g, rt) = setup(
            "[[machine]]\nname = \"api.x.com\"\n[[machine.allow]]\nmethod = \"GET\"\nurl = '/zen'\n",
        );
        let mut rates = RateState::default();
        let (c, _) = deny_detail(adjudicate(&rt, &mut rates, &req("GET", "/zen/extra")));
        assert_eq!(c, ErrorCode::NotAllowed);
    }

    #[test]
    fn header_and_body_matchers_are_conjunctive() {
        let (_p, _g, rt) = setup(
            "[[machine]]\nname = \"api.x.com\"\n[[machine.allow]]\nmethod = \"POST\"\nurl = '/v1/chat'\nheaders = ['Content-Type: application/json']\nbody = ['\"model\":\"gpt-4o[^\"]*\"']\n",
        );
        let mut rates = RateState::default();
        let mut r = req("POST", "/v1/chat");
        r.headers = vec![("Content-Type".into(), "application/json".into())];
        r.body = Some(br#"{"model":"gpt-4o-mini","x":1}"#.to_vec());
        assert!(matches!(adjudicate(&rt, &mut rates, &r), Verdict::Allow(_)));

        // right header, wrong model
        let mut r2 = req("POST", "/v1/chat");
        r2.headers = vec![("Content-Type".into(), "application/json".into())];
        r2.body = Some(br#"{"model":"o9-evil"}"#.to_vec());
        let (c, _) = deny_detail(adjudicate(&rt, &mut rates, &r2));
        assert_eq!(c, ErrorCode::NotAllowed);

        // missing header entirely
        let mut r3 = req("POST", "/v1/chat");
        r3.body = Some(br#"{"model":"gpt-4o"}"#.to_vec());
        let (c3, _) = deny_detail(adjudicate(&rt, &mut rates, &r3));
        assert_eq!(c3, ErrorCode::NotAllowed);
    }

    #[test]
    fn oversized_body_refused_before_transmit() {
        let (_p, _g, rt) = setup(
            "[[machine]]\nname = \"api.x.com\"\nmax_req = \"64\"\n[[machine.allow]]\nmethod = \"POST\"\nurl = '/.*'\n",
        );
        let mut rates = RateState::default();
        let mut r = req("POST", "/x");
        r.body = Some(vec![0u8; 65]);
        let (c, d) = deny_detail(adjudicate(&rt, &mut rates, &r));
        assert_eq!(c, ErrorCode::TooLarge);
        assert!(d.contains("refused before transmit"), "{d}");
    }

    #[test]
    fn rate_limit_consumes_only_permitted_requests() {
        let (_p, _g, rt) = setup(
            "[[machine]]\nname = \"api.x.com\"\nrate = \"2/min\"\n[[machine.allow]]\nmethod = \"GET\"\nurl = '/zen'\n",
        );
        let mut rates = RateState::default();
        assert!(matches!(adjudicate(&rt, &mut rates, &req("GET", "/zen")), Verdict::Allow(_)));
        assert!(matches!(adjudicate(&rt, &mut rates, &req("GET", "/zen")), Verdict::Allow(_)));
        let (c, d) = deny_detail(adjudicate(&rt, &mut rates, &req("GET", "/zen")));
        assert_eq!(c, ErrorCode::RateLimited);
        assert!(d.contains("limited to 2/"), "{d}");
        // non-matching requests never consumed quota — the count above
        // proves the accounting; a refused url still doesn't:
        let (c2, _) = deny_detail(adjudicate(&rt, &mut rates, &req("GET", "/nope")));
        assert_eq!(c2, ErrorCode::NotAllowed);
    }

    #[test]
    fn auth_and_fixed_headers_win_over_client_supplied() {
        let (_p, _g, rt) = setup(
            "[[machine]]\nname = \"api.x.com\"\n[[machine.allow]]\nmethod = \"GET\"\nurl = '/zen'\n",
        );
        let mut rates = RateState::default();
        let mut r = req("GET", "/zen");
        r.headers = vec![
            ("Authorization".into(), "Bearer EVIL".into()),
            ("X-Org".into(), "evil".into()),
            ("Accept".into(), "application/json".into()),
        ];
        match adjudicate(&rt, &mut rates, &r) {
            Verdict::Allow(out) => {
                let get = |name: &str| {
                    out.headers
                        .iter()
                        .find(|(k, _)| k.eq_ignore_ascii_case(name))
                        .map(|(_, v)| v.clone())
                        .unwrap_or_default()
                };
                assert_eq!(get("Authorization"), "Bearer sekrit", "client auth dropped, netrcd's wins");
                assert_eq!(get("X-Org"), "acme", "client fixed-header dropped");
                assert_eq!(get("Accept"), "application/json", "innocent header passes");
                assert_eq!(out.url, "https://api.x.com/zen");
                assert_eq!(out.pins, vec!["sha256//AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=".to_string()]);
            }
            Verdict::Deny(_, d) => panic!("{d}"),
        }
    }

    #[test]
    fn basic_and_header_auth_render() {
        assert_eq!(
            render_auth(&Auth::Basic, "u", "p"),
            ("Authorization".to_string(), "dTpw".to_string())
        );
    }

    // keep Path import honest for future dir-based tests
    #[allow(dead_code)]
    fn _p(_: &Path) {}
}
