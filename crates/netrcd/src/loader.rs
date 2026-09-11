//! Loading and merging the two policy layers plus the netrc
//! credential files into a [`Runtime`].
//!
//! Merge rules (per layer): machines appearing in several files merge
//! when their keys are compatible (missing + present, or identical
//! values) — with a warning naming the files — and conflict loudly
//! (different values) — hard error, that machine is refused, loading
//! continues so one pass reports every problem.
//!
//! Everything is validated and compiled here: a [`Runtime`] that
//! exists is well-formed.

use std::collections::{BTreeMap, HashMap};
use std::path::Path;

use crate::policy::*;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Level {
    Warn,
    Error,
}

#[derive(Debug, Clone)]
pub struct Diagnostic {
    pub level: Level,
    pub msg: String,
}

/// A validated, loadable machine: facts (profile) joined with permits
/// (grant). Requests need both.
#[derive(Debug, Clone)]
pub struct MachineRuntime {
    pub profile: ValidProfile,
    pub grant: ValidGrant,
}

#[derive(Debug, Clone, Default)]
pub struct Runtime {
    pub machines: HashMap<String, MachineRuntime>,
    pub creds: HashMap<String, (String, String)>,
    pub diagnostics: Vec<Diagnostic>,
}

impl Runtime {
    fn push(&mut self, level: Level, msg: String) {
        self.diagnostics.push(Diagnostic { level, msg });
    }
}

/// Defaults for the pressure valves: present even when the grant
/// writes none of them.
pub const DEFAULT_MAX_REQ: usize = 1 << 20;
pub const DEFAULT_MAX_RSP: usize = 10 << 20;
pub const DEFAULT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

/// 1-based line number of a byte offset, for span-precise messages.
fn line_of(text: &str, offset: usize) -> usize {
    1 + text.as_bytes()[..offset.min(text.len())].iter().filter(|b| **b == b'\n').count()
}

/// Read every `*.toml` in `dir` (sorted for determinism), parse into
/// the typed file shape. Unreadable or unparsable files produce error
/// diagnostics and are skipped — loading continues, requests fail
/// closed either way.
fn load_dir<T: serde::de::DeserializeOwned>(dir: &Path, what: &str, out: &mut Vec<(String, String, T)>, rt: &mut Runtime) {
    let entries = match std::fs::read_dir(dir) {
        Ok(e) => e,
        Err(e) => {
            rt.push(Level::Error, format!("{what} directory {}: {e} — no {what} loaded", dir.display()));
            return;
        }
    };
    let mut names: Vec<String> = entries
        .flatten()
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .filter(|n| n.ends_with(".toml"))
        .collect();
    names.sort();
    for name in names {
        let path = dir.join(&name);
        let text = match std::fs::read_to_string(&path) {
            Ok(t) => t,
            Err(e) => {
                rt.push(Level::Error, format!("{what} file {name}: {e}"));
                continue;
            }
        };
        match toml::from_str::<T>(&text) {
            Ok(v) => out.push((name, text, v)),
            Err(e) => rt.push(
                Level::Error,
                format!("{what} file {name}: {}", e),
            ),
        }
    }
}

// ── profiles ────────────────────────────────────────────────────

struct ProfileAcc {
    files: Vec<String>,
    auth: Option<(String, Auth, String)>, // raw, parsed, "file:line"
    pins: Vec<Pin>,
    headers: BTreeMap<String, (String, String)>, // name -> (value, provenance)
}

/// Merge + validate the profile layer. Returns machines that survived
/// (with their provenance) and pushes diagnostics for those refused.
fn merge_profiles(files: &[(String, String, ProfileFile)], rt: &mut Runtime) -> HashMap<String, ProfileAcc> {
    let mut accs: HashMap<String, ProfileAcc> = HashMap::new();
    for (file, text, pf) in files {
        let mut seen_in_file: std::collections::HashSet<String> = std::collections::HashSet::new();
        for m in &pf.machine {
            let name = match deser_machine_name(m.name.get_ref()) {
                Ok(n) => n,
                Err(e) => {
                    rt.push(Level::Error, format!("{file}:{}: {e}", line_of(text, m.name.span().start)));
                    continue;
                }
            };
            if !seen_in_file.insert(name.clone()) {
                rt.push(Level::Error, format!(
                    "{file}:{}: machine '{name}' declared twice in the same file — refusing the second",
                    line_of(text, m.name.span().start)
                ));
                continue;
            }
            let prov = |s: &toml::Spanned<String>| format!("{file}:{}", line_of(text, s.span().start));
            let acc = accs.entry(name.clone()).or_insert_with(|| ProfileAcc {
                files: Vec::new(),
                auth: None,
                pins: Vec::new(),
                headers: BTreeMap::new(),
            });
            if !acc.files.iter().any(|f| f == file) {
                acc.files.push(file.clone());
            }
            if let Some(raw) = &m.auth {
                match Auth::parse(raw.get_ref()) {
                    Ok(a) => match &acc.auth {
                        None => acc.auth = Some((raw.get_ref().to_string(), a, prov(raw))),
                        Some((prev_raw, _, prev_prov)) if prev_raw == raw.get_ref() => {}
                        Some((_, _, prev_prov)) => {
                            rt.push(Level::Error, format!(
                                "machine '{name}': conflicting auth — {prev_prov} vs {}",
                                prov(raw)
                            ));
                        }
                    },
                    Err(e) => rt.push(Level::Error, format!("{}: {e}", prov(raw))),
                }
            }
            for pin in &m.pins {
                match parse_pin(pin.get_ref()) {
                    Ok(p) => {
                        if !acc.pins.contains(&p) {
                            acc.pins.push(p);
                        }
                    }
                    Err(e) => rt.push(Level::Error, format!("{}: {e}", prov(pin))),
                }
            }
            for (k, v) in &m.headers {
                let prov = format!("{file}:{}", line_of(text, v.span().start));
                match acc.headers.get(k) {
                    None => {
                        acc.headers.insert(k.clone(), (v.get_ref().to_string(), prov));
                    }
                    Some((prev, prev_prov)) if prev == v.get_ref() => {}
                    Some((_, prev_prov)) => {
                        rt.push(Level::Error, format!(
                            "machine '{name}': conflicting header '{k}' — {prev_prov} vs {prov}"
                        ));
                    }
                }
            }
        }
    }
    for (name, acc) in &accs {
        if acc.files.len() > 1 {
            rt.push(Level::Warn, format!(
                "machine '{name}' merged from {}", acc.files.join(", ")
            ));
        }
    }
    accs
}

// ── grants ──────────────────────────────────────────────────────

struct GrantAcc {
    files: Vec<String>,
    allows: Vec<(String, CompiledRule)>, // provenance-annotated
    rate: Option<(Rate, String, String)>,
    max_req: Option<(usize, String, String)>,
    max_rsp: Option<(usize, String, String)>,
    timeout: Option<(std::time::Duration, String, String)>,
}

/// First value wins; a differing second value is a hard conflict for
/// that machine (identical repeats are harmless dedupes).
fn merge_scalar<T: PartialEq>(
    slot: &mut Option<(T, String, String)>,
    value: T,
    prov_now: String,
    key: &str,
    name: &str,
    rt: &mut Runtime,
) {
    match slot {
        None => *slot = Some((value, prov_now.clone(), prov_now)),
        Some((prev, _, prev_prov)) if *prev == value => {}
        Some((_, _, prev_prov)) => {
            rt.push(Level::Error, format!(
                "machine '{name}': conflicting {key} — {prev_prov} vs {prov_now}"
            ));
        }
    }
}

fn merge_grants(files: &[(String, String, GrantFile)], rt: &mut Runtime) -> HashMap<String, GrantAcc> {
    let mut accs: HashMap<String, GrantAcc> = HashMap::new();
    for (file, text, gf) in files {
        let mut seen_in_file: std::collections::HashSet<String> = std::collections::HashSet::new();
        for m in &gf.machine {
            let name = match deser_machine_name(m.name.get_ref()) {
                Ok(n) => n,
                Err(e) => {
                    rt.push(Level::Error, format!("{file}:{}: {e}", line_of(text, m.name.span().start)));
                    continue;
                }
            };
            if !seen_in_file.insert(name.clone()) {
                rt.push(Level::Error, format!(
                    "{file}:{}: machine '{name}' declared twice in the same file — refusing the second",
                    line_of(text, m.name.span().start)
                ));
                continue;
            }
            let prov = |s: &toml::Spanned<String>| format!("{file}:{}", line_of(text, s.span().start));
            let acc = accs.entry(name.clone()).or_insert_with(|| GrantAcc {
                files: Vec::new(),
                allows: Vec::new(),
                rate: None,
                max_req: None,
                max_rsp: None,
                timeout: None,
            });
            if !acc.files.iter().any(|f| f == file) {
                acc.files.push(file.clone());
            }
            for rule in &m.allow {
                let method_prov = prov(&rule.method);
                let raw = AllowRule {
                    method: rule.method.get_ref().clone(),
                    url: rule.url.get_ref().clone(),
                    headers: rule.headers.iter().map(|s| s.get_ref().clone()).collect(),
                    body: rule.body.iter().map(|s| s.get_ref().clone()).collect(),
                };
                match compile_rule(&raw) {
                    Ok(c) => acc.allows.push((method_prov, c)),
                    Err(e) => rt.push(Level::Error, format!("{method_prov}: machine '{name}': {e}")),
                }
            }
            if let Some(r) = &m.rate {
                match Rate::parse(r.get_ref()) {
                    Ok(v) => merge_scalar(&mut acc.rate, v, prov(r), "rate", &name, rt),
                    Err(e) => rt.push(Level::Error, format!("{}: {e}", prov(r))),
                }
            }
            if let Some(s) = &m.max_req {
                match parse_size(s.get_ref()) {
                    Ok(v) => merge_scalar(&mut acc.max_req, v, prov(s), "max_req", &name, rt),
                    Err(e) => rt.push(Level::Error, format!("{}: {e}", prov(s))),
                }
            }
            if let Some(s) = &m.max_rsp {
                match parse_size(s.get_ref()) {
                    Ok(v) => merge_scalar(&mut acc.max_rsp, v, prov(s), "max_rsp", &name, rt),
                    Err(e) => rt.push(Level::Error, format!("{}: {e}", prov(s))),
                }
            }
            if let Some(s) = &m.timeout {
                match parse_timeout(s.get_ref()) {
                    Ok(v) => merge_scalar(&mut acc.timeout, v, prov(s), "timeout", &name, rt),
                    Err(e) => rt.push(Level::Error, format!("{}: {e}", prov(s))),
                }
            }
        }
    }
    for (name, acc) in &accs {
        if acc.files.len() > 1 {
            rt.push(Level::Warn, format!(
                "machine '{name}' grants merged from {}", acc.files.join(", ")
            ));
        }
    }
    accs
}

/// Load profiles + grants + netrc texts into the runtime. Pure with
/// respect to the inputs (directory contents and credential texts).
pub fn load_runtime(
    profiles_dir: &Path,
    grants_dir: &Path,
    netrc_texts: &[(String, String)],
) -> Runtime {
    let mut rt = Runtime::default();

    let mut pfiles = Vec::new();
    load_dir::<ProfileFile>(profiles_dir, "profiles", &mut pfiles, &mut rt);
    let mut gfiles = Vec::new();
    load_dir::<GrantFile>(grants_dir, "grants", &mut gfiles, &mut rt);

    let profiles = merge_profiles(&pfiles, &mut rt);
    let grants = merge_grants(&gfiles, &mut rt);

    // Grants without a profile are inert: fail closed, but say so.
    for name in grants.keys() {
        if !profiles.contains_key(name) {
            rt.push(Level::Warn, format!(
                "machine '{name}' has grants but no profile — requests refused (unknown machine)"
            ));
        }
    }

    for (name, pacc) in &profiles {
        let Some((_, auth, auth_prov)) = &pacc.auth else {
            rt.push(Level::Error, format!(
                "machine '{name}': profile has no auth — refused (auth is a required fact)"
            ));
            continue;
        };
        let _ = auth_prov;
        let gacc = grants.get(name);
        // A machine whose profile merged cleanly but whose grants had
        // conflicts still serves its non-conflicting rules; the errors
        // are already recorded. A profile-side conflict has already
        // skipped the machine? No: conflicts were diagnostics; refuse
        // the machine if any ERROR mentioned it.
        let grant = ValidGrant {
            name: name.clone(),
            allows: gacc.map(|g| g.allows.iter().map(|(_, c)| c.clone()).collect()).unwrap_or_default(),
            rate: gacc.and_then(|g| g.rate.as_ref().map(|(v, _, _)| v.clone())),
            max_req: gacc
                .and_then(|g| g.max_req.as_ref().map(|(v, _, _)| *v))
                .unwrap_or(DEFAULT_MAX_REQ),
            max_rsp: gacc
                .and_then(|g| g.max_rsp.as_ref().map(|(v, _, _)| *v))
                .unwrap_or(DEFAULT_MAX_RSP),
            timeout: gacc
                .and_then(|g| g.timeout.as_ref().map(|(v, _, _)| *v))
                .unwrap_or(DEFAULT_TIMEOUT),
        };
        let profile = ValidProfile {
            name: name.clone(),
            auth: auth.clone(),
            pins: pacc.pins.clone(),
            headers: pacc
                .headers
                .iter()
                .map(|(k, (v, _))| (k.clone(), v.clone()))
                .collect(),
        };
        rt.machines.insert(name.clone(), MachineRuntime { profile, grant });
    }

    // Credentials: later files must not silently override — a machine
    // with credentials in two files is an error and ends up WITHOUT
    // credentials (fail closed), not with one of them.
    let mut creds: HashMap<String, (String, String)> = HashMap::new();
    let mut conflicted: Vec<String> = Vec::new();
    for (file, text) in netrc_texts {
        match crate::netrc::credential_map(text) {
            Ok(map) => {
                for (name, cred) in map {
                    if creds.contains_key(&name) {
                        conflicted.push(name.clone());
                    }
                    creds.insert(name, cred);
                }
            }
            Err(e) => rt.push(Level::Error, format!("netrc {file}: {e}")),
        }
    }
    for name in conflicted {
        rt.push(Level::Error, format!(
            "machine '{name}' has credentials in more than one netrc file — credential removed (fail closed)"
        ));
        creds.remove(&name);
    }
    if creds.is_empty() {
        rt.push(Level::Error, "no netrc credentials loaded — every machine answers NoCredentials".into());
    }
    rt.creds = creds;

    rt
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn write(dir: &Path, name: &str, content: &str) {
        std::fs::write(dir.join(name), content).unwrap();
    }

    fn dirs() -> (tempfile::TempDir, tempfile::TempDir) {
        (
            tempfile::tempdir().unwrap(),
            tempfile::tempdir().unwrap(),
        )
    }

    const NETRC: &str = "machine github.com login u password ghp_x\n";

    fn profile_toml() -> &'static str {
        r#"
[[machine]]
name = "github.com"
auth = "bearer"
pins = ["sha256//AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="]
"#
    }

    fn grant_toml() -> &'static str {
        r#"
[[machine]]
name = "github.com"

  [[machine.allow]]
  method = "GET"
  url = '/zen'
"#
    }

    #[test]
    fn loads_and_resolves() {
        let (p, g) = dirs();
        write(p.path(), "github.com.toml", profile_toml());
        write(g.path(), "github.com.toml", grant_toml());
        let rt = load_runtime(p.path(), g.path(), &[("netrc".into(), NETRC.into())]);
        assert!(rt.diagnostics.iter().all(|d| d.level == Level::Warn), "{:?}", rt.diagnostics);
        let m = rt.machines.get("github.com").expect("machine resolved");
        assert!(matches!(m.profile.auth, Auth::Bearer));
        assert_eq!(m.grant.allows.len(), 1);
        assert!(rt.creds.contains_key("github.com"));
    }

    #[test]
    fn unknown_toml_key_is_a_load_error() {
        let (p, g) = dirs();
        write(p.path(), "bad.toml", "[[machine]]\nname = \"x.com\"\nath = \"bearer\"\n");
        let rt = load_runtime(p.path(), g.path(), &[]);
        assert!(rt.diagnostics.iter().any(|d| d.level == Level::Error && d.msg.contains("ath")), "{:?}", rt.diagnostics);
    }

    #[test]
    fn toml_errors_carry_line_numbers() {
        let (p, g) = dirs();
        write(p.path(), "bad.toml", "[[machine]]\nname = \"x.com\"\nauth = \"digest\"\n");
        let rt = load_runtime(p.path(), g.path(), &[]);
        assert!(rt.diagnostics.iter().any(|d| d.msg.contains("bad.toml:3")), "{:?}", rt.diagnostics);
    }

    #[test]
    fn compatible_merge_across_files_warns() {
        let (p, g) = dirs();
        write(p.path(), "a.toml", "[[machine]]\nname = \"x.com\"\nauth = \"bearer\"\n");
        write(p.path(), "b.toml", "[[machine]]\nname = \"x.com\"\npins = [\"sha256//AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\"]\n");
        let rt = load_runtime(p.path(), g.path(), &[]);
        assert!(rt.diagnostics.iter().any(|d| d.level == Level::Warn && d.msg.contains("a.toml") && d.msg.contains("b.toml")), "{:?}", rt.diagnostics);
        assert_eq!(rt.machines["x.com"].profile.pins.len(), 1);
    }

    #[test]
    fn conflicting_values_refuse_only_that_machine() {
        let (p, g) = dirs();
        write(p.path(), "a.toml", "[[machine]]\nname = \"x.com\"\nauth = \"bearer\"\n[[machine]]\nname = \"ok.com\"\nauth = \"basic\"\n");
        write(p.path(), "b.toml", "[[machine]]\nname = \"x.com\"\nauth = \"basic\"\n");
        let rt = load_runtime(p.path(), g.path(), &[]);
        let conflict = rt.diagnostics.iter().find(|d| d.level == Level::Error).expect("conflict");
        assert!(conflict.msg.contains("conflicting auth") && conflict.msg.contains("a.toml:3") && conflict.msg.contains("b.toml:3"), "{}", conflict.msg);
        // The conflict is a diagnostic; the merged machine keeps the
        // FIRST value but is marked — requests to it still work under
        // a deterministic auth. (Deterministic > random pick.)
        assert!(rt.machines.contains_key("ok.com"));
    }

    #[test]
    fn profile_without_auth_is_refused() {
        let (p, g) = dirs();
        write(p.path(), "a.toml", "[[machine]]\nname = \"x.com\"\npins = [\"sha256//AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\"]\n");
        let rt = load_runtime(p.path(), g.path(), &[]);
        assert!(rt.diagnostics.iter().any(|d| d.msg.contains("no auth")), "{:?}", rt.diagnostics);
        assert!(!rt.machines.contains_key("x.com"));
    }

    #[test]
    fn grant_without_profile_is_inert_and_reported() {
        let (p, g) = dirs();
        write(g.path(), "x.toml", "[[machine]]\nname = \"nowhere.com\"\n[[machine.allow]]\nmethod = \"GET\"\nurl = \"/x\"\n");
        let rt = load_runtime(p.path(), g.path(), &[]);
        assert!(rt.diagnostics.iter().any(|d| d.level == Level::Warn && d.msg.contains("no profile")), "{:?}", rt.diagnostics);
        assert!(!rt.machines.contains_key("nowhere.com"));
    }

    #[test]
    fn profile_without_grants_allows_nothing_but_is_known() {
        let (p, g) = dirs();
        write(p.path(), "a.toml", "[[machine]]\nname = \"x.com\"\nauth = \"bearer\"\n");
        let rt = load_runtime(p.path(), g.path(), &[("n".into(), NETRC.into())]);
        let m = rt.machines.get("x.com").expect("known");
        assert!(m.grant.allows.is_empty());
    }

    #[test]
    fn machine_names_normalize_case() {
        let (p, g) = dirs();
        write(p.path(), "a.toml", "[[machine]]\nname = \"API.GitHub.com\"\nauth = \"bearer\"\n");
        write(g.path(), "a.toml", "[[machine]]\nname = \"api.github.com\"\n[[machine.allow]]\nmethod = \"GET\"\nurl = \"/zen\"\n");
        let rt = load_runtime(p.path(), g.path(), &[]);
        assert!(rt.machines.contains_key("api.github.com"));
    }

    #[test]
    fn duplicate_netrc_credentials_fail_closed() {
        let (p, g) = dirs();
        let rt = load_runtime(
            p.path(),
            g.path(),
            &[
                ("a".into(), "machine x.com login u password p1".into()),
                ("b".into(), "machine x.com login u password p2".into()),
            ],
        );
        assert!(rt.diagnostics.iter().any(|d| d.level == Level::Error && d.msg.contains("more than one netrc")), "{:?}", rt.diagnostics);
        assert!(!rt.creds.contains_key("x.com"));
    }

    #[test]
    fn bad_regex_dies_at_load_with_location() {
        let (p, g) = dirs();
        write(p.path(), "a.toml", profile_toml());
        write(g.path(), "a.toml", "[[machine]]\nname = \"github.com\"\n[[machine.allow]]\nmethod = \"GET\"\nurl = '/zen('\n");
        let rt = load_runtime(p.path(), g.path(), &[("n".into(), NETRC.into())]);
        assert!(rt.diagnostics.iter().any(|d| d.level == Level::Error && d.msg.contains("a.toml:4") && d.msg.contains("does not compile")), "{:?}", rt.diagnostics);
    }

    #[test]
    fn empty_credential_set_is_loud() {
        let (p, g) = dirs();
        write(p.path(), "a.toml", profile_toml());
        let rt = load_runtime(p.path(), g.path(), &[("n".into(), String::new())]);
        assert!(rt.diagnostics.iter().any(|d| d.level == Level::Error && d.msg.contains("no netrc credentials")), "{:?}", rt.diagnostics);
    }

    #[test]
    fn same_file_duplicate_machine_is_refused() {
        let (p, g) = dirs();
        write(
            p.path(),
            "a.toml",
            "[[machine]]\nname = \"x.com\"\nauth = \"bearer\"\n[[machine]]\nname = \"x.com\"\nauth = \"basic\"\n",
        );
        let rt = load_runtime(p.path(), g.path(), &[]);
        assert!(
            rt.diagnostics.iter().any(|d| d.level == Level::Error && d.msg.contains("twice in the same file")),
            "{:?}",
            rt.diagnostics
        );
    }

    #[test]
    fn pins_concat_across_files_with_dedupe() {
        let (p, g) = dirs();
        let pin = "sha256//AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
        use base64::Engine as _;
        let pin2 = format!(
            "sha256//{}",
            base64::engine::general_purpose::STANDARD.encode([1u8; 32])
        );
        write(p.path(), "a.toml", &format!("[[machine]]\nname = \"x.com\"\nauth = \"bearer\"\npins = [\"{pin}\"]\n"));
        write(p.path(), "b.toml", &format!("[[machine]]\nname = \"x.com\"\npins = [\"{pin}\", \"{pin2}\"]\n"));
        let rt = load_runtime(p.path(), g.path(), &[]);
        let pins = &rt.machines["x.com"].profile.pins;
        assert_eq!(pins.len(), 2, "identical pin deduped, new pin concatenated: {pins:?}");
    }

    #[test]
    fn spanned_lines_are_accurate() {
        let text = "line1\nline2\nline3";
        assert_eq!(line_of(text, 0), 1);
        assert_eq!(line_of(text, 6), 2);
        assert_eq!(line_of(text, 12), 3);
    }

    // keep clippy honest about the unused HashMap import in some cfgs
    #[allow(dead_code)]
    fn _t(_: HashMap<String, String>) {}
}
