//! Strict netrc parsing — ported from the gh-curl design and kept
//! fail-closed: a `default` entry (credentials for every host) is
//! refused, partial entries are errors, unknown keywords are errors.
//! Machine names are matched exactly (case-insensitively), exactly
//! like libcurl's netrc lookup — subdomains never match.

use std::collections::HashMap;

/// One parsed netrc machine entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Machine {
    pub name: String,
    pub login: String,
    pub password: String,
}

/// Tokenizer: words split on whitespace, values optionally single- or
/// double-quoted.
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
/// `machine` tokens (they may span lines), so flushing happens only
/// when the next `machine` starts or at EOF.
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

/// Parse netrc text into machine entries. Empty input is fine at this
/// level (the loader decides whether an empty credential set is an
/// error for its deployment).
pub fn parse_netrc(text: &str) -> Result<Vec<Machine>, String> {
    let mut machines = Vec::new();
    let mut current: Option<Machine> = None;

    for (lineno, raw) in text.lines().enumerate() {
        let mut rest = raw;
        while let Some((tok, tail)) = next_token(rest) {
            rest = tail;
            match tok.as_str() {
                "machine" => {
                    finish_entry(current.take(), &mut machines)?;
                    let (name, tail) = next_token(rest).ok_or_else(|| {
                        format!("line {}: machine entry without a name", lineno + 1)
                    })?;
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

/// Parse into the credential map used at runtime: machine (lowercased)
/// → (login, password). A duplicate machine name is an error — the
/// second entry would silently change which credential is used.
pub fn credential_map(text: &str) -> Result<HashMap<String, (String, String)>, String> {
    let mut map = HashMap::new();
    for m in parse_netrc(text)? {
        let name = m.name.to_ascii_lowercase();
        if map.insert(name.clone(), (m.login, m.password)).is_some() {
            return Err(format!("machine `{name}` appears twice — ambiguous credentials"));
        }
    }
    Ok(map)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn machines(list: &[(&str, &str, &str)]) -> Vec<Machine> {
        list.iter()
            .map(|(n, l, p)| Machine {
                name: n.to_string(),
                login: l.to_string(),
                password: p.to_string(),
            })
            .collect()
    }

    #[test]
    fn parses_machine_login_password() {
        assert_eq!(
            parse_netrc("machine api.github.com login u password ghp_a").unwrap(),
            machines(&[("api.github.com", "u", "ghp_a")])
        );
    }

    #[test]
    fn parses_single_line_and_multiple_machines() {
        let text = "machine a.com login u password p1\nmachine b.org login v password p2\n";
        let m = parse_netrc(text).unwrap();
        assert_eq!(m.len(), 2);
        assert_eq!(m[0].password, "p1");
        assert_eq!(m[1].password, "p2");
    }

    #[test]
    fn parses_quoted_values() {
        let m = parse_netrc(r#"machine a.com login u password "p s q""#).unwrap();
        assert_eq!(m[0].password, "p s q");
    }

    #[test]
    fn default_entry_fails_closed() {
        let err = parse_netrc("default login u password p").unwrap_err();
        assert!(err.contains("default") && err.contains("EVERY host"), "{err}");
    }

    #[test]
    fn missing_password_fails_closed() {
        let err = parse_netrc("machine a.com login u").unwrap_err();
        assert!(err.contains("missing"), "{err}");
    }

    #[test]
    fn unknown_keyword_fails_closed() {
        let err = parse_netrc("machine a.com account x password p").unwrap_err();
        assert!(err.contains("account"), "{err}");
    }

    #[test]
    fn empty_file_is_ok_at_parse() {
        assert!(parse_netrc("").unwrap().is_empty());
    }

    #[test]
    fn keyword_outside_machine_fails() {
        let err = parse_netrc("login u").unwrap_err();
        assert!(err.contains("outside"), "{err}");
    }

    #[test]
    fn credential_map_lowercases_and_rejects_duplicates() {
        let map = credential_map("machine API.GitHub.com login u password p").unwrap();
        assert_eq!(map.get("api.github.com").unwrap(), &("u".into(), "p".into()));
        let err = credential_map(
            "machine a.com login u password p1\nmachine a.com login v password p2",
        )
        .unwrap_err();
        assert!(err.contains("appears twice"), "{err}");
    }
}
