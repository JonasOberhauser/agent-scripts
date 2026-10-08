/// WARNING: CUSTOM PARSER — APPROVED BY: <https://github.com/JonasOberhauser/agent-scripts/pull/92#issuecomment-6059228895>
///
/// (Approved use: "filtering among a list of options by a specified
/// prefix string, resulting in all the options that start with the
/// specified prefix".)
///
/// This is the ONE prefix-matching site in the workspace: every
/// completion surface — the TUI completers, `--complete`'s
/// command-name and live-candidate filters — narrows its candidates
/// through this function. `str::starts_with` is the std tool for the
/// job; no crate does it better at completion-scale candidate counts
/// (`fst`/`radix_trie` are prefix SEARCH at thousands of keys —
/// over-engineering here by construction).

/// The candidates that start with `prefix`, in order, unchanged —
/// pure filtering; formatting stays with the callers.
pub fn prefixed<'a, I, S>(candidates: I, prefix: &'a str) -> impl Iterator<Item = S> + 'a
where
    I: IntoIterator<Item = S> + 'a,
    S: AsRef<str>,
{
    candidates
        .into_iter()
        .filter(move |c| c.as_ref().starts_with(prefix))
}

#[cfg(test)]
mod tests {
    use super::prefixed;

    #[test]
    fn filters_by_prefix_keeping_items_and_order() {
        let words: Vec<&str> = vec!["reset", "remove", "rotate", "grant"];
        let got: Vec<&str> = prefixed(words, "re").collect();
        assert_eq!(got, vec!["reset", "remove"]);
        // empty prefix keeps everything
        let all: Vec<&str> = prefixed(vec!["a", "b"], "").collect();
        assert_eq!(all, vec!["a", "b"]);
        // no match keeps nothing
        let none: Vec<&str> = prefixed(vec!["a", "b"], "z").collect();
        assert!(none.is_empty());
    }
}
