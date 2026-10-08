//! The ONE prefix-matching site in the workspace (see the approval
//! request on servyi/lints#9).
//!
//! Every completion surface — the TUI completers, `--complete`'s
//! command-name and live-candidate filters — narrows a candidate list
//! by a typed prefix. `str::starts_with` is the std function for
//! exactly this job; no crate does it better at completion-scale
//! candidate counts (`fst`/`radix_trie` are prefix SEARCH at
//! thousands of keys — over-engineering here by construction).
//!
//! Consolidated into this module so the whole workspace's prefix
//! matching lives behind ONE sanctioned seam. The
//! `/// WARNING: CUSTOM PARSER — APPROVED BY: <url>` header lands on
//! this file together with the maintainer's approval comment (the
//! linter verifies the link, its author, and the sentence).

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
