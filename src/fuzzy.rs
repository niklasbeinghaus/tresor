//! Fuzzy matching shared by the command palette, profile picker, and list filter.

use std::cmp::Ordering;

use nucleo_matcher::pattern::{Atom, AtomKind, CaseMatching, Normalization};
use nucleo_matcher::{Config, Matcher, Utf32Str};

fn atom(needle: &str) -> Atom {
    Atom::new(
        needle,
        CaseMatching::Smart,
        Normalization::Smart,
        AtomKind::Fuzzy,
        false,
    )
}

fn utf32<'a>(text: &'a str, buf: &'a mut Vec<char>) -> Utf32Str<'a> {
    if text.is_ascii() {
        return Utf32Str::Ascii(text.as_bytes());
    }

    buf.clear();
    buf.extend(nucleo_matcher::chars::graphemes(text));
    Utf32Str::Unicode(buf)
}

/// Returns a match score for `haystack` against `needle`, or `None` when it
/// does not match. Higher scores are better; values are only comparable to
/// each other. An empty `needle` matches everything.
#[must_use]
pub fn score(haystack: &str, needle: &str) -> Option<i64> {
    let atom = atom(needle);
    let mut matcher = Matcher::new(Config::DEFAULT);
    let mut buf = Vec::new();
    atom.score(utf32(haystack, &mut buf), &mut matcher)
        .map(i64::from)
}

/// Returns the indices of `labels` that match `needle`, best score first, with
/// ties broken by ascending label so output is deterministic. An empty needle
/// returns `0..labels.len()` in original order.
#[must_use]
pub fn ranked_indices(labels: &[&str], needle: &str) -> Vec<usize> {
    if needle.trim().is_empty() {
        return (0..labels.len()).collect();
    }

    let atom = atom(needle);
    let mut matcher = Matcher::new(Config::DEFAULT);
    let mut buf = Vec::new();

    let mut ranked: Vec<(i64, usize)> = labels
        .iter()
        .enumerate()
        .filter_map(|(index, label)| {
            atom.score(utf32(label, &mut buf), &mut matcher)
                .map(i64::from)
                .map(|score| (score, index))
        })
        .collect();

    ranked.sort_by(|(left_score, left_index), (right_score, right_index)| {
        right_score.cmp(left_score).then_with(|| {
            let left_label = labels.get(*left_index);
            let right_label = labels.get(*right_index);
            match (left_label, right_label) {
                (Some(left), Some(right)) => left.cmp(right),
                (Some(_), None) => Ordering::Less,
                (None, Some(_)) => Ordering::Greater,
                (None, None) => Ordering::Equal,
            }
        })
    });

    ranked.into_iter().map(|(_, index)| index).collect()
}

#[cfg(test)]
mod tests {
    use super::{ranked_indices, score};

    #[test]
    fn score_matches_subsequences() {
        // Given: a haystack containing the needle characters in order.
        let haystack = "kube-httpcache-0";

        // When: scoring a subsequence needle.
        let got = score(haystack, "khc");

        // Then: the fuzzy matcher returns a score.
        assert!(got.is_some());
    }

    #[test]
    fn score_returns_none_for_non_match() {
        // Given: a haystack with no matching subsequence.
        let haystack = "kube-httpcache-0";

        // When: scoring an impossible needle.
        let got = score(haystack, "zzz");

        // Then: there is no fuzzy match score.
        assert_eq!(got, None);
    }

    #[test]
    fn score_uses_smart_case() {
        // Given: one mixed-case and one lowercase haystack.
        let mixed = "Kube-System";
        let lower = "kube-system";

        // When: scoring lowercase and uppercase needles.
        let lower_needle_mixed = score(mixed, "kube");
        let upper_needle_mixed = score(mixed, "Kube");
        let upper_needle_lower = score(lower, "Kube");

        // Then: lowercase needle is case-insensitive, uppercase needle is strict.
        assert!(lower_needle_mixed.is_some());
        assert!(upper_needle_mixed.is_some());
        assert_eq!(upper_needle_lower, None);
    }

    #[test]
    fn empty_needle_matches_all_scores() {
        // Given: any haystack value.
        let haystack = "anything";

        // When: scoring an empty needle.
        let got = score(haystack, "");

        // Then: empty needle matches everything.
        assert!(got.is_some());
    }

    #[test]
    fn empty_needle_keeps_original_rank_order() {
        // Given: labels in a deliberate non-sorted order.
        let labels = ["delta", "alpha", "charlie", "bravo"];

        // When: ranking with an empty or whitespace-only needle.
        let empty = ranked_indices(&labels, "");
        let blank = ranked_indices(&labels, "   ");

        // Then: original order is preserved.
        assert_eq!(empty, vec![0, 1, 2, 3]);
        assert_eq!(blank, vec![0, 1, 2, 3]);
    }

    #[test]
    fn ties_are_broken_by_ascending_label() {
        // Given: two candidates designed to tie in score for needle "a".
        let labels = ["ay", "ax"];

        // When: ranking both matching labels.
        let got = ranked_indices(&labels, "a");

        // Then: deterministic ascending-label tie-break picks "ax" before "ay".
        assert_eq!(got, vec![1, 0]);
    }

    #[test]
    fn pattern_syntax_is_not_interpreted() {
        // Given: haystacks that would differ if special pattern syntax were enabled.
        let plain = "web-1";
        let prefixed = "^web-1";
        let spaced = "default web-1";
        let compact = "defaultweb-1";

        // When: scoring needles containing '^', '!' and spaces.
        let caret_plain = score(plain, "^web");
        let caret_prefixed = score(prefixed, "^web");
        let bang_plain = score(plain, "!web");
        let space_spaced = score(spaced, "t w");
        let space_compact = score(compact, "t w");

        // Then: those characters are treated as literals, not operators.
        assert_eq!(caret_plain, None);
        assert!(caret_prefixed.is_some());
        assert_eq!(bang_plain, None);
        assert!(space_spaced.is_some());
        assert_eq!(space_compact, None);
    }
}
