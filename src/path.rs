//! `SecretPath` — a Vault KV2 path with the Go project's trailing-slash semantics.
//!
//! Directory entries carry a trailing `/` (`a/b/c/`); leaf secret paths do not
//! (`a/b/c`). Every path helper mirrors the original Go `pkg/utils/path.go`
//! exactly, including its "strip the last character first" trick, so the rewrite
//! is behavior-identical to vaultview.

use std::fmt;

/// A Vault KV2 path. Directories end with `/`; the empty string is the mount root.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct SecretPath(String);

impl SecretPath {
    /// The mount root (`""`).
    #[must_use]
    pub const fn root() -> Self {
        Self(String::new())
    }

    /// Builds a path from a raw string. Callers must pass directory paths with a
    /// trailing `/` — this is the project-wide convention (matches Go vaultview).
    #[must_use]
    pub fn new(raw: &str) -> Self {
        Self(raw.to_owned())
    }

    /// The raw path string.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// True when this is the mount root (`""`).
    #[must_use]
    pub fn is_root(&self) -> bool {
        self.0.is_empty()
    }

    /// True when this path denotes a directory (trailing `/`).
    #[must_use]
    pub fn is_dir(&self) -> bool {
        self.0.ends_with('/')
    }

    /// Returns the second-to-last segment as a new path.
    ///
    /// Mirrors Go `utils.GetParentPath`:
    /// `a/b/c/` -> `a/b/`, `a/b/` -> `a/`, `a/` -> `""`, `""` -> `""`.
    #[must_use]
    pub fn parent(&self) -> Self {
        let s = &self.0;
        if s.is_empty() {
            return Self::root();
        }
        let mut end = s.len() - 1;
        while !s.is_char_boundary(end) {
            end -= 1;
        }
        s[..end]
            .rfind('/')
            .map_or_else(Self::root, |idx| Self(s[..=idx].to_owned()))
    }

    /// Returns the last segment, preserving its trailing slash for directories.
    ///
    /// Mirrors Go `utils.GetChildPath`:
    /// `a/b/c/d/` -> `d/`, `a/b/` -> `b/`, `a/` -> `a/`, `"d"` -> `"d"`.
    #[must_use]
    pub fn child_name(&self) -> Self {
        let s = &self.0;
        if s.is_empty() {
            return Self::root();
        }
        let mut end = s.len() - 1;
        while !s.is_char_boundary(end) {
            end -= 1;
        }
        s[..end]
            .rfind('/')
            .map_or_else(|| self.clone(), |idx| Self(s[idx + 1..].to_owned()))
    }

    /// Concatenates a segment onto this path (string concatenation, as in Go).
    ///
    /// `a/b/` + `c/` -> `a/b/c/`; `""` + `d` -> `d`.
    #[must_use]
    pub fn join(&self, segment: &Self) -> Self {
        Self(format!("{}{}", self.0, segment.0))
    }
}

impl fmt::Display for SecretPath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl AsRef<str> for SecretPath {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use super::SecretPath;

    #[test]
    fn parent_when_dir() {
        assert_eq!(SecretPath::new("a/b/c/").parent(), SecretPath::new("a/b/"));
        assert_eq!(SecretPath::new("a/b/").parent(), SecretPath::new("a/"));
        assert_eq!(SecretPath::new("a/").parent(), SecretPath::root());
        assert_eq!(
            SecretPath::new("a/b/c/d/").parent(),
            SecretPath::new("a/b/c/")
        );
    }

    #[test]
    fn parent_when_leaf() {
        assert_eq!(SecretPath::new("a/b/c").parent(), SecretPath::new("a/b/"));
        assert_eq!(SecretPath::new("a/b").parent(), SecretPath::new("a/"));
    }

    #[test]
    fn parent_when_root() {
        assert_eq!(SecretPath::root().parent(), SecretPath::root());
    }

    #[test]
    fn child_name_when_dir() {
        assert_eq!(
            SecretPath::new("a/b/c/d/").child_name(),
            SecretPath::new("d/")
        );
        assert_eq!(SecretPath::new("a/b/").child_name(), SecretPath::new("b/"));
        assert_eq!(SecretPath::new("a/").child_name(), SecretPath::new("a/"));
    }

    #[test]
    fn child_name_when_leaf() {
        assert_eq!(
            SecretPath::new("single").child_name(),
            SecretPath::new("single")
        );
        assert_eq!(SecretPath::new("a/b/c").child_name(), SecretPath::new("c"));
    }

    #[test]
    fn child_name_when_root() {
        assert_eq!(SecretPath::root().child_name(), SecretPath::root());
    }

    #[test]
    fn join_concatenates() {
        assert_eq!(
            SecretPath::new("a/b/").join(&SecretPath::new("c/")),
            SecretPath::new("a/b/c/")
        );
        assert_eq!(
            SecretPath::root().join(&SecretPath::new("d")),
            SecretPath::new("d")
        );
    }

    #[test]
    fn is_dir_and_root() {
        assert!(SecretPath::new("a/b/").is_dir());
        assert!(!SecretPath::new("a").is_dir());
        assert!(SecretPath::root().is_root());
        assert!(!SecretPath::new("a/").is_root());
    }

    #[test]
    fn display_and_as_str() {
        let p = SecretPath::new("secret/data/");
        assert_eq!(p.to_string(), "secret/data/");
        assert_eq!(p.as_str(), "secret/data/");
    }

    proptest::proptest! {
        /// For any directory path and any segment without a slash, join-then-parent
        /// round-trips back to the original directory.
        #[test]
        fn parent_of_join_is_original(prefix in r"[a-z]{0,6}(/[a-z]{1,6}){0,3}/", seg in "[a-z0-9_.-]{1,12}") {
            let dir = if prefix.is_empty() { SecretPath::root() } else { SecretPath::new(&prefix) };
            let joined = dir.join(&SecretPath::new(&format!("{seg}/")));
            prop_assert_eq!(joined.parent(), dir);
        }

        /// child_name(join(dir, name)) == name for slash-free names.
        #[test]
        fn child_of_join_is_segment(prefix in r"[a-z]{0,6}(/[a-z]{1,6}){0,3}/", seg in "[a-z0-9_.-]{1,12}") {
            let dir = if prefix.is_empty() { SecretPath::root() } else { SecretPath::new(&prefix) };
            let joined = dir.join(&SecretPath::new(&format!("{seg}/")));
            prop_assert_eq!(joined.child_name(), SecretPath::new(&format!("{seg}/")));
        }
    }
}
