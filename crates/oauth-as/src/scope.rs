// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Access-token scope, mirrored from RFC 6749 section 3.3: a scope is a space-delimited set of
//! case-sensitive tokens, each drawn from `%x21 / %x23-5B / %x5D-7E` (printable ASCII minus space,
//! double quote, and backslash).

use std::collections::BTreeSet;
use std::fmt;

use serde::de::Error as _;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// One scope token, charset-validated at construction.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Scope(String);

/// The rejection for a malformed scope token (empty, or a byte outside the RFC 6749 section 3.3
/// charset).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InvalidScopeToken(pub String);

impl fmt::Display for InvalidScopeToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "invalid scope token {:?}", self.0)
    }
}

impl std::error::Error for InvalidScopeToken {}

fn scope_char_ok(b: u8) -> bool {
    b == 0x21 || (0x23..=0x5B).contains(&b) || (0x5D..=0x7E).contains(&b)
}

impl Scope {
    /// Validate and wrap one scope token.
    pub fn new(token: impl Into<String>) -> Result<Self, InvalidScopeToken> {
        let token = token.into();
        if token.is_empty() || !token.bytes().all(scope_char_ok) {
            return Err(InvalidScopeToken(token));
        }
        Ok(Scope(token))
    }

    /// The token text.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for Scope {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// An ordered, deduplicated set of scope tokens. The wire form (both directions) is the RFC's
/// space-delimited string; ordering here is lexicographic so serialization is deterministic.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ScopeSet(BTreeSet<Scope>);

impl ScopeSet {
    /// The empty set (serializes to the empty string; hosts normally omit the parameter instead).
    pub fn empty() -> Self {
        ScopeSet(BTreeSet::new())
    }

    /// Parse a space-delimited scope string. Repeated whitespace is tolerated; each token is
    /// charset-validated.
    pub fn parse(s: &str) -> Result<Self, InvalidScopeToken> {
        let mut set = BTreeSet::new();
        for tok in s.split(' ').filter(|t| !t.is_empty()) {
            set.insert(Scope::new(tok)?);
        }
        Ok(ScopeSet(set))
    }

    /// Build from tokens, validating each.
    pub fn from_tokens<I, T>(tokens: I) -> Result<Self, InvalidScopeToken>
    where
        I: IntoIterator<Item = T>,
        T: Into<String>,
    {
        let mut set = BTreeSet::new();
        for t in tokens {
            set.insert(Scope::new(t)?);
        }
        Ok(ScopeSet(set))
    }

    /// True when every token in `self` is also in `other`.
    pub fn is_subset(&self, other: &ScopeSet) -> bool {
        self.0.is_subset(&other.0)
    }

    /// True when the set holds no tokens.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Number of tokens.
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Membership test.
    pub fn contains(&self, token: &str) -> bool {
        self.0.iter().any(|s| s.as_str() == token)
    }

    /// Iterate tokens in lexicographic order.
    pub fn iter(&self) -> impl Iterator<Item = &Scope> {
        self.0.iter()
    }
}

impl fmt::Display for ScopeSet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut first = true;
        for s in &self.0 {
            if !first {
                f.write_str(" ")?;
            }
            first = false;
            f.write_str(s.as_str())?;
        }
        Ok(())
    }
}

impl Serialize for ScopeSet {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for ScopeSet {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        ScopeSet::parse(&s).map_err(D::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn charset_is_rfc6749_3_3() {
        assert!(Scope::new("read").is_ok());
        assert!(Scope::new("urn:example:channel=HBO&level=5").is_ok());
        assert!(Scope::new("!#[]~").is_ok());
        assert!(Scope::new("").is_err(), "empty token");
        assert!(
            Scope::new("has space").is_err(),
            "space is the delimiter, not scope content"
        );
        assert!(Scope::new("dq\"uote").is_err(), "0x22 excluded");
        assert!(Scope::new("back\\slash").is_err(), "0x5C excluded");
        assert!(Scope::new("caf\u{e9}").is_err(), "non-ASCII excluded");
    }

    #[test]
    fn parse_dedupes_orders_and_roundtrips() {
        let set = ScopeSet::parse("write  read read").unwrap();
        assert_eq!(set.len(), 2);
        assert_eq!(set.to_string(), "read write");
        let json = serde_json::to_string(&set).unwrap();
        assert_eq!(json, "\"read write\"");
        let back: ScopeSet = serde_json::from_str(&json).unwrap();
        assert_eq!(back, set);
    }

    #[test]
    fn subset_semantics() {
        let all = ScopeSet::parse("a b c").unwrap();
        let some = ScopeSet::parse("a c").unwrap();
        let other = ScopeSet::parse("a d").unwrap();
        assert!(some.is_subset(&all));
        assert!(!other.is_subset(&all));
        assert!(ScopeSet::empty().is_subset(&all));
    }
}
