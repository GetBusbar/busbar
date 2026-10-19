// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! WHICH `cfg` PREDICATES MEAN "TEST ONLY" — ONE ANSWER FOR EVERY CLASSIFIER.
//!
//! The scanner ([`crate::scan`]), the structure-lint corpus and the LOC counter each decide whether
//! the item under a `#[cfg(..)]` is test code. They used to decide it three ways, and all three read
//! `any(test, X)` as test whatever `X` was. `any(test, feature = "root-admin")` compiles into the
//! DEFAULT build (`root-admin` is on the binary's `default` line), so the code under it ships, yet
//! every gate and the size counter booked it as test and skipped it.
//!
//! The rule, over the predicate as a tree:
//!
//! * `test` is test-only; so is a feature in [`TEST_ONLY_FEATURES`] (a feature no shipping build
//!   enables).
//! * `all(..)` is test-only when ANY conjunct is (the item exists only when that conjunct holds).
//! * `any(..)` is test-only when EVERY arm is (the item exists when any arm holds, so one shipping
//!   arm puts it in the shipping build).
//! * `not(..)` is never test-only: it is the arm that ships.
//! * Anything else (an unlisted feature, `unix`, `debug_assertions`) is not.

/// THE DECLARED LIST of features that only a test or harness build turns on. Each is declared in a
/// `Cargo.toml` of this tree and is on no `default` line and no non-dev dependency edge.
///
/// * `test-support` — `busbar-kernel`, `busbar-core-admin`, `busbar-core-connector`,
///   `busbar-core-oauth2`, `busbar-kernel-audit`, `busbar-plane-llm`, `busbar-llm`, `plugin-loader`
/// * `test-harness` — `busbar`
/// * `test-seal`, `services-double` — `busbar-contract`
/// * `conformance` — `plugin-loader`
///
/// A feature added here is a claim that no shipping build enables it; a shipping feature such as
/// `root-admin` or `openapi-schema` must never be listed.
pub const TEST_ONLY_FEATURES: &[&str] = &[
    "test-support",
    "test-harness",
    "test-seal",
    "services-double",
    "conformance",
];

/// A parsed `cfg` predicate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Pred {
    /// The bare `test` ident.
    Test,
    /// `feature = "name"`.
    Feature(String),
    Not(Vec<Pred>),
    All(Vec<Pred>),
    Any(Vec<Pred>),
    /// Any other predicate (`unix`, `target_os = "linux"`, `debug_assertions`, ...).
    Other,
}

impl Pred {
    /// Is the item under this predicate compiled ONLY in test or test-harness builds, and does the
    /// predicate REQUIRE `test` (or a test-only feature) to hold.
    pub fn is_test_only(&self) -> bool {
        match self {
            Pred::Test => true,
            Pred::Feature(f) => TEST_ONLY_FEATURES.contains(&f.as_str()),
            Pred::All(args) => args.iter().any(Pred::is_test_only),
            Pred::Any(args) => !args.is_empty() && args.iter().all(Pred::is_test_only),
            Pred::Not(_) | Pred::Other => false,
        }
    }

    /// As [`Pred::is_test_only`], but a bare test-only FEATURE does not count: the predicate must
    /// name `test` itself on every path. A feature alone is a feature, not a test build.
    pub fn requires_test(&self) -> bool {
        match self {
            Pred::Test => true,
            Pred::All(args) => args.iter().any(Pred::requires_test),
            Pred::Any(args) => !args.is_empty() && args.iter().all(Pred::is_test_only) && {
                args.iter().any(Pred::requires_test)
            },
            Pred::Feature(_) | Pred::Not(_) | Pred::Other => false,
        }
    }
}

/// Parse the predicate of an attribute line: the text after `cfg(`, up to its matching `)`. A
/// missing close (an attribute continued on the next line) ends the predicate at the end of the
/// text. `None` when `attr` is not a `#[cfg(..)]` attribute.
pub fn parse_attr(attr: &str) -> Option<Pred> {
    let t = attr.trim_start().strip_prefix("#[")?.trim_start();
    let t = t.strip_prefix("cfg")?.trim_start().strip_prefix('(')?;
    let chars: Vec<char> = t.chars().collect();
    let mut at = 0;
    Some(parse_pred(&chars, &mut at))
}

fn skip_ws(c: &[char], at: &mut usize) {
    while *at < c.len() && c[*at].is_whitespace() {
        *at += 1;
    }
}

fn parse_pred(c: &[char], at: &mut usize) -> Pred {
    skip_ws(c, at);
    let start = *at;
    while *at < c.len() && (c[*at].is_alphanumeric() || c[*at] == '_') {
        *at += 1;
    }
    let name: String = c[start..*at].iter().collect();
    skip_ws(c, at);
    match c.get(*at) {
        Some('(') => {
            *at += 1;
            let mut args = Vec::new();
            loop {
                skip_ws(c, at);
                match c.get(*at) {
                    None => break,
                    Some(')') => {
                        *at += 1;
                        break;
                    }
                    Some(',') => *at += 1,
                    Some(_) => {
                        let before = *at;
                        args.push(parse_pred(c, at));
                        if *at == before {
                            *at += 1;
                        }
                    }
                }
            }
            match name.as_str() {
                "not" => Pred::Not(args),
                "all" => Pred::All(args),
                "any" => Pred::Any(args),
                _ => Pred::Other,
            }
        }
        Some('=') => {
            *at += 1;
            skip_ws(c, at);
            let mut value = String::new();
            if c.get(*at) == Some(&'"') {
                *at += 1;
                while *at < c.len() && c[*at] != '"' {
                    value.push(c[*at]);
                    *at += 1;
                }
                *at += 1;
            }
            if name == "feature" {
                Pred::Feature(value)
            } else {
                Pred::Other
            }
        }
        _ if name == "test" => Pred::Test,
        _ => Pred::Other,
    }
}

#[cfg(test)]
#[path = "tests/cfg_scope_tests.rs"]
mod tests;
