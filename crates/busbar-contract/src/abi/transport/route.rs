// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE ROUTE MATCH VOCABULARY, defined once (THE DESIGN §6, "Auth points and guest lists", step 3):
//! how a line on a listener's guest list recognises the requests that are its own. A plane declares
//! its claims in it, the kernel orders a listener's lines by it, and the listener's transport
//! matches a decoded head against it. All three answer through the functions here, so what boot
//! proves and what a request matches cannot differ.
//!
//! A route is a METHOD SET, a PATH in one of five forms, and optional FIELD PREDICATES over the
//! head's field lines. Field names are compared case-insensitively (they are lower-case in a route,
//! refused otherwise at check); a [`FIELD_VALUE_PREFIX`] value is compared case-sensitively.

use crate::abi::mechanism::call::AbiStr;
use crate::grammar::{one_level_under, pattern_matches, PathSeg};

/// `GET`.
pub const METHOD_GET: u32 = 1;
/// `HEAD`.
pub const METHOD_HEAD: u32 = 1 << 1;
/// `POST`.
pub const METHOD_POST: u32 = 1 << 2;
/// `PUT`.
pub const METHOD_PUT: u32 = 1 << 3;
/// `PATCH`.
pub const METHOD_PATCH: u32 = 1 << 4;
/// `DELETE`.
pub const METHOD_DELETE: u32 = 1 << 5;
/// `OPTIONS`.
pub const METHOD_OPTIONS: u32 = 1 << 6;
/// `CONNECT`.
pub const METHOD_CONNECT: u32 = 1 << 7;
/// `TRACE`.
pub const METHOD_TRACE: u32 = 1 << 8;
/// Every method.
pub const METHOD_ANY: u32 = (1 << 9) - 1;

/// The whole path equals the route's path.
pub const PATH_EXACT: u32 = 1;
/// A segment pattern: `/` separated, a `{name}` segment matches one segment of any value, a last
/// `{*name}` segment matches everything that remains, including nothing.
pub const PATH_PATTERN: u32 = 2;
/// Exactly one segment under the route's path (`/a` admits `/a/b`, never `/a`, `/ab` or `/a/b/c`).
pub const PATH_PREFIX: u32 = 3;
/// The path ends with the route's path.
pub const PATH_SUFFIX: u32 = 4;
/// The path contains the route's path.
pub const PATH_CONTAINS: u32 = 5;

/// The field line is present, whatever its value.
pub const FIELD_PRESENT: u32 = 1;
/// The field line is present and its value starts with the predicate's value.
pub const FIELD_VALUE_PREFIX: u32 = 2;

/// One field predicate of a route.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct FieldPredicate {
    /// [`FIELD_PRESENT`] | [`FIELD_VALUE_PREFIX`].
    pub op: u32,
    /// Alignment padding.
    pub _reserved: u32,
    /// The field name, lower-case.
    pub name: AbiStr,
    /// The value prefix ([`FIELD_VALUE_PREFIX`]); absent otherwise.
    pub value: AbiStr,
}

/// One route: which requests a guest-list line is for.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct RouteMatch {
    /// The methods it admits, a set of `METHOD_*` bits.
    pub methods: u32,
    /// `PATH_*`.
    pub path_form: u32,
    /// The path, in its form's spelling.
    pub path: AbiStr,
    /// Its field predicates, all of which hold for a match.
    pub fields: *const FieldPredicate,
    /// How many.
    pub fields_len: usize,
    /// The claimant's own order: among ONE claimant's lines of equal precedence, the lower rung is
    /// tried first (a plane's 1.5.5 dispatch ladder, reproduced). It never orders two claimants.
    pub rung: u32,
    /// Alignment padding.
    pub _reserved: u32,
}

/// A [`RouteMatch`] read into Rust: what the kernel orders and matches, and what
/// [`crate::abi::transport::check::check_route_view`] judges.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RouteView<'a> {
    /// `METHOD_*` bits.
    pub methods: u32,
    /// `PATH_*`.
    pub path_form: u32,
    /// The path.
    pub path: &'a str,
    /// The field predicates: `(FIELD_*, name, value)`.
    pub fields: Vec<(u32, &'a str, &'a [u8])>,
    /// The claimant's own order.
    pub rung: u32,
}

impl RouteView<'_> {
    /// Whether the path and every field predicate hold for a request, whatever its method.
    #[must_use]
    pub fn path_and_fields_match(&self, path: &str, fields: &[(&str, &[u8])]) -> bool {
        path_matches(self.path_form, self.path, path)
            && self
                .fields
                .iter()
                .all(|(op, name, value)| field_holds(*op, name, value, fields))
    }

    /// Whether the route admits `method`.
    #[must_use]
    pub fn admits(&self, method: &str) -> bool {
        self.methods & method_bit(method) != 0
    }
}

/// The `METHOD_*` bit of a request method; `0` for one outside the vocabulary.
#[must_use]
pub fn method_bit(method: &str) -> u32 {
    match method {
        "GET" => METHOD_GET,
        "HEAD" => METHOD_HEAD,
        "POST" => METHOD_POST,
        "PUT" => METHOD_PUT,
        "PATCH" => METHOD_PATCH,
        "DELETE" => METHOD_DELETE,
        "OPTIONS" => METHOD_OPTIONS,
        "CONNECT" => METHOD_CONNECT,
        "TRACE" => METHOD_TRACE,
        _ => 0,
    }
}

/// A `PATH_PATTERN` spelling as segments; `None` when it breaks the syntax (a `{` segment that is
/// not whole, an empty name, or a `{*name}` that is not last).
#[must_use]
pub fn pattern_segments(pattern: &str) -> Option<Vec<PathSeg>> {
    let segs: Vec<&str> = pattern.split('/').filter(|s| !s.is_empty()).collect();
    let mut out = Vec::with_capacity(segs.len());
    for (i, s) in segs.iter().enumerate() {
        let seg = match s.strip_prefix('{').and_then(|r| r.strip_suffix('}')) {
            Some(name) => match name.strip_prefix('*') {
                Some(rest) if !rest.is_empty() && i + 1 == segs.len() => PathSeg::Tail,
                Some(_) => return None,
                None if !name.is_empty() && !name.contains(['{', '}']) => PathSeg::Var,
                None => return None,
            },
            None if s.contains(['{', '}']) => return None,
            // The literal outlives the call as the pattern does; the matcher copies nothing.
            None => PathSeg::Lit(leak(s)),
        };
        out.push(seg);
    }
    Some(out)
}

/// A literal segment for [`PathSeg::Lit`], which holds `'static` strings: interned once per distinct
/// spelling, so a route checked at every boot costs one copy of each literal for the process.
fn leak(s: &str) -> &'static str {
    use std::collections::HashSet;
    use std::sync::{Mutex, OnceLock};
    static SEEN: OnceLock<Mutex<HashSet<&'static str>>> = OnceLock::new();
    let mut seen = SEEN
        .get_or_init(|| Mutex::new(HashSet::new()))
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    if let Some(s) = seen.get(s) {
        return s;
    }
    let s: &'static str = Box::leak(s.to_owned().into_boxed_str());
    seen.insert(s);
    s
}

/// Whether `path` matches a route's path in `form`, the one spelling of every form. A pattern that
/// breaks the syntax matches nothing ([`crate::abi::transport::check::check_route`] refuses it).
#[must_use]
pub fn path_matches(form: u32, route_path: &str, path: &str) -> bool {
    match form {
        PATH_EXACT => path == route_path,
        PATH_PATTERN => pattern_segments(route_path).is_some_and(|p| pattern_matches(&p, path)),
        PATH_PREFIX => one_level_under(route_path, path),
        PATH_SUFFIX => path.ends_with(route_path),
        PATH_CONTAINS => path.contains(route_path),
        _ => false,
    }
}

/// Whether one field predicate holds over a head's field lines (`(name, value)`, names in any
/// case): the name case-insensitively, a value prefix case-sensitively.
#[must_use]
pub fn field_holds(op: u32, name: &str, value: &[u8], fields: &[(&str, &[u8])]) -> bool {
    fields
        .iter()
        .filter(|(n, _)| n.eq_ignore_ascii_case(name))
        .any(|(_, v)| match op {
            FIELD_PRESENT => true,
            FIELD_VALUE_PREFIX => v.starts_with(value),
            _ => false,
        })
}

#[cfg(test)]
#[path = "../tests/transport_route_tests.rs"]
mod tests;
