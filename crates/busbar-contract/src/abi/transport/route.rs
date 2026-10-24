// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE ROUTE MATCH VOCABULARY, defined once (spec: THE DESIGN, Auth points and guest lists, step 3):
//! how a line on a listener's guest list recognises the requests that are its own. A plane declares
//! its claims in it, the kernel orders a listener's lines by it, and the listener's transport
//! matches a decoded head against it. All three answer through the functions here, so what boot
//! proves and what a request matches cannot differ.
//!
//! A route is a METHOD SET, a PATH in one of five forms, and optional FIELD PREDICATES over the
//! head's field lines. Field names are compared case-insensitively (they are lower-case in a route,
//! refused otherwise at check); a [`FIELD_VALUE_PREFIX`] value is compared case-sensitively.

use std::collections::{HashMap, HashSet};

use crate::abi::host::service::AuthRef;
use crate::abi::mechanism::call::AbiStr;
use crate::grammar::{one_level_under, segs_match, PathSeg, SegRef};

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
/// A segment pattern: `/` separated, a `{name}` segment matches one segment of any value, a
/// `{name+}` segment one or more (at most one per pattern), a last `{*name}` segment everything that
/// remains, including nothing.
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

/// One line of an accepting transport's guest list, as the kernel lends it in `BeginIn::lines`.
///
/// THE DESIGN, Auth points and guest lists, items 3 and 4: the listener's transport matches a
/// decoded head against `route`, in table order (the kernel's precedence order), calls the line's
/// auth at `points` through [`op::AUTH_CALL`](crate::abi::host::service::op::AUTH_CALL) with
/// `auth`, and hands the request in with `line`. A line whose auth is `none` has no points. A line
/// with the body point holds the body up to `body_limit` bytes; over it the transport asks
/// [`op::UNIT_REFUSE`](crate::abi::host::service::op::UNIT_REFUSE) with
/// [`REFUSE_OVER_GATE`](crate::abi::host::service::REFUSE_OVER_GATE) before any verdict.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct LineEntry {
    /// The line's id, as the kernel numbers it; never `LINE_NONE`.
    pub line: u32,
    /// The auth points the line's auth needs: `POINT_PEER` | `POINT_HEAD` | `POINT_HEAD_BODY`;
    /// `0` for a line whose auth is `none`.
    pub points: u32,
    /// The line's auth handle, owner-scoped to this listener's transport.
    pub auth: AuthRef,
    /// The body bound at the body point (the size gate's limit); `0` without that point.
    pub body_limit: u64,
    /// Which requests the line is for.
    pub route: RouteMatch,
}

/// HOW THE ROUTE ROW IS MADE (status row 194): from [`RouteMatch::EMPTY`], its plain fields set
/// directly and each list by its setter, to items that live for the program.
impl RouteMatch {
    /// Nothing stated: every string absent, every list empty, every number zero.
    pub const EMPTY: RouteMatch = RouteMatch {
        methods: 0,
        path_form: 0,
        path: AbiStr::ABSENT,
        fields: std::ptr::null(),
        fields_len: 0,
        rung: 0,
        _reserved: 0,
    };

    abi_lists! {
        fields, fields_len: FieldPredicate => fields_ptr, with_fields, with_raw_fields;
    }
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

/// A `PATH_PATTERN` spelling as segments borrowed from it; `None` when it breaks the syntax (a `{`
/// segment that is not whole, an empty name, a `{*name}` that is not last, or a second `{name+}`).
#[must_use]
pub fn pattern_segments(pattern: &str) -> Option<Vec<SegRef<'_>>> {
    let segs: Vec<&str> = pattern.split('/').filter(|s| !s.is_empty()).collect();
    let mut out = Vec::with_capacity(segs.len());
    for (i, s) in segs.iter().enumerate() {
        let seg = match s.strip_prefix('{').and_then(|r| r.strip_suffix('}')) {
            Some(name) => match (name.strip_prefix('*'), name.strip_suffix('+')) {
                (Some(rest), _) if !rest.is_empty() && i + 1 == segs.len() => SegRef::Tail,
                (Some(_), _) => return None,
                (None, Some(rest))
                    if !rest.is_empty()
                        && !rest.contains(['{', '}', '+'])
                        && !out.contains(&SegRef::Plus) =>
                {
                    SegRef::Plus
                }
                (None, Some(_)) => return None,
                (None, None) if !name.is_empty() && !name.contains(['{', '}']) => SegRef::Var,
                (None, None) => return None,
            },
            None if s.contains(['{', '}']) => return None,
            None => SegRef::Lit(s),
        };
        out.push(seg);
    }
    Some(out)
}

/// AN INTERNER OF ROUTE LITERALS, owned by its holder. The grammar's selectors hold `'static`
/// spellings, so a route the kernel orders by CG-62 needs them; each distinct string is copied once
/// for the life of the process and asking this interner again returns the same pointer. It is a
/// plain value: the contract holds no instance (no static), the caller passes its own in, and a
/// holder that keeps one across reloads adds nothing for routes it has seen.
#[derive(Debug, Default)]
pub struct Interner {
    strings: HashSet<&'static str>,
    patterns: HashMap<&'static str, &'static [PathSeg]>,
}

impl Interner {
    /// `s` as a `'static` spelling, one copy per distinct string in this interner.
    #[must_use]
    pub fn intern(&mut self, s: &str) -> &'static str {
        if let Some(s) = self.strings.get(s).copied() {
            return s;
        }
        let s: &'static str = Box::leak(s.to_owned().into_boxed_str());
        self.strings.insert(s);
        s
    }

    /// A `PATH_PATTERN` as the grammar's `'static` segments, parsed and kept once per distinct
    /// pattern; `None` when it breaks the syntax.
    #[must_use]
    pub fn intern_pattern(&mut self, pattern: &str) -> Option<&'static [PathSeg]> {
        let seen = self.strings.get(pattern).copied();
        if let Some(segs) = seen.and_then(|k| self.patterns.get(k).copied()) {
            return Some(segs);
        }
        let spelled = pattern_segments(pattern)?;
        let key = self.intern(pattern);
        let mut segs = Vec::with_capacity(spelled.len());
        for s in spelled {
            segs.push(match s {
                SegRef::Lit(l) => PathSeg::Lit(self.intern(l)),
                SegRef::Var => PathSeg::Var,
                SegRef::Tail => PathSeg::Tail,
                SegRef::Plus => PathSeg::Plus,
            });
        }
        let segs: &'static [PathSeg] = Vec::leak(segs);
        self.patterns.insert(key, segs);
        Some(segs)
    }

    /// How many distinct strings and patterns this interner holds (strings, patterns).
    #[must_use]
    pub fn counts(&self) -> (usize, usize) {
        (self.strings.len(), self.patterns.len())
    }
}

/// Whether `path` matches a route's path in `form`, the one spelling of every form. A pattern that
/// breaks the syntax matches nothing ([`crate::abi::transport::check::check_route`] refuses it).
#[must_use]
pub fn path_matches(form: u32, route_path: &str, path: &str) -> bool {
    match form {
        PATH_EXACT => path == route_path,
        PATH_PATTERN => pattern_segments(route_path).is_some_and(|p| segs_match(p, path)),
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
