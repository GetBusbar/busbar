// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE GUEST LISTS (spec: THE DESIGN, Auth points and guest lists, step 3): one per listener, written
//! by the kernel. A line is route → (claimant, dialect, auth); the lines are ordered by CG-62
//! precedence and the listener's transport matches a request against them in that order.
//!
//! ORDER. Most specific path first (the same scores CG-62 seals claims by,
//! [`crate::registry::precedence`]); at an equal path, a line with field predicates ranks above one
//! without, the more specific predicates first; at an equal key, a claimant's own `rung` orders its
//! own lines. Two different claimants' lines that could match one request at an equal key are
//! refused ([`GuestRefusal::EqualPrecedence`]).
//!
//! MATCH. The first line whose path and predicates hold AND whose method set holds the method wins.
//! When some line's path and predicates hold but none admits the method, the answer is a method
//! miss on the first such line (405, never no-route). Otherwise there is no line (the listener's
//! 1.5.5 no-route answer).

use busbar_contract::abi::transport::route::{
    intern, intern_pattern, RouteView, FIELD_VALUE_PREFIX, PATH_CONTAINS, PATH_EXACT, PATH_PATTERN,
    PATH_PREFIX, PATH_SUFFIX,
};
use busbar_contract::grammar::Selector;

/// Who a line is for.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Claimant {
    /// A plane's claim.
    Plane(String),
    /// A plugin's inbound need: the instance and the need's index.
    Need(String, u32),
    /// A cleanliness crate's route, by its capability key (admin, oauth2, the core's own).
    Clean(String),
}

/// A route as a line owns it: the read form of the contract's `RouteMatch`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Route {
    /// `METHOD_*` bits.
    pub methods: u32,
    /// `PATH_*`.
    pub path_form: u32,
    /// The path in its form's spelling.
    pub path: String,
    /// `(FIELD_*, lower-case name, value)`.
    pub fields: Vec<(u32, String, Vec<u8>)>,
    /// The claimant's own order among its own lines.
    pub rung: u32,
}

impl Route {
    /// The contract's read form, which every match goes through.
    #[must_use]
    pub fn view(&self) -> RouteView<'_> {
        RouteView {
            methods: self.methods,
            path_form: self.path_form,
            path: &self.path,
            fields: self
                .fields
                .iter()
                .map(|(op, n, v)| (*op, n.as_str(), v.as_slice()))
                .collect(),
            rung: self.rung,
        }
    }

    /// The path as the grammar's selector, which CG-62 scores and overlaps.
    fn selector(&self) -> Option<Selector> {
        let p = intern(&self.path);
        Some(match self.path_form {
            PATH_EXACT => Selector::ExactPath(p),
            PATH_PATTERN => Selector::PathPattern(intern_pattern(p)?),
            PATH_PREFIX => Selector::PrefixOneLevel(p),
            PATH_SUFFIX => Selector::PathSuffix(p),
            PATH_CONTAINS => Selector::PathContains(p),
            _ => return None,
        })
    }

    /// The field predicates as the grammar's header selectors.
    fn predicate_selectors(&self) -> Vec<Selector> {
        self.fields
            .iter()
            .map(|(op, n, v)| {
                let n = intern(n);
                if *op == FIELD_VALUE_PREFIX {
                    Selector::HeaderPrefix(n, intern(&String::from_utf8_lossy(v)))
                } else {
                    Selector::HeaderPresent(n)
                }
            })
            .collect()
    }

    /// The order key, highest first: path precedence, then whether predicates are named, then their
    /// precedence.
    fn key(&self) -> ((u32, u32), bool, u32) {
        let path = self
            .selector()
            .map_or((0, 0), |s| crate::registry::precedence(&s));
        let preds = self.predicate_selectors();
        let score = preds.iter().map(|s| crate::registry::precedence(s).0).sum();
        (path, !preds.is_empty(), score)
    }

    /// Whether two routes could match one request: their method sets meet, their paths overlap
    /// (CG-62's overlap), and no pair of predicates on one field rules the other out.
    fn could_meet(&self, other: &Route) -> bool {
        if self.methods & other.methods == 0 {
            return false;
        }
        let (Some(a), Some(b)) = (self.selector(), other.selector()) else {
            return true;
        };
        if !crate::registry::overlaps(&a, &b) {
            return false;
        }
        let (pa, pb) = (self.predicate_selectors(), other.predicate_selectors());
        pa.iter().all(|x| {
            pb.iter()
                .all(|y| x.header_name() != y.header_name() || crate::registry::overlaps(x, y))
        })
    }
}

/// The auth a line's guests must pass.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LineAuth {
    /// Anyone (e.g. `/healthz`).
    None,
    /// The resolved chain, tried in order by 1.5.5's chain rule.
    Chain(Vec<String>),
}

/// One line on a guest list.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Line {
    /// Which requests it is for.
    pub route: Route,
    /// Who it is for.
    pub claimant: Claimant,
    /// The claimant's dialect: an opaque id to the kernel.
    pub dialect: u32,
    /// The auth its guests pass.
    pub auth: LineAuth,
    /// The transport the connection is handed to after the head, for an upgrade line.
    pub upgrade: Option<String>,
}

/// Why a guest list is refused at boot.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GuestRefusal {
    /// Two claimants' lines could match one request at an equal precedence (CG-62).
    EqualPrecedence(Box<(Line, Line)>),
}

/// What a request matched.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Matched<'a> {
    /// The line it is for.
    Line(&'a Line),
    /// A line's path and predicates hold but no line admits the method: 405 on this line.
    MethodMiss(&'a Line),
    /// No line: the listener's no-route answer.
    NoRoute,
}

/// One listener's guest list, ordered.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct GuestList {
    lines: Vec<Line>,
}

impl GuestList {
    /// Order `lines` and refuse two claimants' lines that could meet at an equal precedence.
    ///
    /// # Errors
    ///
    /// [`GuestRefusal::EqualPrecedence`], naming both lines.
    pub fn seal(mut lines: Vec<Line>) -> Result<Self, GuestRefusal> {
        // Stable: equal keys keep the declared order, and a claimant's rung orders its own lines.
        lines.sort_by(|a, b| {
            b.route
                .key()
                .cmp(&a.route.key())
                .then(a.route.rung.cmp(&b.route.rung))
        });
        for (i, a) in lines.iter().enumerate() {
            for b in &lines[i + 1..] {
                if a.route.key() != b.route.key() {
                    break;
                }
                if a.claimant != b.claimant && a.route.could_meet(&b.route) {
                    return Err(GuestRefusal::EqualPrecedence(Box::new((
                        a.clone(),
                        b.clone(),
                    ))));
                }
            }
        }
        Ok(Self { lines })
    }

    /// The lines, in the order they are tried.
    #[must_use]
    pub fn lines(&self) -> &[Line] {
        &self.lines
    }

    /// The line a request is for.
    #[must_use]
    pub fn matched(&self, method: &str, path: &str, fields: &[(&str, &[u8])]) -> Matched<'_> {
        let mut miss = None;
        for line in &self.lines {
            let route = line.route.view();
            if !route.path_and_fields_match(path, fields) {
                continue;
            }
            if route.admits(method) {
                return Matched::Line(line);
            }
            miss.get_or_insert(line);
        }
        miss.map_or(Matched::NoRoute, Matched::MethodMiss)
    }
}

#[cfg(test)]
#[path = "tests/guest_tests.rs"]
mod tests;
