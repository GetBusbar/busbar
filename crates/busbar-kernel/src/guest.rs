// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use std::sync::{Mutex, MutexGuard, OnceLock};

use busbar_contract::abi::auth::{AuthPoint, AuthPoints};
use busbar_contract::abi::mechanism::check::Fault;
use busbar_contract::abi::transport::check::check_route_view;
use busbar_contract::abi::transport::route::{
    Interner, RouteView, FIELD_VALUE_PREFIX, PATH_CONTAINS, PATH_EXACT, PATH_PATTERN, PATH_PREFIX,
    PATH_SUFFIX,
};
use busbar_contract::grammar::Selector;

fn literals() -> MutexGuard<'static, Interner> {
    static LITERALS: OnceLock<Mutex<Interner>> = OnceLock::new();
    LITERALS
        .get_or_init(|| Mutex::new(Interner::default()))
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

#[must_use]
pub fn interned_counts() -> (usize, usize) {
    literals().counts()
}

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

    fn selector(&self) -> Option<Selector> {
        let mut literals = literals();
        let p = literals.intern(&self.path);
        Some(match self.path_form {
            PATH_EXACT => Selector::ExactPath(p),
            PATH_PATTERN => Selector::PathPattern(literals.intern_pattern(p)?),
            PATH_PREFIX => Selector::PrefixOneLevel(p),
            PATH_SUFFIX => Selector::PathSuffix(p),
            PATH_CONTAINS => Selector::PathContains(p),
            _ => return None,
        })
    }

    fn predicate_selectors(&self) -> Vec<Selector> {
        let mut literals = literals();
        self.fields
            .iter()
            .map(|(op, n, v)| {
                let n = literals.intern(n);
                if *op == FIELD_VALUE_PREFIX {
                    Selector::HeaderPrefix(n, literals.intern(&String::from_utf8_lossy(v)))
                } else {
                    Selector::HeaderPresent(n)
                }
            })
            .collect()
    }

    fn key(&self) -> ((u32, u32), bool, u32) {
        let path = self
            .selector()
            .map_or((0, 0), |s| crate::registry::precedence(&s));
        let preds = self.predicate_selectors();
        let score = preds.iter().map(|s| crate::registry::precedence(s).0).sum();
        (path, !preds.is_empty(), score)
    }

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
    /// The resolved chain, tried in order by 1.5.5's chain rule, and the line's point set: the
    /// union of its auths' declared sets.
    Chain(Vec<String>, AuthPoints),
}

impl LineAuth {
    #[must_use]
    pub fn points(&self) -> AuthPoints {
        match self {
            Self::None => AuthPoints::EMPTY,
            Self::Chain(_, points) => *points,
        }
    }
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
    /// The auth points the transport that runs the line's auth offers: its auth may need no other.
    pub offered: AuthPoints,
}

/// Why a guest list is refused at boot.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GuestRefusal {
    /// Two claimants' lines could match one request at an equal precedence (CG-62).
    EqualPrecedence(Box<(Line, Line)>),
    /// Some lines need `Peer` and others need a per-request point without it: the lines that need
    /// `Peer`, then the lines that need only `Head` or `HeadBody`, each in the order they are
    /// tried. A line that needs no point is on neither side.
    PeerMix(Box<(Vec<Line>, Vec<Line>)>),
    /// A line's auth needs a point its transport does not offer: the line.
    PointNotOffered(Box<Line>),
    /// A line's route no request can match, by the contract's content check
    /// (`check_route_view`): the line and the rule it breaks.
    Malformed(Box<(Line, Fault)>),
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
    connection_gated: bool,
}

impl GuestList {
    pub fn seal(mut lines: Vec<Line>) -> Result<Self, GuestRefusal> {
        for line in &lines {
            if let Err(fault) = check_route_view(&line.route.view()) {
                return Err(GuestRefusal::Malformed(Box::new((line.clone(), fault))));
            }
        }

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
        let peer = |l: &Line| l.auth.points().has(AuthPoint::Peer);
        let per_request = |l: &Line| {
            let points = l.auth.points();
            !points.has(AuthPoint::Peer)
                && (points.has(AuthPoint::Head) || points.has(AuthPoint::HeadBody))
        };
        let connection_gated = lines.iter().any(peer);
        if connection_gated && lines.iter().any(per_request) {
            let need = lines.iter().filter(|l| peer(l)).cloned().collect();
            let without = lines.iter().filter(|l| per_request(l)).cloned().collect();
            return Err(GuestRefusal::PeerMix(Box::new((need, without))));
        }
        if let Some(line) = lines
            .iter()
            .find(|l| l.auth.points().bits() & !l.offered.bits() != 0)
        {
            return Err(GuestRefusal::PointNotOffered(Box::new(line.clone())));
        }
        Ok(Self {
            lines,
            connection_gated,
        })
    }

    #[must_use]
    pub fn connection_gated(&self) -> bool {
        self.connection_gated
    }

    #[must_use]
    pub fn lines(&self) -> &[Line] {
        &self.lines
    }

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
