// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE ARRIVAL SPANS (status row 173): the request span an arrival on a plane's route opens, as the
//! previous release's ingress entry spans did (v1.5.5 `docs/observability.md` l.162-174: every
//! hot-path request span at `HOTPATH_LEVEL`, exported by OTLP). The kernel names no dialect: a
//! span's name, and the fields it records, are DATA the plane states on its claims
//! (`busbar_contract::abi::plane::PlaneSnapshot::arrival_spans`), and the kernel builds one tracing
//! callsite per distinct name and field set when it binds the routes, never per request. An arrival
//! then opens that span: a disabled callsite answers [`tracing::Span::none`].

use std::collections::HashMap;
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::{Mutex, OnceLock, PoisonError};

use tracing::callsite::{Callsite, Identifier};
use tracing::field::{FieldSet, Value};
use tracing::metadata::Kind;
use tracing::subscriber::Interest;
use tracing::{Metadata, Span};

use busbar_contract::abi::plane::check::{
    entry_fact, entry_path_matches, raw_affix_matches, EntryPredicate,
};
use busbar_contract::abi::plane::{CLAIM_ENTRY, CLAIM_RAW_AFFIX};

use super::HOTPATH_LEVEL;

/// The target every arrival span is recorded under: the previous release's, whose ingress entry
/// spans were each a `#[tracing::instrument]` in its `ingress` module (v1.5.5 `ingress/mod.rs:788`,
/// `:1043`, `:1070`, `:1161`, `:1292`), so an exporter states the same `target` (status row 173).
const TARGET: &str = "busbar::ingress";

/// The most distinct arrival span callsites one process builds. A plane states a handful; a name
/// past the last site opens no span (and says so once), never an allocation per request.
pub const MAX_ARRIVAL_SPANS: usize = 64;

/// The most fields one arrival span records (an entry fact's named path segments).
pub const MAX_ARRIVAL_FIELDS: usize = 3;

/// What the registered subscribers said of a callsite, cached: never, sometimes, always, or not yet
/// asked.
const NEVER: u8 = 0;
const SOMETIMES: u8 = 1;
const ALWAYS: u8 = 2;
const UNASKED: u8 = 3;

/// One named span's callsite: a slot of the process's fixed table, its name, its field names and
/// its metadata set once when a binding first states them, kept for the life of the process.
struct Site {
    name: OnceLock<String>,
    fields: [OnceLock<String>; MAX_ARRIVAL_FIELDS],
    field_names: OnceLock<Vec<&'static str>>,
    meta: OnceLock<Metadata<'static>>,
    interest: AtomicU8,
}

impl Site {
    const fn new() -> Self {
        Self {
            name: OnceLock::new(),
            fields: [const { OnceLock::new() }; MAX_ARRIVAL_FIELDS],
            field_names: OnceLock::new(),
            meta: OnceLock::new(),
            interest: AtomicU8::new(UNASKED),
        }
    }
}

impl Callsite for Site {
    fn set_interest(&self, interest: Interest) {
        let cached = if interest.is_never() {
            NEVER
        } else if interest.is_always() {
            ALWAYS
        } else {
            SOMETIMES
        };
        self.interest.store(cached, Ordering::Relaxed);
    }

    fn metadata(&self) -> &Metadata<'_> {
        // Set before the site is registered, and never after: registration is what asks for it.
        self.meta.get().unwrap_or(&NONE_META)
    }
}

/// THE CALLSITES, one slot per distinct name and field set, in the order bindings first state them.
static SITES: [Site; MAX_ARRIVAL_SPANS] = [const { Site::new() }; MAX_ARRIVAL_SPANS];

/// The metadata a slot answers before its own is set, which no registered slot ever does.
static NONE_SITE: Site = Site::new();
static NONE_META: Metadata<'static> = Metadata::new(
    "arrival",
    TARGET,
    HOTPATH_LEVEL,
    None,
    None,
    None,
    FieldSet::new(&[], Identifier(&NONE_SITE)),
    Kind::SPAN,
);

/// AN ARRIVAL SPAN: the callsite of one name (and field set) a plane's claim states. `Copy`, so a
/// route's handler holds it by value.
#[derive(Clone, Copy)]
pub struct ArrivalSpan {
    site: &'static Site,
}

impl std::fmt::Debug for ArrivalSpan {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("ArrivalSpan").field(&self.name()).finish()
    }
}

impl ArrivalSpan {
    /// The span `name` opens, with no field; `None` for an empty name (the claim opens none), and
    /// for a name past the process's [`MAX_ARRIVAL_SPANS`].
    #[must_use]
    pub fn named(name: &str) -> Option<Self> {
        Self::with_fields(name, &[])
    }

    /// The span `name` opens, recording `fields` in order; `None` for an empty name, more than
    /// [`MAX_ARRIVAL_FIELDS`] fields, or a callsite past the process's [`MAX_ARRIVAL_SPANS`]. One
    /// callsite per distinct name and field set for the life of the process: binding the same
    /// again answers the same callsite, so a refresh that re-binds routes builds nothing new.
    #[must_use]
    pub fn with_fields(name: &str, fields: &[&str]) -> Option<Self> {
        if name.is_empty() || fields.len() > MAX_ARRIVAL_FIELDS {
            return None;
        }
        static BOUND: OnceLock<Mutex<HashMap<String, usize>>> = OnceLock::new();
        let key = format!("{name}({})", fields.join(","));
        let mut bound = BOUND
            .get_or_init(Mutex::default)
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        if let Some(&at) = bound.get(&key) {
            return Some(Self { site: &SITES[at] });
        }
        let at = bound.len();
        let Some(site) = SITES.get(at) else {
            tracing::warn!(
                span = name,
                most = MAX_ARRIVAL_SPANS,
                "an arrival span past the process's callsite table opens no span"
            );
            return None;
        };
        // Built once per name and field set, off the hot path, and kept: a callsite lives as long
        // as the process.
        let named: &'static str = site.name.get_or_init(|| name.to_owned()).as_str();
        let names: &'static [&'static str] = site
            .field_names
            .get_or_init(|| {
                site.fields
                    .iter()
                    .zip(fields)
                    .map(|(slot, field)| slot.get_or_init(|| (*field).to_owned()).as_str())
                    .collect()
            })
            .as_slice();
        let _set = site.meta.set(Metadata::new(
            named,
            TARGET,
            HOTPATH_LEVEL,
            Some(file!()),
            Some(line!()),
            Some(module_path!()),
            FieldSet::new(names, Identifier(site)),
            Kind::SPAN,
        ));
        tracing::callsite::register(site);
        bound.insert(key, at);
        Some(Self { site })
    }

    /// The span's name.
    #[must_use]
    pub fn name(&self) -> &'static str {
        self.site.name.get().map_or("", String::as_str)
    }

    /// Open the span for one arrival, under the current span, with no field value.
    #[must_use]
    pub fn open(self) -> Span {
        self.open_with(&[])
    }

    /// Open the span for one arrival, under the current span, recording `values` against its
    /// fields in order. [`Span::none`] where no subscriber wants it, or where the values are not
    /// one per field.
    #[must_use]
    pub fn open_with(self, values: &[&str]) -> Span {
        let Some(meta) = self.site.meta.get() else {
            return Span::none();
        };
        if self.site.interest.load(Ordering::Relaxed) == NEVER
            || tracing::level_filters::LevelFilter::current() < HOTPATH_LEVEL
        {
            return Span::none();
        }
        if !tracing::dispatcher::get_default(|d| d.enabled(meta)) {
            return Span::none();
        }
        let set = meta.fields();
        if values.len() != set.len() {
            return Span::none();
        }
        let mut field = set.iter();
        let (a, b, c) = (field.next(), field.next(), field.next());
        match (values, a, b, c) {
            ([], None, None, None) => Span::new(meta, &set.value_set(&[])),
            ([x], Some(a), None, None) => {
                Span::new(meta, &set.value_set(&[(&a, Some(x as &dyn Value))]))
            }
            ([x, y], Some(a), Some(b), None) => Span::new(
                meta,
                &set.value_set(&[(&a, Some(x as &dyn Value)), (&b, Some(y as &dyn Value))]),
            ),
            ([x, y, z], Some(a), Some(b), Some(c)) => Span::new(
                meta,
                &set.value_set(&[
                    (&a, Some(x as &dyn Value)),
                    (&b, Some(y as &dyn Value)),
                    (&c, Some(z as &dyn Value)),
                ]),
            ),
            _ => Span::none(),
        }
    }
}

/// How one of a plane's facts is read off the request.
#[derive(Debug)]
enum Shape {
    /// A raw affix ([`CLAIM_RAW_AFFIX`]) the raw path matches.
    Affix(String),
    /// An entry fact ([`CLAIM_ENTRY`]): head fields, by name and value prefix, and a path pattern.
    Entry {
        fields: Vec<(String, Option<String>)>,
        path: Option<String>,
    },
}

/// One fact: the verb it is for, how it is read, and the span it opens (`None`: the reading ends
/// there with no span).
#[derive(Debug)]
struct Fact {
    verb: String,
    shape: Shape,
    span: Option<ArrivalSpan>,
}

/// THE ENTRY SPANS OF ONE PLANE'S ROUTES (status row 173), built once from its snapshot's claims
/// when the routes are bound: the plane's FACTS, read in its snapshot's order, then each routed
/// claim's own span. A fact mounts no route; it states which entry span an arrival opens when the
/// request meets it, as the previous release chose its entry by the request's head fields and its
/// path's shape (v1.5.5 `proto/detect.rs` `protocol_id`, then the entry's own path test):
///
/// - an entry fact ([`CLAIM_ENTRY`]) by its predicates; one that states no span ends the reading,
///   and the arrival opens none;
/// - a raw affix ([`CLAIM_RAW_AFFIX`]) that states a span, by its affixes (one that states none is
///   no fact here: it states something else about its paths).
///
/// The kernel reads both as data and names no dialect.
#[derive(Debug, Default)]
pub struct EntrySpans {
    /// Each claim's own span, by its index in the snapshot (none for a fact).
    claims: Vec<Option<ArrivalSpan>>,
    /// The facts, in the snapshot's order.
    facts: Vec<Fact>,
}

/// A head field the request carries, as the entry facts read it: its value, or, for a field the
/// host's auth consumed, its scheme word alone (empty when its value has none).
pub type HeadField<'a> = &'a str;

impl EntrySpans {
    /// The entry spans of a snapshot's claims, each `(verb, target, flags, arrival span)` in the
    /// snapshot's order. An entry fact whose target does not parse is no fact.
    #[must_use]
    pub fn of<'a>(claims: impl IntoIterator<Item = (&'a str, &'a str, u32, &'a str)>) -> Self {
        let mut spans = Self::default();
        for (verb, target, flags, name) in claims {
            if flags & CLAIM_ENTRY != 0 {
                spans.claims.push(None);
                let Some(predicates) = entry_fact(target) else {
                    continue;
                };
                let mut fields = Vec::new();
                let mut path = None;
                for p in predicates {
                    match p {
                        EntryPredicate::Field(name, prefix) => {
                            fields.push((name.to_owned(), prefix.map(str::to_owned)));
                        }
                        EntryPredicate::Path(pattern) => path = Some(pattern.to_owned()),
                    }
                }
                let captured = path.as_deref().map(captures_of).unwrap_or_default();
                let span = if name.is_empty() {
                    None
                } else {
                    match ArrivalSpan::with_fields(name, &captured) {
                        Some(span) => Some(span),
                        // A span this process cannot build is no fact rather than a false stop.
                        None => continue,
                    }
                };
                spans.facts.push(Fact {
                    verb: verb.to_owned(),
                    shape: Shape::Entry { fields, path },
                    span,
                });
            } else if flags & CLAIM_RAW_AFFIX != 0 {
                spans.claims.push(None);
                if let Some(span) = ArrivalSpan::named(name) {
                    spans.facts.push(Fact {
                        verb: verb.to_owned(),
                        shape: Shape::Affix(target.to_owned()),
                        span: Some(span),
                    });
                }
            } else {
                spans.claims.push(ArrivalSpan::named(name));
            }
        }
        spans
    }

    /// The span an arrival on routed claim `claim` opens, by its `method`, its RAW path and its
    /// head fields (`field` answers a field by its lower-case name): the first fact of its verb it
    /// meets, else the claim's own. [`Span::none`] where neither states one, or where no subscriber
    /// takes the hot-path level (nothing is compared then).
    #[must_use]
    pub fn open<'h>(
        &self,
        claim: u32,
        method: &str,
        path: &str,
        field: impl Fn(&str) -> Option<HeadField<'h>>,
    ) -> Span {
        if tracing::level_filters::LevelFilter::current() < HOTPATH_LEVEL {
            return Span::none();
        }
        let mut captures = Vec::new();
        for fact in self.facts.iter().filter(|f| f.verb == method) {
            captures.clear();
            let met = match &fact.shape {
                Shape::Affix(affix) => raw_affix_matches(affix, path),
                Shape::Entry {
                    fields,
                    path: pattern,
                } => {
                    fields.iter().all(|(name, prefix)| {
                        field(name.as_str()).is_some_and(|value| {
                            prefix.as_deref().is_none_or(|p| value.starts_with(p))
                        })
                    }) && pattern
                        .as_deref()
                        .is_none_or(|p| entry_path_matches(p, path, &mut captures))
                }
            };
            if !met {
                continue;
            }
            let Some(span) = fact.span else {
                return Span::none();
            };
            let values: Vec<String> = captures
                .iter()
                .map(|(_, seg)| super::percent_decode(&String::from_utf8_lossy(seg)))
                .collect();
            let values: Vec<&str> = values.iter().map(String::as_str).collect();
            return span.open_with(&values);
        }
        self.claims
            .get(claim as usize)
            .copied()
            .flatten()
            .map_or_else(Span::none, ArrivalSpan::open)
    }
}

/// The named segments of an entry path pattern, in order: its span's fields.
fn captures_of(pattern: &str) -> Vec<&str> {
    let mut out = Vec::new();
    let mut rest = pattern;
    while let Some(open) = rest.find('{') {
        let Some(close) = rest[open..].find('}').map(|c| open + c) else {
            break;
        };
        let name = &rest[open + 1..close];
        if !name.is_empty() {
            out.push(name);
        }
        rest = &rest[close + 1..];
    }
    out
}

#[cfg(test)]
#[path = "../tests/arrival_span_tests.rs"]
mod tests;
