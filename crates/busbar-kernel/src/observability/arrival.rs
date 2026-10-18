// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE ARRIVAL SPANS (status row 173): the request span an arrival on a plane's route opens, as the
//! previous release's ingress entry spans did (v1.5.5 `docs/observability.md` l.162-174: every
//! hot-path request span at `HOTPATH_LEVEL`, `skip_all`, exported by OTLP). The kernel names no
//! dialect: a span's name is DATA the plane states on its claim
//! (`busbar_contract::abi::plane::PlaneSnapshot::arrival_spans`), and the kernel builds one tracing
//! callsite per distinct name when it binds the routes, never per request. An arrival then opens
//! that span with no allocation of its own: a disabled callsite answers [`tracing::Span::none`].

use std::collections::HashMap;
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::{Mutex, OnceLock, PoisonError};

use tracing::callsite::{Callsite, Identifier};
use tracing::field::FieldSet;
use tracing::metadata::Kind;
use tracing::subscriber::Interest;
use tracing::{Metadata, Span};

use super::HOTPATH_LEVEL;

/// The target every arrival span is recorded under: the kernel's, as the previous release's ingress
/// entry spans were the binary's own.
const TARGET: &str = "busbar";

/// The most distinct arrival span names one process builds a callsite for. A plane states a handful;
/// a name past the last site opens no span (and says so once), never an allocation per request.
pub const MAX_ARRIVAL_SPANS: usize = 64;

/// What the registered subscribers said of a callsite, cached: never, sometimes, always, or not yet
/// asked.
const NEVER: u8 = 0;
const SOMETIMES: u8 = 1;
const ALWAYS: u8 = 2;
const UNASKED: u8 = 3;

/// One named span's callsite: a slot of the process's fixed table, its name and metadata set once
/// when a binding first states the name, kept for the life of the process.
struct Site {
    name: OnceLock<String>,
    meta: OnceLock<Metadata<'static>>,
    interest: AtomicU8,
}

impl Site {
    const fn new() -> Self {
        Self {
            name: OnceLock::new(),
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

/// THE CALLSITES, one slot per distinct name, in the order bindings first state them.
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

/// AN ARRIVAL SPAN: the callsite of one name a plane's claim states. `Copy`, so a route's handler
/// holds it by value.
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
    /// The span `name` opens; `None` for an empty name (the claim opens none), and for a name past
    /// the process's [`MAX_ARRIVAL_SPANS`]. One callsite per distinct name for the life of the
    /// process: binding the same name again answers the same callsite, so a refresh that re-binds
    /// routes builds nothing new.
    #[must_use]
    pub fn named(name: &str) -> Option<Self> {
        if name.is_empty() {
            return None;
        }
        static BOUND: OnceLock<Mutex<HashMap<String, usize>>> = OnceLock::new();
        let mut bound = BOUND
            .get_or_init(Mutex::default)
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        if let Some(&at) = bound.get(name) {
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
        // Built once per name, off the hot path, and kept: a callsite lives as long as the process.
        let named: &'static str = site.name.get_or_init(|| name.to_owned()).as_str();
        let _set = site.meta.set(Metadata::new(
            named,
            TARGET,
            HOTPATH_LEVEL,
            Some(file!()),
            Some(line!()),
            Some(module_path!()),
            FieldSet::new(&[], Identifier(site)),
            Kind::SPAN,
        ));
        tracing::callsite::register(site);
        bound.insert(name.to_owned(), at);
        Some(Self { site })
    }

    /// The span's name.
    #[must_use]
    pub fn name(&self) -> &'static str {
        self.site.name.get().map_or("", String::as_str)
    }

    /// Open the span for one arrival, under the current span. [`Span::none`] where no subscriber
    /// wants it: nothing is allocated here either way.
    #[must_use]
    pub fn open(self) -> Span {
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
        Span::new(meta, &meta.fields().value_set(&[]))
    }
}

#[cfg(test)]
#[path = "../tests/arrival_span_tests.rs"]
mod tests;
