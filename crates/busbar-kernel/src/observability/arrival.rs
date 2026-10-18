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

/// What the registered subscribers said of a callsite, cached: never, sometimes, always, or not yet
/// asked.
const NEVER: u8 = 0;
const SOMETIMES: u8 = 1;
const ALWAYS: u8 = 2;
const UNASKED: u8 = 3;

/// One named span's callsite, built once and kept for the process.
struct Site {
    meta: OnceLock<&'static Metadata<'static>>,
    interest: AtomicU8,
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
        self.meta.get().copied().unwrap_or(&NONE_META)
    }
}

/// The metadata a site answers before its own is set, which no registered site ever does.
static NONE_SITE: Site = Site {
    meta: OnceLock::new(),
    interest: AtomicU8::new(NEVER),
};
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
        f.debug_tuple("ArrivalSpan")
            .field(&self.site.metadata().name())
            .finish()
    }
}

impl ArrivalSpan {
    /// The span `name` opens; `None` for an empty name (the claim opens none). One callsite per
    /// distinct name for the life of the process: binding the same name again answers the same
    /// callsite, so a refresh that re-binds routes builds nothing new.
    #[must_use]
    pub fn named(name: &str) -> Option<Self> {
        if name.is_empty() {
            return None;
        }
        static SITES: OnceLock<Mutex<HashMap<String, &'static Site>>> = OnceLock::new();
        let mut sites = SITES
            .get_or_init(Mutex::default)
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        if let Some(site) = sites.get(name) {
            return Some(Self { site });
        }
        // Built once per name, off the hot path, and kept: a callsite lives as long as the process.
        let leaked: &'static str = Box::leak(name.to_owned().into_boxed_str());
        let site: &'static Site = Box::leak(Box::new(Site {
            meta: OnceLock::new(),
            interest: AtomicU8::new(UNASKED),
        }));
        let meta: &'static Metadata<'static> = Box::leak(Box::new(Metadata::new(
            leaked,
            TARGET,
            HOTPATH_LEVEL,
            Some(file!()),
            Some(line!()),
            Some(module_path!()),
            FieldSet::new(&[], Identifier(site)),
            Kind::SPAN,
        )));
        let _set = site.meta.set(meta);
        tracing::callsite::register(site);
        sites.insert(name.to_owned(), site);
        Some(Self { site })
    }

    /// The span's name.
    #[must_use]
    pub fn name(&self) -> &'static str {
        self.site.meta.get().map_or("", |m| m.name())
    }

    /// Open the span for one arrival, under the current span. [`Span::none`] where no subscriber
    /// wants it: nothing is allocated here either way.
    #[must_use]
    pub fn open(self) -> Span {
        let Some(meta) = self.site.meta.get().copied() else {
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
