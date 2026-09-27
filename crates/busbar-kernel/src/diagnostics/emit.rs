// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! EMIT A CATALOGUED DIAGNOSTIC WHOSE FIELDS ARE KNOWN ONLY AT RUNTIME (K9c).
//!
//! The `diag_*!` macros name their fields at compile time, which is exactly what a diagnostic a
//! FIRST-PARTY plugin raises over the observability envelope cannot do: the plugin states the code,
//! the message and its `name = value` fields as data. [`emit`] renders that as the SAME line the
//! macro renders — `message diag=BUSBAR-NNNN name=value …`, fields in the plugin's order — through a
//! callsite made once per (code, level, field names) and kept for the process, so the host's
//! subscriber filters, formats and exports it exactly as a compiled-in `diag_*!` site's line.
//!
//! A field value is written as given (Display): a plugin that wants a value quoted the way a string
//! field is (`name="…"`) sends it quoted.

use super::Diagnostic;
use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};
use tracing::callsite::{Callsite, Identifier};
use tracing::field::{FieldSet, Value};
use tracing::metadata::Kind;
use tracing::subscriber::Interest;
use tracing::{Level, Metadata};

/// One runtime callsite: its metadata, set once right after the callsite is leaked (the metadata
/// names the callsite it belongs to).
struct Site(OnceLock<Metadata<'static>>);

impl Callsite for Site {
    fn set_interest(&self, _: Interest) {}

    fn metadata(&self) -> &Metadata<'_> {
        self.0
            .get()
            .expect("a runtime callsite's metadata is set before it is registered")
    }
}

type Key = (u16, Level, Vec<String>);

static SITES: Mutex<Option<HashMap<Key, &'static Site>>> = Mutex::new(None);

/// The callsite for `code` at `level` with `names` (after `message` and `diag`), made once.
fn site(code: u16, level: Level, names: &[String]) -> &'static Site {
    let mut guard = SITES.lock().unwrap_or_else(|e| e.into_inner());
    let sites = guard.get_or_insert_with(HashMap::new);
    let key = (code, level, names.to_vec());
    if let Some(site) = sites.get(&key) {
        return site;
    }
    let leak = |s: &str| -> &'static str { Box::leak(s.to_string().into_boxed_str()) };
    let mut all: Vec<&'static str> = vec!["message", "diag"];
    all.extend(names.iter().map(|n| leak(n)));
    let site: &'static Site = Box::leak(Box::new(Site(OnceLock::new())));
    let meta = Metadata::new(
        "diagnostic",
        module_path!(),
        level,
        Some(file!()),
        Some(line!()),
        Some(module_path!()),
        FieldSet::new(all.leak(), Identifier(site)),
        Kind::EVENT,
    );
    let _ = site.0.set(meta);
    tracing::callsite::register(site);
    sites.insert(key, site);
    site
}

/// Emit `diag` at `level` with `message` and `fields`, as a `diag_*!` site would.
pub fn emit(diag: &Diagnostic, level: Level, message: &str, fields: &[(String, String)]) {
    let names: Vec<String> = fields.iter().map(|(k, _)| k.clone()).collect();
    let site = site(diag.code, level, &names);
    let meta: &'static Metadata<'static> = site.0.get().expect("set when the callsite was made");
    let message = tracing::field::display(message);
    let banner = tracing::field::display(diag.banner());
    let shown: Vec<tracing::field::DisplayValue<&String>> = fields
        .iter()
        .map(|(_, v)| tracing::field::display(v))
        .collect();
    let mut values: Vec<Option<&dyn Value>> = vec![Some(&message), Some(&banner)];
    values.extend(shown.iter().map(|v| Some(v as &dyn Value)));
    let set = meta.fields().value_set_all(&values);
    tracing::dispatcher::get_default(|d| {
        if d.enabled(meta) {
            d.event(&tracing::Event::new(meta, &set));
        }
    });
}

#[cfg(test)]
#[path = "tests/emit_tests.rs"]
mod tests;
