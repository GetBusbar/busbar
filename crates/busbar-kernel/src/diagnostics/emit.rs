// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::Diagnostic;
use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};
use tracing::callsite::{Callsite, Identifier};
use tracing::field::{FieldSet, Value};
use tracing::metadata::Kind;
use tracing::subscriber::Interest;
use tracing::{Level, Metadata};

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
