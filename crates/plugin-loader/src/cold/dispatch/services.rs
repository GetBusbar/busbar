// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The cold code of `crate::dispatch::{conn_services, services, auth_outbound}` and the stores.

use std::hash::{BuildHasher, Hash};

use busbar_contract::abi::mechanism::call::Outcome;

/// A failure cause's text, leaked the first time the process meets it: the connector interns at
/// most a bounded number of distinct causes for the process's life.
#[cold]
pub(crate) fn leak_text(text: &str) -> &'static str {
    Box::leak(text.to_owned().into_boxed_str())
}

/// The process identity's program name, read once per process.
#[cold]
pub(crate) fn program_name() -> String {
    std::env::current_exe()
        .ok()
        .and_then(|p| p.file_name().map(|n| n.to_string_lossy().into_owned()))
        .unwrap_or_default()
}

/// A table built once, at bind or admission (an instance's declared needs): gathered here, out of
/// line, never on a call's path.
#[cold]
pub(crate) fn load_table<C: FromIterator<T>, T>(items: impl Iterator<Item = T>) -> C {
    items.collect()
}

/// The refusal of a settings-only check for a style whose plugin has no such validator.
#[cold]
pub(crate) fn no_settings_validator(style: &str) -> String {
    format!("outbound style '{style}' has no settings-only validator")
}

/// An outcome named as text, when the plugin refused without saying why.
#[cold]
pub(crate) fn outcome_text(outcome: Outcome) -> String {
    format!("{outcome:?}")
}

/// An auth instance that did not validate or open for its outbound styles.
#[cold]
pub(crate) fn not_opened(plugin: &str, what: &str, why: &str) -> String {
    format!("`{plugin}` did not {what} for its outbound styles: {why}")
}

/// An outbound style binding the plugin refused.
#[cold]
pub(crate) fn outbound_not_opened(
    plugin: &str,
    style: &str,
    outcome: Outcome,
    why: &str,
) -> String {
    format!("`{plugin}` did not open the outbound style `{style}`: {outcome:?} {why}")
}

/// A plugin's refusal text, copied out of its answer.
#[cold]
pub(crate) fn lossy_text(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

/// An outbound style's settings, rendered once when the style is bound.
#[cold]
pub(crate) fn render_settings<T: serde::Serialize + ?Sized>(
    settings: &T,
) -> Result<Vec<u8>, (Outcome, String)> {
    let mut rendered = Vec::new();
    busbar_contract::json::to_writer(&mut rendered, settings)
        .map_err(|e| (Outcome::Refused, e.to_string()))?;
    Ok(rendered)
}

/// THE RARE SWEEPS OF A STORE'S OWN STATE: an instance's or a worker's or a binding generation's
/// resources detached when it retires, a faulted worker's results dropped, an instance's
/// conditional exchanges torn down at close, and the owed-settlement search a cancel runs. Each
/// sweeps the map it is called on (state, never request data), out of line.
pub(crate) trait Sweep<K, V> {
    /// Take out every entry `gone` names; the values, to drop after the lock.
    fn drain_where(&mut self, gone: impl FnMut(&K, &mut V) -> bool) -> Vec<V>;

    /// Take out every entry `gone` names into `out`.
    fn drain_into(&mut self, gone: impl FnMut(&K, &mut V) -> bool, out: &mut Vec<V>);

    /// Take out every entry `gone` names, keys with their values.
    fn drain_pairs_where(&mut self, gone: impl FnMut(&K, &mut V) -> bool) -> Vec<(K, V)>;

    /// Take out every value.
    fn drain_values(&mut self) -> Vec<V>;

    /// The keys `wanted` names, copied out.
    fn keys_where(&self, wanted: impl FnMut(&K) -> bool) -> Vec<K>
    where
        K: Copy;

    /// The first answer `found` gives over the entries.
    fn find_value<R>(&self, found: impl FnMut(&K, &V) -> Option<R>) -> Option<R>;

    /// Run `each` over every value (it may take what it removes into the shared buffer), then take
    /// out the entries `empty` names.
    fn teardown<W>(
        &mut self,
        each: impl FnMut(&mut V, &mut Vec<W>),
        empty: impl FnMut(&K, &mut V) -> bool,
    ) -> (Vec<W>, Vec<V>);
}

impl<K: Eq + Hash, V, S: BuildHasher> Sweep<K, V> for std::collections::HashMap<K, V, S> {
    #[cold]
    fn drain_where(&mut self, gone: impl FnMut(&K, &mut V) -> bool) -> Vec<V> {
        self.extract_if(gone).map(|(_, v)| v).collect()
    }

    #[cold]
    fn drain_into(&mut self, gone: impl FnMut(&K, &mut V) -> bool, out: &mut Vec<V>) {
        out.extend(self.extract_if(gone).map(|(_, v)| v));
    }

    #[cold]
    fn drain_pairs_where(&mut self, gone: impl FnMut(&K, &mut V) -> bool) -> Vec<(K, V)> {
        self.extract_if(gone).collect()
    }

    #[cold]
    fn drain_values(&mut self) -> Vec<V> {
        self.drain().map(|(_, v)| v).collect()
    }

    #[cold]
    fn keys_where(&self, mut wanted: impl FnMut(&K) -> bool) -> Vec<K>
    where
        K: Copy,
    {
        self.keys().filter(|k| wanted(*k)).copied().collect()
    }

    #[cold]
    fn find_value<R>(&self, mut found: impl FnMut(&K, &V) -> Option<R>) -> Option<R> {
        self.iter().find_map(|(k, v)| found(k, v))
    }

    #[cold]
    fn teardown<W>(
        &mut self,
        mut each: impl FnMut(&mut V, &mut Vec<W>),
        empty: impl FnMut(&K, &mut V) -> bool,
    ) -> (Vec<W>, Vec<V>) {
        let mut removed = Vec::new();
        for v in self.values_mut() {
            each(v, &mut removed);
        }
        let emptied = self.extract_if(empty).map(|(_, v)| v).collect();
        (removed, emptied)
    }
}
