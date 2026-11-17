// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Native metadata readers for the composition root (LIFECYCLE-A-PLAN WP1).
//!
//! Every fact here is read from what admission already decoded from an image's describe answer
//! (`Described`) and from its header's `former_names` (ABI-MIN3 r34 l.2185-2194: every former
//! Statement REWRITE_ALIAS word is a `former_names` word). Nothing enters a plugin door.

use std::collections::BTreeSet;

use busbar_plugin_abi::records::tag;

use super::{Described, Images};

/// The settings one plugin's schema declares public, and every word a `module:` may name it by.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublicSettings {
    /// The plugin's identity.
    pub name: String,
    /// Its identity, its former names and the caller's `words`, sorted and deduplicated.
    pub words: Vec<String>,
    /// The settings its schema declares `x-busbar-public`; every other setting is sensitive
    /// (`busbar_contract::settings_public`).
    pub public: BTreeSet<String>,
}

impl Images {
    /// The public settings of the admitted image `identity`, from its D_SCHEMA and D_SECRET_PATH
    /// items. `Ok(None)` when it declares no public setting or no such image is admitted.
    ///
    /// # Errors
    ///
    /// The schema's own refusal, or a public field that contains a declared secret position.
    pub fn public_settings(
        &self,
        identity: &str,
        words: &[&str],
    ) -> Result<Option<PublicSettings>, String> {
        let Some(described) = self.described(identity) else {
            return Ok(None);
        };
        public_settings_of_described(identity, &self.names(identity), &described, words)
    }
}

/// [`Images::public_settings`] over one image's admitted facts: `names` is its identity and its
/// former names, as [`Images::names`] answers them.
pub(crate) fn public_settings_of_described(
    identity: &str,
    names: &[&str],
    described: &Described,
    words: &[&str],
) -> Result<Option<PublicSettings>, String> {
    let schema = described.schema.as_deref().unwrap_or("");
    let public = crate::settings_schema::public_settings_of_schema(schema.as_bytes())
        .map_err(|e| format!("plugin '{identity}': {e}"))?;
    let roots: Vec<String> = described
        .paths(tag::D_SECRET_PATH)
        .map(pointer_root)
        .collect();
    for name in &public {
        if roots.iter().any(|root| root == name || root == "*") {
            return Err(format!(
                "plugin '{identity}': its settings schema: field '{name}' contains a declared secret \
                 path and cannot be public"
            ));
        }
    }
    if public.is_empty() {
        return Ok(None);
    }
    let mut answers: Vec<String> = names
        .iter()
        .chain(words.iter())
        .map(|w| (*w).to_string())
        .collect();
    if !answers.iter().any(|w| w == identity) {
        answers.push(identity.to_string());
    }
    answers.sort();
    answers.dedup();
    Ok(Some(PublicSettings {
        name: identity.to_string(),
        words: answers,
        public,
    }))
}

/// The root member an RFC 6901 pointer names (`/a/b` -> `a`, `~1`/`~0` unescaped). The whole
/// document (`""`) and an every-element segment answer `*`: every root is covered.
fn pointer_root(pointer: &str) -> String {
    let Some(rest) = pointer.strip_prefix('/') else {
        return "*".to_string();
    };
    let first = rest.split('/').next().unwrap_or("");
    first.replace("~1", "/").replace("~0", "~")
}

#[cfg(test)]
#[path = "facts_tests.rs"]
mod tests;
