// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! `config::resolve_styles` (IF §12.10 item 3, §12.18; MIGRATE-ON-BOOT r42 §3): STEPS[0] writes an
//! outbound credential whose owner is a style word as a deferred binding,
//! `auth.<provider>-outbound = {module: {"$style": "<word>"}, config: {..}}`. After every image is
//! admitted and described and before `boot_plan`, the gateway calls this directly (one process, no
//! frame) with `Registry::outbound_styles()`: each deferred `module` becomes the identity of the
//! **unique** admitted auth plugin declaring that word, else CONFIG naming the binding and the style.
//! Core holds no style-to-plugin table: the declarations are the only source. A deferred binding an
//! operator wrote in a current config is refused by the strict parse (it is migration-only
//! vocabulary), so this runs only on an unstamped boot's plan.

use busbar_contract::yaml::{Value, ValueExt};

use crate::patch::{document, rewrite};
use crate::Refusal;

/// The one key of a deferred `module`.
pub(crate) const DEFERRED: &str = "$style";

/// Resolve every deferred binding of `text` (the planned config.yaml) against `styles`
/// (`(identity, D_OUTBOUND_STYLE words)` per admitted auth image). Returns the document and one report
/// line per binding; a document with none is returned as written.
///
/// # Errors
/// CONFIG naming the binding and the style when no admitted auth plugin, or several, declare it.
pub fn resolve(text: &str, styles: &[(&str, &[&str])]) -> Result<(String, Vec<String>), Refusal> {
    let before = document(text)?;
    let mut after = before.clone();
    let mut report = Vec::new();
    if let Some(Value::Map(bindings)) = after.get_mut("auth") {
        for (name, binding) in bindings.iter_mut() {
            let (Some(name), Some(module)) = (name.as_text(), binding.get_mut("module")) else {
                continue;
            };
            let Value::Map(pairs) = module else { continue };
            let word = match pairs.as_slice() {
                [(key, word)] if key.as_text() == Some(DEFERRED) => word.as_text(),
                _ => continue,
            };
            let Some(word) = word.map(str::to_owned) else {
                return Err(Refusal::Config(format!(
                    "`auth.{name}`: `module: {{\"{DEFERRED}\": ..}}` carries no style word"
                )));
            };
            let owners: Vec<&str> = styles
                .iter()
                .filter(|(_, words)| words.contains(&word.as_str()))
                .map(|(identity, _)| *identity)
                .collect();
            let identity = match owners.as_slice() {
                [one] => *one,
                [] => {
                    return Err(Refusal::Config(format!(
                        "`auth.{name}`: no admitted auth plugin implements the outbound style \
                         `{word}`; write `module:`"
                    )))
                }
                several => {
                    return Err(Refusal::Config(format!(
                        "`auth.{name}`: several do implement the outbound style `{word}` ({}), so \
                         core cannot choose; write `module:`",
                        several.join(", ")
                    )))
                }
            };
            report.push(format!(
                "auth.{name}.module: the outbound style `{word}` is implemented by `{identity}`"
            ));
            *module = Value::from(identity);
        }
    }
    if report.is_empty() {
        return Ok((text.to_owned(), report));
    }
    Ok((rewrite(text, &before, &after, "config.yaml")?, report))
}

#[cfg(test)]
#[path = "tests/styles_tests.rs"]
mod tests;
