// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! 1d, the store 1.5.5 implied (AGREED QM2, owner 2026-11-15T20:54Z): 1.6.0 has no absent-store
//! default, so every config names its store. 1.5.5 ran a config with no `store:` block, or one
//! naming no `module:`, on the store built into it (v1.5.5 `config/mod.rs:3026-3040`, "Absent block
//! = the compiled-in ephemeral RAM store"). The 1.5.5 -> 1 step writes that block explicitly. The
//! module word is a 1.5.5-shape fact, held by this step alone as one named constant; at boot the
//! store is resolved like any configured module, and a build without it refuses with the loader's
//! explained, audited unknown-module refusal (which carries `UPGRADE_FIRST` on this boot). A config
//! stamped for 1.6.0 that names no store is refused by the strict parse (BUSBAR-3120).

use busbar_contract::yaml::{MappingExt, Pairs, Value, ValueExt};

use crate::patch::schema_insert;
use crate::Refusal;

/// The store module 1.5.5 ran a store-less config on. The one plugin word in this crate: the
/// separation test allows exactly this line (AGREED QM2, owner 2026-11-15T20:54Z).
pub(crate) const STORE_1_5_5_IMPLIED: &str = "memory"; // AGREED QM2: 1.5.5-shape fact

/// Write the store block 1.5.5 implied, decided on the resolved document as 1.5.5 decided it.
pub(crate) fn name_the_implied_store(root: &mut Pairs, resolved: &Value, report: &mut Vec<String>) {
    write_implied(root, resolved, STORE_1_5_5_IMPLIED, report);
}

/// The MIN-3 rule (IF §12.10 item 1, MIGRATE-ON-BOOT r15 §3 1d): absent = the compiled-in ephemeral store,
/// and the build says which one: `stores` are the linked store images declaring `store::FB_EPHEMERAL`
/// (`Registry::ephemeral_stores`). Exactly one is named; core holds no store name.
///
/// # Errors
/// CONFIG when the document names no store module and the build has none or several such stores.
pub(crate) fn name_the_ephemeral_store(
    root: &mut Pairs,
    resolved: &Value,
    stores: &[String],
    report: &mut Vec<String>,
) -> Result<(), Refusal> {
    if module_named(resolved) {
        return Ok(());
    }
    match stores {
        [one] => {
            write_implied(root, resolved, one, report);
            Ok(())
        }
        [] => Err(Refusal::Config(format!(
            "config has no `store:` block naming a `module:`, which 1.5.5 ran on its built-in RAM \
             store; this build has no such store; add `store: {{module: …}}`"
        ))),
        several => Err(Refusal::Config(format!(
            "config has no `store:` block naming a `module:`, which 1.5.5 ran on its built-in RAM \
             store; this build has several such stores ({}); add `store: {{module: …}}` naming one",
            several.join(", ")
        ))),
    }
}

fn module_named(resolved: &Value) -> bool {
    resolved
        .get("store")
        .filter(|store| !store.is_null())
        .and_then(|store| store.get("module"))
        .is_some_and(|module| !module.is_null())
}

fn write_implied(root: &mut Pairs, resolved: &Value, module: &str, report: &mut Vec<String>) {
    if module_named(resolved) {
        return;
    }
    let module_pair = (Value::from("module"), Value::from(module));
    match root.get_key_mut("store") {
        Some(Value::Map(block)) => {
            block.retain(|(key, _)| key.as_str() != Some("module"));
            block.insert(0, module_pair);
            report.push(format!(
                "store.module: added `{module}`, the store 1.5.5 ran a `store:` block \
                 naming no module on (its state is kept in RAM and lost on restart, as in 1.5.5); \
                 1.6.0 has no default store, so the block names it"
            ));
        }
        Some(slot) if slot.is_null() => {
            *slot = Value::Map(vec![module_pair]);
            report.push(implied_line(module));
        }
        // Any other shape 1.5.5 refused; the strict parse refuses it in its own words.
        Some(_) => {}
        None => {
            schema_insert(root, "store", Value::Map(vec![module_pair]));
            report.push(implied_line(module));
        }
    }
}

fn implied_line(module: &str) -> String {
    format!(
        "store: added `store: {{module: {module}}}`, the store 1.5.5 ran a config \
         with no `store:` block on (its state is kept in RAM and lost on restart, as in 1.5.5); \
         1.6.0 has no default store, so the block names it"
    )
}

#[cfg(test)]
#[path = "tests/absent_store_tests.rs"]
mod tests;
