// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The `export:`-SURFACE migration passes of `busbar --migrate-config` (see [`super::migrate`] for
//! the migrator's contract and for the shared [`super::migrate::Taken`] take-on-match machinery
//! every pass here goes through).
//!
//! Everything that moves INTO the single telemetry-egress surface lives here, in the order the
//! migrator runs it:
//!
//! 1. [`migrate_export_named_map`] — 1.5.3 §3: the retired TYPE-KEYED `export:` block becomes the
//!    NAMED-DEFINITION map (`<name>: { module, settings }`), so one module can back several
//!    instances.
//! 2. [`migrate_observability_block`] — 1.5.3 §3: the `observability:` block is DELETED, its last
//!    field folded into an `export:` instance with `module: otlp`.
//! 3. [`migrate_export_projection`] — 1.5.3 A0.1: each instance's PROJECTION is made explicit
//!    (`streams:`), from the same module→streams table the validator reads.
//!
//! Split out of `migrate.rs` for size (the impl-file ceiling in `docs/code-layout.md`); the passes
//! are one cohesive unit — they all rewrite the same section, in sequence.

use super::migrate::{one_line, take, take_mapping, Taken};
use serde_yaml::{Mapping, Value};

/// The default instance NAME each built-in export module gets when the TYPE-KEYED `export:` block is
/// rewritten into the 1.5.3 NAMED map. Chosen to read as an instance (what it IS) rather than as the
/// module (what backs it), so the migrated config teaches the pattern: `metrics: { module: prometheus }`.
/// Shared with the migrator tests so the goldens cannot drift from the rewrite.
pub(crate) const EXPORT_TYPE_KEY_TO_INSTANCE_NAME: &[(&str, &str, &str)] = &[
    // (retired type key, new instance name, `module:` value)
    ("prometheus", "metrics", "prometheus"),
    ("request-log-webhook", "req-log", "request-log-webhook"),
    ("request-log-file", "req-log-file", "request-log-file"),
    // The retired `generic-webhook` exporter FOLDED into `request-log-webhook` (1.5.3): its only
    // extra was `auth_header:`, now just a setting there, and its other reason to exist (a SECOND
    // webhook target) is what the named map itself provides.
    ("generic-webhook", "req-log-audit", "request-log-webhook"),
];

/// Ensure `root.export` exists as a mapping, returning a handle to splice an instance into.
fn export_map_mut(root: &mut Mapping) -> &mut Mapping {
    let entry = root
        .entry("export".into())
        .or_insert_with(|| Value::Mapping(Mapping::new()));
    if !matches!(entry, Value::Mapping(_)) {
        *entry = Value::Mapping(Mapping::new());
    }
    match entry {
        Value::Mapping(m) => m,
        _ => unreachable!("just normalized to a mapping"),
    }
}

/// Pick an instance name not already taken in a NAMED-DEFINITION map (`req-log`, `req-log-2`, …), so
/// migrating a config that already carries a hand-written named instance never clobbers it. Used for
/// `export:` and, when a per-plane settings conflict forces a split, for `identity-providers:`.
pub(super) fn uniq_export_name(export: &Mapping, base: &str) -> String {
    if !export.contains_key(Value::from(base)) {
        return base.to_string();
    }
    (2..)
        .map(|n| format!("{base}-{n}"))
        .find(|c| !export.contains_key(Value::from(c.as_str())))
        .expect("an unbounded counter always finds a free name")
}

/// 1.5.3 §3: rewrite the TYPE-KEYED `export:` block into the NAMED-DEFINITION map
/// (`<name>: { module, settings }`). SHAPE-CONVERGENT and IDEMPOTENT: an entry that already names a
/// `module:` is ALREADY an instance and is left untouched, so a second run is a no-op.
pub(super) fn migrate_export_named_map(root: &mut Mapping, changes: &mut Vec<String>) {
    let Some(Value::Mapping(export)) = root.get(Value::from("export")).cloned() else {
        return;
    };
    // Split: the retired TYPE keys to rewrite vs everything else (already-named instances) to keep.
    let mut kept = Mapping::new();
    let mut to_rewrite: Vec<(String, Value)> = Vec::new();
    for (k, v) in export {
        let key = k.as_str().unwrap_or_default().to_string();
        let is_type_key = EXPORT_TYPE_KEY_TO_INSTANCE_NAME
            .iter()
            .any(|(t, _, _)| *t == key);
        let already_named = v
            .as_mapping()
            .is_some_and(|m| m.contains_key(Value::from("module")));
        if is_type_key && !already_named {
            to_rewrite.push((key, v));
        } else {
            kept.insert(k, v);
        }
    }
    if to_rewrite.is_empty() {
        return;
    }
    for (type_key, body) in to_rewrite {
        let (_, base_name, module) = EXPORT_TYPE_KEY_TO_INSTANCE_NAME
            .iter()
            .find(|(t, _, _)| *t == type_key)
            .expect("only retired type keys reach here");
        let name = uniq_export_name(&kept, base_name);
        let mut inst = Mapping::new();
        inst.insert("module".into(), Value::from(*module));
        // The retired shape nested the bag under `settings:`; carry it through verbatim (an entry
        // with no `settings:` becomes an instance with no settings, which is legal for every module
        // whose settings are all-defaulted).
        if let Some(settings) = body
            .as_mapping()
            .and_then(|m| m.get(Value::from("settings")))
        {
            inst.insert("settings".into(), settings.clone());
        }
        kept.insert(Value::from(name.as_str()), Value::Mapping(inst));
        changes.push(format!(
            "export.{type_key} (type-keyed) -> export.{name}: {{ module: {module} }} (1.5.3 named \
             export map — the same module can now back several named instances)"
        ));
    }
    root.insert("export".into(), Value::Mapping(kept));
}

/// 1.5.3 — the EXPORT PROJECTION GRAMMAR: make each `export:` instance's PROJECTION EXPLICIT by
/// writing the `streams:` its `module:` already implies.
///
/// Nothing about the deployment changes: an instance with no `streams:` still means "the streams
/// this module carries" (see `crate::export::projection::resolve_projection`), so this is a
/// TEACHING rewrite, not a semantic one — the migrated document shows the operator the key they will
/// narrow with `fields:`, and the ledger says so. The streams are read from
/// `crate::export::projection::module_streams`, the SAME table the validator uses, so the migrator
/// cannot write a projection the validator would then reject.
///
/// IDEMPOTENT (an instance that already declares `streams:` is left alone) and NON-DESTRUCTIVE:
///
/// - a MALFORMED instance (`broken: null`, a scalar, a list) is left EXACTLY as written with a TODO,
///   via [`take_mapping`]'s take-on-match discipline — the migrator never drops what it cannot read;
/// - an instance whose `module:` this build does not know gets a TODO rather than a GUESS: writing
///   an inferred projection for a sink we know nothing about is exactly the "reports success while
///   quietly not taking effect" shape;
/// - a hand-written `streams: [audit]` is NOT rewritten. `audit` was REMOVED (an auditor is a
///   projection made of other streams), and WHICH streams replace it is a disclosure decision that
///   belongs to the operator, not to a mechanical rewrite. It gets a TODO naming the shape.
pub(super) fn migrate_export_projection(
    root: &mut Mapping,
    changes: &mut Vec<String>,
    todos: &mut Vec<String>,
) {
    let Some(Value::Mapping(mut export)) = root.get(Value::from("export")).cloned() else {
        return;
    };
    let mut out = Mapping::new();
    for key in export.keys().cloned().collect::<Vec<_>>() {
        let name = key.as_str().unwrap_or_default().to_string();
        match take_mapping(&mut export, &name, "export", todos) {
            // Left EXACTLY as written, in place, with the TODO already pushed by `take_mapping`.
            Taken::Malformed => {
                if let Some(v) = export.get(&key) {
                    out.insert(key.clone(), v.clone());
                }
            }
            Taken::Absent => {}
            Taken::Got(mut inst) => {
                migrate_one_export_projection(&name, &mut inst, changes, todos);
                out.insert(key.clone(), Value::Mapping(inst));
            }
        }
    }
    // `insert` on an existing key keeps its position, so `export:` does not move within the document.
    root.insert("export".into(), Value::Mapping(out));
}

/// The per-instance half of [`migrate_export_projection`].
fn migrate_one_export_projection(
    name: &str,
    inst: &mut Mapping,
    changes: &mut Vec<String>,
    todos: &mut Vec<String>,
) {
    let ctx = format!("export.{name}");
    // ALREADY DECLARED: leave it. The only thing to say is whether it names the retired `audit`.
    if let Some(existing) = inst.get(Value::from("streams")) {
        let names_audit = existing
            .as_sequence()
            .is_some_and(|s| s.iter().any(|v| v.as_str() == Some("audit")));
        if names_audit {
            todos.push(format!(
                "{ctx}.streams: names `audit`, which is NOT a stream in 1.5.3 — it was a use case,                  not a data type, and an auditor is a SINK whose projection includes the right                  streams (e.g. `streams: [logs, identity, decisions, events, costs]`). WHICH                  streams replace it is a disclosure decision, so it was left EXACTLY as written                  rather than rewritten for you. Edit it by hand; the config will not boot until you                  do."
            ));
        }
        return;
    }
    let Some(module) = inst
        .get(Value::from("module"))
        .and_then(|v| v.as_str())
        .map(|m| m.trim().to_string())
    else {
        todos.push(format!(
            "{ctx}: has no `module:`, so its `streams:` projection could not be inferred. Add              `module:` and re-run `--migrate-config`."
        ));
        return;
    };
    let Some(streams) = crate::export::projection::module_streams(&module) else {
        todos.push(format!(
            "{ctx}: `module: {module}` is not a built-in export module in this build, so its              `streams:` projection could not be inferred and was NOT guessed. Add `streams:` by              hand naming what this sink subscribes to."
        ));
        return;
    };
    let list: Vec<Value> = streams.iter().map(|s| Value::from(s.as_token())).collect();
    let tokens = streams
        .iter()
        .map(|s| s.as_token())
        .collect::<Vec<_>>()
        .join(", ");
    inst.insert("streams".into(), Value::Sequence(list));
    changes.push(format!(
        "{ctx}: added `streams: [{tokens}]` (1.5.3 projection grammar — each export instance is a          PROJECTION of the engine's data, and the streams a sink subscribes to are now declared          rather than implied by `module:`. This is what the deployment already meant; narrow it          further with `fields:`)."
    ));
}

/// 1.5.3 §3: DELETE the `observability:` block, folding its last field (`otlp_url`, or the 1.4.x
/// `otlp_endpoint` if `migrate_observability`'s rename has not run) into an `export:` instance with
/// `module: otlp`. IDEMPOTENT: a config with no `observability:` block has nothing to fold.
///
/// A MALFORMED block (`observability: null`, a sequence, a scalar — real hand-edited shapes) is still
/// DELETED: the section does not exist in 1.5.3, so there is nothing to carry it into and leaving it
/// would fail the `deny_unknown_fields` parse. But the deletion is RECORDED in the ledger (audit
/// MED-1) — `root.remove` always removes the key, so without this arm a malformed block vanished from
/// the migrated document with no `changes` entry at all, which is exactly the "silently lost operator
/// config" shape `migrate_auth` refuses.
pub(super) fn migrate_observability_block(root: &mut Mapping, changes: &mut Vec<String>) {
    let removed = root.remove(Value::from("observability"));
    let Some(Value::Mapping(mut obs)) = removed else {
        if let Some(other) = removed {
            changes.push(format!(
                "observability: block removed (DELETED in 1.5.3; it was not a mapping — the value \
                 `{}` carried nothing foldable into an `export:` instance)",
                one_line(&other)
            ));
        }
        return;
    };
    let url = take(&mut obs, "otlp_url").or_else(|| take(&mut obs, "otlp_endpoint"));
    // A `null` URL is how the shipped example spelled "tracing off" — folding it into an instance
    // would turn an OFF sink into a boot error (`settings.url` is REQUIRED), so drop it instead.
    let url = url.filter(|v| !v.is_null());
    if let Some(url) = url {
        let export = export_map_mut(root);
        let name = uniq_export_name(export, "traces");
        let mut settings = Mapping::new();
        settings.insert("url".into(), url);
        let mut inst = Mapping::new();
        inst.insert("module".into(), Value::from("otlp"));
        inst.insert("settings".into(), Value::Mapping(settings));
        export.insert(Value::from(name.as_str()), Value::Mapping(inst));
        changes.push(format!(
            "observability.otlp_url -> export.{name}: {{ module: otlp }} (the `observability:` block \
             is DELETED in 1.5.3; `export:` is the single telemetry-egress surface)"
        ));
    } else {
        changes.push(
            "observability: block removed (DELETED in 1.5.3; it carried no otlp_url to fold)"
                .into(),
        );
    }
}
