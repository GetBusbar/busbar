// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The `export:`-SURFACE migration passes of `busbar --migrate-config` (see [`super::migrate`] for
//! the migrator's contract and for the shared [`super::migrate::Taken`] take-on-match machinery
//! every pass here goes through).
//!
//! Everything that moves INTO the single telemetry-egress surface lives here, in the order the
//! migrator runs it:
//!
//! 1. [`migrate_export_named_map`] — 1.5.3: the retired TYPE-KEYED `export:` block becomes the
//!    NAMED-DEFINITION map (`<name>: { module, settings }`), so one module can back several
//!    instances.
//! 2. [`migrate_observability_block`] — 1.5.3: the `observability:` block is DELETED, its last
//!    field folded into an `export:` instance of the trace exporter (the root migration table names it).
//! 3. [`migrate_export_projection`] — 1.5.3 A0.1: each instance's PROJECTION is made explicit
//!    (`streams:`), from the same module→streams table the validator reads.
//!
//! Split out of `migrate.rs` for size (the impl-file ceiling in `docs/code-layout.md`); the passes
//! are one cohesive unit — they all rewrite the same section, in sequence.

use super::migrate::{one_line, take, take_mapping, Taken};
use busbar_contract::abi::export::ExportStream;
use busbar_contract::plugin::Kind;
use serde_yaml::{Mapping, Value};

pub(crate) fn export_type_keys() -> Vec<(&'static str, &'static str, &'static str)> {
    super::migration_table::text("export_type_keys")
        .split(" | ")
        .filter_map(|row| {
            let mut field = row.split(':');
            Some((field.next()?, field.next()?, field.next()?))
        })
        .collect()
}

fn released_module_streams() -> Vec<(&'static str, Vec<ExportStream>)> {
    super::migration_table::text("export_module_streams")
        .split(" | ")
        .filter_map(|row| {
            let (module, streams) = row.split_once(':')?;
            let streams = streams
                .split(',')
                .map(ExportStream::from_token)
                .collect::<Option<Vec<_>>>()?;
            Some((module, streams))
        })
        .collect()
}

fn export_map_mut(root: &mut Mapping) -> &mut Mapping {
    let entry = root
        .entry(Kind::Export.root().into())
        .or_insert_with(|| Value::Mapping(Mapping::new()));
    if !matches!(entry, Value::Mapping(_)) {
        *entry = Value::Mapping(Mapping::new());
    }
    match entry {
        Value::Mapping(m) => m,
        _ => unreachable!("just normalized to a mapping"),
    }
}

pub(super) fn uniq_export_name(export: &Mapping, base: &str) -> String {
    if !export.contains_key(Value::from(base)) {
        return base.to_string();
    }
    (2..)
        .map(|n| format!("{base}-{n}"))
        .find(|c| !export.contains_key(Value::from(c.as_str())))
        .expect("an unbounded counter always finds a free name")
}

pub(super) fn migrate_export_named_map(root: &mut Mapping, changes: &mut Vec<String>) {
    let Some(Value::Mapping(export)) = root.get(Value::from(Kind::Export.root())).cloned() else {
        return;
    };
    let type_keys = export_type_keys();

    let mut kept = Mapping::new();
    let mut to_rewrite: Vec<(String, Value)> = Vec::new();
    for (k, v) in export {
        let key = k.as_str().unwrap_or_default().to_string();
        let is_type_key = type_keys.iter().any(|(t, _, _)| *t == key);
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
        let (_, base_name, module) = type_keys
            .iter()
            .find(|(t, _, _)| *t == type_key)
            .expect("only retired type keys reach here");
        let name = uniq_export_name(&kept, base_name);
        let mut inst = Mapping::new();
        inst.insert("module".into(), Value::from(*module));

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
    root.insert(Kind::Export.root().into(), Value::Mapping(kept));
}

pub(super) fn migrate_export_projection(
    root: &mut Mapping,
    changes: &mut Vec<String>,
    todos: &mut Vec<String>,
) {
    let Some(Value::Mapping(mut export)) = root.get(Value::from(Kind::Export.root())).cloned()
    else {
        return;
    };
    let mut out = Mapping::new();
    for key in export.keys().cloned().collect::<Vec<_>>() {
        let Some(name) = key.as_str().map(str::to_string) else {
            if let Some(value) = export.get(&key) {
                out.insert(key, value.clone());
            }
            todos.push("export: an instance name is not a string; its definition was left unchanged for manual migration".into());
            continue;
        };
        match take_mapping(&mut export, &name, Kind::Export.root(), todos) {
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

    root.insert(Kind::Export.root().into(), Value::Mapping(out));
}

fn migrate_one_export_projection(
    name: &str,
    inst: &mut Mapping,
    changes: &mut Vec<String>,
    todos: &mut Vec<String>,
) {
    let ctx = format!("export.{name}");

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
    let released = released_module_streams();
    let released = released.iter().find(|(m, _)| *m == module);
    let Some(streams) = released.map(|(_, s)| s.as_slice()) else {
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
    let key = super::migration_table::text("observability_trace_key");
    let key_1_4 = super::migration_table::text("observability_trace_key_1_4");
    let url = [key, key_1_4]
        .into_iter()
        .filter(|k| !k.is_empty())
        .find_map(|k| take(&mut obs, k));

    let url = url.filter(|v| !v.is_null());
    if let Some(url) = url {
        let export = export_map_mut(root);
        let module = super::migration_table::text("export_trace_module");
        let name = uniq_export_name(
            export,
            super::migration_table::text("export_trace_instance"),
        );
        let mut settings = Mapping::new();
        settings.insert("url".into(), url);
        let mut inst = Mapping::new();
        inst.insert("module".into(), Value::from(module));
        inst.insert("settings".into(), Value::Mapping(settings));
        export.insert(Value::from(name.as_str()), Value::Mapping(inst));
        changes.push(format!(
            "observability.{key} -> export.{name}: {{ module: {module} }} (the `observability:` block \
             is DELETED in 1.5.3; `export:` is the single telemetry-egress surface)"
        ));
    } else {
        changes.push(format!(
            "observability: block removed (DELETED in 1.5.3; it carried no {key} to fold)"
        ));
    }
}
