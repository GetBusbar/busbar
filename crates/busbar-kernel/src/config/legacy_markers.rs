// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use busbar_contract::plugin::Kind;
use serde_yaml::{Mapping, Value};

pub(super) mod field {
    pub const ACTION: &str = "action";
    pub const ADMIN_AUTH: &str = "admin_auth";
    pub const ADMIN_INSECURE: &str = "admin_insecure";
    pub const API_KEY_ENV: &str = "api_key_env";
    pub const AUTH: &str = "auth";
    pub const CHAIN: &str = "chain";
    pub const CLIENT_TOKENS: &str = "client_tokens";
    pub const GLOBAL_HOOKS: &str = "global_hooks";
    pub const GOVERNANCE: &str = "governance";
    pub const GROUP_MAP: &str = "group_map";
    pub const MEMBERS: &str = "members";
    pub const METHODS: &str = "methods";
    pub const METRICS: &str = "metrics";
    pub const MODE: &str = "mode";
    pub const MODULE: &str = "module";
    pub const MODULES: &str = "modules";
    pub const OBSERVABILITY: &str = "observability";
    pub const ON_EXHAUSTED: &str = "on_exhausted";
    pub const POOLS: &str = "pools";
    pub const SOCKET: &str = "socket";
    pub const TARGET: &str = "target";
    pub const UPSTREAM_CREDENTIALS: &str = "upstream_credentials";
}

pub(super) const LEGACY_TOKENS_MODULE: &str = "tokens";
pub(super) const LEGACY_STATIC_TOKENS_MODULE: &str = "static-tokens";

pub(crate) fn legacy_config_error(markers: &[String]) -> String {
    format!(
        "this looks like a busbar 1.x config; run `busbar --migrate-config <config.yaml>` and \
         review the flagged items. 1.x markers found:\n  - {}\n\
         The 1.5.0 config redesign moved these surfaces (governance dissolved into \
         store/rate_card/groups/advanced; group_map became auth.role_bindings; hooks became \
         inline refs; *_env fields became secret references; pool member target became model). \
         Booting a 1.x config under 1.5.0 rules would silently flip semantics (most critically \
         `allowed_pools: []`, which now means NO pools), so busbar refuses to start instead.\n\
         ALREADY RAN THE MIGRATOR AND STILL SEEING THIS? Then the flagged block was written in a \
         shape the migrator could not read, so it was LEFT EXACTLY AS YOU WROTE IT rather than \
         being silently dropped, and it is still a 1.x marker. Running `--migrate-config` again \
         will produce the same file. Look for the `# TODO` the migrator emitted for that exact \
         path, then either fix the block into the shape the TODO names or delete it by hand.",
        markers.join("\n  - ")
    )
}

pub(crate) fn detect_legacy_markers(doc: &Value) -> Vec<String> {
    let mut markers = Vec::new();
    let Some(root) = doc.as_mapping() else {
        return markers;
    };
    let get = |m: &Mapping, k: &str| -> Option<Value> { m.get(Value::from(k)).cloned() };

    if get(root, field::GOVERNANCE).is_some() {
        markers.push(
            "`governance:` block (dissolved into store / rate_card / per_request_fee / groups / \
             advanced / auth)"
                .to_string(),
        );
    }
    if let Some(auth) = get(root, field::AUTH).and_then(|v| v.as_mapping().cloned()) {
        if get(&auth, field::MODE).is_some() {
            markers
                .push("`auth.mode:` (replaced by auth.chain / auth.upstream_credentials)".into());
        }
        if get(&auth, field::GROUP_MAP).is_some() {
            markers.push(
                "`auth.group_map:` (replaced by auth.role_bindings, NESTED BY MODULE; its \
                 rate/budget caps move to a groups: entry)"
                    .into(),
            );
        }
        if get(&auth, field::CLIENT_TOKENS).is_some() {
            markers.push("`auth.client_tokens:` (static tokens removed; mint signed keys)".into());
        }
        if get(&auth, field::MODULES).is_some() {
            markers.push(
                "`auth.modules:` (per-module trust caps removed; max_admin_scope moves onto the \
                 chain entry, allowed_groups is gone)"
                    .into(),
            );
        }
        if get(&auth, field::GROUP_MAP).is_some() {
            markers.push(
                "`auth.group_map:` (replaced by auth.role_bindings, NESTED BY MODULE)".into(),
            );
        }
        if get(&auth, field::CHAIN)
            .and_then(|v| v.as_sequence().cloned())
            .is_some_and(|seq| {
                seq.iter().any(|e| {
                    matches!(
                        e.as_str(),
                        Some(LEGACY_TOKENS_MODULE) | Some(LEGACY_STATIC_TOKENS_MODULE)
                    )
                })
            })
        {
            markers.push(
                "`auth.chain: [tokens]` (the static-token module was removed; the 1.5.0 signed-key \
                 verifier is `keys`)"
                    .into(),
            );
        }
    }

    if get(root, field::GROUP_MAP).is_some() {
        markers.push(
            "top-level `group_map:` (moved under auth as auth.role_bindings, nested by module)"
                .into(),
        );
    }
    if get(root, field::ADMIN_AUTH).is_some() {
        markers.push("top-level `admin_auth:` (moved under auth as auth.admin_auth)".into());
    }

    if let Some(Value::Mapping(hooks)) = get(root, Kind::Hook.root()) {
        if !is_new_hook_defs(&hooks) {
            markers.push(format!(
                "top-level `hooks:` REGISTRY block with legacy socket:/{}: entries (1.x \
                 transports removed; a 1.5.3 `hooks:` DEFINITION entry names a `module:` — a \
                 `kind: hook` plugin — and carries `groups:`/`phase:` scope)",
                busbar_kernel::config::migration_table::text("hook_1x_url_transport")
            ));
        }
    }

    if get(root, field::GLOBAL_HOOKS).is_some() {
        markers.push(
            "top-level `global_hooks:` (removed 1.5.3 → the reserved `pools.hooks:` all-pools \
             attach list; run `busbar --migrate-config`)"
                .into(),
        );
    }

    if get(root, field::METRICS).is_some() {
        markers.push(format!(
            "top-level `metrics:` block (retired 1.5.3 → export.{}.settings.{{buffer_seconds, \
             key_gauge_limit}})",
            busbar_kernel::config::migration_table::text("metrics_type_key")
        ));
    }
    if let Some(obs) = get(root, field::OBSERVABILITY).and_then(|v| v.as_mapping().cloned()) {
        for (old, new) in busbar_kernel::config::retired_observability_keys() {
            if old != field::METRICS && get(&obs, old).is_some() {
                markers.push(format!("`observability.{old}:` (retired 1.5.3 → {new})"));
            }
        }
    }

    let retired_home = |key: &str| -> String {
        busbar_kernel::config::retired_config_keys_1_5_3()
            .into_iter()
            .find(|(old, _)| *old == key)
            .map_or_else(|| "its 1.5.3 replacement".to_string(), |(_, new)| new)
    };

    if get(root, field::OBSERVABILITY).is_some() {
        markers.push(format!(
            "top-level `observability:` block (DELETED 1.5.3 → {}); all telemetry egress is now the \
             single `export:` surface",
            retired_home(busbar_kernel::config::migration_table::text("observability_trace_key"))
        ));
    }

    if get(root, field::ADMIN_INSECURE).is_some() {
        markers.push(format!(
            "top-level `admin_insecure:` (retired 1.5.3 → {})",
            retired_home(field::ADMIN_INSECURE)
        ));
    }
    if let Some(auth) = get(root, field::AUTH).and_then(|v| v.as_mapping().cloned()) {
        if get(&auth, field::UPSTREAM_CREDENTIALS).is_some() {
            markers.push(format!(
                "`auth.upstream_credentials:` (retired 1.5.3 → {})",
                retired_home(field::UPSTREAM_CREDENTIALS)
            ));
        }

        if get(&auth, field::METHODS).is_some() {
            markers.push(format!(
                "`auth.methods:` (retired 1.5.3 → {})",
                retired_home(field::METHODS)
            ));
        }

        for plane in [field::CHAIN, field::ADMIN_AUTH] {
            if get(&auth, plane)
                .and_then(|v| v.as_sequence().cloned())
                .is_some_and(|seq| seq.iter().any(|e| e.is_mapping()))
            {
                markers.push(format!(
                    "`auth.{plane}:` carries INLINE module entries (retired 1.5.3 → define the \
                     provider once under `identity-providers:` and reference it by bare name)"
                ));
            }
        }
    }

    if let Some(Value::Mapping(export)) = get(root, Kind::Export.root()) {
        if export.values().any(|v| {
            v.as_mapping()
                .is_some_and(|m| !m.contains_key(Value::from(field::MODULE)))
        }) {
            markers.push(
                "top-level `export:` is TYPE-KEYED (retired 1.5.3 → a NAMED map `<name>: { module, \
                 settings }`, so the same module can back several instances)"
                    .to_string(),
            );
        }
    }

    if let Some(mut store) = get(root, Kind::Store.root()).and_then(|v| v.as_mapping().cloned()) {
        if let Some((module, alias)) = busbar_kernel::config::migration_table::rewrite_retired(
            Kind::Store.root(),
            &mut store,
            false,
        ) {
            markers.push(format!(
                "`store.module: {module}` (RENAMED 1.5.3 → `{alias}`; the first-party store plugin \
                 is {} — artifact `{}-<ver>-<target>.tar.gz`, manifest name `{}`. The old \
                 name/alias resolve against NOTHING, so this would fail at boot with a generic \
                 unresolved-plugin error; run `busbar --migrate-config`)",
                busbar_kernel::config::migration_table::text("renamed_display"),
                busbar_kernel::config::migration_table::text(&format!("asset.{alias}")),
                busbar_kernel::config::migration_table::text(&format!("manifest.{alias}")),
            ));
        }
    }
    if let Some(providers) = get(root, Kind::Transport.root()).and_then(|v| v.as_mapping().cloned())
    {
        for (name, p) in &providers {
            if p.as_mapping()
                .is_some_and(|m| m.contains_key(Value::from(field::API_KEY_ENV)))
            {
                markers.push(format!(
                    "`providers.{}.api_key_env:` (secret fields are now secret references: \
                     api_key: {{ env: VAR }})",
                    name.as_str().unwrap_or("?")
                ));
            }
        }
    }
    if let Some(pools) = get(root, field::POOLS).and_then(|v| v.as_mapping().cloned()) {
        for (name, p) in &pools {
            let members = p
                .as_mapping()
                .and_then(|m| get(m, field::MEMBERS))
                .and_then(|v| v.as_sequence().cloned())
                .unwrap_or_default();
            if members.iter().any(|mem| {
                mem.as_mapping()
                    .is_some_and(|m| m.contains_key(Value::from(field::TARGET)))
            }) {
                markers.push(format!(
                    "`pools.{}.members[].target:` (renamed to model)",
                    name.as_str().unwrap_or("?")
                ));
            }

            if p.as_mapping()
                .and_then(|m| get(m, field::ON_EXHAUSTED))
                .and_then(|v| v.as_mapping().cloned())
                .is_some_and(|m| m.contains_key(Value::from(field::ACTION)))
            {
                markers.push(format!(
                    "`pools.{}.on_exhausted.action:` (the action wrapper is gone; use a bare \
                     `reject`/`least_bad` or `{{ fallback_pool: <pool> }}`)",
                    name.as_str().unwrap_or("?")
                ));
            }
        }
    }
    markers
}

pub(super) fn is_new_hook_defs(hooks: &Mapping) -> bool {
    !hooks.is_empty()
        && hooks.iter().all(|(_, e)| {
            e.as_mapping().is_some_and(|em| {
                em.get(Value::from(field::MODULE))
                    .and_then(|v| v.as_str())
                    .is_some_and(|s| !s.trim().is_empty())
                    && !em.contains_key(Value::from(field::SOCKET))
                    && !em.contains_key(Value::from(busbar_kernel::config::migration_table::text(
                        "hook_1x_url_transport",
                    )))
            })
        })
}
