// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! 1a, the pre-1.5.5 markers (MIGRATE-ON-BOOT §A3 1a): whatever v1.5.5's own boot loud-fail
//! (`config/migrate.rs` `detect_legacy_markers`) reports, this reports, word for word, and the
//! config is refused UNSUPPORTED: 1.5.5 itself refused to boot it, so it was written for an older
//! busbar, and 1.6.0 upgrades only from 1.5.5.
//!
//! Two departures from the tag, both required by the design: v1.5.5's one name-based marker (a
//! retired `store.module`, its `RETIRED_STORE_MODULES_1_5_3` table) is not copied, since core holds
//! no plugin name (such a module fails step 2's generic unknown-module refusal, which carries
//! `UPGRADE_FIRST`); and the clause of the `global_hooks:` marker that sent the operator to a
//! migration flag 1.6.0 no longer has is cut (r41 §9 C1 (mc1)).
//!
//! The markers are read on I, the interpolated document, as 1.5.5's boot read them. No pass
//! converts a marker's input (the dead-pass rule).

use busbar_contract::yaml::{MappingExt, Pairs, Value, ValueExt};

use crate::{Refusal, UPGRADE_FIRST};

/// v1.5.5 `config/mod.rs` `RETIRED_OBSERVABILITY_KEYS`, word for word.
const RETIRED_OBSERVABILITY_KEYS: &[(&str, &str)] = &[
    (
        "request_log_webhook_url",
        "export.request-log-webhook.settings.url",
    ),
    (
        "max_inflight_webhook_deliveries",
        "export.request-log-webhook.settings.max_inflight_deliveries",
    ),
    (
        "webhook_delivery_timeout_secs",
        "export.request-log-webhook.settings.delivery_timeout_secs",
    ),
    (
        "metrics",
        "export.prometheus.settings (buffer_seconds / key_gauge_limit)",
    ),
];

/// v1.5.5 `config/mod.rs` `RETIRED_CONFIG_KEYS_1_5_3`, word for word.
const RETIRED_CONFIG_KEYS_1_5_3: &[(&str, &str)] = &[
    (
        "observability",
        "the `export:` NAMED map — a `module: prometheus` / `module: request-log-webhook` / \
         `module: otlp` instance (all telemetry egress is now the single `export:` surface)",
    ),
    (
        "admin_insecure",
        "admin_require_mtls (INVERTED: `admin_insecure: true` ⇒ `admin_require_mtls: false`)",
    ),
    (
        "upstream_credentials",
        "pools.upstream_credentials (the all-pools default) + a per-pool \
         `pools.<p>.upstream_credentials` override",
    ),
    (
        "methods",
        "the matching `identity-providers:` definition (browser_login + settings are per-provider)",
    ),
    (
        "otlp_url",
        "an `export:` instance with `module: otlp` and `settings.url`",
    ),
    (
        "otlp_endpoint",
        "an `export:` instance with `module: otlp` and `settings.url`",
    ),
];

/// 1a over the interpolated document: UNSUPPORTED with every marker v1.5.5 reports, then
/// [`UPGRADE_FIRST`]; and CONFIG for a top-level `transport` section, which no 1.5.5 config could
/// hold (round 12 C-RETIRE).
pub(crate) fn refuse(doc: &Value) -> Result<(), Refusal> {
    let markers = detect(doc);
    if !markers.is_empty() {
        return Err(Refusal::Unsupported(format!(
            "config.yaml was written for a busbar older than 1.5.5: 1.5.5 itself refused to boot \
             it, and 1.6.0 upgrades only a config 1.5.5 ran. 1.x markers found:\n  - {}\n\
             {UPGRADE_FIRST}",
            markers.join("\n  - ")
        )));
    }
    // Decision 16: a section that names only the retired carrier modules (`tcp`, `stdio`) is accepted; 1d
    // removes its entries with a report line (`retired_carriers::drop_retired`).
    if doc
        .as_mapping()
        .is_some_and(|root| root.contains_key("transport"))
        && !crate::retired_carriers::only_retired(doc)
    {
        return Err(Refusal::Config(format!(
            "config.yaml has no `config_version` but holds a top-level `transport:` section, which \
             no 1.5.5 config could hold (1.5.5 had no transport plugins), so this file was not \
             written for 1.5.5. If it was written for 1.6.0, add `config_version: 1` as its first \
             key; otherwise remove the section.\n{UPGRADE_FIRST}"
        )));
    }
    Ok(())
}

/// v1.5.5 `detect_legacy_markers`, word for word (but for the two departures in the module doc),
/// in its order. Empty = not a 1.x config.
pub(crate) fn detect(doc: &Value) -> Vec<String> {
    let mut markers = Vec::new();
    let Some(root) = doc.as_mapping() else {
        return markers;
    };
    let get = |m: &Pairs, k: &str| -> Option<Value> { m.get_key(k).cloned() };

    if get(root, "governance").is_some() {
        markers.push(
            "`governance:` block (dissolved into store / rate_card / per_request_fee / groups / \
             advanced / auth)"
                .to_string(),
        );
    }
    if let Some(auth) = get(root, "auth").and_then(|v| v.as_mapping().cloned()) {
        if get(&auth, "mode").is_some() {
            markers
                .push("`auth.mode:` (replaced by auth.chain / auth.upstream_credentials)".into());
        }
        if get(&auth, "group_map").is_some() {
            markers.push(
                "`auth.group_map:` (replaced by auth.role_bindings, NESTED BY MODULE; its \
                 rate/budget caps move to a groups: entry)"
                    .into(),
            );
        }
        if get(&auth, "client_tokens").is_some() {
            markers.push("`auth.client_tokens:` (static tokens removed; mint signed keys)".into());
        }
        if get(&auth, "modules").is_some() {
            markers.push(
                "`auth.modules:` (per-module trust caps removed; max_admin_scope moves onto the \
                 chain entry, allowed_groups is gone)"
                    .into(),
            );
        }
        if get(&auth, "group_map").is_some() {
            markers.push(
                "`auth.group_map:` (replaced by auth.role_bindings, NESTED BY MODULE)".into(),
            );
        }
        if get(&auth, "chain")
            .and_then(|v| v.as_sequence().cloned())
            .is_some_and(|seq| {
                seq.iter()
                    .any(|e| matches!(e.as_str(), Some("tokens") | Some("static-tokens")))
            })
        {
            markers.push(
                "`auth.chain: [tokens]` (the static-token module was removed; the 1.5.0 signed-key \
                 verifier is `keys`)"
                    .into(),
            );
        }
    }
    if get(root, "group_map").is_some() {
        markers.push(
            "top-level `group_map:` (moved under auth as auth.role_bindings, nested by module)"
                .into(),
        );
    }
    if get(root, "admin_auth").is_some() {
        markers.push("top-level `admin_auth:` (moved under auth as auth.admin_auth)".into());
    }
    if let Some(Value::Map(hooks)) = get(root, "hooks") {
        if !is_new_hook_defs(&hooks) {
            markers.push(
                "top-level `hooks:` REGISTRY block with legacy socket:/webhook: entries (1.x \
                 transports removed; a 1.5.3 `hooks:` DEFINITION entry names a `module:` — a \
                 `kind: hook` plugin — and carries `groups:`/`phase:` scope)"
                    .into(),
            );
        }
    }
    if get(root, "global_hooks").is_some() {
        markers.push(
            "top-level `global_hooks:` (removed 1.5.3 → the reserved `pools.hooks:` all-pools \
             attach list)"
                .into(),
        );
    }
    if get(root, "metrics").is_some() {
        markers.push(
            "top-level `metrics:` block (retired 1.5.3 → export.prometheus.settings.{buffer_seconds, \
             key_gauge_limit})"
                .into(),
        );
    }
    if let Some(obs) = get(root, "observability").and_then(|v| v.as_mapping().cloned()) {
        for (old, new) in RETIRED_OBSERVABILITY_KEYS {
            if *old != "metrics" && get(&obs, old).is_some() {
                markers.push(format!("`observability.{old}:` (retired 1.5.3 → {new})"));
            }
        }
    }
    let retired_home = |key: &str| -> &'static str {
        RETIRED_CONFIG_KEYS_1_5_3
            .iter()
            .find(|(old, _)| *old == key)
            .map_or("its 1.5.3 replacement", |(_, new)| new)
    };
    if get(root, "observability").is_some() {
        markers.push(format!(
            "top-level `observability:` block (DELETED 1.5.3 → {}); all telemetry egress is now the \
             single `export:` surface",
            retired_home("otlp_url")
        ));
    }
    if get(root, "admin_insecure").is_some() {
        markers.push(format!(
            "top-level `admin_insecure:` (retired 1.5.3 → {})",
            retired_home("admin_insecure")
        ));
    }
    if let Some(auth) = get(root, "auth").and_then(|v| v.as_mapping().cloned()) {
        if get(&auth, "upstream_credentials").is_some() {
            markers.push(format!(
                "`auth.upstream_credentials:` (retired 1.5.3 → {})",
                retired_home("upstream_credentials")
            ));
        }
        if get(&auth, "methods").is_some() {
            markers.push(format!(
                "`auth.methods:` (retired 1.5.3 → {})",
                retired_home("methods")
            ));
        }
        for plane in ["chain", "admin_auth"] {
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
    if let Some(Value::Map(export)) = get(root, "export") {
        if export
            .values()
            .any(|v| v.as_mapping().is_some_and(|m| !m.contains_key("module")))
        {
            markers.push(
                "top-level `export:` is TYPE-KEYED (retired 1.5.3 → a NAMED map `<name>: { module, \
                 settings }`, so the same module can back several instances)"
                    .to_string(),
            );
        }
    }
    if let Some(providers) = get(root, "providers").and_then(|v| v.as_mapping().cloned()) {
        for (name, p) in &providers {
            if p.as_mapping()
                .is_some_and(|m| m.contains_key("api_key_env"))
            {
                markers.push(format!(
                    "`providers.{}.api_key_env:` (secret fields are now secret references: \
                     api_key: {{ env: VAR }})",
                    name.as_str().unwrap_or("?")
                ));
            }
        }
    }
    if let Some(pools) = get(root, "pools").and_then(|v| v.as_mapping().cloned()) {
        for (name, p) in &pools {
            let members = p
                .as_mapping()
                .and_then(|m| get(m, "members"))
                .and_then(|v| v.as_sequence().cloned())
                .unwrap_or_default();
            if members
                .iter()
                .any(|mem| mem.as_mapping().is_some_and(|m| m.contains_key("target")))
            {
                markers.push(format!(
                    "`pools.{}.members[].target:` (renamed to model)",
                    name.as_str().unwrap_or("?")
                ));
            }
            if p.as_mapping()
                .and_then(|m| get(m, "on_exhausted"))
                .and_then(|v| v.as_mapping().cloned())
                .is_some_and(|m| m.contains_key("action"))
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

/// v1.5.5 `is_new_hook_defs`: a `hooks:` map already in the 1.5.3 named-definition shape (every
/// entry names a non-empty `module:` and carries no `socket:`/`webhook:` transport).
fn is_new_hook_defs(hooks: &Pairs) -> bool {
    !hooks.is_empty()
        && hooks.iter().all(|(_, e)| {
            e.as_mapping().is_some_and(|em| {
                em.get_key("module")
                    .and_then(|v| v.as_str())
                    .is_some_and(|s| !s.trim().is_empty())
                    && !em.contains_key("socket")
                    && !em.contains_key("webhook")
            })
        })
}

#[cfg(test)]
#[path = "tests/legacy_markers_tests.rs"]
mod tests;
