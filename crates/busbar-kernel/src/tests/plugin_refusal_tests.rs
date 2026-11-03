// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::log_scanned_rows;
use crate::audit::auditlog::{
    ensure_global_audit_stream_registered, plugin_refusal_resource, PluginRefusal, AUDIT_LOG,
    PLUGIN_REFUSAL_PRINCIPAL,
};
use busbar_contract::plugin_rows::{NeedLevel, Row, Skipped, Trust};

#[test]
fn a_trust_policy_skip_seals_one_plugin_trust_record() {
    ensure_global_audit_stream_registered();

    let row = Skipped {
        file: "bind-audit-trust-probe.tar.gz".into(),
        name: "bind-audit-probe".into(),
        alias: "bind-audit-probe".into(),
        reason: "unknown publisher 'acme|key.create|x'; refusing to load".into(),
        code: "unknown_publisher",
    };

    log_scanned_rows(&[], &[row], &[], "/plugins");

    let resource =
        plugin_refusal_resource("file", "bind-audit-trust-probe.tar.gz", "unknown_publisher");
    assert_eq!(
        resource,
        "plugin:file/bind-audit-trust-probe.tar.gz#unknown_publisher"
    );
    let sealed = AUDIT_LOG.list_filtered(
        0,
        usize::MAX,
        Some(PluginRefusal::Trust.action()),
        Some(&resource),
    );
    assert_eq!(sealed.len(), 1, "one record per skip: {sealed:?}");
    assert_eq!(sealed[0].outcome, "rejected");
    assert_eq!(sealed[0].principal, PLUGIN_REFUSAL_PRINCIPAL);
}

#[test]
fn an_unverified_load_seals_one_degraded_plugin_trust_record() {
    ensure_global_audit_stream_registered();
    let row = Row {
        file: "item1-unsigned-probe.tar.gz".into(),
        key: "item1-unsigned-probe".into(),
        name: "item1-unsigned-probe".into(),
        alias: "item1-unsigned-probe".into(),
        kind: "store".into(),
        version: "1.0.0".into(),
        abi_version: 3,
        trust: Trust::Allowed {
            reason: "plugin manifest is unsigned|x; loaded because allow_unsigned is set".into(),
        },
        ephemeral: false,
        in_process: false,
        linked: false,
        needs_prompt: NeedLevel::No,
        needs_user: NeedLevel::No,
        settings_schema: None,
    };

    log_scanned_rows(&[row], &[], &[], "/plugins");

    let resource = plugin_refusal_resource("file", "item1-unsigned-probe.tar.gz", "unverified");
    let sealed = AUDIT_LOG.list_filtered(
        0,
        usize::MAX,
        Some(PluginRefusal::Unverified.action()),
        Some(&resource),
    );
    assert_eq!(
        sealed.len(),
        1,
        "one record per unverified load: {sealed:?}"
    );
    assert_eq!(sealed[0].outcome, "degraded");
    assert_eq!(sealed[0].principal, PLUGIN_REFUSAL_PRINCIPAL);
}

#[test]
fn a_retired_key_skip_seals_one_rejected_plugin_trust_record() {
    ensure_global_audit_stream_registered();
    let row = Skipped {
        file: "sec-allowuns-retired-probe.tar.gz".into(),
        name: "sec-allowuns-retired-probe".into(),
        alias: "sec-allowuns-retired-probe".into(),
        reason:
            "first-party manifest signed by the RETIRED busbar release key b18395|x (retired); \
         refusing to load it. plugins.trust.allow_unsigned does not admit a retired key"
                .into(),
        code: "retired_key",
    };

    log_scanned_rows(&[], &[row], &[], "/plugins");

    let resource =
        plugin_refusal_resource("file", "sec-allowuns-retired-probe.tar.gz", "retired_key");
    let sealed = AUDIT_LOG.list_filtered(
        0,
        usize::MAX,
        Some(PluginRefusal::Trust.action()),
        Some(&resource),
    );
    assert_eq!(sealed.len(), 1, "one record per skip: {sealed:?}");
    assert_eq!(sealed[0].outcome, "rejected");
    assert_eq!(sealed[0].principal, PLUGIN_REFUSAL_PRINCIPAL);
    let unverified = AUDIT_LOG.list_filtered(
        0,
        usize::MAX,
        Some(PluginRefusal::Unverified.action()),
        Some(&plugin_refusal_resource(
            "file",
            "sec-allowuns-retired-probe.tar.gz",
            "unverified",
        )),
    );
    assert!(
        unverified.is_empty(),
        "a refused retired-key plugin is never recorded as an unverified load: {unverified:?}"
    );
}
