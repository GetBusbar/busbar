// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! A PLUGIN THE TRUST POLICY SKIPS AT BOOT IS AUDITED (owner rule: every refusal is audited and
//! explained; nothing silent). The skip was a WARN line (BUSBAR-6002) and nothing on the chain.

use super::{log_build, BuildNote};
use crate::audit::auditlog::{
    ensure_global_audit_stream_registered, plugin_refusal_resource, PluginRefusal, AUDIT_LOG,
    PLUGIN_REFUSAL_PRINCIPAL,
};
use crate::test_support::rows::{skipped, Rows};

#[test]
fn a_trust_policy_skip_seals_one_plugin_trust_record() {
    ensure_global_audit_stream_registered();
    // The evaluator's words carry manifest bytes, a `|` among them: none of it reaches the chain.
    let mut row = skipped(
        "bind-audit-probe",
        "bind-audit-probe",
        "unknown publisher 'acme|key.create|x'; refusing to load",
    );
    row.file = "bind-audit-trust-probe.tar.gz".to_string();
    row.code = "unknown_publisher";
    let rows = Rows::new().with_skipped(row).into_rows();

    log_build(
        BuildNote::Scanned {
            rows: rows.as_ref(),
            copies: &[],
        },
        "/plugins",
    );

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

/// A PLUGIN LOADED AS UNVERIFIED IS AUDITED (lead ruling, security report 2026-10-29, item 1):
/// `plugins.trust.allow_unsigned` loads an UNSIGNED plugin as UNVERIFIED code, with the BUSBAR-6003
/// warning (1.5.5's line, unchanged) AND one `plugin.trust` record on the chain, outcome `degraded`:
/// the plugin loaded, and nothing vouches for its bytes. The evaluator's reason stays in the
/// warning; the chain holds the host's category, `unverified`. (A RETIRED-key signature no longer
/// reaches this path: owner-signed 2026-10-30, it is refused even under allow_unsigned; see the
/// test below.)
#[test]
fn an_unverified_load_seals_one_degraded_plugin_trust_record() {
    use busbar_contract::plugin_rows::Trust;
    ensure_global_audit_stream_registered();
    let mut row =
        crate::test_support::rows::row("item1-unsigned-probe", "item1-unsigned-probe", "store");
    row.file = "item1-unsigned-probe.tar.gz".to_string();
    row.trust = Trust::Allowed {
        reason: "plugin manifest is unsigned|x; loaded because allow_unsigned is set".to_string(),
    };
    let rows = Rows::new().with_dropped(row).into_rows();

    log_build(
        BuildNote::Scanned {
            rows: rows.as_ref(),
            copies: &[],
        },
        "/plugins",
    );

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

/// A RETIRED-KEY SIGNATURE UNDER `allow_unsigned` IS A REFUSAL, AUDITED LIKE EVERY OTHER TRUST SKIP
/// (owner-signed 2026-10-30, SEC-ALLOWUNS): the boot skips it and seals one `plugin.trust` record,
/// outcome `rejected`, under the `retired_key` category, never a `degraded` unverified load.
#[test]
fn a_retired_key_skip_seals_one_rejected_plugin_trust_record() {
    ensure_global_audit_stream_registered();
    let mut row = skipped(
        "sec-allowuns-retired-probe",
        "sec-allowuns-retired-probe",
        "first-party manifest signed by the RETIRED busbar release key b18395|x (retired); \
         refusing to load it. plugins.trust.allow_unsigned does not admit a retired key",
    );
    row.file = "sec-allowuns-retired-probe.tar.gz".to_string();
    row.code = "retired_key";
    let rows = Rows::new().with_skipped(row).into_rows();

    log_build(
        BuildNote::Scanned {
            rows: rows.as_ref(),
            copies: &[],
        },
        "/plugins",
    );

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
