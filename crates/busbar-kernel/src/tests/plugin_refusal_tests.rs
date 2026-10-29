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
