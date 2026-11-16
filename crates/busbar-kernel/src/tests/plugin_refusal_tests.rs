// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::log_scanned_rows;
use crate::audit::auditlog::{
    ensure_global_audit_stream_registered, plugin_refusal_resource, PluginRefusal, AUDIT_LOG,
    PLUGIN_REFUSAL_PRINCIPAL,
};
use busbar_contract::plugin_rows::{NeedLevel, Row, Skipped, Trust};

#[tokio::test]
async fn a_trust_policy_skip_seals_one_plugin_trust_record() {
    ensure_global_audit_stream_registered().await;

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
    crate::audit::auditlog::flush_pending()
        .await
        .expect("native refusal audit confirmed");
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

#[tokio::test]
async fn an_unverified_load_seals_one_degraded_plugin_trust_record() {
    ensure_global_audit_stream_registered().await;
    let row = Row {
        file: "item1-unsigned-probe.tar.gz".into(),
        key: "item1-unsigned-probe".into(),
        name: "item1-unsigned-probe".into(),
        alias: "item1-unsigned-probe".into(),
        kind: "store".into(),
        version: "1.0.0".into(),
        abi_version: 3,
        trust: Trust::Allowed {
            reason: "plugin manifest is unsigned|x; loaded because allow_untrusted is set".into(),
            setting: "allow_untrusted",
        },
        ephemeral: false,
        in_process: false,
        linked: false,
        needs_prompt: NeedLevel::No,
        needs_user: NeedLevel::No,
        settings_schema: None,
    };

    log_scanned_rows(&[row], &[], &[], "/plugins");

    let resource =
        plugin_refusal_resource("file", "item1-unsigned-probe.tar.gz", "allow_untrusted");
    crate::audit::auditlog::flush_pending()
        .await
        .expect("native refusal audit confirmed");
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

fn allowed_row(file: &str, setting: &'static str) -> Row {
    Row {
        file: file.into(),
        key: file.into(),
        name: file.into(),
        alias: file.into(),
        kind: "store".into(),
        version: "1.0.0".into(),
        abi_version: 3,
        trust: Trust::Allowed {
            reason: format!("admitted by {setting}"),
            setting,
        },
        ephemeral: false,
        in_process: false,
        linked: false,
        needs_prompt: NeedLevel::No,
        needs_user: NeedLevel::No,
        settings_schema: None,
    }
}

/// SEC-4 / PRD-5: the audit record of an opt-in admission names WHICH `plugins.trust` setting
/// admitted the plugin; the unified override covers unsigned and unknown publishers.
#[tokio::test]
async fn each_untrusted_admission_seals_a_record_naming_the_override() {
    ensure_global_audit_stream_registered().await;
    for (file, setting) in [
        ("trust-optin-third-party.tar.gz", "allow_untrusted"),
        ("trust-optin-unsigned.tar.gz", "allow_untrusted"),
    ] {
        log_scanned_rows(&[allowed_row(file, setting)], &[], &[], "/plugins");
        crate::audit::auditlog::flush_pending()
            .await
            .expect("native refusal audit confirmed");
        let sealed = AUDIT_LOG.list_filtered(
            0,
            usize::MAX,
            Some(PluginRefusal::Unverified.action()),
            Some(&plugin_refusal_resource("file", file, setting)),
        );
        assert_eq!(sealed.len(), 1, "{setting}: one record: {sealed:?}");
        assert_eq!(sealed[0].outcome, "degraded");
    }
}

#[tokio::test]
async fn a_retired_key_skip_seals_one_rejected_plugin_trust_record() {
    ensure_global_audit_stream_registered().await;
    let row = Skipped {
        file: "sec-allowuns-retired-probe.tar.gz".into(),
        name: "sec-allowuns-retired-probe".into(),
        alias: "sec-allowuns-retired-probe".into(),
        reason:
            "first-party manifest signed by the RETIRED busbar release key b18395|x (retired); \
         refusing to load it. plugins.trust.allow_untrusted does not admit a retired key"
                .into(),
        code: "retired_key",
    };

    log_scanned_rows(&[], &[row], &[], "/plugins");

    let resource =
        plugin_refusal_resource("file", "sec-allowuns-retired-probe.tar.gz", "retired_key");
    crate::audit::auditlog::flush_pending()
        .await
        .expect("native refusal audit confirmed");
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

/// FIPS admission (CRYPTO-SEAM §9 "no external"): on a crypto backend that admits no external
/// plugin, an unsigned drop-in is refused through the real directory scan with every
/// `plugins.trust` opt-in on, and the boot logger seals one rejected `plugin.trust` record coded
/// `external_crypto`, never an unverified load. `FipsBackend` substitutes only the backend's
/// answer (`EXTERNAL_PLUGINS = false`); the scan and the logger are the shipped ones.
#[tokio::test]
async fn a_fips_backend_refusal_of_an_unsigned_drop_in_seals_one_external_crypto_record() {
    use busbar_contract::plugin_rows::PluginRows;
    use busbar_plugin_loader::sign::{sha256_hex, FipsBackend, Manifest, TrustPolicy};

    ensure_global_audit_stream_registered().await;
    let file = "fips-external-unsigned-probe.tar.gz";
    let lib = b"fips external-plugin probe library; refused before it is ever opened";
    let manifest = Manifest {
        name: "fips-external-unsigned-probe".into(),
        alias: "fips-external-unsigned-probe".into(),
        kind: "store".into(),
        version: "1.0.0".into(),
        publisher: "acme".into(),
        abi_version: busbar_contract::abi::store::ABI_VERSION,
        sha256: sha256_hex(lib),
        ..Manifest::default()
    };
    let dir = std::env::temp_dir().join(format!(
        "busbar-kernel-fips-external-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("create the plugins dir");
    let tarball = busbar_plugin_loader::tarball::package(&manifest, "libplugin.so", lib)
        .expect("package the probe");
    std::fs::write(dir.join(file), tarball).expect("write the probe tarball");
    let policy = TrustPolicy {
        allow_untrusted: true,
        binary_version: "1.6.0".into(),
        ..TrustPolicy::default()
    };
    let registry = {
        let _fips = FipsBackend::link();
        busbar_plugin_loader::scan_and_validate(&dir, &policy)
            .expect("a refused plugin is skipped, not fatal")
    };
    let _ = std::fs::remove_dir_all(&dir);

    let loadable = PluginRows::loadable(&registry);
    let skipped = PluginRows::skipped(&registry);
    assert!(
        loadable.is_empty(),
        "a FIPS backend loads no unsigned plugin, allow_untrusted or not: {loadable:?}"
    );
    assert_eq!(skipped.len(), 1, "the refusal is a skip: {skipped:?}");
    assert_eq!(skipped[0].code, "external_crypto", "{}", skipped[0].reason);

    log_scanned_rows(&loadable, &skipped, &[], "/plugins");

    let resource = plugin_refusal_resource("file", file, "external_crypto");
    crate::audit::auditlog::flush_pending()
        .await
        .expect("native refusal audit confirmed");
    let sealed = AUDIT_LOG.list_filtered(
        0,
        usize::MAX,
        Some(PluginRefusal::Trust.action()),
        Some(&resource),
    );
    assert_eq!(sealed.len(), 1, "one record per refusal: {sealed:?}");
    assert_eq!(sealed[0].outcome, "rejected");
    assert_eq!(sealed[0].principal, PLUGIN_REFUSAL_PRINCIPAL);
    let unverified = AUDIT_LOG.list_filtered(
        0,
        usize::MAX,
        Some(PluginRefusal::Unverified.action()),
        Some(&plugin_refusal_resource("file", file, "unverified")),
    );
    assert!(
        unverified.is_empty(),
        "a refused plugin is never recorded as an unverified load: {unverified:?}"
    );
}
