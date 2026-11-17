// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;

fn acceptance(text: &str) -> Option<busbar_contract::yaml::Value> {
    Some(busbar_contract::yaml::from_str(text).expect("YAML"))
}

#[test]
fn each_root_listener_names_its_own_tls_and_acceptance_keys_in_its_remedy() {
    for (listener, setting, tls, key) in [
        (DATA, "listen", "tls", "listen_insecure_transport"),
        (
            ADMIN,
            "admin_listen",
            "admin_tls",
            "admin_listen_insecure_transport",
        ),
    ] {
        let refusal = listener.refusal("127.0.0.1:1");
        assert!(refusal.starts_with("BUSBAR-3172"), "{refusal}");
        assert!(refusal.contains(&format!("`{setting}` 127.0.0.1:1 has no TLS")));
        assert!(refusal.contains(&format!("add `{tls}:`")));
        assert!(refusal.contains(&format!(
            "`{key}: {{ accept: [plaintext], reason: \"<why>\" }}`"
        )));
        assert_eq!(
            audit_resource(&listener),
            format!("listener:{setting}:accept=plaintext")
        );
    }
}

#[test]
fn resolve_admits_only_plaintext_with_a_reason_and_never_beside_tls() {
    let mut deploy = crate::config::tests::base_deploy();
    deploy.listen_insecure_transport = acceptance("{ accept: plaintext, reason: lab }");
    deploy.admin_listen_insecure_transport =
        acceptance("{ accept: [plaintext, unverified_tls], reason: lab }");
    let mut errors = Vec::new();
    let resolved = resolve(&deploy, &mut errors);
    assert_eq!(
        resolved.listen.as_ref().map(|t| &*t.reason),
        Some("lab"),
        "plaintext with a reason is accepted"
    );
    assert!(resolved.admin_listen.is_none());
    assert_eq!(errors.len(), 1, "{errors:?}");
    assert!(errors[0].starts_with("BUSBAR-3163: admin_listen_insecure_transport.accept"));

    deploy.admin_listen_insecure_transport = None;
    deploy.tls = Some(crate::config::TlsCfg {
        cert: crate::config::secret::descriptor_reference("cert.pem"),
        key: crate::config::secret::descriptor_reference("key.pem"),
        client_ca: None,
    });
    let mut errors = Vec::new();
    let resolved = resolve(&deploy, &mut errors);
    assert!(resolved.listen.is_none());
    assert_eq!(errors.len(), 1, "{errors:?}");
    assert!(errors[0].contains("`listen_insecure_transport` is written beside `tls`"));
}

#[test]
fn an_overlay_tls_supersedes_the_file_acceptance_once() {
    let mut deploy = crate::config::tests::base_deploy();
    deploy.admin_listen_insecure_transport = acceptance("{ accept: plaintext, reason: lab }");
    supersede(&mut deploy, &DATA);
    assert!(
        deploy.inert_listener_acceptances.is_empty(),
        "nothing written, nothing inert"
    );
    supersede(&mut deploy, &ADMIN);
    supersede(&mut deploy, &ADMIN);
    assert!(deploy.admin_listen_insecure_transport.is_none());
    assert_eq!(
        deploy.inert_listener_acceptances,
        ["admin_listen_insecure_transport"]
    );
    let mut errors = Vec::new();
    let resolved = resolve(&deploy, &mut errors);
    assert!(errors.is_empty(), "{errors:?}");
    assert_eq!(resolved.inert, ["admin_listen_insecure_transport"]);
    assert!(inert_line("admin_listen_insecure_transport")
        .contains("Remove `admin_listen_insecure_transport`"));
}
