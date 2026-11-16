// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;
use std::{
    future::Future as _,
    task::{Context, Poll, Waker},
};

#[test]
fn typed_builder_refusal_survives_an_async_cleanup_without_lending_thread_authority() {
    let mut future = Box::pin(scoped_async::<(), TxnError>(None, async {
        BUILD_AUTHORITY.with(|held| held.borrow_mut().refusal = Some(TxnError::Forbidden));
        let mut first = true;
        std::future::poll_fn(move |_| {
            if std::mem::take(&mut first) {
                Poll::Pending
            } else {
                Poll::Ready(())
            }
        })
        .await;
        Err(TxnError::Validation(
            "a failed builder finished its cleanup".into(),
        ))
    }));
    let mut context = Context::from_waker(Waker::noop());
    assert!(future.as_mut().poll(&mut context).is_pending());
    assert!(BUILD_AUTHORITY.with(|held| held.borrow().refusal.is_none()));
    assert!(matches!(
        future.as_mut().poll(&mut context),
        Poll::Ready(Err(TxnError::Forbidden))
    ));
    assert!(BUILD_AUTHORITY.with(|held| held.borrow().refusal.is_none()));
}

/// SECRET-SHORTHAND-BOOT F10 (R12 at the digest): `plugins.fetch` is part of the security digest.
/// A candidate that only adds a fetch URL is a security change, so a caller without full-operator
/// authority is refused before the build fetches anything.
#[test]
fn a_plugins_fetch_change_is_security_relevant() {
    let deploy: super::super::DeployCfg =
        serde_json::from_value(serde_json::json!({"providers": {}, "models": {}}))
            .expect("a minimal document reads");
    let cfg = super::super::resolve(&deploy, &std::collections::HashMap::new())
        .expect("a minimal document resolves");
    let plain = super::super::PluginsCfg::default();
    let fetching: super::super::PluginsCfg = serde_json::from_value(serde_json::json!({
        "fetch": [{"url": "https://plugins.example/fixture-plugin.tar.gz"}]
    }))
    .expect("a plugins block with one fetch entry reads");
    assert_ne!(
        root_digest(&cfg, &plain),
        root_digest(&cfg, &fetching),
        "adding a plugins.fetch entry must change the security digest"
    );
    let by_env: super::super::PluginsCfg = serde_json::from_value(serde_json::json!({
        "fetch": [{"env": "FIXTURE_PLUGIN_URL"}]
    }))
    .expect("a plugins block with one env fetch entry reads");
    assert_ne!(
        root_digest(&cfg, &plain),
        root_digest(&cfg, &by_env),
        "an env fetch entry changes the digest by its variable's name"
    );
}

/// A grammar that declares no shorthand: the documents below write canonical references only.
fn no_shorthand() -> super::super::Grammar {
    super::super::Grammar::new(
        busbar_contract::secret_ref::Sugars::default(),
        std::collections::BTreeMap::new(),
        Vec::new(),
    )
}

/// SECRET-SHORTHAND-BOOT §3.12: the authority pre-check reads a candidate body's security fields,
/// before any scan, into exactly the digest its build would store, and names the field class a
/// change touches.
#[test]
fn a_candidate_digests_its_security_fields_as_its_build_does() {
    let document = serde_json::json!({
        "providers": {},
        "models": {},
        "security": { "blocked_metadata_hosts": ["169.254.169.254"] },
        "plugins": {
            "enabled": true,
            "dir": "/srv/busbar/plugins",
            "fetch": [{ "url": "https://plugins.example/fixture-plugin.tar.gz" }],
        },
    });
    let grammar = no_shorthand();
    let deploy = super::super::deploy_from_deserializer(document.clone(), &grammar)
        .expect("the document reads");
    let cfg = super::super::resolve(&deploy, &std::collections::HashMap::new())
        .expect("the document resolves");
    let built = root_digest(&cfg, &deploy.plugins);
    let candidate =
        Candidate::of_json(&document, &grammar, None).expect("the candidate's policy reads");
    assert_eq!(
        candidate.digest.as_ref(),
        Some(&built),
        "the pre-check and the build digest the same fields the same way"
    );
    assert_eq!(candidate.plugins.dir, "/srv/busbar/plugins");
    assert_eq!(
        candidate.blocked_metadata_hosts,
        vec!["169.254.169.254".to_owned()]
    );

    for (path, value, class) in [
        ("dir", serde_json::json!("/elsewhere"), "plugins.dir"),
        ("fetch", serde_json::json!([]), "plugins.fetch"),
        (
            "trust",
            serde_json::json!({ "allow_untrusted": true }),
            "plugins.trust",
        ),
    ] {
        let mut changed = document.clone();
        changed["plugins"][path] = value;
        let other = Candidate::of_json(&changed, &grammar, None).expect("the change reads");
        assert_eq!(
            built.changed(other.digest.as_ref().expect("its fields read")),
            vec![class],
            "changing plugins.{path} is a change of exactly {class}"
        );
    }
}

/// A candidate whose security fields use a shorthand the running generation does not declare
/// cannot be compared field by field: it counts as changed (§3.12), while its plugin policy (which
/// holds no reference) still reads for its own phase 1.
#[test]
fn a_candidate_unreadable_under_the_running_grammar_counts_as_changed() {
    let document = serde_json::json!({
        "providers": {},
        "models": {},
        "auth": { "admin_auth": [], "signing_key": { "fixture-word": "slot" } },
        "plugins": { "enabled": true, "dir": "/srv/busbar/plugins" },
    });
    let candidate = Candidate::of_json(&document, &no_shorthand(), None)
        .expect("the plugin policy reads without a grammar");
    assert!(
        candidate.digest.is_none(),
        "a word the running generation does not know leaves the fields unread"
    );
    assert!(candidate.plugins.enabled);
}

#[test]
fn publisher_scope_key_rotation_and_revocation_change_security_policy() {
    let deploy: super::super::DeployCfg =
        busbar_contract::yaml::from_str("providers: {}\nmodels: {}\n").unwrap();
    let cfg = super::super::resolve(&deploy, &std::collections::HashMap::new()).unwrap();
    let policy = |scope: &str, key: &str, revoked: bool| -> super::super::PluginsCfg {
        busbar_contract::yaml::from_str(&format!("trust: {{publishers: [{{name: vendor, plugins: [{scope}], keys: [{{public_key: '{key}', revoked: {revoked}}}]}}]}}")).unwrap()
    };
    let base = policy("example", "aa", false);
    for changed in [
        policy("other", "aa", false),
        policy("example", "bb", false),
        policy("example", "aa", true),
    ] {
        assert_ne!(root_digest(&cfg, &base), root_digest(&cfg, &changed));
    }
}
