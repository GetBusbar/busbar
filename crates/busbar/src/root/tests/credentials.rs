// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use std::sync::Arc;

use busbar_contract::abi::host::service::{SECRET_LIVE, SECRET_NOT_LIVE};
use busbar_contract::services::{CredentialRead, HostServices, Ran, Stored};
use busbar_kernel::governance::{GovState, NewKeySpec};
use busbar_kernel::host_services::{KernelServices, NOT_READABLE, NO_CREDENTIAL_SOURCE};

use super::AppCredentials;

fn signed_kind() -> String {
    const FROZEN_SIGNED_CREDENTIAL_KIND: &str = "sigv4";
    FROZEN_SIGNED_CREDENTIAL_KIND.to_string()
}

fn gov_with_key(name: &str) -> (Arc<GovState>, String, String) {
    let gov = Arc::new(GovState::new(crate::root::real_store::records(), None).unwrap());
    let spec = NewKeySpec {
        name: name.to_string(),
        ..Default::default()
    };
    gov.set_signing_key(Some(
        busbar_kernel::governance::signing::TokenSigner::from_secret_bytes(
            &[9u8; 32],
            busbar_kernel::governance::signing::DEFAULT_KID,
        ),
    ));
    gov.set_at_rest_keys(Some(busbar_kernel::governance::at_rest::AtRestKeys::new(
        &[3u8; 32], None,
    )));
    let shape = busbar_contract::auth_calls::IssuedShape {
        id_prefix: "AKIA".into(),
        id_len: 20,
        id_alphabet: "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789".into(),
        secret_len: 40,
        secret_alphabet: "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/".into(),
    };
    let (_key, _bearer, id, secret) = gov
        .mint_signed_with_credential(
            spec,
            4_000_000_000,
            busbar_kernel::store::now(),
            &signed_kind(),
            &shape,
        )
        .unwrap();
    let secret = secret.expose(&busbar_kernel::seal::lend()).clone();
    (gov, id, secret)
}

#[test]
fn the_credential_read_follows_the_app_swap() {
    let (first, old_id, old_secret) = gov_with_key("first");
    let (second, new_id, new_secret) = gov_with_key("second");
    let kind = signed_kind();
    let handle = Arc::new(busbar_kernel::state::AppHandle::new({
        crate::dist_root_install::install();
        let module = busbar_kernel::preflight::root_rows()
            .stores
            .first()
            .expect("the distribution links its actual store")
            .0;
        let settings: serde_json::Value = serde_json::from_str(
            &std::env::var("BUSBAR_GOVERNANCE_TEST_STORE_SETTINGS").unwrap_or_else(|_| "{}".into()),
        )
        .unwrap();
        let deploy = busbar_kernel::config::deploy_from_deserializer(serde_json::json!({
            "providers": {}, "models": {}, "auth": {"chain": [], "admin_auth": []},
            "store": {"module": module, "settings": settings},
            "advanced": {"allow_destinations": ["127.0.0.1"]}
        }))
        .unwrap();
        let config = busbar_kernel::config::resolve(&deploy, &Default::default()).unwrap();
        let rules = Arc::new(crate::root::door_steps::Rules::default())
            as Arc<dyn busbar_kernel::appbuild::RootRules>;
        let (mut app, rotate, limits) = busbar_kernel::build_app_from_config(
            config,
            Default::default(),
            None,
            Default::default(),
            Default::default(),
            (None, None),
            None,
            &rules,
        )
        .expect("the production root builds the credential generation");
        limits.stage_boot();
        crate::root::kernel::ROOT_CARD.keep_in_store(
            app.governance
                .as_ref()
                .expect("the actual deployment configured governance")
                .store_calls()
                .expect("the actual configured Store exposes its rate-history slots"),
            123,
        );
        crate::root::kernel::ROOT_CARD
            .boot_in_store(None)
            .expect("the actual configured Store boots its rate history");
        limits.keep().unwrap();
        if let Some(rotate) = rotate {
            rotate();
        }
        app.governance = Some(first);
        Arc::new(app)
    }));
    let creds = AppCredentials::new(Arc::clone(&handle));
    let (s, live) = creds.read(&kind, &old_id);
    assert_eq!(
        (s.expose(&busbar_kernel::seal::lend()).as_str(), live),
        (old_secret.as_str(), true)
    );
    handle.swap({
        crate::dist_root_install::install();
        let module = busbar_kernel::preflight::root_rows()
            .stores
            .first()
            .expect("the distribution links its actual store")
            .0;
        let settings: serde_json::Value = serde_json::from_str(
            &std::env::var("BUSBAR_GOVERNANCE_TEST_STORE_SETTINGS").unwrap_or_else(|_| "{}".into()),
        )
        .unwrap();
        let deploy = busbar_kernel::config::deploy_from_deserializer(serde_json::json!({
            "providers": {}, "models": {}, "auth": {"chain": [], "admin_auth": []},
            "store": {"module": module, "settings": settings},
            "advanced": {"allow_destinations": ["127.0.0.1"]}
        }))
        .unwrap();
        let config = busbar_kernel::config::resolve(&deploy, &Default::default()).unwrap();
        let rules = Arc::new(crate::root::door_steps::Rules::default())
            as Arc<dyn busbar_kernel::appbuild::RootRules>;
        let (mut app, rotate, limits) = busbar_kernel::build_app_from_config(
            config,
            Default::default(),
            None,
            Default::default(),
            Default::default(),
            (None, None),
            None,
            &rules,
        )
        .expect("the production root builds the credential generation");
        limits.stage_boot();
        crate::root::kernel::ROOT_CARD.keep_in_store(
            app.governance
                .as_ref()
                .expect("the actual deployment configured governance")
                .store_calls()
                .expect("the actual configured Store exposes its rate-history slots"),
            123,
        );
        crate::root::kernel::ROOT_CARD
            .boot_in_store(None)
            .expect("the actual configured Store boots its rate history");
        limits.keep().unwrap();
        if let Some(rotate) = rotate {
            rotate();
        }
        app.governance = Some(second);
        Arc::new(app)
    });
    let (s, live) = creds.read(&kind, &new_id);
    assert_eq!(
        (s.expose(&busbar_kernel::seal::lend()).as_str(), live),
        (new_secret.as_str(), true)
    );
    let (s, live) = creds.read(&kind, &old_id);
    assert_eq!(
        (s.expose(&busbar_kernel::seal::lend()).as_str(), live),
        ("", false),
        "a removed id is no longer live"
    );
}

struct Source;
impl CredentialRead for Source {
    fn read(&self, kind: &str, id: &str) -> (busbar_contract::redacted::Secret<String>, bool) {
        let secret = busbar_contract::redacted::Secret::new(format!("{kind}:{id}"));
        (secret, id.starts_with("live"))
    }
}

fn now(ran: Ran) -> Stored {
    match ran {
        Ran::Now(stored) => stored,
        Ran::Later => panic!("answered at once"),
    }
}

#[test]
fn the_kernel_serves_the_read_from_its_source() {
    let s = KernelServices::new().with_credentials(Arc::new(Source));
    for (id, value) in [("live-1", SECRET_LIVE), ("gone", SECRET_NOT_LIVE)] {
        let read = now(s.records_secret("a-kind", id, Box::new(|_| {})));
        let span = read.spans[0];
        let bytes = &read.bytes[span.value.offset as usize..][..span.value.len as usize];
        assert_eq!(
            (bytes, read.value),
            (format!("a-kind:{id}").as_bytes(), value)
        );
    }
    assert_eq!(
        now(KernelServices::new().records_secret("a-kind", "live-1", Box::new(|_| {}))),
        Stored::refused(NO_CREDENTIAL_SOURCE)
    );
}

#[test]
fn a_late_source_refuses_until_its_handle_is_set() {
    let (gov, id, secret) = gov_with_key("late");
    let kind = signed_kind();
    let (credentials, late) = AppCredentials::late();
    let s = KernelServices::new().with_credentials(Arc::new(credentials));
    let Ran::Now(before) = s.records_secret(&kind, &id, Box::new(|_| {})) else {
        panic!("answered at once");
    };
    assert_eq!(before, Stored::refused(NOT_READABLE), "not installed yet");
    assert!(!late.is_set());
    let handle = Arc::new(busbar_kernel::state::AppHandle::new({
        crate::dist_root_install::install();
        let module = busbar_kernel::preflight::root_rows()
            .stores
            .first()
            .expect("the distribution links its actual store")
            .0;
        let settings: serde_json::Value = serde_json::from_str(
            &std::env::var("BUSBAR_GOVERNANCE_TEST_STORE_SETTINGS").unwrap_or_else(|_| "{}".into()),
        )
        .unwrap();
        let deploy = busbar_kernel::config::deploy_from_deserializer(serde_json::json!({
            "providers": {}, "models": {}, "auth": {"chain": [], "admin_auth": []},
            "store": {"module": module, "settings": settings},
            "advanced": {"allow_destinations": ["127.0.0.1"]}
        }))
        .unwrap();
        let config = busbar_kernel::config::resolve(&deploy, &Default::default()).unwrap();
        let rules = Arc::new(crate::root::door_steps::Rules::default())
            as Arc<dyn busbar_kernel::appbuild::RootRules>;
        let (mut app, rotate, limits) = busbar_kernel::build_app_from_config(
            config,
            Default::default(),
            None,
            Default::default(),
            Default::default(),
            (None, None),
            None,
            &rules,
        )
        .expect("the production root builds the credential generation");
        limits.stage_boot();
        crate::root::kernel::ROOT_CARD.keep_in_store(
            app.governance
                .as_ref()
                .expect("the actual deployment configured governance")
                .store_calls()
                .expect("the actual configured Store exposes its rate-history slots"),
            123,
        );
        crate::root::kernel::ROOT_CARD
            .boot_in_store(None)
            .expect("the actual configured Store boots its rate history");
        limits.keep().unwrap();
        if let Some(rotate) = rotate {
            rotate();
        }
        app.governance = Some(gov);
        Arc::new(app)
    }));
    late.set(Arc::clone(&handle));
    assert!(late.is_set());
    let Ran::Now(after) = s.records_secret(&kind, &id, Box::new(|_| {})) else {
        panic!("answered at once");
    };
    let span = after.spans[0];
    let bytes = &after.bytes[span.value.offset as usize..][..span.value.len as usize];
    assert_eq!((bytes, after.value), (secret.as_bytes(), SECRET_LIVE));
    let owner = Arc::downgrade(&handle);
    drop(handle);
    assert!(
        owner.upgrade().is_none(),
        "the credential source cannot keep its owner alive"
    );
    assert!(!late.is_set());
    assert_eq!(
        now(s.records_secret(&kind, &id, Box::new(|_| {}))),
        Stored::refused(NOT_READABLE)
    );
}
