// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;
use crate::root::loader::sign::Declares;
use crate::root::loader::{LinkedPlugin, PluginRegistry};
use crate::root::test_plugins;
use busbar_contract::abi::auth::AuthPoints;
use busbar_contract::abi::mechanism::door::Statement;
use busbar_contract::abi::mechanism::extensions::EXT_DECLARES;
use busbar_contract::abi::mechanism::kind;
use busbar_contract::abi::sdk::auth_door::{verify_tail, with_tail, VerifyPlugin};
use busbar_contract::abi::sdk::door::statement;
use busbar_contract::abi::sdk::hook::{Hook, HookOpen};
use busbar_contract::abi::sdk::life::Refusal;

const AUTH_JSON: &[u8] = br#"{"diagnostics":[{"code":4998,"slug":"fixture-auth-declared","title":"Auth fixture","severity":"actionable","summary":"Auth fixture declaration.","action":"Inspect the auth fixture.","since":"1.6.0"}]}"#;
const HOOK_JSON: &[u8] = br#"{"diagnostics":[{"code":6998,"slug":"fixture-hook-declared","title":"Hook fixture","severity":"actionable","summary":"Hook fixture declaration.","action":"Inspect the hook fixture.","since":"1.6.0"}]}"#;
const AUTH_CODE: u16 = 4998;
const HOOK_CODE: u16 = 6998;
const AUTH_NAME: &str = "catalogue-auth";
const HOOK_NAME: &str = "catalogue-hook";
const FIXTURE_VERSION: &str = "1.0.0";
const FIXTURE_MAX_INFLIGHT: u32 = 1;
const RELEASE_KEY_BYTE: u8 = 7;
const THIRD_PARTY_KEY_BYTE: u8 = 8;
const THIRD_PARTY_PUBLISHER: &str = "catalogue-third-party";

mod auth {
    use super::*;

    pub(super) struct Disabled;
    impl VerifyPlugin for Disabled {
        fn open_refusing(_: &[u8], _: &[&[u8]]) -> Result<Self, Refusal> {
            panic!("cataloguing a disabled auth row must never open it")
        }
    }

    busbar_contract::statement_extensions!(
        pub EXTENSIONS: [(EXT_DECLARES, AUTH_JSON)]
    );
    pub(super) const TAIL: &busbar_contract::abi::auth::AuthTail =
        &verify_tail(0, AuthPoints::HEAD);
    busbar_contract::auth_verify_door!(
        Disabled,
        with_tail(
            Statement {
                extensions: EXTENSIONS,
                ..statement(AUTH_NAME, FIXTURE_VERSION, FIXTURE_MAX_INFLIGHT)
            },
            TAIL
        )
    );
}

mod hook {
    use super::*;

    struct Disabled;
    impl HookOpen for Disabled {
        fn open(_: &str) -> Result<Box<dyn Hook>, String> {
            panic!("cataloguing a disabled hook row must never open it")
        }
    }
    busbar_contract::statement_extensions!(
        pub EXTENSIONS: [(EXT_DECLARES, HOOK_JSON)]
    );
    busbar_contract::hook_door!(
        open: Disabled,
        statement: Statement {
            extensions: EXTENSIONS,
            ..statement(HOOK_NAME, FIXTURE_VERSION, FIXTURE_MAX_INFLIGHT)
        }
    );
}

fn dropped(tag: &str, third_party: bool) -> PluginRegistry {
    let release = test_plugins::key(RELEASE_KEY_BYTE);
    let third = test_plugins::key(THIRD_PARTY_KEY_BYTE);
    let (signer, publisher) = if third_party {
        (&third, THIRD_PARTY_PUBLISHER)
    } else {
        (&release, crate::root::loader::sign::FIRST_PARTY_PUBLISHER)
    };
    let dir = test_plugins::scratch(tag);
    for (kind, name, json, door) in [
        (
            kind::AUTH,
            AUTH_NAME,
            AUTH_JSON,
            auth::door as busbar_contract::abi::mechanism::door::DoorFn,
        ),
        (kind::HOOK, HOOK_NAME, HOOK_JSON, hook::door),
    ] {
        let mut manifest = test_plugins::manifest(kind, name, publisher);
        manifest.version = FIXTURE_VERSION.into();
        manifest.declares = Declares::from_declares_json(json).unwrap();
        manifest.statement = Some(hex::encode(
            crate::root::loader::dispatch::LinkedRow::of(door)
                .unwrap()
                .statement,
        ));
        std::fs::write(
            dir.join(format!("{kind}.tar.gz")),
            test_plugins::signed(signer, manifest, b"catalogue-only artifact"),
        )
        .unwrap();
    }
    let mut policy = test_plugins::release_policy(&release);
    if third_party {
        policy.publishers = [(publisher.to_string(), signer.verifying_key())]
            .into_iter()
            .collect();
    }
    let registry = test_plugins::boot_with(&dir, &policy);
    std::fs::remove_dir_all(dir).unwrap();
    registry
}

#[test]
fn disabled_linked_auth_and_hook_codes_are_registered_as_their_signed_dropped_declarations_are() {
    let linked = PluginRegistry::empty()
        .link(vec![
            LinkedPlugin::auth_door_named(AUTH_NAME, AUTH_NAME, auth::door),
            LinkedPlugin::door_of_kind(kind::HOOK, HOOK_NAME, hook::door),
        ])
        .unwrap();
    let declared = declared_diagnostics(&linked, &[]).unwrap();
    let catalogue = busbar_kernel::diagnostics::Catalogue::lent(declared.leak());
    let dropped_declarations =
        declared_diagnostics(&dropped("linked-auth-hook-equivalence", false), &[]).unwrap();
    for expected in dropped_declarations {
        let registered = catalogue
            .by_code(expected.code)
            .expect("the compiled-in disabled row's declared code is registered");
        assert_eq!(
            registered.banner().to_string(),
            expected.banner().to_string()
        );
        assert_eq!(registered.slug, expected.slug);
        assert_eq!(registered.title, expected.title);
        assert_eq!(registered.severity, expected.severity);
        assert_eq!(registered.summary, expected.summary);
        assert_eq!(registered.action, expected.action);
    }

    let copies = dropped("linked-auth-hook-copies", false)
        .link(vec![
            LinkedPlugin::auth_door_named(AUTH_NAME, AUTH_NAME, auth::door),
            LinkedPlugin::door_of_kind(kind::HOOK, HOOK_NAME, hook::door),
        ])
        .expect("signed copies of linked rows are admitted once");
    let declared = declared_diagnostics(&copies, &[]).unwrap();
    assert_eq!(declared.iter().filter(|d| d.code == AUTH_CODE).count(), 1);
    assert_eq!(declared.iter().filter(|d| d.code == HOOK_CODE).count(), 1);
}

mod malformed {
    use super::*;

    const MALFORMED_NAME: &str = "catalogue-malformed-auth";
    busbar_contract::statement_extensions!(
        EXTENSIONS: [(EXT_DECLARES, b"{")]
    );
    busbar_contract::auth_verify_door!(
        auth::Disabled,
        with_tail(
            Statement {
                extensions: EXTENSIONS,
                ..statement(MALFORMED_NAME, FIXTURE_VERSION, FIXTURE_MAX_INFLIGHT)
            },
            auth::TAIL
        )
    );

    #[test]
    fn a_malformed_linked_declaration_refuses_the_catalogue() {
        let registry = PluginRegistry::empty()
            .link(vec![LinkedPlugin::auth_door_named(
                MALFORMED_NAME,
                MALFORMED_NAME,
                door,
            )])
            .unwrap();
        let refused = declared_diagnostics(&registry, &[]).expect_err("malformed declares");
        assert!(refused.contains(MALFORMED_NAME), "{refused}");
        assert!(refused.contains("does not read"), "{refused}");
    }
}

#[test]
fn a_linked_code_cannot_shadow_an_installed_declaration() {
    let installed = declared_diagnostics(&dropped("linked-auth-hook-collision", false), &[])
        .expect("the signed declarations are valid");
    let linked = PluginRegistry::empty()
        .link(vec![LinkedPlugin::auth_door_named(
            AUTH_NAME,
            AUTH_NAME,
            auth::door,
        )])
        .unwrap();
    let refused = declared_diagnostics(&linked, &installed).expect_err("the code is installed");
    assert!(refused.contains(AUTH_NAME), "{refused}");
    assert!(refused.contains("already holds that code"), "{refused}");
}

#[test]
fn signed_third_party_auth_and_hook_codes_cannot_join_the_catalogue() {
    let registry = dropped("linked-auth-hook-third-party", true);
    let refused = declared_diagnostics(&registry, &[]).expect_err("third-party declarations");
    assert!(refused.contains("not first-party"), "{refused}");
}

#[test]
fn linked_auth_and_hook_declarations_need_neither_configuration_nor_an_open_instance() {
    const AUTHS: &[busbar_kernel::preflight::LinkedAuth] = &[(AUTH_NAME, AUTH_NAME, auth::door)];
    const HOOKS: &[busbar_contract::abi::mechanism::door::DoorFn] = &[hook::door];
    let linked = Linked {
        auths: AUTHS,
        hook_doors: HOOKS,
        ..crate::LINKED
    };
    let declared = linked_declared_diagnostics(&linked, &[])
        .expect("the build's auth and hook rows declare codes without configuration");
    let catalogue = busbar_kernel::diagnostics::Catalogue::lent(declared.leak());
    assert_eq!(
        catalogue.by_code(AUTH_CODE).expect("the auth code").slug,
        "fixture-auth-declared"
    );
    assert_eq!(
        catalogue.by_code(HOOK_CODE).expect("the hook code").slug,
        "fixture-hook-declared"
    );
}
