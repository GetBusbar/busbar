// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The `migrate` slot over a plugin's own [`Migrate`]: what the host lends in, what it reads back.

use super::*;
use crate::abi::mechanism::call::{Blob, BLOB_JSON, BLOB_OCTETS};
use crate::abi::mechanism::lifecycle::slot;

/// A stub plugin's migration: renames `signing-secret` to `signing_secret`, and asks core to allow
struct Stub;
impl Migrate for Stub {
    type Kind = FixtureKind;
    fn migrate(mut settings: serde_json::Value, from: &str) -> Migrated {
        let mut report = Vec::new();
        let mut needs = Vec::new();
        if let Some(m) = settings.as_object_mut() {
            if let Some(v) = m.remove("signing-secret") {
                m.insert("signing_secret".into(), v);
                report.push(format!(
                    "signing-secret -> signing_secret (renamed after {from})"
                ));
            }
            if let Some(host) = m.get("url").and_then(|u| u.as_str()) {
                needs.push(MigrateNeed::AllowDestination(host.to_string()));
            }
        }
        Migrated {
            settings,
            report,
            needs,
        }
    }
}

fn call(settings: &[u8], from: &'static [u8], buf: &mut [u8]) -> (Outcome, Vec<u8>) {
    let mut input = ValidateIn::default();
    input.head.op = slot::MIGRATE;
    input.head.extensions = Blob {
        ptr: from.as_ptr(),
        len: from.len(),
        fmt: BLOB_OCTETS,
        flags: 0,
    };
    input.settings = Blob {
        ptr: settings.as_ptr(),
        len: settings.len(),
        fmt: BLOB_JSON,
        flags: 0,
    };
    input.err_buf = buf.as_mut_ptr();
    input.err_cap = buf.len();
    let mut out = OutHead::default();
    // SAFETY: no instance (`migrate` reads none), and `input`'s buffers are this test's own, live
    // for the call.
    let outcome = unsafe { Migrator::<Stub>::call(std::ptr::null_mut(), &input, &mut out) };
    let named = if out.error.ptr.is_null() {
        Vec::new()
    } else {
        assert_eq!(
            out.error.ptr,
            buf.as_ptr(),
            "the answer is in the host's buffer"
        );
        buf[..out.error.len].to_vec()
    };
    (outcome, named)
}

#[test]
fn the_plugins_migration_is_answered_into_the_hosts_buffer() {
    let mut buf = vec![0u8; 4096];
    let (outcome, answer) = call(
        br#"{"signing-secret": {"env": "S"}, "url": "10.0.0.7"}"#,
        b"1.5.5",
        &mut buf,
    );
    assert_eq!(outcome, Outcome::Ready);
    let m = read_answer(outcome, &answer).expect("a migration");
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(
            m.encode().unwrap().expose(&crate::plugin::TestKernelSeal)
        )
        .unwrap(),
        serde_json::json!({"signing_secret": {"env": "S"}, "url": "10.0.0.7"})
    );
    assert_eq!(
        m.report,
        vec!["signing-secret -> signing_secret (renamed after 1.5.5)"]
    );
    assert_eq!(
        m.needs,
        vec![MigrateNeed::AllowDestination("10.0.0.7".into())]
    );
}

#[test]
fn a_section_the_plugin_has_none_of_is_null_and_comes_back_unchanged() {
    let mut buf = vec![0u8; 4096];
    let (outcome, answer) = call(b"", b"", &mut buf);
    let m = read_answer(outcome, &answer).expect("a migration");
    assert_eq!(m, Migrated::unchanged(serde_json::Value::Null).into());
}

#[test]
fn host_answer_preserves_arbitrary_json_and_redacts_debug() {
    for settings in [
        serde_json::Value::Null,
        serde_json::json!(true),
        serde_json::json!(42),
        serde_json::json!("PRIVATE-MIGRATION-CANARY"),
        serde_json::json!(["PRIVATE-MIGRATION-CANARY", null, {"nested": 1}]),
        serde_json::json!({"PRIVATE-KEY-CANARY": "PRIVATE-MIGRATION-CANARY"}),
    ] {
        let owner = Migrated::unchanged(settings.clone());
        let wire = serde_json::to_vec(&owner).unwrap();
        let held = read_answer(Outcome::Ready, &wire).unwrap();
        let encoded = held.encode().unwrap();
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(
                encoded.expose(&crate::plugin::TestKernelSeal)
            )
            .unwrap(),
            settings
        );
        assert!(!format!("{held:?}").contains("CANARY"));
        assert!(held.report.is_empty());
        assert!(held.needs.is_empty());
    }
}

#[test]
fn host_answer_preserves_exact_numbers_and_literal_number_marker_objects() {
    for original in [
        "18446744073709551616",
        "1.00000000000000001",
        "1e999",
        r#"{"$serde_json::private::Number":"123","other":true}"#,
    ] {
        let wire = format!("{{\"settings\":{original}}}");
        let held = read_answer(Outcome::Ready, wire.as_bytes()).unwrap();
        let encoded = held.encode().unwrap();
        let expected = original
            .parse::<serde_json::Number>()
            .map(|number| number.to_string())
            .unwrap_or_else(|_| original.to_owned());
        // Compare wire text too: serde_json's Value reader can itself interpret a marker
        // object as a number, masking a holder that changed the physical JSON shape.
        assert_eq!(
            std::str::from_utf8(encoded.expose(&crate::plugin::TestKernelSeal)).unwrap(),
            expected
        );
    }
}

#[cfg(feature = "test-seal")]
#[test]
fn only_kernel_authoring_borrows_the_original_migration_document() {
    let seal = crate::caps::KernelSeal::acquire_for_kernel();
    for settings in [
        serde_json::Value::Null,
        serde_json::json!(["secret", {"nested": 1}]),
    ] {
        let held: MigrationAnswer = Migrated::unchanged(settings.clone()).into();
        assert_eq!(
            serde_json::to_value(held.authoring(&seal)).unwrap(),
            settings
        );
        assert!(!format!("{:?}", held.authoring(&seal)).contains("secret"));
    }
}

#[test]
fn malformed_host_answer_does_not_echo_owner_data() {
    for wire in [
        br#"{"settings":{"token":"PRIVATE-CANARY"},"PRIVATE-UNKNOWN-CANARY":0}"#.as_slice(),
        br#"{"settings":null,"report":"PRIVATE-REPORT-CANARY"}"#.as_slice(),
        br#"{"settings":null,"needs":[{"PRIVATE-NEED-CANARY":1}]}"#.as_slice(),
    ] {
        let error = read_answer(Outcome::Ready, wire).unwrap_err();
        assert_eq!(
            error,
            "its migrate answered something that is not a migration"
        );
        assert!(!error.contains("CANARY"));
    }
}

#[test]
fn settings_that_are_not_json_are_refused_with_the_reason() {
    let mut buf = vec![0u8; 4096];
    let (outcome, answer) = call(b"{not json", b"1.5.5", &mut buf);
    assert_eq!(outcome, Outcome::Refused);
    let e = read_answer(outcome, &answer).expect_err("refused");
    assert!(e.contains("the settings are not JSON"), "{e}");
}

#[test]
fn an_answer_larger_than_the_buffer_is_refused_and_writes_nothing() {
    let mut buf = vec![0u8; 8];
    let (outcome, answer) = call(br#"{"url": "10.0.0.7"}"#, b"1.5.5", &mut buf);
    assert_eq!(outcome, Outcome::Refused);
    assert!(answer.is_empty());
    assert!(
        buf.iter().all(|b| *b == 0),
        "nothing written past what was lent"
    );
}

/// The host can explain an oversized migration without printing any of its settings. The reason
#[test]
fn an_oversized_answer_names_a_nonsecret_reason_when_it_fits() {
    let secret = "private-setting-sentinel".repeat(32);
    let settings = serde_json::to_vec(&serde_json::json!({ "secret": secret })).unwrap();
    let mut buf = vec![0xa5; 128];
    let (outcome, answer) = call(&settings, b"1.5.5", &mut buf);
    assert_eq!(outcome, Outcome::Refused);
    let reason = read_answer(outcome, &answer).expect_err("the oversized migration is refused");
    assert_eq!(reason, "migrate: the answer is larger than the host buffer");
    assert!(!reason.contains("private-setting-sentinel"));
    assert!(buf[answer.len()..].iter().all(|b| *b == 0xa5));
}

/// A reason that exactly fills the lent buffer is named in full. One byte less cannot carry it,
#[test]
fn an_overflow_reason_fits_exactly_or_writes_nothing() {
    let settings = serde_json::to_vec(&serde_json::json!({ "data": "x".repeat(512) })).unwrap();
    let reason = b"migrate: the answer is larger than the host buffer";
    for capacity in [reason.len(), reason.len() - 1] {
        let mut buf = vec![0xa5; capacity];
        let (outcome, answer) = call(&settings, b"1.5.5", &mut buf);
        assert_eq!(outcome, Outcome::Refused);
        if capacity == reason.len() {
            assert_eq!(answer, reason);
            assert_eq!(buf, reason);
        } else {
            assert!(answer.is_empty());
            assert!(buf.iter().all(|b| *b == 0xa5));
        }
    }
}

#[test]
fn the_needs_are_one_closed_vocabulary_on_the_wire() {
    let wire = serde_json::to_value(MigrateNeed::AllowDestination("db.internal".into())).unwrap();
    assert_eq!(
        wire,
        serde_json::json!({"allow_destination": "db.internal"})
    );
    assert!(
        serde_json::from_value::<MigrateNeed>(serde_json::json!({"set_anything": "x"})).is_err(),
        "a need core does not know is refused, never applied"
    );
}

/// A door that states `migrate` over [`Stub`], and the same plugin's door stating none.
mod witness {
    use super::{FixtureKind, Instance};
    use crate::abi::mechanism::call::Outcome;
    use crate::abi::sdk::life::{Held, Life, Refreshed, Refusal};
    use crate::abi::sdk::{Lent, Out, SafeSlot};
    use crate::abi::secret::{ResolveIn, ResolveOut};

    pub struct L;
    impl Life for L {
        type Kind = FixtureKind;
        const CANCEL: u32 = 0;
        fn open(_: &[u8], _: &[&[u8]], _: u64) -> Result<Self, Refusal> {
            Ok(Self)
        }
        fn refresh(&self, _: &[u8], _: &[&[u8]], _: u64) -> Result<Refreshed, Refusal> {
            Ok(Refreshed::default())
        }
    }

    pub struct Resolve;
    impl SafeSlot for Resolve {
        type Kind = FixtureKind;
        type In = ResolveIn;
        type Out = ResolveOut;
        type State = Held<L>;
        fn call(
            _: Instance<'_, Held<L>>,
            _: Lent<'_, ResolveIn>,
            _: Out<'_, ResolveOut>,
        ) -> Outcome {
            Outcome::Refused
        }
    }

    pub mod with {
        crate::plugin_door! {
            ops: crate::abi::secret::Ops,
            statement: crate::abi::sdk::door::statement("migrate-witness", "1.6.0", 1),
            lifecycle: life(super::L),
            migrate: crate::abi::sdk::migrate::Migrator<super::super::Stub>,
            kind_ops: { resolve: crate::abi::sdk::Safe<super::Resolve> },
        }
    }

    pub mod without {
        crate::plugin_door! {
            ops: crate::abi::secret::Ops,
            statement: crate::abi::sdk::door::statement("migrate-witness", "1.5.5", 1),
            lifecycle: life(super::L),
            kind_ops: { resolve: crate::abi::sdk::Safe<super::Resolve> },
        }
    }
}

/// THE DOOR STATES IT: `plugin_door!`'s `migrate:` lands on the door's tail, the host calls it
#[test]
fn a_door_states_migrate_on_its_tail_and_the_host_calls_it_with_no_instance() {
    use crate::abi::mechanism::door::Door;
    let door = witness::with::door();
    assert!(
        witness::without::door().migrate().is_none(),
        "no migrate: none"
    );
    let op = door.migrate().expect("the door states migrate");
    // SAFETY: `door` is the macro's `'static` door; its stated size covers the tail.
    let read = unsafe { Door::read_migrate(std::ptr::from_ref(door)) };
    assert!(read.is_some(), "the host reads it off the door's tail");

    let settings = br#"{"signing-secret": "x"}"#;
    let from = b"1.5.5";
    let mut buf = vec![0u8; 4096];
    let mut input = ValidateIn::default();
    input.head.size = size_of::<ValidateIn>() as u32;
    input.head.op = slot::MIGRATE;
    input.head.extensions = Blob {
        ptr: from.as_ptr(),
        len: from.len(),
        fmt: BLOB_OCTETS,
        flags: 0,
    };
    input.settings = Blob {
        ptr: settings.as_ptr(),
        len: settings.len(),
        fmt: BLOB_JSON,
        flags: 0,
    };
    input.err_buf = buf.as_mut_ptr();
    input.err_cap = buf.len();
    let mut out = OutHead {
        size: size_of::<OutHead>() as u32,
        ..OutHead::default()
    };
    // SAFETY: the stateless SDK MIGRATE accepts NULL instance; input settings/from and writable error buffer remain live.
    let raw = unsafe {
        op(
            std::ptr::null_mut(),
            std::ptr::from_ref(&input).cast(),
            std::ptr::from_mut(&mut out).cast(),
        )
    };
    assert_eq!(raw.outcome(), Outcome::Ready);
    let m = read_answer(raw.outcome(), &buf[..out.error.len]).expect("a migration");
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(
            m.encode().unwrap().expose(&crate::plugin::TestKernelSeal)
        )
        .unwrap(),
        serde_json::json!({"signing_secret": "x"})
    );
    assert_eq!(
        m.report,
        vec!["signing-secret -> signing_secret (renamed after 1.5.5)"]
    );
}

/// A host the plugin cannot judge itself (its `migrate` reads nothing but its arguments) is raised
#[test]
fn the_allow_if_private_need_is_its_own_word_on_the_wire() {
    let need = MigrateNeed::AllowDestinationIfPrivate("ollama.internal".into());
    let wire = serde_json::to_value(&need).unwrap();
    assert_eq!(
        wire,
        serde_json::json!({"allow_destination_if_private": "ollama.internal"})
    );
    assert_eq!(serde_json::from_value::<MigrateNeed>(wire).unwrap(), need);
}

#[test]
fn secret_externalization_need_contains_only_the_relative_path() {
    let need = super::MigrateNeed::ExternalizeSecret {
        path: vec!["token".into()],
    };
    let encoded = serde_json::to_value(&need).unwrap();
    assert_eq!(
        encoded,
        serde_json::json!({"externalize_secret": {"path": ["token"]}})
    );
    assert_eq!(
        serde_json::from_value::<super::MigrateNeed>(encoded).unwrap(),
        need
    );
}

type Instance<'a, T> = crate::abi::sdk::safe::Instance<'a, T, FixtureKind>;

type FixtureKind = crate::plugin::markers::SecretKind;

#[test]
fn credential_entry_is_guarded_kind_specific_and_separate_from_settings() {
    struct Auth;
    impl Migrate for Auth {
        type Kind = crate::plugin::markers::AuthKind;
        fn migrate(_: serde_json::Value, _: &str) -> Migrated {
            panic!("wrong entry")
        }
        fn migrate_credential(
            value: super::MigrationCredential<'_, Self::Kind>,
            from: &str,
        ) -> Result<super::CredentialMigration, super::CredentialRefusal> {
            assert_eq!(value.text(), "SYNTHETIC_CREDENTIAL");
            assert_eq!(from, "1.5.5");
            Ok(super::CredentialMigration::unchanged())
        }
    }
    let mut input = ValidateIn::default();
    input.settings = Blob::of(b"SYNTHETIC_CREDENTIAL")
        .with_fmt(BLOB_OCTETS)
        .with_flags(crate::abi::mechanism::call::BLOB_SECRET);
    input.head.extensions = Blob::of(b"1.5.5");
    let mut buffer = [0; 256];
    input.err_buf = buffer.as_mut_ptr();
    input.err_cap = buffer.len();
    let mut out = OutHead::default();
    // SAFETY: all lent buffers live for each complete synchronous call.
    let outcome = unsafe { Migrator::<Auth>::call(std::ptr::null_mut(), &input, &mut out) };
    assert_eq!(outcome, Outcome::Ready);
    let answer: super::CredentialMigration =
        serde_json::from_slice(&buffer[..out.error.len]).unwrap();
    assert!(answer
        .into_reference(&Default::default())
        .unwrap()
        .is_none());
    input.settings.flags = 0;
    // SAFETY: same complete frame, missing the required secret flag.
    assert_eq!(
        unsafe { Migrator::<Auth>::call(std::ptr::null_mut(), &input, &mut out) },
        Outcome::Refused
    );
    input.settings.flags = crate::abi::mechanism::call::BLOB_SECRET;
    // SAFETY: same frame; an unrelated kind must refuse before delivery.
    assert_eq!(
        unsafe { Migrator::<Stub>::call(std::ptr::null_mut(), &input, &mut out) },
        Outcome::Refused
    );
}
