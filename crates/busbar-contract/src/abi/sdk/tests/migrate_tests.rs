// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The `migrate` slot over a plugin's own [`Migrate`]: what the host lends in, what it reads back.

use super::*;
use crate::abi::mechanism::call::{Blob, BLOB_JSON, BLOB_OCTETS};
use crate::abi::mechanism::lifecycle::slot;

/// A stub plugin's migration: renames `signing-secret` to `signing_secret`, and asks core to allow
/// the private host its `url` names.
struct Stub;
impl Migrate for Stub {
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
    let outcome = Migrator::<Stub>::call(std::ptr::null_mut(), &input, &mut out);
    let named = if out.error.ptr.is_null() {
        Vec::new()
    } else {
        assert_eq!(
            out.error.ptr,
            buf.as_ptr().cast_const(),
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
        m.settings,
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
    assert_eq!(m, Migrated::unchanged(serde_json::Value::Null));
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
    use crate::abi::mechanism::call::Outcome;
    use crate::abi::sdk::life::{Held, Life, Refreshed, Refusal};
    use crate::abi::sdk::{Instance, Lent, Out, SafeSlot};
    use crate::abi::secret::{ResolveIn, ResolveOut};

    pub struct L;
    impl Life for L {
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
/// through the door with no instance and no ticket, and reads the answer; a door that names none
/// states none.
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
    let mut out = OutHead::default();
    out.size = size_of::<OutHead>() as u32;
    let raw = op(
        std::ptr::null_mut(),
        std::ptr::from_ref(&input).cast(),
        std::ptr::from_mut(&mut out).cast(),
    );
    assert_eq!(raw.outcome(), Outcome::Ready);
    let m = read_answer(raw.outcome(), &buf[..out.error.len]).expect("a migration");
    assert_eq!(m.settings, serde_json::json!({"signing_secret": "x"}));
    assert_eq!(
        m.report,
        vec!["signing-secret -> signing_secret (renamed after 1.5.5)"]
    );
}
