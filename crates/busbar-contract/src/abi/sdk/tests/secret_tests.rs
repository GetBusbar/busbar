// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The secret kind's shared source pieces through a real door: a source built from them refuses
//! instance settings in the sources' words, reads a reference's settings as an object, and answers
//! a failed resolve FAILED with the error's code and text.

use super::*;
use crate::abi::mechanism::call::{Outcome, BLOB_JSON};
use crate::abi::mechanism::lifecycle::{slot, OpenIn, OpenOut};
use crate::abi::sdk::door::statement;
use crate::abi::sdk::life::{Held, Life, Refreshed};
use crate::abi::sdk::test_support::reply;
use crate::abi::sdk::test_support::test_in::TestIn;
use crate::abi::sdk::test_support::{zeroed, DoorView};
use crate::abi::sdk::{Instance, Lent, Safe, SafeSlot};
use crate::abi::secret::{Ops, ResolveIn, ERROR_KIND_UNSET};

/// Where the probe's references name their value.
const NAMES: &str = "variable in its own settings.key";

/// The probe source: it holds nothing and takes no instance settings.
struct Probe;

impl Life for Probe {
    const CANCEL: u32 = 0;

    fn validate(settings: &[u8]) -> Result<(), Refusal> {
        takes_no_settings(settings, "probe", NAMES).map_err(Refusal::failed)
    }

    fn open(settings: &[u8], _: &[&[u8]], _: u64) -> Result<Self, Refusal> {
        Self::validate(settings).map(|()| Probe)
    }

    fn refresh(&self, _: &[u8], _: &[&[u8]], _: u64) -> Result<Refreshed, Refusal> {
        Ok(Refreshed::default())
    }
}

/// `resolve`: `{key: K}` resolves to K's bytes; a missing key is NOT FOUND.
struct Resolve;

impl SafeSlot for Resolve {
    type In = ResolveIn;
    type Out = ResolveOut;
    type State = Held<Probe>;
    fn call(
        instance: Instance<'_, Held<Probe>>,
        input: Lent<'_, ResolveIn>,
        mut out: Out<'_, ResolveOut>,
    ) -> Outcome {
        if instance.get().is_none() {
            return Outcome::Refused;
        }
        let answered = settings_of(input.field(|i| &i.settings).bytes()).and_then(|s| {
            s.get("key")
                .and_then(|v| v.as_str())
                .map(|k| k.as_bytes().to_vec())
                .ok_or_else(|| SecretModuleError::not_found("probe: no key"))
        });
        match answered {
            // Into the host's buffer, never leased (the credential chip, row 6).
            Ok(material) => crate::abi::sdk::cred::resolved(
                input,
                &mut out,
                crate::abi::sdk::cred::Held::new(material),
            ),
            Err(e) => failed(&mut out, e),
        }
    }
}

mod plugin {
    crate::plugin_door! {
        ops: super::Ops,
        statement: super::statement("probe-secret", "0.0.1", 4),
        lifecycle: life(super::Probe),
        kind_ops: { resolve: super::Safe<super::Resolve> },
    }
}

/// Each kind to its ABI code.
#[test]
fn every_error_kind_has_its_abi_code() {
    for (kind, code) in [
        (SecretErrorKind::NotFound, ERROR_KIND_NOT_FOUND),
        (SecretErrorKind::Unavailable, ERROR_KIND_UNAVAILABLE),
        (SecretErrorKind::Denied, ERROR_KIND_DENIED),
        (SecretErrorKind::Invalid, ERROR_KIND_INVALID),
        (SecretErrorKind::Internal, ERROR_KIND_INTERNAL),
    ] {
        assert_eq!(error_kind(kind), code);
    }
}

/// A reference's settings: empty is none, an object is read, anything else is INVALID in words.
#[test]
fn a_references_settings_are_an_object() {
    assert!(settings_of(b"").expect("empty").is_empty());
    assert_eq!(
        settings_of(br#"{"key":"A"}"#).expect("an object")["key"],
        serde_json::json!("A")
    );
    for bytes in [&b"[1]"[..], b"7", b"{"] {
        let e = settings_of(bytes).expect_err("not an object");
        assert_eq!(e.kind, SecretErrorKind::Invalid);
        assert!(
            e.message
                .starts_with("secret settings are not a JSON object: "),
            "{}",
            e.message
        );
    }
}

/// A source that takes no settings opens on empty bytes or `{}`, and refuses a setting naming it,
/// or bytes that are not an object, in the sources' words.
#[test]
fn a_source_that_takes_no_settings_refuses_one_naming_it() {
    assert_eq!(takes_no_settings(b"", "env", NAMES), Ok(()));
    assert_eq!(takes_no_settings(b"{}", "env", NAMES), Ok(()));
    assert_eq!(
        takes_no_settings(br#"{"key":"X"}"#, "env", NAMES),
        Err(
            "secret module 'env' takes no settings; remove settings.key (each reference names \
             its variable in its own settings.key)"
                .to_string()
        )
    );
    assert_eq!(
        takes_no_settings(b"[]", "env", NAMES),
        Err("settings: must be a JSON object".to_string())
    );
}

/// Through the door: instance settings refused FAILED in the words above; a resolve that fails is
/// FAILED with its code and text and no material; one that succeeds is READY with it.
#[test]
fn a_failed_resolve_answers_its_code_and_text_through_the_door() {
    let view = DoorView::of(plugin::MACRO_DOOR);
    let open = view.op::<Ops>(|t| &t.head.open).expect("open");
    let resolve = view.op::<Ops>(|t| &t.resolve).expect("resolve");
    let open_with = |settings: &'static [u8]| {
        reply::call_in(
            open,
            None,
            &TestIn::<OpenIn>::new()
                .set(|i| &i.head.op, slot::OPEN)
                .settings(settings),
            zeroed::<OpenOut>(),
        )
    };

    let c = open_with(br#"{"key":"X"}"#);
    assert_eq!(c.outcome, Outcome::Failed);
    let mut c = open_with(b"");
    assert_eq!(c.outcome, Outcome::Ready);
    let instance = c.take_instance().expect("an instance");

    // The host lends the buffer a READY value is written into (row 6); the reply copies it out.
    let resolve_with = |settings: &'static [u8]| {
        let mut secret = [0u8; 64];
        reply::call_in(
            resolve,
            Some(&instance),
            &TestIn::<ResolveIn>::new()
                .set(|i| &i.head.op, crate::abi::secret::slot::RESOLVE)
                .blob(|i| &i.settings, settings, BLOB_JSON)
                .buffer(|i| &i.secret_buf, |i| &i.secret_cap, &mut secret),
            zeroed::<ResolveOut>(),
        )
    };
    let c = resolve_with(b"{}");
    assert_eq!(c.outcome, Outcome::Failed);
    assert_eq!(c.out.error_kind, ERROR_KIND_NOT_FOUND);
    assert_eq!(c.error.as_deref(), Some("probe: no key"));
    assert!(c.owned.material().is_empty());

    let c = resolve_with(b"[1]");
    assert_eq!(c.outcome, Outcome::Failed);
    assert_eq!(c.out.error_kind, ERROR_KIND_INVALID);

    let c = resolve_with(br#"{"key":"value"}"#);
    assert_eq!(c.outcome, Outcome::Ready);
    assert_eq!(c.out.error_kind, ERROR_KIND_UNSET);
    assert_eq!(c.owned.material(), b"value");

    // A value that resolved to nothing is FAILED, INVALID, in words (S3): never READY empty.
    let c = resolve_with(br#"{"key":""}"#);
    assert_eq!(c.outcome, Outcome::Failed);
    assert_eq!(c.out.error_kind, ERROR_KIND_INVALID);
    assert_eq!(c.error.as_deref(), Some(crate::abi::sdk::cred::EMPTY_VALUE));
    assert!(c.owned.material().is_empty());
}
