// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The secret kind's shared source pieces through a real door: a source built from them refuses

use super::*;
use crate::abi::mechanism::call::{Outcome, BLOB_JSON};
use crate::abi::mechanism::lifecycle::{slot, OpenIn, OpenOut};
use crate::abi::sdk::door::statement;
use crate::abi::sdk::life::{Held, Life, Refreshed};
use crate::abi::sdk::test_support::zeroed;
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
#[test]
fn a_failed_resolve_answers_its_code_and_text_through_the_door() {
    // SAFETY: the actual SDK-generated secret door declares this full Ops table.
    let table = unsafe { &*plugin::door().ops().cast::<Ops>() };
    let open_with = |settings: &[u8]| {
        let mut input: OpenIn = zeroed();
        input.head.size = std::mem::size_of::<OpenIn>() as u32;
        input.head.op = slot::OPEN;
        input.settings = crate::abi::mechanism::call::Blob {
            ptr: settings.as_ptr(),
            len: settings.len(),
            fmt: BLOB_JSON,
            flags: 0,
        };
        let mut output: OpenOut = zeroed();
        output.head.size = std::mem::size_of::<OpenOut>() as u32;
        // SAFETY: exact initialized frames and settings owned by this synchronous call.
        let outcome = unsafe {
            table.head.open.unwrap()(
                std::ptr::null_mut(),
                std::ptr::from_ref(&input).cast(),
                std::ptr::from_mut(&mut output).cast(),
            )
        }
        .outcome();
        (outcome, output)
    };
    let (outcome, _) = open_with(br#"{"key":"X"}"#);
    assert_eq!(outcome, Outcome::Failed);
    let (outcome, opened) = open_with(b"");
    assert_eq!(outcome, Outcome::Ready);
    let instance = opened.instance;
    assert!(!instance.is_null(), "an instance");

    struct Resolved {
        outcome: Outcome,
        out: ResolveOut,
        error: Option<String>,
        owned: zeroize::Zeroizing<Vec<u8>>,
    }
    let resolve_with = |settings: &[u8]| {
        let mut secret = [0u8; 64];
        let mut input: ResolveIn = zeroed();
        input.head.size = std::mem::size_of::<ResolveIn>() as u32;
        input.head.op = crate::abi::secret::slot::RESOLVE;
        input.settings = crate::abi::mechanism::call::Blob {
            ptr: settings.as_ptr(),
            len: settings.len(),
            fmt: BLOB_JSON,
            flags: 0,
        };
        input.secret_buf = secret.as_mut_ptr();
        input.secret_cap = secret.len();
        let mut output: ResolveOut = zeroed();
        output.head.size = std::mem::size_of::<ResolveOut>() as u32;
        // SAFETY: this door's live instance and exact initialized frames, with exclusive host
        // output storage held here until its answer has been checked and copied.
        let outcome = unsafe {
            table.resolve.unwrap()(
                instance,
                std::ptr::from_ref(&input).cast(),
                std::ptr::from_mut(&mut output).cast(),
            )
        }
        .outcome();
        crate::abi::secret::validate::check_resolve(
            &output,
            secret.as_ptr() as usize,
            secret.len() as u64,
        )
        .expect("the actual SDK answer obeys the secret buffer contract");
        let error = if output.head.error.len == 0 {
            None
        } else {
            // SAFETY: the SDK's live answer lends exactly these initialized error bytes until release.
            Some(
                std::str::from_utf8(unsafe {
                    std::slice::from_raw_parts(output.head.error.ptr, output.head.error.len)
                })
                .unwrap()
                .to_owned(),
            )
        };
        let owned = zeroize::Zeroizing::new(secret[..output.secret.len].to_vec());
        zeroize::Zeroize::zeroize(&mut secret);
        if output.head.lease != 0 {
            let mut release: crate::abi::mechanism::lifecycle::ReleaseIn = zeroed();
            release.head.size = std::mem::size_of_val(&release) as u32;
            release.head.op = slot::RELEASE;
            release.lease = output.head.lease;
            let mut released: crate::abi::mechanism::call::OutHead = zeroed();
            released.size = std::mem::size_of_val(&released) as u32;
            // SAFETY: return only this answer's actual lease to its original live instance.
            assert_eq!(
                unsafe {
                    table.head.release.unwrap()(
                        instance,
                        std::ptr::from_ref(&release).cast(),
                        std::ptr::from_mut(&mut released).cast(),
                    )
                }
                .outcome(),
                Outcome::Ready
            );
        }
        Resolved {
            outcome,
            out: output,
            error,
            owned,
        }
    };
    let c = resolve_with(b"{}");
    assert_eq!(c.outcome, Outcome::Failed);
    assert_eq!(c.out.error_kind, ERROR_KIND_NOT_FOUND);
    assert_eq!(c.error.as_deref(), Some("probe: no key"));
    assert!(c.owned.as_slice().is_empty());

    let c = resolve_with(b"[1]");
    assert_eq!(c.outcome, Outcome::Failed);
    assert_eq!(c.out.error_kind, ERROR_KIND_INVALID);

    let c = resolve_with(br#"{"key":"value"}"#);
    assert_eq!(c.outcome, Outcome::Ready);
    assert_eq!(c.out.error_kind, ERROR_KIND_UNSET);
    assert_eq!(c.owned.as_slice(), b"value");

    let c = resolve_with(br#"{"key":""}"#);
    assert_eq!(c.outcome, Outcome::Failed);
    assert_eq!(c.out.error_kind, ERROR_KIND_INVALID);
    assert_eq!(c.error.as_deref(), Some(crate::abi::sdk::cred::EMPTY_VALUE));
    assert!(c.owned.as_slice().is_empty());

    let big = format!(
        r#"{{"key":"{}"}}"#,
        "x".repeat(crate::abi::secret::MAX_SECRET_BYTES + 1)
    );
    let c = resolve_with(big.as_bytes());
    assert_eq!(c.outcome, Outcome::Failed);
    assert_eq!(c.out.error_kind, ERROR_KIND_INVALID);
    assert_eq!(c.out.needed, 0);
    assert!(c.error.as_deref().is_some_and(|e| e.contains("over the")));
    let mut close: crate::abi::mechanism::call::InHead = zeroed();
    close.size = std::mem::size_of_val(&close) as u32;
    close.op = slot::CLOSE;
    let mut closed: crate::abi::mechanism::call::OutHead = zeroed();
    closed.size = std::mem::size_of_val(&closed) as u32;
    // SAFETY: consume the one instance created by this test's successful OPEN, once.
    assert_eq!(
        unsafe {
            table.head.close.unwrap()(
                instance,
                std::ptr::from_ref(&close).cast(),
                std::ptr::from_mut(&mut closed).cast(),
            )
        }
        .outcome(),
        Outcome::Ready
    );
}
