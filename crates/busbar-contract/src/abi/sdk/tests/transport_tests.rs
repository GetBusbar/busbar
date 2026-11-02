// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The transport SDK's shared pieces through a real door: a role stub is REFUSED naming its op and

use super::*;
use crate::abi::mechanism::call::{InHead, OutHead, Outcome};
use crate::abi::mechanism::lifecycle::{slot as life, OpenIn, OpenOut};
use crate::abi::sdk::door::statement;
use crate::abi::sdk::life::Refreshed;
use crate::abi::sdk::test_support::zeroed;
use crate::abi::sdk::{Lent, Out, Safe, SafeSlot};
use crate::abi::transport::{slot, ConnIn, Ops, ShutIn};

/// The probe's one setting.
const BODY: [SettingRow; 1] = [SettingRow {
    path: "limits.request_body_max_bytes",
    kind: SETTING_COUNT,
    default: DEFAULT_BODY_MAX,
}];

/// The probe carrier: it holds nothing and reads one setting. `pub`: the stubs `not_served!`
pub struct Probe;

impl Life for Probe {
    const CANCEL: u32 = 0;

    fn validate(settings: &[u8]) -> Result<(), Refusal> {
        settings_reading(settings, &BODY).map(|_| ())
    }

    fn open(settings: &[u8], _: &[&[u8]], _: u64) -> Result<Self, Refusal> {
        Self::validate(settings).map(|()| Probe)
    }

    fn refresh(&self, _: &[u8], _: &[&[u8]], _: u64) -> Result<Refreshed, Refusal> {
        Ok(Refreshed::default())
    }
}

/// `flush`: READY over the instance's armed I/O, refused without it.
struct Flush;

impl SafeSlot for Flush {
    type In = ConnIn;
    type Out = OutHead;
    type State = Held<Probe>;
    fn call(
        i: Instance<'_, Held<Probe>>,
        _: Lent<'_, ConnIn>,
        mut out: Out<'_, OutHead>,
    ) -> Outcome {
        match crate::carried!(i, "flush") {
            Ok(_) => Outcome::Ready,
            Err(r) => out.fail(r),
        }
    }
}

crate::not_served! {
    state: Held<Probe>, role: "probe carrier";
    /// `shut`: not served, for the test.
    NoShut(ShutIn => OutHead) "shut";
}

mod plugin {
    crate::plugin_door! {
        ops: super::Ops,
        statement: super::statement("probe-transport", "0.0.1", 4),
        lifecycle: life(super::Probe),
        kind_ops: { flush: super::Safe<super::Flush>, shut: super::Safe<super::NoShut> },
    }
}

fn out() -> OutHead {
    let mut h: OutHead = zeroed();
    h.size = std::mem::size_of::<OutHead>() as u32;
    h
}

/// Through the door: the stub is REFUSED in the role's words, and a carrier op on an instance the
#[test]
fn a_role_stub_and_a_carrier_op_without_io_answer_in_words() {
    // SAFETY: this is the complete transport table exported by the actual SDK-generated door.
    let table = unsafe { &*plugin::door().ops().cast::<Ops>() };
    let mut input: OpenIn = zeroed();
    input.head.size = std::mem::size_of::<OpenIn>() as u32;
    input.head.op = life::OPEN;
    let mut opened: OpenOut = zeroed();
    opened.head.size = std::mem::size_of::<OpenOut>() as u32;
    // SAFETY: exact initialized OPEN frames; this synchronous call creates the sole instance.
    assert_eq!(
        unsafe {
            table.head.open.unwrap()(
                std::ptr::null_mut(),
                std::ptr::from_ref(&input).cast(),
                std::ptr::from_mut(&mut opened).cast(),
            )
        }
        .outcome(),
        Outcome::Ready
    );
    assert!(!opened.instance.is_null(), "an instance");

    let mut shut: ShutIn = zeroed();
    shut.head.size = std::mem::size_of::<ShutIn>() as u32;
    shut.head.op = slot::SHUT;
    let mut output = out();
    // SAFETY: this table's live instance and complete SHUT/OutHead frames, all live for the call.
    assert_eq!(
        unsafe {
            table.shut.unwrap()(
                opened.instance,
                std::ptr::from_ref(&shut).cast(),
                std::ptr::from_mut(&mut output).cast(),
            )
        }
        .outcome(),
        Outcome::Refused
    );
    // SAFETY: the actual SDK answer lends its initialized diagnostic bytes until next crossing.
    let error = unsafe { std::slice::from_raw_parts(output.error.ptr, output.error.len) };
    assert_eq!(
        std::str::from_utf8(error).unwrap(),
        "shut: the probe carrier does not serve this op"
    );

    let mut flush: ConnIn = zeroed();
    flush.head.size = std::mem::size_of::<ConnIn>() as u32;
    flush.head.op = slot::FLUSH;
    let mut output = out();
    // SAFETY: exact FLUSH frames on the still-live instance; no host I/O was installed at OPEN.
    assert_eq!(
        unsafe {
            table.flush.unwrap()(
                opened.instance,
                std::ptr::from_ref(&flush).cast(),
                std::ptr::from_mut(&mut output).cast(),
            )
        }
        .outcome(),
        Outcome::Failed
    );
    // SAFETY: initialized diagnostic bytes lent by this actual SDK answer.
    let error = unsafe { std::slice::from_raw_parts(output.error.ptr, output.error.len) };
    assert_eq!(
        std::str::from_utf8(error).unwrap(),
        "flush: the host lent this carrier no I/O"
    );

    let mut close: InHead = zeroed();
    close.size = std::mem::size_of::<InHead>() as u32;
    close.op = life::CLOSE;
    // SAFETY: consume the sole instance created by this table's OPEN, once.
    assert_eq!(
        unsafe {
            table.head.close.unwrap()(
                opened.instance,
                std::ptr::from_ref(&close).cast(),
                std::ptr::from_mut(&mut out()).cast(),
            )
        }
        .outcome(),
        Outcome::Ready
    );
}

/// A carrier op on no open instance is FAILED saying so: the words reach the caller although the
#[test]
fn a_carrier_op_on_no_instance_answers_in_words() {
    // SAFETY: the actual macro door exports this complete transport Ops table.
    let table = unsafe { &*plugin::door().ops().cast::<Ops>() };
    let flush = table.flush.expect("flush");
    let mut input: ConnIn = zeroed();
    input.head.size = std::mem::size_of::<ConnIn>() as u32;
    input.head.op = slot::FLUSH;
    let mut o = out();
    // SAFETY: the SDK FLUSH accepts NULL instance to report failure; the initialized input/output frames stay live.
    let raw = unsafe {
        flush(
            std::ptr::null_mut(),
            std::ptr::from_ref(&input).cast(),
            std::ptr::from_mut(&mut o).cast(),
        )
    };
    assert_eq!(raw.outcome(), Outcome::Failed);
    assert!(!o.error.ptr.is_null(), "the words reach the caller");
    // SAFETY: a non-null `error` names `len` bytes the door lent for the call's answer.
    let words = unsafe { std::slice::from_raw_parts(o.error.ptr, o.error.len) };
    assert_eq!(String::from_utf8_lossy(words), "flush: no open instance");
}

/// A transport's settings: empty or an object of keys it reads; any other key refused naming it,
#[test]
fn a_key_a_transport_does_not_read_is_refused_naming_it() {
    let reads = BODY;
    assert!(settings_reading(b"", &reads).expect("empty").is_empty());
    let object = settings_reading(br#"{"limits.request_body_max_bytes":5}"#, &reads).expect("read");
    assert_eq!(object["limits.request_body_max_bytes"], 5);
    let refused = |bytes: &[u8], reads: &[SettingRow]| {
        let r = settings_reading(bytes, reads).expect_err("refused");
        assert_eq!(r.outcome(), Outcome::Failed);
        r.text().expect("words").to_string()
    };
    assert_eq!(
        refused(br#"{"port":1}"#, &[]),
        "settings: port is not a setting this transport reads"
    );
    assert_eq!(
        refused(br#"{"limits.request_body_max_bytes":5,"z":1}"#, &reads),
        "settings: z is not a setting this transport reads"
    );
    assert_eq!(refused(b"[]", &reads), "settings: must be a JSON object");
}

/// A value its setting's declared kind refuses is refused naming the key: a count that is zero or
#[test]
fn a_value_its_declared_kind_refuses_is_refused_naming_it() {
    let row = |path, kind| SettingRow {
        path,
        kind,
        default: "",
    };
    let reads = [BODY[0], row("h2", SETTING_FLAG), row("name", SETTING_TEXT)];
    let count = "settings: limits.request_body_max_bytes must be a count above 0";
    for (bytes, words) in [
        (r#"{"limits.request_body_max_bytes":0}"#, count),
        (r#"{"limits.request_body_max_bytes":"5"}"#, count),
        (r#"{"limits.request_body_max_bytes":-1}"#, count),
        (r#"{"h2":"yes"}"#, "settings: h2 must be true or false"),
        (r#"{"name":5}"#, "settings: name must be text"),
    ] {
        let r = settings_reading(bytes.as_bytes(), &reads).expect_err(bytes);
        assert_eq!(r.outcome(), Outcome::Failed, "{bytes}");
        assert_eq!(r.text(), Some(words), "{bytes}");
    }
    let object = settings_reading(
        br#"{"limits.request_body_max_bytes":5,"h2":true,"name":"x"}"#,
        &reads,
    )
    .expect("every value its kind");
    assert_eq!(object.len(), 3);
}

/// The rows render the Statement's declarations: each path, kind and default as stated.
#[test]
fn the_rows_render_the_declarations() {
    let [decl] = setting_decls(&BODY);
    assert_eq!(decl.kind, SETTING_COUNT);
    // SAFETY: `decl` names `BODY`'s `'static` strings.
    let (path, default) = unsafe {
        (
            std::slice::from_raw_parts(decl.path.ptr(), decl.path.len()),
            std::slice::from_raw_parts(decl.default.ptr(), decl.default.len()),
        )
    };
    assert_eq!(path, b"limits.request_body_max_bytes");
    assert_eq!(default, DEFAULT_BODY_MAX.as_bytes());
}

/// The declared default is the host's bound, in decimal.
#[test]
fn the_declared_body_bound_is_the_hosts() {
    assert_eq!(
        DEFAULT_BODY_MAX,
        crate::transport::DEFAULT_REQUEST_BODY_MAX_BYTES.to_string()
    );
}
