// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The transport SDK's shared pieces through a real door: a role stub is REFUSED naming its op and
//! the role, a carrier op with no host I/O is FAILED saying so, a settings key a transport does not
//! read is refused naming it, and the declared body bound is the host's.

use super::*;
use crate::abi::mechanism::call::{InHead, OutHead, Outcome};
use crate::abi::mechanism::lifecycle::{slot as life, OpenIn, OpenOut};
use crate::abi::sdk::door::statement;
use crate::abi::sdk::life::Refreshed;
use crate::abi::sdk::test_support::reply;
use crate::abi::sdk::test_support::test_in::TestIn;
use crate::abi::sdk::test_support::{zeroed, DoorView};
use crate::abi::sdk::{Lent, Out, Safe, SafeSlot};
use crate::abi::transport::{slot, ConnIn, Ops, ShutIn};

/// The probe's one setting.
const BODY: [SettingRow; 1] = [SettingRow {
    path: "limits.request_body_max_bytes",
    kind: SETTING_COUNT,
    default: DEFAULT_BODY_MAX,
}];

/// The probe carrier: it holds nothing and reads one setting. `pub`: the stubs `not_served!`
/// states are `pub`, as a transport's are, so their state is too.
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
        match carried(&i, "flush") {
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
/// host lent no I/O is FAILED saying so.
#[test]
fn a_role_stub_and_a_carrier_op_without_io_answer_in_words() {
    let view = DoorView::of(plugin::MACRO_DOOR);
    let open = view.op::<Ops>(|t| &t.head.open).expect("open");
    let mut opened = reply::call_in(
        open,
        None,
        &TestIn::<OpenIn>::new().set(|i| &i.head.op, life::OPEN),
        zeroed::<OpenOut>(),
    );
    assert_eq!(opened.outcome, Outcome::Ready);
    let instance = opened.take_instance().expect("an instance");

    let shut = view.op::<Ops>(|t| &t.shut).expect("shut");
    let c = reply::call_in(
        shut,
        Some(&instance),
        &TestIn::<ShutIn>::new().set(|i| &i.head.op, slot::SHUT),
        out(),
    );
    assert_eq!(c.outcome, Outcome::Refused);
    assert_eq!(
        c.error.as_deref(),
        Some("shut: the probe carrier does not serve this op")
    );

    let flush = view.op::<Ops>(|t| &t.flush).expect("flush");
    let c = reply::call_in(
        flush,
        Some(&instance),
        &TestIn::<ConnIn>::new().set(|i| &i.head.op, slot::FLUSH),
        out(),
    );
    assert_eq!(c.outcome, Outcome::Failed);
    assert_eq!(
        c.error.as_deref(),
        Some("flush: the host lent this carrier no I/O")
    );

    let close = view.op::<Ops>(|t| &t.head.close).expect("close");
    let c = reply::close_in(
        close,
        instance,
        &TestIn::<InHead>::new().set(|i| &i.op, life::CLOSE),
        out(),
    );
    assert_eq!(c.outcome, Outcome::Ready);
}

/// A transport's settings: empty or an object of keys it reads; any other key refused naming it,
/// and bytes that are not an object refused as the SDK's object rule says.
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
/// not a count, a flag that is not `true`/`false`, text that is not a string.
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
