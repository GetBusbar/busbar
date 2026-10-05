// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! `OutboundInstance` over a real auth door, loaded and opened through the one dispatcher: the
//! binding `open_outbound` answers, the ONE `fields` call answered on the spot and submitted on a
//! ticket (the same fields both ways), the short answer re-called once with the buffers it named, a
//! refusal, the request's facts reaching the plugin, and the auth point the call is made at with
//! the body lent only at `HeadBody`. Every answer passes the kind's own
//! validator (`check_fields`) on the way back.

use std::marker::PhantomData;
use std::sync::Arc;
use std::time::Duration;

use busbar_contract::abi::auth::{
    AuthPoint, AuthTail, FieldSpan, FieldsIn, FieldsOut, OpenOutboundIn, OpenOutboundOut,
    StyleDecl, CAP_INBOUND, CAP_OUTBOUND, FIELD_SENSITIVE, LOGIN_KIND_NONE, MODE_PASSTHROUGH,
    POINT_HEAD, POINT_HEAD_BODY,
};
use busbar_contract::abi::mechanism::call::{DeadlineClass, Outcome, Span};
use busbar_contract::abi::mechanism::door::KindTailHead;
use busbar_contract::abi::mechanism::lifecycle::{slot as life, OpenIn, OpenOut};
use busbar_contract::abi::sdk::auth_door::{Answer, Verdict, Verifier, VerifyPlugin, VerifyView};
use busbar_contract::abi::sdk::door::{abi_str, statement};
use busbar_contract::abi::sdk::lent::Lent;
use busbar_contract::abi::sdk::life::Held;
use busbar_contract::abi::sdk::safe::{Instance, SafeSlot};
use busbar_contract::abi::sdk::Out;
use busbar_contract::auth_calls::{AuthField, Fields, FieldsRequest, OutboundAuth};

use super::*;
use crate::dispatch::{
    load_linked, Adopter, Bind, Budgets, DispatchConfig, Dispatcher, EnvelopeSink, LinkedRow,
    NO_BLOB,
};

/// The style whose fields fit the host's starting buffers.
const BEARER: &str = "bearer";
/// The style whose fields do not: seventeen fields, one over `FIELDS_MAX`.
const WIDE: &str = "wide";
/// The style that signs the body: it needs the `HeadBody` point.
const SIGNED: &str = "signed";

mod plugin {
    use super::*;

    /// An outbound-only test plugin: its verdicts pass; its bindings are its style names.
    pub struct Outbound;

    impl VerifyPlugin for Outbound {
        fn open(_: &[u8], _: &[&[u8]]) -> Result<Self, &'static str> {
            Ok(Outbound)
        }
        fn verify(&self, _: &VerifyView<'_>) -> Answer {
            Verdict::Pass.into()
        }
    }

    /// The instance state the shared lifecycle serves.
    type Inst = Held<Verifier<Outbound>>;

    /// `open_outbound`: `bearer` binds handle 1, `wide` handle 2, `signed` handle 3; any other
    /// style FAILs.
    pub struct Open(PhantomData<Outbound>);
    impl SafeSlot for Open {
        type In = OpenOutboundIn;
        type Out = OpenOutboundOut;
        type State = Inst;
        fn call(
            _: Instance<'_, Inst>,
            input: Lent<'_, OpenOutboundIn>,
            mut out: Out<'_, OpenOutboundOut>,
        ) -> Outcome {
            let handle = match input.field(|i| &i.style).bytes() {
                b"bearer" => 1,
                b"wide" => 2,
                b"signed" => 3,
                _ => return Outcome::Failed,
            };
            out.set(|o| &o.handle, handle);
            Outcome::Ready
        }
    }

    /// `fields`: handle 1 answers `authorization: Bearer <method> <authority><path>` (sensitive);
    /// handle 2 answers seventeen fields, short until its buffers hold them; handle 3 answers
    /// `x-signed: <point> <body>` (the body as lent, `-` when none); a passthrough on handle 1 is
    /// REFUSED.
    pub struct Fields(PhantomData<Outbound>);
    impl SafeSlot for Fields {
        type In = FieldsIn;
        type Out = FieldsOut;
        type State = Inst;
        fn call(
            _: Instance<'_, Inst>,
            input: Lent<'_, FieldsIn>,
            mut out: Out<'_, FieldsOut>,
        ) -> Outcome {
            let i: &FieldsIn = &input;
            let fields: Vec<(Vec<u8>, Vec<u8>, u32)> = match (i.handle, i.mode) {
                (1, MODE_PASSTHROUGH) => return Outcome::Refused,
                (1, _) => {
                    let mut v = b"Bearer ".to_vec();
                    v.extend_from_slice(input.field(|i| &i.request.method).bytes());
                    v.push(b' ');
                    v.extend_from_slice(input.field(|i| &i.request.authority).bytes());
                    v.extend_from_slice(input.field(|i| &i.request.canonical_path).bytes());
                    vec![(b"authorization".to_vec(), v, FIELD_SENSITIVE)]
                }
                (2, _) => (0..17)
                    .map(|k| (format!("x-f{k:02}").into_bytes(), b"v".to_vec(), 0))
                    .collect(),
                (3, _) => {
                    let mut v = i.point.to_string().into_bytes();
                    v.push(b' ');
                    match i.body.fmt {
                        busbar_contract::abi::mechanism::call::BLOB_ABSENT => v.push(b'-'),
                        _ => v.extend_from_slice(input.field(|i| &i.body).bytes()),
                    }
                    vec![(b"x-signed".to_vec(), v, 0)]
                }
                _ => return Outcome::Failed,
            };
            let bytes: usize = fields.iter().map(|(n, v, _)| n.len() + v.len()).sum();
            if fields.len() > i.fields_cap as usize || bytes > i.field_buf_cap {
                out.set(|o| &o.needed_fields, fields.len() as u32);
                out.set(|o| &o.needed_bytes, bytes as u64);
                return Outcome::Failed;
            }
            let mut at = 0usize;
            for (k, (n, v, flags)) in fields.iter().enumerate() {
                // SAFETY: the host lends `field_buf` (`field_buf_cap` bytes) and `fields`
                // (`fields_cap` spans) for the call; both bounds were checked above.
                unsafe {
                    std::ptr::copy_nonoverlapping(n.as_ptr(), i.field_buf.add(at), n.len());
                    std::ptr::copy_nonoverlapping(
                        v.as_ptr(),
                        i.field_buf.add(at + n.len()),
                        v.len(),
                    );
                    *i.fields.add(k) = FieldSpan {
                        name: Span {
                            offset: at as u32,
                            len: n.len() as u32,
                        },
                        value: Span {
                            offset: (at + n.len()) as u32,
                            len: v.len() as u32,
                        },
                        flags: *flags,
                        _reserved: 0,
                    };
                }
                at += n.len() + v.len();
            }
            out.set(|o| &o.fields_len, fields.len() as u32);
            Outcome::Ready
        }
    }

    const STYLES: &[StyleDecl] = &[
        StyleDecl {
            name: abi_str("bearer"),
            flags: 0,
            points: POINT_HEAD,
        },
        StyleDecl {
            name: abi_str("wide"),
            flags: 0,
            points: POINT_HEAD,
        },
        StyleDecl {
            name: abi_str("signed"),
            flags: 0,
            points: POINT_HEAD_BODY,
        },
    ];
    const TAIL: &AuthTail = &AuthTail {
        head: KindTailHead {
            size: std::mem::size_of::<AuthTail>() as u32,
            _reserved: 0,
        },
        caps: CAP_INBOUND | CAP_OUTBOUND,
        facts: 0,
        login_kind: LOGIN_KIND_NONE,
        inbound_points: POINT_HEAD,
        styles: STYLES.as_ptr(),
        styles_len: STYLES.len(),
        operator_principal: busbar_contract::abi::sdk::door::abi_str(""),
        credential_kinds: std::ptr::null(),
        credential_kinds_len: 0,
    };

    use busbar_contract::abi::sdk::auth_door as a;
    busbar_contract::plugin_door! {
        ops: busbar_contract::abi::auth::Ops,
        statement: a::with_tail(statement("outbound-test", "1.0.0", 8), TAIL),
        lifecycle: life(a::Verifier<Outbound>),
        kind_ops: {
            verify: busbar_contract::abi::sdk::Safe<a::Verify<Outbound>>,
            begin_login: busbar_contract::abi::sdk::Safe<a::NotServed<
                Outbound, busbar_contract::abi::auth::BeginLoginIn,
                busbar_contract::abi::auth::BeginLoginOut>>,
            complete_login: busbar_contract::abi::sdk::Safe<a::NotServed<
                Outbound, busbar_contract::abi::auth::CompleteLoginIn,
                busbar_contract::abi::auth::IdentifyOut>>,
            open_outbound: busbar_contract::abi::sdk::Safe<Open>,
            outbound_ready: busbar_contract::abi::sdk::Safe<a::NotServed<
                Outbound, busbar_contract::abi::auth::OutboundReadyIn,
                busbar_contract::abi::auth::OutboundReadyOut>>,
            fields: busbar_contract::abi::sdk::Safe<Fields>,
        },
    }
}

struct Quiet;
impl EnvelopeSink for Quiet {
    fn metric(&self, _: crate::dispatch::Metric<'_>) {}
    fn diag(&self, _: crate::dispatch::Diagnostic<'_>) {}
    fn dropped(&self, _: crate::dispatch::Dropped) {}
}

/// The test door, linked, adopted by a fresh dispatcher and opened: the instance under test.
fn opened() -> OutboundInstance {
    let d = Arc::new(Dispatcher::new(DispatchConfig {
        workers: 1,
        budgets: Budgets {
            call: Duration::from_millis(400),
            ..Budgets::default()
        },
        watchdog_period: Duration::from_millis(20),
    }));
    let row = LinkedRow::of(plugin::door).expect("the test auth door states its Statement");
    let p = load_linked::<Auth>(
        &row,
        Bind {
            instance: Arc::from("the-instance"),
            max_inflight_cap: 64,
            sink: Arc::new(Quiet),
            dispatcher: Adopter::unwatched(),
            conns: crate::dispatch::ConnTable::NoNeeds,
        },
    )
    .expect("the test auth door loads");
    let t = d.mint(0).expect("a ticket");
    let done = d
        .submit(
            &p,
            t,
            life::OPEN,
            Frame::new(
                OpenIn {
                    head: in_head(),
                    host: std::ptr::null(),
                    settings: NO_BLOB,
                    secrets: std::ptr::null(),
                    secrets_len: 0,
                    generation: 1,
                    err_buf: std::ptr::null_mut(),
                    err_cap: 0,
                },
                OpenOut {
                    head: out_head(),
                    instance: std::ptr::null_mut(),
                    err_len: 0,
                },
            ),
            DeadlineClass::Call,
            0,
        )
        .wait(Duration::from_secs(10))
        .expect("open answers");
    d.recycle(t);
    assert_eq!(done.outcome, Outcome::Ready, "the test door opens");
    OutboundInstance::new(p, d, 0)
}

fn request() -> FieldsRequest {
    FieldsRequest {
        method: b"POST".to_vec(),
        authority: "far.example:443".into(),
        path: b"/v1/call".to_vec(),
        timestamp: 1_700_000_000,
        ..FieldsRequest::default()
    }
}

fn bearer() -> Fields {
    Fields::Ready(vec![AuthField {
        name: b"authorization".to_vec(),
        value: b"Bearer POST far.example:443/v1/call".to_vec().into(),
        sensitive: true,
    }])
}

#[test]
fn open_outbound_answers_the_binding_and_refuses_a_style_it_does_not_serve() {
    let a = opened();
    let settings = serde_json::json!({});
    assert_eq!(a.open_outbound(BEARER, b"k", &settings), Ok(1));
    assert_eq!(a.open_outbound(WIDE, b"", &settings), Ok(2));
    assert_eq!(a.open_outbound(SIGNED, b"k", &settings), Ok(3));
    let err = a.open_outbound("nope", b"k", &settings).unwrap_err();
    assert!(err.contains("`nope`"), "{err}");
}

/// THE ONE CALL, both ways: on the spot and submitted on a ticket, the same fields, carrying the
/// request's facts, the sensitive flag kept.
#[test]
fn fields_answers_alike_on_the_spot_and_on_a_ticket() {
    let a = opened();
    assert_eq!(a.fields_now(1, &request()), Some(bearer()));
    let submitted = futures_lite_block_on(a.fields(1, request(), 0));
    assert_eq!(submitted, bearer());
}

/// A short answer is re-called once with the buffers it named, both ways.
#[test]
fn a_short_fields_answer_is_recalled_once_with_what_it_needs() {
    let a = opened();
    let wide = |f: Fields| match f {
        Fields::Ready(v) => v.len(),
        other => panic!("{other:?}"),
    };
    assert_eq!(a.fields_now(2, &request()).map(wide), Some(17));
    assert_eq!(wide(futures_lite_block_on(a.fields(2, request(), 0))), 17);
}

/// A refusal is not an answer on the spot, and the submitted call answers it: a passthrough on a
/// style that does not pass the caller's credential.
#[test]
fn a_refused_fields_is_refused_on_a_ticket_and_left_to_it_on_the_spot() {
    let a = opened();
    let passthrough = FieldsRequest {
        caller_credential: Some(b"caller-key".to_vec().into()),
        ..request()
    };
    assert_eq!(a.fields_now(1, &passthrough), None);
    let passthrough = FieldsRequest {
        caller_credential: Some(b"caller-key".to_vec().into()),
        ..request()
    };
    assert_eq!(
        futures_lite_block_on(a.fields(1, passthrough, 0)),
        Fields::Refused
    );
    assert_eq!(
        futures_lite_block_on(a.fields(9, request(), 0)),
        Fields::Failed
    );
}

/// AUTH POINTS: the call carries the point it is made at; the body is lent at `HeadBody`, whole,
/// both ways, and never at `Head` even when the request holds one.
#[test]
fn the_body_is_lent_at_head_body_and_never_at_head() {
    let a = opened();
    let signed = |f: Fields| match f {
        Fields::Ready(v) => String::from_utf8(v[0].value.expose_secret().clone()).unwrap(),
        other => panic!("{other:?}"),
    };
    let at = |point| FieldsRequest {
        point,
        body: Some(b"{\"a\":1}".to_vec()),
        ..request()
    };
    let head_body = format!("{POINT_HEAD_BODY} {{\"a\":1}}");
    let head = format!("{POINT_HEAD} -");
    assert_eq!(
        a.fields_now(3, &at(AuthPoint::HeadBody)).map(signed),
        Some(head_body.clone())
    );
    assert_eq!(
        signed(futures_lite_block_on(a.fields(
            3,
            at(AuthPoint::HeadBody),
            0
        ))),
        head_body
    );
    assert_eq!(
        a.fields_now(3, &at(AuthPoint::Head)).map(signed),
        Some(head)
    );
    // An empty body at `HeadBody` is lent present and empty, never absent.
    let empty = FieldsRequest {
        point: AuthPoint::HeadBody,
        body: Some(Vec::new()),
        ..request()
    };
    assert_eq!(
        a.fields_now(3, &empty).map(signed),
        Some(format!("{POINT_HEAD_BODY} "))
    );
}

/// Drive a future to completion on this thread, polling on every wake.
fn futures_lite_block_on<F: std::future::Future>(f: F) -> F::Output {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("a runtime");
    rt.block_on(async {
        tokio::time::timeout(Duration::from_secs(10), f)
            .await
            .expect("fields answers")
    })
}
