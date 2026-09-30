// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! `OutboundInstance` over a real auth door, loaded and opened through the one dispatcher: the
//! binding `open_outbound` answers, the ONE `fields` call answered on the spot and submitted on a
//! ticket (the same fields both ways), the short answer re-called once with the buffers it named, a
//! refusal, and the request's facts reaching the plugin. Every answer passes the kind's own
//! validator (`check_fields`) on the way back.

use std::marker::PhantomData;
use std::sync::Arc;
use std::time::Duration;

use busbar_contract::abi::auth::{
    AuthTail, FieldSpan, FieldsIn, FieldsOut, OpenOutboundIn, OpenOutboundOut, Span, StyleDecl,
    CAP_INBOUND, CAP_OUTBOUND, FIELD_SENSITIVE, LOGIN_KIND_NONE, MODE_PASSTHROUGH,
};
use busbar_contract::abi::mechanism::call::{DeadlineClass, Outcome};
use busbar_contract::abi::mechanism::door::KindTailHead;
use busbar_contract::abi::mechanism::lifecycle::{slot as life, OpenIn, OpenOut};
use busbar_contract::abi::sdk::auth_door::{Held, Verdict, VerifyPlugin, VerifyView};
use busbar_contract::abi::sdk::door::{abi_str, statement};
use busbar_contract::abi::sdk::lent::Lent;
use busbar_contract::abi::sdk::safe::{Instance, SafeSlot};
use busbar_contract::auth_calls::{AuthField, Fields, FieldsRequest, OutboundAuth};

use super::*;
use crate::dispatch::{
    load_linked, Adopter, Bind, Budgets, DispatchConfig, Dispatcher, EnvelopeSink, NO_BLOB,
};

/// The style whose fields fit the host's starting buffers.
const BEARER: &str = "bearer";
/// The style whose fields do not: seventeen fields, one over `FIELDS_MAX`.
const WIDE: &str = "wide";

mod plugin {
    use super::*;

    /// An outbound-only test plugin: its verdicts pass; its bindings are its style names.
    pub struct Outbound;

    impl VerifyPlugin for Outbound {
        fn open(_: &[u8], _: &[&[u8]]) -> Result<Self, &'static str> {
            Ok(Outbound)
        }
        fn verify(&self, _: &VerifyView<'_>) -> Verdict {
            Verdict::Pass
        }
    }

    /// `open_outbound`: `bearer` binds handle 1, `wide` handle 2; any other style FAILs.
    pub struct Open(PhantomData<Outbound>);
    impl SafeSlot for Open {
        type In = OpenOutboundIn;
        type Out = OpenOutboundOut;
        type State = Held<Outbound>;
        fn call(
            _: Instance<'_, Held<Outbound>>,
            input: Lent<'_, OpenOutboundIn>,
            out: &mut OpenOutboundOut,
        ) -> Outcome {
            out.handle = match input.field(|i| &i.style).bytes() {
                b"bearer" => 1,
                b"wide" => 2,
                _ => return Outcome::Failed,
            };
            Outcome::Ready
        }
    }

    /// `fields`: handle 1 answers `authorization: Bearer <method> <authority><path>` (sensitive);
    /// handle 2 answers seventeen fields, short until its buffers hold them; a passthrough on
    /// handle 1 is REFUSED.
    pub struct Fields(PhantomData<Outbound>);
    impl SafeSlot for Fields {
        type In = FieldsIn;
        type Out = FieldsOut;
        type State = Held<Outbound>;
        fn call(
            _: Instance<'_, Held<Outbound>>,
            input: Lent<'_, FieldsIn>,
            out: &mut FieldsOut,
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
                _ => return Outcome::Failed,
            };
            let bytes: usize = fields.iter().map(|(n, v, _)| n.len() + v.len()).sum();
            if fields.len() > i.fields_cap as usize || bytes > i.field_buf_cap {
                out.needed_fields = fields.len() as u32;
                out.needed_bytes = bytes as u64;
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
                            off: at as u32,
                            len: n.len() as u32,
                        },
                        value: Span {
                            off: (at + n.len()) as u32,
                            len: v.len() as u32,
                        },
                        flags: *flags,
                        _reserved: 0,
                    };
                }
                at += n.len() + v.len();
            }
            out.fields_len = fields.len() as u32;
            Outcome::Ready
        }
    }

    const STYLES: &[StyleDecl] = &[
        StyleDecl {
            name: abi_str("bearer"),
            flags: 0,
            _reserved: 0,
        },
        StyleDecl {
            name: abi_str("wide"),
            flags: 0,
            _reserved: 0,
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
        _reserved: 0,
        styles: STYLES.as_ptr(),
        styles_len: STYLES.len(),
        aliases: std::ptr::null(),
        aliases_len: 0,
        carriers: std::ptr::null(),
        carriers_len: 0,
    };

    use busbar_contract::abi::sdk::auth_door as a;
    busbar_contract::plugin_door! {
        ops: busbar_contract::abi::auth::Ops,
        statement: a::with_tail(statement("outbound-test", "1.0.0", 8), TAIL),
        lifecycle: {
            validate: busbar_contract::abi::sdk::Safe<a::Validate<Outbound>>,
            open: busbar_contract::abi::sdk::Safe<a::Open<Outbound>>,
            refresh: busbar_contract::abi::sdk::Safe<a::Refresh<Outbound>>,
            retire: busbar_contract::abi::sdk::Safe<a::Retire<Outbound>>,
            tick: busbar_contract::abi::sdk::Safe<a::Tick<Outbound>>,
            drive: busbar_contract::abi::sdk::Safe<a::Drive<Outbound>>,
            cancel: busbar_contract::abi::sdk::Safe<a::Cancel<Outbound>>,
            release: busbar_contract::abi::sdk::Safe<a::Release<Outbound>>,
            close: busbar_contract::abi::sdk::Safe<a::Close<Outbound>>,
        },
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
    let p = load_linked::<Auth>(
        plugin::door,
        Bind {
            max_inflight_cap: 64,
            sink: Arc::new(Quiet),
            dispatcher: Adopter::unwatched(),
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
                },
                OpenOut {
                    head: out_head(),
                    instance: std::ptr::null_mut(),
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
