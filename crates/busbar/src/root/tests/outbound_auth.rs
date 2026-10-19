// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE OUTBOUND HALF OF THE HOST AUTH HANDLE, composed: a registration's binding begins its dials
//! with a handle minted for the framer alone, and the framer's `auth.call` on it is served from the
//! unit's record, never from anything the transport states beyond its head.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use busbar_contract::abi::auth::{AuthPoints, POINT_HEAD, POINT_HEAD_BODY, STYLE_NEEDS_HEADERS};
use busbar_contract::abi::host::service::UnitRef;
use busbar_contract::auth_calls::{AuthField, Fielding, Fields, FieldsRequest, OutboundAuth};
use busbar_contract::conn::{InstanceId, NeedId};
use busbar_kernel::plane_driver::attempt_auth::{self, AttemptAuth};

use super::*;

/// The framer that dials, and another.
const FRAMER: u64 = 41;
const OTHER: u64 = 42;
const PLANE: InstanceId = InstanceId(9);

/// What the binding's auth was called with: the handle, and the request (its credential exposed).
type Seen = (u64, FieldsRequest, Option<Vec<u8>>);

/// A binding's auth that answers `authorization: Bearer h<handle>`, keeping every call.
#[derive(Default)]
struct ByHandle {
    seen: Mutex<Vec<Seen>>,
}

struct Done(Fields);
impl std::future::Future for Done {
    type Output = Fields;
    fn poll(
        self: std::pin::Pin<&mut Self>,
        _: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Fields> {
        std::task::Poll::Ready(self.0.clone())
    }
}
impl Fielding for Done {
    fn settled(&mut self) -> Option<Fields> {
        Some(self.0.clone())
    }
}

impl OutboundAuth for ByHandle {
    fn open_outbound(&self, _: &str, _: &[u8], _: &serde_json::Value) -> Result<u64, String> {
        Ok(1)
    }
    fn fields_now(&self, handle: u64, r: &FieldsRequest) -> Option<Fields> {
        let lent = r
            .caller_credential
            .as_ref()
            .map(|c| c.expose(&busbar_kernel::seal::lend()).clone());
        let copy = FieldsRequest {
            point: r.point,
            conn: r.conn,
            unit: r.unit,
            body: r.body.clone(),
            method: r.method.clone(),
            authority: r.authority.clone(),
            path: r.path.clone(),
            query: r.query.clone(),
            timestamp: r.timestamp,
            headers: r.headers.clone(),
            caller_credential: None,
            extensions: r.extensions.clone(),
        };
        self.seen.lock().unwrap().push((handle, copy, lent));
        Some(Fields::Ready(vec![AuthField {
            name: b"authorization".to_vec(),
            value: format!("Bearer h{handle}").into_bytes().into(),
            sensitive: true,
        }]))
    }
    fn fields(&self, h: u64, r: FieldsRequest, _: u64) -> Box<dyn Fielding> {
        Box::new(Done(self.fields_now(h, &r).unwrap_or(Fields::Failed)))
    }
    fn ready(&self, _: u64) -> bool {
        true
    }
}

fn binding(auth: &Arc<ByHandle>, points: AuthPoints, flags: u32) -> AuthBinding {
    AuthBinding {
        auth: Arc::clone(auth) as Arc<dyn OutboundAuth>,
        handle: 1,
        style_flags: flags,
        points,
        passthrough: false,
        per_request: None,
    }
}

/// A unit key of the test's own (the attempt table is the process's).
fn unit() -> u64 {
    static NEXT: AtomicU64 = AtomicU64::new(0x0b0b_0000_0000);
    NEXT.fetch_add(1, Ordering::SeqCst) + 1
}

fn attempt(member: &str, handle: u64) -> AttemptAuth {
    AttemptAuth {
        member: member.to_owned(),
        handle,
        extensions: Vec::new(),
        caller_credential: None,
        waived: false,
        secret: [0, 0],
        outcome: None,
    }
}

/// The framer's ask for `binding` on `unit`, over a head of one plane line.
fn ask(owner: u64, binding: u64, unit: UnitRef, point: u32) -> AuthAsk {
    AuthAsk {
        owner,
        binding,
        unit,
        point,
        conn: 3,
        stream: 1,
        method: b"POST".to_vec(),
        target: b"/v1/chat".to_vec(),
        authority: b"api.example".to_vec(),
        query: None,
        fields: vec![
            (b"content-type".to_vec(), b"application/json".to_vec()),
            (b"content-length".to_vec(), b"2".to_vec()),
        ],
        body: (point == POINT_HEAD_BODY).then(|| b"{}".to_vec()),
    }
}

fn lines(served: Option<AuthServed>) -> Vec<(Vec<u8>, Vec<u8>)> {
    match served {
        Some(AuthServed::Fields { fields, .. }) => fields
            .into_iter()
            .map(|f| (f.name.clone(), f.value.0.clone()))
            .collect(),
        other => panic!("served lines, got {other:?}"),
    }
}

/// THE DIAL'S BINDING: a registration's dials begin with its handle, minted for the dialling framer
/// at the current generation and verifying for no other; its points are the style's; a
/// registration with no binding, and a binding with no points, begin with none. Ids are
/// outbound-tagged, so no inbound line's id is ever served here.
#[test]
fn a_registrations_dial_begins_with_a_handle_minted_for_its_framer_alone() {
    let bindings = OutboundBindings::default();
    let auth = Arc::new(ByHandle::default());
    let id = bindings.register(PLANE, NeedId(0), "p0", &binding(&auth, AuthPoints::HEAD, 0));
    assert_ne!(id & OUTBOUND_ID, 0, "an outbound id");
    let dial = bindings
        .binding(FRAMER, PLANE, NeedId(0), "p0")
        .expect("a binding");
    assert_eq!(dial.points, POINT_HEAD);
    assert_eq!(
        auth_handle::verify_auth_ref(FRAMER, auth_handle::generation(), &dial.auth),
        Ok(id)
    );
    assert!(
        auth_handle::verify_auth_ref(OTHER, auth_handle::generation(), &dial.auth).is_err(),
        "another framer cannot present it"
    );
    assert!(bindings.binding(FRAMER, PLANE, NeedId(0), "p1").is_none());
    assert!(bindings.binding(FRAMER, PLANE, NeedId(1), "p0").is_none());
    bindings.register(
        PLANE,
        NeedId(2),
        "p2",
        &binding(&auth, AuthPoints::EMPTY, 0),
    );
    assert!(bindings.binding(FRAMER, PLANE, NeedId(2), "p2").is_none());
    assert!(bindings.serves(FRAMER, id));
    assert!(
        !bindings.serves(FRAMER, id & !OUTBOUND_ID),
        "an untagged id is not outbound"
    );
    // A new generation's binding for the same registration keeps its id.
    assert_eq!(
        bindings.register(PLANE, NeedId(0), "p0", &binding(&auth, AuthPoints::HEAD, 0)),
        id
    );
}

/// RED (#74): the unit a framer presents is verified against the unit's own secret for that
/// framer: a unit minted for another framer, a forged one, and one with no live attempt are each
/// refused, and the binding's auth is never called for them.
#[test]
fn a_unit_not_handed_to_this_framer_is_refused_and_the_auth_never_called() {
    let bindings = OutboundBindings::default();
    let auth = Arc::new(ByHandle::default());
    let id = bindings.register(PLANE, NeedId(0), "p0", &binding(&auth, AuthPoints::HEAD, 0));
    let u = unit();
    attempt_auth::record(u, attempt("p0", 7));
    let theirs = bindings.unit_ref(OTHER, u).expect("minted");
    let mine = bindings.unit_ref(FRAMER, u).expect("minted");
    let forged = UnitRef {
        mac: mine.mac ^ 1,
        ..mine
    };
    let gone = UnitRef { id: unit(), ..mine };
    for presented in [theirs, forged, gone, UnitRef::NONE] {
        let served = bindings.serve(ask(FRAMER, id, presented, POINT_HEAD), None);
        assert!(
            matches!(served, Some(AuthServed::Refused(UNIT_NOT_HANDED))),
            "{presented:?}: {served:?}"
        );
    }
    assert!(
        auth.seen.lock().unwrap().is_empty(),
        "the auth was never called"
    );
    attempt_auth::forget(u);
}

/// A unit whose live attempt rides ANOTHER registration than the binding the framer presents is
/// refused: a framer cannot present one member's handle for another member's request.
#[test]
fn a_unit_riding_another_registration_is_refused() {
    let bindings = OutboundBindings::default();
    let auth = Arc::new(ByHandle::default());
    let p0 = bindings.register(PLANE, NeedId(0), "p0", &binding(&auth, AuthPoints::HEAD, 0));
    let u = unit();
    attempt_auth::record(u, attempt("p1", 7));
    let mine = bindings.unit_ref(FRAMER, u).expect("minted");
    let served = bindings.serve(ask(FRAMER, p0, mine, POINT_HEAD), None);
    assert!(matches!(served, Some(AuthServed::Refused(UNIT_NOT_HANDED))));
    assert!(auth.seen.lock().unwrap().is_empty());
    attempt_auth::forget(u);
}

/// THE SERVED CALL: the binding's auth is called with the unit's attempt's handle, the plane's
/// scope and a passthrough member's lent credential (all read from the unit, none from the
/// transport), at the framer's point with the framer's head (the head it is about to encode, a
/// signing style's headers included), and its lines go back to the framer, the unit named.
#[test]
fn the_framers_call_is_served_from_the_units_record_with_the_head_it_encodes() {
    let bindings = OutboundBindings::default();
    let auth = Arc::new(ByHandle::default());
    let id = bindings.register(
        PLANE,
        NeedId(0),
        "p0",
        &binding(&auth, AuthPoints::HEAD_BODY, STYLE_NEEDS_HEADERS),
    );
    let u = unit();
    attempt_auth::record(
        u,
        AttemptAuth {
            extensions: b"scope-ext".to_vec(),
            caller_credential: Some(b"caller-key".to_vec().into()),
            ..attempt("p0", 8)
        },
    );
    let mine = bindings.unit_ref(FRAMER, u).expect("minted");
    let served = bindings.serve(ask(FRAMER, id, mine, POINT_HEAD_BODY), None);
    let unit_named = match &served {
        Some(AuthServed::Fields { unit, .. }) => *unit,
        other => panic!("{other:?}"),
    };
    assert_eq!(unit_named, mine);
    assert_eq!(
        lines(served),
        vec![(b"authorization".to_vec(), b"Bearer h8".to_vec())],
        "the attempt's handle, not the sealed one"
    );
    let seen = auth.seen.lock().unwrap();
    let (handle, request, lent) = &seen[0];
    assert_eq!(*handle, 8);
    assert_eq!(request.extensions, b"scope-ext");
    assert_eq!(lent.as_deref(), Some(&b"caller-key"[..]));
    assert_eq!(
        request.point,
        busbar_contract::abi::auth::AuthPoint::HeadBody
    );
    assert_eq!(request.body.as_deref(), Some(&b"{}"[..]));
    assert_eq!(
        (
            request.method.as_slice(),
            request.authority.as_str(),
            request.path.as_slice()
        ),
        (&b"POST"[..], "api.example", &b"/v1/chat"[..])
    );
    assert_eq!(
        request.headers,
        vec![
            (b"content-type".to_vec(), b"application/json".to_vec()),
            (b"content-length".to_vec(), b"2".to_vec()),
        ],
        "the signing style signs the head the framer finalised, its length included"
    );
    assert_eq!(request.unit, u);
    drop(seen);
    attempt_auth::forget(u);
}

/// THE PLANE'S WAIVER: a waived request is served NO line and the auth is never called.
#[test]
fn a_waived_request_is_served_no_line() {
    let bindings = OutboundBindings::default();
    let auth = Arc::new(ByHandle::default());
    let id = bindings.register(PLANE, NeedId(0), "p0", &binding(&auth, AuthPoints::HEAD, 0));
    let u = unit();
    attempt_auth::record(
        u,
        AttemptAuth {
            waived: true,
            ..attempt("p0", 0)
        },
    );
    let mine = bindings.unit_ref(FRAMER, u).expect("minted");
    assert!(lines(bindings.serve(ask(FRAMER, id, mine, POINT_HEAD), None)).is_empty());
    assert!(auth.seen.lock().unwrap().is_empty());
    attempt_auth::forget(u);
}

/// A style that does not read the head is handed none of it: only the head words.
#[test]
fn a_style_that_reads_no_head_is_handed_none() {
    let bindings = OutboundBindings::default();
    let auth = Arc::new(ByHandle::default());
    let id = bindings.register(PLANE, NeedId(0), "p0", &binding(&auth, AuthPoints::HEAD, 0));
    let u = unit();
    attempt_auth::record(u, attempt("p0", 3));
    let mine = bindings.unit_ref(FRAMER, u).expect("minted");
    let _ = lines(bindings.serve(ask(FRAMER, id, mine, POINT_HEAD), None));
    let seen = auth.seen.lock().unwrap();
    assert!(seen[0].1.headers.is_empty());
    assert!(seen[0].1.body.is_none(), "no body at the head point");
    assert!(
        seen[0].2.is_none(),
        "an own-credential member lends no caller credential"
    );
    drop(seen);
    attempt_auth::forget(u);
}

/// A PLUGIN'S OWN REQUEST to a member is recorded under a request unit of its own (never a unit's
/// walk key), and the framer's call on the member's binding is served from it as a walk's attempt
/// is: its handle, its scope, its lent credential. Forgotten, it is served no more.
#[test]
fn a_plugins_own_request_is_served_from_its_recorded_unit_until_forgotten() {
    let bindings = OutboundBindings::default();
    let auth = Arc::new(ByHandle::default());
    let id = bindings.register(PLANE, NeedId(0), "p0", &binding(&auth, AuthPoints::HEAD, 0));
    let unit = bindings
        .record_request(crate::root::loader::dispatch::auth_serve::OwnRequest {
            member: "p0".to_owned(),
            handle: 11,
            extensions: b"own-scope".to_vec(),
            caller_credential: Some(b"lent".to_vec().into()),
            waived: false,
        })
        .expect("recorded");
    assert_ne!(unit & OWN_REQUEST, 0, "a request unit, never a walk's");
    let mine = bindings.unit_ref(FRAMER, unit).expect("minted");
    assert_eq!(
        lines(bindings.serve(ask(FRAMER, id, mine, POINT_HEAD), None)),
        vec![(b"authorization".to_vec(), b"Bearer h11".to_vec())]
    );
    {
        let seen = auth.seen.lock().unwrap();
        assert_eq!(seen[0].1.extensions, b"own-scope");
        assert_eq!(seen[0].2.as_deref(), Some(&b"lent"[..]));
    }
    bindings.forget_request(unit);
    assert!(matches!(
        bindings.serve(ask(FRAMER, id, mine, POINT_HEAD), None),
        Some(AuthServed::Refused(UNIT_NOT_HANDED))
    ));
}
