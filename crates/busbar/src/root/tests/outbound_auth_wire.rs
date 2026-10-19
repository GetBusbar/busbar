// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! END TO END, OUTBOUND (THE DESIGN §4 item 5 / §6 "Auth points and guest lists" item 5, §11.6;
//! l.3779: nothing is added to the head after the auth has run, for every transport, with a RED):
//! a LINKED TEST FRAMER, loaded through the loader's one load and bound like every transport door,
//! is begun over a dial whose binding handle the root minted for it, and handed the request on an
//! emit naming the unit the root minted for it. The framer finalises its head (its own line: the
//! body's length), calls the binding's auth through the host auth handle (`auth.call`), adds the
//! auth's lines FIRST (1.5.5's order, v1.5.5 walk.rs:564-590), replacing any plane line of the same
//! name, adds nothing after, and writes the wire.
//!
//! The root serves the call from the unit's record; the binding's auth is a signing style
//! (`STYLE_NEEDS_HEADERS`) that signs the head it is handed. Proven: the wire is the request line,
//! the auth's line, then EXACTLY the head the auth signed, in its order, then the body; and the
//! signature on the wire is the auth's over those bytes. RED (before this lane): the kernel signed
//! the head before the framer added its own lines, and the framer's `auth.call` was not served.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::task::Poll;

use busbar_contract::abi::auth::{AuthPoints, POINT_HEAD, STYLE_NEEDS_HEADERS};
use busbar_contract::abi::host::service::{AuthRef, UnitRef};
use busbar_contract::abi::mechanism::call::{AbiStr, InHead, OutHead, Outcome};
use busbar_contract::abi::mechanism::door::{KindTailHead, Statement};
use busbar_contract::abi::mechanism::lifecycle::{
    CancelIn, CancelOut, DriveIn, GenIn, OpenIn, OpenOut, RefreshIn, ReleaseIn, TickIn, TickOut,
    ValidateIn,
};
use busbar_contract::abi::mechanism::ticket::CompletionHandle;
use busbar_contract::abi::sdk::door::{abi_str, statement};
use busbar_contract::abi::sdk::services::{HeadViewArgs, Services};
use busbar_contract::abi::sdk::{self as sdk, Lent, Out, Safe, SafeSlot};
use busbar_contract::abi::transport::{
    AcceptIn, AcceptOut, AdoptIn, ArrivalIn, ArrivalOut, BeginIn, Claim, ConnIn, ConnOut, DialIn,
    EmitIn, EncodeIn, FinishIn, FramerOut, FramingIn, IngestIn, IoOut, ListenIn, ListenOut,
    LocateIn, LocateOut, Ops, ReadIn, RefuseIn, ShutIn, TransportTail, WriteIn,
    CANCEL_NOTHING_MOVED, FRAMING_STREAM, ROLE_FRAMER, SIDE_DIAL, YIELD_ENDED,
};
use busbar_contract::auth_calls::{AuthField, Fielding, Fields, FieldsRequest, OutboundAuth};
use busbar_contract::conn::{InstanceId, NeedId};
use busbar_core_connector::framer::{self, BindingRefs, Established, FramerDoor, Framing};
use busbar_kernel::plane_driver::attempt_auth::{self, AttemptAuth};
use busbar_kernel::plane_driver::AuthBinding;

use crate::root::doors::{row_bind, Dispatched};
use crate::root::loader::dispatch::kinds::transport::Transport as TransportKind;
use crate::root::loader::dispatch::{load_linked, LinkedRow};

// ── the linked test framer ──────────────────────────────────────────────────────────────────────

busbar_contract::own_seal!(WireSeal);

const CLAIMS: &[Claim] = &[Claim {
    selector_forms: abi_str(""),
    egress_selector_forms: abi_str(""),
    facts: std::ptr::null(),
    facts_len: 0,
    status_namespace: abi_str(""),
    session: 0,
    session_bound: 0,
    unit0_trigger: 0,
    status_at: 0,
    _reserved: 0,
}];

const CLAIM_NAMES: &[AbiStr] = &[abi_str("tst")];

const NONE: AbiStr = AbiStr {
    ptr: std::ptr::null(),
    len: 0,
};

const TAIL: TransportTail = TransportTail {
    head: KindTailHead {
        size: std::mem::size_of::<TransportTail>() as u32,
        _reserved: 0,
    },
    role: ROLE_FRAMER,
    framing: FRAMING_STREAM,
    facts: 0,
    handshake_max_steps: 0,
    composes_over: std::ptr::null(),
    composes_over_len: 0,
    claim_rows: CLAIMS.as_ptr(),
    claim_rows_len: CLAIMS.len(),
    upgrades_to: std::ptr::null(),
    upgrades_to_len: 0,
    handoff_from: NONE,
    handoff_to: NONE,
    handoff_binding_fact: NONE,
    handshake_frame_kind: NONE,
    status_rows: std::ptr::null(),
    status_rows_len: 0,
    settings: std::ptr::null(),
    settings_len: 0,
    fault_rows: std::ptr::null(),
    fault_rows_len: 0,
    frame_piece_size: 0,
    _reserved: 0,
};

/// The test framer's Statement.
const STATEMENT: Statement = Statement {
    kind_tail: (&TAIL as *const TransportTail).cast::<KindTailHead>(),
    claims: CLAIM_NAMES.as_ptr(),
    claims_len: CLAIM_NAMES.len(),
    ..statement("tst", "0", 8)
};

/// One framing: the binding it was begun with, the authority it was begun for and the scheme the
/// host declared for its connection (`BeginIn::scheme`).
struct Bound {
    auth: AuthRef,
    points: u32,
    authority: String,
    scheme: u8,
}

/// The framer's instance: the host services `open` handed it, and its framings.
struct Instance {
    services: Option<Services>,
    framings: Mutex<HashMap<u64, Bound>>,
    next: AtomicU64,
}

macro_rules! slot {
    ($name:ident, $in:ty, $out:ty, |$inst:pat_param, $input:pat_param, $o:ident| $body:block) => {
        struct $name;
        impl SafeSlot for $name {
            type In = $in;
            type Out = $out;
            type State = Instance;
            fn call(
                $inst: sdk::Instance<'_, Instance>,
                $input: Lent<'_, $in>,
                #[allow(unused_mut)] mut $o: Out<'_, $out>,
            ) -> Outcome $body
        }
    };
}

macro_rules! answer {
    ($name:ident, $in:ty, $out:ty, $outcome:expr) => {
        slot!($name, $in, $out, |_, _, _o| { $outcome });
    };
}

slot!(Open, OpenIn, OpenOut, |instance, i, _o| {
    let services = i.host().and_then(|h| Services::of(&h));
    instance.open(Instance {
        services,
        framings: Mutex::new(HashMap::new()),
        next: AtomicU64::new(1),
    });
    Outcome::Ready
});
answer!(Validate, ValidateIn, OutHead, Outcome::Ready);
answer!(Refresh, RefreshIn, OutHead, Outcome::Ready);
answer!(Retire, GenIn, OutHead, Outcome::Ready);
answer!(Tick, TickIn, TickOut, Outcome::Ready);
answer!(Drive, DriveIn, OutHead, Outcome::Ready);
answer!(Release, ReleaseIn, OutHead, Outcome::Ready);
answer!(Close, InHead, OutHead, Outcome::Ready);
slot!(Cancel, CancelIn, CancelOut, |_, _, o| {
    o.set(|x| &x.disposition, CANCEL_NOTHING_MOVED);
    Outcome::Ready
});
answer!(Listen, ListenIn, ListenOut, Outcome::Refused);
answer!(Accept, AcceptIn, AcceptOut, Outcome::Refused);
answer!(Dial, DialIn, ConnOut, Outcome::Refused);
answer!(Read, ReadIn, IoOut, Outcome::Refused);
answer!(Write, WriteIn, IoOut, Outcome::Refused);
answer!(Flush, ConnIn, OutHead, Outcome::Refused);
answer!(Shut, ShutIn, OutHead, Outcome::Refused);
answer!(Arrival, ArrivalIn, ArrivalOut, Outcome::Refused);
answer!(Refuse, RefuseIn, FramerOut, Outcome::Refused);
answer!(Detach, FramingIn, FramerOut, Outcome::Refused);
answer!(Adopt, AdoptIn, FramerOut, Outcome::Refused);
answer!(Ingest, IngestIn, FramerOut, Outcome::Ready);
answer!(Timer, FramingIn, FramerOut, Outcome::Ready);

/// The authority a `tst://host:port/...` target names.
fn authority_of(target: &[u8]) -> Option<String> {
    let t = std::str::from_utf8(target).ok()?;
    let rest = t.strip_prefix("tst://")?;
    Some(rest.split('/').next()?.to_owned())
}

slot!(Locate, LocateIn, LocateOut, |_, i, o| {
    let Some(authority) = authority_of(i.field(|x| &x.target).bytes()) else {
        o.error("locate: not a tst target");
        return Outcome::Failed;
    };
    let mut a = i.authority_buf();
    a.extend(authority.as_bytes());
    let (written, needed) = a.settle(!a.fits());
    o.set(|x| &x.authority_written, written as u64);
    o.set(|x| &x.authority_needed, needed as u64);
    if !a.fits() {
        o.error("locate: short");
        return Outcome::Failed;
    }
    Outcome::Ready
});

slot!(Begin, BeginIn, FramerOut, |p, i, o| {
    let Some(inst) = p.get() else {
        return Outcome::Failed;
    };
    if i.side != SIDE_DIAL {
        return Outcome::Refused;
    }
    let Some(authority) = authority_of(i.field(|x| &x.target).bytes()) else {
        o.error("begin: not a tst target");
        return Outcome::Failed;
    };
    let token = inst.next.fetch_add(1, Ordering::Relaxed);
    inst.framings.lock().expect("framings").insert(
        token,
        Bound {
            auth: i.auth,
            points: i.points,
            authority,
            scheme: i.scheme,
        },
    );
    o.set(|x| &x.framing, token);
    Outcome::Ready
});

slot!(Finish, FinishIn, FramerOut, |p, i, o| {
    if let Some(inst) = p.get() {
        inst.framings.lock().expect("framings").remove(&i.framing);
    }
    o.set(|x| &x.yielded.flags, YIELD_ENDED);
    Outcome::Ready
});

// `encode`: the envelope as this wire's message: `METHOD TARGET`, a `name: value` line per field,
// a blank line, the body (LF-separated; the wire form is `emit`'s).
slot!(Encode, EncodeIn, FramerOut, |_, i, o| {
    let mut m = Vec::new();
    m.extend_from_slice(i.field(|x| &x.method).bytes());
    m.push(b' ');
    m.extend_from_slice(i.field(|x| &x.target).bytes());
    m.push(b'\n');
    for f in i.fields().iter() {
        m.extend_from_slice(f.field(|x| &x.name).bytes());
        m.extend_from_slice(b": ");
        m.extend_from_slice(f.field(|x| &x.value).bytes());
        m.push(b'\n');
    }
    m.push(b'\n');
    m.extend_from_slice(i.body());
    let mut wire = i.field(|x| &x.sink).wire();
    if m.len() > wire.cap() {
        o.error("encode: larger than the wire buffer");
        return Outcome::Failed;
    }
    wire.extend(&m);
    o.set(|x| &x.yielded.wire_len, wire.written() as u64);
    Outcome::Ready
});

/// The message `encode` wrote, read back: its head words, its lines and its body.
type Message = (String, String, Vec<(String, Vec<u8>)>, Vec<u8>);

fn parse(m: &[u8]) -> Option<Message> {
    let at = m.windows(2).position(|w| w == b"\n\n")?;
    let (head, body) = (&m[..at], &m[at + 2..]);
    let text = std::str::from_utf8(head).ok()?;
    let mut lines = text.split('\n');
    let (method, target) = lines.next()?.split_once(' ')?;
    let fields = lines
        .map(|l| {
            let (n, v) = l.split_once(": ")?;
            Some((n.to_owned(), v.as_bytes().to_vec()))
        })
        .collect::<Option<Vec<_>>>()?;
    Some((method.to_owned(), target.to_owned(), fields, body.to_vec()))
}

// `emit`: THE OUTBOUND HEAD, as every transport builds it (THE DESIGN §6 item 5): the framer's own
// line first finalises the head (the body's length), then the binding's auth is called at its
// point with that head, its lines go out FIRST replacing any line of the same name, and nothing is
// added after.
slot!(Emit, EmitIn, FramerOut, |p, i, o| {
    let Some(inst) = p.get() else {
        return Outcome::Failed;
    };
    let Some((method, target, mut fields, body)) = parse(i.bytes()) else {
        o.error("emit: not this wire's message");
        return Outcome::Failed;
    };
    let (auth, points, authority, scheme) = {
        let framings = inst.framings.lock().expect("framings");
        let Some(b) = framings.get(&i.framing) else {
            o.error("emit: no such framing");
            return Outcome::Failed;
        };
        (b.auth, b.points, b.authority.clone(), b.scheme)
    };
    // The framer's own line: the head is final once it is here.
    if !body.is_empty() {
        fields.push((
            "content-length".to_owned(),
            body.len().to_string().into_bytes(),
        ));
    }
    let mut lines: Vec<(String, Vec<u8>)> = Vec::new();
    if points & POINT_HEAD != 0 {
        let Some(services) = inst.services.as_ref() else {
            o.error("emit: no host services");
            return Outcome::Failed;
        };
        let view: Vec<(&str, &[u8])> = fields
            .iter()
            .map(|(n, v)| (n.as_str(), v.as_slice()))
            .collect();
        let handle = CompletionHandle {
            ticket: i.head.ticket,
            seq: 0,
            _reserved: 0,
        };
        let called = services.auth_call::<WireSeal>(
            handle,
            auth,
            i.unit,
            POINT_HEAD,
            0,
            i.stream,
            &HeadViewArgs {
                method: &method,
                target: &target,
                authority: &authority,
                query: None,
                fields: &view,
                // The scheme the host declared at begin, as it declared it.
                scheme,
            },
            None,
        );
        match called {
            Poll::Pending => return Outcome::Pending,
            Poll::Ready(Err(_)) => {
                o.error("emit: the auth refused the request");
                return Outcome::Refused;
            }
            Poll::Ready(Ok(c)) => {
                for f in c.fields {
                    lines.push((f.name, f.value.expose_own(&WireSeal::here()).clone()));
                }
            }
        }
    }
    // The wire: the request line, the auth's lines FIRST, the head (a line the auth named is the
    // auth's), the body. Nothing after.
    let mut w = format!("{method} {target} TST/1\r\n").into_bytes();
    for (n, v) in &lines {
        w.extend_from_slice(n.as_bytes());
        w.extend_from_slice(b": ");
        w.extend_from_slice(v);
        w.extend_from_slice(b"\r\n");
    }
    for (n, v) in fields
        .iter()
        .filter(|(n, _)| !lines.iter().any(|(a, _)| a.eq_ignore_ascii_case(n)))
    {
        w.extend_from_slice(n.as_bytes());
        w.extend_from_slice(b": ");
        w.extend_from_slice(v);
        w.extend_from_slice(b"\r\n");
    }
    w.extend_from_slice(b"\r\n");
    w.extend_from_slice(&body);
    let mut wire = i.field(|x| &x.sink).wire();
    if w.len() > wire.cap() {
        o.error("emit: larger than the wire buffer");
        return Outcome::Failed;
    }
    wire.extend(&w);
    o.set(|x| &x.yielded.wire_len, wire.written() as u64);
    Outcome::Ready
});

busbar_contract::plugin_door! {
    ops: Ops,
    statement: STATEMENT,
    lifecycle: {
        validate: Safe<Validate>,
        open: Safe<Open>,
        refresh: Safe<Refresh>,
        retire: Safe<Retire>,
        tick: Safe<Tick>,
        drive: Safe<Drive>,
        cancel: Safe<Cancel>,
        release: Safe<Release>,
        close: Safe<Close>,
    },
    kind_ops: {
        listen: Safe<Listen>,
        accept: Safe<Accept>,
        dial: Safe<Dial>,
        read: Safe<Read>,
        write: Safe<Write>,
        flush: Safe<Flush>,
        shut: Safe<Shut>,
        arrival: Safe<Arrival>,
        locate: Safe<Locate>,
        begin: Safe<Begin>,
        ingest: Safe<Ingest>,
        emit: Safe<Emit>,
        encode: Safe<Encode>,
        refuse: Safe<Refuse>,
        finish: Safe<Finish>,
        detach: Safe<Detach>,
        adopt: Safe<Adopt>,
        timer: Safe<Timer>,
    },
}

// ── the signing auth ────────────────────────────────────────────────────────────────────────────

/// FNV-1a 64 over `bytes`: the test style's signature.
fn digest(bytes: &[u8]) -> u64 {
    bytes.iter().fold(0xcbf2_9ce4_8422_2325, |h, b| {
        (h ^ u64::from(*b)).wrapping_mul(0x0100_0000_01b3)
    })
}

/// What a signing style signs: the head words, the authority, then each line, in order.
fn canonical(
    method: &[u8],
    path: &[u8],
    authority: &str,
    headers: &[(Vec<u8>, Vec<u8>)],
) -> Vec<u8> {
    let mut c = Vec::new();
    c.extend_from_slice(method);
    c.push(b' ');
    c.extend_from_slice(path);
    c.push(b' ');
    c.extend_from_slice(authority.as_bytes());
    c.push(b'\n');
    for (n, v) in headers {
        c.extend_from_slice(n);
        c.push(b':');
        c.extend_from_slice(v);
        c.push(b'\n');
    }
    c
}

/// One head a signing style signed: the handle it was called on, the method, the path, the
/// authority and the head's lines.
type SignedHead = (u64, Vec<u8>, Vec<u8>, String, Vec<(Vec<u8>, Vec<u8>)>);

/// A signing style: answers `authorization: Sig <digest of the head it was handed>`, keeping the
/// head it signed.
#[derive(Default)]
struct Signer {
    signed: Mutex<Vec<SignedHead>>,
}

struct Done(Fields);
impl std::future::Future for Done {
    type Output = Fields;
    fn poll(self: std::pin::Pin<&mut Self>, _: &mut std::task::Context<'_>) -> Poll<Fields> {
        Poll::Ready(self.0.clone())
    }
}
impl Fielding for Done {
    fn settled(&mut self) -> Option<Fields> {
        Some(self.0.clone())
    }
}

impl OutboundAuth for Signer {
    fn open_outbound(&self, _: &str, _: &[u8], _: &serde_json::Value) -> Result<u64, String> {
        Ok(5)
    }
    fn fields_now(&self, handle: u64, r: &FieldsRequest) -> Option<Fields> {
        let sig = digest(&canonical(&r.method, &r.path, &r.authority, &r.headers));
        self.signed.lock().unwrap().push((
            handle,
            r.method.clone(),
            r.path.clone(),
            r.authority.clone(),
            r.headers.clone(),
        ));
        Some(Fields::Ready(vec![AuthField {
            name: b"authorization".to_vec(),
            value: format!("Sig {sig:016x}").into_bytes().into(),
            sensitive: true,
        }]))
    }
    fn fields(&self, h: u64, r: FieldsRequest, _: u64) -> Box<dyn Fielding> {
        Box::new(Done(self.fields_now(h, &r).unwrap_or(Fields::Failed)))
    }
}

/// A request as the wire carried it: its request line, its head lines in order, and its body.
type WireRequest = (String, Vec<(String, Vec<u8>)>, Vec<u8>);

/// The wire's request line, its head lines in order, and its body.
fn read_wire(w: &[u8]) -> WireRequest {
    let at = w.windows(4).position(|x| x == b"\r\n\r\n").expect("a head");
    let head = std::str::from_utf8(&w[..at]).expect("text");
    let mut lines = head.split("\r\n");
    let first = lines.next().expect("a request line").to_owned();
    let fields = lines
        .map(|l| {
            let (n, v) = l.split_once(": ").expect("a field line");
            (n.to_owned(), v.as_bytes().to_vec())
        })
        .collect();
    (first, fields, w[at + 4..].to_vec())
}

/// THE AUTH SIGNS THE EXACT HEAD THAT GOES ON THE WIRE. The plane's lines, the framer's own length
/// line, then the framer's call through the host auth handle, served by the root from the unit's
/// record: the wire is the request line, the auth's line FIRST, then exactly the head the auth signed
/// (the framer's length line included), then the body, and nothing after; the signature on the wire
/// is the auth's over that head. The auth was called once, with the unit's attempt's handle.
#[test]
fn the_auth_signs_the_exact_head_that_goes_on_the_wire() {
    const PLANE: InstanceId = InstanceId(77);
    const MEMBER: &str = "wire-member";
    let row = LinkedRow::of(door).expect("the test framer's door is a door");
    let plugin =
        load_linked::<TransportKind>(&row, row_bind("tst-wire")).expect("the test framer loads");
    let door: Arc<dyn FramerDoor> = Arc::new(
        Dispatched::open(
            plugin,
            &busbar_contract::transport::TransportSettings::default(),
        )
        .expect("the test framer opens"),
    );
    let owner = door.owner();
    assert_ne!(owner, 0, "a loaded framer has an owner identity");

    // The root's outbound half, as the boot arms it.
    let bindings = Arc::clone(crate::root::outbound_auth::process());
    crate::root::outbound_auth::arm_dispatcher(crate::root::doors::dispatcher());
    let signer = Arc::new(Signer::default());
    bindings.register(
        PLANE,
        NeedId(0),
        MEMBER,
        &AuthBinding {
            auth: Arc::clone(&signer) as Arc<dyn OutboundAuth>,
            handle: 1,
            style_flags: STYLE_NEEDS_HEADERS,
            points: AuthPoints::HEAD,
            passthrough: false,
            per_request: None,
        },
    );
    // The kernel's record of the unit's attempt: its handle now is 5.
    let unit = 0x7e57_0000_0001;
    attempt_auth::record(
        unit,
        AttemptAuth {
            member: MEMBER.to_owned(),
            handle: 5,
            extensions: Vec::new(),
            caller_credential: None,
            waived: false,
            secret: [0, 0],
            outcome: None,
        },
    );
    let binding = bindings
        .binding(owner, PLANE, NeedId(0), MEMBER)
        .expect("the member's binding");
    let unit_ref: UnitRef = bindings.unit_ref(owner, unit).expect("the unit's ref");

    let (mut framing, _) = Framing::begin_bound(
        Arc::clone(&door),
        SIDE_DIAL,
        "tst://api.example:443/v1",
        &Established {
            scheme: Established::scheme_of(false),
            ..Established::default()
        },
        &[],
        &binding,
    )
    .expect("the dial's framing begins with its binding");
    assert!(!framing.parked());
    let message = framer::encode_head(
        door.as_ref(),
        b"POST",
        b"/v1/chat",
        &[
            ("content-type", b"application/json".as_slice()),
            ("x-trace", b"t1".as_slice()),
        ],
        b"{\"q\":1}",
    )
    .expect("the framer encodes the message");
    let y = framing
        .emit_unit(1, &message, true, false, None, unit_ref)
        .expect("the framer emits");
    assert!(!framing.parked(), "the auth answered at once");

    let (first, wire_fields, body) = read_wire(&y.wire);
    assert_eq!(first, "POST /v1/chat TST/1");
    assert_eq!(body, b"{\"q\":1}");
    let signed = signer.signed.lock().unwrap().clone();
    assert_eq!(signed.len(), 1, "one auth call");
    let (handle, method, path, authority, head) = &signed[0];
    assert_eq!(*handle, 5, "served on the unit's attempt's handle");
    assert_eq!(
        (method.as_slice(), path.as_slice(), authority.as_str()),
        (&b"POST"[..], &b"/v1/chat"[..], "api.example:443")
    );
    // The auth's line FIRST, then EXACTLY the head it signed, in its order, and nothing after.
    assert_eq!(wire_fields[0].0, "authorization");
    let after: Vec<(Vec<u8>, Vec<u8>)> = wire_fields[1..]
        .iter()
        .map(|(n, v)| (n.as_bytes().to_vec(), v.clone()))
        .collect();
    assert_eq!(
        &after, head,
        "the wire carries the head the auth signed, in its order, and nothing after"
    );
    assert_eq!(
        after
            .iter()
            .map(|(n, _)| String::from_utf8_lossy(n).into_owned())
            .collect::<Vec<_>>(),
        ["content-type", "x-trace", "content-length"],
        "the framer's own length line is in the head the auth signed"
    );
    let expected = format!(
        "Sig {:016x}",
        digest(&canonical(method, path, authority, head))
    );
    assert_eq!(
        wire_fields[0].1,
        expected.as_bytes(),
        "the auth's signature, as it signed"
    );
    attempt_auth::forget(unit);
}

// ── the composed open: the media session's signalling request (coordinator ruling) ─────────────────────────

/// A LINKED dialling DATAGRAM framer, as small as the composed open needs: its `begin` answers its
/// own session description as the stream-0 piece the connector sends as the signalling body.
mod media {
    use super::*;
    use busbar_contract::abi::transport::{FramePiece, FRAMING_DATAGRAM, PIECE_END_OF_FRAME};

    /// The description the datagram framer offers.
    pub(super) const OFFER: &[u8] = b"v=0 offer";

    const MEDIA_NAMES: &[AbiStr] = &[abi_str("dg")];

    const MEDIA_TAIL: TransportTail = TransportTail {
        framing: FRAMING_DATAGRAM,
        ..TAIL
    };

    const MEDIA_STATEMENT: Statement = Statement {
        kind_tail: (&MEDIA_TAIL as *const TransportTail).cast::<KindTailHead>(),
        claims: MEDIA_NAMES.as_ptr(),
        claims_len: MEDIA_NAMES.len(),
        ..statement("dg", "0", 8)
    };

    slot!(Begin, BeginIn, FramerOut, |_, i, o| {
        let mut frame = i.field(|x| &x.sink).frame();
        frame.extend(OFFER);
        let mut pieces = i.field(|x| &x.sink).pieces();
        pieces.push(FramePiece {
            stream: 0,
            offset: 0,
            len: OFFER.len() as u64,
            code: 0,
            status_class: 0,
            fault: 0,
            flags: PIECE_END_OF_FRAME,
            retry_after_secs: 0,
            declared_len: 0,
        });
        o.set(|x| &x.framing, 7);
        o.set(|x| &x.yielded.frame_len, OFFER.len() as u64);
        o.set(|x| &x.yielded.pieces_len, 1);
        Outcome::Ready
    });
    answer!(MediaEmit, EmitIn, FramerOut, Outcome::Ready);

    busbar_contract::plugin_door! {
        ops: Ops,
        statement: MEDIA_STATEMENT,
        lifecycle: {
            validate: Safe<Validate>,
            open: Safe<Open>,
            refresh: Safe<Refresh>,
            retire: Safe<Retire>,
            tick: Safe<Tick>,
            drive: Safe<Drive>,
            cancel: Safe<Cancel>,
            release: Safe<Release>,
            close: Safe<Close>,
        },
        kind_ops: {
            listen: Safe<Listen>,
            accept: Safe<Accept>,
            dial: Safe<Dial>,
            read: Safe<Read>,
            write: Safe<Write>,
            flush: Safe<Flush>,
            shut: Safe<Shut>,
            arrival: Safe<Arrival>,
            locate: Safe<Locate>,
            begin: Safe<Begin>,
            ingest: Safe<Ingest>,
            emit: Safe<MediaEmit>,
            encode: Safe<Encode>,
            refuse: Safe<Refuse>,
            finish: Safe<Finish>,
            detach: Safe<Detach>,
            adopt: Safe<Adopt>,
            timer: Safe<Timer>,
        },
    }
}

/// The caller's leg of the held session: it is never written in this cell.
struct Quiet;

impl busbar_core_connector::datagram::LegSink for Quiet {
    fn line(&self, _: busbar_core_connector::datagram::Across, _: std::time::Instant) {}
    fn close(&self) {}
}

/// THE COMPOSED SIGNALLING REQUEST CARRIES THE BINDING'S CREDENTIAL (coordinator ruling; THE
/// DESIGN §6 item 5): a held session's upstream leg, opened over a datagram framer's need, sends
/// the framer's session description as the body of a signalling exchange over the stream framer
/// its target names. That exchange's framing begins with the member's binding handle and emits
/// naming the session's unit, so the framer calls the member's auth through the host auth handle:
/// the request that reaches the far end carries the auth's line FIRST, then exactly the head the
/// auth signed (its own length line included), and the description as its body. RED: before, the
/// composed open's inner exchange began with no binding, and with the kernel's fields call gone
/// the signalling request went out with no credential.
#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn a_composed_signalling_request_carries_the_auth_line_over_the_head_it_signed() {
    use busbar_contract::conn::{Conns as _, OpenDesc, PollConns as _};
    use busbar_core_connector::registry::{Entry, Transports};
    use tokio::io::AsyncReadExt;
    const PLANE: InstanceId = InstanceId(78);
    const MEMBER: &str = "signalling-member";
    const UNIT: u64 = 0x7e57_0000_0002;

    // The far end: everything the signalling request put on the wire.
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let seen = Arc::new(Mutex::new(Vec::<u8>::new()));
    let heard = Arc::clone(&seen);
    tokio::spawn(async move {
        let (mut s, _) = listener.accept().await.unwrap();
        let mut buf = [0_u8; 4096];
        loop {
            match s.read(&mut buf).await {
                Ok(0) | Err(_) => return,
                Ok(n) => heard.lock().unwrap().extend_from_slice(&buf[..n]),
            }
        }
    });

    // The connector: the build's transports, the linked test framer under `tst`, the datagram
    // framer under `dg`; the root's outbound half armed on it.
    let row = LinkedRow::of(door).expect("the test framer's door is a door");
    let plugin =
        load_linked::<TransportKind>(&row, row_bind("tst-signal")).expect("the test framer loads");
    let tst: Arc<dyn FramerDoor> = Arc::new(
        Dispatched::open(
            plugin,
            &busbar_contract::transport::TransportSettings::default(),
        )
        .expect("the test framer opens"),
    );
    let settings = busbar_contract::transport::TransportSettings::default();
    let mut entries = crate::root::connector::entries(crate::LINKED_TRANSPORT_DOORS, &settings)
        .expect("the linked doors open");
    entries.push(Entry {
        door: Arc::clone(&tst),
        alpn: Vec::new(),
    });
    let media_row = LinkedRow::of(media::door).expect("the media framer's door is a door");
    let media = load_linked::<TransportKind>(&media_row, row_bind("dg-signal"))
        .expect("the media framer loads");
    entries.push(Entry {
        door: Arc::new(
            Dispatched::open(
                media,
                &busbar_contract::transport::TransportSettings::default(),
            )
            .expect("the media framer opens"),
        ),
        alpn: Vec::new(),
    });
    let dest = crate::root::connector::guard_for(&busbar_kernel::config::Destinations {
        block_private_addresses: false,
        ..busbar_kernel::config::Destinations::default()
    })
    .expect("the guard");
    let c = busbar_core_connector::Connector::serving(
        Transports::new(entries).expect("the view"),
        busbar_core_connector::process::judge(dest, &[]),
        None,
        Arc::new(|_, _| {}),
    );
    c.declare_over(PLANE, NeedId(0), "dg")
        .expect("the datagram need");
    crate::root::outbound_auth::arm(&c);

    // The member's binding, the kernel's record of the unit's attempt, the held session.
    let bindings = crate::root::outbound_auth::process();
    let signer = Arc::new(Signer::default());
    bindings.register(
        PLANE,
        NeedId(0),
        MEMBER,
        &AuthBinding {
            auth: Arc::clone(&signer) as Arc<dyn OutboundAuth>,
            handle: 1,
            style_flags: STYLE_NEEDS_HEADERS,
            points: AuthPoints::HEAD,
            passthrough: false,
            per_request: None,
        },
    );
    attempt_auth::record(
        UNIT,
        AttemptAuth {
            member: MEMBER.to_owned(),
            handle: 9,
            extensions: Vec::new(),
            caller_credential: None,
            waived: false,
            secret: [0, 0],
            outcome: None,
        },
    );
    let pairing = busbar_core_connector::datagram::Pairing::new(
        Arc::new(Quiet),
        "127.0.0.1:3478".parse().unwrap(),
    );
    c.pair(UNIT, pairing).expect("the session registers");

    let target = format!("tst://127.0.0.1:{port}/v1/offer");
    let conn = c
        .open(
            PLANE,
            NeedId(0),
            &OpenDesc {
                target: &target,
                fields: &[("content-type", b"application/sdp")],
                body: b"",
                timeout_ms: 5_000,
                method: b"POST",
                head_target: b"/v1/offer",
                within: &[],
                member: MEMBER,
                unit: UNIT,
            },
        )
        .expect("the upstream leg opens");

    // Drive the connection until the whole signalling request reached the far end.
    let whole = |w: &[u8]| {
        w.windows(4)
            .position(|x| x == b"\r\n\r\n")
            .is_some_and(|at| w.len() >= at + 4 + media::OFFER.len())
    };
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    let mut buf = vec![0_u8; 4096];
    while !whole(&seen.lock().unwrap()) {
        assert!(
            std::time::Instant::now() < deadline,
            "the signalling request reaches the far end: {:?}",
            String::from_utf8_lossy(&seen.lock().unwrap())
        );
        let _ = tokio::time::timeout(
            std::time::Duration::from_millis(50),
            std::future::poll_fn(|cx| c.poll_read(PLANE, conn, cx, &mut buf)),
        )
        .await;
    }

    let wire = seen.lock().unwrap().clone();
    let (first, wire_fields, body) = read_wire(&wire);
    assert_eq!(first, "POST /v1/offer TST/1");
    assert_eq!(
        body,
        media::OFFER,
        "the signalling body is the datagram framer's description"
    );
    let signed = signer.signed.lock().unwrap().clone();
    assert_eq!(signed.len(), 1, "one auth call");
    let (handle, method, path, authority, head) = &signed[0];
    assert_eq!(*handle, 9, "served on the session's attempt's handle");
    assert_eq!(wire_fields[0].0, "authorization", "the auth's line first");
    let after: Vec<(Vec<u8>, Vec<u8>)> = wire_fields[1..]
        .iter()
        .map(|(n, v)| (n.as_bytes().to_vec(), v.clone()))
        .collect();
    assert_eq!(
        &after, head,
        "the signalling request carries exactly the head the auth signed, and nothing after"
    );
    let expected = format!(
        "Sig {:016x}",
        digest(&canonical(method, path, authority, head))
    );
    assert_eq!(wire_fields[0].1, expected.as_bytes());
    let _ = c.close(PLANE, conn);
    c.unpair(UNIT);
    attempt_auth::forget(UNIT);
}
