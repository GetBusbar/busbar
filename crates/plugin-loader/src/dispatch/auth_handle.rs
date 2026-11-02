// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use busbar_contract::abi::host::service::{AuthRef, UnitRef};

use super::handle::{key, siphash24};

const DOMAIN_AUTH_REF: u64 = u64::from_le_bytes(*b"bb.aref1");

const DOMAIN_UNIT_REF: u64 = u64::from_le_bytes(*b"bb.unit1");

static GENERATION: AtomicU64 = AtomicU64::new(0);

/// Why a ref was refused. Each has one interned text ([`RefRefused::text`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RefRefused {
    /// The ref names nothing (`id == 0`).
    Absent,
    /// The `mac` is not the one the host mints for this owner, generation and id: a ref of another
    /// owner, of another generation, or forged.
    NotMinted,
    /// The host's key could not be drawn (the boot refuses first; this is the fail-closed arm).
    NoKey,
}

pub const REF_ABSENT: &str = "the call names no handle";

pub const REF_NOT_MINTED: &str =
    "the handle is not one the host minted for this caller at this generation";

pub const REF_NO_KEY: &str = "the host holds no key to verify the handle";

impl RefRefused {
    #[must_use]
    pub const fn text(self) -> &'static str {
        match self {
            Self::Absent => REF_ABSENT,
            Self::NotMinted => REF_NOT_MINTED,
            Self::NoKey => REF_NO_KEY,
        }
    }
}

pub fn publish_generation(generation: u64) {
    GENERATION.store(generation, Ordering::Release);
}

#[must_use]
pub fn generation() -> u64 {
    GENERATION.load(Ordering::Acquire)
}

/// THE TWO SPACES AN AUTH REF'S ID IS DRAWN FROM: an inbound guest-list LINE's, top bit clear,
/// and an outbound BINDING's, top bit set. One allocator for both ([`next_ref_id`]), so a line's id
/// is never a binding's: whoever looks an id up holds the table of its space ([`space_of`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RefSpace {
    /// An inbound line: ids `1..=2^63-1`.
    Line,
    /// An outbound binding: ids with the top bit set.
    Binding,
}

const BINDING_BIT: u64 = 1 << 63;

#[must_use]
pub fn next_ref_id(space: RefSpace) -> u64 {
    static LINES: AtomicU64 = AtomicU64::new(0);
    static BINDINGS: AtomicU64 = AtomicU64::new(0);
    let (counter, tag) = match space {
        RefSpace::Line => (&LINES, 0),
        RefSpace::Binding => (&BINDINGS, BINDING_BIT),
    };
    let n = counter.fetch_add(1, Ordering::Relaxed) % (BINDING_BIT - 1) + 1;
    tag | n
}

#[must_use]
pub const fn space_of(id: u64) -> Option<RefSpace> {
    match id {
        0 => None,
        i if i & BINDING_BIT != 0 => Some(RefSpace::Binding),
        _ => Some(RefSpace::Line),
    }
}

fn auth_tag(key: (u64, u64), owner: u64, generation: u64, id: u64) -> u64 {
    siphash24(key, &[DOMAIN_AUTH_REF, owner, generation, id])
}

fn unit_tag(
    key: (u64, u64),
    secret: [u64; 2],
    generation: u64,
    owner: u64,
    line: u32,
    unit: u64,
) -> u64 {
    siphash24(
        key,
        &[
            DOMAIN_UNIT_REF,
            secret[0],
            secret[1],
            generation,
            owner,
            u64::from(line),
            unit,
        ],
    )
}

fn same(want: u64, got: u64) -> bool {
    std::hint::black_box(want ^ got) == 0
}

#[must_use]
pub fn mint_auth_ref(owner: u64, generation: u64, id: u64) -> Option<AuthRef> {
    if id == 0 {
        return None;
    }
    let key = key().ok()?;
    Some(AuthRef {
        id,
        mac: auth_tag(key, owner, generation, id),
    })
}

pub fn verify_auth_ref(owner: u64, generation: u64, r: &AuthRef) -> Result<u64, RefRefused> {
    if r.is_none() {
        return Err(RefRefused::Absent);
    }
    let key = key().map_err(|_| RefRefused::NoKey)?;
    if !same(auth_tag(key, owner, generation, r.id), r.mac) {
        return Err(RefRefused::NotMinted);
    }
    Ok(r.id)
}

#[must_use]
pub fn mint_unit_ref(
    secret: [u64; 2],
    generation: u64,
    owner: u64,
    line: u32,
    unit: u64,
) -> Option<UnitRef> {
    if unit == 0 {
        return None;
    }
    let key = key().ok()?;
    Some(UnitRef {
        id: unit,
        mac: unit_tag(key, secret, generation, owner, line, unit),
    })
}

pub fn verify_unit_ref(
    secret: [u64; 2],
    generation: u64,
    owner: u64,
    line: u32,
    r: &UnitRef,
) -> Result<u64, RefRefused> {
    if r.is_none() {
        return Err(RefRefused::Absent);
    }
    let key = key().map_err(|_| RefRefused::NoKey)?;
    if !same(unit_tag(key, secret, generation, owner, line, r.id), r.mac) {
        return Err(RefRefused::NotMinted);
    }
    Ok(r.id)
}

/// One request's head as a transport lent it ([`HeadView`](busbar_contract::abi::host::service::HeadView)),
/// copied out of the caller's memory before anything else runs: neutral fields only.
#[derive(Clone, Default, PartialEq, Eq)]
pub struct HeadCopy {
    /// The method.
    pub method: String,
    /// The target's path, as received.
    pub target: String,
    /// The authority.
    pub authority: String,
    /// The query without `?`; `None` = absent.
    pub query: Option<String>,
    /// The field lines, in order, as received: (name, value). A value may be a credential.
    pub fields: Vec<(String, Vec<u8>)>,
}

impl std::fmt::Debug for HeadCopy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HeadCopy")
            .field("method", &self.method)
            .field("target", &self.target)
            .finish_non_exhaustive()
    }
}

/// `auth.call`, as the loader hands it to the kernel once the refs, the unit and the `in` passed
/// their checks.
#[derive(Debug)]
pub struct AuthCallAsk {
    /// The calling instance's identity: the owner its refs verified for.
    pub owner: u64,
    /// The generation its ref verified at.
    pub generation: u64,
    /// The verified ref's id: the line or binding the kernel minted it for.
    pub auth: u64,
    /// The presented unit, verified by the loader when not [`UnitRef::NONE`].
    pub unit: UnitRef,
    /// The point bit.
    pub point: u32,
    /// The connection.
    pub conn: u64,
    /// The stream on it.
    pub stream: u64,
    /// The request; empty at the peer point.
    pub request: HeadCopy,
    /// The whole body, at the body point only.
    pub body: Option<Vec<u8>>,
    /// THE FRAMING the call was made on: the ticket of the framer op it was made inside
    /// ([`framing_of`]), the host's own identity of the connection side, never the transport's
    /// word. Its end is [`AuthHandleHost::framing_ended`].
    pub framing: u64,
    /// What remains of the deadline of the framer op the call was made in (its ticket was minted
    /// for that op with its deadline class): `None` = none (a write-behind op, or no deadline).
    pub deadline: Option<std::time::Duration>,
}

/// What `auth.call` answers a transport: continue or stop, the request's unit, and the NAMES the
/// auths named for stripping, each with its `FIELD_SENSITIVE` / `FIELD_QUERY` flag. Never a value
/// and never the verdict (THE DESIGN §6 "Auth points and guest lists", step 4).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthCallAnswer {
    /// `FLOW_CONTINUE` | `FLOW_STOP`.
    pub flow: u32,
    /// The request's unit.
    pub unit: UnitRef,
    /// The names to strip and their flags.
    pub strips: Vec<(String, u32)>,
}

pub type AuthDone = Box<dyn FnOnce(Result<AuthCallAnswer, &'static str>) + Send>;

/// How the kernel ran an `auth.call`.
#[derive(Debug)]
pub enum AuthRan {
    /// Finished: the answer, or REFUSED with the text.
    Now(Result<AuthCallAnswer, &'static str>),
    /// The kernel kept the [`AuthDone`] and answers through it; the call pends on its ticket.
    Pending,
}

/// `unit.hand_in`, as the loader hands it to the kernel.
#[derive(Debug)]
pub struct HandInAsk {
    /// The calling instance's identity.
    pub owner: u64,
    /// The generation its ref verified at.
    pub generation: u64,
    /// The verified ref's id.
    pub auth: u64,
    /// The presented unit (verified when not [`UnitRef::NONE`]).
    pub unit: UnitRef,
    /// The line the transport matched.
    pub line: u32,
    /// The connection.
    pub conn: u64,
    /// The stream on it.
    pub stream: u64,
    /// The request, after the transport stripped what the auth named.
    pub request: HeadCopy,
    /// The framing the hand-in was made on ([`framing_of`] its ticket); `None` for a ticketless
    /// hand-in.
    pub framing: Option<u64>,
}

/// `unit.refuse`, as the loader hands it to the kernel.
#[derive(Debug)]
pub struct RefuseAsk {
    /// The calling instance's identity.
    pub owner: u64,
    /// The published generation.
    pub generation: u64,
    /// The presented unit (verified when not [`UnitRef::NONE`]).
    pub unit: UnitRef,
    /// `REFUSE_*`.
    pub cause: u32,
    /// The matched line; `LINE_NONE` for no route.
    pub line: u32,
    /// The connection.
    pub conn: u64,
    /// The stream on it.
    pub stream: u64,
    /// The host framing making the refusal, absent for a ticketless call.
    pub framing: Option<u64>,
    /// The request being refused (`UnitRefuseIn::request`): its path shapes a refusal with no unit
    /// as 1.5.5's router shaped it.
    pub request: HeadCopy,
}

/// The refusal the kernel owns: status, head fields and body, framed verbatim by the transport.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RefusalBytes {
    /// The status.
    pub status: u16,
    /// The head fields, in order.
    pub fields: Vec<(String, Vec<u8>)>,
    /// The body.
    pub body: Vec<u8>,
}

/// The secret a live unit's ref was minted under, and what else its MAC covers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UnitSecret {
    /// The request's own kernel secret.
    pub secret: [u64; 2],
    /// The generation it was minted at.
    pub generation: u64,
    /// The line it was minted for.
    pub line: u32,
}

/// An immutable policy loan selected by the serving host, never by a transport.
#[derive(Debug, Clone)]
pub struct StreamPolicy {
    /// The actual listener, generation and route rows.
    pub policy: Arc<busbar_contract::abi::transport::guest_policy::Policy>,
    /// The full policy extension, encoded once per generation.
    pub full: Arc<[u8]>,
    /// The small unchanged-policy acknowledgement extension.
    pub current: Arc<[u8]>,
}

pub trait AuthHandleHost: Send + Sync {
    fn unit_secret(&self, owner: u64, unit: u64) -> Option<UnitSecret>;

    fn auth_call(&self, ask: AuthCallAsk, done: AuthDone) -> AuthRan;

    fn hand_in(&self, ask: HandInAsk) -> Result<(u32, UnitRef), &'static str>;

    fn hand_in_with_deadline(
        &self,
        ask: HandInAsk,
        _deadline: Option<std::time::Duration>,
    ) -> Result<(u32, UnitRef), &'static str> {
        self.hand_in(ask)
    }

    fn refuse(&self, ask: RefuseAsk) -> Result<RefusalBytes, &'static str>;

    fn framing_started(
        &self,
        _owner: u64,
        _listener: u64,
        _framing: u64,
    ) -> Result<Option<StreamPolicy>, &'static str> {
        Ok(None)
    }

    fn requires_scope(&self) -> bool {
        false
    }

    fn stream_open(
        &self,
        _owner: u64,
        _listener: u64,
        _framing: u64,
        _stream: u64,
    ) -> Result<StreamPolicy, &'static str> {
        Err("the host serves no stream policy")
    }

    fn stream_ended(&self, _owner: u64, _framing: u64, _stream: u64) {}

    fn framing_ready(&self, _owner: u64, _framing: u64) {}

    fn framing_detached(&self, _owner: u64, _framing: u64) -> Result<(), &'static str> {
        Err("the host cannot detach an admitted session")
    }

    fn framing_adopting(
        &self,
        _source: busbar_contract::framing_scope::AdoptionSource,
        _owner: u64,
        _framing: u64,
    ) -> Result<busbar_contract::framing_scope::SessionTransfer, &'static str> {
        Err("the host cannot transfer an admitted session")
    }

    fn framing_adopted(&self, _owner: u64, _framing: u64, _conn: u64) -> Result<(), &'static str> {
        Err("the host has no staged session")
    }

    fn framing_ended(&self, framing: u64);
}

#[must_use]
pub const fn framing_of(t: busbar_contract::abi::mechanism::ticket::Ticket) -> u64 {
    ((t.slot as u64) << 32) | t.generation as u64
}

static NONE_LINES: std::sync::Mutex<Vec<(u64, u64)>> = std::sync::Mutex::new(Vec::new());

static NONE_UNITS: AtomicU64 = AtomicU64::new(0);

#[must_use]
pub fn lend_none_line(owner: u64, id: u64) -> Option<AuthRef> {
    let r = mint_auth_ref(owner, generation(), id)?;
    let mut lines = NONE_LINES
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    if !lines.contains(&(owner, id)) {
        lines.push((owner, id));
    }
    Some(r)
}

#[must_use]
pub fn is_none_line(owner: u64, id: u64) -> bool {
    NONE_LINES
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .contains(&(owner, id))
}

#[must_use]
pub fn mint_none_unit(owner: u64, line: u32) -> Option<UnitRef> {
    let unit = NONE_UNITS.fetch_add(1, Ordering::Relaxed) + 1;
    let key = key().ok()?;
    let secret = [
        siphash24(key, &[DOMAIN_UNIT_REF, owner, unit, 1]),
        siphash24(key, &[DOMAIN_UNIT_REF, owner, unit, 2]),
    ];
    mint_unit_ref(secret, generation(), owner, line, unit)
}
