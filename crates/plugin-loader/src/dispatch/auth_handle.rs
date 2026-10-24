// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE AUTH HANDLE'S REFS, HOST SIDE (BUSBAR-1.6.0.md Part 2 #74, the untrusted-ABI half, and #65;
//! THE DESIGN, Auth points and guest lists): minting and verifying the two kernel-MAC'd refs a
//! transport hands back on the auth handle's services, [`AuthRef`] and [`UnitRef`].
//!
//! THE PRIMITIVE IS THE INSTANCE HANDLE'S. Both refs are tagged with the same keyed SipHash-2-4,
//! under the same 128-bit key drawn from the OS random source at the loader's boot
//! ([`super::handle::arm`]), that tags every instance handle and permutes every ticket generation;
//! each under its own domain word, so a tag minted for one is never a tag for another. No new
//! crypto and no second key: the key never leaves host memory, and its one residual is the one #75
//! accepts (a native plugin that reads process memory).
//!
//! * An [`AuthRef`]'s `mac` covers (owner, configuration generation, `id`). It is OWNER-SCOPED:
//!   the owner is the calling instance's identity on the instance table, so a ref minted for one
//!   transport and presented by another does not verify; and a ref of an older generation does not
//!   verify against the current one.
//! * A [`UnitRef`]'s `mac` covers (the request's own kernel secret, generation, owner, line, unit):
//!   a unit replayed from another request (another secret), for another line or by another owner
//!   does not verify.
//!
//! Every comparison folds the whole difference before it is judged (constant time), and a refusal
//! names no reason a guesser could steer by beyond "not minted".
//!
//! THE GENERATION. The kernel publishes the configuration generation its guest lists and bindings
//! belong to ([`publish_generation`]); a ref is verified against the published one. Until the
//! kernel publishes one it is `0`.

use std::sync::atomic::{AtomicU64, Ordering};

use busbar_contract::abi::host::service::{AuthRef, UnitRef};

use super::handle::{key, siphash24};

/// Domain separation: an auth ref's tag is never an instance handle's, a ticket's or a unit's.
const DOMAIN_AUTH_REF: u64 = u64::from_le_bytes(*b"bb.aref1");
/// Domain separation: a unit ref's tag is never an auth ref's.
const DOMAIN_UNIT_REF: u64 = u64::from_le_bytes(*b"bb.unit1");

/// The configuration generation the kernel last published.
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

/// The text of [`RefRefused::Absent`].
pub const REF_ABSENT: &str = "the call names no handle";
/// The text of [`RefRefused::NotMinted`].
pub const REF_NOT_MINTED: &str =
    "the handle is not one the host minted for this caller at this generation";
/// The text of [`RefRefused::NoKey`].
pub const REF_NO_KEY: &str = "the host holds no key to verify the handle";

impl RefRefused {
    /// The interned refusal text, valid for the process's life.
    #[must_use]
    pub const fn text(self) -> &'static str {
        match self {
            Self::Absent => REF_ABSENT,
            Self::NotMinted => REF_NOT_MINTED,
            Self::NoKey => REF_NO_KEY,
        }
    }
}

/// Publish the configuration generation refs are verified against. The kernel's, at boot and at
/// each reload, once the generation's guest lists and bindings are built.
pub fn publish_generation(generation: u64) {
    GENERATION.store(generation, Ordering::Release);
}

/// The configuration generation refs are verified against now.
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

/// The top bit: set on every binding id, clear on every line id.
const BINDING_BIT: u64 = 1 << 63;

/// The next id of `space`, never `0` and never one of the other space. Each space counts on its
/// own; a holder that keeps an id stable across generations allocates it once (the ref's mac
/// carries the generation).
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

/// The space id `id` was drawn from; `None` for `0` (no handle).
#[must_use]
pub const fn space_of(id: u64) -> Option<RefSpace> {
    match id {
        0 => None,
        i if i & BINDING_BIT != 0 => Some(RefSpace::Binding),
        _ => Some(RefSpace::Line),
    }
}

/// The tag of an auth ref.
fn auth_tag(key: (u64, u64), owner: u64, generation: u64, id: u64) -> u64 {
    siphash24(key, &[DOMAIN_AUTH_REF, owner, generation, id])
}

/// The tag of a unit ref.
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

/// `want` against `got`, the whole difference folded before it is judged.
fn same(want: u64, got: u64) -> bool {
    std::hint::black_box(want ^ got) == 0
}

/// Mint the ref of line or binding `id` for `owner` (the instance identity of the transport that
/// will present it) at `generation`. `None` for `id == 0` or when the host's key cannot be drawn.
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

/// Verify a presented auth ref for `owner` (the calling instance) at `generation`; the line or
/// binding id it names.
///
/// # Errors
///
/// [`RefRefused::Absent`] for no ref; [`RefRefused::NotMinted`] for a ref of another owner, of
/// another generation, or with a forged `mac`; [`RefRefused::NoKey`] when the key cannot be drawn.
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

/// Mint unit `unit`'s ref for one request: its kernel secret, the generation, the owner (the
/// transport's instance identity) and the line it matched. `None` for `unit == 0` or when the key
/// cannot be drawn.
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

/// Verify a presented unit ref against the request's own secret, the generation, the owner and the
/// line; the unit it names.
///
/// # Errors
///
/// [`RefRefused::Absent`] for no unit; [`RefRefused::NotMinted`] for a unit of another request,
/// generation, owner or line, or a forged `mac`; [`RefRefused::NoKey`] when the key cannot be
/// drawn.
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

// ── the kernel's side of the handle, as the loader calls it ─────────────────────────────────

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
    // Never a field value: a field line may carry the credential.
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

/// Where a pended `auth.call`'s answer goes: called once, from any thread. `Err` is REFUSED with
/// that text.
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

/// THE KERNEL'S SIDE OF THE HOST AUTH HANDLE (THE DESIGN §6, "Auth points and guest lists", step 4;
/// Part 2 #65, #74), as the loader calls it. The composition root installs one on the dispatcher
/// ([`Dispatcher::install_auth_handle`](super::Dispatcher::install_auth_handle)) over the kernel's
/// inbound module; the loader names no kernel crate. Every call reaches it only after the loader
/// verified the call's refs, its unit (against [`AuthHandleHost::unit_secret`]) and its `in`.
pub trait AuthHandleHost: Send + Sync {
    /// The secret, generation and line `owner`'s live unit `unit` was minted under; `None` for a
    /// unit the kernel holds no record of for that owner (the loader then refuses it).
    fn unit_secret(&self, owner: u64, unit: u64) -> Option<UnitSecret>;

    /// `auth.call`: answer at once, or keep `done` and answer [`AuthRan::Pending`] (the call pends).
    fn auth_call(&self, ask: AuthCallAsk, done: AuthDone) -> AuthRan;

    /// `unit.hand_in`: `(flow, unit)`, or REFUSED with the text. Never pends.
    ///
    /// # Errors
    ///
    /// The kernel serves no list for the caller, or holds no record of its unit.
    fn hand_in(&self, ask: HandInAsk) -> Result<(u32, UnitRef), &'static str>;

    /// `unit.refuse`: the refusal's bytes, or REFUSED with the text. Never pends.
    ///
    /// # Errors
    ///
    /// The kernel serves no list for the caller, or the cause names no line it holds.
    fn refuse(&self, ask: RefuseAsk) -> Result<RefusalBytes, &'static str>;

    /// THE FRAMING ENDED: the loader retired the ticket `framing` names (the connection side it
    /// drove was dropped). Everything the kernel holds for that framing goes.
    fn framing_ended(&self, framing: u64);
}

/// The host's identity of the framing a ticket drives: its slot and its generation, which no
/// later minting of the slot repeats.
#[must_use]
pub const fn framing_of(t: busbar_contract::abi::mechanism::ticket::Ticket) -> u64 {
    // The contract's one reading, the connector's too (`Framing::framing_id`).
    t.framing()
}
