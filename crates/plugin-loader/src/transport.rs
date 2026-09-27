// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Loading a **TRANSPORT** over the HOT-tier ABI ([`busbar_contract::abi::hot::transport`]) — the
//! transport analogue of [`crate::plane`] (#3: a transport is swappable, compiled in OR dropped in;
//! #30: it rides the HOT lane).
//!
//! ONE ADMISSION, BOTH DOORS. A transport dropped into `plugins/` reaches the host as a
//! [`DynTransport`] through [`load_transport_from_bytes`] (the signed-tarball path, via
//! [`PluginRegistry::open_transport`](crate::registry::PluginRegistry::open_transport)); a decl
//! handed over by address reaches it through [`link_transport`]. Both run [`assemble`]: the frozen
//! preamble, the transport-decl major, the attested-size bound and the capped reads of the ROW — every
//! constant the transport declares, as the same [`TransportRow`] a linked transport's type yields — so
//! a registry cannot tell which door a row came in by.
//!
//! THE INVERSE OF THE LOWERING. [`DynTransport::build`] runs the decl's `init` and answers the built
//! transport as the contract's own trait object: a [`DeclCarrier`] ([`Carrier`]) or a [`DeclFramer`]
//! ([`Framer`]), each method one call of the slot named for it. So a dropped-in transport is driven
//! through exactly the methods a linked one implements, by the same host code.
//!
//! # The carrier's poll slots and the host's waker
//!
//! No carrier slot blocks: each answers Ready | Pending | Error at once. A method polled with `cx`
//! registers `cx`'s waker with the [`WakeToken`] of its connection and direction, and hands the slot
//! that token's number; the transport keeps it and wakes it through [`HOST_WAKER`] — the `#[repr(C)]`
//! [`WireWaker`] every built transport is handed at `init`. A token is a number the host resolves in
//! its own table ([`host_wake`]), so the transport holds no pointer into the host (#40(c)).
//!
//! # The image stays mapped
//!
//! The slots are the per-request hot path, so they run INLINE on the caller's thread (#30), and a
//! transport's own I/O driver may arm thread-locals on those threads. A library whose code a
//! thread-local destructor still points into must not be unmapped under that thread, so a loaded
//! transport's image is mapped for the life of the process. Build-time crossings (`init` and the
//! state's `free`) run confined, as a plane's do.

use crate::stage;
use busbar_contract::abi::hot::decl::{DeclStr, OpaqueHandle};
use busbar_contract::abi::hot::transport::{
    code, CarrierSlots, DeclByteList, DeclStrList, FramerSlots, RawWireOutcome, TransportDecl,
    WireBytesOut, WireConnFacts, WireDest, WireEnvPair, WireField, WireFramed, WireFramerOut,
    WireOutcome, WireSettings, WireWaker, FRAMED_HAS_RETRY_AFTER, FRAMED_HAS_STATUS_CODE, NO_WAKER,
    TRANSPORT_DECL_MAJOR, TRANSPORT_DECL_MINOR,
};
use busbar_contract::abi::hot::TransportDeclFn;
use busbar_contract::abi::{check_preamble, AbiPreamble};
use busbar_contract::grammar::SelectorForm;
use busbar_contract::ids::StreamId;
use busbar_contract::transport::wire::{
    CloseReason, Encode, Handoff, HandshakeTrigger, TransportError,
};
use busbar_contract::transport::{
    BytesOut, Carrier, CarrierFacts, CarrierPoll, ConnFacts, Dest, Framed, Framer, FramerOut,
    Located, Role, Side, TransportRow, TransportSettings,
};
use busbar_contract::{AbiVersion, Kind, Plugin};
use core::mem::MaybeUninit;
use futures::task::AtomicWaker;
use libloading::Library;
use std::collections::HashMap;
use std::os::raw::c_void;
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, Waker};

/// Cap on the key and every declared string (plugin-attested lengths, capped before any slice is
/// formed — the same discipline as a plane's vocabulary).
const MAX_TRANSPORT_STR_LEN: usize = 256;

/// Cap on every declared list's entries.
const MAX_LIST: usize = 64;

/// Cap on an address, peer or name a slot writes back (a socket address is tens of bytes).
const MAX_ADDR_LEN: usize = 1024;

// ── the host's waker handle ─────────────────────────────────────────────────────────────────────

/// THE HOST'S WAKER HANDLE, handed to every transport's `init`: one function, [`host_wake`].
pub static HOST_WAKER: WireWaker = WireWaker {
    size: core::mem::size_of::<WireWaker>() as u32,
    version: busbar_contract::abi::ABI_MINOR,
    wake: Some(host_wake),
};

/// The table a token resolves in: slot `i` holds its generation and, while a [`WakeToken`] holds it,
/// the waker cell of the task waiting on it. Token = `generation << 32 | (i + 1)`, so no live token
/// is [`NO_WAKER`] and a slot reused after its token dropped answers a stale token with nothing.
struct Wakers {
    slots: Vec<(u32, Option<Arc<AtomicWaker>>)>,
    free: Vec<usize>,
}

static WAKERS: Mutex<Wakers> = Mutex::new(Wakers {
    slots: Vec::new(),
    free: Vec::new(),
});

fn wakers() -> std::sync::MutexGuard<'static, Wakers> {
    WAKERS
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// THE ONE FUNCTION a transport calls: wake the task `token` names, if it still waits. Any thread,
/// any time; a stale or unknown token is ignored. Never unwinds.
pub extern "C-unwind" fn host_wake(token: u64) {
    let (generation, index) = ((token >> 32) as u32, (token & 0xffff_ffff) as usize);
    let Some(index) = index.checked_sub(1) else {
        return;
    };
    let cell = match wakers().slots.get(index) {
        Some((held, Some(cell))) if *held == generation => Arc::clone(cell),
        _ => return,
    };
    cell.wake();
}

/// One host task's registration for a poll slot: the token it hands the slot and the waker the
/// slot wakes through it. Register the task's waker, then poll with [`Self::id`]; dropping it
/// retires the token.
pub struct WakeToken {
    id: u64,
    cell: Arc<AtomicWaker>,
}

impl WakeToken {
    /// Mint a token.
    #[must_use]
    pub fn new() -> Self {
        let cell = Arc::new(AtomicWaker::new());
        let mut table = wakers();
        let index = match table.free.pop() {
            Some(index) => index,
            None => {
                table.slots.push((0, None));
                table.slots.len() - 1
            }
        };
        let slot = &mut table.slots[index];
        slot.0 = slot.0.wrapping_add(1);
        slot.1 = Some(Arc::clone(&cell));
        let id = u64::from(slot.0) << 32 | (index as u64 + 1);
        Self { id, cell }
    }

    /// The token a poll slot is handed.
    #[must_use]
    pub fn id(&self) -> u64 {
        self.id
    }

    /// The task to wake when a slot polled with this token may progress. Register BEFORE the poll,
    /// so a wake that lands between the two is not lost.
    pub fn register(&self, waker: &Waker) {
        self.cell.register(waker);
    }
}

impl Default for WakeToken {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for WakeToken {
    fn drop(&mut self) {
        let index = (self.id & 0xffff_ffff) as usize - 1;
        let mut table = wakers();
        table.slots[index].1 = None;
        table.free.push(index);
    }
}

impl std::fmt::Debug for WakeToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("WakeToken").field(&self.id).finish()
    }
}

// ── the admitted transport ──────────────────────────────────────────────────────────────────────

/// A transport admitted over the HOT-tier ABI: its declared row, owned, and its decl, read through
/// the sized guard. Holds the mapped library (when it came in dropped in) for the life of the
/// process — see the module docs.
pub struct DynTransport {
    decl: *const TransportDecl,
    row: TransportRow,
    init: busbar_contract::abi::hot::transport::WireInitFn,
    carrier: Option<CarrierSlots>,
    framer: Option<FramerSlots>,
    path: String,
    _lib: Option<Library>,
    _backing: Option<stage::Staged>,
}

// SAFETY: `decl` points into an image the transport guarantees is immutable for its life (and that
// image is never unmapped, see `Drop`); the row and slot tables are copied out at load.
unsafe impl Send for DynTransport {}
// SAFETY: see the `Send` impl above.
unsafe impl Sync for DynTransport {}

/// Every transport image this process has mapped, with its staged backing: held here from the moment
/// its [`DynTransport`] drops until the process exits (module docs).
static PINNED: std::sync::Mutex<Vec<(Library, Option<stage::Staged>)>> =
    std::sync::Mutex::new(Vec::new());

impl Drop for DynTransport {
    fn drop(&mut self) {
        if let Some(lib) = self._lib.take() {
            PINNED
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .push((lib, self._backing.take()));
        }
    }
}

impl std::fmt::Debug for DynTransport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DynTransport")
            .field("key", &self.row.key)
            .field("composes_over", &self.row.composes_over)
            .field("path", &self.path)
            .finish()
    }
}

/// The deployment's [`TransportSettings`] as the `#[repr(C)]` [`WireSettings`] a transport's `init` is
/// handed: one resolution of the operator's limits reaches both doors.
#[must_use]
pub fn wire_settings(settings: &TransportSettings) -> WireSettings {
    WireSettings::of(settings)
}

/// A built transport, as the contract's own trait object of its role.
#[derive(Clone)]
pub enum Built {
    /// A carrier.
    Carrier(Arc<dyn Carrier>),
    /// A framer.
    Framer(Arc<dyn Framer>),
}

impl std::fmt::Debug for Built {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Built::Carrier(c) => f.debug_tuple("Carrier").field(&c.key()).finish(),
            Built::Framer(x) => f.debug_tuple("Framer").field(&x.key()).finish(),
        }
    }
}

impl DynTransport {
    /// Every constant the transport declares — the same row a linked transport's type yields.
    #[must_use]
    pub fn row(&self) -> &TransportRow {
        &self.row
    }

    /// The transport's registry key.
    #[must_use]
    pub fn key(&self) -> &'static str {
        self.row.key
    }

    /// The layers it declares it composes over, in declared order.
    #[must_use]
    pub fn composes_over(&self) -> &'static [&'static str] {
        self.row.composes_over
    }

    /// Whether it carries sessions.
    #[must_use]
    pub fn session(&self) -> bool {
        self.row.session
    }

    /// Its role (derived from what it composes over).
    #[must_use]
    pub fn role(&self) -> Role {
        self.row.role()
    }

    /// The decl it was admitted with.
    #[must_use]
    pub fn decl(&self) -> *const TransportDecl {
        self.decl
    }

    /// BUILD the transport from `settings` — the linked row's constructor, over the ABI's `init`
    /// (handed [`HOST_WAKER`]) — as the contract's trait object of its role. Confined: a per-build
    /// crossing.
    ///
    /// # Errors
    ///
    /// The transport's `init` refused, or answered no state.
    pub fn build(&'static self, settings: &WireSettings) -> Result<Built, WireOutcome> {
        let image = self.init(settings)?;
        Ok(match (self.carrier, self.framer) {
            (Some(slots), None) => Built::Carrier(Arc::new(DeclCarrier {
                image,
                slots,
                tokens: Mutex::new(HashMap::new()),
            })),
            (None, Some(slots)) => Built::Framer(Arc::new(DeclFramer { image, slots })),
            // `assemble` admits exactly one slot table.
            _ => return Err(WireOutcome::Fault),
        })
    }

    /// Run the decl's `init` over `settings`, handed [`HOST_WAKER`]: the built state. Confined.
    fn init(&'static self, settings: &WireSettings) -> Result<Image, WireOutcome> {
        let init = self.init;
        let mut out = MaybeUninit::<OpaqueHandle>::uninit();
        let out_ptr: *mut MaybeUninit<OpaqueHandle> = &mut out;
        let settings_ptr: *const WireSettings = settings;
        let waker: *const WireWaker = &HOST_WAKER;
        let status = crate::ffi_guard_confined(&self.path, "transport_init", || {
            init(settings_ptr, waker, out_ptr)
        })
        .map_err(|_| WireOutcome::Fault)?
        .outcome();
        if status != WireOutcome::Ok {
            return Err(status);
        }
        // SAFETY: init-only-on-Ok — the transport wrote `out` before answering `Ok`.
        let state = unsafe { out.assume_init() };
        if state.ptr.is_null() {
            return Err(WireOutcome::Fault);
        }
        Ok(Image { wire: self, state })
    }

    /// The decl-backed carrier itself, for a test that crosses one slot with nothing around it.
    #[cfg(test)]
    pub(crate) fn decl_carrier(&'static self, settings: &WireSettings) -> DeclCarrier {
        DeclCarrier {
            image: self.init(settings).expect("the carrier builds"),
            slots: self.carrier.expect("a carrier"),
            tokens: Mutex::new(HashMap::new()),
        }
    }
}

/// One built transport's state, freed through its own `free` on drop.
struct Image {
    wire: &'static DynTransport,
    state: OpaqueHandle,
}

// SAFETY: the state is the transport's own, synchronised by the transport (the HOT-lane call
// discipline has the host call the slots from any thread, several at once). The host never reads
// through the state pointer; it only hands it back to the slots and, once, to `free`.
unsafe impl Send for Image {}
// SAFETY: see the `Send` impl above.
unsafe impl Sync for Image {}

impl Drop for Image {
    fn drop(&mut self) {
        let (Some(free), ptr) = (self.state.free, self.state.ptr) else {
            return;
        };
        if crate::ffi_guard_confined(&self.wire.path, "transport_free", || free(ptr)).is_err() {
            tracing::warn!(
                plugin = %self.wire.path,
                "transport state free panicked; leaking the state to keep the engine alive"
            );
        }
    }
}

impl Image {
    /// One guarded crossing into slot `what`.
    fn call(&self, what: &str, f: impl FnOnce(*mut c_void) -> RawWireOutcome) -> WireOutcome {
        let ptr = self.state.ptr;
        crate::ffi_guard(&self.wire.path, what, || f(ptr))
            .map_or(WireOutcome::Fault, RawWireOutcome::outcome)
    }

    fn key(&self) -> &'static str {
        self.wire.row.key
    }
}

/// An answer that is ready or refused (never pending: the slot answers at once).
fn done(outcome: WireOutcome) -> Result<(), TransportError> {
    match outcome {
        WireOutcome::Ok => Ok(()),
        other => Err(other.error()),
    }
}

/// A poll slot's answer.
fn poll_of<T>(
    outcome: WireOutcome,
    value: impl FnOnce() -> Result<T, TransportError>,
) -> CarrierPoll<T> {
    match outcome {
        WireOutcome::Ok => Poll::Ready(value()),
        WireOutcome::Pending => Poll::Pending,
        other => Poll::Ready(Err(other.error())),
    }
}

/// The UTF-8 string a slot wrote into `buf[..len]`.
fn written(buf: &[u8], len: usize) -> Result<String, TransportError> {
    let bytes = buf.get(..len).ok_or(TransportError::Closed)?;
    std::str::from_utf8(bytes)
        .map(str::to_string)
        .map_err(|_| TransportError::Closed)
}

/// A borrowed range of a host string, for the call.
fn range(s: &str) -> DeclStr {
    DeclStr {
        ptr: s.as_ptr(),
        len: s.len(),
    }
}

// ── the decl-backed carrier ─────────────────────────────────────────────────────────────────────

/// A dropped-in (or decl-linked) CARRIER as the contract's [`Carrier`]: each method one call of the
/// slot named for it.
pub struct DeclCarrier {
    image: Image,
    slots: CarrierSlots,
    /// The token each handle's waits hand the slots, by handle and direction.
    tokens: Mutex<HashMap<(u64, u8), Arc<WakeToken>>>,
}

/// The direction a token is keyed under.
const ACCEPT: u8 = 0;
const READ: u8 = 1;
const WRITE: u8 = 2;
const CLOSE: u8 = 3;

impl DeclCarrier {
    /// The token for `(handle, dir)`, registered with `cx`'s waker.
    fn token(&self, handle: u64, dir: u8, cx: &Context<'_>) -> u64 {
        let token = Arc::clone(
            self.tokens
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .entry((handle, dir))
                .or_insert_with(|| Arc::new(WakeToken::new())),
        );
        token.register(cx.waker());
        token.id()
    }

    /// Retire every token `handle` holds.
    fn forget(&self, handle: u64) {
        let mut tokens = self
            .tokens
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        // A listener's accept is keyed in its own space: a connection that shares its number is not
        // it, and retiring the listener's token would lose the wake of its next arrival.
        for dir in [READ, WRITE, CLOSE] {
            tokens.remove(&(handle, dir));
        }
    }
}

#[cfg(test)]
impl DeclCarrier {
    /// One `poll_flush` crossing, nothing around it: the #30 measurement's floor.
    pub(crate) fn raw_poll_flush(&self, conn: u64) -> WireOutcome {
        let f = self.slots.poll_flush.expect("the carrier flushes");
        let state = self.image.state.ptr;
        f(state, conn, NO_WAKER).outcome()
    }
}

impl std::fmt::Debug for DeclCarrier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DeclCarrier")
            .field("key", &self.image.key())
            .finish()
    }
}

impl Plugin for DeclCarrier {
    fn key(&self) -> &'static str {
        self.image.key()
    }
    fn kind(&self) -> Kind {
        Kind::Transport
    }
    fn abi(&self) -> AbiVersion {
        busbar_contract::transport::TRANSPORT_ABI
    }
}

impl Carrier for DeclCarrier {
    fn listen(&self, bind: &str) -> Result<(u64, String), TransportError> {
        let f = self.slots.listen.ok_or(TransportError::Closed)?;
        let mut addr = [0_u8; MAX_ADDR_LEN];
        let (mut addr_len, mut listener) = (0_usize, 0_u64);
        done(self.image.call("transport_listen", |s| {
            f(
                s,
                bind.as_ptr(),
                bind.len(),
                addr.as_mut_ptr(),
                addr.len(),
                &mut addr_len,
                &mut listener,
            )
        }))?;
        Ok((listener, written(&addr, addr_len)?))
    }

    fn poll_accept(&self, listener: u64, cx: &mut Context<'_>) -> CarrierPoll<(u64, String)> {
        let Some(f) = self.slots.poll_accept else {
            return Poll::Ready(Err(TransportError::Closed));
        };
        let token = self.token(listener, ACCEPT, cx);
        let mut peer = [0_u8; MAX_ADDR_LEN];
        let (mut peer_len, mut conn) = (0_usize, 0_u64);
        let outcome = self.image.call("transport_poll_accept", |s| {
            f(
                s,
                listener,
                token,
                peer.as_mut_ptr(),
                peer.len(),
                &mut peer_len,
                &mut conn,
            )
        });
        poll_of(outcome, || Ok((conn, written(&peer, peer_len)?)))
    }

    fn dial(&self, dest: &Dest<'_>) -> Result<u64, TransportError> {
        let f = self.slots.dial.ok_or(TransportError::Closed)?;
        let (args, env): (Vec<DeclStr>, Vec<WireEnvPair>) = match dest {
            Dest::Authority(_) => (Vec::new(), Vec::new()),
            Dest::Program { args, env, .. } => (
                args.iter().map(|a| range(a)).collect(),
                env.iter()
                    .map(|(n, v)| WireEnvPair {
                        name: range(n),
                        value: range(v),
                    })
                    .collect(),
            ),
        };
        let wire = WireDest {
            size: core::mem::size_of::<WireDest>() as u32,
            kind: u8::from(matches!(dest, Dest::Program { .. })),
            _reserved: [0; 3],
            authority: match dest {
                Dest::Authority(a) => range(a),
                Dest::Program { .. } => DeclStr::NONE,
            },
            program: match dest {
                Dest::Program { program, .. } => range(program),
                Dest::Authority(_) => DeclStr::NONE,
            },
            args: DeclStrList {
                ptr: args.as_ptr(),
                len: args.len(),
            },
            env: env.as_ptr(),
            env_len: env.len(),
        };
        let mut conn = 0_u64;
        done(
            self.image
                .call("transport_dial", |s| f(s, &wire, &mut conn)),
        )?;
        Ok(conn)
    }

    fn poll_read(&self, conn: u64, cx: &mut Context<'_>, buf: &mut [u8]) -> CarrierPoll<usize> {
        let Some(f) = self.slots.poll_read else {
            return Poll::Ready(Err(TransportError::Closed));
        };
        let token = self.token(conn, READ, cx);
        let (cap, mut n) = (buf.len(), 0_usize);
        let outcome = self.image.call("transport_poll_read", |s| {
            f(s, conn, token, buf.as_mut_ptr(), cap, &mut n)
        });
        // A slot that claims more bytes than the buffer holds is a fault, never trusted.
        poll_of(outcome, || {
            if n > cap {
                Err(TransportError::Closed)
            } else {
                Ok(n)
            }
        })
    }

    fn poll_write(&self, conn: u64, cx: &mut Context<'_>, bytes: &[u8]) -> CarrierPoll<usize> {
        let Some(f) = self.slots.poll_write else {
            return Poll::Ready(Err(TransportError::Closed));
        };
        let token = self.token(conn, WRITE, cx);
        let mut n = 0_usize;
        let outcome = self.image.call("transport_poll_write", |s| {
            f(s, conn, token, bytes.as_ptr(), bytes.len(), &mut n)
        });
        // Taking more than it was offered, or none of a non-empty offer, is a fault.
        poll_of(outcome, || {
            if n > bytes.len() || (n == 0 && !bytes.is_empty()) {
                Err(TransportError::Closed)
            } else {
                Ok(n)
            }
        })
    }

    fn poll_flush(&self, conn: u64, cx: &mut Context<'_>) -> CarrierPoll<()> {
        let Some(f) = self.slots.poll_flush else {
            return Poll::Ready(Err(TransportError::Closed));
        };
        let token = self.token(conn, WRITE, cx);
        let outcome = self
            .image
            .call("transport_poll_flush", |s| f(s, conn, token));
        poll_of(outcome, || Ok(()))
    }

    fn poll_close(&self, conn: u64, cx: &mut Context<'_>, reason: CloseReason) -> CarrierPoll<()> {
        let Some(f) = self.slots.poll_close else {
            return Poll::Ready(Err(TransportError::Closed));
        };
        let token = if cx.waker().will_wake(Waker::noop()) {
            NO_WAKER
        } else {
            self.token(conn, CLOSE, cx)
        };
        let reason = code::close_reason(reason);
        let outcome = self
            .image
            .call("transport_poll_close", |s| f(s, conn, token, reason));
        let closed = poll_of(outcome, || Ok(()));
        if closed.is_ready() {
            self.forget(conn);
        }
        closed
    }

    fn arrival(&self, conn: u64) -> Option<CarrierFacts> {
        let f = self.slots.arrival?;
        let mut peer = [0_u8; MAX_ADDR_LEN];
        let (mut peer_len, mut local_port) = (0_usize, 0_u16);
        done(self.image.call("transport_arrival", |s| {
            f(
                s,
                conn,
                peer.as_mut_ptr(),
                peer.len(),
                &mut peer_len,
                &mut local_port,
            )
        }))
        .ok()?;
        Some(CarrierFacts {
            peer: written(&peer, peer_len).ok()?,
            local_port,
        })
    }
}

// ── the decl-backed framer ──────────────────────────────────────────────────────────────────────

/// A dropped-in (or decl-linked) FRAMER as the contract's [`Framer`]: each method one call of the
/// slot named for it, its outputs handed straight back to the caller's own sink.
pub struct DeclFramer {
    image: Image,
    slots: FramerSlots,
}

impl std::fmt::Debug for DeclFramer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DeclFramer")
            .field("key", &self.image.key())
            .finish()
    }
}

impl Plugin for DeclFramer {
    fn key(&self) -> &'static str {
        self.image.key()
    }
    fn kind(&self) -> Kind {
        Kind::Transport
    }
    fn abi(&self) -> AbiVersion {
        busbar_contract::transport::TRANSPORT_ABI
    }
}

/// `ctx` is a `*mut &mut dyn FramerOut` for the call.
extern "C-unwind" fn out_send(ctx: *mut c_void, bytes: *const u8, len: usize) {
    let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        if ctx.is_null() || (bytes.is_null() && len != 0) {
            return;
        }
        // SAFETY: `ctx` is the caller's sink for this call (see `framer_out`), and the framer hands a
        // live `len`-byte range for the callback.
        let (out, bytes) = unsafe {
            (
                &mut **ctx.cast::<&mut dyn FramerOut>(),
                if len == 0 {
                    &[][..]
                } else {
                    std::slice::from_raw_parts(bytes, len)
                },
            )
        };
        out.send(bytes);
    }));
}

/// `ctx` is a `*mut &mut dyn FramerOut` for the call.
extern "C-unwind" fn out_frame(ctx: *mut c_void, piece: *const WireFramed) {
    let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        if ctx.is_null() || piece.is_null() {
            return;
        }
        // SAFETY: the framer hands a live sized `WireFramed` for the callback, read only as far as
        // it attests.
        let p = unsafe {
            let size = core::ptr::read_unaligned(core::ptr::addr_of!((*piece).size)) as usize;
            if size < core::mem::size_of::<WireFramed>() {
                return;
            }
            core::ptr::read_unaligned(piece)
        };
        if p.bytes.is_null() && p.len != 0 {
            return;
        }
        let Ok(status) = code::status_class_of(p.status_class) else {
            return;
        };
        // SAFETY: `ctx` is the caller's sink for this call, and `p.bytes` a live `p.len`-byte range.
        let (out, bytes) = unsafe {
            (
                &mut **ctx.cast::<&mut dyn FramerOut>(),
                if p.len == 0 {
                    &[][..]
                } else {
                    std::slice::from_raw_parts(p.bytes, p.len)
                },
            )
        };
        out.frame(Framed {
            stream: StreamId(p.stream),
            bytes,
            end_of_frame: p.end_of_frame == 1,
            status,
            status_code: (p.flags & FRAMED_HAS_STATUS_CODE != 0).then_some(p.status_code),
            retry_after_secs: (p.flags & FRAMED_HAS_RETRY_AFTER != 0).then_some(p.retry_after_secs),
        });
    }));
}

/// `ctx` is a `*mut &mut dyn FramerOut` for the call.
extern "C-unwind" fn out_end(ctx: *mut c_void) {
    let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        if ctx.is_null() {
            return;
        }
        // SAFETY: `ctx` is the caller's sink for this call.
        unsafe { (**ctx.cast::<&mut dyn FramerOut>()).end() };
    }));
}

/// `ctx` is a `*mut &mut dyn BytesOut` for the call.
extern "C-unwind" fn bytes_put(ctx: *mut c_void, bytes: *const u8, len: usize) {
    let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        if ctx.is_null() || (bytes.is_null() && len != 0) {
            return;
        }
        // SAFETY: `ctx` is the caller's sink for this call, and the framer hands a live range.
        let (out, bytes) = unsafe {
            (
                &mut **ctx.cast::<&mut dyn BytesOut>(),
                if len == 0 {
                    &[][..]
                } else {
                    std::slice::from_raw_parts(bytes, len)
                },
            )
        };
        out.put(bytes);
    }));
}

/// The host callbacks over the caller's sink, valid while `sink` is borrowed.
fn framer_out(sink: &mut &mut dyn FramerOut) -> WireFramerOut {
    WireFramerOut {
        ctx: (sink as *mut &mut dyn FramerOut).cast(),
        send: out_send,
        frame: out_frame,
        end: out_end,
    }
}

/// The host callback over the caller's byte sink, valid while `sink` is borrowed.
fn bytes_out(sink: &mut &mut dyn BytesOut) -> WireBytesOut {
    WireBytesOut {
        ctx: (sink as *mut &mut dyn BytesOut).cast(),
        put: bytes_put,
    }
}

/// The facts connection security established, borrowed as they cross.
fn wire_facts(facts: &ConnFacts) -> WireConnFacts {
    let opt = |s: Option<&String>| s.map_or(DeclStr::NONE, |s| range(s));
    let cert = facts.peer_cert.as_ref();
    WireConnFacts {
        size: core::mem::size_of::<WireConnFacts>() as u32,
        version: TRANSPORT_DECL_MAJOR,
        sni: opt(facts.sni.as_ref()),
        alpn: opt(facts.alpn.as_ref()),
        cert_subject: opt(cert.map(|c| &c.subject)),
        cert_issuer: opt(cert.map(|c| &c.issuer)),
        cert_fingerprint: opt(cert.map(|c| &c.fingerprint)),
    }
}

impl Framer for DeclFramer {
    fn locate(&self, target: &str) -> Result<Located, TransportError> {
        let f = self.slots.locate.ok_or(TransportError::Closed)?;
        let (mut auth, mut name) = ([0_u8; MAX_ADDR_LEN], [0_u8; MAX_ADDR_LEN]);
        let (mut auth_len, mut name_len, mut secure) = (0_usize, 0_usize, 0_u8);
        done(self.image.call("transport_locate", |s| {
            f(
                s,
                target.as_ptr(),
                target.len(),
                auth.as_mut_ptr(),
                auth.len(),
                &mut auth_len,
                name.as_mut_ptr(),
                name.len(),
                &mut name_len,
                &mut secure,
            )
        }))?;
        Ok(Located {
            authority: written(&auth, auth_len)?,
            secure: secure == 1,
            server_name: if name_len == usize::MAX {
                None
            } else {
                Some(written(&name, name_len)?)
            },
        })
    }

    fn open(
        &self,
        side: Side,
        target: &str,
        facts: &ConnFacts,
        mut out: &mut dyn FramerOut,
    ) -> Result<u64, TransportError> {
        let f = self.slots.open.ok_or(TransportError::Closed)?;
        let (facts, sink) = (wire_facts(facts), framer_out(&mut out));
        let mut state = 0_u64;
        done(self.image.call("transport_open", |s| {
            f(
                s,
                code::side(side),
                target.as_ptr(),
                target.len(),
                &facts,
                &sink,
                &mut state,
            )
        }))?;
        Ok(state)
    }

    fn ingest(
        &self,
        state: u64,
        bytes: &[u8],
        end: bool,
        mut out: &mut dyn FramerOut,
    ) -> Result<(), TransportError> {
        let f = self.slots.ingest.ok_or(TransportError::Closed)?;
        let sink = framer_out(&mut out);
        done(self.image.call("transport_ingest", |s| {
            f(s, state, bytes.as_ptr(), bytes.len(), u8::from(end), &sink)
        }))
    }

    fn emit(
        &self,
        state: u64,
        stream: StreamId,
        bytes: &[u8],
        end_of_frame: bool,
        mut out: &mut dyn FramerOut,
    ) -> Result<(), TransportError> {
        let f = self.slots.emit.ok_or(TransportError::Closed)?;
        let sink = framer_out(&mut out);
        done(self.image.call("transport_emit", |s| {
            f(
                s,
                state,
                stream.0,
                bytes.as_ptr(),
                bytes.len(),
                u8::from(end_of_frame),
                &sink,
            )
        }))
    }

    fn encode_envelope(
        &self,
        fields: &[(&str, &[u8])],
        body: &[u8],
        mut out: &mut dyn BytesOut,
    ) -> Result<(), Encode> {
        let f = self.slots.encode_envelope.ok_or(Encode::Poisoned)?;
        let fields: Vec<WireField> = fields
            .iter()
            .map(|(name, value)| WireField {
                name: range(name),
                value: DeclStr {
                    ptr: value.as_ptr(),
                    len: value.len(),
                },
            })
            .collect();
        let sink = bytes_out(&mut out);
        match self.image.call("transport_encode_envelope", |s| {
            f(
                s,
                fields.as_ptr(),
                fields.len(),
                body.as_ptr(),
                body.len(),
                &sink,
            )
        }) {
            WireOutcome::Ok => Ok(()),
            other => Err(other.encode_error()),
        }
    }

    fn refusal(
        &self,
        state: u64,
        stream: Option<StreamId>,
        bytes: &[u8],
        mut out: &mut dyn FramerOut,
    ) -> Result<(), TransportError> {
        let f = self.slots.refusal.ok_or(TransportError::Closed)?;
        let sink = framer_out(&mut out);
        done(self.image.call("transport_refusal", |s| {
            f(
                s,
                state,
                u8::from(stream.is_some()),
                stream.map_or(0, |s| s.0),
                bytes.as_ptr(),
                bytes.len(),
                &sink,
            )
        }))
    }

    fn close(&self, state: u64, reason: CloseReason, mut out: &mut dyn FramerOut) {
        let Some(f) = self.slots.close else {
            return;
        };
        let sink = framer_out(&mut out);
        let reason = code::close_reason(reason);
        let _ = self
            .image
            .call("transport_close", |s| f(s, state, reason, &sink));
    }

    fn detach(&self, state: u64, mut out: &mut dyn BytesOut) -> Result<(), TransportError> {
        let f = self.slots.detach.ok_or(TransportError::HandoffMismatch)?;
        let sink = bytes_out(&mut out);
        done(self.image.call("transport_detach", |s| f(s, state, &sink)))
    }

    fn adopt(
        &self,
        side: Side,
        facts: &ConnFacts,
        leftover: &[u8],
        mut out: &mut dyn FramerOut,
    ) -> Result<u64, TransportError> {
        let f = self.slots.adopt.ok_or(TransportError::HandoffMismatch)?;
        let (facts, sink) = (wire_facts(facts), framer_out(&mut out));
        let mut state = 0_u64;
        done(self.image.call("transport_adopt", |s| {
            f(
                s,
                code::side(side),
                &facts,
                leftover.as_ptr(),
                leftover.len(),
                &sink,
                &mut state,
            )
        }))?;
        Ok(state)
    }
}

// ── the admission ───────────────────────────────────────────────────────────────────────────────

/// Load a transport from EXACTLY the verified library `bytes` (the TOCTOU-safe entrypoint, as
/// [`crate::plane::load_plane_from_bytes`]). `manifest_kind` is the trust-verified signed-manifest
/// `kind`, cross-checked against `busbar_plugin_kind()`.
///
/// # Errors
///
/// The library does not load, is not a transport, or its decl is refused.
pub fn load_transport_from_bytes(
    bytes: &[u8],
    display: &str,
    manifest_kind: &str,
) -> Result<DynTransport, String> {
    let (lib, staged) = stage::load_library_from_bytes(bytes, display)?;
    wire_up_transport(lib, display.to_string(), manifest_kind, Some(staged))
}

/// Load a transport from the `cdylib` at `lib_path`. A bare path load has no signed manifest, so the
/// seam's expected kind (`transport`) is the authority; [`load_transport_from_bytes`] is the real
/// gate for a dropped-in tarball.
///
/// # Errors
///
/// As [`load_transport_from_bytes`].
#[cold]
#[inline(never)]
pub fn load_transport(lib_path: &Path) -> Result<DynTransport, String> {
    let display = lib_path.display().to_string();
    let lib = crate::dlopen_on_worker(lib_path.as_os_str())
        .map_err(|e| format!("failed to load transport '{display}': {e}"))?;
    wire_up_transport(
        lib,
        display,
        busbar_contract::abi::cold::kind::TRANSPORT,
        None,
    )
}

/// Admit a transport decl handed over by address through exactly the admission a dropped-in one
/// gets.
///
/// # Safety
/// `decl`, when non-null, must address a `'static`, immutable transport decl laid out as
/// [`TransportDecl`] (at least its attested prefix), whose borrowed ranges live as long.
///
/// # Errors
///
/// The decl is refused (see [`assemble`]).
pub unsafe fn link_transport(
    decl: *const TransportDecl,
    display: &str,
) -> Result<DynTransport, String> {
    assemble(decl, display.to_string(), None, None)
}

/// The handshake, the kind, then the decl — the plane's `wire_up_plane`, for a transport.
fn wire_up_transport(
    lib: Library,
    display: String,
    manifest_kind: &str,
    backing: Option<stage::Staged>,
) -> Result<DynTransport, String> {
    let handshake = {
        let f = unsafe {
            lib.get::<busbar_contract::abi::cold::AbiFn>(busbar_contract::abi::cold::symbol::ABI)
        }
        .map_err(|_| format!("'{display}' is not a busbar plugin (no busbar_abi symbol)"))?;
        crate::ffi_guard_confined(&display, "abi", || unsafe { (*f)() })?
    };
    if handshake != busbar_contract::abi::cold::TRANSPORT_VERSION {
        return Err(format!(
            "transport '{display}' targets transport ABI v{handshake}, engine speaks v{}",
            busbar_contract::abi::cold::TRANSPORT_VERSION
        ));
    }
    let exported_kind = crate::read_plugin_kind(&lib, &display)?;
    if exported_kind != busbar_contract::abi::cold::kind::TRANSPORT {
        return Err(format!(
            "transport '{display}' exports kind '{exported_kind}', not 'transport'"
        ));
    }
    if exported_kind != manifest_kind {
        return Err(format!(
            "transport '{display}' kind mismatch: exported symbol says '{exported_kind}', signed \
             manifest says '{manifest_kind}' — refusing to load"
        ));
    }
    let decl = {
        let f = unsafe {
            lib.get::<TransportDeclFn>(busbar_contract::abi::hot::symbol::TRANSPORT_DECL)
        }
        .map_err(|_| format!("transport '{display}' missing busbar_transport_decl symbol"))?;
        crate::ffi_guard_confined(&display, "transport_decl", || unsafe { (*f)() })?
    };
    assemble(decl, display, Some(lib), backing)
}

/// THE ONE ADMISSION both doors run: refuse a null decl, check the FROZEN preamble and the
/// transport-decl major, bound the attested size on both sides, then copy the ROW and the role's
/// slot table out — exactly one table, the one the declared composition derives.
fn assemble(
    decl: *const TransportDecl,
    display: String,
    lib: Option<Library>,
    backing: Option<stage::Staged>,
) -> Result<DynTransport, String> {
    if decl.is_null() {
        return Err(format!("transport '{display}' returned a null decl"));
    }
    // SAFETY: a non-null decl addresses at least its leading preamble, size and version (every decl
    // generation led with them); read by address and unaligned.
    let (abi, advertised, version): (AbiPreamble, u32, u32) = unsafe {
        (
            core::ptr::read_unaligned(core::ptr::addr_of!((*decl).abi)),
            core::ptr::read_unaligned(core::ptr::addr_of!((*decl).size)),
            core::ptr::read_unaligned(core::ptr::addr_of!((*decl).version)),
        )
    };
    check_preamble(&abi).map_err(|e| {
        format!("transport '{display}' decl preamble refused: {e:?} (rebuild it against this ABI)")
    })?;
    if version != TRANSPORT_DECL_MAJOR || abi.abi_minor < TRANSPORT_DECL_MINOR {
        return Err(format!(
            "transport '{display}' states transport-decl generation {version} at airlock minor {}; \
             this build admits generation {TRANSPORT_DECL_MAJOR} (the carrier/framer decl, from \
             minor {TRANSPORT_DECL_MINOR}) — rebuild it against this ABI",
            abi.abi_minor
        ));
    }
    let ours = core::mem::size_of::<TransportDecl>() as u32;
    if advertised < ours {
        return Err(format!(
            "transport '{display}' decl attests size {advertised}, below the {ours}-byte decl — it \
             does not reach its own row and slots"
        ));
    }
    if advertised > ours {
        return Err(format!(
            "transport '{display}' decl attests size {advertised}, exceeding this build's own \
             TransportDecl ({ours} bytes); this build will not call a slot it cannot describe"
        ));
    }
    // SAFETY: the attested size is exactly this build's decl (checked above), and the decl is
    // immutable image data; copied out unaligned.
    let d = unsafe { core::ptr::read_unaligned(decl) };
    let row = read_row(&d, &display)?;
    let init = d
        .init
        .ok_or_else(|| format!("transport '{display}' declares no `init`"))?;
    let (carrier, framer) = match (row.role(), d.carrier.is_null(), d.framer.is_null()) {
        // SAFETY (both arms): a non-null table is the image's own `'static` sized struct.
        (Role::Carrier, false, true) => (
            Some(unsafe { slots::<CarrierSlots>(d.carrier, &display)? }),
            None,
        ),
        (Role::Framer, true, false) => (
            None,
            Some(unsafe { slots::<FramerSlots>(d.framer, &display)? }),
        ),
        (role, ..) => {
            return Err(format!(
                "transport '{display}' composes over {:?}, so it is a {role:?}, and must state \
                 exactly that role's slots",
                row.composes_over
            ))
        }
    };
    Ok(DynTransport {
        decl,
        row,
        init,
        carrier,
        framer,
        path: display,
        _lib: lib,
        _backing: backing,
    })
}

/// A role's slot table, copied out when its attested size is exactly this build's.
///
/// # Safety
/// `table` must address the image's own `'static` table, leading with its `size: u32`.
unsafe fn slots<T: Copy>(table: *const T, display: &str) -> Result<T, String> {
    // SAFETY: per this fn's contract; the size leads every table.
    let size = unsafe { core::ptr::read_unaligned(table.cast::<u32>()) } as usize;
    if size != core::mem::size_of::<T>() {
        return Err(format!(
            "transport '{display}' slot table attests size {size}, not this build's {}",
            core::mem::size_of::<T>()
        ));
    }
    // SAFETY: the whole table is present (checked above).
    Ok(unsafe { core::ptr::read_unaligned(table) })
}

/// The ROW a decl declares, every string and list capped, checked and borrowed for the life of the
/// image (never unmapped, module docs), the lists copied into owned `'static` storage once.
fn read_row(d: &TransportDecl, display: &str) -> Result<TransportRow, String> {
    let key = decl_str(d.key, display)?
        .filter(|k| !k.is_empty())
        .ok_or_else(|| format!("transport '{display}' declares no key"))?;
    let byte = |what: &str, v: u8| format!("transport '{display}' declares {what} byte {v}");
    let flag = |what: &str, v: u8| match v {
        0 => Ok(false),
        1 => Ok(true),
        other => Err(format!(
            "transport '{display}' declares {what} flag {other}; a transport declares 0 or 1"
        )),
    };
    let handoff = match decl_str(d.handoff_from, display)? {
        None => None,
        Some(from) => Some(Handoff {
            from,
            to: decl_str(d.handoff_to, display)?
                .ok_or_else(|| format!("transport '{display}' declares a handoff with no `to`"))?,
            binding_fact: decl_str(d.handoff_binding_fact, display)?.ok_or_else(|| {
                format!("transport '{display}' declares a handoff with no binding fact")
            })?,
        }),
    };
    Ok(TransportRow {
        key,
        composes_over: strs(d.composes_over, display)?,
        selector_forms: forms(d.selector_forms, display)?,
        egress_selector_forms: forms(d.egress_selector_forms, display)?,
        handoff,
        framing: code::framing_of(d.framing).map_err(|v| byte("framing", v))?,
        session: flag("session", d.session)?,
        session_bound: flag("session-bound", d.session_bound)?,
        unit0_trigger: code::unit0_trigger_of(d.unit0_trigger)
            .map_err(|v| byte("first-unit trigger", v))?,
        upgrades_to: strs(d.upgrades_to, display)?,
        handshake_trigger: decl_str(d.handshake_frame_kind, display)?.map(|frame_kind| {
            HandshakeTrigger {
                frame_kind,
                max_steps: d.handshake_max_steps,
            }
        }),
        transport_facts: strs(d.transport_facts, display)?,
        decodes_payload: flag("decodes-payload", d.decodes_payload)?,
        status_at: code::status_at_of(d.status_at).map_err(|v| byte("status position", v))?,
        status_namespace: decl_str(d.status_namespace, display)?,
    })
}

/// A declared string list, owned `'static` (the entries borrow the image).
fn strs(list: DeclStrList, display: &str) -> Result<&'static [&'static str], String> {
    if list.len > MAX_LIST || (list.len > 0 && list.ptr.is_null()) {
        return Err(format!(
            "transport '{display}' declares a {}-entry list it cannot back (null, or past the \
             {MAX_LIST}-entry cap)",
            list.len
        ));
    }
    let entries = (0..list.len)
        .map(|i| {
            // SAFETY: a non-null list addresses `len` live entries (bounded above) for the life of
            // the image; each is copied out unaligned.
            let entry = unsafe { core::ptr::read_unaligned(list.ptr.add(i)) };
            decl_str(entry, display)?
                .ok_or_else(|| format!("transport '{display}' states a null list entry"))
        })
        .collect::<Result<Vec<_>, _>>()?;
    Ok(Box::leak(entries.into_boxed_slice()))
}

/// A declared selector-form list, owned `'static`.
fn forms(list: DeclByteList, display: &str) -> Result<&'static [SelectorForm], String> {
    if list.len > MAX_LIST || (list.len > 0 && list.ptr.is_null()) {
        return Err(format!(
            "transport '{display}' declares a {}-entry form list it cannot back",
            list.len
        ));
    }
    let forms = (0..list.len)
        .map(|i| {
            // SAFETY: a non-null list addresses `len` live bytes (bounded above).
            let b = unsafe { core::ptr::read_unaligned(list.ptr.add(i)) };
            code::selector_form_of(b)
                .ok_or_else(|| format!("transport '{display}' declares selector-form byte {b}"))
        })
        .collect::<Result<Vec<_>, _>>()?;
    Ok(Box::leak(forms.into_boxed_slice()))
}

/// One borrowed range as a string of the image (`None` for NULL), capped before the slice is formed
/// and checked UTF-8. `'static` because the image is never unmapped (module docs).
fn decl_str(d: DeclStr, display: &str) -> Result<Option<&'static str>, String> {
    if d.ptr.is_null() {
        return Ok(None);
    }
    if d.len > MAX_TRANSPORT_STR_LEN {
        return Err(format!(
            "transport '{display}' declares a {}-byte string, past the \
             {MAX_TRANSPORT_STR_LEN}-byte cap — refusing to load",
            d.len
        ));
    }
    // SAFETY: a non-null range addresses `len` (bounded above) immutable bytes of the image, which
    // stays mapped for the life of the process.
    let bytes: &'static [u8] = unsafe { std::slice::from_raw_parts(d.ptr, d.len) };
    std::str::from_utf8(bytes)
        .map(Some)
        .map_err(|_| format!("transport '{display}' declares a string that is not UTF-8"))
}

#[cfg(test)]
#[path = "tests/transport_conformance_tests.rs"]
mod tests;
