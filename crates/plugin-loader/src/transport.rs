// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Loading a **TRANSPORT** over the HOT-tier ABI ([`busbar_plugin::hot::transport`]) — the
//! transport analogue of [`crate::plane`] (#3, OWNER-LOCKED: transport is one of the seven kinds, and
//! a kind is swappable, compiled in OR dropped in over the ABI; #30: transport rides the HOT lane).
//!
//! ONE ADMISSION, BOTH DOORS. A transport dropped into `plugins/` reaches the host as a
//! [`DynTransport`] through [`load_transport_from_bytes`] (the signed-tarball path, via
//! [`PluginRegistry::open_transport`](crate::registry::PluginRegistry::open_transport)); the SAME
//! transport linked into the binary reaches it through [`link_transport`], handed the address of its
//! own `'static` decl. Both run [`assemble`]: the frozen preamble, the attested-size bound, the capped
//! reads of the declared row — so the row a registry holds (the key, the layers it composes over)
//! cannot tell which door it came in by, and neither can the slots, which are the transport's own.
//!
//! A [`DynTransport`] is the row the composition root folds: [`DynTransport::key`],
//! [`DynTransport::composes_over`] and [`DynTransport::build`] — the three things a linked transport
//! row carries (`KEY`, `COMPOSES_OVER`, `build(lower, &TransportSettings)`; [`wire_settings`] is that
//! same `TransportSettings` as the decl's `init` takes it). [`BuiltTransport`] then moves bytes over
//! the built state, through the POLL slots (airlock minor 28).
//!
//! # The poll slots and the host's waker
//!
//! No slot blocks: each answers Ready(n) | Pending | Error at once ([`WirePoll`]). A slot that answers
//! Pending keeps the call's TOKEN and wakes it through the host's waker handle, [`HOST_WAKER`] — the
//! `#[repr(C)]` [`WireWaker`] every built transport is handed at `init`. A token is minted by a
//! [`WakeToken`]: a number the host resolves in its own table ([`host_wake`]) to the task waiting on
//! it, so the transport holds no pointer into the host (#40(c)), and a token woken after its
//! [`WakeToken`] dropped resolves to nothing.
//!
//! # The image stays mapped
//!
//! The byte-moving slots are the per-request hot path, so they run INLINE on the caller's thread
//! (the confined worker handoff costs tens of microseconds; the HOT-lane budget is one, #30), and a
//! transport's own I/O driver may arm thread-locals on those threads. A library whose code a
//! thread-local destructor still points into must not be unmapped under that thread, so a loaded
//! transport's image is mapped for the life of the process: dropping a [`DynTransport`] frees nothing
//! of the image. Build-time crossings (`init` and the state's `free`) run confined, as a plane's do.

use crate::stage;
use busbar_contract::transport::TransportSettings;
use busbar_plugin::hot::decl::{DeclStr, OpaqueHandle};
use busbar_plugin::hot::transport::{
    RawWireOutcome, TransportDecl, WireConfig, WireConnectFn, WireInitFn, WireListenFn, WireLower,
    WireOutcome, WirePollAcceptFn, WirePollCloseFn, WirePollFlushFn, WirePollReadFn,
    WirePollWriteFn, WireSettings, WireWaker, NO_WAKER, TRANSPORT_DECL_MINOR,
};
use busbar_plugin::hot::TransportDeclFn;
use busbar_plugin::{check_preamble, AbiPreamble};
use core::mem::MaybeUninit;
use futures::task::AtomicWaker;
use libloading::Library;
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::task::{Poll, Waker};

/// Cap on the transport key and each composes-over entry (plugin-attested lengths, capped before
/// any slice is formed — the same discipline as a plane's vocabulary).
const MAX_TRANSPORT_STR_LEN: usize = 256;

/// Cap on the composes-over list's entries.
const MAX_COMPOSES_OVER: usize = 64;

/// Cap on an address or peer string a slot writes back (a socket address is tens of bytes).
const MAX_ADDR_LEN: usize = 1024;

/// What a poll slot answered: `Ready(Ok(n))`, `Pending`, or `Ready(Err(outcome))`.
pub type WirePoll<T> = Poll<Result<T, WireOutcome>>;

// ── the host's waker handle ─────────────────────────────────────────────────────────────────────

/// THE HOST'S WAKER HANDLE, handed to every transport's `init`: one function, [`host_wake`].
pub static HOST_WAKER: WireWaker = WireWaker {
    size: core::mem::size_of::<WireWaker>() as u32,
    version: busbar_plugin::ABI_MINOR,
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

/// One host task's registration for the poll slots: the token it hands them and the waker they
/// wake through it. Register the task's waker, then poll with [`Self::id`]; dropping it retires the
/// token.
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

/// A transport admitted over the HOT-tier ABI: its declared row, owned, and its decl, read through
/// the sized guard. Holds the mapped library (when it came in dropped in) for the life of the
/// process — see the module docs.
pub struct DynTransport {
    decl: *const TransportDecl,
    honoured_size: u32,
    key: &'static str,
    composes_over: Vec<&'static str>,
    session: bool,
    path: String,
    _lib: Option<Library>,
    _backing: Option<stage::Staged>,
}

// SAFETY: `decl` points into an image the transport guarantees is immutable for its life (and that
// image is never unmapped, see `Drop`); the row is copied out at load; the slots are code addresses.
unsafe impl Send for DynTransport {}
// SAFETY: see the `Send` impl above.
unsafe impl Sync for DynTransport {}

/// Every transport image this process has mapped, with its staged backing: held here from the moment
/// its [`DynTransport`] drops until the process exits, so no image is unmapped under a thread whose
/// thread-locals may still point into it (module docs).
static PINNED: std::sync::Mutex<Vec<(Library, Option<stage::Staged>)>> =
    std::sync::Mutex::new(Vec::new());

impl Drop for DynTransport {
    fn drop(&mut self) {
        // A linked transport holds no library; a dropped-in one hands its image to `PINNED`.
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
            .field("key", &self.key)
            .field("composes_over", &self.composes_over)
            .field("path", &self.path)
            .finish()
    }
}

/// The deployment's [`TransportSettings`] — what every linked transport's `build` is handed — as
/// the `#[repr(C)]` [`WireSettings`] a HOT-lane transport's `build` is handed: one resolution of the
/// operator's limits reaches both doors.
#[must_use]
pub fn wire_settings(settings: &TransportSettings) -> WireSettings {
    WireSettings {
        size: core::mem::size_of::<WireSettings>() as u32,
        version: TRANSPORT_DECL_MINOR as u16,
        upstream_http1_only: u8::from(settings.upstream_http1_only),
        upstream_h2_prior_knowledge: u8::from(settings.upstream_h2_prior_knowledge),
        pool_max_idle_per_host: settings.pool_max_idle_per_host as u64,
        pool_idle_timeout_secs: settings.pool_idle_timeout_secs,
        request_body_max_bytes: settings.request_body_max_bytes as u64,
        response_body_max_bytes: settings.response_body_max_bytes as u64,
        request_timeout_secs: settings.request_timeout_secs,
    }
}

impl DynTransport {
    /// The transport's registry key, borrowed from the image that declared it (mapped for the life
    /// of the process, see the module docs).
    #[must_use]
    pub fn key(&self) -> &'static str {
        self.key
    }

    /// The keys of the layers this transport declares it can be built over, in declared order, each
    /// borrowed from the image that declared it.
    #[must_use]
    pub fn composes_over(&self) -> &[&'static str] {
        &self.composes_over
    }

    /// Whether this transport carries sessions (the linked row's `SESSION`).
    #[must_use]
    pub fn session(&self) -> bool {
        self.session
    }

    /// The decl this transport was admitted with — what an upper layer's [`WireLower`] names.
    #[must_use]
    pub fn decl(&self) -> *const TransportDecl {
        self.decl
    }

    fn slot_init(&self) -> Option<WireInitFn> {
        busbar_plugin::read_sized_field!(self.decl, self.honoured_size, TransportDecl, init)
            .flatten()
    }
    fn slot_listen(&self) -> Option<WireListenFn> {
        busbar_plugin::read_sized_field!(self.decl, self.honoured_size, TransportDecl, listen)
            .flatten()
    }
    fn slot_connect(&self) -> Option<WireConnectFn> {
        busbar_plugin::read_sized_field!(self.decl, self.honoured_size, TransportDecl, connect)
            .flatten()
    }
    fn slot_poll_accept(&self) -> Option<WirePollAcceptFn> {
        busbar_plugin::read_sized_field!(self.decl, self.honoured_size, TransportDecl, poll_accept)
            .flatten()
    }
    fn slot_poll_read(&self) -> Option<WirePollReadFn> {
        busbar_plugin::read_sized_field!(self.decl, self.honoured_size, TransportDecl, poll_read)
            .flatten()
    }
    fn slot_poll_write(&self) -> Option<WirePollWriteFn> {
        busbar_plugin::read_sized_field!(self.decl, self.honoured_size, TransportDecl, poll_write)
            .flatten()
    }
    fn slot_poll_flush(&self) -> Option<WirePollFlushFn> {
        busbar_plugin::read_sized_field!(self.decl, self.honoured_size, TransportDecl, poll_flush)
            .flatten()
    }
    fn slot_poll_close(&self) -> Option<WirePollCloseFn> {
        busbar_plugin::read_sized_field!(self.decl, self.honoured_size, TransportDecl, poll_close)
            .flatten()
    }

    /// BUILD the transport over `lower` (the built layer under it, `None` = it opens its own socket)
    /// from `settings` — the linked row's `build(lower, settings)`, over the ABI's `init`, which is
    /// handed the host's waker handle ([`HOST_WAKER`]). Confined: a per-build crossing.
    pub fn build<'t>(
        &'t self,
        lower: Option<&BuiltTransport<'_>>,
        settings: &WireSettings,
    ) -> Result<BuiltTransport<'t>, WireOutcome> {
        let f = self.slot_init().ok_or(WireOutcome::Unsupported)?;
        let lower = lower.map(|l| WireLower {
            decl: l.wire.decl,
            state: l.state.ptr,
        });
        let lower_ptr = lower
            .as_ref()
            .map_or(core::ptr::null(), |l| l as *const WireLower);
        let mut out = MaybeUninit::<OpaqueHandle>::uninit();
        let out_ptr: *mut MaybeUninit<OpaqueHandle> = &mut out;
        let settings_ptr: *const WireSettings = settings;
        let waker: *const WireWaker = &HOST_WAKER;
        let status = crate::ffi_guard_confined(&self.path, "transport_init", || {
            f(lower_ptr, settings_ptr, waker, out_ptr)
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
        Ok(BuiltTransport { wire: self, state })
    }
}

/// One built transport: the state its `init` produced, freed through its own `free` on drop, and
/// borrow-bound to the [`DynTransport`] whose slots drive it. No method blocks: `listen` and
/// `connect` answer at once, and the `poll_*` methods answer Ready | Pending | Error — call them
/// inline from the host's reactor, each with the [`WakeToken`] id of the task that will poll again.
pub struct BuiltTransport<'t> {
    wire: &'t DynTransport,
    state: OpaqueHandle,
}

// SAFETY: the state is the transport's own, and the HOT-lane call discipline
// (`busbar_plugin::hot::transport`) has the host poll the slots from its request threads — from any
// thread, several at once — so a transport synchronises its own built state. The host never reads
// through the state pointer; it only hands it back to the slots and, once, to `free`.
unsafe impl Send for BuiltTransport<'_> {}
// SAFETY: see the `Send` impl above.
unsafe impl Sync for BuiltTransport<'_> {}

impl std::fmt::Debug for BuiltTransport<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BuiltTransport")
            .field("key", &self.wire.key)
            .finish_non_exhaustive()
    }
}

impl Drop for BuiltTransport<'_> {
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

/// A slot's answer as a `Result`. A `Pending` from a slot that answers at once is a fault.
fn answered(r: Result<RawWireOutcome, String>) -> Result<(), WireOutcome> {
    match r.map_err(|_| WireOutcome::Fault)?.outcome() {
        WireOutcome::Ok => Ok(()),
        WireOutcome::Pending => Err(WireOutcome::Fault),
        other => Err(other),
    }
}

/// A poll slot's answer: `Ok` is ready with `value()`, `Pending` is pending, anything else refused.
fn poll_answered<T>(
    r: Result<RawWireOutcome, String>,
    value: impl FnOnce() -> Result<T, WireOutcome>,
) -> WirePoll<T> {
    match r.map_or(WireOutcome::Fault, RawWireOutcome::outcome) {
        WireOutcome::Ok => Poll::Ready(value()),
        WireOutcome::Pending => Poll::Pending,
        other => Poll::Ready(Err(other)),
    }
}

/// The UTF-8 string a slot wrote into `buf[..len]`.
fn written(buf: &[u8], len: usize) -> Result<String, WireOutcome> {
    let bytes = buf.get(..len).ok_or(WireOutcome::Fault)?;
    std::str::from_utf8(bytes)
        .map(str::to_string)
        .map_err(|_| WireOutcome::Fault)
}

impl<'t> BuiltTransport<'t> {
    /// The transport this was built from, for as long as it lives.
    #[must_use]
    pub fn transport(&self) -> &'t DynTransport {
        self.wire
    }

    /// Open a listener on `bind`, presenting `config` (the kernel-built opaque handle, if the
    /// accepting end needs one). Answers the listener handle and the address actually bound.
    pub fn listen(
        &self,
        bind: &str,
        config: Option<&WireConfig>,
    ) -> Result<(u64, String), WireOutcome> {
        let f = self.wire.slot_listen().ok_or(WireOutcome::Unsupported)?;
        let config = config.map_or(core::ptr::null(), |c| c as *const WireConfig);
        let mut addr = [0_u8; MAX_ADDR_LEN];
        let (mut addr_len, mut listener) = (0_usize, 0_u64);
        answered(crate::ffi_guard(
            &self.wire.path,
            "transport_listen",
            || {
                f(
                    self.state.ptr,
                    bind.as_ptr(),
                    bind.len(),
                    config,
                    addr.as_mut_ptr(),
                    addr.len(),
                    &mut addr_len,
                    &mut listener,
                )
            },
        ))?;
        Ok((listener, written(&addr, addr_len)?))
    }

    /// BEGIN dialing `authority` (already admitted by the host), presenting `config` if the dialing
    /// end needs one. Answers the connection handle at once; the connection is open once
    /// [`Self::poll_flush`] answers ready.
    pub fn connect(
        &self,
        authority: &str,
        config: Option<&WireConfig>,
    ) -> Result<u64, WireOutcome> {
        let f = self.wire.slot_connect().ok_or(WireOutcome::Unsupported)?;
        let config = config.map_or(core::ptr::null(), |c| c as *const WireConfig);
        let mut conn = 0_u64;
        answered(crate::ffi_guard(
            &self.wire.path,
            "transport_connect",
            || {
                f(
                    self.state.ptr,
                    authority.as_ptr(),
                    authority.len(),
                    config,
                    &mut conn,
                )
            },
        ))?;
        Ok(conn)
    }

    /// POLL `listener` for its next connection: the connection handle and the peer.
    pub fn poll_accept(&self, listener: u64, token: u64) -> WirePoll<(u64, String)> {
        let Some(f) = self.wire.slot_poll_accept() else {
            return Poll::Ready(Err(WireOutcome::Unsupported));
        };
        let mut peer = [0_u8; MAX_ADDR_LEN];
        let (mut peer_len, mut conn) = (0_usize, 0_u64);
        let r = crate::ffi_guard(&self.wire.path, "transport_poll_accept", || {
            f(
                self.state.ptr,
                listener,
                token,
                peer.as_mut_ptr(),
                peer.len(),
                &mut peer_len,
                &mut conn,
            )
        });
        poll_answered(r, || Ok((conn, written(&peer, peer_len)?)))
    }

    /// POLL the next bytes of `conn` into `buf` (non-empty); `Ready(Ok(0))` is the clean end of the
    /// stream. A slot that claims more bytes than `buf` holds is a fault, never trusted.
    pub fn poll_read(&self, conn: u64, token: u64, buf: &mut [u8]) -> WirePoll<usize> {
        let Some(f) = self.wire.slot_poll_read() else {
            return Poll::Ready(Err(WireOutcome::Unsupported));
        };
        let (cap, mut n) = (buf.len(), 0_usize);
        let r = crate::ffi_guard(&self.wire.path, "transport_poll_read", || {
            f(self.state.ptr, conn, token, buf.as_mut_ptr(), cap, &mut n)
        });
        poll_answered(r, || {
            if n > cap {
                Err(WireOutcome::Fault)
            } else {
                Ok(n)
            }
        })
    }

    /// POLL some of `bytes` onto `conn`: how many the transport took. A slot that claims more than it
    /// was offered, or none of a non-empty offer, is a fault.
    pub fn poll_write(&self, conn: u64, token: u64, bytes: &[u8]) -> WirePoll<usize> {
        let Some(f) = self.wire.slot_poll_write() else {
            return Poll::Ready(Err(WireOutcome::Unsupported));
        };
        let mut n = 0_usize;
        let r = crate::ffi_guard(&self.wire.path, "transport_poll_write", || {
            f(
                self.state.ptr,
                conn,
                token,
                bytes.as_ptr(),
                bytes.len(),
                &mut n,
            )
        });
        poll_answered(r, || {
            if n > bytes.len() || (n == 0 && !bytes.is_empty()) {
                Err(WireOutcome::Fault)
            } else {
                Ok(n)
            }
        })
    }

    /// POLL `conn`'s taken bytes — and, for a connection [`Self::connect`] began, its opening — onto
    /// the wire.
    pub fn poll_flush(&self, conn: u64, token: u64) -> WirePoll<()> {
        let Some(f) = self.wire.slot_poll_flush() else {
            return Poll::Ready(Err(WireOutcome::Unsupported));
        };
        let r = crate::ffi_guard(&self.wire.path, "transport_poll_flush", || {
            f(self.state.ptr, conn, token)
        });
        poll_answered(r, || Ok(()))
    }

    /// POLL `conn` closed (idempotent). Polled with [`NO_WAKER`], the transport closes it whether or
    /// not anyone polls again.
    pub fn poll_close(&self, conn: u64, token: u64) -> WirePoll<()> {
        let Some(f) = self.wire.slot_poll_close() else {
            return Poll::Ready(Err(WireOutcome::Unsupported));
        };
        let r = crate::ffi_guard(&self.wire.path, "transport_poll_close", || {
            f(self.state.ptr, conn, token)
        });
        poll_answered(r, || Ok(()))
    }

    /// Close `conn` with nobody waiting: [`Self::poll_close`] with [`NO_WAKER`], its answer dropped.
    pub fn close_now(&self, conn: u64) {
        let _ = self.poll_close(conn, NO_WAKER);
    }
}

/// Load a transport from EXACTLY the verified library `bytes` (the TOCTOU-safe entrypoint, as
/// [`crate::plane::load_plane_from_bytes`]). `manifest_kind` is the trust-verified signed-manifest
/// `kind`, cross-checked against `busbar_plugin_kind()`.
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
#[cold]
#[inline(never)]
pub fn load_transport(lib_path: &Path) -> Result<DynTransport, String> {
    let display = lib_path.display().to_string();
    let lib = crate::dlopen_on_worker(lib_path.as_os_str())
        .map_err(|e| format!("failed to load transport '{display}': {e}"))?;
    wire_up_transport(lib, display, busbar_plugin::cold::kind::TRANSPORT, None)
}

/// Admit a transport LINKED into this binary through exactly the admission a dropped-in one gets,
/// over the address of its own `'static` decl (the one its `busbar_transport_decl` would return).
///
/// # Safety
/// `decl`, when non-null, must address a `'static`, immutable transport decl laid out as
/// [`TransportDecl`] (at least its attested prefix), whose borrowed ranges live as long.
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
        let f = unsafe { lib.get::<busbar_plugin::cold::AbiFn>(busbar_plugin::cold::symbol::ABI) }
            .map_err(|_| format!("'{display}' is not a busbar plugin (no busbar_abi symbol)"))?;
        crate::ffi_guard_confined(&display, "abi", || unsafe { (*f)() })?
    };
    if handshake != busbar_plugin::cold::TRANSPORT_VERSION {
        return Err(format!(
            "transport '{display}' targets transport ABI v{handshake}, engine speaks v{}",
            busbar_plugin::cold::TRANSPORT_VERSION
        ));
    }
    let exported_kind = crate::read_plugin_kind(&lib, &display)?;
    if exported_kind != busbar_plugin::cold::kind::TRANSPORT {
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
        let f = unsafe { lib.get::<TransportDeclFn>(busbar_plugin::hot::symbol::TRANSPORT_DECL) }
            .map_err(|_| {
            format!("transport '{display}' missing busbar_transport_decl symbol")
        })?;
        crate::ffi_guard_confined(&display, "transport_decl", || unsafe { (*f)() })?
    };
    assemble(decl, display, Some(lib), backing)
}

/// THE ONE ADMISSION both doors run: refuse a null decl, check the FROZEN preamble, bound the
/// attested size on both sides (it must reach the last slot of the minor that introduced the decl,
/// and may not exceed this build's), then copy the declared row out.
fn assemble(
    decl: *const TransportDecl,
    display: String,
    lib: Option<Library>,
    backing: Option<stage::Staged>,
) -> Result<DynTransport, String> {
    if decl.is_null() {
        return Err(format!("transport '{display}' returned a null decl"));
    }
    // SAFETY: a non-null decl addresses at least its leading preamble + size (the decl discipline);
    // read by address and unaligned, without forming a `&TransportDecl` over a shorter peer.
    let (abi, advertised): (AbiPreamble, u32) = unsafe {
        (
            core::ptr::read_unaligned(core::ptr::addr_of!((*decl).abi)),
            core::ptr::read_unaligned(core::ptr::addr_of!((*decl).size)),
        )
    };
    check_preamble(&abi).map_err(|e| {
        format!("transport '{display}' decl preamble refused: {e:?} (rebuild it against this ABI)")
    })?;
    if abi.abi_minor < TRANSPORT_DECL_MINOR {
        return Err(format!(
            "transport '{display}' was built at airlock minor {}, before the transport decl this \
             build admits (minor {TRANSPORT_DECL_MINOR}: the poll slots; the blocking slots are \
             retired) — rebuild it against this ABI",
            abi.abi_minor
        ));
    }
    let whole = (core::mem::offset_of!(TransportDecl, poll_close)
        + core::mem::size_of::<Option<WirePollCloseFn>>()) as u32;
    if advertised < whole {
        return Err(format!(
            "transport '{display}' decl attests size {advertised}, below the {whole}-byte decl — \
             it does not reach its own slots and declaration"
        ));
    }
    let ours = core::mem::size_of::<TransportDecl>() as u32;
    if advertised > ours {
        return Err(format!(
            "transport '{display}' decl attests size {advertised}, exceeding this build's own \
             TransportDecl ({ours} bytes); this build will not call a slot it cannot describe"
        ));
    }
    let size = advertised;
    // THE RETIRED BLOCKING SLOTS (minor 28): a decl that still fills one was written for a host that
    // parks a thread per call; this host never calls them, and will not admit a decl expecting it to.
    // SAFETY: `size` reaches past every one of them (checked above), so each field is in the decl.
    let retired = unsafe {
        [
            (
                "build",
                core::ptr::read_unaligned(core::ptr::addr_of!((*decl).build)).is_some(),
            ),
            (
                "accept",
                core::ptr::read_unaligned(core::ptr::addr_of!((*decl).accept)).is_some(),
            ),
            (
                "dial",
                core::ptr::read_unaligned(core::ptr::addr_of!((*decl).dial)).is_some(),
            ),
            (
                "read",
                core::ptr::read_unaligned(core::ptr::addr_of!((*decl).read)).is_some(),
            ),
            (
                "write",
                core::ptr::read_unaligned(core::ptr::addr_of!((*decl).write)).is_some(),
            ),
            (
                "close",
                core::ptr::read_unaligned(core::ptr::addr_of!((*decl).close)).is_some(),
            ),
        ]
    };
    if let Some((slot, _)) = retired.iter().find(|(_, filled)| *filled) {
        return Err(format!(
            "transport '{display}' fills the blocking `{slot}` slot, retired at airlock minor \
             {TRANSPORT_DECL_MINOR} — a transport speaks the poll slots"
        ));
    }
    let field = |what: &str| format!("transport '{display}' decl does not reach its `{what}`");
    let key = decl_str(
        busbar_plugin::read_sized_field!(decl, size, TransportDecl, key)
            .ok_or_else(|| field("key"))?,
        &display,
    )?
    .filter(|k| !k.is_empty())
    .ok_or_else(|| format!("transport '{display}' declares no key"))?;
    let list_ptr = busbar_plugin::read_sized_field!(decl, size, TransportDecl, composes_over_ptr)
        .ok_or_else(|| field("composes_over_ptr"))?;
    let list_len = busbar_plugin::read_sized_field!(decl, size, TransportDecl, composes_over_len)
        .ok_or_else(|| field("composes_over_len"))?;
    if list_len > MAX_COMPOSES_OVER || (list_len > 0 && list_ptr.is_null()) {
        return Err(format!(
            "transport '{display}' declares {list_len} composes-over entries it cannot back \
             (null list, or past the {MAX_COMPOSES_OVER}-entry cap)"
        ));
    }
    let composes_over = (0..list_len)
        .map(|i| {
            // SAFETY: a non-null list addresses `list_len` live entries (bounded above) for the life
            // of the image; each is copied out unaligned.
            let entry = unsafe { core::ptr::read_unaligned(list_ptr.add(i)) };
            decl_str(entry, &display)?
                .ok_or_else(|| format!("transport '{display}' states a null composes-over entry"))
        })
        .collect::<Result<Vec<_>, _>>()?;
    let session = match busbar_plugin::read_sized_field!(decl, size, TransportDecl, session)
        .ok_or_else(|| field("session"))?
    {
        0 => false,
        1 => true,
        other => {
            return Err(format!(
                "transport '{display}' declares session flag {other}; a transport declares 0 or 1"
            ))
        }
    };
    Ok(DynTransport {
        decl,
        honoured_size: size,
        key,
        composes_over,
        session,
        path: display,
        _lib: lib,
        _backing: backing,
    })
}

/// One borrowed range as a string of the image (`None` for NULL), capped before the slice is formed
/// and checked UTF-8. `'static` because the image is: a linked decl's ranges are the binary's own
/// `'static` data, and a loaded image is never unmapped (module docs, [`PINNED`]).
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
    // stays mapped for the life of the process (a linked decl's are `'static`; a loaded image is
    // pinned, never unmapped).
    let bytes: &'static [u8] = unsafe { std::slice::from_raw_parts(d.ptr, d.len) };
    std::str::from_utf8(bytes)
        .map(Some)
        .map_err(|_| format!("transport '{display}' declares a string that is not UTF-8"))
}

#[cfg(test)]
#[path = "tests/transport_conformance_tests.rs"]
mod tests;
