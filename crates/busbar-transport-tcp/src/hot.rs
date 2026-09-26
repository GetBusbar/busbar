// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE HOT-LANE DOOR (#3, #30, #40, #84): this transport as a `#[repr(C)]` decl, so it is swappable
//! compiled in OR dropped in. [`TRANSPORT_DECL`] is the one decl both doors hand the host: a build
//! that links this crate passes its address to the loader's `link_transport`; the `cdylib` built with
//! the `dropped-in` feature exports it as `busbar_transport_decl` (with `busbar_abi` and
//! `busbar_plugin_kind`) for the loader's `load_transport`. The same slots run whichever door the host
//! came in by.
//!
//! # A layout, not a crate (#84, #40(a))
//!
//! This crate's dependency closure is the contract and nothing else, so it does not link the crate
//! that DEFINES the HOT lane: [`layout`] restates the published `#[repr(C)]` layout it implements —
//! the frozen airlock preamble, the decl's header and slot order — the way a C author includes a
//! header. The host re-checks every byte of it at load (the preamble, the attested size), and the
//! loader's conformance test compares every offset of [`layout::TransportDecl`] against the host's
//! own, so a drift is a red test, never a silent misread.
//!
//! # What the slots are (airlock minor 28: the POLL shape)
//!
//! [`TRANSPORT_DECL`]'s row IS the linked row ([`crate::linked`]): its key, the layers it composes
//! over and whether it carries sessions are [`crate::linked::KEY`], [`crate::linked::COMPOSES_OVER`]
//! and [`crate::linked::SESSION`], and `init` constructs the transport exactly as
//! [`crate::linked::build`] does (this wire takes no lower layer and reads no setting). Its slots are
//! one-line bridges onto the SAME helpers the [`Transport`](busbar_contract::Transport)
//! implementation runs — the dial (`dialing`), the reads and writes (`poll_read_into`,
//! `poll_write_on`, `poll_flush_on`), `register` and `close` — poll-shaped: NO SLOT BLOCKS. A slot
//! that cannot progress answers `Pending` and keeps the call's token; the socket's readiness is
//! delivered by this wire's own I/O reactor (one thread per built instance, driving its sockets and
//! its dial clock), which calls the host's `wake(token)` — the waker handle the host passed to
//! `init`. The host polls again inline, on its own thread; the bytes move on that thread.
//!
//! `listen` binds SO_REUSEPORT on unix: the host listens once per acceptor on one address (its
//! per-core fan-out, the same model as its own data listeners).
//!
//! Every slot catches its own panics and answers the fault byte — a panic cannot unwind out of a
//! dropped-in image. Configuration handles and the build settings are accepted and not read: this
//! wire opens its own socket, carries no key material and reads no setting. The six slots the
//! airlock retired at minor 28 (`build`, `accept`, `dial`, `read`, `write`, `close`) are `None`.

#![allow(unsafe_code)]

use std::collections::HashMap;
use std::future::Future;
use std::net::SocketAddr;
use std::os::raw::c_void;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, Waker};

use busbar_contract::transport::wire::{CloseReason, Conn, TransportError};
use busbar_contract::Transport;
use core::mem::MaybeUninit;
use tokio::net::TcpStream;

use crate::TcpTransport;

/// The published HOT-lane layout this transport implements, restated (see the module docs).
pub mod layout {
    use core::mem::MaybeUninit;
    use std::os::raw::c_void;

    /// The airlock magic every HOT-lane peer stamps.
    pub const ABI_MAGIC: u64 = u64::from_le_bytes(*b"BUSPLANE");
    /// The airlock major this decl is laid out for.
    pub const ABI_MAJOR: u32 = 2;
    /// The airlock minor this decl is laid out at (the first minor with the POLL-shaped decl).
    pub const ABI_MINOR: u32 = 28;
    /// The shared library handshake `busbar_abi` answers.
    pub const HANDSHAKE_VERSION: u32 = 1;

    /// The slot answers this transport writes (the host's outcome vocabulary, by discriminant).
    pub mod outcome {
        /// Done.
        pub const OK: u8 = 0;
        /// The far side refused the connection.
        pub const REFUSED: u8 = 1;
        /// A deadline expired.
        pub const TIMEOUT: u8 = 2;
        /// The connection was reset.
        pub const RESET: u8 = 3;
        /// Closed, or an unknown handle.
        pub const CLOSED: u8 = 4;
        /// The secure handshake failed.
        pub const HANDSHAKE_FAILED: u8 = 5;
        /// Configuration could not be resolved.
        pub const KEY_UNAVAILABLE: u8 = 6;
        /// The address was not admissible.
        pub const ADDRESS_REFUSED: u8 = 7;
        /// The far side stopped reading.
        pub const BACKPRESSURE: u8 = 8;
        /// The bytes broke this transport's framing.
        pub const FRAMING: u8 = 9;
        /// A handoff neither leg declared.
        pub const HANDOFF_MISMATCH: u8 = 10;
        /// An internal fault (a caught panic, an unusable argument).
        pub const FAULT: u8 = 12;
        /// A poll slot's "not yet": the call's token is woken once it may progress.
        pub const PENDING: u8 = 13;
    }

    /// The token that names no waiting task.
    pub const NO_WAKER: u64 = 0;

    /// The frozen airlock header.
    #[repr(C)]
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct AbiPreamble {
        /// [`ABI_MAGIC`].
        pub magic: u64,
        /// [`ABI_MAJOR`].
        pub abi_major: u32,
        /// [`ABI_MINOR`].
        pub abi_minor: u32,
    }

    /// A borrowed UTF-8 range (NULL = absent).
    #[repr(C)]
    #[derive(Debug, Clone, Copy)]
    pub struct DeclStr {
        /// The bytes.
        pub ptr: *const u8,
        /// Their length.
        pub len: usize,
    }

    impl DeclStr {
        /// A stated string, borrowed for the life of the image.
        #[must_use]
        pub const fn new(s: &'static str) -> Self {
            DeclStr {
                ptr: s.as_ptr(),
                len: s.len(),
            }
        }
    }

    // SAFETY: a `DeclStr` borrows the image's own read-only bytes, mapped for its whole life.
    unsafe impl Send for DeclStr {}
    // SAFETY: see the `Send` impl above.
    unsafe impl Sync for DeclStr {}

    /// The built state handed back to the host: a pointer it never reads and the fn that frees it.
    #[repr(C)]
    pub struct OpaqueHandle {
        /// The state.
        pub ptr: *mut c_void,
        /// Frees `ptr`; never panics.
        pub free: Option<extern "C-unwind" fn(*mut c_void)>,
    }

    /// A retired slot's field: always `None` from minor 28.
    pub type RetiredFn = extern "C-unwind" fn();

    /// `wake(token)`: the host's one waker function.
    pub type WakeFn = extern "C-unwind" fn(token: u64);

    /// The host's waker handle, handed to `init`.
    #[repr(C)]
    #[derive(Debug, Clone, Copy)]
    pub struct WireWaker {
        /// `size_of::<WireWaker>()`.
        pub size: u32,
        /// The host's airlock minor.
        pub version: u32,
        /// Wake the task a token names.
        pub wake: Option<WakeFn>,
    }

    /// `init(lower, settings, waker, out_state)`. This wire reads neither `lower` nor `settings`.
    pub type InitFn = extern "C-unwind" fn(
        lower: *const c_void,
        settings: *const c_void,
        waker: *const WireWaker,
        out_state: *mut MaybeUninit<OpaqueHandle>,
    ) -> u8;
    /// `listen(state, bind, config, addr_buf, out_addr_len, out_listener)`.
    pub type ListenFn = extern "C-unwind" fn(
        state: *mut c_void,
        bind_ptr: *const u8,
        bind_len: usize,
        config: *const c_void,
        addr_buf: *mut u8,
        addr_cap: usize,
        out_addr_len: *mut usize,
        out_listener: *mut u64,
    ) -> u8;
    /// `connect(state, authority, config, out_conn)`: begin a dial, answering at once.
    pub type ConnectFn = extern "C-unwind" fn(
        state: *mut c_void,
        authority_ptr: *const u8,
        authority_len: usize,
        config: *const c_void,
        out_conn: *mut u64,
    ) -> u8;
    /// `poll_accept(state, listener, token, peer_buf, out_peer_len, out_conn)`.
    pub type PollAcceptFn = extern "C-unwind" fn(
        state: *mut c_void,
        listener: u64,
        token: u64,
        peer_buf: *mut u8,
        peer_cap: usize,
        out_peer_len: *mut usize,
        out_conn: *mut u64,
    ) -> u8;
    /// `poll_read(state, conn, token, buf, out_read)`.
    pub type PollReadFn = extern "C-unwind" fn(
        state: *mut c_void,
        conn: u64,
        token: u64,
        buf: *mut u8,
        buf_cap: usize,
        out_read: *mut usize,
    ) -> u8;
    /// `poll_write(state, conn, token, buf, out_written)`.
    pub type PollWriteFn = extern "C-unwind" fn(
        state: *mut c_void,
        conn: u64,
        token: u64,
        buf: *const u8,
        len: usize,
        out_written: *mut usize,
    ) -> u8;
    /// `poll_flush(state, conn, token)` and `poll_close(state, conn, token)`.
    pub type PollConnFn = extern "C-unwind" fn(state: *mut c_void, conn: u64, token: u64) -> u8;

    /// The transport decl, slot for slot in the host's order.
    #[repr(C)]
    pub struct TransportDecl {
        /// The airlock header.
        pub abi: AbiPreamble,
        /// `size_of::<TransportDecl>()`.
        pub size: u32,
        /// The airlock minor it was built at.
        pub version: u32,
        /// The registry key.
        pub key: DeclStr,
        /// The layers it composes over.
        pub composes_over_ptr: *const DeclStr,
        /// How many.
        pub composes_over_len: usize,
        /// Retired (minor 28).
        pub build: Option<RetiredFn>,
        /// Listen.
        pub listen: Option<ListenFn>,
        /// Retired (minor 28).
        pub accept: Option<RetiredFn>,
        /// Retired (minor 28).
        pub dial: Option<RetiredFn>,
        /// Retired (minor 28).
        pub read: Option<RetiredFn>,
        /// Retired (minor 28).
        pub write: Option<RetiredFn>,
        /// Retired (minor 28).
        pub close: Option<RetiredFn>,
        /// `1` = carries sessions.
        pub session: u32,
        /// Padding.
        pub _reserved: u32,
        /// Init, handed the host's waker handle.
        pub init: Option<InitFn>,
        /// Begin a dial.
        pub connect: Option<ConnectFn>,
        /// Poll a listener.
        pub poll_accept: Option<PollAcceptFn>,
        /// Poll bytes in.
        pub poll_read: Option<PollReadFn>,
        /// Poll bytes out.
        pub poll_write: Option<PollWriteFn>,
        /// Poll bytes (and the opening) onto the wire.
        pub poll_flush: Option<PollConnFn>,
        /// Poll a connection closed.
        pub poll_close: Option<PollConnFn>,
    }

    // SAFETY: every pointer in the decl addresses this image's own `'static` read-only data.
    unsafe impl Send for TransportDecl {}
    // SAFETY: see the `Send` impl above.
    unsafe impl Sync for TransportDecl {}
}

use layout::{outcome, DeclStr, OpaqueHandle, TransportDecl, WakeFn, WireWaker};

/// How many layers this wire declares it composes over — the length of its linked row's list.
const COMPOSES_OVER_LEN: usize = crate::linked::COMPOSES_OVER.len();

/// The composes-over list: the linked row's own [`crate::linked::COMPOSES_OVER`], as borrowed ranges.
static COMPOSES_OVER: [DeclStr; COMPOSES_OVER_LEN] = decl_list(crate::linked::COMPOSES_OVER);

/// `names` as borrowed ranges, in declared order.
const fn decl_list<const N: usize>(names: &[&'static str]) -> [DeclStr; N] {
    let mut list = [DeclStr {
        ptr: core::ptr::null(),
        len: 0,
    }; N];
    let mut i = 0;
    while i < N {
        list[i] = DeclStr::new(names[i]);
        i += 1;
    }
    list
}

/// THE decl: this transport's row and slots, for both doors.
pub static TRANSPORT_DECL: TransportDecl = TransportDecl {
    abi: layout::AbiPreamble {
        magic: layout::ABI_MAGIC,
        abi_major: layout::ABI_MAJOR,
        abi_minor: layout::ABI_MINOR,
    },
    size: core::mem::size_of::<TransportDecl>() as u32,
    version: layout::ABI_MINOR,
    key: DeclStr::new(crate::linked::KEY),
    composes_over_ptr: COMPOSES_OVER.as_ptr(),
    composes_over_len: COMPOSES_OVER_LEN,
    build: None,
    listen: Some(listen),
    accept: None,
    dial: None,
    read: None,
    write: None,
    close: None,
    session: crate::linked::SESSION as u32,
    _reserved: 0,
    init: Some(init),
    connect: Some(connect),
    poll_accept: Some(poll_accept),
    poll_read: Some(poll_read),
    poll_write: Some(poll_write),
    poll_flush: Some(poll_flush),
    poll_close: Some(poll_close),
};

/// The dropped-in door's three symbols, compiled only into the dropped-in build (feature
/// `dropped-in`). A build that links this crate takes [`TRANSPORT_DECL`] and never these: rustc emits
/// the `rlib` and the `cdylib` from one set of objects, so a symbol compiled here is in the linked
/// `rlib` too, where it is a second definition of the shared handshake the SDK defines for every
/// SDK-built plugin — a refused link under the release profile's fat LTO.
#[cfg(feature = "dropped-in")]
pub mod exports {
    /// The shared library handshake.
    #[no_mangle]
    pub extern "C-unwind" fn busbar_abi() -> u32 {
        super::layout::HANDSHAKE_VERSION
    }

    /// This library's plugin kind, a `'static` NUL-terminated string.
    #[no_mangle]
    pub extern "C-unwind" fn busbar_plugin_kind() -> *const u8 {
        c"transport".as_ptr().cast()
    }

    /// The transport decl, `'static`, never freed by the loader.
    #[no_mangle]
    pub extern "C-unwind" fn busbar_transport_decl() -> *const super::TransportDecl {
        core::ptr::addr_of!(super::TRANSPORT_DECL)
    }
}

/// One built instance of the wire: the transport, the connections it minted, the listeners it
/// bound, the dials still opening, the host's waker, and the I/O reactor its sockets are registered
/// with (declared last, so it stops after everything that holds a socket registered with it).
struct Wire {
    tcp: TcpTransport,
    wake: WakeFn,
    conns: Mutex<HashMap<u64, Arc<Slot>>>,
    listeners: Mutex<HashMap<u64, Arc<Listening>>>,
    next_listener: AtomicU64,
    dialing: Mutex<HashMap<u64, Dialing>>,
    reactor: Reactor,
}

/// A dial `connect` began: its connection's handle is out, its socket not yet open.
type Dialing =
    Pin<Box<dyn Future<Output = Result<(TcpStream, SocketAddr), TransportError>> + Send>>;

/// One connection's handle, and the wakers its parked reading and writing hold — so a close wakes
/// both, and each sees the connection closed.
struct Slot {
    conn: Conn,
    reading: WakerCell,
    writing: WakerCell,
}

/// One listener, and the waker its parked accept holds.
struct Listening {
    listener: tokio::net::TcpListener,
    accepting: WakerCell,
}

/// The waker for one host token, made once per token and handed out by clone: a poll that parks
/// hands the socket a waker that calls the host's `wake(token)`.
#[derive(Default)]
struct WakerCell(Mutex<Option<(u64, Waker)>>);

/// The host's `wake(token)`, as a [`Waker`].
struct HostWake {
    wake: WakeFn,
    token: u64,
}

impl std::task::Wake for HostWake {
    fn wake(self: Arc<Self>) {
        (self.wake)(self.token);
    }
    fn wake_by_ref(self: &Arc<Self>) {
        (self.wake)(self.token);
    }
}

impl WakerCell {
    /// The waker for `token` (a no-op for [`layout::NO_WAKER`]).
    fn waker(&self, wake: WakeFn, token: u64) -> Waker {
        if token == layout::NO_WAKER {
            return Waker::noop().clone();
        }
        let mut cell = self.0.lock().expect("waker cell poisoned");
        match &*cell {
            Some((held, waker)) if *held == token => waker.clone(),
            _ => {
                let waker = Waker::from(Arc::new(HostWake { wake, token }));
                *cell = Some((token, waker.clone()));
                waker
            }
        }
    }

    /// Wake whoever parked here last.
    fn wake(&self) {
        if let Some((_, waker)) = self.0.lock().expect("waker cell poisoned").take() {
            waker.wake();
        }
    }
}

/// This instance's I/O reactor: a single-threaded runtime on a thread of its own, driving the
/// readiness of every socket this instance registers and the clock that bounds its dials. It runs
/// no task of the host's and no slot waits on it: it only delivers readiness, as `wake(token)`.
struct Reactor {
    handle: tokio::runtime::Handle,
    stop: Option<tokio::sync::oneshot::Sender<()>>,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl Reactor {
    fn start() -> std::io::Result<Self> {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?;
        let handle = runtime.handle().clone();
        let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
        let thread = std::thread::Builder::new()
            .name("busbar-wire-io".into())
            .spawn(move || {
                runtime.block_on(async {
                    let _ = stopped.await;
                });
            })?;
        Ok(Self {
            handle,
            stop: Some(stop),
            thread: Some(thread),
        })
    }
}

impl Drop for Reactor {
    fn drop(&mut self) {
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

/// The outcome byte for a transport error.
fn code(e: TransportError) -> u8 {
    match e {
        TransportError::Refused => outcome::REFUSED,
        TransportError::Timeout => outcome::TIMEOUT,
        TransportError::Reset => outcome::RESET,
        TransportError::Closed => outcome::CLOSED,
        TransportError::HandshakeFailed => outcome::HANDSHAKE_FAILED,
        TransportError::KeyUnavailable => outcome::KEY_UNAVAILABLE,
        TransportError::AddressRefused => outcome::ADDRESS_REFUSED,
        TransportError::Backpressure => outcome::BACKPRESSURE,
        TransportError::Framing => outcome::FRAMING,
        TransportError::HandoffMismatch => outcome::HANDOFF_MISMATCH,
    }
}

/// Run a slot body, answering the fault byte for a panic instead of unwinding out of the image. A
/// body answers `Ok(Some(()))` when ready, `Ok(None)` when pending, `Err(code)` on a refusal.
fn guarded(body: impl FnOnce() -> Result<Option<()>, u8> + std::panic::UnwindSafe) -> u8 {
    match std::panic::catch_unwind(body) {
        Ok(Ok(Some(()))) => outcome::OK,
        Ok(Ok(None)) => outcome::PENDING,
        Ok(Err(code)) => code,
        Err(_) => outcome::FAULT,
    }
}

/// A poll's answer as a slot body's: ready, pending, or refused.
fn polled<T>(p: Poll<Result<T, TransportError>>) -> Result<Option<T>, u8> {
    match p {
        Poll::Pending => Ok(None),
        Poll::Ready(r) => r.map(Some).map_err(code),
    }
}

/// The built wire behind a slot's `state`.
///
/// # Safety
/// `state` must be a pointer [`init`] produced and the host has not yet freed.
unsafe fn wire<'a>(state: *mut c_void) -> Result<&'a Wire, u8> {
    // SAFETY: per this fn's contract, a non-null `state` is a live `Wire` `init` boxed.
    unsafe { (state as *const Wire).as_ref() }.ok_or(outcome::FAULT)
}

/// A borrowed UTF-8 argument.
///
/// # Safety
/// `ptr`, when non-null, must address `len` readable bytes for the call.
unsafe fn utf8<'a>(ptr: *const u8, len: usize) -> Result<&'a str, u8> {
    if ptr.is_null() {
        return Err(outcome::ADDRESS_REFUSED);
    }
    // SAFETY: per this fn's contract.
    let bytes = unsafe { std::slice::from_raw_parts(ptr, len) };
    std::str::from_utf8(bytes).map_err(|_| outcome::ADDRESS_REFUSED)
}

/// Copy `text` into the caller's `(buf, cap)`, setting `out_len`, or refuse when it does not fit.
///
/// # Safety
/// `buf` must address `cap` writable bytes and `out_len` a writable `usize`.
unsafe fn put(text: &str, buf: *mut u8, cap: usize, out_len: *mut usize) -> Result<(), u8> {
    if buf.is_null() || out_len.is_null() || text.len() > cap {
        return Err(outcome::FAULT);
    }
    // SAFETY: `text.len() <= cap` bytes into the caller's writable range, then its length out.
    unsafe {
        core::ptr::copy_nonoverlapping(text.as_ptr(), buf, text.len());
        *out_len = text.len();
    }
    Ok(())
}

impl Wire {
    /// Hold a connection this wire minted and answer its handle.
    fn hold(&self, conn: Conn) -> u64 {
        let id = conn.id();
        self.conns.lock().expect("slot registry poisoned").insert(
            id,
            Arc::new(Slot {
                conn,
                reading: WakerCell::default(),
                writing: WakerCell::default(),
            }),
        );
        id
    }

    fn slot(&self, id: u64) -> Option<Arc<Slot>> {
        self.conns
            .lock()
            .expect("slot registry poisoned")
            .get(&id)
            .cloned()
    }

    /// Drive the dial `connect` began for `id`, if it is still opening: the connection is held
    /// once its socket is open, and forgotten if the dial failed.
    fn settle(&self, id: u64, waker: &Waker) -> Poll<Result<(), TransportError>> {
        let mut dialing = self.dialing.lock().expect("dial registry poisoned");
        let Some(dial) = dialing.get_mut(&id) else {
            return Poll::Ready(Ok(()));
        };
        let opened = std::task::ready!(dial.as_mut().poll(&mut Context::from_waker(waker)));
        dialing.remove(&id);
        drop(dialing);
        let (stream, addr) = opened?;
        let conn = self
            .tcp
            .register_as(id, stream, addr)
            .map_err(|e| TcpTransport::map_io_err(&e))?;
        self.hold(conn);
        Poll::Ready(Ok(()))
    }

    /// Poll one direction of connection `id` with the waker for `token`, once its dial settled.
    fn poll_conn<T>(
        &self,
        id: u64,
        token: u64,
        cell: fn(&Slot) -> &WakerCell,
        op: impl FnOnce(&Wire, &mut Context<'_>) -> Poll<Result<T, TransportError>>,
    ) -> Poll<Result<T, TransportError>> {
        let dial_waker;
        let waker = match self.slot(id) {
            Some(slot) => cell(&slot).waker(self.wake, token),
            None => {
                dial_waker = WakerCell::default().waker(self.wake, token);
                std::task::ready!(self.settle(id, &dial_waker))?;
                match self.slot(id) {
                    Some(slot) => cell(&slot).waker(self.wake, token),
                    None => return Poll::Ready(Err(TransportError::Closed)),
                }
            }
        };
        op(self, &mut Context::from_waker(&waker))
    }
}

extern "C-unwind" fn free_wire(state: *mut c_void) {
    if state.is_null() {
        return;
    }
    let _ = std::panic::catch_unwind(|| {
        // SAFETY: `state` is the `Box<Wire>` `init` leaked, freed exactly once by the host.
        drop(unsafe { Box::from_raw(state.cast::<Wire>()) });
    });
}

extern "C-unwind" fn init(
    _lower: *const c_void,
    _settings: *const c_void,
    waker: *const WireWaker,
    out_state: *mut MaybeUninit<OpaqueHandle>,
) -> u8 {
    guarded(|| {
        if out_state.is_null() || waker.is_null() {
            return Err(outcome::FAULT);
        }
        // SAFETY: a non-null host waker handle addresses at least its sized header; the `wake` slot
        // is read only when the attested size reaches it.
        let wake = unsafe {
            let size = core::ptr::read_unaligned(core::ptr::addr_of!((*waker).size)) as usize;
            if size < core::mem::size_of::<WireWaker>() {
                return Err(outcome::FAULT);
            }
            core::ptr::read_unaligned(core::ptr::addr_of!((*waker).wake))
        }
        .ok_or(outcome::FAULT)?;
        let reactor = Reactor::start().map_err(|_| outcome::FAULT)?;
        let state = Box::into_raw(Box::new(Wire {
            tcp: TcpTransport::new(),
            wake,
            conns: Mutex::new(HashMap::new()),
            listeners: Mutex::new(HashMap::new()),
            next_listener: AtomicU64::new(1),
            dialing: Mutex::new(HashMap::new()),
            reactor,
        }));
        // SAFETY: `out_state` is the host's writable slot (checked non-null above).
        unsafe {
            (*out_state).write(OpaqueHandle {
                ptr: state.cast(),
                free: Some(free_wire),
            });
        }
        Ok(Some(()))
    })
}

#[allow(clippy::too_many_arguments)]
extern "C-unwind" fn listen(
    state: *mut c_void,
    bind_ptr: *const u8,
    bind_len: usize,
    _config: *const c_void,
    addr_buf: *mut u8,
    addr_cap: usize,
    out_addr_len: *mut usize,
    out_listener: *mut u64,
) -> u8 {
    guarded(|| {
        // SAFETY: the host passes the state `init` produced and its own live argument ranges.
        let (wire, bind) = unsafe { (wire(state)?, utf8(bind_ptr, bind_len)?) };
        if out_listener.is_null() {
            return Err(outcome::FAULT);
        }
        let _in = wire.reactor.handle.enter();
        let (listener, addr) = TcpTransport::bind_shared(bind).map_err(code)?;
        // SAFETY: the host's writable address range and length slot.
        unsafe { put(&addr, addr_buf, addr_cap, out_addr_len)? };
        let id = wire.next_listener.fetch_add(1, Ordering::Relaxed);
        wire.listeners
            .lock()
            .expect("listener registry poisoned")
            .insert(
                id,
                Arc::new(Listening {
                    listener,
                    accepting: WakerCell::default(),
                }),
            );
        // SAFETY: checked non-null above.
        unsafe { *out_listener = id };
        Ok(Some(()))
    })
}

extern "C-unwind" fn poll_accept(
    state: *mut c_void,
    listener: u64,
    token: u64,
    peer_buf: *mut u8,
    peer_cap: usize,
    out_peer_len: *mut usize,
    out_conn: *mut u64,
) -> u8 {
    guarded(|| {
        // SAFETY: the host passes the state `init` produced.
        let wire = unsafe { wire(state)? };
        if out_conn.is_null() {
            return Err(outcome::FAULT);
        }
        let listening = wire
            .listeners
            .lock()
            .expect("listener registry poisoned")
            .get(&listener)
            .cloned()
            .ok_or(outcome::CLOSED)?;
        let waker = listening.accepting.waker(wire.wake, token);
        let _in = wire.reactor.handle.enter();
        let accepted = listening
            .listener
            .poll_accept(&mut Context::from_waker(&waker))
            .map_err(|e| TcpTransport::map_io_err(&e));
        let Some((stream, peer)) = polled(accepted)? else {
            return Ok(None);
        };
        let conn = wire
            .tcp
            .register(stream, peer)
            .map_err(|e| code(TcpTransport::map_io_err(&e)))?;
        let peer = conn.peer();
        let id = wire.hold(conn);
        // SAFETY: the host's writable peer range and length slot, and its connection slot.
        unsafe {
            if let Err(e) = put(&peer, peer_buf, peer_cap, out_peer_len) {
                release(wire, id);
                return Err(e);
            }
            *out_conn = id;
        }
        Ok(Some(()))
    })
}

extern "C-unwind" fn connect(
    state: *mut c_void,
    authority_ptr: *const u8,
    authority_len: usize,
    _config: *const c_void,
    out_conn: *mut u64,
) -> u8 {
    guarded(|| {
        // SAFETY: the host passes the state `init` produced and its own live argument range.
        let (wire, authority) = unsafe { (wire(state)?, utf8(authority_ptr, authority_len)?) };
        if out_conn.is_null() {
            return Err(outcome::FAULT);
        }
        let _in = wire.reactor.handle.enter();
        let dial = wire.tcp.dialing(authority).map_err(code)?;
        let id = wire.tcp.next_conn_id();
        wire.dialing
            .lock()
            .expect("dial registry poisoned")
            .insert(id, Box::pin(dial));
        // SAFETY: checked non-null above.
        unsafe { *out_conn = id };
        Ok(Some(()))
    })
}

extern "C-unwind" fn poll_read(
    state: *mut c_void,
    conn: u64,
    token: u64,
    buf: *mut u8,
    buf_cap: usize,
    out_read: *mut usize,
) -> u8 {
    guarded(|| {
        // SAFETY: the host passes the state `init` produced.
        let wire = unsafe { wire(state)? };
        // A zero-capacity read could only ever answer `0`, which is the end of the stream.
        if buf.is_null() || buf_cap == 0 || out_read.is_null() {
            return Err(outcome::FAULT);
        }
        // SAFETY: the host's live, writable `buf_cap`-byte range for the call.
        let into = unsafe { std::slice::from_raw_parts_mut(buf, buf_cap) };
        let _in = wire.reactor.handle.enter();
        let read = wire.poll_conn(
            conn,
            token,
            |s| &s.reading,
            |w, cx| w.tcp.poll_read_into(conn, cx, into),
        );
        let Some(n) = polled(read)? else {
            return Ok(None);
        };
        // SAFETY: checked non-null above.
        unsafe { *out_read = n };
        Ok(Some(()))
    })
}

extern "C-unwind" fn poll_write(
    state: *mut c_void,
    conn: u64,
    token: u64,
    buf: *const u8,
    len: usize,
    out_written: *mut usize,
) -> u8 {
    guarded(|| {
        // SAFETY: the host passes the state `init` produced.
        let wire = unsafe { wire(state)? };
        if (buf.is_null() && len != 0) || out_written.is_null() {
            return Err(outcome::FAULT);
        }
        let bytes: &[u8] = if len == 0 {
            &[]
        } else {
            // SAFETY: the host's live `len`-byte range for the call.
            unsafe { std::slice::from_raw_parts(buf, len) }
        };
        let _in = wire.reactor.handle.enter();
        let wrote = wire.poll_conn(
            conn,
            token,
            |s| &s.writing,
            |w, cx| w.tcp.poll_write_on(conn, cx, bytes),
        );
        let Some(n) = polled(wrote)? else {
            return Ok(None);
        };
        // SAFETY: checked non-null above.
        unsafe { *out_written = n };
        Ok(Some(()))
    })
}

extern "C-unwind" fn poll_flush(state: *mut c_void, conn: u64, token: u64) -> u8 {
    guarded(|| {
        // SAFETY: the host passes the state `init` produced.
        let wire = unsafe { wire(state)? };
        let _in = wire.reactor.handle.enter();
        polled(wire.poll_conn(
            conn,
            token,
            |s| &s.writing,
            |w, cx| w.tcp.poll_flush_on(conn, cx),
        ))
    })
}

/// Forget a connection and close it the way the transport closes one, waking whatever was parked on
/// it; a dial still opening is dropped where it stood.
fn release(wire: &Wire, id: u64) {
    drop(
        wire.dialing
            .lock()
            .expect("dial registry poisoned")
            .remove(&id),
    );
    let slot = wire
        .conns
        .lock()
        .expect("slot registry poisoned")
        .remove(&id);
    if let Some(slot) = slot {
        wire.tcp.close(slot.conn.clone(), CloseReason::Normal);
        slot.reading.wake();
        slot.writing.wake();
    }
}

extern "C-unwind" fn poll_close(state: *mut c_void, conn: u64, _token: u64) -> u8 {
    guarded(|| {
        // SAFETY: the host passes the state `init` produced.
        let wire = unsafe { wire(state)? };
        let _in = wire.reactor.handle.enter();
        release(wire, conn);
        Ok(Some(()))
    })
}
