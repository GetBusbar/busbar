// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE HOT-LANE DOOR (#3, #30, #40, #84): this transport as a `#[repr(C)]` decl, so it is swappable
//! compiled in OR dropped in. [`TRANSPORT_DECL`] is the one decl both doors hand the host: a build
//! that links this crate passes its address to the loader's `link_transport`; the `cdylib` exports it
//! as `busbar_transport_decl` (with `busbar_abi` and `busbar_plugin_kind`) for the loader's
//! `load_transport`. The same slots run whichever door the host came in by.
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
//! # What the slots are
//!
//! [`TRANSPORT_DECL`]'s row IS the linked row ([`crate::linked`]): its key, the layers it composes
//! over and whether it carries sessions are [`crate::linked::KEY`], [`crate::linked::COMPOSES_OVER`]
//! and [`crate::linked::SESSION`], and `build` constructs the
//! transport exactly as [`crate::linked::build`] does (this wire takes no lower layer and reads no
//! setting). Its slots
//! are one-line bridges onto the SAME async helpers the [`Transport`](busbar_contract::Transport)
//! implementation runs (`listen_on`, `accept_on`, `dial_authority`, `send`, the frame pump and
//! `close`). The built state owns a single-threaded I/O driver of its own: a slot blocks on it until
//! its operation completes, so the host drives the slots off its request threads. Every slot catches
//! its own panics and answers the fault byte — a panic cannot unwind out of a dropped-in image.
//! Configuration handles and the build settings are accepted and not read: this wire opens its own
//! socket, carries no key material and reads no setting.

#![allow(unsafe_code)]

use std::collections::HashMap;
use std::os::raw::c_void;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use busbar_contract::transport::wire::{CloseReason, Conn, TransportError};
use busbar_contract::transport::FrameStream;
use busbar_contract::Transport;
use core::mem::MaybeUninit;
use futures::StreamExt;

use crate::TcpTransport;

/// The published HOT-lane layout this transport implements, restated (see the module docs).
pub mod layout {
    use core::mem::MaybeUninit;
    use std::os::raw::c_void;

    /// The airlock magic every HOT-lane peer stamps.
    pub const ABI_MAGIC: u64 = u64::from_le_bytes(*b"BUSPLANE");
    /// The airlock major this decl is laid out for.
    pub const ABI_MAJOR: u32 = 2;
    /// The airlock minor this decl is laid out at (the first minor with a whole transport decl).
    pub const ABI_MINOR: u32 = 26;
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
    }

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

    /// `build(lower, settings, out_state)`. This wire reads neither argument.
    pub type BuildFn = extern "C-unwind" fn(
        lower: *const c_void,
        settings: *const c_void,
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
    /// `accept(state, listener, peer_buf, out_peer_len, out_conn)`.
    pub type AcceptFn = extern "C-unwind" fn(
        state: *mut c_void,
        listener: u64,
        peer_buf: *mut u8,
        peer_cap: usize,
        out_peer_len: *mut usize,
        out_conn: *mut u64,
    ) -> u8;
    /// `dial(state, authority, config, out_conn)`.
    pub type DialFn = extern "C-unwind" fn(
        state: *mut c_void,
        authority_ptr: *const u8,
        authority_len: usize,
        config: *const c_void,
        out_conn: *mut u64,
    ) -> u8;
    /// `read(state, conn, buf, out_written)`.
    pub type ReadFn = extern "C-unwind" fn(
        state: *mut c_void,
        conn: u64,
        buf: *mut u8,
        buf_cap: usize,
        out_written: *mut usize,
    ) -> u8;
    /// `write(state, conn, buf)`.
    pub type WriteFn =
        extern "C-unwind" fn(state: *mut c_void, conn: u64, buf: *const u8, len: usize) -> u8;
    /// `close(state, conn)`.
    pub type CloseFn = extern "C-unwind" fn(state: *mut c_void, conn: u64) -> u8;

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
        /// Build.
        pub build: Option<BuildFn>,
        /// Listen.
        pub listen: Option<ListenFn>,
        /// Accept.
        pub accept: Option<AcceptFn>,
        /// Dial.
        pub dial: Option<DialFn>,
        /// Read.
        pub read: Option<ReadFn>,
        /// Write.
        pub write: Option<WriteFn>,
        /// Close.
        pub close: Option<CloseFn>,
        /// `1` = carries sessions.
        pub session: u32,
        /// Padding.
        pub _reserved: u32,
    }

    // SAFETY: every pointer in the decl addresses this image's own `'static` read-only data.
    unsafe impl Send for TransportDecl {}
    // SAFETY: see the `Send` impl above.
    unsafe impl Sync for TransportDecl {}
}

use layout::{outcome, DeclStr, OpaqueHandle, TransportDecl};

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
    build: Some(build),
    listen: Some(listen),
    accept: Some(accept),
    dial: Some(dial),
    read: Some(read),
    write: Some(write),
    close: Some(close),
    session: crate::linked::SESSION as u32,
    _reserved: 0,
};

/// The dropped-in door's three symbols. In a module of their own, so a build that links this crate
/// and takes [`TRANSPORT_DECL`] does not also take a second definition of the shared handshake
/// symbols another linked plugin exports.
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
/// bound, and the I/O driver its slots block on (declared last, so it drops after everything that
/// holds a socket registered with it).
struct Wire {
    tcp: TcpTransport,
    conns: Mutex<HashMap<u64, Arc<Slot>>>,
    listeners: Mutex<HashMap<u64, String>>,
    next_listener: AtomicU64,
    driver: tokio::runtime::Runtime,
}

/// One connection: its handle and the frame pump its reads drain, with the unread tail of the last
/// frame when a caller's buffer was shorter than the frame.
struct Slot {
    conn: Conn,
    reader: Mutex<Reader>,
}

struct Reader {
    frames: FrameStream,
    held: Vec<u8>,
    at: usize,
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

/// Run a slot body, answering the fault byte for a panic instead of unwinding out of the image.
fn guarded(body: impl FnOnce() -> Result<(), u8> + std::panic::UnwindSafe) -> u8 {
    match std::panic::catch_unwind(body) {
        Ok(Ok(())) => outcome::OK,
        Ok(Err(code)) => code,
        Err(_) => outcome::FAULT,
    }
}

/// The built wire behind a slot's `state`.
///
/// # Safety
/// `state` must be a pointer [`build`] produced and the host has not yet freed.
unsafe fn wire<'a>(state: *mut c_void) -> Result<&'a Wire, u8> {
    // SAFETY: per this fn's contract, a non-null `state` is a live `Wire` `build` boxed.
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
    /// Hold a connection this wire minted, with its frame pump, and answer its handle.
    fn hold(&self, conn: Conn) -> u64 {
        let id = conn.id();
        let frames = self.tcp.frames(conn.clone());
        self.conns.lock().expect("slot registry poisoned").insert(
            id,
            Arc::new(Slot {
                conn,
                reader: Mutex::new(Reader {
                    frames,
                    held: Vec::new(),
                    at: 0,
                }),
            }),
        );
        id
    }

    fn slot(&self, id: u64) -> Result<Arc<Slot>, u8> {
        self.conns
            .lock()
            .expect("slot registry poisoned")
            .get(&id)
            .cloned()
            .ok_or(outcome::CLOSED)
    }
}

extern "C-unwind" fn free_wire(state: *mut c_void) {
    if state.is_null() {
        return;
    }
    let _ = std::panic::catch_unwind(|| {
        // SAFETY: `state` is the `Box<Wire>` `build` leaked, freed exactly once by the host.
        drop(unsafe { Box::from_raw(state.cast::<Wire>()) });
    });
}

extern "C-unwind" fn build(
    _lower: *const c_void,
    _settings: *const c_void,
    out_state: *mut MaybeUninit<OpaqueHandle>,
) -> u8 {
    guarded(|| {
        if out_state.is_null() {
            return Err(outcome::FAULT);
        }
        let driver = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|_| outcome::FAULT)?;
        let state = Box::into_raw(Box::new(Wire {
            tcp: TcpTransport::new(),
            conns: Mutex::new(HashMap::new()),
            listeners: Mutex::new(HashMap::new()),
            next_listener: AtomicU64::new(1),
            driver,
        }));
        // SAFETY: `out_state` is the host's writable slot (checked non-null above).
        unsafe {
            (*out_state).write(OpaqueHandle {
                ptr: state.cast(),
                free: Some(free_wire),
            });
        }
        Ok(())
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
        // SAFETY: the host passes the state `build` produced and its own live argument ranges.
        let (wire, bind) = unsafe { (wire(state)?, utf8(bind_ptr, bind_len)?) };
        if out_listener.is_null() {
            return Err(outcome::FAULT);
        }
        let addr = wire
            .driver
            .block_on(wire.tcp.listen_on(bind))
            .map_err(code)?;
        // SAFETY: the host's writable address range and length slot.
        unsafe { put(&addr, addr_buf, addr_cap, out_addr_len)? };
        let id = wire.next_listener.fetch_add(1, Ordering::Relaxed);
        wire.listeners
            .lock()
            .expect("listener registry poisoned")
            .insert(id, addr);
        // SAFETY: checked non-null above.
        unsafe { *out_listener = id };
        Ok(())
    })
}

extern "C-unwind" fn accept(
    state: *mut c_void,
    listener: u64,
    peer_buf: *mut u8,
    peer_cap: usize,
    out_peer_len: *mut usize,
    out_conn: *mut u64,
) -> u8 {
    guarded(|| {
        // SAFETY: the host passes the state `build` produced.
        let wire = unsafe { wire(state)? };
        if out_conn.is_null() {
            return Err(outcome::FAULT);
        }
        let addr = wire
            .listeners
            .lock()
            .expect("listener registry poisoned")
            .get(&listener)
            .cloned()
            .ok_or(outcome::CLOSED)?;
        let conn = wire
            .driver
            .block_on(wire.tcp.accept_on(&addr))
            .map_err(code)?;
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
        Ok(())
    })
}

extern "C-unwind" fn dial(
    state: *mut c_void,
    authority_ptr: *const u8,
    authority_len: usize,
    _config: *const c_void,
    out_conn: *mut u64,
) -> u8 {
    guarded(|| {
        // SAFETY: the host passes the state `build` produced and its own live argument range.
        let (wire, authority) = unsafe { (wire(state)?, utf8(authority_ptr, authority_len)?) };
        if out_conn.is_null() {
            return Err(outcome::FAULT);
        }
        let conn = wire
            .driver
            .block_on(wire.tcp.dial_authority(authority))
            .map_err(code)?;
        let id = wire.hold(conn);
        // SAFETY: checked non-null above.
        unsafe { *out_conn = id };
        Ok(())
    })
}

extern "C-unwind" fn read(
    state: *mut c_void,
    conn: u64,
    buf: *mut u8,
    buf_cap: usize,
    out_written: *mut usize,
) -> u8 {
    guarded(|| {
        // SAFETY: the host passes the state `build` produced.
        let wire = unsafe { wire(state)? };
        // A zero-capacity read could only ever answer `0`, which is the end of the stream.
        if buf.is_null() || buf_cap == 0 || out_written.is_null() {
            return Err(outcome::FAULT);
        }
        let slot = wire.slot(conn)?;
        let mut reader = slot.reader.lock().expect("reader poisoned");
        if reader.at >= reader.held.len() {
            match wire.driver.block_on(reader.frames.next()) {
                None => {
                    // SAFETY: checked non-null above.
                    unsafe { *out_written = 0 };
                    return Ok(());
                }
                Some(Err(e)) => return Err(code(e)),
                Some(Ok((_, frame))) => {
                    reader.held.clear();
                    reader.held.extend_from_slice(frame.bytes.as_slice());
                    reader.at = 0;
                }
            }
        }
        let n = buf_cap.min(reader.held.len() - reader.at);
        // SAFETY: `n <= buf_cap` bytes into the host's writable range, then the count out.
        unsafe {
            core::ptr::copy_nonoverlapping(reader.held[reader.at..].as_ptr(), buf, n);
            *out_written = n;
        }
        reader.at += n;
        Ok(())
    })
}

extern "C-unwind" fn write(state: *mut c_void, conn: u64, buf: *const u8, len: usize) -> u8 {
    guarded(|| {
        // SAFETY: the host passes the state `build` produced.
        let wire = unsafe { wire(state)? };
        if buf.is_null() && len != 0 {
            return Err(outcome::FAULT);
        }
        let bytes: &[u8] = if len == 0 {
            &[]
        } else {
            // SAFETY: the host's live `len`-byte range for the call.
            unsafe { std::slice::from_raw_parts(buf, len) }
        };
        wire.driver
            .block_on(wire.tcp.send(conn, bytes))
            .map_err(code)
    })
}

/// Forget a connection and close it the way the transport closes one.
fn release(wire: &Wire, id: u64) {
    let slot = wire
        .conns
        .lock()
        .expect("slot registry poisoned")
        .remove(&id);
    if let Some(slot) = slot {
        wire.tcp.close(slot.conn.clone(), CloseReason::Normal);
    }
}

extern "C-unwind" fn close(state: *mut c_void, conn: u64) -> u8 {
    guarded(|| {
        // SAFETY: the host passes the state `build` produced.
        let wire = unsafe { wire(state)? };
        release(wire, conn);
        Ok(())
    })
}
