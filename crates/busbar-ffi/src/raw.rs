// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The C-layout values both sides of the boundary share (UNSAFE-MIN §2.2, §2.3; IF §2, §5, §6.2).
//!
//! `unsafe` here: the three non-empty view reads, the `Out` write view, the `RawLent` read, the view
//! argument read, the `ChainBytes` read and `Send`/`Sync` for `Shared` (the one impl pair the views and the
//! `Plugin` header derive theirs from).

#![allow(unsafe_code)]

use core::cell::Cell;
use core::marker::PhantomData;
use core::ptr::NonNull;

mechanism! {
/// Borrowed bytes. Valid for `'a` only. `{ptr, 0}` with any `ptr` (null, dangling or misaligned) is the
/// empty value, from either side and from C: `get` tests `len == 0` first and never reads `ptr` then.
/// Fields are private: a Rust producer builds one only from a `&'a [u8]`.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct Bytes<'a> { ptr: Shared<u8>, len: usize, _l: PhantomData<&'a [u8]> }

/// Borrowed UTF-8. The producer guarantees UTF-8 (every Rust producer builds it from `&str`); `get` does
/// not re-validate, and core re-validates every `Str` it turns into a core string.
#[repr(transparent)]
#[derive(Clone, Copy)]
pub struct Str<'a>(Bytes<'a>);

/// Borrowed array of `T: View`, under the same empty rule.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct Slice<'a, T: View> { ptr: Shared<T>, len: usize, _l: PhantomData<&'a [T]> }

/// A name/value pair (headers, query params, claims).
#[repr(C)]
#[derive(Clone, Copy)]
pub struct Pair<'a> { pub name: Str<'a>, pub value: Bytes<'a> }

/// The answer block (core 3.0). It is the caller's: any storage of at least `RawOut::MIN` bytes, not
/// pre-filled; `grow` (on demand, through the host) rewrites `ptr`/`cap` through the `&mut RawOut` it is
/// handed. The callee writes only `[len, cap)` and states what it wrote in `len`; the caller reads only
/// `[0, len)`. No `Default`, no `Clone`, private fields.
#[repr(C)]
pub struct RawOut { ptr: *mut u8, len: usize, cap: usize }

/// The one return value of every raw entry.
#[repr(transparent)]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Status(pub u32);

/// Shim-minted handle for a chain or a session: bit 63 = session, bits 32..=62 = slot generation (never 0),
/// bits 0..=31 = slot index (IF §2).
pub type Token = u64;
/// Bit 63 of a session token.
pub const TOKEN_SESSION: u64 = 1 << 63;

/// The seven kinds.
#[repr(u32)]
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum KindCode { Store = 1, Secret = 2, Auth = 3, Hook = 4, Export = 5, Plane = 6, Transport = 7 }

/// The host's context word, branded with the entry lifetime `'e` (`uintptr_t` in C). The host never
/// dereferences it; it is data the host gave itself in `Host`.
#[repr(transparent)]
#[derive(Clone, Copy)]
pub struct Ctx<'e> { word: usize, _e: PhantomData<&'e EntryScope<'e>> }

/// Host-lent bytes in the thread's crypto arena, valid until the outermost entry returns: branded with
/// `'e`, so they cannot leave the `Host::scoped` call that received them.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct RawLent<'e> { ptr: *const u8, len: usize, _e: PhantomData<&'e [u8]> }

/// The answer of `random` and `crypto`: a `crypto_status` and the output; on every non-OK status `out`
/// is EMPTY.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct CryptoRet<'e> { pub status: u32, pub _r: u32, pub out: RawLent<'e> }

/// One crypto operation (IF §5).
#[repr(C)]
#[derive(Clone, Copy)]
pub struct CryptoReq<'a> {
    pub alg: u32, pub key_form: u32, pub param: u64,
    pub key: Bytes<'a>, pub data: Bytes<'a>, pub aux: Bytes<'a>, pub aad: Bytes<'a>,
}

/// A deployment id by value (16 bytes, align 1; `bb_deployment_id` in C).
#[repr(C)]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct DeploymentId(pub [u8; 16]);

/// The host table's nine entries (IF §5; core 3.0: the ninth is `service`), as safe higher-ranked fn pointers; every one is nullable in
/// C, and a `None` reads as the entry's panic fallback.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct HostFns {
    /// UTC nanoseconds since the Unix epoch.
    pub now: Option<for<'e> extern "C" fn(Ctx<'e>) -> u64>,
    /// Monotonic nanoseconds, the WAKE_AT clock.
    pub mono: Option<for<'e> extern "C" fn(Ctx<'e>) -> u64>,
    /// `len` random bytes in the thread's crypto arena.
    pub random: Option<for<'e> extern "C" fn(Ctx<'e>, usize) -> CryptoRet<'e>>,
    /// One crypto operation, output in the thread's crypto arena.
    pub crypto: Option<for<'e, 'a> extern "C" fn(Ctx<'e>, &CryptoReq<'a>) -> CryptoRet<'e>>,
    /// One log line: level, a declared error number (0 = none), the text.
    pub log: Option<for<'e, 'a> extern "C" fn(Ctx<'e>, u32, u32, Str<'a>)>,
    /// The most verbose level enabled (0 = off).
    pub log_level: Option<for<'e> extern "C" fn(Ctx<'e>) -> u32>,
    /// Grow this thread's ACTIVE out buffer by `need`; writes `ptr`/`cap` through the `&mut RawOut`.
    pub grow: Option<for<'e, 'o> extern "C" fn(Ctx<'e>, &'o mut RawOut, usize) -> bool>,
    /// The 16-byte install identity, all zero until known.
    pub deployment: Option<for<'e> extern "C" fn(Ctx<'e>) -> DeploymentId>,
    /// A kind's own host service (core 3.0): `id` is allotted by that kind's contract (kind code in the
    /// high 32 bits, the kind's service number in the low 32), so a kind gains a service without a new
    /// table entry. The answer is records in the caller-owned `out`; an unknown id is FAULT.
    pub service: Option<for<'e, 'a, 'o> extern "C" fn(Ctx<'e>, u64, &'a crate::vt::Call<'a>, &'o mut RawOut) -> Status>,
}

/// The host table (`bb_host`). One process-wide static; plugins get `&'static Host`. It begins with its own
/// size in bytes and its number of entries (core 3.0): entries are only ever appended, and an image reads
/// the prefix it was built for (an image newer than its host is never loaded). It holds only numbers and
/// safe fn pointers, so it is `Sync` without an `unsafe impl`.
#[repr(C)]
pub struct Host { size: u32, count: u32, ctx: usize, fns: HostFns }
}

/// A read-only, non-owning pointer inside a lifetime-branded view (`Bytes<'a>`, `Slice<'a, T>`, the
/// `Plugin` header's two image pointers). The one place the pointer-carrying views get `Send`/`Sync`, so
/// `Bytes`, `Str`, `Slice`, `Pair` and `Plugin` derive them structurally. `repr(transparent)`: the layout
/// is that of `*const T`.
#[repr(transparent)]
pub(crate) struct Shared<T>(*const T);

impl<T> Clone for Shared<T> {
    fn clone(&self) -> Self {
        *self
    }
}
impl<T> Copy for Shared<T> {}

impl<T> Shared<T> {
    pub(crate) const fn new(p: *const T) -> Self {
        Shared(p)
    }
    pub(crate) const fn get(self) -> *const T {
        self.0
    }
}

// SAFETY: a `Shared<T>` is only ever a pointer to memory that is immutable for the view's lifetime and is
// only read through a shared `&[T]`, so it is semantically `&'a T`, which is `Send` and `Sync` exactly
// when `T: Sync`.
unsafe impl<T: Sync> Send for Shared<T> {}
// SAFETY: as above; sharing the pointer shares only reads of `T`.
unsafe impl<T: Sync> Sync for Shared<T> {}

/// The brand behind `Ctx<'e>` and `RawLent<'e>`. It has no constructor: the only `'e` that exists is
/// the fresh one `Host::scoped` hands its closure.
pub struct EntryScope<'e>(PhantomData<*mut &'e ()>);

/// Seals `View`: busbar-ffi implements them for its own types only.
pub(crate) mod seal {
    pub trait Sealed {}
}

/// Byte offset of `RawOut::ptr` (a private field), for busbar-plugin-abi's C-HEADER static asserts (IF §7.8).
pub const RAW_OUT_PTR_AT: usize = core::mem::offset_of!(RawOut, ptr);
/// Byte offset of `RawOut::len`.
pub const RAW_OUT_LEN_AT: usize = core::mem::offset_of!(RawOut, len);
/// Byte offset of `RawOut::cap`.
pub const RAW_OUT_CAP_AT: usize = core::mem::offset_of!(RawOut, cap);
/// Byte offset of `Host::ctx` (a private field), for busbar-plugin-abi's C-HEADER static asserts (IF §7.8).
pub const HOST_CTX_AT: usize = core::mem::offset_of!(Host, ctx);
/// Byte offset of `Host::fns` (a private field); each `bb_host` entry sits at this plus its `HostFns` offset.
pub const HOST_FNS_AT: usize = core::mem::offset_of!(Host, fns);

/// Types allowed inside an input view: `Copy`, C layout, only pointer, length and `View` fields.
/// Sealed: busbar-ffi implements it for the view types it defines (here and in `vt`).
pub trait View: Copy + seal::Sealed {}

impl seal::Sealed for Bytes<'_> {}
impl seal::Sealed for Str<'_> {}
impl<T: View> seal::Sealed for Slice<'_, T> {}
impl seal::Sealed for Pair<'_> {}
impl seal::Sealed for u32 {}
impl seal::Sealed for u64 {}
impl View for Bytes<'_> {}
impl View for Str<'_> {}
impl<T: View> View for Slice<'_, T> {}
impl View for Pair<'_> {}
impl View for u32 {}
impl View for u64 {}

impl<'a> Bytes<'a> {
    pub const EMPTY: Bytes<'static> = Bytes {
        ptr: Shared::new(NonNull::<u8>::dangling().as_ptr().cast_const()),
        len: 0,
        _l: PhantomData,
    };
    pub const fn new(s: &'a [u8]) -> Self {
        Bytes {
            ptr: Shared::new(s.as_ptr()),
            len: s.len(),
            _l: PhantomData,
        }
    }
    /// The slice. `len == 0` returns `&[]` and never reads `ptr`.
    pub fn get(self) -> &'a [u8] {
        if self.len == 0 {
            return &[];
        }
        // SAFETY: a non-empty `Bytes<'a>` is built only by `new` from a `&'a [u8]` (or by the trusted
        // foreign caller under the same contract), so `ptr` is valid for `len` bytes for `'a`.
        unsafe { core::slice::from_raw_parts(self.ptr.get(), self.len) }
    }
    /// A pair list as one blob of a call: the borrowed array itself (its length is `32 * n`). The read
    /// side is `Args::pairs`, inside an entry whose layout names this blob a pair list.
    pub const fn of_pairs(pairs: &'a [Pair<'a>]) -> Bytes<'a> {
        Bytes {
            ptr: Shared::new(pairs.as_ptr().cast()),
            len: size_of_val(pairs),
            _l: PhantomData,
        }
    }
    /// This blob as the pair array it was built from. None: not a whole number of pairs, or misaligned.
    ///
    /// # Safety
    /// The blob is empty or was built by `of_pairs` from a `&'a [Pair<'a>]` (or by the trusted foreign
    /// caller under the same contract: an aligned array of pairs valid for `'a`, every name UTF-8).
    pub(crate) unsafe fn as_pairs(self) -> Option<Slice<'a, Pair<'a>>> {
        let each = size_of::<Pair<'static>>();
        if self.len == 0 {
            return Some(Slice::EMPTY);
        }
        if !self.len.is_multiple_of(each)
            || !self
                .ptr
                .get()
                .addr()
                .is_multiple_of(align_of::<Pair<'static>>())
        {
            return None;
        }
        Some(Slice {
            ptr: Shared::new(self.ptr.get().cast()),
            len: self.len / each,
            _l: PhantomData,
        })
    }
    /// Host side: the address and length, for the image bounds check (never dereferenced).
    #[cfg(feature = "host")]
    pub(crate) fn span(self) -> (usize, usize) {
        (self.ptr.get().addr(), self.len)
    }
    pub const fn len(self) -> usize {
        self.len
    }
    pub const fn is_empty(self) -> bool {
        self.len == 0
    }
}

impl<'a> Str<'a> {
    pub const EMPTY: Str<'static> = Str(Bytes::EMPTY);
    pub const fn new(s: &'a str) -> Self {
        Str(Bytes::new(s.as_bytes()))
    }
    /// The text. `len == 0` returns `""` without reading `ptr`.
    pub fn get(self) -> &'a str {
        let bytes = self.0.get();
        // SAFETY: a `Str` is built only by `new` from a `&'a str` (or by the trusted foreign caller, which
        // guarantees UTF-8, IF §2), so the bytes are UTF-8.
        unsafe { core::str::from_utf8_unchecked(bytes) }
    }
    /// The bytes, for a reader that checks UTF-8 itself (the loader's names view).
    pub const fn bytes(self) -> Bytes<'a> {
        self.0
    }
    pub const fn len(self) -> usize {
        self.0.len()
    }
    pub const fn is_empty(self) -> bool {
        self.0.is_empty()
    }
}

impl<'a, T: View> Slice<'a, T> {
    pub const EMPTY: Self = Slice {
        ptr: Shared::new(NonNull::<T>::dangling().as_ptr().cast_const()),
        len: 0,
        _l: PhantomData,
    };
    pub const fn new(s: &'a [T]) -> Self {
        Slice {
            ptr: Shared::new(s.as_ptr()),
            len: s.len(),
            _l: PhantomData,
        }
    }
    /// `len == 0` returns `&[]` without reading `ptr`.
    pub fn get(self) -> &'a [T] {
        if self.len == 0 {
            return &[];
        }
        // SAFETY: a non-empty `Slice<'a, T>` is built only by `new` from a `&'a [T]` (or by the trusted
        // foreign caller), so `ptr` is aligned and valid for `len` values of `T` for `'a`; `T: View` is
        // `Copy` with no invalid bit patterns a producer could have written.
        unsafe { core::slice::from_raw_parts(self.ptr.get(), self.len) }
    }
    pub const fn len(self) -> usize {
        self.len
    }
    pub const fn is_empty(self) -> bool {
        self.len == 0
    }
}

impl Status {
    /// Answer records are in Out.
    pub const OK: Status = Status(0);
    /// A domain verdict: one FAIL record (REFUSED) is in Out.
    pub const REFUSED: Status = Status(1);
    /// The backend failed: one FAIL record (FAILED) is in Out.
    pub const FAILED: Status = Status(2);
    /// A step: NEED records and exactly one TOKEN record are in Out.
    pub const NEED: Status = Status(3);
    /// A panic was caught or the contract was broken. Any value above 4 is FAULT too.
    pub const FAULT: Status = Status(4);
}

impl KindCode {
    pub const ALL: [KindCode; 7] = [
        KindCode::Store,
        KindCode::Secret,
        KindCode::Auth,
        KindCode::Hook,
        KindCode::Export,
        KindCode::Plane,
        KindCode::Transport,
    ];
    pub const fn from_raw(raw: u32) -> Option<KindCode> {
        match raw {
            1 => Some(KindCode::Store),
            2 => Some(KindCode::Secret),
            3 => Some(KindCode::Auth),
            4 => Some(KindCode::Hook),
            5 => Some(KindCode::Export),
            6 => Some(KindCode::Plane),
            7 => Some(KindCode::Transport),
            _ => None,
        }
    }
    /// The manifest word.
    pub const fn word(self) -> &'static str {
        match self {
            KindCode::Store => "store",
            KindCode::Secret => "secret",
            KindCode::Auth => "auth",
            KindCode::Hook => "hook",
            KindCode::Export => "export",
            KindCode::Plane => "plane",
            KindCode::Transport => "transport",
        }
    }
}

impl RawOut {
    /// The smallest answer block a caller may hand: the largest fixed answer (a failure with its error
    /// number and two facts). Anything larger is reached through `grow`.
    pub const MIN: usize = 80;
    /// A channel over caller storage `buf` (any content: it is not read), nothing written yet. The
    /// channel must not outlive `buf`, which the caller leaves untouched while an entry holds the channel.
    pub fn over(buf: &mut [u8]) -> RawOut {
        RawOut {
            ptr: buf.as_mut_ptr(),
            len: 0,
            cap: buf.len(),
        }
    }
    /// Host side: point the channel at a new buffer, keeping `len` (the grow path).
    #[cfg(feature = "host")]
    pub(crate) fn repoint(&mut self, buf: &mut [u8]) {
        self.ptr = buf.as_mut_ptr();
        self.cap = buf.len();
    }
    pub fn len(&self) -> usize {
        self.len
    }
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }
    pub fn cap(&self) -> usize {
        self.cap
    }
    /// Host side: the address the ACTIVE stack matches `grow` against (identity, never dereferenced).
    #[cfg(feature = "host")]
    pub(crate) fn identity(&self) -> usize {
        core::ptr::from_ref(self).addr()
    }
}

/// The plugin side's one write view over the host buffer (IF §3.2 `Out`'s sink). It never exposes the
/// `&mut RawOut`; growth goes through `Host::grow`, after which `ptr`/`cap` are re-read.
pub struct Out<'call> {
    raw: &'call mut RawOut,
    host: &'static Host,
}

impl<'call> Out<'call> {
    /// Minted by the shims only.
    pub(crate) fn new(raw: &'call mut RawOut, host: &'static Host) -> Self {
        Out { raw, host }
    }
    /// The host this entry runs under.
    pub fn host(&self) -> &'static Host {
        self.host
    }
    /// The same channel for a shorter borrow (safe: it only reborrows `&mut RawOut`). The shims hand the
    /// adapters `&mut Out`; plugin-abi's `records::Out` wraps one of these per call (W1-A4).
    pub fn reborrow(&mut self) -> Out<'_> {
        Out {
            raw: &mut *self.raw,
            host: self.host,
        }
    }
    /// Bytes written so far.
    pub fn written(&self) -> usize {
        self.raw.len
    }
    /// Ensure room for `need` more bytes, growing through the host. False: no room (Full).
    pub fn room(&mut self, need: usize) -> bool {
        if self.raw.cap.saturating_sub(self.raw.len) >= need {
            return true;
        }
        let Some(grow) = self.host.fns.grow else {
            return false;
        };
        let host = self.host;
        let raw = &mut *self.raw;
        host.scoped(|ctx| grow(ctx, raw, need)) && self.raw.cap.saturating_sub(self.raw.len) >= need
    }
    /// Append `bytes` (growing first). False: Full, nothing written.
    pub fn append(&mut self, bytes: &[u8]) -> bool {
        if !self.room(bytes.len()) {
            return false;
        }
        if bytes.is_empty() {
            return true;
        }
        let at = self.raw.len;
        // SAFETY: `room` just proved `cap - len >= bytes.len()`, and a `RawOut` is built only over caller
        // storage of `cap` bytes that the caller keeps alive and does not touch while the entry runs
        // (`grow` repoints it only to another such block), so `[len, len + n)` is inside it and `ptr` is
        // non-null; `bytes` is a separate borrow. The spare part is written, never read: it need not be
        // initialised (core 3.0: the answer block is not pre-filled).
        unsafe {
            core::ptr::copy_nonoverlapping(
                bytes.as_ptr(),
                self.raw.ptr.wrapping_add(at),
                bytes.len(),
            )
        };
        self.raw.len = at + bytes.len();
        true
    }
    /// Overwrite already-written bytes at `at`. False: outside what was written.
    pub fn patch(&mut self, at: usize, bytes: &[u8]) -> bool {
        let Some(end) = at.checked_add(bytes.len()) else {
            return false;
        };
        if end > self.raw.len {
            return false;
        }
        match self.view().get_mut(at..end) {
            Some(dst) => {
                dst.copy_from_slice(bytes);
                true
            }
            None => false,
        }
    }
    /// Cut back to `len`, zeroing what is cut (I11).
    pub fn truncate(&mut self, len: usize) {
        let old = self.raw.len;
        if len >= old {
            return;
        }
        if let Some(cut) = self.view().get_mut(len..old) {
            cut.fill(0);
            core::hint::black_box(&*cut);
        }
        self.raw.len = len;
    }
    /// What was written, `[0, len)`: the only part of the block ever read here.
    fn view(&mut self) -> &mut [u8] {
        if self.raw.len == 0 || self.raw.ptr.is_null() || self.raw.len > self.raw.cap {
            return &mut [];
        }
        // SAFETY: a `RawOut` is built only over caller storage of `cap` bytes that the caller keeps alive
        // and does not touch while the entry runs, and `grow` repoints it only to another such block with
        // `[0, len)` copied. `[0, len)` was written through this channel (`append`), so it is initialised.
        // `&mut self` holds the channel exclusively, and the view lives only for this call.
        unsafe { core::slice::from_raw_parts_mut(self.raw.ptr, self.raw.len) }
    }
}

impl<'e> Ctx<'e> {
    /// The host's context word (host side).
    pub fn word(self) -> usize {
        self.word
    }
}

impl<'e> RawLent<'e> {
    pub const EMPTY: RawLent<'static> = RawLent {
        ptr: NonNull::<u8>::dangling().as_ptr().cast_const(),
        len: 0,
        _e: PhantomData,
    };
    /// Host side: lend `ptr..ptr+len`, which the caller keeps valid and unchanged for `'e`.
    #[cfg(feature = "host")]
    pub(crate) fn lent(ptr: *const u8, len: usize, _ctx: Ctx<'e>) -> RawLent<'e> {
        RawLent {
            ptr,
            len,
            _e: PhantomData,
        }
    }
    /// The lent bytes. EMPTY reads `&[]` without reading `ptr`.
    pub fn get(self) -> &'e [u8] {
        if self.len == 0 {
            return &[];
        }
        // SAFETY: a non-empty `RawLent<'e>` is made only by the host's `Arena::lend`, which appends into
        // an arena allocated once at its cap and reset only when the outermost entry exits; `'e` is the
        // fresh brand of one `Host::scoped` call, which runs inside that entry, so the bytes are valid
        // and unchanged for `'e`.
        unsafe { core::slice::from_raw_parts(self.ptr, self.len) }
    }
    pub fn len(self) -> usize {
        self.len
    }
    pub fn is_empty(self) -> bool {
        self.len == 0
    }
}

impl<'e> CryptoRet<'e> {
    /// A status with no output (every non-OK answer).
    pub fn empty(_ctx: Ctx<'e>, status: u32) -> CryptoRet<'e> {
        CryptoRet {
            status,
            _r: 0,
            out: RawLent::EMPTY,
        }
    }
}

/// The number of entries in this build's host table.
pub const HOST_ENTRIES: u32 = 9;

impl Host {
    /// The table's size in bytes as its builder stated it.
    pub const fn size(&self) -> u32 {
        self.size
    }
    /// The number of entries its builder stated.
    pub const fn count(&self) -> u32 {
        self.count
    }
    pub const fn new(ctx: usize, fns: HostFns) -> Host {
        Host {
            size: size_of::<Host>() as u32,
            count: HOST_ENTRIES,
            ctx,
            fns,
        }
    }
    /// The nine entries, for the plugin-abi safe API.
    pub const fn fns(&self) -> &HostFns {
        &self.fns
    }
    /// Run `f` with this host's context under a fresh entry brand: nothing `f` receives from the host
    /// (`CryptoRet<'e>`, `RawLent<'e>`) can outlive the call.
    pub fn scoped<R>(&self, f: impl for<'e> FnOnce(Ctx<'e>) -> R) -> R {
        f(Ctx {
            word: self.ctx,
            _e: PhantomData,
        })
    }
}

/// The never-reused check value of chain-scoped bytes (IF §6.2): instance serial, the starting thread's
/// ordinal, that thread's chain counter. Minted only inside busbar-ffi and never handed out.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct ChainId {
    inst: u64,
    thread: u32,
    serial: u64,
}

static NEXT_THREAD: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(1);
std::thread_local! {
    static THREAD: Cell<u32> = const { Cell::new(0) };
    static SERIAL: Cell<u64> = const { Cell::new(0) };
    static CURRENT: Cell<Option<ChainId>> = const { Cell::new(None) };
}

impl ChainId {
    /// A fresh id for a chain of instance `inst` (0 = the image's open slab). None: this image has run
    /// out of thread ordinals (FAULT `Exhausted`).
    pub(crate) fn mint(inst: u64) -> Option<ChainId> {
        let mut thread = THREAD.get();
        if thread == 0 {
            thread = NEXT_THREAD.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
            if thread == u32::MAX || thread == 0 {
                return None;
            }
            THREAD.set(thread);
        }
        let serial = SERIAL.get().wrapping_add(1);
        SERIAL.set(serial);
        Some(ChainId {
            inst,
            thread,
            serial,
        })
    }
}

/// Sets `CURRENT` for one poll and restores the previous value on return and on unwind (IF §6.2, the
/// one restore).
pub(crate) struct CurrentGuard {
    prev: Option<ChainId>,
}
impl CurrentGuard {
    pub(crate) fn enter(id: ChainId) -> CurrentGuard {
        CurrentGuard {
            prev: CURRENT.replace(Some(id)),
        }
    }
}
impl Drop for CurrentGuard {
    fn drop(&mut self) {
        CURRENT.set(self.prev);
    }
}

/// An async argument (IF §6.2). Valid only while its own chain is being polled on this thread: the host
/// keeps every argument and result buffer of a chain until its token retires, and `CURRENT` names a
/// chain only during that chain's polls. `!Sync`, `Send`.
pub struct ChainBytes {
    ptr: Shared<u8>,
    len: usize,
    id: ChainId,
    _ns: PhantomData<Cell<()>>,
}

// `Send` comes from `Shared<u8>`: the bytes are host memory the host keeps alive for the whole chain and
// never mutates, and
// every read is gated on `CURRENT == id`, which holds only on a thread that is polling this chain, so
// moving the handle to another thread (the future migrating between resumes) cannot make a read unsound.

impl ChainBytes {
    /// A blob of an async call or a resume's results, as chain `id` keeps it (the shims only).
    pub(crate) fn of(bytes: Bytes<'_>, id: &ChainId) -> ChainBytes {
        ChainBytes {
            ptr: bytes.ptr,
            len: bytes.len,
            id: *id,
            _ns: PhantomData,
        }
    }
    /// Checks `CURRENT == self.id`, then calls `f`. Any other thread or chain: panic (FAULT StaleHandle).
    pub fn with<R>(&self, f: impl for<'a> FnOnce(&'a [u8]) -> R) -> R {
        if CURRENT.get() != Some(self.id) {
            panic!("busbar-ffi: a ChainBytes read outside its own chain (StaleHandle)");
        }
        if self.len == 0 {
            return f(&[]);
        }
        // SAFETY: `ChainBytes` is made only by `ChainBytes::of` inside busbar-ffi's shims, from a host
        // argument or result buffer that the host keeps alive and unchanged until this chain's token
        // retires; `CURRENT == id` proves this chain is being polled on this thread now, so it is alive.
        // The slice is higher-ranked in `f` and cannot escape the call.
        f(unsafe { core::slice::from_raw_parts(self.ptr.get(), self.len) })
    }
    pub fn len(&self) -> usize {
        self.len
    }
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }
    /// Checked copy: the way to keep bytes across an `.await` or past the chain.
    pub fn to_vec(&self) -> Vec<u8> {
        self.with(<[u8]>::to_vec)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// C-NULL-EMPTY (c), the Rust arm: `{NULL, 0}`, `{dangling, 0}` and `{misaligned, 0}` read empty and
    /// never touch the pointer (Miri runs this).
    #[test]
    fn an_empty_view_reads_empty_whatever_its_pointer() {
        let bytes = [
            Bytes {
                ptr: Shared::new(core::ptr::null()),
                len: 0,
                _l: PhantomData,
            },
            Bytes::EMPTY,
            Bytes {
                ptr: Shared::new(core::ptr::without_provenance(1)),
                len: 0,
                _l: PhantomData,
            },
        ];
        for b in bytes {
            assert!(b.is_empty());
            assert_eq!(b.get(), &[] as &[u8]);
            assert_eq!(Str(b).get(), "");
        }
        let slices: [Slice<'static, u64>; 2] = [
            Slice {
                ptr: Shared::new(core::ptr::null()),
                len: 0,
                _l: PhantomData,
            },
            Slice {
                ptr: Shared::new(core::ptr::without_provenance(3)),
                len: 0,
                _l: PhantomData,
            },
        ];
        for s in slices {
            assert!(s.get().is_empty());
        }
        assert!(RawLent::EMPTY.get().is_empty());
    }

    /// C-SEND-SYNC: the borrowed views cross threads like `&[u8]`/`&[T]` (the kernel holds `&[Pair]`
    /// across an await in a `Send` future). Compile-time only.
    #[test]
    fn the_views_are_send_and_sync() {
        fn send_sync<T: Send + Sync>() {}
        send_sync::<Bytes<'static>>();
        send_sync::<Str<'static>>();
        send_sync::<Slice<'static, u64>>();
        send_sync::<Slice<'static, Pair<'static>>>();
        send_sync::<Pair<'static>>();
        send_sync::<&[Pair<'static>]>();
        send_sync::<crate::Plugin>();
        fn send<T: Send>() {}
        send::<ChainBytes>();
    }

    #[test]
    fn a_view_reads_back_what_it_borrows() {
        assert_eq!(Bytes::new(b"abc").get(), b"abc");
        assert_eq!(Str::new("h\u{e9}").get(), "h\u{e9}");
        assert_eq!(Slice::new(&[1u64, 2, 3][..]).get(), &[1, 2, 3]);
        let pairs = [Pair {
            name: Str::new("accept"),
            value: Bytes::new(b"*/*"),
        }];
        let read = Slice::new(&pairs[..]).get();
        assert_eq!(read[0].name.get(), "accept");
        assert_eq!(read[0].value.get(), b"*/*");
        assert!(!Bytes::new(&[]).ptr.get().is_null());
    }

    extern "C" fn grow_to_64(_ctx: Ctx<'_>, raw: &mut RawOut, need: usize) -> bool {
        // The test host keeps its own record of what was written: mirror it before the block moves.
        GROWN.with(|g| {
            let mut next = vec![0u8; 64];
            if raw.len + need > next.len() {
                return false;
            }
            let old = raw.len;
            if let Some(src) = g.borrow().get(..old) {
                next[..old].copy_from_slice(src);
            }
            raw.repoint_for_tests(&mut next);
            *g.borrow_mut() = next;
            true
        })
    }
    std::thread_local! {
        static GROWN: core::cell::RefCell<Vec<u8>> = const { core::cell::RefCell::new(Vec::new()) };
    }
    impl RawOut {
        fn repoint_for_tests(&mut self, buf: &mut [u8]) {
            self.ptr = buf.as_mut_ptr();
            self.cap = buf.len();
        }
    }
    static TEST_HOST: Host = Host::new(
        0,
        HostFns {
            now: None,
            mono: None,
            random: None,
            crypto: None,
            log: None,
            log_level: None,
            grow: Some(grow_to_64),
            deployment: None,
            service: None,
        },
    );

    /// `Out` writes, patches and zeroes in place, and re-reads `ptr`/`cap` after a grow (A5, under Miri).
    #[test]
    fn out_writes_in_place_and_follows_a_grow() {
        let mut first = vec![0u8; 4];
        GROWN.with(|g| *g.borrow_mut() = first.clone());
        let mut raw = RawOut {
            ptr: first.as_mut_ptr(),
            len: 0,
            cap: first.len(),
        };
        let mut out = Out::new(&mut raw, &TEST_HOST);
        assert!(out.append(b"abc"));
        // The test grow copies from its own record of the buffer, so mirror the bytes there.
        GROWN.with(|g| g.borrow_mut()[..3].copy_from_slice(b"abc"));
        assert!(out.append(b"defgh"), "grows past 4");
        assert!(out.patch(0, b"A"));
        assert!(!out.patch(7, b"zz"), "past what was written");
        out.truncate(2);
        assert_eq!(out.written(), 2);
        assert!(!out.append(&[0u8; 100]), "over the host's cap: Full");
        GROWN.with(|g| {
            let g = g.borrow();
            assert_eq!(&g[..2], b"Ab");
            assert!(g[2..8].iter().all(|b| *b == 0), "the cut is zeroed");
        });
        drop(first);
    }

    #[test]
    fn chain_bytes_refuse_a_read_outside_their_chain() {
        let data = b"chain".to_vec();
        let Some(id) = ChainId::mint(7) else {
            panic!("mint");
        };
        let handle = ChainBytes::of(Bytes::new(&data), &id);
        {
            let _current = CurrentGuard::enter(id);
            assert_eq!(handle.to_vec(), b"chain");
        }
        let stale = std::panic::catch_unwind(core::panic::AssertUnwindSafe(|| handle.to_vec()));
        assert!(stale.is_err(), "no chain is being polled");
        let Some(other) = ChainId::mint(7) else {
            panic!("mint");
        };
        assert_ne!(other, id, "ids are never reused");
    }
}
