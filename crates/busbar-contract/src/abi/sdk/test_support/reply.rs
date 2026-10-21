// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! A SLOT CALLED AND ITS REPLY COPIED: [`call`] runs one door op and, before it returns, validates
//! and copies every reviewed reply field (`head.error`, and each `AbiStr`, `Blob` and list a
//! reviewed `out` names) into owned values. The test never holds a pointer into the plugin's leased
//! or published memory: the `out` it gets back has every such pointer cleared, so a `release`, a
//! `retire` or the next generation can run straight after with nothing left to dangle.
//!
//! ```ignore
//! use busbar_contract::abi::sdk::test_support::reply::call;
//!
//! let resolved = call(table.resolve.unwrap(), instance, &input, out);
//! assert_eq!(resolved.owned.material(), b"s3cret");
//! release(instance, resolved.out.head.lease); // the copy is already taken
//! ```
//!
//! Each reviewed `out` is first judged by its kind's own answer validator (`check_resolve`,
//! `check_serve`, `check_check`, `check_status`, `check_begin_login`, `check_snapshot`), the one
//! the host runs; then every list is held to [`STATEMENT_LIST_MAX`] entries and an aligned pointer,
//! every text and blob to [`HARD_MAX_BYTES`], and NULL is refused with a count. A breach panics
//! naming the field, before any byte is read.
//!
//! TRUST: `op` is a door's slot, and what it writes into the `out` is what the door contract says:
//! live plugin memory until the lease, generation or instance ends. Every reviewed pointer field of
//! the `out` is cleared before the call, so a pointer read afterwards is one the op wrote.

use core::ffi::c_void;
use core::fmt;
use core::mem::size_of;
use core::ptr;

use zeroize::Zeroizing;

use crate::abi::mechanism::call::{AbiStr, Blob, InHead, Op, OutHead, Outcome};
use crate::abi::mechanism::check::{Fault, HARD_MAX_BYTES, STATEMENT_LIST_MAX};
use crate::abi::sdk::door::{AbiIn, AbiOut};

mod sealed {
    use crate::abi::mechanism::call::{OutHead, Outcome};

    /// Only [`super::call`] makes one: the reads below run from nowhere else.
    #[derive(Debug, Clone, Copy)]
    pub struct Token(pub(super) ());

    /// Only this module implements it: the reviewed `out`s and how each is copied.
    pub trait Take: Sized {
        /// The `out`'s head.
        fn head(&mut self) -> &mut OutHead;
        /// Clear every reviewed pointer field (the head's included), keeping every scalar.
        fn clear(&mut self, token: Token);
        /// Judge and copy every reviewed field the op wrote.
        fn take(&self, outcome: Outcome, token: Token) -> <Self as super::Reply>::Owned
        where
            Self: super::Reply;
    }
}

use sealed::Token;

/// A reviewed `out` [`call`] copies. Sealed.
pub trait Reply: AbiOut + sealed::Take {
    /// The owned copies of its reviewed fields.
    type Owned: fmt::Debug;
}

/// One op called: its outcome, its `out` with every reviewed pointer cleared (its scalars as
/// written: `head.lease`, `instance`, `status_code`, ...), `head.error` copied, and the owned copies
/// of the `out`'s own fields.
#[derive(Debug)]
pub struct Called<O: Reply> {
    /// What the op answered.
    pub outcome: Outcome,
    /// The `out`, every reviewed pointer cleared.
    pub out: O,
    /// `head.error`, copied (`None` = absent).
    pub error: Option<String>,
    /// The `out`'s own fields, copied.
    pub owned: O::Owned,
}

/// Run `op` on `instance` over `input` and `out`, and copy the reply before returning. The heads
/// the op reads state the sizes of exactly the `I` and `O` passed (`in.head.size`,
/// `out.head.size`), whatever the caller wrote there: a slot reads and writes no byte past them.
///
/// # Panics
///
/// The `out` breaks its kind's answer validator, or a reviewed field is NULL with a count,
/// misaligned, over its bound, or (for text) not UTF-8; the message names the field.
pub fn call<I: AbiIn, O: Reply>(op: Op, instance: *mut c_void, input: &I, mut out: O) -> Called<O> {
    out.clear(Token(()));
    out.head().size = size_of::<O>() as u32;
    let mut input = *input;
    // SAFETY: `I: AbiIn` is `#[repr(C)]` and leads with an `InHead` (its unsafe contract), so the
    // first bytes of this private copy are an `InHead`.
    unsafe { (*ptr::addr_of_mut!(input).cast::<InHead>()).size = size_of::<I>() as u32 };
    let raw = op(
        instance,
        ptr::from_ref(&input).cast(),
        ptr::from_mut(&mut out).cast(),
    );
    let outcome = raw.outcome();
    let error = optional_text(out.head().error, "head.error");
    let owned = out.take(outcome, Token(()));
    out.clear(Token(()));
    Called {
        outcome,
        out,
        error,
        owned,
    }
}

// ── the reviewed copies ──────────────────────────────────────────────────────────────────────────

/// Secret material, copied into memory wiped on drop; never printed.
pub struct SecretCopy(Zeroizing<Vec<u8>>);

impl SecretCopy {
    /// The material.
    #[must_use]
    pub fn material(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Debug for SecretCopy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SecretCopy(<{} bytes>)", self.0.len())
    }
}

/// An export `serve` reply, copied.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Served {
    /// `headers_out`, as (name, value, name, value, ...).
    pub headers: Vec<String>,
    /// The body.
    pub body: Vec<u8>,
}

/// One login form field, copied.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LoginFieldCopy {
    /// Its name.
    pub name: String,
    /// Its label.
    pub label: String,
    /// `LOGIN_FIELD_*`.
    pub kind: u32,
    /// `1` = required.
    pub required: u32,
}

/// An auth `begin_login` reply, copied.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BeganLogin {
    /// The authorize URL (empty = absent).
    pub authorize_url: String,
    /// The form's fields.
    pub form: Vec<LoginFieldCopy>,
}

/// One snapshot claim, copied.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClaimCopy {
    /// Its verb.
    pub verb: String,
    /// Its target.
    pub target: String,
    /// Its carrier.
    pub carrier: String,
    /// `CLAIM_*` bits.
    pub flags: u32,
    /// Its refusal dialect.
    pub refusal_dialect: u16,
}

/// One snapshot admin route, copied.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdminRouteCopy {
    /// Its verb.
    pub verb: String,
    /// Its target.
    pub target: String,
    /// Its flags.
    pub flags: u32,
    /// Its audit verb.
    pub audit_verb: String,
}

/// A plane's published snapshot, copied.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SnapshotCopy {
    /// Its generation.
    pub generation: u64,
    /// Its claims.
    pub claims: Vec<ClaimCopy>,
    /// Its admin routes.
    pub admin_routes: Vec<AdminRouteCopy>,
    /// Its OpenAPI document.
    pub openapi: Vec<u8>,
    /// Its audience.
    pub audience: String,
    /// Its resource metadata.
    pub resource_metadata: String,
    /// Its resource facts.
    pub resource_facts: Vec<u8>,
    /// Its listed names.
    pub listed: Vec<String>,
    /// Its arrival spans.
    pub arrival_spans: Vec<String>,
}

// ── the reviewed `out`s ──────────────────────────────────────────────────────────────────────────

/// The head's pointer fields cleared: its error, its envelope's lists, its extensions.
fn clear_head(h: &mut OutHead) {
    h.error = AbiStr {
        ptr: ptr::null(),
        len: 0,
    };
    h.envelope.metrics = ptr::null();
    h.envelope.metrics_len = 0;
    h.envelope.diags = ptr::null();
    h.envelope.diags_len = 0;
    h.extensions = Blob {
        ptr: ptr::null(),
        len: 0,
        ..h.extensions
    };
}

/// `Err` from a kind's validator, as a panic naming the field.
fn judged(r: Result<(), Fault>) {
    if let Err(f) = r {
        panic!("{}: {:?}", f.field, f.rule);
    }
}

impl sealed::Take for OutHead {
    fn head(&mut self) -> &mut OutHead {
        self
    }
    fn clear(&mut self, _: Token) {
        clear_head(self);
    }
    fn take(&self, _: Outcome, _: Token) {}
}
impl Reply for OutHead {
    type Owned = ();
}

impl sealed::Take for crate::abi::mechanism::lifecycle::OpenOut {
    fn head(&mut self) -> &mut OutHead {
        &mut self.head
    }
    fn clear(&mut self, _: Token) {
        clear_head(&mut self.head);
    }
    fn take(&self, _: Outcome, _: Token) {}
}
impl Reply for crate::abi::mechanism::lifecycle::OpenOut {
    type Owned = ();
}

impl sealed::Take for crate::abi::secret::ResolveOut {
    fn head(&mut self) -> &mut OutHead {
        &mut self.head
    }
    fn clear(&mut self, _: Token) {
        clear_head(&mut self.head);
        self.secret = Blob {
            ptr: ptr::null(),
            len: 0,
            ..self.secret
        };
    }
    fn take(&self, _: Outcome, _: Token) -> SecretCopy {
        judged(crate::abi::secret::validate::check_resolve(self));
        let mut copy = Zeroizing::new(Vec::new());
        copy.extend_from_slice(lent(self.secret.ptr, self.secret.len, "resolve.secret"));
        SecretCopy(copy)
    }
}
impl Reply for crate::abi::secret::ResolveOut {
    type Owned = SecretCopy;
}

impl sealed::Take for crate::abi::export::ServeOut {
    fn head(&mut self) -> &mut OutHead {
        &mut self.head
    }
    fn clear(&mut self, _: Token) {
        clear_head(&mut self.head);
        self.headers_out = ptr::null();
        self.headers_out_len = 0;
        self.body = Blob {
            ptr: ptr::null(),
            len: 0,
            ..self.body
        };
    }
    fn take(&self, _: Outcome, _: Token) -> Served {
        judged(crate::abi::export::validate::check_serve(self));
        Served {
            headers: list(self.headers_out, self.headers_out_len, "serve.headers_out")
                .iter()
                .map(|s| text(*s, "serve.headers_out.entry"))
                .collect(),
            body: lent(self.body.ptr, self.body.len, "serve.body").to_vec(),
        }
    }
}
impl Reply for crate::abi::export::ServeOut {
    type Owned = Served;
}

impl sealed::Take for crate::abi::export::CheckOut {
    fn head(&mut self) -> &mut OutHead {
        &mut self.head
    }
    fn clear(&mut self, _: Token) {
        clear_head(&mut self.head);
        self.findings = Blob {
            ptr: ptr::null(),
            len: 0,
            ..self.findings
        };
    }
    fn take(&self, _: Outcome, _: Token) -> Vec<u8> {
        judged(crate::abi::export::validate::check_check(self));
        lent(self.findings.ptr, self.findings.len, "check.findings").to_vec()
    }
}
impl Reply for crate::abi::export::CheckOut {
    type Owned = Vec<u8>;
}

impl sealed::Take for crate::abi::export::StatusOut {
    fn head(&mut self) -> &mut OutHead {
        &mut self.head
    }
    fn clear(&mut self, _: Token) {
        clear_head(&mut self.head);
        self.status = Blob {
            ptr: ptr::null(),
            len: 0,
            ..self.status
        };
    }
    fn take(&self, _: Outcome, _: Token) -> Vec<u8> {
        judged(crate::abi::export::validate::check_status(self));
        lent(self.status.ptr, self.status.len, "status.status").to_vec()
    }
}
impl Reply for crate::abi::export::StatusOut {
    type Owned = Vec<u8>;
}

impl sealed::Take for crate::abi::auth::BeginLoginOut {
    fn head(&mut self) -> &mut OutHead {
        &mut self.head
    }
    fn clear(&mut self, _: Token) {
        clear_head(&mut self.head);
        self.authorize_url = AbiStr {
            ptr: ptr::null(),
            len: 0,
        };
        self.form = ptr::null();
        self.form_len = 0;
    }
    fn take(&self, outcome: Outcome, _: Token) -> BeganLogin {
        judged(crate::abi::auth::check_begin_login(outcome, self));
        BeganLogin {
            authorize_url: text(self.authorize_url, "begin_login.authorize_url"),
            form: list(self.form, self.form_len, "begin_login.form")
                .iter()
                .map(|f| LoginFieldCopy {
                    name: text(f.name, "begin_login.form.name"),
                    label: text(f.label, "begin_login.form.label"),
                    kind: f.kind,
                    required: f.required,
                })
                .collect(),
        }
    }
}
impl Reply for crate::abi::auth::BeginLoginOut {
    type Owned = BeganLogin;
}

impl sealed::Take for crate::abi::plane::PlaneOpenOut {
    fn head(&mut self) -> &mut OutHead {
        &mut self.open.head
    }
    fn clear(&mut self, _: Token) {
        clear_head(&mut self.open.head);
        self.snapshot = ptr::null();
    }
    fn take(&self, _: Outcome, _: Token) -> Option<SnapshotCopy> {
        snapshot(self.snapshot)
    }
}
impl Reply for crate::abi::plane::PlaneOpenOut {
    type Owned = Option<SnapshotCopy>;
}

impl sealed::Take for crate::abi::plane::PlaneRefreshOut {
    fn head(&mut self) -> &mut OutHead {
        &mut self.head
    }
    fn clear(&mut self, _: Token) {
        clear_head(&mut self.head);
        self.snapshot = ptr::null();
    }
    fn take(&self, _: Outcome, _: Token) -> Option<SnapshotCopy> {
        snapshot(self.snapshot)
    }
}
impl Reply for crate::abi::plane::PlaneRefreshOut {
    type Owned = Option<SnapshotCopy>;
}

/// The snapshot a plane published at `p` (NULL = none), judged by the kind's own check and copied.
fn snapshot(p: *const crate::abi::plane::PlaneSnapshot) -> Option<SnapshotCopy> {
    use crate::abi::plane::PlaneSnapshot;
    if p.is_null() {
        return None;
    }
    assert!(p.is_aligned(), "snapshot: misaligned");
    // SAFETY: a non-NULL, aligned snapshot the op published, live while its generation is (the
    // door contract); its leading `size` is read first.
    let size = unsafe { p.cast::<u32>().read() } as usize;
    assert_eq!(
        size,
        core::mem::size_of::<PlaneSnapshot>(),
        "snapshot.size: not this contract's snapshot"
    );
    // SAFETY: as above, and the snapshot states this contract's whole size.
    let s = unsafe { p.read() };
    judged(crate::abi::plane::check::check_snapshot(&s, s.generation));
    Some(SnapshotCopy {
        generation: s.generation,
        claims: list(s.claims, s.claims_len, "snapshot.claims")
            .iter()
            .map(|c| ClaimCopy {
                verb: text(c.verb, "snapshot.claim.verb"),
                target: text(c.target, "snapshot.claim.target"),
                carrier: text(c.carrier, "snapshot.claim.carrier"),
                flags: c.flags,
                refusal_dialect: c.refusal_dialect,
            })
            .collect(),
        admin_routes: list(s.admin_routes, s.admin_routes_len, "snapshot.admin_routes")
            .iter()
            .map(|r| AdminRouteCopy {
                verb: text(r.verb, "snapshot.admin_route.verb"),
                target: text(r.target, "snapshot.admin_route.target"),
                flags: r.flags,
                audit_verb: text(r.audit_verb, "snapshot.admin_route.audit_verb"),
            })
            .collect(),
        openapi: lent(s.openapi.ptr, s.openapi.len, "snapshot.openapi").to_vec(),
        audience: text(s.audience, "snapshot.audience"),
        resource_metadata: text(s.resource_metadata, "snapshot.resource_metadata"),
        resource_facts: lent(
            s.resource_facts.ptr,
            s.resource_facts.len,
            "snapshot.resource_facts",
        )
        .to_vec(),
        listed: list(s.listed, s.listed_len, "snapshot.listed")
            .iter()
            .map(|n| text(*n, "snapshot.listed.entry"))
            .collect(),
        arrival_spans: list(
            s.arrival_spans,
            s.arrival_spans_len,
            "snapshot.arrival_spans",
        )
        .iter()
        .map(|n| text(*n, "snapshot.arrival_spans.entry"))
        .collect(),
    })
}

// ── the reads, each checked first ────────────────────────────────────────────────────────────────
//
// Called ONLY from a reviewed `take` (or `call`'s head read), over a field the op wrote.

/// `len` bytes at `ptr`, borrowed just long enough to copy.
fn lent<'a>(ptr: *const u8, len: usize, field: &str) -> &'a [u8] {
    if len == 0 {
        return &[];
    }
    assert!(!ptr.is_null(), "{field}: NULL with a count of {len}");
    assert!(
        len as u64 <= HARD_MAX_BYTES,
        "{field}: {len} bytes, over the bound of {HARD_MAX_BYTES}"
    );
    // SAFETY: non-NULL and bounded; `len` live bytes the op wrote (the door contract).
    unsafe { core::slice::from_raw_parts(ptr, len) }
}

/// `len` entries at `ptr`, borrowed just long enough to copy.
fn list<'a, T>(ptr: *const T, len: usize, field: &str) -> &'a [T] {
    if len == 0 {
        return &[];
    }
    assert!(!ptr.is_null(), "{field}: NULL with a count of {len}");
    assert!(
        len <= STATEMENT_LIST_MAX,
        "{field}: a count of {len}, over the bound of {STATEMENT_LIST_MAX}"
    );
    assert!(ptr.is_aligned(), "{field}: misaligned");
    // SAFETY: non-NULL, aligned and bounded; `len` live entries the op wrote (the door contract).
    unsafe { core::slice::from_raw_parts(ptr, len) }
}

/// A text the op wrote, copied (empty = absent).
fn text(s: AbiStr, field: &str) -> String {
    let b = lent(s.ptr, s.len, field);
    match core::str::from_utf8(b) {
        Ok(t) => t.to_owned(),
        Err(_) => panic!("{field}: not UTF-8"),
    }
}

/// A text the op wrote, copied; `None` = absent (NULL).
fn optional_text(s: AbiStr, field: &str) -> Option<String> {
    if s.ptr.is_null() {
        assert!(s.len == 0, "{field}: NULL with a count of {}", s.len);
        return None;
    }
    Some(text(s, field))
}
