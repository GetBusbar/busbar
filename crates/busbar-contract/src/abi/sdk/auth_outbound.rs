// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE AUTH KIND'S OUTBOUND DOOR, FOR A SAFE PLUGIN (`abi::auth`, the outbound family; THE DESIGN,
//! section 6 and sections 11.4 and 11.6): the auth kind's outbound bits over the SDK's safe layer
//! ([`SafeSlot`], [`Lent`], [`HostBuf`]). An auth plugin that presents credentials to an upstream
//! implements [`OutboundPlugin`], and [`auth_outbound_door!`](macro@crate::auth_outbound_door)
//! builds its whole door over the auth table: the lifecycle, `open_outbound`, `outbound_ready`,
//! `fields`, and
//! the inbound ops answering REFUSED (the plugin states only
//! [`CAP_OUTBOUND`](crate::abi::auth::CAP_OUTBOUND)). A plugin that also verifies (one mechanism
//! both ways, as SigV4) implements [`VerifyPlugin`] too and names
//! [`auth_door!`](macro@crate::auth_door)`(verify_and_outbound: ..)`. The plugin crate holds no `unsafe`.
//!
//! * The lifecycle is the SDK's shared one (`abi::sdk::life`), over [`Outbound`], the kind's
//!   [`Life`]: `open` builds the plugin from its settings blob and secrets
//!   ([`OutboundPlugin::open`]); `refresh`, `retire` and `tick` forward to the plugin (a minted
//!   token refreshes ahead of expiry on `tick`).
//! * `open_outbound` binds a style to its credential and settings and answers the plugin's handle
//!   ([`OutboundPlugin::open_outbound`]); a refusal is FAILED with the plugin's lines
//!   ([`OpenRefusal`]).
//! * `fields` hands [`OutboundPlugin::fields`] a [`FieldsView`] of the request at one auth point
//!   and a [`FieldsWriter`]. The plugin stages its fields there; the kit writes them under THE
//!   SHORT-BUFFER RULE ([`FieldsOut`]): all of them, or (when they do not fit) nothing and the
//!   full sizes, so the host re-calls once with buffers that large and the plugin answers again.
//!   The staging copy is zeroised when the call returns (THE DESIGN: auth material is zeroised).
//! * A `fields` that waits (an expired token whose refresh is in flight) answers
//!   [`Poll::Pending`] while its one [`Op::exchange`] pends, as a hook does: the op answers
//!   PENDING and the host re-enters it on its ticket when the wake fires. A TICKET-LESS `fields`
//!   (the host's on-the-spot try) cannot pend: it answers REFUSED there, and the host submits the
//!   same call on a ticket.
//! * THE DECLARED DIAGNOSTICS (#85, the reply envelope's `diags` in every op's out head): the
//!   lines the plugin's Statement names in `diag_ids` (its 1.5.5 builders' own lines), staged into
//!   [`Diags`] by `open_outbound` (READY or FAILED), `fields` ([`FieldsWriter::diag`]), `tick` and
//!   `drive`, and written by the kit into that call's envelope through [`Out::diag`]: kept by the
//!   answering instance until the host has copied the reply. The host renders each as the plugin's
//!   main-log line.
//! * THE DRIVER TICKET (`abi::mechanism::lifecycle`, `tick`/`drive`/`cancel`): a plugin that mints
//!   ahead of expiry runs its exchange on the instance's driver ticket. `tick` hands it the host
//!   tables and that ticket ([`OutboundPlugin::tick`]); `drive` re-enters it when the ticket is
//!   woken ([`OutboundPlugin::drive`]); `cancel` answers the plugin's own disposition for the
//!   cancelled ticket ([`OutboundPlugin::cancel`]). The defaults are a plugin that holds no driver
//!   ticket: `tick` wants none, `drive` is REFUSED, `cancel` is
//!   [`CANCEL_ABANDONED`](crate::abi::auth::CANCEL_ABANDONED).

use std::borrow::Cow;
use std::marker::PhantomData;
use std::task::Poll;

use zeroize::Zeroizing;

use crate::abi::auth::{
    AuthPoint, AuthPoints, AuthTail, FieldSpan, FieldsIn, FieldsOut, IdentifyOut, OpenOutboundIn,
    OpenOutboundOut, OutboundReadyIn, OutboundReadyOut, StyleDecl, VerifyIn, EXT_SCOPE,
    FIELD_QUERY, FIELD_SENSITIVE, MODE_OWN, MODE_PASSTHROUGH,
};
use crate::abi::mechanism::call::{Blob, OutHead, Outcome, Span, BLOB_ABSENT};
use crate::abi::mechanism::door::KindTailHead;
use crate::abi::mechanism::lifecycle::{CancelIn, CancelOut, DriveIn, TickIn, TickOut};
use crate::abi::mechanism::ticket::Ticket;
use crate::abi::sdk::auth_door::{verify_answer, verify_op, VerifyPlugin};
use crate::abi::sdk::conn::Host;
use crate::abi::sdk::door::{AbiIn, AbiOut};
use crate::abi::sdk::exchange::Op;
use crate::abi::sdk::lent::{HostBuf, Lent};
use crate::abi::sdk::life::{Counted, Held, Life, Refreshed, Refusal};
use crate::abi::sdk::out::Out;
use crate::abi::sdk::safe::{Instance, SafeSlot};

/// A present blob's bytes; `None` when absent.
fn present(b: Lent<'_, Blob>) -> Option<&[u8]> {
    (b.fmt != BLOB_ABSENT && !b.ptr.is_null()).then(|| b.bytes())
}

/// Whose credential a `fields` call presents ([`FieldsIn::mode`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    /// [`MODE_OWN`]: the plugin's own bound credential.
    Own,
    /// [`MODE_PASSTHROUGH`]: the caller's verified credential
    /// ([`FieldsView::caller_credential`]).
    Passthrough,
}

/// One `fields`' request, as a safe plugin reads it; lent for the call.
#[derive(Debug, Clone, Copy)]
pub struct FieldsView<'a> {
    input: Lent<'a, FieldsIn>,
}

impl<'a> FieldsView<'a> {
    /// The handle `open_outbound` answered.
    #[must_use]
    pub fn handle(&self) -> u64 {
        self.input.handle
    }

    /// Whose credential to present. (A mode outside the vocabulary never reaches the plugin: the
    /// kit answers it FAULT.)
    #[must_use]
    pub fn mode(&self) -> Mode {
        if self.input.mode == MODE_PASSTHROUGH {
            Mode::Passthrough
        } else {
            Mode::Own
        }
    }

    /// The point this call is made at; `None` for a value outside the vocabulary.
    #[must_use]
    pub fn point(&self) -> Option<AuthPoint> {
        AuthPoint::from_bit(self.input.point)
    }

    /// The connection the binding sends on; `0` while none is dialed yet.
    #[must_use]
    pub fn conn(&self) -> u64 {
        self.input.conn
    }

    /// The unit the request belongs to; `0` = none.
    #[must_use]
    pub fn unit(&self) -> u64 {
        self.input.unit
    }

    /// The method.
    #[must_use]
    pub fn method(&self) -> &'a [u8] {
        self.input.field(|i| &i.request.method).bytes()
    }

    /// The authority (host\[:port\]).
    #[must_use]
    pub fn authority(&self) -> &'a [u8] {
        self.input.field(|i| &i.request.authority).bytes()
    }

    /// The path exactly as the framer will send it (already percent-encoded).
    #[must_use]
    pub fn path(&self) -> &'a [u8] {
        self.input.field(|i| &i.request.canonical_path).bytes()
    }

    /// The query without `?`, as it will be sent; `None` = none.
    #[must_use]
    pub fn query(&self) -> Option<&'a [u8]> {
        let q = self.input.field(|i| &i.request.query);
        (!q.ptr.is_null()).then(|| q.bytes())
    }

    /// Wall-clock seconds, read once by the host for this call.
    #[must_use]
    pub fn timestamp(&self) -> u64 {
        self.input.request.timestamp
    }

    /// The exact head envelope the framer will send, in order: (name, value). Empty unless the
    /// style declares [`STYLE_NEEDS_HEADERS`](crate::abi::auth::STYLE_NEEDS_HEADERS).
    pub fn headers(&self) -> impl Iterator<Item = (&'a [u8], &'a [u8])> + 'a {
        self.input
            .headers()
            .iter()
            .map(|l| (l.field(|c| &c.name).bytes(), l.field(|c| &c.value).bytes()))
    }

    /// The caller's verified credential, in [`Mode::Passthrough`]; `None` otherwise.
    #[must_use]
    pub fn caller_credential(&self) -> Option<&'a [u8]> {
        present(self.input.field(|i| &i.caller_credential))
    }

    /// The whole body; `None` = the host lent none (every point but [`AuthPoint::HeadBody`]).
    #[must_use]
    pub fn body(&self) -> Option<&'a [u8]> {
        let b = self.input.field(|i| &i.body);
        (b.fmt != BLOB_ABSENT).then(|| b.bytes())
    }

    /// The per-call scope the request stated ([`EXT_SCOPE`] in the call's extensions); `None` =
    /// none.
    #[must_use]
    pub fn scope(&self) -> Option<&'a [u8]> {
        let ext = self.input.field(|i| &i.head.extensions).bytes();
        crate::abi::mechanism::extensions::get(ext, EXT_SCOPE)
    }
}

/// THE DECLARED DIAGNOSTICS ONE CALL REPORTS (#85): each the id at its index in the Statement's
/// `diag_ids`, a `SEVERITY_*` (`abi::mechanism::call`) and its text, in order. The kit writes them
/// into the call's reply envelope (`OutHead.envelope.diags`) through [`Out::diag`] when the plugin
/// answers, whatever it answers; the host renders each as the plugin's main-log line. Past
/// [`MAX_ENVELOPE_ENTRIES`](crate::abi::mechanism::call::MAX_ENVELOPE_ENTRIES) in one reply, the
/// rest are not reported.
#[derive(Debug, Default)]
pub struct Diags {
    staged: Vec<(u32, u8, Box<str>)>,
}

impl Diags {
    /// None staged.
    #[must_use]
    pub const fn new() -> Self {
        Self { staged: Vec::new() }
    }

    /// Report the diagnostic `id_idx` at `severity`, saying `text`, after those before it.
    pub fn push(&mut self, id_idx: u32, severity: u8, text: impl Into<Box<str>>) {
        self.staged.push((id_idx, severity, text.into()));
    }

    /// How many are staged.
    #[must_use]
    pub fn len(&self) -> usize {
        self.staged.len()
    }

    /// Whether none is.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.staged.is_empty()
    }

    /// The staged diagnostics, in order: `(id_idx, severity, text)` (a plugin's own tests read
    /// what it noted here).
    pub fn iter(&self) -> impl Iterator<Item = (u32, u8, &str)> {
        self.staged
            .iter()
            .map(|(id, sev, text)| (*id, *sev, &**text))
    }

    /// Write them into the reply's envelope, in order.
    pub(crate) fn write<T: AbiOut>(self, out: &mut Out<'_, T>) {
        for (id_idx, severity, text) in self.staged {
            if !out.diag(id_idx, severity, text) {
                break;
            }
        }
    }
}

/// One staged field: its name and value lengths in the staging bytes, in order, and its flags.
#[derive(Debug, Clone, Copy)]
struct Staged {
    name: usize,
    value: usize,
    flags: u32,
}

/// THE FIELDS A `fields` ANSWERS, staged by the plugin and written by the kit into the host's
/// field buffer and field array when the plugin answers [`FieldsAnswer::Ready`]: all of them, or
/// (short) none. The staging bytes are credential material: zeroised when the writer drops, and
/// never left behind in a freed allocation as they grow.
pub struct FieldsWriter<'a> {
    bytes: HostBuf<'a, u8>,
    spans: HostBuf<'a, FieldSpan>,
    staged: Zeroizing<Vec<u8>>,
    fields: Vec<Staged>,
    stray: bool,
    diags: Diags,
}

impl std::fmt::Debug for FieldsWriter<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never the staged bytes: they are credential material.
        f.debug_struct("FieldsWriter")
            .field("fields", &self.fields.len())
            .finish_non_exhaustive()
    }
}

impl<'a> FieldsWriter<'a> {
    fn of(input: Lent<'a, FieldsIn>) -> Self {
        Self {
            bytes: input.field_buf(),
            spans: input.fields(),
            staged: Zeroizing::new(Vec::new()),
            fields: Vec::new(),
            stray: false,
            diags: Diags::default(),
        }
    }

    /// Report the declared diagnostic `id_idx` at `severity`, saying `text`, in this call's reply
    /// envelope (whatever the call answers): [`Diags::push`].
    pub fn diag(&mut self, id_idx: u32, severity: u8, text: impl Into<Box<str>>) {
        self.diags.push(id_idx, severity, text);
    }

    /// Stage the field `name: value`, after those staged before it. `flags` holds only
    /// [`FIELD_SENSITIVE`] and [`FIELD_QUERY`]; any other bit is the plugin's bug, and the call
    /// answers FAULT.
    pub fn push(&mut self, name: &[u8], value: &[u8], flags: u32) {
        if flags & !(FIELD_SENSITIVE | FIELD_QUERY) != 0 {
            self.stray = true;
            return;
        }
        self.stage(name);
        self.stage(value);
        self.fields.push(Staged {
            name: name.len(),
            value: value.len(),
            flags,
        });
    }

    /// How many fields are staged.
    #[must_use]
    pub fn len(&self) -> usize {
        self.fields.len()
    }

    /// Whether none is (a READY answer with none = no auth header).
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.fields.is_empty()
    }

    /// Append `b` to the staging bytes. Growing moves them into a new allocation and drops the old
    /// one zeroised, so no copy of a credential is freed unwiped.
    fn stage(&mut self, b: &[u8]) {
        let want = self.staged.len().saturating_add(b.len());
        if want > self.staged.capacity() {
            let cap = want.max(self.staged.capacity().saturating_mul(2));
            let mut grown = Zeroizing::new(Vec::with_capacity(cap));
            grown.extend_from_slice(&self.staged);
            self.staged = grown;
        }
        self.staged.extend_from_slice(b);
    }

    /// WRITE the staged fields into the host's buffers and answer READY, or, when they do not fit,
    /// the SHORT FAILED: nothing written, `needed_fields`/`needed_bytes` at their full sizes (the
    /// host re-calls once with buffers that large). Never writes past a capacity.
    fn write(mut self, out: &mut Out<'_, FieldsOut>) -> Outcome {
        if self.stray {
            return Outcome::Fault;
        }
        let count = self.fields.len();
        let bytes = self.staged.len();
        if u32::try_from(bytes).is_err() {
            return out.fail(Refusal::failed("auth fields: over 4 GiB"));
        }
        // The fit check first: a short answer writes nothing into the host's buffers.
        if count > self.spans.cap() || bytes > self.bytes.cap() {
            out.set(
                |o| &o.needed_fields,
                u32::try_from(count).unwrap_or(u32::MAX),
            );
            out.set(|o| &o.needed_bytes, bytes as u64);
            return Outcome::Failed;
        }
        self.bytes.extend(&self.staged);
        let mut at = 0_u32;
        let mut span = |len: usize| {
            let len = u32::try_from(len).unwrap_or(u32::MAX);
            let s = Span { offset: at, len };
            at = at.saturating_add(len);
            s
        };
        for f in &self.fields {
            let name = span(f.name);
            let value = span(f.value);
            self.spans.push(FieldSpan {
                name,
                value,
                flags: f.flags,
                ..FieldSpan::ZERO
            });
        }
        out.set(
            |o| &o.fields_len,
            u32::try_from(self.spans.written()).unwrap_or(u32::MAX),
        );
        Outcome::Ready
    }
}

/// A plugin's answer to one `fields` call.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FieldsAnswer {
    /// The fields the writer holds are the answer; none = no auth header (the upstream answers
    /// 401, as 1.5.5 did before the first mint).
    Ready,
    /// The handle refuses the request, saying nothing of why: superseded by
    /// [`FieldsAnswer::RefusedBecause`], kept so a plugin built against the earlier kit still
    /// compiles; the kit answers it REFUSED with [`REFUSED_UNSAID`].
    Refused,
    /// The call could not answer: the attempt fails, with this text.
    Failed(Cow<'static, str>),
    /// The handle refuses the request (a passthrough on a style that does not pass the caller's
    /// credential, or a handle this generation does not hold), saying why.
    RefusedBecause(Cow<'static, str>),
}

/// What a [`FieldsAnswer::Refused`] that named no reason answers REFUSED with.
pub const REFUSED_UNSAID: &str = "the auth plugin refused the request's fields and gave no reason";

/// Why `open_outbound` did not bind: one or more lines (a `credential: ...` line names a refusal
/// of the credential itself, as the `--validate` dry run reads it), answered FAILED with the lines
/// as its text, one per line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpenRefusal {
    lines: Vec<Cow<'static, str>>,
}

impl OpenRefusal {
    /// A refusal saying `line`.
    #[must_use]
    pub fn new(line: impl Into<Cow<'static, str>>) -> Self {
        Self {
            lines: vec![line.into()],
        }
    }

    /// This refusal with `line` after its lines.
    #[must_use]
    pub fn and(mut self, line: impl Into<Cow<'static, str>>) -> Self {
        self.lines.push(line.into());
        self
    }

    /// Its lines.
    #[must_use]
    pub fn lines(&self) -> &[Cow<'static, str>] {
        &self.lines
    }

    /// The answer's text: the lines, one per line (a single `'static` line is not copied).
    fn text(mut self) -> Cow<'static, str> {
        if self.lines.len() == 1 {
            return self.lines.remove(0);
        }
        Cow::Owned(self.lines.join("\n"))
    }
}

impl From<&'static str> for OpenRefusal {
    fn from(line: &'static str) -> Self {
        Self::new(line)
    }
}

impl From<String> for OpenRefusal {
    fn from(line: String) -> Self {
        Self::new(line)
    }
}

/// AN AUTH PLUGIN THAT PRESENTS CREDENTIALS UPSTREAM, in safe Rust.
pub trait OutboundPlugin: Send + Sync + Sized + 'static {
    /// `validate`: whether `settings` (one JSON document) open an instance; `Err` answers its
    /// outcome (REFUSED or FAILED) with its text. The default takes any settings (`open` judges).
    ///
    /// # Errors
    /// The settings are not this plugin's.
    fn validate(settings: &[u8]) -> Result<(), Refusal> {
        let _ = settings;
        Ok(())
    }

    /// Build the plugin from its settings blob (one JSON document) and its resolved secrets (one
    /// per Statement `secret_refs` key, in order), at `generation` (the generation the handles it
    /// opens belong to until [`OutboundPlugin::refresh`] names the next). `Err` answers `open`
    /// with the refusal's outcome and text.
    ///
    /// # Errors
    /// The settings are not this plugin's.
    fn open(settings: &[u8], secrets: &[&[u8]], generation: u64) -> Result<Self, Refusal>;

    /// Bind `style` (one the tail declares) to its resolved `credential` (`None` for a
    /// passthrough-only binding) and the provider's auth `settings` (`None` when absent); the
    /// handle, valid until `retire` of this generation. Never waits: a first mint runs on the
    /// driver ticket ([`OutboundPlugin::tick`]; `host` wakes it at once). What the binding notes
    /// (a credential it opened but cannot present) goes in `diags`, READY or FAILED alike.
    ///
    /// # Errors
    /// The binding is refused, in the plugin's own lines.
    fn open_outbound(
        &self,
        style: &str,
        credential: Option<&[u8]>,
        settings: Option<&[u8]>,
        host: Option<&Host>,
        diags: &mut Diags,
    ) -> Result<u64, OpenRefusal>;

    /// The auth fields for `request`, staged into `out`; [`Poll::Pending`] while `op`'s one
    /// exchange pends (an expired token being refreshed), re-entered from the top on the wake.
    fn fields(
        &self,
        request: &FieldsView<'_>,
        out: &mut FieldsWriter<'_>,
        op: &Op<'_>,
    ) -> Poll<FieldsAnswer>;

    /// Whether `fields` on `handle` would answer with a credential now (`false` before a minting
    /// style's first mint, or expired with a failed refresh, or for a handle it does not hold).
    fn outbound_ready(&self, handle: u64) -> bool;

    /// A reload to `generation`, with the new settings and secrets: the handles opened from now on
    /// belong to it. The outbound token cache survives it (it is keyed by style, credential and
    /// settings, never by handle). `Err` refuses the reload with the refusal's outcome and text.
    ///
    /// # Errors
    /// The new settings are not this plugin's.
    fn refresh(&self, settings: &[u8], secrets: &[&[u8]], generation: u64) -> Result<(), Refusal> {
        let _ = (settings, secrets, generation);
        Ok(())
    }

    /// `retire` of `generation`: drop the handles opened at it.
    fn retire(&self, generation: u64) {
        let _ = generation;
    }

    /// `tick` at `now_ns` on the instance's DRIVER TICKET `driver` (owned by the instance, outside
    /// `max_inflight`), over the host tables `open` handed the instance (`None`: none): refresh
    /// what is about to expire, starting its exchange on `driver` (`host.connector(driver)`); the
    /// next tick wanted, `0` = none. What it notes goes in `diags`.
    fn tick(&self, now_ns: u64, host: Option<&Host>, driver: Ticket, diags: &mut Diags) -> u64 {
        let _ = (now_ns, host, driver, diags);
        0
    }

    /// `drive`: the driver ticket `driver` was woken (a read of the exchange that pended, or a
    /// mint wanted at once): carry the exchange on. [`Driven::Pending`] while it waits, with the
    /// instant to be re-driven at even if nothing wakes it; the plugin wakes the call tickets that
    /// wait on what it minted ([`Host::wake`]). The default holds no driver ticket: REFUSED.
    fn drive(&self, host: Option<&Host>, driver: Ticket, diags: &mut Diags) -> Driven {
        let _ = (host, driver, diags);
        Driven::Refused
    }

    /// `cancel` of `ticket` (a call that waited, or the driver ticket): forget what waits on it,
    /// and answer the kind's disposition (`abi::auth`: [`CANCEL_ABANDONED`] = nothing kept,
    /// [`CANCEL_CONTINUES`] = the work it started completes and fills the cache). The SDK has
    /// already dropped what the ticket parked.
    ///
    /// [`CANCEL_ABANDONED`]: crate::abi::auth::CANCEL_ABANDONED
    /// [`CANCEL_CONTINUES`]: crate::abi::auth::CANCEL_CONTINUES
    fn cancel(&self, ticket: Ticket) -> u32 {
        let _ = ticket;
        crate::abi::auth::CANCEL_ABANDONED
    }
}

/// What a `drive` answers ([`OutboundPlugin::drive`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Driven {
    /// Nothing waits on the driver ticket now: READY.
    Ready,
    /// The exchange waits: PENDING, re-driven when its wake fires, and no later than `wake_at_ns`
    /// on the host's monotonic clock (`0` = on a wake only). A ticket-less `drive` cannot pend: it
    /// answers READY.
    Pending {
        /// The latest re-drive, `0` = none.
        wake_at_ns: u64,
    },
    /// The plugin holds no driver ticket: REFUSED.
    Refused,
}

/// A [`Life`] that holds an [`OutboundPlugin`] `T`: [`Outbound<T>`], or [`Both<T>`] for a plugin
/// that verifies too. The outbound slots serve either.
pub trait HoldsOutbound<T: OutboundPlugin>: Life {
    /// The plugin.
    fn outbound(&self) -> &T;
}

/// THE AUTH KIND'S [`Life`] over an [`OutboundPlugin`] `T`: the instance state the shared
/// lifecycle slots (`abi::sdk::life`) serve, a [`Held`] of it. Each per-kind value is stated here:
///
/// * `validate`, `open`, `refresh` and `retire` are the plugin's (`open` and `refresh` with the
///   generation, so a handle is generation data);
/// * `tick`, `drive` and `cancel` are the plugin's too, through the kit's own slots
///   ([`OutboundTick`], [`OutboundDrive`], [`OutboundCancel`]), which hand it the host tables and
///   the driver ticket: [`Life::DRIVE`] and [`Life::CANCEL`] here are what a door naming the
///   generic slots would answer for a plugin with no driver ticket (REFUSED, and
///   [`CANCEL_ABANDONED`](crate::abi::auth::CANCEL_ABANDONED)).
pub struct Outbound<T>(T);

impl<T> std::fmt::Debug for Outbound<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Outbound").finish_non_exhaustive()
    }
}

impl<T> Outbound<T> {
    /// The plugin.
    #[must_use]
    pub const fn plugin(&self) -> &T {
        &self.0
    }
}

impl<T: OutboundPlugin> Life for Outbound<T> {
    const CANCEL: u32 = crate::abi::auth::CANCEL_ABANDONED;
    const DRIVE: Outcome = Outcome::Refused;

    fn validate(settings: &[u8]) -> Result<(), Refusal> {
        T::validate(settings)
    }

    fn open(settings: &[u8], secrets: &[&[u8]], generation: u64) -> Result<Self, Refusal> {
        T::open(settings, secrets, generation).map(Outbound)
    }

    fn refresh(
        &self,
        settings: &[u8],
        secrets: &[&[u8]],
        generation: u64,
    ) -> Result<Refreshed, Refusal> {
        self.0.refresh(settings, secrets, generation)?;
        Ok(Refreshed::default())
    }

    fn retire(&self, generation: u64) {
        self.0.retire(generation);
    }
}

impl<T: OutboundPlugin> HoldsOutbound<T> for Outbound<T> {
    fn outbound(&self) -> &T {
        &self.0
    }
}

/// THE AUTH KIND'S [`Life`] over a plugin `T` that both verifies and presents (the SigV4 shape):
/// ONE `T`, built by [`OutboundPlugin::open`] (its [`VerifyPlugin::open`] must build the same
/// plugin). `refresh` calls both refreshes and reports the inbound entries
/// [`VerifyPlugin::refresh`] dropped under [`VerifyPlugin::CACHE_FAMILY`] (the outbound side's
/// refusal first: a refused reload flushes nothing); `validate`, `retire`, `tick`, `drive` and
/// `cancel` are the outbound side's.
pub struct Both<T>(T);

impl<T> std::fmt::Debug for Both<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Both").finish_non_exhaustive()
    }
}

impl<T> Both<T> {
    /// The plugin.
    #[must_use]
    pub const fn plugin(&self) -> &T {
        &self.0
    }
}

impl<T: VerifyPlugin + OutboundPlugin> Life for Both<T> {
    const CANCEL: u32 = crate::abi::auth::CANCEL_ABANDONED;
    const DRIVE: Outcome = Outcome::Refused;

    fn validate(settings: &[u8]) -> Result<(), Refusal> {
        <T as OutboundPlugin>::validate(settings)
    }

    fn open(settings: &[u8], secrets: &[&[u8]], generation: u64) -> Result<Self, Refusal> {
        <T as OutboundPlugin>::open(settings, secrets, generation).map(Both)
    }

    fn refresh(
        &self,
        settings: &[u8],
        secrets: &[&[u8]],
        generation: u64,
    ) -> Result<Refreshed, Refusal> {
        // The outbound side judges the new settings first: a refused reload flushes nothing.
        OutboundPlugin::refresh(&self.0, settings, secrets, generation)?;
        let dropped = VerifyPlugin::reload(&self.0, settings, secrets)?;
        Ok(Refreshed {
            counted: <T as VerifyPlugin>::CACHE_FAMILY.map(|family| Counted {
                family,
                value: dropped as f64,
            }),
        })
    }

    fn retire(&self, generation: u64) {
        OutboundPlugin::retire(&self.0, generation);
    }
}

impl<T: VerifyPlugin + OutboundPlugin> HoldsOutbound<T> for Both<T> {
    fn outbound(&self) -> &T {
        &self.0
    }
}

/// `open_outbound`: [`OutboundPlugin::open_outbound`], its handle answered.
#[derive(Debug)]
pub struct OpenOutboundSlot<T, L = Outbound<T>>(PhantomData<(T, L)>);
impl<T: OutboundPlugin, L: HoldsOutbound<T>> SafeSlot for OpenOutboundSlot<T, L> {
    type In = OpenOutboundIn;
    type Out = OpenOutboundOut;
    type State = Held<L>;
    fn call(
        instance: Instance<'_, Held<L>>,
        input: Lent<'_, OpenOutboundIn>,
        mut out: Out<'_, OpenOutboundOut>,
    ) -> Outcome {
        let Some(h) = instance.get() else {
            return Outcome::Fault;
        };
        // A style that is not UTF-8 is none the plugin declares.
        let Ok(style) = input.field(|i| &i.style).as_str() else {
            return out.fail(Refusal::refused(
                "open_outbound: the style is not UTF-8, so it is none this plugin declares",
            ));
        };
        let credential = present(input.field(|i| &i.credential));
        let settings = present(input.field(|i| &i.settings));
        let plugin = h.life().outbound();
        let mut diags = Diags::default();
        let opened = plugin.open_outbound(style, credential, settings, h.host(), &mut diags);
        diags.write(&mut out);
        match opened {
            Ok(handle) => {
                out.set(|o| &o.handle, handle);
                Outcome::Ready
            }
            Err(refusal) => out.fail(Refusal::failed(refusal.text())),
        }
    }
}

/// `outbound_ready`: [`OutboundPlugin::outbound_ready`].
#[derive(Debug)]
pub struct OutboundReadySlot<T, L = Outbound<T>>(PhantomData<(T, L)>);
impl<T: OutboundPlugin, L: HoldsOutbound<T>> SafeSlot for OutboundReadySlot<T, L> {
    type In = OutboundReadyIn;
    type Out = OutboundReadyOut;
    type State = Held<L>;
    fn call(
        instance: Instance<'_, Held<L>>,
        input: Lent<'_, OutboundReadyIn>,
        mut out: Out<'_, OutboundReadyOut>,
    ) -> Outcome {
        let Some(h) = instance.get() else {
            return Outcome::Fault;
        };
        let ready = h.life().outbound().outbound_ready(input.handle);
        out.set(|o| &o.ready, u32::from(ready));
        Outcome::Ready
    }
}

/// `fields`: [`OutboundPlugin::fields`], its staged fields written under the short-buffer rule;
/// PENDING while the plugin's exchange pends.
#[derive(Debug)]
pub struct FieldsSlot<T, L = Outbound<T>>(PhantomData<(T, L)>);
impl<T: OutboundPlugin, L: HoldsOutbound<T>> SafeSlot for FieldsSlot<T, L> {
    type In = FieldsIn;
    type Out = FieldsOut;
    type State = Held<L>;
    fn call(
        instance: Instance<'_, Held<L>>,
        input: Lent<'_, FieldsIn>,
        mut out: Out<'_, FieldsOut>,
    ) -> Outcome {
        let Some(h) = instance.get() else {
            return Outcome::Fault;
        };
        if !matches!(input.mode, MODE_OWN | MODE_PASSTHROUGH) {
            // A host bug: the plugin never reads a mode outside the vocabulary.
            return Outcome::Fault;
        }
        let mut writer = FieldsWriter::of(input);
        let op = Op::new(&instance, h.host());
        let plugin = h.life().outbound();
        let answer = plugin.fields(&FieldsView { input }, &mut writer, &op);
        if writer.stray {
            // The plugin's bug: FAULT, and a FAULT reply carries no envelope.
            return Outcome::Fault;
        }
        std::mem::take(&mut writer.diags).write(&mut out);
        match answer {
            // On the spot the call cannot pend (a ticket-less PENDING is FAULT): REFUSED there,
            // and the host submits it on a ticket.
            Poll::Pending if instance.ticket().is_none() => out.fail(Refusal::refused(
                "fields waits on its exchange: it is answered on a ticket, not on the spot",
            )),
            Poll::Pending => Outcome::Pending,
            Poll::Ready(FieldsAnswer::Ready) => writer.write(&mut out),
            Poll::Ready(FieldsAnswer::Refused) => out.fail(Refusal::refused(REFUSED_UNSAID)),
            Poll::Ready(FieldsAnswer::RefusedBecause(why)) => out.fail(Refusal::refused(why)),
            Poll::Ready(FieldsAnswer::Failed(why)) => out.fail(Refusal::failed(why)),
        }
    }
}

/// `tick` on an outbound door: [`OutboundPlugin::tick`] on the call's ticket (the instance's driver
/// ticket), over the host tables `open` handed the instance; what it noted rides the reply.
#[derive(Debug)]
pub struct OutboundTick<T, L = Outbound<T>>(PhantomData<(T, L)>);
impl<T: OutboundPlugin, L: HoldsOutbound<T>> SafeSlot for OutboundTick<T, L> {
    type In = TickIn;
    type Out = TickOut;
    type State = Held<L>;
    fn call(
        instance: Instance<'_, Held<L>>,
        input: Lent<'_, TickIn>,
        mut out: Out<'_, TickOut>,
    ) -> Outcome {
        let Some(h) = instance.get() else {
            return Outcome::Fault;
        };
        let mut diags = Diags::default();
        let next = h
            .life()
            .outbound()
            .tick(input.now_ns, h.host(), instance.ticket(), &mut diags);
        diags.write(&mut out);
        out.set(|o| &o.next_tick_ns, next);
        Outcome::Ready
    }
}

/// `drive` on an outbound door: [`OutboundPlugin::drive`] on the woken driver ticket; PENDING (with
/// its latest re-drive) while the exchange waits, READY on a ticket-less call.
#[derive(Debug)]
pub struct OutboundDrive<T, L = Outbound<T>>(PhantomData<(T, L)>);
impl<T: OutboundPlugin, L: HoldsOutbound<T>> SafeSlot for OutboundDrive<T, L> {
    type In = DriveIn;
    type Out = OutHead;
    type State = Held<L>;
    fn call(
        instance: Instance<'_, Held<L>>,
        input: Lent<'_, DriveIn>,
        mut out: Out<'_, OutHead>,
    ) -> Outcome {
        let Some(h) = instance.get() else {
            return Outcome::Fault;
        };
        // The driver ticket that woke (`DriveIn::driver`); the call's own when the host named none.
        let driver = if input.driver.is_none() {
            instance.ticket()
        } else {
            input.driver
        };
        let mut diags = Diags::default();
        let driven = h.life().outbound().drive(h.host(), driver, &mut diags);
        diags.write(&mut out);
        match driven {
            Driven::Ready => Outcome::Ready,
            // A ticket-less PENDING is FAULT: only a drive on the driver ticket waits.
            Driven::Pending { .. } if instance.ticket().is_none() => Outcome::Ready,
            Driven::Pending { wake_at_ns } => {
                if wake_at_ns != 0 {
                    out.wake_at(wake_at_ns);
                }
                Outcome::Pending
            }
            Driven::Refused => Outcome::Refused,
        }
    }
}

/// `cancel` on an outbound door: [`OutboundPlugin::cancel`] of the cancelled ticket, its
/// disposition answered (the SDK has dropped what the ticket parked, `abi::sdk::safe`).
#[derive(Debug)]
pub struct OutboundCancel<T, L = Outbound<T>>(PhantomData<(T, L)>);
impl<T: OutboundPlugin, L: HoldsOutbound<T>> SafeSlot for OutboundCancel<T, L> {
    type In = CancelIn;
    type Out = CancelOut;
    type State = Held<L>;
    fn call(
        instance: Instance<'_, Held<L>>,
        input: Lent<'_, CancelIn>,
        mut out: Out<'_, CancelOut>,
    ) -> Outcome {
        let disposition = instance
            .get()
            .map_or(L::CANCEL, |h| h.life().outbound().cancel(input.ticket));
        out.set(|o| &o.disposition, disposition);
        Outcome::Ready
    }
}

/// `verify` on a [`Both`] door: [`VerifyPlugin::verify_ticketed`] on the call's ticket, written as
/// the verify door writes it; PENDING while a service it made pends.
#[derive(Debug)]
pub struct VerifyBoth<T>(PhantomData<T>);
impl<T: VerifyPlugin + OutboundPlugin> SafeSlot for VerifyBoth<T> {
    type In = VerifyIn;
    type Out = IdentifyOut;
    type State = Held<Both<T>>;
    fn call(
        instance: Instance<'_, Held<Both<T>>>,
        input: Lent<'_, VerifyIn>,
        out: Out<'_, IdentifyOut>,
    ) -> Outcome {
        let Some(h) = instance.get() else {
            return Outcome::Fault;
        };
        verify_answer(
            h.life().plugin(),
            &verify_op(&instance, h.host()),
            input,
            out,
        )
    }
}

/// An auth op this kit's plugin does not serve (its tail does not state the capability): REFUSED,
/// saying so, never called.
#[derive(Debug)]
pub struct NotServed<L, I, O>(PhantomData<(L, I, O)>);
impl<L: Life, I: AbiIn, O: AbiOut> SafeSlot for NotServed<L, I, O> {
    type In = I;
    type Out = O;
    type State = Held<L>;
    fn call(_: Instance<'_, Held<L>>, _: Lent<'_, I>, mut out: Out<'_, O>) -> Outcome {
        out.fail(Refusal::refused(crate::abi::sdk::auth_door::NOT_SERVED))
    }
}

/// THE OUTBOUND DOOR: `plugin_door!` over the auth table for an [`OutboundPlugin`] `$plugin`,
/// stating `$statement` (its `kind_tail` an [`AuthTail`] from [`outbound_tail`], through
/// [`with_tail`](crate::abi::sdk::auth_door::with_tail)). The lifecycle is the SDK's generic one
/// but for `tick`, `drive` and `cancel`, which are the plugin's ([`OutboundTick`],
/// [`OutboundDrive`], [`OutboundCancel`]). `verify` and the login pair answer REFUSED.
///
/// ```ignore
/// busbar_contract::auth_outbound_door!(MyPlugin, STATEMENT);
/// ```
#[macro_export]
macro_rules! auth_outbound_door {
    ($plugin:ty, $statement:expr $(,)?) => {
        $crate::plugin_door! {
            ops: $crate::abi::auth::Ops,
            statement: $statement,
            lifecycle: {
                validate: $crate::abi::sdk::Safe<$crate::abi::sdk::life::Validate<
                    $crate::abi::sdk::auth_outbound::Outbound<$plugin>>>,
                open: $crate::abi::sdk::Safe<$crate::abi::sdk::life::Open<
                    $crate::abi::sdk::auth_outbound::Outbound<$plugin>>>,
                refresh: $crate::abi::sdk::Safe<$crate::abi::sdk::life::Refresh<
                    $crate::abi::sdk::auth_outbound::Outbound<$plugin>>>,
                retire: $crate::abi::sdk::Safe<$crate::abi::sdk::life::Retire<
                    $crate::abi::sdk::auth_outbound::Outbound<$plugin>>>,
                tick: $crate::abi::sdk::Safe<$crate::abi::sdk::auth_outbound::OutboundTick<
                    $plugin, $crate::abi::sdk::auth_outbound::Outbound<$plugin>>>,
                drive: $crate::abi::sdk::Safe<$crate::abi::sdk::auth_outbound::OutboundDrive<
                    $plugin, $crate::abi::sdk::auth_outbound::Outbound<$plugin>>>,
                cancel: $crate::abi::sdk::Safe<$crate::abi::sdk::auth_outbound::OutboundCancel<
                    $plugin, $crate::abi::sdk::auth_outbound::Outbound<$plugin>>>,
                release: $crate::abi::sdk::Safe<$crate::abi::sdk::life::Release<
                    $crate::abi::sdk::auth_outbound::Outbound<$plugin>>>,
                close: $crate::abi::sdk::Safe<$crate::abi::sdk::life::Close<
                    $crate::abi::sdk::auth_outbound::Outbound<$plugin>>>,
            },
            kind_ops: {
                verify: $crate::abi::sdk::Safe<$crate::abi::sdk::auth_outbound::NotServed<
                    $crate::abi::sdk::auth_outbound::Outbound<$plugin>,
                    $crate::abi::auth::VerifyIn, $crate::abi::auth::IdentifyOut>>,
                begin_login: $crate::abi::sdk::Safe<$crate::abi::sdk::auth_outbound::NotServed<
                    $crate::abi::sdk::auth_outbound::Outbound<$plugin>,
                    $crate::abi::auth::BeginLoginIn, $crate::abi::auth::BeginLoginOut>>,
                complete_login: $crate::abi::sdk::Safe<$crate::abi::sdk::auth_outbound::NotServed<
                    $crate::abi::sdk::auth_outbound::Outbound<$plugin>,
                    $crate::abi::auth::CompleteLoginIn, $crate::abi::auth::IdentifyOut>>,
                open_outbound: $crate::abi::sdk::Safe<
                    $crate::abi::sdk::auth_outbound::OpenOutboundSlot<$plugin>>,
                outbound_ready: $crate::abi::sdk::Safe<
                    $crate::abi::sdk::auth_outbound::OutboundReadySlot<$plugin>>,
                fields: $crate::abi::sdk::Safe<
                    $crate::abi::sdk::auth_outbound::FieldsSlot<$plugin>>,
            },
        }
    };
}

/// AN AUTH DOOR BY SHAPE. `verify_and_outbound`: `plugin_door!` over the auth table for a plugin
/// `$plugin` implementing both [`VerifyPlugin`] and [`OutboundPlugin`], over one instance
/// ([`Both`]); the login pair answers REFUSED. Its tail is [`outbound_tail`] through
/// [`with_inbound`].
///
/// ```ignore
/// busbar_contract::auth_door!(verify_and_outbound: MyPlugin, STATEMENT);
/// ```
#[macro_export]
macro_rules! auth_door {
    (verify_and_outbound: $plugin:ty, $statement:expr $(,)?) => {
        $crate::plugin_door! {
            ops: $crate::abi::auth::Ops,
            statement: $statement,
            lifecycle: {
                validate: $crate::abi::sdk::Safe<$crate::abi::sdk::life::Validate<
                    $crate::abi::sdk::auth_outbound::Both<$plugin>>>,
                open: $crate::abi::sdk::Safe<$crate::abi::sdk::life::Open<
                    $crate::abi::sdk::auth_outbound::Both<$plugin>>>,
                refresh: $crate::abi::sdk::Safe<$crate::abi::sdk::life::Refresh<
                    $crate::abi::sdk::auth_outbound::Both<$plugin>>>,
                retire: $crate::abi::sdk::Safe<$crate::abi::sdk::life::Retire<
                    $crate::abi::sdk::auth_outbound::Both<$plugin>>>,
                tick: $crate::abi::sdk::Safe<$crate::abi::sdk::auth_outbound::OutboundTick<
                    $plugin, $crate::abi::sdk::auth_outbound::Both<$plugin>>>,
                drive: $crate::abi::sdk::Safe<$crate::abi::sdk::auth_outbound::OutboundDrive<
                    $plugin, $crate::abi::sdk::auth_outbound::Both<$plugin>>>,
                cancel: $crate::abi::sdk::Safe<$crate::abi::sdk::auth_outbound::OutboundCancel<
                    $plugin, $crate::abi::sdk::auth_outbound::Both<$plugin>>>,
                release: $crate::abi::sdk::Safe<$crate::abi::sdk::life::Release<
                    $crate::abi::sdk::auth_outbound::Both<$plugin>>>,
                close: $crate::abi::sdk::Safe<$crate::abi::sdk::life::Close<
                    $crate::abi::sdk::auth_outbound::Both<$plugin>>>,
            },
            kind_ops: {
                verify: $crate::abi::sdk::Safe<
                    $crate::abi::sdk::auth_outbound::VerifyBoth<$plugin>>,
                begin_login: $crate::abi::sdk::Safe<$crate::abi::sdk::auth_outbound::NotServed<
                    $crate::abi::sdk::auth_outbound::Both<$plugin>,
                    $crate::abi::auth::BeginLoginIn, $crate::abi::auth::BeginLoginOut>>,
                complete_login: $crate::abi::sdk::Safe<$crate::abi::sdk::auth_outbound::NotServed<
                    $crate::abi::sdk::auth_outbound::Both<$plugin>,
                    $crate::abi::auth::CompleteLoginIn, $crate::abi::auth::IdentifyOut>>,
                open_outbound: $crate::abi::sdk::Safe<
                    $crate::abi::sdk::auth_outbound::OpenOutboundSlot<
                        $plugin, $crate::abi::sdk::auth_outbound::Both<$plugin>>>,
                outbound_ready: $crate::abi::sdk::Safe<
                    $crate::abi::sdk::auth_outbound::OutboundReadySlot<
                        $plugin, $crate::abi::sdk::auth_outbound::Both<$plugin>>>,
                fields: $crate::abi::sdk::Safe<
                    $crate::abi::sdk::auth_outbound::FieldsSlot<
                        $plugin, $crate::abi::sdk::auth_outbound::Both<$plugin>>>,
            },
        }
    };
}

/// One outbound style the plugin serves, as its tail states it: `name`, its `STYLE_*` `flags` and
/// the auth `points` it needs (a valid, non-empty set: the loader refuses any other).
#[must_use]
pub const fn style(name: &'static str, flags: u32, points: AuthPoints) -> StyleDecl {
    StyleDecl {
        name: crate::abi::sdk::door::abi_str(name),
        flags,
        points: points.bits(),
    }
}

/// An [`AuthTail`] for an outbound-only plugin, with `facts` (`FACT_*`), serving `styles`.
#[must_use]
pub const fn outbound_tail(facts: u32, styles: &'static [StyleDecl]) -> AuthTail {
    AuthTail {
        head: KindTailHead {
            size: std::mem::size_of::<AuthTail>() as u32,
            ..KindTailHead::ZERO
        },
        caps: crate::abi::auth::CAP_OUTBOUND,
        facts,
        login_kind: crate::abi::auth::LOGIN_KIND_NONE,
        styles: styles.as_ptr(),
        styles_len: styles.len(),
        operator_principal: crate::abi::sdk::door::abi_str(""),
        ..AuthTail::ZERO
    }
}

/// `tail` as a verifier too: it states [`CAP_INBOUND`](crate::abi::auth::CAP_INBOUND), called at
/// the inbound `points` (a valid, non-empty set).
#[must_use]
pub const fn with_inbound(tail: AuthTail, points: AuthPoints) -> AuthTail {
    AuthTail {
        caps: tail.caps | crate::abi::auth::CAP_INBOUND,
        inbound_points: points.bits(),
        ..tail
    }
}

#[cfg(test)]
#[path = "tests/auth_outbound_tests.rs"]
mod tests;
