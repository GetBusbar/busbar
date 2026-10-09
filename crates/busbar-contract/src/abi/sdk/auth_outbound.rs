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

use std::borrow::Cow;
use std::marker::PhantomData;
use std::ptr;
use std::task::Poll;

use zeroize::Zeroizing;

use crate::abi::auth::{
    AuthPoint, AuthPoints, AuthTail, FieldSpan, FieldsIn, FieldsOut, IdentifyOut, OpenOutboundIn,
    OpenOutboundOut, OutboundReadyIn, OutboundReadyOut, StyleDecl, VerifyIn, EXT_SCOPE, FIELD_QUERY,
    FIELD_SENSITIVE, MODE_OWN, MODE_PASSTHROUGH,
};
use crate::abi::mechanism::call::{Blob, Outcome, Span, BLOB_ABSENT};
use crate::abi::mechanism::door::KindTailHead;
use crate::abi::sdk::auth_door::{verify_answer, VerifyPlugin};
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
        }
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
                _reserved: 0,
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
    /// The handle refuses the request (a passthrough on a style that does not pass the caller's
    /// credential, or a handle this generation does not hold).
    Refused,
    /// The call could not answer: the attempt fails, with this text.
    Failed(Cow<'static, str>),
}

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
    /// Build the plugin from its settings blob (one JSON document) and its resolved secrets (one
    /// per Statement `secret_refs` key, in order). `Err` answers `open` FAILED with that text.
    ///
    /// # Errors
    /// The settings are not this plugin's.
    fn open(settings: &[u8], secrets: &[&[u8]]) -> Result<Self, &'static str>;

    /// Bind `style` (one the tail declares) to its resolved `credential` (`None` for a
    /// passthrough-only binding) and the provider's auth `settings` (`None` when absent); the
    /// handle, valid until `retire` of this generation. Never waits: a first mint runs on `tick`.
    ///
    /// # Errors
    /// The binding is refused, in the plugin's own lines.
    fn open_outbound(
        &self,
        style: &str,
        credential: Option<&[u8]>,
        settings: Option<&[u8]>,
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

    /// A reload, with the new settings and secrets. The outbound token cache survives it (it is
    /// keyed by style, credential and settings, never by handle). The count it answers is not
    /// reported: the flushed count is the inbound cache's ([`VerifyPlugin::refresh`]).
    fn refresh(&self, settings: &[u8], secrets: &[&[u8]]) -> u64 {
        let _ = (settings, secrets);
        0
    }

    /// `retire` of `generation`: drop the handles opened at it.
    fn retire(&self, generation: u64) {
        let _ = generation;
    }

    /// `tick` at `now_ns`: refresh what is about to expire; the next tick wanted, `0` = none.
    fn tick(&self, now_ns: u64) -> u64 {
        let _ = now_ns;
        0
    }
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
/// * `validate` answers READY: the settings are judged by `open`;
/// * `open`, `refresh`, `retire` and `tick` are the plugin's;
/// * `drive` answers REFUSED (the plugin holds no driver ticket: a pending `fields` is re-entered
///   on its own ticket, never through `drive`), and `cancel` answers
///   [`CANCEL_ABANDONED`](crate::abi::auth::CANCEL_ABANDONED): the SDK drops what the cancelled
///   ticket parked.
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

    fn validate(_: &[u8]) -> Result<(), Refusal> {
        Ok(())
    }

    fn open(settings: &[u8], secrets: &[&[u8]], _: u64) -> Result<Self, Refusal> {
        T::open(settings, secrets)
            .map(Outbound)
            .map_err(Refusal::failed)
    }

    fn refresh(&self, settings: &[u8], secrets: &[&[u8]], _: u64) -> Result<Refreshed, Refusal> {
        self.0.refresh(settings, secrets);
        Ok(Refreshed::default())
    }

    fn retire(&self, generation: u64) {
        self.0.retire(generation);
    }

    fn tick(&self, now_ns: u64) -> u64 {
        self.0.tick(now_ns)
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
/// [`VerifyPlugin::refresh`] dropped under [`VerifyPlugin::CACHE_FAMILY`]; `retire` and `tick`
/// are the outbound side's; `validate`, `drive` and `cancel` are [`Outbound`]'s.
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

    fn validate(_: &[u8]) -> Result<(), Refusal> {
        Ok(())
    }

    fn open(settings: &[u8], secrets: &[&[u8]], _: u64) -> Result<Self, Refusal> {
        <T as OutboundPlugin>::open(settings, secrets)
            .map(Both)
            .map_err(Refusal::failed)
    }

    fn refresh(&self, settings: &[u8], secrets: &[&[u8]], _: u64) -> Result<Refreshed, Refusal> {
        let dropped = VerifyPlugin::refresh(&self.0, settings, secrets);
        OutboundPlugin::refresh(&self.0, settings, secrets);
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

    fn tick(&self, now_ns: u64) -> u64 {
        OutboundPlugin::tick(&self.0, now_ns)
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
            return Outcome::Refused;
        };
        let credential = present(input.field(|i| &i.credential));
        let settings = present(input.field(|i| &i.settings));
        let plugin = h.life().outbound();
        match plugin.open_outbound(style, credential, settings) {
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
        match plugin.fields(&FieldsView { input }, &mut writer, &op) {
            // On the spot the call cannot pend (a ticket-less PENDING is FAULT): REFUSED there,
            // and the host submits it on a ticket.
            Poll::Pending if instance.ticket().is_none() => Outcome::Refused,
            Poll::Pending => Outcome::Pending,
            Poll::Ready(FieldsAnswer::Ready) => writer.write(&mut out),
            Poll::Ready(FieldsAnswer::Refused) => Outcome::Refused,
            Poll::Ready(FieldsAnswer::Failed(why)) => out.fail(Refusal::failed(why)),
        }
    }
}

/// `verify` on a [`Both`] door: [`VerifyPlugin::verify`], written as the verify door writes it.
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
        verify_answer(h.life().plugin(), input, out)
    }
}

/// An auth op this kit's plugin does not serve (its tail does not state the capability): REFUSED,
/// never called.
#[derive(Debug)]
pub struct NotServed<L, I, O>(PhantomData<(L, I, O)>);
impl<L: Life, I: AbiIn, O: AbiOut> SafeSlot for NotServed<L, I, O> {
    type In = I;
    type Out = O;
    type State = Held<L>;
    fn call(_: Instance<'_, Held<L>>, _: Lent<'_, I>, _: Out<'_, O>) -> Outcome {
        Outcome::Refused
    }
}

/// THE OUTBOUND DOOR: `plugin_door!` over the auth table for an [`OutboundPlugin`] `$plugin`,
/// stating `$statement` (its `kind_tail` an [`AuthTail`] from [`outbound_tail`], through
/// [`with_tail`](crate::abi::sdk::auth_door::with_tail)). `verify` and the login pair answer
/// REFUSED.
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
            lifecycle: life($crate::abi::sdk::auth_outbound::Outbound<$plugin>),
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
            lifecycle: life($crate::abi::sdk::auth_outbound::Both<$plugin>),
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
            _reserved: 0,
        },
        caps: crate::abi::auth::CAP_OUTBOUND,
        facts,
        login_kind: crate::abi::auth::LOGIN_KIND_NONE,
        inbound_points: 0,
        styles: styles.as_ptr(),
        styles_len: styles.len(),
        operator_principal: crate::abi::sdk::door::abi_str(""),
        credential_kinds: ptr::null(),
        credential_kinds_len: 0,
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
