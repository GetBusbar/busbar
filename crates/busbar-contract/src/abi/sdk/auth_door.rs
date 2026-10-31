// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE AUTH KIND'S VERIFY DOOR, FOR A SAFE PLUGIN (`abi::auth`, THE DESIGN, sections 11.4 and 11.6): the auth
//! kind's bits over the SDK's safe layer ([`SafeSlot`], [`Lent`], [`HostBuf`]). An auth plugin that
//! judges an inbound credential on the spot implements [`VerifyPlugin`], and
//! [`auth_verify_door!`](crate::auth_verify_door) builds its whole door over the auth table: the
//! lifecycle, `verify`, and every other auth op answering REFUSED (the plugin states only
//! [`CAP_INBOUND`](crate::abi::auth::CAP_INBOUND)). The plugin crate holds no `unsafe`.
//!
//! * The lifecycle is the SDK's shared one (`abi::sdk::life`), over [`Verifier`], the kind's
//!   [`Life`]: `open` builds the plugin from its settings blob and secrets
//!   ([`VerifyPlugin::open`]); `close` answering READY drops it (the SDK owns the state).
//! * `verify` hands [`VerifyPlugin::verify`] a [`VerifyView`] of the request at one auth point and
//!   writes its [`Answer`]: the [`Verdict`] (an identity goes into the host's
//!   [`IdentityBuf`](crate::abi::auth::IdentityBuf)), the [`Decision`] and the credential lines to
//!   strip ([`Strip`], named whatever the verdict; THE DESIGN, "Auth points and guest lists").
//!   One that does not fit is the short answer (FAILED, every `needed_*` at its full size); the
//!   host re-calls once and the plugin judges again. A plugin whose verdict is not deterministic
//!   remembers it per ticket.
//! * `refresh` calls [`VerifyPlugin::refresh`] and reports the inbound cache entries it dropped
//!   under [`METRIC_CACHE_FLUSHED`](crate::abi::auth::METRIC_CACHE_FLUSHED), when the plugin states
//!   that family ([`VerifyPlugin::CACHE_FAMILY`]).
//!
//! * A `verify` that WAITS on a host service (a credential's secret through `records.secret`)
//!   implements [`VerifyPlugin::verify_ticketed`] instead of [`VerifyPlugin::verify`]: it is
//!   handed a [`VerifyOp`], the call's ticket and the host services, and answers
//!   [`Poll::Pending`] while a service it made pends. The op answers PENDING, the host wakes the
//!   ticket when the service completes, and re-enters `verify` (`FLAG_RESUME`) on the SAME ticket:
//!   the body runs again from the top, making the same services in the same order, and each
//!   re-issued handle reads its stored answer (nothing runs twice). A TICKET-LESS `verify` (the
//!   host's on-the-spot try) cannot pend: it answers REFUSED there, and the host submits the same
//!   `verify` on a ticket. The verify slot's own Ready|Pending: no ABI shape changes.
//!
//! A `verify` that waits on its own I/O (a key-set fetch, a directory read over a need) writes its
//! own slots over [`crate::plugin_door!`].

use std::borrow::Cow;
use std::cell::{Cell, RefCell};
use std::marker::PhantomData;
use std::ptr;
use std::task::Poll;

use crate::abi::auth::{
    AuthPoint, AuthPoints, AuthTail, IdentifyOut, IdentityBuf, StripName, VerifyIn,
    DECISION_CONTINUE, DECISION_STOP, IDENTITY_HAS_TTL, SPAN_ABSENT, STRIP_FIELD, STRIP_QUERY,
    VERDICT_IDENTITY, VERDICT_PASS, VERDICT_REJECT,
};
use crate::abi::mechanism::call::{AbiStr, Blob, Outcome, Span, BLOB_ABSENT};
use crate::abi::mechanism::door::{KindTailHead, MarkWord, Statement, MARK_WORD_CARRIER};
use crate::abi::mechanism::ticket::{CompletionHandle, Ticket};
use crate::abi::sdk::auth_outbound::Diags;
use crate::abi::sdk::conn::Host;
use crate::abi::sdk::door::{AbiIn, AbiOut};
use crate::abi::sdk::lent::{HostBuf, Lent};
use crate::abi::sdk::life::{Counted, Held, Life, Refreshed, Refusal};
use crate::abi::sdk::out::Out;
use crate::abi::sdk::safe::{Instance, SafeSlot};
use crate::abi::sdk::services::{CredentialSecret, Pend, Services};
pub use crate::auth_calls::{Decision, Strip, StripPlace, VerifiedIdentity};

/// One `verify`'s request, as a safe plugin reads it; lent for the call.
#[derive(Debug, Clone, Copy)]
pub struct VerifyView<'a> {
    input: Lent<'a, VerifyIn>,
}

impl<'a> VerifyView<'a> {
    /// The candidate credential; `None` = none presented.
    #[must_use]
    pub fn credential(&self) -> Option<&'a [u8]> {
        let c = self.input.field(|i| &i.credential);
        (c.fmt != BLOB_ABSENT && !c.ptr.is_null()).then(|| c.bytes())
    }

    /// The point this call is made at; `None` for a value outside the vocabulary.
    #[must_use]
    pub fn point(&self) -> Option<AuthPoint> {
        AuthPoint::from_bit(self.input.point)
    }

    /// The connection the request arrived on.
    #[must_use]
    pub fn conn(&self) -> u64 {
        self.input.conn
    }

    /// The unit the kernel minted for the request; `0` at [`AuthPoint::Peer`].
    #[must_use]
    pub fn unit(&self) -> u64 {
        self.input.unit
    }

    /// The peer facts; `None` = the host lent none (every point but [`AuthPoint::Peer`]).
    #[must_use]
    pub fn peer(&self) -> Option<&'a [u8]> {
        let b = self.input.field(|i| &i.peer);
        (b.fmt != BLOB_ABSENT).then(|| b.bytes())
    }

    /// The whole body; `None` = the host lent none (every point but [`AuthPoint::HeadBody`]).
    #[must_use]
    pub fn body(&self) -> Option<&'a [u8]> {
        let b = self.input.field(|i| &i.body);
        (b.fmt != BLOB_ABSENT).then(|| b.bytes())
    }

    /// The field lines lent, in order: (name, value).
    pub fn lines(&self) -> impl Iterator<Item = (&'a [u8], &'a [u8])> + 'a {
        self.input
            .lines()
            .iter()
            .map(|l| (l.field(|c| &c.name).bytes(), l.field(|c| &c.value).bytes()))
    }

    /// The field line `name` (ASCII case-insensitive), as presented; `None` = absent.
    #[must_use]
    pub fn line(&self, name: &str) -> Option<&'a [u8]> {
        self.input
            .lines()
            .iter()
            .find(|c| {
                c.field(|c| &c.name)
                    .bytes()
                    .eq_ignore_ascii_case(name.as_bytes())
            })
            .map(|c| c.field(|c| &c.value))
            .filter(|v| v.fmt != BLOB_ABSENT && !v.ptr.is_null())
            .map(Lent::<Blob>::bytes)
    }

    /// The method.
    #[must_use]
    pub fn method(&self) -> &'a [u8] {
        self.input.field(|i| &i.request.method).bytes()
    }

    /// The authority.
    #[must_use]
    pub fn authority(&self) -> &'a [u8] {
        self.input.field(|i| &i.request.authority).bytes()
    }

    /// The path, raw as received.
    #[must_use]
    pub fn path(&self) -> &'a [u8] {
        self.input.field(|i| &i.request.canonical_path).bytes()
    }

    /// The query, raw as received; `None` = none.
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
}

/// WHY A CREDENTIAL WAS REJECTED, in the plugin's words: the host writes it to the instance's own
/// log and the host log, never to the client (the client's answer stays the same 401). Operator
/// text: it never carries secret material (no credential, no signature, no token byte).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Reason(Cow<'static, str>);

impl Reason {
    /// The reason `text`.
    #[must_use]
    pub fn new(text: impl Into<Cow<'static, str>>) -> Self {
        Self(text.into())
    }

    /// Its text.
    #[must_use]
    pub fn text(&self) -> &str {
        &self.0
    }

    /// Its text, owned or `'static`, for the kit's writer.
    pub(crate) fn into_text(self) -> Cow<'static, str> {
        self.0
    }
}

impl From<&'static str> for Reason {
    fn from(text: &'static str) -> Self {
        Self::new(text)
    }
}

impl From<String> for Reason {
    fn from(text: String) -> Self {
        Self::new(text)
    }
}

/// A plugin's verdict on one credential.
///
/// `large_enum_variant`: `Identity` carries the whole identity by value; the verdict is built once
/// per call and consumed at once, never held in a collection, so a box would only add an
/// allocation per verify.
#[allow(clippy::large_enum_variant)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    /// Identified.
    Identity(VerifiedIdentity),
    /// A credential was presented and is invalid, the plugin saying nothing of why: the operator's
    /// log can only say it was rejected. Superseded by [`Verdict::RejectBecause`]
    /// ([`Verdict::reject`]); kept so a plugin built against the earlier kit still compiles.
    Reject,
    /// Not this plugin's credential.
    Pass,
    /// A credential was presented and is invalid, for the [`Reason`] it names: the host writes the
    /// reason to the instance's own log and the host log, never to the client (THE REASON,
    /// [`IdentifyOut`]).
    RejectBecause(Reason),
}

impl Verdict {
    /// [`Verdict::RejectBecause`], saying `why`.
    #[must_use]
    pub fn reject(why: impl Into<Cow<'static, str>>) -> Self {
        Self::RejectBecause(Reason::new(why))
    }
}

/// A plugin's whole answer at one point: the verdict (the kernel's), the decision and the lines to
/// strip (the transport's).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Answer {
    /// The verdict.
    pub verdict: Verdict,
    /// The credential lines and query keys to strip, named whatever the verdict.
    pub strips: Vec<Strip>,
    /// Continue or stop.
    pub decision: Decision,
}

impl From<Verdict> for Answer {
    /// The verdict with no strips and its default decision: [`Decision::Continue`] for an
    /// identity or a pass, [`Decision::Stop`] for a reject.
    fn from(verdict: Verdict) -> Self {
        let decision = match verdict {
            Verdict::Identity(_) | Verdict::Pass => Decision::Continue,
            Verdict::Reject | Verdict::RejectBecause(_) => Decision::Stop,
        };
        Self {
            verdict,
            strips: Vec::new(),
            decision,
        }
    }
}

/// `VerifyOp` over the host services a real host's `open` handed (status row 194). #1471 ties
/// `VerifyOp` to the tables its services were read from (`VerifyOp<'t>`) and states this alias as
/// `VerifyOp<'static>`; a plugin names it where it names the op's type, and the same spelling
/// compiles before and after.
pub type StaticVerifyOp = VerifyOp;

/// ONE `verify`'S HOST CALLS, on its ticket: what [`VerifyPlugin::verify_ticketed`] is handed. Each
/// service it makes is issued the call's next completion handle, counted from `0` on every entry,
/// so a body that runs again from the top on its RESUME (or on the host's re-call after a short
/// answer) and makes the same services in the same order re-issues the same handles and reads the
/// answers the host stored (THE DESIGN, the plugin ABI: a pending service is never run twice).
#[derive(Debug)]
pub struct VerifyOp {
    services: Option<Services>,
    ticket: Ticket,
    issued: Cell<u32>,
    diags: RefCell<Diags>,
}

impl VerifyOp {
    /// The op on `ticket` over `services` (`None`: the host offers none, and every service is
    /// [`ServiceError::Unserved`](crate::abi::sdk::services::ServiceError::Unserved)). The kit
    /// builds it for every `verify`; a plugin's own unit tests build one over a hand-built table.
    #[must_use]
    pub const fn new(services: Option<Services>, ticket: Ticket) -> Self {
        Self {
            services,
            ticket,
            issued: Cell::new(0),
            diags: RefCell::new(Diags::new()),
        }
    }

    /// Report the declared diagnostic `id_idx` (its index in the Statement's `diag_ids`) at
    /// `severity` (`SEVERITY_*`, `abi::mechanism::call`), saying `text`, in this call's reply
    /// envelope, whatever the call answers: the host writes it to the instance's own log (and, at
    /// warn or error, the host log). Operator text: never secret material.
    pub fn diag(&self, id_idx: u32, severity: u8, text: impl Into<Box<str>>) {
        self.diags.borrow_mut().push(id_idx, severity, text);
    }

    /// The diagnostics reported so far, taken (the kit writes them into the reply).
    pub(crate) fn take_diags(&self) -> Diags {
        std::mem::take(&mut *self.diags.borrow_mut())
    }

    /// The call's ticket ([`Ticket::NONE`] for the host's on-the-spot try, which may not pend).
    #[must_use]
    pub const fn ticket(&self) -> Ticket {
        self.ticket
    }

    /// The host services the instance was opened with, for a service this op has no call of its
    /// own for; issue each one [`VerifyOp::handle`]. `None` when the host offers none.
    #[must_use]
    pub const fn services(&self) -> Option<&Services> {
        self.services.as_ref()
    }

    /// The next completion handle on the call's ticket, in issue order.
    #[must_use]
    pub fn handle(&self) -> CompletionHandle {
        let seq = self.issued.get();
        self.issued.set(seq.saturating_add(1));
        CompletionHandle {
            ticket: self.ticket,
            seq,
            _reserved: 0,
        }
    }

    /// [`Services::records_secret`] of credential `id` of `kind` on the call's next handle: the
    /// secret in a zeroizing holder the plugin owns, and whether it is live (an unknown id answers
    /// the host's dummy, not live, on the same path). [`Poll::Pending`] while the host reads it;
    /// answer it as the verdict's `Pending`, and the RESUME reads the stored answer. On no ticket
    /// it is [`Poll::Pending`] at once, without a crossing (the service may pend, so the host would
    /// refuse it): the kit answers that `verify` REFUSED and the host submits it on a ticket.
    pub fn records_secret(&self, kind: &str, id: &str) -> Pend<CredentialSecret> {
        if self.ticket.is_none() {
            return Poll::Pending;
        }
        let handle = self.handle();
        match &self.services {
            Some(s) => s.records_secret(handle, kind, id),
            None => Poll::Ready(Err(crate::abi::sdk::services::ServiceError::Unserved)),
        }
    }
}

/// AN AUTH PLUGIN THAT VERIFIES ON THE SPOT, or on its ticket over the host's services, in safe
/// Rust. A plugin implements exactly one of [`VerifyPlugin::verify`] (it judges with what the
/// request carries) and [`VerifyPlugin::verify_ticketed`] (it waits on a host service).
pub trait VerifyPlugin: Send + Sync + Sized + 'static {
    /// The index, in the plugin's Statement `families`, of its
    /// [`METRIC_CACHE_FLUSHED`](crate::abi::auth::METRIC_CACHE_FLUSHED) counter; `None` when it
    /// caches nothing.
    const CACHE_FAMILY: Option<u32> = None;

    /// `validate`: whether `settings` (one JSON document) are this plugin's, refused in the words
    /// and with the outcome boot's `open` would refuse them with, so `busbar --validate` refuses
    /// what boot refuses (boot runs it before every `open`, too). It is handed NO secrets, so it
    /// judges the settings alone: a plugin whose `open` needs no secret answers
    /// [`validate_by_opening`]`::<Self>(settings)`; one whose `open` refuses a missing secret parses
    /// its settings as `open` does and stops there. The default accepts any settings (a plugin
    /// built against the earlier kit, whose `open` judges them at boot): it cannot open without the
    /// secrets, and boot validates before every `open`.
    ///
    /// # Errors
    /// The settings are not this plugin's.
    fn validate(settings: &[u8]) -> Result<(), Refusal> {
        let _ = settings;
        Ok(())
    }

    /// Build the plugin from its settings blob (one JSON document) and its resolved secrets (one
    /// per Statement `secret_refs` key, in order), refusing in the plugin's own words and outcome.
    /// The kit opens through this. The default is [`VerifyPlugin::open`], its text answered FAILED.
    ///
    /// # Errors
    /// The settings or the secrets are not this plugin's.
    fn open_refusing(settings: &[u8], secrets: &[&[u8]]) -> Result<Self, Refusal> {
        Self::open(settings, secrets).map_err(Refusal::failed)
    }

    /// [`VerifyPlugin::open_refusing`] with a fixed text, answered FAILED: the earlier kit's form,
    /// kept so a plugin built against it still compiles. A plugin implements one of the two; the
    /// default refuses, saying so.
    ///
    /// # Errors
    /// The settings are not this plugin's.
    fn open(settings: &[u8], secrets: &[&[u8]]) -> Result<Self, &'static str> {
        let _ = (settings, secrets);
        Err(OPENS_NOTHING)
    }

    /// Judge the request at one point: the verdict, the decision and the lines to strip (a bare
    /// [`Verdict`] converts, with no strips and its default decision). A plugin that implements
    /// [`VerifyPlugin::verify_ticketed`] instead leaves this alone: the kit never calls it then, and
    /// its default fails closed (a reject, saying so).
    fn verify(&self, request: &VerifyView<'_>) -> Answer {
        let _ = request;
        Verdict::reject("the plugin implements no on-the-spot verify").into()
    }

    /// Judge the request at one point, over `op`: the call's ticket and the host services, so the
    /// judgement may wait on a service ([`VerifyOp::records_secret`]). [`Poll::Pending`] while a
    /// service it made pends (answer it whenever one answers `Pending`): the kit answers PENDING,
    /// and the host re-enters this from the top on the same ticket when the service completes,
    /// where each re-issued service reads its stored answer. Ticket-less, a `Pending` answers
    /// REFUSED and the host submits the call on a ticket. The default is [`VerifyPlugin::verify`],
    /// READY on the spot.
    fn verify_ticketed(&self, request: &VerifyView<'_>, op: &VerifyOp) -> Poll<Answer> {
        let _ = op;
        Poll::Ready(self.verify(request))
    }

    /// A reload (the admin cache flush is one with unchanged settings): drop the inbound cache and
    /// answer how many entries it held, or refuse the reload in the plugin's own words and outcome
    /// (the instance keeps serving as it was). The kit reloads through this. The default is
    /// [`VerifyPlugin::refresh`], which cannot refuse.
    ///
    /// # Errors
    /// The new settings or secrets are not this plugin's.
    fn reload(&self, settings: &[u8], secrets: &[&[u8]]) -> Result<u64, Refusal> {
        Ok(self.refresh(settings, secrets))
    }

    /// [`VerifyPlugin::reload`] that cannot refuse: the earlier kit's form, kept so a plugin built
    /// against it still compiles. Drop the inbound cache and answer how many entries it held.
    fn refresh(&self, settings: &[u8], secrets: &[&[u8]]) -> u64 {
        let _ = (settings, secrets);
        0
    }
}

/// [`VerifyPlugin::validate`] for a plugin whose `open` needs no secret: open over `settings` with
/// none, and drop the instance.
///
/// # Errors
/// [`VerifyPlugin::open`] refuses the settings.
pub fn validate_by_opening<T: VerifyPlugin>(settings: &[u8]) -> Result<(), Refusal> {
    T::open_refusing(settings, &[]).map(drop)
}

/// What [`VerifyPlugin::open`]'s default answers: the plugin implements neither open.
pub const OPENS_NOTHING: &str =
    "the auth plugin implements neither `open` nor `open_refusing`: it cannot open";

/// THE AUTH KIND'S [`Life`] over a [`VerifyPlugin`] `T`: the instance state the shared lifecycle
/// slots (`abi::sdk::life`) serve, a [`Held`] of it. Each per-kind value is stated here:
///
/// * `validate`, `open` and `refresh` are [`VerifyPlugin::validate`],
///   [`VerifyPlugin::open_refusing`] and [`VerifyPlugin::reload`] (`--validate` refuses what boot
///   refuses); the entries
///   `refresh` dropped are reported under [`VerifyPlugin::CACHE_FAMILY`], when the plugin states
///   it;
/// * `drive` answers REFUSED (the plugin holds no driver ticket), and `cancel` answers
///   [`CANCEL_ABANDONED`](crate::abi::auth::CANCEL_ABANDONED): a pending `verify` parks nothing
///   (its pending service is the host's, dropped with the ticket), so nothing of the plugin's is
///   in flight;
/// * `retire` and `tick` hold nothing: nothing is generation data, and no tick is asked for.
pub struct Verifier<T>(T);

impl<T> std::fmt::Debug for Verifier<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Verifier").finish_non_exhaustive()
    }
}

impl<T> Verifier<T> {
    /// The plugin.
    #[must_use]
    pub const fn plugin(&self) -> &T {
        &self.0
    }
}

impl<T: VerifyPlugin> Life for Verifier<T> {
    const CANCEL: u32 = crate::abi::auth::CANCEL_ABANDONED;
    const DRIVE: Outcome = Outcome::Refused;

    fn validate(settings: &[u8]) -> Result<(), Refusal> {
        T::validate(settings)
    }

    fn open(settings: &[u8], secrets: &[&[u8]], _: u64) -> Result<Self, Refusal> {
        T::open_refusing(settings, secrets).map(Verifier)
    }

    fn refresh(&self, settings: &[u8], secrets: &[&[u8]], _: u64) -> Result<Refreshed, Refusal> {
        let dropped = self.0.reload(settings, secrets)?;
        Ok(Refreshed {
            counted: T::CACHE_FAMILY.map(|family| Counted {
                family,
                value: dropped as f64,
            }),
        })
    }
}

/// `verify`: [`VerifyPlugin::verify_ticketed`] on the call's ticket, its identity written into the
/// host's buffer; PENDING while a service it made pends.
#[derive(Debug)]
pub struct Verify<T>(PhantomData<T>);
impl<T: VerifyPlugin> SafeSlot for Verify<T> {
    type In = VerifyIn;
    type Out = IdentifyOut;
    type State = Held<Verifier<T>>;
    fn call(
        instance: Instance<'_, Held<Verifier<T>>>,
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

/// The [`VerifyOp`] of the `verify` `instance` runs, over the host tables `open` handed it.
pub(crate) fn verify_op<T: Send + Sync + 'static>(
    instance: &Instance<'_, T>,
    host: Option<&Host>,
) -> VerifyOp {
    VerifyOp::new(host.and_then(Host::services), instance.ticket())
}

/// `verify` over `plugin` on `op`: [`VerifyPlugin::verify_ticketed`], its identity written into
/// the host's buffer; PENDING while it pends on a ticket, REFUSED when it would pend on none (a
/// ticket-less PENDING is FAULT). THE ONE COPY: the verify door and the combined
/// verify-and-outbound door (`abi::sdk::auth_outbound::Both`) answer `verify` through it.
pub(crate) fn verify_answer<T: VerifyPlugin>(
    plugin: &T,
    op: &VerifyOp,
    input: Lent<'_, VerifyIn>,
    mut out: Out<'_, IdentifyOut>,
) -> Outcome {
    let judged = plugin.verify_ticketed(&VerifyView { input }, op);
    op.take_diags().write(&mut out);
    let answer = match judged {
        Poll::Ready(answer) => answer,
        // On the spot the call cannot pend: REFUSED there, and the host submits it on a ticket.
        Poll::Pending if op.ticket().is_none() => {
            return out.fail(Refusal::refused(
                "verify waits on a host service: it is answered on a ticket, not on the spot",
            ))
        }
        // Nothing written: a PENDING `verify` names no `needed_*` and no verdict.
        Poll::Pending => return Outcome::Pending,
    };
    let Answer {
        verdict,
        strips,
        decision,
    } = answer;
    let (id, verdict) = match verdict {
        Verdict::Identity(id) => (Some(id), VERDICT_IDENTITY),
        Verdict::Reject => (None, VERDICT_REJECT),
        Verdict::RejectBecause(why) => {
            out.reason(why.into_text());
            (None, VERDICT_REJECT)
        }
        Verdict::Pass => (None, VERDICT_PASS),
    };
    let decision = match decision {
        Decision::Continue => DECISION_CONTINUE,
        Decision::Stop => DECISION_STOP,
    };
    write(
        id.as_ref(),
        Some((strips.as_slice(), input.strip(), decision)),
        input.field(|i| &i.out_buf),
        out,
        verdict,
    )
}

/// Write `id` into the host's identity buffer under `verdict` (`VERDICT_IDENTITY` for `verify`,
/// `LOGIN_IDENTITY` for `complete_login`) and answer READY; or, when it does not fit, answer the
/// SHORT FAILED: every `needed_*` at its full size and nothing written into the host's buffers
/// (the host re-calls once with buffers that large). THE ONE COPY: the verify door and a login
/// door both write an identity through it.
pub fn write_identity(
    id: &VerifiedIdentity,
    buf: Lent<'_, IdentityBuf>,
    out: Out<'_, IdentifyOut>,
    verdict: u32,
) -> Outcome {
    write(Some(id), None, buf, out, verdict)
}

/// Write the identity `id` (if any) and, for `verify`, the strip names into the host's strip array
/// and the decision, under `verdict`; or the SHORT FAILED when any of them does not fit.
fn write(
    id: Option<&VerifiedIdentity>,
    strip: Option<(&[Strip], HostBuf<'_, StripName>, u32)>,
    buf: Lent<'_, IdentityBuf>,
    mut out: Out<'_, IdentifyOut>,
    verdict: u32,
) -> Outcome {
    let mut bytes: HostBuf<'_, u8> = buf.buf();
    let mut groups: HostBuf<'_, Span> = buf.groups();
    let (strips, mut strip_buf, decision) = match strip {
        Some((strips, host, decision)) => (strips, Some(host), decision),
        None => (&[][..], None, 0),
    };
    // The FULL sizes first: a short answer writes nothing into the host's buffers.
    let texts = id.map_or([None; 8], |id| {
        [
            Some(id.subject.as_str()),
            id.key_id.as_deref(),
            id.key_name.as_deref(),
            id.user.as_deref(),
            id.provider.as_deref(),
            id.name.as_deref(),
            id.replay.as_ref().map(|r| r.key.as_str()),
            // The plugin's own credential, written back as it supplied it: this crate reads its own
            // `Secret`'s field (a plugin holds no seal to `expose` with).
            id.credential.as_ref().map(|c| c.0.as_str()),
        ]
    });
    let id_groups: &[String] = id.map_or(&[][..], |id| id.groups.as_slice());
    let need_bytes = texts.iter().flatten().map(|t| t.len()).sum::<usize>()
        + id_groups.iter().map(String::len).sum::<usize>()
        + strips.iter().map(|s| s.name.len()).sum::<usize>();
    let need_groups = id_groups.len();
    let strip_cap = strip_buf.as_ref().map_or(0, |h| h.cap());
    if need_bytes > bytes.cap() || need_groups > groups.cap() || strips.len() > strip_cap {
        out.set(|o| &o.needed_bytes, need_bytes as u64);
        out.set(
            |o| &o.needed_groups,
            u32::try_from(need_groups).unwrap_or(u32::MAX),
        );
        out.set(
            |o| &o.needed_strip,
            u32::try_from(strips.len()).unwrap_or(u32::MAX),
        );
        return Outcome::Failed;
    }
    let mut span = |t: Option<&str>| -> Span {
        match t {
            None => Span {
                offset: SPAN_ABSENT,
                ..Span::ZERO
            },
            Some(s) => {
                let at = bytes.extend(s.as_bytes());
                Span {
                    offset: u32::try_from(at).unwrap_or(u32::MAX),
                    len: u32::try_from(s.len()).unwrap_or(u32::MAX),
                }
            }
        }
    };
    if let Some(host) = strip_buf.as_mut() {
        for s in strips {
            let name = span(Some(&*s.name));
            host.push(StripName {
                name,
                place: match s.place {
                    StripPlace::Field => STRIP_FIELD,
                    StripPlace::Query => STRIP_QUERY,
                },
                _reserved: 0,
            });
        }
        out.set(
            |o| &o.strip_len,
            u32::try_from(host.written()).unwrap_or(u32::MAX),
        );
        out.set(|o| &o.decision, decision);
    }
    let Some(id) = id else {
        out.set(|o| &o.verdict, verdict);
        return Outcome::Ready;
    };
    let [subject, key_id, key_name, user, provider, name, replay_key, credential] =
        texts.map(&mut span);
    for g in &id.groups {
        let s = span(Some(g));
        groups.push(s);
    }
    out.set(|o| &o.identity.subject, subject);
    out.set(|o| &o.identity.key_id, key_id);
    out.set(|o| &o.identity.key_name, key_name);
    out.set(|o| &o.identity.user, user);
    out.set(|o| &o.identity.provider, provider);
    out.set(|o| &o.identity.name, name);
    out.set(
        |o| &o.identity.claims,
        Span {
            offset: SPAN_ABSENT,
            ..Span::ZERO
        },
    );
    out.set(|o| &o.identity.claims_fmt, BLOB_ABSENT);
    out.set(
        |o| &o.identity.groups_len,
        u32::try_from(groups.written()).unwrap_or(u32::MAX),
    );
    let (flags, ttl_secs) = match id.ttl_secs {
        Some(t) => (IDENTITY_HAS_TTL, t),
        None => (0, 0),
    };
    out.set(|o| &o.identity.flags, flags);
    out.set(|o| &o.identity.ttl_secs, ttl_secs);
    out.set(|o| &o.identity.replay_key, replay_key);
    out.set(
        |o| &o.identity.replay_ttl_secs,
        id.replay.as_ref().map_or(0, |r| r.ttl_secs),
    );
    out.set(|o| &o.identity.credential, credential);
    out.set(|o| &o.verdict, verdict);
    Outcome::Ready
}

/// What an auth op a plugin does not serve answers REFUSED with.
pub(crate) const NOT_SERVED: &str =
    "this auth plugin does not serve the op: its auth tail does not state the capability";

/// An auth op this kit's plugin does not serve (it states only `CAP_INBOUND`): REFUSED, saying so,
/// never called.
#[derive(Debug)]
pub struct NotServed<T, I, O>(PhantomData<(T, I, O)>);
impl<T: VerifyPlugin, I: AbiIn, O: AbiOut> SafeSlot for NotServed<T, I, O> {
    type In = I;
    type Out = O;
    type State = Held<Verifier<T>>;
    fn call(_: Instance<'_, Held<Verifier<T>>>, _: Lent<'_, I>, mut out: Out<'_, O>) -> Outcome {
        out.fail(Refusal::refused(NOT_SERVED))
    }
}

/// THE VERIFY DOOR: `plugin_door!` over the auth table for a [`VerifyPlugin`] `$plugin`, stating
/// `$statement` (its `kind_tail` an [`AuthTail`] from [`verify_tail`], through [`with_tail`]).
///
/// ```ignore
/// busbar_contract::auth_verify_door!(MyPlugin, STATEMENT);
/// ```
#[macro_export]
macro_rules! auth_verify_door {
    ($plugin:ty, $statement:expr $(,)?) => {
        $crate::plugin_door! {
            ops: $crate::abi::auth::Ops,
            statement: $statement,
            lifecycle: life($crate::abi::sdk::auth_door::Verifier<$plugin>),
            kind_ops: {
                verify: $crate::abi::sdk::Safe<$crate::abi::sdk::auth_door::Verify<$plugin>>,
                begin_login: $crate::abi::sdk::Safe<$crate::abi::sdk::auth_door::NotServed<
                    $plugin, $crate::abi::auth::BeginLoginIn, $crate::abi::auth::BeginLoginOut>>,
                complete_login: $crate::abi::sdk::Safe<$crate::abi::sdk::auth_door::NotServed<
                    $plugin, $crate::abi::auth::CompleteLoginIn, $crate::abi::auth::IdentifyOut>>,
                open_outbound: $crate::abi::sdk::Safe<$crate::abi::sdk::auth_door::NotServed<
                    $plugin, $crate::abi::auth::OpenOutboundIn, $crate::abi::auth::OpenOutboundOut>>,
                outbound_ready: $crate::abi::sdk::Safe<$crate::abi::sdk::auth_door::NotServed<
                    $plugin, $crate::abi::auth::OutboundReadyIn, $crate::abi::auth::OutboundReadyOut>>,
                fields: $crate::abi::sdk::Safe<$crate::abi::sdk::auth_door::NotServed<
                    $plugin, $crate::abi::auth::FieldsIn, $crate::abi::auth::FieldsOut>>,
            },
        }
    };
}

/// An [`AuthTail`] for a verify-only plugin, with `facts` (`FACT_*`), called at the inbound `points`
/// (a valid, non-empty set: the loader refuses any other). The carriers it reads are its
/// Statement's [`carrier`] word marks, not a tail fact.
#[must_use]
pub const fn verify_tail(facts: u32, points: AuthPoints) -> AuthTail {
    AuthTail {
        head: KindTailHead {
            size: std::mem::size_of::<AuthTail>() as u32,
            ..KindTailHead::ZERO
        },
        caps: crate::abi::auth::CAP_INBOUND,
        facts,
        login_kind: crate::abi::auth::LOGIN_KIND_NONE,
        inbound_points: points.bits(),
        operator_principal: crate::abi::sdk::door::abi_str(""),
        ..AuthTail::ZERO
    }
}

/// `tail` as THE OPERATOR CREDENTIAL's: it states [`FACT_OPERATOR`](crate::abi::auth::FACT_OPERATOR)
/// and `principal`, the principal id its `verify` identifies.
#[must_use]
pub const fn with_operator(tail: AuthTail, principal: &'static str) -> AuthTail {
    AuthTail {
        facts: tail.facts | crate::abi::auth::FACT_OPERATOR,
        operator_principal: crate::abi::sdk::door::abi_str(principal),
        ..tail
    }
}

/// `tail` as a verifier that reads host-held credentials of `kinds` through `records.secret`: it
/// states [`FACT_READS_CREDENTIALS`](crate::abi::auth::FACT_READS_CREDENTIALS) and the kinds.
#[must_use]
pub const fn with_credential_kinds(tail: AuthTail, kinds: &'static [AbiStr]) -> AuthTail {
    AuthTail {
        facts: tail.facts | crate::abi::auth::FACT_READS_CREDENTIALS,
        credential_kinds: kinds.as_ptr(),
        credential_kinds_len: kinds.len(),
        ..tail
    }
}

/// One inbound carrier `verify` reads (a field line's name), as the Statement states it: a
/// [`MARK_WORD_CARRIER`] word mark in [`Statement::mark_words`].
#[must_use]
pub const fn carrier(name: &'static str) -> MarkWord {
    MarkWord {
        class: MARK_WORD_CARRIER,
        word: crate::abi::sdk::door::abi_str(name),
        ..MarkWord::ZERO
    }
}

/// `statement` with its kind tail set to `tail`.
#[must_use]
pub const fn with_tail(statement: Statement, tail: &'static AuthTail) -> Statement {
    Statement {
        kind_tail: ptr::from_ref(tail).cast(),
        ..statement
    }
}

#[cfg(test)]
#[path = "tests/auth_door_tests.rs"]
mod tests;
