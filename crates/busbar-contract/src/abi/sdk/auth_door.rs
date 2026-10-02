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
//! This kit answers every verdict READY: a plugin whose `verify` waits on I/O (a key-set fetch, a
//! directory read) writes its own slots over [`crate::plugin_door!`].

use std::marker::PhantomData;
use std::ptr;

use crate::abi::auth::{
    AuthPoint, AuthPoints, AuthTail, IdentifyOut, IdentityBuf, StripName, VerifyIn,
    DECISION_CONTINUE, DECISION_STOP, IDENTITY_HAS_TTL, SPAN_ABSENT, STRIP_FIELD, STRIP_QUERY,
    VERDICT_IDENTITY, VERDICT_PASS, VERDICT_REJECT,
};
use crate::abi::mechanism::call::{Blob, Outcome, Span, BLOB_ABSENT};
use crate::abi::mechanism::door::{KindTailHead, MarkWord, Statement, MARK_WORD_CARRIER};
use crate::abi::sdk::door::{AbiIn, AbiOut};
use crate::abi::sdk::lent::{HostBuf, Lent};
use crate::abi::sdk::life::{Counted, Held, Life, Refreshed, Refusal};
use crate::abi::sdk::out::Out;
use crate::abi::sdk::safe::{Instance, SafeSlot};
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
    /// A credential was presented and is invalid.
    Reject,
    /// Not this plugin's credential.
    Pass,
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
            Verdict::Reject => Decision::Stop,
        };
        Self {
            verdict,
            strips: Vec::new(),
            decision,
        }
    }
}

/// AN AUTH PLUGIN THAT VERIFIES ON THE SPOT, in safe Rust.
pub trait VerifyPlugin: Send + Sync + Sized + 'static {
    /// The index, in the plugin's Statement `families`, of its
    /// [`METRIC_CACHE_FLUSHED`](crate::abi::auth::METRIC_CACHE_FLUSHED) counter; `None` when it
    /// caches nothing.
    const CACHE_FAMILY: Option<u32> = None;

    /// Build the plugin from its settings blob (one JSON document) and its resolved secrets (one
    /// per Statement `secret_refs` key, in order). `Err` answers `open` FAILED with that text.
    ///
    /// # Errors
    /// The settings are not this plugin's.
    fn open(settings: &[u8], secrets: &[&[u8]]) -> Result<Self, &'static str>;

    /// Judge the request at one point: the verdict, the decision and the lines to strip (a bare
    /// [`Verdict`] converts, with no strips and its default decision).
    fn verify(&self, request: &VerifyView<'_>) -> Answer;

    /// A reload (the admin cache flush is one with unchanged settings): drop the inbound cache and
    /// answer how many entries it held.
    fn refresh(&self, settings: &[u8], secrets: &[&[u8]]) -> u64 {
        let _ = (settings, secrets);
        0
    }
}

/// THE AUTH KIND'S [`Life`] over a [`VerifyPlugin`] `T`: the instance state the shared lifecycle
/// slots (`abi::sdk::life`) serve, a [`Held`] of it. Each per-kind value is stated here:
///
/// * `validate` answers READY: the settings are judged by `open`;
/// * `open` and `refresh` are [`VerifyPlugin::open`] and [`VerifyPlugin::refresh`]; the entries
///   `refresh` dropped are reported under [`VerifyPlugin::CACHE_FAMILY`], when the plugin states
///   it;
/// * `drive` answers REFUSED (the plugin holds no driver ticket), and `cancel` answers
///   [`CANCEL_ABANDONED`](crate::abi::auth::CANCEL_ABANDONED): `verify` never pends, so nothing is
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

    fn validate(_: &[u8]) -> Result<(), Refusal> {
        Ok(())
    }

    fn open(settings: &[u8], secrets: &[&[u8]], _: u64) -> Result<Self, Refusal> {
        T::open(settings, secrets)
            .map(Verifier)
            .map_err(Refusal::failed)
    }

    fn refresh(&self, settings: &[u8], secrets: &[&[u8]], _: u64) -> Result<Refreshed, Refusal> {
        let dropped = self.0.refresh(settings, secrets);
        Ok(Refreshed {
            counted: T::CACHE_FAMILY.map(|family| Counted {
                family,
                value: dropped as f64,
            }),
        })
    }
}

/// `verify`: [`VerifyPlugin::verify`], its identity written into the host's buffer.
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
        let answer = h.life().plugin().verify(&VerifyView { input });
        let (id, verdict) = match &answer.verdict {
            Verdict::Identity(id) => (Some(id), VERDICT_IDENTITY),
            Verdict::Reject => (None, VERDICT_REJECT),
            Verdict::Pass => (None, VERDICT_PASS),
        };
        let decision = match answer.decision {
            Decision::Continue => DECISION_CONTINUE,
            Decision::Stop => DECISION_STOP,
        };
        write(
            id,
            Some((answer.strips.as_slice(), input.strip(), decision)),
            input.field(|i| &i.out_buf),
            out,
            verdict,
        )
    }
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
            id.credential.as_ref().map(|c| c.expose_secret().as_str()),
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
                len: 0,
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
            len: 0,
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

/// An auth op this kit's plugin does not serve (it states only `CAP_INBOUND`): REFUSED, never
/// called.
#[derive(Debug)]
pub struct NotServed<T, I, O>(PhantomData<(T, I, O)>);
impl<T: VerifyPlugin, I: AbiIn, O: AbiOut> SafeSlot for NotServed<T, I, O> {
    type In = I;
    type Out = O;
    type State = Held<Verifier<T>>;
    fn call(_: Instance<'_, Held<Verifier<T>>>, _: Lent<'_, I>, _: Out<'_, O>) -> Outcome {
        Outcome::Refused
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
            _reserved: 0,
        },
        caps: crate::abi::auth::CAP_INBOUND,
        facts,
        login_kind: crate::abi::auth::LOGIN_KIND_NONE,
        inbound_points: points.bits(),
        styles: ptr::null(),
        styles_len: 0,
        operator_principal: crate::abi::sdk::door::abi_str(""),
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

/// One inbound carrier `verify` reads (a field line's name), as the Statement states it: a
/// [`MARK_WORD_CARRIER`] word mark in [`Statement::mark_words`].
#[must_use]
pub const fn carrier(name: &'static str) -> MarkWord {
    MarkWord {
        class: MARK_WORD_CARRIER,
        _reserved: 0,
        word: crate::abi::sdk::door::abi_str(name),
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
