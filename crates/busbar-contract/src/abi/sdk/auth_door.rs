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
//! * `verify` hands [`VerifyPlugin::verify`] a [`VerifyView`] and writes its [`Verdict`]: an
//!   identity goes into the host's [`IdentityBuf`](crate::abi::auth::IdentityBuf). One that does not
//!   fit is the short answer (FAILED, every `needed_*` at its full size); the host re-calls once and
//!   the plugin judges again. A plugin whose verdict is not deterministic remembers it per ticket.
//! * `refresh` calls [`VerifyPlugin::refresh`] and reports the inbound cache entries it dropped
//!   under [`METRIC_CACHE_FLUSHED`](crate::abi::auth::METRIC_CACHE_FLUSHED), when the plugin states
//!   that family ([`VerifyPlugin::CACHE_FAMILY`]).
//!
//! This kit answers every verdict READY: a plugin whose `verify` waits on I/O (a key-set fetch, a
//! directory read) writes its own slots over [`crate::plugin_door!`].

use std::marker::PhantomData;
use std::ptr;

use crate::abi::auth::{
    AuthTail, IdentifyOut, IdentityBuf, VerifyIn, IDENTITY_HAS_TTL, SPAN_ABSENT, VERDICT_IDENTITY,
    VERDICT_PASS, VERDICT_REJECT,
};
use crate::abi::mechanism::call::{AbiStr, Blob, Outcome, Span, BLOB_ABSENT};
use crate::abi::mechanism::door::{KindTailHead, Statement};
use crate::abi::sdk::door::{AbiIn, AbiOut};
use crate::abi::sdk::lent::{HostBuf, Lent};
use crate::abi::sdk::life::{Counted, Held, Life, Refreshed, Refusal};
use crate::abi::sdk::out::Out;
use crate::abi::sdk::safe::{Instance, SafeSlot};
pub use crate::auth_calls::VerifiedIdentity;

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

    /// The carrier field `name` (ASCII case-insensitive), as presented; `None` = absent.
    #[must_use]
    pub fn carrier(&self, name: &str) -> Option<&'a [u8]> {
        self.input
            .carrier()
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

    /// SHA-256 of the body, when the tail states the plugin reads it.
    #[must_use]
    pub fn body_hash(&self) -> Option<[u8; 32]> {
        (self.input.request.body_hash_present == 1).then_some(self.input.request.body_hash)
    }
}

/// A plugin's verdict on one credential.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    /// Identified.
    Identity(VerifiedIdentity),
    /// A credential was presented and is invalid.
    Reject,
    /// Not this plugin's credential.
    Pass,
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

    /// Judge one credential.
    fn verify(&self, request: &VerifyView<'_>) -> Verdict;

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
        mut out: Out<'_, IdentifyOut>,
    ) -> Outcome {
        let Some(h) = instance.get() else {
            return Outcome::Fault;
        };
        match h.life().plugin().verify(&VerifyView { input }) {
            Verdict::Reject => {
                out.set(|o| &o.verdict, VERDICT_REJECT);
                Outcome::Ready
            }
            Verdict::Pass => {
                out.set(|o| &o.verdict, VERDICT_PASS);
                Outcome::Ready
            }
            Verdict::Identity(id) => {
                write_identity(&id, input.field(|i| &i.out_buf), out, VERDICT_IDENTITY)
            }
        }
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
    mut out: Out<'_, IdentifyOut>,
    verdict: u32,
) -> Outcome {
    let mut bytes: HostBuf<'_, u8> = buf.buf();
    let mut groups: HostBuf<'_, Span> = buf.groups();
    // The FULL sizes first: a short answer writes nothing into the host's buffers.
    let texts = [
        Some(id.subject.as_str()),
        id.key_id.as_deref(),
        id.key_name.as_deref(),
        id.user.as_deref(),
        id.provider.as_deref(),
        id.name.as_deref(),
        id.replay.as_ref().map(|r| r.key.as_str()),
    ];
    let need_bytes = texts.iter().flatten().map(|t| t.len()).sum::<usize>()
        + id.groups.iter().map(String::len).sum::<usize>();
    let need_groups = id.groups.len();
    if need_bytes > bytes.cap() || need_groups > groups.cap() {
        out.set(|o| &o.needed_bytes, need_bytes as u64);
        out.set(
            |o| &o.needed_groups,
            u32::try_from(need_groups).unwrap_or(u32::MAX),
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
    let [subject, key_id, key_name, user, provider, name, replay_key] = texts.map(&mut span);
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

/// An [`AuthTail`] for a verify-only plugin reading `carriers`, with `facts` (`FACT_*`).
#[must_use]
pub const fn verify_tail(facts: u32, carriers: &'static [AbiStr]) -> AuthTail {
    AuthTail {
        head: KindTailHead {
            size: std::mem::size_of::<AuthTail>() as u32,
            _reserved: 0,
        },
        caps: crate::abi::auth::CAP_INBOUND,
        facts,
        login_kind: crate::abi::auth::LOGIN_KIND_NONE,
        _reserved: 0,
        styles: ptr::null(),
        styles_len: 0,
        aliases: ptr::null(),
        aliases_len: 0,
        carriers: carriers.as_ptr(),
        carriers_len: carriers.len(),
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
