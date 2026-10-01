// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE AUTH KIND'S VERIFY DOOR, FOR A SAFE PLUGIN (`abi::auth`, THE DESIGN, sections 11.4 and 11.6): the auth
//! kind's bits over the SDK's safe layer ([`SafeSlot`], [`Lent`], [`HostBuf`]). An auth plugin that
//! judges an inbound credential on the spot implements [`VerifyPlugin`], and
//! [`auth_verify_door!`](crate::auth_verify_door) builds its whole door over the auth table: the
//! lifecycle, `verify`, and every other auth op answering REFUSED (the plugin states only
//! [`CAP_INBOUND`](crate::abi::auth::CAP_INBOUND)). The plugin crate holds no `unsafe`.
//!
//! * `open` builds the plugin from its settings blob and secrets ([`VerifyPlugin::open`]); `close`
//!   answering READY drops it (the SDK owns the state).
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

use std::cell::UnsafeCell;
use std::marker::PhantomData;
use std::ptr;

use crate::abi::auth::{
    AuthTail, IdentifyOut, IdentityBuf, VerifyIn, IDENTITY_HAS_TTL, SPAN_ABSENT, VERDICT_IDENTITY,
    VERDICT_PASS, VERDICT_REJECT,
};
use crate::abi::mechanism::call::{AbiStr, Blob, InHead, MetricEntry, OutHead, Outcome, Span};
use crate::abi::mechanism::call::{BLOB_ABSENT, METRIC_ADD};
use crate::abi::mechanism::door::{KindTailHead, MarkWord, Statement, MARK_WORD_CARRIER};
use crate::abi::mechanism::lifecycle::{
    CancelIn, CancelOut, DriveIn, GenIn, OpenIn, OpenOut, RefreshIn, ReleaseIn, TickIn, TickOut,
    ValidateIn,
};
use crate::abi::sdk::door::{AbiIn, AbiOut};
use crate::abi::sdk::lent::{HostBuf, Lent};
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

/// The metric entry a `refresh` reports, held by the instance: its address stays put until the
/// host has copied the reply (lifecycle ops never overlap on one instance, and the host copies a
/// ticketless reply before its next call).
struct FlushedEntry(UnsafeCell<MetricEntry>);

// SAFETY: written only inside `refresh`, which never overlaps another lifecycle op on the instance
// and is the only op that touches it; read only by the host between that write and the next.
unsafe impl Send for FlushedEntry {}
// SAFETY: as above.
unsafe impl Sync for FlushedEntry {}

/// The instance state the SDK holds for a [`VerifyPlugin`] `T`.
pub struct Held<T> {
    plugin: T,
    flushed: FlushedEntry,
}

impl<T> std::fmt::Debug for Held<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Held").finish_non_exhaustive()
    }
}

fn no_metric() -> MetricEntry {
    MetricEntry {
        family_idx: 0,
        kind: METRIC_ADD,
        _reserved: [0; 3],
        value: 0.0,
        label_vals: ptr::null(),
        label_vals_len: 0,
    }
}

fn secrets<'a>(list: crate::abi::sdk::lent::LentList<'a, Blob>) -> Vec<&'a [u8]> {
    list.iter().map(Lent::<Blob>::bytes).collect()
}

/// A lifecycle slot answering READY with nothing to do.
macro_rules! ready_slot {
    ($(#[$doc:meta] $name:ident: $in:ty => $out:ty;)*) => {$(
        #[$doc]
        #[derive(Debug)]
        pub struct $name<T>(PhantomData<T>);
        impl<T: VerifyPlugin> SafeSlot for $name<T> {
            type In = $in;
            type Out = $out;
            type State = Held<T>;
            fn call(_: Instance<'_, Held<T>>, _: Lent<'_, $in>, _: Out<'_, $out>) -> Outcome {
                Outcome::Ready
            }
        }
    )*};
}

ready_slot! {
    /// `validate`: the settings are judged by `open`.
    Validate: ValidateIn => OutHead;
    /// `retire`: nothing is generation data.
    Retire: GenIn => OutHead;
    /// `tick`: never asked for (`next_tick_ns` stays `0`).
    Tick: TickIn => TickOut;
    /// `release`: no lease is ever handed out.
    Release: ReleaseIn => OutHead;
    /// `close`: READY; the SDK drops the state.
    Close: InHead => OutHead;
}

/// `open`: [`VerifyPlugin::open`].
#[derive(Debug)]
pub struct Open<T>(PhantomData<T>);
impl<T: VerifyPlugin> SafeSlot for Open<T> {
    type In = OpenIn;
    type Out = OpenOut;
    type State = Held<T>;
    fn call(
        instance: Instance<'_, Held<T>>,
        input: Lent<'_, OpenIn>,
        mut out: Out<'_, OpenOut>,
    ) -> Outcome {
        let out = out.raw();
        let settings = input.field(|i| &i.settings).bytes();
        match T::open(settings, &secrets(input.secrets())) {
            Ok(plugin) => {
                instance.open(Held {
                    plugin,
                    flushed: FlushedEntry(UnsafeCell::new(no_metric())),
                });
                Outcome::Ready
            }
            Err(e) => {
                out.head.error = AbiStr {
                    ptr: e.as_ptr(),
                    len: e.len(),
                };
                Outcome::Failed
            }
        }
    }
}

/// `refresh`: [`VerifyPlugin::refresh`], its count reported under the cache family.
#[derive(Debug)]
pub struct Refresh<T>(PhantomData<T>);
impl<T: VerifyPlugin> SafeSlot for Refresh<T> {
    type In = RefreshIn;
    type Out = OutHead;
    type State = Held<T>;
    fn call(
        instance: Instance<'_, Held<T>>,
        input: Lent<'_, RefreshIn>,
        mut out: Out<'_, OutHead>,
    ) -> Outcome {
        let out = out.raw();
        let Some(h) = instance.get() else {
            return Outcome::Fault;
        };
        let settings = input.field(|i| &i.settings).bytes();
        let dropped = h.plugin.refresh(settings, &secrets(input.secrets()));
        if let Some(family) = T::CACHE_FAMILY {
            let entry = h.flushed.0.get();
            // SAFETY: `FlushedEntry`: no other op touches the entry while `refresh` runs, and the
            // host copied the previous reply before this call began.
            unsafe {
                *entry = MetricEntry {
                    family_idx: family,
                    value: dropped as f64,
                    ..no_metric()
                };
            }
            out.envelope.metrics = entry.cast_const();
            out.envelope.metrics_len = 1;
        }
        Outcome::Ready
    }
}

/// `drive`: the plugin holds no driver ticket.
#[derive(Debug)]
pub struct Drive<T>(PhantomData<T>);
impl<T: VerifyPlugin> SafeSlot for Drive<T> {
    type In = DriveIn;
    type Out = OutHead;
    type State = Held<T>;
    fn call(_: Instance<'_, Held<T>>, _: Lent<'_, DriveIn>, _: Out<'_, OutHead>) -> Outcome {
        Outcome::Refused
    }
}

/// `cancel`: `verify` never pends, so nothing is in flight; the call is abandoned.
#[derive(Debug)]
pub struct Cancel<T>(PhantomData<T>);
impl<T: VerifyPlugin> SafeSlot for Cancel<T> {
    type In = CancelIn;
    type Out = CancelOut;
    type State = Held<T>;
    fn call(
        _: Instance<'_, Held<T>>,
        _: Lent<'_, CancelIn>,
        mut out: Out<'_, CancelOut>,
    ) -> Outcome {
        let out = out.raw();
        out.disposition = crate::abi::auth::CANCEL_ABANDONED;
        Outcome::Ready
    }
}

/// `verify`: [`VerifyPlugin::verify`], its identity written into the host's buffer.
#[derive(Debug)]
pub struct Verify<T>(PhantomData<T>);
impl<T: VerifyPlugin> SafeSlot for Verify<T> {
    type In = VerifyIn;
    type Out = IdentifyOut;
    type State = Held<T>;
    fn call(
        instance: Instance<'_, Held<T>>,
        input: Lent<'_, VerifyIn>,
        mut out: Out<'_, IdentifyOut>,
    ) -> Outcome {
        let out = out.raw();
        let Some(h) = instance.get() else {
            return Outcome::Fault;
        };
        match h.plugin.verify(&VerifyView { input }) {
            Verdict::Reject => {
                out.verdict = VERDICT_REJECT;
                Outcome::Ready
            }
            Verdict::Pass => {
                out.verdict = VERDICT_PASS;
                Outcome::Ready
            }
            Verdict::Identity(id) => write_identity(&id, input.field(|i| &i.out_buf), out),
        }
    }
}

/// Write `id` into the host's identity buffer and answer READY, or answer the short FAILED (every
/// `needed_*` at its full size) when it does not fit.
fn write_identity(
    id: &VerifiedIdentity,
    buf: Lent<'_, IdentityBuf>,
    out: &mut IdentifyOut,
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
        out.needed_bytes = need_bytes as u64;
        out.needed_groups = u32::try_from(need_groups).unwrap_or(u32::MAX);
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
    let o = &mut out.identity;
    (o.subject, o.key_id, o.key_name) = (subject, key_id, key_name);
    (o.user, o.provider, o.name) = (user, provider, name);
    o.claims = Span {
        offset: SPAN_ABSENT,
        len: 0,
    };
    o.claims_fmt = BLOB_ABSENT;
    o.groups_len = u32::try_from(groups.written()).unwrap_or(u32::MAX);
    (o.flags, o.ttl_secs) = match id.ttl_secs {
        Some(t) => (IDENTITY_HAS_TTL, t),
        None => (0, 0),
    };
    o.replay_key = replay_key;
    o.replay_ttl_secs = id.replay.as_ref().map_or(0, |r| r.ttl_secs);
    out.verdict = VERDICT_IDENTITY;
    Outcome::Ready
}

/// An auth op this kit's plugin does not serve (it states only `CAP_INBOUND`): REFUSED, never
/// called.
#[derive(Debug)]
pub struct NotServed<T, I, O>(PhantomData<(T, I, O)>);
impl<T: VerifyPlugin, I: AbiIn, O: AbiOut> SafeSlot for NotServed<T, I, O> {
    type In = I;
    type Out = O;
    type State = Held<T>;
    fn call(_: Instance<'_, Held<T>>, _: Lent<'_, I>, _: Out<'_, O>) -> Outcome {
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
            lifecycle: {
                validate: $crate::abi::sdk::Safe<$crate::abi::sdk::auth_door::Validate<$plugin>>,
                open: $crate::abi::sdk::Safe<$crate::abi::sdk::auth_door::Open<$plugin>>,
                refresh: $crate::abi::sdk::Safe<$crate::abi::sdk::auth_door::Refresh<$plugin>>,
                retire: $crate::abi::sdk::Safe<$crate::abi::sdk::auth_door::Retire<$plugin>>,
                tick: $crate::abi::sdk::Safe<$crate::abi::sdk::auth_door::Tick<$plugin>>,
                drive: $crate::abi::sdk::Safe<$crate::abi::sdk::auth_door::Drive<$plugin>>,
                cancel: $crate::abi::sdk::Safe<$crate::abi::sdk::auth_door::Cancel<$plugin>>,
                release: $crate::abi::sdk::Safe<$crate::abi::sdk::auth_door::Release<$plugin>>,
                close: $crate::abi::sdk::Safe<$crate::abi::sdk::auth_door::Close<$plugin>>,
            },
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

/// An [`AuthTail`] for a verify-only plugin, with `facts` (`FACT_*`). The carriers it reads are its
/// Statement's [`carrier`] word marks, not a tail fact (the One Statement).
#[must_use]
pub const fn verify_tail(facts: u32) -> AuthTail {
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
