// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE LIFECYCLE, ONCE FOR EVERY KIND (THE DESIGN, the plugin ABI: setup and refresh go through `open`,
//! `refresh` and `tick`; one shared mechanism): the nine lifecycle slots of a kind's door as
//! [`SafeSlot`]s over ONE instance state, [`Held<L>`], which a kind's SDK fills by implementing
//! [`Life`]. A kind's SDK keeps only what is its own: its author trait, its `impl Life` (the
//! per-kind values — the `cancel` disposition, the `drive` answer, what `validate` checks — stated
//! there), its op slots and its door macro. [`plugin_door!`](crate::plugin_door) names the nine
//! slots at once: `lifecycle: life(L)`; `lifecycle: life(L, ready)` names the door's optional
//! `ready` too ([`Life::ready`], awaited at boot before any listener binds).
//!
//! What every kind shares, here once:
//!
//! * [`Leases`] — an answer's owned bytes, held under a lease (memory class iv) until `release`;
//!   an unknown lease is REFUSED. Secret bytes are zeroized when released or dropped.
//! * [`Refusal`] — a FAILED or REFUSED answer's text, answered through
//!   [`Out::fail`](crate::abi::sdk::Out::fail): an owned text is kept by the instance that answered
//!   (never by a thread or the process), or, before there is an instance (`validate`, `open`),
//!   written into the reason buffer the host lent the call. A `'static` text is not copied.
//! * [`settings_object`] — a settings blob as the JSON object it must be (`{}` when empty).
//!
//! ```
//! use busbar_contract::abi::sdk::life::{Life, Refusal, Refreshed};
//! struct Echo(usize);
//! impl Life for Echo {
//!     const CANCEL: u32 = 0;
//!     fn validate(_: &[u8]) -> Result<(), Refusal> { Ok(()) }
//!     fn open(settings: &[u8], _: &[&[u8]], _: u64) -> Result<Self, Refusal> {
//!         Ok(Echo(settings.len()))
//!     }
//!     fn refresh(&self, _: &[u8], _: &[&[u8]], _: u64) -> Result<Refreshed, Refusal> {
//!         Ok(Refreshed::default())
//!     }
//! }
//! busbar_contract::plugin_door! {
//!     ops: busbar_contract::abi::secret::Ops,
//!     statement: busbar_contract::abi::sdk::door::statement("echo", "0", 1),
//!     lifecycle: life(Echo),
//!     kind_ops: { resolve: busbar_contract::abi::sdk::Safe<Resolve> },
//! }
//! # use busbar_contract::abi::mechanism::call::Outcome;
//! # use busbar_contract::abi::sdk::{life::Held, Instance, Lent, Out, SafeSlot};
//! # struct Resolve;
//! # impl SafeSlot for Resolve {
//! #     type In = busbar_contract::abi::secret::ResolveIn;
//! #     type Out = busbar_contract::abi::secret::ResolveOut;
//! #     type State = Held<Echo>;
//! #     fn call(_: Instance<'_, Held<Echo>>, _: Lent<'_, Self::In>, _: Out<'_, Self::Out>) -> Outcome {
//! #         Outcome::Ready } }
//! # fn main() { let _ = door(); }
//! ```

use std::borrow::Cow;
use std::collections::BTreeMap;
use std::marker::PhantomData;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;
use std::task::Poll;

use zeroize::Zeroizing;

use crate::abi::mechanism::call::{
    AbiStr, Blob, Diag, InHead, MetricEntry, OutHead, Outcome, BLOB_SECRET, METRIC_ADD,
};
use crate::abi::mechanism::lifecycle::{
    CancelIn, CancelOut, DriveIn, GenIn, OpenIn, OpenOut, ReadyIn, RefreshIn, ReleaseIn, TickIn,
    TickOut, ValidateIn,
};
use crate::abi::mechanism::ticket::Ticket;
use crate::abi::sdk::conn::Host;
use crate::abi::sdk::lent::{Lent, LentList};
use crate::abi::sdk::out::Out;
use crate::abi::sdk::safe::{Instance, SafeSlot};

// ── the failure text ────────────────────────────────────────────────────────────────────────

/// Why a lifecycle or op answered without its result: FAILED or REFUSED, with the text the host
/// renders (none = the outcome alone).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Refusal {
    outcome: Outcome,
    text: Option<Cow<'static, str>>,
}

impl Refusal {
    /// FAILED, saying `text`.
    #[must_use]
    pub fn failed(text: impl Into<Cow<'static, str>>) -> Self {
        Self {
            outcome: Outcome::Failed,
            text: Some(text.into()),
        }
    }

    /// REFUSED, saying `text`.
    #[must_use]
    pub fn refused(text: impl Into<Cow<'static, str>>) -> Self {
        Self {
            outcome: Outcome::Refused,
            text: Some(text.into()),
        }
    }

    /// REFUSED, saying nothing.
    #[must_use]
    pub const fn bare() -> Self {
        Self {
            outcome: Outcome::Refused,
            text: None,
        }
    }

    /// The outcome it answers.
    #[must_use]
    pub const fn outcome(&self) -> Outcome {
        self.outcome
    }

    /// Its text, if any.
    #[must_use]
    pub fn text(&self) -> Option<&str> {
        self.text.as_deref()
    }

    /// Its outcome and its text, for the SDK's writer ([`Out::fail`]).
    pub(crate) fn into_parts(self) -> (Outcome, Option<Cow<'static, str>>) {
        (self.outcome, self.text)
    }
}

impl std::fmt::Display for Refusal {
    /// Its text; a refusal saying nothing reads as its outcome.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self.text {
            Some(text) => f.write_str(text),
            None => write!(f, "{:?}", self.outcome),
        }
    }
}

/// A settings blob's bytes as the JSON object they must be; empty is `{}`.
///
/// # Errors
/// The bytes are not a JSON object: FAILED, saying so under `settings`.
pub fn settings_object(
    bytes: &[u8],
) -> Result<serde_json::Map<String, serde_json::Value>, Refusal> {
    if bytes.is_empty() {
        return Ok(serde_json::Map::new());
    }
    match serde_json::from_slice(bytes) {
        Ok(serde_json::Value::Object(m)) => Ok(m),
        _ => Err(Refusal::failed("settings: must be a JSON object")),
    }
}

/// A settings blob's bytes as the JSON value they hold; empty is `{}`.
///
/// # Errors
/// The bytes are not JSON: FAILED, `settings: <serde's words>`.
pub fn settings_value(bytes: &[u8]) -> Result<serde_json::Value, Refusal> {
    let bytes = if bytes.is_empty() { b"{}" } else { bytes };
    serde_json::from_slice(bytes).map_err(|e| Refusal::failed(format!("settings: {e}")))
}

/// A settings blob's bytes as the plugin's settings type `T`, read from their JSON value (as the
/// configuration grammar reads them, so serde's words name no line or column); empty is `{}`.
///
/// # Errors
/// The bytes are not JSON, or not `T`: FAILED, `settings: <serde's words>`.
pub fn settings_as<T: serde::de::DeserializeOwned>(bytes: &[u8]) -> Result<T, Refusal> {
    serde_json::from_value(settings_value(bytes)?)
        .map_err(|e| Refusal::failed(format!("settings: {e}")))
}

// ── leases ─────────────────────────────────────────────────────────────────────────────────

/// What one lease holds: bytes, zeroized on drop when secret.
enum Lease {
    Bytes(#[allow(dead_code)] Box<[u8]>),
    Secret(#[allow(dead_code)] Zeroizing<Vec<u8>>),
    Kept(#[allow(dead_code)] Box<dyn std::any::Any + Send + Sync>),
}

/// The answers an instance handed the host, each held under its lease until `release`. ONE
/// answer names ONE lease (`head.lease`): what it leases more than once is CHAINED under that
/// lease as its parts `(lease, 0)`, `(lease, 1)`, ... — map entries, no list to allocate — and the
/// host's one release of it frees every part.
#[derive(Default)]
pub struct Leases {
    next: AtomicU64,
    held: Mutex<BTreeMap<(u64, u32), Lease>>,
    /// Alive while this table is: an answer that leased from it is FAULT when the table is gone
    /// by the time the body returns (`abi::sdk::out::Holders`).
    pub(crate) alive: crate::abi::sdk::out::Alive,
}

impl std::fmt::Debug for Leases {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Leases")
            .field("held", &self.held())
            .finish()
    }
}

impl Leases {
    fn lock(&self) -> std::sync::MutexGuard<'_, BTreeMap<(u64, u32), Lease>> {
        self.held
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Hold `lease` for the answer `head` belongs to: chained as the next part of the lease
    /// `head.lease` already names when this answer leased before, else under a new lease.
    fn hold(&self, head: &mut OutHead, lease: Lease) -> u64 {
        let mut held = self.lock();
        let id = head.lease;
        if id != 0 {
            let last = held
                .range((id, 0)..=(id, u32::MAX))
                .next_back()
                .map(|(k, _)| k.1);
            if let Some(part) = last {
                held.insert((id, part.saturating_add(1)), lease);
                return id;
            }
        }
        let id = self.next.fetch_add(1, Ordering::Relaxed) + 1;
        held.insert((id, 0), lease);
        head.lease = id;
        id
    }

    /// Hold `lease` under a new lease of its own; its number.
    fn fresh(&self, lease: Lease) -> u64 {
        let id = self.next.fetch_add(1, Ordering::Relaxed) + 1;
        self.lock().insert((id, 0), lease);
        id
    }

    /// Hold `bytes` under a new lease named in `head.lease`; the blob of `fmt` naming them. Empty
    /// bytes lease nothing and answer an absent blob.
    pub fn blob(&self, head: &mut OutHead, bytes: Vec<u8>, fmt: u32) -> Blob {
        if bytes.is_empty() {
            return absent();
        }
        let held: Box<[u8]> = bytes.into();
        let blob = Blob {
            ptr: held.as_ptr(),
            len: held.len(),
            fmt,
            ..Blob::ZERO
        };
        self.hold(head, Lease::Bytes(held));
        blob
    }

    /// As [`Leases::blob`], for secret material: the blob is flagged secret and the bytes are
    /// zeroized when the lease is released (or the instance closes).
    pub fn secret_blob(&self, head: &mut OutHead, bytes: Vec<u8>, fmt: u32) -> Blob {
        if bytes.is_empty() {
            return absent();
        }
        let held = Zeroizing::new(bytes);
        let blob = Blob {
            ptr: held.as_ptr(),
            len: held.len(),
            fmt,
            flags: BLOB_SECRET,
        };
        // The Vec's heap buffer does not move when the map takes the Vec.
        self.hold(head, Lease::Secret(held));
        blob
    }

    /// Hold `text` under a new lease named in `head.lease`; the string naming it. Empty text
    /// leases nothing and answers the empty string.
    pub fn str(&self, head: &mut OutHead, text: String) -> AbiStr {
        if text.is_empty() {
            return AbiStr::ZERO;
        }
        let held: Box<[u8]> = text.into_bytes().into();
        let s = AbiStr {
            ptr: held.as_ptr(),
            len: held.len(),
        };
        self.hold(head, Lease::Bytes(held));
        s
    }

    /// Hold `owned` — an answer's storage of any shape (several buffers, the arrays naming them) —
    /// under a new lease named in `head.lease`, until `release`. The caller names memory INSIDE
    /// `owned` in its `out`: heap contents do not move when `owned` moves here. Its `Drop` runs at
    /// release (zeroize there what is secret).
    pub fn keep<T: Send + Sync + 'static>(&self, head: &mut OutHead, owned: T) -> u64 {
        self.hold(head, Lease::Kept(Box::new(owned)))
    }

    /// As [`Leases::keep`], always under a new lease, for a kind door that writes the number into
    /// its answer's head itself (the store door's typed answers).
    pub(crate) fn keep_new<T: Send + Sync + 'static>(&self, owned: T) -> u64 {
        self.fresh(Lease::Kept(Box::new(owned)))
    }

    /// Release `lease` and every part chained under it: READY when it was held, REFUSED when it
    /// was not (a host bug). Only the SDK's `release` slot calls it: a body that released a lease
    /// the host is still copying would free memory under it.
    pub(crate) fn release(&self, lease: u64) -> Outcome {
        let mut held = self.lock();
        let mut freed = false;
        while let Some(key) = held
            .range((lease, 0)..=(lease, u32::MAX))
            .next()
            .map(|(k, _)| *k)
        {
            held.remove(&key);
            freed = true;
        }
        if freed {
            Outcome::Ready
        } else {
            Outcome::Refused
        }
    }

    /// How many leases are held (a chained answer is one lease).
    #[must_use]
    pub fn held(&self) -> usize {
        self.lock().keys().filter(|k| k.1 == 0).count()
    }
}

fn absent() -> Blob {
    Blob {
        fmt: crate::abi::mechanism::call::BLOB_ABSENT,
        ..Blob::ZERO
    }
}

// ── the kind's part ────────────────────────────────────────────────────────────────────────

/// One metric a `refresh` reports in its envelope (an unlabelled counter add).
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Counted {
    /// The index of its family in the plugin's Statement `families`.
    pub family: u32,
    /// The amount.
    pub value: f64,
}

/// What a READY `refresh` reports.
#[derive(Debug, Clone, Copy, Default, PartialEq)]
pub struct Refreshed {
    /// The one metric it reports, if any.
    pub counted: Option<Counted>,
}

/// A diagnostic the plugin's Statement declares, raised by the instance an `open` or `refresh`
/// built: the host audits one at warn or error on the plugin's behalf (a flagged open loaded,
/// `plugin.open`, `degraded`), and writes it to the plugin's own log.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Flagged {
    /// The index of its id in the plugin's Statement `diag_ids`.
    pub id_idx: u32,
    /// `SEVERITY_WARN` or `SEVERITY_ERROR` (`abi::mechanism::call`).
    pub severity: u8,
    /// The operator's words; never secret material.
    pub text: String,
}

/// ONE KIND'S LIFECYCLE, as its SDK states it: the instance state the nine generic slots serve,
/// and each per-kind value. A kind's SDK implements it over its author trait; a plugin names it
/// through its kind's door macro.
pub trait Life: Send + Sync + Sized + 'static {
    /// The kind's `cancel` disposition (its own vocabulary, `abi/<kind>/`): the SDK's ops never
    /// pend, so a cancel finds nothing in flight.
    const CANCEL: u32;

    /// The kind's `drive` answer: the SDK holds no driver ticket. READY unless the kind states
    /// otherwise.
    const DRIVE: Outcome = Outcome::Ready;

    /// `validate`: whether `settings` open an instance. The default is the SDK's object check
    /// ([`settings_object`]: "settings: must be a JSON object"); a kind's SDK forwards it to its
    /// author trait's `validate`, so a plugin answers with its own refusal text (its 1.5.5 words).
    ///
    /// # Errors
    /// Why not.
    fn validate(settings: &[u8]) -> Result<(), Refusal> {
        settings_object(settings).map(|_| ())
    }

    /// `open`: the instance over `settings` and its resolved `secrets`, at `generation`.
    ///
    /// # Errors
    /// Why it will not open.
    fn open(settings: &[u8], secrets: &[&[u8]], generation: u64) -> Result<Self, Refusal>;

    /// `refresh` to `generation` with `settings` and `secrets`.
    ///
    /// # Errors
    /// Why the refresh did not apply.
    fn refresh(
        &self,
        settings: &[u8],
        secrets: &[&[u8]],
        generation: u64,
    ) -> Result<Refreshed, Refusal>;

    /// `retire` of `generation`: nothing held per generation unless the kind says so.
    fn retire(&self, generation: u64) {
        let _ = generation;
    }

    /// `tick` at `now_ns`: the next tick wanted, `0` = none.
    fn tick(&self, now_ns: u64) -> u64 {
        let _ = now_ns;
        0
    }

    /// `ready` (`abi::mechanism::lifecycle`, READY): what the instance must do on the network
    /// before it serves (a discovery exchange through its declared need), on `ticket` with the
    /// instance's `host` tables — `host.connector(ticket)` reaches its needs. The host calls it
    /// after `open`, before any listener binds, and boot awaits it: `Poll::Pending` after
    /// registering interest (a pending connector service, or [`Host::wake`] on `ticket` later) is
    /// re-entered with the same ticket after the wake; `Ready(Err)` refuses the boot with the
    /// refusal's text. Called only when the door states it: `lifecycle: life(L, ready)` in
    /// [`plugin_door!`](crate::plugin_door). The default answers at once.
    ///
    /// # Errors
    /// Why the instance cannot serve.
    fn ready(&self, host: &Host, ticket: Ticket) -> Poll<Result<(), Refusal>> {
        let _ = (host, ticket);
        Poll::Ready(Ok(()))
    }

    /// `close`: what the instance lets go before the SDK drops it, over the host tables `open`
    /// handed it (`None` when it was handed none): a carrier closes the host I/O handles it still
    /// holds. The default lets go of nothing.
    fn close(&self, host: Option<&Host>) {
        let _ = host;
    }

    /// What the instance an `open` or `refresh` just built raises on that answer
    /// ([`Flagged`]): asked after each READY `open` and `refresh`. `None` (the default) raises
    /// nothing.
    fn flagged(&self) -> Option<Flagged> {
        None
    }
}

/// The diagnostic an `open` or `refresh` raised ([`Life::flagged`]), held by the instance until
/// the host has copied the reply, as [`Reported`] is. BOXED: an `open` raises it before its state
/// moves into the instance box, so the entry the envelope points to must not move with it.
struct Raised(Mutex<Option<Box<(Flagged, Diag)>>>);

// SAFETY: the entry's one pointer (`text`) points into the `Flagged` text held beside it.
unsafe impl Send for Raised {}
// SAFETY: as above.
unsafe impl Sync for Raised {}

/// The metric entry a `refresh` reports, held by the instance until the host has copied the reply
/// (lifecycle ops never overlap on one instance, and the host copies a reply as it returns).
struct Reported(Mutex<MetricEntry>);

// SAFETY: the entry's one pointer (`label_vals`) is always NULL here.
unsafe impl Send for Reported {}
// SAFETY: as above.
unsafe impl Sync for Reported {}

/// THE INSTANCE STATE every generic lifecycle slot serves: the kind's [`Life`] and the leases its
/// answers hold. A kind's op slots read it as `Instance<'_, Held<L>>`.
pub struct Held<L> {
    life: L,
    leases: Leases,
    reported: Reported,
    raised: Raised,
    host: Option<Host>,
}

impl<L> std::fmt::Debug for Held<L> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Held")
            .field("leases", &self.leases)
            .finish_non_exhaustive()
    }
}

impl<L: Life> Held<L> {
    /// The instance state over `life`, with no lease held and the host tables `host`. A kind
    /// whose `open` the generic slot cannot serve (the store's, whose connect step pends) builds
    /// it itself.
    pub(crate) fn new(life: L, host: Option<Host>) -> Self {
        Self {
            life,
            leases: Leases::default(),
            reported: Reported(Mutex::new(entry(None))),
            raised: Raised(Mutex::new(None)),
            host,
        }
    }

    /// The kind's state.
    pub const fn life(&self) -> &L {
        &self.life
    }

    /// The leases its answers hold.
    pub const fn leases(&self) -> &Leases {
        &self.leases
    }

    /// The host tables `open` handed this instance (`OpenIn.host`); `None` when it was handed
    /// none. Its connector is `host().map(|h| h.connector(ticket))` (`abi::sdk::conn`).
    pub const fn host(&self) -> Option<&Host> {
        self.host.as_ref()
    }
}

fn entry(counted: Option<Counted>) -> MetricEntry {
    MetricEntry {
        family_idx: counted.map_or(0, |c| c.family),
        kind: METRIC_ADD,
        _reserved: [0; 3],
        value: counted.map_or(0.0, |c| c.value),
        label_vals: std::ptr::null(),
        label_vals_len: 0,
    }
}

/// Put what `h`'s instance raises ([`Life::flagged`]) in `head`'s envelope as its one declared
/// diagnostic, held by the instance until its next lifecycle op; nothing when it raises none.
fn raise<L: Life>(h: &Held<L>, head: &mut OutHead) {
    let Some(flag) = h.life.flagged() else {
        return;
    };
    let mut held = h
        .raised
        .0
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let (flag, diag) = &mut **held.insert(Box::new((flag, Diag::ZERO)));
    *diag = Diag {
        id_idx: flag.id_idx,
        severity: flag.severity,
        text: AbiStr {
            ptr: flag.text.as_ptr(),
            len: flag.text.len(),
        },
        ..Diag::ZERO
    };
    head.envelope.diags = std::ptr::from_ref(&*diag);
    head.envelope.diags_len = 1;
}

fn secrets<'a>(list: LentList<'a, Blob>) -> Vec<&'a [u8]> {
    list.iter().map(Lent::<Blob>::bytes).collect()
}

// ── the nine slots ──────────────────────────────────────────────────────────────────────────

/// What `release` answers for a lease this instance does not hold.
pub const NO_SUCH_LEASE: &str = "release: no such lease";

macro_rules! life_slot {
    ($(#[$doc:meta])* $name:ident($in:ty => $out:ty) |$inst:pat_param, $input:pat_param, $o:ident| $body:block) => {
        $(#[$doc])*
        #[derive(Debug)]
        pub struct $name<L>(PhantomData<L>);
        impl<L: Life> SafeSlot for $name<L> {
            type In = $in;
            type Out = $out;
            type State = Held<L>;
            fn call(
                $inst: Instance<'_, Held<L>>,
                $input: Lent<'_, $in>,
                #[allow(unused_mut)] mut $o: Out<'_, $out>,
            ) -> Outcome {
                $body
            }
        }
    };
}

life_slot!(
    /// `validate`: [`Life::validate`].
    Validate(ValidateIn => OutHead) |_, input, out| {
        match L::validate(input.field(|i| &i.settings).bytes()) {
            Ok(()) => Outcome::Ready,
            Err(r) => out.fail(r),
        }
    }
);

life_slot!(
    /// `open`: [`Life::open`]; the SDK holds the state it answers.
    Open(OpenIn => OpenOut) |instance, input, out| {
        let settings = input.field(|i| &i.settings).bytes();
        match L::open(settings, &secrets(input.secrets()), input.generation) {
            Ok(life) => {
                let host = input.host().map(|h| Host::of(&h));
                // Raised from the state before it is installed: the instance is not this
                // call's to read until `open` returns (`Instance::get` answers `None` here).
                let held = Held::new(life, host);
                raise(&held, &mut out.raw().head);
                instance.open(held);
                Outcome::Ready
            }
            Err(r) => out.fail(r),
        }
    }
);

life_slot!(
    /// `refresh`: [`Life::refresh`]; what it counted rides the reply's envelope.
    Refresh(RefreshIn => OutHead) |instance, input, out| {
        let Some(h) = instance.get() else {
            return Outcome::Fault;
        };
        let settings = input.field(|i| &i.settings).bytes();
        match h.life.refresh(settings, &secrets(input.secrets()), input.generation) {
            Ok(Refreshed { counted: Some(c) }) => {
                let mut held = h
                    .reported
                    .0
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                *held = entry(Some(c));
                let o = out.raw();
                o.envelope.metrics = std::ptr::from_ref(&*held);
                o.envelope.metrics_len = 1;
                raise(h, o);
                Outcome::Ready
            }
            Ok(Refreshed { counted: None }) => {
                raise(h, out.raw());
                Outcome::Ready
            }
            Err(r) => out.fail(r),
        }
    }
);

life_slot!(
    /// `ready`: [`Life::ready`], over the host tables the call hands it (a door names it with
    /// `lifecycle: life(L, ready)`).
    Ready(ReadyIn => OutHead) |instance, input, out| {
        let Some(h) = instance.get() else {
            return Outcome::Fault;
        };
        let Some(host) = input.host().map(|t| Host::of(&t)) else {
            return Outcome::Fault;
        };
        match h.life.ready(&host, instance.ticket()) {
            Poll::Pending => Outcome::Pending,
            Poll::Ready(Ok(())) => Outcome::Ready,
            Poll::Ready(Err(r)) => out.fail(r),
        }
    }
);

life_slot!(
    /// `retire`: [`Life::retire`].
    Retire(GenIn => OutHead) |instance, input, _out| {
        if let Some(h) = instance.get() {
            h.life.retire(input.generation);
        }
        Outcome::Ready
    }
);

life_slot!(
    /// `tick`: [`Life::tick`].
    Tick(TickIn => TickOut) |instance, input, out| {
        let next = instance.get().map_or(0, |h| h.life.tick(input.now_ns));
        out.set(|o| &o.next_tick_ns, next);
        Outcome::Ready
    }
);

life_slot!(
    /// `drive`: [`Life::DRIVE`].
    Drive(DriveIn => OutHead) |_, _, _out| { L::DRIVE }
);

life_slot!(
    /// `cancel`: [`Life::CANCEL`] (the SDK drops what the cancelled ticket parked,
    /// `abi::sdk::safe`).
    Cancel(CancelIn => CancelOut) |_, _, out| {
        out.set(|o| &o.disposition, L::CANCEL);
        Outcome::Ready
    }
);

life_slot!(
    /// `release`: the lease's bytes go (zeroized when secret); an unknown lease is REFUSED, in
    /// [`NO_SUCH_LEASE`]'s words.
    Release(ReleaseIn => OutHead) |instance, input, out| {
        match instance.get().map(|h| h.leases.release(input.lease)) {
            Some(Outcome::Ready) => Outcome::Ready,
            _ => out.fail(Refusal::refused(NO_SUCH_LEASE)),
        }
    }
);

life_slot!(
    /// `close`: [`Life::close`], then READY; the SDK drops the state (every lease with it).
    Close(InHead => OutHead) |instance, _, _out| {
        if let Some(h) = instance.get() {
            h.life.close(h.host());
        }
        Outcome::Ready
    }
);

#[cfg(test)]
#[path = "tests/life_tests.rs"]
mod tests;
