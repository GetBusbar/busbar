// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE LIFECYCLE, ONCE FOR EVERY KIND (THE DESIGN §11.2: setup and refresh go through `open`,
//! `refresh` and `tick`; one shared mechanism): the nine lifecycle slots of a kind's door as
//! [`SafeSlot`]s over ONE instance state, [`Held<L>`], which a kind's SDK fills by implementing
//! [`Life`]. A kind's SDK keeps only what is its own: its author trait, its `impl Life` (the
//! per-kind values — the `cancel` disposition, the `drive` answer, what `validate` checks — stated
//! there), its op slots and its door macro. [`plugin_door!`](crate::plugin_door) names the nine
//! slots at once: `lifecycle: life(L)`.
//!
//! What every kind shares, here once:
//!
//! * [`Leases`] — an answer's owned bytes, held under a lease (memory class iv) until `release`;
//!   an unknown lease is REFUSED. Secret bytes are zeroized when released or dropped.
//! * [`fail`] — a FAILED or REFUSED answer's text: ONE slot per thread, overwritten by the thread's
//!   next failure and freed when the thread exits; the host copies it as the crossing returns,
//!   before the thread can make another call. A `'static` text is not copied.
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

use zeroize::Zeroizing;

use crate::abi::mechanism::call::{
    AbiStr, Blob, InHead, MetricEntry, OutHead, Outcome, BLOB_SECRET, METRIC_ADD,
};
use crate::abi::mechanism::lifecycle::{
    CancelIn, CancelOut, DriveIn, GenIn, OpenIn, OpenOut, RefreshIn, ReleaseIn, TickIn, TickOut,
    ValidateIn,
};
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
}

thread_local! {
    /// The text of this thread's last failed answer: ONE slot per thread, overwritten by the
    /// next, freed when the thread exits. It never grows with calls, instances or threads gone.
    static LAST_ERROR: std::cell::RefCell<Box<str>> = std::cell::RefCell::new(Box::from(""));
}

/// Answer `refusal`: its outcome, with `head.error` naming its text until this thread's next
/// failure (a `'static` text is named where it lives).
pub fn fail(head: &mut OutHead, refusal: Refusal) -> Outcome {
    head.error = match refusal.text {
        None => AbiStr {
            ptr: std::ptr::null(),
            len: 0,
        },
        Some(Cow::Borrowed(s)) => AbiStr {
            ptr: s.as_ptr(),
            len: s.len(),
        },
        Some(Cow::Owned(s)) => {
            let held: Box<str> = s.into();
            let named = AbiStr {
                ptr: held.as_ptr(),
                len: held.len(),
            };
            LAST_ERROR.with(|e| *e.borrow_mut() = held);
            named
        }
    };
    refusal.outcome
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

// ── leases ─────────────────────────────────────────────────────────────────────────────────

/// What one lease holds: bytes, zeroized on drop when secret.
enum Lease {
    Bytes(#[allow(dead_code)] Box<[u8]>),
    Secret(#[allow(dead_code)] Zeroizing<Vec<u8>>),
    Kept(#[allow(dead_code)] Box<dyn std::any::Any + Send + Sync>),
}

/// The answers an instance handed the host, each held under its lease until `release`.
#[derive(Default)]
pub struct Leases {
    next: AtomicU64,
    held: Mutex<BTreeMap<u64, Lease>>,
}

impl std::fmt::Debug for Leases {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Leases")
            .field("held", &self.held())
            .finish()
    }
}

impl Leases {
    fn lock(&self) -> std::sync::MutexGuard<'_, BTreeMap<u64, Lease>> {
        self.held
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn hold(&self, head: &mut OutHead, lease: Lease) -> u64 {
        let id = self.next.fetch_add(1, Ordering::Relaxed) + 1;
        self.lock().insert(id, lease);
        head.lease = id;
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
            flags: 0,
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

    /// Hold `owned` — an answer's storage of any shape (several buffers, the arrays naming them) —
    /// under a new lease named in `head.lease`, until `release`. The caller names memory INSIDE
    /// `owned` in its `out`: heap contents do not move when `owned` moves here. Its `Drop` runs at
    /// release (zeroize there what is secret).
    pub fn keep<T: Send + Sync + 'static>(&self, head: &mut OutHead, owned: T) -> u64 {
        self.hold(head, Lease::Kept(Box::new(owned)))
    }

    /// Release `lease`: READY when it was held, REFUSED when it was not (a host bug).
    pub fn release(&self, lease: u64) -> Outcome {
        match self.lock().remove(&lease) {
            Some(_) => Outcome::Ready,
            None => Outcome::Refused,
        }
    }

    /// How many leases are held.
    #[must_use]
    pub fn held(&self) -> usize {
        self.lock().len()
    }
}

fn absent() -> Blob {
    Blob {
        ptr: std::ptr::null(),
        len: 0,
        fmt: crate::abi::mechanism::call::BLOB_ABSENT,
        flags: 0,
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
}

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
}

impl<L> std::fmt::Debug for Held<L> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Held")
            .field("leases", &self.leases)
            .finish_non_exhaustive()
    }
}

impl<L: Life> Held<L> {
    fn new(life: L) -> Self {
        Self {
            life,
            leases: Leases::default(),
            reported: Reported(Mutex::new(entry(None))),
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

fn secrets<'a>(list: LentList<'a, Blob>) -> Vec<&'a [u8]> {
    list.iter().map(Lent::<Blob>::bytes).collect()
}

// ── the nine slots ──────────────────────────────────────────────────────────────────────────

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
                instance.open(Held::new(life));
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
                Outcome::Ready
            }
            Ok(Refreshed { counted: None }) => Outcome::Ready,
            Err(r) => out.fail(r),
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
    /// `cancel`: nothing pends, so [`Life::CANCEL`].
    Cancel(CancelIn => CancelOut) |_, _, out| {
        out.set(|o| &o.disposition, L::CANCEL);
        Outcome::Ready
    }
);

life_slot!(
    /// `release`: the lease's bytes go (zeroized when secret); an unknown lease is REFUSED.
    Release(ReleaseIn => OutHead) |instance, input, _out| {
        instance
            .get()
            .map_or(Outcome::Refused, |h| h.leases.release(input.lease))
    }
);

life_slot!(
    /// `close`: READY; the SDK drops the state (every lease with it).
    Close(InHead => OutHead) |_, _, _out| { Outcome::Ready }
);

#[cfg(test)]
#[path = "tests/life_tests.rs"]
mod tests;
