// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Describe-only admission for inspection (DES-443 r3, #443): read a Trusted native candidate's describe without
//! admitting it for life.
//!
//! Steps 1-7 are `admit`'s own ([`crate::admit::verify`]), then:
//! - **Cache hit** (same sha256 and `former_names`): the cached describe answers on the request thread. Nothing is
//!   opened and no slot is taken.
//! - **Resident hit** (the bytes are already installed): the resident image is described on a permanent worker and
//!   cached. Nothing is opened and no slot is taken (B-2).
//! - **Miss:** the one global inspection slot is tried on the request thread (busy is a 503 at once, F4). A
//!   `busbar-inspect` thread then owns the slot across open, the step-9 checks, describe, close on a worker, the
//!   `name_still_loaded` probe and the cache insert, and always finishes, even after the request's deadline
//!   (`late`, audited through the caller's sink).
//!
//! Each distinct sha256 is opened at most once per process, so whatever an initializer leaks is bounded by the cap:
//! [`CAP_IMAGES`] distinct images and [`CAP_BYTES`] of their bytes. The cache never evicts (evicting would reopen);
//! a restart clears it.

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex, OnceLock};
use std::time::{Duration, Instant};

use busbar_plugin_abi::host::Host;

use crate::admit::{SignedManifest, TrustConfig};
use crate::instance::{Described, SlotTable};
use crate::refusal::{Refusal, RefusalCode};

/// The request's wall-clock bound on one inspection miss (DES-443 M1).
pub const DEADLINE: Duration = Duration::from_secs(10);

/// The `Retry-After` an inspection 503 carries, in seconds.
pub const RETRY_AFTER_S: u32 = 10;

/// At most this many distinct images are ever opened for inspection in one process. A restart clears it.
pub const CAP_IMAGES: usize = 32;

/// At most this many bytes of distinct images are ever opened for inspection in one process. A restart clears it.
pub const CAP_BYTES: u64 = 4 << 30;

/// How an inspection ended, as its audit row states it (DES-443 r3 §5).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Outcome {
    /// Answered from the cache or a resident image; nothing was opened.
    Cached,
    /// Opened, described, closed and unmapped.
    Unloaded,
    /// Opened, described and closed, but the image is still mapped (it pinned itself).
    Pinned,
    /// The inspect thread finished after the request's deadline had answered 503.
    Late,
    /// Refused: before any open, or by its describe, or at the cap, busy or past the deadline.
    Refused,
}

impl Outcome {
    /// The audit word.
    #[must_use]
    pub fn word(self) -> &'static str {
        match self {
            Outcome::Cached => "cached",
            Outcome::Unloaded => "unloaded",
            Outcome::Pinned => "pinned",
            Outcome::Late => "late",
            Outcome::Refused => "refused",
        }
    }
}

/// One inspection's audit facts (DES-443 r3 §5).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InspectOutcome {
    /// The image's sha256.
    pub sha256: [u8; 32],
    /// Whether this inspection opened the image.
    pub opened: bool,
    /// How it ended.
    pub outcome: Outcome,
    /// Why, for a refusal, a pin or a late completion.
    pub reason: Option<String>,
}

/// Why an inspection did not answer a describe.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Unanswered {
    /// The image, or its describe, was refused.
    Refused(Refusal),
    /// Busy, past the deadline or at the cap: a 503 the caller may retry after `retry_after_s`.
    Unavailable { text: String, retry_after_s: u32 },
}

/// What a cached inspection answers.
#[derive(Clone)]
struct Entry {
    answer: Result<Described, Refusal>,
    /// The `former_names` the image's header stated when it was described (F2: re-checked on every hit).
    header_former: String,
}

#[derive(Default)]
struct Cache {
    /// Keyed by sha256 and the signed `former_names` (F2).
    answers: HashMap<([u8; 32], String), Entry>,
    /// Every distinct image this process opened for inspection: its byte length and how often it was opened.
    opened: HashMap<[u8; 32], Opened>,
    cap_warned: Option<Instant>,
}

struct Opened {
    bytes: u64,
    opens: u32,
    pinned: bool,
    /// The `former_names` its header stated, once an open got that far (F2: a later manifest is checked against it
    /// without reopening).
    header_former: Option<String>,
}

fn cache() -> &'static Mutex<Cache> {
    static CACHE: OnceLock<Mutex<Cache>> = OnceLock::new();
    CACHE.get_or_init(Mutex::default)
}

fn locked() -> std::sync::MutexGuard<'static, Cache> {
    cache().lock().unwrap_or_else(|p| p.into_inner())
}

/// How many times this process opened the image with this sha256 for inspection (at most once, DES-443 r3 §2).
#[must_use]
pub fn opens(sha256: &[u8; 32]) -> u32 {
    locked().opened.get(sha256).map_or(0, |o| o.opens)
}

/// Whether an inspection left the image with this sha256 mapped after close (it pinned itself).
#[must_use]
pub fn pinned(sha256: &[u8; 32]) -> bool {
    locked().opened.get(sha256).is_some_and(|o| o.pinned)
}

/// The one global inspection slot (DES-443 M1). Held by the inspect thread from before open until the cache
/// insert, so a hung initializer or describe keeps it and every later miss answers 503.
static SLOT: AtomicBool = AtomicBool::new(false);

/// When the slot was taken, and for which image.
static HELD: Mutex<Option<(Instant, [u8; 32])>> = Mutex::new(None);

/// When `plugin.inspect.slot_held` was last logged.
static SLOT_WARNED: Mutex<Option<Instant>> = Mutex::new(None);

/// How long the slot has been held, in whole seconds (0 when free): the gauge
/// `busbar_plugin_inspect_slot_held_seconds`.
#[must_use]
pub fn slot_held_seconds() -> u64 {
    HELD.lock()
        .unwrap_or_else(|p| p.into_inner())
        .map_or(0, |(since, _)| since.elapsed().as_secs())
}

struct Slot;

impl Slot {
    fn try_take(sha256: [u8; 32]) -> Option<Slot> {
        if SLOT.swap(true, Ordering::AcqRel) {
            return None;
        }
        *HELD.lock().unwrap_or_else(|p| p.into_inner()) = Some((Instant::now(), sha256));
        Some(Slot)
    }
}

impl Drop for Slot {
    fn drop(&mut self) {
        *HELD.lock().unwrap_or_else(|p| p.into_inner()) = None;
        SLOT.store(false, Ordering::Release);
    }
}

/// A miss while the slot is held: 503, and a WARN at most once a minute once the slot has been held past the
/// deadline (DES-443 r3 §3).
fn busy() -> Unanswered {
    let held = *HELD.lock().unwrap_or_else(|p| p.into_inner());
    if let Some((since, sha256)) = held {
        let elapsed = since.elapsed();
        if elapsed > DEADLINE {
            let mut warned = SLOT_WARNED.lock().unwrap_or_else(|p| p.into_inner());
            if warned.is_none_or(|at| at.elapsed() >= Duration::from_secs(60)) {
                *warned = Some(Instant::now());
                tracing::warn!(
                    event = "plugin.inspect.slot_held",
                    sha256 = %hex::encode(sha256),
                    elapsed_s = elapsed.as_secs(),
                    "a plugin inspection has held the one inspection slot past its deadline; every other \
                     uncached inspection is refused until it returns or busbar restarts"
                );
            }
        }
    }
    Unanswered::Unavailable {
        text: "another plugin inspection is loading an image; retry when it finishes".into(),
        retry_after_s: RETRY_AFTER_S,
    }
}

/// Inspect a native candidate under `trust`: its describe, from the cache, a resident image or one describe-only
/// open (see the module docs). `late` receives the outcome of an inspection that finishes after its request
/// answered 503; it runs on the inspect thread.
pub fn describe(
    bytes: &[u8],
    manifest: &SignedManifest,
    trust: &TrustConfig,
    host: &'static Host,
    slots: &Arc<SlotTable>,
    late: Box<dyn FnOnce(InspectOutcome) + Send>,
) -> (Result<Described, Unanswered>, InspectOutcome) {
    let sha256 = busbar_contract::crypto::sha256(bytes);
    let refused = |refusal: Refusal, opened: bool| {
        let reason = Some(refusal.to_string());
        (
            Err(Unanswered::Refused(refusal)),
            InspectOutcome {
                sha256,
                opened,
                outcome: Outcome::Refused,
                reason,
            },
        )
    };
    let fd = match crate::stage::sealed_memfd(bytes) {
        Ok(fd) => fd,
        Err(e) => {
            return refused(
                Refusal::new(RefusalCode::Integrity, "file", e, "a readable image")
                    .named(manifest.name.as_str()),
                false,
            );
        }
    };
    let v = match crate::admit::verify(fd, manifest, trust, &crate::admit::CryptoFacts::FACADE) {
        Ok(v) => v,
        Err(refusal) => return refused(refusal, false),
    };
    let key = (v.sha256, v.former_names.clone());
    if let Some(entry) = locked().answers.get(&key).cloned() {
        return answer_hit(&v, entry);
    }
    if let Some((header, former)) = crate::admit::resident_header(&v.sha256) {
        if former != v.former_names {
            return refused(
                Refusal::new(
                    RefusalCode::DoorStampMismatch,
                    "former_names",
                    former,
                    v.former_names.clone(),
                )
                .named(&v.name),
                false,
            );
        }
        let max_out = crate::instance::Ceilings::DEFAULT.max_out;
        let (slots, name, kind) = (Arc::clone(slots), v.name.clone(), v.kind);
        let answer = crate::ffi_thread::on_plugin_thread(move || {
            crate::instance::describe_with(&slots, max_out, &name, kind, |out| {
                header.describe(host, out)
            })
        });
        let answer = match answer {
            Ok(described) => described.and_then(|(described, _)| {
                crate::instance::inspect_checks(&v.name, &described)?;
                Ok(described)
            }),
            Err(_) => return refused(host_panic(&v.name), false),
        };
        let entry = Entry {
            answer,
            header_former: former,
        };
        locked().answers.insert(key, entry.clone());
        return answer_hit(&v, entry);
    }
    let opened_former = locked()
        .opened
        .get(&v.sha256)
        .and_then(|o| o.header_former.clone());
    if let Some(former) = opened_former.filter(|former| *former != v.former_names) {
        return refused(
            Refusal::new(
                RefusalCode::DoorStampMismatch,
                "former_names",
                former,
                v.former_names.clone(),
            )
            .named(&v.name),
            false,
        );
    }
    if let Some(at_cap) = at_cap(&v) {
        return at_cap;
    }
    let Some(slot) = Slot::try_take(v.sha256) else {
        return (
            Err(busy()),
            InspectOutcome {
                sha256,
                opened: false,
                outcome: Outcome::Refused,
                reason: Some("busy".into()),
            },
        );
    };
    let shared = Arc::new(Handoff::default());
    let theirs = Arc::clone(&shared);
    let slots = Arc::clone(slots);
    let spawned = std::thread::Builder::new()
        .name("busbar-inspect".into())
        .spawn(move || {
            let _slot = slot;
            let done = open_and_describe(&v, host, &slots);
            theirs.finish(done, late);
        });
    if let Err(e) = spawned {
        return refused(
            Refusal::new(
                RefusalCode::Integrity,
                "inspect",
                format!("the inspect thread could not start: {e}"),
                "a running inspection",
            ),
            false,
        );
    }
    match shared.wait(DEADLINE) {
        Some(done) => done,
        None => (
            Err(Unanswered::Unavailable {
                text: format!(
                    "the plugin's describe did not answer within {} s; its inspection finishes in the \
                     background and holds the one inspection slot until it does",
                    DEADLINE.as_secs()
                ),
                retry_after_s: RETRY_AFTER_S,
            }),
            InspectOutcome {
                sha256,
                opened: true,
                outcome: Outcome::Refused,
                reason: Some("deadline".into()),
            },
        ),
    }
}

/// A cache or resident answer: its `former_names` re-checked against what the header stated (F2).
fn answer_hit(
    v: &crate::admit::Verified,
    entry: Entry,
) -> (Result<Described, Unanswered>, InspectOutcome) {
    let answer = if entry.header_former == v.former_names {
        entry.answer
    } else {
        Err(Refusal::new(
            RefusalCode::DoorStampMismatch,
            "former_names",
            entry.header_former,
            v.former_names.clone(),
        )
        .named(&v.name))
    };
    let reason = answer.as_ref().err().map(ToString::to_string);
    (
        answer.map_err(Unanswered::Refused),
        InspectOutcome {
            sha256: v.sha256,
            opened: false,
            outcome: Outcome::Cached,
            reason,
        },
    )
}

/// The cap check for a new image: 503 once [`CAP_IMAGES`] distinct images or [`CAP_BYTES`] of them were opened,
/// with a WARN at most once an hour.
fn at_cap(v: &crate::admit::Verified) -> Option<(Result<Described, Unanswered>, InspectOutcome)> {
    let mut cache = locked();
    if cache.opened.contains_key(&v.sha256) {
        return None;
    }
    let bytes: u64 = cache.opened.values().map(|o| o.bytes).sum();
    let len = v.bytes.len() as u64;
    if cache.opened.len() < CAP_IMAGES && bytes.saturating_add(len) <= CAP_BYTES {
        return None;
    }
    if cache
        .cap_warned
        .is_none_or(|at| at.elapsed() >= Duration::from_secs(3600))
    {
        cache.cap_warned = Some(Instant::now());
        tracing::warn!(
            event = "plugin.inspect.cap_reached",
            images = cache.opened.len(),
            bytes,
            "plugin inspection reached its cap of {CAP_IMAGES} distinct images or {CAP_BYTES} bytes; new images \
             are refused until busbar restarts, which clears it"
        );
    }
    Some((
        Err(Unanswered::Unavailable {
            text: format!(
                "plugin inspection has opened its cap of {CAP_IMAGES} distinct images or {} GiB in this \
                 process; a restart clears it",
                CAP_BYTES >> 30
            ),
            retry_after_s: RETRY_AFTER_S,
        }),
        InspectOutcome {
            sha256: v.sha256,
            opened: false,
            outcome: Outcome::Refused,
            reason: Some("inspect-cap".into()),
        },
    ))
}

fn host_panic(name: &str) -> Refusal {
    Refusal::new(
        RefusalCode::DescribeInvalid,
        "describe",
        "the host panicked while describing the image",
        "a describe answer",
    )
    .named(name)
}

/// The inspect thread's work, under the slot: open, step-9 checks, describe, close on a worker, probe and cache.
fn open_and_describe(
    v: &crate::admit::Verified,
    host: &'static Host,
    slots: &Arc<SlotTable>,
) -> (Result<Described, Unanswered>, InspectOutcome) {
    let len = v.bytes.len() as u64;
    let record = |pinned: bool, header_former: Option<&str>| {
        let mut cache = locked();
        let opened = cache.opened.entry(v.sha256).or_insert(Opened {
            bytes: len,
            opens: 0,
            pinned: false,
            header_former: None,
        });
        opened.opens += 1;
        opened.pinned |= pinned;
        if let Some(former) = header_former {
            opened.header_former = Some(former.to_owned());
        }
    };
    let (opened, staged) = match crate::admit::open_checked(v) {
        Ok(opened) => opened,
        Err(refusal) => {
            // open_checked closed whatever it opened; the image counts as opened once, and its refusal is cached
            // under this key so the same request never reopens it.
            record(false, None);
            locked().answers.insert(
                (v.sha256, v.former_names.clone()),
                Entry {
                    answer: Err(refusal.clone()),
                    header_former: v.former_names.clone(),
                },
            );
            let reason = Some(refusal.to_string());
            return (
                Err(Unanswered::Refused(refusal)),
                InspectOutcome {
                    sha256: v.sha256,
                    opened: true,
                    outcome: Outcome::Refused,
                    reason,
                },
            );
        }
    };
    let header_former = opened.former_names().map(str::to_owned).unwrap_or_default();
    let max_out = crate::instance::Ceilings::DEFAULT.max_out;
    let described = {
        let (slots, name, kind, opened) = (Arc::clone(slots), v.name.as_str(), v.kind, &opened);
        crate::ffi_thread::on_plugin_thread(move || {
            crate::instance::describe_with(&slots, max_out, name, kind, |out| {
                opened.describe(host, out)
            })
        })
    };
    let answer = match described {
        Ok(described) => described.and_then(|(described, _)| {
            crate::instance::inspect_checks(&v.name, &described)?;
            Ok(described)
        }),
        Err(_) => {
            // A host-side panic inside the worker closure: the image may be mid-entry, so it is never closed
            // (DES-443 r3 §4). It counts as pinned.
            core::mem::forget(opened);
            core::mem::forget(staged);
            record(true, Some(header_former.as_str()));
            let refusal = host_panic(&v.name);
            locked().answers.insert(
                (v.sha256, v.former_names.clone()),
                Entry {
                    answer: Err(refusal.clone()),
                    header_former,
                },
            );
            return (
                Err(Unanswered::Refused(refusal)),
                InspectOutcome {
                    sha256: v.sha256,
                    opened: true,
                    outcome: Outcome::Refused,
                    reason: Some("host-panic".into()),
                },
            );
        }
    };
    crate::stage::close_on_worker(opened);
    let pinned = staged.still_loaded();
    drop(staged);
    record(pinned, Some(header_former.as_str()));
    locked().answers.insert(
        (v.sha256, v.former_names.clone()),
        Entry {
            answer: answer.clone(),
            header_former,
        },
    );
    let outcome = if pinned {
        Outcome::Pinned
    } else {
        Outcome::Unloaded
    };
    let reason = match &answer {
        Err(refusal) => Some(refusal.to_string()),
        Ok(_) if pinned => Some("still-mapped".into()),
        Ok(_) => None,
    };
    (
        answer.map_err(Unanswered::Refused),
        InspectOutcome {
            sha256: v.sha256,
            opened: true,
            outcome,
            reason,
        },
    )
}

/// The request thread's wait and the inspect thread's answer, decided under one lock: either the request takes
/// the answer, or it has gone and the inspect thread reports `late`.
#[derive(Default)]
struct Handoff {
    state: Mutex<HandoffState>,
    ready: Condvar,
}

#[derive(Default)]
struct HandoffState {
    done: Option<(Result<Described, Unanswered>, InspectOutcome)>,
    abandoned: bool,
}

impl Handoff {
    fn finish(
        &self,
        done: (Result<Described, Unanswered>, InspectOutcome),
        late: Box<dyn FnOnce(InspectOutcome) + Send>,
    ) {
        let mut state = self.state.lock().unwrap_or_else(|p| p.into_inner());
        if state.abandoned {
            drop(state);
            let (_, outcome) = done;
            let reason = match (outcome.outcome, outcome.reason) {
                (word, Some(reason)) => format!("{}: {reason}", word.word()),
                (word, None) => word.word().to_owned(),
            };
            late(InspectOutcome {
                sha256: outcome.sha256,
                opened: outcome.opened,
                outcome: Outcome::Late,
                reason: Some(reason),
            });
        } else {
            state.done = Some(done);
            self.ready.notify_all();
        }
    }

    fn wait(&self, deadline: Duration) -> Option<(Result<Described, Unanswered>, InspectOutcome)> {
        let state = self.state.lock().unwrap_or_else(|p| p.into_inner());
        let (mut state, _) = self
            .ready
            .wait_timeout_while(state, deadline, |s| s.done.is_none())
            .unwrap_or_else(|p| p.into_inner());
        match state.done.take() {
            Some(done) => Some(done),
            None => {
                state.abandoned = true;
                None
            }
        }
    }
}

#[cfg(test)]
#[path = "tests/inspect_tests.rs"]
mod tests;
