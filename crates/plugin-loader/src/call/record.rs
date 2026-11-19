// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The crossing recorder: one hook on the one crossing place (DESIGN-interface-revision G.1 item 7, F2).
//!
//! Every call of every kind is built by `call::frame` and invoked by `call` (the five functions of
//! `call/mod.rs`), so this hook sees every byte the engine lets a plugin read (the head, every text,
//! every blob, every pair of a lent list, every result a resumed chain is handed) and every answer that
//! comes back. With no recorder installed a crossing pays one load and one untaken branch.
//!
//! `Crossings` is the recorder the security test `abi_crossings` installs: secrets are planted with the
//! instances allowed to see them, and any planted secret found in a crossing toward another instance is a
//! leak, kept with the place it was found.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, OnceLock, PoisonError};

use busbar_plugin_abi::host_side::driver::Instance;
use busbar_plugin_abi::types::{Bytes, KindCode, Pair, Status, Str};

use super::ffi::Call;
use super::layout::{self, Drift};

/// The instance a crossing goes toward.
#[derive(Clone, Copy, Debug)]
pub struct Who<'a> {
    pub kind: KindCode,
    /// The verified stamp name of the image.
    pub plugin: &'a str,
    /// The configured instance name.
    pub name: &'a str,
    pub instance: u64,
    pub slot: u32,
}

impl<'a> Who<'a> {
    pub fn of(inst: &'a Instance) -> Who<'a> {
        Who {
            kind: inst.kind,
            plugin: &inst.identity,
            name: &inst.name,
            instance: inst.id,
            slot: inst.slot,
        }
    }
}

/// Everything one call lets the plugin read.
pub struct Seen<'a> {
    pub session: u64,
    pub mono_ns: u64,
    pub head: &'a [u8],
    pub texts: &'a [Str<'a>],
    pub blobs: &'a [Bytes<'a>],
    /// The pair list lent in one blob position, by content (the blob itself holds no content bytes).
    pub list: &'a [Pair<'a>],
}

impl<'a> Seen<'a> {
    pub fn of(session: u64, call: &'a Call<'a>, list: &'a [Pair<'a>]) -> Seen<'a> {
        Seen {
            session,
            mono_ns: call.mono_ns(),
            head: call.head(),
            texts: call.texts(),
            blobs: call.blobs(),
            list,
        }
    }
}

/// The hook. Implementations run on the calling thread, inside the crossing, and must not call a plugin.
pub trait Recorder: Send + Sync {
    /// A call about to cross toward `who`, table entry `method`.
    fn toward(&self, who: &Who<'_>, method: u8, seen: &Seen<'_>);
    /// The answer that came back: the terminal status and the answer block as the plugin wrote it.
    fn back(&self, who: &Who<'_>, method: u8, status: Status, answer: &[u8]);
    /// The results a parked chain of `slot` is resumed with (the bytes of its Needs' answers).
    fn resumed(&self, slot: u32, results: &[u8]);
}

static HOOK: OnceLock<&'static dyn Recorder> = OnceLock::new();

/// Install the process's recorder. Once; a second call changes nothing and answers false.
pub fn install(recorder: &'static dyn Recorder) -> bool {
    let first = HOOK.set(recorder).is_ok();
    if first {
        // The host half taps every resume through the same recorder.
        busbar_plugin_abi::host_side::driver::set_resume_tap(resume_tap);
    }
    first
}

fn resume_tap(slot: u32, results: &[u8]) {
    if let Some(hook) = HOOK.get() {
        hook.resumed(slot, results);
    }
}

#[inline(always)]
pub(crate) fn toward(
    inst: &Instance,
    method: u8,
    session: u64,
    call: &Call<'_>,
    list: &[Pair<'_>],
) {
    if let Some(hook) = HOOK.get() {
        toward_cold(*hook, inst, method, session, call, list);
    }
}

#[cold]
fn toward_cold(
    hook: &dyn Recorder,
    inst: &Instance,
    method: u8,
    session: u64,
    call: &Call<'_>,
    list: &[Pair<'_>],
) {
    hook.toward(&Who::of(inst), method, &Seen::of(session, call, list));
}

/// The `open` crossing: the bound configuration an image is opened with, shown before it crosses. It
/// is made through the image's header, not a kind's table, so the method is the header entry
/// (`ENTRY_OPEN`) and no row of the method table is held against it.
#[inline(always)]
pub(crate) fn toward_open(who: &Who<'_>, flags: u32, config: &[u8]) {
    if let Some(hook) = HOOK.get() {
        open_cold(*hook, who, flags, config);
    }
}

#[cold]
fn open_cold(hook: &dyn Recorder, who: &Who<'_>, flags: u32, config: &[u8]) {
    let head = flags.to_le_bytes();
    let blobs = [Bytes::new(config)];
    hook.toward(
        who,
        busbar_plugin_abi::host_side::watch::ENTRY_OPEN,
        &Seen {
            session: 0,
            mono_ns: 0,
            head: &head,
            texts: &[],
            blobs: &blobs,
            list: &[],
        },
    );
}

/// A chain start, whose call record is built past the bolt: the same parts, by content. `blob` is the
/// method's one byte argument, None for a method that takes no bytes.
#[inline(always)]
pub(crate) fn toward_start(
    inst: &Instance,
    method: u8,
    mono_ns: u64,
    head: &[u8],
    blob: Option<&[u8]>,
) {
    if let Some(hook) = HOOK.get() {
        start_cold(*hook, inst, method, mono_ns, head, blob);
    }
}

#[cold]
fn start_cold(
    hook: &dyn Recorder,
    inst: &Instance,
    method: u8,
    mono_ns: u64,
    head: &[u8],
    blob: Option<&[u8]>,
) {
    let lent = [Bytes::new(blob.unwrap_or(&[]))];
    let blobs: &[Bytes<'_>] = if blob.is_some() { &lent } else { &[] };
    hook.toward(
        &Who::of(inst),
        method,
        &Seen {
            session: 0,
            mono_ns,
            head,
            texts: &[],
            blobs,
            list: &[],
        },
    );
}

#[inline(always)]
pub(crate) fn back(inst: &Instance, method: u8, status: Status, answer: &[u8]) {
    if let Some(hook) = HOOK.get() {
        back_cold(*hook, inst, method, status, answer);
    }
}

#[cold]
fn back_cold(hook: &dyn Recorder, inst: &Instance, method: u8, status: Status, answer: &[u8]) {
    hook.back(&Who::of(inst), method, status, answer);
}

// ---- the recorder of `abi_crossings` ----

/// Where in a crossing a planted secret was found.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Place {
    Head,
    Text(usize),
    Blob(usize),
    PairName(usize),
    PairValue(usize),
    /// In the results a chain was resumed with.
    Resume,
}

/// One planted secret found in a crossing toward an instance that does not own it.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Leak {
    /// The label the secret was planted under (never the secret).
    pub label: Box<str>,
    pub kind: KindCode,
    pub plugin: Box<str>,
    pub name: Box<str>,
    pub method: u8,
    pub place: Place,
}

struct Planted {
    label: Box<str>,
    /// The secret in every form searched for: as given, and base64 (standard and URL-safe, unpadded
    /// prefix) and lowercase hex of it, so a re-encoded copy is found too.
    forms: Vec<Box<[u8]>>,
    /// Instance names or image identities allowed to read it (the secret plugin that resolved it, the
    /// auth plugin it was
    /// minted by). Empty: no plugin may.
    owners: Vec<Box<str>>,
}

/// The scanning recorder.
#[derive(Default)]
pub struct Crossings {
    planted: Mutex<Vec<Planted>>,
    leaks: Mutex<Vec<Leak>>,
    /// Calls that were not the call their row of the method table states.
    drifts: Mutex<Vec<Drift>>,
    /// The instance name of each slot seen, so a resume (which names only the slot) is attributed.
    slots: Mutex<Vec<(u32, KindCode, Box<str>, Box<str>)>>,
    crossings: AtomicU64,
    /// Calls toward each kind, index `KindCode as usize - 1`.
    by_kind: [AtomicU64; 7],
    bytes: AtomicU64,
}

/// The shortest secret worth searching for: below this a match is chance, not a leak.
pub const SHORTEST: usize = 8;

impl Crossings {
    pub fn new() -> Crossings {
        Crossings::default()
    }

    /// Plant `secret` under `label`; `owners` are the instance names that may read it. A secret shorter
    /// than `SHORTEST` is refused (false): the test must plant long random values.
    pub fn plant(&self, label: &str, secret: &[u8], owners: &[&str]) -> bool {
        if secret.len() < SHORTEST {
            return false;
        }
        let mut forms: Vec<Box<[u8]>> = vec![Box::from(secret)];
        forms.push(hex(secret).into_bytes().into_boxed_slice());
        for alphabet in [B64_STANDARD, B64_URL] {
            let encoded = base64_stem(secret, alphabet);
            if encoded.len() >= SHORTEST {
                forms.push(encoded.into_boxed_slice());
            }
        }
        self.planted
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push(Planted {
                label: Box::from(label),
                forms,
                owners: owners.iter().map(|owner| Box::from(*owner)).collect(),
            });
        true
    }

    /// Every leak found so far.
    pub fn leaks(&self) -> Vec<Leak> {
        self.leaks
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    /// Every call so far that was not the call its row of the method table states.
    pub fn drifts(&self) -> Vec<Drift> {
        self.drifts
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    /// Crossings scanned (calls toward a plugin plus resumes).
    pub fn crossings(&self) -> u64 {
        self.crossings.load(Ordering::Relaxed)
    }

    /// Calls seen toward `kind`.
    pub fn toward_kind(&self, kind: KindCode) -> u64 {
        self.by_kind[kind as usize - 1].load(Ordering::Relaxed)
    }

    /// Bytes scanned.
    pub fn bytes(&self) -> u64 {
        self.bytes.load(Ordering::Relaxed)
    }

    /// How many secrets are planted.
    pub fn planted(&self) -> usize {
        self.planted
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .len()
    }

    fn scan(&self, who: &Who<'_>, method: u8, place: Place, hay: &[u8]) {
        self.bytes.fetch_add(hay.len() as u64, Ordering::Relaxed);
        if hay.len() < SHORTEST {
            return;
        }
        let planted = self.planted.lock().unwrap_or_else(PoisonError::into_inner);
        for secret in planted.iter() {
            // An owner is named by its instance name or by its image's verified identity.
            if secret
                .owners
                .iter()
                .any(|owner| **owner == *who.name || **owner == *who.plugin)
            {
                continue;
            }
            if secret.forms.iter().any(|form| contains(hay, form)) {
                self.leaks
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner)
                    .push(Leak {
                        label: secret.label.clone(),
                        kind: who.kind,
                        plugin: Box::from(who.plugin),
                        name: Box::from(who.name),
                        method,
                        place,
                    });
            }
        }
    }

    fn remember(&self, who: &Who<'_>) {
        let mut slots = self.slots.lock().unwrap_or_else(PoisonError::into_inner);
        match slots.iter_mut().find(|(slot, ..)| *slot == who.slot) {
            Some(row) => {
                if *row.3 != *who.name {
                    *row = (
                        who.slot,
                        who.kind,
                        Box::from(who.plugin),
                        Box::from(who.name),
                    );
                }
            }
            None => slots.push((
                who.slot,
                who.kind,
                Box::from(who.plugin),
                Box::from(who.name),
            )),
        }
    }
}

impl Recorder for Crossings {
    fn toward(&self, who: &Who<'_>, method: u8, seen: &Seen<'_>) {
        self.crossings.fetch_add(1, Ordering::Relaxed);
        self.by_kind[who.kind as usize - 1].fetch_add(1, Ordering::Relaxed);
        // Header entries (open, resume) are not rows of a kind's method table.
        if method < busbar_plugin_abi::host_side::watch::ENTRY_DESCRIBE {
            if let Err(drift) = layout::check(who.kind, method, seen) {
                self.drifts
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner)
                    .push(drift);
            }
        }
        self.remember(who);
        self.scan(who, method, Place::Head, seen.head);
        for (at, text) in seen.texts.iter().enumerate() {
            self.scan(who, method, Place::Text(at), text.get().as_bytes());
        }
        for (at, blob) in seen.blobs.iter().enumerate() {
            self.scan(who, method, Place::Blob(at), blob.get());
        }
        for (at, pair) in seen.list.iter().enumerate() {
            self.scan(who, method, Place::PairName(at), pair.name.get().as_bytes());
            self.scan(who, method, Place::PairValue(at), pair.value.get());
        }
    }

    fn back(&self, _who: &Who<'_>, _method: u8, _status: Status, _answer: &[u8]) {
        // An answer comes from the plugin: it can hold only what the plugin was given or made. The
        // custody question is what goes toward a plugin; answers are counted by the caller's own tests.
    }

    fn resumed(&self, slot: u32, results: &[u8]) {
        self.crossings.fetch_add(1, Ordering::Relaxed);
        let row = self
            .slots
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .iter()
            .find(|(s, ..)| *s == slot)
            .map(|(_, kind, plugin, name)| (*kind, plugin.clone(), name.clone()));
        let Some((kind, plugin, name)) = row else {
            return;
        };
        self.scan(
            &Who {
                kind,
                plugin: &plugin,
                name: &name,
                instance: 0,
                slot,
            },
            busbar_plugin_abi::host_side::watch::ENTRY_RESUME,
            Place::Resume,
            results,
        );
    }
}

fn contains(hay: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty()
        && hay.len() >= needle.len()
        && hay.windows(needle.len()).any(|w| w == needle)
}

fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(char::from(DIGITS[usize::from(byte >> 4)]));
        out.push(char::from(DIGITS[usize::from(byte & 15)]));
    }
    out
}

const B64_STANDARD: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
const B64_URL: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

/// The base64 of the whole 3-byte groups of `bytes`: the stem every encoding of a value that starts
/// with `bytes` begins with, whatever follows it and however it is padded.
fn base64_stem(bytes: &[u8], alphabet: &[u8; 64]) -> Vec<u8> {
    let mut out = Vec::with_capacity(bytes.len() / 3 * 4);
    for group in bytes.chunks_exact(3) {
        let word = u32::from(group[0]) << 16 | u32::from(group[1]) << 8 | u32::from(group[2]);
        for shift in [18, 12, 6, 0] {
            out.push(alphabet[((word >> shift) & 63) as usize]);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::call::frame::{Frame, Mono};

    const KEY: &[u8] = b"sk-planted-0f3a9c1e77b2-provider-credential";

    fn transport() -> Who<'static> {
        Who {
            kind: KindCode::Transport,
            plugin: "busbar-transport-http",
            name: "http",
            instance: 4,
            slot: 9,
        }
    }

    fn vault() -> Who<'static> {
        Who {
            kind: KindCode::Secret,
            plugin: "busbar-secret-vault",
            name: "vault",
            instance: 2,
            slot: 3,
        }
    }

    #[test]
    fn a_planted_credential_in_a_blob_toward_a_non_owner_is_a_leak() {
        let rec = Crossings::new();
        assert!(rec.plant("provider-key", KEY, &["vault"]));
        let mut head = b"authorization: Bearer ".to_vec();
        head.extend_from_slice(KEY);
        let frame = Frame::new((), [], [head.as_slice()]);
        let call = frame.call(Mono::NONE);
        rec.toward(&transport(), 2, &Seen::of(0, &call, &[]));
        let leaks = rec.leaks();
        assert_eq!(leaks.len(), 1);
        assert_eq!(&*leaks[0].label, "provider-key");
        assert_eq!(leaks[0].place, Place::Blob(0));
        assert_eq!(
            (leaks[0].kind, &*leaks[0].name),
            (KindCode::Transport, "http")
        );
        assert_eq!(rec.crossings(), 1);
    }

    #[test]
    fn the_owner_may_read_its_own_secret() {
        let rec = Crossings::new();
        rec.plant("provider-key", KEY, &["vault"]);
        let frame = Frame::new((), [], [KEY]);
        let call = frame.call(Mono::NONE);
        rec.toward(&vault(), 0, &Seen::of(0, &call, &[]));
        assert!(rec.leaks().is_empty());
        assert_eq!(rec.crossings(), 1);
    }

    #[test]
    fn a_secret_in_a_text_a_head_or_a_lent_pair_is_found() {
        let rec = Crossings::new();
        rec.plant("provider-key", KEY, &[]);
        let text = format!("?key={}", core::str::from_utf8(KEY).unwrap());
        let pairs = [Pair {
            name: Str::new("x-api-key"),
            value: Bytes::new(KEY),
        }];
        let frame = Frame::new((), [text.as_str()], []);
        let call = frame.call(Mono::NONE);
        rec.toward(&transport(), 1, &Seen::of(0, &call, &pairs));
        let places: Vec<Place> = rec.leaks().iter().map(|leak| leak.place).collect();
        assert_eq!(places, [Place::Text(0), Place::PairValue(0)]);
    }

    #[test]
    fn a_re_encoded_copy_is_found() {
        let rec = Crossings::new();
        rec.plant("provider-key", KEY, &[]);
        let as_hex = hex(KEY);
        let frame = Frame::new((), [], [as_hex.as_bytes()]);
        let call = frame.call(Mono::NONE);
        rec.toward(&transport(), 1, &Seen::of(0, &call, &[]));
        let mut basic = b"Basic ".to_vec();
        basic.extend_from_slice(&base64_stem(KEY, B64_STANDARD));
        let frame = Frame::new((), [], [basic.as_slice()]);
        let call = frame.call(Mono::NONE);
        rec.toward(&transport(), 1, &Seen::of(0, &call, &[]));
        assert_eq!(rec.leaks().len(), 2);
    }

    #[test]
    fn a_resume_is_attributed_to_the_slot_it_was_seen_on() {
        let rec = Crossings::new();
        rec.plant("provider-key", KEY, &["vault"]);
        let frame = Frame::new((), [], []);
        let call = frame.call(Mono::NONE);
        rec.toward(&transport(), 1, &Seen::of(0, &call, &[]));
        rec.resumed(9, KEY);
        let leaks = rec.leaks();
        assert_eq!(leaks.len(), 1);
        assert_eq!(leaks[0].place, Place::Resume);
        rec.resumed(3, KEY);
        assert_eq!(rec.leaks().len(), 1, "an unseen slot is not attributed");
    }

    #[test]
    fn a_short_secret_is_not_planted() {
        let rec = Crossings::new();
        assert!(!rec.plant("pin", b"1234", &[]));
        assert_eq!(rec.planted(), 0);
    }
}
