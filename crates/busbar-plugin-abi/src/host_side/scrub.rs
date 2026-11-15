// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Core's one redactor: per-instance scrub sets and the URL/FAIL-text helpers (IF §12.16; W1-H0). Plugins log
//! and fail with plain text; core masks it here, and every other core redactor calls these functions.

use core::fmt;
use core::ops::Deref;
use std::borrow::Cow;
use std::collections::BTreeMap;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError, TryLockError};

use aho_corasick::{AhoCorasick, MatchKind};
use arc_swap::ArcSwap;
use base64::Engine as _;
use base64::engine::general_purpose::{STANDARD, STANDARD_NO_PAD, URL_SAFE, URL_SAFE_NO_PAD};
use percent_encoding::{NON_ALPHANUMERIC, percent_encode};
use zeroize::Zeroize as _;

use crate::fail::FAIL_TEXT_WIRE_MAX;

/// What every masked run becomes.
const MASK: &str = "***";

/// One instance's scrub set. Lock-free reads (ArcSwap of an aho-corasick automaton). Keyed by **slot**: one
/// entry per bound secret handle (≤ `MAX_BINDINGS` = 1,024 per instance, §12.7) plus the kernel's own slots for
/// that instance (`slot >= 0x1_0000`: upstream client identities, stdio env secrets; ≤ 64), so its size is
/// bounded by config, never by how often secrets rotate (round 18: each slot holds at most two generations, the
/// current values and the ones they replaced, so ≤ 2 × (MAX_BINDINGS + 64) value sets per instance). Round 8 correction: the **pattern map** holds only
/// wiped-on-free copies ([`Needle`]); the **automaton** does not (§12.16's stated residual).
/// Round 16: `live` holds one immutable snapshot per version, the automaton **and** the flat list of the needles it
/// was built from (the same [`Needle`]s the slots hold, shared, so the snapshot adds no copy), so every reader,
/// the FAIL tail check included, is one `ArcSwap::load` (round 17: = 2 RMWs on the
/// reader's own debt slot, I5's fourth stated exception) and takes no lock. `state` is the writers' lock only.
/// **Round 17, writer-side retirement (I5: no free on a reader thread).** A reader's guard never frees a `Snap`:
/// every `store` goes through `ArcSwap::swap`, and the writer pushes the returned old `Arc<Snap>` onto
/// `ScrubState::retired` before releasing `state`. So after the swap the writer's copy keeps every replaced
/// snapshot alive; a reader whose debt the swap paid (arc-swap `wait_for_readers`) drops its now-owned `Arc` to a
/// count ≥ 1, never 0. Old snapshots are freed (needles zeroed, automaton freed) **only on a writer thread**:
/// at the start of every `register`/`forget` (under `state`, `retired.retain(|s| Arc::strong_count(s) > 1)`) and
/// on `reclaim`, which the loader's watchdog thread calls every scan tick (100 ms, §10.6) for each live slot
/// record with `state.try_lock()` (skips the instance if a writer holds it; never blocks). `Drop for Scrub` (after
/// close, cold) frees the rest. `retired` holds at most the snapshots replaced in the last 100 ms plus those a
/// reader still holds.
pub struct Scrub {
    live: ArcSwap<Snap>,
    state: Mutex<ScrubState>,
}

/// One published version: the automaton and the needles it was built from (every slot's two generations).
/// `ac` is `None` only for an empty set, or if the automaton could not be built, which masks every text whole
/// (fail closed, never open).
struct Snap {
    ac: Option<AhoCorasick>,
    needles: Box<[Arc<Needle>]>,
}

/// Round 8: everything a rebuild reads, behind the one per-instance Mutex. `version` bumps on every change.
#[derive(Default)]
struct ScrubState {
    slots: BTreeMap<u32, Slot>,
    version: u64,
    retired: Vec<Arc<Snap>>,
}

/// Round 17/18: a slot's patterns, every value registered under it (a template's rendered value and each fill),
/// for the current generation and the one it replaced (empty until the first change).
struct Slot {
    /// SHA-256 over the current values, each length-prefixed, in order.
    digest: [u8; 32],
    current: Vec<Arc<Needle>>,
    previous: Vec<Arc<Needle>>,
}

impl ScrubState {
    /// Frees the retired snapshots no reader still holds. Runs only on a writer or the watchdog thread.
    fn retire(&mut self) {
        self.retired.retain(|snap| Arc::strong_count(snap) > 1);
    }
}

impl Default for Scrub {
    fn default() -> Self {
        Self::new()
    }
}

impl Scrub {
    pub fn new() -> Self {
        Scrub {
            live: ArcSwap::from_pointee(Snap {
                ac: None,
                needles: Box::default(),
            }),
            state: Mutex::new(ScrubState::default()),
        }
    }

    fn lock(&self) -> MutexGuard<'_, ScrubState> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Custody calls this **only on a per-instance custody cache miss** (§12.2 steps 4-5; the cache is keyed by
    /// `(instance, handle)`, round 7, so every instance's first resolve registers here), never on a hit. It hashes the value
    /// (SHA-256 through `busbar-crypto`) and compares with the slot's stored digest: equal => return at once
    /// (no lock held beyond the compare, no allocation, no rebuild). Otherwise it **shifts** the slot (round 18,
    /// I14): the current patterns become the slot's previous generation (the generation they displace is dropped and
    /// zeroized, never appended), and the new value's patterns become current: for **each** of
    /// `values` (round 17: a plain SecretRef passes one value; a template passes the rendered text first, then
    /// every fill value, §12.2 step 5), `scrub::needles(value)` (each ≥ 4 bytes; a value shorter than that is not
    /// matched, and custody audits `secret_too_short_to_scrub`), deduplicated across values; then rebuilds the
    /// automaton once, over every slot's current **and** previous patterns, and swaps it in (the snapshot's `needles`
    /// list is the same union, so `text_tail` covers both). The digest is SHA-256 over the length-prefixed values in order. Rebuilds are
    /// therefore bounded by value changes, not by resolves.
    /// **Round 8, normative (linearizable)**: the digest compare, the map update, the automaton rebuild **from the
    /// whole map** and the `ArcSwap::store` all happen while holding `state`'s Mutex, in that order; the lock is
    /// released only after the store. The digest of the needles is computed before taking the lock (so the
    /// critical section does no hashing), and the equal-digest early return also happens under the lock. Two
    /// concurrent misses of one instance (two chains, or open plus a request) are therefore serialized: the
    /// second rebuild always sees the first's patterns, and no store can overwrite a newer automaton with an
    /// older one. Readers (`text`, `text_tail`, `scrub::fail_text`) never take the lock: one `ArcSwap::load` of
    /// the current `Snap` (round 16: `text_tail` included). `forget` follows the same rule.
    /// C-SCRUB-RACE (§14) pins it. Round 19: custody publishes a resolved value only after this call returns
    /// (§12.2 step 5, register-then-publish); `register` itself adds no lock and no wait for it. C-SCRUB-HIT's
    /// publish-order arm pins the order.
    pub fn register(&self, slot: u32, values: &[&[u8]]) {
        let digest = digest(values);
        let mut state = self.lock();
        state.retire();
        if state.slots.get(&slot).is_some_and(|s| s.digest == digest) {
            return;
        }
        let mut current: Vec<Arc<Needle>> = Vec::new();
        for value in values {
            for needle in needles(value) {
                if !current.iter().any(|have| same(have, &needle)) {
                    current.push(Arc::new(needle));
                }
            }
        }
        match state.slots.get_mut(&slot) {
            Some(entry) => {
                entry.previous = core::mem::replace(&mut entry.current, current);
                entry.digest = digest;
            }
            None => {
                state.slots.insert(
                    slot,
                    Slot {
                        digest,
                        current,
                        previous: Vec::new(),
                    },
                );
            }
        }
        self.publish(&mut state);
    }

    /// Drops a slot's patterns, both generations (unbind, reconfigure removed the handle). Same lock rule as `register`.
    pub fn forget(&self, slot: u32) {
        let mut state = self.lock();
        state.retire();
        if state.slots.remove(&slot).is_some() {
            self.publish(&mut state);
        }
    }

    /// Round 17: frees retired snapshots no reader holds (`strong_count == 1`), if `state` is free
    /// (`try_lock`; returns at once otherwise). Called only by the loader's watchdog thread each scan tick.
    pub fn reclaim(&self) {
        let mut state = match self.state.try_lock() {
            Ok(state) => state,
            Err(TryLockError::Poisoned(poisoned)) => poisoned.into_inner(),
            Err(TryLockError::WouldBlock) => return,
        };
        state.retire();
    }

    /// Rebuilds the automaton from the whole map and swaps it in, under `state`; the replaced snapshot is
    /// retired, never dropped here (a reader may still hold it).
    fn publish(&self, state: &mut ScrubState) {
        state.version = state.version.wrapping_add(1);
        let mut all: Vec<Arc<Needle>> = Vec::new();
        for slot in state.slots.values() {
            all.extend(slot.current.iter().chain(&slot.previous).cloned());
        }
        let ac = if all.is_empty() {
            None
        } else {
            AhoCorasick::builder()
                .match_kind(MatchKind::LeftmostLongest)
                .build(all.iter().map(|needle| &needle[..]))
                .ok()
        };
        let old = self.live.swap(Arc::new(Snap {
            ac,
            needles: all.into_boxed_slice(),
        }));
        state.retired.push(old);
    }

    /// Every match -> `***`; then URL userinfo (`scheme://user:pass@` -> `scheme://***@`), credential-named
    /// query parameters (`token, access_token, refresh_token, id_token, key, api_key, apikey, sig, signature,
    /// password, secret, client_secret, code` -> `=***`) and `Authorization:`/`Proxy-Authorization:` values.
    /// Borrowed when nothing matched (no allocation on the common path).
    pub fn text<'t>(&self, text: &'t str) -> Cow<'t, str> {
        scrubbed(&self.live.load(), text)
    }

    /// A scrub set from explicit needles, not bound to an instance (config_validate's per-credential redaction).
    pub fn from_needles<'n>(needles: impl IntoIterator<Item = &'n [u8]>) -> Self {
        let scrub = Scrub::new();
        let mut current: Vec<Arc<Needle>> = Vec::new();
        for needle in needles {
            if needle.len() >= MIN_NEEDLE && !current.iter().any(|have| same(have, needle)) {
                current.push(Arc::new(Needle::copied(needle)));
            }
        }
        if !current.is_empty() {
            let mut state = scrub.lock();
            state.slots.insert(
                u32::MAX,
                Slot {
                    digest: [0; 32],
                    current,
                    previous: Vec::new(),
                },
            );
            scrub.publish(&mut state);
        }
        scrub
    }

    /// Round 15 (I14, C-SCRUB-CUT): `text` first; then, if the result ends in a run of ≥ `MIN_NEEDLE` bytes that
    /// is a proper prefix of any registered needle (a secret or encoding the plugin's wire cut split), that run
    /// becomes `***`. Over-masks a benign tail that happens to match a needle prefix; never under-masks one.
    /// **Round 16 (I5, speed):** lock-free: both passes read the one `Snap` loaded once (the tail walk goes over
    /// `Snap::needles`, never `state`), so a `register` rebuild never blocks it and it never queues behind one;
    /// and the tail walk (O(total needle bytes)) runs **only when `text.len() ≥ FAIL_TEXT_WIRE_MAX − 3`**, i.e.
    /// when the text can be the shim's char-boundary cut (§4.1, §7.8 `bb_fail`: a cut lands in
    /// `[FAIL_TEXT_WIRE_MAX − 3, FAIL_TEXT_WIRE_MAX]`). Only a cut text can end in a split needle: a plugin passes
    /// upstream text whole and never slices it (§4.1). Every shorter text costs exactly `text`. An auth `verify`
    /// REFUSED on every request of a credential-stuffing flood is therefore one load plus one automaton scan of
    /// its (short) text on the worker, with no lock (B-SYNC's REFUSED arm).
    pub fn text_tail<'t>(&self, text: &'t str) -> Cow<'t, str> {
        let snap = self.live.load();
        let out = scrubbed(&snap, text);
        if text.len() < FAIL_TEXT_WIRE_MAX - 3 {
            return out;
        }
        match tail_run(&snap.needles, &out) {
            None => out,
            Some(start) => {
                let mut owned = out.into_owned();
                owned.truncate(start);
                owned.push_str(MASK);
                Cow::Owned(owned)
            }
        }
    }
}

/// One pattern a secret value is matched as. It stands where the IF writes `zeroize::Zeroizing<Vec<u8>>`, which
/// core bans (LR-094); the `busbar_contract::secure` types it points to sit above this crate (IF §16.23), so the
/// pattern keeps their rule itself: allocated once at its exact length, never grown, wiped before it is freed.
/// `Debug` prints the length only.
pub struct Needle(Box<[u8]>);

impl Needle {
    fn zeroed(len: usize) -> Self {
        Needle(vec![0; len].into_boxed_slice())
    }

    fn copied(bytes: &[u8]) -> Self {
        Needle(Box::from(bytes))
    }
}

impl Deref for Needle {
    type Target = [u8];
    fn deref(&self) -> &[u8] {
        &self.0
    }
}

impl Drop for Needle {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl fmt::Debug for Needle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Needle({} bytes)", self.0.len())
    }
}

fn same(a: &[u8], b: &[u8]) -> bool {
    a == b
}

/// SHA-256 over the values, each length-prefixed (u64 LE), in order.
fn digest(values: &[&[u8]]) -> [u8; 32] {
    let mut hash = busbar_crypto::Sha256::new();
    for value in values {
        hash.update(&(value.len() as u64).to_le_bytes());
        hash.update(value);
    }
    hash.finish()
}

// The free functions every core redactor uses (round 6; the one implementation).
// The IF writes these inside `pub mod scrub { .. }`; this file *is* the `scrub` module, so they sit at its top
// level and are reached as `abi::host::scrub::{needles, mask_url, strip_userinfo, fail_text}`, the paths
// §12.16 names.

/// Every pattern one secret value is matched as, each ≥ MIN_NEEDLE (4) bytes, longest first, deduplicated:
/// the raw value, its trimmed form, the part after the first `:` of the trimmed form (`user:secret`), and for
/// each of raw and trimmed: standard and URL-safe base64, padded and unpadded (`base64`), percent-encoding
/// (`percent-encoding`, NON_ALPHANUMERIC) and lowercase hex (`hex`). Callers with a structured credential (a
/// service-account JSON `private_key`) call it once more on that inner value. A source shorter than
/// `MIN_NEEDLE` yields nothing, its encodings included. Each pattern is written once into its own exact-size
/// buffer, so no unwiped intermediate copy of the secret is left behind.
pub fn needles(value: &[u8]) -> Vec<Needle> {
    let trimmed = value.trim_ascii();
    let after_colon = trimmed
        .iter()
        .position(|&b| b == b':')
        .map(|colon| &trimmed[colon + 1..]);
    let mut out: Vec<Needle> = Vec::new();
    let mut add = |needle: Needle| {
        if needle.len() >= MIN_NEEDLE && !out.iter().any(|have| same(have, &needle)) {
            out.push(needle);
        }
    };
    for source in [Some(value), Some(trimmed), after_colon]
        .into_iter()
        .flatten()
    {
        if source.len() >= MIN_NEEDLE {
            add(Needle::copied(source));
        }
    }
    for source in [value, trimmed] {
        if source.len() < MIN_NEEDLE {
            continue;
        }
        for (engine, padded) in [
            (&STANDARD, true),
            (&STANDARD_NO_PAD, false),
            (&URL_SAFE, true),
            (&URL_SAFE_NO_PAD, false),
        ] {
            let Some(len) = base64::encoded_len(source.len(), padded) else {
                continue;
            };
            let mut needle = Needle::zeroed(len);
            if engine.encode_slice(source, &mut needle.0).is_ok() {
                add(needle);
            }
        }
        let len: usize = percent_encode(source, NON_ALPHANUMERIC).map(str::len).sum();
        let mut needle = Needle::zeroed(len);
        let mut at = 0;
        for piece in percent_encode(source, NON_ALPHANUMERIC) {
            needle.0[at..at + piece.len()].copy_from_slice(piece.as_bytes());
            at += piece.len();
        }
        add(needle);
        let mut needle = Needle::zeroed(source.len() * 2);
        if hex::encode_to_slice(source, &mut needle.0).is_ok() {
            add(needle);
        }
    }
    out.sort_by_key(|needle| core::cmp::Reverse(needle.len()));
    out
}

pub const MIN_NEEDLE: usize = 4;

/// `scheme://user:pass@host` -> `scheme://***@host`; borrowed when there is no userinfo.
pub fn mask_url(url: &str) -> Cow<'_, str> {
    mask_userinfo(url).map_or(Cow::Borrowed(url), Cow::Owned)
}

/// `scheme://user:pass@host` -> `scheme://host` (for building a dial URL, not for display).
pub fn strip_userinfo(url: &str) -> Cow<'_, str> {
    let Some(sep) = url.find("://") else {
        return Cow::Borrowed(url);
    };
    let rest = &url[sep + 3..];
    let end = rest.find(['/', '?', '#', '\\']).unwrap_or(rest.len());
    match rest[..end].rfind('@') {
        Some(at) => {
            let mut out = String::with_capacity(url.len());
            out.push_str(&url[..sep + 3]);
            out.push_str(&rest[at + 1..]);
            Cow::Owned(out)
        }
        None => Cow::Borrowed(url),
    }
}

/// Round 15: the most plugin FAIL text core shows, logs or audits.
pub const FAIL_TEXT_SHOWN: usize = 512;

/// Round 15 (I14): the one way core turns `Answer::fail` text into shown text, in this order and no other:
/// `scrub.text_tail(text)` (whole needles, URL userinfo, credential parameters, then a trailing partial
/// needle when the text is wire-cut length), then cut to `FAIL_TEXT_SHOWN` bytes at a char boundary. Round 16:
/// lock-free, as `text_tail`. Every adapter (§11.3), the refusal map
/// (§12.15) and the boot-migration report (§12.10) call it; C-SCRUB-CUT pins the order. The general rule it
/// applies, for every plugin text core shortens (FAIL, hook MESSAGE, FACT_TEXT tails): **scrub first, cut
/// after**, never the reverse.
pub fn fail_text<'t>(scrub: &Scrub, text: &'t str) -> Cow<'t, str> {
    let shown = scrub.text_tail(text);
    if shown.len() <= FAIL_TEXT_SHOWN {
        return shown;
    }
    let cut = floor_boundary(&shown, FAIL_TEXT_SHOWN);
    match shown {
        Cow::Borrowed(text) => Cow::Borrowed(&text[..cut]),
        Cow::Owned(mut text) => {
            text.truncate(cut);
            Cow::Owned(text)
        }
    }
}

/// The whole-text passes, in order: needles, then URL userinfo, credential parameters and Authorization values.
fn scrubbed<'t>(snap: &Snap, text: &'t str) -> Cow<'t, str> {
    let mut out = Cow::Borrowed(text);
    if !snap.needles.is_empty() {
        let Some(ac) = &snap.ac else {
            return Cow::Borrowed(MASK);
        };
        if let Some(masked) = mask_needles(ac, text) {
            out = Cow::Owned(masked);
        }
    }
    for pass in [
        mask_userinfo as fn(&str) -> Option<String>,
        mask_params,
        mask_authorization,
    ] {
        if let Some(masked) = pass(&out) {
            out = Cow::Owned(masked);
        }
    }
    out
}

/// Every needle match -> `***`, widened to char boundaries (a needle need not end on one). None when nothing
/// matched.
fn mask_needles(ac: &AhoCorasick, text: &str) -> Option<String> {
    let mut matches = ac.find_iter(text).peekable();
    matches.peek()?;
    let mut out = String::with_capacity(text.len());
    let mut copied = 0;
    for found in matches {
        let end = ceil_boundary(text, found.end());
        if end <= copied {
            continue;
        }
        let start = floor_boundary(text, found.start()).max(copied);
        out.push_str(&text[copied..start]);
        out.push_str(MASK);
        copied = end;
    }
    out.push_str(&text[copied..]);
    Some(out)
}

/// `scheme://user:pass@host` -> `scheme://***@host` for every URL in `text`. The authority ends at the first
/// `/`, `?`, `#` or `\` (as today's kernel-egress and connector helpers read it), whitespace or quote; the userinfo
/// is everything before its last `@`.
fn mask_userinfo(text: &str) -> Option<String> {
    let mut out: Option<String> = None;
    let mut copied = 0;
    let mut from = 0;
    while let Some(found) = text[from..].find("://") {
        let start = from + found + 3;
        let rest = &text[start..];
        let end = start
            + rest
                .find(|c: char| {
                    matches!(c, '/' | '?' | '#' | '\\' | '"' | '\'' | '<' | '>')
                        || c.is_whitespace()
                })
                .unwrap_or(rest.len());
        if let Some(at) = text[start..end].rfind('@').map(|at| start + at)
            && &text[start..at] != MASK
        {
            let masked = out.get_or_insert_with(|| String::with_capacity(text.len()));
            masked.push_str(&text[copied..start]);
            masked.push_str(MASK);
            copied = at;
        }
        from = end;
    }
    out.map(|mut masked| {
        masked.push_str(&text[copied..]);
        masked
    })
}

/// The query parameter names whose values are credentials, matched ASCII case-insensitively.
const CREDENTIAL_PARAMS: [&str; 13] = [
    "token",
    "access_token",
    "refresh_token",
    "id_token",
    "key",
    "api_key",
    "apikey",
    "sig",
    "signature",
    "password",
    "secret",
    "client_secret",
    "code",
];

/// `?name=value`, `&name=value` and `;name=value` with a credential name -> `name=***`. The value ends at `&`, `;`,
/// `#`, whitespace or a quote.
fn mask_params(text: &str) -> Option<String> {
    let bytes = text.as_bytes();
    let mut out: Option<String> = None;
    let mut copied = 0;
    let mut from = 0;
    while let Some(found) = bytes[from..]
        .iter()
        .position(|&b| matches!(b, b'?' | b'&' | b';'))
    {
        let name_start = from + found + 1;
        from = name_start;
        let Some(name_len) = bytes[name_start..]
            .iter()
            .position(|&b| !(b.is_ascii_alphanumeric() || b == b'_' || b == b'-'))
        else {
            break;
        };
        let eq = name_start + name_len;
        let name = &text[name_start..eq];
        if bytes[eq] != b'='
            || !CREDENTIAL_PARAMS
                .iter()
                .any(|p| p.eq_ignore_ascii_case(name))
        {
            continue;
        }
        let value = eq + 1;
        let end = value
            + bytes[value..]
                .iter()
                .position(|&b| {
                    matches!(b, b'&' | b';' | b'#' | b'"' | b'\'' | b'<' | b'>')
                        || b.is_ascii_whitespace()
                })
                .unwrap_or(bytes.len() - value);
        from = end;
        if end == value || &text[value..end] == MASK {
            continue;
        }
        let masked = out.get_or_insert_with(|| String::with_capacity(text.len()));
        masked.push_str(&text[copied..value]);
        masked.push_str(MASK);
        copied = end;
    }
    out.map(|mut masked| {
        masked.push_str(&text[copied..]);
        masked
    })
}

/// `Authorization: <value>` and `Proxy-Authorization: <value>` (any case) -> `...: ***`, the value running to the
/// end of its line.
fn mask_authorization(text: &str) -> Option<String> {
    const NAME: &[u8] = b"authorization:";
    let bytes = text.as_bytes();
    let mut out: Option<String> = None;
    let mut copied = 0;
    let mut at = 0;
    while at + NAME.len() <= bytes.len() {
        if !bytes[at..at + NAME.len()].eq_ignore_ascii_case(NAME) {
            at += 1;
            continue;
        }
        let mut value = at + NAME.len();
        while value < bytes.len() && matches!(bytes[value], b' ' | b'\t') {
            value += 1;
        }
        let end = value
            + bytes[value..]
                .iter()
                .position(|&b| matches!(b, b'\r' | b'\n'))
                .unwrap_or(bytes.len() - value);
        if end > value && &text[value..end] != MASK {
            let masked = out.get_or_insert_with(|| String::with_capacity(text.len()));
            masked.push_str(&text[copied..value]);
            masked.push_str(MASK);
            copied = end;
        }
        at = end.max(at + 1);
    }
    out.map(|mut masked| {
        masked.push_str(&text[copied..]);
        masked
    })
}

/// The start of the longest trailing run of `out` (≥ `MIN_NEEDLE` bytes) that is a proper prefix of a needle,
/// moved back to a char boundary.
fn tail_run(needles: &[Arc<Needle>], out: &str) -> Option<usize> {
    let bytes = out.as_bytes();
    let mut best = 0;
    for needle in needles {
        let longest = (needle.len() - 1).min(bytes.len());
        for len in (MIN_NEEDLE.max(best + 1)..=longest).rev() {
            if bytes[bytes.len() - len..] == needle[..len] {
                best = len;
                break;
            }
        }
    }
    (best >= MIN_NEEDLE).then(|| floor_boundary(out, bytes.len() - best))
}

fn floor_boundary(text: &str, mut at: usize) -> usize {
    while !text.is_char_boundary(at) {
        at -= 1;
    }
    at
}

fn ceil_boundary(text: &str, mut at: usize) -> usize {
    while !text.is_char_boundary(at) {
        at += 1;
    }
    at
}

#[cfg(test)]
impl Drop for Snap {
    fn drop(&mut self) {
        tests::snap_dropped();
    }
}

#[cfg(test)]
mod tests {
    //! The H0 arms of C-SCRUB, C-SCRUB-HIT, C-SCRUB-RACE, C-SCRUB-ONE and C-SCRUB-CUT (IF §12.16, §14), over
    //! the scrub set alone. The encodings are literals, so a wrong encoder cannot agree with itself.

    use super::*;
    use crate::fail::FAIL_TEXT_WIRE_MAX;
    use std::sync::{Arc, Barrier};

    const SECRET: &str = "s3cr3t-T0ken!42?";
    /// SECRET's standard base64 (padded, unpadded), percent (NON_ALPHANUMERIC) and lowercase hex forms.
    const ENCODED: [&str; 4] = [
        "czNjcjN0LVQwa2VuITQyPw==",
        "czNjcjN0LVQwa2VuITQyPw",
        "s3cr3t%2DT0ken%2142%3F",
        "7333637233742d54306b656e2134323f",
    ];
    /// A value whose base64 holds a `+`: standard `UGE1NXcwcmR+eA==`, URL-safe `UGE1NXcwcmR-eA`.
    const PLUS: &str = "Pa55w0rd~x";

    /// Whether any run of `MIN_NEEDLE` bytes of `secret` survives in `out`.
    fn leaks(out: &str, secret: &str) -> bool {
        secret
            .as_bytes()
            .windows(MIN_NEEDLE)
            .any(|w| out.as_bytes().windows(MIN_NEEDLE).any(|o| o == w))
    }

    #[test]
    fn c_scrub_masks_a_value_and_every_encoding() {
        let s = Scrub::new();
        s.register(1, &[SECRET.as_bytes()]);
        let mut text = format!("raw {SECRET} trimmed-free");
        for form in ENCODED {
            text.push_str(" | ");
            text.push_str(form);
        }
        let out = s.text(&text);
        assert!(!leaks(&out, SECRET), "{out}");
        for form in ENCODED {
            assert!(!out.contains(form), "{form} survived: {out}");
        }
        assert_eq!(out.matches("***").count(), 5, "{out}");

        let p = Scrub::new();
        p.register(7, &[PLUS.as_bytes()]);
        let out = p.text("std UGE1NXcwcmR+eA== url UGE1NXcwcmR-eA== bare UGE1NXcwcmR-eA end");
        assert_eq!(out, "std *** url *** bare *** end");
    }

    #[test]
    fn c_scrub_masks_the_secret_after_a_colon_and_a_trimmed_value() {
        let s = Scrub::new();
        s.register(3, &[b"  alice:Pa55w0rd~x\n"]);
        let out = s.text("login alice:Pa55w0rd~x then Pa55w0rd~x alone");
        assert!(!out.contains("Pa55w0rd~x"), "{out}");
        assert!(!leaks(&out, PLUS), "{out}");
    }

    #[test]
    fn c_scrub_masks_url_userinfo_credential_params_and_authorization() {
        let s = Scrub::new();
        let out = s.text(
            "GET https://alice:pw@example.com/x?token=abc&b=1&API_KEY=k1;sig=zz#f code=9 \
             Authorization: Bearer xyz\nProxy-Authorization: Basic qqq\r\nnext",
        );
        assert_eq!(
            out,
            "GET https://***@example.com/x?token=***&b=1&API_KEY=***;sig=***#f code=9 \
             Authorization: ***\nProxy-Authorization: ***\r\nnext"
        );
    }

    #[test]
    fn c_scrub_nothing_matched_borrows() {
        let s = Scrub::new();
        s.register(1, &[SECRET.as_bytes()]);
        assert!(matches!(
            s.text("a plain line with https://example.com/?b=1"),
            Cow::Borrowed(_)
        ));
        assert!(matches!(s.text_tail("short"), Cow::Borrowed(_)));
        assert!(matches!(
            mask_url("https://example.com/a@b"),
            Cow::Borrowed(_)
        ));
        assert!(matches!(
            strip_userinfo("https://example.com"),
            Cow::Borrowed(_)
        ));
    }

    #[test]
    fn c_scrub_short_values_are_not_needles() {
        let s = Scrub::new();
        s.register(1, &[b"abc"]);
        assert_eq!(s.text("abc abcd"), "abc abcd");
    }

    #[test]
    fn c_scrub_template_registers_every_value() {
        let s = Scrub::new();
        s.register(9, &[b"Bearer abcdef12", b"abcdef12"]);
        let out = s.text("token abcdef12 rejected; base64 YWJjZGVmMTI=; Bearer abcdef12");
        assert_eq!(out, "token *** rejected; base64 ***; ***");
    }

    #[test]
    fn c_scrub_hit_rotation_keeps_two_generations() {
        let s = Scrub::new();
        s.register(1, &[b"value-one-1"]);
        s.register(1, &[b"value-one-1"]);
        s.register(1, &[b"value-two-2"]);
        let both = "v1 value-one-1 v2 value-two-2";
        assert_eq!(s.text(both), "v1 *** v2 ***");
        s.register(1, &[b"value-three-3"]);
        assert_eq!(
            s.text("v1 value-one-1 v2 value-two-2 v3 value-three-3"),
            "v1 value-one-1 v2 *** v3 ***"
        );
    }

    #[test]
    fn c_scrub_forget_drops_both_generations() {
        let s = Scrub::new();
        s.register(1, &[b"first-value"]);
        s.register(1, &[b"second-value"]);
        s.register(2, &[b"other-slot"]);
        s.forget(1);
        assert_eq!(
            s.text("first-value second-value other-slot"),
            "first-value second-value ***"
        );
        s.reclaim();
    }

    #[test]
    fn c_scrub_race_both_slots_masked_after_every_round() {
        const ROUNDS: usize = 2_000;
        let s = Arc::new(Scrub::new());
        let barrier = Arc::new(Barrier::new(2));
        let run = |slot: u32| {
            let (s, barrier) = (Arc::clone(&s), Arc::clone(&barrier));
            std::thread::spawn(move || {
                // Misses are counted, not asserted here: a panic on one side would park the other at the barrier.
                let mut misses = 0_usize;
                let last = format!("slot1-round{:05} slot2-round{:05}", ROUNDS - 1, ROUNDS - 1);
                for round in 0..ROUNDS {
                    let mine = format!("slot{slot}-round{round:05}");
                    s.register(slot, &[mine.as_bytes()]);
                    barrier.wait();
                    let other = format!("slot{}-round{round:05}", 3 - slot);
                    let text = format!("{mine} and {other}");
                    misses += usize::from(s.text(&text) != "*** and ***");
                    barrier.wait();
                }
                // The forget race: both slots dropped at once leave nothing masked.
                s.forget(slot);
                barrier.wait();
                misses += usize::from(s.text(&last) != last);
                misses
            })
        };
        let (a, b) = (run(1), run(2));
        assert_eq!(a.join().expect("slot 1 thread"), 0);
        assert_eq!(b.join().expect("slot 2 thread"), 0);
    }

    #[test]
    fn c_scrub_one_url_helpers() {
        assert_eq!(mask_url("https://u:p@h:1/x?y"), "https://***@h:1/x?y");
        assert_eq!(mask_url("https://tok@h"), "https://***@h");
        assert_eq!(mask_url("https://u:p@w@h/a@b"), "https://***@h/a@b");
        assert_eq!(mask_url("postgres://u:p@h\\x@y"), "postgres://***@h\\x@y");
        assert_eq!(strip_userinfo("https://u:p@h:1/x"), "https://h:1/x");
        assert_eq!(strip_userinfo("https://u@w@h/a@b"), "https://h/a@b");
        assert_eq!(strip_userinfo("no scheme u:p@h"), "no scheme u:p@h");
        let s = Scrub::new();
        assert_eq!(
            s.text("dial https://u:p@h:1/x now"),
            "dial https://***@h:1/x now"
        );
    }

    #[test]
    fn c_scrub_from_needles_masks_what_it_is_given() {
        let s = Scrub::from_needles([b"hunter22".as_slice(), b"abc".as_slice()]);
        assert_eq!(s.text("pw hunter22 abc"), "pw *** abc");
    }

    #[test]
    fn c_scrub_cut_scrub_first_then_cut() {
        let secret = "S3CRETVALUE-0123456789-abcdefghijklmnopq";
        assert_eq!(secret.len(), 40);
        let s = Scrub::new();
        s.register(4, &[secret.as_bytes()]);

        // A secret at bytes 500..540: scrubbed whole, then the cut.
        let text = format!("{}{secret}{}", "a".repeat(500), "b".repeat(60));
        let shown = fail_text(&s, &text);
        assert!(shown.len() <= FAIL_TEXT_SHOWN, "{}", shown.len());
        assert!(!leaks(&shown, secret), "{shown}");

        // A secret starting at byte 3,060 and cut by the wire bound at 3,072: the partial tail is masked.
        let cut = format!(
            "{}{}",
            "c".repeat(3_060),
            &secret[..FAIL_TEXT_WIRE_MAX - 3_060]
        );
        assert_eq!(cut.len(), FAIL_TEXT_WIRE_MAX);
        let tail = s.text_tail(&cut);
        assert!(tail.ends_with("***"), "{}", &tail[tail.len() - 20..]);
        assert!(!leaks(&tail, secret));

        // A text shorter than the cut length never pays the tail walk: an ending that is a needle prefix stays.
        assert_eq!(s.text_tail("ends S3CRETVAL"), "ends S3CRETVAL");

        // A benign 600-byte text is shown cut to 512 bytes, at a char boundary.
        let benign = "z".repeat(600);
        assert_eq!(fail_text(&s, &benign), benign[..FAIL_TEXT_SHOWN]);
        let wide = format!("{}é{}", "y".repeat(511), "y".repeat(50));
        let shown = fail_text(&s, &wide);
        assert_eq!(shown.len(), 511);
    }

    #[test]
    fn c_scrub_needles_are_every_form_longest_first() {
        let found = needles(b"  alice:Pa55w0rd~x\n");
        let got: Vec<&[u8]> = found.iter().map(|n| &n[..]).collect();
        for want in [
            b"  alice:Pa55w0rd~x\n".as_slice(),
            b"alice:Pa55w0rd~x",
            b"Pa55w0rd~x",
            b"YWxpY2U6UGE1NXcwcmR+eA==",
            b"YWxpY2U6UGE1NXcwcmR+eA",
            b"YWxpY2U6UGE1NXcwcmR-eA==",
            b"YWxpY2U6UGE1NXcwcmR-eA",
            b"alice%3APa55w0rd%7Ex",
            b"616c6963653a50613535773072647e78",
        ] {
            assert!(
                got.contains(&want),
                "{:?} missing",
                String::from_utf8_lossy(want)
            );
        }
        assert!(
            got.windows(2).all(|w| w[0].len() >= w[1].len()),
            "longest first"
        );
        assert!(got.iter().all(|n| n.len() >= MIN_NEEDLE));
        for (i, n) in got.iter().enumerate() {
            assert!(!got[i + 1..].contains(n), "duplicate");
        }
        assert!(needles(b"abc").is_empty());
        assert_eq!(
            format!("{:?}", found[0]),
            format!("Needle({} bytes)", found[0].len())
        );
    }

    #[test]
    fn c_scrub_hit_an_equal_value_does_not_rebuild() {
        let s = Scrub::new();
        s.register(1, &[b"value-one-1"]);
        let built = s.lock().version;
        for _ in 0..10_000 {
            s.register(1, &[b"value-one-1"]);
        }
        assert_eq!(s.lock().version, built);
        s.register(1, &[b"value-two-2"]);
        assert_eq!(s.lock().version, built + 1);
        assert_eq!(s.lock().slots.len(), 1);
        // A template with the same rendered value but a different fill is a change.
        s.register(1, &[b"value-two-2", b"fill-1"]);
        assert_eq!(s.lock().version, built + 2);
    }

    std::thread_local! {
        static READER: core::cell::Cell<bool> = const { core::cell::Cell::new(false) };
    }
    static READER_FREES: core::sync::atomic::AtomicUsize = core::sync::atomic::AtomicUsize::new(0);

    /// `Drop for Snap` in the test build: counts a snapshot freed on a thread marked as a reader.
    pub(super) fn snap_dropped() {
        if READER.with(core::cell::Cell::get) {
            READER_FREES.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
        }
    }

    #[test]
    fn c_scrub_retire_frees_snapshots_only_on_writer_threads() {
        use core::sync::atomic::{AtomicBool, Ordering};
        let s = Arc::new(Scrub::new());
        for slot in 0..64 {
            s.register(slot, &[format!("binding-{slot:03}-value").as_bytes()]);
        }
        let stop = Arc::new(AtomicBool::new(false));
        let readers: Vec<_> = (0..16)
            .map(|_| {
                let (s, stop) = (Arc::clone(&s), Arc::clone(&stop));
                std::thread::spawn(move || {
                    READER.with(|r| r.set(true));
                    let mut misses = 0_usize;
                    while !stop.load(Ordering::Relaxed) {
                        misses += usize::from(fail_text(&s, "bad binding-007-value") != "bad ***");
                        misses += usize::from(s.text("x binding-063-value") != "x ***");
                    }
                    misses
                })
            })
            .collect();
        let writer = {
            let s = Arc::clone(&s);
            std::thread::spawn(move || {
                for round in 0..2_000 {
                    s.register(1_000, &[format!("rotating-{round:05}").as_bytes()]);
                }
            })
        };
        while !writer.is_finished() {
            s.reclaim();
            std::thread::yield_now();
        }
        writer.join().expect("writer");
        stop.store(true, Ordering::Relaxed);
        for reader in readers {
            assert_eq!(reader.join().expect("reader"), 0);
        }
        s.reclaim();
        s.reclaim();
        assert!(s.lock().retired.is_empty());
        assert_eq!(READER_FREES.load(Ordering::Relaxed), 0);
    }
}
