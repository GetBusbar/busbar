// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE INSTANCE HANDLE (BUSBAR-1.6.0.md Part 2 #74, the untrusted-ABI half: "the handle a plugin
//! holds is kernel-MAC'd ... the kernel verifies it on every ABI call, so a plugin cannot forge,
//! reuse across flows, or replay a stale handle").
//!
//! A plugin is handed one [`HostCtx`] per instance and hands it back on every host call: `wake`,
//! every host service, every connector and I/O slot. It used to be the address of the instance's
//! leaked [`InstanceWake`], and every one of those entries dereferenced whatever pointer came back.
//! A plugin that passed another value got the host to read through it: not a refused handle,
//! undefined behaviour inside the host.
//!
//! Now no host address crosses. The handle is `tag << 24 | id`: `id` indexes the host's table of
//! instances ([`HANDLE_ID_BITS`] bits, `0` = none) and `tag` is the high [`HANDLE_TAG_BITS`] bits of
//! a SipHash-2-4 over `(domain, id)` under a 128-bit key drawn from the OS random source at the
//! first bind, held in host memory only and never written anywhere. [`resolve`] recomputes the tag
//! and compares it in constant time BEFORE the table is read; a handle the host did not mint names
//! no instance, is counted ([`forged`]), and the entry answers as it answers no context. Made inside
//! a crossing, it QUARANTINES the instance making that crossing (N = 1): faulted, never called
//! again, so no plugin gets a second guess at a tag; inside a crossing a context must name the
//! crossing's own instance. Made outside any crossing it names no one to quarantine, so it counts
//! against a process-wide LATCH: at [`LATCH_AT`] such forgeries nothing resolves outside a
//! crossing again. A handle whose instance was quarantined, faulted, closed or let go is REVOKED:
//! its tag still verifies, and it names nothing.
//!
//! Width: the handle is the 8 bytes the pointer was, so no struct that carries it moves (the layout
//! golden changes one field name). A guess at a 40-bit tag is right once in about 10^12 tries, each
//! one counted. The key is readable to a native plugin that ignores the ABI and reads process
//! memory; that is the channel-2 residual BUSBAR-1.6.0.md #75 accepts, not a hole this closes.

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{OnceLock, RwLock};

use busbar_contract::abi::mechanism::ticket::HostCtx;
use busbar_contract::conn::InstanceId;

use super::load::LoadError;
use super::ticket::InstanceWake;

/// The bits of a handle that index the instance table.
pub const HANDLE_ID_BITS: u32 = 24;
/// The bits of a handle that carry the tag.
pub const HANDLE_TAG_BITS: u32 = 64 - HANDLE_ID_BITS;

const ID_MASK: u64 = (1 << HANDLE_ID_BITS) - 1;

/// Domain separation: a tag minted for an instance handle is never a tag for anything else the
/// key signs.
const DOMAIN_INSTANCE: u64 = u64::from_le_bytes(*b"bb.inst1");

/// THE LATCH (#74): unattributed forgeries (made outside any crossing, so no instance can be
/// quarantined for them) the process tolerates. At this many, every resolve made outside a crossing
/// is refused for the rest of the process: off-crossing guessing is bounded at K tries in all.
pub const LATCH_AT: u64 = 16;

/// Every handle the host was handed back and did not mint.
static FORGED: AtomicU64 = AtomicU64::new(0);

/// The process's off-crossing latch ([`LATCH_AT`]).
static LATCH: Latch = Latch::new();

/// Every instance the host has minted a handle for, by `id - 1`. Instances are leaked, so an entry
/// never dangles.
static INSTANCES: RwLock<Vec<&'static InstanceWake>> = RwLock::new(Vec::new());

/// The off-crossing latch: unattributed forgeries counted; tripped at [`LATCH_AT`].
pub(crate) struct Latch {
    /// Every forgery judged against this latch, attributed or not: what a test asserts on, so no
    /// test reads the process-wide [`forged`] another test moves.
    forged: AtomicU64,
    unattributed: AtomicU64,
    tripped: AtomicBool,
}

impl Latch {
    pub(crate) const fn new() -> Self {
        Self {
            forged: AtomicU64::new(0),
            unattributed: AtomicU64::new(0),
            tripped: AtomicBool::new(false),
        }
    }

    /// One unattributed forgery; trips the latch at [`LATCH_AT`], with ONE error line.
    fn count(&self) {
        let n = self.unattributed.fetch_add(1, Ordering::AcqRel) + 1;
        if n >= LATCH_AT && !self.tripped.swap(true, Ordering::AcqRel) {
            tracing::error!(
                forgeries = n,
                "plugins handed the host {n} contexts or tickets it did not mint with no instance \
                 to blame; every host call made outside a crossing is refused for the rest of the \
                 process"
            );
        }
    }

    pub(crate) fn tripped(&self) -> bool {
        self.tripped.load(Ordering::Acquire)
    }

    /// Forgeries judged against this latch: the tests' reading (no production path reads a
    /// latch's own count; the process's figure is [`forged`]).
    #[cfg(test)]
    pub(crate) fn forged(&self) -> u64 {
        self.forged.load(Ordering::Acquire)
    }

    /// Unattributed forgeries counted towards the trip: the tests' reading.
    #[cfg(test)]
    pub(crate) fn unattributed(&self) -> u64 {
        self.unattributed.load(Ordering::Acquire)
    }
}

#[cfg(test)]
thread_local! {
    /// THE TEST SEAM: this thread's next key draw finds the OS random source failing.
    pub(crate) static ENTROPY_FAILS: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

/// 16 bytes from `source` as the key; a source that cannot answer is a refusal, never a weaker key.
fn draw(source: impl FnOnce(&mut [u8]) -> Result<(), String>) -> Result<(u64, u64), LoadError> {
    let mut b = [0u8; 16];
    source(&mut b).map_err(LoadError::Entropy)?;
    let (lo, hi) = b.split_at(8);
    Ok((
        u64::from_le_bytes(lo.try_into().unwrap_or_default()),
        u64::from_le_bytes(hi.try_into().unwrap_or_default()),
    ))
}

/// The host's key: 16 bytes from the OS random source, drawn once, at the loader's boot
/// ([`arm`]) and at the latest by the first bind. A source that cannot answer refuses the boot
/// ([`LoadError::Entropy`]): there is no fallback key.
pub(crate) fn key() -> Result<(u64, u64), LoadError> {
    #[cfg(test)]
    if ENTROPY_FAILS.with(std::cell::Cell::get) {
        return draw(|_| Err("the test seam's failing entropy source".to_string()));
    }
    drawn_key()
}

/// The process's one key, drawn on first use; [`key`] is this behind the test seam.
fn drawn_key() -> Result<(u64, u64), LoadError> {
    static KEY: OnceLock<(u64, u64)> = OnceLock::new();
    if let Some(k) = KEY.get() {
        return Ok(*k);
    }
    let k = draw(|b| getrandom::fill(b).map_err(|e| e.to_string()))?;
    Ok(*KEY.get_or_init(|| k))
}

/// THE LOADER'S BOOT: draw the key now, before any plugin binds. A failure is the boot's refusal.
///
/// # Errors
///
/// [`LoadError::Entropy`] when the OS random source cannot answer.
pub fn arm() -> Result<(), LoadError> {
    key().map(|_| ())
}

/// SipHash-2-4 over `words`, each eight little-endian message bytes.
pub(crate) fn siphash24((k0, k1): (u64, u64), words: &[u64]) -> u64 {
    let mut v = [
        k0 ^ 0x736f_6d65_7073_6575,
        k1 ^ 0x646f_7261_6e64_6f6d,
        k0 ^ 0x6c79_6765_6e65_7261,
        k1 ^ 0x7465_6462_7974_6573,
    ];
    let round = |v: &mut [u64; 4]| {
        v[0] = v[0].wrapping_add(v[1]);
        v[1] = v[1].rotate_left(13) ^ v[0];
        v[0] = v[0].rotate_left(32);
        v[2] = v[2].wrapping_add(v[3]);
        v[3] = v[3].rotate_left(16) ^ v[2];
        v[0] = v[0].wrapping_add(v[3]);
        v[3] = v[3].rotate_left(21) ^ v[0];
        v[2] = v[2].wrapping_add(v[1]);
        v[1] = v[1].rotate_left(17) ^ v[2];
        v[2] = v[2].rotate_left(32);
    };
    for &m in words {
        v[3] ^= m;
        round(&mut v);
        round(&mut v);
        v[0] ^= m;
    }
    let last = ((words.len() as u64).wrapping_mul(8) & 0xff) << 56;
    v[3] ^= last;
    round(&mut v);
    round(&mut v);
    v[0] ^= last;
    v[2] ^= 0xff;
    for _ in 0..4 {
        round(&mut v);
    }
    v[0] ^ v[1] ^ v[2] ^ v[3]
}

/// The tag `id`'s handle carries under `key`.
fn tag_of(key: (u64, u64), id: u64) -> u64 {
    siphash24(key, &[DOMAIN_INSTANCE, id]) >> HANDLE_ID_BITS
}

/// Mint the handle for `wake`: the next id, and its tag.
///
/// # Errors
///
/// [`LoadError::Entropy`] when the key cannot be drawn; [`LoadError::HandlesSpent`] once the id
/// space is spent (16.7M instances in one process): the bind is refused rather than a handle
/// reused.
pub(crate) fn mint(wake: &'static InstanceWake) -> Result<HostCtx, LoadError> {
    let key = key()?;
    let mut table = INSTANCES
        .write()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let id = table.len() as u64 + 1;
    if id > ID_MASK {
        return Err(LoadError::HandlesSpent);
    }
    table.push(wake);
    Ok(HostCtx {
        handle: (tag_of(key, id) << HANDLE_ID_BITS) | id,
    })
}

/// THE INSTANCE'S IDENTITY ON THE CONNECTION TABLE: its handle's id. Never `0` (ids are minted from
/// 1), which is the composition root's own identity on the one connector, and never reused in one
/// process. One numbering, so a table's wake names its caller's entry with no second registry (#74).
pub(crate) fn instance_id(ctx: HostCtx) -> InstanceId {
    InstanceId(ctx.handle & ID_MASK)
}

/// The entry the connection table's caller `owner` is ([`instance_id`]), revoked or not; `None` for
/// the root's own identity (`0`) or an id the host never minted. Host-side only: `owner` is the
/// identity the table registered a ticket under, never a plugin's word.
pub(crate) fn supplier_of(owner: InstanceId) -> Option<&'static InstanceWake> {
    let i = usize::try_from(owner.0.checked_sub(1)?).ok()?;
    INSTANCES
        .read()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .get(i)
        .copied()
}

/// THE ONE CHECK: the instance `ctx` names, when the host minted it, it is live, and (inside a
/// crossing) it is the crossing's own.
pub(crate) fn resolve(ctx: HostCtx) -> Option<&'static InstanceWake> {
    resolve_in(ctx, &LATCH, super::plugin::crossing_wake())
}

/// [`resolve`] against `latch`, with `crossing` the entry of the instance crossing on this thread.
///
/// In order: no context is no context (not counted); past a tripped latch, nothing resolves outside
/// a crossing; the tag is recomputed and compared in constant time BEFORE the table is read, and a
/// tag that does not verify, or an id the host never minted, is a FORGERY; a revoked entry (its
/// instance quarantined, faulted, closed or let go) names nothing and is NOT a forgery, its tag
/// being the host's own; and inside a crossing a context naming another instance is a forgery.
pub(crate) fn resolve_in(
    ctx: HostCtx,
    latch: &Latch,
    crossing: Option<&'static InstanceWake>,
) -> Option<&'static InstanceWake> {
    if ctx.handle == 0 {
        return None;
    }
    if crossing.is_none() && latch.tripped() {
        return None;
    }
    let key = key().ok()?;
    let id = ctx.handle & ID_MASK;
    let want = tag_of(key, id);
    let got = ctx.handle >> HANDLE_ID_BITS;
    // Constant time: the whole difference is folded before it is judged.
    if id == 0 || std::hint::black_box(want ^ got) != 0 {
        count_forgery(latch, crossing);
        return None;
    }
    let table = INSTANCES
        .read()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let found = usize::try_from(id - 1)
        .ok()
        .and_then(|i| table.get(i).copied());
    drop(table);
    let Some(entry) = found else {
        count_forgery(latch, crossing);
        return None;
    };
    // Inside a crossing another instance's handle is a forgery, revoked or not: judged BEFORE the
    // revocation, so a stale handle of another instance cannot pass as merely revoked.
    if let Some(own) = crossing {
        if !std::ptr::eq(own, entry) {
            count_forgery(latch, crossing);
            return None;
        }
    }
    if entry.revoked.load(Ordering::Acquire) {
        return None;
    }
    // The latch read again after any counting this or another thread did: once it trips, not one
    // off-crossing resolve passes, so the bound is exactly `LATCH_AT`.
    if crossing.is_none() && latch.tripped() {
        return None;
    }
    // THE REVOKE/USE RACE, memory-safe by construction: an entry revoked by another thread after
    // this load is still a leaked, valid `InstanceWake`; the call it serves finishes against an
    // instance that refuses its next op.
    Some(entry)
}

/// A handle the host did not mint, or another instance's inside a crossing: counted; the instance
/// crossing on this thread, if any, quarantined ([`super::plugin::quarantine_crossing`], one guess,
/// never a second); and with no crossing to blame, counted against `latch`.
fn count_forgery(latch: &Latch, crossing: Option<&'static InstanceWake>) {
    FORGED.fetch_add(1, Ordering::Relaxed);
    latch.forged.fetch_add(1, Ordering::AcqRel);
    if crossing.is_none() || !super::plugin::quarantine_crossing() {
        latch.count();
    }
}

/// A ticket generation the host never minted (#74, the ticket half), judged against `latch`:
/// counted; its SUPPLIER (the instance whose context handed the host the ticket, carried with the
/// wake, never read off the thread it fires on) quarantined; a wake with no supplier (the host's
/// own) counted against `latch`.
pub(crate) fn forged_ticket(supplier: Option<&'static InstanceWake>, latch: &Latch) {
    FORGED.fetch_add(1, Ordering::Relaxed);
    latch.forged.fetch_add(1, Ordering::AcqRel);
    match supplier {
        Some(wake) => super::plugin::quarantine_entry(wake),
        None => latch.count(),
    }
}

/// The process's latch, which every dispatcher judges against but in a test that names its own.
pub(crate) fn process_latch() -> &'static Latch {
    &LATCH
}

// ── THE TICKET GENERATION: a keyed permutation of the slot's counter ───────────────────────────

/// Domain separation from the instance handle's tags.
const DOMAIN_TICKET: u64 = u64::from_le_bytes(*b"bb.tick1");

/// Feistel rounds: six, each a SipHash-2-4 of the round's half under the key and the slot's tweak.
const ROUNDS: u64 = 6;

/// A keyed permutation of `[0, 2^(2*half))` (a balanced Feistel network of `half`-bit halves),
/// forward or `inverse`.
fn feistel(key: (u64, u64), tweak: (u64, u64), half: u32, x: u64, inverse: bool) -> u64 {
    let mask = (1u64 << half) - 1;
    let f = |i: u64, v: u64| siphash24(key, &[DOMAIN_TICKET, tweak.0, tweak.1, i, v]) & mask;
    let (mut l, mut r) = ((x >> half) & mask, x & mask);
    if inverse {
        for i in (0..ROUNDS).rev() {
            (l, r) = (r ^ f(i, l), l);
        }
    } else {
        for i in 0..ROUNDS {
            (l, r) = (r, l ^ f(i, r));
        }
    }
    (l << half) | r
}

/// The permutation of `[1, 2^(2*half))`, `0` excluded by cycle-walking (a walk ends at the first
/// nonzero point of `x`'s cycle, so the map stays a bijection of the nonzero values).
fn nonzero_permutation(
    key: (u64, u64),
    tweak: (u64, u64),
    half: u32,
    x: u64,
    inverse: bool,
) -> u64 {
    let mut y = feistel(key, tweak, half, x, inverse);
    while y == 0 {
        y = feistel(key, tweak, half, y, inverse);
    }
    y
}

/// The key tickets are permuted under: the handle key, held by the dispatcher that drew it. Only
/// [`ticket_key`] makes one, so no ticket is ever minted under a key that was not drawn.
#[derive(Clone, Copy)]
pub(crate) struct TicketKey((u64, u64));

/// THE DISPATCHER'S BOOT: the ticket key, drawn now ([`arm`]'s draw). A failure is the boot's
/// refusal; there is no fallback key.
///
/// # Errors
///
/// [`LoadError::Entropy`] when the OS random source cannot answer.
pub(crate) fn ticket_key() -> Result<TicketKey, LoadError> {
    key().map(TicketKey)
}

/// THE GENERATION of worker `worker`'s slot `idx` at its `count`-th mint (`count` >= 1):
/// `PRP_k(count)`, a bijection of the nonzero 32-bit values for each slot, so uniqueness per slot is
/// exact (as the bare counter it replaces) and no generation tells a plugin the next.
pub(crate) fn ticket_generation(key: TicketKey, worker: u32, idx: u32, count: u32) -> u32 {
    let tweak = (u64::from(worker), u64::from(idx));
    nonzero_permutation(key.0, tweak, 16, u64::from(count), false) as u32
}

/// The count `generation` is the image of, for worker `worker`'s slot `idx`: the inverse of
/// [`ticket_generation`]. A generation the slot minted maps to a count it has reached; one it never
/// minted maps, but for a 1-in-2^32 chance, past it.
pub(crate) fn ticket_count(key: TicketKey, worker: u32, idx: u32, generation: u32) -> u32 {
    if generation == 0 {
        return 0;
    }
    let tweak = (u64::from(worker), u64::from(idx));
    nonzero_permutation(key.0, tweak, 16, u64::from(generation), true) as u32
}

/// Whether the process's off-crossing latch has tripped ([`LATCH_AT`]).
#[must_use]
pub fn latched() -> bool {
    LATCH.tripped()
}

/// How many handles the host was handed back and did not mint, since the process started.
#[must_use]
pub fn forged() -> u64 {
    FORGED.load(Ordering::Relaxed)
}

#[cfg(test)]
#[path = "../tests/handle_tests.rs"]
mod handle_tests;
