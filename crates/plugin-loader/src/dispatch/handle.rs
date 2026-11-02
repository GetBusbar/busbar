// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{OnceLock, RwLock};

use busbar_contract::abi::mechanism::ticket::HostCtx;
use busbar_contract::conn::InstanceId;

use super::load::LoadError;
use super::ticket::InstanceWake;

pub const HANDLE_ID_BITS: u32 = 24;

pub const HANDLE_TAG_BITS: u32 = 64 - HANDLE_ID_BITS;

const ID_MASK: u64 = (1 << HANDLE_ID_BITS) - 1;

const DOMAIN_INSTANCE: u64 = u64::from_le_bytes(*b"bb.inst1");

pub const LATCH_AT: u64 = 16;

static FORGED: AtomicU64 = AtomicU64::new(0);

static LATCH: Latch = Latch::new();

static INSTANCES: RwLock<Vec<&'static InstanceWake>> = RwLock::new(Vec::new());

pub(crate) struct Latch {
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

    #[cfg(test)]
    pub(crate) fn forged(&self) -> u64 {
        self.forged.load(Ordering::Acquire)
    }

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

fn draw(source: impl FnOnce(&mut [u8]) -> Result<(), String>) -> Result<(u64, u64), LoadError> {
    let mut b = [0u8; 16];
    source(&mut b).map_err(LoadError::Entropy)?;
    let (lo, hi) = b.split_at(8);
    Ok((
        u64::from_le_bytes(lo.try_into().unwrap_or_default()),
        u64::from_le_bytes(hi.try_into().unwrap_or_default()),
    ))
}

pub(crate) fn key() -> Result<(u64, u64), LoadError> {
    #[cfg(test)]
    if ENTROPY_FAILS.with(std::cell::Cell::get) {
        return draw(|_| Err("the test seam's failing entropy source".to_string()));
    }
    drawn_key()
}

fn drawn_key() -> Result<(u64, u64), LoadError> {
    static KEY: OnceLock<(u64, u64)> = OnceLock::new();
    if let Some(k) = KEY.get() {
        return Ok(*k);
    }
    let k = draw(|b| getrandom::fill(b).map_err(|e| e.to_string()))?;
    Ok(*KEY.get_or_init(|| k))
}

pub fn arm() -> Result<(), LoadError> {
    key().map(|_| ())
}

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

fn tag_of(key: (u64, u64), id: u64) -> u64 {
    siphash24(key, &[DOMAIN_INSTANCE, id]) >> HANDLE_ID_BITS
}

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

pub(crate) fn instance_id(ctx: HostCtx) -> InstanceId {
    InstanceId(ctx.handle & ID_MASK)
}

pub(crate) fn supplier_of(owner: InstanceId) -> Option<&'static InstanceWake> {
    let i = usize::try_from(owner.0.checked_sub(1)?).ok()?;
    INSTANCES
        .read()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .get(i)
        .copied()
}

pub(crate) fn resolve(ctx: HostCtx) -> Option<&'static InstanceWake> {
    resolve_in(ctx, &LATCH, super::plugin::crossing_wake())
}

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

    if let Some(own) = crossing {
        if !std::ptr::eq(own, entry) {
            count_forgery(latch, crossing);
            return None;
        }
    }
    if entry.revoked.load(Ordering::Acquire) {
        return None;
    }

    if crossing.is_none() && latch.tripped() {
        return None;
    }

    Some(entry)
}

fn count_forgery(latch: &Latch, crossing: Option<&'static InstanceWake>) {
    FORGED.fetch_add(1, Ordering::Relaxed);
    latch.forged.fetch_add(1, Ordering::AcqRel);
    if crossing.is_none() || !super::plugin::quarantine_crossing() {
        latch.count();
    }
}

pub(crate) fn forged_ticket(supplier: Option<&'static InstanceWake>, latch: &Latch) {
    FORGED.fetch_add(1, Ordering::Relaxed);
    latch.forged.fetch_add(1, Ordering::AcqRel);
    match supplier {
        Some(wake) => super::plugin::quarantine_entry(wake),
        None => latch.count(),
    }
}

pub(crate) fn process_latch() -> &'static Latch {
    &LATCH
}

const DOMAIN_TICKET: u64 = u64::from_le_bytes(*b"bb.tick1");

const ROUNDS: u64 = 6;

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

pub(crate) fn ticket_key() -> Result<TicketKey, LoadError> {
    key().map(TicketKey)
}

pub(crate) fn ticket_generation(key: TicketKey, worker: u32, idx: u32, count: u32) -> u32 {
    let tweak = (u64::from(worker), u64::from(idx));
    nonzero_permutation(key.0, tweak, 16, u64::from(count), false) as u32
}

pub(crate) fn ticket_count(key: TicketKey, worker: u32, idx: u32, generation: u32) -> u32 {
    if generation == 0 {
        return 0;
    }
    let tweak = (u64::from(worker), u64::from(idx));
    nonzero_permutation(key.0, tweak, 16, u64::from(generation), true) as u32
}

#[must_use]
pub fn latched() -> bool {
    LATCH.tripped()
}

#[must_use]
pub fn forged() -> u64 {
    FORGED.load(Ordering::Relaxed)
}

#[cfg(test)]
#[path = "../tests/handle_tests.rs"]
mod handle_tests;
