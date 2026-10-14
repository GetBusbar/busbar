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
//! again, so no plugin gets a second guess at a tag.
//!
//! Width: the handle is the 8 bytes the pointer was, so no struct that carries it moves (the layout
//! golden changes one field name). A guess at a 40-bit tag is right once in about 10^12 tries, each
//! one counted. The key is readable to a native plugin that ignores the ABI and reads process
//! memory; that is the channel-2 residual BUSBAR-1.6.0.md #75 accepts, not a hole this closes.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{OnceLock, RwLock};

use busbar_contract::abi::mechanism::ticket::HostCtx;

use super::ticket::InstanceWake;

/// The bits of a handle that index the instance table.
pub const HANDLE_ID_BITS: u32 = 24;
/// The bits of a handle that carry the tag.
pub const HANDLE_TAG_BITS: u32 = 64 - HANDLE_ID_BITS;

const ID_MASK: u64 = (1 << HANDLE_ID_BITS) - 1;

/// Domain separation: a tag minted for an instance handle is never a tag for anything else the
/// key signs.
const DOMAIN_INSTANCE: u64 = u64::from_le_bytes(*b"bb.inst1");

/// Every handle the host was handed back and did not mint.
static FORGED: AtomicU64 = AtomicU64::new(0);

/// Every instance the host has minted a handle for, by `id - 1`. Instances are leaked, so an entry
/// never dangles.
static INSTANCES: RwLock<Vec<&'static InstanceWake>> = RwLock::new(Vec::new());

/// The host's key: 16 bytes from the OS random source, drawn once. A source that cannot answer
/// falls back to the standard library's own per-process random hasher keys (also OS-seeded), never
/// to a constant.
fn key() -> (u64, u64) {
    static KEY: OnceLock<(u64, u64)> = OnceLock::new();
    *KEY.get_or_init(|| {
        let mut b = [0u8; 16];
        if getrandom::fill(&mut b).is_err() {
            use std::hash::{BuildHasher, Hasher};
            let s = std::collections::hash_map::RandomState::new();
            for (i, chunk) in b.chunks_mut(8).enumerate() {
                let mut h = s.build_hasher();
                h.write_usize(i);
                chunk.copy_from_slice(&h.finish().to_le_bytes());
            }
        }
        let (lo, hi) = b.split_at(8);
        (
            u64::from_le_bytes(lo.try_into().unwrap_or_default()),
            u64::from_le_bytes(hi.try_into().unwrap_or_default()),
        )
    })
}

/// SipHash-2-4 over `words`, each eight little-endian message bytes.
fn siphash24((k0, k1): (u64, u64), words: &[u64]) -> u64 {
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

/// Mint the handle for `wake`: the next id, and its tag. `None` once the id space is spent (16.7M
/// instances in one process): the bind is refused rather than a handle reused.
pub(crate) fn mint(wake: &'static InstanceWake) -> Option<HostCtx> {
    let mut table = INSTANCES
        .write()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let id = table.len() as u64 + 1;
    if id > ID_MASK {
        return None;
    }
    table.push(wake);
    Some(HostCtx {
        handle: (tag_of(key(), id) << HANDLE_ID_BITS) | id,
    })
}

/// THE ONE CHECK: the instance `ctx` names, when the host minted it. The tag is recomputed and
/// compared before the table is read; a context with no id is no context (not counted), and one
/// whose tag does not verify, or whose id the host never minted, is counted as forged.
pub(crate) fn resolve(ctx: HostCtx) -> Option<&'static InstanceWake> {
    let id = ctx.handle & ID_MASK;
    if ctx.handle == 0 {
        return None;
    }
    let want = tag_of(key(), id);
    let got = ctx.handle >> HANDLE_ID_BITS;
    // Constant time: the whole difference is folded before it is judged.
    if id == 0 || std::hint::black_box(want ^ got) != 0 {
        refused();
        return None;
    }
    let table = INSTANCES
        .read()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let found = usize::try_from(id - 1)
        .ok()
        .and_then(|i| table.get(i).copied());
    drop(table);
    if found.is_none() {
        refused();
    }
    found
}

/// A handle the host did not mint: counted, and the instance crossing on this thread, if any,
/// quarantined ([`super::plugin::quarantine_crossing`]): one guess, never a second.
fn refused() {
    FORGED.fetch_add(1, Ordering::Relaxed);
    super::plugin::quarantine_crossing();
}

/// How many handles the host was handed back and did not mint, since the process started.
#[must_use]
pub fn forged() -> u64 {
    FORGED.load(Ordering::Relaxed)
}

#[cfg(test)]
#[path = "../tests/handle_tests.rs"]
mod handle_tests;
