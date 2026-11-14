// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! FAST-MAPS B1: the map hasher on host-minted and config keys, incumbent against foldhash.
//!
//! Rows (FAST-MAPS.md §7):
//! 1. `UnitKey` get/insert/remove at 64 and 4,096 entries: SipHash against `FastMap`.
//! 2. `Ticket` and `ReplySlot` get: SipHash against `FastMap`.
//! 3. breaker `Destinations` get at 8 and 64 destinations: `DestinationHash` against `FastMap`.
//! 4. `routing_price(lane, class)` over a 16-lane card: nested `BTreeMap` against nested `FastMap`.
//! 5. `HashMap<String, HookCfg>` get at 4 and 32 hooks: SipHash against `FastMap`.
//! 6. `SortedMap` against `FastMap` get at 4 and 16 `String` keys (where a B-tree can win).
//!
//! `FastMap` here is foldhash's own `HashMap` alias, the type `busbar_contract::collections`
//! will name. The bench lands before any map switches, so the gate (decision 215: `FastMap` no
//! slower on any row, faster on rows 1-2) is read against an unchanged dev.

use busbar_contract::abi::mechanism::ticket::Ticket;
use busbar_contract::dest::DestinationId;
use busbar_contract::ids::UnitKey;
use busbar_kernel::config::hooks::HookCfg;
use criterion::{criterion_group, criterion_main, Criterion};
use std::collections::{BTreeMap, HashMap};
use std::hash::BuildHasherDefault;
use std::hint::black_box;

type FastMap<K, V> = foldhash::HashMap<K, V>;

/// The incumbent breaker hasher, copied verbatim from `busbar-kernel-breaker/src/lib.rs:153-172`
/// (private there). Bench code only: it is the baseline row 3 measures `FastMap` against.
#[derive(Default, Clone, Copy)]
struct DestinationHash(u64);

impl std::hash::Hasher for DestinationHash {
    fn finish(&self) -> u64 {
        self.0
    }

    fn write(&mut self, bytes: &[u8]) {
        for b in bytes {
            self.0 = (self.0 ^ u64::from(*b)).wrapping_mul(0x0100_0000_01b3);
        }
    }

    fn write_u64(&mut self, n: u64) {
        self.0 = (self.0 ^ n).wrapping_mul(0x9e37_79b9_7f4a_7c15);
    }
}

/// The shape of the SDK's private `ReplySlot` (`busbar-contract/src/abi/sdk/out.rs:94`).
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
enum ReplySlot {
    Ticket(u32),
    Thread(std::thread::ThreadId),
}

/// A breaker destination's bucket footprint (the breaker's `Destination` is private).
#[derive(Clone, Copy)]
struct Destination([u64; 4]);

/// `HashMap<String, HookCfg>`'s bucket footprint without building a full hook config.
#[derive(Clone, Copy)]
struct HookSlot([u8; std::mem::size_of::<HookCfg>()]);

fn lookup<M, K>(c: &mut Criterion, name: &str, map: &M, keys: &[K], get: impl Fn(&M, &K) -> bool) {
    c.bench_function(name, |b| {
        let mut i = 0usize;
        b.iter(|| {
            let key = &keys[i % keys.len()];
            i = i.wrapping_add(1);
            black_box(get(black_box(map), black_box(key)))
        })
    });
}

fn unit_keys(n: u64) -> Vec<UnitKey> {
    // Host-minted: a counter, as `UnitKeyMint` hands them out.
    (1..=n).map(UnitKey::new).collect()
}

fn churn<M>(
    c: &mut Criterion,
    name: &str,
    keys: &[UnitKey],
    mut map: M,
    ops: impl Fn(&mut M, UnitKey),
) {
    c.bench_function(name, |b| {
        let mut i = 0usize;
        b.iter(|| {
            let key = keys[i % keys.len()];
            i = i.wrapping_add(1);
            ops(black_box(&mut map), black_box(key));
        })
    });
}

fn row1_unit_key(c: &mut Criterion) {
    for n in [64u64, 4096] {
        let keys = unit_keys(n);
        let sip: HashMap<UnitKey, u64> = keys.iter().map(|k| (*k, k.get())).collect();
        let fast: FastMap<UnitKey, u64> = keys.iter().map(|k| (*k, k.get())).collect();
        lookup(c, &format!("unit_key/get/{n}/sip"), &sip, &keys, |m, k| {
            m.contains_key(k)
        });
        lookup(
            c,
            &format!("unit_key/get/{n}/fast"),
            &fast,
            &keys,
            |m, k| m.contains_key(k),
        );
        churn(
            c,
            &format!("unit_key/remove_insert/{n}/sip"),
            &keys,
            sip,
            |m, k| {
                let v = m.remove(&k);
                m.insert(k, v.unwrap_or_default());
            },
        );
        churn(
            c,
            &format!("unit_key/remove_insert/{n}/fast"),
            &keys,
            fast,
            |m, k| {
                let v = m.remove(&k);
                m.insert(k, v.unwrap_or_default());
            },
        );
    }
}

fn row2_ticket_reply_slot(c: &mut Criterion) {
    let tickets: Vec<Ticket> = (1..=256u32)
        .map(|slot| Ticket {
            slot,
            generation: 1 + slot % 7,
        })
        .collect();
    let sip: HashMap<Ticket, u64> = tickets.iter().map(|t| (*t, u64::from(t.slot))).collect();
    let fast: FastMap<Ticket, u64> = tickets.iter().map(|t| (*t, u64::from(t.slot))).collect();
    lookup(c, "ticket/get/256/sip", &sip, &tickets, |m, k| {
        m.contains_key(k)
    });
    lookup(c, "ticket/get/256/fast", &fast, &tickets, |m, k| {
        m.contains_key(k)
    });

    // Ticketed replies plus the crossing thread's own unticketed slot.
    let mut slots: Vec<ReplySlot> = (1..=255u32).map(ReplySlot::Ticket).collect();
    slots.push(ReplySlot::Thread(std::thread::current().id()));
    let sip: HashMap<ReplySlot, u64> = slots.iter().map(|s| (*s, 0)).collect();
    let fast: FastMap<ReplySlot, u64> = slots.iter().map(|s| (*s, 0)).collect();
    lookup(c, "reply_slot/get/256/sip", &sip, &slots, |m, k| {
        m.contains_key(k)
    });
    lookup(c, "reply_slot/get/256/fast", &fast, &slots, |m, k| {
        m.contains_key(k)
    });
}

fn row3_destinations(c: &mut Criterion) {
    for n in [8u64, 64] {
        let ids: Vec<DestinationId> = (1..=n).map(DestinationId::new).collect();
        let incumbent: HashMap<DestinationId, Destination, BuildHasherDefault<DestinationHash>> =
            ids.iter()
                .map(|d| (*d, Destination([d.get(); 4])))
                .collect();
        let fast: FastMap<DestinationId, Destination> = ids
            .iter()
            .map(|d| (*d, Destination([d.get(); 4])))
            .collect();
        lookup(
            c,
            &format!("destinations/get/{n}/destination_hash"),
            &incumbent,
            &ids,
            |m, k| m.get(k).is_some_and(|d| d.0[0] != 0),
        );
        lookup(
            c,
            &format!("destinations/get/{n}/fast"),
            &fast,
            &ids,
            |m, k| m.get(k).is_some_and(|d| d.0[0] != 0),
        );
    }
}

const CLASSES: [&str; 4] = ["input", "output", "cached_input", "reasoning"];

fn row4_routing_price(c: &mut Criterion) {
    let lanes: Vec<String> = (0..16).map(|i| format!("openai-lane-{i:02}")).collect();
    let probes: Vec<(String, &str)> = lanes
        .iter()
        .flat_map(|l| CLASSES.iter().map(move |c| (l.clone(), *c)))
        .collect();
    let sorted: BTreeMap<String, BTreeMap<String, f64>> = lanes
        .iter()
        .map(|l| {
            (
                l.clone(),
                CLASSES.iter().map(|c| (c.to_string(), 1.5)).collect(),
            )
        })
        .collect();
    let fast: FastMap<String, FastMap<String, f64>> = lanes
        .iter()
        .map(|l| {
            (
                l.clone(),
                CLASSES.iter().map(|c| (c.to_string(), 1.5)).collect(),
            )
        })
        .collect();
    lookup(
        c,
        "routing_price/16x4/btree",
        &sorted,
        &probes,
        |m, (lane, class)| m.get(lane.as_str()).and_then(|p| p.get(*class)).is_some(),
    );
    lookup(
        c,
        "routing_price/16x4/fast",
        &fast,
        &probes,
        |m, (lane, class)| m.get(lane.as_str()).and_then(|p| p.get(*class)).is_some(),
    );
}

fn string_keys(n: usize, stem: &str) -> Vec<String> {
    (0..n).map(|i| format!("{stem}-{i:02}")).collect()
}

fn by_name<V: Copy, M: FromIterator<(String, V)>>(keys: &[String], v: V) -> M {
    keys.iter().map(|k| (k.clone(), v)).collect()
}

fn row5_hooks(c: &mut Criterion) {
    let slot = HookSlot([0; std::mem::size_of::<HookCfg>()]);
    for n in [4usize, 32] {
        let names = string_keys(n, "audit-gate");
        let sip: HashMap<String, HookSlot> = by_name(&names, slot);
        let fast: FastMap<String, HookSlot> = by_name(&names, slot);
        lookup(c, &format!("hooks/get/{n}/sip"), &sip, &names, |m, k| {
            m.get(k.as_str()).is_some_and(|h| h.0[0] == 0)
        });
        lookup(c, &format!("hooks/get/{n}/fast"), &fast, &names, |m, k| {
            m.get(k.as_str()).is_some_and(|h| h.0[0] == 0)
        });
    }
}

fn row6_sorted_vs_fast(c: &mut Criterion) {
    for n in [4usize, 16] {
        let names = string_keys(n, "lane");
        let sorted: BTreeMap<String, u64> = by_name(&names, 1);
        let fast: FastMap<String, u64> = by_name(&names, 1);
        lookup(
            c,
            &format!("string_get/{n}/sorted"),
            &sorted,
            &names,
            |m, k| m.contains_key(k.as_str()),
        );
        lookup(c, &format!("string_get/{n}/fast"), &fast, &names, |m, k| {
            m.contains_key(k.as_str())
        });
    }
}

criterion_group!(
    benches,
    row1_unit_key,
    row2_ticket_reply_slot,
    row3_destinations,
    row4_routing_price,
    row5_hooks,
    row6_sorted_vs_fast
);
criterion_main!(benches);
