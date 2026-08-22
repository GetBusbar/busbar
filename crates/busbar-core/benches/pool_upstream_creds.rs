//! Per-request egress credential-mode resolution micro-bench.
//!
//! `App::pool_upstream_creds(pool)` runs on the always-on egress path (`forward_with_pool_parsed_
//! inner`'s dispatch loop). Its body is `pool_runtime.get(pool).and_then(|rt| rt.upstream_
//! credentials).unwrap_or(default)` over a `HashMap<String, PoolRuntime>` with std's default
//! (SipHash) hasher — so each call SipHashes the pool NAME and probes the map. The 1.5.1 baseline
//! had no per-pool override: it read one `Copy` field. The p0-perfa-poolcreds fix restores that
//! read for the common config (no pool sets `upstream_credentials:`) via a boolean flag resolved
//! once at config apply; the map probe now runs ONLY when an override actually exists.
//!
//! This bench models the exact operation the accessor performs (the crate-internal `App`/`pub(crate)`
//! accessor is unreachable from a bench crate, so we reproduce its data shape faithfully: an identical
//! std `HashMap<String, Option<Creds>>` keyed by pool name). `old_lookup` is the pre-fix per-request
//! cost; `new_flag_copy` is the post-fix fast path; `override_lookup` confirms the rare
//! override-present config still pays the full probe (behavior preserved).

use criterion::{criterion_group, criterion_main, Criterion};
use std::collections::HashMap;
use std::hint::black_box;

/// A 2-variant `Copy` enum, byte-identical in cost to `busbar_core::auth::UpstreamCreds`.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Creds {
    Own,
    Passthrough,
}

/// Build a `pool_runtime`-shaped map: `n` pools, none overriding (`None`) — the common config.
fn pools_no_override(n: usize) -> (HashMap<String, Option<Creds>>, Vec<String>) {
    let mut m = HashMap::new();
    let mut names = Vec::new();
    for i in 0..n {
        let name = format!("pool-{i:03}-egress");
        m.insert(name.clone(), None);
        names.push(name);
    }
    (m, names)
}

/// The pre-fix accessor body: SipHash the pool name, probe the map, fall back to the default.
#[inline]
fn old_lookup(runtime: &HashMap<String, Option<Creds>>, pool: &str, default: Creds) -> Creds {
    runtime.get(pool).and_then(|rt| *rt).unwrap_or(default)
}

/// The post-fix fast path: no pool overrides, so return the default with a `Copy` read.
#[inline]
fn new_flag_copy(any_override: bool, runtime: &HashMap<String, Option<Creds>>, pool: &str, default: Creds) -> Creds {
    if !any_override {
        return default;
    }
    old_lookup(runtime, pool, default)
}

fn bench(c: &mut Criterion) {
    // A realistic pool count (a fleet with a few dozen egress pools) so the map probe pays a real
    // SipHash, not a 1-entry special case.
    let (runtime, names) = pools_no_override(32);
    let default = Creds::Own;

    // PRE-FIX: one String-keyed SipHash probe per request.
    c.bench_function("old_lookup_no_override", |b| {
        let mut i = 0usize;
        b.iter(|| {
            let pool = &names[i % names.len()];
            i = i.wrapping_add(1);
            black_box(old_lookup(black_box(&runtime), black_box(pool), black_box(default)))
        })
    });

    // POST-FIX common config: flag is false, so a branch + Copy read, no hashing.
    c.bench_function("new_flag_copy_no_override", |b| {
        let mut i = 0usize;
        b.iter(|| {
            let pool = &names[i % names.len()];
            i = i.wrapping_add(1);
            black_box(new_flag_copy(black_box(false), black_box(&runtime), black_box(pool), black_box(default)))
        })
    });

    // POST-FIX override-present config: flag is true, so the full probe runs (behavior preserved,
    // same cost as pre-fix — the fix does not regress the rare configured-override path). Uses a
    // `Passthrough` default to exercise the other credential variant end-to-end.
    let pt_default = Creds::Passthrough;
    c.bench_function("new_flag_copy_with_override", |b| {
        let mut i = 0usize;
        b.iter(|| {
            let pool = &names[i % names.len()];
            i = i.wrapping_add(1);
            black_box(new_flag_copy(black_box(true), black_box(&runtime), black_box(pool), black_box(pt_default)))
        })
    });
}

criterion_group!(benches, bench);
criterion_main!(benches);
