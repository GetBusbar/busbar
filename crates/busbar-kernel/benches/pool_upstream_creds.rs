use criterion::{criterion_group, criterion_main, Criterion};
use std::collections::HashMap;
use std::hint::black_box;

/// A 2-variant `Copy` enum, byte-identical in cost to `busbar_kernel::auth::UpstreamCreds`.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Creds {
    Own,
    Passthrough,
}

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

#[inline]
fn old_lookup(runtime: &HashMap<String, Option<Creds>>, pool: &str, default: Creds) -> Creds {
    runtime.get(pool).and_then(|rt| *rt).unwrap_or(default)
}

#[inline]
fn new_flag_copy(
    any_override: bool,
    runtime: &HashMap<String, Option<Creds>>,
    pool: &str,
    default: Creds,
) -> Creds {
    if !any_override {
        return default;
    }
    old_lookup(runtime, pool, default)
}

fn bench(c: &mut Criterion) {
    let (runtime, names) = pools_no_override(32);
    let default = Creds::Own;

    c.bench_function("old_lookup_no_override", |b| {
        let mut i = 0usize;
        b.iter(|| {
            let pool = &names[i % names.len()];
            i = i.wrapping_add(1);
            black_box(old_lookup(
                black_box(&runtime),
                black_box(pool),
                black_box(default),
            ))
        })
    });

    c.bench_function("new_flag_copy_no_override", |b| {
        let mut i = 0usize;
        b.iter(|| {
            let pool = &names[i % names.len()];
            i = i.wrapping_add(1);
            black_box(new_flag_copy(
                black_box(false),
                black_box(&runtime),
                black_box(pool),
                black_box(default),
            ))
        })
    });

    let pt_default = Creds::Passthrough;
    c.bench_function("new_flag_copy_with_override", |b| {
        let mut i = 0usize;
        b.iter(|| {
            let pool = &names[i % names.len()];
            i = i.wrapping_add(1);
            black_box(new_flag_copy(
                black_box(true),
                black_box(&runtime),
                black_box(pool),
                black_box(pt_default),
            ))
        })
    });
}

criterion_group!(benches, bench);
criterion_main!(benches);
