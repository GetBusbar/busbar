// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Criterion bench proving the plugin-ABI performance claim in code.
//!
//! Shapes measured (identical governance work behind each):
//!   (a) direct        — `govern_admit_direct(&Facts)`            (in-core baseline)
//!   (b) vtable        — `(host.govern_admit)(&facts)` fn-pointer (compiled-in plugin proxy)
//!   (c) vec_returning — `govern_admit_vec(&[u8]) -> Vec<u8>`     (shipped anti-pattern)
//!   (d) dlopen        — `spike_govern_admit` across a real `.so`/`.dylib` PLT (if the cdylib built)
//!
//! Before criterion runs, a manual pass prints the per-call ns, the (b)-(a) and (c)-(a) deltas
//! against the 1µs/call budget, and the ALLOC-GATE result (0 allocs for the POD paths).

use std::hint::black_box;
use std::path::PathBuf;
use std::time::Instant;

use criterion::{criterion_group, criterion_main, Criterion};
use plane_abi_spike::{
    encode_facts, govern_admit_direct, govern_admit_vec, CountingAlloc, Decision, Facts,
    PlaneHostVtable,
};

/// The govern_admit signature exported by the cdylib, as reached across the dlopen boundary.
type DlGovernAdmit = extern "C-unwind" fn(*const Facts) -> Decision;

fn sample_name() -> &'static [u8] {
    b"tenant-pool-eu-west-1"
}

fn sample_facts() -> plane_abi_spike::FactsGuard<'static> {
    // tokens=100, budget=1000, tenant=42, priority=7, flags=1 (trusted) => Admit
    Facts::new(100, 1000, 42, 7, 1, sample_name())
}

/// Locate the compiled cdylib next to the workspace target dir. Returns None if it wasn't built.
fn find_plugin() -> Option<PathBuf> {
    let name = if cfg!(target_os = "macos") {
        "libplane_abi_spike_plugin.dylib"
    } else if cfg!(target_os = "windows") {
        "plane_abi_spike_plugin.dll"
    } else {
        "libplane_abi_spike_plugin.so"
    };
    // CARGO_MANIFEST_DIR = <ws>/crates/plane-abi-spike ; target is <ws>/target
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let ws_target = manifest.parent()?.parent()?.join("target");
    for profile in ["release", "debug"] {
        for sub in ["", "deps"] {
            let mut p = ws_target.join(profile);
            if !sub.is_empty() {
                p = p.join(sub);
            }
            let cand = p.join(name);
            if cand.exists() {
                return Some(cand);
            }
        }
    }
    None
}

/// A loaded plugin, kept alive for the process. Leaks the Library on purpose so the fn-pointer stays
/// valid for criterion's whole run.
fn load_plugin() -> Option<DlGovernAdmit> {
    let path = find_plugin()?;
    unsafe {
        let lib = libloading::Library::new(&path).ok()?;
        let sym: libloading::Symbol<DlGovernAdmit> = lib.get(b"spike_govern_admit").ok()?;
        let f = *sym;
        // Keep the library resident for the whole process.
        std::mem::forget(lib);
        Some(f)
    }
}

/// Manual timing + alloc-gate pass, printed before criterion for a quick verdict. Criterion's own
/// numbers below are the authoritative measurement.
fn manual_report(dl: Option<DlGovernAdmit>) {
    const N: u64 = 5_000_000;
    let g = sample_facts();
    let vt = &PlaneHostVtable::IN_CORE;
    let enc = encode_facts(&g);

    // Warm up + correctness cross-check.
    let a0 = govern_admit_direct(&g);
    let b0 = (vt.govern_admit)(&*g as *const Facts);
    let c0 = govern_admit_vec(&enc).unwrap()[0];
    assert_eq!(a0, b0);
    assert_eq!(a0 as u8, c0);

    let t = Instant::now();
    for _ in 0..N {
        black_box(govern_admit_direct(black_box(&g)));
    }
    let a_ns = t.elapsed().as_nanos() as f64 / N as f64;

    let t = Instant::now();
    for _ in 0..N {
        black_box((vt.govern_admit)(black_box(&*g as *const Facts)));
    }
    let b_ns = t.elapsed().as_nanos() as f64 / N as f64;

    let t = Instant::now();
    for _ in 0..N {
        let out = black_box(govern_admit_vec(black_box(&enc))).unwrap();
        black_box(out);
    }
    let c_ns = t.elapsed().as_nanos() as f64 / N as f64;

    let d_ns = dl.map(|f| {
        let t = Instant::now();
        for _ in 0..N {
            black_box(f(black_box(&*g as *const Facts)));
        }
        t.elapsed().as_nanos() as f64 / N as f64
    });

    // ── ALLOC-GATE (counting global allocator) ──
    const M: u64 = 100_000;
    CountingAlloc::reset();
    for _ in 0..M {
        black_box(govern_admit_direct(black_box(&g)));
    }
    let a_alloc = CountingAlloc::count();
    CountingAlloc::reset();
    for _ in 0..M {
        black_box((vt.govern_admit)(black_box(&*g as *const Facts)));
    }
    let b_alloc = CountingAlloc::count();
    CountingAlloc::reset();
    for _ in 0..M {
        black_box(govern_admit_vec(black_box(&enc)).unwrap());
    }
    let c_alloc = CountingAlloc::count();

    eprintln!("\n=========== PLANE-ABI SPIKE — manual pass ({N} iters/shape) ===========");
    eprintln!("(a) direct        : {a_ns:8.3} ns/call");
    eprintln!("(b) vtable fnptr  : {b_ns:8.3} ns/call");
    eprintln!("(c) vec-returning : {c_ns:8.3} ns/call");
    match d_ns {
        Some(d) => eprintln!("(d) dlopen PLT    : {d:8.3} ns/call"),
        None => eprintln!("(d) dlopen PLT    :   (cdylib not found — build plane-abi-spike-plugin)"),
    }
    eprintln!("---------------------------------------------------------------------");
    eprintln!("delta (b)-(a) vtable overhead : {:+8.3} ns   (budget: < 1000 ns)", b_ns - a_ns);
    if let Some(d) = d_ns {
        eprintln!("delta (d)-(a) dlopen overhead : {:+8.3} ns   (budget: < 1000 ns)", d - a_ns);
    }
    eprintln!("delta (c)-(a) anti-pattern    : {:+8.3} ns   ({:.1}x the direct call)", c_ns - a_ns, c_ns / a_ns);
    eprintln!("---------------------------------------------------------------------");
    eprintln!("ALLOC-GATE ({M} calls each):");
    eprintln!("  (a) direct        allocs = {a_alloc}   {}", if a_alloc == 0 { "PASS (0)" } else { "FAIL" });
    eprintln!("  (b) vtable fnptr  allocs = {b_alloc}   {}", if b_alloc == 0 { "PASS (0)" } else { "FAIL" });
    eprintln!("  (c) vec-returning allocs = {c_alloc}   ({} per call)", c_alloc as f64 / M as f64);
    eprintln!("---------------------------------------------------------------------");
    let vtable_ok = (b_ns - a_ns) < 1000.0;
    eprintln!(
        "VERDICT: vtable overhead {:+.3} ns is {} the 1µs budget by {:.0}x",
        b_ns - a_ns,
        if vtable_ok { "UNDER" } else { "OVER" },
        if (b_ns - a_ns).abs() > 0.0 { 1000.0 / (b_ns - a_ns).abs() } else { f64::INFINITY }
    );
    eprintln!("=====================================================================\n");
}

fn benches(c: &mut Criterion) {
    let dl = load_plugin();
    manual_report(dl);

    let g = sample_facts();
    let vt = &PlaneHostVtable::IN_CORE;
    let enc = encode_facts(&g);

    let mut grp = c.benchmark_group("govern_admit");

    grp.bench_function("a_direct", |bch| {
        bch.iter(|| black_box(govern_admit_direct(black_box(&g))));
    });

    grp.bench_function("b_vtable_fnptr", |bch| {
        bch.iter(|| black_box((vt.govern_admit)(black_box(&*g as *const Facts))));
    });

    grp.bench_function("c_vec_returning", |bch| {
        bch.iter(|| {
            let out = black_box(govern_admit_vec(black_box(&enc))).unwrap();
            black_box(out);
        });
    });

    if let Some(f) = dl {
        grp.bench_function("d_dlopen_plt", |bch| {
            bch.iter(|| black_box(f(black_box(&*g as *const Facts))));
        });
    }

    grp.finish();
}

criterion_group!(abi, benches);
criterion_main!(abi);
