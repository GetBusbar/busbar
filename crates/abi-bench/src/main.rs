// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE PLUGIN-ABI MARSHALLING INSTRUMENT. Measurement-only; nothing here ships.
//!
//! # The question
//!
//! A `dlopen`'d call is a PLT indirection — single-digit nanoseconds. The cost of a dropped-in
//! plugin is therefore never the dynamic linking; it is whatever the ABI puts ON the boundary. Today
//! that is a JSON round trip per crossing. The bar is: **a plugin must add nanoseconds, not
//! microseconds.**
//!
//! # What is measured, and how the arms are kept honest
//!
//! Every arm performs the SAME work (`busbar_abi_bench::work_owned` / `work_archived`: touch every
//! text-bearing field of the request). The arms differ only in how the payload reached the plugin.
//!
//! | arm | what it is |
//! |---|---|
//! | `native` | a direct in-process Rust call. No `dlopen`, no marshalling. **The floor.** |
//! | `xport-noop` | a full `busbar_call` crossing with a 16-byte request and a 0-byte response. **The irreducible transport cost** — `catch_unwind` on both sides, the fn-pointer call, the out-buffer publish, the host's `free` callback. Every encoding pays this. |
//! | `xport-echo` | the same crossing, but the plugin returns a response the size of the real one. Isolates the payload-PROPORTIONAL half of the transport (plugin allocates, host copies out, host frees) from the fixed half. |
//! | `json` | today's ABI: host `to_vec` → cross → plugin `from_slice` → work → plugin `to_vec` → host `from_slice`. |
//! | `postcard` | the same shape with a compact binary encoding that still has a parse step. The control that separates "binary" from "zero-copy". |
//! | `rkyv-checked` | host `to_bytes` → cross → plugin VALIDATES and reads in place → work → plugin builds a fresh archive → host validates and reads in place. |
//! | `rkyv-unchecked` | the same with validation off. Unsound for an untrusted buffer; measured to price validation, not to recommend it. |
//! | `rkyv-prebuilt` | the same, except the response archive was built once at open. **The "the serialize step disappeared" arm** — the floor a zero-copy design reaches only if the producer's native output IS the archive. |
//! | `rawbytes→rkyv` | the host hands the plugin the caller's UNPARSED HTTP body; the plugin does the parse it was going to do anyway and returns an IR archive. The marginal cost over compiled-in is one IR encode plus one access. |
//!
//! Two reference scales are printed alongside so a crossing figure can be read against the work the
//! codec was going to do regardless: a bare `serde_json::Value` parse of the body, and the real
//! `AnthropicReader::read_request` over that value.
//!
//! # Method
//!
//! Release only. `wt-proto-abi` recorded debug at 53,332 ns/crossing against release at 3,321 — a
//! 16× gap that produces a number no shipped build has. The harness refuses to run under `debug`.
//!
//! Arms are interleaved ROUND-ROBIN at block granularity within a trial, per the lesson in
//! `wt-ffiperf`'s `ffi_hop` bench: run sequentially, this machine's own drift between cells is
//! larger than the effect under test. One warm-up trial is discarded, then five trials are reported
//! with their spread.

use busbar_abi_bench::{op, wire::WireRequest, HDR};
use libloading::{Library, Symbol};
use std::ffi::c_void;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::ptr::null_mut;
use std::time::Instant;

type OpenFn = unsafe extern "C-unwind" fn(
    *const u8,
    usize,
    *mut *mut c_void,
    *mut *mut u8,
    *mut usize,
) -> i32;
type CallFn =
    unsafe extern "C-unwind" fn(*mut c_void, *const u8, usize, *mut *mut u8, *mut usize) -> i32;
type FreeFn = unsafe extern "C-unwind" fn(*mut u8, usize);
type CloseFn = unsafe extern "C-unwind" fn(*mut c_void);

/// The host side of the crossing, replicating `plugin-loader`'s `RawPlugin::transport_call_status`
/// step for step: `catch_unwind` around the fn-pointer call, the response-length cap check, a full
/// COPY of the response out of plugin memory, then the `busbar_free` callback. The copy is not an
/// artifact of this harness — the loader does it too (`from_raw_parts(out, out_len).to_vec()`), and
/// it is the reason a zero-copy response can still be read in place: the copy the transport already
/// performs can land in aligned storage for free.
struct Plugin {
    handle: *mut c_void,
    call: CallFn,
    free: FreeFn,
    close: CloseFn,
    _lib: Library,
}

impl Plugin {
    fn open(path: &str, cfg: &str) -> Plugin {
        unsafe {
            let lib = Library::new(path).unwrap_or_else(|e| panic!("dlopen {path}: {e}"));
            let abi: Symbol<unsafe extern "C-unwind" fn() -> u32> = lib.get(b"busbar_abi\0").unwrap();
            assert_eq!(abi(), busbar_plugin_abi_version(), "transport version mismatch");
            let open: Symbol<OpenFn> = lib.get(b"busbar_open\0").unwrap();
            let call: CallFn = *lib.get::<CallFn>(b"busbar_call\0").unwrap();
            let free: FreeFn = *lib.get::<FreeFn>(b"busbar_free\0").unwrap();
            let close: CloseFn = *lib.get::<CloseFn>(b"busbar_close\0").unwrap();
            let mut handle: *mut c_void = null_mut();
            let mut err: *mut u8 = null_mut();
            let mut err_len = 0usize;
            let st = open(
                cfg.as_ptr(),
                cfg.len(),
                &mut handle,
                &mut err,
                &mut err_len,
            );
            assert_eq!(st, 0, "busbar_open failed with status {st}");
            drop(open);
            drop(abi);
            Plugin {
                handle,
                call,
                free,
                close,
                _lib: lib,
            }
        }
    }

    /// One crossing. Returns the response copied into 16-byte-aligned storage, because the response
    /// copy has to happen anyway and landing it aligned is what makes an in-place read possible.
    #[inline]
    fn cross(&self, req: &rkyv::util::AlignedVec) -> rkyv::util::AlignedVec {
        let mut out: *mut u8 = null_mut();
        let mut out_len: usize = 0;
        let status = catch_unwind(AssertUnwindSafe(|| unsafe {
            (self.call)(self.handle, req.as_ptr(), req.len(), &mut out, &mut out_len)
        }))
        .expect("plugin unwound into the host");
        assert_eq!(status, 0, "busbar_call status {status}");
        assert!(out_len <= busbar_plugin_abi_max_len());
        let mut buf = rkyv::util::AlignedVec::<16>::with_capacity(out_len);
        if out_len > 0 {
            buf.extend_from_slice(unsafe { std::slice::from_raw_parts(out, out_len) });
        }
        unsafe { (self.free)(out, out_len) };
        buf
    }
}

impl Drop for Plugin {
    fn drop(&mut self) {
        unsafe { (self.close)(self.handle) };
    }
}

// Kept as free fns rather than importing plugin-abi so this crate's dependency list stays the
// instrument's own; the two constants are part of the frozen contract and will not drift.
fn busbar_plugin_abi_version() -> u32 {
    1
}
fn busbar_plugin_abi_max_len() -> usize {
    256 * 1024 * 1024
}

/// Build a request buffer: opcode in byte 0, payload from [`HDR`], the whole thing 16-byte aligned
/// so an archive inside it can be read in place.
fn framed(opcode: u8, payload: &[u8]) -> rkyv::util::AlignedVec {
    let mut v = rkyv::util::AlignedVec::<16>::with_capacity(HDR + payload.len());
    v.extend_from_slice(&[0u8; HDR]);
    v[0] = opcode;
    v.extend_from_slice(payload);
    v
}

// ── the harness ─────────────────────────────────────────────────────────────────────────────────

/// One measured arm: a name and a closure that performs exactly one operation.
struct Arm<'a> {
    name: &'static str,
    run: Box<dyn FnMut() -> u64 + 'a>,
}

/// Interleave the arms round-robin at block granularity, five reported trials after one discarded
/// warm-up. Returns per-arm nanoseconds-per-operation for each trial.
fn measure(arms: &mut [Arm], iters: usize, blocks: usize) -> Vec<Vec<f64>> {
    let per_block = (iters / blocks).max(1);
    let mut out = vec![Vec::new(); arms.len()];
    // Nine passes: one discarded warm-up plus eight reported trials. Eight rather than five because
    // the sweeps estimate the cost by the BEST trial (see `best`), and the odds that every one of
    // eight passes was interrupted by a competing build fall off fast with the count.
    for trial in 0..9 {
        let mut totals = vec![0u128; arms.len()];
        for _ in 0..blocks {
            for (i, arm) in arms.iter_mut().enumerate() {
                let t0 = Instant::now();
                let mut acc = 0u64;
                for _ in 0..per_block {
                    acc = acc.wrapping_add((arm.run)());
                }
                totals[i] += t0.elapsed().as_nanos();
                std::hint::black_box(acc);
            }
        }
        if trial == 0 {
            continue; // warm-up trial, discarded
        }
        for (i, t) in totals.iter().enumerate() {
            out[i].push(*t as f64 / (blocks * per_block) as f64);
        }
    }
    out
}

fn report(title: &str, names: &[&str], results: &[Vec<f64>], baseline: Option<f64>) {
    println!("\n### {title}");
    println!(
        "{:<22} {:>12} {:>12} {:>12} {:>10}",
        "arm", "median ns", "min ns", "max ns", "vs native"
    );
    for (name, trials) in names.iter().zip(results) {
        let mut s = trials.clone();
        s.sort_by(|a, b| a.partial_cmp(b).unwrap());
        let med = s[s.len() / 2];
        let rel = match baseline {
            Some(b) if b > 0.0 => format!("{:+.0} ns", med - b),
            _ => "-".to_string(),
        };
        println!(
            "{:<22} {:>12.1} {:>12.1} {:>12.1} {:>10}",
            name,
            med,
            s[0],
            s[s.len() - 1],
            rel
        );
    }
}

fn median(v: &[f64]) -> f64 {
    let mut s = v.to_vec();
    s.sort_by(|a, b| a.partial_cmp(b).unwrap());
    s[s.len() / 2]
}

/// The BEST trial, which is the right estimator for the sweeps.
///
/// Contention is strictly additive noise: a competing build can only ever make a trial slower, never
/// faster, so the distribution has a hard floor at the true cost and a long right tail. Under a
/// build fleet the median sits somewhere in that tail and moves with the fleet's mood — the density
/// table came back non-monotonic across two runs on medians while the curve's minima agreed to
/// within a few percent. The minimum estimates the floor, which is the quantity the design decision
/// needs. It is reported alongside the spread so a reader can see how much tail was discarded.
fn best(v: &[f64]) -> f64 {
    v.iter().copied().fold(f64::INFINITY, f64::min)
}

/// Relative spread of the trials, as a percentage of the best — the noise column.
fn spread_pct(v: &[f64]) -> f64 {
    let b = best(v);
    let w = v.iter().copied().fold(0.0f64, f64::max);
    if b > 0.0 {
        (w - b) / b * 100.0
    } else {
        0.0
    }
}

/// Locate the bench cdylib: a scoped `cargo build -p` writes only into `deps/`, a workspace build
/// writes both, so take the newest of the two rather than guessing.
fn cdylib_path() -> String {
    let ext = if cfg!(target_os = "macos") {
        "dylib"
    } else if cfg!(windows) {
        "dll"
    } else {
        "so"
    };
    let prefix = if cfg!(windows) { "" } else { "lib" };
    let name = format!("{prefix}busbar_abi_bench_plugin.{ext}");
    let root = std::env::current_exe()
        .unwrap()
        .parent()
        .unwrap()
        .to_path_buf();
    let mut best: Option<(std::time::SystemTime, String)> = None;
    for dir in [root.clone(), root.join("deps")] {
        let p = dir.join(&name);
        if let Ok(md) = std::fs::metadata(&p) {
            let t = md.modified().unwrap();
            if best.as_ref().is_none_or(|(bt, _)| t > *bt) {
                best = Some((t, p.to_string_lossy().into_owned()));
            }
        }
    }
    best.map(|(_, p)| p).unwrap_or_else(|| {
        panic!("{name} not found next to the harness — run `cargo build --release -p busbar-abi-bench-plugin -p busbar-abi-bench` first")
    })
}

/// An Anthropic-shaped wire body of roughly `target` bytes — the input the "hand the codec raw
/// bytes" arm and both reference scales are driven with.
fn anthropic_body(target: usize) -> Vec<u8> {
    let lorem = "You are a careful assistant operating inside an enterprise gateway. Prefer precise answers, cite the tool you used, and never invent an identifier you were not given. ";
    let mut messages = Vec::new();
    let mut size = 0usize;
    let mut i = 0;
    while size < target {
        let text = lorem.repeat(((target - size) / lorem.len()).clamp(1, 400));
        size += text.len();
        messages.push(serde_json::json!({
            "role": if i % 2 == 0 { "user" } else { "assistant" },
            "content": [{"type": "text", "text": text}]
        }));
        i += 1;
    }
    let body = serde_json::json!({
        "model": "claude-sonnet-4-6",
        "max_tokens": 4096,
        "temperature": 0.7,
        "stream": true,
        "system": [{"type": "text", "text": lorem}],
        "tools": [{
            "name": "search_corpus",
            "description": "Search the enterprise corpus for matching documents.",
            "input_schema": {"type": "object", "properties": {"query": {"type": "string"}}, "required": ["query"]}
        }],
        "messages": messages,
    });
    serde_json::to_vec(&body).unwrap()
}

fn main() {
    if cfg!(debug_assertions) {
        eprintln!(
            "REFUSING TO RUN IN DEBUG. `wt-proto-abi` measured 53,332 ns/crossing in debug against \
             3,321 ns in release — a 16x gap that yields a number no shipped build has. \
             Run: cargo run --release -p busbar-abi-bench --bin abi-bench"
        );
        std::process::exit(2);
    }

    let path = cdylib_path();
    println!("busbar plugin-ABI marshalling instrument");
    println!("cdylib: {path}");
    println!(
        "host:   {} {}, release, {} logical cpus",
        std::env::consts::OS,
        std::env::consts::ARCH,
        std::thread::available_parallelism().map_or(0, |n| n.get())
    );

    // Timer overhead, so a reader can see how much of a sub-100 ns figure is the clock. Blocks of
    // `per_block` operations amortize this away, but the number belongs on the record.
    let t0 = Instant::now();
    for _ in 0..10_000 {
        std::hint::black_box(Instant::now());
    }
    println!(
        "clock:  Instant::now() ~{:.1} ns",
        t0.elapsed().as_nanos() as f64 / 10_000.0
    );

    // ── the fixed transport cost, priced on its own ────────────────────────────────────────────
    {
        let p = Plugin::open(&path, "1024");
        let noop = framed(op::NOOP, &[]);
        let mut echo_bufs: Vec<rkyv::util::AlignedVec> = [1024usize, 10_240, 51_200, 512_000]
            .iter()
            .map(|n| framed(op::ECHO_N, &(*n as u32).to_le_bytes()))
            .collect();
        let (e500k, rest) = echo_bufs.split_last_mut().unwrap();
        let (e50k, rest) = rest.split_last_mut().unwrap();
        let (e10k, rest) = rest.split_last_mut().unwrap();
        let e1k = &mut rest[0];
        let names = [
            "xport-noop",
            "xport-echo-1KB",
            "xport-echo-10KB",
            "xport-echo-50KB",
            "xport-echo-500KB",
        ];
        let mut arms = vec![
            Arm {
                name: names[0],
                run: Box::new(|| p.cross(&noop).len() as u64),
            },
            Arm {
                name: names[1],
                run: Box::new(|| p.cross(e1k).len() as u64),
            },
            Arm {
                name: names[2],
                run: Box::new(|| p.cross(e10k).len() as u64),
            },
            Arm {
                name: names[3],
                run: Box::new(|| p.cross(e50k).len() as u64),
            },
            Arm {
                name: names[4],
                run: Box::new(|| p.cross(e500k).len() as u64),
            },
        ];
        let res = measure(&mut arms, 20_000, 20);
        let n: Vec<&str> = arms.iter().map(|a| a.name).collect();
        report(
            "TRANSPORT ONLY — no encoding of any kind (this is what every design pays)",
            &n,
            &res,
            None,
        );
    }

    // ── the encodings, per payload size ────────────────────────────────────────────────────────
    for (label, target, iters) in [
        ("1 KB — a small chat request", 1024usize, 20_000usize),
        ("10 KB — a typical request with tools and history", 10_240, 8_000),
        ("50 KB — a long system prompt plus history", 51_200, 3_000),
        ("500 KB — an embedded document or base64 image", 512_000, 400),
    ] {
        let cfg = target.to_string();
        let p = Plugin::open(&path, &cfg);
        let req = busbar_abi_bench::build_request(target);
        let body = anthropic_body(target);

        let json_bytes = serde_json::to_vec(&req).unwrap();
        let pc_bytes = postcard::to_allocvec(&req).unwrap();
        let rk_bytes = rkyv::to_bytes::<rkyv::rancor::Error>(&req).unwrap();
        println!(
            "\n-- {label}: json {} B, postcard {} B, rkyv {} B, anthropic wire body {} B",
            json_bytes.len(),
            pc_bytes.len(),
            rk_bytes.len(),
            body.len()
        );

        let json_req = framed(op::JSON, &json_bytes);
        let pc_req = framed(op::POSTCARD, &pc_bytes);
        let rk_req_checked = framed(op::RKYV_CHECKED, &rk_bytes);
        let rk_req_unchecked = framed(op::RKYV_UNCHECKED, &rk_bytes);
        let rk_req_prebuilt = framed(op::RKYV_PREBUILT, &rk_bytes);
        let raw_req = framed(op::RAW_BYTES_TO_RKYV, &body);

        let reader = busbar_proto_anthropic::protocol();

        let mut arms = vec![
            Arm {
                name: "native",
                run: Box::new(|| busbar_abi_bench::work_owned(&req)),
            },
            Arm {
                name: "json",
                run: Box::new(|| {
                    // Host encodes, crosses, decodes — the full round trip the loader performs.
                    let enc = framed(op::JSON, &serde_json::to_vec(&req).unwrap());
                    let resp = p.cross(&enc);
                    serde_json::from_slice::<WireRequest>(&resp).unwrap().messages.len() as u64
                }),
            },
            Arm {
                name: "postcard",
                run: Box::new(|| {
                    let enc = framed(op::POSTCARD, &postcard::to_allocvec(&req).unwrap());
                    let resp = p.cross(&enc);
                    postcard::from_bytes::<WireRequest>(&resp).unwrap().messages.len() as u64
                }),
            },
            Arm {
                name: "rkyv-checked",
                run: Box::new(|| {
                    let enc = framed(
                        op::RKYV_CHECKED,
                        &rkyv::to_bytes::<rkyv::rancor::Error>(&req).unwrap(),
                    );
                    let resp = p.cross(&enc);
                    let a = rkyv::access::<busbar_abi_bench::wire::ArchivedWireRequest, rkyv::rancor::Error>(&resp)
                        .unwrap();
                    a.messages.len() as u64
                }),
            },
            Arm {
                name: "rkyv-unchecked",
                run: Box::new(|| {
                    let enc = framed(
                        op::RKYV_UNCHECKED,
                        &rkyv::to_bytes::<rkyv::rancor::Error>(&req).unwrap(),
                    );
                    let resp = p.cross(&enc);
                    let a = unsafe {
                        rkyv::access_unchecked::<busbar_abi_bench::wire::ArchivedWireRequest>(&resp)
                    };
                    a.messages.len() as u64
                }),
            },
            Arm {
                name: "rkyv-prebuilt",
                run: Box::new(|| {
                    // Neither side runs an encode pass: the host reuses an archive it already has
                    // and the plugin returns one it built at open. The zero-copy ideal.
                    let resp = p.cross(&rk_req_prebuilt);
                    let a = unsafe {
                        rkyv::access_unchecked::<busbar_abi_bench::wire::ArchivedWireRequest>(&resp)
                    };
                    a.messages.len() as u64
                }),
            },
            Arm {
                name: "rawbytes->rkyv",
                run: Box::new(|| {
                    let resp = p.cross(&raw_req);
                    let a = unsafe {
                        rkyv::access_unchecked::<busbar_abi_bench::wire::ArchivedWireRequest>(&resp)
                    };
                    a.messages.len() as u64
                }),
            },
            Arm {
                name: "ref: value parse",
                run: Box::new(|| {
                    serde_json::from_slice::<serde_json::Value>(&body)
                        .map(|v| v.as_object().map_or(0, |o| o.len() as u64))
                        .unwrap_or(0)
                }),
            },
            Arm {
                name: "ref: anthropic read",
                run: Box::new(|| {
                    let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
                    reader
                        .reader()
                        .read_request(&v)
                        .map(|ir| ir.messages.len() as u64)
                        .unwrap_or(0)
                }),
            },
        ];
        let res = measure(&mut arms, iters, 20);
        let n: Vec<&str> = arms.iter().map(|a| a.name).collect();
        let base = median(&res[0]);
        report(label, &n, &res, Some(base));
        let _ = (&json_req, &pc_req, &rk_req_checked, &rk_req_unchecked);
    }

    // ── THE CURVE: is the crossing linear in payload bytes? ────────────────────────────────────
    // Ten points across two and a half decades, so the SHAPE is read off a fit rather than asserted
    // from two points. Reported as ns and as ns/byte: a linear cost shows a FLAT ns/byte column, a
    // cost with a fixed floor shows ns/byte falling as size grows, and a superlinear cost shows it
    // rising.
    {
        println!("\n### THE CURVE — crossing cost vs payload size (release)");
        println!(
            "{:<10} {:>9} {:>11} {:>9} {:>11} {:>9} {:>11} {:>9} {:>11} {:>9}",
            "target",
            "json B",
            "json ns",
            "ns/B",
            "rkyv-un ns",
            "ns/B",
            "prebuilt ns",
            "ns/B",
            "xport ns",
            "ns/B"
        );
        // EVERY POINT IS AN ARM IN ONE INTERLEAVED TRIAL. Measuring each size in its own `measure()`
        // call is the very mistake this harness's header warns about: consecutive calls are minutes
        // apart, and on a machine running a build fleet the drift between them is larger than the
        // slope being fitted. Interleaved, all 40 cells see the same weather, so the SHAPE of the
        // curve survives contention even when the absolute level does not.
        let targets = [
            1024usize, 2048, 4096, 8192, 16_384, 32_768, 65_536, 131_072, 262_144, 524_288,
        ];
        let plugins: Vec<Plugin> = targets
            .iter()
            .map(|t| Plugin::open(&path, &t.to_string()))
            .collect();
        let reqs: Vec<WireRequest> = targets
            .iter()
            .map(|t| busbar_abi_bench::build_request(*t))
            .collect();
        let jsonb: Vec<Vec<u8>> = reqs.iter().map(|r| serde_json::to_vec(r).unwrap()).collect();
        let rkb: Vec<rkyv::util::AlignedVec> = reqs
            .iter()
            .map(|r| rkyv::to_bytes::<rkyv::rancor::Error>(r).unwrap())
            .collect();
        let prebuilt: Vec<rkyv::util::AlignedVec> = rkb
            .iter()
            .map(|b| framed(op::RKYV_PREBUILT, b))
            .collect();
        let echo: Vec<rkyv::util::AlignedVec> = jsonb
            .iter()
            .map(|b| framed(op::ECHO_N, &(b.len() as u32).to_le_bytes()))
            .collect();

        let mut arms: Vec<Arm> = Vec::new();
        for i in 0..targets.len() {
            let (p, req) = (&plugins[i], &reqs[i]);
            arms.push(Arm {
                name: "json",
                run: Box::new(move || {
                    let enc = framed(op::JSON, &serde_json::to_vec(req).unwrap());
                    let resp = p.cross(&enc);
                    serde_json::from_slice::<WireRequest>(&resp).unwrap().messages.len() as u64
                }),
            });
            arms.push(Arm {
                name: "rkyv-unchecked",
                run: Box::new(move || {
                    let enc = framed(
                        op::RKYV_UNCHECKED,
                        &rkyv::to_bytes::<rkyv::rancor::Error>(req).unwrap(),
                    );
                    let resp = p.cross(&enc);
                    let a = unsafe {
                        rkyv::access_unchecked::<busbar_abi_bench::wire::ArchivedWireRequest>(&resp)
                    };
                    a.messages.len() as u64
                }),
            });
            let pre = &prebuilt[i];
            arms.push(Arm {
                name: "rkyv-prebuilt",
                run: Box::new(move || p.cross(pre).len() as u64),
            });
            let e = &echo[i];
            arms.push(Arm {
                name: "xport",
                run: Box::new(move || p.cross(e).len() as u64),
            });
        }
        // A modest per-arm iteration count: with 40 arms the trial is already long, and the
        // round-robin is what buys precision here, not depth within a cell.
        let res = measure(&mut arms, 600, 6);
        for (i, target) in targets.iter().enumerate() {
            let nb = jsonb[i].len() as f64;
            let m: Vec<f64> = (0..4).map(|k| best(&res[i * 4 + k])).collect();
            println!(
                "{:<10} {:>9} {:>11.1} {:>9.3} {:>11.1} {:>9.3} {:>11.1} {:>9.3} {:>11.1} {:>9.3}",
                format!("{} KB", target / 1024),
                jsonb[i].len(),
                m[0],
                m[0] / nb,
                m[1],
                m[1] / nb,
                m[2],
                m[2] / nb,
                m[3],
                m[3] / nb
            );
        }
    }

    // ── THE CONTROL: same bytes, different structural density ──────────────────────────────────
    // If the crossing tracks BYTES, these rows are flat. If it tracks the number of JSON values,
    // they are not — and "proportional to payload size" is the wrong model.
    {
        println!("\n### DENSITY CONTROL — ~32 KB held constant, structure varied (release)");
        println!(
            "{:<12} {:>9} {:>10} {:>11} {:>13} {:>13} {:>9}",
            "blocks", "json B", "values", "json ns", "ns/byte", "ns/value", "spread%"
        );
        // Interleaved for the same reason the curve is: measured row-by-row, this table came back
        // NON-MONOTONIC in the block count (a 64% jump between adjacent rows that then reversed),
        // which is drift, not structure.
        let densities = [2usize, 4, 8, 16, 32, 64, 128];
        let p = Plugin::open(&path, "32768");
        let dreqs: Vec<WireRequest> = densities
            .iter()
            .map(|n| busbar_abi_bench::build_request_dense(32_768, *n))
            .collect();
        let dbytes: Vec<usize> = dreqs
            .iter()
            .map(|r| serde_json::to_vec(r).unwrap().len())
            .collect();
        let dvalues: Vec<u64> = dreqs
            .iter()
            .map(busbar_abi_bench::value_count)
            .collect();
        let pr = &p;
        let mut arms: Vec<Arm> = dreqs
            .iter()
            .map(|req| Arm {
                name: "json",
                run: Box::new(move || {
                    let enc = framed(op::JSON, &serde_json::to_vec(req).unwrap());
                    let resp = pr.cross(&enc);
                    serde_json::from_slice::<WireRequest>(&resp).unwrap().messages.len() as u64
                }),
            })
            .collect();
        let res = measure(&mut arms, 1_200, 6);
        for (i, n_blocks) in densities.iter().enumerate() {
            let m = best(&res[i]);
            println!(
                "{:<12} {:>9} {:>10} {:>11.1} {:>13.3} {:>13.1} {:>9.1}",
                n_blocks,
                dbytes[i],
                dvalues[i],
                m,
                m / dbytes[i] as f64,
                m / dvalues[i] as f64,
                spread_pct(&res[i])
            );
        }
    }

    // ── THE DECISIVE CASE: one SSE frame ───────────────────────────────────────────────────────
    {
        let p = Plugin::open(&path, "1024");
        let frame = busbar_abi_bench::build_frame();
        let fj = serde_json::to_vec(&frame).unwrap();
        let fr = rkyv::to_bytes::<rkyv::rancor::Error>(&frame).unwrap();
        println!("\n-- streaming frame: json {} B, rkyv {} B", fj.len(), fr.len());
        let rk_prebuilt = framed(op::RKYV_FRAME_PREBUILT, &fr);
        let noop = framed(op::NOOP, &[]);
        let mut arms = vec![
            Arm {
                name: "native",
                run: Box::new(|| busbar_abi_bench::frame_work_owned(&frame)),
            },
            Arm {
                name: "xport-noop",
                run: Box::new(|| p.cross(&noop).len() as u64),
            },
            Arm {
                name: "json",
                run: Box::new(|| {
                    let enc = framed(op::JSON_FRAME, &serde_json::to_vec(&frame).unwrap());
                    let resp = p.cross(&enc);
                    serde_json::from_slice::<busbar_abi_bench::wire::WireStreamEvent>(&resp)
                        .map(|e| busbar_abi_bench::frame_work_owned(&e))
                        .unwrap_or(0)
                }),
            },
            Arm {
                name: "rkyv",
                run: Box::new(|| {
                    let enc = framed(
                        op::RKYV_FRAME,
                        &rkyv::to_bytes::<rkyv::rancor::Error>(&frame).unwrap(),
                    );
                    let resp = p.cross(&enc);
                    let a = unsafe {
                        rkyv::access_unchecked::<
                            busbar_abi_bench::wire::ArchivedWireStreamEvent,
                        >(&resp)
                    };
                    busbar_abi_bench::frame_work_archived(a)
                }),
            },
            Arm {
                name: "rkyv-prebuilt",
                run: Box::new(|| {
                    let resp = p.cross(&rk_prebuilt);
                    let a = unsafe {
                        rkyv::access_unchecked::<
                            busbar_abi_bench::wire::ArchivedWireStreamEvent,
                        >(&resp)
                    };
                    busbar_abi_bench::frame_work_archived(a)
                }),
            },
        ];
        let res = measure(&mut arms, 40_000, 20);
        let n: Vec<&str> = arms.iter().map(|a| a.name).collect();
        let base = median(&res[0]);
        report(
            "ONE SSE FRAME — multiply by the frame count for the real streaming cost",
            &n,
            &res,
            Some(base),
        );
        let med: Vec<f64> = res.iter().map(|t| median(t)).collect();
        println!("\nper-completion streaming cost (crossing cost x frame count, over native):");
        println!("{:<22} {:>14} {:>14}", "arm", "300 frames", "2000 frames");
        for (i, name) in n.iter().enumerate() {
            if i == 0 {
                continue;
            }
            let d = med[i] - med[0];
            println!(
                "{:<22} {:>11.1} us {:>11.1} us",
                name,
                d * 300.0 / 1000.0,
                d * 2000.0 / 1000.0
            );
        }
    }
}
