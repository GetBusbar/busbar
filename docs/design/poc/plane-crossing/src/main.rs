// SPDX-License-Identifier: Apache-2.0
//! THE PROTOCOL CROSSING, MEASURED AGAINST REAL LIBRARIES.
//!
//! The in-tree `marshal_cost_tests.rs` hand-rolls its zero-copy side with a bare
//! offset table. That measures the CLASS but flatters it in two specific ways
//! this harness removes:
//!   1. it never builds the buffer inside the measurement, so the "the serialize
//!      step must vanish" claim is asserted rather than tested;
//!   2. it never VERIFIES the buffer, and an unverified zero-copy read of a
//!      buffer authored by an untrusted plugin is unsound by construction.
//!
//! So this harness uses flatc-generated FlatBuffers code (real vtable
//! indirection, real verifier), real rkyv, and a real dlopen'd cdylib for the
//! bare cross-DSO floor.
//!
//! ## WHAT THIS HARNESS DOES **NOT** MEASURE — read this before quoting a number
//!
//! The `fb`/`rkyv`/`L1 facts` columns time **VERIFY + READ ONLY**. The buffers
//! are built OUTSIDE the timing loop, so no allocation, no `memcpy`, no free and
//! no DSO transit is inside the measured region. **They are half a crossing.**
//!
//! The frozen transport contract is *plugin allocates -> host copies out -> host
//! calls `busbar_free`*, and that copy is O(bytes) by construction no matter how
//! little of the buffer the host then reads. `perf/1.6.0-plugin-abi-measurement`
//! measures that half and puts it at ~0.03 ns/byte.
//!
//! So a flat column HERE does not mean a flat crossing. It means the read is
//! bounded. Getting a flat CROSSING additionally requires borrow-not-copy
//! transport -- see PART 3.10 of `docs/design/1.6.0-plane-abi-two-layer.md`.
//! An earlier draft of that document quoted these figures as end-to-end crossing
//! costs, and this comment exists so nobody does it again.
//!
//! EVERY NUMBER IS RELEASE PROFILE. Debug is ~16x and exists in no shipped build.

#[allow(clippy::all, unused_imports, dead_code)]
#[path = "ir_generated.rs"]
mod ir_generated;
use ir_generated::zcir;

#[allow(clippy::all, unused_imports, dead_code)]
#[path = "facts_generated.rs"]
mod facts_generated;
use facts_generated::zcfacts;

use serde::{Deserialize, Serialize};
use std::time::Instant;

// ---------------------------------------------------------------- payload

const PROSE: &str = "Summarise the attached incident report and list the load-bearing facts. \
                     Prefer evidence over assertion, and name the file and line for each claim.";

#[derive(Clone)]
struct Src {
    model: String,
    max_tokens: u32,
    stream: bool,
    system: String,
    end_user: String,
    messages: Vec<(String, Vec<String>)>,
    tools: Vec<(String, String, String)>,
}

fn source(turns: usize) -> Src {
    Src {
        model: "claude-sonnet-4".into(),
        max_tokens: 4096,
        stream: true,
        system: "You are a careful assistant. Prefer evidence over assertion.".into(),
        end_user: "user-8f21c3".into(),
        messages: (0..turns)
            .map(|i| {
                (
                    if i % 2 == 0 { "user" } else { "assistant" }.to_string(),
                    vec![PROSE.to_string()],
                )
            })
            .collect(),
        tools: vec![(
            "search_incidents".into(),
            "Search the incident database by free text and date range.".into(),
            r#"{"type":"object","properties":{"query":{"type":"string"},"since":{"type":"string"},"limit":{"type":"integer"}},"required":["query"]}"#.into(),
        )],
    }
}

// ------------------------------------------------------------------- JSON

#[derive(Serialize, Deserialize)]
struct JBlock { r#type: String, text: String }
#[derive(Serialize, Deserialize)]
struct JMsg { role: String, content: Vec<JBlock> }
#[derive(Serialize, Deserialize)]
struct JTool { name: String, description: String, input_schema: serde_json::Value }
#[derive(Serialize, Deserialize)]
struct JReq {
    model: String,
    max_tokens: u32,
    stream: bool,
    system: String,
    end_user: String,
    messages: Vec<JMsg>,
    tools: Vec<JTool>,
}

fn to_jreq(s: &Src) -> JReq {
    JReq {
        model: s.model.clone(),
        max_tokens: s.max_tokens,
        stream: s.stream,
        system: s.system.clone(),
        end_user: s.end_user.clone(),
        messages: s.messages.iter().map(|(r, c)| JMsg {
            role: r.clone(),
            content: c.iter().map(|t| JBlock { r#type: "text".into(), text: t.clone() }).collect(),
        }).collect(),
        tools: s.tools.iter().map(|(n, d, sc)| JTool {
            name: n.clone(),
            description: d.clone(),
            input_schema: serde_json::from_str(sc).unwrap(),
        }).collect(),
    }
}

// ------------------------------------------------------------ FlatBuffers

/// The plugin's NATIVE OUTPUT: it writes the archived buffer directly. There is
/// no struct-then-encode step, which is the whole point of the claim under test.
fn fb_build(s: &Src) -> Vec<u8> {
    let mut b = flatbuffers::FlatBufferBuilder::with_capacity(64 * 1024);
    let model = b.create_string(&s.model);
    let system = b.create_string(&s.system);
    let end_user = b.create_string(&s.end_user);

    let tools: Vec<_> = s.tools.iter().map(|(n, d, sc)| {
        let n = b.create_string(n);
        let d = b.create_string(d);
        let sc = b.create_string(sc);
        zcir::Tool::create(&mut b, &zcir::ToolArgs {
            name: Some(n), description: Some(d), input_schema: Some(sc),
        })
    }).collect();
    let tools = b.create_vector(&tools);

    let msgs: Vec<_> = s.messages.iter().map(|(r, c)| {
        let blocks: Vec<_> = c.iter().map(|t| {
            let t = b.create_string(t);
            zcir::TextBlock::create(&mut b, &zcir::TextBlockArgs { text: Some(t) })
        }).collect();
        let blocks = b.create_vector(&blocks);
        let r = b.create_string(r);
        zcir::Message::create(&mut b, &zcir::MessageArgs {
            role: Some(r), content: Some(blocks),
        })
    }).collect();
    let msgs = b.create_vector(&msgs);

    let root = zcir::ChatReq::create(&mut b, &zcir::ChatReqArgs {
        model: Some(model),
        max_tokens: s.max_tokens,
        stream: s.stream,
        system: Some(system),
        messages: Some(msgs),
        tools: Some(tools),
        end_user: Some(end_user),
    });
    b.finish(root, None);
    b.finished_data().to_vec()
}

/// EXACTLY the `IrFacts` surface core actually reads: verb/shape are implied by
/// the root type, plus wants_stream, end_user, and enough of content to route.
#[inline]
fn read_facts(r: &zcir::ChatReq) -> usize {
    let mut acc = 0usize;
    acc += r.model().map_or(0, |m| m.len());
    acc += r.max_tokens() as usize;
    acc += r.stream() as usize;
    acc += r.end_user().map_or(0, |e| e.len());
    if let Some(ms) = r.messages() {
        acc += ms.len();
        if !ms.is_empty() {
            let m0 = ms.get(0);
            acc += m0.role().map_or(0, |x| x.len());
            if let Some(c) = m0.content() {
                if !c.is_empty() {
                    acc += c.get(0).text().map_or(0, |t| t.len());
                }
            }
        }
    }
    acc
}

// ------------------------------------------- THE DECISIVE VARIANT: FACTS+BODY

/// LAYER 1 as a wire object: the plane writes the small OPEN facts table, and
/// the request body rides beside it as an untraversed `[ubyte]` vector.
///
/// The bet under test: FlatBuffers' verifier TRAVERSES strings, tables and
/// tables-vectors, but only RANGE-CHECKS a scalar vector. So verifying this
/// should be O(size of the facts), not O(size of the payload) — which would
/// make a SOUND (verified) crossing flat in payload bytes, the thing the
/// unverified read gets only by being unsound.
fn facts_build(s: &Src, body: &[u8]) -> Vec<u8> {
    let mut b = flatbuffers::FlatBufferBuilder::with_capacity(body.len() + 4096);
    let verb = b.create_string("chat");
    let end_user = b.create_string(&s.end_user);
    let shape = b.create_string("messages");
    let model = b.create_string(&s.model);
    let body = b.create_vector(body);
    let root = zcfacts::Facts::create(&mut b, &zcfacts::FactsArgs {
        verb: Some(verb),
        wants_stream: s.stream,
        end_user: Some(end_user),
        shape: Some(shape),
        model: Some(model),
        n_parts: s.messages.len() as u32,
        body: Some(body),
    });
    b.finish(root, None);
    b.finished_data().to_vec()
}

/// Everything core reads, and it reads the body only as ptr+len — it never
/// walks it, because forwarding is not reading.
#[inline]
fn read_layer1(f: &zcfacts::Facts) -> usize {
    let mut acc = 0usize;
    acc += f.verb().map_or(0, |v| v.len());
    acc += f.wants_stream() as usize;
    acc += f.end_user().map_or(0, |e| e.len());
    acc += f.shape().map_or(0, |x| x.len());
    acc += f.model().map_or(0, |m| m.len());
    acc += f.n_parts() as usize;
    acc += f.body().map_or(0, |b| b.len()); // range, not contents
    acc
}

// ------------------------------------------------------------------- rkyv

#[derive(rkyv::Archive, rkyv::Serialize)]
struct RBlock { text: String }
#[derive(rkyv::Archive, rkyv::Serialize)]
struct RMsg { role: String, content: Vec<RBlock> }
#[derive(rkyv::Archive, rkyv::Serialize)]
struct RReq {
    model: String,
    max_tokens: u32,
    stream: bool,
    system: String,
    end_user: String,
    messages: Vec<RMsg>,
}

fn to_rreq(s: &Src) -> RReq {
    RReq {
        model: s.model.clone(),
        max_tokens: s.max_tokens,
        stream: s.stream,
        system: s.system.clone(),
        end_user: s.end_user.clone(),
        messages: s.messages.iter().map(|(r, c)| RMsg {
            role: r.clone(),
            content: c.iter().map(|t| RBlock { text: t.clone() }).collect(),
        }).collect(),
    }
}

#[inline]
fn read_facts_rkyv(a: &ArchivedRReq) -> usize {
    let mut acc = a.model.len() + a.max_tokens.to_native() as usize + a.stream as usize
        + a.end_user.len() + a.messages.len();
    if let Some(m0) = a.messages.first() {
        acc += m0.role.len();
        if let Some(c0) = m0.content.first() { acc += c0.text.len(); }
    }
    acc
}

// -------------------------------------------------------------------- DSO

struct Dso {
    noop: unsafe extern "C" fn(u64) -> u64,
    read: unsafe extern "C" fn(*const u8, usize, *const usize, usize) -> u64,
}

fn load_dso(path: &str) -> Dso {
    unsafe {
        let c = std::ffi::CString::new(path).unwrap();
        let h = libc::dlopen(c.as_ptr(), libc::RTLD_NOW);
        assert!(!h.is_null(), "dlopen failed for {path}");
        let g = |n: &str| {
            let s = std::ffi::CString::new(n).unwrap();
            let p = libc::dlsym(h, s.as_ptr());
            assert!(!p.is_null(), "dlsym failed for {n}");
            p
        };
        Dso {
            noop: std::mem::transmute(g("zc_noop")),
            read: std::mem::transmute(g("zc_read_offsets")),
        }
    }
}

// ------------------------------------------------------------- timing rig

/// Run `f` `iters` times, `reps` times over, and return per-op nanos for each
/// rep. Reporting the SPREAD is the point: under machine contention a point
/// estimate is a fiction, and the orchestrator asked for variance explicitly.
fn bench<F: FnMut()>(reps: usize, iters: u32, mut f: F) -> Vec<f64> {
    // warm
    for _ in 0..(iters / 10).max(1) { f(); }
    (0..reps).map(|_| {
        let t = Instant::now();
        for _ in 0..iters { f(); }
        t.elapsed().as_nanos() as f64 / f64::from(iters)
    }).collect()
}

struct Stat { min: f64, med: f64, max: f64 }
fn stat(mut v: Vec<f64>) -> Stat {
    v.sort_by(|a, b| a.partial_cmp(b).unwrap());
    Stat { min: v[0], med: v[v.len() / 2], max: v[v.len() - 1] }
}
/// min is the least contaminated estimate under contention; spread is the honesty column.
fn cell(s: &Stat) -> String {
    format!("{:>10.1} [{:.1}-{:.1}]", s.med, s.min, s.max)
}

fn loadavg() -> String {
    let mut l = [0f64; 3];
    unsafe { libc::getloadavg(l.as_mut_ptr(), 3); }
    format!("{:.2} {:.2} {:.2}", l[0], l[1], l[2])
}

fn main() {
    let dso_path = std::env::args().nth(1).expect("usage: zcpoc <path-to-libzcdso.dylib>");
    let dso = load_dso(&dso_path);
    let reps: usize = std::env::var("REPS").ok().and_then(|s| s.parse().ok()).unwrap_or(9);

    println!("== PROTOCOL VERIFY+READ COST — RELEASE PROFILE, lto=true, codegen-units=1 ==");
    println!("NOTE: buffers are prebuilt OUTSIDE the loop. These are the READ HALF of a");
    println!("      crossing: no alloc, no memcpy, no free, no DSO transit is timed.");
    println!("flatc {}, flatbuffers 25, rkyv 0.8", "25.12.19");
    println!("loadavg at start: {}", loadavg());
    println!("reps={reps}; each cell is  median [min-max]  ns/op\n");

    // ---- the bare linkage floor, across a real dlopen'd boundary
    let s0 = stat(bench(reps, 2_000_000, || { std::hint::black_box(unsafe { (dso.noop)(std::hint::black_box(7)) }); }));
    println!("bare cross-DSO extern \"C\" call : {} ns", cell(&s0));
    println!("  ^ this is the linkage cost. Everything below is what we PUT on it.\n");

    println!("{:<8} {:>8} {:>24} {:>24} {:>24} {:>24} {:>24} {:>24} {:>24}",
        "turns", "json B", "json Value crossing", "json typed crossing",
        "fb build (native out)", "fb read UNVERIFIED", "fb L2 read VERIFIED",
        "rkyv read VERIFIED", "** L1 FACTS VERIFIED **");

    // 2000 turns is ~400 KB — deliberately past L2, so a flat result cannot be
    // explained away as "the whole buffer was cache-resident".
    for turns in [1usize, 4, 12, 64, 320, 2000] {
        let s = source(turns);
        let jr = to_jreq(&s);
        let jbytes = serde_json::to_vec(&jr).unwrap();
        let n = jbytes.len();

        let fb = fb_build(&s);
        let rr = to_rreq(&s);
        let rb = rkyv::to_bytes::<rkyv::rancor::Error>(&rr).unwrap();

        let it_heavy = if n > 200_000 { 300 } else if n > 20_000 { 2_000 } else { 20_000 };
        let it_light = 200_000u32;

        // status quo: what plugin-abi does today (opaque Value on the host side)
        let a = stat(bench(reps, it_heavy, || {
            let b = serde_json::to_vec(&jr).unwrap();
            let v: serde_json::Value = serde_json::from_slice(&b).unwrap();
            std::hint::black_box(v);
        }));
        // fairest possible JSON: typed both ways
        let b_ = stat(bench(reps, it_heavy, || {
            let b = serde_json::to_vec(&jr).unwrap();
            let v: JReq = serde_json::from_slice(&b).unwrap();
            std::hint::black_box(v);
        }));
        // the plugin's native output step
        let c = stat(bench(reps, it_heavy, || { std::hint::black_box(fb_build(&s)); }));
        // the host crossing, unverified (O(1), but UNSOUND against a hostile plugin)
        let d = stat(bench(reps, it_light, || {
            let r = unsafe { zcir::root_as_chat_req_unchecked(&fb) };
            std::hint::black_box(read_facts(&r));
        }));
        // the host crossing, VERIFIED (what a trust boundary actually requires)
        let e = stat(bench(reps, it_light, || {
            let r = zcir::root_as_chat_req(&fb).unwrap();
            std::hint::black_box(read_facts(&r));
        }));
        // rkyv, validated
        let f = stat(bench(reps, it_light, || {
            let a = rkyv::access::<ArchivedRReq, rkyv::rancor::Error>(&rb).unwrap();
            std::hint::black_box(read_facts_rkyv(a));
        }));

        // THE DECISIVE ONE: verified, but only over Layer 1. Body is opaque.
        let fbody = facts_build(&s, &jbytes);
        let g = stat(bench(reps, it_light, || {
            let r = zcfacts::root_as_facts(&fbody).unwrap();
            std::hint::black_box(read_layer1(&r));
        }));

        println!("{:<8} {:>8} {:>24} {:>24} {:>24} {:>24} {:>24} {:>24} {:>24}",
            turns, n, cell(&a), cell(&b_), cell(&c), cell(&d), cell(&e), cell(&f), cell(&g));
        let _ = &fb;
    }

    // ---- the stream frame: the per-EVENT crossing, which multiplies by frame count
    let ev = serde_json::json!({
        "type": "content_block_delta", "index": 0,
        "delta": {"type": "text_delta", "text": " the"}
    });
    let evb = serde_json::to_vec(&ev).unwrap();
    let ejson = stat(bench(reps, 200_000, || {
        let b = serde_json::to_vec(&ev).unwrap();
        let v: serde_json::Value = serde_json::from_slice(&b).unwrap();
        std::hint::black_box(v);
    }));
    let small = source(1);
    let sfb = fb_build(&small);
    let offs: Vec<usize> = vec![0];
    let mut buf = Vec::new();
    buf.extend_from_slice(&(4u32).to_le_bytes());
    buf.extend_from_slice(b" the");
    let edso = stat(bench(reps, 500_000, || {
        std::hint::black_box(unsafe { (dso.read)(buf.as_ptr(), buf.len(), offs.as_ptr(), offs.len()) });
    }));
    let efb = stat(bench(reps, 500_000, || {
        let r = zcir::root_as_chat_req(&sfb).unwrap();
        std::hint::black_box(read_facts(&r));
    }));
    println!("\nstream frame ({} B):", evb.len());
    println!("  json crossing            : {} ns", cell(&ejson));
    println!("  offset read ACROSS DSO   : {} ns", cell(&edso));
    println!("  fb VERIFIED read (1-turn): {} ns", cell(&efb));

    println!("\nloadavg at end: {}", loadavg());
}
