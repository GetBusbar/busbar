// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE EXPORT KIND'S SCRIPT (B.5 export v3: `deliver`, `scrape`, `status`, `check`, `serve`).
//! Inputs (`conformance.json`):
//!
//! ```json
//! { "settings": <the settings it opens over>,
//!   <export>: {        (the section under the kind's config root key, `Kind::Export`)
//!     "bad_settings": [ { "settings": <settings validate must refuse>,
//!                         "refusal": "<text the refusal carries>" }, ... ],
//!     "deliver": [ { "stream": "<an ExportStream token, e.g. logs>",
//!                    "batch": "<the JSON-lines batch>",
//!                    "observed": ["<text the host's sink must observe for it>", ...] }, ... ],
//!     "scrape":  [ { "families": [ { "name": "..", "help": "..", "unit": "..",
//!                                    "kind": "counter|gauge|histogram|summary|untyped",
//!                                    "samples": [ { "name": "..", "labels": [["k", "v"], ...],
//!                                                   "value": ".." } ] } ],
//!                    "cap": <the host's first buffer, bytes; default 65536>,
//!                    "exposition": "<the text it renders ('' for a push sink)>" }, ... ],
//!     "status":  { "outcome": "Ready|Refused|Failed" },                       (default Ready)
//!     "check":   { "instances": [ { "name": "..", "settings": <..> } ],       (default: one,
//!                  "outcome": "Ready|..." },                                    the settings)
//!     "serve":   [ { "method": "GET", "path": "/exports/<name>/..", "query": "..",
//!                    "body": "..", "outcome": "Ready|...", "status_code": <n> }, ... ] } }
//! ```
//!
//! Every step is ONE ticket-less crossing of the export table (`Plugin::call`), but:
//! * `facts` and `own leases` read the host's own record: 0;
//! * `deliver unopened` and `deliver after close`: the host answers an unopened (REFUSED) or a
//!   closed (FAULT) instance's kind op without a crossing: 0;
//! * a `scrape` whose `exposition` is longer than its `cap`: the call answers SHORT and earns the
//!   ONE re-call into a buffer of the size it named: 2;
//! * `ready`: [`super::ready_step`]'s pin.
//!
//! A plugin-owned result (`status`, `check`'s findings, `serve`'s response: memory class iv) that
//! answers under a lease is read, then released: its `release <op>` step is one crossing.
//!
//! WHAT THE HOST OBSERVES IS THE ANSWER: every step's line ends with every envelope entry the
//! host's sink ingested during it (metrics, diagnostics, log records, drops), so an export op
//! whose effect is host-written (a delivery's record, a dropped line naming why) is compared
//! across the two legs, and the kind's contract asserts the `observed` texts.

use std::sync::{Arc, Mutex, PoisonError};

use busbar_contract::abi::export::{
    self, CheckIn, CheckInstance, CheckOut, DeliverIn, ExportStream, ScrapeFamily, ScrapeIn,
    ScrapeLabel, ScrapeOut, ScrapeSample, ServeIn, ServeOut, StatusOut, CHECK_PHASE_INSTANCES,
    CHECK_PHASE_LIMITS, SCRAPE_KIND_COUNTER, SCRAPE_KIND_GAUGE, SCRAPE_KIND_HISTOGRAM,
    SCRAPE_KIND_SUMMARY, SCRAPE_KIND_UNTYPED,
};
use busbar_contract::abi::mechanism::call::{
    AbiStr, Blob, InHead, OutHead, BLOB_JSON, BLOB_JSONL, BLOB_OCTETS,
};

use super::{
    bind, called, close, crossings, dispatcher, input, load, open, output, ready_step, refresh,
    release, tick, validate, Fold, Leg, Recorder, Subject,
};
use crate::dispatch::kinds::export::Export;
use crate::dispatch::{Bind, Diagnostic, Dropped, EnvelopeSink, Frame, Metric, Plugin, NO_BLOB};

/// This kind's section of the plugin's `conformance.json`, and its instance label: the kind's
/// config root key, read off the kind list (`busbar_contract::plugin::Kind::verb`).
const ROOT: &str = match busbar_contract::plugin::Kind::Export.root_key() {
    Some(key) => key,
    None => panic!("the export kind has a config root key"),
};

/// The host's first `scrape` buffer when the inputs name none (the kernel's 64 KiB).
const SCRAPE_CAP: usize = 64 * 1024;

/// THE HOST'S SINK, recorded: every envelope entry the host ingested, as text, in order.
#[derive(Default)]
struct Tape(Mutex<Vec<String>>);

impl Tape {
    fn push(&self, line: String) {
        self.0
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push(line);
    }

    /// What the host observed since the last read.
    fn seen(&self) -> String {
        let mut held = self.0.lock().unwrap_or_else(PoisonError::into_inner);
        let seen = held.join(" | ");
        held.clear();
        seen
    }
}

impl EnvelopeSink for Tape {
    fn metric(&self, m: Metric<'_>) {
        let labels: Vec<_> = m
            .labels
            .iter()
            .map(|l| String::from_utf8_lossy(l))
            .collect();
        self.push(format!(
            "metric {} {} {} {labels:?}",
            m.family, m.kind, m.value
        ));
    }
    fn diag(&self, d: Diagnostic<'_>) {
        self.push(format!(
            "diag {} {} {}",
            String::from_utf8_lossy(d.name),
            d.severity,
            String::from_utf8_lossy(d.text)
        ));
    }
    fn dropped(&self, why: Dropped) {
        self.push(format!("dropped {why:?}"));
    }
}

/// The text of a settings-like input: a string as is, anything else as its JSON.
fn text(v: &serde_json::Value) -> Vec<u8> {
    match v {
        serde_json::Value::String(s) => s.as_bytes().to_vec(),
        serde_json::Value::Null => panic!("conformance.json: an export input is missing"),
        other => other.to_string().into_bytes(),
    }
}

/// The input's string at `key`, `""` when absent.
fn field<'v>(v: &'v serde_json::Value, key: &str) -> &'v str {
    v.get(key).and_then(serde_json::Value::as_str).unwrap_or("")
}

/// The outcome an input expects (`"outcome"`), `Ready` when it names none.
fn expected(v: &serde_json::Value) -> String {
    v.get("outcome")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("Ready")
        .to_string()
}

/// Borrowed bytes; NULL when empty (absent).
fn lend(s: &str) -> AbiStr {
    AbiStr {
        ptr: if s.is_empty() {
            std::ptr::null()
        } else {
            s.as_ptr()
        },
        len: s.len(),
    }
}

fn blob(bytes: &[u8], fmt: u32) -> Blob {
    if bytes.is_empty() {
        return NO_BLOB;
    }
    Blob {
        ptr: bytes.as_ptr(),
        len: bytes.len(),
        fmt,
        flags: 0,
    }
}

/// `len` bytes at `ptr`, copied (`""` for none).
///
/// # Safety
/// `ptr`/`len` are a plugin-owned result the dispatcher's kind check judged, live under its
/// lease, which has not been released.
unsafe fn copied(ptr: *const u8, len: usize) -> String {
    if ptr.is_null() || len == 0 {
        return String::new();
    }
    // SAFETY: the caller's.
    String::from_utf8_lossy(unsafe { std::slice::from_raw_parts(ptr, len) }).into_owned()
}

/// A list's pointer; NULL when empty.
fn list<T>(v: &[T]) -> *const T {
    if v.is_empty() {
        std::ptr::null()
    } else {
        v.as_ptr()
    }
}

/// The scrape snapshot an input names, lowered onto the ABI's shapes. The strings stay the
/// inputs'; the arrays are held here for the call.
struct Snapshot {
    _labels: Vec<Vec<ScrapeLabel>>,
    _samples: Vec<Vec<ScrapeSample>>,
    families: Vec<ScrapeFamily>,
}

fn snapshot(families: &serde_json::Value) -> Snapshot {
    let families: &[serde_json::Value] = families.as_array().map_or(&[][..], Vec::as_slice);
    let mut labels = Vec::new();
    for f in families {
        for s in f
            .get("samples")
            .and_then(serde_json::Value::as_array)
            .into_iter()
            .flatten()
        {
            let pairs: Vec<ScrapeLabel> = s
                .get("labels")
                .and_then(serde_json::Value::as_array)
                .into_iter()
                .flatten()
                .map(|kv| ScrapeLabel {
                    key: lend(kv.get(0).and_then(serde_json::Value::as_str).unwrap_or("")),
                    value: lend(kv.get(1).and_then(serde_json::Value::as_str).unwrap_or("")),
                })
                .collect();
            labels.push(pairs);
        }
    }
    let mut at = 0;
    let mut samples = Vec::new();
    for f in families {
        let mut row = Vec::new();
        for s in f
            .get("samples")
            .and_then(serde_json::Value::as_array)
            .into_iter()
            .flatten()
        {
            row.push(ScrapeSample {
                name: lend(field(s, "name")),
                labels: list(&labels[at]),
                labels_len: labels[at].len(),
                value: lend(field(s, "value")),
            });
            at += 1;
        }
        samples.push(row);
    }
    let lowered = families
        .iter()
        .zip(&samples)
        .map(|(f, s)| ScrapeFamily {
            name: lend(field(f, "name")),
            help: lend(field(f, "help")),
            unit: lend(field(f, "unit")),
            kind: match field(f, "kind") {
                "counter" => SCRAPE_KIND_COUNTER,
                "gauge" => SCRAPE_KIND_GAUGE,
                "histogram" => SCRAPE_KIND_HISTOGRAM,
                "summary" => SCRAPE_KIND_SUMMARY,
                "untyped" | "" => SCRAPE_KIND_UNTYPED,
                other => panic!("conformance.json: export.scrape kind '{other}'"),
            },
            _reserved: [0; 7],
            samples: list(s),
            samples_len: s.len(),
        })
        .collect();
    Snapshot {
        _labels: labels,
        _samples: samples,
        families: lowered,
    }
}

/// One `deliver` of `batch` on `stream`.
fn deliver(p: &Plugin<Export>, stream: u8, batch: &[u8], n: u8) -> String {
    let mut f: Frame<DeliverIn, OutHead> = Frame::new(input(), output());
    f.input.op_id = [n; 16];
    f.input.stream = stream;
    f.input.batch = blob(batch, BLOB_JSONL);
    called(&p.call(export::slot::DELIVER, &mut f))
}

/// One `scrape` over `families` into a host buffer of `cap` bytes, and the ONE re-call a short
/// answer earns, into a buffer of the size it named: its line (whether it was re-called, what it
/// wrote and whether that is `exposition`).
fn scrape(p: &Plugin<Export>, families: &[ScrapeFamily], cap: usize, exposition: &[u8]) -> String {
    let mut buf = vec![0_u8; cap];
    let mut f: Frame<ScrapeIn, ScrapeOut> = Frame::new(input(), output());
    f.input.families = list(families);
    f.input.families_len = families.len();
    f.input.buf = buf.as_mut_ptr();
    f.input.cap = buf.len();
    let mut c = p.call(export::slot::SCRAPE, &mut f);
    let needed = f.out.needed;
    let recalled = if let Some(token) = c.recall.take() {
        buf = vec![0_u8; needed];
        f.input.buf = buf.as_mut_ptr();
        f.input.cap = buf.len();
        f.out = output();
        c = p.recall(token, export::slot::SCRAPE, &mut f);
        true
    } else {
        false
    };
    let written = f.out.written.min(buf.len());
    format!(
        "{} recalled={recalled} needed={needed} written={written} equal={}",
        called(&c),
        &buf[..written] == exposition
    )
}

/// `status`: its line and its lease, still held.
fn status(p: &Plugin<Export>) -> (String, u64) {
    let mut f: Frame<InHead, StatusOut> = Frame::new(input(), output());
    let c = p.call(export::slot::STATUS, &mut f);
    // SAFETY: the plugin's status blob, judged by `check_status`, live under the lease.
    let body = unsafe { copied(f.out.status.ptr, f.out.status.len) };
    (format!("{} status={body:?}", called(&c)), c.lease)
}

/// `check` at `phase` across `instances`: its line and its lease, still held.
fn check(p: &Plugin<Export>, phase: u32, instances: &[CheckInstance]) -> (String, u64) {
    let mut f: Frame<CheckIn, CheckOut> = Frame::new(input(), output());
    f.input.phase = phase;
    f.input.instances = list(instances);
    f.input.instances_len = instances.len();
    let c = p.call(export::slot::CHECK, &mut f);
    // SAFETY: the plugin's findings blob, judged by `check_check`, live under the lease.
    let findings = unsafe { copied(f.out.findings.ptr, f.out.findings.len) };
    (format!("{} findings={findings:?}", called(&c)), c.lease)
}

/// One `serve` of the request `r` names: its line (code, headers, body) and its lease, still held.
fn serve(p: &Plugin<Export>, r: &serde_json::Value) -> (String, u64) {
    let body = field(r, "body");
    let mut f: Frame<ServeIn, ServeOut> = Frame::new(input(), output());
    f.input.method = lend(match field(r, "method") {
        "" => "GET",
        m => m,
    });
    f.input.path = lend(field(r, "path"));
    f.input.query = lend(field(r, "query"));
    f.input.body = blob(body.as_bytes(), BLOB_OCTETS);
    let c = p.call(export::slot::SERVE, &mut f);
    let headers: Vec<String> = if f.out.headers_out.is_null() || f.out.headers_out_len == 0 {
        Vec::new()
    } else {
        // SAFETY: `check_serve` bounded the list and refused a count behind NULL; it and every
        // string in it live under the lease.
        unsafe { std::slice::from_raw_parts(f.out.headers_out, f.out.headers_out_len) }
            .iter()
            // SAFETY: as above.
            .map(|h| unsafe { copied(h.ptr, h.len) })
            .collect()
    };
    // SAFETY: the response body, judged by `check_serve`, live under the lease.
    let out = unsafe { copied(f.out.body.ptr, f.out.body.len) };
    (
        format!(
            "{} code={} headers={headers:?} body={out:?}",
            called(&c),
            f.out.status_code
        ),
        c.lease,
    )
}

/// The stream a `deliver` input names.
fn stream(d: &serde_json::Value) -> u8 {
    let tok = field(d, "stream");
    ExportStream::from_token(tok).unwrap_or_else(|| {
        panic!(
            "conformance.json: export.deliver stream '{tok}' (the streams are {})",
            ExportStream::vocabulary()
        )
    }) as u8
}

pub(super) fn fold(s: &Subject, leg: Leg) -> Fold {
    let k = s.kind_inputs(ROOT);
    assert!(k.is_object(), "conformance.json has no `export` inputs");
    let settings = s.settings();
    let empty = Vec::new();
    let arr = |key: &str| {
        k.get(key)
            .and_then(serde_json::Value::as_array)
            .unwrap_or(&empty)
    };
    let bad = arr("bad_settings");
    assert!(
        !bad.is_empty(),
        "conformance.json: export.bad_settings is empty"
    );
    let delivers = arr("deliver");
    assert!(
        !delivers.is_empty(),
        "conformance.json: export.deliver is empty"
    );
    let scrapes = arr("scrape");
    let serves = arr("serve");
    let snapshots: Vec<Snapshot> = scrapes.iter().map(|sc| snapshot(&sc["families"])).collect();
    // The script's own `check.instances`, else the one `conformance` instance over the subject's
    // settings (built as the pair it is read into, never as a JSON body carrying a settings bag).
    let instance_settings: Vec<(String, Vec<u8>)> =
        match k.get("check").and_then(|c| c.get("instances")) {
            Some(list) => list
                .as_array()
                .map_or(&[][..], Vec::as_slice)
                .iter()
                .map(|i| (field(i, "name").to_string(), text(&i["settings"])))
                .collect(),
            None => vec![("conformance".to_string(), settings.clone())],
        };
    let instances: Vec<CheckInstance> = instance_settings
        .iter()
        .map(|(name, set)| CheckInstance {
            name: lend(name),
            settings: blob(set, BLOB_JSON),
        })
        .collect();

    let d = dispatcher();
    let tape = Arc::new(Tape::default());
    let b = Bind {
        sink: tape.clone(),
        ..bind(&d, ROOT)
    };
    let p = load::<Export>(s, leg, b).expect("the export door loads");
    let mut r = Recorder::new(crossings(&p));
    // Every line ends with what the host's sink observed while the step ran.
    let host = |line: String| format!("{line} host=[{}]", tape.seen());
    r.line("facts", 0, || {
        host(format!(
            "{:?} {} max_inflight={}",
            p.kind(),
            p.name(),
            p.max_inflight()
        ))
    });
    for (i, b) in bad.iter().enumerate() {
        r.line(&format!("validate bad #{i}"), 1, || {
            host(called(&validate(&p, &text(&b["settings"]))))
        });
    }
    r.line("validate", 1, || host(called(&validate(&p, &settings))));
    // The host refuses an unopened instance's kind op before any crossing.
    r.line("deliver unopened", 0, || {
        let d0 = &delivers[0];
        host(deliver(&p, stream(d0), &text(&d0["batch"]), 0))
    });
    r.line("open", 1, || host(called(&open(&p, &settings))));
    ready_step(&mut r, s, &p, &d);
    for (i, dl) in delivers.iter().enumerate() {
        r.line(&format!("deliver #{i}"), 1, || {
            host(deliver(&p, stream(dl), &text(&dl["batch"]), i as u8 + 1))
        });
    }
    for (i, (sc, snap)) in scrapes.iter().zip(&snapshots).enumerate() {
        let cap = sc
            .get("cap")
            .and_then(serde_json::Value::as_u64)
            .map_or(SCRAPE_CAP, |c| c as usize);
        let exposition = field(sc, "exposition").as_bytes();
        // A rendering longer than the host's buffer answers SHORT: the ONE re-call is +1.
        let pinned = if exposition.len() > cap { 2 } else { 1 };
        r.line(&format!("scrape #{i}"), pinned, || {
            host(scrape(&p, &snap.families, cap, exposition))
        });
    }
    let mut leases = Vec::new();
    let mut leased = |r: &mut Recorder<'_>, label: &str, f: &dyn Fn() -> (String, u64)| {
        let lease = r.step(label, 1, || {
            let (line, lease) = f();
            (host(line), lease)
        });
        if lease != 0 {
            leases.push((format!("release {label}"), lease));
        }
    };
    leased(&mut r, "status", &|| status(&p));
    leased(&mut r, "check limits", &|| {
        check(&p, CHECK_PHASE_LIMITS, &instances)
    });
    leased(&mut r, "check instances", &|| {
        check(&p, CHECK_PHASE_INSTANCES, &instances)
    });
    for (i, sv) in serves.iter().enumerate() {
        leased(&mut r, &format!("serve #{i}"), &|| serve(&p, sv));
    }
    r.line("own leases", 0, || {
        let mut ids: Vec<u64> = leases.iter().map(|l| l.1).collect();
        ids.sort_unstable();
        ids.dedup();
        format!("distinct={}", ids.len() == leases.len())
    });
    for (label, lease) in &leases {
        r.line(label, 1, || host(called(&release(&p, *lease))));
    }
    if let Some((_, first)) = leases.first() {
        r.line("release again", 1, || host(called(&release(&p, *first))));
    }
    r.line("tick", 1, || {
        let (c, next) = tick(&p, 1);
        host(format!("{} next={next}", called(&c)))
    });
    r.line("refresh bad", 1, || {
        host(called(&refresh(&p, &text(&bad[0]["settings"]))))
    });
    r.line("refresh", 1, || host(called(&refresh(&p, &settings))));
    r.line("deliver after refresh", 1, || {
        let d0 = &delivers[0];
        host(deliver(&p, stream(d0), &text(&d0["batch"]), 0xfe))
    });
    r.line("close", 1, || host(called(&close(&p))));
    // A closed instance answers FAULT without a crossing.
    r.line("deliver after close", 0, || {
        let d0 = &delivers[0];
        host(deliver(&p, stream(d0), &text(&d0["batch"]), 0xff))
    });
    let fold = r.fold();
    contract(&fold, k);
    fold
}

/// THE KIND'S CONTRACT over the fold, so two equal folds of failures prove nothing: the good
/// settings validate, open, refresh and close READY; each refused settings FAILS naming why; a
/// delivery is READY and the host observes what the inputs say it observes, again after a
/// refresh; a scrape renders exactly the inputs' exposition; `status`, `check` and `serve` answer
/// as the inputs say; every lease is its own and is released once; an unopened or closed instance
/// serves nothing.
fn contract(fold: &Fold, k: &serde_json::Value) {
    let at = |label: &str| {
        fold.iter()
            .find(|s| s.label == label)
            .map(|s| s.answer.as_str())
            .unwrap_or_else(|| panic!("the script ran no step '{label}'"))
    };
    let empty = Vec::new();
    let arr = |key: &str| {
        k.get(key)
            .and_then(serde_json::Value::as_array)
            .unwrap_or(&empty)
    };
    for label in ["validate", "open", "tick", "refresh", "close"] {
        assert!(at(label).starts_with("Ready "), "{label}: {}", at(label));
    }
    for (i, b) in arr("bad_settings").iter().enumerate() {
        let line = at(&format!("validate bad #{i}"));
        assert!(
            line.starts_with("Failed lease=false ")
                && !line.starts_with("Failed lease=false  host="),
            "a refused validate names why: {line}"
        );
        let refusal = field(b, "refusal");
        assert!(
            line.contains(refusal),
            "validate bad #{i}: {refusal:?} not in {line}"
        );
    }
    for (label, dl) in arr("deliver")
        .iter()
        .enumerate()
        .map(|(i, dl)| (format!("deliver #{i}"), dl))
        .chain(std::iter::once((
            "deliver after refresh".to_string(),
            &arr("deliver")[0],
        )))
    {
        let line = at(&label);
        assert!(line.starts_with("Ready lease=false "), "{label}: {line}");
        let seen = line.split_once(" host=[").map_or("", |(_, h)| h);
        for want in dl
            .get("observed")
            .and_then(serde_json::Value::as_array)
            .into_iter()
            .flatten()
        {
            let want = want.as_str().unwrap_or_default();
            assert!(
                seen.contains(want),
                "{label}: the host did not observe {want:?}: {line}"
            );
        }
    }
    for i in 0..arr("scrape").len() {
        let line = at(&format!("scrape #{i}"));
        assert!(
            line.starts_with("Ready lease=false ") && line.contains(" equal=true "),
            "scrape #{i} renders the inputs' exposition: {line}"
        );
    }
    let want = |v: Option<&serde_json::Value>| v.map_or("Ready".to_string(), expected);
    let status = want(k.get("status"));
    assert!(
        at("status").starts_with(&format!("{status} ")),
        "status: {}",
        at("status")
    );
    let check = want(k.get("check"));
    for label in ["check limits", "check instances"] {
        assert!(
            at(label).starts_with(&format!("{check} ")),
            "{label}: {}",
            at(label)
        );
    }
    for (i, sv) in arr("serve").iter().enumerate() {
        let line = at(&format!("serve #{i}"));
        assert!(
            line.starts_with(&format!("{} ", expected(sv))),
            "serve #{i}: {line}"
        );
        if let Some(code) = sv.get("status_code").and_then(serde_json::Value::as_u64) {
            assert!(
                line.contains(&format!(" code={code} ")),
                "serve #{i}: {line}"
            );
        }
    }
    assert_eq!(
        at("own leases"),
        "distinct=true",
        "each leased result has its own lease"
    );
    for s in fold
        .iter()
        .filter(|s| s.label.starts_with("release ") && s.label != "release again")
    {
        assert!(s.answer.starts_with("Ready "), "{}: {}", s.label, s.answer);
    }
    if fold.iter().any(|s| s.label == "release again") {
        assert!(
            at("release again").starts_with("Refused "),
            "{}",
            at("release again")
        );
    }
    for label in ["deliver unopened", "deliver after close"] {
        assert!(!at(label).starts_with("Ready"), "{label}: {}", at(label));
    }
}
