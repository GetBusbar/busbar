// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors
//! The load driver: HTTP/1.1 keep-alive or h2c (prior knowledge) clients, closed-loop (N
//! concurrent requests) or open-loop (fixed arrival rate), with a warmup phase, HDR latency
//! histograms, per-second throughput windows and error accounting by status.
//!
//! Design rules, all for "the driver is never the bottleneck":
//! * one hyper client connection per worker (h1) or `streams` workers per connection (h2), no
//!   connection pool, no per-request allocation beyond the request head hyper needs;
//! * every worker owns its histogram and window counters; they are merged once at the end;
//! * request heads (URI, header map) and bodies (`Bytes`) are built once and cloned per send;
//! * open-loop arrivals come from one pacing thread that releases semaphore permits at the
//!   scheduled instants; latency is measured from the SCHEDULED start, so a stalled gateway shows
//!   up as latency rather than as a silently lower offered rate (no coordinated omission).

use crate::mock::llm::memfind;
use bytes::Bytes;
use hdrhistogram::Histogram;
use http::{HeaderMap, HeaderName, HeaderValue, Method, Request, Uri};
use http_body_util::{BodyExt, Full};
use hyper_util::rt::{TokioExecutor, TokioIo};
use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::net::TcpStream;
use tokio::sync::Semaphore;

/// Wire protocol to the target.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum Proto {
    #[default]
    H1,
    H2c,
}

/// One request the driver sends.
#[derive(Debug, Clone)]
pub struct Req {
    pub method: Method,
    /// Path and query.
    pub path: String,
    pub headers: Vec<(HeaderName, HeaderValue)>,
    pub body: Bytes,
    pub expect_status: u16,
    /// Bytes each response with `expect_status` must contain; every such body is checked. A miss
    /// counts as `body_miss` only for a request started in the measured window; warmup and later
    /// misses are only logged.
    pub expect_contains: Option<Vec<u8>>,
    /// Relative weight in the case's mix.
    pub weight: u32,
}

/// The traffic shape.
#[derive(Debug, Clone, Copy)]
pub enum Shape {
    /// `concurrency` requests always in flight.
    Closed { concurrency: usize },
    /// `rate` arrivals per second, at most `connections` in flight.
    Open { rate: f64, connections: usize },
}

impl Shape {
    pub fn describe(&self) -> String {
        match self {
            Shape::Closed { concurrency } => format!("c={concurrency}"),
            Shape::Open { rate, connections } => format!("{rate:.0}/s (<= {connections} conns)"),
        }
    }
}

/// Everything one driver run needs.
#[derive(Clone)]
pub struct Plan {
    pub addr: SocketAddr,
    pub proto: Proto,
    pub reqs: Vec<Req>,
    pub shape: Shape,
    /// Sends start at `start`; requests that start before `start + warmup` are not recorded.
    pub start: Instant,
    pub warmup: Duration,
    pub measure: Duration,
    pub timeout: Duration,
    /// h2c: in-flight streams per connection.
    pub h2_streams: usize,
}

impl Plan {
    pub fn measure_start(&self) -> Instant {
        self.start + self.warmup
    }
    pub fn end(&self) -> Instant {
        self.start + self.warmup + self.measure
    }
}

/// What a run measured: every request whose (scheduled) start is inside the measured window,
/// however late it completes (no coordinated omission).
#[derive(Debug)]
pub struct Outcome {
    /// Request latency, nanoseconds (open loop: from the scheduled start).
    pub latency: Histogram<u64>,
    /// Time to the first body chunk, nanoseconds.
    pub first_byte: Histogram<u64>,
    pub ok: u64,
    /// Failures by cause: `status 503`, `io`, `timeout`, `body`.
    pub errors: BTreeMap<String, u64>,
    /// Successful requests per one-second window of the measured phase, by start.
    pub windows: Vec<u64>,
    pub measured: Duration,
    /// Bodies checked against `expect_contains` in the measured window, and those that missed.
    pub body_total: u64,
    pub body_miss: u64,
}

impl Outcome {
    fn new(windows: usize) -> Self {
        Self {
            latency: hist(),
            first_byte: hist(),
            ok: 0,
            errors: BTreeMap::new(),
            windows: vec![0; windows],
            measured: Duration::ZERO,
            body_total: 0,
            body_miss: 0,
        }
    }

    fn merge(&mut self, o: Local) {
        let _ = self.latency.add(&o.latency);
        let _ = self.first_byte.add(&o.first_byte);
        self.ok += o.ok;
        for (k, v) in o.errors {
            *self.errors.entry(k).or_insert(0) += v;
        }
        for (i, w) in o.windows.iter().enumerate() {
            if let Some(slot) = self.windows.get_mut(i) {
                *slot += u64::from(*w);
            }
        }
        self.body_total += o.body_total;
        self.body_miss += o.body_miss;
    }

    /// Merge a joined worker; a panicked worker is counted under `worker panic` rather than
    /// dropped, and its message is returned for `first_error`.
    fn merge_join(&mut self, r: Result<Local, tokio::task::JoinError>) -> Option<String> {
        match r {
            Ok(local) => {
                self.merge(local);
                None
            }
            Err(e) => {
                *self.errors.entry("worker panic".into()).or_insert(0) += 1;
                Some(format!("worker panic: {e}"))
            }
        }
    }

    pub fn rps(&self) -> f64 {
        if self.measured.is_zero() {
            return 0.0;
        }
        self.ok as f64 / self.measured.as_secs_f64()
    }
}

/// 1 ns .. 10 min at 3 significant digits.
pub fn hist() -> Histogram<u64> {
    Histogram::new_with_bounds(1, 600_000_000_000, 3).expect("valid histogram bounds")
}

/// One worker's private tallies.
struct Local {
    latency: Histogram<u64>,
    first_byte: Histogram<u64>,
    ok: u64,
    errors: BTreeMap<String, u64>,
    windows: Vec<u32>,
    body_total: u64,
    body_miss: u64,
}

impl Local {
    fn new(windows: usize) -> Self {
        Self {
            latency: hist(),
            first_byte: hist(),
            ok: 0,
            errors: BTreeMap::new(),
            windows: vec![0; windows],
            body_total: 0,
            body_miss: 0,
        }
    }
    fn error(&mut self, what: String) {
        *self.errors.entry(what).or_insert(0) += 1;
    }
}

/// A request with its head prepared once.
struct Prepared {
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
    expect_status: u16,
    expect_contains: Option<Vec<u8>>,
}

/// A request path the driver sends as written: an absolute path with an optional query.
pub fn check_path(path: &str) -> Result<(), String> {
    if !path.starts_with('/') {
        return Err(format!("bad path {path:?}: not an absolute path"));
    }
    http::uri::PathAndQuery::try_from(path)
        .map(drop)
        .map_err(|e| format!("bad path {path:?}: {e}"))
}

fn prepare(plan: &Plan) -> Result<Vec<Prepared>, String> {
    let authority = plan.addr.to_string();
    // The mix: each request repeated `weight` times, interleaved deterministically.
    let mut order: Vec<usize> = Vec::new();
    let max_w = plan.reqs.iter().map(|r| r.weight.max(1)).max().unwrap_or(1);
    for round in 0..max_w {
        for (i, r) in plan.reqs.iter().enumerate() {
            if round < r.weight.max(1) {
                order.push(i);
            }
        }
    }
    order
        .into_iter()
        .map(|i| -> Result<Prepared, String> {
            let r = &plan.reqs[i];
            check_path(&r.path)?;
            // h1 sends the origin form (the authority goes in `host`); h2c the absolute form,
            // whose authority becomes `:authority`.
            let uri = match plan.proto {
                Proto::H1 => Uri::builder(),
                Proto::H2c => Uri::builder().scheme("http").authority(authority.as_str()),
            }
            .path_and_query(r.path.as_str())
            .build()
            .map_err(|e| format!("bad path {:?}: {e}", r.path))?;
            let mut headers = HeaderMap::new();
            if plan.proto == Proto::H1 {
                headers.insert(
                    http::header::HOST,
                    HeaderValue::from_str(&authority).expect("authority is a header value"),
                );
            }
            for (k, v) in &r.headers {
                headers.append(k.clone(), v.clone());
            }
            Ok(Prepared {
                method: r.method.clone(),
                uri,
                headers,
                body: r.body.clone(),
                expect_status: r.expect_status,
                expect_contains: r.expect_contains.clone(),
            })
        })
        .collect()
}

type Body = Full<Bytes>;

enum Sender {
    H1(hyper::client::conn::http1::SendRequest<Body>),
    H2(hyper::client::conn::http2::SendRequest<Body>),
}

async fn connect(addr: SocketAddr, proto: Proto) -> std::io::Result<Sender> {
    let stream = TcpStream::connect(addr).await?;
    stream.set_nodelay(true)?;
    let io = TokioIo::new(stream);
    match proto {
        Proto::H1 => {
            let (send, conn) = hyper::client::conn::http1::Builder::new()
                .handshake(io)
                .await
                .map_err(std::io::Error::other)?;
            tokio::spawn(async move {
                let _ = conn.await;
            });
            Ok(Sender::H1(send))
        }
        Proto::H2c => {
            let (send, conn) = hyper::client::conn::http2::Builder::new(TokioExecutor::new())
                .initial_stream_window_size(4 << 20)
                .initial_connection_window_size(16 << 20)
                .max_concurrent_reset_streams(1024)
                .handshake(io)
                .await
                .map_err(std::io::Error::other)?;
            tokio::spawn(async move {
                let _ = conn.await;
            });
            Ok(Sender::H2(send))
        }
    }
}

impl Sender {
    fn clone_h2(&self) -> Option<Sender> {
        match self {
            Sender::H2(s) => Some(Sender::H2(s.clone())),
            Sender::H1(_) => None,
        }
    }
}

/// The result of one exchange.
struct Exchange {
    status: u16,
    first_byte: Option<Instant>,
    body: Option<Vec<u8>>,
}

async fn exchange(
    sender: &mut Sender,
    p: &Prepared,
    collect: bool,
) -> Result<Exchange, hyper::Error> {
    let mut req = Request::new(Full::new(p.body.clone()));
    *req.method_mut() = p.method.clone();
    *req.uri_mut() = p.uri.clone();
    *req.headers_mut() = p.headers.clone();
    let resp = match sender {
        Sender::H1(s) => {
            s.ready().await?;
            s.send_request(req).await?
        }
        Sender::H2(s) => {
            s.ready().await?;
            s.send_request(req).await?
        }
    };
    let status = resp.status().as_u16();
    let mut body = resp.into_body();
    let mut out = Exchange {
        status,
        first_byte: None,
        // A wrong status keeps its body for the error report.
        body: (collect || status != p.expect_status).then(Vec::new),
    };
    while let Some(frame) = body.frame().await {
        let frame = frame?;
        if let Some(d) = frame.data_ref() {
            if out.first_byte.is_none() {
                out.first_byte = Some(Instant::now());
            }
            if let Some(b) = out.body.as_mut() {
                if b.len() < 4 << 20 {
                    b.extend_from_slice(d);
                }
            }
        }
    }
    Ok(out)
}

struct Ctx {
    plan: Plan,
    reqs: Vec<Prepared>,
    windows: usize,
    /// Open loop: arrival permits and the arrival counter.
    permits: Option<Arc<Semaphore>>,
    arrivals: AtomicU64,
    rate: f64,
    seq: AtomicU64,
    first_error: std::sync::OnceLock<String>,
    /// h2c: one connection slot per group of `h2_streams` workers, the only place an h2c worker
    /// gets a connection from (a dead one is redialled once for its whole group).
    h2: Vec<tokio::sync::Mutex<Option<Sender>>>,
}

impl Ctx {
    fn record(
        &self,
        local: &mut Local,
        started: Instant,
        done: Instant,
        result: Result<Result<Exchange, hyper::Error>, tokio::time::error::Elapsed>,
        p: &Prepared,
    ) -> bool {
        let ms = self.plan.measure_start();
        let in_window = started >= ms && started < self.plan.end();
        let mut healthy = true;
        // `Some(hit)` when the body was checked against `expect_contains`.
        let mut checked: Option<bool> = None;
        let verdict: Result<Exchange, String> = match result {
            Err(_) => {
                healthy = false;
                Err("timeout".into())
            }
            Ok(Err(e)) => {
                healthy = false;
                self.note_error(|| format!("io: {e}"));
                Err("io".into())
            }
            Ok(Ok(x)) if x.status != p.expect_status => {
                let st = x.status;
                if let Some(b) = &x.body {
                    self.note_error(|| {
                        format!(
                            "status {st}: {}",
                            String::from_utf8_lossy(&b[..b.len().min(400)])
                        )
                    });
                } else {
                    self.note_error(|| format!("status {st}"));
                }
                Err(format!("status {st}"))
            }
            Ok(Ok(x)) => {
                if let (Some(b), Some(want)) = (&x.body, &p.expect_contains) {
                    checked = Some(memfind(b, want));
                    if checked == Some(false) {
                        self.note_error(|| {
                            format!(
                                "body without expected marker: {}",
                                String::from_utf8_lossy(&b[..b.len().min(400)])
                            )
                        });
                        Err("body".into())
                    } else {
                        Ok(x)
                    }
                } else {
                    Ok(x)
                }
            }
        };
        if !in_window {
            return healthy;
        }
        if let Some(hit) = checked {
            local.body_total += 1;
            local.body_miss += u64::from(!hit);
        }
        match verdict {
            Ok(x) => {
                local.ok += 1;
                let _ = local
                    .latency
                    .record((done - started).as_nanos().max(1) as u64);
                if let Some(fb) = x.first_byte {
                    let _ = local
                        .first_byte
                        .record((fb.saturating_duration_since(started)).as_nanos().max(1) as u64);
                }
                let w = (started - ms).as_secs() as usize;
                if let Some(slot) = local.windows.get_mut(w.min(self.windows - 1)) {
                    *slot += 1;
                }
            }
            Err(what) => local.error(what),
        }
        healthy
    }

    fn note_error(&self, f: impl FnOnce() -> String) {
        if self.first_error.get().is_none() {
            let _ = self.first_error.set(f()); // a lost race just drops a String
        }
    }
}

/// Whether a worker sends the request scheduled at `started` in a plan that ends at `end`: every
/// arrival scheduled before the end is sent, also when a worker only frees up after it (the
/// open-loop backlog), so a stalled gateway shows up as latency.
fn sends(started: Instant, end: Instant) -> bool {
    started < end
}

async fn worker(ctx: Arc<Ctx>, mut sender: Option<Sender>, group: usize) -> Local {
    let mut local = Local::new(ctx.windows);
    let end = ctx.plan.end();
    let n = ctx.reqs.len() as u64;
    loop {
        // The scheduled start: now (closed loop) or the next arrival instant (open loop).
        let started = if let Some(permits) = &ctx.permits {
            let acquire = tokio::time::timeout_at(end.into(), permits.acquire()).await;
            match acquire {
                Ok(Ok(p)) => p.forget(),
                _ => break,
            }
            let k = ctx.arrivals.fetch_add(1, Ordering::Relaxed);
            ctx.plan.start + Duration::from_secs_f64(k as f64 / ctx.rate)
        } else {
            Instant::now()
        };
        if !sends(started, end) {
            break;
        }
        let seq = ctx.seq.fetch_add(1, Ordering::Relaxed);
        let p = &ctx.reqs[(seq % n) as usize];
        let collect = p.expect_contains.is_some();
        let closed = matches!(&sender, Some(Sender::H2(s)) if s.is_closed());
        if sender.is_none() || closed {
            let got = match ctx.plan.proto {
                Proto::H1 => connect(ctx.plan.addr, Proto::H1).await,
                Proto::H2c => {
                    let mut slot = ctx.h2[group].lock().await;
                    if !matches!(&*slot, Some(Sender::H2(s)) if !s.is_closed()) {
                        *slot = connect(ctx.plan.addr, Proto::H2c).await.ok();
                    }
                    slot.as_ref()
                        .and_then(Sender::clone_h2)
                        .ok_or_else(|| std::io::Error::other("h2 group connect"))
                }
            };
            match got {
                Ok(s) => sender = Some(s),
                Err(e) => {
                    ctx.note_error(|| format!("connect: {e}"));
                    if Instant::now() >= ctx.plan.measure_start() {
                        local.error("connect".into());
                    }
                    tokio::time::sleep(Duration::from_millis(5)).await;
                    continue;
                }
            }
        }
        let s = sender.as_mut().expect("connected above");
        let result = tokio::time::timeout(ctx.plan.timeout, exchange(s, p, collect)).await;
        let done = Instant::now();
        // A failed h2 stream (above all a timeout) leaves its connection usable, and a closed one
        // is redialled for its whole group above: only an h1 connection is dropped here.
        if !ctx.record(&mut local, started, done, result, p) && ctx.plan.proto == Proto::H1 {
            sender = None;
        }
    }
    local
}

/// Run `plan` to completion on the current tokio runtime. Returns the merged outcome and the
/// first error text seen (for diagnosis), if any.
pub async fn run(plan: Plan) -> (Outcome, Option<String>) {
    let windows = (plan.measure.as_secs_f64().ceil() as usize).max(1);
    let (workers, rate) = match plan.shape {
        Shape::Closed { concurrency } => (concurrency.max(1), 0.0),
        Shape::Open { rate, connections } => (connections.max(1), rate.max(0.001)),
    };
    // A request the driver cannot send as written fails the run: never a substitute target.
    let reqs = match prepare(&plan) {
        Ok(r) => r,
        Err(e) => {
            let mut out = Outcome::new(windows);
            out.errors.insert("bad path".into(), 1);
            out.measured = plan.measure;
            return (out, Some(e));
        }
    };
    let permits = matches!(plan.shape, Shape::Open { .. }).then(|| Arc::new(Semaphore::new(0)));
    let per_conn = plan.h2_streams.max(1);
    let groups = match plan.proto {
        Proto::H1 => 0,
        Proto::H2c => workers.div_ceil(per_conn),
    };
    let ctx = Arc::new(Ctx {
        reqs,
        windows,
        permits: permits.clone(),
        arrivals: AtomicU64::new(0),
        rate,
        seq: AtomicU64::new(0),
        first_error: std::sync::OnceLock::new(),
        h2: (0..groups).map(|_| tokio::sync::Mutex::new(None)).collect(),
        plan,
    });

    // Connections first (outside the measured window), then wait for the start instant.
    let mut senders: Vec<Option<Sender>> = Vec::with_capacity(workers);
    for i in 0..workers {
        let s = match ctx.plan.proto {
            Proto::H1 => connect(ctx.plan.addr, Proto::H1).await.ok(),
            Proto::H2c => {
                let mut slot = ctx.h2[i / per_conn].lock().await;
                if i % per_conn == 0 {
                    *slot = connect(ctx.plan.addr, Proto::H2c).await.ok();
                }
                slot.as_ref().and_then(Sender::clone_h2)
            }
        };
        senders.push(s);
    }
    tokio::time::sleep_until(ctx.plan.start.into()).await;

    let stop = Arc::new(AtomicBool::new(false));
    let pacer = permits.map(|sem| {
        let (start, end, stop) = (ctx.plan.start, ctx.plan.end(), Arc::clone(&stop));
        std::thread::Builder::new()
            .name("hammer-pacer".into())
            .spawn(move || pace(sem, start, end, rate, &stop))
            .expect("spawn pacer")
    });

    let handles: Vec<_> = senders
        .into_iter()
        .enumerate()
        .map(|(i, s)| tokio::spawn(worker(Arc::clone(&ctx), s, i / per_conn)))
        .collect();
    let mut out = Outcome::new(windows);
    for h in handles {
        if let Some(msg) = out.merge_join(h.await) {
            ctx.note_error(|| msg);
        }
    }
    stop.store(true, Ordering::Relaxed);
    if let Some(p) = pacer {
        if p.join().is_err() {
            *out.errors.entry("pacer panic".into()).or_insert(0) += 1;
            ctx.note_error(|| "pacer panic".into());
        }
    }
    out.measured = ctx.plan.measure;
    let first = ctx.first_error.get().cloned();
    (out, first)
}

/// Release one permit per scheduled arrival: sleep while the next arrival is far, spin when it is
/// near (the OS sleep granularity would otherwise skew every latency by up to a millisecond).
fn pace(sem: Arc<Semaphore>, start: Instant, end: Instant, rate: f64, stop: &AtomicBool) {
    let mut issued: u64 = 0;
    loop {
        let now = Instant::now();
        if now >= end || stop.load(Ordering::Relaxed) {
            break;
        }
        if now >= start {
            let due = ((now - start).as_secs_f64() * rate) as u64 + 1;
            if due > issued {
                sem.add_permits((due - issued) as usize);
                issued = due;
            }
        }
        let next = start + Duration::from_secs_f64(issued as f64 / rate);
        let gap = next.saturating_duration_since(Instant::now());
        if gap > Duration::from_micros(400) {
            std::thread::sleep(gap - Duration::from_micros(250));
        } else {
            std::hint::spin_loop();
        }
    }
}

/// Percentile of a nanosecond histogram, in microseconds.
pub fn pct_us(h: &Histogram<u64>, q: f64) -> f64 {
    if h.is_empty() {
        return 0.0;
    }
    h.value_at_quantile(q) as f64 / 1000.0
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicUsize;

    fn req(path: &str) -> Req {
        Req {
            method: Method::GET,
            path: path.into(),
            headers: Vec::new(),
            body: Bytes::new(),
            expect_status: 200,
            expect_contains: None,
            weight: 1,
        }
    }

    fn plan(addr: SocketAddr, proto: Proto, path: &str) -> Plan {
        Plan {
            addr,
            proto,
            reqs: vec![req(path)],
            shape: Shape::Closed { concurrency: 1 },
            start: Instant::now(),
            warmup: Duration::from_millis(10),
            measure: Duration::from_millis(100),
            timeout: Duration::from_secs(1),
            h2_streams: 1,
        }
    }

    fn ctx(plan: Plan, reqs: Vec<Prepared>, windows: usize) -> Ctx {
        Ctx {
            plan,
            reqs,
            windows,
            permits: None,
            arrivals: AtomicU64::new(0),
            rate: 0.0,
            seq: AtomicU64::new(0),
            first_error: std::sync::OnceLock::new(),
            h2: Vec::new(),
        }
    }

    /// No coordinated omission: a request that STARTS inside the measured window is counted
    /// (with its full latency) even when it completes after the window closed.
    #[test]
    fn a_request_started_in_the_window_counts_when_it_completes_after_it() {
        let p = plan(([127, 0, 0, 1], 9).into(), Proto::H1, "/");
        let started = p.measure_start() + Duration::from_millis(50);
        let done = p.end() + Duration::from_millis(500);
        let ctx = ctx(
            p,
            vec![Prepared {
                method: Method::GET,
                uri: Uri::from_static("/"),
                headers: HeaderMap::new(),
                body: Bytes::new(),
                expect_status: 200,
                expect_contains: None,
            }],
            1,
        );
        let mut local = Local::new(ctx.windows);
        let x = Exchange {
            status: 200,
            first_byte: Some(done),
            body: None,
        };
        assert!(ctx.record(&mut local, started, done, Ok(Ok(x)), &ctx.reqs[0]));
        assert_eq!(
            local.ok, 1,
            "the late completion of an in-window start is counted"
        );
        assert_eq!(local.latency.len(), 1, "and its latency recorded");
    }

    /// The open-loop backlog: an arrival scheduled before the end is still sent (and measured
    /// from its scheduled start) when a worker only frees up after the end.
    #[test]
    fn an_arrival_scheduled_before_the_end_is_sent_after_the_end() {
        let started = Instant::now();
        let end = started + Duration::from_millis(1);
        std::thread::sleep(Duration::from_millis(5));
        assert!(sends(started, end), "the backlog is sent, not dropped");
        assert!(!sends(end, end), "an arrival at the end is not");
    }

    /// A path that is not a URI path is refused with a diagnosis, never sent as `/` (and, over
    /// h2c, never without its authority).
    #[test]
    fn an_unparsable_path_is_refused_not_sent_as_the_root() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        // A listener that never answers: whatever is sent to it only times out.
        let silent = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = silent.local_addr().unwrap();
        for proto in [Proto::H1, Proto::H2c] {
            let (out, first) = rt.block_on(run(plan(addr, proto, "/v1/chat completions")));
            assert_eq!(out.ok, 0);
            assert!(
                first.as_deref().is_some_and(|e| e.contains("bad path")),
                "{proto:?}: {first:?}"
            );
        }
        drop(silent);
    }

    /// The text between `from` and `to` in `src`: the doc comment of the field named by `to`.
    fn doc_of<'a>(src: &'a str, from: &str, to: &str) -> &'a str {
        let end = src.find(to).expect("field present");
        let start = src[..end].rfind(from).expect("previous field present");
        &src[start..end]
    }

    /// A `contains:` marker is checked on every answer with the expected status, but a miss is
    /// counted as `body_miss` (and fails the case) only for a request started inside the
    /// measured window; warmup and later misses are only logged. The field docs must state
    /// exactly that scope.
    #[test]
    fn contains_miss_counts_only_in_window_and_docs_say_so() {
        let start = Instant::now();
        let plan = Plan {
            addr: "127.0.0.1:9".parse().unwrap(),
            proto: Proto::H1,
            reqs: Vec::new(),
            shape: Shape::Closed { concurrency: 1 },
            start,
            warmup: Duration::from_secs(5),
            measure: Duration::from_secs(5),
            timeout: Duration::from_secs(1),
            h2_streams: 1,
        };
        let ctx = ctx(plan, Vec::new(), 5);
        let p = Prepared {
            method: Method::GET,
            uri: Uri::from_static("/"),
            headers: HeaderMap::new(),
            body: Bytes::new(),
            expect_status: 200,
            expect_contains: Some(b"hammer-ok".to_vec()),
        };
        let miss =
            |status: u16| -> Result<Result<Exchange, hyper::Error>, tokio::time::error::Elapsed> {
                Ok(Ok(Exchange {
                    status,
                    first_byte: None,
                    body: Some(b"no".to_vec()),
                }))
            };
        let mut local = Local::new(ctx.windows);
        let s = Duration::from_secs;
        // Warmup miss: logged, not counted.
        ctx.record(&mut local, start + s(1), start + s(2), miss(200), &p);
        // Miss of a request started after the window: logged, not counted.
        ctx.record(&mut local, start + s(10), start + s(11), miss(200), &p);
        assert_eq!((local.body_total, local.body_miss), (0, 0));
        assert!(ctx.first_error.get().is_some(), "the miss is logged");
        // Wrong status in the window: a status error, the body is not checked.
        ctx.record(&mut local, start + s(6), start + s(7), miss(503), &p);
        assert_eq!((local.body_total, local.body_miss), (0, 0));
        // Expected status in the window: checked and counted.
        ctx.record(&mut local, start + s(6), start + s(7), miss(200), &p);
        assert_eq!((local.body_total, local.body_miss), (1, 1));

        // The docs state that scope, not "every body, any miss fails".
        for doc in [
            doc_of(
                include_str!("scenario.rs"),
                "pub expect: u16,",
                "pub contains: Option<String>",
            ),
            doc_of(
                include_str!("driver.rs"),
                "pub expect_status: u16,",
                "pub expect_contains: Option<Vec<u8>>",
            ),
        ] {
            assert!(
                doc.contains("measured window") && doc.contains("warmup"),
                "doc must say misses count only in the measured window: {doc}"
            );
            assert!(
                !doc.contains("EVERY"),
                "doc must not overstate the check: {doc}"
            );
        }
    }

    /// Error text for the first-error report must be built inside the lazy
    /// `note_error` closure, so an error storm does not allocate per response.
    #[test]
    fn note_error_text_built_lazily() {
        let src = include_str!("driver.rs");
        let prod = src.split("#[cfg(test)]").next().unwrap();
        let mut rest = prod;
        let mut seen = 0;
        while let Some(i) = rest.find("from_utf8_lossy") {
            let before = &rest[..i];
            let open = before
                .rfind("note_error(||")
                .expect("from_utf8_lossy used outside a note_error closure");
            assert!(
                !before[open..].contains(';'),
                "from_utf8_lossy evaluated eagerly before note_error: {}",
                &before[open.saturating_sub(200)..]
            );
            seen += 1;
            rest = &rest[i + 1..];
        }
        assert!(seen > 0, "expected error-text sites in driver.rs");
    }

    /// h2c keeps `ceil(workers / h2_streams)` connections for the whole run: a stream that times
    /// out does not break its h2 connection, so no worker dials a private one.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn h2c_timeouts_keep_the_shared_connections() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let accepts = Arc::new(AtomicUsize::new(0));
        let counted = Arc::clone(&accepts);
        tokio::spawn(async move {
            while let Ok((stream, _)) = listener.accept().await {
                counted.fetch_add(1, Ordering::SeqCst);
                tokio::spawn(async move {
                    let svc =
                        hyper::service::service_fn(|_req: Request<hyper::body::Incoming>| async {
                            tokio::time::sleep(Duration::from_millis(200)).await;
                            Ok::<_, std::convert::Infallible>(http::Response::new(Full::new(
                                Bytes::from_static(b"ok"),
                            )))
                        });
                    let _ = hyper::server::conn::http2::Builder::new(TokioExecutor::new())
                        .serve_connection(TokioIo::new(stream), svc)
                        .await;
                });
            }
        });
        let plan = Plan {
            addr,
            proto: Proto::H2c,
            reqs: vec![req("/")],
            shape: Shape::Closed { concurrency: 8 },
            start: Instant::now() + Duration::from_millis(100),
            warmup: Duration::ZERO,
            measure: Duration::from_secs(1),
            timeout: Duration::from_millis(50),
            h2_streams: 4,
        };
        let (out, _) = run(plan).await;
        assert!(out.errors.get("timeout").copied().unwrap_or(0) > 0);
        assert_eq!(accepts.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn a_panicking_worker_is_counted_as_an_error_not_dropped() {
        let mut out = Outcome::new(1);
        let r = tokio::spawn(async {
            panic!("boom");
            #[allow(unreachable_code)]
            Local::new(1)
        })
        .await;
        assert!(out.merge_join(r).is_some());
        assert_eq!(out.errors.get("worker panic"), Some(&1));
    }
}
