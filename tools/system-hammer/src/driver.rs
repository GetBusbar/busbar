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
    /// Bytes EVERY response body must contain: a request that states it has each body checked.
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
    /// Sends start at `start`; completions before `start + warmup` are not recorded.
    pub start: Instant,
    pub warmup: Duration,
    pub measure: Duration,
    pub timeout: Duration,
    /// h2c: in-flight streams per connection.
    pub h2_streams: usize,
    /// Every n-th response body is collected (for the error report); a request with
    /// `expect_contains` has every body collected and checked.
    pub sample_every: u64,
}

impl Plan {
    pub fn measure_start(&self) -> Instant {
        self.start + self.warmup
    }
    pub fn end(&self) -> Instant {
        self.start + self.warmup + self.measure
    }
}

/// What a run measured (completions inside the measured window only).
#[derive(Debug)]
pub struct Outcome {
    /// Request latency, nanoseconds (open loop: from the scheduled start).
    pub latency: Histogram<u64>,
    /// Time to the first body chunk, nanoseconds.
    pub first_byte: Histogram<u64>,
    pub ok: u64,
    /// Failures by cause: `status 503`, `io`, `timeout`, `body`.
    pub errors: BTreeMap<String, u64>,
    /// Successful completions per one-second window of the measured phase.
    pub windows: Vec<u64>,
    pub measured: Duration,
    pub bytes_in: u64,
    pub chunks_in: u64,
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
            bytes_in: 0,
            chunks_in: 0,
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
        self.bytes_in += o.bytes_in;
        self.chunks_in += o.chunks_in;
        self.body_total += o.body_total;
        self.body_miss += o.body_miss;
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
    bytes_in: u64,
    chunks_in: u64,
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
            bytes_in: 0,
            chunks_in: 0,
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

fn prepare(plan: &Plan) -> Vec<Prepared> {
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
        .map(|i| {
            let r = &plan.reqs[i];
            let uri: Uri = match plan.proto {
                Proto::H1 => r.path.parse(),
                Proto::H2c => format!("http://{authority}{}", r.path).parse(),
            }
            .unwrap_or_else(|_| Uri::from_static("/"));
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
            Prepared {
                method: r.method.clone(),
                uri,
                headers,
                body: r.body.clone(),
                expect_status: r.expect_status,
                expect_contains: r.expect_contains.clone(),
            }
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
    bytes: u64,
    chunks: u64,
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
        bytes: 0,
        chunks: 0,
        // A wrong status keeps its body for the error report.
        body: (collect || status != p.expect_status).then(Vec::new),
    };
    while let Some(frame) = body.frame().await {
        let frame = frame?;
        if let Some(d) = frame.data_ref() {
            if out.first_byte.is_none() {
                out.first_byte = Some(Instant::now());
            }
            out.bytes += d.len() as u64;
            out.chunks += 1;
            if let Some(b) = out.body.as_mut() {
                if b.len() < 4 << 20 {
                    b.extend_from_slice(d);
                }
            }
        }
    }
    Ok(out)
}

fn contains(hay: &[u8], needle: &[u8]) -> bool {
    needle.is_empty() || hay.windows(needle.len()).any(|w| w == needle)
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
    first_error: std::sync::Mutex<Option<String>>,
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
        let in_window = started >= ms && done <= self.plan.end();
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
                    let text = String::from_utf8_lossy(&b[..b.len().min(400)]).into_owned();
                    self.note_error(|| format!("status {st}: {text}"));
                } else {
                    self.note_error(|| format!("status {st}"));
                }
                Err(format!("status {st}"))
            }
            Ok(Ok(x)) => {
                if let (Some(b), Some(want)) = (&x.body, &p.expect_contains) {
                    checked = Some(contains(b, want));
                    if checked == Some(false) {
                        let text = String::from_utf8_lossy(&b[..b.len().min(400)]).into_owned();
                        self.note_error(|| format!("body without expected marker: {text}"));
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
                local.bytes_in += x.bytes;
                local.chunks_in += x.chunks;
                let w = (done - ms).as_secs() as usize;
                if let Some(slot) = local.windows.get_mut(w.min(self.windows - 1)) {
                    *slot += 1;
                }
            }
            Err(what) => local.error(what),
        }
        healthy
    }

    fn note_error(&self, f: impl FnOnce() -> String) {
        let mut g = self.first_error.lock().unwrap();
        if g.is_none() {
            *g = Some(f());
        }
    }
}

async fn worker(ctx: Arc<Ctx>, mut sender: Option<Sender>) -> Local {
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
        if started >= end || Instant::now() >= end {
            break;
        }
        let seq = ctx.seq.fetch_add(1, Ordering::Relaxed);
        let p = &ctx.reqs[(seq % n) as usize];
        let collect = p.expect_contains.is_some()
            || (ctx.plan.sample_every > 0 && seq.is_multiple_of(ctx.plan.sample_every));
        if sender.is_none() {
            match connect(ctx.plan.addr, ctx.plan.proto).await {
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
        if !ctx.record(&mut local, started, done, result, p) {
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
    let permits = matches!(plan.shape, Shape::Open { .. }).then(|| Arc::new(Semaphore::new(0)));
    let ctx = Arc::new(Ctx {
        reqs: prepare(&plan),
        windows,
        permits: permits.clone(),
        arrivals: AtomicU64::new(0),
        rate,
        seq: AtomicU64::new(0),
        first_error: std::sync::Mutex::new(None),
        plan,
    });

    // Connections first (outside the measured window), then wait for the start instant.
    let mut senders: Vec<Option<Sender>> = Vec::with_capacity(workers);
    let per_conn = ctx.plan.h2_streams.max(1);
    let mut shared: Option<Sender> = None;
    for i in 0..workers {
        let s = match ctx.plan.proto {
            Proto::H1 => connect(ctx.plan.addr, Proto::H1).await.ok(),
            Proto::H2c => {
                if i % per_conn == 0 {
                    shared = connect(ctx.plan.addr, Proto::H2c).await.ok();
                }
                shared.as_ref().and_then(Sender::clone_h2)
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
        .map(|s| tokio::spawn(worker(Arc::clone(&ctx), s)))
        .collect();
    let mut out = Outcome::new(windows);
    for h in handles {
        if let Ok(local) = h.await {
            out.merge(local);
        }
    }
    stop.store(true, Ordering::Relaxed);
    if let Some(p) = pacer {
        let _ = p.join();
    }
    out.measured = ctx.plan.measure;
    let first = ctx.first_error.lock().unwrap().take();
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
