use super::*;

use busbar_contract::diag_debug;

/// Where to charge a request's token usage when its response stream completes (the resolved virtual
/// key + its budget period + the governance store). `None` when governance is off or no key resolved.
#[derive(Clone)]
pub(crate) struct UsageSink {
    /// The request's METER PIN — the kernel-owned opaque carrier of the governance state and the rate
    /// card in force when this request was admitted (minted host-side via `BudgetHost::meter_pin`).
    /// The plane holds it and hands it BACK to the metering seams (`meter_ledger`, `meter_series`,
    /// `meter_series_billed`), which read it kernel-side — so the sink names no cost or price type
    /// (#43) and the accrual lands against the SAME `GovState`/card it always did. An Arc bump per
    /// request; a failover clone shares it.
    pub(crate) pin: busbar_kernel::plane_host::MeterPin,
    /// The resolved virtual key, shared via `Arc`: `key_id` is read THROUGH it (`key.id`) at
    /// charge time, so building the sink (once per request) and cloning it (once per failover
    /// attempt) is a refcount bump, not a per-request `String` clone.
    pub(crate) key: Arc<busbar_contract::records::VirtualKey>,
    /// The pool this request was ADMITTED through (the ingress-requested pool) - the accounting
    /// scope for pool-qualified limits. Stream-end token accrual charges exactly the buckets the
    /// admission charged, so the two can never disagree on a pool-scoped budget. `Arc<str>`: the
    /// sink clones per failover attempt.
    pub(crate) pool: std::sync::Arc<str>,
    /// Wall-clock epoch (seconds) captured ONCE at header-arrival time for this request. Both the
    /// flat per-request fee (`ingress::budget_check` → `try_charge_request_within_budget`) and the token fee (`record_tokens`,
    /// fired at stream end / on the buffered path) are attributed to the window this epoch implies,
    /// so a single streaming request whose stream completes in a later rate-limit/budget window than
    /// its headers arrived cannot split its two charges across two windows (#29). Without it, the two
    /// calls read the clock independently and could land in different 60s rate windows / budget
    /// periods, mis-attributing spend and TPM.
    pub(crate) charged_at: u64,
    /// The admission's in-flight HOLDS (the `concurrent` limit gauges), released when the LAST
    /// clone of this sink drops - i.e. when the response stream completes or the request context
    /// unwinds on any error path. `Arc` because the sink clones per failover attempt; `None` for
    /// a chain with no concurrent caps or a test sink built off the admission path. Never read:
    /// the field exists purely so its Drop (on the last clone) releases the gauges.
    #[allow(dead_code)]
    pub(crate) admit: Option<busbar_kernel::plane_host::AdmitHandle>,
}

/// HOW A RESPONSE ENDED, in the ENGINE'S OWN vocabulary.
///
/// Three classes, and they map one-for-one onto the loop's `FinishClass` — the mapping is written
/// once, in the Audit step, which is the only place on this plane that speaks the loop's vocabulary
/// at all. It is spelled here rather than imported because the contract crate is linked ONLY behind
/// the teller waist, while this engine is built on every configuration: naming it here would make the
/// default build depend on a flag it has nothing to do with.
///
/// There is no fourth class. The loop also knows `TurnComplete` — one turn of a duplex exchange whose
/// session continues — and no dialect this plane speaks has one: an LLM completion's end is the end
/// of the unit, not the end of a turn. A plane that reported it here would be claiming a session it
/// never opened.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum TapFinish {
    /// The whole answer reached the client.
    Complete,
    /// The answer was cut short: bytes were relayed and then the response stopped before its end.
    Partial,
    /// The response ended in failure — the destination said so, or the transfer never delivered a
    /// usable answer at all.
    Error,
}

/// WHAT THE TAP SAW — the report the walk's completion tap hands back to the steps that ran before
/// it.
///
/// Three of these four figures are knowable ONLY at the end of the response, and that is the whole
/// reason this type exists. The Route step returns while a stream is still flowing: the lane that
/// answered is resolved inside the walk, the dialect's terminal usage frame has not arrived, and
/// whether the translator will report a terminal error is a question about bytes that do not exist
/// yet. So the walk hands out a cell, the tap fills it once, and the Meter and Audit steps read what
/// is there when they run.
///
/// [`TapReport::finish`] is the fourth, and it is the one a status line cannot answer. A stream is
/// served on 2xx headers and can still die mid-body; the client-facing status says `Complete` and
/// the truth is `Partial`. Only the tap knows which.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct TapReport {
    /// The SERVING lane, as an index into the engine's lane table — the lane that actually
    /// answered, after any failover. The accounting key for both the ledger and the metering series.
    pub(crate) lane: usize,
    /// The token usage the dialect's reader found up to the end the response reached, or `None`
    /// where nothing reported any. It is the CHARGE on every end, a cut one included: a mid-stream
    /// cut is an interruption, not a reversal of incurred cost, so what streamed before it bills
    /// (#62). A transfer that delivered nothing has nothing read here, which is what bills it zero.
    pub(crate) usage: Option<busbar_contract::billing::TokenUsage>,
    /// EVERY OPEN CLASS the response billed beside the token split — a rerank's search units
    /// (item 134) — as the class map the governance ledger accrued them under
    /// ([`crate::engine::usage::open_units_of`], the one projection both books read). Empty where the
    /// response billed tokens only or nothing. It used to be absent: the governance ledger held a
    /// rerank's search units and the late reading handed the durable book none (#71: the ledger event
    /// is the raw counts per class, every class).
    pub(crate) open_units: std::collections::BTreeMap<String, u64>,
    /// How the response ENDED, as the plane says it.
    pub(crate) finish: TapFinish,
}

/// THE CELL the walk hands out and the tap fills exactly once.
///
/// `OnceLock` rather than a mutex or an atomic flag because "exactly once" is the whole contract:
/// the stream-end arm and the drop-time partial can both be reached for one response (a clean end
/// runs `Poll::Ready(None)` and THEN `Drop`), and the second write must be a no-op rather than a
/// correction. `Arc` because the cell is handed to the body wrapper, which outlives the step that
/// created it by exactly the length of the stream, and rides back on the response as an extension so
/// the terminal can read it without the plane growing a second carry.
///
/// What a report can SAY is [`TapFinish`]'s three classes and nothing more — see there for why the
/// loop's fourth, a completed turn of a continuing session, is not one of them on this plane.
#[derive(Clone, Default)]
pub(crate) struct TapCell(Arc<std::sync::OnceLock<TapReport>>);

impl TapCell {
    /// An empty cell, for one response.
    pub(crate) fn new() -> Self {
        Self::default()
    }

    /// Report what the tap saw. The FIRST report wins and every later one is discarded — see the
    /// type's own docs for why that is the contract rather than an accident.
    pub(crate) fn report(&self, report: TapReport) {
        let _ = self.0.set(report);
    }

    /// What the tap reported, or `None` while the response is still in flight.
    pub(crate) fn get(&self) -> Option<&TapReport> {
        self.0.get()
    }
}

impl std::fmt::Debug for TapCell {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("TapCell").field(&self.get()).finish()
    }
}

/// Bytes-per-token divisor for the truncated-tail billing FLOOR (the plane's), read by the tests.
#[cfg(test)]
pub(crate) use busbar_plane_llm::codec::wire_shim::TRUNCATED_TAIL_BYTES_PER_TOKEN;

/// The floor over a truncated tail (the plane's reply), read by the tests.
#[cfg(test)]
pub(crate) use crate::engine::xchg::reply::wire::estimate_usage_from_truncated_tail;

use crate::engine::xchg::reply::relay::{Fed, Relay};

/// Body wrapper that drives IR-based usage extraction, billing, and mid-stream error handling for
/// streaming responses.
///
/// The BYTES are the plane's [`Relay`] (`busbar_plane_llm::exchange::reply::relay`): the
/// translator feed, the JSON-array framer, the same-protocol non-stream relay's tail-anchored
/// usage copy and stop-reason scan, the stream end's terminator and usage, and the cut's in-band
/// error frame. This wrapper keeps what is not the plane's: the permit, the stream ceiling, the
/// breaker records, the budget refund, the accrual and the tap.
pub(crate) struct FirstByteBody<S, P> {
    inner: S,
    /// The plane's relay of this answer's bytes.
    relay: Relay,
    permit: Option<P>,
    /// App-retype WEDGE 3: the neutral engine host + this plane's runtime tables the mid-stream
    /// breaker-trip / refund / stream-end metering reach. `Option` for the same reason `app` was (a
    /// degraded/test body may carry none).
    host: Option<Arc<dyn EngineHost>>,
    rt: Option<Arc<NativeRuntime>>,
    lane_idx: usize,
    /// Resolved breaker config for the routing pool, so a mid-stream failure trips this lane using
    /// the same thresholds the synchronous path used (defaults on the degraded path).
    breaker_cfg: Arc<busbar_kernel::store::BreakerCfg>,
    /// Routing pool name, so a mid-stream failure trips this lane's per-pool breaker cell (empty on
    /// the degraded path → the lane-default cell).
    pool: Box<str>,
    /// When set, the token usage tapped from this response is charged to a virtual key's budget at
    /// stream end (token-accurate accounting). Taken (fired) exactly once when the stream completes.
    usage_sink: Option<UsageSink>,
    /// True when the 2xx-headers `spend_budget(lane_idx)` on this request actually decremented the
    /// lane's `max_requests` budget; a pre-first-byte transport failure refunds it (#21), once.
    budget_spent: bool,
    /// Set once the stream has fully ended (after any translation terminator), so a later poll
    /// returns None instead of re-polling a finished inner stream.
    ended: bool,
    /// THE STREAM CEILING — the re-provision of reqwest's total-timeout envelope over the BODY:
    /// a `Sleep` polled BEFORE the inner stream on every wakeup, so expiry cuts the body exactly
    /// as reqwest's `TotalTimeoutBody` did, even while chunks are still flowing. The DEADLINE is
    /// the caller's per-attempt instant, so send + body share ONE envelope anchored at send start.
    ceiling: std::pin::Pin<Box<tokio::time::Sleep>>,
    /// THE REPORT-BACK. Filled exactly once, at whichever of this body's four ends is reached — the
    /// clean stream end, the mid-stream cut, the pre-first-byte cut, or the drop-time partial.
    tap: TapCell,
}

impl<S, P> FirstByteBody<S, P>
where
    S: Stream<Item = Result<Bytes, hyper::Error>> + Send + 'static,
{
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        inner: S,
        is_sse: bool,
        ingress_protocol: &str,
        op: Op,
        permit: P,
        ceiling_deadline: tokio::time::Instant,
        host: Arc<dyn EngineHost>,
        rt: Arc<NativeRuntime>,
        lane_idx: usize,
        breaker_cfg: Arc<busbar_kernel::store::BreakerCfg>,
        pool: &str,
        translate: Option<Box<dyn busbar_kernel::proto::StreamTranslator>>,
        json_array: Option<Box<dyn busbar_kernel::proto::ArrayStreamFramer>>,
        usage_sink: Option<UsageSink>,
        budget_spent: bool,
        tap: TapCell,
    ) -> Self {
        // The relay reads usage only when there is a sink to bill it to: with governance off the
        // same-protocol non-stream copy and its stream-end read would be pure waste.
        let relay = Relay::from_parts(
            ingress_protocol,
            is_sse,
            op.op_handler,
            usage_sink.is_some(),
            translate,
            json_array,
        );
        Self {
            inner,
            relay,
            permit: Some(permit),
            host: Some(host),
            rt: Some(rt),
            lane_idx,
            breaker_cfg,
            pool: Box::from(pool),
            usage_sink,
            budget_spent,
            ended: false,
            ceiling: Box::pin(tokio::time::sleep_until(ceiling_deadline)),
            tap,
        }
    }
}

/// Why the inner byte stream was cut short — either the transport itself failed (a hyper error,
/// whose Display embeds backend internals and must never reach the client) or the stream ceiling
/// expired (the reqwest total-timeout re-provision). One type so the single error arm below handles
/// both identically, logging the real cause server-side.
enum StreamCut {
    Transport(hyper::Error),
    Ceiling,
}

impl std::fmt::Display for StreamCut {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            StreamCut::Transport(e) => e.fmt(f),
            StreamCut::Ceiling => f.write_str(
                "upstream response exceeded limits.upstream_request_timeout_secs (stream ceiling)",
            ),
        }
    }
}

impl<S, P> FirstByteBody<S, P> {
    /// Record a transient fault for this lane's pool cell, and the trip it drives (#29).
    fn record_transient(&self, what: &str) {
        if let (Some(host), Some(rt)) = (self.host.as_ref(), self.rt.as_ref()) {
            let tripped = host.lane_store().record_transient_in(
                &self.pool,
                self.lane_idx,
                what,
                &self.breaker_cfg,
                None,
            );
            if tripped {
                emit_breaker_trip(host, rt, &self.pool, self.lane_idx);
            }
        }
    }
}

impl<S, P> Stream for FirstByteBody<S, P>
where
    S: Stream<Item = Result<Bytes, hyper::Error>> + Unpin + Send + 'static,
    P: Send + Unpin + 'static,
{
    type Item = Result<Bytes, std::io::Error>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = self.get_mut();
        if this.ended {
            return Poll::Ready(None);
        }
        // Loop so a piece that completes no frame yet re-polls the inner stream instead of emitting
        // an empty chunk to the client.
        loop {
            // The stream ceiling is polled BEFORE the inner stream (registering its waker either
            // way), so expiry cuts even a still-flowing body. Both cut causes funnel into the ONE
            // error arm below.
            let step: Poll<Option<Result<Bytes, StreamCut>>> =
                if std::future::Future::poll(this.ceiling.as_mut(), cx).is_ready() {
                    Poll::Ready(Some(Err(StreamCut::Ceiling)))
                } else {
                    Pin::new(&mut this.inner)
                        .poll_next(cx)
                        .map(|o| o.map(|r| r.map_err(StreamCut::Transport)))
                };
            match step {
                Poll::Ready(Some(Ok(chunk))) => {
                    // The plane's relay: the translated frames, or the far end's own bytes (the
                    // chunk itself, never copied) with a bounded tail-anchored copy kept for usage.
                    let (fed, truncated_now) = this.relay.feed(&chunk);
                    let out = match fed {
                        Fed::Nothing => None,
                        Fed::Bytes(std::borrow::Cow::Borrowed(_)) => Some(None),
                        Fed::Bytes(std::borrow::Cow::Owned(v)) => Some(Some(v)),
                    };
                    if truncated_now {
                        // Fires ONCE per response: an over-cap body is alertable even though the
                        // tail-anchored copy still recovers usage for every recognized dialect.
                        metrics::counter!(busbar_kernel::metrics::BILLING_TRUNCATED_TOTAL)
                            .increment(1);
                        diag_debug!(
                            USAGE_TAP_REASSEMBLY_CAP_EXCEEDED,
                            cap = max_translated_body_bytes(),
                            "same-protocol non-stream body exceeded the usage-tap reassembly \
                             cap; retaining the TAIL (not the head) so the trailing usage \
                             object still bills correctly for a recognized dialect"
                        );
                    }
                    match out {
                        None => continue,
                        Some(None) => return Poll::Ready(Some(Ok(chunk))),
                        Some(Some(v)) => return Poll::Ready(Some(Ok(Bytes::from(v)))),
                    }
                }
                Poll::Ready(Some(Err(e))) => {
                    // An upstream transport error (or the stream ceiling) cut the response. What
                    // streamed before the cut is still billed — by the Drop below (#62: a
                    // mid-stream cut is not a refund).
                    let had_first = this.relay.had_first();
                    let cut = this.relay.cut(matches!(e, StreamCut::Transport(_)));
                    if let Some(err_bytes) = cut.bytes {
                        // After the first byte of a stream: the breaker records the failure, the
                        // client's stream ends on the plane's in-band error frame in its own
                        // framing (never the raw transport error, which embeds backend
                        // internals), and the stream is marked ended so the inner stream's
                        // trailing `None` does not re-record it.
                        this.record_transient(cut.reason);
                        drop(this.permit.take());
                        this.ended = true;
                        this.tap.report(TapReport {
                            lane: this.lane_idx,
                            usage: cut.usage,
                            open_units: Default::default(),
                            finish: TapFinish::Partial,
                        });
                        diag_debug!(
                            UPSTREAM_MIDSTREAM_TRANSPORT_ERROR,
                            ingress = %this.relay.ingress(),
                            error = %e,
                            "mid-stream upstream transport error; returning generic interruption to client"
                        );
                        return Poll::Ready(Some(Ok(Bytes::from(err_bytes))));
                    }
                    // Before the first byte, or a non-stream body mid-transfer: the body ends on a
                    // generic error. The optimistic headers-time success was wrong, so a
                    // compensating transient is recorded UNCONDITIONALLY (a lane that dies before
                    // its first byte on every attempt must still trip), and the headers-time
                    // budget unit is refunded once (#21) — only when the spend decremented.
                    diag_debug!(
                        UPSTREAM_PREFIRSTBYTE_TRANSPORT_ERROR,
                        ingress = %this.relay.ingress(),
                        error = %e,
                        "pre-first-byte upstream transport error; terminating body stream generically"
                    );
                    this.record_transient(cut.reason);
                    if this.budget_spent {
                        if let Some(host) = this.host.as_ref() {
                            host.lane_store().refund_budget(this.lane_idx);
                        }
                        this.budget_spent = false;
                    }
                    drop(this.permit.take());
                    this.ended = true;
                    // A cut before the first byte delivered nothing (`Error`); after it, a
                    // non-stream prefix the caller cannot use whole (`Partial`). The usage is what
                    // the relay had incurred — the figure the Drop bills (item 367).
                    this.tap.report(TapReport {
                        lane: this.lane_idx,
                        usage: cut.usage,
                        open_units: Default::default(),
                        finish: if had_first {
                            TapFinish::Partial
                        } else {
                            TapFinish::Error
                        },
                    });
                    return Poll::Ready(Some(Err(std::io::Error::other(
                        MID_STREAM_GENERIC_DETAIL,
                    ))));
                }
                Poll::Ready(None) => {
                    // Stream ended. A clean end is NOT a failure (success was recorded at headers
                    // time); the breaker hears only a stream the relay saw fail after its first
                    // byte, and a same-protocol non-stream body whose own stop reason says the
                    // generation failed (owner ruling Q31).
                    let end = this.relay.end();
                    if let Some(reason) = end.stream_fault {
                        this.record_transient(reason);
                    }
                    // The stream's drops (design F3 "Drops"), already warned once each: one audit row
                    // per wire path, the twin of the buffered answer's rows.
                    if let (Some(host), Some(rt)) = (this.host.as_ref(), this.rt.as_ref()) {
                        if let Some(lane) = EngineTables::new(rt).lanes().get(this.lane_idx) {
                            let caller = this
                                .usage_sink
                                .as_ref()
                                .map_or("anonymous", |s| s.key.id.as_str());
                            for path in &end.dropped {
                                host.audit_record(
                                    "egress.control_unrepresentable",
                                    &format!("{path} from {}", lane.protocol),
                                    busbar_contract::vocab::OUTCOME_DEGRADED,
                                    caller,
                                );
                            }
                        }
                    }
                    drop(this.permit.take());
                    this.ended = true;
                    if end.generation_failed {
                        this.record_transient("upstream-generation-failed");
                    }
                    // Charge the usage (once) on EVERY end this arm reaches: a failed stream is a
                    // cut, and a cut is not a refund (#62). The SERVING lane is ledgered and
                    // metered through the one accrual seam.
                    if let Some(sink) = this.usage_sink.take() {
                        let tier = end
                            .usage
                            .as_ref()
                            .map(crate::engine::usage::tier_usage)
                            .unwrap_or_default();
                        if let (Some(host), Some(lane)) = (
                            this.host.as_ref(),
                            this.rt
                                .as_ref()
                                .and_then(|rt| EngineTables::new(rt).lanes().get(this.lane_idx)),
                        ) {
                            crate::engine::usage::ledger_and_meter(
                                host,
                                &sink,
                                lane,
                                end.usage.as_ref(),
                                &tier,
                            );
                            crate::engine::usage::ledger_open_units(
                                host,
                                &sink,
                                lane,
                                end.open_units.clone(),
                            );
                        }
                    }
                    // THE REPORT-BACK, after the accrual so the figures move rather than copy.
                    this.tap.report(TapReport {
                        lane: this.lane_idx,
                        usage: end.usage,
                        open_units: end.open_units,
                        finish: if end.failed {
                            TapFinish::Error
                        } else {
                            TapFinish::Complete
                        },
                    });
                    if !end.bytes.is_empty() {
                        return Poll::Ready(Some(Ok(Bytes::from(end.bytes))));
                    }
                    return Poll::Ready(None);
                }
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}

impl<S, P> Drop for FirstByteBody<S, P> {
    fn drop(&mut self) {
        // Cancellation: the stream was dropped before any terminal arm (a client disconnect / LB
        // reset); refund the headers-time budget unit once, only when the spend decremented.
        if !self.ended && self.budget_spent {
            if let Some(host) = self.host.as_ref() {
                host.lane_store().refund_budget(self.lane_idx);
            }
            self.budget_spent = false;
        }
        // THE REPORT-BACK on the end no arm reached: the caller got a prefix and stopped
        // listening, so the answer is `Partial`. The tokens incurred up to here really were
        // generated and delivered, and the arm below bills them — as it bills a cut's (#62).
        let usage = if !self.ended || self.usage_sink.is_some() {
            self.relay.incurred_usage()
        } else {
            None
        };
        if !self.ended {
            self.tap.report(TapReport {
                lane: self.lane_idx,
                usage: usage.clone(),
                open_units: Default::default(),
                finish: TapFinish::Partial,
            });
        }
        // A `None` sink means the natural end already billed; a `Some` means the body ended
        // WITHOUT that arm (dropped or cut), so bill what was incurred up to the cut.
        let Some(sink) = self.usage_sink.take() else {
            return;
        };
        let tier = usage
            .as_ref()
            .map(crate::engine::usage::tier_usage)
            .unwrap_or_default();
        if !tier.usage_units.is_empty() {
            if let (Some(host), Some(lane)) = (
                self.host.as_ref(),
                self.rt
                    .as_ref()
                    .and_then(|rt| EngineTables::new(rt).lanes().get(self.lane_idx)),
            ) {
                crate::engine::usage::ledger_and_meter(host, &sink, lane, usage.as_ref(), &tier);
            }
        }
    }
}

impl<S, P> FirstByteBody<S, P> {
    pub(crate) fn into_body(self) -> Body
    where
        S: Stream<Item = Result<Bytes, hyper::Error>> + Unpin + Send + 'static,
        P: Send + Unpin + 'static,
    {
        Body::from_stream(self)
    }
}

#[cfg(test)]
#[path = "tests/unreadable_usage_floor_tests.rs"]
mod unreadable_usage_floor_tests;

#[cfg(test)]
#[path = "engine_tests/nonstream_drop_billing_tests.rs"]
mod nonstream_drop_billing_tests;
