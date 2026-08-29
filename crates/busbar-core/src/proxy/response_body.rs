use super::*;

use crate::diagnostics::{
    diag_debug, UPSTREAM_MIDSTREAM_TRANSPORT_ERROR, UPSTREAM_PREFIRSTBYTE_TRANSPORT_ERROR,
    USAGE_TAP_REASSEMBLY_CAP_EXCEEDED,
};

/// Where to charge a request's token usage when its response stream completes (the resolved virtual
/// key + its budget period + the governance store). `None` when governance is off or no key resolved.
#[derive(Clone)]
pub(crate) struct UsageSink {
    pub(crate) gov: Arc<crate::governance::GovState>,
    /// The resolved cost model (chain topology; rates are NOT used at accrual - tokens are the
    /// ledger, spend derives at read time). Arc bump per request, rebuilt on config apply.
    pub(crate) cost: Arc<crate::cost::CostModel>,
    /// The resolved virtual key, shared via `Arc`: `key_id` is read THROUGH it (`key.id`) at
    /// charge time, so building the sink (once per request) and cloning it (once per failover
    /// attempt) is a refcount bump, not a per-request `String` clone.
    pub(crate) key: Arc<crate::governance::VirtualKey>,
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
    pub(crate) admit: Option<Arc<crate::governance::AdmitGrant>>,
}

/// Body wrapper that drives IR-based usage extraction, billing, and mid-stream error handling for
/// streaming responses.
pub(crate) struct FirstByteBody<S, P> {
    inner: S,
    // Plain bool: the flag is only ever read/written from the stream's own poll context (the
    // Arc<AtomicBool> capability was never shared with anyone) — no alloc, no atomics.
    first_byte_sent: bool,
    /// True when the upstream body is an incremental stream (SSE or AWS event-stream). Drives the
    /// after-first-byte error-emission behavior (vs. propagating the error for pre-first-byte
    /// failover). Derived from the UPSTREAM Content-Type.
    is_sse: bool,
    /// The INGRESS protocol the CLIENT speaks (NOT the upstream/egress protocol). A mid-stream error
    /// is emitted in THIS protocol's framing so a native client SDK can decode it — keying the
    /// framing decision off the upstream CT (which on a cross-protocol reframe describes the egress,
    /// not the client) was the bug.
    ///
    /// Held as `&'static str` (the registry interns every protocol name as `&'static`), not an owned
    /// `Box<str>` — the previous `Box::from(ingress_protocol)` heap-allocated + memcpy'd this short
    /// static name on EVERY streaming response. Resolved once in the constructor to the canonical
    /// interned name (falling back to `"openai"` for an unknown ingress, the same default the error
    /// framing already uses), so a streaming response no longer allocates for it.
    ingress_protocol: &'static str,
    /// The operation this response belongs to. Drives whether the non-stream body is buffered for
    /// usage extraction (`taps_nonstream_usage`) and how usage is read from it (`extract_usage`).
    /// Chat reads the egress reader's IR usage; a flat-fee op taps nothing.
    op: crate::handlers::Op,
    /// True when the INGRESS client decodes a binary `application/vnd.amazon.eventstream` body (a
    /// native AWS SDK Bedrock client). A mid-stream error must then be a BINARY exception frame, not
    /// an SSE `event: error` text frame — writing SSE text into a binary eventstream body yields an
    /// undecodable prelude/CRC for the SDK's decoder. Independent of `is_sse` (which reflects the
    /// upstream CT) so a bedrock-ingress → SSE-egress reframe is handled correctly.
    ingress_eventstream: bool,
    permit: Option<P>,
    app: Option<Arc<App>>,
    lane_idx: usize,
    /// Resolved breaker config for the routing pool, so a mid-stream failure trips this lane using
    /// the same thresholds the synchronous path used (defaults on the degraded path).
    breaker_cfg: Arc<crate::store::BreakerCfg>,
    /// Routing pool name, so a mid-stream failure trips this lane's per-pool breaker cell (empty on
    /// the degraded path → the lane-default cell).
    pool: Box<str>,
    /// when Some, translate each egress SSE chunk to the caller's ingress protocol.
    /// None = native passthrough (same-protocol or non-SSE). Held behind the neutral
    /// [`crate::proto::StreamTranslator`] seam so this streaming body never names the concrete
    /// translator.
    translate: Option<Box<dyn crate::proto::StreamTranslator>>,
    /// When set (gemini ingress streaming WITHOUT `?alt=sse`), the SSE bytes — whether from a
    /// same-protocol passthrough or the cross-protocol `translate` stage above, both of which are
    /// gemini SSE here — are reframed into the JSON-array streaming format the native non-`alt=sse`
    /// `:streamGenerateContent` request expects (`[{...},{...}]`). Runs AFTER `translate`.
    json_array: Option<Box<dyn crate::proto::ArrayStreamFramer>>,
    /// When set, the token usage tapped from this response is charged to a virtual key's budget at
    /// stream end (token-accurate accounting). Taken (fired) exactly once when the stream completes.
    usage_sink: Option<UsageSink>,
    /// True when the 2xx-headers `spend_budget(lane_idx)` on this request actually decremented the
    /// lane's `max_requests` budget. A pre-first-byte upstream transport failure on the streaming
    /// path delivers NO usable body, so it must refund that unit — symmetric with the buffered
    /// `ReadEnd::TransportError` path (#21). Guarding the refund on this flag keeps `refund_budget`
    /// (an unconditional `fetch_add`) from raising the budget above its cap when the spend was a
    /// no-op (unlimited lane, or budget already 0). Cleared once a refund fires so it happens once.
    budget_spent: bool,
    /// Set once the stream has fully ended (after any translation terminator), so a later poll
    /// returns None instead of re-polling a finished inner stream.
    ended: bool,
    /// Set when the stream failed via an upstream TRANSPORT error mid/pre-stream (`Poll::Ready(Some(
    /// Err))`). Unlike a reader-emitted in-band `Error` (which sets `translate.terminal_error`) or a
    /// translate buffer-overflow (`translate.aborted`), a raw transport error leaves both clear — so
    /// without this flag the `Drop` billing gate would token-bill the PARTIAL usage accumulated before
    /// the cut, asymmetric with every other failure path (which suppress/refund). Gates `Drop` billing
    /// off, mirroring the terminal-error suppression.
    stream_failed: bool,
    /// Bounded reassembly buffer for a SAME-PROTOCOL NON-STREAM (`!is_sse`, `translate == None`)
    /// `application/json` body that reqwest delivers across multiple transport frames. This is the
    /// non-stream analog of the streaming read-for-IR-emit-verbatim path: the body is relayed to the
    /// client byte-for-byte (each chunk passes through unchanged), but a bounded copy is retained here
    /// so the stream-end arm can run the EGRESS READER over the reassembled body and source `IrUsage`
    /// for billing. Same-proto means egress == ingress, so the body is in the ingress
    /// protocol's native shape and `ingress_protocol`'s reader decodes it.
    ///
    /// Capped at `MAX_TRANSLATED_BODY_BYTES`, but TAIL-anchored, not head-truncated: every dialect's
    /// `usage` object sits at (or near) the END of the response JSON, so once the body exceeds the
    /// cap this buffer drops from the FRONT (oldest bytes) rather than refusing new bytes, keeping
    /// the LAST `cap` bytes at all times. A contiguous `Vec<u8>` (memcpy appends via
    /// `extend_from_slice` on the hot path — it was once a `VecDeque` extended byte-by-byte; the
    /// drop site's comment records the trade): the front drop is `drain(..excess)`, one memmove of
    /// the kept tail per over-cap chunk, paid only on the RARE over-cap response and never on the
    /// common path. `taps_nonstream_usage`
    /// gates this: the client stream is untouched either way (verbatim relay, below). The SSE /
    /// translation paths never touch this (they bill via `translate.usage()`).
    nonstream_buf: Vec<u8>,
    /// Set once `nonstream_buf` has dropped ANY front bytes for this response — the buffer is then a
    /// TAIL FRAGMENT, not a well-formed top-level JSON document, so the stream-end arm routes usage
    /// extraction through `usage::recover_truncated_usage` (isolates the self-contained `usage`
    /// sub-object) instead of `Op::extract_usage` (which needs the whole document and would
    /// otherwise reliably fail to parse a fragment). Also gates the truncation counter/warn to fire
    /// ONCE per response rather than once per over-cap chunk.
    nonstream_buf_truncated: bool,
    /// THE STREAM CEILING — the re-provision of reqwest's total-timeout envelope over the BODY:
    /// a `Sleep` polled BEFORE the inner stream on every wakeup, so expiry cuts the body exactly
    /// as reqwest's `TotalTimeoutBody` did, even while chunks are still flowing. The DEADLINE is
    /// the caller's — the engine passes the one per-attempt instant its send already ran under
    /// (stream: send-start + `limits.upstream_request_timeout_secs`; non-stream passthrough: the
    /// failover-budget remainder), so send + body share ONE envelope anchored at send start,
    /// byte-for-byte reqwest's shape (audit finding F1 closed: no window is unbounded).
    ceiling: std::pin::Pin<Box<tokio::time::Sleep>>,
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
        op: crate::handlers::Op,
        permit: P,
        ceiling_deadline: tokio::time::Instant,
        app: Arc<App>,
        lane_idx: usize,
        breaker_cfg: Arc<crate::store::BreakerCfg>,
        pool: &str,
        translate: Option<Box<dyn crate::proto::StreamTranslator>>,
        json_array: Option<Box<dyn crate::proto::ArrayStreamFramer>>,
        usage_sink: Option<UsageSink>,
        budget_spent: bool,
    ) -> Self {
        let _t = busbar_timing::timeit!("rb_first_byte_body_new");
        // Resolve the ingress protocol ONCE: it supplies both the binary-eventstream flag AND the
        // interned `&'static` name we store (no per-response allocation for the name). An unknown
        // ingress protocol falls back to `openai` — the exact default `ingress_error` /
        // `mid_stream_error_bytes` already use for framing, so the fallback is behavior-preserving.
        // Resolve the ingress protocol ONCE (was two linear `decl_for` scans) — it supplies both the
        // binary-eventstream flag AND the interned `&'static` name we store.
        let ingress_decl = crate::proto::decl_for(ingress_protocol);
        // Arm the stream ceiling on the CALLER's per-attempt deadline — see the `ceiling` field
        // docs for the one-envelope exactness argument.
        let ceiling = Box::pin(tokio::time::sleep_until(ceiling_deadline));
        Self {
            inner,
            first_byte_sent: false,
            is_sse,
            // Whether the client expects a binary event-stream body (Bedrock) rather than SSE text.
            // Dispatches through the `ingress_is_eventstream` vtable method so this constructor carries
            // no `== "bedrock"` branch — a future protocol with binary framing just overrides it.
            ingress_eventstream: ingress_decl.is_some_and(|d| d.ingress_is_eventstream),
            ingress_protocol: ingress_decl.map(|d| d.name).unwrap_or("openai"),
            op,
            permit: Some(permit),
            app: Some(app),
            lane_idx,
            breaker_cfg,
            pool: Box::from(pool),
            translate,
            json_array,
            usage_sink,
            budget_spent,
            ended: false,
            stream_failed: false,
            nonstream_buf: Vec::new(),
            nonstream_buf_truncated: false,
            ceiling,
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
        // Loop so a translated chunk that yields no complete frame yet (partial) re-polls the
        // inner stream instead of emitting an empty chunk to the client.
        loop {
            // The stream ceiling is polled BEFORE the inner stream (registering its waker either
            // way), so expiry cuts even a still-flowing body — reqwest's `TotalTimeoutBody` order,
            // which this re-provides. Both cut causes funnel into the ONE error arm below.
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
                    if !this.first_byte_sent {
                        this.first_byte_sent = true;
                    }
                    // cross-protocol → translate egress SSE bytes to the ingress format. SAME-protocol
                    // → `t.feed` returns the VERBATIM original frame bytes. Billing reads the
                    // IR-derived `t.usage()` at stream end — there is no byte-scanner tap on this
                    // path, so `feed` is the single usage source for both modes.
                    if let Some(t) = this.translate.as_mut() {
                        let out = t.feed(&chunk);
                        let out_bytes = Bytes::from(out);
                        // Gemini non-`alt=sse` ingress: reframe the (now gemini-SSE) bytes into the
                        // JSON-array streaming shape. Run AFTER translate so accounting is unaffected.
                        if let Some(framer) = this.json_array.as_mut() {
                            let framed = framer.feed(&out_bytes);
                            if framed.is_empty() {
                                continue; // no complete object yet; poll inner again
                            }
                            return Poll::Ready(Some(Ok(Bytes::from(framed))));
                        }
                        if out_bytes.is_empty() {
                            continue; // only a partial frame buffered; poll inner again
                        }
                        return Poll::Ready(Some(Ok(out_bytes)));
                    }
                    // Passthrough: the raw chunk is already in the client's shape. This branch is reached
                    // only for (a) a SAME-PROTOCOL NON-STREAM (`!is_sse`) `application/json` body — the
                    // streaming SSE/eventstream same-proto path always builds a `Some(translate)` now —
                    // and (b) the unknown-protocol fallback (`new_same_proto` returned `None`), which has
                    // no reader to drive the IR and therefore no usage source. The bytes always stream to
                    // the client unchanged; for (a) we retain a bounded copy for IR-based billing below.
                    // Only buffer when the operation taps usage from the body AND there is a sink to
                    // bill it to. Chat and the token-billed ops tap; but with governance OFF (or no
                    // resolved key) `usage_sink` is `None`, so the reassembled copy + stream-end
                    // parse+IR-decode below would be pure waste — nothing consumes the extracted usage.
                    // Gating on `usage_sink.is_some()` skips the per-response buffer copy AND the
                    // full-body JSON parse + IR build entirely on the no-governance hot path (a large
                    // RPS/RSS win), while a flat-fee op (or a large-binary response) skips it too. The
                    // bytes still relay verbatim below, unbuffered.
                    if !this.is_sse && this.op.taps_nonstream_usage() && this.usage_sink.is_some() {
                        // SAME-PROTOCOL NON-STREAM `application/json` passthrough: the
                        // non-stream analog of read-for-IR-emit-verbatim. The body relays verbatim,
                        // but a bounded copy is retained so the stream-end arm can source `IrUsage`
                        // for billing from it. Cap at `MAX_TRANSLATED_BODY_BYTES`, but TAIL-anchored:
                        // every dialect's `usage` object lives at (or near) the END of the response
                        // JSON, so once the body exceeds the cap this buffer drops bytes from the
                        // FRONT (oldest) to keep the LAST `cap` bytes, not the first `cap` bytes — the
                        // usage object then survives an over-cap body instead of falling past a
                        // head-truncated cap.
                        // ONE read of the live-reloadable cap: `INSTALLED` is a `RwLock` a config
                        // apply can mutate mid-response (`limits.rs:74-96`), so a second read
                        // later in this same decision could observe a DIFFERENT cap mid-computation.
                        let cap = max_translated_body_bytes();
                        // CONTIGUOUS buffer, memcpy appends. This was a `VecDeque<u8>` extended
                        // element-by-element (`chunk.iter().copied()`) — a per-BYTE write loop on
                        // every governed non-stream passthrough response, replacing what had been a
                        // single `extend_from_slice` memcpy. The tail-anchoring the deque bought is
                        // kept below, but paid only on the RARE over-cap response (already counted
                        // on a dashboard), never on the per-chunk hot path.
                        this.nonstream_buf.extend_from_slice(&chunk);
                        if this.nonstream_buf.len() > cap {
                            let excess = this.nonstream_buf.len() - cap;
                            // Tail-anchor by dropping the OLDEST bytes: one memmove of the kept
                            // tail (`Vec::drain` of a front range), amortized over an over-cap
                            // response's lifetime — not a per-byte cost, and only ever off the
                            // common path.
                            this.nonstream_buf.drain(..excess);
                            if !this.nonstream_buf_truncated {
                                // Fires ONCE per response (the flag stays set for every subsequent
                                // over-cap chunk). Count it so an over-cap body is alertable on a
                                // dashboard even though the tail-anchored buffer now recovers usage
                                // for every dialect this fix covers — a residual undercount (an
                                // unrecognized protocol, or a usage object so large it doesn't fit in
                                // `cap` itself) is still observable here, not silent.
                                this.nonstream_buf_truncated = true;
                                metrics::counter!(crate::metrics::BILLING_TRUNCATED_TOTAL)
                                    .increment(1);
                                diag_debug!(
                                    USAGE_TAP_REASSEMBLY_CAP_EXCEEDED,
                                    cap,
                                    "same-protocol non-stream body exceeded the usage-tap reassembly \
                                     cap; retaining the TAIL (not the head) so the trailing usage \
                                     object still bills correctly for a recognized dialect"
                                );
                            }
                        }
                    }
                    // Gemini same-protocol passthrough WITHOUT `?alt=sse` on the unknown-protocol
                    // fallback: the upstream chunk is gemini SSE (busbar always requests `?alt=sse`
                    // upstream); reframe it into the JSON-array streaming shape the native client
                    // expects. (The known-protocol gemini same-proto path runs through `translate`.)
                    if let Some(framer) = this.json_array.as_mut() {
                        let framed = framer.feed(&chunk);
                        if framed.is_empty() {
                            continue; // no complete object yet; poll inner again
                        }
                        return Poll::Ready(Some(Ok(Bytes::from(framed))));
                    }
                    return Poll::Ready(Some(Ok(chunk)));
                }
                Poll::Ready(Some(Err(e))) => {
                    // An upstream transport error delivered a broken/partial response — suppress
                    // Drop-time token billing (both this SSE arm and the non-SSE arm below), symmetric
                    // with the terminal-error / abort no-bill gates.
                    this.stream_failed = true;
                    let had_first = this.first_byte_sent;
                    if had_first && this.is_sse {
                        // Mid-stream failure after first byte in SSE mode: record breaker failure then emit SSE error event
                        if let Some(ref app) = this.app {
                            let tripped = app.store.record_transient_in(
                                &this.pool,
                                this.lane_idx,
                                "mid-stream",
                                &this.breaker_cfg,
                                None,
                            );
                            // A mid-stream failure that drives a Closed→Open trip is a breaker trip
                            // for this (pool, lane) — emit BREAKER_TRIPS_TOTAL once (#29).
                            if tripped {
                                emit_breaker_trip(app, &this.pool, this.lane_idx);
                            }
                        }
                        // Mark the stream ended so the subsequent `Poll::Ready(None)` arm returns
                        // early instead of re-recording this same failure (the inner stream closes
                        // with `None` right after the error). Without this, one mid-stream transport
                        // failure double-counted against the breaker.
                        drop(this.permit.take());
                        this.ended = true;
                        // The raw reqwest/transport error (`e`) must NEVER reach the client body: its
                        // Display embeds hyper/reqwest/tokio internals and the egress backend URL
                        // (hostname, region, port) — a protocol-indistinguishability tell (no native
                        // AI vendor emits hyper/reqwest strings) AND an infrastructure-disclosure leak.
                        // Log the real cause server-side for operator observability, then put only a
                        // static, vendor-neutral detail into the client-facing frame. A native vendor
                        // mid-stream interruption carries a generic message, never a backend URL.
                        diag_debug!(
                            UPSTREAM_MIDSTREAM_TRANSPORT_ERROR,
                            ingress = %this.ingress_protocol,
                            error = %e,
                            "mid-stream upstream transport error; returning generic interruption to client"
                        );
                        // Gemini JSON-array ingress (non-`alt=sse`): the client has been receiving a
                        // streaming JSON ARRAY (`[obj,obj`), so the in-band error MUST be a valid
                        // trailing array element followed by the closing `]` — NOT the SSE text frame
                        // `mid_stream_error_bytes` produces. Emitting `event: error\ndata:{...}` into a
                        // JSON-array body splices non-JSON into the array (unparseable) and is a
                        // protocol tell (a native Gemini JSON-array stream never contains SSE framing).
                        // Route the error through the framer instead: a Gemini `google.rpc.Status`
                        // element + `]`.
                        if let Some(framer) = this.json_array.as_mut() {
                            // The framer owns the wire status/code shape (Gemini → 500/`INTERNAL`); the
                            // agnostic core supplies only the generic message.
                            let err_bytes =
                                framer.finish_with_server_error(MID_STREAM_GENERIC_DETAIL);
                            return Poll::Ready(Some(Ok(Bytes::from(err_bytes))));
                        }
                        // Emit the error in the INGRESS protocol's framing, NOT a hard-coded SSE
                        // text frame. For a bedrock-ingress client (binary eventstream) this is a
                        // valid AWS exception frame; for SSE clients it is shaped to the ingress
                        // protocol's native error envelope. Keying off `is_sse` (the upstream CT)
                        // alone would inject SSE text into a binary eventstream body on a
                        // bedrock-ingress → SSE-egress reframe — an undecodable frame for the SDK.
                        let err_bytes = mid_stream_error_bytes(
                            this.ingress_protocol,
                            this.ingress_eventstream,
                            MID_STREAM_GENERIC_DETAIL,
                        );
                        return Poll::Ready(Some(Ok(Bytes::from(err_bytes))));
                    } else {
                        // Before first byte or non-SSE: terminate the body stream with an error. The
                        // raw reqwest error (with its embedded backend URL / hyper internals) must not
                        // ride out on the io::Error either — log the real cause server-side and surface
                        // only a generic, vendor-neutral message on the stream item.
                        diag_debug!(
                            UPSTREAM_PREFIRSTBYTE_TRANSPORT_ERROR,
                            ingress = %this.ingress_protocol,
                            error = %e,
                            "pre-first-byte upstream transport error; terminating body stream generically"
                        );
                        // Transport failure on the streaming path - reached for a PRE-first-byte failure
                        // (either SSE or non-SSE) and for a post-first-byte NON-SSE mid-body failure
                        // (the post-first-byte SSE case is handled by the if-branch above). In ALL of
                        // these the 2xx headers already recorded an optimistic breaker SUCCESS (via
                        // `record_success_in`), but the response never arrived intact, so that success is
                        // wrong. Record a COMPENSATING transient so the failure counts against the lane.
                        //
                        // The transient is recorded UNCONDITIONALLY on the transport failure - it is
                        // NOT gated on `had_first`. Gating it there recorded nothing for a
                        // pre-first-byte failure (treated as "refund-only, no body content emitted"),
                        // which meant a lane that connects, returns headers, then dies before the first
                        // byte on EVERY attempt kept accruing optimistic successes and NEVER tripped its
                        // circuit breaker - traffic pinned to a black-hole lane. A pre-first-byte
                        // transport death IS a lane fault (the connection was accepted then broke with
                        // zero usable bytes), exactly like the buffered `ReadEnd::TransportError` paths,
                        // which already record a transient with no first-byte gate. Budget is still
                        // refunded below (no usable response was delivered); the two are independent.
                        if let Some(ref app) = this.app {
                            let what = if had_first {
                                "mid-body-transport"
                            } else {
                                "pre-first-byte-transport"
                            };
                            let tripped = app.store.record_transient_in(
                                &this.pool,
                                this.lane_idx,
                                what,
                                &this.breaker_cfg,
                                None,
                            );
                            // A threshold-based Closed→Open trip here is a breaker trip (#29).
                            if tripped {
                                emit_breaker_trip(app, &this.pool, this.lane_idx);
                            }
                        }
                        // Symmetric with the buffered `ReadEnd::TransportError` path (#21): the 2xx
                        // headers already spent one `max_requests` budget unit on this lane, but a
                        // pre-first-byte body transport failure delivers NO usable response — so refund
                        // that unit, or sustained streaming transport failures would permanently drain
                        // the lane's serving-capacity budget one unit at a time. Without this refund the
                        // streaming path leaked units here while the buffered paths did not. Refund
                        // ONLY when the headers-spend actually decremented (`budget_spent`): a no-op
                        // spend (unlimited lane, or budget already 0) must not be refunded, since
                        // `refund_budget` is an unconditional `fetch_add` that would otherwise push the
                        // budget above its cap. Mark the stream ended and clear the flag so the inner
                        // stream's trailing `Poll::Ready(None)` neither double-refunds nor token-bills.
                        if this.budget_spent {
                            if let Some(ref app) = this.app {
                                app.store.refund_budget(this.lane_idx);
                            }
                            this.budget_spent = false;
                        }
                        drop(this.permit.take());
                        this.ended = true;
                        return Poll::Ready(Some(Err(std::io::Error::other(
                            MID_STREAM_GENERIC_DETAIL,
                        ))));
                    }
                }
                Poll::Ready(None) => {
                    // Stream ended. A clean `Poll::Ready(None)` is the NORMAL termination for both
                    // clean and truncated streams and is NOT a failure — success was already
                    // recorded synchronously (record_success_in) before streaming began. Only record
                    // a breaker failure here if the tap actually saw a terminal ERROR frame
                    // (`{"type":"error", ...}`) mid-stream. Previously this arm recorded a failure on
                    // EVERY completed SSE stream, so healthy streaming lanes tripped after a handful
                    // of successful requests.
                    //
                    // Hoist the TRANSLATE-side abort flag ONCE, at the top of this arm, BEFORE
                    // `finish()` consumes the translate below. A cross-protocol `StreamTranslate`
                    // that overflowed `MAX_BUF` (>16MiB without a frame terminator) or hit a
                    // malformed egress prelude calls `abort()` and stops feeding the body — but it
                    // leaves `tap.terminal_error` clear (no in-band `{"type":"error"}` frame was ever
                    // scanned). That is the SIBLING condition to a mid-body terminal error:
                    // both deliver a partial/aborted response the caller cannot use, so BOTH must be
                    // treated as a failed stream by ALL THREE downstream gates (breaker, token
                    // billing, json-array byte-shaping). The json-array close path below previously
                    // read `aborted()` locally for its own byte-shaping; that single read is hoisted
                    // here and reused so the three gates can never diverge.
                    let translate_aborted = this
                        .translate
                        .as_ref()
                        .map(|t| t.aborted())
                        .unwrap_or(false);
                    // A stream is FAILED for breaker purposes when EITHER a reader-emitted terminal ERROR
                    // event was seen (the IR-sourced `translate.terminal_error()`) OR the cross-protocol
                    // translate aborted mid-flight. Every same-proto/cross-proto SSE+eventstream stream flows
                    // through `translate`, so the terminal error is observable at this point in the arm
                    // for all of them; the billing gate re-evaluates the same predicate AFTER the bedrock
                    // deferred `finish()` below (whose `metadata` frame can surface usage/error at end).
                    let stream_terminal_error = this
                        .translate
                        .as_ref()
                        .and_then(|t| t.terminal_error())
                        .is_some();
                    let breaker_failed = stream_terminal_error || translate_aborted;
                    if this.is_sse && this.first_byte_sent && breaker_failed {
                        if let Some(app) = this.app.as_ref() {
                            // Distinguish the two failure lineages in the recorded reason so the
                            // terminal-error path and its translate-abort sibling remain
                            // separable in breaker telemetry.
                            let reason = if stream_terminal_error {
                                "stream-terminal-error"
                            } else {
                                // translate_aborted must hold here (breaker_failed && no
                                // terminal_error) — name the sibling lineage explicitly.
                                "stream-translate-abort"
                            };
                            let tripped = app.store.record_transient_in(
                                &this.pool,
                                this.lane_idx,
                                reason,
                                &this.breaker_cfg,
                                None,
                            );
                            // A terminal-error frame OR translate abort that drives a Closed→Open
                            // trip is a breaker trip for this (pool, lane) — emit BREAKER_TRIPS_TOTAL
                            // once (#29). This is also the arm `response.failed` recognition reaches
                            // for a streaming Responses FAILURE, which would otherwise record as a
                            // success.
                            if tripped {
                                emit_breaker_trip(app, &this.pool, this.lane_idx);
                            }
                        }
                    }
                    // emit the ingress terminator before close. `finish()` can emit CONTENT frames — the
                    // deferred terminal `message_delta` carrying the folded trailing usage (see
                    // StreamTranslate::finish / `folds_terminal_usage`). Drain it ONCE here so both the
                    // decode side-effects run and the bytes are available to deliver.
                    let tail = this
                        .translate
                        .as_mut()
                        .map(|t| t.finish())
                        .unwrap_or_default();
                    // For a gemini JSON-array stream the terminator is the closing `]` from the framer.
                    // finish()'s content frames MUST still reach the client, so feed them THROUGH the
                    // framer (wrapping them as array elements) rather than discarding them — the fix for
                    // the non-uniform delivery contract where the SSE path delivered finish() but the
                    // json-array path dropped it, silently losing the terminal usage. A json-array
                    // ingress is always gemini, whose finish() never carries the SSE `[DONE]` literal
                    // (emit_done is false), so nothing spurious is wrapped. The TRANSLATE-side abort flag
                    // was hoisted above; `finish_for_translate(translate_aborted)` still surfaces a
                    // NATIVE error element + `]` on an aborted stream, not a silently-truncated bare `]`.
                    // For a plain SSE ingress `tail` is streamed as-is (the [DONE] literal, if any, is
                    // an OpenAI-ingress terminator finish() itself appends).
                    let done = if let Some(framer) = this.json_array.as_mut() {
                        // On a translate ABORT, `tail` IS the native error frame from finish(), and
                        // `finish_for_translate(true)` already surfaces the canonical json-array error
                        // element + `]`. Feeding `tail` too would wrap a SECOND (differently-worded)
                        // error element — the 1.4.0 double-emit regression (1.3.0 discarded `tail`). So
                        // feed `tail` ONLY on the non-aborted path, where it carries finish()'s content /
                        // trailing-usage frames that must reach the client.
                        let mut wrapped = if translate_aborted {
                            Vec::new()
                        } else {
                            framer.feed(&tail)
                        };
                        wrapped.extend_from_slice(&framer.finish_for_translate(translate_aborted));
                        wrapped
                    } else {
                        tail
                    };
                    // Bedrock ingress: `finish()` may emit a deferred terminal `metadata` frame (the
                    // default-OpenAI-streaming case carries usage there). Its usage is folded into the
                    // translator's `last_usage` A-tap by `finish()` itself, so `translate.usage()` below
                    // already reflects it — no separate tap-feed of the binary `done` bytes is needed.
                    drop(this.permit.take());
                    this.ended = true;
                    // Token usage for billing, sourced from the IR:
                    //   - STREAMING (SSE / eventstream, same- or cross-proto): `translate.usage()` — the
                    //     terminal `IrUsage` the readers accumulated, post Anthropic start-usage backfill.
                    //   - SAME-PROTOCOL NON-STREAM (`!is_sse`, `translate == None`): run the EGRESS reader
                    //     (`ingress_protocol`'s reader — same-proto, egress == ingress) over the
                    //     reassembled `nonstream_buf` body and read `ir.usage`. The body
                    //     was relayed verbatim; this is the read-for-IR side-channel for billing.
                    // The unknown-protocol fallback passthrough has no reader and yields `None` (no usage
                    // source — same as before; an unknown protocol cannot be metered).
                    // Skip usage extraction ENTIRELY when there is no sink to bill (governance off /
                    // no key): the terminal-usage clone and the non-stream reader run only to feed
                    // `record_tokens`, which the `usage_sink.take()` gate below no-ops.
                    // Projected to the neutral `billing::TokenUsage` at the boundary: the streaming
                    // producer (`translate.usage()`, now the `StreamTranslator` seam) hands back the
                    // OWNED token totals directly; the non-stream producers (the truncated-tail
                    // recovery, `op.extract_usage`) still hand back the concrete `IrUsage`, projected
                    // here. Either way the billing consumers below speak token totals and name zero
                    // concrete IR. Byte-identical (the projection carries the four billed totals).
                    let token_usage: Option<crate::billing::TokenUsage> =
                        if this.usage_sink.is_none() {
                            None
                        } else if let Some(t) = this.translate.as_ref() {
                            t.usage()
                        } else if !this.is_sse && !this.nonstream_buf.is_empty() {
                            // Same-protocol non-stream body relayed verbatim; the operation reads
                            // usage from the reassembled bytes. Chat runs the egress reader and
                            // reports IR usage (byte-identical to the previous inline read); a
                            // flat-fee op returns None and bills nothing.
                            let truncated = this.nonstream_buf_truncated;
                            let buf: Vec<u8> = std::mem::take(&mut this.nonstream_buf);
                            if truncated {
                                // The buffer is a TAIL FRAGMENT (its head was dropped to stay within
                                // cap), not a well-formed top-level document — `Op::extract_usage`'s
                                // full-document parse would reliably fail on it. Isolate and parse just
                                // the self-contained `usage` sub-object instead (see
                                // `usage::recover_truncated_usage`'s doc comment for why this is safe and
                                // why it duplicates rather than reuses each reader's field mapping).
                                crate::proto::decl_for(this.ingress_protocol)
                                    .and_then(|d| d.dialect())
                                    .and_then(|di| di.recover_truncated_usage(&buf))
                            } else {
                                this.op.extract_usage(this.ingress_protocol, &buf)
                            }
                        } else {
                            None
                        };
                    // Charge this request's token usage to the virtual key's budget (once) — but ONLY
                    // for a cleanly-terminated stream. A stream that saw a reader-emitted terminal ERROR
                    // event (`translate.terminal_error()`) OR whose cross-protocol translate aborted
                    // mid-flight (`translate_aborted`) delivered a partial/aborted response the caller
                    // cannot use, and billing it contradicts the flat-fee-only-on-success policy (the
                    // per-request fee is charged at admission by
                    // `ingress::budget_check`→`try_charge_request_within_budget`, and `ingress::finish`
                    // REFUNDS it on a non-2xx, so the net flat fee lands only on a 2xx). Mirror that
                    // here with the SAME `failed` predicate the breaker gate above uses: a failed
                    // stream is not token-billed, covering BOTH the SSE-ingress and json-array close
                    // paths (the json-array path previously fell through and billed an aborted
                    // stream's partial tokens). A same-proto non-stream body has no terminal-error/abort
                    // path here (it is `!is_sse`), so `billing_failed` is false there.
                    if let Some(sink) = this.usage_sink.take() {
                        // Re-read the terminal error AFTER the deferred bedrock `finish()` above (whose
                        // `metadata`/exception frame can surface an error only at stream end), OR'd with
                        // the hoisted translate-abort flag — keeping the SAME failed semantics the breaker
                        // gate used. An aborted translate's `feed` is a no-op, so the `translate_aborted`
                        // snapshot taken at the top of the arm is still authoritative.
                        let billing_failed = this
                            .translate
                            .as_ref()
                            .and_then(|t| t.terminal_error())
                            .is_some()
                            || translate_aborted;
                        if !billing_failed {
                            // Ledger + meter the SERVING lane (`lane_idx` is the lane that
                            // actually answered, post-failover) through the one accrual seam.
                            // Readers normalize `input_tokens` to UNCACHED and keep the cache
                            // fields ADDITIVE, so the four tiers are correct provider-agnostically.
                            let tier = token_usage
                                .as_ref()
                                .map(crate::proxy::usage::tier_tokens)
                                .unwrap_or_default();
                            if let Some(lane) =
                                this.app.as_ref().and_then(|a| a.lanes.get(this.lane_idx))
                            {
                                crate::proxy::usage::ledger_and_meter(
                                    &sink,
                                    lane,
                                    token_usage.as_ref(),
                                    &tier,
                                );
                            }
                        }
                    }
                    if !done.is_empty() {
                        return Poll::Ready(Some(Ok(Bytes::from(done))));
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
        // Cancellation: the stream was dropped before reaching any terminal arm (`ended` is set only
        // by the three deliberate exits - mid-stream SSE error, pre-first-byte/non-SSE transport
        // error, and clean end - none of which leave it false). A pre-first-byte or mid-stream client
        // disconnect / LB reset otherwise leaks the headers-time `spend_budget` unit forever.
        // `budget_spent` guards both against refunding a no-op spend and against double-refunding
        // the transport-error arm's own clear of the flag.
        if !self.ended && self.budget_spent {
            if let Some(ref app) = self.app {
                app.store.refund_budget(self.lane_idx);
            }
            self.budget_spent = false;
        }
        // Token-fee billing normally fires in `Poll::Ready(None)` (natural stream end), which TAKES
        // `usage_sink`. So a `None` here means "already billed" and this Drop is a no-op — no
        // double-charge. A `Some` means the body was DROPPED MID-STREAM (client disconnect /
        // cancellation) before the natural end, so the token-fee site never ran and the tokens already
        // generated + delivered would go unbilled — an under-billing on every cancel. Bill the
        // tokens the readers accumulated up to the drop point instead.
        //
        // Best-effort: the provider's terminal usage frame may not have arrived before the cancel, so
        // `translate.usage()` may be partial or absent — partial/zero usage bills partial/zero
        // (`record_tokens` no-ops on 0 tokens). Only the streaming `translate.usage()` source is
        // consulted; a partially-buffered same-proto non-stream body cannot be reliably parsed for
        // usage, so it is not billed on a mid-buffer drop.
        let Some(sink) = self.usage_sink.take() else {
            return;
        };
        // Mirror the `Poll::Ready(None)` failed-gate EXACTLY: do not bill a stream that surfaced a
        // terminal reader error OR whose cross-protocol translate aborted mid-flight (buffer overflow
        // etc.) — both delivered a partial/aborted response the caller cannot use, and billing either
        // contradicts the no-bill-on-failure policy (asserted by
        // `test_streaming_translate_abort_trips_breaker_and_skips_billing`).
        let translate = self.translate.as_ref();
        if self.stream_failed
            || translate.and_then(|t| t.terminal_error()).is_some()
            || translate.map(|t| t.aborted()).unwrap_or(false)
        {
            return;
        }
        let usage = self.translate.as_ref().and_then(|t| t.usage());
        let tier = usage
            .as_ref()
            .map(crate::proxy::usage::tier_tokens)
            .unwrap_or_default();
        if !tier.is_zero() {
            if let Some(lane) = self.app.as_ref().and_then(|a| a.lanes.get(self.lane_idx)) {
                // Ledger + meter the partial through the one accrual seam (the tokens were
                // really generated + delivered before the drop).
                crate::proxy::usage::ledger_and_meter(&sink, lane, usage.as_ref(), &tier);
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
