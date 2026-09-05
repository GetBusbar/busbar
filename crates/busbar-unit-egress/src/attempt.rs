// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE ONE ATTEMPT — the single place in this unit that sends a request to a destination and turns
//! what comes back into a breaker outcome and an answer for the client.
//!
//! Both the ordered walk and every degraded terminal call [`attempt`] with an [`AttemptInput`]
//! describing the posture of one hop, and each maps the [`AttemptOutcome`] with its own policy:
//! the walk fails over on a failure, a degraded caller relays the upstream's answer when one came
//! back and tries the next member only when nothing came back at all. Everything that must happen
//! exactly once per attempt — the durable dispatch record, probe ownership, the encode, the
//! decoration, the lane cross-check, the send with its two deadlines, the breaker record, the
//! budget spend and its refund guard, the per-frame decode — lives here and nowhere else.
//!
//! The stages, in call order, and the design's own sentence about each:
//!
//! 1. a delta record durable BEFORE the dial;
//! 2. the dial, from the pool, with the breaker already consulted for this attempt;
//! 3. the wire request from the verified destination plus the plane's egress encode;
//! 4. the egress-auth unit decorates it;
//! 5. the lane cross-check, on the POST-DECORATION bytes;
//! 6. the send;
//! 7. the plane's response decode, per frame, relayed under the hold.

use busbar_caps::{Route, UnitToken};
use busbar_contract::{Ctx, EgressBody, Frame, Plane, Transport, Unit};
use busbar_contract_transport::wire::{Conn, StatusClass};
use futures::StreamExt;

use crate::ports::{
    disposition, net, Breaker, Capacity, Classified, Clock, DestinationId, Dispatched, Disposition,
    EgressAuth, Journal, OutboundRequest, Outcome, Permit, Telemetry, UpstreamStatus,
};
use crate::race;
use crate::select::ProbeGuard;
use crate::wire::{Delivered, Shed};

/// Everything one hop shares, borrowed and cheap to pass down the stages.
///
/// The fields that differ between the ordered walk and a degraded terminal are plain inputs here,
/// so the two postures are data rather than two copies of the code: `degraded` selects the
/// degraded diagnostics and asks for the relayed upstream answer a degraded caller returns instead
/// of failing over, and `metric_pool` carries the label the caller resolved.
pub struct Hop<'a> {
    /// The breaker unit.
    pub breaker: &'a dyn Breaker,
    /// The capability token proving the loop is at the route step for this unit right now, lent
    /// down from [`crate::Egress::route`]'s own `&UnitToken<Route>` and threaded through to every
    /// [`Breaker::observe`] call this hop makes.
    pub token: &'a UnitToken<Route>,
    /// The pool's permit store. Held so a failure can drop the permit at the exact point the
    /// previous release dropped it.
    pub capacity: &'a dyn Capacity,
    /// The write-ahead journal.
    pub journal: &'a dyn Journal,
    /// The egress-auth unit.
    pub egress_auth: &'a dyn EgressAuth,
    /// The node's clock and its only sleep.
    pub clock: &'a dyn Clock,
    /// The counters.
    pub telemetry: &'a dyn Telemetry,
    /// The transport that dials this destination.
    pub transport: &'a dyn Transport,
    /// The plane that says what the bytes mean.
    pub plane: &'a dyn Plane,
    /// The transport's key material.
    pub keys: &'a busbar_contract::TransportKeyHandle,
    /// The destination the trust unit sealed.
    pub dest: &'a busbar_contract::VerifiedDestination,
    /// Which member of the verified set this is.
    pub destination: DestinationId,
    /// Which pool cell this attempt records against. The empty name is the default cell.
    pub pool: &'a str,
    /// The metric label for this hop, which the caller resolved. It is not always the pool name:
    /// on the default cell the previous release labelled by the member's own name so the series
    /// correlated with the request counter.
    pub metric_pool: &'a str,
    /// Which leg of the route plan this is.
    pub leg: u8,
    /// Which attempt of the walk this is, counted from one.
    pub attempt_no: u32,
    /// The member's own cap on time to response headers, where it overrides the destination's.
    pub attempt_timeout_ms: Option<u64>,
    /// Whether the client asked for an incremental answer.
    pub wants_stream: bool,
    /// How many whole seconds are left of the walk's deadline.
    pub remaining_secs: u64,
    /// The client-level ceiling that bounds a streamed answer, in whole seconds.
    pub stream_ceiling_secs: u64,
    /// The envelope field the lane name is carried in, where the transport carries one.
    pub lane_field: Option<&'a str>,
    /// Which stream of the connection this request goes out on.
    pub stream: busbar_contract::StreamId,
    /// Whether this hop is a degraded one.
    pub degraded: bool,
}

/// Everything one attempt needs: the hop, the slot it holds, the probe it may own, and the unit
/// and context the plane is called with.
pub struct AttemptInput<'a> {
    /// The hop.
    pub hop: Hop<'a>,
    /// The concurrency slot the caller took. Held for the life of a delivered answer, dropped at
    /// every failure.
    pub permit: Permit,
    /// Set only when the caller's pick won a single-flight recovery probe on this cell. This
    /// attempt then owns its release. The one documented breaker bypass passes `None` and so
    /// builds no guard at all, which is what stops it ever reverting a probe a peer won.
    pub probe_epoch: Option<u64>,
    /// The unit, as the plane reads it.
    pub unit: &'a Unit<'a>,
    /// The context the plane is called with.
    pub ctx: &'a Ctx<'a>,
}

/// What one attempt produced.
#[derive(Debug)]
pub enum AttemptOutcome {
    /// An upstream answered and its frames were relayed.
    Delivered(Delivered),
    /// The upstream did not serve this request and the destination's breaker has been told why.
    /// The caller decides between failing over and relaying: `relay` carries the upstream's own
    /// answer when the caller asked for it and there was one to relay — never for a transport
    /// failure or a cap that fired before any answer arrived.
    Failed {
        /// Where the walk sends the request next.
        disposition: Disposition,
        /// The metric label for this failure.
        err_type: &'static str,
        /// The upstream's own answer, for a degraded caller that relays instead of failing over.
        relay: Option<Delivered>,
    },
    /// The attempt could not be assembled: nothing was sent and nothing was recorded against the
    /// destination. The caller returns this refusal.
    Bail(Shed),
}

/// The three ways a send can end, so the cap and the deadline compose without nesting error types.
enum SendOutcome {
    /// An answer, or a transport failure.
    Sent(Result<FirstFrame, busbar_contract_transport::wire::TransportError>),
    /// The per-attempt cap fired before any answer arrived.
    AttemptTimeout(u64),
    /// The walk's own deadline expired.
    BudgetTimeout,
}

/// The connection, the frame that came back first, and the pump the rest will come from.
struct FirstFrame {
    conn: Conn,
    frame: Frame,
    frames: busbar_contract::transport::FrameStream,
}

/// The attempt's outer deadline: what is left of the walk's budget for a buffered answer, the
/// client-level ceiling for a streamed one. Anchored at send start.
///
/// Bounding a stream with the (much shorter) walk budget would truncate a healthy long answer;
/// bounding it with nothing would let a black-holed upstream hold the send open forever with no
/// signal to the breaker. Both deadlines are floored at one second, because a zero-length deadline
/// would fail an attempt before it was tried.
fn send_deadline_ms(hop: &Hop<'_>) -> u64 {
    let secs = if hop.wants_stream {
        hop.stream_ceiling_secs.max(1)
    } else {
        hop.remaining_secs.max(1)
    };
    secs.saturating_mul(1000)
}

/// The per-attempt cap on time to the first answer, floored by what the walk has left. A cap can
/// never grant more time than the request still has, and it is never zero.
fn attempt_cap_ms(ms: u64, remaining_secs: u64) -> u64 {
    ms.min(remaining_secs.saturating_mul(1000).max(1))
}

/// Give back one unit of lifetime budget when a delivery that spent it does not complete.
///
/// The spend happens after the upstream's success is read, which leaves a window: the answer's
/// body may still fail to arrive. This is armed for exactly that window, disarmed at every exit
/// that must keep the charge, and — because the refund on the other side is unconditional — armed
/// only when the spend actually happened.
struct BudgetGuard<'a> {
    breaker: &'a dyn Breaker,
    destination: DestinationId,
    armed: bool,
}

impl BudgetGuard<'_> {
    fn disarm(&mut self) {
        self.armed = false;
    }
}

impl Drop for BudgetGuard<'_> {
    fn drop(&mut self) {
        if self.armed {
            self.breaker.refund_budget(self.destination);
        }
    }
}

/// The one attempt.
pub async fn attempt(input: AttemptInput<'_>) -> AttemptOutcome {
    let AttemptInput {
        hop,
        permit,
        probe_epoch,
        unit,
        ctx,
    } = input;
    let now = hop.clock.now_secs();

    // Probe ownership for the whole attempt window, armed only when this dispatch won one. If this
    // future is dropped part-way the guard releases the probe owner-checked, so the cell never
    // wedges half-open; it stays armed across every failure exit — each records an outcome first,
    // which makes the release a safe no-op — and is disarmed once a success is recorded.
    let mut probe_guard = probe_epoch
        .map(|epoch| ProbeGuard::new(hop.breaker, hop.pool, hop.destination, epoch, now));

    // 1. The delta record, durable BEFORE the dial. A dispatch this unit cannot prove it recorded
    //    is a dispatch that must not happen, so a failure here sends nothing and records nothing
    //    against the destination — the armed probe guard gives the probe back on return.
    let record = Dispatched {
        leg: hop.leg,
        attempt: hop.attempt_no,
        pool: hop.pool.to_string(),
        destination: hop.destination,
        lane: hop.dest.lane(),
    };
    if hop.journal.dispatched(&record).is_err() {
        drop(permit);
        return AttemptOutcome::Bail(Shed::internal());
    }

    // 2-5. Assemble: the plane's egress encode, the egress-auth decoration, and the lane
    //      cross-check on the bytes that decoration produced. A failure at any of the three is an
    //      internal failure before any send.
    let wire = match assemble(&hop, unit, ctx) {
        Ok(bytes) => bytes,
        Err(shed) => {
            hop.journal.abandoned(&record);
            drop(permit);
            return AttemptOutcome::Bail(shed);
        }
    };

    hop.telemetry
        .upstream_attempt(hop.metric_pool, hop.destination);

    // 6. The send, under the outer deadline with the per-attempt cap raced inside it.
    let deadline_ms = send_deadline_ms(&hop);
    let cap_ms = hop
        .attempt_timeout_ms
        .map(|ms| attempt_cap_ms(ms, hop.remaining_secs));
    let outcome = send(&hop, &wire, deadline_ms, cap_ms).await;

    let first = match outcome {
        SendOutcome::AttemptTimeout(ms) => {
            hop.journal.abandoned(&record);
            drop(permit);
            return attempt_timeout(&hop, ms, now);
        }
        SendOutcome::BudgetTimeout => {
            hop.journal.abandoned(&record);
            drop(permit);
            return transport_failure(&hop, net::TIMEOUT, now);
        }
        SendOutcome::Sent(Err(e)) => {
            hop.journal.abandoned(&record);
            drop(permit);
            let label = if matches!(e, busbar_contract_transport::wire::TransportError::Timeout) {
                net::TIMEOUT
            } else {
                net::CONNECT
            };
            return transport_failure(&hop, label, now);
        }
        SendOutcome::Sent(Ok(first)) => first,
    };

    // 7. The answer. The transport's status reading on the first frame is the leg the fee decision
    //    reads and the leg the breaker is told about; the plane's own decode runs per frame from
    //    here on.
    let status = UpstreamStatus {
        class: first.frame.meta.status,
        code: None,
        retry_after: None,
    };
    let succeeded = matches!(first.frame.meta.status, Some(StatusClass::Success) | None);
    if !succeeded {
        return classify_failure(&hop, status, permit, now);
    }

    deliver(&hop, first, permit, &mut probe_guard, ctx, now).await
}

// ── assemble ────────────────────────────────────────────────────────────────────────────────────

/// The wire request: the envelope the plane built with the decoration applied, then the body.
struct Wire {
    bytes: Vec<u8>,
}

/// Build the outbound request, decorate it, and check the lane on what came out.
///
/// The order here is the design's and it is the whole point of the step: the plane encodes for the
/// destination but never holds a credential; the egress-auth unit decorates and substitutes every
/// secret itself; and the lane cross-check runs on the RESULT, so a decoration cannot quietly move
/// the request onto a cheaper or a different lane.
fn assemble(hop: &Hop<'_>, unit: &Unit<'_>, ctx: &Ctx<'_>) -> Result<Wire, Shed> {
    let encoded: EgressBody<'_> = hop
        .plane
        .encode_egress(unit, hop.dest, None, ctx)
        .map_err(|_| Shed::internal())?;

    let mut request = OutboundRequest {
        fields: encoded
            .envelope
            .fields
            .as_slice()
            .iter()
            .map(|f| (f.name.to_string(), f.value.as_slice().to_vec()))
            .collect(),
        body: encoded.body.as_slice(),
        scheme: encoded.auth,
        body_signature: None,
    };
    hop.egress_auth
        .decorate(&mut request)
        .map_err(|_| Shed::internal())?;

    // The byte layout of an envelope belongs to the transport, and this asks the transport for it.
    // This unit used to write a neutral one — every field as `name: value`, a blank line, the body
    // — because it must run the lane cross-check over the same bytes it hands to `write` and had
    // nothing else to run it over. That made the check honest about ONE buffer and wrong about
    // which bytes were in it: no wire in the design has ever looked like that.
    //
    // The fields are the POST-DECORATION ones, so what the egress-auth unit added and what it
    // substituted a secret into are in the bytes the cross-check reads.
    let mut fields: Vec<(&str, &[u8])> = request
        .fields
        .iter()
        .map(|(name, value)| (name.as_str(), value.as_slice()))
        .collect();
    if let Some(signature) = &request.body_signature {
        fields.push(("signature", signature.as_slice()));
    }
    let bytes = hop
        .transport
        .encode_envelope(&fields, request.body, ctx.arena())
        .map_err(|_| Shed::internal())?
        .as_slice()
        .to_vec();

    lane_cross_check(hop, &request)?;
    Ok(Wire { bytes })
}

/// The lane cross-check, on the post-decoration request.
///
/// Two things are checked and they are different. First, the decoration may not have written the
/// field the lane name is read out of — an egress-auth scheme that could set it could re-price the
/// request. Second, where the envelope names a lane at all, the name must be the one the trust
/// unit sealed on the destination.
fn lane_cross_check(hop: &Hop<'_>, request: &OutboundRequest<'_>) -> Result<(), Shed> {
    let Some(field) = hop.lane_field else {
        return Ok(());
    };
    let Some((_, value)) = request.fields.iter().find(|(name, _)| name == field) else {
        return Ok(());
    };
    let Some(sealed) = hop.dest.lane() else {
        return Ok(());
    };
    if value.as_slice() == sealed.as_str().as_bytes() {
        Ok(())
    } else {
        Err(Shed::internal())
    }
}

// ── send ────────────────────────────────────────────────────────────────────────────────────────

/// Dial, write and wait for the first answering frame, under both deadlines.
async fn send(hop: &Hop<'_>, wire: &Wire, deadline_ms: u64, cap_ms: Option<u64>) -> SendOutcome {
    let work = async {
        let conn = match race::with_deadline(
            hop.transport.dial(hop.dest, hop.keys),
            hop.clock.sleep(deadline_ms),
        )
        .await
        {
            Ok(Ok(conn)) => conn,
            Ok(Err(e)) => return SendOutcome::Sent(Err(e)),
            Err(race::Elapsed) => return SendOutcome::BudgetTimeout,
        };
        let bytes = busbar_contract::ArenaBytes::new(&wire.bytes);
        if let Ok(Err(e)) = race::with_deadline(
            hop.transport.write(&conn, hop.stream, bytes),
            hop.clock.sleep(deadline_ms),
        )
        .await
        {
            return SendOutcome::Sent(Err(e));
        }
        let mut frames = hop.transport.frames(conn.clone());
        // The per-attempt cap is the hang detector and it covers exactly this: the time to the
        // FIRST answering frame. Once a frame is in hand the cap is done and only the outer
        // deadline remains.
        let first = match cap_ms {
            Some(ms) => match race::with_deadline(frames.next(), hop.clock.sleep(ms)).await {
                Ok(f) => f,
                Err(race::Elapsed) => return SendOutcome::AttemptTimeout(ms),
            },
            None => frames.next().await,
        };
        match first {
            Some(Ok((_, frame))) => SendOutcome::Sent(Ok(FirstFrame {
                conn,
                frame,
                frames,
            })),
            Some(Err(e)) => SendOutcome::Sent(Err(e)),
            None => SendOutcome::Sent(Err(busbar_contract_transport::wire::TransportError::Closed)),
        }
    };
    match race::with_deadline(work, hop.clock.sleep(deadline_ms)).await {
        Ok(outcome) => outcome,
        Err(race::Elapsed) => SendOutcome::BudgetTimeout,
    }
}

// ── classify ────────────────────────────────────────────────────────────────────────────────────

/// The per-attempt cap fired before any answer arrived: a transient failure on this pool's cell,
/// counted under its own label so a hang is visible separately from a refusal.
fn attempt_timeout(hop: &Hop<'_>, _ms: u64, now: u64) -> AttemptOutcome {
    let tripped = hop.breaker.observe(
        hop.pool,
        hop.destination,
        Outcome::Transient { retry_after: None },
        now,
        hop.token,
    );
    if tripped {
        hop.telemetry.breaker_trip(hop.metric_pool, hop.destination);
    }
    hop.telemetry.upstream_failure(
        hop.metric_pool,
        hop.destination,
        disposition::ATTEMPT_TIMEOUT,
    );
    AttemptOutcome::Failed {
        disposition: Disposition::TransientUpstream,
        err_type: disposition::ATTEMPT_TIMEOUT,
        relay: None,
    }
}

/// A failure before any answer arrived — refused, reset, a handshake that failed, a deadline that
/// expired. A transient failure on this pool's cell, with the same timeout-versus-connect split
/// the previous release made.
fn transport_failure(hop: &Hop<'_>, label: &'static str, now: u64) -> AttemptOutcome {
    let tripped = hop.breaker.observe(
        hop.pool,
        hop.destination,
        Outcome::Transient { retry_after: None },
        now,
        hop.token,
    );
    if tripped {
        hop.telemetry.breaker_trip(hop.metric_pool, hop.destination);
    }
    hop.telemetry
        .upstream_failure(hop.metric_pool, hop.destination, disposition::TRANSIENT);
    AttemptOutcome::Failed {
        disposition: Disposition::TransientUpstream,
        err_type: label,
        relay: None,
    }
}

/// An answer that was not a success: ask the breaker what it means, record it, and shape the
/// outcome.
fn classify_failure(
    hop: &Hop<'_>,
    status: UpstreamStatus,
    permit: Permit,
    now: u64,
) -> AttemptOutcome {
    let Classified {
        disposition,
        outcome,
        label,
    } = hop.breaker.classify(hop.destination, status);
    let tripped = hop
        .breaker
        .observe(hop.pool, hop.destination, outcome, now, hop.token);
    if tripped {
        hop.telemetry.breaker_trip(hop.metric_pool, hop.destination);
    }
    drop(permit);

    // The caller's own fault is not the destination's: nothing is recorded — which the breaker
    // already knows, because the classifier answered `RecordNothing` — and the answer goes back as
    // it came, on the ordered walk as well as a degraded one.
    if matches!(disposition, Disposition::ClientFault) {
        return AttemptOutcome::Delivered(Delivered {
            destination: hop.destination,
            pool: hop.pool.to_string(),
            status: status.class,
            frames: 1,
            finish: None,
            degraded: hop.degraded,
            relayed_error: status.code,
        });
    }

    hop.telemetry
        .upstream_failure(hop.metric_pool, hop.destination, label);
    AttemptOutcome::Failed {
        disposition,
        err_type: label,
        relay: hop.degraded.then(|| Delivered {
            destination: hop.destination,
            pool: hop.pool.to_string(),
            status: status.class,
            frames: 1,
            finish: None,
            degraded: true,
            relayed_error: status.code,
        }),
    }
}

// ── deliver ─────────────────────────────────────────────────────────────────────────────────────

/// The delivered answer: record the success, hand the probe over, spend one unit of the
/// destination's lifetime budget under a refund guard, and relay the frames.
async fn deliver(
    hop: &Hop<'_>,
    first: FirstFrame,
    permit: Permit,
    probe_guard: &mut Option<ProbeGuard<'_>>,
    ctx: &Ctx<'_>,
    now: u64,
) -> AttemptOutcome {
    hop.breaker
        .observe(hop.pool, hop.destination, Outcome::Success, now, hop.token);
    // The request now owns the probe through the outcome it just recorded; from here the answer's
    // own frames are responsible for the cell, so the guard must not also release.
    if let Some(guard) = probe_guard.as_mut() {
        guard.disarm();
    }

    // Cost accounting, not admission: one unit of the destination's lifetime budget, spent after
    // the success is read. The result is BOUND to the refund decision, because the refund on the
    // other side is unconditional and refunding a spend that never happened would push the budget
    // above its own ceiling.
    let spent = hop.breaker.spend_budget(hop.destination);
    let mut budget = BudgetGuard {
        breaker: hop.breaker,
        destination: hop.destination,
        armed: spent,
    };

    let FirstFrame {
        conn,
        frame,
        mut frames,
    } = first;
    let status = frame.meta.status;
    let mut relayed = 0_usize;
    let mut finish = None;
    let mut clean = false;

    // The plane reads each frame as it arrives and the answer is relayed under the hold. From the
    // moment the first frame is relayed there is no failing over: the client already has part of
    // the answer, so a later failure ends the answer rather than starting another attempt.
    let mut pending = Some(frame);
    let deadline_ms = send_deadline_ms(hop);
    loop {
        let next = match pending.take() {
            Some(frame) => Some(Ok((hop.stream, frame))),
            // A deadline that expires while waiting for the next frame ends the answer here; the
            // client already has what arrived, so there is nothing to fail over to.
            None => race::with_deadline(frames.next(), hop.clock.sleep(deadline_ms))
                .await
                .unwrap_or_default(),
        };
        let Some(Ok((_, frame))) = next else {
            break;
        };
        let carried = [frame];
        let mut cursor = busbar_contract::FrameCursor::new(&carried);
        match hop.plane.decode_response(&mut cursor, hop.dest, None, ctx) {
            Ok(busbar_contract::Progress::NeedMore) => {
                relayed += 1;
            }
            Ok(busbar_contract::Progress::Frame { r, .. }) => {
                relayed += 1;
                finish = Some(r.finish);
            }
            Ok(busbar_contract::Progress::Terminal { r, .. }) => {
                relayed += 1;
                finish = Some(r.finish);
                clean = true;
                break;
            }
            Ok(busbar_contract::Progress::Open(_) | busbar_contract::Progress::OneShot(_)) => {
                relayed += 1;
                clean = true;
                break;
            }
            Ok(busbar_contract::Progress::Discard { .. }) => {}
            Err(_) => break,
        }
    }

    hop.transport
        .close(conn, busbar_contract_transport::wire::CloseReason::Normal);
    drop(permit);

    if clean {
        // The answer arrived whole: the charge stands.
        budget.disarm();
    } else {
        // The success was recorded on the first frame and the budget was spent there, but the body
        // never arrived intact. Record a compensating transient failure and let the still-armed
        // guard give the budget unit back.
        let tripped = hop.breaker.observe(
            hop.pool,
            hop.destination,
            Outcome::Transient { retry_after: None },
            hop.clock.now_secs(),
            hop.token,
        );
        if tripped {
            hop.telemetry.breaker_trip(hop.metric_pool, hop.destination);
        }
    }

    AttemptOutcome::Delivered(Delivered {
        destination: hop.destination,
        pool: hop.pool.to_string(),
        status,
        frames: relayed,
        finish,
        degraded: hop.degraded,
        relayed_error: None,
    })
}
