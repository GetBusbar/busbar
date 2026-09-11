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

use busbar_caps::{BodyLease, CompletedUnits, Completion, MeterClassId, Route, UnitToken};
use busbar_contract::{Ctx, EgressBody, Frame, Plane, Transport, Unit};
use busbar_contract_transport::wire::{Conn, StatusClass};
use futures::StreamExt;

use crate::ports::{
    disposition, net, Breaker, Capacity, Classified, Clock, DestinationId, Dispatched, Disposition,
    EgressAuth, Journal, OutboundRequest, Outcome, Permit, Telemetry, UpstreamStatus,
};
use crate::race;
use crate::select::ProbeGuard;
use crate::wire::{Delivered, Relayed, Shed};

/// Everything one hop shares, borrowed and cheap to pass down the stages.
///
/// The fields that differ between the ordered walk and a degraded terminal are plain inputs here,
/// so the two postures are data rather than two copies of the code: `degraded` selects the
/// degraded diagnostics and asks for the relayed upstream answer a degraded caller returns instead
/// of failing over, and `metric_pool` carries the label the caller resolved.
pub struct Hop<'a, 'm> {
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
    ///
    /// Its own lifetime, and shorter than everything else here: on the default cell the label is
    /// borrowed from the pool's MEMBER LIST, which the walk builds per call and drops when it
    /// returns. Everything else on this hop outlives the walk because it came off the route
    /// request, and the body pump — which outlives the walk by construction — may hold only those.
    pub metric_pool: &'m str,
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
    /// The unit, as the plane reads it.
    ///
    /// It lives here rather than beside the hop because every stage that calls the plane needs it
    /// and because it is exactly what the hop is: what this unit shares, borrowed, for the length
    /// of one attempt.
    pub unit: &'a Unit<'a>,
    /// The context the plane is called with.
    pub ctx: &'a Ctx<'a>,
}

/// Everything one attempt needs: the hop, the slot it holds, the probe it may own, and the unit
/// and context the plane is called with.
pub struct AttemptInput<'a, 'm> {
    /// The hop, which carries the unit and the context the plane is called with.
    pub hop: Hop<'a, 'm>,
    /// The concurrency slot the caller took. Held for the life of a delivered answer, dropped at
    /// every failure.
    pub permit: Permit,
    /// Set only when the caller's pick won a single-flight recovery probe on this cell. This
    /// attempt then owns its release. The one documented breaker bypass passes `None` and so
    /// builds no guard at all, which is what stops it ever reverting a probe a peer won.
    pub probe_epoch: Option<u64>,
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
fn send_deadline_ms(hop: &Hop<'_, '_>) -> u64 {
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

/// The dispatch record's own exit, for the attempt that never reaches one of its own.
///
/// The record is durable before the dial and the design asks for its abandonment to be EXPLICIT
/// rather than inferred from a missing settle. Every exit the attempt returns through says so
/// itself; a future dropped part-way through the send returns through none of them, and the record
/// it strands is what recovery later settles as a crash — a dispatch that never happened, counted
/// against the destination as one that did. Armed the instant the record is durable, this makes
/// the cancelled exit say exactly what the returned ones say.
struct JournalGuard<'a> {
    journal: &'a dyn Journal,
    record: &'a Dispatched,
    armed: bool,
}

impl<'a> JournalGuard<'a> {
    /// Arm on a record that is now durable.
    fn arm(journal: &'a dyn Journal, record: &'a Dispatched) -> Self {
        Self {
            journal,
            record,
            armed: true,
        }
    }

    /// Say it now, at the point in the exit the attempt has always said it.
    fn abandon(&mut self) {
        if self.armed {
            self.armed = false;
            self.journal.abandoned(self.record);
        }
    }

    /// An answer arrived: this record settles on the answer and not as an abandonment.
    fn disarm(&mut self) {
        self.armed = false;
    }
}

impl Drop for JournalGuard<'_> {
    fn drop(&mut self) {
        if self.armed {
            self.journal.abandoned(self.record);
        }
    }
}

/// The one attempt.
pub async fn attempt<'a>(input: AttemptInput<'a, '_>) -> (AttemptOutcome, Option<BodyPump<'a>>) {
    let AttemptInput {
        hop,
        permit,
        probe_epoch,
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
        return (AttemptOutcome::Bail(Shed::internal()), None);
    }
    // From here the record exists and something must settle it. The guard is what settles it on
    // the one exit that runs none of this function's own code — a caller that drops this future
    // mid-send.
    let mut journal = JournalGuard::arm(hop.journal, &record);

    // 2-5. Assemble: the plane's egress encode, the egress-auth decoration, and the lane
    //      cross-check on the bytes that decoration produced. A failure at any of the three is an
    //      internal failure before any send.
    let wire = match assemble(&hop) {
        Ok(bytes) => bytes,
        Err(shed) => {
            journal.abandon();
            drop(permit);
            return (AttemptOutcome::Bail(shed), None);
        }
    };

    hop.telemetry
        .upstream_attempt(hop.metric_pool, hop.destination);

    // 6. The send, under the outer deadline with the per-attempt cap raced inside it. The anchor
    //    is read here, once, because the deadline is a bound on the WHOLE send — headers and the
    //    answer's frames together — and every later reading of what is left of it measures from
    //    this instant.
    let anchor_ms = hop.clock.now_millis();
    let deadline_ms = send_deadline_ms(&hop);
    let cap_ms = hop
        .attempt_timeout_ms
        .map(|ms| attempt_cap_ms(ms, hop.remaining_secs));
    let outcome = send(&hop, &wire, deadline_ms, cap_ms).await;

    let first = match outcome {
        SendOutcome::AttemptTimeout(ms) => {
            journal.abandon();
            drop(permit);
            return (attempt_timeout(&hop, ms, now), None);
        }
        SendOutcome::BudgetTimeout => {
            journal.abandon();
            drop(permit);
            return (transport_failure(&hop, net::TIMEOUT, now), None);
        }
        SendOutcome::Sent(Err(e)) => {
            journal.abandon();
            drop(permit);
            let label = if matches!(e, busbar_contract_transport::wire::TransportError::Timeout) {
                net::TIMEOUT
            } else {
                net::CONNECT
            };
            return (transport_failure(&hop, label, now), None);
        }
        SendOutcome::Sent(Ok(first)) => first,
    };

    // 7. The answer. The transport's status reading on the first frame is the leg the fee decision
    //    reads and the leg the breaker is told about; the plane's own decode runs per frame from
    //    here on.
    // The whole leg the transport read, not just the coarse class. A classifier handed the class
    // alone folds every 4xx together, so a withdrawn credential — the one signal that should take
    // the destination down across every pool that names it — arrives looking like a caller typo,
    // and an upstream that named its own wait has that wait dropped on the floor before the
    // cooldown is computed.
    let status = UpstreamStatus {
        class: first.frame.meta.status,
        code: first.frame.meta.status_code,
        retry_after: first.frame.meta.retry_after_secs,
    };
    let succeeded = matches!(first.frame.meta.status, Some(StatusClass::Success) | None);
    // An upstream answered, which is the one thing an abandonment says did not happen. From here
    // the record settles on that answer however the rest of it goes.
    journal.disarm();
    if !succeeded {
        return (classify_failure(&hop, status, permit, now), None);
    }

    deliver(&hop, first, permit, &mut probe_guard, now, anchor_ms)
}

// ── assemble ────────────────────────────────────────────────────────────────────────────────────

/// The wire request: the envelope the plane built with the decoration applied, then the body.
///
/// The bytes BORROW the arena the transport rendered them into. Owning a copy of them instead would
/// pay for the whole request a second time on the money path, and would hand `write` a buffer the
/// arena never saw — the arena is where the hot path allocates, so these bytes go out from where
/// they were built.
struct Wire<'a> {
    bytes: busbar_contract::ArenaBytes<'a>,
}

/// Build the outbound request, decorate it, and check the lane on what came out.
///
/// The order here is the design's and it is the whole point of the step: the plane encodes for the
/// destination but never holds a credential; the egress-auth unit decorates and substitutes every
/// secret itself; and the lane cross-check runs on the RESULT, so a decoration cannot quietly move
/// the request onto a cheaper or a different lane.
fn assemble<'a>(hop: &Hop<'a, '_>) -> Result<Wire<'a>, Shed> {
    let (unit, ctx) = (hop.unit, hop.ctx);
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
        .map_err(|_| Shed::internal())?;

    lane_cross_check(hop, &request)?;
    Ok(Wire { bytes })
}

/// The lane cross-check, on the post-decoration request.
///
/// Two things are checked and they are different. First, the decoration may not have written the
/// field the lane name is read out of — an egress-auth scheme that could set it could re-price the
/// request. Second, where the envelope names a lane at all, the name must be the one the trust
/// unit sealed on the destination.
///
/// The field is matched CASE-INSENSITIVELY, as the egress-auth unit's own cross-check matches it.
/// Envelope field names are case-insensitive on the wire, so a decoration that wrote `Host` where
/// the lane field is spelled `host` reached an upstream on a lane nobody checked — the exact bypass
/// this check exists to close, available to anyone who could pick the capitalisation.
///
/// More than one entry carrying the field is a REFUSAL rather than a first-match. Two spellings of
/// the same field name is not a request whose lane can be read: the check would be answering about
/// one of them and the wire about whichever the transport encoded, and there is no reading of
/// "which lane is this priced on" that a duplicate has an answer to.
///
/// Takes the three values it decides from rather than the whole hop, so the rule is exercised
/// directly instead of through a dialled attempt.
fn lane_cross_check(hop: &Hop<'_, '_>, request: &OutboundRequest<'_>) -> Result<(), Shed> {
    lane_matches_seal(hop.lane_field, &request.fields, hop.dest.lane())
}

pub(crate) fn lane_matches_seal(
    lane_field: Option<&str>,
    fields: &[(String, Vec<u8>)],
    sealed: Option<busbar_contract::LaneId>,
) -> Result<(), Shed> {
    let Some(field) = lane_field else {
        return Ok(());
    };
    let mut carrying = fields
        .iter()
        .filter(|(name, _)| name.eq_ignore_ascii_case(field));
    let Some((_, value)) = carrying.next() else {
        return Ok(());
    };
    if carrying.next().is_some() {
        return Err(Shed::internal());
    }
    let Some(sealed) = sealed else {
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
async fn send(
    hop: &Hop<'_, '_>,
    wire: &Wire<'_>,
    deadline_ms: u64,
    cap_ms: Option<u64>,
) -> SendOutcome {
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
        if let Ok(Err(e)) = race::with_deadline(
            hop.transport.write(&conn, hop.stream, wire.bytes),
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
fn attempt_timeout(hop: &Hop<'_, '_>, _ms: u64, now: u64) -> AttemptOutcome {
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
fn transport_failure(hop: &Hop<'_, '_>, label: &'static str, now: u64) -> AttemptOutcome {
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
    hop: &Hop<'_, '_>,
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
            body: body_lease(hop),
            destination: hop.destination,
            pool: hop.pool.to_string(),
            status: status.class,
            degraded: hop.degraded,
            relayed_error: status.code,
            // THE ANSWER WAS OVER BEFORE IT GOT HERE, so there is nothing to pump and the relay's
            // reading is complete on the spot. One frame, no finish the plane ever read — the
            // upstream refused the caller's own request and this unit relayed the refusal rather
            // than decoding an answer — and an EMPTY completion, which says there is no body of
            // the caller's for a dimension to be counted against and is a different statement from
            // a completion that counted zero of something.
            relayed: Some(Relayed {
                frames: 1,
                finish: None,
                carried: Completion::default(),
            }),
        });
    }

    hop.telemetry
        .upstream_failure(hop.metric_pool, hop.destination, label);
    AttemptOutcome::Failed {
        disposition,
        err_type: label,
        relay: hop.degraded.then(|| Delivered {
            body: body_lease(hop),
            destination: hop.destination,
            pool: hop.pool.to_string(),
            status: status.class,
            degraded: true,
            relayed_error: status.code,
            // Same: the walk is failing over and only a degraded caller relays this at all, and
            // what it relays is one frame that is already over.
            relayed: Some(Relayed {
                frames: 1,
                finish: None,
                carried: Completion::default(),
            }),
        }),
    }
}

// ── deliver ─────────────────────────────────────────────────────────────────────────────────────

/// What is left of the send's deadline, measured from the anchor the send started at. `None` once
/// the whole budget is spent.
///
/// The relay loop asks this before every wait rather than arming a fresh full-length deadline: a
/// deadline re-armed per frame bounds the gap BETWEEN frames and nothing else, so an upstream that
/// emits one frame just inside it holds the permit, the connection and the answer open for as long
/// as it cares to keep dripping.
fn remaining_ms(clock: &dyn Clock, anchor_ms: u128, budget_ms: u64) -> Option<u64> {
    let elapsed = clock.now_millis().saturating_sub(anchor_ms);
    let left = u128::from(budget_ms).checked_sub(elapsed)?;
    (left > 0).then(|| u64::try_from(left).unwrap_or(budget_ms))
}

/// The delivered answer's HEAD: record the success, hand the probe over, spend one unit of the
/// destination's lifetime budget under a refund guard, and hand the relay back UNRUN.
///
/// The relay used to run here, which is why the walk could not return until the last frame of the
/// answer had gone past. That made the kernel's hold over the routed body a hold over a body that
/// was already drained — the Meter step "reading a body that is still the unit's" was true only
/// because nothing could tell the difference — and it is the shape P4 handed back as owed.
///
/// It does not run here now. What comes back is the head and a [`BodyPump`], and the ROOT drives
/// the pump: the root is what already owns the transport runtime the frames are arriving on, and
/// this crate has no runtime and must not grow one. Nothing is spawned and nothing is joined; the
/// pump is an ordinary future over the same ports the walk itself awaits.
///
/// `anchor_ms` is the instant the send started, which is what the deadline is measured from.
fn deliver<'a>(
    hop: &Hop<'a, '_>,
    first: FirstFrame,
    permit: Permit,
    probe_guard: &mut Option<ProbeGuard<'_>>,
    now: u64,
    anchor_ms: u128,
) -> (AttemptOutcome, Option<BodyPump<'a>>) {
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
    // above its own ceiling. The guard travels WITH the pump, because the window it covers is the
    // body's and the body has not arrived yet.
    let spent = hop.breaker.spend_budget(hop.destination);
    let budget = BudgetGuard {
        breaker: hop.breaker,
        destination: hop.destination,
        armed: spent,
    };

    let FirstFrame {
        conn,
        frame,
        frames,
    } = first;
    let status = frame.meta.status;

    let delivered = Delivered {
        body: body_lease(hop),
        destination: hop.destination,
        pool: hop.pool.to_string(),
        status,
        degraded: hop.degraded,
        relayed_error: None,
        // NOT YET RELAYED, and said as `None` rather than as a zero. A frame count of zero on an
        // answer whose body has not started arriving is a lie a reader cannot detect.
        relayed: None,
    };
    let pump = BodyPump {
        breaker: hop.breaker,
        token: hop.token,
        clock: hop.clock,
        telemetry: hop.telemetry,
        transport: hop.transport,
        plane: hop.plane,
        dest: hop.dest,
        destination: hop.destination,
        pool: hop.pool.to_string(),
        metric_pool: hop.metric_pool.to_string(),
        unit: hop.unit,
        ctx: hop.ctx,
        conn,
        frames,
        first: Some(frame),
        permit,
        budget,
        anchor_ms,
        budget_ms: send_deadline_ms(hop),
    };
    (AttemptOutcome::Delivered(delivered), Some(pump))
}

/// THE RELAY, HANDED BACK RATHER THAN RUN: one answer's body, everything it needs to go past, and
/// nothing that could read it.
///
/// It owns the things that must not outlive the answer — the connection, the stream, the
/// concurrency permit and the budget's refund guard — and borrows the four seams the loop reads
/// plus the unit and the context the plane is called with. Every borrow is one the walk already
/// held, so driving the pump after the walk has returned reads exactly what driving it inside the
/// walk read.
///
/// **It names no runtime.** [`drain`](BodyPump::drain) is an ordinary future over the same ports
/// the walk itself awaits: a clock that is a port and a stream the transport handed over. A cell
/// drives it on one thread with no timer wheel, and the root drives it on the runtime the frames
/// are already arriving on.
pub struct BodyPump<'a> {
    breaker: &'a dyn Breaker,
    token: &'a UnitToken<Route>,
    clock: &'a dyn Clock,
    telemetry: &'a dyn Telemetry,
    transport: &'a dyn Transport,
    plane: &'a dyn Plane,
    dest: &'a busbar_contract::VerifiedDestination,
    destination: DestinationId,
    pool: String,
    metric_pool: String,
    unit: &'a Unit<'a>,
    ctx: &'a Ctx<'a>,
    conn: Conn,
    frames: busbar_contract::transport::FrameStream,
    first: Option<Frame>,
    permit: Permit,
    budget: BudgetGuard<'a>,
    anchor_ms: u128,
    budget_ms: u64,
}

impl std::fmt::Debug for BodyPump<'_> {
    /// Says which answer it is over, never what is in it. A relay's whole point is that the bytes
    /// belong to the connection, and a log line that printed them would be this unit reading a body.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BodyPump")
            .field("pool", &self.pool)
            .field("destination", &self.destination)
            .finish_non_exhaustive()
    }
}

impl BodyPump<'_> {
    /// DRIVE THE RELAY TO THE END OF THE ANSWER, and say what it carried.
    ///
    /// The plane reads each frame as it arrives and the answer is relayed under the hold. From the
    /// moment the first frame was relayed there is no failing over: the client already has part of
    /// the answer, so a later failure ends the answer rather than starting another attempt.
    pub async fn drain(mut self) -> Relayed {
        let mut relayed = 0_usize;
        let mut bytes = 0_u64;
        let mut finish = None;
        let mut dimensions: Vec<CompletedUnits> = Vec::new();
        let mut clean = false;

        let mut pending = self.first.take();
        loop {
            let next = match pending.take() {
                Some(frame) => Some(Ok((busbar_contract::StreamId(0), frame))),
                // A deadline that expires while waiting for the next frame ends the answer here;
                // the client already has what arrived, so there is nothing to fail over to. The
                // wait is bounded by what is LEFT of the send's deadline, and a spent one ends the
                // answer without waiting at all — both by the same path, so a cut stream is the
                // same partial answer it has always been.
                None => match remaining_ms(self.clock, self.anchor_ms, self.budget_ms) {
                    Some(ms) => race::with_deadline(self.frames.next(), self.clock.sleep(ms))
                        .await
                        .unwrap_or_default(),
                    None => None,
                },
            };
            let Some(Ok((_, frame))) = next else {
                break;
            };
            // COUNTED, NOT READ. The transport already told this unit how many bytes the frame was;
            // adding them up as they go past is the whole of the count this unit can produce, and
            // it is produced WHILE the stream runs rather than by looking at a body afterwards —
            // there is no afterwards to look at, because the bytes belong to the connection.
            bytes = bytes.saturating_add(frame.meta.bytes);
            let carried = [frame];
            let mut cursor = busbar_contract::FrameCursor::new(&carried);
            match self
                .plane
                .decode_response(&mut cursor, self.dest, None, self.ctx)
            {
                Ok(busbar_contract::Progress::NeedMore) => {
                    relayed += 1;
                }
                Ok(busbar_contract::Progress::Frame { r, .. }) => {
                    relayed += 1;
                    finish = Some(r.finish);
                    read_dimensions(self.plane, self.unit, &r, self.ctx, &mut dimensions);
                }
                Ok(busbar_contract::Progress::Terminal { r, .. }) => {
                    relayed += 1;
                    finish = Some(r.finish);
                    read_dimensions(self.plane, self.unit, &r, self.ctx, &mut dimensions);
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

        self.transport.close(
            self.conn,
            busbar_contract_transport::wire::CloseReason::Normal,
        );
        drop(self.permit);

        if clean {
            // The answer arrived whole: the charge stands.
            self.budget.disarm();
        } else {
            // The success was recorded on the first frame and the budget was spent there, but the
            // body never arrived intact. Record a compensating transient failure and let the
            // still-armed guard give the budget unit back.
            let tripped = self.breaker.observe(
                &self.pool,
                self.destination,
                Outcome::Transient { retry_after: None },
                self.clock.now_secs(),
                self.token,
            );
            if tripped {
                self.telemetry
                    .breaker_trip(&self.metric_pool, self.destination);
            }
        }

        Relayed {
            frames: relayed,
            finish,
            carried: relayed_body(relayed, bytes, dimensions),
        }
    }
}

/// WHAT THE ANSWER WAS WORTH, as the PLANE's own declared locators read it off the PLANE's own
/// decoded response.
///
/// This unit does not read a body and this is not it reading one. `Plane::meter` is a pure function
/// of a `Response` the plane itself produced one line above, so what happens here is that the value
/// the plane made is handed back to the plane and the plane says what is in it. The unit holds the
/// answer; it never looks inside.
///
/// The LAST non-empty reading wins. A dialect that reports its usage on the final chunk reports it
/// once, and a dialect that repeats it on every chunk is repeating the same number — so replacing
/// is right and accumulating would double every streamed answer in the tree.
fn read_dimensions(
    plane: &dyn Plane,
    unit: &Unit<'_>,
    r: &busbar_contract::Response<'_>,
    ctx: &Ctx<'_>,
    into: &mut Vec<CompletedUnits>,
) {
    let locators = plane.meter(unit, r, ctx);
    let read: Vec<CompletedUnits> = locators
        .lines
        .as_slice()
        .iter()
        .filter_map(|line| {
            line.quantity.map(|units| CompletedUnits {
                class: MeterClassId::new(line.class.as_str()),
                units,
            })
        })
        .collect();
    if !read.is_empty() {
        *into = read;
    }
}

/// The lease the answer's stream is held under.
///
/// It names the stream of the connection the answer came back on, because that is what the body
/// IS: one stream of one connection, held open by the transport. It is not derived from the bytes
/// and it is not an index into anything this unit owns — a lease is a name, and the only thing a
/// name has to do is name the one thing.
fn body_lease(hop: &Hop<'_, '_>) -> BodyLease {
    BodyLease::new(hop.stream.0)
}

/// What the relay counted while it ran, and what the plane read off it.
///
/// The frames and the bytes are this unit's OWN count of what went past. The per-class dimensions
/// are the plane's — its declared locators, evaluated over its own decoded response, by the plane
/// itself. A unit that filled those in by parsing the answer would be a unit that had read a body,
/// which is the one thing this crate says it never does.
fn relayed_body(frames: usize, bytes: u64, dimensions: Vec<CompletedUnits>) -> Completion {
    Completion::of(frames as u64, bytes, dimensions).unwrap_or_else(|_| Completion::default())
}
