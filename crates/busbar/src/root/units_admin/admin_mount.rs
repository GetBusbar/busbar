//! The admin mount: one HTTP surface, one loop, one answer.
//!
//! Split out of `units_admin/mod.rs` so that file measures the twelve steps and nothing else.
//! A child module, not a sibling: it reads its parent's items directly through `use super::*`,
//! so nothing had to be re-typed or re-plumbed to move it here.

use super::*;

// ── the mount: one HTTP surface, one loop, one answer ───────────────────────────────────────────

/// The node an admin request is answered by.
///
/// Everything a request needs and nothing it does not: the kernel that mints its tokens, the units
/// its steps run against, and the in-flight table its hold lives in. Built once at boot and shared
/// by every request, which is what makes the counts the canary balances node-wide rather than
/// per-request.
#[cfg(feature = "root-admin")]
pub struct AdminNode {
    // `pub(super)` and no wider: these stay readable to `units_admin` and its test module,
    // which is exactly who read them when this type lived in that file.
    pub(super) kernel: busbar_kernel::teller::Kernel,
    pub(super) units: crate::root::kernel::ProductionUnits,
    pub(super) inflight: busbar_kernel::inflight::InFlight,
    pub(super) gauge: busbar_kernel::slice::ConcurrencyGauge,
    pub(super) canary: busbar_contract::caps::Canary,
    pub(super) next_key: std::sync::atomic::AtomicU64,
}

#[cfg(feature = "root-admin")]
impl AdminNode {
    /// Compose the node an admin request is answered by.
    #[must_use]
    pub fn new(
        kernel: busbar_kernel::teller::Kernel,
        units: crate::root::kernel::ProductionUnits,
    ) -> Self {
        AdminNode {
            kernel,
            units,
            // The administrative listener is outside the in-flight cap entirely — the design says
            // so, and for the reason the exemption exists: the surface an operator reaches to find
            // out why the node is shedding has to answer while it is shedding. The table is still
            // real, because a hold still has to live somewhere.
            inflight: busbar_kernel::inflight::InFlight::new(0),
            gauge: busbar_kernel::slice::ConcurrencyGauge::new(),
            canary: busbar_contract::caps::Canary::new(),
            next_key: std::sync::atomic::AtomicU64::new(1),
        }
    }

    /// Draw the key of the next unit this node will walk.
    ///
    /// Drawn by the caller rather than inside the walk because the key is what names this unit on
    /// BOTH sides of the walk: the steps read it, and the exit path releases against it whatever the
    /// unit asked to outlive its response.
    pub fn next_unit(&self) -> u64 {
        self.next_key
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    }

    /// Walk one admin request through the loop and answer with what it produced.
    ///
    /// The whole of the kernel's ten steps, two audit doors and one exit, for a request that used
    /// to reach its handler directly. What comes back is what the operation's own surface answered:
    /// this function chooses the PATH, never the bytes.
    pub fn answer(&self, request: AdminRequest) -> AdminAnswer {
        // The key the caller already drew for this request. It is drawn OUTSIDE this walk because
        // the caller has to name the same unit on the way out — the exit path releases what this
        // unit asked to outlive its response, and a key invented in here would be a key the exit
        // path could not name.
        let key = UnitKey::new(request.unit);
        // The arrival clock, read ONCE and read where the request arrived. Every step that asks what
        // time it is for this unit — the auth unit's expiry and revocation window, the verbs unit's
        // rate class, the nonce the one-time secrets bind to — is handed this same number, so a
        // second reading here would put the in-flight table's idea of when the unit arrived after
        // the one every other step works from. The gap is small and the disagreement is not: a
        // credential can expire between two readings, and then the unit is authenticated against one
        // clock and aged against another.
        let arrived_at = request.at;
        self.units.admin.units.open(key, request);
        // From here the unit occupies two tables, and every way out of this function gives both
        // back — including the way a panicking step takes.
        let occupied = Occupied {
            inflight: &self.inflight,
            units: &self.units.admin.units,
            key,
        };

        let call = self.kernel.next_call();
        let arrival = busbar_kernel::inflight::arrival_hold(
            &self.kernel,
            &self.units.arrival_door,
            PrincipalId::new("admin"),
            call,
        );
        let entered = self.inflight.insert(busbar_kernel::inflight::Enter {
            key,
            origin: busbar_contract::caps::OriginKind::Client,
            session: None,
            admin_listener: true,
            zero_hold_tick: false,
            arrival,
            now: arrived_at,
        });

        let answer = match entered {
            // The table is uncapped for this listener, so this arm is the table declining for a
            // reason that is not capacity. It is still an answer rather than a panic.
            Err(_refused) => unavailable_answer(),
            Ok(slot) => {
                let ctx = UnitCtx {
                    call,
                    key,
                    origin: busbar_contract::caps::OriginKind::Client,
                    session: None,
                    generation: busbar_kernel::registry::Generation::FIRST,
                    admin_listener: true,
                    // An admin unit's whole verified set is a kernel verb, which is what exempts it
                    // from the concurrency gauge — and what makes the admin API answer at a
                    // saturated cap.
                    kernel_verb_only: true,
                };
                let meter = busbar_kernel::teller::AccrualMeter::new();
                let ended = busbar_kernel::teller::run_unit(
                    &self.kernel,
                    &self.units,
                    &ctx,
                    busbar_kernel::teller::Run {
                        cell: slot.cell(),
                        parent: None,
                        leases: slot.leases(),
                        gauge: &self.gauge,
                        canary: &self.canary,
                        meter: &meter,
                    },
                );
                // The loop ran; the answer is whatever Route put there. A unit refused before Route
                // has none, and the refusal it ended on is what the surface renders. Read BEFORE
                // the guard below hands the entry back, because the entry is where the answer is.
                self.units.admin.units.answer(key).unwrap_or_else(|| {
                    // The request is read back for the one refusal whose message names a
                    // property of the endpoint rather than of the ending. It is still open here:
                    // the guard below is what closes it.
                    refused_answer(&ended, self.units.admin.units.request(key).as_ref())
                })
            }
        };

        // THE UNIT'S ONE RECORD (THE DESIGN §1: "The audit step writes one fixed record, for every
        // plane"; U14: one record per unit, and a refused unit gets one too), sealed on the node's
        // book once the unit's answer is in hand, as a request unit's is beside its line.
        if let Some(sealing) = self.units.admin.units.take_sealing(key) {
            self.seal(key, arrived_at, sealing);
        }

        // The guard closes last, whatever happened — including a step that panicked, which the two
        // statements this replaces walked straight past. An entry or a slot that outlived its unit
        // is the leak per request this root may not have.
        drop(occupied);
        answer
    }

    /// Seal admin unit `key`'s record on the node's book: who the auth step resolved (or the
    /// arrival, for a unit refused before anybody was), the operation class its audit door stated,
    /// how it ended, and no amount: an admin unit counts nothing.
    fn seal(&self, key: UnitKey, arrived_at: u64, sealing: AdminSealing) {
        use busbar_kernel_audit::{AuditInputs, Controls, OutcomeFacts, Subject, Usage, What};
        let (facts, ended) = (sealing.facts, sealing.ended);
        let subject = self
            .units
            .admin
            .units
            .principal(key)
            .map_or(Subject::Arrival, |p| {
                Subject::PrincipalId(p.as_str().to_string())
            });
        let inputs = AuditInputs {
            subject,
            what: What {
                unit_key: key,
                incarnation: 0,
                op_class: busbar_kernel_audit::OpClassId::new(facts.op_class.as_str()),
                destination: None,
                parent: None,
                pre_hook_head: None,
                post_hook_head: None,
            },
            wall: arrived_at,
            // The admin units' own order: the key each was drawn as, in arrival order.
            mono: key.get(),
            origin: self
                .kernel
                .origin(busbar_contract::caps::OriginKind::Client),
            outcome: OutcomeFacts {
                unit_end: ended,
                step: ended.step(),
                finish: crate::root::plane_node::audit_finish(facts.finish),
                hook_failed: false,
                emission_delta: 0,
                stale_policy: false,
            },
            usage: Usage {
                lines: Vec::new(),
                tier_bp: 10_000,
                fee_count: 0,
                rate_card_version: crate::root::plane_node::card_in_force(
                    crate::root::kernel::ROOT_CARD.pin().as_ref(),
                    arrived_at.saturating_mul(1_000),
                ),
                bucket_chain_ref: String::new(),
            },
            controls: Controls::default(),
            correlation_label: None,
        };
        let token = self.kernel.durability_token();
        let sealed = self
            .units
            .durability
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .seal_unit(inputs, sealing.pass, &token);
        if let Err(lost) = sealed {
            tracing::error!(
                step = lost.step().as_str(),
                unit = key.get(),
                "the journal lost an admin unit's audit record: it is sealed on the chain and \
                 cached, and a restart will not read it back"
            );
        }
    }
}

/// ONE UNIT'S EXIT PATH, held rather than written.
///
/// The release of an effect that outlives the response used to be the last statement of the
/// answering future, which is the one place it cannot be: a client that disconnects mid-walk drops
/// that future, and a statement in a dropped future does not run. What was left behind was a drain
/// asked for and never released — a restart the caller never got its 202 for, whose shutdown then
/// waited for whichever unrelated request reached a release next.
///
/// As a guard the release is on every way out, including the drop. `unit` is what makes it this
/// unit's release and nobody else's.
#[cfg(feature = "root-admin")]
pub(crate) struct ExitPath {
    // `pub(super)`: readable to `units_admin` and its test module, as it was in that file.
    pub(super) unit: u64,
}

#[cfg(feature = "root-admin")]
impl Drop for ExitPath {
    fn drop(&mut self) {
        busbar_core_admin::restart::UnitDrain::of_unit(self.unit).release();
    }
}

/// THE TWO TABLES A UNIT OCCUPIES, for the length of one unit.
///
/// The in-flight table bounds how many units this node has open and the units table holds the
/// request its steps read, so both have to come back on every way out of one unit — the answer, and
/// the one this guard exists for: a step that panics, which takes the rest of the function with it.
/// A removal and a close written as the last statements of that function come back on the first of
/// those and not on the second, and what they leave behind is per request and resident for the life
/// of the node.
///
/// Dropped explicitly at the end of the answering path rather than at the closing brace, because
/// the answer is read OUT of the entry this guard gives back.
#[cfg(feature = "root-admin")]
pub(crate) struct Occupied<'n> {
    inflight: &'n busbar_kernel::inflight::InFlight,
    units: &'n AdminUnits,
    key: UnitKey,
}

#[cfg(feature = "root-admin")]
impl Drop for Occupied<'_> {
    fn drop(&mut self) {
        self.inflight.remove(self.key);
        let _ = self.units.close(self.key);
    }
}

/// What a unit that never reached Route answers with.
///
/// The plane's own error envelope, which is the previous release's: the caller is the same caller
/// and the shape is pinned. What is NOT pinned to one value is the status — the surface has ten of
/// them and the loop knows which one this unit earned, so the ending is read rather than replaced
/// by a single word.
#[cfg(feature = "root-admin")]
pub(crate) fn refused_answer(
    ended: &busbar_kernel::teller::Ended,
    request: Option<&AdminRequest>,
) -> AdminAnswer {
    match ended {
        busbar_kernel::teller::Ended::Settled { end, .. } => {
            if is_credential_refusal(end.outcome()) {
                return door_answer();
            }
            if let (true, Some(request)) = (is_scope_refusal(end.outcome()), request) {
                return scope_answer(request);
            }
            if is_rate_refusal(end.outcome()) {
                return rate_limited_answer();
            }
            answer_for(end.outcome())
        }
        // The node's own sweep took the hold first, which means this unit is not going to produce an
        // answer at all. That is the node being unable to serve the request, not the caller being
        // told no.
        busbar_kernel::teller::Ended::AlreadySettled => unavailable_answer(),
    }
}

/// Whether this ending is one about WHO is calling.
///
/// The two the authenticate step can reach: a credential the chain would not identify, and one it
/// identified and the revocation set had taken away. Both are the same thing to the caller — the
/// door — and both are answered with the door's own bytes.
#[cfg(feature = "root-admin")]
pub(crate) fn is_credential_refusal(outcome: Outcome) -> bool {
    matches!(
        outcome,
        Outcome::Refused(_, ReasonCode::Unauthenticated | ReasonCode::Revoked)
            | Outcome::Failed(_, ReasonCode::Unauthenticated | ReasonCode::Revoked)
    )
}

/// Whether this ending is the one about what the caller may DO, having been identified.
#[cfg(feature = "root-admin")]
pub(crate) fn is_scope_refusal(outcome: Outcome) -> bool {
    matches!(
        outcome,
        Outcome::Refused(_, ReasonCode::ScopeDenied) | Outcome::Failed(_, ReasonCode::ScopeDenied)
    )
}

/// Whether this ending is the verbs unit spending past the node's mutation budget.
#[cfg(feature = "root-admin")]
pub(crate) fn is_rate_refusal(outcome: Outcome) -> bool {
    matches!(
        outcome,
        Outcome::Refused(_, ReasonCode::RateLimited) | Outcome::Failed(_, ReasonCode::RateLimited)
    )
}

/// What a principal past its mutation budget is answered, whichever limiter refused it.
///
/// A legacy mutation is refused by the mounted surface's own limiter and a new verb by the verbs
/// unit's, and the caller must not be able to tell which: the status, the `Retry-After` window,
/// the code and the message are the kernel's admin rate-limit answer, read from the kernel's own
/// words rather than written a second time here.
#[cfg(feature = "root-admin")]
pub(crate) fn rate_limited_answer() -> AdminAnswer {
    let refused = busbar_kernel::admin::gate::ApiError::RateLimited;
    AdminAnswer {
        status: refused.http_status(),
        headers: vec![
            (
                "retry-after".to_string(),
                busbar_core_admin::rate::MUTATION_RATE_WINDOW_SECS.to_string(),
            ),
            ("content-type".to_string(), "application/json".to_string()),
        ],
        body: busbar_core_admin::admin_codec::refusal::envelope_of(
            refused.code(),
            &refused.message(),
        )
        .into_bytes(),
    }
}

/// What the previous release answers a caller whose grant does not reach the operation.
///
/// Its message NAMES the scope that would have sufficed, which is why this cannot be rendered from
/// the code alone: the scope is a property of the endpoint, read from the same matrix the approve
/// step compared the grant against. No recorded cell exercises this ending — the published release's
/// recordings hold no under-scoped call — so the three values are taken from that release's own
/// admin error contract (`crates/busbar-core/src/admin/v1/contract/mod.rs`, `AdminError::Forbidden`)
/// rather than from a recording, and the oracle cannot confirm them.
#[cfg(feature = "root-admin")]
pub(crate) fn scope_answer(request: &AdminRequest) -> AdminAnswer {
    let needed = busbar_kernel_scope::admin_required_scope(&request.method, &request.path);
    error_answer_with_message(
        403,
        "forbidden",
        &format!(
            "insufficient scope: this endpoint requires `{}`",
            needed.as_str()
        ),
    )
}

/// The status the previous release's administrative door answers an unidentified caller with.
#[cfg(feature = "root-admin")]
pub(crate) const DOOR_STATUS: u16 = 401;

/// The frozen `code` that door writes.
#[cfg(feature = "root-admin")]
pub(crate) const DOOR_CODE: &str = "unauthorized";

/// The frozen human message that door writes, character for character.
#[cfg(feature = "root-admin")]
pub(crate) const DOOR_MESSAGE: &str =
    "missing or invalid admin credential (Bearer or x-admin-token)";

/// What the deployment's own door answers a caller it will not identify.
///
/// THE LOOP DECIDES THE PATH; THE BYTES ARE STILL THE DOOR'S — WRITTEN, NOT RE-RUN. A unit refused at
/// Authenticate never reaches the operation, which is the whole point of refusing there, and the
/// caller must not be able to tell that the path changed. The three values above are the previous
/// release's, and the envelope around them is the plane's one source for the frozen shape, so the
/// answer is composed from what is written down rather than obtained by asking the surface for it.
///
/// It is composed rather than obtained BECAUSE a refusal path may not execute anything. Sending the
/// request back down to the mounted gate to be refused a second time runs a request on the path
/// where nothing is supposed to run, and it makes the bytes depend on an invariant — that gate
/// refusing a credential-less request — which nothing here can hold. A status check afterwards
/// discards an answer; it cannot discard an execution that already happened.
#[cfg(feature = "root-admin")]
pub(crate) fn door_answer() -> AdminAnswer {
    error_answer_with_message(DOOR_STATUS, DOOR_CODE, DOOR_MESSAGE)
}

/// The surface's answer for one ending.
///
/// The vocabulary is the previous release's admin envelope and nothing here invents a status: each
/// arm is a reason the loop can end on paired with the status that release already gave the same
/// condition. `forbidden` stays the answer for the authorization endings and for every class the
/// previous release gave no status of its own, so no ending can quietly become a new status on a
/// surface a caller has pinned.
#[cfg(feature = "root-admin")]
pub(crate) fn answer_for(outcome: Outcome) -> AdminAnswer {
    use busbar_contract::abi::plane::{class_of, RefusalClass};
    let (status, code) = match outcome {
        // A class-to-wire table over the one classification
        // (`busbar_contract::abi::plane::RefusalClass`; the P-item "refusal-reason collapse").
        Outcome::Refused(_, reason) | Outcome::Failed(_, reason) => match class_of(reason) {
            // A body or a verb the plane could not read is a bad request, not a denied one.
            RefusalClass::Unreadable => (400, "invalid_request"),
            // Nothing on this surface answers that method and path.
            RefusalClass::NotFound => (404, "not_found"),
            // The caller is inside its rights and the node is over a limit.
            RefusalClass::QuotaExhausted | RefusalClass::Busy => (429, "rate_limited"),
            // The node cannot record what the operation would do, so it does not do it. An
            // administrative write that cannot be journalled is unavailability, not refusal.
            RefusalClass::Unavailable => (503, "unavailable"),
            RefusalClass::Rejected
            | RefusalClass::Unauthenticated
            | RefusalClass::Forbidden
            | RefusalClass::TooLarge
            | RefusalClass::Throttled
            | RefusalClass::Unreachable
            | RefusalClass::Timeout
            | RefusalClass::PlaneFault
            | RefusalClass::NodeFault => (403, "forbidden"),
        },
        _ => (403, "forbidden"),
    };
    error_answer(status, code)
}

/// One error answer in the surface's envelope.
///
/// The single construction site, so a status and its code cannot be paired differently in two
/// places — which is the shape the previous release's own admin error rendering has.
///
/// The ENVELOPE is the plane's, not this file's. Which code a condition renders under is this
/// file's question (it maps a `ReasonCode` and pairs it with a status); the two keys, their order
/// and their quoting are the frozen wire shape, and the plane is where that shape is written down.
/// A second `format!` of it here was a second chance for a surface a client pinned to change in one
/// place and not the other.
#[cfg(feature = "root-admin")]
pub(crate) fn error_answer(status: u16, code: &str) -> AdminAnswer {
    error_answer_with_message(status, code, code)
}

/// The same envelope where the previous release writes prose rather than the code again.
///
/// Two of its ten errors carry a message this file cannot derive from the code alone — the door's,
/// and the scope refusal's, which names the scope that would have sufficed. They are the same
/// envelope from the same source; only the second string differs.
pub(crate) fn error_answer_with_message(status: u16, code: &str, message: &str) -> AdminAnswer {
    AdminAnswer {
        status,
        headers: vec![("content-type".to_string(), "application/json".to_string())],
        body: busbar_core_admin::admin_codec::refusal::envelope_of(code, message).into_bytes(),
    }
}

/// What a node that cannot take the unit at all answers with.
#[cfg(feature = "root-admin")]
pub(crate) fn unavailable_answer() -> AdminAnswer {
    error_answer(503, "unavailable")
}

/// The dispatch that hands an operation to the surface that already answers it.
///
/// The seam's production half, and deliberately the thinnest thing in the file: it rebuilds the
/// request the caller sent, hands it to the router the operation is mounted on, and returns that
/// router's whole response. No status is computed here, no header is added and no body is touched —
/// and that is the property the oracle measures.
/// One operation, handed across the boundary between the loop and the runtime.
///
/// The request goes one way and the answer comes back the other, on a channel the caller owns. The
/// pair travels together so the async side never has to know which of several outstanding calls it
/// is answering.
#[cfg(feature = "root-admin")]
pub(crate) type Errand = (AdminRequest, std::sync::mpsc::SyncSender<AdminAnswer>);

#[cfg(feature = "root-admin")]
pub struct RouterDispatch {
    errands: tokio::sync::mpsc::UnboundedSender<Errand>,
}

#[cfg(feature = "root-admin")]
use busbar_core_admin::keys::KeyReplayCache;

#[cfg(feature = "root-admin")]
impl RouterDispatch {
    /// Bind the seam to a mounted router, and start the task that drives it.
    ///
    /// **Why a channel and not `Handle::block_on`.** The loop is synchronous and runs on a blocking
    /// worker; the router is asynchronous. Blocking on a runtime handle from inside a blocking
    /// worker is legal on some runtime flavours and a panic on others, which makes it a thing that
    /// works until the deployment's shape changes — a single-worker node panicked on the exact call
    /// a multi-worker node served. A channel is flavour-independent: the blocking side waits on a
    /// standard-library receiver, which knows nothing about runtimes, and the async side is an
    /// ordinary task. The seam is the same seam; only the way it is crossed stopped depending on
    /// how the node was configured.
    #[must_use]
    pub fn new(
        inner: axum::Router,
        runtime: &tokio::runtime::Handle,
        replays: Arc<KeyReplayCache>,
    ) -> Self {
        let (errands, mut inbox) = tokio::sync::mpsc::unbounded_channel::<Errand>();
        runtime.spawn(async move {
            while let Some((request, reply)) = inbox.recv().await {
                let inner = inner.clone();
                let replays = replays.clone();
                // One task per operation, so a slow verb cannot hold up the one behind it — the
                // surface was concurrent before the switch and stays concurrent through it.
                tokio::spawn(async move {
                    // THE UNIT'S KEY IS AMBIENT FOR THE LENGTH OF ITS BODY. An operation whose
                    // effect outlives its own response asks for that effect from inside its own
                    // handler, which knows nothing about the composition it is answering under —
                    // so the composition says, here, which unit the handler's ask belongs to.
                    let unit = request.unit;
                    let answer = busbar_core_admin::restart::UnitDrain::of_unit(unit)
                        .scoping(call(inner, &request, &replays))
                        .await;
                    let _ = reply.send(answer);
                });
            }
        });
        RouterDispatch { errands }
    }
}

/// Hand one request to the router and take its whole answer.
///
/// `replays` is the node's one key replay cache, built once for the life of the process (see
/// [`mount`]); it rides on the built [`axum::http::Request`] as an extension — never as a header,
/// which would put it on the wire this seam otherwise forwards byte-identical to the mounted
/// surface — so `busbar_core_admin::keys::create_key`/`rotate_key` replay and reserve against it.
/// It journals each claim it takes (item 271) on the node's journal where one is bound.
#[cfg(feature = "root-admin")]
async fn call(
    inner: axum::Router,
    request: &AdminRequest,
    replays: &Arc<KeyReplayCache>,
) -> AdminAnswer {
    use tower::ServiceExt;

    let mut builder = axum::http::Request::builder()
        .method(request.method.as_str())
        .uri(request.path.as_str());
    for (name, value) in &request.headers {
        builder = builder.header(name.as_str(), value.as_str());
    }
    builder = builder.extension(Arc::clone(replays));
    let Ok(http) = builder.body(axum::body::Body::from(request.body.clone())) else {
        // A method, path or header the http types themselves will not carry. That is a request
        // this surface cannot make sense of, which is the 400 answer and not the 403 one: nothing
        // here was denied, it was unreadable.
        return error_answer(400, "invalid_request");
    };

    // The router's own error type is uninhabited: a mounted axum router answers, and failing is not
    // among the things it can do. So there is no error arm to write here, and writing one anyway
    // would be a branch that can never be taken pretending to be a fallback that could be.
    let response = inner.oneshot(http).await.unwrap_or_else(|e| match e {});
    let (parts, body) = response.into_parts();
    // The surface answered and its body did not come back. Serving the status with an EMPTY body
    // was the worst of the available answers: a 200 whose document is missing reads, to every
    // client and every operator dashboard, as an operation that succeeded and returned nothing.
    // The node could not produce the answer, and that is what it says.
    let Ok(bytes) = axum::body::to_bytes(body, usize::MAX).await else {
        return unavailable_answer();
    };
    AdminAnswer {
        status: parts.status.as_u16(),
        headers: header_pairs(&parts.headers),
        body: bytes.to_vec(),
    }
}

#[cfg(feature = "root-admin")]
impl AdminDispatch for RouterDispatch {
    fn execute(&self, _verb: KernelVerb, request: &AdminRequest) -> AdminAnswer {
        let (reply, answer) = std::sync::mpsc::sync_channel(1);
        if self.errands.send((request.clone(), reply)).is_err() {
            // The driving task is gone, which happens only as the node itself goes away. There is
            // no surface left to ask, and saying so is the only answer left.
            return unavailable_answer();
        }
        answer.recv().unwrap_or_else(|_| unavailable_answer())
    }
}

/// The name of the second carrier the administrative surface has always accepted.
///
/// Not a synonym this root invented: the pinned document advertises it as a security scheme of its
/// own, and a deployment's tooling is free to have picked either. Spelt as a constant because it is
/// a wire name, and a wire name written twice is a wire name that can be written two ways.
#[cfg(feature = "root-admin")]
pub(crate) const ADMIN_TOKEN_HEADER: &str = "x-admin-token";

/// The credential this request presents, whichever of the two carriers it came in.
///
/// TWO CARRIERS, NOT ONE. The previous release folds `Authorization: Bearer …` and `x-admin-token`
/// together and accepts either; this used to read only the first, which was invisible for exactly as
/// long as the loop admitted anonymously and the surface underneath did the deciding. The moment a
/// closed chain runs here, every deployment whose tooling sends the second header would be refused
/// by a node that had accepted it the day before — and the refusal would look like a revoked
/// credential rather than like a carrier this root forgot to read.
///
/// The scheme prefix is stripped ONCE and case-insensitively. `Bearer` is a case-insensitive token
/// on the wire, so `bearer <t>` is the same credential as `Bearer <t>`; and a token that itself
/// began with the word would previously have had it stripped again, turning one caller's valid
/// secret into a different string. Anything that is not the bearer scheme is handed on as presented,
/// because deciding what an unrecognised scheme means is the chain's and not this reader's.
#[cfg(feature = "root-admin")]
pub(crate) fn presented_credential(headers: &axum::http::HeaderMap) -> Option<String> {
    let authorization = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .map(|value| {
            let trimmed = value.trim_start();
            match trimmed.split_once(' ') {
                Some((scheme, rest)) if scheme.eq_ignore_ascii_case("bearer") => {
                    rest.trim_start().to_string()
                }
                _ => trimmed.to_string(),
            }
        })
        .filter(|credential| !credential.is_empty());
    // The order is the legacy fold's: both carriers are recognised and either identifies, so a
    // request that sends only the second is a request that presented a credential.
    authorization.or_else(|| {
        headers
            .get(ADMIN_TOKEN_HEADER)
            .and_then(|value| value.to_str().ok())
            .map(str::to_string)
            .filter(|credential| !credential.is_empty())
    })
}

/// Header names and values as owned pairs, in emission order.
///
/// A header value is bytes rather than text, and this is the one place that matters: rendering it
/// lossily here would change a byte the oracle compares. Everything the admin surface emits is
/// ASCII, so the conversion is exact — and it is written as a conversion rather than an assumption
/// so that a value which was not would be visible rather than silent.
#[cfg(feature = "root-admin")]
pub(crate) fn header_pairs(headers: &axum::http::HeaderMap) -> Vec<(String, String)> {
    headers
        .iter()
        .map(|(name, value)| {
            (
                name.as_str().to_string(),
                String::from_utf8_lossy(value.as_bytes()).into_owned(),
            )
        })
        .collect()
}

/// One answer as the response this listener writes.
///
/// Written once because two paths reach it: the request that ran and the one this wrap refused
/// before the loop was entered. A second builder would be a second chance for the two to differ.
#[cfg(feature = "root-admin")]
pub(crate) fn http_response(answer: AdminAnswer) -> axum::http::Response<axum::body::Body> {
    let mut response = axum::http::Response::builder().status(answer.status);
    for (name, value) in &answer.headers {
        response = response.header(name.as_str(), value.as_str());
    }
    response
        .body(axum::body::Body::from(answer.body))
        .unwrap_or_else(|_| {
            axum::http::Response::builder()
                .status(500)
                .body(axum::body::Body::empty())
                .expect("an empty 500 always builds")
        })
}

/// Wrap a mounted admin surface so every request on it travels through the kernel.
///
/// The router that goes in is the one that already answers; the router that comes out answers the
/// same operations through the loop. The seam between them is [`RouterDispatch`], so the inner
/// router remains the only thing that knows what any of these operations do.
///
/// The loop is synchronous and the router is not, so the walk runs on a blocking worker and the one
/// await inside it — the inner router's own — is driven on the runtime this was handed. That is the
/// honest ordering: Route drives the seam, the seam drives the surface, and the answer comes back
/// through the steps that are still to run.
///
/// `request_body_max_bytes` is the operator's own ingress cap, the same figure the mounted router's
/// body limit was built with. It is a parameter rather than a constant because this wrap reads the
/// body BEFORE that limit gets a chance to: a cap written down twice is a cap that can differ, and
/// the one that matters is the one the deployment configured.
#[cfg(feature = "root-admin")]
pub fn mount(
    inner: axum::Router,
    kernel: busbar_kernel::teller::Kernel,
    request_body_max_bytes: usize,
    build_units: impl FnOnce(Arc<dyn AdminDispatch>) -> crate::root::kernel::ProductionUnits,
) -> axum::Router {
    let runtime = tokio::runtime::Handle::current();
    // THIS COMPOSITION HAS AN EXIT PATH, so the one operation whose effect outlives its own
    // response — the restart — hands that effect to it instead of starting it mid-flight. Declared
    // here because this is where the loop is put in front of the surface: the operation's own
    // surface is unchanged and does not know which composition it is answering under.
    busbar_core_admin::restart::drain_released_at_exit();
    // THE NODE'S KEY REPLAY CACHE, built here once: this function runs once per process, so the
    // cache lives as long as the node does and a mint's in-flight sentinel outlives every config
    // reload. What outlives the process is the key's claim in the store.
    let replays = Arc::new(KeyReplayCache::new());
    let dispatch: Arc<dyn AdminDispatch> =
        Arc::new(RouterDispatch::new(inner.clone(), &runtime, replays));
    let node = Arc::new(AdminNode::new(kernel, build_units(dispatch)));

    axum::Router::new().fallback(axum::routing::any(
        move |req: axum::http::Request<axum::body::Body>| {
            let node = Arc::clone(&node);
            let inner = inner.clone();
            async move {
                use tower::ServiceExt;

                // THE CLAIM IS WHAT DECIDES. The admin plane claims one path pattern and nothing
                // else, and this listener carries routes that are deliberately outside it: the
                // health probe answers on both listeners with the auth chain bypassed entirely, and
                // it is not an administrative verb. Walking those through a loop whose decode step
                // reads a table they were never in would refuse a route that has always answered.
                // So the claim is asked first, and a path outside it goes straight to the surface it
                // already reached.
                let path = req.uri().path().to_string();
                let claimed = path.starts_with(busbar_contract::surface::ADMIN_PREFIX);

                // AND THE TABLE IS WHAT DECIDES WHICH UNIT. Inside the claim, the plane declares a
                // closed table of operations, and a method-and-path pair outside it is not a unit
                // this plane has — it is a request the surface's own fallback already answers, with
                // the 404 or the 405 that release pinned. Manufacturing a status here for a pair
                // this plane never claimed would be the root inventing an answer it has no basis
                // for, and the whole point of the seam is that it never does that.
                let declared =
                    busbar_core_admin::admin_codec::verbs::resolve(req.method().as_str(), &path)
                        .is_some_and(|resolved| served_here(&resolved));
                if !claimed || !declared {
                    return inner.oneshot(req).await.unwrap_or_else(|e| match e {});
                }

                // A BODY BIGGER THAN THE OPERATOR'S CAP IS NOT THIS WRAP'S TO ANSWER. The mounted
                // surface carries that cap and the answer release pinned for exceeding it, and
                // this wrap reads the body first — so a request that DECLARES more than the cap
                // goes straight there rather than being buffered into this node's memory on the
                // way to being rejected anyway.
                let declared = req
                    .headers()
                    .get(axum::http::header::CONTENT_LENGTH)
                    .and_then(|value| value.to_str().ok())
                    .and_then(|value| value.parse::<usize>().ok());
                if declared.is_some_and(|len| len > request_body_max_bytes) {
                    return inner.oneshot(req).await.unwrap_or_else(|e| match e {});
                }

                let (parts, body) = req.into_parts();
                // AND A BODY THAT COULD NOT BE READ IS NOT AN EMPTY ONE. Read to the same cap, so
                // an undeclared length cannot buffer without bound either; and where the read does
                // not finish, the request is refused. It used to become an empty body — which a
                // mutating verb would go on to execute, with whatever an empty document means to
                // it, on a request the caller never finished sending.
                let Ok(bytes) = axum::body::to_bytes(body, request_body_max_bytes).await else {
                    return http_response(error_answer(400, "invalid_request"));
                };
                // The unit's key, drawn here because both sides of the walk name it: the steps read
                // it going in, and the exit path releases against it coming out.
                let unit = node.next_unit();
                let request = AdminRequest {
                    method: parts.method.as_str().to_string(),
                    path: parts
                        .uri
                        .path_and_query()
                        .map_or_else(|| parts.uri.path().to_string(), ToString::to_string),
                    credential: presented_credential(&parts.headers),
                    headers: header_pairs(&parts.headers),
                    body: bytes.to_vec(),
                    at: std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .map_or(0, |d| d.as_secs()),
                    unit,
                };
                // AND THE EXIT PATH RUNS EVEN WHERE THERE IS NO EXIT. A client that hangs up while
                // the walk is running takes this whole future with it, and the line at the bottom
                // never executes — so a restart that had already asked for its drain left the ask
                // standing, owned by a unit whose exit path was never going to come. Held by a
                // guard instead, the release happens on every way out of here, including the one
                // that is a drop rather than a return.
                let exit = ExitPath { unit };
                let answer = tokio::task::spawn_blocking(move || node.answer(request))
                    .await
                    .unwrap_or_else(|_| unavailable_answer());

                let response = http_response(answer);

                // THE END OF THE EXIT PATH: whatever this unit asked to outlive its response is
                // released HERE, with the response built and handed back and nothing left that can
                // change a byte of it. For the one operation that asks — the restart — that is the
                // graceful drain, which the surface used to begin from inside its own handler. It
                // still begins at the same point relative to the answer; what moved is the steps
                // that now sit between the handler and this line, and they no longer sit between
                // the drain and the write. Every other unit releases nothing, which costs one
                // atomic read.
                drop(exit);
                response
            }
        },
    ))
}

/// THE NODE'S ADMIN SURFACE, AS BOOT MOUNTS IT: [`mount`] over `admin_router`, its units the
/// admin-only composition sharing the node's one `book`, bound to this node's live snapshot
/// (`app`): the configured pools an `adjust` may
/// name, the planes and their record sink, the kernel's trust book the three trust verbs read and
/// decide over (ARCHITECT 2026-10-06, through `late`), the kernel's own breaker (`breaker`), and
/// the governance directory the authenticate step gates an identification with.
///
/// ONE function, called by the boot path and by a root cell that builds its own admin router, so
/// the surface a cell drives is the one production serves (ruling (d), coordinator 2026-10-07: the
/// generic `/api/v1/admin/trust` verbs were mounted at boot and absent from the cell's
/// composition).
///
/// `retired_operator_key` is the slot the operator key held before #77(9)
/// (`docs/design/BUSBAR-1.6.0.md` l.2279: no verb carries operator signatures, and
/// `set_operator_key` does not exist). Nothing reads it. It stays in the call shape because the
/// root cells a pinned door plugin carries (its `tests/root/mod.rs`) drive this one function
/// with it, the way the v3 amendment record keeps its `operator_fingerprint` slot written empty so
/// no stored shape moves; it leaves with the repin that drops it from that call.
#[cfg(feature = "root-admin")]
pub fn mount_node(
    admin_router: axum::Router,
    request_body_max_bytes: usize,
    app: &Arc<busbar_kernel::state::AppHandle>,
    book: &crate::root::durability::NodeBook,
    retired_operator_key: Option<[u8; 32]>,
    late: &Arc<crate::root::serve::LateServices>,
    breaker: crate::root::adapters::BreakerPolicy,
) -> axum::Router {
    let _ = retired_operator_key;
    mount(
        admin_router,
        crate::root::kernel::new_kernel(),
        // The same ingress cap the router below the wrap was built with, because the wrap reads the
        // body before that router's own limit can.
        request_body_max_bytes,
        |dispatch| {
            // THE ADMIN DOOR: the deployment's live `admin_auth` chain, read per unit off the same
            // snapshot the kernel middleware reads and `PUT /api/v1/admin/admin-auth` swaps.
            // Over the book boot opened AND the store boot bound beside it, so the three
            // disaster-recovery verbs reach the configured store (row 113).
            let mut units = crate::root::kernel::ProductionUnits::admin_over_book(
                dispatch,
                live_admin_door(Arc::clone(app)),
                book,
            );
            // Q64/Q67: an `adjust` names the pool its unit was dispatched through, checked against
            // the pools this node has CONFIGURED — read off the live snapshot on every call, so a
            // config apply that adds or removes a pool is what the check sees.
            let live = Arc::clone(app);
            units.admin.pools = Arc::new(move |pool: &str| {
                busbar_kernel::governance::group_provision::pool_known(&live.load(), pool)
            });
            // Q71(2): `plane_facts` / `plane_record_write` read the planes this node serves off the
            // live snapshot (Law 7) and write through the configured store's plane-facing seam.
            units.admin.planes = live_planes(Arc::clone(app));
            units.admin.records = Some(live_records(Arc::clone(app)));
            // An `Idempotency-Key` is claimed in the same configured store.
            units.admin.replay_store = Some(live_replay_store(Arc::clone(app)));
            // ARCHITECT 2026-10-06: the trust verbs read and decide over the kernel's trust
            // book — the composed services, reached through the late install.
            let late = Arc::clone(late);
            units.admin.trust = Arc::new(move || late.kernel());
            // The root breaker is the kernel's own: one cell set on the node, read through the
            // live snapshot so an apply's rebuilt store is the one it observes into.
            units.breaker =
                crate::root::adapters::BreakerAdapter::over_kernel(Arc::clone(app), breaker);
            // THE REVOCATION SET the authenticate step gates an identification with: the same
            // governance state's directory, so the revocation set is the one this node keeps. No
            // governance state is no directory, left as the assembly built it.
            match app.load().governance.clone() {
                Some(gov) => {
                    units.with_auth_bindings(crate::root::kernel::auth_bindings::AuthBindings::new(
                        Arc::new(crate::root::kernel::auth_bindings::GovernanceDirectory::new(gov)),
                    ))
                }
                None => units,
            }
        },
    )
}

/// Whether THIS node serves the row `resolved` names, beyond the table declaring it.
///
/// A row whose verb this build binds no effect to (`busbar_core_admin::verb::effect_bound`) is
/// served nowhere; every other row is served. No row is conditional on an operator key: every verb
/// is a plain scoped verb (#77(9), OWNER-LOCKED, `docs/design/BUSBAR-1.6.0.md` l.2279), so
/// `amend_rate_history` is the verb's on every node and every refusal is the verb's own.
#[cfg(feature = "root-admin")]
pub(crate) fn served_here(resolved: &ResolvedVerb) -> bool {
    // A verb this build binds no effect to is not served at all (architect ruling 2026-09-24): the
    // surface's own fallback answers it — the unmounted `404`, byte for byte, no audit row.
    kernel_verb(resolved).is_none_or(busbar_core_admin::verb::effect_bound)
}

/// Cells for THE ADMIN REQUEST CHAIN as a whole, end to end over this mount.
///
/// A file of their own rather than more rows in `tests/units_admin.rs`, because what they measure
/// is different in kind: that file drives the steps, and these drive the WHOLE chain — a real verb
/// in at the listener, every step, the mounted surface, and the answer back — which is the only
/// shape that can say the surface still works now that `busbar-core-admin` carries no `Plane`.
#[cfg(test)]
#[path = "tests/admin_path_without_plane_face.rs"]
mod admin_path_without_plane_face;
