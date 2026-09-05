// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE AUDIT STEP — the one place a unit of this plane ends.
//!
//! Audit is the last of the unit's seven steps, and it is the only one that returns a finished
//! response. Everything else in the unit answers with a decision and hands the response along; this
//! file turns the last of those into a posted record, a metric, a request-log link and a refund
//! where one is owed, and gives the bytes back to the loop.
//!
//! ## Two doors, one terminal
//!
//! A unit that PASSED the admission door is audited WITH its charge: the caller was charged, the
//! record has to say what for, and a non-2xx outcome refunds the flat fee it actually paid. A unit
//! that never passed is audited WITHOUT one: nothing was charged, so there is nothing to refund, and
//! a refund on that path would be a blind decrement against a different request's spend in the same
//! window. That is the whole difference between [`audit`] and [`audit_refused`] — and it is a
//! difference of evidence, not of destination. Both doors lead to the same terminal, which settles,
//! emits and links exactly once, and there is no third way out of this plane.
//!
//! ## Which pool the record says
//!
//! Both doors name the destination the same way: through [`EngineHost::pool_label`], the host's own
//! bound, so an unconfigured model name can never open a new metric series on either path. A unit
//! that reached routing names the pool the charge landed on. A unit refused before routing names
//! whatever destination it had got as far as reading — a CONFIGURED pool it was not permitted to
//! reach is recorded under that pool's name, exactly as the live pre-admission guard records it —
//! and a unit refused before any destination was read names the reserved unresolved label, which
//! the same bound maps to itself. Both are still counted and still fire the request-log webhook: a
//! pre-routing turn-away that is invisible to the operator is the failure mode this rule exists to
//! prevent, and a raw early return is exactly that failure.
//!
//! ## Why the doors live here and nowhere else
//!
//! The construction gate names this file, and a call to either door anywhere else in this crate is
//! counted against the plane. That is not tidiness: a second call site is a second way for a unit to
//! be posted, and "posted exactly once" is a property of the call graph, not of the intent of
//! whoever wrote the second site.
//!
//! ## Why the RENDERING lives here too
//!
//! A refusal taken at any earlier step is not bytes yet: it is a named outcome — a status, a
//! dialect-neutral code word, the sentence the client reads, and whatever headers the refusal itself
//! carries. [`RefusalOutcome`] is that value, and [`render_refusal`] is the one function in this
//! directory that turns one into a response. An earlier step that could build a response could hand
//! it straight back to the loop and skip the terminal, which is the same hole the two doors close
//! from the other side: the gate forbids a `Response` return anywhere under the step directory but
//! this file, so "every outcome is rendered at the terminal" is a property the compiler and the gate
//! hold jointly rather than a convention.

// BUILT DARK, as the Route step beside it is: the doors below have no production caller until the
// unit's own shell is assembled, and the identity harness at the bottom is what drives them until
// then. The allow is scoped to this file so it retires with the step it covers.
#![allow(dead_code)]

use std::borrow::Cow;
use std::sync::Arc;
use std::time::Instant;

use axum::http::{HeaderName, HeaderValue, StatusCode};
use axum::response::Response;

use busbar_caps::{step::Audit, AuditFacts, Decision, OpClassId, UnitToken};
use busbar_contract::FinishClass;
use busbar_substrate::plane_host::EngineHost;

/// A REFUSAL AS A VALUE — what an earlier step answers with instead of bytes.
///
/// The three parts are the three a client can observe of a turn-away, and they are deliberately
/// dialect-NEUTRAL: the `status` it wears, the `kind` code word (one of the substrate's shared
/// tokens, not a dialect's spelling of it) and the `message` sentence. Which envelope those are
/// poured into — which member names, which nesting, which synthesized header — is the caller's
/// dialect's business and is decided at the terminal, from the protocol name, by
/// [`render_refusal`]. A step that chose the envelope would be a step that had to know the dialects,
/// and "delete a dialect and the plane is free of it" would stop being true of the step files.
///
/// `headers` is for the refusals that carry one of their OWN — a `Retry-After` on a rate-limit
/// turn-away is the live example. They are stamped onto the rendered response after the envelope, so
/// a refusal that carries none is byte-for-byte what the bare shaper produces.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RefusalOutcome {
    status: StatusCode,
    kind: &'static str,
    message: Cow<'static, str>,
    headers: Vec<(HeaderName, HeaderValue)>,
}

impl RefusalOutcome {
    /// Name a refusal: the status, the code word, the sentence. No headers of its own.
    pub fn new(
        status: StatusCode,
        kind: &'static str,
        message: impl Into<Cow<'static, str>>,
    ) -> Self {
        Self {
            status,
            kind,
            message: message.into(),
            headers: Vec::new(),
        }
    }

    /// Add a header this refusal carries in its own right.
    #[must_use]
    pub fn with_header(mut self, name: HeaderName, value: HeaderValue) -> Self {
        self.headers.push((name, value));
        self
    }

    /// The status this refusal wears on the wire.
    pub fn status(&self) -> StatusCode {
        self.status
    }

    /// The dialect-neutral code word this refusal wears on the wire.
    pub fn kind(&self) -> &'static str {
        self.kind
    }

    /// The sentence the client reads.
    pub fn message(&self) -> &str {
        &self.message
    }

    /// The headers the refusal carries in its own right, in the order they were named.
    pub fn headers(&self) -> &[(HeaderName, HeaderValue)] {
        &self.headers
    }
}

/// THE ONE PLACE A NAMED REFUSAL BECOMES BYTES.
///
/// The shaper is the same `ingress_error` the live arms call, given the same three values, so the
/// bytes are the live path's bytes rather than an equivalent set of them. The refusal's own headers
/// are stamped afterwards, which is the order the live arms stamp them in: the envelope first, the
/// refusal's additions over it.
///
/// This does NOT post the unit. Rendering and sealing are two jobs and they are two functions: a
/// refusal is rendered here and then handed to [`audit_refused`], which is what makes the record and
/// the response come from one place without making them one call.
pub fn render_refusal(proto: &str, refusal: &RefusalOutcome) -> Response {
    let mut resp = busbar_substrate::proxy::ingress_error(
        proto,
        refusal.status(),
        refusal.kind(),
        refusal.message(),
    );
    for (name, value) in refusal.headers() {
        resp.headers_mut().insert(name.clone(), value.clone());
    }
    resp
}

/// What the terminal needs that the step shape has nowhere to put.
///
/// The same evidence the two doors always took — who was calling, on what wire, as what operation
/// class, to what destination, since when, and in which charge window — gathered into one value so
/// the step itself can be what every other step is: a token in, a decision out. The destination is
/// the only field either door reads differently, and it does not: both bound it through
/// [`EngineHost::pool_label`], so an unconfigured name can never open a metric series on either
/// path, and a CONFIGURED one is recorded under its own name on both.
pub struct AuditCtx<'a> {
    /// The neutral host seam the terminal is reached through.
    pub host: &'a Arc<dyn EngineHost>,
    /// This request's governance context — the resolved key, or none.
    pub gov: &'a busbar_api::PlaneRequestCtx,
    /// The ingress protocol name, as the record spells the wire.
    pub proto: &'static str,
    /// The operation class the unit was, as the sealed facts name it.
    pub op_class: OpClassId,
    /// The destination the record names. For a unit that reached routing, the pool the charge
    /// landed on — post-downgrade. For one refused before a destination was ever read, the reserved
    /// unresolved label, which the host's own bound maps to itself.
    pub destination: &'a str,
    /// When the request started, for the finish-stage latency observation.
    pub started: Instant,
    /// The pinned header-arrival epoch the refund, where one is owed, lands in.
    pub charged_at: u64,
}

/// The terminal's answer: the sealed step-7 facts, and the bytes the loop gives the client.
///
/// [`Audited::decision`] is exactly what the kernel's `Units::audit` returns. The response rides
/// beside it because this step is the only one in the plane that has one to give, and the loop —
/// not this step — is what hands it back to the transport.
pub struct Audited {
    /// The sealed step-7 answer: what the plane says this unit was, and how it says it ended.
    pub decision: Decision<Audit>,
    /// The posted response.
    pub response: Response,
}

impl Audited {
    /// The step's answer on its own, which is what the loop takes.
    pub fn into_decision(self) -> Decision<Audit> {
        self.decision
    }
}

/// The shape of this step, as a value — the `Units::audit` row with the plane's own context.
///
/// The kernel's row takes a `UnitCtx` and a `UnitEnd` the kernel owns and this crate cannot name; a
/// plane is a plugin on the neutral ABI and does not depend on the kernel. So the context is the
/// plane's and the provisional end is the response itself, while the token and the sealed answer
/// are the kernel's own vocabulary, named at `busbar-caps` where a plugin may name it.
pub type AuditStep = for<'a> fn(&UnitToken<Audit>, &AuditCtx<'a>, Response, bool) -> Audited;

/// How the plane says a unit ended, read off the bytes the client is actually given.
///
/// The client-facing status and nothing else: an upstream that answered 200 into a client-facing
/// 502 ended in error, because the end a record seals is the end the caller experienced.
fn finish_of(resp: &Response) -> FinishClass {
    if resp.status().is_success() {
        FinishClass::Complete
    } else {
        FinishClass::Error
    }
}

/// Seal the end of a unit that PASSED the door.
///
/// `charged` is the door's own answer, carried through Route unchanged: an admission that
/// fail-opened without charging must not refund, because the refund is a decrement of a shared
/// window and there is nothing of this unit's in it.
pub fn audit(
    unit_token: &UnitToken<Audit>,
    ctx: &AuditCtx<'_>,
    resp: Response,
    charged: bool,
) -> Audited {
    let facts = AuditFacts {
        op_class: ctx.op_class,
        finish: finish_of(&resp),
    };
    Audited {
        response: ctx.host.finish_admitted(
            ctx.gov,
            ctx.proto,
            ctx.host.pool_label(ctx.destination),
            ctx.started,
            ctx.charged_at,
            resp,
            charged,
        ),
        decision: Decision::proceed(unit_token, facts),
    }
}

/// Seal the end of a unit that never passed the door. Nothing was charged, so nothing is refunded.
///
/// The label is the SAME bound the admitted door applies, over the same destination, and that is
/// the whole of the difference this function used to get wrong: it named the reserved unresolved
/// label unconditionally, so a 403 raised against a CONFIGURED pool was recorded as if the pool had
/// never resolved, while the live pre-admission guard recorded it under the pool's own name. The
/// bytes agreed and the record did not. A caller that genuinely has no destination yet — a refusal
/// taken before the model was ever read — passes [`crate::engine::POOL_LABEL_UNRESOLVED`], which
/// the bound maps to itself because no deployment may configure a pool by that name.
pub fn audit_refused(unit_token: &UnitToken<Audit>, ctx: &AuditCtx<'_>, resp: Response) -> Audited {
    // A refusal is never a completion, whatever status it wears.
    let facts = AuditFacts {
        op_class: ctx.op_class,
        finish: FinishClass::Error,
    };
    Audited {
        response: ctx.host.finish_rejected(
            ctx.gov,
            ctx.proto,
            ctx.host.pool_label(ctx.destination),
            ctx.started,
            ctx.charged_at,
            resp,
        ),
        decision: Decision::proceed(unit_token, facts),
    }
}

/// THE AUDIT-STEP IDENTITY HARNESS: this step against the live terminal it was lifted from.
///
/// Each case drives two governed callers — so each has a request chain of its own and the two can be
/// told apart in a process-wide log — through the live door and through the step, and compares the
/// response the client is given and the record the operator can read back: same protocol, same pool
/// label, same outcome, same status, and EXACTLY ONE link per unit on each chain.
#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::POOL_LABEL_UNRESOLVED;
    use crate::test_support::{LaneSpec, TestApp};
    use axum::http::StatusCode;
    use axum::response::IntoResponse;
    use busbar_caps::KernelSeal;
    use busbar_core::governance::{GovState, MemoryStore};
    use busbar_core::proxy::reqlog::{RequestRecord, REQUESTS};

    /// The one operation class these fixtures seal, as a plane names its own.
    const OP: OpClassId = OpClassId::new("chat");

    /// A kernel seal for the length of one test, and the step-7 token minted from it — exactly as
    /// the loop lends it, and dropped when the call it was lent to returns.
    fn tokens() -> (KernelSeal, UnitToken<Audit>) {
        let seal = KernelSeal::acquire_for_kernel();
        let token = UnitToken::mint(&seal);
        (seal, token)
    }

    /// The terminal's context for one leg.
    fn ctx<'a>(
        host: &'a Arc<dyn EngineHost>,
        gov: &'a busbar_api::PlaneRequestCtx,
        destination: &'a str,
        at: u64,
    ) -> AuditCtx<'a> {
        AuditCtx {
            host,
            gov,
            proto: "openai",
            op_class: OP,
            destination,
            started: Instant::now(),
            charged_at: at,
        }
    }

    /// A governed deployment with one key per leg, so each leg's terminal writes to a chain nothing
    /// else in this process is writing to.
    fn governed(names: [&str; 2]) -> (Arc<busbar_core::state::App>, [busbar_api::VirtualKey; 2]) {
        let store = Arc::new(MemoryStore::new());
        let signer = busbar_substrate::governance::signing::TokenSigner::from_secret_bytes(
            &[7u8; 32],
            busbar_substrate::governance::signing::DEFAULT_KID,
        );
        let gov = Arc::new(GovState::new_with_signer(store, None, Some(signer)).unwrap());
        let keys = names.map(|name| {
            gov.mint_signed(
                busbar_substrate::governance::NewKeySpec {
                    name: name.to_string(),
                    group: None,
                    labels: Default::default(),
                    ..Default::default()
                },
                2_000_000_000,
                1_000_000_000,
            )
            .unwrap()
            .0
        });
        // A CONFIGURED pool named `p`, because the label is bounded: an unconfigured destination
        // reads back as the reserved unresolved label whichever door it went through, and a fixture
        // that never configures one cannot tell the two doors apart at all.
        let app = TestApp::new()
            .keys_chain()
            .governance(gov)
            .lane(LaneSpec::new(
                "m",
                crate::proto_codec::PROTO_OPENAI,
                "http://127.0.0.1:1/",
            ))
            .pool("p", &[(0, 1)])
            .build();
        (app, keys)
    }

    /// A unique name per test run, so two tests running concurrently never share a chain.
    fn unique(prefix: &str) -> String {
        static N: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        format!(
            "{prefix}-{}",
            N.fetch_add(1, std::sync::atomic::Ordering::SeqCst)
        )
    }

    /// The fields of a record that identify the unit, as opposed to identifying the link: the
    /// principal, the sequence, the clock and the two hashes are per-chain by construction.
    fn shape(r: &RequestRecord) -> (String, String, String, String, u16) {
        (
            r.ingress_protocol.clone(),
            r.pool.clone(),
            r.outcome.clone(),
            r.reason.clone(),
            r.status,
        )
    }

    fn one_record(principal: &str) -> RequestRecord {
        let records = REQUESTS.records_for(principal);
        assert_eq!(
            records.len(),
            1,
            "a unit is posted exactly once; {principal} has {} link(s)",
            records.len()
        );
        records.into_iter().next().unwrap()
    }

    async fn body_of(resp: Response) -> (u16, String) {
        let status = resp.status().as_u16();
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap_or_default();
        (status, String::from_utf8_lossy(&bytes).into_owned())
    }

    /// The ADMITTED door: a unit that passed the door and then failed upstream posts the same
    /// record, and the same bytes, through the step as through the live terminal — once each.
    #[tokio::test]
    async fn audit_matches_the_live_admitted_terminal_and_posts_once() {
        crate::testkit::install_test_seams();
        busbar_core::metrics::init();
        let (app, keys) = governed([&unique("audit-live"), &unique("audit-unit")]);
        let (host, _rt) = crate::engine::test_host_rt(&app);
        let at = busbar_substrate::store::now();

        let live_gov = busbar_api::PlaneRequestCtx {
            key: Some(Arc::new(keys[0].clone())),
        };
        let live = host.finish_admitted(
            &live_gov,
            "openai",
            host.pool_label("p"),
            Instant::now(),
            at,
            (StatusCode::BAD_GATEWAY, "upstream said no").into_response(),
            true,
        );

        let unit_gov = busbar_api::PlaneRequestCtx {
            key: Some(Arc::new(keys[1].clone())),
        };
        let (seal, token) = tokens();
        let unit = audit(
            &token,
            &ctx(&host, &unit_gov, "p", at),
            (StatusCode::BAD_GATEWAY, "upstream said no").into_response(),
            true,
        );
        assert_eq!(
            unit.decision
                .into_result(&seal)
                .expect("the terminal seals rather than refuses"),
            AuditFacts {
                op_class: OP,
                finish: FinishClass::Error
            },
            "a client-facing 502 is sealed as an error end"
        );
        let unit = unit.response;

        assert_eq!(body_of(live).await, body_of(unit).await);
        assert_eq!(
            shape(&one_record(&keys[0].id)),
            shape(&one_record(&keys[1].id)),
            "the step's record and the live terminal's record are the same record"
        );
    }

    /// The REFUSED door: a pre-forward turn-away — the class the plane once let escape as a raw
    /// early return — posts one link against the reserved unresolved label on both paths, and never
    /// refunds, because nothing was ever charged.
    #[tokio::test]
    async fn audit_refused_matches_the_live_rejected_terminal_and_posts_once() {
        crate::testkit::install_test_seams();
        busbar_core::metrics::init();
        let (app, keys) = governed([&unique("refused-live"), &unique("refused-unit")]);
        let (host, _rt) = crate::engine::test_host_rt(&app);
        let at = busbar_substrate::store::now();
        let refusal = || {
            busbar_substrate::proxy::ingress_error(
                "openai",
                StatusCode::BAD_REQUEST,
                crate::engine::KIND_INVALID_REQUEST,
                "Missing required parameter: 'model'.",
            )
        };

        let live_gov = busbar_api::PlaneRequestCtx {
            key: Some(Arc::new(keys[0].clone())),
        };
        let live = host.finish_rejected(
            &live_gov,
            "openai",
            POOL_LABEL_UNRESOLVED,
            Instant::now(),
            at,
            refusal(),
        );

        let unit_gov = busbar_api::PlaneRequestCtx {
            key: Some(Arc::new(keys[1].clone())),
        };
        let (_seal, token) = tokens();
        let unit = audit_refused(
            &token,
            &ctx(&host, &unit_gov, POOL_LABEL_UNRESOLVED, at),
            refusal(),
        )
        .response;

        assert_eq!(body_of(live).await, body_of(unit).await);
        let live_record = one_record(&keys[0].id);
        let unit_record = one_record(&keys[1].id);
        assert_eq!(shape(&live_record), shape(&unit_record));
        assert_eq!(
            unit_record.pool, POOL_LABEL_UNRESOLVED,
            "a refusal taken before routing names no pool of its own"
        );
        assert_eq!(unit_record.status, 400);
    }

    /// The two doors are not interchangeable, and the record says so: the same response through the
    /// admitted door and through the refused door is posted against different pools. A step that
    /// picked the wrong door would still return the right bytes, so the bytes are not the proof.
    #[tokio::test]
    async fn the_two_doors_post_different_evidence_for_the_same_bytes() {
        crate::testkit::install_test_seams();
        busbar_core::metrics::init();
        let (app, keys) = governed([&unique("doors-admitted"), &unique("doors-refused")]);
        let (host, _rt) = crate::engine::test_host_rt(&app);
        let at = busbar_substrate::store::now();

        let admitted_gov = busbar_api::PlaneRequestCtx {
            key: Some(Arc::new(keys[0].clone())),
        };
        let (_seal, token) = tokens();
        let _ = audit(
            &token,
            &ctx(&host, &admitted_gov, "p", at),
            (StatusCode::NOT_FOUND, "no such model").into_response(),
            true,
        );
        let refused_gov = busbar_api::PlaneRequestCtx {
            key: Some(Arc::new(keys[1].clone())),
        };
        let _ = audit_refused(
            &token,
            &ctx(&host, &refused_gov, POOL_LABEL_UNRESOLVED, at),
            (StatusCode::NOT_FOUND, "no such model").into_response(),
        );

        let admitted = one_record(&keys[0].id);
        let refused = one_record(&keys[1].id);
        assert_eq!(admitted.status, refused.status);
        assert_ne!(
            admitted.pool, refused.pool,
            "the door a unit left through is visible in the record it left behind"
        );
        assert_eq!(refused.pool, POOL_LABEL_UNRESOLVED);
    }

    /// Every chain this file wrote must recompute. A terminal that posts a link the verifier rejects
    /// has recorded nothing an operator can rely on.
    #[tokio::test]
    async fn the_chains_this_step_writes_verify() {
        crate::testkit::install_test_seams();
        busbar_core::metrics::init();
        let (app, keys) = governed([&unique("verify-a"), &unique("verify-b")]);
        let (host, _rt) = crate::engine::test_host_rt(&app);
        let at = busbar_substrate::store::now();
        let gov = busbar_api::PlaneRequestCtx {
            key: Some(Arc::new(keys[0].clone())),
        };
        let (_seal, token) = tokens();
        for _ in 0..3 {
            let _ = audit(
                &token,
                &ctx(&host, &gov, "p", at),
                (StatusCode::OK, "ok").into_response(),
                true,
            );
        }
        let refused = busbar_api::PlaneRequestCtx {
            key: Some(Arc::new(keys[1].clone())),
        };
        let _ = audit_refused(
            &token,
            &ctx(&host, &refused, POOL_LABEL_UNRESOLVED, at),
            (StatusCode::FORBIDDEN, "no").into_response(),
        );
        assert_eq!(REQUESTS.records_for(&keys[0].id).len(), 3);
        assert!(REQUESTS.verify_principal_chain(&keys[0].id).is_ok());
        assert!(REQUESTS.verify_principal_chain(&keys[1].id).is_ok());
    }

    /// THE PRE-ADMISSION LABEL IDENTITY. A refusal raised against a CONFIGURED pool is recorded
    /// under that pool's name through the not-charged door, exactly as the live pre-admission guard
    /// records it — and an unconfigured name still reads back as the reserved unresolved label, so
    /// the fix widens nothing.
    ///
    /// The literal is the pool's own name, `p`, on both legs: the live guard's terminal is
    /// `finish_rejected` with `pool_label(app, pool)`, and this step's is the same call with the
    /// same bound over the same string.
    #[tokio::test]
    async fn the_refused_door_labels_a_configured_pool_with_its_own_name() {
        crate::testkit::install_test_seams();
        busbar_core::metrics::init();
        let (app, keys) = governed([&unique("label-live"), &unique("label-unit")]);
        let (host, _rt) = crate::engine::test_host_rt(&app);
        let at = busbar_substrate::store::now();

        let live_gov = busbar_api::PlaneRequestCtx {
            key: Some(Arc::new(keys[0].clone())),
        };
        let _ = host.finish_rejected(
            &live_gov,
            "openai",
            host.pool_label("p"),
            Instant::now(),
            at,
            (StatusCode::FORBIDDEN, "not permitted").into_response(),
        );

        let unit_gov = busbar_api::PlaneRequestCtx {
            key: Some(Arc::new(keys[1].clone())),
        };
        let (_seal, token) = tokens();
        let _ = audit_refused(
            &token,
            &ctx(&host, &unit_gov, "p", at),
            (StatusCode::FORBIDDEN, "not permitted").into_response(),
        );

        let live_record = one_record(&keys[0].id);
        let unit_record = one_record(&keys[1].id);
        assert_eq!(live_record.pool, "p", "the live guard names the pool");
        assert_eq!(shape(&live_record), shape(&unit_record));
        assert_eq!(
            unit_record.pool, "p",
            "the step names it too, rather than calling a configured pool unresolved"
        );
        // And the bound still holds on the way out: a name no deployment configured cannot open a
        // series of its own on this door any more than on the other.
        assert_eq!(host.pool_label("no-such-pool"), POOL_LABEL_UNRESOLVED);
    }

    /// The step is the `Units::audit` row's shape, as a value: a mismatch in the token, the context
    /// or the answer stops compiling here rather than at the root.
    #[test]
    fn the_step_has_the_terminals_shape() {
        let _: AuditStep = audit;
    }
}
