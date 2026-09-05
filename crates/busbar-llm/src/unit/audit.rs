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
//! A unit that reached routing names the pool the charge landed on, bounded through the host's own
//! label so an unconfigured model name can never open a new metric series. A unit refused BEFORE
//! routing has no pool to name — the destination never resolved, or was never read — so it is
//! recorded against the reserved unresolved label. Both are still counted and still fire the
//! request-log webhook: a pre-routing turn-away that is invisible to the operator is the failure
//! mode this rule exists to prevent, and a raw early return is exactly that failure.
//!
//! ## Why the doors live here and nowhere else
//!
//! The construction gate names this file, and a call to either door anywhere else in this crate is
//! counted against the plane. That is not tidiness: a second call site is a second way for a unit to
//! be posted, and "posted exactly once" is a property of the call graph, not of the intent of
//! whoever wrote the second site.

// BUILT DARK, as the Route step beside it is: the doors below have no production caller until the
// unit's own shell is assembled, and the identity harness at the bottom is what drives them until
// then. The allow is scoped to this file so it retires with the step it covers.
#![allow(dead_code)]

use std::sync::Arc;
use std::time::Instant;

use axum::response::Response;

use busbar_substrate::plane_host::EngineHost;

use crate::engine::POOL_LABEL_UNRESOLVED;

/// Seal the end of a unit that PASSED the door.
///
/// `charged` is the door's own answer, carried through Route unchanged: an admission that
/// fail-opened without charging must not refund, because the refund is a decrement of a shared
/// window and there is nothing of this unit's in it.
pub(crate) fn audit(
    host: &Arc<dyn EngineHost>,
    gov: &busbar_api::PlaneRequestCtx,
    proto: &'static str,
    // The destination the charge landed on — post-downgrade, and bounded to a configured pool or
    // lane by the host's label.
    destination: &str,
    started: Instant,
    charged_at: u64,
    resp: Response,
    charged: bool,
) -> Response {
    host.finish_admitted(
        gov,
        proto,
        host.pool_label(destination),
        started,
        charged_at,
        resp,
        charged,
    )
}

/// Seal the end of a unit that never passed the door. Nothing was charged, so nothing is refunded.
pub(crate) fn audit_refused(
    host: &Arc<dyn EngineHost>,
    gov: &busbar_api::PlaneRequestCtx,
    proto: &'static str,
    started: Instant,
    charged_at: u64,
    resp: Response,
) -> Response {
    host.finish_rejected(
        gov,
        proto,
        POOL_LABEL_UNRESOLVED,
        started,
        charged_at,
        resp,
    )
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
    use crate::test_support::{LaneSpec, TestApp};
    use axum::http::StatusCode;
    use axum::response::IntoResponse;
    use busbar_core::governance::{GovState, MemoryStore};
    use busbar_core::proxy::reqlog::{RequestRecord, REQUESTS};

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
        let unit = audit(
            &host,
            &unit_gov,
            "openai",
            "p",
            Instant::now(),
            at,
            (StatusCode::BAD_GATEWAY, "upstream said no").into_response(),
            true,
        );

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
        let unit = audit_refused(&host, &unit_gov, "openai", Instant::now(), at, refusal());

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
        let _ = audit(
            &host,
            &admitted_gov,
            "openai",
            "p",
            Instant::now(),
            at,
            (StatusCode::NOT_FOUND, "no such model").into_response(),
            true,
        );
        let refused_gov = busbar_api::PlaneRequestCtx {
            key: Some(Arc::new(keys[1].clone())),
        };
        let _ = audit_refused(
            &host,
            &refused_gov,
            "openai",
            Instant::now(),
            at,
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
        for _ in 0..3 {
            let _ = audit(
                &host,
                &gov,
                "openai",
                "p",
                Instant::now(),
                at,
                (StatusCode::OK, "ok").into_response(),
                true,
            );
        }
        let refused = busbar_api::PlaneRequestCtx {
            key: Some(Arc::new(keys[1].clone())),
        };
        let _ = audit_refused(
            &host,
            &refused,
            "openai",
            Instant::now(),
            at,
            (StatusCode::FORBIDDEN, "no").into_response(),
        );
        assert_eq!(REQUESTS.records_for(&keys[0].id).len(), 3);
        assert!(REQUESTS.verify_principal_chain(&keys[0].id).is_ok());
        assert!(REQUESTS.verify_principal_chain(&keys[1].id).is_ok());
    }
}
