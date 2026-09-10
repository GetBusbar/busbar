//! THE PUBLISHED BYTES OF ONE REFUSAL — the 403 a session open gets when the deployment refuses its
//! destination, pinned whole.
//!
//! ## Why this cell exists
//!
//! Before the migration below it, NOTHING pinned these bytes. The one cell that exercised the denial
//! (`mount_tests`' `arrival_runs_run_gauntlet_session_refusing_a_denied_destination_before_charge`)
//! asserted the STATUS and never the body, and it drives the one-shot mint pass — a different leg
//! with a different published body. The oracle pins nothing here either: there is no `voice` family
//! in the 1.5.5 golden, because there was no voice in 1.5.5. So the whole of the guarantee that a
//! deployment's operators keep reading the same refusal through a decision moving between layers was
//! a literal in one file that a refactor could have edited without a single test going red.
//!
//! ## The expected bytes are RECORDED, not written here
//!
//! `fixtures/session-destination-denied.body` was extracted from commit 8f1197016 — the base this
//! migration stands on — by reading the body expression out of `topology/mod.rs` at that commit. It
//! is 32 bytes. A literal retyped in this file would prove that this file agrees with itself; a
//! recording proves the wire did not move.
//!
//! ## What is asserted, and what deliberately is not
//!
//! The status, the body bytes, and the ABSENCE of a content-type — the three things the plane itself
//! decides. `date` and `content-length` are the HTTP serializer's and are not this response's to
//! own; asserting them would pin a dependency's behaviour as this plane's contract.

use busbar_substrate::plane_host::{run_gauntlet_session, GauntletPlane, GauntletRequest};

use crate::topology::SessionGauntlet;

/// The refusal body as the base published it, byte for byte.
const RECORDED: &[u8] = include_bytes!("fixtures/session-destination-denied.body");

/// Drive the REAL open-pass gate for one destination against one deployment's denial set, and hand
/// back whatever it answered with.
fn refused(destination: &str, denied: &[&str]) -> Option<axum::response::Response> {
    let gov = busbar_api::PlaneRequestCtx::default();
    let req = GauntletRequest {
        gov: &gov,
        destination,
        correlation_id: 0,
        charged_at: 1,
        started: std::time::Instant::now(),
    };
    let gate: Box<dyn GauntletPlane> = Box::new(SessionGauntlet {
        denied: denied.iter().map(|d| (*d).to_string()).collect(),
    });
    run_gauntlet_session(req, gate).err()
}

/// EVERY BYTE OF THE REFUSAL, through the real gate.
#[tokio::test]
async fn a_refused_destination_publishes_the_recorded_403_byte_for_byte() {
    let resp = refused("blocked-model", &["blocked-model"])
        .expect("a destination the deployment refused is refused");

    assert_eq!(
        resp.status(),
        axum::http::StatusCode::FORBIDDEN,
        "the status spelling this plane published for a refused destination"
    );
    assert!(
        resp.headers()
            .get(axum::http::header::CONTENT_TYPE)
            .is_none(),
        "the refusal carries no content-type, exactly as the base published it — adding one would \
         change what a client parses without changing a single byte of the body"
    );

    let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .expect("a static refusal body always reads");
    assert_eq!(
        body.as_ref(),
        RECORDED,
        "THE PUBLISHED BYTES. The expected value is a recording of commit 8f1197016's own body \
         expression, so this assertion is the wire's, not this file's"
    );
    assert_eq!(
        RECORDED.len(),
        32,
        "the recording is the 32 bytes the base published"
    );
}

/// AND THE CONTROL: a destination the deployment did not name is not refused at all.
///
/// Without it the cell above would still pass against a gate that refused everything, which is the
/// one way this migration could break a deployment that never asked for a denial policy — and that
/// is every deployment today, because the set had no configuration key until this landing.
#[tokio::test]
async fn a_destination_the_deployment_never_named_is_not_refused() {
    assert!(
        refused("allowed-model", &["blocked-model"]).is_none(),
        "a destination outside the denial set proceeds past the open-pass gate"
    );
    assert!(
        refused("anything-at-all", &[]).is_none(),
        "and a deployment that named nothing refuses nothing — the posture every deployment has now"
    );
}
