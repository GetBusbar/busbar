//! THE ADMIN REQUEST CHAIN, END TO END, WITH NO PLANE ENTRY FACE ANYWHERE ON IT.
//!
//! `busbar-core-admin` used to carry an `impl Plane for AdminPlane`. It is gone: a `Plane` is how
//! TRAFFIC enters the dispatch loop, and the administrative surface serves OPERATORS, on its own
//! listener (#3/#5 — admin is a compiled-in cleanliness crate, not a plugin, and there is no
//! `control` kind; #83 def 11 — "the operator-facing verbs and their HTTP/OpenAPI surface. Serves
//! operators, never traffic").
//!
//! Nothing ever dispatched through that face. The chain an administrative request actually takes,
//! which is what this file drives:
//!
//! 1. the connection arrives on `admin_listen`, a listener of its own, bound in `main.rs` and
//!    ABSENT from the data router;
//! 2. [`super::mount`] wraps the admin router. It asks two questions of the closed table before it
//!    will take a request into the loop at all — is the path under `ADMIN_PREFIX`, and does
//!    `busbar_core_admin::admin_codec::verbs::resolve` name a row for this method and path — and
//!    hands anything else straight to the surface that already answers it;
//! 3. the body is read to the operator's own cap, an `AdminRequest` is built, and
//!    `AdminNode::answer` walks it through `busbar_kernel::teller::run_unit`;
//! 4. the steps are the ADMIN UNITS' — `impl RegisteredUnits for units_admin::AdminPlane` — not a
//!    `Plane`'s: decode resolves the verb off the same closed table, authenticate/verify resolve and
//!    keep the principal, approve compares the 1.5.5 matrix against the grant, admit takes no
//!    concurrency lease, ROUTE hands the operation to the mounted surface, METER reports the empty
//!    line, and AUDIT seals the mutation onto the previous release's chain;
//! 5. the answer the surface produced comes back through the exit path, byte for byte.
//!
//! So these cells assert two things the removal must not have cost: that a real verb still travels
//! that whole chain and comes back with the surface's own bytes, and that the metering and audit the
//! chain performs are still performed — by the admin units, explicitly, where they always were,
//! rather than inherited by pretending an operator's request is somebody's traffic.

use super::*;

// ── the fixtures: one identified operator, one recording surface ───────────────────────────────

/// The credential these cells present. One string, one directory that minted it, one door that
/// identifies it — so the audit attribution below is an identity the node resolved rather than a
/// fallback word.
#[cfg(feature = "root-admin")]
const THE_OPERATORS_CREDENTIAL: &str = "admin-token";

/// A directory that knows exactly the one credential these cells present, and revokes nobody.
#[cfg(feature = "root-admin")]
struct ADirectoryThatMintedIt;

#[cfg(feature = "root-admin")]
impl crate::root::auth_bindings::VirtualKeyDirectory for ADirectoryThatMintedIt {
    fn verify(
        &self,
        credential: &str,
        _now: u64,
        _expected_aud: Option<&str>,
    ) -> Option<crate::root::auth_bindings::KeyFacts> {
        (credential == THE_OPERATORS_CREDENTIAL).then(|| crate::root::auth_bindings::KeyFacts {
            id: "key-admin-1".to_string(),
            name: "the operator credential these cells present".to_string(),
        })
    }

    fn revoked(&self, _credential: &str) -> bool {
        false
    }
}

/// A door that IDENTIFIES that credential as the operator, and identifies nothing else.
///
/// Closed rather than open on purpose: the open front door grants `Full` to anybody, so a cell that
/// ran behind it would prove the walk reaches the surface without proving the walk authenticated.
#[cfg(feature = "root-admin")]
struct IdentifiesTheOperator;

#[cfg(feature = "root-admin")]
impl busbar_kernel_identity::module::AuthModule for IdentifiesTheOperator {
    fn name(&self) -> &'static str {
        "identifies-the-operator"
    }

    fn authenticate(&self, candidate: Option<&str>) -> busbar_kernel_identity::module::AuthOutcome {
        match candidate {
            Some(THE_OPERATORS_CREDENTIAL) => {
                busbar_kernel_identity::module::AuthOutcome::Identify(
                    busbar_kernel_identity::principal::Principal::from_id(
                        crate::root::auth_bindings::ADMIN_PRINCIPAL_ID,
                    ),
                )
            }
            _ => busbar_kernel_identity::module::AuthOutcome::Pass,
        }
    }
}

#[cfg(feature = "root-admin")]
fn a_door_that_identifies_the_operator() -> busbar_kernel_identity::AuthChain {
    busbar_kernel_identity::AuthChain::new(
        vec![busbar_kernel_identity::chain::ChainEntry {
            provider: "identifies-the-operator".to_string(),
            module: Box::new(IdentifiesTheOperator),
        }],
        false,
    )
}

/// What the mounted surface below the wrap saw, and what it answered.
///
/// A RECORDING surface, not a silent one: a walk that never reached the operation and a walk that
/// reached it and came back look identical from the response alone if the wrap is willing to
/// manufacture an answer of its own. Reading what the surface received is what tells them apart.
#[cfg(feature = "root-admin")]
#[derive(Default)]
struct SurfaceLog {
    seen: std::sync::Mutex<Vec<(String, String, Vec<u8>)>>,
}

#[cfg(feature = "root-admin")]
impl SurfaceLog {
    fn seen(&self) -> Vec<(String, String, Vec<u8>)> {
        self.seen.lock().unwrap_or_else(|p| p.into_inner()).clone()
    }
}

/// The bytes the surface answers with. Distinctive on purpose: a body the wrap could have invented
/// would not be these.
#[cfg(feature = "root-admin")]
const THE_SURFACES_OWN_BYTES: &[u8] =
    br#"{"answered_by":"the surface below the wrap","entries":[]}"#;

/// An axum router standing in for the mounted admin surface, recording every request it is handed.
#[cfg(feature = "root-admin")]
fn a_recording_surface(log: Arc<SurfaceLog>) -> axum::Router {
    axum::Router::new().fallback(axum::routing::any(
        move |req: axum::http::Request<axum::body::Body>| {
            let log = Arc::clone(&log);
            async move {
                let (parts, body) = req.into_parts();
                let bytes = axum::body::to_bytes(body, usize::MAX)
                    .await
                    .expect("a test body is always readable");
                log.seen.lock().unwrap_or_else(|p| p.into_inner()).push((
                    parts.method.as_str().to_string(),
                    parts
                        .uri
                        .path_and_query()
                        .map_or_else(|| parts.uri.path().to_string(), ToString::to_string),
                    bytes.to_vec(),
                ));
                axum::http::Response::builder()
                    .status(200)
                    .header("content-type", "application/json")
                    .body(axum::body::Body::from(THE_SURFACES_OWN_BYTES.to_vec()))
                    .expect("the response builds")
            }
        },
    ))
}

/// A node whose book this cell holds the other half of.
///
/// The durability is built HERE rather than inside `ProductionUnits::admin_only` so that the audit
/// chain the walk seals onto is a chain this cell can read back. Same value, two holders: that is
/// the whole point — a second chain read here would be a second answer to what the walk wrote.
#[cfg(feature = "root-admin")]
struct ANodeWhoseChainThisCellReads {
    router: axum::Router,
    durability: Arc<std::sync::Mutex<crate::root::durability::Durability>>,
    rows: busbar_kernel_ledger::legacy::RecordingRows,
    surface: Arc<SurfaceLog>,
}

#[cfg(feature = "root-admin")]
impl ANodeWhoseChainThisCellReads {
    /// How many entries the previous release's administrative chain holds right now, and whether it
    /// is still linked.
    fn chain(&self) -> (usize, bool) {
        let durability = self.durability.lock().unwrap_or_else(|p| p.into_inner());
        (durability.legacy.len(), durability.legacy.verify())
    }

    /// The most recent entry on that chain.
    fn last_entry(&self) -> busbar_kernel_audit::legacy::AuditEntry {
        let durability = self.durability.lock().unwrap_or_else(|p| p.into_inner());
        durability
            .legacy
            .list(1)
            .pop()
            .expect("the chain holds at least one entry")
    }

    /// Every money posting the node's book has taken, which for an administrative walk must be none.
    ///
    /// Read off the write half the node was built over, which is the half the ledger dual-writes
    /// onto. A count taken anywhere else would be a count of something the walk does not touch.
    fn postings(&self) -> usize {
        self.rows.written().len()
    }
}

/// Compose the real mount over the real loop, exactly as `main.rs` composes it for `admin_listen`.
#[cfg(feature = "root-admin")]
fn a_node() -> ANodeWhoseChainThisCellReads {
    let surface = Arc::new(SurfaceLog::default());
    let rows = busbar_kernel_ledger::legacy::RecordingRows::new();
    let durability = crate::root::durability::build(
        &crate::root::durability::DurabilityConfig { data_dir: None },
        Box::new(busbar_kernel_wal::NullShipper::new()),
        Box::new(rows.clone()),
    )
    .expect("a memory-buffered journal cannot fail to open");
    let durability = Arc::new(std::sync::Mutex::new(durability));
    let held = Arc::clone(&durability);
    let read = Arc::new(rows.clone());
    // The SAME ingress cap `main.rs` hands the wrap, so the body read below is the one a deployment
    // configured rather than one this cell invented.
    let router = mount(
        a_recording_surface(Arc::clone(&surface)),
        crate::root::kernel::new_kernel(),
        64 * 1024,
        move |dispatch| {
            crate::root::kernel::ProductionUnits::admin_only_sharing(dispatch, held, read)
                .with_auth_chain(a_door_that_identifies_the_operator())
                .with_auth_bindings(crate::root::auth_bindings::AuthBindings::new(Arc::new(
                    ADirectoryThatMintedIt,
                )))
        },
    );
    ANodeWhoseChainThisCellReads {
        router,
        durability,
        rows,
        surface,
    }
}

/// One request over the mounted listener, with the operator's credential on it.
#[cfg(feature = "root-admin")]
async fn over_the_listener(
    node: &ANodeWhoseChainThisCellReads,
    method: &str,
    path: &str,
    body: &'static [u8],
) -> (u16, Vec<u8>, Vec<(String, String)>) {
    use tower::ServiceExt;

    let request = axum::http::Request::builder()
        .method(method)
        .uri(path)
        .header(
            axum::http::header::AUTHORIZATION,
            format!("Bearer {THE_OPERATORS_CREDENTIAL}"),
        )
        .header(axum::http::header::CONTENT_TYPE, "application/json")
        .body(axum::body::Body::from(body))
        .expect("the request builds");
    let response = node
        .router
        .clone()
        .oneshot(request)
        .await
        .expect("the mounted router answers");
    let status = response.status().as_u16();
    let headers = header_pairs(response.headers());
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("the answer's body is readable");
    (status, bytes.to_vec(), headers)
}

// ── the cells ──────────────────────────────────────────────────────────────────────────────────

/// A REAL VERB STILL TRAVELS THE WHOLE CHAIN AND COMES BACK WITH THE SURFACE'S OWN BYTES.
///
/// `GET /api/v1/admin/audit` is row `get_audit` of the closed 1.5.5 table, read-only. It goes in at
/// the mount, is matched against that table, walks every step of the loop behind an authenticated
/// operator, reaches the mounted surface at Route, and the answer comes back unchanged.
///
/// Three assertions, because a walk can fail in three different ways that a status alone cannot
/// tell apart: the status, the BYTES (the wrap chooses the path and never the body — a manufactured
/// answer would not be the surface's distinctive bytes), and what the surface itself RECEIVED
/// (a wrap that short-circuited would answer without the surface ever having been asked).
#[cfg(feature = "root-admin")]
#[tokio::test]
async fn a_real_verb_still_answers_end_to_end_over_the_admin_listener() {
    let node = a_node();
    let (status, body, headers) =
        over_the_listener(&node, "GET", "/api/v1/admin/audit?limit=4", b"").await;

    assert_eq!(status, 200, "the walk reached the operation and came back");
    assert_eq!(
        body, THE_SURFACES_OWN_BYTES,
        "the answer is the surface's own bytes, not something the wrap composed"
    );
    assert!(
        headers
            .iter()
            .any(|(name, value)| name == "content-type" && value == "application/json"),
        "the surface's own headers travel back too: {headers:?}"
    );
    assert_eq!(
        node.surface.seen(),
        vec![(
            "GET".to_string(),
            "/api/v1/admin/audit?limit=4".to_string(),
            Vec::new()
        )],
        "the operation was reached exactly once, with the request the caller sent"
    );
}

/// AND THE AUDIT THE CHAIN PERFORMS IS STILL PERFORMED — by the admin units, on the admin path.
///
/// This is the money-adjacent half of the removal. If the walk had been getting its audit through
/// the plane face, deleting the face would have silently stopped recording administrative
/// mutations, and an empty history reads exactly like a quiet fleet. It was not: the `audit` step
/// of `impl RegisteredUnits for AdminPlane` seals onto the previous release's chain, and it still
/// does.
///
/// One mutating verb, one entry — under the operation's own name, the applied outcome, and the
/// identity the door resolved (never the credential, which is a secret and stays off the chain) —
/// and the chain still verifies as linked afterwards.
#[cfg(feature = "root-admin")]
#[tokio::test]
async fn a_mutating_verb_still_seals_exactly_one_entry_onto_the_audit_chain() {
    let node = a_node();
    let (before, linked) = node.chain();
    assert!(linked, "the chain starts linked");

    let (status, _body, _headers) = over_the_listener(
        &node,
        "POST",
        "/api/v1/admin/keys",
        br#"{"name":"a-key-this-cell-asked-for"}"#,
    )
    .await;
    assert_eq!(status, 200, "the mutation reached the operation");

    let (after, linked) = node.chain();
    assert_eq!(after, before + 1, "one unit, one entry");
    assert!(linked, "the chain is still linked");

    let entry = node.last_entry();
    assert_eq!(entry.action, "post_keys");
    assert_eq!(entry.resource, "/api/v1/admin/keys");
    assert_eq!(entry.outcome, busbar_kernel_audit::OUTCOME_APPLIED);
    assert_eq!(
        entry.principal,
        crate::root::auth_bindings::ADMIN_PRINCIPAL_ID
    );
    assert!(
        !entry.principal.contains(THE_OPERATORS_CREDENTIAL),
        "the chain names the identity, never the credential"
    );
}

/// A READ still seals nothing, which is the other half of the same step.
///
/// A cell that only counted entries after a mutation would pass just as well against a step that
/// recorded EVERY unit — and a chain that grew on every GET buries the mutations an operator came
/// to find. So the read is walked over the same node, right after the mutation, and the chain does
/// not move.
#[cfg(feature = "root-admin")]
#[tokio::test]
async fn a_read_verb_still_seals_nothing_onto_the_audit_chain() {
    let node = a_node();
    let (status, _body, _headers) = over_the_listener(
        &node,
        "POST",
        "/api/v1/admin/keys",
        br#"{"name":"a-key-this-cell-asked-for"}"#,
    )
    .await;
    assert_eq!(status, 200);
    let (after_the_mutation, _) = node.chain();

    let (status, _body, _headers) =
        over_the_listener(&node, "GET", "/api/v1/admin/audit", b"").await;
    assert_eq!(status, 200, "the read reached the operation");
    let (after_the_read, linked) = node.chain();

    assert_eq!(
        after_the_read, after_the_mutation,
        "a read is not a mutation and the chain does not record it"
    );
    assert!(linked, "the chain is still linked");
}

/// AND THE METER STEP STILL RUNS, AND STILL PRICES AN ADMIN VERB AT NOTHING.
///
/// The admin surface declares NO meter classes, so the honest report is the empty one — and the
/// empty report is a report, not an absence. Two things are observable about it from here and both
/// are asserted, because either alone is satisfiable by a walk that is wrong:
///
/// * the unit COMPLETED. The meter step refuses with `Unpriced` when the usage grant will not take
///   its report, and a refusal there renders as an error answer rather than the surface's bytes. A
///   200 carrying the surface's own body is the walk having passed Meter;
/// * NOTHING WAS POSTED. The node's book has taken no row for an administrative walk — which is the
///   design's own statement that an admin verb's `requests` draw and its flat fee are both zero
///   under a configured non-zero fee. A walk that started charging the operator for reading their
///   own audit page would move this number, and nothing else in this file would notice.
#[cfg(feature = "root-admin")]
#[tokio::test]
async fn an_admin_verb_still_meters_to_nothing_and_posts_nothing() {
    let node = a_node();
    assert_eq!(node.postings(), 0, "a fresh book has taken no rows");

    let (status, body, _headers) =
        over_the_listener(&node, "GET", "/api/v1/admin/audit", b"").await;
    assert_eq!(status, 200, "the unit completed, so it passed Meter");
    assert_eq!(
        body, THE_SURFACES_OWN_BYTES,
        "and the body is the operation's, not a refusal the meter step raised"
    );

    let (status, _body, _headers) = over_the_listener(
        &node,
        "POST",
        "/api/v1/admin/keys",
        br#"{"name":"a-key-this-cell-asked-for"}"#,
    )
    .await;
    assert_eq!(status, 200, "and so did the mutation");

    assert_eq!(
        node.postings(),
        0,
        "an administrative walk posts no money, on either side of the read/write split"
    );
}

/// A PATH THE CLOSED TABLE DOES NOT DECLARE NEVER ENTERS THE LOOP AT ALL.
///
/// The mount asks the table first, and hands anything it does not name straight to the surface
/// underneath. That is the property that keeps `/healthz` — which answers on this listener with the
/// auth chain bypassed entirely and is not an administrative verb — answering. It is asserted here
/// because it is the one place the closed table still decides something on the live path, and the
/// removal must not have moved it: the surface still sees the request, and the chain still does not.
#[cfg(feature = "root-admin")]
#[tokio::test]
async fn a_path_the_table_does_not_declare_reaches_the_surface_without_the_loop() {
    let node = a_node();
    let (before, _) = node.chain();

    let (status, body, _headers) = over_the_listener(&node, "GET", "/healthz", b"").await;
    assert_eq!(status, 200);
    assert_eq!(body, THE_SURFACES_OWN_BYTES);
    assert_eq!(
        node.surface.seen().len(),
        1,
        "the surface answered it, once"
    );

    let (after, _) = node.chain();
    assert_eq!(
        after, before,
        "a request that never entered the loop never reached the audit step"
    );
}
