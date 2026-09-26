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
//!    line, and AUDIT seals the operation class and finish — the mutation's row on the ONE
//!    administrative ring is the kernel's, written by the core-admin handler at Route (item 237);
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
/// The book is built HERE rather than inside `ProductionUnits::admin_only` so that the rows the
/// ledger dual-writes onto are rows this cell can read back. Same value, two holders.
#[cfg(feature = "root-admin")]
struct ANodeWhoseChainThisCellReads {
    router: axum::Router,
    rows: busbar_kernel_ledger::legacy::RecordingRows,
    surface: Arc<SurfaceLog>,
}

#[cfg(feature = "root-admin")]
impl ANodeWhoseChainThisCellReads {
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
    let held = Arc::new(std::sync::Mutex::new(durability));
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
        rows,
        surface,
    }
}

/// The REAL administrative surface, twice: bare (the leg a node without the root serves, which
/// never had a root-held ring) and wrapped by the root's mount exactly as `main.rs` wraps it.
///
/// Both answer `GET /api/v1/admin/audit` off the kernel's one administrative ring, which the
/// core-admin handlers write as each mutation applies. The ring is process-wide, so every cell
/// that reads it filters on a resource only that cell minted.
#[cfg(feature = "root-admin")]
fn the_real_surface_bare_and_mounted() -> (axum::Router, axum::Router) {
    busbar_kernel::metrics::init();
    busbar_core_admin::install();
    // Governance ON, with a signer, so a key can be minted, renamed, revoked and deleted.
    let signer = busbar_kernel::governance::signing::TokenSigner::from_secret_bytes(
        &[0x5a; 32],
        busbar_kernel::governance::signing::DEFAULT_KID,
    );
    let gov = Arc::new(
        busbar_kernel::governance::GovState::new_with_signer(
            Arc::new(busbar_kernel::governance::MemoryStore::new()),
            None,
            Some(signer),
        )
        .expect("governance"),
    );
    let app = busbar_kernel::test_support::TestApp::new()
        .admin_chain(vec![])
        .governance(gov)
        .build();
    let (_data, bare, _handle) =
        busbar_kernel::build_split_routers_with_limits(app, 1 << 20, 0, false);
    let rows = busbar_kernel_ledger::legacy::RecordingRows::new();
    let durability = crate::root::durability::build(
        &crate::root::durability::DurabilityConfig { data_dir: None },
        Box::new(busbar_kernel_wal::NullShipper::new()),
        Box::new(rows.clone()),
    )
    .expect("a memory-buffered journal cannot fail to open");
    let held = Arc::new(std::sync::Mutex::new(durability));
    let read = Arc::new(rows);
    let mounted = mount(
        bare.clone(),
        crate::root::kernel::new_kernel(),
        1 << 20,
        move |dispatch| {
            crate::root::kernel::ProductionUnits::admin_only_sharing(dispatch, held, read)
                .with_auth_chain(a_door_that_identifies_the_operator())
                .with_auth_bindings(crate::root::auth_bindings::AuthBindings::new(Arc::new(
                    ADirectoryThatMintedIt,
                )))
        },
    );
    (bare, mounted)
}

/// One request over the mounted listener, with the operator's credential on it.
#[cfg(feature = "root-admin")]
async fn over_the_listener(
    node: &ANodeWhoseChainThisCellReads,
    method: &str,
    path: &str,
    body: &'static [u8],
) -> (u16, Vec<u8>, Vec<(String, String)>) {
    over(&node.router, method, path, body.to_vec()).await
}

/// One request over any router, with the operator's credential on it.
#[cfg(feature = "root-admin")]
async fn over(
    router: &axum::Router,
    method: &str,
    path: &str,
    body: Vec<u8>,
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
    let response = router
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

/// The served audit rows for one resource, as the operator's `/audit` page returns them.
#[cfg(feature = "root-admin")]
async fn audit_rows_for(router: &axum::Router, resource: &str) -> (u16, Vec<u8>) {
    let (status, body, _headers) = over(
        router,
        "GET",
        &format!("/api/v1/admin/audit?resource={resource}&limit=50"),
        Vec::new(),
    )
    .await;
    (status, body)
}

/// `(action, outcome)` for every served row, newest first.
#[cfg(feature = "root-admin")]
fn actions_and_outcomes(body: &[u8]) -> Vec<(String, String)> {
    let page: serde_json::Value = serde_json::from_slice(body).expect("the audit page is JSON");
    page["items"]
        .as_array()
        .expect("the page carries items")
        .iter()
        .map(|row| {
            (
                row["action"].as_str().unwrap_or_default().to_string(),
                row["outcome"].as_str().unwrap_or_default().to_string(),
            )
        })
        .collect()
}

/// Mint one key over `router`, and name the resource the ring files it under.
#[cfg(feature = "root-admin")]
async fn a_key_minted_over(router: &axum::Router, name: &str) -> String {
    let (status, body, _headers) = over(
        router,
        "POST",
        "/api/v1/admin/keys",
        format!(r#"{{"name":"{name}"}}"#).into_bytes(),
    )
    .await;
    assert_eq!(status, 201, "the mint reached the operation");
    let minted: serde_json::Value = serde_json::from_slice(&body).expect("the mint answers JSON");
    let id = minted["id"].as_str().expect("the minted key has an id");
    format!("key:{id}")
}

/// AND THE AUDIT IS STILL PERFORMED — ONCE, ON THE ONE RING (item 237).
///
/// If the walk had been getting its audit through the plane face, deleting the face would have
/// silently stopped recording administrative mutations, and an empty history reads exactly like a
/// quiet fleet. It was not: the mutation's row is written by the core-admin handler the walk reaches
/// at Route, onto the kernel's durable ring, and that is what the operator's `/audit` page serves.
/// The root used to write a second copy onto a RAM-only ring of its own; one mutation is now ONE row.
#[cfg(feature = "root-admin")]
#[tokio::test]
async fn a_mutating_verb_still_seals_exactly_one_entry_onto_the_audit_chain() {
    let (_bare, mounted) = the_real_surface_bare_and_mounted();
    let resource = a_key_minted_over(&mounted, "p2-rootcleanup-one-entry").await;

    let (status, body) = audit_rows_for(&mounted, &resource).await;
    assert_eq!(status, 200);
    assert_eq!(
        actions_and_outcomes(&body),
        vec![("key.create".to_string(), "applied".to_string())],
        "one mutation, one row, on the ring the operator reads"
    );
}

/// A READ still seals nothing, which is the other half of the same step.
#[cfg(feature = "root-admin")]
#[tokio::test]
async fn a_read_verb_still_seals_nothing_onto_the_audit_chain() {
    let (_bare, mounted) = the_real_surface_bare_and_mounted();
    let resource = a_key_minted_over(&mounted, "p2-rootcleanup-read-seals-nothing").await;
    let (_status, after_the_mutation) = audit_rows_for(&mounted, &resource).await;

    let (status, _body, _headers) = over(
        &mounted,
        "GET",
        &format!("/api/v1/admin/{}", resource.replacen("key:", "keys/", 1)),
        Vec::new(),
    )
    .await;
    assert_eq!(status, 200, "the read reached the operation");
    let (_status, after_the_read) = audit_rows_for(&mounted, &resource).await;

    assert_eq!(
        after_the_read, after_the_mutation,
        "a read is not a mutation and the ring does not record it"
    );
}

/// THE SERVED AUDIT BODY IS BYTE-IDENTICAL THROUGH THE ROOT AND WITHOUT IT (item 237).
///
/// A fixed sequence of mutations — mint, disable, revoke, delete one key — is walked through the
/// root's mount over the real surface. The operator's `/audit` page for that key is then asked for
/// twice: through the root, and through the bare surface a node without the root serves, which
/// never held a second ring. The two bodies are the same bytes, and they list exactly one row per
/// mutation, in order: the root adds no second answer to "what changed" and routes the read to the
/// kernel's one ring. Run at the phase-start tree (the root still keeping its RAM-only ring) this
/// cell passes with the same literal, which is the before/after comparison: deleting the ring moved
/// no served byte.
#[cfg(feature = "root-admin")]
#[tokio::test]
async fn the_served_audit_body_is_byte_identical_with_and_without_the_root() {
    let (bare, mounted) = the_real_surface_bare_and_mounted();
    let resource = a_key_minted_over(&mounted, "p2-rootcleanup-byte-identity").await;
    let path = format!("/api/v1/admin/{}", resource.replacen("key:", "keys/", 1));

    let (status, _, _) = over(&mounted, "PATCH", &path, br#"{"enabled":false}"#.to_vec()).await;
    assert_eq!(status, 200, "the disable applied");
    let (status, _, _) = over(&mounted, "POST", &format!("{path}/revoke"), b"{}".to_vec()).await;
    assert!((200..300).contains(&status), "the revoke applied: {status}");
    let (status, _, _) = over(&mounted, "DELETE", &path, Vec::new()).await;
    assert!((200..300).contains(&status), "the delete applied: {status}");

    let (status, through_the_root) = audit_rows_for(&mounted, &resource).await;
    assert_eq!(status, 200);
    let (status, without_the_root) = audit_rows_for(&bare, &resource).await;
    assert_eq!(status, 200);

    assert_eq!(
        through_the_root, without_the_root,
        "the served audit body differs through the root"
    );
    assert_eq!(
        actions_and_outcomes(&through_the_root),
        vec![
            ("key.delete".to_string(), "applied".to_string()),
            ("key.revoke".to_string(), "applied".to_string()),
            ("key.patch".to_string(), "applied".to_string()),
            ("key.create".to_string(), "applied".to_string()),
        ],
        "one row per mutation, newest first, and no second copy"
    );
}

/// A store that applies each recovery verb, so a root-only verb can end `applied`.
#[cfg(feature = "root-admin")]
struct AnApplyingStore;

#[cfg(feature = "root-admin")]
impl busbar_contract::verb_store::Store for AnApplyingStore {
    fn chain_break(
        &self,
        _admin: &busbar_contract::caps::Grant<busbar_contract::caps::AdminVerb>,
    ) -> Result<(), busbar_contract::verb_store::StoreError> {
        Ok(())
    }

    fn store_restore(
        &self,
        _admin: &busbar_contract::caps::Grant<busbar_contract::caps::AdminVerb>,
        _backup_ref: &str,
    ) -> Result<(), busbar_contract::verb_store::StoreError> {
        Ok(())
    }

    fn reseal_epoch_floor(
        &self,
        _admin: &busbar_contract::caps::Grant<busbar_contract::caps::AdminVerb>,
    ) -> Result<(), busbar_contract::verb_store::StoreError> {
        Ok(())
    }

    fn replay_new_verb(
        &self,
        _key: &(String, String),
    ) -> Result<Option<Vec<u8>>, busbar_contract::verb_store::StoreError> {
        Ok(None)
    }

    fn commit_new_verb_replay(
        &self,
        _key: &(String, String),
        _response: &[u8],
    ) -> Result<(), busbar_contract::verb_store::StoreError> {
        Ok(())
    }
}

/// The served rows for one resource that the operator (`admin`) is attributed, as
/// `(action, outcome)`, newest first. Filtered on the principal because the ring is process-wide
/// and the step-level cells in `units_admin.rs` seal the same verbs under another identity.
#[cfg(feature = "root-admin")]
async fn the_operators_rows_for(router: &axum::Router, resource: &str) -> Vec<(String, String)> {
    let (status, body) = audit_rows_for(router, resource).await;
    assert_eq!(status, 200, "the audit page answers");
    let page: serde_json::Value = serde_json::from_slice(&body).expect("the audit page is JSON");
    page["items"]
        .as_array()
        .expect("the page carries items")
        .iter()
        .filter(|row| row["principal"] == crate::root::auth_bindings::ADMIN_PRINCIPAL_ID)
        .map(|row| {
            (
                row["action"].as_str().unwrap_or_default().to_string(),
                row["outcome"].as_str().unwrap_or_default().to_string(),
            )
        })
        .collect()
}

/// EVERY ROOT-ONLY MUTATING VERB SEALS EXACTLY ONE DURABLE ROW; A READ SEALS NONE (P2-rootfollow).
///
/// The 1.6.0 verbs have no core-admin handler, so nothing wrote their row once the root's RAM ring
/// went (item 237). Each is walked through the root's mount over the real surface, once, and the
/// operator's `/audit` page must then carry exactly one row for it on the kernel's durable ring:
/// `applied` where the effect landed (the three store verbs, under a sealed operator key and a store
/// that applies), `rejected` where it did not. A ledger view seals nothing.
#[cfg(feature = "root-admin")]
#[tokio::test]
async fn every_root_only_mutating_verb_seals_one_durable_row_and_a_read_seals_none() {
    busbar_kernel::metrics::init();
    busbar_core_admin::install();
    let app = busbar_kernel::test_support::TestApp::new()
        .admin_chain(vec![])
        .build();
    let (_data, bare, _handle) =
        busbar_kernel::build_split_routers_with_limits(app, 1 << 20, 0, false);
    let rows = busbar_kernel_ledger::legacy::RecordingRows::new();
    let durability = crate::root::durability::build(
        &crate::root::durability::DurabilityConfig { data_dir: None },
        Box::new(busbar_kernel_wal::NullShipper::new()),
        Box::new(rows.clone()),
    )
    .expect("a memory-buffered journal cannot fail to open");
    let held = Arc::new(std::sync::Mutex::new(durability));
    let read = Arc::new(rows);
    let mounted = mount(
        bare,
        crate::root::kernel::new_kernel(),
        1 << 20,
        move |dispatch| {
            let mut units =
                crate::root::kernel::ProductionUnits::admin_only_sharing(dispatch, held, read)
                    .with_auth_chain(a_door_that_identifies_the_operator())
                    .with_auth_bindings(crate::root::auth_bindings::AuthBindings::new(Arc::new(
                        ADirectoryThatMintedIt,
                    )));
            units.admin.posture = Arc::new(SealedPosture::new(Some([7u8; 32])));
            units.store = Arc::new(AnApplyingStore);
            units
        },
    );

    let applied = [
        ("/api/v1/admin/chain-break", "{}", "chain_break"),
        (
            "/api/v1/admin/store-restore",
            r#"{"backup_ref":"nightly"}"#,
            "store_restore",
        ),
        (
            "/api/v1/admin/reseal-epoch-floor",
            "{}",
            "reseal_epoch_floor",
        ),
    ];
    for (path, body, verb) in applied {
        let (status, _, _) = over(&mounted, "POST", path, body.as_bytes().to_vec()).await;
        assert_eq!(status, 204, "{verb} applied");
        assert_eq!(
            the_operators_rows_for(&mounted, path).await,
            vec![(verb.to_string(), "applied".to_string())],
            "{verb}: one applied row on the durable ring"
        );
    }

    // Only the verbs with a bound effect are walked here; the unbound ones are not served at all
    // (`an_unbound_verb_is_not_served_it_answers_the_unmounted_404_and_seals_nothing`).
    let rejected = [
        ("/api/v1/admin/adjust", "adjust"),
        (
            "/api/v1/admin/ledger/amend-rate-history",
            "amend_rate_history",
        ),
    ];
    for (path, verb) in rejected {
        let (status, _, _) = over(&mounted, "POST", path, b"{}".to_vec()).await;
        assert!(
            !(200..300).contains(&status),
            "{verb} did not apply: {status}"
        );
        assert_eq!(
            the_operators_rows_for(&mounted, path).await,
            vec![(verb.to_string(), "rejected".to_string())],
            "{verb}: one rejected row on the durable ring"
        );
    }

    for path in ["/api/v1/admin/ledger/totals"] {
        let _ = over(&mounted, "GET", path, Vec::new()).await;
        assert_eq!(
            the_operators_rows_for(&mounted, path).await,
            Vec::<(String, String)>::new(),
            "{path}: a read seals nothing"
        );
    }
}

/// The 1.6.0 verbs this build binds NO EFFECT to, as `(method, path)`. Empty since owner answer
/// Q71(2) bound the last four (`verify`, `plane_facts`, `plane_record_write`, `commit_upgrade` —
/// `the_four_q71_verbs_are_served_and_refuse_by_name`); a verb added to `NEW_VERBS` without an
/// `effect_bound` arm lands here, measured by the one generic check below.
#[cfg(feature = "root-admin")]
const THE_UNBOUND_VERBS: [(&str, &str); 0] = [];

/// The nine verbs the owner removed from 1.6.0 — on 2026-09-08 (`set_operator_key`, `set_escrow`,
/// `set_dual_control`, `export_keyset`, `approve`) and by #77(9), owner answer Q71(1)
/// (`set_overdraft_ceiling`, `set_dispute_max_age`, `resolve_dispute`, `resolve_slice`) — as
/// `(method, path)`. They are no longer in the
/// table at all; while they were, they were unbound and answered the unmounted `404`. Removing them
/// must not move that answer by a byte.
#[cfg(feature = "root-admin")]
const THE_REMOVED_VERBS: [(&str, &str); 9] = [
    ("POST", "/api/v1/admin/operator-key"),
    ("POST", "/api/v1/admin/escrow"),
    ("POST", "/api/v1/admin/dual-control"),
    ("POST", "/api/v1/admin/export-keyset"),
    ("POST", "/api/v1/admin/approve"),
    ("POST", "/api/v1/admin/overdraft-ceiling"),
    ("POST", "/api/v1/admin/dispute-max-age"),
    ("POST", "/api/v1/admin/disputes/resolve"),
    ("POST", "/api/v1/admin/slices/resolve"),
];

/// AN ADMIN VERB WHOSE EFFECT IS NOT BOUND IS NOT SERVED (architect ruling 2026-09-24).
///
/// Under a sealed operator key and a full-scope operator — the posture in which every gate admits —
/// each unbound verb (none since Q71(2)) and each of the nine the owner removed (which the table no
/// longer names) answers EXACTLY what an unmounted path answers (`404 not_found` /
/// `resource not found`, byte for byte, which is also the published 1.5.5 answer for every one of
/// these paths) and seals NO audit row. It used to be walked through the gates, sealed a `rejected`
/// row, and then answered the same 404 from a surface with no handler for it. And the set is the
/// one generic `effect_bound` check's, not a list kept beside it.
#[cfg(feature = "root-admin")]
#[tokio::test]
async fn an_unbound_verb_is_not_served_it_answers_the_unmounted_404_and_seals_nothing() {
    busbar_kernel::metrics::init();
    busbar_core_admin::install();
    let app = busbar_kernel::test_support::TestApp::new()
        .admin_chain(vec![])
        .build();
    let (_data, bare, _handle) =
        busbar_kernel::build_split_routers_with_limits(app, 1 << 20, 0, false);
    let rows = busbar_kernel_ledger::legacy::RecordingRows::new();
    let durability = crate::root::durability::build(
        &crate::root::durability::DurabilityConfig { data_dir: None },
        Box::new(busbar_kernel_wal::NullShipper::new()),
        Box::new(rows.clone()),
    )
    .expect("a memory-buffered journal cannot fail to open");
    let held = Arc::new(std::sync::Mutex::new(durability));
    let read = Arc::new(rows);
    let mounted = mount(
        bare,
        crate::root::kernel::new_kernel(),
        1 << 20,
        move |dispatch| {
            let mut units =
                crate::root::kernel::ProductionUnits::admin_only_sharing(dispatch, held, read)
                    .with_auth_chain(a_door_that_identifies_the_operator())
                    .with_auth_bindings(crate::root::auth_bindings::AuthBindings::new(Arc::new(
                        ADirectoryThatMintedIt,
                    )));
            units.admin.posture = Arc::new(SealedPosture::new(Some([7u8; 32])));
            units
        },
    );
    let (unmounted_status, unmounted, _) = over(
        &mounted,
        "POST",
        "/api/v1/admin/no-such-operation",
        b"{}".to_vec(),
    )
    .await;
    assert_eq!(unmounted_status, 404, "the control is the unmounted path");
    assert_eq!(
        unmounted,
        br#"{"error":{"code":"not_found","message":"resource not found"}}"#.to_vec(),
        "the control is the router's generic miss"
    );
    for (method, path) in THE_UNBOUND_VERBS.into_iter().chain(THE_REMOVED_VERBS) {
        let body = if method == "GET" {
            Vec::new()
        } else {
            b"{}".to_vec()
        };
        let (status, answer, _) = over(&mounted, method, path, body).await;
        assert_eq!(
            (status, answer.as_slice()),
            (unmounted_status, unmounted.as_slice()),
            "{method} {path}: an unbound or removed verb answers exactly what an unmounted path answers"
        );
        assert_eq!(
            the_operators_rows_for(&mounted, path).await,
            Vec::<(String, String)>::new(),
            "{method} {path}: an unserved verb seals no audit row"
        );
    }
    let unbound: std::collections::BTreeSet<(&str, &str)> = busbar_core_admin::NEW_VERBS
        .iter()
        .filter(|verb| !busbar_core_admin::verb::effect_bound(**verb))
        .filter_map(|verb| {
            let name = busbar_core_admin::verb_name(*verb)?;
            busbar_core_admin::admin_codec::verbs::table()
                .into_iter()
                .find(|row| row.verb == name)
                .map(|row| (row.method, row.template))
        })
        .collect();
    assert_eq!(
        unbound,
        THE_UNBOUND_VERBS.into_iter().collect(),
        "the measured set is exactly what the one generic check leaves unbound"
    );
    let table = busbar_core_admin::admin_codec::verbs::table();
    for (method, path) in THE_REMOVED_VERBS {
        assert!(
            !table
                .iter()
                .any(|row| row.method == method && row.template == path),
            "{method} {path}: a verb the owner removed from 1.6.0 still has a row in the table"
        );
    }
}

/// A NODE WITH NO SEALED OPERATOR KEY ANSWERS THE AMEND PATH AS 1.5.5 DOES (oracle cells
/// `ledger|amend|adjusting-entries` and `|refused-unsigned`).
///
/// `amend_rate_history` verifies a signature against `auth.operator_pub`; with none sealed there is
/// nothing to verify against, and the deployment is a 1.5.5-shaped one. The published binary
/// answers this path with its router's generic miss, `404 not_found` / `resource not found`; the
/// mount used to walk it to a `403` "insufficient scope: this endpoint requires `full`" — told to
/// the operator credential, which holds `full`. Signed or unsigned, the unsealed node answers the
/// surface's own 404. With a key sealed the verb is claimed and refuses on its own terms.
#[cfg(feature = "root-admin")]
#[tokio::test]
async fn the_amend_path_on_a_node_with_no_operator_key_is_1_5_5_s_404() {
    busbar_kernel::metrics::init();
    busbar_core_admin::install();
    let mount_under = |operator_key: Option<[u8; 32]>| {
        let app = busbar_kernel::test_support::TestApp::new()
            .admin_chain(vec![])
            .build();
        let (_data, bare, _handle) =
            busbar_kernel::build_split_routers_with_limits(app, 1 << 20, 0, false);
        let rows = busbar_kernel_ledger::legacy::RecordingRows::new();
        let durability = crate::root::durability::build(
            &crate::root::durability::DurabilityConfig { data_dir: None },
            Box::new(busbar_kernel_wal::NullShipper::new()),
            Box::new(rows.clone()),
        )
        .expect("a memory-buffered journal cannot fail to open");
        let held = Arc::new(std::sync::Mutex::new(durability));
        let read = Arc::new(rows);
        mount(
            bare,
            crate::root::kernel::new_kernel(),
            1 << 20,
            move |dispatch| {
                let mut units =
                    crate::root::kernel::ProductionUnits::admin_only_sharing(dispatch, held, read)
                        .with_auth_chain(a_door_that_identifies_the_operator())
                        .with_auth_bindings(crate::root::auth_bindings::AuthBindings::new(
                            Arc::new(ADirectoryThatMintedIt),
                        ));
                units.admin.posture = Arc::new(SealedPosture::new(operator_key));
                units
            },
        )
    };
    let path = "/api/v1/admin/ledger/amend-rate-history";
    let body = br#"{"effective_from":1,"rate_card":{}}"#.to_vec();

    // The SEALED half is `every_root_only_mutating_verb_seals_one_durable_row_and_a_read_seals_none`
    // (the verb claimed, walked, and sealing its one `rejected` row). It is not repeated here: the
    // ring is process-wide and a second sealed walk would add a row to that cell's count.
    let (status, answer, headers) = over(&mount_under(None), "POST", path, body).await;
    assert_eq!(status, 404, "{}", String::from_utf8_lossy(&answer));
    assert_eq!(
        answer,
        br#"{"error":{"code":"not_found","message":"resource not found"}}"#.to_vec(),
        "the 1.5.5 router's generic miss, byte for byte"
    );
    assert!(
        headers
            .iter()
            .any(|(k, v)| k == "content-type" && v == "application/json"),
        "{headers:?}"
    );
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
/// removal must not have moved it: the surface still sees the request, once.
#[cfg(feature = "root-admin")]
#[tokio::test]
async fn a_path_the_table_does_not_declare_reaches_the_surface_without_the_loop() {
    let node = a_node();

    let (status, body, _headers) = over_the_listener(&node, "GET", "/healthz", b"").await;
    assert_eq!(status, 200);
    assert_eq!(body, THE_SURFACES_OWN_BYTES);
    assert_eq!(
        node.surface.seen().len(),
        1,
        "the surface answered it, once"
    );
}

// ── the four verbs owner answer Q71(2) binds ─────────────────────────────────────────────────────

/// A plane declaration for the Q71(2) cells: the one plane the lookup below serves.
#[cfg(feature = "root-admin")]
const A_SERVED_PLANE: busbar_contract::plane::PlaneDeclaration =
    busbar_contract::plane::PlaneDeclaration {
        key: "example",
        fallback: false,
        config_section: "examples",
        scope_kinds: &["example"],
        subject_noun: "example",
        admin_noun: "example",
        audit_kind: "example",
        card_signing_domain: None,
        card_kid_prefix: None,
        owned_config_sections: &["examples"],
        billable_classes: &[busbar_contract::plane::BillableClass {
            class: "calls",
            family: "count",
        }],
        fee_units: &[busbar_contract::plane::PER_REQUEST],
        metric_families: &[],
        record_kinds: &["note"],
        served_op_classes: &[],
    };

/// A door that identifies ANOTHER principal than the operator: authenticated, and holding no grant.
#[cfg(feature = "root-admin")]
struct IdentifiesATenant;

#[cfg(feature = "root-admin")]
impl busbar_kernel_identity::module::AuthModule for IdentifiesATenant {
    fn name(&self) -> &'static str {
        "identifies-a-tenant"
    }

    fn authenticate(&self, candidate: Option<&str>) -> busbar_kernel_identity::module::AuthOutcome {
        match candidate {
            Some(THE_OPERATORS_CREDENTIAL) => {
                busbar_kernel_identity::module::AuthOutcome::Identify(
                    busbar_kernel_identity::principal::Principal::from_id("a-tenant"),
                )
            }
            _ => busbar_kernel_identity::module::AuthOutcome::Pass,
        }
    }
}

/// The node the Q71(2) cells walk: a real surface, a memory-buffered journal, the given door and
/// posture, the one served plane, and a record sink that keeps what it was handed.
#[cfg(feature = "root-admin")]
fn a_q71_node(
    door: busbar_kernel_identity::AuthChain,
    operator_key: Option<[u8; 32]>,
) -> (
    axum::Router,
    Arc<std::sync::Mutex<Vec<busbar_contract::records::PlaneRecord>>>,
) {
    busbar_kernel::metrics::init();
    busbar_core_admin::install();
    let app = busbar_kernel::test_support::TestApp::new()
        .admin_chain(vec![])
        .build();
    let (_data, bare, _handle) =
        busbar_kernel::build_split_routers_with_limits(app, 1 << 20, 0, false);
    let rows = busbar_kernel_ledger::legacy::RecordingRows::new();
    let durability = crate::root::durability::build(
        &crate::root::durability::DurabilityConfig { data_dir: None },
        Box::new(busbar_kernel_wal::NullShipper::new()),
        Box::new(rows.clone()),
    )
    .expect("a memory-buffered journal cannot fail to open");
    let held = Arc::new(std::sync::Mutex::new(durability));
    let read = Arc::new(rows);
    let kept = Arc::new(std::sync::Mutex::new(Vec::new()));
    let sink = Arc::clone(&kept);
    let mounted = mount(
        bare,
        crate::root::kernel::new_kernel(),
        1 << 20,
        move |dispatch| {
            let mut units =
                crate::root::kernel::ProductionUnits::admin_only_sharing(dispatch, held, read)
                    .with_auth_chain(door)
                    .with_auth_bindings(crate::root::auth_bindings::AuthBindings::new(Arc::new(
                        ADirectoryThatMintedIt,
                    )));
            units.admin.posture = Arc::new(SealedPosture::new(operator_key));
            units.admin.planes =
                Arc::new(|key: &str| (key == A_SERVED_PLANE.key).then_some(A_SERVED_PLANE));
            units.admin.records = Some(Arc::new(
                move |record: &busbar_contract::records::PlaneRecord| {
                    sink.lock().expect("the sink").push(record.clone());
                    Ok(())
                },
            ));
            units
        },
    );
    (mounted, kept)
}

/// One request over `router` presenting `credential` (or none).
#[cfg(feature = "root-admin")]
async fn over_as(
    router: &axum::Router,
    method: &str,
    path: &str,
    body: &str,
    credential: Option<&str>,
) -> (u16, String) {
    use tower::ServiceExt;

    let mut request = axum::http::Request::builder().method(method).uri(path);
    if let Some(credential) = credential {
        request = request.header(
            axum::http::header::AUTHORIZATION,
            format!("Bearer {credential}"),
        );
    }
    let request = request
        .header(axum::http::header::CONTENT_TYPE, "application/json")
        .body(axum::body::Body::from(body.to_string()))
        .expect("the request builds");
    let response = router
        .clone()
        .oneshot(request)
        .await
        .expect("the mounted router answers");
    let status = response.status().as_u16();
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("the answer's body is readable");
    (
        status,
        String::from_utf8(bytes.to_vec()).expect("the answer is text"),
    )
}

/// The four verbs as `(method, path, a body that applies)`.
#[cfg(feature = "root-admin")]
fn the_q71_verbs() -> [(&'static str, &'static str, String); 4] {
    [
        ("GET", "/api/v1/admin/verify", String::new()),
        (
            "GET",
            "/api/v1/admin/plane-facts?plane=example",
            String::new(),
        ),
        (
            "POST",
            "/api/v1/admin/plane-record-write",
            r#"{"plane":"example","kind":"note","id":"n-1","body":{"text":"hello"}}"#.to_string(),
        ),
        (
            "POST",
            "/api/v1/admin/commit-upgrade",
            format!(r#"{{"version":"{}"}}"#, super::bound::RUNNING_RELEASE),
        ),
    ]
}

/// OWNER ANSWER Q71(2): `verify`, `plane_facts`, `plane_record_write` and `commit_upgrade` ARE
/// SERVED, each by its own effect, and each refuses a bad argument BY NAME.
///
/// Walked over the real mount behind the operator under a sealed operator key (the posture in which
/// the irreducible `commit_upgrade` is admitted). Every answer is asserted by status AND body text.
#[cfg(feature = "root-admin")]
#[tokio::test]
async fn the_four_q71_verbs_are_served_and_refuse_by_name() {
    let (node, kept) = a_q71_node(a_door_that_identifies_the_operator(), Some([7u8; 32]));
    let op = Some(THE_OPERATORS_CREDENTIAL);

    // verify: a fresh node has sealed nothing and posted nothing, and says so — `ok`, with the
    // book NOT verified (there is no checkpoint to verify it against).
    let (status, body) = over_as(&node, "GET", "/api/v1/admin/verify", "", op).await;
    assert_eq!(status, 200, "verify is served: {body}");
    assert_eq!(
        body,
        r#"{"book_verified":false,"checkpoints":0,"discrepancies":0,"findings":[],"identity_holds":true,"ok":true,"since":null}"#
    );

    // plane_facts: the served plane's declaration; an unserved key is 404 by name; none is 400.
    let (status, body) = over_as(
        &node,
        "GET",
        "/api/v1/admin/plane-facts?plane=example",
        "",
        op,
    )
    .await;
    assert_eq!(status, 200, "plane_facts is served: {body}");
    let facts: serde_json::Value = serde_json::from_str(&body).expect("JSON");
    assert_eq!(facts["plane"], "example");
    assert_eq!(facts["config_section"], "examples");
    assert_eq!(
        facts["billable_classes"],
        serde_json::json!([{"class": "calls", "family": "count"}])
    );
    assert_eq!(facts["fee_units"], serde_json::json!(["per_request"]));
    assert_eq!(facts["record_kinds"], serde_json::json!(["note"]));
    assert_eq!(
        over_as(&node, "GET", "/api/v1/admin/plane-facts?plane=nope", "", op).await,
        (
            404,
            r#"{"error":{"code":"not_found","message":"plane `nope` not found"}}"#.to_string()
        )
    );
    assert_eq!(
        over_as(&node, "GET", "/api/v1/admin/plane-facts", "", op).await,
        (
            400,
            r#"{"error":{"code":"invalid_request","message":"plane is required"}}"#.to_string()
        )
    );

    // plane_record_write: the record reaches the sink exactly as written.
    let (_, _, write) = the_q71_verbs()[2].clone();
    let (status, body) = over_as(
        &node,
        "POST",
        "/api/v1/admin/plane-record-write",
        &write,
        op,
    )
    .await;
    assert_eq!(status, 200, "plane_record_write is served: {body}");
    let at = serde_json::from_str::<serde_json::Value>(&body).expect("JSON")["written_at"]
        .as_u64()
        .expect("written_at");
    assert_eq!(
        body,
        format!(
            r#"{{"id":"n-1","kind":"note","parent":null,"plane":"example","terminal":false,"written_at":{at}}}"#
        )
    );
    {
        let kept = kept.lock().expect("the sink");
        assert_eq!(kept.len(), 1, "exactly one record written");
        assert_eq!(
            (kept[0].kind.as_str(), kept[0].id.as_str(), kept[0].ts),
            ("note", "n-1", at)
        );
        assert_eq!(kept[0].body, br#"{"text":"hello"}"#.to_vec());
        assert_eq!(
            kept[0].disposition,
            busbar_contract::records::PlaneDisposition::Active
        );
    }
    assert_eq!(
        over_as(
            &node,
            "POST",
            "/api/v1/admin/plane-record-write",
            r#"{"plane":"example","id":"n-1","body":{}}"#,
            op
        )
        .await,
        (
            400,
            r#"{"error":{"code":"invalid_request","message":"kind is required"}}"#.to_string()
        )
    );
    assert_eq!(
        over_as(
            &node,
            "POST",
            "/api/v1/admin/plane-record-write",
            r#"{"plane":"nope","kind":"note","id":"n-1","body":{}}"#,
            op
        )
        .await,
        (
            404,
            r#"{"error":{"code":"not_found","message":"plane `nope` not found"}}"#.to_string()
        )
    );
    // ARCHITECT RULING (b): a kind the named plane does not declare is refused by name.
    assert_eq!(
        over_as(
            &node,
            "POST",
            "/api/v1/admin/plane-record-write",
            r#"{"plane":"example","kind":"task","id":"t-1","body":{}}"#,
            op
        )
        .await,
        (
            403,
            r#"{"error":{"code":"forbidden","message":"plane `example` may not write record kind `task`"}}"#
                .to_string()
        )
    );
    assert_eq!(
        kept.lock().expect("the sink").len(),
        1,
        "a refusal writes nothing"
    );

    // commit_upgrade: the running release is committed and sealed on the journal; any other is a
    // named conflict.
    let (_, _, commit) = the_q71_verbs()[3].clone();
    let (status, body) = over_as(&node, "POST", "/api/v1/admin/commit-upgrade", &commit, op).await;
    assert_eq!(status, 200, "commit_upgrade is served: {body}");
    let committed: serde_json::Value = serde_json::from_str(&body).expect("JSON");
    assert_eq!(committed["committed"], super::bound::RUNNING_RELEASE);
    assert_eq!(committed["hash"].as_str().map(str::len), Some(64));
    assert_eq!(
        over_as(
            &node,
            "POST",
            "/api/v1/admin/commit-upgrade",
            r#"{"version":"0.0.1"}"#,
            op
        )
        .await,
        (
            409,
            format!(
                r#"{{"error":{{"code":"conflict","message":"this node runs `{}`; it cannot commit `0.0.1`"}}}}"#,
                super::bound::RUNNING_RELEASE
            )
        )
    );
}

/// THE Q71(2) VERBS ARE AUTHORIZED LIKE EVERY OTHER ADMIN VERB, AND REFUSE BY THE DOOR'S AND THE
/// SCOPE'S OWN TEXT.
///
/// No credential is the door's `401`; a caller the door identifies as somebody other than the
/// operator holds no grant and is told the scope the endpoint needed (`read-only` for the two
/// reads, `full` for the two writes); and the irreducible `commit_upgrade` on a fleet with no
/// sealed operator key is refused at the ceremony gate — nothing is written in any of them.
#[cfg(feature = "root-admin")]
#[tokio::test]
async fn the_four_q71_verbs_refuse_an_unauthorized_caller_by_text() {
    const DOOR: &str = r#"{"error":{"code":"unauthorized","message":"missing or invalid admin credential (Bearer or x-admin-token)"}}"#;
    let scope = |needed: &str| {
        format!(
            r#"{{"error":{{"code":"forbidden","message":"insufficient scope: this endpoint requires `{needed}`"}}}}"#
        )
    };

    let (node, kept) = a_q71_node(a_door_that_identifies_the_operator(), Some([7u8; 32]));
    for (method, path, body) in the_q71_verbs() {
        assert_eq!(
            over_as(&node, method, path, &body, None).await,
            (401, DOOR.to_string()),
            "{method} {path}: no credential is the door"
        );
    }

    let tenant = busbar_kernel_identity::AuthChain::new(
        vec![busbar_kernel_identity::chain::ChainEntry {
            provider: "identifies-a-tenant".to_string(),
            module: Box::new(IdentifiesATenant),
        }],
        false,
    );
    let (tenants_node, tenants_kept) = a_q71_node(tenant, Some([7u8; 32]));
    for (method, path, body) in the_q71_verbs() {
        let needed = if method == "GET" { "read-only" } else { "full" };
        assert_eq!(
            over_as(
                &tenants_node,
                method,
                path,
                &body,
                Some(THE_OPERATORS_CREDENTIAL)
            )
            .await,
            (403, scope(needed)),
            "{method} {path}: an identified caller with no grant is told the scope"
        );
    }

    let (unsealed, unsealed_kept) = a_q71_node(a_door_that_identifies_the_operator(), None);
    let (_, _, commit) = the_q71_verbs()[3].clone();
    assert_eq!(
        over_as(
            &unsealed,
            "POST",
            "/api/v1/admin/commit-upgrade",
            &commit,
            Some(THE_OPERATORS_CREDENTIAL)
        )
        .await,
        (403, scope("full")),
        "commit_upgrade is irreducible: refused while no operator key is sealed"
    );

    for sink in [kept, tenants_kept, unsealed_kept] {
        assert!(
            sink.lock().expect("the sink").is_empty(),
            "no refusal wrote a record"
        );
    }
}

/// One request as the operator, carrying `Idempotency-Key: <key>`.
#[cfg(feature = "root-admin")]
async fn over_with_key(router: &axum::Router, path: &str, body: &str, key: &str) -> (u16, String) {
    use tower::ServiceExt;

    let request = axum::http::Request::builder()
        .method("POST")
        .uri(path)
        .header(
            axum::http::header::AUTHORIZATION,
            format!("Bearer {THE_OPERATORS_CREDENTIAL}"),
        )
        .header("idempotency-key", key)
        .header(axum::http::header::CONTENT_TYPE, "application/json")
        .body(axum::body::Body::from(body.to_string()))
        .expect("the request builds");
    let response = router
        .clone()
        .oneshot(request)
        .await
        .expect("the mounted router answers");
    let status = response.status().as_u16();
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("the answer's body is readable");
    (
        status,
        String::from_utf8(bytes.to_vec()).expect("the answer is text"),
    )
}

/// CONTRACT D-3 ON THE TWO Q71(2) WRITES (ARCHITECT RULING (a)): a retry carrying the same
/// `Idempotency-Key` and the same body answers the FIRST answer byte for byte and runs nothing again;
/// the same key with a different body is refused by name and runs nothing; a different key runs.
#[cfg(feature = "root-admin")]
#[tokio::test]
async fn the_q71_writes_replay_under_an_idempotency_key() {
    const MISMATCH: &str = r#"{"error":{"code":"conflict","message":"this Idempotency-Key was already used with a different request body"}}"#;
    let (node, kept) = a_q71_node(a_door_that_identifies_the_operator(), Some([7u8; 32]));

    // plane_record_write: one record for two identical calls.
    let (_, _, write) = the_q71_verbs()[2].clone();
    let path = "/api/v1/admin/plane-record-write";
    let first = over_with_key(&node, path, &write, "k-write").await;
    assert_eq!(first.0, 200, "the first call writes: {}", first.1);
    assert_eq!(
        over_with_key(&node, path, &write, "k-write").await,
        first,
        "the retry answers the first answer, byte for byte"
    );
    assert_eq!(
        kept.lock().expect("the sink").len(),
        1,
        "and writes nothing again"
    );
    let other = r#"{"plane":"example","kind":"note","id":"n-2","body":{}}"#;
    assert_eq!(
        over_with_key(&node, path, other, "k-write").await,
        (409, MISMATCH.to_string()),
        "the same key with a different body is refused by name"
    );
    assert_eq!(
        kept.lock().expect("the sink").len(),
        1,
        "and writes nothing"
    );
    assert_eq!(over_with_key(&node, path, other, "k-other").await.0, 200);
    assert_eq!(
        kept.lock().expect("the sink").len(),
        2,
        "a different key runs"
    );

    // commit_upgrade: one sealed record (the same seq and hash) for two identical calls.
    let (_, _, commit) = the_q71_verbs()[3].clone();
    let path = "/api/v1/admin/commit-upgrade";
    let first = over_with_key(&node, path, &commit, "k-commit").await;
    assert_eq!(first.0, 200, "the first commit seals: {}", first.1);
    assert_eq!(
        over_with_key(&node, path, &commit, "k-commit").await,
        first,
        "the retry answers the first commit's seq and hash, sealing nothing again"
    );
    assert_eq!(
        over_with_key(&node, path, r#"{"version":"0.0.1"}"#, "k-commit").await,
        (409, MISMATCH.to_string())
    );
}
