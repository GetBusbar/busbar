//! Tests for `units_admin.rs`. Lifted out of the implementation file so its line count
//! measures implementation and nothing else; still a direct child module, so `use
//! super::*` reaches the private items it always did.

use super::*;

/// A key no other request in this binary is walking. The unit key names one live unit, so two
/// fixtures sharing a literal would be two requests claiming one entry in the units table.
fn a_fresh_unit() -> u64 {
    static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);
    NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
}

fn a_request() -> AdminRequest {
    AdminRequest {
        method: "GET".to_string(),
        path: "/api/v1/admin/audit?limit=4".to_string(),
        credential: Some("admin-token".to_string()),
        headers: vec![("accept".to_string(), "application/json".to_string())],
        body: Vec::new(),
        at: 1_700_000_000,
        unit: a_fresh_unit(),
    }
}

/// THE PRESENTED CREDENTIAL IN `Debug`. A derived `Debug` on [`AdminRequest`] prints
/// `credential: Some("<the operator's live admin token>")` verbatim — and prints it a SECOND time
/// inside `headers`, because `header_pairs` copies every arriving header in as it stands, so the
/// same bytes arrive again as `authorization: Bearer <token>` and `x-admin-token: <token>`. Any
/// `{:?}` publishes them: a tracing line, a panic message, an `assert_eq!` failure in a CI log.
///
/// The secret here is a planted marker and its ABSENCE is what is asserted — the test never has to
/// print a real credential to fail informatively. The ASCII check alone is enough to catch a
/// regression to `#[derive(Debug)]` in this case (unlike `CredentialSlab`, whose secret is a
/// `Vec<u8>` and would render as a decimal array): a `String` and an `Option<String>` both render
/// their text, so a derived impl fails the very first assertion.
#[test]
fn debug_redacts_the_presented_credential_and_the_header_it_arrived_in() {
    const SECRET: &str = "a-distinctive-admin-secret-7f31c9";
    let request = AdminRequest {
        method: "POST".to_string(),
        path: "/api/v1/admin/config/apply".to_string(),
        credential: Some(SECRET.to_string()),
        headers: vec![
            ("authorization".to_string(), format!("Bearer {SECRET}")),
            ("x-admin-token".to_string(), SECRET.to_string()),
            ("content-type".to_string(), "application/json".to_string()),
        ],
        body: b"{}".to_vec(),
        at: 1_700_000_000,
        unit: a_fresh_unit(),
    };

    let rendered = format!("{request:?}");
    assert!(
        !rendered.contains(SECRET),
        "Debug must never carry the presented credential — not in the field, not in the header it \
         arrived in. Got: {rendered}"
    );
    assert!(
        rendered.matches("<redacted>").count() >= 3,
        "the field and BOTH carriers must be redacted, got: {rendered}"
    );
    // The non-secret shape survives, or the redaction has cost the operator the diagnosis it was
    // supposed to leave behind.
    assert!(rendered.contains("AdminRequest"), "got: {rendered}");
    assert!(
        rendered.contains("/api/v1/admin/config/apply"),
        "got: {rendered}"
    );
    assert!(
        rendered.contains("content-type") && rendered.contains("application/json"),
        "a header that carries no credential still prints as itself, got: {rendered}"
    );
    assert!(rendered.contains("\"POST\""), "got: {rendered}");

    // AND THE REDACTION NEVER MANUFACTURES A CREDENTIAL OUT OF AN ABSENT ONE. With nothing
    // presented there is nothing to hide, and every header prints as itself.
    let nothing_presented = AdminRequest {
        credential: None,
        headers: vec![(
            "authorization".to_string(),
            "Bearer not-what-was-presented".to_string(),
        )],
        ..request
    };
    let rendered = format!("{nothing_presented:?}");
    assert!(rendered.contains("credential: None"), "got: {rendered}");
    assert!(
        !rendered.contains("<redacted>"),
        "nothing was presented, so nothing is redacted, got: {rendered}"
    );
    assert!(
        rendered.contains("Bearer not-what-was-presented"),
        "got: {rendered}"
    );
}

/// THE DOOR'S BYTES, PINNED TO THE PUBLISHED RELEASE'S OWN.
///
/// A refusal path may not execute anything, so these bytes are composed from what is written
/// down rather than obtained by sending the request back down to be refused a second time.
/// Composed bytes are only as good as what they were copied from, which is why the comparison is
/// against the recorded cell the oracle replays — the published binary's actual answer, read out
/// of the golden tree here — and not against a literal restated in this test.
#[cfg(feature = "root-admin")]
#[test]
fn the_door_answers_the_published_releases_own_bytes() {
    const GOLDEN: &str = include_str!(concat!(
        env!("BUSBAR_CORE_DIR"),
        "/../../testing/shadow-oracle/golden/1.5.5/cells/admin.ops__GetConfig__unauth.json"
    ));
    let cell: serde_json::Value = serde_json::from_str(GOLDEN).expect("the golden cell parses");
    let answer = door_answer();

    assert_eq!(
        u64::from(answer.status),
        cell["status"].as_u64().expect("the cell records a status"),
        "the door's status is the recorded one"
    );
    // Serialised out of the cell's OWN recorded body: two keys, in the order the wire has them.
    // Nothing in this comparison is a value this file chose.
    let recorded = serde_json::to_vec(&cell["body"]["json"]).expect("the recorded body serialises");
    assert_eq!(
        answer.body, recorded,
        "the door's bytes are the recorded answer's bytes"
    );
    assert_eq!(
        answer.body.len().to_string(),
        cell["headers"]["content-length"]
            .as_str()
            .expect("the cell records a content length"),
        "the length the caller is told is the length the recorded answer had"
    );
}

/// A GRANT THAT DOES NOT REACH THE ENDPOINT IS THE PREVIOUS RELEASE'S FORBIDDEN, NAMING THE
/// SCOPE.
///
/// Its message is the one refusal message this file cannot derive from the code, because it
/// states a property of the endpoint. No recorded cell holds an under-scoped call, so this is
/// pinned to the previous release's own admin error contract and the oracle cannot confirm it —
/// which is exactly why it is written down here rather than left to a reader to re-derive.
#[cfg(feature = "root-admin")]
#[test]
fn a_grant_that_does_not_reach_the_endpoint_is_answered_with_the_scope_it_needed() {
    let answer = scope_answer(&a_request());
    assert_eq!(answer.status, 403);
    assert_eq!(
        String::from_utf8(answer.body).expect("the envelope is text"),
        r#"{"error":{"code":"forbidden","message":"insufficient scope: this endpoint requires `read-only`"}}"#
    );
}

/// A DISCONNECT IS STILL AN EXIT. The release of an effect that outlives the response used to be
/// the last statement of the answering future, and a client that hangs up mid-walk drops that
/// future before the statement runs — leaving a drain asked for and owned by a unit whose exit
/// path was never coming, for the next unrelated request to release under its own response.
///
/// Driven at the guard rather than through a socket, because what is being pinned is the guard's
/// own obligation: dropped without ever reaching the write, it still releases, and it still
/// releases only what ITS unit asked for.
#[cfg(feature = "root-admin")]
#[tokio::test]
async fn a_walk_dropped_before_its_answer_still_releases_the_drain_it_asked_for() {
    busbar_core_admin::restart::drain_released_at_exit();
    let unit = a_fresh_unit();
    // The operation's body asks, from inside its own unit, exactly as the restart handler does.
    busbar_core_admin::restart::UnitDrain::of_unit(unit)
        .scoping(async {
            busbar_core_admin::restart::begin_drain();
        })
        .await;

    // The future carrying the guard is dropped before anything is written back.
    let exit = ExitPath { unit };
    drop(exit);

    assert!(
        !busbar_core_admin::restart::UnitDrain::of_unit(unit).release(),
        "the drop released the ask, so there is nothing left for a later exit to release — \
         which is the leak: without the guard this would still be standing"
    );
}

/// A body this wrap cannot read is refused, and one too big for the operator's cap is not read
/// here at all.
///
/// Both used to end in the same place: an empty body, handed to whichever mutating verb the
/// path named, which then executed whatever an empty document means to it on a request the
/// caller never finished sending. And the read was unbounded, so the cap the deployment
/// configured was applied by a layer this wrap had already buffered past.
#[cfg(feature = "root-admin")]
#[tokio::test]
async fn a_body_the_wrap_will_not_read_is_refused_rather_than_emptied() {
    use tower::ServiceExt;

    let inner = axum::Router::new().fallback(axum::routing::any(|| async { "the surface" }));
    let wrapped = mount(inner, busbar_kernel::teller::Kernel::new(), 4, |dispatch| {
        crate::root::kernel::ProductionUnits::admin_only(dispatch, open_door())
    });

    // Longer than the cap and no declared length: the read stops at the cap and the request is
    // refused, rather than becoming a document nobody sent.
    let request = axum::http::Request::builder()
        .method("POST")
        .uri("/api/v1/admin/keys")
        .body(axum::body::Body::from(b"0123456789".to_vec()))
        .expect("the request builds");
    let response = wrapped
        .clone()
        .oneshot(request)
        .await
        .expect("the router answers");
    assert_eq!(response.status(), 400);

    // A declared length past the cap is the mounted surface's own answer to give, and this wrap
    // does not buffer the body to find that out.
    let request = axum::http::Request::builder()
        .method("POST")
        .uri("/api/v1/admin/keys")
        .header(axum::http::header::CONTENT_LENGTH, "10")
        .body(axum::body::Body::from(b"0123456789".to_vec()))
        .expect("the request builds");
    let response = wrapped.oneshot(request).await.expect("the router answers");
    assert_eq!(
        response.status(),
        200,
        "the request reached the surface below, which is where the cap is enforced"
    );
}

/// A unit that reached no answer is rendered under the status its ending earned.
///
/// One 403 for every ending told an operator that a journal it could not write, a body it could
/// not read and a scope it did not hold were the same thing, and told a client that a request
/// worth retrying was one that never would be. The two authorization endings keep the answer
/// they had, and so does an ending this table does not name.
/// EVERY REFUSAL EXPLAINS ITSELF (OWNER 2026-10-27): an `amend-rate-history` body the verb cannot
/// read (the oracle's pre-1.6.0 `rate_card`/`window` body) is answered 400 `invalid_request` with
/// a message that names what the body must carry. RED: the bare `{"code":"invalid_request",
/// "message":"invalid_request"}`. Every other verb's unreadable body keeps its answer.
#[cfg(feature = "root-admin")]
#[test]
fn an_unreadable_amendment_is_told_what_the_body_must_carry() {
    let refused = Outcome::Refused(
        busbar_contract::caps::StepName::Route,
        ReasonCode::DecodeFailed,
    );
    let amend = AdminRequest {
        method: "POST".to_string(),
        path: "/api/v1/admin/ledger/amend-rate-history".to_string(),
        body: br#"{"rate_card":{},"window":{}}"#.to_vec(),
        ..a_request()
    };
    let answer = explained_answer(&amend, refused).expect("the amendment's refusal is explained");
    assert_eq!(answer.status, 400);
    assert_eq!(
        answer.body,
        br#"{"error":{"code":"invalid_request","message":"amend-rate-history: body must carry effective_from, reason, and rates and/or per_request_fee; rate_card/window is the pre-1.6.0 shape"}}"#.to_vec()
    );
    // another verb's unreadable body, and the amendment's other endings, keep their answers
    assert!(explained_answer(&a_request(), refused).is_none());
    let unavailable = Outcome::Failed(
        busbar_contract::caps::StepName::Route,
        ReasonCode::DurabilityUnavailable,
    );
    assert!(explained_answer(&amend, unavailable).is_none());
}

#[cfg(feature = "root-admin")]
#[test]
fn a_refused_units_status_is_the_one_its_ending_earned() {
    let status = |reason| {
        answer_for(Outcome::Refused(
            busbar_contract::caps::StepName::Admit,
            reason,
        ))
    };
    assert_eq!(status(ReasonCode::DecodeFailed).status, 400);
    assert_eq!(status(ReasonCode::NoDestination).status, 404);
    assert_eq!(status(ReasonCode::InFlightCap).status, 429);
    assert_eq!(status(ReasonCode::OverBudget).status, 429);
    assert_eq!(status(ReasonCode::DurabilityUnavailable).status, 503);
    assert_eq!(status(ReasonCode::ScopeDenied).status, 403);
    assert_eq!(status(ReasonCode::Unauthenticated).status, 403);
    assert_eq!(
        status(ReasonCode::PlanePanic).status,
        403,
        "an ending nobody mapped keeps the pinned answer rather than inventing one"
    );

    // A failure past the door renders the same way a refusal before it does: what the caller is
    // owed is the reason, and the side of the door it happened on is not the caller's business.
    assert_eq!(
        answer_for(Outcome::Failed(
            busbar_contract::caps::StepName::Route,
            ReasonCode::DurabilityUnavailable
        )),
        error_answer(503, "unavailable")
    );

    // And the envelope is the surface's, whatever the status.
    assert_eq!(
        status(ReasonCode::NoDestination).body,
        br#"{"error":{"code":"not_found","message":"not_found"}}"#.to_vec()
    );
    assert_eq!(
        status(ReasonCode::NoDestination).headers,
        vec![("content-type".to_string(), "application/json".to_string())]
    );
}

/// Neither audit door carries the presented credential into what it seals.
///
/// Both doors are walked, completed and refused, with a live-looking credential on the request.
/// The facts they seal are the operation class and the finish, and nothing the caller presented;
/// the administrative ring that names a principal is the kernel's one ring (item 237), written by
/// the core-admin handler, not by this step.
#[test]
fn the_audit_doors_carry_no_credential_into_the_sealed_facts() {
    for ended in [
        Outcome::Completed,
        Outcome::Refused(
            busbar_contract::caps::StepName::Approve,
            ReasonCode::ScopeDenied,
        ),
    ] {
        let mut request = a_request();
        request.method = "PUT".to_string();
        request.path = "/api/v1/admin/config/settings".to_string();
        request.credential = Some("sk-live-the-presented-secret".to_string());
        let mut walk = AdminWalk::new(request);
        let _ = decode(&mut walk);
        let _ = verify(&mut walk, &PrincipalId::new("key_operator_7"));

        let facts = audit(&walk, &ended);
        assert!(
            !format!("{facts:?}").contains("sk-live-the-presented-secret"),
            "the presented credential reached the sealed facts"
        );
    }
}

/// THE VERBS THAT USED TO WAIT ON AN OPERATOR KEY ARE PLAIN SCOPED VERBS AT THE ROUTE STEP
/// (#77(9), OWNER-LOCKED, `docs/design/BUSBAR-1.6.0.md` l.2279: "no verb carries dual control,
/// escrow or operator signatures. Each verb is a plain scoped verb authorized by the per-verb
/// allow-list on the admin token").
///
/// A binding as `AdminBinding::new` builds it — no operator key anywhere, because there is none to
/// configure — walks each of `chain_break`, `store_restore`, `commit_upgrade`, `adjust` and
/// `amend_rate_history` past authorization under a grant that
/// covers it (`full`): whatever the verb's own effect then answers over this fixture's refusing
/// store and empty bodies, it is never the scope refusal. Under a grant that does NOT cover it
/// (`read-only`) every one is refused at scope. RED before the fix: under the default unsealed
/// posture every one of them was refused `OperatorUnset`, which this step says as
/// `ScopeDenied`, whatever the grant.
#[test]
#[cfg(feature = "root-admin")]
fn the_formerly_irreducible_verbs_are_authorized_by_the_grant_alone() {
    let admin = crate::root::kernel::new_kernel().admin_token();

    let under = |path: &str, granted: VerbScope| -> Result<(), ReasonCode> {
        let binding = AdminBinding::new(Arc::new(AnsweringDispatch), open_door());
        let mut request = a_request();
        request.method = "POST".to_string();
        request.path = path.to_string();
        // `store_restore` refuses a body naming no backup before it reaches authorization, so every
        // body names one; the others read nothing from it that would change the assertion.
        request.body = b"{\"backup_ref\":\"backup-1\"}".to_vec();
        let mut walk = AdminWalk::new(request);
        decode(&mut walk).expect("the plane's table declares this operation");
        walk.granted = Some(granted);
        route(&binding, None, &admin, &mut walk)
    };

    for path in [
        "/api/v1/admin/chain-break",
        "/api/v1/admin/store-restore",
        "/api/v1/admin/commit-upgrade",
        "/api/v1/admin/adjust",
        "/api/v1/admin/ledger/amend-rate-history",
    ] {
        assert_ne!(
            under(path, VerbScope::Full),
            Err(ReasonCode::ScopeDenied),
            "{path}: a grant that covers the verb was refused with no operator key configured"
        );
        assert_eq!(
            under(path, VerbScope::ReadOnly),
            Err(ReasonCode::ScopeDenied),
            "{path}: a grant that does not cover the verb was not refused"
        );
    }
}

// ── #77(9) l.2279: the per-verb allow-list, at authenticate and approve ─────────────────────────

/// A door that answers every request with `door`: the verdict the kernel's admin door reaches for a
/// principal (`busbar_kernel::auth::admin_door`), stated rather than derived, so these cells read
/// what the root's steps do with it.
#[cfg(feature = "root-admin")]
fn a_door_answering(door: busbar_kernel::auth::AdminDoor) -> AdminDoorFn {
    Arc::new(move |_: &AdminRequest| door.clone())
}

/// The verdict for a principal holding `named` verbs BY NAME and no rung whole: its matrix reaches
/// every rung a named verb needs (`needs`), as the kernel's door computes it.
#[cfg(feature = "root-admin")]
fn listed_door(named: &[&str], needs: Scope) -> busbar_kernel::auth::AdminDoor {
    busbar_kernel::auth::AdminDoor::Listed(
        busbar_contract::auth::Principal::from_id("acct:verb-listed"),
        busbar_contract::authz::Grants::of(needs),
        busbar_kernel::auth::VerbAllowList {
            rungs: busbar_contract::authz::Grants::default(),
            named: named.iter().map(|verb| verb.to_string()).collect(),
        },
    )
}

/// Walk `method path` through decode, authenticate and approve under `door`: the two steps the
/// allow-list lives in. `Ok` = approve admitted it; `Err` = the reason a step refused it.
#[cfg(feature = "root-admin")]
fn approved_under(
    door: busbar_kernel::auth::AdminDoor,
    method: &str,
    path: &str,
) -> Result<(), ReasonCode> {
    let binding = AdminBinding::new(Arc::new(AnsweringDispatch), a_door_answering(door));
    let mut request = a_request();
    request.method = method.to_string();
    request.path = path.to_string();
    let mut walk = AdminWalk::new(request);
    decode(&mut walk).expect("the plane's table declares this operation");
    let bindings = crate::root::auth_bindings::AuthBindings::without_directory();
    authenticate(&binding, &bindings, &mut walk)?;
    approve(&walk)
}

/// One request through the WHOLE loop under `door`, answered as the listener answers it.
#[cfg(feature = "root-admin")]
fn answered_under(door: busbar_kernel::auth::AdminDoor, request: AdminRequest) -> AdminAnswer {
    let units = crate::root::kernel::ProductionUnits::admin_only(
        Arc::new(AnsweringDispatch),
        a_door_answering(door),
    );
    AdminNode::new(crate::root::kernel::new_kernel(), units).answer(request)
}

/// RED 1 — A VERB THE ALLOW-LIST NAMES IS ADMITTED: a mutation and a read, each held by name, pass
/// approve, and the named read is answered by its operation through the whole loop. RED before the
/// allow-list: the door had no `Listed` verdict and authenticate no list to record, so nothing
/// could be held by name — a principal with no `admin_scope` earned no grant and was refused.
#[cfg(feature = "root-admin")]
#[test]
fn a_verb_the_allow_list_names_is_admitted() {
    let door = || listed_door(&["post_keys", "get_audit"], Scope::Full);
    assert_eq!(
        approved_under(door(), "POST", "/api/v1/admin/keys"),
        Ok(()),
        "a mutation the list names is admitted"
    );
    assert_eq!(
        approved_under(door(), "GET", "/api/v1/admin/audit?limit=4"),
        Ok(()),
        "a read the list names is admitted"
    );
    assert_eq!(
        answered_under(door(), a_request()).status,
        200,
        "and the named read reaches its operation"
    );
}

/// RED 2 — A VERB THE ALLOW-LIST DOES NOT NAME IS REFUSED, with the existing scope refusal: the
/// 403 a missing rung gets, byte for byte (`scope_answer`), whether the verb is a read or a
/// mutation — even though the principal's matrix reaches the rung, because a named list is not a
/// rung. RED before the allow-list: approve compared the rung alone, so a `full` matrix admitted
/// every verb.
#[cfg(feature = "root-admin")]
#[test]
fn a_verb_the_allow_list_does_not_name_is_refused_with_the_scope_answer() {
    let door = || listed_door(&["post_keys"], Scope::Full);
    assert_eq!(
        approved_under(door(), "POST", "/api/v1/admin/hooks"),
        Err(ReasonCode::ScopeDenied),
        "a mutation the list does not name is refused at approve"
    );
    assert_eq!(
        approved_under(door(), "GET", "/api/v1/admin/audit?limit=4"),
        Err(ReasonCode::ScopeDenied),
        "a read the list does not name is refused at approve"
    );
    let read = a_request();
    let refused = answered_under(door(), read.clone());
    assert_eq!(refused, scope_answer(&read), "the existing scope refusal");
    assert_eq!(refused.status, 403);
    assert_eq!(
        String::from_utf8(refused.body).expect("the envelope is text"),
        "{\"error\":{\"code\":\"forbidden\",\"message\":\"insufficient scope: this endpoint \
         requires `read-only`\"}}"
    );
    let mut mutation = a_request();
    mutation.method = "POST".to_string();
    mutation.path = "/api/v1/admin/hooks".to_string();
    assert_eq!(
        answered_under(door(), mutation.clone()),
        scope_answer(&mutation),
        "a mutation the list does not name is answered with the scope it needed"
    );
}

/// RED 3 — `verbs: "*"` BEHAVES EXACTLY AS `full`. The kernel's door turns a `"*"` binding into the
/// very verdict an `admin_scope: full` binding earns (`verbs_star_is_exactly_admin_scope_full`,
/// busbar-kernel); here a list that holds the full rung WHOLE — the shape `"*"` beside named verbs
/// takes — admits a mutation and a read exactly as that verdict does, verb for verb.
#[cfg(feature = "root-admin")]
#[test]
fn a_rung_held_whole_beside_a_list_admits_exactly_as_full() {
    let full = || {
        busbar_kernel::auth::AdminDoor::Identified(
            busbar_contract::auth::Principal::from_id("acct:verb-listed"),
            busbar_contract::authz::Grants::of(Scope::Full),
        )
    };
    let whole = || {
        busbar_kernel::auth::AdminDoor::Listed(
            busbar_contract::auth::Principal::from_id("acct:verb-listed"),
            busbar_contract::authz::Grants::of(Scope::Full),
            busbar_kernel::auth::VerbAllowList {
                rungs: busbar_contract::authz::Grants::of(Scope::Full),
                named: ["get_audit".to_string()].into_iter().collect(),
            },
        )
    };
    for (method, path) in [
        ("POST", "/api/v1/admin/hooks"),
        ("POST", "/api/v1/admin/keys"),
        ("GET", "/api/v1/admin/audit?limit=4"),
    ] {
        assert_eq!(
            approved_under(full(), method, path),
            Ok(()),
            "{method} {path}"
        );
        assert_eq!(
            approved_under(whole(), method, path),
            approved_under(full(), method, path),
            "{method} {path}: a full rung held whole admits exactly as `full` does"
        );
    }
}

/// RED 4 — A TOKEN WITH NO `verbs` KEY BEHAVES EXACTLY AS TODAY. The door's `Identified` verdict
/// (what every binding without `verbs` earns) is decided by its rung alone: `read-only` reaches a
/// read and is refused a mutation with the scope answer, `full` reaches both. A no-regression pin:
/// it holds on the code before the allow-list too, by design.
#[cfg(feature = "root-admin")]
#[test]
fn a_grant_with_no_verbs_key_is_decided_by_its_rung_as_before() {
    let rung = |scope: Scope| {
        busbar_kernel::auth::AdminDoor::Identified(
            busbar_contract::auth::Principal::from_id("acct:verb-listed"),
            busbar_contract::authz::Grants::of(scope),
        )
    };
    let read = "/api/v1/admin/audit?limit=4";
    let mutation = "/api/v1/admin/hooks";
    assert_eq!(approved_under(rung(Scope::ReadOnly), "GET", read), Ok(()));
    assert_eq!(
        approved_under(rung(Scope::ReadOnly), "POST", mutation),
        Err(ReasonCode::ScopeDenied)
    );
    assert_eq!(approved_under(rung(Scope::Full), "GET", read), Ok(()));
    assert_eq!(approved_under(rung(Scope::Full), "POST", mutation), Ok(()));
    let mut refused = a_request();
    refused.method = "POST".to_string();
    refused.path = mutation.to_string();
    assert_eq!(
        answered_under(rung(Scope::ReadOnly), refused.clone()),
        scope_answer(&refused)
    );
}

/// Both tables were extracted from the same pinned tag. Every row the plane decodes to has to
/// name a verb the executing unit knows, or the root would be binding an operation to nothing.
#[test]
fn every_row_the_plane_decodes_names_a_verb_the_unit_knows() {
    let mut unmatched = Vec::new();
    for row in busbar_core_admin::admin_codec::verbs::table() {
        if kernel_verb(&row).is_none() {
            unmatched.push(row.verb);
        }
    }
    assert!(
        unmatched.is_empty(),
        "rows with no kernel verb: {unmatched:?}"
    );
}

/// The 66 join on method and path — the columns the pinned document fixed — and all 66 of them
/// do. A row that fell through to the name join would be a legacy operation matched on a casing
/// convention rather than on what the tag actually pinned.
#[test]
fn all_sixty_six_legacy_rows_join_on_the_pinned_method_and_path() {
    let joined = busbar_core_admin::admin_codec::verbs::table()
        .iter()
        .filter(|row| {
            LEGACY_VERBS
                .iter()
                .any(|legacy| legacy.method == row.method && legacy.path == row.template)
        })
        .count();
    assert_eq!(joined, 66);
}

/// The two spellings of one operation's name really are two spellings, and the join does not
/// depend on either of them. This is the finding that made the join what it is, kept as a test
/// so that a future crate quietly agreeing on one casing does not look like a fix.
#[test]
fn the_two_tables_spell_one_operations_name_two_ways() {
    let audit = busbar_core_admin::admin_codec::verbs::resolve("GET", "/api/v1/admin/audit")
        .expect("audit is in the plane's table");
    let row = LEGACY_VERBS
        .iter()
        .find(|row| row.method == "GET" && row.path == "/api/v1/admin/audit")
        .expect("audit is in the unit's table");
    assert_eq!(audit.verb, "get_audit");
    assert_eq!(row.verb, KernelVerb::GetAudit);
    assert_eq!(kernel_verb(&audit), Some(KernelVerb::GetAudit));
}

/// The rate class comes off the shipped table, not off the blast-radius-blind default: a config
/// mutation is limited at the config budget and an ordinary read is forbidden from mutating at
/// all.
#[test]
fn the_rate_class_is_the_shipped_table_and_not_the_default() {
    assert_eq!(
        mutation_class(KernelVerb::PostConfigApply),
        MutationClass::Config
    );
    assert_eq!(
        mutation_class(KernelVerb::PostConfigReload),
        MutationClass::Config
    );
    assert_eq!(
        mutation_class(KernelVerb::PostRestart),
        MutationClass::Config
    );
    assert_eq!(
        mutation_class(KernelVerb::PutAdminAuth),
        MutationClass::Config
    );
    assert_eq!(mutation_class(KernelVerb::PostKeys), MutationClass::Crud);
    assert_eq!(
        mutation_class(KernelVerb::PostPluginsInspect),
        MutationClass::PluginInspect
    );
    // `Forbidden` names a verb the MUTATION budget does not apply to — every read is one. It is
    // not a refusal, and an admit step that read it as one turned every read on the surface into
    // a 403. That is the hazard a vocabulary shared between two crates invites, so the reading
    // is pinned here rather than left to the name.
    assert_eq!(
        mutation_class(KernelVerb::GetAudit),
        MutationClass::Forbidden
    );
    assert_eq!(MutationClass::Forbidden.limit(), 0);
    assert!(
        busbar_kernel::admin::scope::admin_required_scope("GET", "/api/v1/admin/audit")
            == Scope::ReadOnly
    );
}

/// The two spellings of the two-rung split are one split. If they ever stopped agreeing, a
/// read-only credential would be admitted to a mutation or a full one refused a read.
#[test]
fn the_two_spellings_of_the_scope_split_agree() {
    assert_eq!(scope_as_verb_scope(Scope::ReadOnly), VerbScope::ReadOnly);
    assert_eq!(scope_as_verb_scope(Scope::Full), VerbScope::Full);
    assert!(VerbScope::Full.allows(VerbScope::ReadOnly));
    assert!(!VerbScope::ReadOnly.allows(VerbScope::Full));
}

/// Route is the one place that chooses between the unit's general execution path and its two
/// dedicated minting methods, and the choice is exactly the two credential-minting verbs. Every
/// other verb on the keys surface — reading them, revoking one, listing a key's usage — goes
/// through the general path, because none of them mints an identity.
#[test]
fn only_the_two_minting_verbs_are_reached_through_the_seam_directly() {
    assert!(mints_its_own_identity(KernelVerb::PostKeys));
    assert!(mints_its_own_identity(KernelVerb::PostKeysIdRotate));
    for verb in [
        KernelVerb::GetKeys,
        KernelVerb::GetKeysId,
        KernelVerb::PatchKeysId,
        KernelVerb::DeleteKeysId,
        KernelVerb::PostKeysIdRevoke,
        KernelVerb::GetKeysIdUsage,
        KernelVerb::PostSigningKeyRotate,
        KernelVerb::GetAudit,
    ] {
        assert!(
            !mints_its_own_identity(verb),
            "{verb:?} mints nothing and belongs on the general path"
        );
    }
}

/// A replayed idempotency key answers with the FIRST answer — status, headers and body, byte for
/// byte — through the claim the configured store keeps (`durable::claim`). Byte-identical is the
/// property: a re-render would mint a second one-time secret over one identity. Asked of the same
/// process, of a restarted one and of another node over the same store, the answer is the first
/// one and the effect that minted it ran once.
#[test]
fn a_replayed_idempotency_key_answers_the_first_answers_bytes() {
    let store: Arc<dyn busbar_contract::records::RecordStore> =
        Arc::new(busbar_kernel::governance::MemoryStore::new());
    let held = Arc::clone(&store);
    let replay_store: bound::ReplayStore = Arc::new(move || Some(Arc::clone(&held)));
    let request = AdminRequest {
        method: "POST".to_string(),
        path: "/api/v1/admin/commit-upgrade".to_string(),
        credential: None,
        headers: vec![("idempotency-key".to_string(), "idem-1".to_string())],
        body: br#"{"version":"once"}"#.to_vec(),
        at: 1_700_000_000,
        unit: a_fresh_unit(),
    };
    let minted = std::sync::atomic::AtomicUsize::new(0);
    // Every run mints a fresh one-time secret, so a second run is told apart from a replay.
    let mint = || {
        let n = minted.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        Ok(AdminAnswer {
            status: 201,
            headers: vec![
                ("content-type".to_string(), "application/json".to_string()),
                ("location".to_string(), format!("/api/v1/admin/keys/vk_{n}")),
            ],
            body: format!(r#"{{"id":"vk_{n}","secret":"once-{n}"}}"#).into_bytes(),
        })
    };
    let first_answer = AdminAnswer {
        status: 201,
        headers: vec![
            ("content-type".to_string(), "application/json".to_string()),
            (
                "location".to_string(),
                "/api/v1/admin/keys/vk_0".to_string(),
            ),
        ],
        body: br#"{"id":"vk_0","secret":"once-0"}"#.to_vec(),
    };
    let node = bound::ReplayCache::new();
    let ask = |cache: &bound::ReplayCache| {
        bound::replayable(
            cache,
            Some(&replay_store),
            KernelVerb::CommitUpgrade,
            "operator",
            &request,
            &request.body,
            mint,
        )
        .expect("the write answers")
    };

    let first = ask(&node);
    assert_eq!(first, first_answer, "the first call runs and answers");
    let again = ask(&node);
    let restarted = ask(&bound::ReplayCache::new());
    let sibling = ask(&bound::ReplayCache::new());
    for (who, replayed) in [
        ("the same node", &again),
        ("a restarted node", &restarted),
        ("another node", &sibling),
    ] {
        assert_eq!(replayed.status, first.status, "{who}: the first status");
        assert_eq!(replayed.headers, first.headers, "{who}: the first headers");
        assert_eq!(replayed.body, first.body, "{who}: the first body's bytes");
    }
    assert_eq!(
        minted.load(std::sync::atomic::Ordering::SeqCst),
        1,
        "the one-time secret was minted once"
    );
}

/// The dispatch a test drives the loop against: it answers, and its answer is recognisable, so a
/// step that refused before Route is told apart from one that reached it.
#[cfg(feature = "root-admin")]
struct AnsweringDispatch;

#[cfg(feature = "root-admin")]
impl AdminDispatch for AnsweringDispatch {
    fn execute(&self, _verb: KernelVerb, _request: &AdminRequest) -> AdminAnswer {
        AdminAnswer {
            status: 200,
            headers: vec![("content-type".to_string(), "application/json".to_string())],
            body: br#"{"entries":[]}"#.to_vec(),
        }
    }
}

/// A directory whose whole opinion is the denylist.
#[cfg(feature = "root-admin")]
struct Denylist(bool);

#[cfg(feature = "root-admin")]
impl crate::root::auth_bindings::VirtualKeyDirectory for Denylist {
    fn verify(
        &self,
        credential: &str,
        _now: u64,
        _expected_aud: Option<&str>,
    ) -> Option<crate::root::auth_bindings::KeyFacts> {
        // A revocation withdraws an IDENTIFICATION: the directory has to know the credential
        // before its denylist can take it away, or the refusal would be a probe answered for
        // a string nothing verified. So the one credential these cells present is one this
        // directory minted.
        (credential == "admin-token").then(|| crate::root::auth_bindings::KeyFacts {
            id: "key-admin-1".to_string(),
            name: "the operator credential these cells present".to_string(),
        })
    }

    fn revoked(&self, _credential: &str) -> bool {
        self.0
    }
}

/// A door that IDENTIFIES the operator credential these cells present, so that a revocation has
/// an identification to withdraw. Revocation is a statement about a credential the chain
/// resolved to somebody; on an open door nothing is resolved, and a denylist consulted there
/// would be a probe answered for a string nothing verified.
#[cfg(feature = "root-admin")]
struct IdentifiesOperator;

#[cfg(feature = "root-admin")]
impl busbar_kernel_identity::module::AuthModule for IdentifiesOperator {
    fn name(&self) -> &'static str {
        "identifies-operator"
    }
    fn authenticate(&self, candidate: Option<&str>) -> busbar_kernel_identity::module::AuthOutcome {
        match candidate {
            Some("admin-token") => busbar_kernel_identity::module::AuthOutcome::Identify(
                busbar_kernel_identity::principal::Principal::from_id(
                    crate::root::auth_bindings::ADMIN_PRINCIPAL_ID,
                ),
            ),
            _ => busbar_kernel_identity::module::AuthOutcome::Pass,
        }
    }
}

#[cfg(feature = "root-admin")]
fn a_door_that_identifies_the_operator() -> busbar_kernel_identity::AuthChain {
    busbar_kernel_identity::AuthChain::new(
        vec![busbar_kernel_identity::chain::ChainEntry {
            provider: "identifies-operator".to_string(),
            module: Box::new(IdentifiesOperator),
        }],
        false,
    )
}

/// Walk one request through the whole loop against a node whose door identifies the operator
/// credential and whose directory then revokes everything, or nothing.
#[cfg(feature = "root-admin")]
fn answer_under_denylist(revoked: bool) -> AdminAnswer {
    let units = crate::root::kernel::ProductionUnits::admin_only(
        Arc::new(AnsweringDispatch),
        door_of_chain(a_door_that_identifies_the_operator()),
    )
    .with_auth_bindings(crate::root::auth_bindings::AuthBindings::new(Arc::new(
        Denylist(revoked),
    )));
    AdminNode::new(crate::root::kernel::new_kernel(), units).answer(a_request())
}

/// A revoked credential is refused on the root leg, and refused BEFORE the operation runs.
///
/// This is the seam the step was handed three absences for: revocation gates a new unit's
/// identification, an admin unit is always a new unit, and a set nothing supplies revokes
/// nothing — so an unbound step would have let a revoked credential through the front door of
/// the administrative surface. The door here identifies the operator credential, so the
/// revocation has an identification to withdraw; the control is the same request over a
/// directory that revokes nobody, which reaches the operation and comes back with its answer.
/// The refusal is the DOOR'S answer: a refusal at the authenticate step is written with the
/// door's own bytes, not re-run through the surface to get them.
#[cfg(feature = "root-admin")]
#[test]
fn a_revoked_credential_is_refused_before_the_operation_runs() {
    assert_eq!(
        answer_under_denylist(false).status,
        200,
        "a credential on nobody's denylist reaches the operation"
    );
    let refused = answer_under_denylist(true);
    assert_eq!(
        refused,
        door_answer(),
        "a credential the node took away is the door's answer, written and not re-run"
    );
}

/// On an OPEN door a denylist withdraws nothing, because nothing was identified: a string on
/// the list is admitted anonymously exactly as any other string is. A refusal there would tell
/// an unauthenticated caller whether the string they presented was ever a credential.
#[cfg(feature = "root-admin")]
#[test]
fn an_open_door_does_not_consult_the_denylist_for_a_string_it_never_identified() {
    let units =
        crate::root::kernel::ProductionUnits::admin_only(Arc::new(AnsweringDispatch), open_door())
            .with_auth_bindings(crate::root::auth_bindings::AuthBindings::new(Arc::new(
                Denylist(true),
            )));
    let answer = AdminNode::new(crate::root::kernel::new_kernel(), units).answer(a_request());
    assert_eq!(
        answer.status, 200,
        "the open door admits, and the denylist is not a probe"
    );
}

/// A door that identifies SOMEBODY, and it is not the operator.
///
/// The sibling of `IdentifiesOperator`, and the only way this plane reaches its 403: the grant an
/// admin unit carries is the operator principal's or none at all, so a caller the chain resolves to
/// any other identity is authenticated and then has nothing to compare the endpoint's matrix row
/// against. That is the authorization ending, and it is a different answer from the door's.
#[cfg(feature = "root-admin")]
struct IdentifiesSomebodyElse;

#[cfg(feature = "root-admin")]
impl busbar_kernel_identity::module::AuthModule for IdentifiesSomebodyElse {
    fn name(&self) -> &'static str {
        "identifies-somebody-else"
    }
    fn authenticate(&self, candidate: Option<&str>) -> busbar_kernel_identity::module::AuthOutcome {
        match candidate {
            Some("a-tenants-token") => busbar_kernel_identity::module::AuthOutcome::Identify(
                busbar_kernel_identity::principal::Principal::from_id("acct:not-the-operator"),
            ),
            _ => busbar_kernel_identity::module::AuthOutcome::Pass,
        }
    }
}

/// Walk one request through the whole loop against a node whose door is CLOSED — one module,
/// identifying exactly one string — presenting `credential` and nothing else.
///
/// Closed is the property that makes the negative arms mean anything: a chain naming a module is
/// not the open front door, so a candidate no arm identifies ends `Denied` rather than admitted
/// anonymously. The denylist revokes nobody here, so every refusal below is about the credential
/// the caller presented and not about a credential the node withdrew.
#[cfg(feature = "root-admin")]
fn answer_at_the_closed_door(
    door: busbar_kernel_identity::AuthChain,
    credential: Option<&str>,
) -> AdminAnswer {
    let units = crate::root::kernel::ProductionUnits::admin_only(
        Arc::new(AnsweringDispatch),
        door_of_chain(door),
    )
    .with_auth_bindings(crate::root::auth_bindings::AuthBindings::new(Arc::new(
        Denylist(false),
    )));
    let mut request = a_request();
    request.credential = credential.map(str::to_string);
    AdminNode::new(crate::root::kernel::new_kernel(), units).answer(request)
}

/// THE DOOR IS TWO-SIDED: A CALLER WHO PRESENTS THE WRONG STRING, OR NONE, IS REFUSED.
///
/// Every other credential-negative cell in this file is the REVOCATION path — a credential the door
/// identified and the node then took away — and each one presents the operator's own string. None
/// of them asks the prior question, which is whether the authenticate step reads what the CALLER
/// presented at all. A step that stopped reading the request's credential and handed the chain a
/// fixed operator string would satisfy every revocation cell in this file while authenticating any
/// caller as the operator, including one who presented nothing.
///
/// Three arms over the same closed door and the same whole loop, so the refusals are known to be
/// about the credential rather than about a fixture that refuses everything:
///
/// - the operator's own string reaches the operation and comes back with its 200 — the control;
/// - a string the chain will not identify is the door's answer;
/// - NO credential at all is the same door's answer, which is the arm a step that ignores the
///   request cannot produce.
#[cfg(feature = "root-admin")]
#[test]
fn a_wrong_or_absent_credential_is_refused_at_the_door() {
    assert_eq!(
        answer_at_the_closed_door(a_door_that_identifies_the_operator(), Some("admin-token"))
            .status,
        200,
        "the control must actually be admitted, or the refusals below prove only that the fixture \
         refuses everything"
    );

    let wrong = answer_at_the_closed_door(
        a_door_that_identifies_the_operator(),
        Some("not-the-admin-token"),
    );
    assert_eq!(
        wrong,
        door_answer(),
        "a credential no arm of the chain identifies must be the door's answer"
    );
    assert_eq!(wrong.status, 401, "and that answer's status is the door's");

    let absent = answer_at_the_closed_door(a_door_that_identifies_the_operator(), None);
    assert_eq!(
        absent,
        door_answer(),
        "a caller who presented NO credential must be the door's answer — this is the arm a step \
         that never reads `request.credential` cannot produce"
    );
    assert_eq!(absent.status, 401, "and that answer's status is the door's");
}

/// THE REFUSED CALLER'S ENVELOPE, BYTE FOR BYTE, OFF THE LOOP.
///
/// The first test in this file pins `door_answer()`'s bytes to the published release's own
/// recording; this one pins what a REFUSED WALK hands back, so the two are joined end to end. The
/// literal is restated here deliberately: it is the second, independent pin, and a change to the
/// frozen envelope has to move both this line and the golden recording rather than either alone.
#[cfg(feature = "root-admin")]
#[test]
fn the_refusal_the_loop_hands_back_is_the_frozen_envelope_byte_for_byte() {
    let absent = answer_at_the_closed_door(a_door_that_identifies_the_operator(), None);
    assert_eq!(absent.status, 401);
    assert_eq!(
        String::from_utf8(absent.body).expect("the envelope is text"),
        r#"{"error":{"code":"unauthorized","message":"missing or invalid admin credential (Bearer or x-admin-token)"}}"#
    );
    assert_eq!(
        absent.headers,
        vec![("content-type".to_string(), "application/json".to_string())],
        "the refused caller is told the envelope is JSON, and told nothing else"
    );
}

/// AN IDENTIFIED CALLER WHO IS NOT THE OPERATOR IS ANSWERED WITH THE SCOPE, NOT WITH THE DOOR.
///
/// The other half of the gate, and the half that proves the two endings are distinguished: this
/// caller PASSES authenticate — the chain resolved a real identity for the string it presented —
/// and is refused at approve, because the grant an admin unit carries belongs to the operator
/// principal and this is not it. The status and the envelope are the authorization ending's, so a
/// loop that had collapsed the two refusals into one would fail here rather than answer 403.
#[cfg(feature = "root-admin")]
#[test]
fn a_caller_the_door_identifies_as_somebody_else_is_answered_with_the_scope_it_needed() {
    let door = busbar_kernel_identity::AuthChain::new(
        vec![busbar_kernel_identity::chain::ChainEntry {
            provider: "identifies-somebody-else".to_string(),
            module: Box::new(IdentifiesSomebodyElse),
        }],
        false,
    );
    let refused = answer_at_the_closed_door(door, Some("a-tenants-token"));
    assert_eq!(
        refused.status, 403,
        "an identified caller with no grant is the authorization ending, not the door's"
    );
    assert_ne!(
        refused,
        door_answer(),
        "and it is not the door's answer: the two endings must stay distinguishable"
    );
    assert_eq!(
        String::from_utf8(refused.body).expect("the envelope is text"),
        r#"{"error":{"code":"forbidden","message":"insufficient scope: this endpoint requires `read-only`"}}"#
    );
}

/// One admin request with the decode step run, so the verb is resolved exactly as the steps resolve
/// it: a cell drives the real steps rather than a walk it filled in by hand.
#[cfg(feature = "root-admin")]
fn a_bound_unit(request: AdminRequest) -> AdminWalk {
    let mut walk = AdminWalk::new(request);
    // Decode is what resolves the verb. A cell that set it itself would be asserting over a verb
    // the steps never resolved.
    let _ = decode(&mut walk);
    walk
}

/// The administrative listener answers on a table with no room in it at all, and the data
/// listener does not.
///
/// THE arrival STEP, over the loop. This plane's Arrival has one decision of its own and this
/// is it: units on the administrative listener are EXEMPT from `in_flight_cap`, for the
/// reason the exemption exists — the surface an operator reaches to find out why the node is
/// shedding has to answer while it is shedding. This node's table makes that the only thing
/// keeping it alive: its cap is ZERO, so every unit under the cap is refused and every unit that
/// answers did so because the exemption carried it.
///
/// Two answers, at one moment:
///
/// - a unit that did NOT arrive on the administrative listener is refused by a table with no room,
///   `InFlightCap`, stamped at `Arrival` because the origin is a client, with its arrival hold
///   handed back reserving nothing — the shedding the operator came to ask about;
/// - a real admin request comes back with the operation's own 200 rather than the node's
///   `unavailable`: an admin unit takes no slot in any in-flight table, so no cap can shed it. (It
///   is not asserted that the full table stayed empty: the node never touches that table, so the
///   assertion could not fail; the 200 is what says the cap did not shed it.)
#[cfg(feature = "root-admin")]
#[test]
fn the_admin_listener_is_exempt_from_the_cap_the_data_listener_is_refused_at() {
    use busbar_contract::caps::{OriginKind, StepName};
    use busbar_kernel::inflight::{arrival_hold, cap_refusal_step, Enter, InFlight};

    let units =
        crate::root::kernel::ProductionUnits::admin_only(Arc::new(AnsweringDispatch), open_door());
    let node = AdminNode::new(crate::root::kernel::new_kernel(), units);
    let full = InFlight::new(0);
    assert_eq!(full.cap(), 0, "a table with no room");

    // REFUSED: that table, asked for a unit that is under the cap.
    let entering = Enter {
        key: UnitKey::new(9_000),
        origin: OriginKind::Client,
        session: None,
        admin_listener: false,
        zero_hold_tick: false,
        now: 0,
        arrival: arrival_hold(
            &node.kernel,
            &node.units.arrival_door,
            PrincipalId::new("caller"),
            node.kernel.next_call(),
        ),
    };
    let Err(refused) = full.insert(entering) else {
        panic!("a table with no room admits nothing that is under the cap");
    };
    assert_eq!(refused.reason, ReasonCode::InFlightCap);
    assert_eq!(refused.step, StepName::Arrival);
    assert_eq!(refused.step, cap_refusal_step(OriginKind::Client));
    let handed_back = refused.hold;
    assert_eq!(
        handed_back.principal(),
        &PrincipalId::new("caller"),
        "the refused unit's hold comes back to its caller, untouched"
    );

    // ANSWERED: an ordinary administrative request, at the same moment.
    let answer = node.answer(a_request());
    assert_eq!(
        answer.status, 200,
        "the admin listener answers while shedding"
    );
    assert_ne!(answer, unavailable_answer());
    assert_ne!(
        answer,
        answer_for(Outcome::Refused(StepName::Arrival, ReasonCode::InFlightCap)),
        "the answer is the request's own, not the gate's refusal"
    );
}

/// Where an admin unit may go, and what that costs it.
///
/// THE verify STEP, over the loop. The gating contract is that a destination the caller cannot
/// reach is refused before Admit draws a bucket, and this plane answers it in a shape worth
/// pinning precisely BECAUSE the admin principal is exempt and full: there is no scope to cap,
/// so the only destination question left is whether the verb resolved at all — and the step
/// still refuses, with `NoDestination`, for a path the table never named.
///
/// The other half is the one the money path reads. A resolved verb proceeds with an EMPTY
/// verified set, and that emptiness is not an oversight: a sealed destination carries a LANE,
/// the priced axis a charge sits on, and a kernel verb is not dialled and not billed. So the
/// empty set IS the fact that makes the admin unit draw no request slot and post no fee,
/// whatever the deployment configured the fee to be. A verify that returned one destination
/// would put an admin request on the priced axis, and nothing downstream would object.
#[cfg(feature = "root-admin")]
#[test]
fn a_verb_the_table_never_named_has_nowhere_to_go_and_a_resolved_one_has_nowhere_priced() {
    let principal = PrincipalId::new("admin");

    // A path no row names: the unit has nowhere to go at all, and is refused here.
    let mut unknown = a_request();
    unknown.path = "/api/v1/admin/not-a-real-operation".to_string();
    let mut walk = a_bound_unit(unknown);
    assert!(
        walk.verb.is_none(),
        "the fixture must be a path the table never resolved"
    );
    assert_eq!(
        verify(&mut walk, &principal),
        Err(ReasonCode::NoDestination),
        "a verb that resolved to nothing has nowhere to go"
    );

    // A real operation: it proceeds, and it proceeds to nowhere PRICED — the step seals no
    // destination at all.
    let mut walk = a_bound_unit(a_request());
    assert!(
        walk.verb.is_some(),
        "the fixture must be a path the table did resolve"
    );
    assert_eq!(
        verify(&mut walk, &principal),
        Ok(()),
        "a resolved verb has somewhere to go"
    );
}

/// The audit step seals the resolved operation class and its finish, and keeps no ring of its own.
///
/// Item 237: there is ONE administrative audit ring, the kernel's durable one, written by the
/// core-admin handler as a mutation applies (the end-to-end cell in
/// `admin_path_without_plane_face.rs` reads it back over the served `/audit`); a root-only verb's
/// row is written onto that same ring by this step, and is asserted there too. The step used to
/// append a second copy onto a RAM-only root ring; it now holds no ring at all, so what is left to
/// assert here is what it still decides — the facts the audit unit seals:
///
/// - a mutating verb completes under its own write class and a complete finish;
/// - a READ completes under its read class;
/// - a refused mutation, attributed or not, seals an error finish under its write class.
#[cfg(feature = "root-admin")]
#[test]
fn the_audit_doors_seal_the_resolved_class_and_append_to_no_ring() {
    let mut mutating = a_request();
    mutating.method = "POST".to_string();
    mutating.path = "/api/v1/admin/plane-record-write".to_string();
    let mut walk = a_bound_unit(mutating.clone());
    let resolved = walk
        .verb
        .expect("the plane-record write is a row the table names");
    assert!(!resolved.read_only, "the fixture must be a mutation");
    walk.principal = Some(PrincipalId::new(AN_IDENTIFIED_OPERATOR));
    let facts = audit(&walk, &Outcome::Completed);
    assert_eq!(facts.op_class, resolved.op_class());
    assert_eq!(facts.finish, busbar_contract::FinishClass::Complete);

    // A read.
    let walk = a_bound_unit(a_request());
    let read = walk
        .verb
        .expect("the audit listing is a row the table names");
    assert!(read.read_only, "the fixture must be a read");
    let facts = audit(&walk, &Outcome::Completed);
    assert_eq!(facts.op_class, read.op_class());
    assert_ne!(
        facts.op_class,
        resolved.op_class(),
        "a read and a write seal under two classes"
    );

    // A refused mutation, by somebody the node identified and by nobody.
    for identified in [true, false] {
        let mut walk = a_bound_unit(mutating.clone());
        if identified {
            walk.principal = Some(PrincipalId::new(AN_IDENTIFIED_OPERATOR));
        }
        let facts = audit(
            &walk,
            &Outcome::Refused(
                busbar_contract::caps::StepName::Admit,
                ReasonCode::OverBudget,
            ),
        );
        assert_eq!(facts.op_class, resolved.op_class());
        assert_eq!(facts.finish, busbar_contract::FinishClass::Error);
    }
}

/// The rows the kernel's one administrative ring holds for `principal`, newest first.
///
/// The ring is process-wide, so a cell that counts on it counts only rows attributed to an
/// identity no other cell in this binary uses.
#[cfg(feature = "root-admin")]
fn the_one_rings_rows_by(principal: &str) -> Vec<busbar_kernel::audit_ring::AuditEntry> {
    busbar_kernel::audit::auditlog::AUDIT_LOG
        .list_filtered(0, usize::MAX, None, None)
        .into_iter()
        .filter(|entry| entry.principal == principal)
        .collect()
}

/// ONE ADMIN UNIT SEALS EXACTLY ONE ENTRY, AND A READ SEALS NONE — THE audit STEP, OVER THE LOOP.
///
/// The rig column reads the fresh four-op chain from the outside; this reads the ONE ring (item
/// 237) from the step that writes it, which is where "exactly one" is decided for every verb the
/// core-admin handler does not write itself. Four answers, each a different way the step could be
/// wrong:
///
/// - a root-only mutating verb that applied appends exactly ONE entry, under the operation's own
///   name and `applied`, attributed to the identity Verify resolved — not zero, not one per step;
/// - a READ appends none: the chain records what changed, and a listing changed nothing;
/// - a 1.5.5 mutating verb appends none AT THIS STEP, because its one row is the core-admin
///   handler's (`admin_path_without_plane_face.rs` reads that one row back over the served
///   `/audit`) and a second here is the doubled row item 237 deleted;
/// - a unit refused before Admit, by somebody the node identified, still appends one under
///   `rejected` — a chain that recorded only successes is the one an attacker wants.
///
/// Each appended entry is checked against the entry the ring holds directly before it, so the
/// entries are linked rather than merely counted.
#[cfg(feature = "root-admin")]
#[test]
fn one_admin_unit_seals_exactly_one_entry_on_the_one_ring_and_a_read_seals_none() {
    const WHO: &str = "operator-cifollow-one-entry";
    // The admin audit seam's `audit` stream, registered once for the process the way the kernel's
    // test harness registers it, so the rows this test seals reach the seam's read model.
    let _ = busbar_kernel::test_support::TestApp::new().build();
    let linked = |entry: &busbar_kernel::audit_ring::AuditEntry| {
        let ring =
            busbar_kernel::audit::auditlog::AUDIT_LOG.list_filtered(0, usize::MAX, None, None);
        let at = ring
            .iter()
            .position(|e| e.seq == entry.seq)
            .expect("the entry just sealed is on the ring");
        assert!(!entry.hash.is_empty(), "the entry carries its digest");
        if let Some(before) = ring.get(at + 1) {
            assert_eq!(
                entry.prev_hash, before.hash,
                "the entry is chained to the one before it"
            );
        }
    };
    let mutating = |path: &str| {
        let mut request = a_request();
        request.method = "POST".to_string();
        request.path = path.to_string();
        request
    };

    // A root-only mutation that applied: exactly one row, under its own name, `applied`.
    let mut walk = a_bound_unit(mutating("/api/v1/admin/plane-record-write"));
    let resolved = walk
        .verb
        .expect("the plane-record write is a row the table names");
    assert!(!resolved.read_only, "the fixture must be a mutation");
    walk.principal = Some(PrincipalId::new(WHO));
    walk.answer = Some(AdminAnswer {
        status: 204,
        headers: Vec::new(),
        body: Vec::new(),
    });
    let before = the_one_rings_rows_by(WHO).len();
    let _ = audit(&walk, &Outcome::Completed);
    let rows = the_one_rings_rows_by(WHO);
    assert_eq!(rows.len(), before + 1, "one unit, one entry");
    assert_eq!(rows[0].action, resolved.verb);
    assert_eq!(rows[0].outcome, busbar_kernel::audit_ring::OUTCOME_APPLIED);
    assert!(
        !rows[0].principal.contains("admin-token"),
        "the entry names the identity, never the presented credential"
    );
    linked(&rows[0]);

    // A read changes nothing and records nothing.
    let mut walk = a_bound_unit(a_request());
    assert!(
        walk.verb
            .expect("the audit listing is a row the table names")
            .read_only,
        "the fixture must be a read"
    );
    walk.principal = Some(PrincipalId::new(WHO));
    let before = the_one_rings_rows_by(WHO).len();
    let _ = audit(&walk, &Outcome::Completed);
    assert_eq!(
        the_one_rings_rows_by(WHO).len(),
        before,
        "a read is not a mutation"
    );

    // A 1.5.5 mutation: its one row is the handler's, so the step adds none.
    let mut walk = a_bound_unit(mutating("/api/v1/admin/keys"));
    assert!(
        !walk
            .verb
            .expect("the key mint is a row the table names")
            .read_only,
        "the fixture must be a mutation"
    );
    walk.principal = Some(PrincipalId::new(WHO));
    let before = the_one_rings_rows_by(WHO).len();
    let _ = audit(&walk, &Outcome::Completed);
    assert_eq!(
        the_one_rings_rows_by(WHO).len(),
        before,
        "the handler's row is the one row; the step writes no second copy"
    );

    // A refused mutation by somebody the node identified is recorded as an attempt, not dropped.
    let mut walk = a_bound_unit(mutating("/api/v1/admin/plane-record-write"));
    walk.principal = Some(PrincipalId::new(WHO));
    let before = the_one_rings_rows_by(WHO).len();
    let _ = audit(
        &walk,
        &Outcome::Refused(
            busbar_contract::caps::StepName::Admit,
            ReasonCode::OverBudget,
        ),
    );
    let rows = the_one_rings_rows_by(WHO);
    assert_eq!(rows.len(), before + 1, "the attempt is on the chain");
    assert_eq!(rows[0].action, resolved.verb);
    assert_eq!(rows[0].outcome, busbar_kernel::audit_ring::OUTCOME_REJECTED);
    linked(&rows[0]);
}

/// The identity a fixture stands Verify's answer in for. Deliberately NOT the word the
/// unresolved fallback uses, so a test that passed by accident because the two agreed would
/// stop passing.
const AN_IDENTIFIED_OPERATOR: &str = "operator-alice";

/// Each of the two recovery verbs reaches the STORE, and a refusing store's answer is the
/// caller's.
///
/// The three used to travel `Verbs::execute`, which sends every new verb to the governance seam
/// — and the governance seam is the mounted router, which has no route for any of them. So all
/// three passed the scope check and the rate class, and then received a 404 from the surface
/// underneath: the gates on the most destructive operations this node has were being run in front
/// of nothing.
///
/// Two assertions per verb, and both are needed. That the store METHOD was reached — recorded by
/// the store itself, so nothing here infers it from a status — and that a store which refuses
/// surfaces as the documented refusal rather than as a success or as a decode failure. A test
/// that only checked the second would pass against a verb that never touched the store at all.
#[cfg(feature = "root-admin")]
#[test]
fn each_recovery_verb_reaches_the_store_and_a_refusing_store_is_the_answer() {
    /// A store that records what reached it and refuses it.
    #[derive(Debug, Default)]
    struct RecordingStore(Mutex<Vec<String>>);

    impl busbar_contract::verb_store::Store for RecordingStore {
        fn chain_break(
            &self,
            _admin: &busbar_contract::caps::Grant<busbar_contract::caps::AdminVerb>,
        ) -> Result<(), busbar_contract::verb_store::StoreError> {
            self.0.lock().unwrap().push("chain_break".to_string());
            Err(busbar_contract::verb_store::StoreError::Failed)
        }

        fn store_restore(
            &self,
            _admin: &busbar_contract::caps::Grant<busbar_contract::caps::AdminVerb>,
            backup_ref: &str,
        ) -> Result<(), busbar_contract::verb_store::StoreError> {
            self.0
                .lock()
                .unwrap()
                .push(format!("store_restore:{backup_ref}"));
            Err(busbar_contract::verb_store::StoreError::Failed)
        }
    }

    /// A dispatch that must never be asked. If a recovery verb still travelled the governance
    /// seam this would answer instead of the store, and the store's log would be empty — so the
    /// two halves of the proof check each other.
    struct NeverDispatched;
    impl AdminDispatch for NeverDispatched {
        fn execute(&self, verb: KernelVerb, _request: &AdminRequest) -> AdminAnswer {
            panic!("a recovery verb reached the governance seam: {verb:?}");
        }
    }

    let admin = crate::root::kernel::new_kernel().admin_token();

    for (path, body, reached) in [
        ("/api/v1/admin/chain-break", "{}", "chain_break"),
        (
            "/api/v1/admin/store-restore",
            "{\"backup_ref\":\"nightly-2026-09-05\"}",
            "store_restore:nightly-2026-09-05",
        ),
    ] {
        let store = Arc::new(RecordingStore::default());
        let binding = AdminBinding::new(Arc::new(NeverDispatched), open_door());
        let mut request = a_request();
        request.method = "POST".to_string();
        request.path = path.to_string();
        request.body = body.as_bytes().to_vec();
        let mut walk = AdminWalk::new(request);
        decode(&mut walk).unwrap_or_else(|_| panic!("{path} is a row the plane's table declares"));
        walk.granted = Some(VerbScope::Full);

        let outcome = route(
            &binding,
            Some(Arc::clone(&store) as Arc<dyn busbar_contract::verb_store::Store + Send + Sync>),
            &admin,
            &mut walk,
        );

        assert_eq!(
            store.0.lock().unwrap().as_slice(),
            [reached.to_string()],
            "{path} did not reach the store method it names"
        );
        assert_eq!(
            outcome.err(),
            Some(ReasonCode::DurabilityUnavailable),
            "{path} did not surface the refusing store's refusal"
        );
    }
}

/// A `store_restore` that names no backup restores nothing.
///
/// The single most destructive request this surface takes, and the one whose argument must not
/// be defaulted: a body that names no reference is refused before it reaches the store, so the
/// store is never asked to restore "whatever it thinks". The reader is exercised over the shapes
/// a real body has and the shapes a malformed one does, because the refusal is only worth having
/// if it survives both.
///
/// Every document below is written with ordinary escaped literals rather than raw ones. That is
/// not a style choice: the structure lints read this file by blanking string literals and then
/// counting braces, and their blanker does not know the raw byte-string form \u2014 so a JSON body
/// spelt that way leaks its braces into their depth tracking and silently reclassifies the rest
/// of this test module as production source.
#[test]
fn a_restore_that_names_no_backup_is_refused_rather_than_defaulted() {
    assert_eq!(
        backup_ref_of("{\"backup_ref\":\"nightly-2026-09-05\"}".as_bytes()),
        Some("nightly-2026-09-05".to_string())
    );
    assert_eq!(
        backup_ref_of("{ \"backup_ref\" : \"with \\\"quotes\\\" and \\\\slash\" }".as_bytes()),
        Some("with \"quotes\" and \\slash".to_string())
    );
    // A `\u` escape, which is one of the two ways a JSON document carries a non-ASCII name.
    assert_eq!(
        backup_ref_of("{\"backup_ref\":\"\\u00e9t\\u00e9\"}".as_bytes()),
        Some("\u{e9}t\u{e9}".to_string())
    );
    // And the other: the same name spelt as UTF-8 bytes.
    assert_eq!(
        backup_ref_of("{\"backup_ref\":\"\u{e9}t\u{e9}\"}".as_bytes()),
        Some("\u{e9}t\u{e9}".to_string())
    );
    for malformed in [
        "{}",
        "{\"backup\":\"x\"}",
        "{\"backup_ref\":\"\"}",
        "{\"backup_ref\":null}",
        "{\"backup_ref\":42}",
        "{\"backup_ref\":\"unterminated",
        "{\"backup_ref\":\"\\q\"}",
        "",
    ] {
        assert_eq!(
            backup_ref_of(malformed.as_bytes()),
            None,
            "a body naming no usable reference must not resolve to one"
        );
    }
    // And bytes that are not text at all.
    assert_eq!(backup_ref_of(&[0xff, 0xfe]), None);
}

/// Both carriers the administrative surface accepts reach the loop as one credential.
///
/// The reader is what a closed chain here would judge, so every form a deployment's tooling
/// actually sends has to arrive as the secret itself and nothing else. Each row below is a
/// caller that works against the previous release today: the two carriers, the scheme spelt in
/// either case, and a token whose own first word is the scheme's — that last one is why the
/// strip is single, because stripping repeatedly hands the chain a different string from the one
/// the caller holds.
#[cfg(feature = "root-admin")]
#[test]
fn either_carrier_reaches_the_loop_as_the_credential_itself() {
    let presented = |name: &str, value: &str| -> Option<String> {
        let mut headers = axum::http::HeaderMap::new();
        headers.insert(
            axum::http::HeaderName::from_bytes(name.as_bytes()).expect("a header name"),
            axum::http::HeaderValue::from_str(value).expect("a header value"),
        );
        presented_credential(&headers)
    };
    let secret = "shadow-oracle-admin";

    for value in [
        format!("Bearer {secret}"),
        format!("bearer {secret}"),
        format!("BEARER {secret}"),
        format!("Bearer  {secret}"),
        format!("  Bearer {secret}"),
    ] {
        assert_eq!(
            presented("authorization", &value).as_deref(),
            Some(secret),
            "{value:?} did not arrive as the secret"
        );
    }
    assert_eq!(
        presented(ADMIN_TOKEN_HEADER, secret).as_deref(),
        Some(secret),
        "the second carrier is a carrier"
    );

    // A token whose own first word is the scheme. Stripped once it is itself; stripped
    // repeatedly it becomes somebody else's string, and the chain judges the wrong secret.
    assert_eq!(
        presented("authorization", "Bearer Bearer token").as_deref(),
        Some("Bearer token")
    );
    // A scheme this reader does not know is handed on as presented; what it means is the
    // chain's to decide, not this reader's to guess.
    assert_eq!(
        presented("authorization", "Basic abc123").as_deref(),
        Some("Basic abc123")
    );
    // And nothing presented is nothing presented -- an empty carrier is not a credential.
    assert_eq!(presented("authorization", "Bearer ").as_deref(), None);
    assert_eq!(presented(ADMIN_TOKEN_HEADER, "").as_deref(), None);
    assert_eq!(
        presented_credential(&axum::http::HeaderMap::new()),
        None,
        "a request with no carrier at all presents nothing"
    );
}

/// These two verbs and no others land on the store.
///
/// Written from this side as well as the verbs unit's, because the split is a fact two crates
/// have to agree about: a verb added to the unit's store methods without a row here would go
/// back to the governance seam and its 404, silently.
#[test]
fn exactly_two_verbs_land_on_the_store() {
    let landing: Vec<KernelVerb> = NEW_VERBS
        .iter()
        .copied()
        .filter(|verb| recovery_verb(*verb).is_some())
        .collect();
    assert_eq!(
        landing,
        vec![KernelVerb::ChainBreak, KernelVerb::StoreRestore]
    );
    for verb in LEGACY_VERBS
        .iter()
        .map(|row| row.verb)
        .chain(LEDGER_VERBS.iter().chain(NAMED_SURFACES.iter()).copied())
    {
        assert!(
            recovery_verb(verb).is_none(),
            "{verb:?} is not a recovery verb"
        );
    }
}

/// A unit whose verb never resolved is sealed by its METHOD, not as a read whatever it asked.
///
/// Written as an inequality against the read class as well as an equality on the write one,
/// because what matters is not the spelling that replaced it but that an attempted mutation
/// stops leaving the record as somebody browsing a page. The safe methods stay reads, and an
/// absent request — a unit that presented no method at all — stays one too, because it
/// attempted nothing.
#[cfg(feature = "root-admin")]
#[test]
fn an_unresolved_unit_is_sealed_by_the_method_it_asked_with() {
    let refused = &Outcome::Refused(
        busbar_contract::caps::StepName::Decode,
        ReasonCode::DecodeFailed,
    );
    let read = busbar_contract::OpClassId::new(OP_UNRESOLVED_READ);
    let write = busbar_contract::OpClassId::new(OP_UNRESOLVED_WRITE);

    for method in ["GET", "HEAD", "head"] {
        assert_eq!(
            unresolved_facts(Some(method), refused).op_class,
            read,
            "{method} reads"
        );
    }
    for method in ["POST", "PUT", "PATCH", "DELETE", "delete", "WHAT"] {
        let facts = unresolved_facts(Some(method), refused);
        assert_ne!(facts.op_class, read, "{method} is not a read");
        assert_eq!(facts.op_class, write, "{method} seals as a write");
    }
    assert_eq!(
        unresolved_facts(None, refused).op_class,
        read,
        "a unit that presented no method attempted no mutation"
    );
    assert_eq!(
        unresolved_facts(None, refused).finish,
        busbar_contract::FinishClass::Error
    );
}

/// The refused-audit door seals the refusal that HAPPENED, not one it composed.
///
/// The door used to answer with a decode failure raised at Decode for every unresolved unit,
/// whatever it had actually been refused for — which overwrote the single field an audit record
/// exists to state. Two different refusals are asked for here, because one would pass against a
/// fixed sentinel that happened to match it.
#[cfg(feature = "root-admin")]
#[test]
fn the_refused_door_seals_the_refusal_that_happened() {
    // A path the plane's table does not declare, so the verb never resolves and the door takes
    // its unresolved arm — the one that used to fabricate.
    let mut unrouted = a_request();
    unrouted.method = "DELETE".to_string();
    unrouted.path = "/api/v1/admin/nothing-declares-this".to_string();
    let walk = a_bound_unit(unrouted);
    assert!(
        walk.verb.is_none(),
        "the fixture must be a unit whose verb never resolved"
    );

    let facts = audit(
        &walk,
        &Outcome::Refused(
            busbar_contract::caps::StepName::Authenticate,
            ReasonCode::Unauthenticated,
        ),
    );
    assert_eq!(
        facts.op_class,
        busbar_contract::OpClassId::new(OP_UNRESOLVED_WRITE),
        "the DELETE it asked with, not the read it used to be sealed as"
    );
    assert_eq!(facts.finish, busbar_contract::FinishClass::Error);
}

// ── the five ledger views ───────────────────────────────────────────────────────────────────

/// The window the fixture's rows are in.
const A_DAY: u64 = 1_767_225_600;

/// A ledger with something in it: two priced rows and one the card refused, so the views have a
/// figure to serve and a refusal to name.
struct SeededLedger;

impl LedgerView for SeededLedger {
    fn priced(&self) -> Result<crate::root::units_admin::PricedLedger, String> {
        use crate::root::units_admin::{LedgerRow, PricedLedger, RefusedRow};
        Ok(PricedLedger {
            rows: vec![
                LedgerRow {
                    bucket: "key-1".to_string(),
                    day: A_DAY,
                    priced_nanos: 7_000_000,
                    fee_count: 2,
                },
                LedgerRow {
                    bucket: "key-2".to_string(),
                    day: A_DAY,
                    priced_nanos: 1_000_000,
                    fee_count: 1,
                },
            ],
            refused: vec![RefusedRow {
                bucket: "key-3".to_string(),
                day: A_DAY,
                refusal: "ClassUnpriced(cache_read)".to_string(),
            }],
        })
    }
}

/// The five paths, in the order the closed table declares them.
const LEDGER_PATHS: &[&str] = &[
    "/api/v1/admin/ledger/totals",
    "/api/v1/admin/ledger/checkpoints",
    "/api/v1/admin/ledger/reconciliation",
    "/api/v1/admin/ledger/migration",
    "/api/v1/admin/ledger/openapi.json",
];

fn a_ledger_request(path: &str) -> AdminRequest {
    AdminRequest {
        method: "GET".to_string(),
        path: path.to_string(),
        credential: Some("admin-token".to_string()),
        headers: vec![("accept".to_string(), "application/json".to_string())],
        body: Vec::new(),
        at: 1_700_000_000,
        unit: a_fresh_unit(),
    }
}

/// Walk one request through the whole loop against a node whose ledger holds the fixture.
#[cfg(feature = "root-admin")]
fn answer_over_seeded_ledger(request: AdminRequest) -> AdminAnswer {
    let mut units =
        crate::root::kernel::ProductionUnits::admin_only(Arc::new(AnsweringDispatch), open_door());
    units.admin = AdminBinding::new(Arc::new(AnsweringDispatch), open_door())
        .with_ledger_view(Arc::new(SeededLedger));
    AdminNode::new(crate::root::kernel::new_kernel(), units).answer(request)
}

/// A cost model whose one lane `m` prices input at 2.5 micro-units a token, no fee.
#[cfg(feature = "root-admin")]
fn one_lane_card() -> busbar_kernel::cost::CostModel {
    let rates = std::collections::BTreeMap::from([(
        "m".to_string(),
        busbar_kernel::config::RateEntryCfg {
            input_utok: 2.5,
            ..Default::default()
        },
    )]);
    busbar_kernel::cost::CostModel::resolve_parts(
        Some(&rates),
        0,
        &std::collections::BTreeMap::new(),
    )
}

/// One ledger request walked through the loop against a node whose ledger views read `gov`'s
/// live usage counts ([`crate::root::units_admin::CountsLedger`]), as `mount_node` binds them.
#[cfg(feature = "root-admin")]
fn answer_over_counts(
    gov: Arc<busbar_kernel::governance::GovState>,
    path: &str,
) -> serde_json::Value {
    let app = busbar_kernel::test_support::TestApp::new()
        .governance(gov)
        .cost(one_lane_card())
        .build();
    let handle = Arc::new(busbar_kernel::state::AppHandle::new(app));
    let mut units =
        crate::root::kernel::ProductionUnits::admin_only(Arc::new(AnsweringDispatch), open_door());
    units.admin = AdminBinding::new(Arc::new(AnsweringDispatch), open_door()).with_ledger_view(
        Arc::new(crate::root::units_admin::CountsLedger::new(handle)),
    );
    let answer =
        AdminNode::new(crate::root::kernel::new_kernel(), units).answer(a_ledger_request(path));
    assert_eq!(answer.status, 200, "{path} did not answer");
    serde_json::from_slice(&answer.body).unwrap_or_else(|e| panic!("{path}: {e}"))
}

/// **THE KEPT LEDGER PATHS ANSWER FROM THE ONE LEDGER** (MONEY-DESIGN §4, PR-C): money is the
/// store's usage counts x the rate card. A key spends 1,000 input tokens at 2.5 micro-units:
/// `GET /api/v1/admin/ledger/totals` serves 2,500 micro-units on that key's row — the counts the
/// store holds after the flush, priced by the card — `reconciliation` holds, and a restart (a new
/// governance state over the same store, hydrated as the boot hydrates it) serves the same bytes.
/// The second book is gone, so there is nothing else for the paths to answer from.
///
/// RED on the base: the paths answered from the node's second book, which a spend recorded only
/// in the usage counts never reached — `totals` served no row for the key.
#[cfg(feature = "root-admin")]
#[test]
fn the_ledger_paths_answer_counts_times_card_and_survive_a_restart() {
    use busbar_contract::records::RecordStore as _;
    use busbar_kernel::governance::{GovState, MemoryStore, VirtualKey};
    let store = Arc::new(MemoryStore::new());
    let key = VirtualKey {
        id: "vk_one_ledger".to_string(),
        generation_hash: "h:vk_one_ledger".to_string(),
        name: "one-ledger".to_string(),
        enabled: true,
        revision: 1,
        ..Default::default()
    };
    store.put_key(&key).expect("the key persists");
    let gov = Arc::new(GovState::new(store.clone(), None).expect("governance builds"));
    let now = busbar_kernel::store::now();
    let input = std::collections::BTreeMap::from([(
        busbar_contract::records::UNIT_INPUT.to_string(),
        1_000u64,
    )]);
    gov.record_usage(&one_lane_card(), &key, "", "m", &input, now);
    gov.flush_budgets();

    // The store's own counts, after the spend.
    let stored = store.get_usage(&key.id, 0).expect("the row reads");
    assert_eq!(
        stored.tokens_for("m"),
        Some(1_000),
        "the store holds the spend"
    );

    let totals = answer_over_counts(Arc::clone(&gov), "/api/v1/admin/ledger/totals");
    let rows = totals["rows"].as_array().expect("rows");
    let row = rows
        .iter()
        .find(|r| r["bucket"] == "vk_one_ledger")
        .unwrap_or_else(|| panic!("the key's row is served: {totals}"));
    assert_eq!(row["priced_micros"], "2500", "1,000 tokens x 2.5: {totals}");
    assert_eq!(row["priced_nanos"], "2500000");
    assert_eq!(
        answer_over_counts(Arc::clone(&gov), "/api/v1/admin/ledger/reconciliation")["holds"],
        true
    );

    let restarted = Arc::new(GovState::new(store, None).expect("governance builds"));
    restarted
        .hydrate_budgets(&one_lane_card(), now)
        .expect("the boot hydrates");
    assert_eq!(
        answer_over_counts(restarted, "/api/v1/admin/ledger/totals"),
        totals,
        "a restart serves the same money from the same counts"
    );
}

/// Every view answers, through the whole loop, with a JSON document of its own.
///
/// "Of its own" is half the assertion. The dispatch this node is built over answers every verb
/// with the same recognisable body, so a view that had fallen through to it — which is exactly
/// what would happen if the executing unit stopped recognising a ledger verb — would still come
/// back 200 and still be JSON. Requiring five distinct bodies, none of them the dispatch's, is
/// what makes the green mean the ledger was read rather than the router.
#[cfg(feature = "root-admin")]
#[test]
fn every_ledger_view_answers_from_the_ledger_and_not_from_the_dispatch() {
    let mut bodies = Vec::new();
    for path in LEDGER_PATHS {
        let answer = answer_over_seeded_ledger(a_ledger_request(path));
        assert_eq!(answer.status, 200, "{path} did not answer");
        assert_eq!(
            answer.headers,
            vec![("content-type".to_string(), "application/json".to_string())],
            "{path} carried a header the view does not set"
        );
        let parsed: serde_json::Value =
            serde_json::from_slice(&answer.body).unwrap_or_else(|e| panic!("{path}: {e}"));
        assert!(parsed.is_object(), "{path} did not answer a JSON object");
        assert_ne!(
            answer.body, br#"{"entries":[]}"#,
            "{path} fell through to the dispatch"
        );
        bodies.push(answer.body);
    }
    let mut distinct = bodies.clone();
    distinct.sort_unstable();
    distinct.dedup();
    assert_eq!(
        distinct.len(),
        LEDGER_PATHS.len(),
        "two views answered the same bytes"
    );
}

/// The figures each view serves are the figures the ledger holds, field by field.
#[cfg(feature = "root-admin")]
#[test]
fn each_view_serves_the_figures_the_ledger_holds() {
    let body = |path: &str| -> serde_json::Value {
        serde_json::from_slice(&answer_over_seeded_ledger(a_ledger_request(path)).body)
            .expect("valid JSON")
    };

    let totals = body("/api/v1/admin/ledger/totals");
    let rows = totals["rows"].as_array().expect("rows");
    assert_eq!(rows.len(), 2);
    assert_eq!(rows[0]["bucket"], "key-1");
    assert_eq!(rows[0]["day"], A_DAY);
    assert_eq!(rows[0]["lane"], "");
    assert_eq!(rows[0]["provider"], "");
    // Money is text and a count is a number — the rule the served document states.
    assert_eq!(rows[0]["priced_nanos"], "7000000");
    assert_eq!(rows[0]["priced_micros"], "7000");
    assert_eq!(rows[0]["fee_count"], 2);
    let refused = totals["refused"].as_array().expect("refused");
    assert_eq!(refused.len(), 1, "the refused row is named, never served");
    assert_eq!(refused[0]["bucket"], "key-3");
    assert_eq!(refused[0]["refusal"], "ClassUnpriced(cache_read)");

    // No checkpoint is sealed and nothing is migrated: the ledger is the store's counts.
    assert_eq!(
        body("/api/v1/admin/ledger/checkpoints"),
        serde_json::json!({"checkpoints": []})
    );
    assert_eq!(
        body("/api/v1/admin/ledger/migration"),
        serde_json::json!({"migrated": false, "marker": null})
    );

    let document = body("/api/v1/admin/ledger/openapi.json");
    assert_eq!(document["info"]["version"], "1.6.0");
}

/// A dispatch that panics where an operation's body would run.
#[cfg(feature = "root-admin")]
struct PanickingDispatch;

#[cfg(feature = "root-admin")]
impl AdminDispatch for PanickingDispatch {
    fn execute(&self, _verb: KernelVerb, _request: &AdminRequest) -> AdminAnswer {
        panic!("the operation's body panicked");
    }
}

/// A STEP THAT PANICS LEAVES THE NODE ANSWERING.
///
/// A unit's state lives in its own walk and nowhere node-wide, so a panic in one operation's body
/// takes that walk with it and leaves nothing resident: the node answers the next request exactly
/// as if the panicking one had never arrived — no slot held, no request body kept, no lock poisoned.
#[cfg(feature = "root-admin")]
#[test]
fn a_panicking_step_leaves_both_tables_empty() {
    let units =
        crate::root::kernel::ProductionUnits::admin_only(Arc::new(PanickingDispatch), open_door());
    let node = AdminNode::new(crate::root::kernel::new_kernel(), units);

    let previous = std::panic::take_hook();
    std::panic::set_hook(Box::new(|_| {}));
    let ended = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| node.answer(a_request())));
    std::panic::set_hook(previous);
    assert!(ended.is_err(), "the fixture's dispatch panics");

    // The same node, asked a question no dispatch is reached for, still answers it.
    let mut unknown = a_request();
    unknown.path = "/api/v1/admin/not-a-real-operation".to_string();
    assert_eq!(
        node.answer(unknown).status,
        400,
        "the node answers after a panicking unit"
    );
}

/// A node whose ledger has nothing in it says so, rather than reporting a balance it never read.
///
/// The views here are bound to the node's own durability, and that durability is genuinely
/// empty: nothing settled, nothing sealed, nothing migrated. Each emptiness is a fact about this
/// node rather than a placeholder — which is exactly what the two tests below establish by
/// settling on the same composition and watching the same endpoints change.
#[cfg(feature = "root-admin")]
#[test]
fn an_unopened_ledger_answers_empty_rather_than_absent() {
    let units =
        crate::root::kernel::ProductionUnits::admin_only(Arc::new(AnsweringDispatch), open_door());
    let node = AdminNode::new(crate::root::kernel::new_kernel(), units);
    let body = |path: &str| -> serde_json::Value {
        let answer = node.answer(a_ledger_request(path));
        assert_eq!(answer.status, 200, "{path}");
        serde_json::from_slice(&answer.body).expect("valid JSON")
    };
    assert_eq!(
        body("/api/v1/admin/ledger/totals")["rows"],
        serde_json::json!([])
    );
    assert_eq!(
        body("/api/v1/admin/ledger/checkpoints")["checkpoints"],
        serde_json::json!([])
    );
    assert_eq!(body("/api/v1/admin/ledger/migration")["migrated"], false);
    assert_eq!(
        body("/api/v1/admin/ledger/migration")["marker"],
        serde_json::Value::Null
    );
    // The identity over two empty snapshots holds, and it is honest here only because the
    // totals view beside it reports the empty set it held over.
    assert_eq!(body("/api/v1/admin/ledger/reconciliation")["holds"], true);
}

/// THE RECONCILIATION over one ledger: there is no second set of rows to disagree with it, so it
/// holds exactly when every count is priced, and a row the card refused is named.
#[cfg(feature = "root-admin")]
#[test]
fn the_reconciliation_holds_unless_a_row_is_refused_and_names_it() {
    let served: serde_json::Value = serde_json::from_slice(
        &answer_over_seeded_ledger(a_ledger_request("/api/v1/admin/ledger/reconciliation")).body,
    )
    .expect("valid JSON");
    assert_eq!(
        served["holds"], false,
        "a refused row is a row not measured"
    );
    assert_eq!(served["discrepancies"], serde_json::json!([]));
    let refused = served["refused"].as_array().expect("refused");
    assert_eq!(refused.len(), 1);
    assert_eq!(refused[0]["bucket"], "key-3");
}

/// **`GET /admin/verify` NAMES A REFUSED ROW AND EVERY OTHER FINDING** (#42; audit root-R1 #10): a
/// row the card refused is a finding naming it, and an independent finding beside it (here, what
/// the boot could not read back of the journal) is still reported.
#[cfg(feature = "root-admin")]
#[test]
fn verify_names_a_refused_row_and_every_other_finding() {
    let node_book = crate::root::durability::node_book();
    node_book
        .durability
        .lock()
        .expect("unpoisoned")
        .restart_findings
        .push("the journal does not verify: a forged record".to_string());
    let audit =
        crate::root::units_admin::NodeAudit::new(std::sync::Arc::clone(&node_book.durability));
    let answer = crate::root::units_admin::bound::verify_effect(&SeededLedger, Some(&audit))
        .expect("a refused row must not take /admin/verify down");
    let body: serde_json::Value = serde_json::from_slice(&answer.body).expect("valid JSON");
    let findings: Vec<&str> = body["findings"]
        .as_array()
        .expect("findings")
        .iter()
        .filter_map(serde_json::Value::as_str)
        .collect();
    assert!(
        findings
            .iter()
            .any(|f| f.starts_with("restart: ") && f.contains("a forged record")),
        "the independent finding must still be reported: {body}"
    );
    assert!(
        findings.iter().any(|f| f.starts_with("refused counts: ")
            && f.contains("key-3")
            && f.contains(&A_DAY.to_string())
            && f.contains("ClassUnpriced(cache_read)")),
        "the refused row must be a named finding: {body}"
    );
    assert_eq!(body["identity_holds"], false, "{body}");
    assert_eq!(body["ok"], false, "{body}");
}

/// A caller the node will not authenticate gets from a ledger view exactly what it gets from
/// the legacy read that touches the same money — byte for byte, including the status.
///
/// Stated as an equality against `GET /usage` rather than against a literal, because the claim
/// the design makes about these verbs is not "they answer 403"; it is that their auth posture is
/// the SAME one. A literal would still pass on the day the shared posture changed and the views
/// were left behind.
///
/// The refused case is a credential the door identified and the node's directory has revoked.
/// That is what an unauthenticated caller IS on this composition: a request carrying no
/// credential at all is admitted by an open door — for the views exactly as for `/usage`, which
/// the second half asserts over an open chain. Choosing the reachable refusal over the
/// unreachable one is what keeps this test about the posture the two share rather than about a
/// 401 this node never produces.
#[cfg(feature = "root-admin")]
#[test]
fn a_ledger_view_answers_an_unauthenticated_caller_exactly_as_the_legacy_usage_read_does() {
    let under = |path: &str, credential: Option<&str>, revoked: bool| -> AdminAnswer {
        let mut request = a_ledger_request(path);
        request.credential = credential.map(ToString::to_string);
        // The revocation withdraws an identification, so when it is on, the door must identify first.
        let door = if revoked {
            door_of_chain(a_door_that_identifies_the_operator())
        } else {
            open_door()
        };
        let units =
            crate::root::kernel::ProductionUnits::admin_only(Arc::new(AnsweringDispatch), door)
                .with_auth_bindings(crate::root::auth_bindings::AuthBindings::new(Arc::new(
                    Denylist(revoked),
                )));
        AdminNode::new(crate::root::kernel::new_kernel(), units).answer(request)
    };

    let refused = under("/api/v1/admin/usage", Some("admin-token"), true);
    assert_ne!(
        refused.status, 200,
        "the control must actually be a refusal, or this test compares two successes"
    );
    for path in LEDGER_PATHS {
        assert_eq!(
            under(path, Some("admin-token"), true),
            refused,
            "{path} does not refuse a revoked credential the way /usage does"
        );
    }

    // And the other half: where `/usage` admits a caller carrying no credential, so does every
    // view. The bodies differ — they are different operations — but the admission does not.
    let admitted = under("/api/v1/admin/usage", None, false);
    assert_eq!(admitted.status, 200, "the open chain admits the control");
    for path in LEDGER_PATHS {
        assert_eq!(
            under(path, None, false).status,
            admitted.status,
            "{path} does not admit a credential-less caller the way /usage does"
        );
    }
}

/// The scope gate is live on this path, and the views sit on the rung the legacy read sits on.
///
/// Two halves, and both are needed. A credential granted `read-only` reaches every view — which
/// is the whole point of putting them on that rung — and the SAME credential is refused a
/// mutation on the same surface, which is what proves the gate is a gate rather than an absence.
/// Without the second half, a step that had stopped checking scope altogether would pass the
/// first.
#[test]
fn a_read_only_credential_reaches_every_view_and_still_no_mutation() {
    let decide = |path: &str, method: &str, granted: VerbScope| -> bool {
        let mut request = a_ledger_request(path);
        request.method = method.to_string();
        let mut walk = AdminWalk::new(request);
        walk.granted = Some(granted);
        approve(&walk).is_ok()
    };

    for path in LEDGER_PATHS {
        assert!(
            decide(path, "GET", VerbScope::ReadOnly),
            "{path} refused a read-only credential"
        );
        assert!(
            decide(path, "GET", VerbScope::Full),
            "{path} refused a full credential"
        );
    }
    assert!(
        !decide("/api/v1/admin/config/settings", "PUT", VerbScope::ReadOnly),
        "the scope gate is not checking anything: a read-only credential reached a mutation"
    );
}

/// Both of the unit's own answers about a ledger verb put it on the read side, and the plane's
/// row agrees. Three tables, one split — and the rate class is the one that bites: a view whose
/// class fell through to `Crud` would spend a mutation slot every time somebody looked at a
/// balance, and would eventually refuse an operator's config change because of it.
#[test]
fn a_ledger_view_is_read_only_in_every_table_that_has_an_opinion() {
    for path in LEDGER_PATHS {
        let row = busbar_core_admin::admin_codec::verbs::resolve("GET", path)
            .unwrap_or_else(|| panic!("{path} is not in the plane's table"));
        assert!(
            row.read_only,
            "{path} is not read-only in the plane's table"
        );
        assert_eq!(
            row.op_class(),
            busbar_contract::ids::OpClassId::new("admin_read")
        );

        let verb = kernel_verb(&row).unwrap_or_else(|| panic!("{path} names no kernel verb"));
        assert!(LEDGER_VERBS.contains(&verb), "{path} is not a ledger verb");
        assert_eq!(
            busbar_core_admin::required_scope(verb),
            busbar_core_admin::required_scope(KernelVerb::GetUsage),
            "{path} does not require what the legacy /usage read requires"
        );
        assert_eq!(
            mutation_class(verb),
            MutationClass::Forbidden,
            "{path} would spend a mutation slot per read"
        );
        assert_eq!(
            busbar_kernel::admin::scope::admin_required_scope("GET", path),
            Scope::ReadOnly
        );
    }
}

/// A ledger verb never reaches the dispatch, and answers a read-only grant.
///
/// The governance seam is the boundary this is asserted at: a recording seam that would notice a
/// legacy or new-verb call, under the read-only grant that refuses every mutation.
#[test]
fn a_view_never_reaches_the_dispatch_and_answers_a_read_only_grant() {
    use std::sync::atomic::{AtomicUsize, Ordering};

    struct CountingDispatch(Arc<AtomicUsize>);
    impl AdminDispatch for CountingDispatch {
        fn execute(&self, _verb: KernelVerb, _request: &AdminRequest) -> AdminAnswer {
            self.0.fetch_add(1, Ordering::Relaxed);
            // A recognisable answer rather than a realistic one: if a view ever reached the
            // dispatch, the count below is what says so, and the body only has to be something
            // no view would produce.
            AdminAnswer {
                status: 599,
                headers: Vec::new(),
                body: b"the dispatch was reached".to_vec(),
            }
        }
    }

    let calls = Arc::new(AtomicUsize::new(0));
    let admin = crate::root::kernel::new_kernel().admin_token();

    for verb in LEDGER_VERBS {
        let verbs = busbar_core_admin::Verbs::new(
            CoreGovernance::new(
                Arc::new(CountingDispatch(Arc::clone(&calls))),
                Arc::new(SeededLedger),
                None,
                *verb,
                a_ledger_request("/api/v1/admin/ledger/totals"),
            ),
            None::<Arc<dyn busbar_contract::verb_store::Store + Send + Sync>>,
            CONFIG_CLASS_RULES,
            Arc::new(busbar_core_admin::rate::MutationLimiter::new()),
        );
        let answer = verbs
            .execute(
                *verb,
                &admin,
                "admin",
                VerbScope::ReadOnly,
                1_700_000_000,
                b"",
            )
            .unwrap_or_else(|r| panic!("{verb:?} was refused: {r:?}"));
        assert_eq!(answer.status, 200);
    }
    assert_eq!(
        calls.load(Ordering::Relaxed),
        0,
        "a ledger view reached the dispatch, which has no handler for it"
    );

    // The control: a money-governance verb under the same read-only grant IS refused, so the green
    // above is the views being reads rather than the scope check being unbound.
    let verbs = busbar_core_admin::Verbs::new(
        CoreGovernance::new(
            Arc::new(CountingDispatch(Arc::clone(&calls))),
            Arc::new(SeededLedger),
            None,
            KernelVerb::Adjust,
            a_ledger_request("/api/v1/admin/adjust"),
        ),
        None::<Arc<dyn busbar_contract::verb_store::Store + Send + Sync>>,
        CONFIG_CLASS_RULES,
        Arc::new(busbar_core_admin::rate::MutationLimiter::new()),
    );
    assert!(verbs
        .execute(
            KernelVerb::Adjust,
            &admin,
            "admin",
            VerbScope::ReadOnly,
            1_700_000_000,
            b"",
        )
        .is_err());
}

// ── the three audit-chain reads ─────────────────────────────────────────────────────────────────

/// The three paths, as the closed table declares them.
#[cfg(feature = "root-admin")]
const AUDIT_PATHS: &[&str] = &[
    "/api/v1/admin/audit/head",
    "/api/v1/admin/audit/range",
    "/api/v1/admin/audit/keys",
];

/// A chain with three records actually sealed onto it, signed by a key the set publishes.
///
/// Sealed rather than hand-built: a record whose `seq`, `prev_hash` and `hash` were written by this
/// test would prove the renderer runs and nothing about what it renders. These three went through
/// [`busbar_kernel_audit::Audit::seal`], so the positions are contiguous, each `prev_hash` is the
/// previous record's digest, and the signatures are over the digests the recipe took.
#[cfg(feature = "root-admin")]
struct SealedChain {
    chain: busbar_kernel_audit::AuditChain,
    records: Vec<busbar_kernel_audit::AuditRecord>,
    keys: busbar_kernel_audit::AuditKeySet,
}

#[cfg(feature = "root-admin")]
impl AuditView for SealedChain {
    fn read(
        &self,
        take: &mut dyn FnMut(
            &busbar_kernel_audit::AuditChain,
            Option<&[busbar_kernel_audit::AuditRecord]>,
        ),
    ) {
        take(&self.chain, Some(&self.records));
    }

    fn keys(&self) -> busbar_kernel_audit::AuditKeySet {
        self.keys.clone()
    }
}

/// The audit step's pass, as the loop lends it at that step — one mint for every chain test here.
#[cfg(feature = "root-admin")]
fn an_audit_pass() -> busbar_contract::caps::Pass<busbar_contract::caps::Audit> {
    busbar_kernel::test_support::tokens::pass()
}

/// Seal three records onto a signing chain, and publish the key's public half.
#[cfg(feature = "root-admin")]
fn a_sealed_chain() -> SealedChain {
    use busbar_contract::caps::{OriginKind, Outcome as UnitOutcome, UnitKey};
    use busbar_kernel_audit::{
        Audit as _, AuditInputs, Controls, FinishClass, OpClassId, OutcomeFacts, Subject, Usage,
        What,
    };

    let signer = busbar_kernel_audit::AuditSigningKey::from_seed(&[7u8; 32]);
    let mut keys = busbar_kernel_audit::AuditKeySet::new();
    keys.insert(
        busbar_kernel_audit::AuditVerifyingKey::from_hex(&signer.public_key_hex())
            .expect("a public key"),
    );
    let mut chain = busbar_kernel_audit::AuditChain::new().signing_with(signer);

    let token = an_audit_pass();
    let mut records = Vec::new();
    for unit in 1..=3u64 {
        records.push(chain.seal(
            AuditInputs {
                subject: Subject::PrincipalId(format!("pseudonym-{unit}")),
                what: What {
                    unit_key: UnitKey::new(unit),
                    incarnation: 0,
                    op_class: OpClassId::new("chat.completion"),
                    destination: Some("upstream-a".into()),
                    parent: None,
                    pre_hook_head: None,
                    post_hook_head: None,
                },
                wall: 1_700_000_000 + unit,
                mono: unit * 1_000,
                origin: busbar_kernel::test_support::tokens::origin(OriginKind::Client),
                outcome: OutcomeFacts {
                    unit_end: UnitOutcome::Completed,
                    step: None,
                    finish: FinishClass::Complete,
                    hook_failed: false,
                    emission_delta: 0,
                    stale_policy: false,
                },
                usage: Usage {
                    lines: Vec::new(),
                    tier_bp: 9_000,
                    fee_count: 1,
                    rate_card_version: 3,
                    bucket_chain_ref: "chain:free>paid".into(),
                },
                controls: Controls {
                    lease_epoch: 4,
                    policy_epoch: 7,
                    ..Controls::default()
                },
                correlation_label: None,
            },
            &token,
        ));
    }
    SealedChain {
        chain,
        records,
        keys,
    }
}

/// Walk one request through the whole loop against a node whose chain holds those three records.
#[cfg(feature = "root-admin")]
fn answer_over_a_sealed_chain(request: AdminRequest) -> AdminAnswer {
    let mut units =
        crate::root::kernel::ProductionUnits::admin_only(Arc::new(AnsweringDispatch), open_door());
    units.admin = AdminBinding::new(Arc::new(AnsweringDispatch), open_door())
        .with_audit_view(Arc::new(a_sealed_chain()) as Arc<dyn AuditView>);
    AdminNode::new(crate::root::kernel::new_kernel(), units).answer(request)
}

/// ALL THREE CHAIN READS ANSWER, over the whole loop, with the chain's own bytes.
///
/// This is the test the verbs were missing. They were mounted on the closed table in `b1a448454`
/// and resolved from that moment — right scope, right rate class, right row — and then `execute`
/// fell past the ledger branch and past the new-verb branch into the legacy catch-all, where
/// the mounted router answered a 404 for a path that release never had. Resolving is not answering.
///
/// So the assertion is on the BODIES, not on the statuses: a 200 could come from the dispatch
/// standing in (`AnsweringDispatch` answers `{"entries":[]}` to anything), and what proves the
/// audit arm ran is that the head read names the signature domain, the range read carries the
/// sealed positions, and the key read publishes the public half of the key that signed them.
#[test]
#[cfg(feature = "root-admin")]
fn the_three_chain_reads_answer_with_the_chains_own_bytes() {
    let head = answer_over_a_sealed_chain(a_ledger_request("/api/v1/admin/audit/head"));
    assert_eq!(head.status, 200, "the head read did not answer");
    let head_body = String::from_utf8(head.body).expect("the head read answers UTF-8");
    assert!(
        head_body.contains(r#""signature_domain":"busbar.audit.record.v1""#),
        "the head read did not come from the chain: {head_body}"
    );
    // Three records sealed, so the NEXT position is four and the tip is the third.
    assert!(
        head_body.contains(r#""next_seq":4"#),
        "the head read does not see the sealed records: {head_body}"
    );
    assert!(
        head_body.contains(r#""head":{"#) && head_body.contains(r#""seq":3"#),
        "the head read reports no tip: {head_body}"
    );

    let range =
        answer_over_a_sealed_chain(a_ledger_request("/api/v1/admin/audit/range?from=2&to=3"));
    assert_eq!(range.status, 200, "the range read did not answer");
    let range_body = String::from_utf8(range.body).expect("the range read answers UTF-8");
    assert!(
        range_body.contains(r#""from":2"#) && range_body.contains(r#""to":3"#),
        "the range read did not take its window from the query: {range_body}"
    );
    // The window is inclusive at both ends and selects only what it names: the first record is
    // sealed and is NOT in the answer, which is what says the selection happened.
    assert!(
        range_body.contains("pseudonym-2") && range_body.contains("pseudonym-3"),
        "the range read is missing records inside its window: {range_body}"
    );
    assert!(
        !range_body.contains("pseudonym-1"),
        "the range read returned a record outside its window: {range_body}"
    );

    let keys = answer_over_a_sealed_chain(a_ledger_request("/api/v1/admin/audit/keys"));
    assert_eq!(keys.status, 200, "the key read did not answer");
    let keys_body = String::from_utf8(keys.body).expect("the key read answers UTF-8");
    let signer = busbar_kernel_audit::AuditSigningKey::from_seed(&[7u8; 32]);
    assert!(
        keys_body.contains(&signer.public_key_hex()),
        "the key read does not publish the key that signed the chain: {keys_body}"
    );
    assert!(
        keys_body.contains(r#""algorithm":"ed25519""#),
        "the key read names no algorithm: {keys_body}"
    );
    // The CONTROL that makes the three greens mean something: the secret half is not on the wire.
    // `from_seed` is deterministic, so the seed's own bytes are checkable, and a key set that
    // published a signing key would carry them.
    assert!(
        !keys_body.contains(&"07".repeat(32)),
        "the key read published secret key material: {keys_body}"
    );
}

/// A node no root bound a chain into REFUSES the three reads. It does not answer an empty head.
///
/// `docs/design/BUSBAR-1.6.0.md:2079` — a gap and a failure must never be the same output. A node
/// that has sealed nothing and a node nobody wired a chain into are different facts: the first has
/// a chain whose head is null, the second has no chain to have a head. Rendering the first for the
/// second is an instrument reporting over nothing.
///
/// The 404 is `NoDestination` at the loop's edge, which is the same status this surface gives any
/// path it cannot answer — correct, because from outside, a node with no chain bound genuinely does
/// not have that surface.
#[test]
#[cfg(feature = "root-admin")]
fn an_unbound_chain_refuses_rather_than_answering_an_empty_head() {
    let mut units =
        crate::root::kernel::ProductionUnits::admin_only(Arc::new(AnsweringDispatch), open_door());
    // `AnsweringDispatch` answers 200 to ANYTHING, which is what makes this a real test: if the
    // audit verbs fell through to the legacy catch-all — the defect this slice fixes — they would
    // come back 200 with `{"entries":[]}` and look like they worked.
    units.admin = AdminBinding::new(Arc::new(AnsweringDispatch), open_door());
    let node = AdminNode::new(crate::root::kernel::new_kernel(), units);
    for path in AUDIT_PATHS {
        let answer = node.answer(a_ledger_request(path));
        assert_eq!(answer.status, 404, "{path} answered over an unbound chain");
        assert!(
            !String::from_utf8_lossy(&answer.body).contains("entries"),
            "{path} reached the legacy dispatch"
        );
    }
}

/// A range read that names no window is refused as a BAD REQUEST, not answered with a default one.
///
/// And the distinction from the refusal above is the point: 400 says the caller did not say what it
/// wanted, 404 says the node has nothing to say. A single status for both would make an auditor
/// debug their firewall over a missing query parameter.
#[test]
#[cfg(feature = "root-admin")]
fn a_range_read_that_names_no_window_is_refused_rather_than_widened() {
    for target in [
        "/api/v1/admin/audit/range",
        "/api/v1/admin/audit/range?from=2",
        "/api/v1/admin/audit/range?to=3",
        "/api/v1/admin/audit/range?from=3&to=2",
        "/api/v1/admin/audit/range?from=two&to=three",
    ] {
        let answer = answer_over_a_sealed_chain(a_ledger_request(target));
        assert_eq!(answer.status, 400, "{target} was not refused as malformed");
    }
    // The control: the same node, asked properly, answers.
    assert_eq!(
        answer_over_a_sealed_chain(a_ledger_request("/api/v1/admin/audit/range?from=1&to=3"))
            .status,
        200
    );
}

/// Both of the unit's own answers about a chain read put it on the read side, and the plane's row
/// agrees — the same three-table check the ledger views get, for the same reason.
///
/// The rung matters more here than anywhere else on the surface: these three exist so that somebody
/// who does NOT trust the node can check it, and a full-scope gate would mean the only party who
/// can read the evidence is the party the evidence is about.
#[test]
#[cfg(feature = "root-admin")]
fn a_chain_read_is_read_only_in_every_table_that_has_an_opinion() {
    for path in AUDIT_PATHS {
        let row = busbar_core_admin::admin_codec::verbs::resolve("GET", path)
            .unwrap_or_else(|| panic!("{path} is not in the plane's table"));
        assert!(
            row.read_only,
            "{path} is not read-only in the plane's table"
        );
        assert_eq!(
            row.op_class(),
            busbar_contract::ids::OpClassId::new("admin_read")
        );

        let verb = kernel_verb(&row).unwrap_or_else(|| panic!("{path} names no kernel verb"));
        assert!(AUDIT_VERBS.contains(&verb), "{path} is not an audit verb");
        assert_eq!(
            busbar_core_admin::required_scope(verb),
            busbar_core_admin::required_scope(KernelVerb::GetAudit),
            "{path} does not require what the legacy /audit read requires"
        );
        assert_eq!(
            mutation_class(verb),
            MutationClass::Forbidden,
            "{path} would spend a mutation slot per read"
        );
        assert_eq!(
            busbar_kernel::admin::scope::admin_required_scope("GET", path),
            Scope::ReadOnly
        );
    }
}

/// THE JOIN BETWEEN THE TWO SPELLINGS IS TOTAL, and nothing in it resolves to an empty name.
///
/// Every row of the closed table that is joined by NAME reaches a kernel verb, and every 1.6.0
/// kernel verb has a name. The `_ => ""` arm this file used to carry meant a row nobody named
/// resolved to the empty string, matched no verb, and refused — which is how the three chain reads
/// shipped resolving and answering nothing. The compiler enforces the agreement now
/// (`crates/busbar-core-admin/src/admin_codec/verbs.rs`, the `const` assertions); this is the
/// behavioural half of it, over the function the live path actually calls.
#[test]
#[cfg(feature = "root-admin")]
fn every_1_6_0_row_names_a_kernel_verb_and_no_name_is_empty() {
    for verb in NEW_VERBS
        .iter()
        .chain(LEDGER_VERBS.iter())
        .chain(AUDIT_VERBS.iter())
    {
        let name = busbar_core_admin::verb_name(*verb)
            .unwrap_or_else(|| panic!("{verb:?} has no name, so no row can ever reach it"));
        assert!(!name.is_empty(), "{verb:?} names the empty string");
        let row = busbar_core_admin::admin_codec::verbs::table()
            .into_iter()
            .find(|row| row.verb == name)
            .unwrap_or_else(|| panic!("{verb:?} ({name}) has no row in the closed table"));
        assert_eq!(
            kernel_verb(&row),
            Some(*verb),
            "{name} resolves to a different verb than the one that names it"
        );
    }
    // The CONTROL: a legacy verb is deliberately NOT joined by name, and says so with `None` rather
    // than with an empty string. It still resolves — by method and path, which is the stronger join.
    assert_eq!(busbar_core_admin::verb_name(KernelVerb::GetAudit), None);
    assert_eq!(
        kernel_verb(
            &busbar_core_admin::admin_codec::verbs::resolve("GET", "/api/v1/admin/audit")
                .expect("the legacy audit read is in the table")
        ),
        Some(KernelVerb::GetAudit)
    );
}

/// THE LEDGER VIEWS ARE DESCRIBED IN THE ONE DOCUMENT, and their own document path serves it.
///
/// There used to be a side-car document here, hand-maintained so the served one's bytes need not
/// move. It is gone (owner ruling Q41, items 45/46): the served document is generated from the code,
/// and `GET /ledger/openapi.json` answers with exactly its bytes. What the side-car's test proved
/// still has to hold of the one document — every ledger view is described, under the method the
/// table declares, at the scope it is served at, with the table's own verb as its operationId — and
/// the views are still NEW surface: none of their paths is in the pinned 1.5.5 document.
#[cfg(feature = "root-admin")]
#[test]
fn the_ledger_document_path_serves_the_one_document_and_it_describes_the_views() {
    let answer = answer_over_seeded_ledger(a_ledger_request("/api/v1/admin/ledger/openapi.json"));
    assert_eq!(answer.status, 200);
    let served = String::from_utf8(answer.body).expect("the document is text");
    assert_eq!(
        served,
        busbar_core_admin::v1::json::openapi_document(),
        "the ledger's document path must serve the one generated document, byte for byte"
    );
    let document: serde_json::Value = serde_json::from_str(&served).expect("it is JSON");
    let paths = document["paths"].as_object().expect("it declares paths");
    assert!(
        paths.contains_key("/api/v1/admin/usage"),
        "the ledger path serves a document that is not the administrative one"
    );

    for path in LEDGER_PATHS {
        let op = &paths
            .get(*path)
            .unwrap_or_else(|| panic!("{path} is served and in no document"))["get"];
        assert!(
            op.is_object(),
            "{path} is described under a method the table does not declare"
        );
        assert_eq!(
            op["x-busbar-required-scope"], "read-only",
            "{path} is documented at a scope it is not served at"
        );
        let operation_id = op["operationId"].as_str().expect("an operationId");
        let verb = busbar_core_admin::admin_codec::verbs::resolve("GET", path)
            .expect("the table declares it")
            .verb;
        assert_eq!(
            snake_of(operation_id),
            verb,
            "{path}: the document's operationId is not the table's verb"
        );
    }

    let pinned: serde_json::Value = serde_json::from_str(include_str!(concat!(
        env!("BUSBAR_CORE_DIR"),
        "/../../testing/shadow-oracle/fixtures/openapi-1.5.5.json"
    )))
    .expect("the pinned fixture is JSON");
    let pinned_paths = pinned["paths"].as_object().expect("it declares paths");
    assert!(
        !pinned_paths
            .keys()
            .any(|p| p.starts_with("/api/v1/admin/ledger/")),
        "the ledger views are 1.6.0 surface; the pinned 1.5.5 document must not carry them"
    );
}

/// `GetLedgerTotals` -> `get_ledger_totals`, so the test above can compute the expected verb
/// name rather than hand-transcribing a second copy of the five-row mapping.
#[cfg(feature = "root-admin")]
fn snake_of(operation_id: &str) -> String {
    let mut out = String::new();
    for (i, c) in operation_id.chars().enumerate() {
        if c.is_uppercase() {
            if i != 0 {
                out.push('_');
            }
            out.extend(c.to_lowercase());
        } else {
            out.push(c);
        }
    }
    out
}

/// A string a deployment configured is escaped on the way out, so a name holding a quote cannot
/// end the document early and hand a reader a different one from the one this rendered.
#[test]
fn a_configured_name_cannot_break_out_of_the_document() {
    use crate::root::units_admin::{LedgerRow, PricedLedger, RefusedRow};

    let hostile = "a\"b\\c\nd\te\u{1}";
    let ledger = PricedLedger {
        rows: vec![LedgerRow {
            bucket: hostile.to_string(),
            day: A_DAY,
            priced_nanos: 1_000,
            fee_count: 0,
        }],
        refused: vec![RefusedRow {
            bucket: hostile.to_string(),
            day: A_DAY,
            refusal: hostile.to_string(),
        }],
    };
    let parsed: serde_json::Value =
        serde_json::from_str(&render_totals(&ledger).expect("projects"))
            .expect("a hostile name still renders JSON");
    assert_eq!(parsed["rows"][0]["bucket"], hostile);
    assert_eq!(parsed["refused"][0]["bucket"], hostile);
    assert_eq!(parsed["refused"][0]["refusal"], hostile);
}

// ── D38 `amend_rate_history` — the money-path verb's effect half ──────────────────────────────────

/// A history seeded with one opening card, effective from instant zero.
#[cfg(test)]
fn a_seeded_history() -> crate::root::kernel::RootHistory {
    let history = crate::root::kernel::RootHistory::default();
    let opening = busbar_kernel_ledger::cost::RateCard::from_micro_rates(
        [(
            busbar_kernel_ledger::cost::LaneClass::new(
                "gpt",
                busbar_kernel_ledger::cost::CLASS_INPUT,
            ),
            2.0,
        )],
        0,
    );
    history.apply(opening, 1_000);
    history
}

/// A correction body as a caller sends it: plain JSON. `amend_rate_history` is a plain scoped verb
/// (#77(9), OWNER-LOCKED), so nothing about the body is signed.
#[cfg(test)]
fn a_body(body: serde_json::Value) -> Vec<u8> {
    serde_json::to_vec(&body).expect("the correction serialises")
}

/// A memory-buffered book, as a node with no data directory has.
#[cfg(test)]
fn a_memory_book() -> Arc<Mutex<crate::root::durability::Durability>> {
    Arc::new(Mutex::new(
        crate::root::durability::build(
            &crate::root::durability::DurabilityConfig { data_dir: None },
            Box::new(busbar_kernel_wal::NullShipper::new()),
        )
        .expect("a memory-buffered journal cannot fail to open"),
    ))
}

/// The amendment journal over `book`, under a durability token minted the way the kernel mints one.
#[cfg(test)]
fn a_journal_over(book: &Arc<Mutex<crate::root::durability::Durability>>) -> AmendmentJournal {
    AmendmentJournal::new(
        Arc::clone(book),
        busbar_kernel::test_support::tokens::grant::<busbar_contract::caps::DurableWrite>(),
    )
}

/// The attribution a production call carries: the admin principal.
#[cfg(test)]
fn an_attribution() -> AmendAttribution {
    AmendAttribution {
        principal: "admin".to_string(),
    }
}

/// Run the effect with a durable amendment journal bound, as production binds one.
#[cfg(test)]
fn amend_through_a_journal(
    history: &crate::root::kernel::RootHistory,
    body: &[u8],
    arrival_secs: u64,
) -> Result<AdminAnswer, busbar_core_admin::GovernanceError> {
    let book = a_memory_book();
    amend_rate_history_effect(
        history,
        Some(&a_journal_over(&book)),
        body,
        arrival_secs,
        &an_attribution(),
    )
}

/// The Policy-class amendment records a book's journal replays.
#[cfg(test)]
fn replayed_amendments(durability: &crate::root::durability::Durability) -> Vec<AmendmentRecord> {
    durability
        .journal
        .replay()
        .expect("the journal reads back")
        .expect("the journal verifies")
        .iter()
        .filter(|r| r.class == busbar_kernel_wal::RecordClass::Policy)
        .map(|r| amendment_from_body(&r.body).expect("a Policy record is an amendment"))
        .collect()
}

/// A well-formed correction body: a back-dated amendment of the `gpt`/`input` rate over a bounded
/// window. No signer and no signature (#77(9)).
#[cfg(test)]
fn a_correction_body() -> Vec<u8> {
    a_body(serde_json::json!({
        "effective_from": 0,
        "effective_until": 86_400_000,
        "rates": [ { "lane": "gpt", "class": "input", "micro_per_unit": 1.0 } ],
        "reason": "vendor corrected the March price sheet",
    }))
}

/// THE HAPPY PATH, AND THE PROOF IT REWRITES NOTHING. An amendment appends a signed, back-dated
/// entry that out-ranks the one it corrects for the window it names — and the corrected entry, and
/// every snapshot taken before the amendment, is byte-for-byte what it was. A bill already sent
/// re-derives unchanged; only a recompute against the new head moves.
#[test]
fn amend_rate_history_appends_a_signed_back_dated_correction_and_rewrites_nothing() {
    let history = a_seeded_history();
    let instant = 5_000u64;

    // Before: the opening entry (seq 0) prices the instant.
    let before = history.pin().expect("the opening pinned");
    let (before_seq, _) = before
        .view()
        .card_at(instant)
        .expect("the opening prices the instant");
    assert_eq!(before_seq, busbar_kernel_ledger::cost::HistorySeq(0));

    // The correction applies, arriving at second 6 (→ 6000 ms).
    let answer =
        amend_through_a_journal(&history, &a_correction_body(), 6).expect("the correction applies");
    assert_eq!(answer.status, 200);
    let doc: serde_json::Value = serde_json::from_slice(&answer.body).expect("the answer is JSON");
    assert_eq!(doc["history_seq"], 1);
    assert_eq!(doc["effective_from"], 0);
    assert_eq!(doc["effective_until"], 86_400_000);
    assert_eq!(doc["amended_at"], 6_000);
    assert!(
        doc.get("operator_fingerprint").is_none(),
        "the answer names no signer: {doc}"
    );
    assert!(
        doc["reason_sha256"].as_str().is_some_and(|s| s.len() == 64),
        "the reason is sealed as its 32-byte SHA-256, hex-encoded"
    );

    // After: exactly one entry was appended, and the opening entry is untouched.
    assert_eq!(history.len(), 2);
    let after = history.pin().expect("pinned after");
    let view = after.view();
    let entries = view.entries();
    assert_eq!(entries[0].seq(), busbar_kernel_ledger::cost::HistorySeq(0));
    assert_eq!(entries[0].effective_from(), 0);
    assert!(matches!(
        entries[0].author(),
        busbar_kernel_ledger::cost::Author::Config { .. }
    ));
    // The correction out-ranks the opening for the window it covers.
    let (now_seq, _) = view
        .card_at(instant)
        .expect("the correction prices the instant");
    assert_eq!(now_seq, busbar_kernel_ledger::cost::HistorySeq(1));
    assert!(
        matches!(
            entries[1].author(),
            busbar_kernel_ledger::cost::Author::Amend { .. }
        ),
        "the appended entry must be an amendment, got {:?}",
        entries[1].author()
    );

    // AN INVOICE CUT BEFORE THE AMENDMENT RE-DERIVES UNCHANGED: an older snapshot never sees the
    // correction, so money already booked stays booked.
    let old = crate::root::kernel::PinnedHistory::for_test_at(
        &after,
        busbar_kernel_ledger::cost::HistorySeq(0),
    );
    let (old_seq, _) = old
        .view()
        .card_at(instant)
        .expect("the old snapshot still prices the instant");
    assert_eq!(old_seq, busbar_kernel_ledger::cost::HistorySeq(0));
}

/// **A CORRECTION THAT NAMES A DENOMINATION IS REFUSED, NOT IGNORED** (#66 `BUSBAR-1.6.0.md:528`,
/// owner-locked: money is UNITLESS abstract cost, no currency type and no symbol).
///
/// THE DEFECT THIS CLOSES. `amend_rate_history` used to read a `currency` key off the correction
/// body into an ISO-4217 code, and that code decided a ROUNDING SCALE: `"JPY"` moved the divisor
/// from ten million nano-units per minor unit to a billion, so the SAME `micro_per_unit` figures on
/// a corrected card became a hundred times different money — with no conversion, no restatement,
/// and nothing on the sealed amendment record to say the scale had moved. Every other card in the
/// tree was built at one hardcoded scale; this one body could move it.
///
/// **REFUSED, NOT ACCEPTED-AND-IGNORED**, which is the whole point. Tolerating the key and quietly
/// pricing at the one scale would leave a caller believing it had asked for yen and been given yen,
/// which is the same defect with a longer fuse. A body written against a contract this node does not
/// honour is refused at the shape, before it can touch the history — and a refusal appends nothing.
///
/// Every spelling refuses, including the ones a "just validate it" reading would let through: a
/// code the old table knew, a code it did not, the node's own former default, and `null`.
#[test]
fn amend_rate_history_refuses_a_correction_that_names_a_currency() {
    for named in [
        serde_json::json!("JPY"),
        serde_json::json!("USD"),
        serde_json::json!("nonsense"),
        serde_json::json!(null),
    ] {
        let history = a_seeded_history();
        let body = a_body(serde_json::json!({
            "effective_from": 0,
            "effective_until": 86_400_000,
            "currency": named,
            "rates": [ { "lane": "gpt", "class": "input", "micro_per_unit": 1.0 } ],
            "reason": "vendor corrected the March price sheet",
        }));
        let err = amend_through_a_journal(&history, &body, 6)
            .expect_err("a correction naming a currency must be refused");
        assert!(
            matches!(err, busbar_core_admin::GovernanceError::Validation),
            "a correction naming {named} must refuse Validation, got {err:?}"
        );
        assert_eq!(
            history.len(),
            1,
            "a refused correction appends nothing: {named}"
        );
    }

    // THE CONTROL: the same body WITHOUT the key applies. Without this arm a rule that refused
    // every correction would satisfy the assertions above.
    let history = a_seeded_history();
    amend_through_a_journal(&history, &a_correction_body(), 6)
        .expect("the same correction with no `currency` key applies");
    assert_eq!(history.len(), 2);
}

/// **THE SIGNED PAYLOAD CANNOT COVER A KEY NOTHING CAN SEND.** `currency` is gone from the canonical
/// amend payload's fixed key order, so the bytes an operator signs are the bytes this seam verifies
/// and neither carries a denomination. A payload that still rendered `currency=null` would be a
/// field in the signature for a field the shape refuses.
#[test]
fn the_canonical_amend_payload_names_no_currency() {
    let body = serde_json::json!({
        "effective_from": 0,
        "effective_until": 86_400_000,
        "rates": [ { "lane": "gpt", "class": "input", "micro_per_unit": 1.0 } ],
        "reason": "vendor corrected the March price sheet",
    });
    let payload = canonical_amend_payload(body.as_object().expect("an object"));
    let text = String::from_utf8(payload).expect("the payload is text");
    assert!(
        !text.contains("currency"),
        "the signed payload still names a currency: {text}"
    );
    // The domain separator and every field that IS signed are still there, in order.
    assert!(text.starts_with("busbar/amend-rate-history/v1\n"), "{text}");
    for key in [
        "effective_from=",
        "effective_until=",
        "per_request_fee=",
        "reason=",
        "rates=",
    ] {
        assert!(text.contains(key), "the payload dropped {key}: {text}");
    }
}

/// **A NEGATIVE FEE IS REFUSED AT THE SIGNING DOOR, NEVER SEALED AND CLAMPED** (item 29 — a RATECARD
/// fault).
///
/// THE DEFECT THIS CLOSES. `per_request_fee` was read with `as_i64` and handed straight to the card
/// constructor, whose `max(0)` clamp turned `-5` into `0`. So an operator-signed correction whose
/// signature covers `per_request_fee=-5` was appended to the append-only history as a card charging
/// `0` — a sealed entry whose figure is not the figure its signer signed, and a window silently
/// repriced to free. A fee below zero is not a price; it is refused before the history is touched.
///
/// The body is validly SIGNED, so the refusal is the fee rule and not the signature seam.
#[test]
fn amend_rate_history_refuses_a_negative_fee_and_appends_nothing() {
    for fee in [-1_i64, -5, i64::MIN] {
        let history = a_seeded_history();
        let body = a_body(serde_json::json!({
            "effective_from": 0,
            "effective_until": 86_400_000,
            "per_request_fee": fee,
            "rates": [ { "lane": "gpt", "class": "input", "micro_per_unit": 1.0 } ],
            "reason": "vendor corrected the March price sheet",
        }));
        let err = amend_through_a_journal(&history, &body, 6)
            .expect_err("a correction carrying a negative fee must be refused");
        assert!(
            matches!(err, busbar_core_admin::GovernanceError::Validation),
            "fee {fee} must refuse Validation, got {err:?}"
        );
        assert_eq!(history.len(), 1, "a refused fee {fee} appends nothing");
    }

    // THE CONTROL: the same signed shape with a fee of 5 applies, and the card it seals charges
    // exactly 5 — the figure signed is the figure sealed. Zero is a legitimate explicit fee too.
    for fee in [5_i64, 0] {
        let history = a_seeded_history();
        let body = a_body(serde_json::json!({
            "effective_from": 0,
            "effective_until": 86_400_000,
            "per_request_fee": fee,
            "rates": [ { "lane": "gpt", "class": "input", "micro_per_unit": 1.0 } ],
            "reason": "vendor corrected the March price sheet",
        }));
        amend_through_a_journal(&history, &body, 6).expect("a non-negative fee applies");
        assert_eq!(history.len(), 2);
        let pinned = history.pin().expect("pinned");
        let view = pinned.view();
        let (_, card) = view
            .card_at(5_000)
            .expect("the correction prices its window");
        assert_eq!(card.fee(), fee, "the sealed fee is the signed fee");
    }
}

/// A history whose opening card prices two flat lanes, a flat fee of 3 and the `plane-b` plane's own
/// card — the shape a correction of one cell must leave standing everywhere it does not name.
#[cfg(test)]
fn a_full_card_history() -> crate::root::kernel::RootHistory {
    use busbar_kernel_ledger::cost::TierRates;
    let history = crate::root::kernel::RootHistory::default();
    let card = busbar_kernel_ledger::cost::RateCard::from_config(
        Some([
            (
                "gpt",
                TierRates {
                    input: busbar_kernel_ledger::cost::representable_nano_rate(2.0),
                    output: busbar_kernel_ledger::cost::representable_nano_rate(8.0),
                    cache_read: busbar_kernel_ledger::cost::representable_nano_rate(0.5),
                    cache_write: busbar_kernel_ledger::cost::representable_nano_rate(2.5),
                },
            ),
            (
                "claude",
                TierRates {
                    input: busbar_kernel_ledger::cost::representable_nano_rate(3.0),
                    output: busbar_kernel_ledger::cost::representable_nano_rate(15.0),
                    cache_read: busbar_kernel_ledger::cost::representable_nano_rate(0.3),
                    cache_write: busbar_kernel_ledger::cost::representable_nano_rate(3.75),
                },
            ),
            (
                "plane-b\u{1f}search",
                TierRates {
                    input: busbar_kernel_ledger::cost::representable_nano_rate(5.0),
                    output: busbar_kernel_ledger::cost::representable_nano_rate(6.0),
                    cache_read: busbar_kernel_ledger::cost::representable_nano_rate(0.0),
                    cache_write: busbar_kernel_ledger::cost::representable_nano_rate(0.0),
                },
            ),
        ]),
        3,
    );
    history.apply(card, 1_000);
    history
}

/// The nano-units one row prices at, at `at`, on `history`'s head.
#[cfg(test)]
fn priced_at(
    history: &crate::root::kernel::RootHistory,
    lane: &str,
    class: &str,
    count: u64,
    fee_count: u64,
    at: u64,
) -> Result<u128, busbar_kernel_ledger::cost::MoneyError> {
    use busbar_kernel_ledger::cost::{nanos_of_exact, whole, Tally, STANDARD_TIER_BP};
    let pinned = history.pin().expect("a history");
    let mut tally = Tally::in_view(pinned.view());
    tally.row(
        lane,
        at,
        STANDARD_TIER_BP,
        [(class, whole(count))],
        whole(fee_count),
    )?;
    nanos_of_exact(tally.exact()?)
}

/// **A CORRECTION OF ONE CELL REPRICES THAT CELL AND NOTHING ELSE** (#79 "a
/// correction reprices exactly its window", #42 "never a silent 0", #44).
///
/// THE DEFECT THIS CLOSES. The corrected card was built from the cells the body named ALONE, with
/// the fee defaulting to 0, and it out-ranked the whole card for its window: correcting `gpt`/`input`
/// priced every request's fee at 0, refused `gpt`/`output` and every `claude` class (a served unit
/// turned into a refusal), and priced every `plane-b` row at 0 (no plane card on the correction). The
/// corrected card is now the card in force with the named cell set.
#[test]
fn a_correction_of_one_cell_keeps_every_other_price_and_the_fee() {
    let history = a_full_card_history();
    let inside = 5_000;
    let outside = 100_000_000;
    // The configured figures, read outside the window, before and after.
    let configured = |history: &crate::root::kernel::RootHistory, lane: &str, class: &str| {
        priced_at(history, lane, class, 1_000, 1, outside).expect("the configured card prices it")
    };
    let gpt_output = configured(&history, "gpt", "output");
    let claude_input = configured(&history, "claude", "input");
    let plane_b_input = configured(&history, "plane-b\u{1f}search", "input");

    amend_through_a_journal(&history, &a_correction_body(), 6).expect("the correction applies");

    // THE NAMED CELL MOVES: 1,000 units at 1 micro-unit (1,000 nano-units) plus the fee of 3 minor
    // units (30,000,000 nano-units).
    assert_eq!(
        priced_at(&history, "gpt", "input", 1_000, 1, inside).expect("the corrected cell prices"),
        1_000_000 + 30_000_000,
        "the corrected rate and the configured fee"
    );
    // EVERY OTHER CELL, THE FEE AND THE OTHER PLANE ARE PRICED AS CONFIGURED INSIDE THE WINDOW.
    for (lane, class, want) in [
        ("gpt", "output", gpt_output),
        ("claude", "input", claude_input),
        ("plane-b\u{1f}search", "input", plane_b_input),
    ] {
        assert_eq!(
            priced_at(&history, lane, class, 1_000, 1, inside),
            Ok(want),
            "{lane}/{class} inside the corrected window prices at the configured card, fee included"
        );
    }
    assert_eq!(
        configured(&history, "gpt", "input"),
        2_000_000 + 30_000_000,
        "outside the window the configured card still prices the corrected cell"
    );
}

/// **A CORRECTION NAMING A FEE MOVES THE FEE AND KEEPS EVERY RATE** (D-1), and one naming a cell on a
/// plane prices that plane's card, not the flat card.
#[test]
fn a_fee_or_plane_correction_moves_only_what_it_names() {
    let history = a_full_card_history();
    let body = a_body(serde_json::json!({
        "effective_from": 0,
        "effective_until": 86_400_000,
        "per_request_fee": 7,
        "rates": [ { "lane": "plane-b\u{1f}search", "class": "input", "micro_per_unit": 9.0 } ],
        "reason": "vendor corrected the March price sheet",
    }));
    amend_through_a_journal(&history, &body, 6).expect("the correction applies");
    assert_eq!(
        priced_at(&history, "gpt", "output", 1_000, 1, 5_000),
        Ok(8_000_000 + 70_000_000),
        "gpt/output keeps its configured rate; the fee is the corrected 7"
    );
    assert_eq!(
        priced_at(&history, "plane-b\u{1f}search", "input", 1_000, 0, 5_000),
        Ok(9_000_000),
        "the plane's own cell is corrected"
    );
    assert_eq!(
        priced_at(&history, "plane-b\u{1f}search", "output", 1_000, 0, 5_000),
        Ok(6_000_000),
        "the plane's other cell is kept"
    );
}

/// One card pricing `gpt` input at `micro_per_unit`, with the flat fee `fee_minor`.
fn a_card_at(micro_per_unit: f64, fee_minor: i64) -> busbar_kernel_ledger::cost::RateCard {
    busbar_kernel_ledger::cost::RateCard::from_micro_rates(
        [(
            busbar_kernel_ledger::cost::LaneClass::new(
                "gpt",
                busbar_kernel_ledger::cost::CLASS_INPUT,
            ),
            micro_per_unit,
        )],
        fee_minor,
    )
}

/// **A CORRECTION NO SINGLE CARD PRICES IS REFUSED, AND APPENDS NOTHING** (D-1). A config apply at
/// 6,000 resolves part of `[0, 86,400,000)`; correcting the card in force at 0 for the whole
/// window would silently revert that apply for the rest of it. A cell on a plane whose billing is
/// off has no card to land on: correcting it would switch the plane's billing on and refuse every
/// class the correction is silent about.
#[test]
fn a_correction_across_a_card_boundary_or_onto_an_absent_plane_is_refused() {
    let history = a_full_card_history();
    history.apply(a_card_at(4.0, 0), 6_000);
    let before = history.len();
    let refused = amend_through_a_journal(&history, &a_correction_body(), 7);
    assert!(
        matches!(refused, Err(busbar_core_admin::GovernanceError::Validation)),
        "{refused:?}"
    );
    assert_eq!(
        history.len(),
        before,
        "a refused correction appends nothing"
    );

    let history = a_full_card_history();
    let body = a_body(serde_json::json!({
        "effective_from": 0,
        "effective_until": 86_400_000,
        "rates": [ { "lane": "plane-c\u{1f}hop", "class": "bytes", "micro_per_unit": 1.0 } ],
        "reason": "vendor corrected the March price sheet",
    }));
    let refused = amend_through_a_journal(&history, &body, 6);
    assert!(
        matches!(refused, Err(busbar_core_admin::GovernanceError::Validation)),
        "{refused:?}"
    );
    assert_eq!(history.len(), 1, "a refused correction appends nothing");
}

/// One UTC day and one hour, in milliseconds: a metering row is one day per price era (#32).
#[cfg(test)]
const DAY_MS: u64 = 86_400_000;
#[cfg(test)]
const HOUR_MS: u64 = 3_600_000;

/// A signed correction of `gpt`/`input` over `[from, until)`.
#[cfg(test)]
fn a_window_correction(from: u64, until: Option<u64>) -> Vec<u8> {
    a_body(serde_json::json!({
        "effective_from": from,
        "effective_until": until,
        "rates": [ { "lane": "gpt", "class": "input", "micro_per_unit": 1.0 } ],
        "reason": "vendor corrected the March price sheet",
    }))
}

/// Run one correction over `history` arriving at `arrival_ms`, answering the effect's result and how
/// many amendment records its journal took.
#[cfg(test)]
fn amend_at(
    history: &crate::root::kernel::RootHistory,
    body: &[u8],
    arrival_ms: u64,
) -> (
    Result<AdminAnswer, busbar_core_admin::GovernanceError>,
    usize,
) {
    let book = a_memory_book();
    let result = amend_rate_history_effect(
        history,
        Some(&a_journal_over(&book)),
        body,
        arrival_ms / 1_000,
        &an_attribution(),
    );
    let records = replayed_amendments(&book.lock().unwrap()).len();
    (result, records)
}

/// **A RETROACTIVE RATE CORRECTION THAT WOULD CUT INSIDE A STORED ROW IS REFUSED** (OWNER
/// ruling #32, 2026-09-29: "a retroactive RATE correction that would cut inside a stored row is
/// refused").
///
/// A metering row is one UTC day per price era, priced at its own first instant. Before this
/// refusal a correction `[day 1 12:00, 18:00)` answered 200 and repriced nothing (the day-1 row
/// resolves at 00:00, outside the window); `[day 1 00:00, 06:00)` repriced the WHOLE day; and a
/// window over a midnight (`[day 2 12:00, day 3 06:00)`, signed on day 2) priced every unit after
/// 06:00 on day 3 at the correction, because they accrue into the day-3 row of the card the window
/// interrupts, which resolves at day 3 00:00 — inside the window. Each is refused now, and nothing
/// is recorded or appended.
#[test]
fn a_correction_that_would_cut_inside_a_stored_row_is_refused() {
    let arrival = 2 * DAY_MS + 10 * HOUR_MS;
    for (from, until) in [
        (DAY_MS + 12 * HOUR_MS, Some(DAY_MS + 18 * HOUR_MS)),
        (DAY_MS, Some(DAY_MS + 6 * HOUR_MS)),
        (DAY_MS + 12 * HOUR_MS, None),
        (2 * DAY_MS + 12 * HOUR_MS, Some(3 * DAY_MS + 6 * HOUR_MS)),
    ] {
        let history = a_seeded_history();
        let (result, records) = amend_at(&history, &a_window_correction(from, until), arrival);
        assert!(
            matches!(result, Err(busbar_core_admin::GovernanceError::Validation)),
            "[{from}, {until:?}) cuts inside a row and must be refused: {result:?}"
        );
        assert_eq!(history.len(), 1, "[{from}, {until:?}): nothing appended");
        assert_eq!(records, 0, "[{from}, {until:?}): nothing recorded");
    }
}

/// THE CONTROLS FOR #32: a correction whose boundaries every row already splits at applies — whole
/// UTC days, an open end, and the instant a config apply started a new price era (every unit from it
/// on accrued under that era). A window that opens after the arrival is not a correction at all:
/// [`a_future_dated_correction_is_refused_and_appends_nothing`].
#[test]
fn a_correction_on_row_boundaries_applies() {
    let arrival = 2 * DAY_MS + 10 * HOUR_MS;
    for (from, until) in [
        (DAY_MS, Some(2 * DAY_MS)),
        (DAY_MS, None),
        (0, Some(3 * DAY_MS)),
    ] {
        let history = a_seeded_history();
        let (result, records) = amend_at(&history, &a_window_correction(from, until), arrival);
        assert!(
            result.is_ok(),
            "[{from}, {until:?}) cuts no row: {result:?}"
        );
        assert_eq!((history.len(), records), (2, 1), "[{from}, {until:?})");
    }

    let era = DAY_MS + 12 * HOUR_MS;
    let history = a_seeded_history();
    history.apply(a_card_at(4.0, 0), era);
    let (result, _) = amend_at(
        &history,
        &a_window_correction(era, Some(2 * DAY_MS)),
        arrival,
    );
    assert!(
        result.is_ok(),
        "a correction from the instant a config apply opened an era cuts no row: {result:?}"
    );
}

/// **A CORRECTION IS BACK-DATED OR IT IS REFUSED** (#79: a correction is "an entry whose
/// `effective_from` lies in the past"). A signed window that opens after the call arrived prices a
/// future no booked line has reached: a forward price under an amendment's signature, standing in
/// for a configuration write. Refused at the shape, and nothing is recorded or appended — including a
/// window of whole future days and one inside one future day, both of which cut no row and applied
/// before this refusal. The control: the whole-day window, arriving after it closed, applies.
#[test]
fn a_future_dated_correction_is_refused_and_appends_nothing() {
    let arrival = 2 * DAY_MS + 10 * HOUR_MS;
    let future = (3 * DAY_MS, Some(4 * DAY_MS));
    for (from, until) in [
        future,
        (2 * DAY_MS + 12 * HOUR_MS, Some(2 * DAY_MS + 18 * HOUR_MS)),
        (2 * DAY_MS + 10 * HOUR_MS + 1_000, None),
    ] {
        let history = a_seeded_history();
        let (result, records) = amend_at(&history, &a_window_correction(from, until), arrival);
        assert!(
            matches!(result, Err(busbar_core_admin::GovernanceError::Validation)),
            "[{from}, {until:?}) opens after the arrival at {arrival} and must be refused: {result:?}"
        );
        assert_eq!(history.len(), 1, "[{from}, {until:?}): nothing appended");
        assert_eq!(records, 0, "[{from}, {until:?}): nothing recorded");
    }

    let history = a_seeded_history();
    let (result, records) = amend_at(
        &history,
        &a_window_correction(future.0, future.1),
        4 * DAY_MS + HOUR_MS,
    );
    assert!(
        result.is_ok(),
        "the same window, once past, applies: {result:?}"
    );
    assert_eq!((history.len(), records), (2, 1));
}

/// **A SIGNED CORRECTION APPLIES ONCE**. The signature covers the window, the figures and
/// the reason, and nothing that tells one submission from the next, so the same signed bytes sent
/// again after a later correction would put the earlier price back with no new operator act. The
/// replay is refused `Conflict`, nothing is recorded and nothing appended, and the later correction
/// still prices the window.
#[test]
fn a_replayed_signed_correction_is_refused_and_appends_nothing() {
    let book = a_memory_book();
    let journal = a_journal_over(&book);
    let history = a_seeded_history();
    let first = a_priced_correction(5, serde_json::json!(1.5));
    let apply = |body: &[u8], arrival_secs: u64| {
        amend_rate_history_effect(
            &history,
            Some(&journal),
            body,
            arrival_secs,
            &an_attribution(),
        )
    };
    apply(&first, 6).expect("the first correction applies");
    apply(&a_priced_correction(9, serde_json::json!(3.0)), 7)
        .expect("a later correction of the same window applies");
    assert_eq!(history.len(), 3);

    let replayed = apply(&first, 8);
    assert!(
        matches!(replayed, Err(busbar_core_admin::GovernanceError::Conflict)),
        "the first correction's signed bytes, sent again, must be refused: {replayed:?}"
    );
    assert_eq!(history.len(), 3, "a replay appends nothing");
    assert_eq!(
        replayed_amendments(&book.lock().unwrap()).len(),
        2,
        "a replay records nothing"
    );
    let pinned = history.pin().expect("pinned");
    let view = pinned.view();
    let (seq, card) = view.card_at(1_000).expect("the window is priced");
    assert_eq!(seq, busbar_kernel_ledger::cost::HistorySeq(2));
    assert_eq!(
        card.fee(),
        9,
        "the later correction still prices the window"
    );
}

/// A scratch data directory, removed on drop.
#[cfg(test)]
struct AmendScratch(std::path::PathBuf);

#[cfg(test)]
impl AmendScratch {
    fn new(tag: &str) -> Self {
        let path = std::env::temp_dir().join(format!(
            "busbar-amend-journal-{tag}-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&path);
        std::fs::create_dir_all(&path).expect("scratch directory");
        AmendScratch(path)
    }

    fn book(&self) -> Arc<Mutex<crate::root::durability::Durability>> {
        Arc::new(Mutex::new(
            crate::root::durability::build(
                &crate::root::durability::DurabilityConfig {
                    data_dir: Some(self.0.clone()),
                },
                Box::new(busbar_kernel_wal::NullShipper::new()),
            )
            .expect("the directory is writable"),
        ))
    }
}

#[cfg(test)]
impl Drop for AmendScratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// A signed correction with a fee and one rate, so the record has figures to carry.
#[cfg(test)]
fn a_priced_correction(fee: i64, micro: serde_json::Value) -> Vec<u8> {
    a_body(serde_json::json!({
        "effective_from": 0,
        "effective_until": 86_400_000,
        "per_request_fee": fee,
        "rates": [ { "lane": "gpt", "class": "input", "micro_per_unit": micro } ],
        "reason": "vendor corrected the March price sheet",
    }))
}

/// **A SEALED AMENDMENT IS RECORDED DURABLY, WITH ITS FIGURES, AND SURVIVES A RESTART** (item 30).
///
/// THE DEFECT THIS CLOSES. The only trail an amendment left was the root's legacy admin ring — a
/// volatile thousand entries behind `NoSeam`, four strings (action, path, outcome, principal) and no
/// figure. One restart erased it. The record now goes onto the node's journal: after the book is
/// dropped and reopened over the same data directory, the amendment is there with the window, the
/// sealed fee and rate, the submitter and the canonical bytes of the correction; the signer and
/// signature slots are empty (#77(9)).
#[test]
fn a_sealed_amendment_survives_a_restart_with_its_figures() {
    let scratch = AmendScratch::new("restart");
    {
        let book = scratch.book();
        let history = a_seeded_history();
        amend_rate_history_effect(
            &history,
            Some(&a_journal_over(&book)),
            &a_priced_correction(5, serde_json::json!(1.5)),
            6,
            &an_attribution(),
        )
        .expect("the correction applies");
    }

    // RESTART: a fresh book over the same directory.
    let restarted = scratch.book();
    let records = replayed_amendments(&restarted.lock().unwrap());
    assert_eq!(records.len(), 1, "the amendment survived the restart");
    let record = &records[0];
    assert_eq!(record.effective_from, 0);
    assert_eq!(record.effective_until, Some(86_400_000));
    assert_eq!(record.amended_at_ms, 6_000);
    assert_eq!(record.sealed_fee, 5);
    assert_eq!(
        record.rates,
        vec![("gpt".to_string(), "input".to_string(), Some(1_500))],
        "1.5 micro per unit is sealed as 1500 nano per unit"
    );
    assert_eq!(record.operator_fingerprint, "");
    assert_eq!(record.principal, "admin");
    assert_eq!(record.dual_control, "single");
    assert_eq!(record.signature, "");
    assert!(
        record
            .signed_payload
            .starts_with(b"busbar/amend-rate-history/v1\n"),
        "the record keeps the correction's canonical bytes"
    );
}

/// **A CORRECTION'S RATE BECOMES THE CARD'S INTEGER EXACTLY, OR IS REFUSED** (architect ruling
/// 2026-09-24, no-float-money).
///
/// The wire keeps the decimal micro-units-per-unit form (1.5.5's rate card took its rates as
/// decimals); the edge turns it into integer nano-units by shifting decimal digits, never by float
/// arithmetic. A figure the card can hold exactly is sealed as exactly that integer. A figure finer
/// than one nano-unit used to be ROUNDED (half away from zero) or, below the half-nano quantum,
/// sealed as an UNPRICED cell under a signature that covered a price — a card that was not the card
/// its signer signed. It is now refused, and nothing is appended to the history or the journal.
#[test]
fn a_correction_rate_is_sealed_as_an_exact_integer_or_refused() {
    for (micro, nanos) in [
        (serde_json::json!(1.5), 1_500),
        (serde_json::json!(0.001), 1),
        (serde_json::json!(2e-3), 2),
        (serde_json::json!(7), 7_000),
        (serde_json::json!(0.0), 0),
    ] {
        let scratch = AmendScratch::new("exact-rate");
        let book = scratch.book();
        amend_rate_history_effect(
            &a_seeded_history(),
            Some(&a_journal_over(&book)),
            &a_priced_correction(0, micro.clone()),
            6,
            &an_attribution(),
        )
        .unwrap_or_else(|e| panic!("{micro} is exactly {nanos} nano-units: {e:?}"));
        let records = replayed_amendments(&book.lock().unwrap());
        assert_eq!(
            records[0].rates,
            vec![("gpt".to_string(), "input".to_string(), Some(nanos))],
            "{micro} micro per unit is sealed as exactly {nanos} nano per unit"
        );
    }
    for micro in [
        serde_json::json!(0.0001),
        serde_json::json!(0.0015),
        serde_json::json!(-1.0),
        serde_json::json!(1e30),
        serde_json::json!("1.5"),
    ] {
        let scratch = AmendScratch::new("inexact-rate");
        let book = scratch.book();
        let history = a_seeded_history();
        let before = history.history().expect("a history").len();
        let refused = amend_rate_history_effect(
            &history,
            Some(&a_journal_over(&book)),
            &a_priced_correction(0, micro.clone()),
            6,
            &an_attribution(),
        );
        assert!(
            matches!(refused, Err(busbar_core_admin::GovernanceError::Validation)),
            "{micro} is not an exact integer of nano-units and must be refused: {refused:?}"
        );
        assert_eq!(
            history.history().expect("a history").len(),
            before,
            "{micro}: a refused correction appends nothing to the history"
        );
        assert!(
            replayed_amendments(&book.lock().unwrap()).is_empty(),
            "{micro}: a refused correction journals nothing"
        );
    }
}

/// **VOLUME DOES NOT ERASE AN AMENDMENT** (item 30). The legacy ring prunes at a thousand entries;
/// the journal prunes nothing. After the first amendment, a thousand more are sealed and the book is
/// restarted — the first is still there, first, with its own figures.
#[test]
fn a_thousand_later_amendments_do_not_erase_the_first() {
    let scratch = AmendScratch::new("volume");
    {
        let book = scratch.book();
        let journal = a_journal_over(&book);
        let history = a_seeded_history();
        amend_rate_history_effect(
            &history,
            Some(&journal),
            &a_priced_correction(7, serde_json::json!(2.0)),
            6,
            &an_attribution(),
        )
        .expect("the first correction applies");
        // A thousand DIFFERENT corrections: the same signed body twice is a replay and is refused,
        // so each later one moves the fee.
        for fee in 8..1_008 {
            amend_rate_history_effect(
                &history,
                Some(&journal),
                &a_priced_correction(fee, serde_json::json!(1.0)),
                7,
                &an_attribution(),
            )
            .expect("a later correction applies");
        }
    }
    let restarted = scratch.book();
    let records = replayed_amendments(&restarted.lock().unwrap());
    assert_eq!(records.len(), 1_001, "every amendment is on the journal");
    assert_eq!(
        records[0].sealed_fee, 7,
        "the first amendment is still first"
    );
    assert_eq!(
        records[0].rates,
        vec![("gpt".to_string(), "input".to_string(), Some(2_000))]
    );
    assert_eq!(records[0].amended_at_ms, 6_000);
}

/// **NO DURABLE RECORD, NO AMENDMENT.** With no journal bound the correction is refused (`Store`)
/// and the history is untouched — a correction nothing recorded never prices a window.
#[test]
fn an_amendment_with_no_journal_bound_is_refused_and_appends_nothing() {
    let history = a_seeded_history();
    let err = amend_rate_history_effect(&history, None, &a_correction_body(), 6, &an_attribution())
        .expect_err("no journal, no amendment");
    assert!(matches!(err, busbar_core_admin::GovernanceError::Store));
    assert_eq!(history.len(), 1);

    // THE CONTROL: the same body with a journal applies and leaves exactly one record.
    let book = a_memory_book();
    amend_rate_history_effect(
        &history,
        Some(&a_journal_over(&book)),
        &a_correction_body(),
        6,
        &an_attribution(),
    )
    .expect("with a journal the correction applies");
    assert_eq!(history.len(), 2);
    assert_eq!(replayed_amendments(&book.lock().unwrap()).len(), 1);
}

/// A refused correction leaves no durable record: a negative fee is refused before the journal is
/// written.
#[test]
fn a_refused_amendment_leaves_no_record() {
    let book = a_memory_book();
    let history = a_seeded_history();
    amend_rate_history_effect(
        &history,
        Some(&a_journal_over(&book)),
        &a_priced_correction(-5, serde_json::json!(1.0)),
        6,
        &an_attribution(),
    )
    .expect_err("refused");
    assert_eq!(history.len(), 1);
    assert!(replayed_amendments(&book.lock().unwrap()).is_empty());
}

/// VALIDATION REFUSALS. Every malformed or empty correction is refused at its shape, before it can
/// touch the history — and each leaves the history exactly as it was.
#[test]
fn amend_rate_history_refuses_a_correction_that_names_no_reason_window_or_price() {
    let cases: &[serde_json::Value] = &[
        // No reason.
        serde_json::json!({ "effective_from": 1, "rates": [{"lane":"gpt","class":"input","micro_per_unit":1.0}] }),
        // Inverted window.
        serde_json::json!({ "effective_from": 9, "effective_until": 1, "rates": [{"lane":"gpt","class":"input","micro_per_unit":1.0}], "reason": "r" }),
        // Corrects no price: no rates and no fee.
        serde_json::json!({ "effective_from": 1, "reason": "r" }),
        // Missing effective_from.
        serde_json::json!({ "rates": [{"lane":"gpt","class":"input","micro_per_unit":1.0}], "reason": "r" }),
    ];
    for case in cases {
        let history = a_seeded_history();
        let body = serde_json::to_vec(case).expect("serialises");
        let err = amend_through_a_journal(&history, &body, 6)
            .expect_err("a malformed correction must be refused");
        assert!(
            matches!(err, busbar_core_admin::GovernanceError::Validation),
            "{case} must refuse Validation, got {err:?}"
        );
        assert_eq!(
            history.len(),
            1,
            "a refused correction appends nothing: {case}"
        );
    }
    // A body that is not JSON at all is also a validation refusal.
    let history = a_seeded_history();
    assert!(matches!(
        amend_through_a_journal(&history, b"not json", 6),
        Err(busbar_core_admin::GovernanceError::Validation)
    ));
    assert_eq!(history.len(), 1);
}

/// A history with no opening entry has nothing to correct: the correction is refused `NotFound`
/// rather than sealing a card no configuration ever wrote.
#[test]
fn amend_rate_history_refuses_when_there_is_no_history_to_amend() {
    let empty = crate::root::kernel::RootHistory::default();
    let err = amend_through_a_journal(&empty, &a_correction_body(), 6)
        .expect_err("an empty history cannot be amended");
    assert!(matches!(err, busbar_core_admin::GovernanceError::NotFound));
    assert_eq!(empty.len(), 0);
}

// ── #77(9): a plain scoped verb, no operator signature ─────────────────────────────────────────────

/// A CORRECTION WITH NO SIGNATURE APPLIES (#77(9), OWNER-LOCKED, `docs/design/BUSBAR-1.6.0.md`
/// l.2279: "no verb carries dual control, escrow or operator signatures"). The body names no
/// `signature` and no `operator_fingerprint`; it is applied, answered 200, and the answer names no
/// signer. RED before the fix: the effect refused
/// it `Validation` at the shape (no signer, no signature) and, with no sealed operator key, at the
/// verify seam.
#[test]
fn amend_rate_history_applies_a_correction_that_carries_no_signature() {
    let history = a_seeded_history();
    let body = a_correction_body();
    let doc: serde_json::Value = serde_json::from_slice(&body).expect("the body is JSON");
    assert!(doc.get("signature").is_none() && doc.get("operator_fingerprint").is_none());
    let answer =
        amend_through_a_journal(&history, &body, 6).expect("an unsigned correction applies");
    assert_eq!(answer.status, 200);
    let doc: serde_json::Value = serde_json::from_slice(&answer.body).expect("JSON");
    assert!(
        doc.get("operator_fingerprint").is_none(),
        "the answer names no signer: {doc}"
    );
    assert_eq!(history.len(), 2, "the correction appended one entry");
}

/// A body that still names `signature` / `operator_fingerprint` (a caller written against the
/// earlier draft) has them IGNORED like any other member the verb does not read: the correction
/// applies exactly as the same body without them, and nothing it named reaches the record.
#[test]
fn amend_rate_history_ignores_a_signature_a_body_still_carries() {
    let history = a_seeded_history();
    let mut doc: serde_json::Value =
        serde_json::from_slice(&a_correction_body()).expect("the body is JSON");
    doc["operator_fingerprint"] = serde_json::json!("a-fingerprint-nothing-checks");
    doc["signature"] = serde_json::json!("00".repeat(64));
    let answer = amend_through_a_journal(&history, &a_body(doc), 6)
        .expect("a body carrying a stale signature still applies");
    let doc: serde_json::Value = serde_json::from_slice(&answer.body).expect("JSON");
    assert!(
        doc.get("operator_fingerprint").is_none(),
        "the answer names no signer: {doc}"
    );
}

/// THE DEPLOYMENT KEYSET IS WHAT `/audit/keys` PUBLISHES (spec #82(a)(b); BUSBAR-1.6.0.md THE DESIGN, §2,
/// PB-13; architect ruling 2026-09-26): a node bound to its keyset seals a SIGNED record, and it
/// verifies against the key the served read publishes — parsed off the wire, not handed over
/// in-process. RED arm: the same node before the keyset is bound publishes no key and seals the
/// record unsigned.
#[cfg(feature = "root-admin")]
#[test]
fn a_signed_record_verifies_against_the_served_audit_keys() {
    use busbar_contract::caps::{OriginKind, Outcome as UnitOutcome, UnitKey};
    use busbar_kernel_audit::{
        Audit as _, AuditChain, AuditInputs, AuditVerifyingKey, Controls, FinishClass, OpClassId,
        OutcomeFacts, Subject, Usage, What,
    };

    let inputs = || AuditInputs {
        subject: Subject::PrincipalId("pseudonym-keyset".into()),
        what: What {
            unit_key: UnitKey::new(1),
            incarnation: 0,
            op_class: OpClassId::new("chat.completion"),
            destination: Some("upstream-a".into()),
            parent: None,
            pre_hook_head: None,
            post_hook_head: None,
        },
        wall: 1_700_000_001,
        mono: 1_000,
        origin: crate::root::kernel::new_kernel().origin(OriginKind::Client),
        outcome: OutcomeFacts {
            unit_end: UnitOutcome::Completed,
            step: None,
            finish: FinishClass::Complete,
            hook_failed: false,
            emission_delta: 0,
            stale_policy: false,
        },
        usage: Usage {
            lines: Vec::new(),
            tier_bp: 10_000,
            fee_count: 1,
            rate_card_version: 1,
            bucket_chain_ref: "chain:free".into(),
        },
        controls: Controls::default(),
        correlation_label: None,
    };
    let audit_token = an_audit_pass();
    let served_keys = |units: crate::root::kernel::ProductionUnits| -> Vec<String> {
        let node = AdminNode::new(crate::root::kernel::new_kernel(), units);
        let served: serde_json::Value = serde_json::from_slice(
            &node
                .answer(a_ledger_request("/api/v1/admin/audit/keys"))
                .body,
        )
        .expect("valid JSON");
        served["keys"]
            .as_array()
            .expect("keys")
            .iter()
            .map(|k| k["public_key"].as_str().expect("public_key").to_string())
            .collect()
    };

    // RED ARM: no keyset bound — nothing published, the record unsigned.
    let units =
        crate::root::kernel::ProductionUnits::admin_only(Arc::new(AnsweringDispatch), open_door());
    let record = {
        let mut durability = units.durability.lock().expect("durability lock");
        durability.record.seal(inputs(), &audit_token)
    };
    assert!(
        served_keys(units).is_empty(),
        "a keyless node publishes no key"
    );
    assert!(record.signature.is_none());

    // THE KEYSET BOUND, as the boot binds it.
    let units =
        crate::root::kernel::ProductionUnits::admin_only(Arc::new(AnsweringDispatch), open_door());
    let record = {
        let mut durability = units.durability.lock().expect("durability lock");
        crate::root::keyset::bind_ephemeral(&mut durability).expect("the keyset binds");
        durability.record.seal(inputs(), &audit_token)
    };
    let published = served_keys(units);
    assert_eq!(published.len(), 1, "the one deployment key is published");
    let key = AuditVerifyingKey::from_hex(&published[0]).expect("a published public key");
    assert_eq!(record.key_id.as_deref(), Some(key.key_id()));
    AuditChain::verify_signature(&record, &key)
        .expect("the signed record verifies against the served key");
}

// ---------------------------------------------------------------------------------------------
// H3 (ARCHITECT 2026-10-07 ruling (d)): THE DURABLE VERBS OVER A JOURNAL THE STORE KEEPS
// ---------------------------------------------------------------------------------------------

/// A book with no data directory whose journal is kept by `slots`, as the production boot builds
/// one over the configured store.
#[cfg(test)]
fn a_book_over_the_store(
    slots: &crate::root::store_double::RecordSlots,
) -> Arc<Mutex<crate::root::durability::Durability>> {
    let lane = crate::root::durability::JournalLane::start(slots.calls(), "test-store")
        .expect("the lane starts");
    Arc::new(Mutex::new(
        crate::root::durability::build_on_store(
            &crate::root::durability::DurabilityConfig { data_dir: None },
            0,
            lane,
            None,
        )
        .expect("the store reads back"),
    ))
}

/// The status and body of an admin answer.
#[cfg(test)]
fn status_and_body(answer: &AdminAnswer) -> (u16, String) {
    (
        answer.status,
        String::from_utf8_lossy(&answer.body).into_owned(),
    )
}

/// **A SIGNED BACK-DATED CORRECTION SURVIVES A RESTART ON A NODE WITH NO DATA DIRECTORY**
/// (ARCHITECT 2026-10-07 H3 ruling (a), (b), (d)): `amend_rate_history` answers 200 only once the
/// store acknowledged its record, and a fresh book over the same store reads the amendment back,
/// figures and all.
///
/// RED before the fix: the journal shipped to the store adapter's shim, which acknowledged and kept
/// a count — the verb answered 200 and the restarted book held no amendment.
#[test]
fn a_correction_on_a_node_with_no_data_dir_is_kept_by_the_store_and_survives_a_restart() {
    let slots = crate::root::store_double::RecordSlots::new();
    {
        let book = a_book_over_the_store(&slots);
        let answered = amend_rate_history_effect(
            &a_seeded_history(),
            Some(&a_journal_over(&book)),
            &a_priced_correction(5, serde_json::json!(1.5)),
            6,
            &an_attribution(),
        )
        .expect("the correction applies");
        let (status, body) = status_and_body(&answered);
        assert_eq!(status, 200, "{body}");
    }
    let restarted = a_book_over_the_store(&slots);
    let records = replayed_amendments(&restarted.lock().unwrap());
    assert_eq!(
        records.len(),
        1,
        "the store kept the amendment and the restart read it back"
    );
    assert_eq!(records[0].sealed_fee, 5);
}

/// **A STORE THAT REFUSES THE RECORD REFUSES THE VERB** (ARCHITECT 2026-10-07 H3 ruling (d)):
/// `amend_rate_history` answers 503 with the store's reason, never 200 over a record nothing kept.
///
/// RED before the fix: the verb answered 200.
#[test]
fn a_correction_the_store_refuses_answers_503_with_the_reason() {
    let slots = crate::root::store_double::RecordSlots::new();
    slots.refuse(true);
    let book = a_book_over_the_store(&slots);
    let answered = amend_rate_history_effect(
        &a_seeded_history(),
        Some(&a_journal_over(&book)),
        &a_priced_correction(5, serde_json::json!(1.5)),
        6,
        &an_attribution(),
    )
    .expect("an answer, not an error");
    let (status, body) = status_and_body(&answered);
    assert_eq!(status, 503, "{body}");
    assert!(
        body.contains("the test store refuses writes"),
        "the store's reason is stated: {body}"
    );
    // A second correction while the store still refuses records nothing at all.
    let before = book.lock().unwrap().journal.next_seq();
    let again = amend_rate_history_effect(
        &a_seeded_history(),
        Some(&a_journal_over(&book)),
        &a_priced_correction(6, serde_json::json!(2)),
        7,
        &an_attribution(),
    )
    .expect("an answer");
    assert_eq!(status_and_body(&again).0, 503);
    assert_eq!(
        book.lock().unwrap().journal.next_seq(),
        before,
        "nothing is recorded while the store refuses"
    );
}

/// **`commit_upgrade` OVER A STORE THAT REFUSES ANSWERS 503** with the reason ("a commit nothing
/// recorded did not happen"), and 200 over a store that takes it (ARCHITECT 2026-10-07 H3 ruling
/// (d)).
///
/// RED before the fix: 200 over the refusing store.
#[test]
fn commit_upgrade_answers_only_once_the_store_kept_its_record() {
    let body = serde_json::to_vec(&serde_json::json!({ "version": bound::RUNNING_RELEASE }))
        .expect("json");

    let refusing = crate::root::store_double::RecordSlots::new();
    refusing.refuse(true);
    let book = a_book_over_the_store(&refusing);
    let answer =
        bound::commit_upgrade_effect(&body, 1_700_000_000, "admin", Some(&a_journal_over(&book)))
            .expect("an answer");
    assert_eq!(
        answer.status,
        503,
        "{}",
        String::from_utf8_lossy(&answer.body)
    );
    assert!(String::from_utf8_lossy(&answer.body).contains("the test store refuses writes"));

    let taking = crate::root::store_double::RecordSlots::new();
    let book = a_book_over_the_store(&taking);
    let answer =
        bound::commit_upgrade_effect(&body, 1_700_000_000, "admin", Some(&a_journal_over(&book)))
            .expect("an answer");
    assert_eq!(
        answer.status,
        200,
        "{}",
        String::from_utf8_lossy(&answer.body)
    );
    assert!(taking.rows_under(crate::root::durability::JOURNAL_SCHEMA) >= 1);
}

/// A store whose answer the test flips: refusing, a memory-buffered journal over it chains every
/// record, retains the refused batch and offers it again ahead of the next append (`busbar-kernel-wal`
/// `Journal::append`, `Wal::append_batch`); answering, the retained batch lands.
#[cfg(test)]
struct SwitchShipper(Arc<std::sync::atomic::AtomicBool>);

#[cfg(test)]
impl busbar_kernel_wal::Shipper<busbar_kernel_wal::Record> for SwitchShipper {
    fn ship(
        &mut self,
        _records: &[busbar_kernel_wal::Record],
    ) -> Result<(), busbar_kernel_wal::ShipError> {
        if self.0.load(std::sync::atomic::Ordering::SeqCst) {
            return Err(busbar_kernel_wal::ShipError::Unavailable(
                "the store is not answering".into(),
            ));
        }
        Ok(())
    }
}

/// A memory-buffered book whose store refuses while `refusing` holds (opened while it answers).
#[cfg(test)]
fn a_book_whose_store_switches(
    refusing: &Arc<std::sync::atomic::AtomicBool>,
) -> Arc<Mutex<crate::root::durability::Durability>> {
    Arc::new(Mutex::new(
        crate::root::durability::build(
            &crate::root::durability::DurabilityConfig { data_dir: None },
            Box::new(SwitchShipper(Arc::clone(refusing))),
        )
        .expect("a memory-buffered journal cannot fail to open"),
    ))
}

/// Put one record that is not a `Policy` record on `book`'s journal, as the next posting would.
#[cfg(test)]
fn append_the_next_record(book: &Arc<Mutex<crate::root::durability::Durability>>) {
    book.lock()
        .unwrap()
        .journal
        .append(
            &busbar_kernel::test_support::tokens::grant::<busbar_contract::caps::DurableWrite>(),
            busbar_contract::caps::StepName::Meter,
            &[
                busbar_kernel_wal::Entry::new(busbar_kernel_wal::RecordClass::Load, vec![1])
                    .at(7, 0),
            ],
        )
        .expect("the store answers again and the next record lands");
}

/// **A CORRECTION WHOSE RECORD THE JOURNAL CHAINED AND RETAINED IS IN FORCE, AND ANSWERED "SEALED,
/// NOT YET KEPT"** (audit root r4 B-7). The journal chains a record before the log is asked to take
/// it, and a log that could not make it durable retains it and writes it ahead of the next append —
/// so the record reaches the chain a restart rebuilds the dated history from. #79
/// (`docs/design/BUSBAR-1.6.0.md` l.2282: a correction is "an appended, journaled, dated entry")
/// makes the history the chain holds the history in force: the live node must price the correction
/// from the moment its record is chained, and answer `503` "do not re-submit" until it is kept
/// (ARCHITECT 2026-10-07 H3 ruling (d)). Re-sending it is then refused: it is already applied.
///
/// RED before the fix: the journal's `DurabilityLost` was answered `Store` and the history left
/// untouched — then the retained record landed with the next append, and a restart repriced the
/// window by a correction the operator was told had failed.
#[test]
fn a_correction_the_journal_retained_is_in_force_and_answered_not_yet_kept() {
    let refusing = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let book = a_book_whose_store_switches(&refusing);
    refusing.store(true, std::sync::atomic::Ordering::SeqCst);
    let history = a_seeded_history();
    let answered = amend_rate_history_effect(
        &history,
        Some(&a_journal_over(&book)),
        &a_priced_correction(5, serde_json::json!(1.5)),
        6,
        &an_attribution(),
    )
    .expect("a correction the journal chained is answered, never refused as unrecorded");
    let (status, body) = status_and_body(&answered);
    assert_eq!(status, 503, "{body}");
    assert!(body.contains("do not re-submit"), "{body}");
    assert_eq!(
        history.len(),
        2,
        "the correction is in force on the live node from the moment its record is chained"
    );

    refusing.store(false, std::sync::atomic::Ordering::SeqCst);
    append_the_next_record(&book);
    assert_eq!(
        replayed_amendments(&book.lock().unwrap()).len(),
        1,
        "the retained record landed on the chain a restart rebuilds the history from"
    );
    assert!(
        matches!(
            amend_rate_history_effect(
                &history,
                Some(&a_journal_over(&book)),
                &a_priced_correction(5, serde_json::json!(1.5)),
                7,
                &an_attribution(),
            ),
            Err(busbar_core_admin::GovernanceError::Conflict)
        ),
        "a re-submission is refused: the correction is already applied"
    );
    assert_eq!(history.len(), 2);
}

/// **A COMMIT WHOSE RECORD THE JOURNAL CHAINED AND RETAINED IS ANSWERED "SEALED, NOT YET KEPT"**
/// (audit root r4 B-7): `commit_upgrade` answers `503` "do not re-submit" (ARCHITECT 2026-10-07 H3
/// ruling (d)), never a refusal of a commit whose record still reaches the chain.
///
/// RED before the fix: the journal's `DurabilityLost` was answered `Store` (a commit nothing
/// recorded) while the retained record landed with the next append.
#[test]
fn a_commit_the_journal_retained_is_answered_not_yet_kept_and_lands() {
    let refusing = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let book = a_book_whose_store_switches(&refusing);
    refusing.store(true, std::sync::atomic::Ordering::SeqCst);
    let body = serde_json::to_vec(&serde_json::json!({ "version": bound::RUNNING_RELEASE }))
        .expect("json");
    let answer =
        bound::commit_upgrade_effect(&body, 1_700_000_000, "admin", Some(&a_journal_over(&book)))
            .expect("a commit the journal chained is answered, never refused as unrecorded");
    let text = String::from_utf8_lossy(&answer.body).into_owned();
    assert_eq!(answer.status, 503, "{text}");
    assert!(text.contains("do not re-submit"), "{text}");

    refusing.store(false, std::sync::atomic::Ordering::SeqCst);
    append_the_next_record(&book);
    let commits = book
        .lock()
        .unwrap()
        .journal
        .replay()
        .expect("the journal reads back")
        .expect("the journal verifies")
        .iter()
        .filter(|r| r.class == busbar_kernel_wal::RecordClass::Policy)
        .count();
    assert_eq!(commits, 1, "the retained commit landed on the chain");
}

/// ROUTE IS FAIL-CLOSED ON AN ABSENT GRANT (audit root-R1 M7).
///
/// Approve records the caller's grant before Route reads it, and refuses a caller holding none. A
/// unit that reaches Route with no grant on record has skipped that step, and the answer is a
/// refusal: Route used to read the endpoint's own required scope in its place, which is the grant
/// the caller would have needed and not one it holds.
#[test]
#[cfg(feature = "root-admin")]
fn route_refuses_a_unit_whose_grant_was_never_recorded() {
    let admin = crate::root::kernel::new_kernel().admin_token();
    let binding = AdminBinding::new(Arc::new(AnsweringDispatch), open_door());
    let mut request = a_request();
    request.method = "POST".to_string();
    request.path = "/api/v1/admin/chain-break".to_string();
    let mut walk = AdminWalk::new(request);
    decode(&mut walk).expect("the plane's table declares this operation");
    // No grant: the Approve step never ran for this unit.
    let outcome = route(&binding, None, &admin, &mut walk);
    assert_eq!(
        outcome,
        Err(ReasonCode::ScopeDenied),
        "a unit with no recorded grant reached the verb"
    );
}

/// **A KEYED WRITE RETRIED AFTER A RESTART REPLAYS ITS FIRST ANSWER AND RUNS NOTHING AGAIN.**
/// Contract D-3's replay cache is process memory; the claim and the first answer are kept in the
/// configured store. A fresh cache over the same store (a restart, or a sibling node) answers the
/// first answer's bytes, and the effect runs once.
///
/// RED while the claim lived only in the process: the second cache ran the effect again.
#[test]
fn a_keyed_write_retried_after_a_restart_replays_and_runs_nothing_again() {
    let store: Arc<dyn busbar_contract::records::RecordStore> =
        Arc::new(busbar_kernel::governance::MemoryStore::new());
    let held = Arc::clone(&store);
    let replay_store: bound::ReplayStore = Arc::new(move || Some(Arc::clone(&held)));
    let request = AdminRequest {
        method: "POST".to_string(),
        path: "/api/v1/admin/plane-records".to_string(),
        credential: None,
        headers: vec![("idempotency-key".to_string(), "restart-d3".to_string())],
        body: br#"{"record":1}"#.to_vec(),
        at: 1_700_000_000,
        unit: a_fresh_unit(),
    };
    let ran = std::sync::atomic::AtomicUsize::new(0);
    let effect = || {
        let n = ran.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        Ok(AdminAnswer {
            status: 201,
            headers: vec![("content-type".to_string(), "application/json".to_string())],
            body: format!(r#"{{"run":{n}}}"#).into_bytes(),
        })
    };
    let first = bound::replayable(
        &bound::ReplayCache::new(),
        Some(&replay_store),
        KernelVerb::PlaneRecordWrite,
        "operator",
        &request,
        &request.body,
        effect,
    )
    .expect("the first write answers");
    // The restart: a fresh cache, the same store.
    let retried = bound::replayable(
        &bound::ReplayCache::new(),
        Some(&replay_store),
        KernelVerb::PlaneRecordWrite,
        "operator",
        &request,
        &request.body,
        effect,
    )
    .expect("the retry answers");
    assert_eq!(retried, first, "the retry answers the first answer's bytes");
    assert_eq!(
        ran.load(std::sync::atomic::Ordering::SeqCst),
        1,
        "the effect ran once across the restart"
    );
}

/// A REQUEST THE ADMIN PLANE DID NOT COMPOSE IS NEVER SEALED AS AN ADMIN READ (regression guard
/// for 8fb8a1f9ba).
///
/// The bug: a unit that no admin row claimed reached the root's audit door and was sealed under the
/// admin plane's word for a verb that never resolved, `admin_read`, so the record said an operator
/// read a page when no administrative operation was involved. With the steps called directly there
/// is no shared audit door any more; what decides whether an admin record is sealed is the mount's
/// claim. So this drives the mount itself: a path outside the admin prefix, and a path inside it that
/// no row declares, go to the surface below and leave NO record on the node's book, while a declared
/// admin read leaves exactly one, under `admin_read`.
#[cfg(feature = "root-admin")]
#[tokio::test]
async fn a_unit_this_root_did_not_compose_is_not_sealed_as_an_admin_read() {
    use tower::ServiceExt;

    let inner = axum::Router::new().fallback(axum::routing::any(|| async { "the surface" }));
    let book: Arc<std::sync::OnceLock<Arc<Mutex<crate::root::durability::Durability>>>> =
        Arc::new(std::sync::OnceLock::new());
    let kept = Arc::clone(&book);
    let wrapped = mount(
        inner,
        busbar_kernel::teller::Kernel::new(),
        1024,
        move |dispatch| {
            let units = crate::root::kernel::ProductionUnits::admin_only(dispatch, open_door());
            let _ = kept.set(Arc::clone(&units.durability));
            units
        },
    );
    let book = Arc::clone(book.get().expect("the mount built its units"));
    let sealed = || {
        let mut held = Vec::new();
        NodeAudit::new(Arc::clone(&book)).read(&mut |_, records| {
            held = records.map(<[_]>::to_vec).unwrap_or_default();
        });
        held
    };
    let get = |path: &str| {
        axum::http::Request::builder()
            .method("GET")
            .uri(path)
            .body(axum::body::Body::empty())
            .expect("the request builds")
    };
    let admin_read = busbar_kernel_audit::OpClassId::new(OP_UNRESOLVED_READ);

    for uncomposed in ["/v1/chat/completions", "/api/v1/admin/not-a-real-operation"] {
        let response = wrapped
            .clone()
            .oneshot(get(uncomposed))
            .await
            .expect("the router answers");
        let records = sealed();
        assert!(
            records.iter().all(|r| r.what.op_class != admin_read),
            "{uncomposed} was sealed as an administrative read: {records:?}"
        );
        assert!(
            records.is_empty(),
            "{uncomposed} is no admin unit and seals no admin record: {records:?}"
        );
        assert_eq!(
            response.status(),
            200,
            "{uncomposed} reached the surface below"
        );
    }

    // The positive control: a declared admin read is one unit, sealed once, as a read.
    let response = wrapped
        .oneshot(get("/api/v1/admin/audit?limit=4"))
        .await
        .expect("the router answers");
    assert_eq!(response.status(), 200);
    let records = sealed();
    assert_eq!(records.len(), 1, "one declared admin unit, one record");
    assert_eq!(records[0].what.op_class, admin_read);
}

/// A LENGTH THE REQUEST CLAIMS IS CHECKED AGAINST THE BYTES, NEVER TRUSTED (regression guard for
/// e9fbbd4d55).
///
/// The bug: the root's answer framing reserved room for the header count a frame declared before
/// reading a single header, so four bytes off the wire could ask for gigabytes. That framing is gone;
/// the admin input a caller controls now is the request itself, and the same invariant holds there:
/// what the request says about its own size is a claim, and the wrap reads no more than the
/// operator's cap whatever the claim. A request that declares a length inside the cap and then sends
/// more is refused, not read to its end and executed.
#[cfg(feature = "root-admin")]
#[tokio::test]
async fn a_claimed_length_is_checked_against_the_bytes_not_trusted() {
    use tower::ServiceExt;

    let inner = axum::Router::new().fallback(axum::routing::any(|| async { "the surface" }));
    let wrapped = mount(inner, busbar_kernel::teller::Kernel::new(), 4, |dispatch| {
        crate::root::kernel::ProductionUnits::admin_only(dispatch, open_door())
    });
    let request = axum::http::Request::builder()
        .method("POST")
        .uri("/api/v1/admin/keys")
        .header(axum::http::header::CONTENT_LENGTH, "3")
        .body(axum::body::Body::from(b"0123456789".to_vec()))
        .expect("the request builds");
    let response = wrapped.oneshot(request).await.expect("the router answers");
    assert_eq!(
        response.status(),
        400,
        "a body longer than the cap is refused whatever length it declared"
    );
}
