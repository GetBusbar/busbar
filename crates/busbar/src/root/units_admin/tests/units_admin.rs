//! Tests for `units_admin.rs`. Lifted out of the implementation file so its line count
//! measures implementation and nothing else; still a direct child module, so `use
//! super::*` reaches the private items it always did.

use super::*;
use crate::root::unit_views::UnitCtx;

/// The legacy ring binds no clock of its own; a pinned one keeps records comparable.
#[derive(Debug)]
struct PinnedClock;
impl busbar_unit_audit::Clock for PinnedClock {
    fn now(&self) -> u64 {
        1_700_000_000
    }
}

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
        env!("CARGO_MANIFEST_DIR"),
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

/// The round trip is the whole reason the answer travels as bytes: a status, a header value and
/// a body all come back exactly as they went in, including bytes a text framing would mangle.
#[test]
fn an_answer_survives_the_round_trip_through_the_verbs_seam() {
    let answer = AdminAnswer {
        status: 409,
        headers: vec![
            ("etag".to_string(), "\"7\"".to_string()),
            ("content-type".to_string(), "application/json".to_string()),
        ],
        body: vec![0x00, 0xff, b'{', b'}', 0x0a],
    };
    let packed = answer.pack();
    assert_eq!(AdminAnswer::unpack(&packed), Some(answer));
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
    busbar_core::admin::restart::drain_released_at_exit();
    let unit = a_fresh_unit();
    // The operation's body asks, from inside its own unit, exactly as the restart handler does.
    busbar_core::admin::restart::UnitDrain::of_unit(unit)
        .scoping(async {
            busbar_core::admin::restart::begin_drain();
        })
        .await;

    // The future carrying the guard is dropped before anything is written back.
    let exit = ExitPath { unit };
    drop(exit);

    assert!(
        !busbar_core::admin::restart::UnitDrain::of_unit(unit).release(),
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
    let wrapped = mount(
        inner,
        busbar_kernel::teller::Kernel::new(),
        4,
        crate::root::kernel::ProductionUnits::admin_only,
    );

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
#[cfg(feature = "root-admin")]
#[test]
fn a_refused_units_status_is_the_one_its_ending_earned() {
    let status = |reason| answer_for(Outcome::Refused(busbar_caps::StepName::Admit, reason));
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
            busbar_caps::StepName::Route,
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

/// The only producer of the framing is the packer. Anything else is this file being wrong, and
/// a lenient parse would turn that into a silently wrong answer.
#[test]
fn a_shape_the_packer_did_not_write_has_no_answer() {
    assert_eq!(AdminAnswer::unpack(&[]), None);
    assert_eq!(AdminAnswer::unpack(&[0, 200, 0, 0, 0, 1]), None);
    let mut trailing = AdminAnswer {
        status: 200,
        headers: Vec::new(),
        body: Vec::new(),
    }
    .pack();
    trailing.push(0);
    assert_eq!(AdminAnswer::unpack(&trailing), None);
}

/// A count is a claim about bytes that are not there, not an instruction to go and find room
/// for them. The frame below says it carries four billion headers in three bytes: the answer is
/// `None`, and no room is made for the claim on the way to it.
#[test]
fn a_header_count_larger_than_the_frame_is_refused_not_reserved() {
    let mut frame = Vec::new();
    frame.extend_from_slice(&200u16.to_be_bytes());
    frame.extend_from_slice(&u32::MAX.to_be_bytes());
    frame.extend_from_slice(&[0, 0, 0]);
    assert_eq!(AdminAnswer::unpack(&frame), None);

    // What the frame could actually be carrying, not what it says it is.
    assert_eq!(header_capacity(u32::MAX, 3), 0);
    assert_eq!(header_capacity(u32::MAX, 4_096), 512);
    // An honest count is still reserved for in full.
    assert_eq!(header_capacity(2, 4_096), 2);
}

/// A mutation's record names the caller, and never the bytes the caller presented.
///
/// Both doors are walked, because both write a row and either one leaking is the whole leak: the
/// completed mutation and the refused one. The credential in the fixture is deliberately not a
/// substring of the identity, so "the row does not contain the credential" and "the row is the
/// identity" are two independent assertions rather than one restated.
///
/// The chain this writes to is the one an operator's audit page reads and a store persists, so a
/// row carrying a live bearer token publishes it to everybody entitled to read history — a wider
/// set than the set entitled to hold the token.
#[test]
fn a_recorded_mutation_names_the_principal_and_not_the_credential() {
    let seal = busbar_caps::KernelSeal::acquire_for_kernel();
    let binding = AdminBinding::new(Arc::new(RefusingDispatch));

    let rows = |completed: bool| -> Vec<busbar_unit_audit::legacy::AuditEntry> {
        let log = busbar_unit_audit::AuditLog::with(
            Box::new(PinnedClock),
            Box::new(busbar_unit_audit::NoSeam),
        );
        let key = UnitKey::new(1);
        let mut request = a_request();
        request.method = "PUT".to_string();
        request.path = "/api/v1/admin/config/settings".to_string();
        request.credential = Some("sk-live-the-presented-secret".to_string());
        binding.units.open(key, request);
        let ctx = UnitCtx {
            key,
            origin: busbar_caps::OriginKind::Client,
            session: None,
            generation: busbar_kernel::registry::Generation::FIRST,
            admin_listener: true,
            kernel_verb_only: true,
        };
        crate::open_record!(record, &ctx);
        let decode_token: UnitToken<Decode> = UnitToken::mint(&seal);
        let _ = decode(&binding, &decode_token, &record).into_result(&seal);
        let verify_token: UnitToken<Verify> = UnitToken::mint(&seal);
        let _ = verify(
            &binding,
            &verify_token,
            &record,
            &PrincipalId::new("key_operator_7"),
        )
        .into_result(&seal);

        let audit_token: UnitToken<Audit> = UnitToken::mint(&seal);
        if completed {
            let _ = audit(&binding, &log, &audit_token, &record, &Outcome::Completed)
                .into_result(&seal);
        } else {
            let _ = audit_refused(
                &binding,
                &log,
                &audit_token,
                &record,
                &Refusal::new(ReasonCode::ScopeDenied),
            )
            .into_result(&seal);
        }
        binding.units.close(key);
        log.export()
    };

    for completed in [true, false] {
        let entries = rows(completed);
        assert_eq!(entries.len(), 1, "the mutation was not recorded");
        assert_eq!(
            entries[0].principal, "key_operator_7",
            "the record does not name the identity the auth step resolved"
        );
        assert!(
            !entries[0]
                .principal
                .contains("sk-live-the-presented-secret"),
            "the presented credential reached the administrative chain"
        );
    }
}

/// The two money-governance gates are the fleet's, and the route step reads them rather than
/// writing them.
///
/// Three postures over the same step, and each one is a different failure if the seam is not
/// consulted. Under a fleet that sealed dual control, one principal's export is REFUSED — a step
/// that wrote `approved` for itself would let a single operator take the keyset out of a node
/// whose whole reason for sealing the posture was that no single operator can. Under a fleet that
/// HAS run the ceremony, a disaster-recovery verb is ADMITTED — a step that wrote `unset` for
/// itself refused the very operators who ran the ceremony, permanently and with no way to lift
/// it. And a posture the node cannot read at all is refused rather than guessed.
#[test]
#[cfg(feature = "root-admin")]
fn a_money_governance_verb_is_checked_against_the_posture_the_fleet_sealed() {
    struct Sealed(Option<(PostureCtx, ApprovalState)>);
    impl PostureView for Sealed {
        fn resolve(&self, _verb: KernelVerb, _actor: &str) -> Option<(PostureCtx, ApprovalState)> {
            self.0
        }
    }

    let seal = busbar_caps::KernelSeal::acquire_for_kernel();
    let admin = crate::root::kernel::new_kernel().admin_token();

    let under = |path: &str, sealed: Sealed| -> Result<(), ReasonCode> {
        let binding =
            AdminBinding::new(Arc::new(AnsweringDispatch)).with_posture_view(Arc::new(sealed));
        let key = UnitKey::new(1);
        let mut request = a_request();
        request.method = "POST".to_string();
        request.path = path.to_string();
        binding.units.open(key, request);
        let ctx = UnitCtx {
            key,
            origin: busbar_caps::OriginKind::Client,
            session: None,
            generation: busbar_kernel::registry::Generation::FIRST,
            admin_listener: true,
            kernel_verb_only: true,
        };
        crate::open_record!(record, &ctx);
        let decode_token: UnitToken<Decode> = UnitToken::mint(&seal);
        decode(&binding, &decode_token, &record)
            .into_result(&seal)
            .expect("the plane's table declares this operation");
        binding.units.set_granted(key, VerbScope::Full);
        let token: UnitToken<Route> = UnitToken::mint(&seal);
        let outcome = route(
            &binding,
            Arc::new(crate::root::kernel::RefusingStore),
            &admin,
            &token,
            &record,
            &busbar_kernel::teller::AccrualMeter::new(),
        )
        .into_result(&seal);
        binding.units.close(key);
        outcome.map(|_| ()).map_err(|refusal| refusal.reason())
    };

    let required = Sealed(Some((
        PostureCtx {
            operator: busbar_unit_verbs::OperatorState::Unset,
            dual_control: busbar_unit_verbs::DualControl::Required,
        },
        ApprovalState::NotYetApproved,
    )));
    assert!(
        under("/api/v1/admin/export-keyset", required).is_err(),
        "one principal exported the keyset out of a fleet that sealed dual control"
    );

    let ceremony_run = Sealed(Some((
        PostureCtx {
            operator: busbar_unit_verbs::OperatorState::Set,
            dual_control: busbar_unit_verbs::DualControl::Single,
        },
        ApprovalState::NotYetApproved,
    )));
    // The gate is what this cell is about, so the assertion is that the unit got PAST it. It no
    // longer ends `Ok`, and that is the point of the verb reaching the store: the fixture's
    // store refuses everything, so a chain break admitted by the ceremony now ends on the
    // store's own answer rather than on the gate's. What must not appear here is the gate's
    // refusal — that would be a fleet that ran the ceremony being told it had not.
    assert_eq!(
        under("/api/v1/admin/chain-break", ceremony_run),
        Err(ReasonCode::DurabilityUnavailable),
        "a fleet that ran the ceremony was still refused for not having run it"
    );

    assert_eq!(
        under("/api/v1/admin/adjust", Sealed(None)),
        Err(ReasonCode::DecodeFailed),
        "a verb whose posture the node cannot read was admitted under a guessed one"
    );
}

/// The posture a node with no sealed journal is in is the one the design names for a fresh
/// install, and it is that node's TRUE state rather than a permissive default: the ceremony has
/// not run, so the irreducible verbs that need one are still refused.
#[test]
fn an_unsealed_node_reports_the_posture_a_fresh_install_is_actually_in() {
    let (posture, approval) = UnsealedPosture
        .resolve(KernelVerb::Adjust, "admin")
        .expect("a node with no journal knows what it has not sealed");
    assert_eq!(posture.operator, busbar_unit_verbs::OperatorState::Unset);
    assert_eq!(posture.dual_control, busbar_unit_verbs::DualControl::Single);
    assert_eq!(approval, ApprovalState::NotYetApproved);
}

/// Both tables were extracted from the same pinned tag. Every row the plane decodes to has to
/// name a verb the executing unit knows, or the root would be binding an operation to nothing.
#[test]
fn every_row_the_plane_decodes_names_a_verb_the_unit_knows() {
    let mut unmatched = Vec::new();
    for row in busbar_plane_admin::verbs::table() {
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
    let joined = busbar_plane_admin::verbs::table()
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
    let audit = busbar_plane_admin::verbs::resolve("GET", "/api/v1/admin/audit")
        .expect("audit is in the plane's table");
    let row = LEGACY_VERBS
        .iter()
        .find(|row| row.method == "GET" && row.path == "/api/v1/admin/audit")
        .expect("audit is in the unit's table");
    assert_eq!(audit.verb, "get_audit");
    assert_eq!(row.operation_id, "GetAudit");
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
        busbar_unit_scope::admin_required_scope("GET", "/api/v1/admin/audit") == Scope::ReadOnly
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

/// An entry that outlived its unit would be a leak per request. Opening and closing is the whole
/// lifecycle, and the table is empty between requests.
#[test]
fn a_unit_leaves_the_table_when_it_ends() {
    let units = AdminUnits::new();
    let key = UnitKey::new(7);
    assert!(units.is_empty());
    units.open(key, a_request());
    assert_eq!(units.len(), 1);
    assert_eq!(
        units.request(key).map(|r| r.method),
        Some("GET".to_string())
    );
    assert_eq!(units.close(key), None);
    assert!(units.is_empty());
}

/// What the exit path settles for an admin unit: nothing located, no upstream candidate, and
/// therefore no request slot and no flat fee, whatever the deployment configured the fee to be.
#[test]
fn an_admin_unit_settles_at_zero_requests_and_zero_fee() {
    let ctx = UnitCtx {
        key: UnitKey::new(1),
        origin: busbar_caps::OriginKind::Client,
        session: None,
        generation: busbar_kernel::registry::Generation::FIRST,
        admin_listener: true,
        kernel_verb_only: true,
    };
    crate::open_record!(record, &ctx);
    let evidence = evidence(&record);
    assert!(!evidence.upstream_candidate);
    assert_eq!(
        busbar_kernel::teller::requests_drawn(record.origin(), evidence.upstream_candidate),
        0
    );
    assert_eq!(
        busbar_kernel::teller::fee_count(&evidence.fee, record.head()).0,
        0
    );
}

/// The nonce is drawn, not derived. Two draws over the same unit must not agree, or a one-time
/// secret's placeholder would be predictable from the secret it protects.
#[test]
fn two_nonces_over_one_unit_do_not_agree() {
    use busbar_unit_verbs::NonceSource;
    let source = ArrivalNonce(1_700_000_000);
    let mut first = [0u8; 16];
    let mut second = [0u8; 16];
    source.fill(&mut first);
    source.fill(&mut second);
    assert_ne!(first, second);
    assert_ne!(first, [0u8; 16]);
}

/// Both halves of the nonce are drawn, and the second is not the first said again.
///
/// The source it replaced hashed a stack address — the same address on every call from the same
/// frame — and then hashed its own first output to make the second half, so a 128-bit nonce
/// carried at most 64 bits of source and the back half was a function of the front. This walks
/// enough draws that either half repeating, or the two halves agreeing, would show.
///
/// What this cannot assert is unpredictability, which is a property of the SOURCE and not of any
/// finite sample: it is held by reaching the substrate's own operating-system draw — the one a
/// key secret is minted from — rather than by anything checkable here.
#[test]
fn both_halves_of_a_nonce_are_drawn_and_neither_repeats() {
    use busbar_unit_verbs::NonceSource;
    use std::collections::HashSet;

    let source = ArrivalNonce(1_700_000_000);
    let mut fronts = HashSet::new();
    let mut backs = HashSet::new();
    for _ in 0..512 {
        let mut drawn = [0u8; 16];
        source.fill(&mut drawn);
        assert_ne!(drawn, [0u8; 16], "the source handed back nothing");
        assert_ne!(
            drawn[..8],
            drawn[8..],
            "the two halves of one nonce agree, so one of them is the other"
        );
        fronts.insert(drawn[..8].to_vec());
        backs.insert(drawn[8..].to_vec());
    }
    assert_eq!(fronts.len(), 512, "a front half repeated across draws");
    assert_eq!(backs.len(), 512, "a back half repeated across draws");
}

/// The other half of the nonce, and the half a random draw cannot be asserted about: the arrival
/// epoch is what makes two units' nonces distinct, so a source that handed two units the same
/// bytes still cannot make them collide. It touches the first eight bytes and leaves the rest of
/// the material alone, which is what keeps the entropy the entropy.
#[test]
fn the_arrival_epoch_is_what_makes_two_units_nonces_distinct() {
    let material = [7u8; 16];
    assert_ne!(
        mix_arrival(material, 1_700_000_000),
        mix_arrival(material, 1_700_000_001)
    );
    assert_ne!(mix_arrival(material, 1_700_000_000), material);
    assert_eq!(mix_arrival(material, 0), material);
    assert_eq!(mix_arrival(material, u64::MAX)[8..], material[8..]);
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

/// A store that holds one replay slot, so the root's own adapter can be driven over it.
#[derive(Default)]
struct ReplaySlots(Mutex<HashMap<(String, String), Vec<u8>>>);

impl busbar_unit_verbs::store::Store for ReplaySlots {
    fn chain_break(
        &self,
        _admin: &busbar_caps::AdminToken,
    ) -> Result<(), busbar_unit_verbs::StoreError> {
        Ok(())
    }

    fn store_restore(
        &self,
        _admin: &busbar_caps::AdminToken,
        _backup_ref: &str,
    ) -> Result<(), busbar_unit_verbs::StoreError> {
        Ok(())
    }

    fn reseal_epoch_floor(
        &self,
        _admin: &busbar_caps::AdminToken,
    ) -> Result<(), busbar_unit_verbs::StoreError> {
        Ok(())
    }

    fn replay_new_verb(
        &self,
        key: &(String, String),
    ) -> Result<Option<Vec<u8>>, busbar_unit_verbs::StoreError> {
        Ok(self
            .0
            .lock()
            .expect("no test panics under this lock")
            .get(key)
            .cloned())
    }

    fn commit_new_verb_replay(
        &self,
        key: &(String, String),
        response: &[u8],
    ) -> Result<(), busbar_unit_verbs::StoreError> {
        self.0
            .lock()
            .expect("no test panics under this lock")
            .insert(key.clone(), response.to_vec());
        Ok(())
    }
}

/// A replayed idempotency key answers with the FIRST answer's bytes, through the root's own
/// store adapter and its own packing. Byte-identical is the property: a re-render would mint a
/// second one-time secret over one identity, and the whole reason the answer travels as opaque
/// bytes is that there is no decode step here that could.
#[test]
fn a_replayed_idempotency_key_answers_the_first_answers_bytes() {
    use busbar_unit_verbs::store::Store;

    let answer = AdminAnswer {
        status: 201,
        headers: vec![("content-type".to_string(), "application/json".to_string())],
        body: br#"{"id":"vk_1","secret":"once"}"#.to_vec(),
    };
    let first = answer.pack();
    let key = ("idem-1".to_string(), "POST /api/v1/admin/keys".to_string());

    let store = StoreRef(Arc::new(ReplaySlots::default()));
    assert_eq!(
        store.replay_new_verb(&key).expect("the slot reads"),
        None,
        "a key never seen has nothing to replay"
    );
    store
        .commit_new_verb_replay(&key, &first)
        .expect("the slot commits");

    let replayed = store
        .replay_new_verb(&key)
        .expect("the slot reads")
        .expect("a committed key replays");
    assert_eq!(replayed, first);
    assert_eq!(AdminAnswer::unpack(&replayed), Some(answer));
}

/// What the replay encoder writes: an identity, and never the secret beside it. The identity is
/// enough to key a slot and carries nothing a second holder could present.
#[test]
fn the_replay_encoder_carries_an_identity_and_never_a_secret() {
    use busbar_unit_verbs::ReplayEncoder;

    let admin = crate::root::kernel::new_kernel().admin_token();
    let outcome = busbar_unit_verbs::MintedKeyOutcome {
        id: "vk_1".to_string(),
        secret: busbar_caps::SecretOnce::mint(&admin, 42, UnitKey::new(1), "body.secret"),
        expires_at: None,
    };
    let bytes = PackedReplay.encode(&outcome);
    assert_eq!(bytes, b"vk_1");
    assert_eq!(
        PackedReplay.encode(&outcome),
        bytes,
        "two encodings of one outcome are one answer"
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
impl busbar_unit_auth::module::AuthModule for IdentifiesOperator {
    fn name(&self) -> &'static str {
        "identifies-operator"
    }
    fn authenticate(&self, candidate: Option<&str>) -> busbar_unit_auth::module::AuthOutcome {
        match candidate {
            Some("admin-token") => busbar_unit_auth::module::AuthOutcome::Identify(
                busbar_unit_auth::principal::Principal::from_id(
                    crate::root::auth_bindings::ADMIN_PRINCIPAL_ID,
                ),
            ),
            _ => busbar_unit_auth::module::AuthOutcome::Pass,
        }
    }
}

#[cfg(feature = "root-admin")]
fn a_door_that_identifies_the_operator() -> busbar_unit_auth::AuthChain {
    busbar_unit_auth::AuthChain::new(
        vec![busbar_unit_auth::chain::ChainEntry {
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
    let units = crate::root::kernel::ProductionUnits::admin_only(Arc::new(AnsweringDispatch))
        .with_auth_chain(a_door_that_identifies_the_operator())
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
    let units = crate::root::kernel::ProductionUnits::admin_only(Arc::new(AnsweringDispatch))
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
impl busbar_unit_auth::module::AuthModule for IdentifiesSomebodyElse {
    fn name(&self) -> &'static str {
        "identifies-somebody-else"
    }
    fn authenticate(&self, candidate: Option<&str>) -> busbar_unit_auth::module::AuthOutcome {
        match candidate {
            Some("a-tenants-token") => busbar_unit_auth::module::AuthOutcome::Identify(
                busbar_unit_auth::principal::Principal::from_id("acct:not-the-operator"),
            ),
            _ => busbar_unit_auth::module::AuthOutcome::Pass,
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
    door: busbar_unit_auth::AuthChain,
    credential: Option<&str>,
) -> AdminAnswer {
    let units = crate::root::kernel::ProductionUnits::admin_only(Arc::new(AnsweringDispatch))
        .with_auth_chain(door)
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
    let door = busbar_unit_auth::AuthChain::new(
        vec![busbar_unit_auth::chain::ChainEntry {
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

/// A binding holding one open unit, with the decode step run so the verb is resolved exactly as
/// the loop resolves it. Returns the binding and the context every later step reads the unit
/// through, so a cell drives the real steps rather than a table it filled in by hand.
#[cfg(feature = "root-admin")]
fn a_bound_unit(request: AdminRequest) -> (AdminBinding, UnitCtx, busbar_caps::KernelSeal) {
    let binding = AdminBinding::new(Arc::new(AnsweringDispatch));
    let key = UnitKey::new(1);
    binding.units.open(key, request);
    let ctx = UnitCtx {
        key,
        origin: busbar_caps::OriginKind::Client,
        session: None,
        generation: busbar_kernel::registry::Generation::FIRST,
        admin_listener: true,
        kernel_verb_only: true,
    };
    crate::open_record!(record, &ctx);
    let seal = busbar_caps::KernelSeal::acquire_for_kernel();
    // Decode is what puts the verb in the table. A cell that called `set_verb` itself would be
    // asserting over a row the loop never wrote.
    let _ = decode(&binding, &UnitToken::mint(&seal), &record);
    (binding, ctx, seal)
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
/// Three answers, over one table at one moment:
///
/// - a unit that did NOT arrive on the administrative listener is refused, `InFlightCap`,
///   stamped at `Arrival` because the origin is a client, with its arrival hold handed back
///   reserving nothing — the shedding the operator came to ask about;
/// - a real admin request, through the whole loop on that same table, comes back with the
///   operation's own 200 rather than the node's `unavailable`. Not a smaller claim than the
///   refusal above: it is the exemption, on the path the listener actually takes;
/// - the step itself proceeds, and the record it carries names the administrative transport. The
///   admin plane synthesizes its arrival rather than copying a data-listener one, and the chain
///   is where that shows.
#[cfg(feature = "root-admin")]
#[test]
fn the_admin_listener_is_exempt_from_the_cap_the_data_listener_is_refused_at() {
    use busbar_caps::{OriginKind, StepName};
    use busbar_kernel::inflight::{arrival_hold, cap_refusal_step, Enter};

    let units = crate::root::kernel::ProductionUnits::admin_only(Arc::new(AnsweringDispatch));
    let node = AdminNode::new(crate::root::kernel::new_kernel(), units);
    assert_eq!(
        node.inflight.cap(),
        0,
        "the exemption is the only reason anything answers on this table"
    );

    // REFUSED: the same table, asked for a unit that is under the cap.
    let entering = Enter {
        key: UnitKey::new(9_000),
        origin: OriginKind::Client,
        session: None,
        admin_listener: false,
        provider_of_open_session: false,
        zero_hold_tick: false,
        now: 0,
        arrival: arrival_hold(
            &node.kernel,
            &node.units.arrival_door,
            PrincipalId::new("caller"),
        ),
    };
    let Err(refused) = node.inflight.insert(entering) else {
        panic!("a table with no room admits nothing that is under the cap");
    };
    assert_eq!(refused.reason, ReasonCode::InFlightCap);
    assert_eq!(refused.step, StepName::Arrival);
    assert_eq!(refused.step, cap_refusal_step(OriginKind::Client));
    let handed_back = refused.hold;
    assert_eq!(
        handed_back.reserved(),
        0,
        "a unit refused at the gate has spent nothing"
    );

    // ADMITTED: an ordinary administrative request, through the whole loop, on that table.
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
    assert_eq!(node.inflight.len(), 0, "the unit gave its slot back");

    // The step's own answer, for the unit that got through.
    let (binding, ctx, seal) = a_bound_unit(a_request());
    crate::open_record!(record, &ctx);
    assert!(ctx.admin_listener, "the fixture is on the admin listener");
    let record = arrival(&binding, &UnitToken::mint(&seal), &record)
        .into_result(&seal)
        .expect("an admin unit is never refused at the gate");
    assert_eq!(record.transport_chain, vec![ADMIN_TRANSPORT]);
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
    let (binding, ctx, seal) = a_bound_unit(unknown);
    crate::open_record!(record, &ctx);
    assert!(
        binding.units.verb(ctx.key).is_none(),
        "the fixture must be a path the table never resolved"
    );
    let refusal = verify(&binding, &UnitToken::mint(&seal), &record, &principal)
        .into_result(&seal)
        .expect_err("a verb that resolved to nothing has nowhere to go");
    assert_eq!(refusal.reason(), ReasonCode::NoDestination);

    // A real operation: it proceeds, and it proceeds to nowhere PRICED.
    let (binding, ctx, seal) = a_bound_unit(a_request());
    crate::open_record!(record, &ctx);
    assert!(
        binding.units.verb(ctx.key).is_some(),
        "the fixture must be a path the table did resolve"
    );
    let destinations = verify(&binding, &UnitToken::mint(&seal), &record, &principal)
        .into_result(&seal)
        .expect("a resolved verb has somewhere to go");
    assert!(
        destinations.is_empty(),
        "an admin unit that sealed a destination would sit on the priced axis"
    );
}

/// One admin unit seals exactly one entry on the chain, and a read seals none.
///
/// THE audit STEP, over the loop. The rig column reads the fresh four-op chain from the outside;
/// this reads the same chain from the step that writes it, which is where "exactly one" is
/// actually decided. Three answers, and each is a different way the step could be wrong:
///
/// - a mutating verb appends exactly ONE entry, under the operation's own name and the applied
///   outcome — not zero, and not one per step that ran;
/// - a READ appends none, because the chain is a record of what changed and a listing changed
///   nothing. A chain that grew on every GET would bury the mutations an operator came to find;
/// - a unit refused before Admit still appends one, under the rejected outcome, because the
///   attempt happened and a chain that recorded only successes is the one an attacker wants —
///   PROVIDED an identity was resolved for it. A unit refused before that has nobody to
///   attribute to, and the fourth answer below is that it appends nothing rather than
///   attributing an anonymous caller's refused mutation to the configured administrator.
///
/// The chain is verified after each, so the entries are linked rather than merely counted.
#[cfg(feature = "root-admin")]
#[test]
fn one_admin_unit_seals_exactly_one_entry_and_a_read_seals_none() {
    let legacy = busbar_unit_audit::AuditLog::with(
        Box::new(PinnedClock),
        Box::new(busbar_unit_audit::NoSeam),
    );

    // A mutation: an operator-key write, on the mutating side of the closed split.
    let mut mutating = a_request();
    mutating.method = "POST".to_string();
    mutating.path = "/api/v1/admin/operator-key".to_string();
    let (binding, ctx, seal) = a_bound_unit(mutating);
    crate::open_record!(record, &ctx);
    let resolved = binding
        .units
        .verb(ctx.key)
        .expect("the operator-key write is a row the table names");
    assert!(!resolved.read_only, "the fixture must be a mutation");
    // Verify is what keeps the resolved identity, and the fixture stands in for it: a unit that
    // reaches the audit door having been authenticated has one, and that is what the record is
    // attributed to.
    binding
        .units
        .set_principal(ctx.key, PrincipalId::new(AN_IDENTIFIED_OPERATOR));

    let before = legacy.len();
    let _ = audit(
        &binding,
        &legacy,
        &UnitToken::mint(&seal),
        &record,
        &Outcome::Completed,
    );
    assert_eq!(legacy.len(), before + 1, "one unit, one entry");
    let entry = legacy.list(1).pop().expect("the entry just sealed");
    assert_eq!(entry.action, resolved.verb);
    assert_eq!(entry.outcome, busbar_unit_audit::OUTCOME_APPLIED);
    // The record names the identity Verify resolved -- never the credential the request
    // presented, which is a secret and stays out of the chain.
    assert_eq!(entry.principal, AN_IDENTIFIED_OPERATOR);
    assert!(!entry.principal.contains("admin-token"));
    assert!(legacy.verify(), "the chain is linked");

    // A read changes nothing and records nothing.
    let (binding, ctx, seal) = a_bound_unit(a_request());
    crate::open_record!(record, &ctx);
    assert!(
        binding
            .units
            .verb(ctx.key)
            .expect("the audit listing is a row the table names")
            .read_only,
        "the fixture must be a read"
    );
    let before = legacy.len();
    let _ = audit(
        &binding,
        &legacy,
        &UnitToken::mint(&seal),
        &record,
        &Outcome::Completed,
    );
    assert_eq!(legacy.len(), before, "a read is not a mutation");

    // A refused mutation by somebody the node identified is recorded as an attempt, not dropped.
    let mut mutating = a_request();
    mutating.method = "POST".to_string();
    mutating.path = "/api/v1/admin/operator-key".to_string();
    let (binding, ctx, seal) = a_bound_unit(mutating);
    crate::open_record!(record, &ctx);
    binding
        .units
        .set_principal(ctx.key, PrincipalId::new(AN_IDENTIFIED_OPERATOR));
    let before = legacy.len();
    let _ = audit_refused(
        &binding,
        &legacy,
        &UnitToken::mint(&seal),
        &record,
        &Refusal::new(ReasonCode::OverBudget),
    );
    assert_eq!(legacy.len(), before + 1, "the attempt is on the chain");
    let entry = legacy.list(1).pop().expect("the entry just sealed");
    assert_eq!(entry.outcome, busbar_unit_audit::OUTCOME_REJECTED);
    assert_eq!(entry.principal, AN_IDENTIFIED_OPERATOR);
    assert!(legacy.verify(), "the chain is still linked");

    // AND THE SAME MUTATION BY NOBODY IS NOT. No principal was ever set on this unit, which is
    // the state of every request refused at or before Authenticate. The previous release's
    // chain holds no row for one, and neither does this: a record naming the configured
    // administrator for a request that administrator never made would let an anonymous caller
    // grow that operator's history one refused write at a time.
    let mut mutating = a_request();
    mutating.method = "POST".to_string();
    mutating.path = "/api/v1/admin/operator-key".to_string();
    let (binding, ctx, seal) = a_bound_unit(mutating);
    crate::open_record!(record, &ctx);
    assert!(
        binding.units.principal(ctx.key).is_none(),
        "the fixture must be a unit no identity was resolved for"
    );
    let before = legacy.len();
    let _ = audit_refused(
        &binding,
        &legacy,
        &UnitToken::mint(&seal),
        &record,
        &Refusal::new(ReasonCode::Unauthenticated),
    );
    assert_eq!(
        legacy.len(),
        before,
        "an unattributable refusal appends nothing"
    );
    assert!(legacy.verify(), "the chain is still linked");
}

/// The identity a fixture stands Verify's answer in for. Deliberately NOT the word the
/// unresolved fallback uses, so a test that passed by accident because the two agreed would
/// stop passing.
const AN_IDENTIFIED_OPERATOR: &str = "operator-alice";

/// Each of the three recovery verbs reaches the STORE, and a refusing store's answer is the
/// caller's.
///
/// The three used to travel `Verbs::execute`, which sends every new verb to the governance seam
/// — and the governance seam is the mounted router, which has no route for any of them. So all
/// three passed the scope check, the rate class, the operator ceremony and dual control, and
/// then received a 404 from the surface underneath: the gates on the most destructive
/// operations this node has were being run in front of nothing.
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

    impl busbar_unit_verbs::store::Store for RecordingStore {
        fn chain_break(
            &self,
            _admin: &busbar_caps::AdminToken,
        ) -> Result<(), busbar_unit_verbs::StoreError> {
            self.0.lock().unwrap().push("chain_break".to_string());
            Err(busbar_unit_verbs::StoreError::Failed)
        }

        fn store_restore(
            &self,
            _admin: &busbar_caps::AdminToken,
            backup_ref: &str,
        ) -> Result<(), busbar_unit_verbs::StoreError> {
            self.0
                .lock()
                .unwrap()
                .push(format!("store_restore:{backup_ref}"));
            Err(busbar_unit_verbs::StoreError::Failed)
        }

        fn reseal_epoch_floor(
            &self,
            _admin: &busbar_caps::AdminToken,
        ) -> Result<(), busbar_unit_verbs::StoreError> {
            self.0
                .lock()
                .unwrap()
                .push("reseal_epoch_floor".to_string());
            Err(busbar_unit_verbs::StoreError::Failed)
        }

        fn replay_new_verb(
            &self,
            _key: &(String, String),
        ) -> Result<Option<Vec<u8>>, busbar_unit_verbs::StoreError> {
            Ok(None)
        }

        fn commit_new_verb_replay(
            &self,
            _key: &(String, String),
            _response: &[u8],
        ) -> Result<(), busbar_unit_verbs::StoreError> {
            Ok(())
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

    let seal = busbar_caps::KernelSeal::acquire_for_kernel();
    let admin = crate::root::kernel::new_kernel().admin_token();

    // The posture a fleet that has run its ceremony has, so the gates admit and what is left is
    // the destination. Anything less and the verb would be refused before the store.
    let ceremony_run = || -> Arc<dyn PostureView> {
        struct Ran;
        impl PostureView for Ran {
            fn resolve(
                &self,
                _verb: KernelVerb,
                _actor: &str,
            ) -> Option<(PostureCtx, ApprovalState)> {
                Some((
                    PostureCtx {
                        operator: busbar_unit_verbs::OperatorState::Set,
                        dual_control: busbar_unit_verbs::DualControl::Single,
                    },
                    ApprovalState::NotYetApproved,
                ))
            }
        }
        Arc::new(Ran)
    };

    for (path, body, reached) in [
        ("/api/v1/admin/chain-break", "{}", "chain_break"),
        (
            "/api/v1/admin/store-restore",
            "{\"backup_ref\":\"nightly-2026-09-05\"}",
            "store_restore:nightly-2026-09-05",
        ),
        (
            "/api/v1/admin/reseal-epoch-floor",
            "{}",
            "reseal_epoch_floor",
        ),
    ] {
        let store = Arc::new(RecordingStore::default());
        let binding =
            AdminBinding::new(Arc::new(NeverDispatched)).with_posture_view(ceremony_run());
        let key = UnitKey::new(1);
        let mut request = a_request();
        request.method = "POST".to_string();
        request.path = path.to_string();
        request.body = body.as_bytes().to_vec();
        binding.units.open(key, request);
        let ctx = UnitCtx {
            key,
            origin: busbar_caps::OriginKind::Client,
            session: None,
            generation: busbar_kernel::registry::Generation::FIRST,
            admin_listener: true,
            kernel_verb_only: true,
        };
        crate::open_record!(record, &ctx);
        decode(&binding, &UnitToken::mint(&seal), &record)
            .into_result(&seal)
            .unwrap_or_else(|_| panic!("{path} is a row the plane's table declares"));
        binding.units.set_granted(key, VerbScope::Full);

        let token: UnitToken<Route> = UnitToken::mint(&seal);
        let outcome = route(
            &binding,
            Arc::clone(&store) as Arc<dyn busbar_unit_verbs::store::Store + Send + Sync>,
            &admin,
            &token,
            &record,
            &busbar_kernel::teller::AccrualMeter::new(),
        )
        .into_result(&seal);
        binding.units.close(key);

        assert_eq!(
            store.0.lock().unwrap().as_slice(),
            [reached.to_string()],
            "{path} did not reach the store method it names"
        );
        assert_eq!(
            outcome.err().map(|refusal| refusal.reason()),
            Some(ReasonCode::DurabilityUnavailable),
            "{path} did not surface the refusing store's refusal"
        );
    }
}

/// A `store_restore` that names no backup restores nothing.
///
/// The single most destructive request this surface takes, and the one whose argument must not
/// be defaulted: a body that names no reference is refused before the ceremony runs, so the
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

/// These three verbs and no others land on the store.
///
/// Written from this side as well as the verbs unit's, because the split is a fact two crates
/// have to agree about: a verb added to the unit's store methods without a row here would go
/// back to the governance seam and its 404, silently.
#[test]
fn exactly_three_verbs_land_on_the_store() {
    let landing: Vec<KernelVerb> = NEW_VERBS
        .iter()
        .copied()
        .filter(|verb| recovery_verb(*verb).is_some())
        .collect();
    assert_eq!(
        landing,
        vec![
            KernelVerb::ChainBreak,
            KernelVerb::StoreRestore,
            KernelVerb::ResealEpochFloor
        ]
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
    let refused = &Outcome::Refused(busbar_caps::StepName::Decode, ReasonCode::DecodeFailed);
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
    let legacy = busbar_unit_audit::AuditLog::with(
        Box::new(PinnedClock),
        Box::new(busbar_unit_audit::NoSeam),
    );
    // A path the plane's table does not declare, so the verb never resolves and the door takes
    // its unresolved arm — the one that used to fabricate.
    let mut unrouted = a_request();
    unrouted.method = "DELETE".to_string();
    unrouted.path = "/api/v1/admin/nothing-declares-this".to_string();
    let (binding, ctx, seal) = a_bound_unit(unrouted);
    crate::open_record!(record, &ctx);
    assert!(
        binding.units.verb(ctx.key).is_none(),
        "the fixture must be a unit whose verb never resolved"
    );

    let facts = audit_refused(
        &binding,
        &legacy,
        &UnitToken::mint(&seal),
        &record,
        &Refusal::new(ReasonCode::Unauthenticated),
    )
    .into_result(&seal)
    .expect("the door seals a record for an unresolved unit");
    assert_eq!(
        facts.op_class,
        busbar_contract::OpClassId::new(OP_UNRESOLVED_WRITE),
        "the DELETE it asked with, not the read it used to be sealed as"
    );
    assert_eq!(facts.finish, busbar_contract::FinishClass::Error);
    assert_eq!(legacy.len(), 0, "and nobody was attributed for it");
}

// ── the five ledger views ───────────────────────────────────────────────────────────────────

/// The day the fixture's postings fall in.
const A_DAY: u64 = 1_767_225_600;

/// A ledger with something in it.
///
/// Deliberately not balanced: one row reconciles and one does not, so a test that asserted the
/// residual is zero would be asserting something about a table of zeros rather than about the
/// identity. The unbalanced row is short by a known amount, which is the figure the
/// reconciliation view has to report.
struct SeededLedger;

impl SeededLedger {
    /// The row whose two sides disagree, and by how much in micro-units.
    const SHORT_ROW: (&'static str, &'static str, &'static str) = ("key-1", "lane-b", "prov-y");
    const SHORT_BY_MICROS: i64 = 250;
}

impl LedgerView for SeededLedger {
    fn ledger_rows(&self) -> crate::root::ledger_identity::LedgerSnapshot {
        use crate::root::ledger_identity::{LedgerRow, RowKey};
        [
            (
                RowKey::new("key-1", A_DAY, "lane-a", "prov-x"),
                LedgerRow {
                    priced_nanos: 7_000_000,
                    fee_count: 2,
                },
            ),
            (
                RowKey::new(
                    SeededLedger::SHORT_ROW.0,
                    A_DAY,
                    SeededLedger::SHORT_ROW.1,
                    SeededLedger::SHORT_ROW.2,
                ),
                LedgerRow {
                    priced_nanos: 1_000_000,
                    fee_count: 1,
                },
            ),
        ]
        .into_iter()
        .collect()
    }

    fn legacy_rows(&self) -> crate::root::ledger_identity::LegacySnapshot {
        use crate::root::ledger_identity::{LegacyRow, RowKey};
        [
            (
                RowKey::new("key-1", A_DAY, "lane-a", "prov-x"),
                LegacyRow {
                    spend_micros: 7_000,
                    billable_requests: 2,
                },
            ),
            (
                RowKey::new(
                    SeededLedger::SHORT_ROW.0,
                    A_DAY,
                    SeededLedger::SHORT_ROW.1,
                    SeededLedger::SHORT_ROW.2,
                ),
                LegacyRow {
                    // The ledger accounted for 1_000 micro-units against 1_250 drawn, so the
                    // books are short by 250 on this row and by nothing on the other.
                    spend_micros: 1_000 + SeededLedger::SHORT_BY_MICROS,
                    billable_requests: 1,
                },
            ),
        ]
        .into_iter()
        .collect()
    }

    fn checkpoints(&self) -> Vec<busbar_unit_ledger::checkpoint::Checkpoint> {
        use busbar_unit_ledger::totals::{BucketId, BucketScope, CapDimension, TotalsKey};

        let mut totals = std::collections::BTreeMap::new();
        totals.insert(
            (
                TotalsKey::new(
                    BucketId::new("key-1"),
                    CapDimension::NanoUnits,
                    BucketScope::All,
                ),
                A_DAY,
            ),
            busbar_unit_ledger::totals::Totals {
                settled: 8_000,
                drawn: 8_250,
                ..busbar_unit_ledger::totals::Totals::zero()
            },
        );
        vec![busbar_unit_ledger::checkpoint::Checkpoint::seal(
            4,
            1,
            1_700_000_000,
            Vec::new(),
            totals,
            0,
            0,
            None,
        )
        .expect("an unsigned seal cannot fail")]
    }

    fn migration_marker(&self) -> Option<busbar_unit_ledger::migration::MigrationMarker> {
        Some(busbar_unit_ledger::migration::MigrationMarker {
            checkpoint_seq: 0,
            node: 1,
            sealed_at: 1_699_999_000,
            body_hash: [7u8; 32],
            balances: 3,
            cells_read: 11,
            rate_card_version: 5,
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
    let mut units = crate::root::kernel::ProductionUnits::admin_only(Arc::new(AnsweringDispatch));
    units.admin =
        AdminBinding::new(Arc::new(AnsweringDispatch)).with_ledger_view(Arc::new(SeededLedger));
    AdminNode::new(crate::root::kernel::new_kernel(), units).answer(request)
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
    assert_eq!(rows[0]["lane"], "lane-a");
    assert_eq!(rows[0]["provider"], "prov-x");
    // Money is text and a count is a number — the rule the served document states.
    assert_eq!(rows[0]["priced_nanos"], "7000000");
    assert_eq!(rows[0]["priced_micros"], "7000");
    assert_eq!(rows[0]["fee_count"], 2);

    let checkpoints = body("/api/v1/admin/ledger/checkpoints");
    let sealed = checkpoints["checkpoints"].as_array().expect("checkpoints");
    assert_eq!(sealed.len(), 1);
    assert_eq!(sealed[0]["checkpoint_seq"], 4);
    assert_eq!(sealed[0]["node"], 1);
    assert_eq!(sealed[0]["body_hash_verifies"], true);
    assert_eq!(
        sealed[0]["signed"], false,
        "an unsigned seal reports as unsigned"
    );
    let cells = sealed[0]["totals"].as_array().expect("totals");
    assert_eq!(cells.len(), 1);
    assert_eq!(cells[0]["bucket"], "key-1");
    assert_eq!(cells[0]["settled"], "8000");
    assert_eq!(cells[0]["drawn"], "8250");
    assert_eq!(
        sealed[0]["body_hash"]
            .as_str()
            .expect("a hash is text")
            .len(),
        64,
        "a digest is served as 64 hex characters"
    );

    let migration = body("/api/v1/admin/ledger/migration");
    assert_eq!(migration["migrated"], true);
    assert_eq!(migration["marker"]["checkpoint_seq"], 0);
    assert_eq!(migration["marker"]["balances"], 3);
    assert_eq!(migration["marker"]["cells_read"], 11);
    assert_eq!(migration["marker"]["rate_card_version"], 5);
    assert_eq!(
        migration["marker"]["body_hash"],
        "0707070707070707070707070707070707070707070707070707070707070707"
    );

    let document = body("/api/v1/admin/ledger/openapi.json");
    assert_eq!(document["info"]["version"], "1.6.0");
}

/// The previous release's rows, as a binding that counts what the views ask of it.
///
/// Both readings are recorded: how many times the whole history was asked for as a copy, and
/// how many postings a fold was shown. The pair is what tells a copy apart from a walk.
#[cfg(feature = "root-admin")]
#[derive(Default)]
struct CountingRows {
    written: Arc<Mutex<Vec<busbar_unit_ledger::legacy::LegacyPosting>>>,
    copies: Arc<std::sync::atomic::AtomicUsize>,
    folded: Arc<std::sync::atomic::AtomicUsize>,
}

#[cfg(feature = "root-admin")]
impl busbar_unit_ledger::legacy::LegacyRows for CountingRows {
    fn write(
        &mut self,
        posting: &busbar_unit_ledger::legacy::LegacyPosting,
    ) -> Result<(), busbar_unit_ledger::legacy::LegacyWriteError> {
        self.written
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .push(posting.clone());
        Ok(())
    }
}

#[cfg(feature = "root-admin")]
impl LegacyRowsRead for CountingRows {
    fn postings(&self) -> Vec<busbar_unit_ledger::legacy::LegacyPosting> {
        self.copies
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        self.written
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .clone()
    }

    fn fold_postings(&self, take: &mut dyn FnMut(&busbar_unit_ledger::legacy::LegacyPosting)) {
        for posting in self
            .written
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .iter()
        {
            self.folded
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            take(posting);
        }
    }
}

/// THE VIEW WALKS THE HISTORY; IT DOES NOT COPY IT.
///
/// The reconciliation views read the previous release's rows under the SAME lock every
/// settlement takes, and what they render is one line per row — a handful, whatever the node has
/// settled since boot. Asking for a copy of the whole posting history to produce it makes the
/// cost of an operator's read grow with the traffic that came before it, and makes every
/// settlement wait for the copy. Counted rather than timed: the copy is a call that either
/// happened or did not.
#[cfg(feature = "root-admin")]
#[test]
fn a_ledger_view_reads_the_history_without_copying_it() {
    let rows = CountingRows::default();
    let written = Arc::clone(&rows.written);
    let copies = Arc::clone(&rows.copies);
    let folded = Arc::clone(&rows.folded);
    let read: Arc<dyn LegacyRowsRead> = Arc::new(CountingRows {
        written: Arc::clone(&written),
        copies: Arc::clone(&copies),
        folded: Arc::clone(&folded),
    });

    let units = crate::root::kernel::ProductionUnits::admin_only_over(
        Arc::new(AnsweringDispatch),
        Box::new(rows),
        read,
    );
    for _ in 0..8 {
        settle_on(&units, "vk_view", 1_000);
    }
    assert_eq!(
        written.lock().unwrap_or_else(|p| p.into_inner()).len(),
        8,
        "the fixture recorded every settlement"
    );

    let node = AdminNode::new(crate::root::kernel::new_kernel(), units);
    let answer = node.answer(a_ledger_request("/api/v1/admin/ledger/reconciliation"));
    assert_eq!(answer.status, 200);

    assert_eq!(
        copies.load(std::sync::atomic::Ordering::Relaxed),
        0,
        "the view took a copy of the whole history to render a handful of rows"
    );
    assert_eq!(
        folded.load(std::sync::atomic::Ordering::Relaxed),
        8,
        "and it saw each posting exactly once"
    );
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

/// A STEP THAT PANICS STILL GIVES THE TABLES BACK.
///
/// Both tables are per-node and live for the life of the process: the in-flight slot bounds how
/// many units the node has open, and the units table holds the request the steps read. A removal
/// written as the next statement after the loop comes back on the answering path and on no
/// other, so a panic in one operation's body would leave one slot and one whole request body
/// resident for as long as the node runs — a leak per panicking request, and the operator
/// reaching for the admin surface to find out why is the one making them.
#[cfg(feature = "root-admin")]
#[test]
fn a_panicking_step_leaves_both_tables_empty() {
    let units = crate::root::kernel::ProductionUnits::admin_only(Arc::new(PanickingDispatch));
    let node = AdminNode::new(crate::root::kernel::new_kernel(), units);

    let previous = std::panic::take_hook();
    std::panic::set_hook(Box::new(|_| {}));
    let ended = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| node.answer(a_request())));
    std::panic::set_hook(previous);
    assert!(ended.is_err(), "the fixture's dispatch panics");

    assert_eq!(node.inflight.len(), 0, "the in-flight slot came back");
    assert_eq!(
        node.units.admin.units.len(),
        0,
        "the units table gave up the request"
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
    let units = crate::root::kernel::ProductionUnits::admin_only(Arc::new(AnsweringDispatch));
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

/// THE ONE THAT MATTERS: the residual an operator reads is the residual the identity computes.
///
/// Not "a residual of the same magnitude" — the same function's answer. The endpoint calls
/// `ledger_identity::reconcile`, so a second derivation cannot creep into the rendering and make
/// the surface capable of disagreeing with the check that gates the release. This test computes
/// the identity itself, from the same two snapshots, and requires the served figures to be it.
#[cfg(feature = "root-admin")]
#[test]
fn the_reconciliation_served_is_the_identitys_own_answer() {
    let view = SeededLedger;
    let expected =
        crate::root::ledger_identity::reconcile(&view.ledger_rows(), &view.legacy_rows());
    assert_eq!(
        expected.len(),
        1,
        "the fixture must have exactly one row out, or the comparison is vacuous"
    );

    let served: serde_json::Value = serde_json::from_slice(
        &answer_over_seeded_ledger(a_ledger_request("/api/v1/admin/ledger/reconciliation")).body,
    )
    .expect("valid JSON");

    assert_eq!(served["holds"], false);
    let rows = served["discrepancies"].as_array().expect("discrepancies");
    assert_eq!(rows.len(), expected.len());
    for (row, d) in rows.iter().zip(expected.iter()) {
        assert_eq!(row["bucket"], d.row.bucket);
        assert_eq!(row["day"], d.row.day);
        assert_eq!(row["lane"], d.row.lane);
        assert_eq!(row["provider"], d.row.provider);
        assert_eq!(row["residual"]["accounted"], d.spend.accounted.to_string());
        assert_eq!(row["residual"]["drawn"], d.spend.drawn.to_string());
        assert_eq!(row["residual"]["amount"], d.spend.amount().to_string());
        assert_eq!(row["ledger_fee_count"], d.ledger_fee_count);
        assert_eq!(row["legacy_billable_requests"], d.legacy_billable_requests);
    }

    // And the number is the one the fixture was built to be out by, so a rendering that served
    // the right field of the wrong row would still fail.
    assert_eq!(
        rows[0]["residual"]["amount"],
        (-i128::from(SeededLedger::SHORT_BY_MICROS)).to_string()
    );
    assert_eq!(rows[0]["lane"], SeededLedger::SHORT_ROW.1);
}

// ── the views over the node's OWN ledger ─────────────────────────────────────────────────────

/// The two buckets the settling fixture posts against, and what each settles in nano-units.
#[cfg(feature = "root-admin")]
const KEPT: (&str, u64) = ("vk_kept", 7_000_000);
#[cfg(feature = "root-admin")]
const LOST: (&str, u64) = ("vk_lost", 1_000_000);

/// A dual-write binding that drops the postings for one named bucket on the floor.
///
/// The failure it stands in for is real and is the one the identity exists to catch: the books
/// moved, value was delivered, and the previous release's rows never heard about it. The ledger
/// is unaffected — this is a binding the ledger writes THROUGH, so a node built over it settles
/// exactly as any other node does and only the parity obligation is broken.
#[cfg(feature = "root-admin")]
#[derive(Clone)]
struct RowsThatLose {
    drop_bucket: &'static str,
    kept: Arc<Mutex<Vec<busbar_unit_ledger::legacy::LegacyPosting>>>,
}

#[cfg(feature = "root-admin")]
impl RowsThatLose {
    fn new(drop_bucket: &'static str) -> Self {
        RowsThatLose {
            drop_bucket,
            kept: Arc::new(Mutex::new(Vec::new())),
        }
    }
}

#[cfg(feature = "root-admin")]
impl busbar_unit_ledger::legacy::LegacyRows for RowsThatLose {
    fn write(
        &mut self,
        posting: &busbar_unit_ledger::legacy::LegacyPosting,
    ) -> Result<(), busbar_unit_ledger::legacy::LegacyWriteError> {
        if posting.bucket != self.drop_bucket {
            self.kept
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .push(posting.clone());
        }
        Ok(())
    }
}

#[cfg(feature = "root-admin")]
impl LegacyRowsRead for RowsThatLose {
    fn postings(&self) -> Vec<busbar_unit_ledger::legacy::LegacyPosting> {
        self.kept.lock().unwrap_or_else(|p| p.into_inner()).clone()
    }
}

/// Settle one unit against the node's own durability, through the same function the loop's exit
/// path settles through — so what the views read is what a served request would have left.
#[cfg(feature = "root-admin")]
fn settle_on(units: &crate::root::kernel::ProductionUnits, bucket: &str, nanos: u64) {
    use busbar_caps::{
        step::Admit, AdmitToken, Hold, KernelSeal, LedgerToken, MeterClassId, PrincipalId,
        QuantitySource, Usage, UsageLine, UsageToken,
    };
    use busbar_unit_ledger::totals::{BucketId, BucketScope, CapDimension, TotalsKey};

    let seal = KernelSeal::acquire_for_kernel();
    let key = TotalsKey::new(
        BucketId::new(bucket),
        CapDimension::NanoUnits,
        BucketScope::All,
    );
    let usage = Usage::report(
        &UsageToken::mint(&seal),
        vec![UsageLine {
            class: MeterClassId::new("nano_units"),
            quantity: nanos,
            source: QuantitySource::Count,
            estimated: false,
        }],
    )
    .expect("one line");

    let token = busbar_caps::DurabilityToken::mint(&seal);
    let mut durability = units.durability.lock().unwrap_or_else(|p| p.into_inner());
    durability.ledger.record_hold_opened(&key, A_DAY, nanos);
    durability
        .settle(
            &crate::root::durability::Settling {
                key: &key,
                window: A_DAY,
                durability: &token,
                step: busbar_caps::StepName::Meter,
                stamp: crate::root::durability::PostingStamp {
                    rate_card_version: 3,
                    wall: 1_700_000_000,
                    mono: 42,
                },
            },
            Hold::open(
                &AdmitToken::<Admit>::mint(&seal),
                PrincipalId::new(bucket),
                nanos,
            ),
            u128::from(nanos),
            &usage,
            &LedgerToken::mint(&seal),
        )
        .expect("the memory-buffered journal takes it");
}

/// A node that has settled both fixture units, over a dual write that may have lost one of them.
#[cfg(feature = "root-admin")]
fn a_node_that_settled(lose: Option<&'static str>) -> crate::root::kernel::ProductionUnits {
    let units = match lose {
        None => {
            let rows = busbar_unit_ledger::legacy::RecordingRows::new();
            crate::root::kernel::ProductionUnits::admin_only_over(
                Arc::new(AnsweringDispatch),
                Box::new(rows.clone()),
                Arc::new(rows),
            )
        }
        Some(bucket) => {
            let rows = RowsThatLose::new(bucket);
            crate::root::kernel::ProductionUnits::admin_only_over(
                Arc::new(AnsweringDispatch),
                Box::new(rows.clone()),
                Arc::new(rows),
            )
        }
    };
    settle_on(&units, KEPT.0, KEPT.1);
    settle_on(&units, LOST.0, LOST.1);
    units
}

/// THE ONE THAT MATTERS FOR A LIVE NODE: a settlement this node made is in the figures it
/// serves.
///
/// Not a fixture bound behind the seam — the node's own durability, settled through the same
/// function the loop settles through, read back through the served endpoint. A view bound to
/// anything other than this node's ledger answers an empty table here, which is exactly what the
/// unbound default answers and exactly what this test refuses.
///
/// Both halves are asserted because they fail separately. `totals` says the posting reached the
/// books; `reconciliation` says the identity was computed over the rows the node actually holds,
/// and it is asserted against a node whose dual write LOST one of the two settlements — so a
/// reconciliation rendered over two empty snapshots, which balances trivially, cannot pass it.
#[cfg(feature = "root-admin")]
#[test]
fn a_settled_posting_is_in_the_figures_this_node_serves() {
    let units = a_node_that_settled(None);
    let node = AdminNode::new(crate::root::kernel::new_kernel(), units);
    let body = |path: &str| -> serde_json::Value {
        let answer = node.answer(a_ledger_request(path));
        assert_eq!(answer.status, 200, "{path}");
        serde_json::from_slice(&answer.body).expect("valid JSON")
    };

    let rows = body("/api/v1/admin/ledger/totals");
    let rows = rows["rows"].as_array().expect("rows");
    assert_eq!(
        rows.len(),
        2,
        "the two settlements this node made are not in the totals it serves"
    );
    let row = rows
        .iter()
        .find(|r| r["bucket"] == KEPT.0)
        .expect("the settled bucket is named");
    assert_eq!(row["day"], A_DAY);
    assert_eq!(row["priced_nanos"], KEPT.1.to_string());
    assert_eq!(row["priced_micros"], (KEPT.1 / 1_000).to_string());

    // The dual write kept both, so the identity holds — over two rows rather than over nothing,
    // which the totals beside it just established.
    assert_eq!(body("/api/v1/admin/ledger/reconciliation")["holds"], true);
}

/// And the reconciliation names the row the dual write lost, by the amount it lost.
#[cfg(feature = "root-admin")]
#[test]
fn the_reconciliation_names_a_row_this_nodes_dual_write_lost() {
    let units = a_node_that_settled(Some(LOST.0));
    let node = AdminNode::new(crate::root::kernel::new_kernel(), units);
    let served: serde_json::Value = serde_json::from_slice(
        &node
            .answer(a_ledger_request("/api/v1/admin/ledger/reconciliation"))
            .body,
    )
    .expect("valid JSON");

    assert_eq!(
        served["holds"], false,
        "a settlement the previous release's rows never saw reconciled anyway"
    );
    let out = served["discrepancies"].as_array().expect("discrepancies");
    assert_eq!(out.len(), 1, "exactly the lost row must be named: {served}");
    assert_eq!(out[0]["bucket"], LOST.0);
    assert_eq!(out[0]["day"], A_DAY);
    // The ledger accounted for the whole posting against nothing drawn, so the residual is the
    // posting, in micro-units, positive.
    assert_eq!(
        out[0]["residual"]["amount"],
        (LOST.1 / 1_000).to_string(),
        "the residual is not the settlement that went missing"
    );
}

/// The other two views are this node's too: the seal it made and the marker it sealed.
///
/// Both are on the same composition that answered empty above, so the change is the node's own
/// act rather than a fixture swapped in behind the seam. The checkpoint is asserted through its
/// sealed balances, which is the half the journal deliberately does not carry — a view rebuilt
/// from the chain could not answer it at all.
#[cfg(feature = "root-admin")]
#[test]
fn the_seal_and_the_marker_this_node_made_are_the_ones_it_serves() {
    use busbar_unit_ledger::migration::MigrationRecords as _;
    use busbar_unit_ledger::totals::{BucketId, BucketScope, CapDimension, TotalsKey};

    let units = crate::root::kernel::ProductionUnits::admin_only(Arc::new(AnsweringDispatch));
    let seal = busbar_caps::KernelSeal::acquire_for_kernel();
    let token = busbar_caps::DurabilityToken::mint(&seal);
    let marker = busbar_unit_ledger::migration::MigrationMarker {
        checkpoint_seq: 0,
        node: 0,
        sealed_at: 1_699_999_000,
        body_hash: [9u8; 32],
        balances: 2,
        cells_read: 5,
        rate_card_version: 4,
    };

    {
        let mut durability = units.durability.lock().expect("durability lock");
        let mut totals = std::collections::BTreeMap::new();
        totals.insert(
            (
                TotalsKey::new(
                    BucketId::new(KEPT.0),
                    CapDimension::NanoUnits,
                    BucketScope::All,
                ),
                A_DAY,
            ),
            busbar_unit_ledger::totals::Totals {
                settled: 8_000,
                ..busbar_unit_ledger::totals::Totals::zero()
            },
        );
        let checkpoint = busbar_unit_ledger::checkpoint::Checkpoint::seal(
            7,
            0,
            1_700_000_100,
            Vec::new(),
            totals,
            0,
            0,
            None,
        )
        .expect("an unsigned seal cannot fail");
        durability
            .journal_checkpoint(&checkpoint, &token, busbar_caps::StepName::Meter)
            .expect("the memory-buffered journal takes it");
        durability
            .migration_records(&token, busbar_caps::StepName::Meter)
            .write_marker(&marker)
            .expect("the marker goes on the chain");
    }

    let node = AdminNode::new(crate::root::kernel::new_kernel(), units);
    let body = |path: &str| -> serde_json::Value {
        serde_json::from_slice(&node.answer(a_ledger_request(path)).body).expect("valid JSON")
    };

    let sealed = body("/api/v1/admin/ledger/checkpoints");
    let sealed = sealed["checkpoints"].as_array().expect("checkpoints");
    assert_eq!(sealed.len(), 1, "the seal this node made is not served");
    assert_eq!(sealed[0]["checkpoint_seq"], 7);
    assert_eq!(sealed[0]["body_hash_verifies"], true);
    assert_eq!(
        sealed[0]["totals"][0]["settled"], "8000",
        "the sealed balances the journal does not carry"
    );

    let served = body("/api/v1/admin/ledger/migration");
    assert_eq!(served["migrated"], true);
    assert_eq!(served["marker"]["sealed_at"], marker.sealed_at);
    assert_eq!(served["marker"]["balances"], marker.balances);
    assert_eq!(served["marker"]["cells_read"], marker.cells_read);
    assert_eq!(
        served["marker"]["rate_card_version"],
        marker.rate_card_version
    );
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
        let mut units =
            crate::root::kernel::ProductionUnits::admin_only(Arc::new(AnsweringDispatch))
                .with_auth_bindings(crate::root::auth_bindings::AuthBindings::new(Arc::new(
                    Denylist(revoked),
                )));
        if revoked {
            // The revocation withdraws an identification, so the door must identify first.
            units = units.with_auth_chain(a_door_that_identifies_the_operator());
        }
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
    let binding = AdminBinding::new(Arc::new(RefusingDispatch));
    let seal = busbar_caps::KernelSeal::acquire_for_kernel();

    let decide = |path: &str, method: &str, granted: VerbScope| -> bool {
        let key = UnitKey::new(1);
        let mut request = a_ledger_request(path);
        request.method = method.to_string();
        binding.units.open(key, request);
        let ctx = UnitCtx {
            key,
            origin: busbar_caps::OriginKind::Client,
            session: None,
            generation: busbar_kernel::registry::Generation::FIRST,
            admin_listener: true,
            kernel_verb_only: true,
        };
        crate::open_record!(record, &ctx);
        let token: UnitToken<Approve> = UnitToken::mint(&seal);
        let decision = approve(
            &binding,
            Some(granted),
            &token,
            &record,
            &PrincipalId::new("admin"),
        );
        binding.units.close(key);
        decision.into_result(&seal).is_ok()
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
        let row = busbar_plane_admin::verbs::resolve("GET", path)
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
            busbar_unit_verbs::required_scope(verb),
            busbar_unit_verbs::required_scope(KernelVerb::GetUsage),
            "{path} does not require what the legacy /usage read requires"
        );
        assert_eq!(
            mutation_class(verb),
            MutationClass::Forbidden,
            "{path} would spend a mutation slot per read"
        );
        assert_eq!(
            busbar_unit_scope::admin_required_scope("GET", path),
            Scope::ReadOnly
        );
    }
}

/// A ledger verb never reaches the dispatch, and never reaches the posture check either.
///
/// The governance seam is the boundary the two facts meet at, so it is where they are asserted:
/// a recording seam that would notice a legacy or new-verb call, and a `PostureCtx` that refuses
/// every mutation. A view answering under that posture is a view no ceremony gates.
#[test]
fn a_view_reaches_neither_the_dispatch_nor_the_posture_check() {
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
        let verbs = busbar_unit_verbs::Verbs::new(
            CoreGovernance::new(
                Arc::new(CountingDispatch(Arc::clone(&calls))),
                Arc::new(SeededLedger),
                *verb,
                a_ledger_request("/api/v1/admin/ledger/totals"),
            ),
            crate::root::kernel::RefusingStore,
            ArrivalNonce(1),
            PackedReplay,
            CONFIG_CLASS_RULES,
        );
        let packed = verbs
            .execute(
                *verb,
                &admin,
                "admin",
                VerbScope::ReadOnly,
                1_700_000_000,
                // The posture a fleet is in before its operator ceremony has run, under which
                // every one of the 17 money-governance verbs is refused. A view answers anyway,
                // because there is nothing for an operator to have approved about a read.
                Some(busbar_unit_verbs::PostureCtx {
                    operator: busbar_unit_verbs::OperatorState::Unset,
                    dual_control: busbar_unit_verbs::DualControl::Required,
                }),
                busbar_unit_verbs::ApprovalState::NotYetApproved,
                b"",
            )
            .unwrap_or_else(|r| panic!("{verb:?} was refused: {r:?}"));
        let answer = AdminAnswer::unpack(&packed).expect("the view packs an answer");
        assert_eq!(answer.status, 200);
    }
    assert_eq!(
        calls.load(Ordering::Relaxed),
        0,
        "a ledger view reached the dispatch, which has no handler for it"
    );

    // The control: a money-governance verb under the same posture IS refused, so the green above
    // is the views being exempt rather than the posture check being unbound.
    let verbs = busbar_unit_verbs::Verbs::new(
        CoreGovernance::new(
            Arc::new(CountingDispatch(Arc::clone(&calls))),
            Arc::new(SeededLedger),
            KernelVerb::Adjust,
            a_ledger_request("/api/v1/admin/adjust"),
        ),
        crate::root::kernel::RefusingStore,
        ArrivalNonce(1),
        PackedReplay,
        CONFIG_CLASS_RULES,
    );
    assert!(verbs
        .execute(
            KernelVerb::Adjust,
            &admin,
            "admin",
            VerbScope::Full,
            1_700_000_000,
            Some(busbar_unit_verbs::PostureCtx {
                operator: busbar_unit_verbs::OperatorState::Unset,
                dual_control: busbar_unit_verbs::DualControl::Required,
            }),
            busbar_unit_verbs::ApprovalState::NotYetApproved,
            b"",
        )
        .is_err());
}

/// The additive document describes exactly the operations the closed table declares, and not one
/// path the pinned 1.5.5 document already has.
///
/// That second clause is the additivity claim itself. "Additive" is not a promise that the new
/// document is small; it is the statement that nothing in it collides with a path a 1.5.5 client
/// already knows, so the two documents can be read side by side without either contradicting the
/// other.
#[test]
fn the_additive_document_describes_the_ledger_views_and_nothing_the_pinned_one_has() {
    let additive: serde_json::Value =
        serde_json::from_str(LEDGER_OPENAPI_ADDITIVE).expect("the additive document is JSON");
    let paths = additive["paths"].as_object().expect("it declares paths");

    let mut declared: Vec<&str> = paths.keys().map(String::as_str).collect();
    declared.sort_unstable();
    let mut expected: Vec<&str> = LEDGER_PATHS.to_vec();
    expected.sort_unstable();
    assert_eq!(
        declared, expected,
        "the document and the closed table declare different operations"
    );

    for (path, item) in paths {
        let op = &item["get"];
        assert!(
            op.is_object(),
            "{path} is described under a method the table does not declare"
        );
        assert_eq!(
            op["x-busbar-required-scope"], "read-only",
            "{path} is documented at a scope it is not served at"
        );
        let operation_id = op["operationId"].as_str().expect("an operationId");
        let verb = busbar_plane_admin::verbs::resolve("GET", path)
            .expect("the table declares it")
            .verb;
        assert_eq!(
            snake_of(operation_id),
            verb,
            "{path}: the document's operationId is not the table's verb"
        );
    }

    let pinned: serde_json::Value = serde_json::from_str(include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../testing/shadow-oracle/fixtures/openapi-1.5.5.json"
    )))
    .expect("the pinned fixture is JSON");
    let pinned_paths = pinned["paths"].as_object().expect("it declares paths");
    for path in paths.keys() {
        assert!(
            !pinned_paths.contains_key(path),
            "{path} collides with a path the pinned 1.5.5 document already declares"
        );
    }
    // And from the other side: the served 1.5.5 document has no ledger path at all, which is
    // what leaving the released document's bytes alone means.
    assert!(
        !pinned_paths
            .keys()
            .any(|p| p.starts_with("/api/v1/admin/ledger/")),
        "the pinned document has grown a ledger path"
    );
}

/// `GetLedgerTotals` -> `get_ledger_totals`, so the test above can compute the expected verb
/// name rather than hand-transcribing a second copy of the five-row mapping.
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
    use crate::root::ledger_identity::{LedgerRow, LedgerSnapshot, RowKey};

    let hostile = "a\"b\\c\nd\te\u{1}";
    let mut rows = LedgerSnapshot::new();
    rows.insert(
        RowKey::new(hostile, A_DAY, hostile, hostile),
        LedgerRow {
            priced_nanos: 1,
            fee_count: 0,
        },
    );
    let parsed: serde_json::Value =
        serde_json::from_str(&render_totals(&rows)).expect("a hostile name still renders JSON");
    assert_eq!(parsed["rows"][0]["bucket"], hostile);
    assert_eq!(parsed["rows"][0]["lane"], hostile);
    assert_eq!(parsed["rows"][0]["provider"], hostile);
}

/// THE MOUNTED LEG ANSWERS A RECORDED REQUEST BYTE-IDENTICAL, THROUGH THE PLANE'S OWN FACE.
///
/// `busbar_contract::Plane` declares sixteen methods, five planes in this tree implement every one
/// of them, and until this landing the served path called NONE: the only `&dyn Plane` bindings
/// anywhere were in the egress unit and in an object-safety fixture, so the contract's codec face
/// had zero production callers. The admin leg is the one plane already in the Teller loop, so it is
/// the one that can be put through the face first.
///
/// Both halves are here, and the second is the one with a recorded byte behind it.
///
/// **Ingress.** The step used to ask the plane's verb TABLE directly — the same closed table
/// `decode_ingress` walks, reached around the face rather than through it. It now composes the
/// envelope the plane reads a request line out of and asks the plane. The class it answers is the
/// class the table names, because `decode_ingress` and `resolve` run the same `find_verb`; every
/// other admin cell in this file already drives the new path, because the fixture builder calls
/// `decode` to put the verb in the table.
///
/// **Egress.** The answer is the executing verb's own bytes and the plane's response encoder is a
/// verbatim pass-through, so this asserts the thing that would actually break: what leaves the
/// encode step is the recorded cell's body, byte for byte, with nothing re-rendered, re-serialised
/// or re-ordered on the way through the face. The bytes compared against are the ORACLE's own
/// recording of the published binary's answer, read out of the golden tree here and not restated.
///
/// THE ONE BYTE THAT WOULD HAVE MOVED, named because a landing that claims none must say where the
/// risk was. The plane declares a single exception to the pass-through: where the response carries
/// a `verb` fact naming the OpenAPI document, it substitutes `info.version` for the PLANE's own
/// version. The recorded cell holds the EXECUTING unit's rendering. So the encode step does not
/// stamp that fact — the plane's own documented default for an absent one is the pass-through —
/// and `admin.ops|GetOpenapiJson|ok` is unmoved. Whoever wants the substitution owes the recording.
#[cfg(feature = "root-admin")]
#[test]
fn the_mounted_leg_answers_a_recorded_golden_through_the_planes_own_face() {
    const GOLDEN: &str = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../testing/shadow-oracle/golden/1.5.5/cells/admin.ops__GetAdminAuth__ok.json"
    ));
    let cell: serde_json::Value = serde_json::from_str(GOLDEN).expect("the golden cell parses");
    let recorded = serde_json::to_vec(&cell["body"]["json"]).expect("the recorded body serialises");

    let mut request = a_request();
    request.method = "GET".to_string();
    request.path = "/api/v1/admin/admin-auth".to_string();
    let (binding, ctx, seal) = a_bound_unit(request);
    crate::open_record!(record, &ctx);

    // INGRESS, through the face: the plane read the request line and named the class.
    let op = decode(&binding, &UnitToken::mint(&seal), &record)
        .into_result(&seal)
        .expect("the plane decodes a request line the closed table declares");
    let resolved = binding
        .units
        .verb(ctx.key)
        .expect("and the same table names the kernel verb the unit routes to");
    assert_eq!(
        op,
        resolved.op_class(),
        "the class the plane answered is the class the row it resolved prices under"
    );

    // AND IT READ THIS REQUEST LINE, not a request line. The closed split has two sides, so a
    // second unit on the mutating side is what says the answer above came off the bytes rather
    // than off anything constant: fix the envelope's path to any one operation and this reds while
    // the read above still passes.
    let mut mutating = a_request();
    mutating.method = "POST".to_string();
    mutating.path = "/api/v1/admin/operator-key".to_string();
    let (write_binding, write_ctx, write_seal) = a_bound_unit(mutating);
    crate::open_record!(write_record, &write_ctx);
    let write_op = decode(&write_binding, &UnitToken::mint(&write_seal), &write_record)
        .into_result(&write_seal)
        .expect("the plane decodes the mutating row too");
    assert_ne!(
        write_op, op,
        "a write and a read are not one class, and the plane read which of them arrived"
    );

    // EGRESS, through the face: the recorded answer goes in and the recorded answer comes out.
    binding.units.set_answer(
        ctx.key,
        AdminAnswer {
            status: cell["status"].as_u64().expect("the cell records a status") as u16,
            headers: Vec::new(),
            body: recorded.clone(),
        },
    );
    let frame = encode(
        &binding,
        &UnitToken::mint(&seal),
        &record,
        &busbar_caps::Outcome::Completed,
    )
    .into_result(&seal)
    .expect("the encode step answers");
    assert_eq!(
        frame.bytes.as_slice(),
        recorded.as_slice(),
        "the bytes that leave are the recorded answer's bytes, through the plane's own encoder"
    );
}
