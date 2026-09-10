//! Tests for `audit.rs`. Lifted out of the implementation file so its line count
//! measures implementation and nothing else; still a direct child module, so `use
//! super::*` reaches the private items it always did.

use super::*;
use crate::engine::POOL_LABEL_UNRESOLVED;
use crate::test_support::{LaneSpec, TestApp};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use busbar_caps::KernelSeal;
use busbar_core::proxy::reqlog::{RequestRecord, REQUESTS};
use busbar_store_memory::MemoryStore;
use busbar_substrate::testkit::engine_kit::EngineTestKit as _;

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
    gov: &'a busbar_contract::store::PlaneRequestCtx,
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
fn governed(
    names: [&str; 2],
) -> (
    Arc<crate::test_support::BuiltApp>,
    [busbar_contract::store::VirtualKey; 2],
) {
    let store = Arc::new(MemoryStore::new());
    let signer = busbar_substrate::governance::signing::TokenSigner::from_secret_bytes(
        &[7u8; 32],
        busbar_substrate::governance::signing::DEFAULT_KID,
    );
    let gov = crate::test_support::engine_kit::CORE_ENGINE_KIT
        .governance(store, None, Some(signer))
        .unwrap();
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
        .governance_kit(gov)
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
    busbar_substrate::metrics::init();
    let (app, keys) = governed([&unique("audit-live"), &unique("audit-unit")]);
    let (host, _rt) = crate::engine::test_host_rt(&app);
    let at = busbar_substrate::store::now();

    let live_gov = busbar_contract::store::PlaneRequestCtx {
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

    let unit_gov = busbar_contract::store::PlaneRequestCtx {
        key: Some(Arc::new(keys[1].clone())),
    };
    let (seal, token) = tokens();
    let unit = audit(
        &token,
        &ctx(&host, &unit_gov, "p", at),
        Served::of((StatusCode::BAD_GATEWAY, "upstream said no").into_response()),
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
    let unit = unit.response.into_response();

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
    busbar_substrate::metrics::init();
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

    let live_gov = busbar_contract::store::PlaneRequestCtx {
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

    let unit_gov = busbar_contract::store::PlaneRequestCtx {
        key: Some(Arc::new(keys[1].clone())),
    };
    let (_seal, token) = tokens();
    let unit = audit_refused(
        &token,
        &ctx(&host, &unit_gov, POOL_LABEL_UNRESOLVED, at),
        Served::of(refusal()),
    )
    .response
    .into_response();

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
    busbar_substrate::metrics::init();
    let (app, keys) = governed([&unique("doors-admitted"), &unique("doors-refused")]);
    let (host, _rt) = crate::engine::test_host_rt(&app);
    let at = busbar_substrate::store::now();

    let admitted_gov = busbar_contract::store::PlaneRequestCtx {
        key: Some(Arc::new(keys[0].clone())),
    };
    let (_seal, token) = tokens();
    let _ = audit(
        &token,
        &ctx(&host, &admitted_gov, "p", at),
        Served::of((StatusCode::NOT_FOUND, "no such model").into_response()),
        true,
    );
    let refused_gov = busbar_contract::store::PlaneRequestCtx {
        key: Some(Arc::new(keys[1].clone())),
    };
    let _ = audit_refused(
        &token,
        &ctx(&host, &refused_gov, POOL_LABEL_UNRESOLVED, at),
        Served::of((StatusCode::NOT_FOUND, "no such model").into_response()),
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
    busbar_substrate::metrics::init();
    let (app, keys) = governed([&unique("verify-a"), &unique("verify-b")]);
    let (host, _rt) = crate::engine::test_host_rt(&app);
    let at = busbar_substrate::store::now();
    let gov = busbar_contract::store::PlaneRequestCtx {
        key: Some(Arc::new(keys[0].clone())),
    };
    let (_seal, token) = tokens();
    for _ in 0..3 {
        let _ = audit(
            &token,
            &ctx(&host, &gov, "p", at),
            Served::of((StatusCode::OK, "ok").into_response()),
            true,
        );
    }
    let refused = busbar_contract::store::PlaneRequestCtx {
        key: Some(Arc::new(keys[1].clone())),
    };
    let _ = audit_refused(
        &token,
        &ctx(&host, &refused, POOL_LABEL_UNRESOLVED, at),
        Served::of((StatusCode::FORBIDDEN, "no").into_response()),
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
    busbar_substrate::metrics::init();
    let (app, keys) = governed([&unique("label-live"), &unique("label-unit")]);
    let (host, _rt) = crate::engine::test_host_rt(&app);
    let at = busbar_substrate::store::now();

    let live_gov = busbar_contract::store::PlaneRequestCtx {
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

    let unit_gov = busbar_contract::store::PlaneRequestCtx {
        key: Some(Arc::new(keys[1].clone())),
    };
    let (_seal, token) = tokens();
    let _ = audit_refused(
        &token,
        &ctx(&host, &unit_gov, "p", at),
        Served::of((StatusCode::FORBIDDEN, "not permitted").into_response()),
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

/// THE FOUR ENDS THE TERMINAL CAN SEAL, and where each comes from.
///
/// Without a tap the class is the client-facing status and only two values are reachable — which
/// is the whole of what this step could say before, and is still what it says while a response is
/// in flight. With a tap the class is the tap's, and a 2xx stream that died mid-body seals
/// `Partial` rather than the `Complete` its status line claims. `TurnComplete` appears in neither
/// column: it names one turn of a duplex exchange whose session continues, and no dialect this
/// plane speaks has one.
#[tokio::test]
async fn the_sealed_end_is_the_taps_where_there_is_one_and_the_status_where_there_is_not() {
    crate::testkit::install_test_seams();
    busbar_substrate::metrics::init();
    let (app, keys) = governed([&unique("finish-a"), &unique("finish-b")]);
    let (host, _rt) = crate::engine::test_host_rt(&app);
    let at = busbar_substrate::store::now();
    let gov = busbar_contract::store::PlaneRequestCtx {
        key: Some(Arc::new(keys[0].clone())),
    };
    let (seal, token) = tokens();

    // A report the tap could have made, on a response the status line calls a success. One cell
    // per case, because a cell is filled once and a second report is a no-op by design.
    let tapped = |finish| {
        let cell = crate::engine::TapCell::new();
        cell.report(crate::engine::TapReport {
            lane: 0,
            usage: None,
            billing_failed: !matches!(finish, crate::engine::TapFinish::Complete),
            finish,
        });
        let mut resp = (StatusCode::OK, "ok").into_response();
        resp.extensions_mut().insert(cell);
        resp
    };

    for (resp, want, why) in [
        (
            tapped(crate::engine::TapFinish::Complete),
            FinishClass::Complete,
            "the whole answer arrived",
        ),
        (
            tapped(crate::engine::TapFinish::Partial),
            FinishClass::Partial,
            "a 2xx stream that died mid-body — the end no status line can name",
        ),
        (
            tapped(crate::engine::TapFinish::Error),
            FinishClass::Error,
            "a transfer that failed after the upstream's 2xx headers",
        ),
        (
            (StatusCode::OK, "ok").into_response(),
            FinishClass::Complete,
            "no tap: the client-facing status, exactly as before",
        ),
        (
            (StatusCode::BAD_GATEWAY, "no").into_response(),
            FinishClass::Error,
            "no tap, non-2xx: still the status",
        ),
    ] {
        let audited = audit(&token, &ctx(&host, &gov, "p", at), Served::of(resp), true);
        let facts = audited
            .decision
            .into_result(&seal)
            .expect("the terminal seals rather than refuses");
        assert_eq!(facts.finish, want, "{why}");
        assert_ne!(
            facts.finish,
            FinishClass::TurnComplete,
            "{why}: this plane opens no session, so no unit of it ends a turn of one"
        );
        let _ =
            axum::body::to_bytes(audited.response.into_response().into_body(), usize::MAX).await;
    }
}

/// The step is the `Units::audit` row's shape, as a value: a mismatch in the token, the context
/// or the answer stops compiling here rather than at the root.
#[test]
fn the_step_has_the_terminals_shape() {
    let _: AuditStep = audit;
}

// ── THE BYTE-IDENTITY TABLE ──────────────────────────────────────────────────────────────────
//
// The rule the waist is held to is not "the two paths refuse for the same reason", it is that a
// client cannot tell which path answered it. That is a claim about BYTES, and a claim about
// bytes has to be checked over the whole product of what varies: the refusal CLASS (which
// status/kind/message/own-headers a turn-away carries) times the DIALECT the envelope is poured
// into (six on this plane, each with its own member names, nesting and synthesized headers).
//
// The two things compared are the two things that actually exist: `ingress_error`, which every
// live arm of the legacy door calls directly, and `render_refusal`, the ONE place a named
// refusal becomes bytes on the waist. They are compared as a CLIENT sees them — status, headers
// and body — rather than by inspecting that one calls the other, because "one calls the other"
// is exactly the property a future hand-rolled envelope in a step file would quietly stop
// having while still compiling.

/// The per-call NONCE an Anthropic-dialect envelope mints (`req_…`, in both the body member and
/// the mirrored response header) blanked to a fixed token, so two renderings of the same refusal
/// differ in nothing else. Nothing but the id is touched: the surrounding bytes, including the
/// quoting and the member order, are compared exactly as produced.
fn scrub_request_id(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut rest = s;
    while let Some(at) = rest.find("req_") {
        out.push_str(&rest[..at]);
        out.push_str("req_<nonce>");
        let tail = &rest[at + 4..];
        let end = tail
            .find(|c: char| !c.is_ascii_alphanumeric())
            .unwrap_or(tail.len());
        rest = &tail[end..];
    }
    out.push_str(rest);
    out
}

/// The headers whose VALUE is a per-call nonce or a wall clock, and so cannot agree between two
/// calls of the SAME function, let alone two paths. Two dialects mint one: Anthropic's
/// `request-id` and Bedrock's `x-amzn-requestid` (the other four mint none). Their values are
/// MASKED rather than dropped, so whether the header is present at all still has to agree — a
/// path that stopped synthesizing a dialect's request id is exactly the kind of proxy tell this
/// comparison exists to catch, and dropping the row outright would hide it.
const NONCE_HEADERS: [&str; 3] = ["date", "request-id", "x-amzn-requestid"];

/// A response as a client can observe it: the status, the headers, and the body, with the
/// nonces above masked. Everything else — content type, member names, member ORDER, quoting,
/// the sentence — is compared exactly as produced.
async fn observable(resp: Response) -> (u16, Vec<(String, String)>, String) {
    let status = resp.status().as_u16();
    let mut headers: Vec<(String, String)> = resp
        .headers()
        .iter()
        .map(|(n, v)| {
            let value = if NONCE_HEADERS.contains(&n.as_str()) {
                "<nonce>".to_string()
            } else {
                String::from_utf8_lossy(v.as_bytes()).into_owned()
            };
            (n.as_str().to_string(), value)
        })
        .collect();
    headers.sort();
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap_or_default();
    (
        status,
        headers,
        scrub_request_id(&String::from_utf8_lossy(&bytes)),
    )
}

/// Every refusal class the plane can turn a caller away with before it has an upstream answer,
/// as the three values a refusal IS plus the headers it carries in its own right. The
/// status/kind pairs are the live ones: the group-limit arms in `busbar_core::ingress` for the
/// quota and rate-limit rows, `VerifyRefusal` for the scope and unpriced rows, `DecodeRefusal` /
/// the route step for the not-found rows, and the arrival guards for the oversize row.
#[allow(clippy::type_complexity)]
fn refusal_classes() -> Vec<(
    &'static str,
    StatusCode,
    &'static str,
    &'static str,
    Vec<(HeaderName, HeaderValue)>,
)> {
    use busbar_substrate::proxy::{
        KIND_AUTHENTICATION, KIND_INSUFFICIENT_QUOTA, KIND_INVALID_REQUEST, KIND_NOT_FOUND,
        KIND_PERMISSION, KIND_RATE_LIMIT, KIND_REQUEST_TOO_LARGE, PROVIDER_CODE_CONTEXT_LENGTH,
    };
    vec![
        (
            "unauth",
            StatusCode::UNAUTHORIZED,
            KIND_AUTHENTICATION,
            "Invalid API key provided.",
            vec![],
        ),
        (
            "wrong-scope",
            StatusCode::FORBIDDEN,
            KIND_PERMISSION,
            "Your API key does not have permission to use pool 'p'.",
            vec![],
        ),
        (
            "over-budget",
            StatusCode::TOO_MANY_REQUESTS,
            KIND_INSUFFICIENT_QUOTA,
            "You have exceeded your current quota (group 'bgrp' budget per total exhausted). \
             Please check your plan and billing details.",
            vec![],
        ),
        // The one class that carries a header of its OWN: a rolling window tells a well-behaved
        // SDK how long to back off, and that header must survive the waist unchanged.
        (
            "rate-limit",
            StatusCode::TOO_MANY_REQUESTS,
            KIND_RATE_LIMIT,
            "Rate limit exceeded (group 'g': requests per minute). Please retry after the \
             indicated time.",
            vec![(
                HeaderName::from_static("retry-after"),
                HeaderValue::from_static("30"),
            )],
        ),
        (
            "unpriced",
            StatusCode::BAD_REQUEST,
            KIND_INVALID_REQUEST,
            "no configured rate for model 'm'",
            vec![],
        ),
        (
            "no-pool",
            StatusCode::NOT_FOUND,
            KIND_NOT_FOUND,
            "The model 'm' does not exist or you do not have access to it.",
            vec![],
        ),
        (
            "oversize-body",
            StatusCode::PAYLOAD_TOO_LARGE,
            KIND_REQUEST_TOO_LARGE,
            "Request body is too large.",
            vec![],
        ),
        // The breaker's synthesized provider code, which is a DIALECT-FOREIGN token on every
        // wire: each writer projects it into its own vocabulary, so it is the sharpest row in
        // the table for catching a path that skipped the projection.
        (
            "context-overflow",
            StatusCode::BAD_REQUEST,
            PROVIDER_CODE_CONTEXT_LENGTH,
            "prompt is too long: 300000 tokens > 200000 maximum",
            vec![],
        ),
    ]
}

/// THE BYTE-IDENTITY RULE, over every refusal class times every dialect: what the waist's
/// terminal renders is what the legacy door's live arms render, to the byte.
///
/// A divergence here is a client-visible one — a `type` an SDK's error factory cannot map, a
/// dropped `Retry-After`, a status a vendor never returns for that condition — so the failure
/// message names the class, the dialect and the two renderings rather than only that they
/// differed.
#[tokio::test]
async fn every_refusal_class_renders_byte_identically_on_both_paths() {
    // The dialects that mint a request id synthesize it from the plane's own RNG seam, which is
    // process-wide. Install the test seams so this rig produces the SAME set of header rows
    // whether it runs alone or beside the rest of the suite — without it the nonce headers are
    // present or absent depending on what else has run, and the table would be order-dependent
    // about which rows it even compares.
    crate::testkit::install_test_seams();
    let dialects = [
        crate::proto_codec::PROTO_ANTHROPIC,
        crate::proto_codec::PROTO_OPENAI,
        crate::proto_codec::PROTO_GEMINI,
        crate::proto_codec::PROTO_BEDROCK,
        crate::proto_codec::PROTO_COHERE,
        crate::proto_codec::PROTO_RESPONSES,
    ];
    let classes = refusal_classes();
    assert_eq!(classes.len(), 8, "every refusal class stays in the table");

    for (name, status, kind, message, own) in classes {
        for proto in dialects {
            // The legacy door: `ingress_error` with the three values, then the refusal's own
            // headers stamped over the envelope — the order every live arm stamps them in.
            let mut legacy = busbar_substrate::proxy::ingress_error(proto, status, kind, message);
            for (n, v) in &own {
                legacy.headers_mut().insert(n.clone(), v.clone());
            }
            // The waist: the same refusal NAMED as a value, poured out at the one terminal.
            let outcome = own
                .iter()
                .fold(RefusalOutcome::new(status, kind, message), |acc, (n, v)| {
                    acc.with_header(n.clone(), v.clone())
                });
            let teller = render_refusal(proto, &outcome);

            let (ls, lh, lb) = observable(legacy).await;
            let (ts, th, tb) = observable(teller).await;
            assert_eq!(
                (ls, &lh, &lb),
                (ts, &th, &tb),
                "{name} on the {proto} wire diverges between the legacy door and the waist:\n  \
                 legacy: {ls} {lh:?} {lb}\n  teller: {ts} {th:?} {tb}"
            );
            // A rendering that answered nothing at all would be byte-equal to another
            // rendering that answered nothing at all, so pin that the row produced a real
            // envelope: the class's status, and a body carrying its sentence.
            assert_eq!(ts, status.as_u16(), "{name}/{proto} wears its own status");
            assert!(
                !tb.is_empty(),
                "{name}/{proto} renders an envelope, not an empty body"
            );
        }
    }
}
