// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Mutex;
use std::task::{Context, Poll};

use busbar_contract::abi::mechanism::call::{AbiStr, Field, Outcome as AbiOutcome, Span};
use busbar_contract::abi::mechanism::ticket::Ticket;
use busbar_contract::abi::plane::{
    ArriveIn, ArriveOut, OnPieceIn, OnPieceOut, ProjectIn, ProjectOut, RecordWrite, RefusalIn,
    RefusalOut, ServeIn, ServeOut, AUDIT_APPLIED, RECORD_AUDIT, ROUTE_PUBLIC,
};
use busbar_contract::plane_calls::{
    Answered, Grow, InstanceDecl, Lent, PieceInFlight, PlaneCalls, ServeInFlight,
};
use busbar_contract::services::{Caller, HostServices as _, Ran, Stored, TrustKeyRef};

use super::*;
use crate::plane_driver::AuditSink;

type Crossed = (String, Vec<String>);

/// A plane whose `serve` keeps the target and head field names it was handed, answers `200`, and
/// asks for one audit row.
#[derive(Default)]
struct Echo {
    crossed: Mutex<Vec<Crossed>>,
    next: AtomicU32,
    /// The status it answers (`0`: `200`).
    status: AtomicU32,
    /// The audit outcome it reports for the route's own row (`0`: none).
    audit: AtomicU32,
    /// When set, `serve` relays one trust decision through the plugin trust-decision interface
    /// (`trust.decide`) under the request's ticket, as a plane admin route does (r3 G10, R8).
    relay: Mutex<Option<Relay>>,
}

/// The trust decision a relaying [`Echo`] makes for its counterparty, and where it sends the
/// kernel's answer.
struct Relay {
    services: Arc<crate::host_services::KernelServices>,
    caller: Caller,
    counterparty: String,
    expected: Option<String>,
    approve: bool,
    answers: tokio::sync::mpsc::UnboundedSender<Stored>,
}

const READY: Answered = Answered {
    outcome: AbiOutcome::Ready,
    short: false,
    disposition: None,
};

struct Now(ServeOut);
// SAFETY: plain data the double wrote; its pointers are never dereferenced.
unsafe impl Send for Now {}

impl Future for Now {
    type Output = Answered;
    fn poll(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<Answered> {
        Poll::Ready(READY)
    }
}

impl ServeInFlight for Now {
    fn out(&self) -> Option<ServeOut> {
        Some(self.0)
    }
}

struct NoPiece;

impl Future for NoPiece {
    type Output = Answered;
    fn poll(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<Answered> {
        Poll::Ready(Answered {
            outcome: AbiOutcome::Fault,
            short: false,
            disposition: None,
        })
    }
}

impl PieceInFlight for NoPiece {
    fn settled(&mut self) -> Option<Answered> {
        None
    }
    fn out(&self) -> Option<OnPieceOut> {
        None
    }
}

/// The bytes `s` points at.
///
/// # Safety
/// `s` points at `s.len` live bytes (the host's buffers, for the crossing).
unsafe fn text(s: AbiStr) -> String {
    let bytes = unsafe { std::slice::from_raw_parts(s.ptr, s.len) };
    String::from_utf8_lossy(bytes).into_owned()
}

const ROW: (&[u8], &[u8]) = (b"door.check", b"door:a");

impl PlaneCalls for Echo {
    fn now_ns(&self) -> u64 {
        0
    }
    fn arrive(
        &self,
        _: &mut ArriveIn,
        _: &mut ArriveOut,
        _: Grow<'_, ArriveIn, ArriveOut>,
    ) -> AbiOutcome {
        AbiOutcome::Fault
    }
    fn arrived_pool(&self, _: &ArriveOut) -> Option<Vec<u8>> {
        None
    }
    fn refusal(
        &self,
        _: &mut RefusalIn,
        _: &mut RefusalOut,
        _: Grow<'_, RefusalIn, RefusalOut>,
    ) -> AbiOutcome {
        AbiOutcome::Fault
    }
    fn project(
        &self,
        _: &mut ProjectIn,
        _: &mut ProjectOut,
        _: Grow<'_, ProjectIn, ProjectOut>,
    ) -> AbiOutcome {
        AbiOutcome::Ready
    }
    fn cancel(&self, _: Ticket, _: u64) -> Option<busbar_contract::plane_calls::Cancelled> {
        None
    }
    fn declared(&self) -> InstanceDecl {
        InstanceDecl {
            label: "echo".into(),
            ..InstanceDecl::default()
        }
    }
    fn driver(&self) -> Option<Ticket> {
        self.mint()
    }
    fn tick(&self, _: Ticket, _: u64) -> Pin<Box<dyn Future<Output = Option<u64>> + Send>> {
        Box::pin(std::future::ready(Some(0)))
    }
    fn ready(&self) -> Pin<Box<dyn Future<Output = Vec<u64>> + Send>> {
        Box::pin(std::future::ready(Vec::new()))
    }
    fn mint(&self) -> Option<Ticket> {
        Some(Ticket {
            slot: self.next.fetch_add(1, Ordering::SeqCst),
            generation: 1,
        })
    }
    fn recycle(&self, _: Ticket) {}
    fn drop_client(&self, _: Ticket) {}
    fn serve(
        &self,
        ticket: Ticket,
        i: ServeIn,
        mut o: ServeOut,
        _: Lent,
    ) -> Box<dyn ServeInFlight> {
        if let Some(relay) = self.relay.lock().unwrap().as_ref() {
            let answers = relay.answers.clone();
            let key = TrustKeyRef {
                counterparty: &relay.counterparty,
                item: None,
            };
            let ran = relay.services.trust_decide(
                &relay.caller,
                ticket,
                key,
                relay.expected.as_deref(),
                relay.approve,
                Box::new(move |stored| {
                    let _ = answers.send(stored);
                }),
            );
            if let Ran::Now(stored) = ran {
                let _ = relay.answers.send(stored);
            }
        }
        // SAFETY: the driver's target and `fields_len` head fields, live for the crossing. An empty
        // head crosses as a null pointer (`FieldList::as_ptr`), which no slice may be built over.
        let target = unsafe { text(i.target) };
        let fields: &[Field] = if i.fields_len == 0 {
            &[]
        } else {
            unsafe { std::slice::from_raw_parts(i.fields, i.fields_len) }
        };
        let names = fields.iter().map(|f| unsafe { text(f.name) }).collect();
        self.crossed.lock().unwrap().push((target, names));
        let (key, value) = ROW;
        let words = [key, value].concat();
        assert!(words.len() <= i.arena_cap && i.records_cap > 0);
        // SAFETY: the driver's arena of `arena_cap` bytes and records buffer of `records_cap`.
        unsafe {
            std::ptr::copy_nonoverlapping(words.as_ptr(), i.arena_buf, words.len());
            *i.records_buf = RecordWrite {
                kind: AUDIT_APPLIED,
                op: RECORD_AUDIT,
                key: Span {
                    offset: 0,
                    len: key.len() as u32,
                },
                value: Span {
                    offset: key.len() as u32,
                    len: value.len() as u32,
                },
            };
        }
        o.arena_written = words.len() as u64;
        o.records_written = 1;
        o.audit = self.audit.load(Ordering::SeqCst);
        o.status = match self.status.load(Ordering::SeqCst) {
            0 => 200,
            n => n,
        };
        Box::new(Now(o))
    }
    fn on_piece(&self, _: Ticket, _: OnPieceIn, _: OnPieceOut, _: Lent) -> Box<dyn PieceInFlight> {
        Box::new(NoPiece)
    }
}

/// An audit sink that keeps every row's action and principal.
#[derive(Default)]
struct Rows(Mutex<Vec<(String, String)>>);

#[test]
fn a_composition_route_collision_publishes_none_of_its_staged_instances() {
    let tables = ServeTables::default();
    let reader = tables.clone();
    let table = |instance: &str, target: &str| ServeTable {
        instance: instance.into(),
        audit_kind: "door".into(),
        calls: Arc::new(Echo::default()),
        caps: BufferCaps::default(),
        routes: vec![ServeRoute {
            verb: "GET".into(),
            target: target.into(),
            flags: 0,
            audit_verb: String::new(),
        }],
        records: None,
    };
    tables.publish(table("existing", "/held"), &[]).unwrap();
    assert!(tables
        .publish_batch(vec![table("one", "/new"), table("two", "/held")], &[])
        .is_err());
    assert_eq!(
        reader
            .0
            .now
            .load()
            .tables
            .iter()
            .map(|t| t.instance.as_str())
            .collect::<Vec<_>>(),
        ["existing"]
    );
    tables
        .publish_batch(vec![table("one", "/new"), table("two", "/another")], &[])
        .unwrap();
    assert_eq!(
        reader
            .0
            .now
            .load()
            .tables
            .iter()
            .map(|t| t.instance.as_str())
            .collect::<Vec<_>>(),
        ["existing", "one", "two"]
    );
}

impl AuditSink for Rows {
    fn record(&self, action: &str, _: &str, _: &'static str, principal: &str) {
        self.0
            .lock()
            .unwrap()
            .push((action.to_string(), principal.to_string()));
    }
}

#[tokio::test]
async fn a_door_plane_admin_route_sees_no_consumed_credential_and_its_row_names_the_actor() {
    let echo = std::sync::Arc::new(Echo::default());
    let tables = ServeTables::default();
    tables
        .publish(
            ServeTable {
                instance: "served-at-red".to_string(),
                audit_kind: "door".to_string(),
                calls: echo.clone(),
                caps: BufferCaps::default(),
                routes: vec![ServeRoute {
                    verb: "GET".to_string(),
                    target: "/served-at-red/{name}/health".to_string(),
                    flags: 0,
                    audit_verb: String::new(),
                }],
                records: None,
            },
            &[],
        )
        .expect("publishes");
    let consumed = crate::auth::ConsumedCredentials::carrying(&[
        axum::http::HeaderName::from_static("x-admin-token"),
        axum::http::header::AUTHORIZATION,
        axum::http::HeaderName::from_static("x-api-key"),
        axum::http::HeaderName::from_static("x-goog-api-key"),
        axum::http::HeaderName::from_static("dpop"),
    ]);
    let mut headers = axum::http::HeaderMap::new();
    for (name, value) in [
        ("x-admin-token", "operator-secret"),
        ("authorization", "Bearer operator-secret"),
        ("x-api-key", "k"),
        ("x-goog-api-key", "g"),
        ("dpop", "proof"),
        ("x-trace", "t-1"),
    ] {
        headers.insert(name, axum::http::HeaderValue::from_static(value));
    }
    let principal = AuthPrincipal(Some(busbar_contract::auth::Principal::from_id("op")));
    let rows = Rows::default();
    let served = tables
        .served_at_to(
            &rows,
            AdminServe {
                method: "GET",
                path: "/served-at-red/a/health",
                query: Some("x=1"),
                headers: &headers,
                consumed: Some(&consumed),
                principal: Some(&principal),
                trust_authority: None,
            },
            Bytes::new(),
        )
        .await;
    tables.withdraw("served-at-red");
    assert_eq!(
        served
            .expect("an instance names it")
            .expect("served")
            .status,
        200
    );
    let crossed = echo.crossed.lock().unwrap().clone();
    let [(target, names)] = crossed.as_slice() else {
        panic!("one crossing: {crossed:?}");
    };
    for credential in [
        "x-admin-token",
        "authorization",
        "x-api-key",
        "x-goog-api-key",
        "dpop",
    ] {
        assert!(
            !names.iter().any(|n| n == credential),
            "`{credential}` crossed to the plane: {names:?}"
        );
    }
    assert!(names.iter().any(|n| n == "x-trace"), "{names:?}");
    assert_eq!(target, "/served-at-red/a/health?x=1");
    assert_eq!(
        rows.0.lock().unwrap().as_slice(),
        [("door.check".to_string(), "op".to_string())]
    );
}

#[tokio::test]
async fn an_applied_answer_whose_head_cannot_render_is_still_audited() {
    crate::audit::auditlog::ensure_global_audit_stream_registered().await;
    let echo = std::sync::Arc::new(Echo::default());
    echo.status.store(1_000, Ordering::SeqCst);

    echo.audit.store(AUDIT_APPLIED, Ordering::SeqCst);
    let tables = ServeTables::default();
    tables
        .publish(
            ServeTable {
                instance: "unrendered-red".to_string(),
                audit_kind: "unrendered".to_string(),
                calls: echo.clone(),
                caps: BufferCaps::default(),
                routes: vec![ServeRoute {
                    verb: "POST".to_string(),
                    target: "/unrendered-red/{name}/ping".to_string(),
                    flags: ROUTE_PUBLIC,
                    audit_verb: "ping".to_string(),
                }],
                records: None,
            },
            &[],
        )
        .expect("publishes");
    let resp = tables
        .answer_public(
            "POST",
            "/unrendered-red/a/ping",
            "/unrendered-red/a/ping",
            &axum::http::HeaderMap::new(),
            Bytes::new(),
        )
        .await;
    tables.withdraw("unrendered-red");
    assert_eq!(resp.status(), 502, "no response can carry status 1000");
    crate::audit::auditlog::flush_pending()
        .await
        .expect("native applied-answer audit confirmed");
    let rows =
        crate::audit::auditlog::AUDIT_LOG.list_filtered(0, 16, Some("unrendered.ping"), None);
    assert_eq!(rows.len(), 1, "the applied mutation is audited: {rows:?}");
    assert_eq!(rows[0].resource, "unrendered:a");
    assert_eq!(rows[0].outcome, busbar_contract::vocab::OUTCOME_APPLIED);
}

/// The plane caller an instance's served requests are keyed by.
fn a_plane(instance: &str) -> Caller {
    Caller::for_test(
        Arc::from(instance),
        busbar_contract::abi::mechanism::KindCode::Plane,
    )
}

/// A kernel with a host pool admitting `instance` with one counterparty, `peer`, sighted at `h1`;
/// with `custody`, its trust decisions are kept in a bound decision record (r3 §6).
async fn a_trust_kernel(
    instance: &str,
    custody: bool,
) -> Arc<crate::host_services::KernelServices> {
    use busbar_contract::abi::host::service as svc;
    let k = crate::host_services::KernelServices::new().with_pool(Arc::new(
        crate::host_services::BlockingPool::new(tokio::runtime::Handle::current(), 8),
    ));
    let k = if custody {
        k.with_test_custody().await
    } else {
        k
    };
    k.admit(
        instance,
        crate::host_services::InstanceFacts {
            trust: vec![(
                "peer".to_string(),
                crate::trust::section::TrustEntry {
                    pin: None,
                    policy: crate::trust::reverify::Policy {
                        ttl_ms: 0,
                        recovery_backoff_ms: 0,
                    },
                    approved: Default::default(),
                },
            )],
            ..crate::host_services::InstanceFacts::default()
        },
    )
    .await
    .expect("admitted");
    let (sent, settled) = tokio::sync::oneshot::channel();
    let sighted = match k.trust_sight(
        &a_plane(instance),
        "peer",
        "h1",
        Box::new(move |stored| {
            let _ = sent.send(stored);
        }),
    ) {
        Ran::Now(stored) => stored,
        Ran::Later => settled.await.expect("the sighting settles"),
    };
    assert_eq!(sighted.value, svc::TRUST_NEW);
    Arc::new(k)
}

/// [`Echo`] published as `instance` with a mutating admin route `POST /{instance}/{name}/decide`
/// and a read route `GET /{instance}/{name}/peek`, its records keyed by its plane caller. The
/// caller is returned too: the plugin decides through that very binding (a trust decision grant is
/// keyed by the binding's incarnation and the ticket, 32ab284dd9), never through another one.
fn a_relaying_plane(
    instance: &str,
    services: &Arc<crate::host_services::KernelServices>,
) -> (ServeTables, Arc<Echo>, Caller) {
    let echo = Arc::new(Echo::default());
    let caller = a_plane(instance);
    let tables = ServeTables::default();
    let route = |verb: &str, at: &str| ServeRoute {
        verb: verb.to_string(),
        target: format!("/{instance}/{{name}}/{at}"),
        flags: 0,
        audit_verb: String::new(),
    };
    tables
        .publish(
            ServeTable {
                instance: instance.to_string(),
                audit_kind: "relay".to_string(),
                calls: echo.clone(),
                caps: BufferCaps::default(),
                routes: vec![route("POST", "decide"), route("GET", "peek")],
                records: Some((Arc::clone(services), caller.clone())),
            },
            &[],
        )
        .expect("publishes");
    (tables, echo, caller)
}

/// One admin request at `path` (relative to the admin mount) as the inner router receives it after
/// the admin gate admitted `op`: with `authority`, the trust decision authority the gate built
/// from its own verdict; `None`, none.
async fn relayed(
    (tables, echo, caller): &(ServeTables, Arc<Echo>, Caller),
    instance: &str,
    services: &Arc<crate::host_services::KernelServices>,
    (method, path): (&str, &str),
    authority: Option<crate::host_services::TrustDecisionAuthority>,
    (expected, approve): (Option<&str>, bool),
    request_id: &str,
) -> Stored {
    assert_eq!(
        caller.namespace().as_ref(),
        instance,
        "the plane's own binding"
    );
    let (answers, mut answered) = tokio::sync::mpsc::unbounded_channel();
    *echo.relay.lock().unwrap() = Some(Relay {
        services: Arc::clone(services),
        caller: caller.clone(),
        counterparty: "peer".to_string(),
        expected: expected.map(str::to_string),
        approve,
        answers,
    });
    let mut req = axum::http::Request::builder()
        .method(method)
        .uri(format!("{}{path}", crate::admin::gate::ADMIN_PREFIX))
        .body(Body::empty())
        .expect("a request");
    req.extensions_mut().insert(AuthPrincipal(Some(
        busbar_contract::auth::Principal::from_id("op"),
    )));
    if let Some(authority) = authority {
        req.extensions_mut().insert(authority);
    }
    let response = crate::admin::gate::with_request_id(request_id.to_string(), tables.answer(req))
        .await
        .expect("the instance names the route");
    assert_eq!(response.status(), 200, "the plane answered its route");
    *echo.relay.lock().unwrap() = None;
    answered
        .recv()
        .await
        .expect("the kernel answers the plugin's decision")
}

/// The authority the admin gate builds for a full grant ([`crate::auth::trust_decision_authority`]).
fn a_full_grant() -> crate::host_services::TrustDecisionAuthority {
    crate::auth::trust_decision_authority(&crate::auth::AdminDoor::Identified(
        busbar_contract::auth::Principal::from_id("op"),
        busbar_contract::authz::Grants::of(busbar_contract::authz::Scope::Full),
    ))
    .expect("a full grant decides")
}

/// The authority the admin gate builds for a console whose non-empty `verbs` list names
/// `trust_revoke` and not `trust_approve` (asserted through the closed verb table in core-admin's
/// `trust_authority_verb_list_tests`; the kernel alone holds no verb table).
fn a_revoke_only_grant() -> crate::host_services::TrustDecisionAuthority {
    crate::host_services::TrustDecisionAuthority {
        principal: "revoker".to_string(),
        approve: false,
        revoke: true,
    }
}

fn pinned(k: &crate::host_services::KernelServices, instance: &str) -> Option<String> {
    k.trust_rows()
        .into_iter()
        .find(|r| r.key() == format!("{instance}/peer"))
        .and_then(|r| r.approved)
}

/// The typed trust rows written for plane `instance`'s decisions, oldest first.
async fn typed_rows(instance: &str) -> Vec<crate::audit_ring::AuditEntry> {
    crate::audit::auditlog::flush_pending()
        .await
        .expect("the audit rows are confirmed");
    let mut rows: Vec<_> = crate::audit::auditlog::AUDIT_LOG
        .list_filtered(0, 64, None, Some(&format!("plane:{instance}")))
        .into_iter()
        .filter(|row| row.action.starts_with("trust_"))
        .collect();
    rows.reverse();
    rows
}

/// G10 (TRUST-ADMIN-PRODUCER-DESIGN r3 §4.2 (a)–(c), conditions B-C1 and B-C2): a decision a plane
/// admin route relays through the plugin trust-decision interface needs the gate's authority for
/// that ruling, is attributed `Instance{instance, principal}`, approves only at a reviewed digest,
/// revokes without one, and writes one typed row whose `request_id` is the admin request's.
#[tokio::test]
async fn plane_relayed_decision_is_gated_attributed_and_strict() {
    use busbar_contract::abi::host::service as svc;
    use busbar_contract::json::JsonValueTrait as _;
    crate::audit::auditlog::ensure_global_audit_stream_registered().await;
    let instance = "g10-relay";
    let k = a_trust_kernel(instance, true).await;
    let plane = a_relaying_plane(instance, &k);
    let decide = ("POST", "/g10-relay/peer/decide");

    let no_grant = relayed(
        &plane,
        instance,
        &k,
        decide,
        None,
        (Some("h1"), true),
        "r_g10-a",
    )
    .await;
    assert_eq!(
        no_grant.outcome,
        AbiOutcome::Refused,
        "no authority, no decision"
    );
    let wrong_ruling = relayed(
        &plane,
        instance,
        &k,
        decide,
        Some(a_revoke_only_grant()),
        (Some("h1"), true),
        "r_g10-b",
    )
    .await;
    assert_eq!(
        wrong_ruling.outcome,
        AbiOutcome::Refused,
        "an authority without trust_approve approves nothing"
    );
    assert_eq!(pinned(&k, instance), None, "nothing was approved");

    let unreviewed = relayed(
        &plane,
        instance,
        &k,
        decide,
        Some(a_full_grant()),
        (None, true),
        "r_g10-c",
    )
    .await;
    assert_eq!(
        unreviewed.value,
        svc::UNDECIDED_STALE,
        "no key-only approve"
    );
    assert_eq!(pinned(&k, instance), None);

    let approved = relayed(
        &plane,
        instance,
        &k,
        decide,
        Some(a_full_grant()),
        (Some("h1"), true),
        "r_g10-approve",
    )
    .await;
    assert_eq!(approved.value, svc::TRUST_DECIDED_SERVING);
    assert_eq!(pinned(&k, instance).as_deref(), Some("h1"));

    let revoked = relayed(
        &plane,
        instance,
        &k,
        decide,
        Some(a_revoke_only_grant()),
        (None, false),
        "r_g10-revoke",
    )
    .await;
    assert_eq!(
        revoked.value,
        svc::TRUST_DECIDED_PENDING,
        "a revoke needs no reviewed digest"
    );
    assert!(
        k.trust_judge(
            instance,
            &crate::trust::book::TrustFacts {
                counterparty: "peer",
                item: None,
                digest: None,
            },
        )
        .is_err(),
        "revoked, it no longer serves"
    );
    plane.0.withdraw(instance);

    let rows = typed_rows(instance).await;
    let seen: Vec<_> = rows
        .iter()
        .map(|row| {
            (
                row.action.as_str(),
                row.outcome.as_str(),
                row.principal.as_str(),
                row.request_id.as_deref(),
            )
        })
        .collect();
    assert_eq!(
        seen,
        [
            ("trust_approve", "rejected", "op", Some("r_g10-c")),
            ("trust_approve", "applied", "op", Some("r_g10-approve")),
            ("trust_revoke", "applied", "revoker", Some("r_g10-revoke")),
        ],
        "one typed row per decision attempted under a grant, each carrying its admin request's id"
    );
    for (row, principal) in rows.iter().zip(["op", "op", "revoker"]) {
        let data = busbar_contract::json::parse_value(row.data.as_str().as_bytes())
            .expect("the typed row's data is JSON");
        assert_eq!(data["decided_by"]["kind"].as_str(), Some("instance"));
        assert_eq!(data["decided_by"]["instance"].as_str(), Some(instance));
        assert_eq!(data["decided_by"]["principal"].as_str(), Some(principal));
    }
}

/// G10 (r3 §4.1, condition A-C1): a plane-relayed decision on a kernel with no bound decision
/// record is refused as unkept, is never applied in memory only, and is audited once.
#[tokio::test]
async fn plane_relayed_decision_without_custody_is_never_applied_in_memory() {
    use busbar_contract::json::JsonValueTrait as _;
    crate::audit::auditlog::ensure_global_audit_stream_registered().await;
    let instance = "g10-unbound";
    let k = a_trust_kernel(instance, false).await;
    let plane = a_relaying_plane(instance, &k);
    let before = k.trust_rows();
    let unkept = relayed(
        &plane,
        instance,
        &k,
        ("POST", "/g10-unbound/peer/decide"),
        Some(a_full_grant()),
        (Some("h1"), true),
        "r_g10-unbound",
    )
    .await;
    plane.0.withdraw(instance);
    assert_eq!(
        unkept.outcome,
        AbiOutcome::Failed,
        "the decision cannot be kept"
    );
    assert_eq!(k.trust_rows(), before, "nothing changed in memory");
    let rows = typed_rows(instance).await;
    let [row] = rows.as_slice() else {
        panic!("one typed row: {rows:?}");
    };
    assert_eq!(
        (row.action.as_str(), row.outcome.as_str()),
        ("trust_approve", "rejected")
    );
    let data = busbar_contract::json::parse_value(row.data.as_str().as_bytes())
        .expect("the typed row's data is JSON");
    assert_eq!(data["reason"].as_str(), Some("service_unavailable"));
}

/// R8 (r3 §4.2a, condition B-C1), end to end through a plane admin route: a request the gate lent
/// no trust authority, one whose authority does not admit `trust_approve`, and a read route under a
/// full authority all reach the plane, and the plugin's approve through the trust-decision
/// interface is refused every time; nothing changes and no decision is audited.
#[tokio::test]
async fn plane_route_without_trust_verbs_cannot_decide() {
    crate::audit::auditlog::ensure_global_audit_stream_registered().await;
    let instance = "r8-relay";
    let k = a_trust_kernel(instance, true).await;
    let plane = a_relaying_plane(instance, &k);
    let before = k.trust_rows();
    for (route, authority, why) in [
        (
            ("POST", "/r8-relay/peer/decide"),
            None,
            "no admission-grant extension reached the inner router",
        ),
        (
            ("POST", "/r8-relay/peer/decide"),
            Some(a_revoke_only_grant()),
            "the verbs list admits the route but not trust_approve",
        ),
        (
            ("GET", "/r8-relay/peer/peek"),
            Some(a_full_grant()),
            "a read route lends no trust authority",
        ),
    ] {
        let decided = relayed(
            &plane,
            instance,
            &k,
            route,
            authority,
            (Some("h1"), true),
            "r_r8",
        )
        .await;
        assert_eq!(decided.outcome, AbiOutcome::Refused, "{why}");
        assert_eq!(k.trust_rows(), before, "{why}: nothing changes");
    }
    plane.0.withdraw(instance);
    assert_eq!(pinned(&k, instance), None);
    assert!(
        typed_rows(instance).await.is_empty(),
        "no decision was made to audit"
    );
}
