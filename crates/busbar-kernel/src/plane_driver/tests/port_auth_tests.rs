// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! IF §12.11 route auth and §12.15 refusals over the plane port: the class each request runs under, the identity
//! and ticket record the plane is handed, and the refusal a denial becomes.

use busbar_contract::secure::SecureVec;
use busbar_plugin_abi::fail::refused::{
    R_AUTH_REQUIRED, R_BAD_CREDENTIAL, R_EXPIRED, R_POLICY, R_REPLAYED,
};
use busbar_plugin_abi::host_side::caller::BoxFut;
use busbar_plugin_abi::plane::{
    AUTH_OPERATOR, AUTH_OPTIONAL, AUTH_PRINCIPAL, AUTH_PUBLIC, AUTH_SIGNED_INGRESS, AUTH_TICKET,
};
use busbar_plugin_abi::records::{tag as g, Records};
use busbar_ports::auth::Identity;

use super::{
    admit, bearer, classify, effective_classes, plain_refusal, subject_identity, Credentials,
    Presented, Principal, Subject, TicketDoor,
};
use crate::plane_driver::port_session::ToClient;
use crate::plane_grants::{TicketAdmitted, TicketDenied};
use crate::refusal::CoreRefusals;

const TICKET: &str = "ek_bbt1.sealed";

struct Door {
    outcome: Result<(&'static str, Option<&'static [u8]>), TicketDenied>,
}

impl TicketDoor for Door {
    fn is_ticket(&self, credential: &str) -> bool {
        credential.contains("bbt1.")
    }

    fn admit<'a>(
        &'a self,
        _audience: &'a str,
        _credential: &'a str,
        _now_s: u64,
    ) -> BoxFut<'a, Result<TicketAdmitted, TicketDenied>> {
        Box::pin(async move {
            match &self.outcome {
                Ok((subject, record)) => Ok(TicketAdmitted {
                    identity: Identity::from_ticket(subject, "realtime"),
                    record: record.map(|r| {
                        let mut v = SecureVec::new();
                        v.extend_from_slice(r);
                        v
                    }),
                }),
                Err(denied) => Err(*denied),
            }
        })
    }
}

fn door(outcome: Result<(&'static str, Option<&'static [u8]>), TicketDenied>) -> Door {
    Door { outcome }
}

fn ada() -> Principal {
    Principal::Verified(Subject::Shared(std::sync::Arc::from("ada")))
}

fn anonymous<'a>() -> Credentials<'a> {
    Credentials {
        bearer: None,
        principal: Principal::Anonymous,
        operator: false,
        signed: None,
    }
}

async fn run(
    effective: u32,
    creds: Credentials<'_>,
    door: &Door,
) -> Result<super::Admitted, crate::refusal::ClientRefusal> {
    admit(7, effective, &creds, door, &CoreRefusals::new(), "aud", 100).await
}

#[test]
fn the_default_effective_set_is_the_lowest_bit_plus_ticket_beside_principal() {
    assert_eq!(
        effective_classes(AUTH_PRINCIPAL | AUTH_TICKET, None),
        Ok(AUTH_PRINCIPAL | AUTH_TICKET)
    );
    assert_eq!(
        effective_classes(AUTH_OPTIONAL | AUTH_PUBLIC, None),
        Ok(AUTH_OPTIONAL)
    );
    assert_eq!(effective_classes(AUTH_PUBLIC, None), Ok(AUTH_PUBLIC));
    assert_eq!(
        effective_classes(AUTH_TICKET | AUTH_PUBLIC, None),
        Ok(AUTH_PUBLIC)
    );
}

#[test]
fn a_configured_set_must_lie_inside_the_mask() {
    let mask = AUTH_PRINCIPAL | AUTH_TICKET | AUTH_PUBLIC;
    assert_eq!(effective_classes(mask, Some(AUTH_TICKET)), Ok(AUTH_TICKET));
    assert!(effective_classes(mask, Some(AUTH_OPERATOR)).is_err());
    assert!(effective_classes(mask, Some(0)).is_err());
    assert!(effective_classes(0, None).is_err());
}

#[test]
fn a_ticket_beside_principal_is_classified_per_request() {
    let both = AUTH_PRINCIPAL | AUTH_TICKET;
    let d = door(Err(TicketDenied::Invalid));
    assert_eq!(classify(both, Some(TICKET), &d), AUTH_TICKET);
    assert_eq!(classify(both, Some("sk-key"), &d), AUTH_PRINCIPAL);
    assert_eq!(classify(both, None, &d), AUTH_PRINCIPAL);
    assert_eq!(classify(AUTH_PUBLIC, Some(TICKET), &d), AUTH_PUBLIC);
}

#[test]
fn the_bearer_is_read_from_the_authorization_header_whatever_its_case() {
    let h: Vec<(&str, &[u8])> = vec![("x", b"y"), ("Authorization", b"bearer abc")];
    assert_eq!(bearer(h.iter().copied()), Some("abc"));
    let h: Vec<(&str, &[u8])> = vec![("authorization", b"Basic abc")];
    assert_eq!(bearer(h.iter().copied()), None);
    assert_eq!(bearer(std::iter::empty()), None);
}

#[tokio::test]
async fn principal_without_an_identity_is_refused_and_a_bad_credential_is_named() {
    let d = door(Err(TicketDenied::Invalid));
    let r = run(AUTH_PRINCIPAL, anonymous(), &d).await.unwrap_err();
    assert_eq!((r.code, r.status), (R_AUTH_REQUIRED, 401));
    let creds = Credentials {
        principal: Principal::Rejected(busbar_plugin_abi::kinds::auth::auth::BAD_CREDENTIAL),
        ..anonymous()
    };
    let r = run(AUTH_PRINCIPAL, creds, &d).await.unwrap_err();
    assert_eq!((r.code, r.status), (R_BAD_CREDENTIAL, 401));
}

#[tokio::test]
async fn principal_hands_the_plane_the_verified_identity_records() {
    let d = door(Err(TicketDenied::Invalid));
    let creds = Credentials {
        principal: ada(),
        ..anonymous()
    };
    let a = run(AUTH_PRINCIPAL, creds, &d).await.unwrap();
    assert_eq!(a.auth, AUTH_PRINCIPAL);
    assert_eq!(a.identity_records(), subject_identity("ada").as_slice());
    assert!(a.ticket_record().is_empty());
}

#[tokio::test]
async fn optional_and_public_admit_without_credentials_and_with_an_empty_identity() {
    let d = door(Err(TicketDenied::Invalid));
    for class in [AUTH_OPTIONAL, AUTH_PUBLIC] {
        let a = run(class, anonymous(), &d).await.unwrap();
        assert_eq!(a.auth, class);
        assert!(a.identity.is_none());
        assert!(a.identity_records().is_empty());
    }
}

#[tokio::test]
async fn optional_refuses_a_credential_that_was_presented_and_rejected() {
    let d = door(Err(TicketDenied::Invalid));
    let creds = Credentials {
        principal: Principal::Rejected(busbar_plugin_abi::kinds::auth::auth::EXPIRED),
        ..anonymous()
    };
    let r = run(AUTH_OPTIONAL, creds, &d).await.unwrap_err();
    assert_eq!(r.code, R_EXPIRED);
}

#[tokio::test]
async fn a_ticket_admits_with_its_subject_and_record() {
    let d = door(Ok(("sess-1", Some(b"state"))));
    let creds = Credentials {
        bearer: Some(Presented::new(TICKET)),
        ..anonymous()
    };
    let a = run(AUTH_TICKET, creds, &d).await.unwrap();
    assert_eq!(a.auth, AUTH_TICKET);
    assert_eq!(a.ticket_record(), b"state");
    let mut recs = Records::new(a.identity_records());
    let first = recs.next().unwrap().unwrap();
    assert_eq!(first.tag, g::ID_SUBJECT);
    assert_eq!(first.text().unwrap(), "sess-1");
}

#[tokio::test]
async fn a_ticket_denial_is_final_and_maps_to_the_generic_codes() {
    for (denied, code, status) in [
        (TicketDenied::Invalid, R_BAD_CREDENTIAL, 401),
        (TicketDenied::Expired, R_EXPIRED, 401),
        (TicketDenied::Replayed, R_REPLAYED, 409),
        (
            TicketDenied::Unavailable,
            busbar_plugin_abi::fail::failed::F_UNAVAILABLE,
            502,
        ),
    ] {
        let d = door(Err(denied));
        // The same request also carries a verified principal: it is never tried after a ticket refusal.
        let creds = Credentials {
            bearer: Some(Presented::new(TICKET)),
            principal: ada(),
            ..anonymous()
        };
        let r = run(AUTH_PRINCIPAL | AUTH_TICKET, creds, &d)
            .await
            .unwrap_err();
        assert_eq!((r.code, r.status), (code, status), "{denied:?}");
    }
}

#[tokio::test]
async fn a_key_on_a_principal_and_ticket_route_runs_principal() {
    let d = door(Err(TicketDenied::Invalid));
    let creds = Credentials {
        bearer: Some(Presented::new("sk-key")),
        principal: ada(),
        ..anonymous()
    };
    let a = run(AUTH_PRINCIPAL | AUTH_TICKET, creds, &d).await.unwrap();
    assert_eq!(a.auth, AUTH_PRINCIPAL);
}

#[tokio::test]
async fn a_ticket_class_with_no_bearer_needs_authentication() {
    let d = door(Ok(("s", None)));
    let r = run(AUTH_TICKET, anonymous(), &d).await.unwrap_err();
    assert_eq!(r.code, R_AUTH_REQUIRED);
}

#[tokio::test]
async fn operator_and_signed_ingress_follow_what_the_route_checked() {
    let d = door(Err(TicketDenied::Invalid));
    let r = run(AUTH_OPERATOR, anonymous(), &d).await.unwrap_err();
    assert_eq!(r.code, R_POLICY);
    let ok = Credentials {
        operator: true,
        ..anonymous()
    };
    assert_eq!(
        run(AUTH_OPERATOR, ok, &d).await.unwrap().auth,
        AUTH_OPERATOR
    );
    let r = run(AUTH_SIGNED_INGRESS, anonymous(), &d).await.unwrap_err();
    assert_eq!(r.code, R_BAD_CREDENTIAL);
    let signed = Credentials {
        signed: Some(true),
        ..anonymous()
    };
    assert_eq!(
        run(AUTH_SIGNED_INGRESS, signed, &d).await.unwrap().auth,
        AUTH_SIGNED_INGRESS
    );
}

#[test]
fn a_subject_identity_is_one_id_subject_record() {
    let id = subject_identity("ada");
    let mut recs = Records::new(&id);
    let r = recs.next().unwrap().unwrap();
    assert_eq!((r.tag, r.text().unwrap()), (g::ID_SUBJECT, "ada"));
    assert!(recs.next().is_none());
}

#[test]
fn the_plain_refusal_is_a_head_the_text_and_an_end() {
    let refusal = crate::refusal::ClientRefusal {
        status: 401,
        code: R_AUTH_REQUIRED,
        text: "authentication required".into(),
    };
    let items = plain_refusal(&refusal);
    assert!(matches!(items[0], ToClient::Head { status: 401, .. }));
    assert_eq!(
        items[1],
        ToClient::Body(b"authentication required".to_vec())
    );
    assert_eq!(items[2], ToClient::End);
}

#[tokio::test]
async fn two_requests_as_one_principal_hand_the_plane_the_same_identity_bytes() {
    let d = door(Err(TicketDenied::Invalid));
    let key: std::sync::Arc<str> = std::sync::Arc::from("key-alice");
    let mut seen = Vec::new();
    for _ in 0..2 {
        let creds = Credentials {
            principal: Principal::Verified(Subject::Shared(std::sync::Arc::clone(&key))),
            ..anonymous()
        };
        seen.push(
            run(AUTH_PRINCIPAL, creds, &d)
                .await
                .unwrap()
                .identity_records()
                .to_vec(),
        );
    }
    assert_eq!(seen[0], seen[1]);
    assert_eq!(seen[0], subject_identity("key-alice"));
}

/// This thread's bytes allocated and freed so far (jemalloc's own per-thread counters).
#[cfg(not(target_env = "msvc"))]
fn thread_bytes() -> (u64, u64) {
    (
        tikv_jemalloc_ctl::thread::allocatedp::read().map_or(0, |m| m.get()),
        tikv_jemalloc_ctl::thread::deallocatedp::read().map_or(0, |m| m.get()),
    )
}

/// B-IDENTITY: one verified request's identity as the plane is handed it, on this thread: the
/// credentials carry the subject's owner (shared), `admit` writes its one ID_SUBJECT record once,
/// and the plane's bytes are read from it. Nanoseconds and bytes allocated per request, and the
/// bytes still held once every request has ended (must be 0). `B_IDENTITY_REQUESTS` sets the count.
#[cfg(not(target_env = "msvc"))]
fn b_identity_on_this_thread(requests: usize) -> (f64, f64, i64) {
    let d = door(Err(TicketDenied::Invalid));
    let name: std::sync::Arc<str> = std::sync::Arc::from("a-principal-subject-of-ordinary-length");
    let one = || {
        futures::executor::block_on(async {
            let creds = Credentials {
                principal: Principal::Verified(Subject::Shared(std::sync::Arc::clone(&name))),
                ..anonymous()
            };
            let a = run(AUTH_PRINCIPAL, creds, &d).await.unwrap();
            std::hint::black_box(a.identity_records());
        });
    };
    for _ in 0..requests.min(1000) {
        one();
    }
    let (a0, d0) = thread_bytes();
    let start = std::time::Instant::now();
    for _ in 0..requests {
        one();
    }
    let ns = start.elapsed().as_nanos() as f64 / requests as f64;
    let (a1, d1) = thread_bytes();
    let held = (a1 - a0) as i64 - (d1 - d0) as i64;
    (ns, (a1 - a0) as f64 / requests as f64, held)
}

#[test]
#[cfg(not(target_env = "msvc"))]
fn b_identity() {
    let requests = std::env::var("B_IDENTITY_REQUESTS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(200);
    let (ns, bytes, held) = b_identity_on_this_thread(requests);
    eprintln!("B-IDENTITY 1 thread: {ns:.0} ns/request, {bytes:.0} bytes allocated/request, {held} bytes held after");
    assert_eq!(held, 0, "every request's identity is released when it ends");
    let runs: Vec<(f64, f64, i64)> = std::thread::scope(|s| {
        let joins: Vec<_> = (0..8)
            .map(|_| s.spawn(|| b_identity_on_this_thread(requests)))
            .collect();
        joins.into_iter().map(|j| j.join().unwrap()).collect()
    });
    let ns = runs.iter().map(|r| r.0).sum::<f64>() / 8.0;
    let bytes = runs.iter().map(|r| r.1).sum::<f64>() / 8.0;
    eprintln!("B-IDENTITY 8 threads: {ns:.0} ns/request, {bytes:.0} bytes allocated/request, held after {:?}", runs.iter().map(|r| r.2).collect::<Vec<_>>());
    assert!(
        runs.iter().all(|r| r.2 == 0),
        "every request's identity is released when it ends"
    );
}

// ---------------------------------------------------------------------------------------------
// OWED SECURITY PROOFS at the native listener's per-route auth step (ci/owed/cut-root and
// ci/owed/cut SECURITY-OWED.tsv). The old door tests that proved these drove a whole listener;
// the decision they asserted is made here, in `admit`, for every native route.
// ---------------------------------------------------------------------------------------------

/// SECURITY-OWED `actual_signed_reader_preserves_credential_body_gate_and_revocation_custody`:
/// a signed-ingress route admits on the verified body signature and on nothing else. A verified
/// principal, the operator credential, or both, never stand in for it; an unverified or absent
/// signature is refused; and the admitted request carries NO identity, whatever else the caller
/// presented beside the signature.
#[tokio::test]
async fn a_signed_ingress_route_admits_only_on_the_signature_and_carries_no_identity() {
    let d = door(Err(TicketDenied::Invalid));
    for signed in [None, Some(false)] {
        for (principal, operator) in [
            (Principal::Anonymous, false),
            (ada(), false),
            (Principal::Anonymous, true),
            (ada(), true),
        ] {
            let creds = Credentials {
                principal,
                operator,
                signed,
                ..anonymous()
            };
            let refused = run(AUTH_SIGNED_INGRESS, creds, &d).await.unwrap_err();
            assert_eq!(
                refused.code, R_BAD_CREDENTIAL,
                "signed={signed:?} operator={operator}: nothing stands in for the signature"
            );
        }
    }
    let creds = Credentials {
        principal: ada(),
        operator: true,
        signed: Some(true),
        ..anonymous()
    };
    let admitted = run(AUTH_SIGNED_INGRESS, creds, &d).await.unwrap();
    assert_eq!(admitted.auth, AUTH_SIGNED_INGRESS);
    assert!(
        admitted.identity.is_none() && admitted.identity_records().is_empty(),
        "a signed request is admitted with no identity"
    );
    assert!(admitted.ticket_record().is_empty());
}

/// SECURITY-OWED `the_agent_trust_verbs_refuse_a_caller_holding_no_admin_token_or_the_wrong_one`
/// and `test_metrics_requires_auth_in_chain_mode`: a route that asks for the operator refuses
/// every caller that is not the operator: no credential, a verified data-plane principal (the
/// wrong token: it authenticates, as someone else), a rejected credential and a verified body
/// signature. Only the operator is admitted.
#[tokio::test]
async fn an_operator_route_refuses_every_caller_that_is_not_the_operator() {
    let d = door(Err(TicketDenied::Invalid));
    let not_the_operator = [
        anonymous(),
        Credentials {
            principal: ada(),
            ..anonymous()
        },
        Credentials {
            principal: Principal::Rejected(busbar_plugin_abi::kinds::auth::auth::BAD_CREDENTIAL),
            ..anonymous()
        },
        Credentials {
            principal: ada(),
            signed: Some(true),
            ..anonymous()
        },
    ];
    for (case, creds) in not_the_operator.into_iter().enumerate() {
        let refused = run(AUTH_OPERATOR, creds, &d).await.unwrap_err();
        assert_eq!(
            refused.code, R_POLICY,
            "case {case}: a caller that is not the operator was not refused by policy"
        );
    }
    let operator = Credentials {
        operator: true,
        ..anonymous()
    };
    assert_eq!(
        run(AUTH_OPERATOR, operator, &d).await.unwrap().auth,
        AUTH_OPERATOR
    );
}

/// SECURITY-OWED `an_unkeyed_unit_on_a_credential_claim_is_refused` and the three cases of
/// `plane_driver_principal_need.rs`: a route that requires a principal is satisfied by a verified
/// principal only. Holding the operator credential or a verified body signature without one is
/// still no identity, and is refused as unauthenticated.
#[tokio::test]
async fn a_principal_route_is_never_satisfied_by_the_operator_or_a_signature_alone() {
    let d = door(Err(TicketDenied::Invalid));
    for (operator, signed) in [(true, None), (false, Some(true)), (true, Some(true))] {
        let creds = Credentials {
            operator,
            signed,
            ..anonymous()
        };
        let refused = run(AUTH_PRINCIPAL, creds, &d).await.unwrap_err();
        assert_eq!(
            (refused.code, refused.status),
            (R_AUTH_REQUIRED, 401),
            "operator={operator} signed={signed:?}: admitted without a principal"
        );
    }
}

// ---------------------------------------------------------------------------------------------
// OWED P095-8 (pass2/owed/OWED-095.tsv: caller credential carriers and caller reference). Each
// proof drives the production path: `PortDriver::serve` and `PortSeat::answer_line` over a plane
// faked at its port that notes what every crossing was handed; `run_session` with the production
// books for the audit subject; the config resolver for the all-pools credential default.
// ---------------------------------------------------------------------------------------------

mod carriers {
    use std::num::NonZeroU64;
    use std::sync::{Arc, Mutex};

    use busbar_contract::abi::mechanism::KindCode;
    use busbar_contract::abi::plane::UnitCount;
    use busbar_contract::caps::{CallId, OriginKind};
    use busbar_contract::config::UpstreamCreds;
    use busbar_contract::services::Caller;
    use busbar_contract::UnitKey;
    use busbar_plugin_abi::fail::FaultReason;
    use busbar_plugin_abi::host_side::caller::BoxFut;
    use busbar_plugin_abi::plane::{
        AUDIT_APPLIED, AUTH_OPTIONAL, AUTH_PRINCIPAL, AUTH_PUBLIC, CALLERS_SHARED, MONEY_NONE,
        RENDER_CATALOG, ROUTE_CATALOG, ROUTE_LINE, SCOPE_NONE, SCOPE_WALK,
    };
    use busbar_plugin_abi::records::{tag as g, Records};
    use busbar_ports::plane::{
        PlaneIn, PlaneOut, PlanePort, PlaneSession, RouteInfo, TargetIn, UsageClass,
    };
    use busbar_ports::{CallCx, PortError};

    use crate::host_services::KernelServices;
    use crate::limits::process_admission::{AdmissionClass, ProcessAdmission};
    use crate::plane_driver::cancel::{CancelBill, Checkpoint, MoneySeam};
    use crate::plane_driver::port::{
        HttpHead, HttpIn, LineCaller, PortDriver, PortSeat, ServeError, ServeIn, Served, Unit,
        CLIENT_CREDENTIAL_FIELDS,
    };
    use crate::plane_driver::port_auth::{
        admit, subject_identity, Credentials, NoTickets, Presented, Principal, Subject,
    };
    use crate::plane_driver::port_intents::{IntentHost, Looked, Namespace, Resolver};
    use crate::plane_driver::port_money::{AuditRow, PortMoney};
    use crate::plane_driver::port_serve::{run_session, AuditOnly, Books, Drive, UnitBooks};
    use crate::plane_driver::port_session::{finish, Calls, Effects, ToClient};
    use crate::plane_driver::AuditSink;
    use crate::plugin_records::{CommitOp, CommitOutcome, RecordsDenied, Scope};
    use crate::refusal::CoreRefusals;
    use crate::registry::Generation;
    use crate::teller::{Ended, UnitCtx};

    const PUBLIC: u32 = 1;
    const CATALOG: u32 = 2;
    const CLAIM: u32 = 3;
    const OPEN: u32 = 4;
    const LINE: u32 = 5;
    /// The bytes every credential the caller presents is written with: no crossing may hold them.
    const SECRET: &[u8] = b"caller-secret-never-lent";

    fn refused() -> PortError {
        PortError::Refused {
            code: 1,
            text: "refused".into(),
            error: None,
        }
    }

    fn route(id: u32, flags: u32, auth: u32, pattern: &str) -> RouteInfo {
        RouteInfo {
            route: id,
            methods: 1,
            flags,
            auth,
            pattern: pattern.into(),
            cred_header: None,
            resource_kinds: Default::default(),
        }
    }

    /// What one crossing into the plane was handed.
    #[derive(Clone, Debug, PartialEq, Eq)]
    struct Crossed {
        call: &'static str,
        route: u32,
        auth: u32,
        what: u32,
        headers: Vec<(String, Vec<u8>)>,
        identity: Vec<u8>,
        ticket_record: Vec<u8>,
        carrier: u64,
        body: Vec<u8>,
        arg: Vec<u8>,
    }

    impl Crossed {
        fn of(call: &'static str, req: &PlaneIn<'_>, what: u32, body: &[u8], arg: &[u8]) -> Self {
            Self {
                call,
                route: req.route,
                auth: req.auth,
                what,
                headers: req
                    .headers
                    .iter()
                    .map(|pair| (pair.name.get().to_owned(), pair.value.get().to_vec()))
                    .collect(),
                identity: req.identity.to_vec(),
                ticket_record: req.ticket_record.to_vec(),
                carrier: req.carrier,
                body: body.to_vec(),
                arg: arg.to_vec(),
            }
        }

        /// Every byte this crossing was handed, the body and the render argument included.
        fn holds(&self, needle: &[u8]) -> bool {
            let has = |hay: &[u8]| hay.windows(needle.len()).any(|w| w == needle);
            self.headers
                .iter()
                .any(|(name, value)| has(name.as_bytes()) || has(value))
                || has(&self.identity)
                || has(&self.ticket_record)
                || has(&self.body)
                || has(&self.arg)
        }
    }

    /// A plane faked at its port: it notes every `request` and `render` crossing; its `request`
    /// refuses (a live plane session is an ffi handle), its `render` answers 200 "rendered".
    struct Recording {
        routes: Vec<RouteInfo>,
        crossed: Mutex<Vec<Crossed>>,
    }

    impl Recording {
        fn new(routes: Vec<RouteInfo>) -> Arc<Self> {
            Arc::new(Self {
                routes,
                crossed: Mutex::new(Vec::new()),
            })
        }

        fn take(&self) -> Vec<Crossed> {
            std::mem::take(&mut *self.crossed.lock().unwrap())
        }
    }

    impl PlanePort for Recording {
        fn route_admission(&self, id: u32) -> Option<(u32, u32, u32, &str)> {
            let r = self.routes.iter().find(|r| r.route == id)?;
            Some(if r.flags & ROUTE_CATALOG != 0 {
                (SCOPE_WALK, MONEY_NONE, CALLERS_SHARED, "pool")
            } else {
                (SCOPE_NONE, MONEY_NONE, CALLERS_SHARED, "")
            })
        }
        fn routes(&self) -> &[RouteInfo] {
            &self.routes
        }
        fn dialects(&self) -> &[Box<str>] {
            &[]
        }
        fn usage_classes(&self) -> &[UsageClass] {
            &[]
        }
        fn usage_shared(&self) -> (Arc<[UsageClass]>, Arc<[Box<str>]>) {
            Default::default()
        }
        fn facts(&self) -> u64 {
            0
        }
        fn tick_s(&self) -> Option<u64> {
            None
        }
        fn admin_openapi(&self) -> Option<&str> {
            None
        }
        fn charge(&self, _: FaultReason) {}
        fn request(
            &self,
            req: &PlaneIn<'_>,
            body: &[u8],
            _: &mut dyn FnMut(PlaneOut<'_>),
        ) -> Result<PlaneSession, PortError> {
            self.crossed
                .lock()
                .unwrap()
                .push(Crossed::of("request", req, 0, body, &[]));
            Err(refused())
        }
        fn upstream(
            &self,
            _: &mut PlaneSession,
            _: &TargetIn<'_>,
            _: &mut dyn FnMut(PlaneOut<'_>),
        ) -> Result<(), PortError> {
            Err(refused())
        }
        fn piece(
            &self,
            _: &mut PlaneSession,
            _: u32,
            _: u32,
            _: u32,
            _: &[u8],
            _: &mut dyn FnMut(PlaneOut<'_>),
        ) -> Result<(), PortError> {
            Err(refused())
        }
        fn rewrite(
            &self,
            _: &mut PlaneSession,
            _: &[u8],
            _: &mut dyn FnMut(PlaneOut<'_>),
        ) -> Result<(), PortError> {
            Err(refused())
        }
        fn end(&self, _: PlaneSession, _: &mut dyn FnMut(PlaneOut<'_>)) -> Result<(), PortError> {
            Err(refused())
        }
        fn render(
            &self,
            req: &PlaneIn<'_>,
            what: u32,
            arg: &[u8],
            sink: &mut dyn FnMut(PlaneOut<'_>),
        ) -> Result<(), PortError> {
            self.crossed
                .lock()
                .unwrap()
                .push(Crossed::of("render", req, what, &[], arg));
            sink(PlaneOut::Respond { status: 200 });
            sink(PlaneOut::Body(b"rendered"));
            sink(PlaneOut::End);
            Ok(())
        }
        fn probe(
            &self,
            _: &TargetIn<'_>,
            _: &mut dyn FnMut(PlaneOut<'_>),
        ) -> Result<PlaneSession, PortError> {
            Err(refused())
        }
        fn demux(
            &self,
            _: &str,
            _: &[u8],
            _: &mut dyn FnMut(PlaneOut<'_>),
        ) -> Result<(), PortError> {
            Err(refused())
        }
        fn admin<'a>(
            &'a self,
            _: CallCx,
            _: u32,
            _: &'a [u8],
        ) -> BoxFut<'a, Result<Vec<u8>, PortError>> {
            Box::pin(async { Err(refused()) })
        }
    }

    /// A host with no store: these routes state no intent.
    struct NoIntents;

    impl IntentHost for NoIntents {
        fn lookup<'a>(
            &'a self,
            _: Scope,
            _: u32,
            _: u32,
            _: &'a [u8],
            _: &'a mut Looked,
        ) -> BoxFut<'a, Result<(), RecordsDenied>> {
            Box::pin(std::future::ready(Err(RecordsDenied::Unavailable)))
        }
        fn store<'a>(
            &'a self,
            _: Scope,
            _: u32,
            _: u64,
            _: &'a [u8],
            _: &'a [u8],
        ) -> BoxFut<'a, Result<(), RecordsDenied>> {
            Box::pin(std::future::ready(Err(RecordsDenied::Unavailable)))
        }
        fn delete<'a>(&'a self, _: Scope, _: &'a [u8]) -> BoxFut<'a, Result<(), RecordsDenied>> {
            Box::pin(std::future::ready(Err(RecordsDenied::Unavailable)))
        }
        fn commit<'a>(
            &'a self,
            _: Scope,
            _: &'a [CommitOp<'a>],
        ) -> BoxFut<'a, Result<CommitOutcome, RecordsDenied>> {
            Box::pin(std::future::ready(Err(RecordsDenied::Unavailable)))
        }
        fn push<'a>(&'a self, _: u64, _: &'a [u8]) -> BoxFut<'a, Result<(), RecordsDenied>> {
            Box::pin(std::future::ready(Err(RecordsDenied::Unavailable)))
        }
        fn signal(&self, _: &[u8], _: Option<[u8; 32]>) {}
    }

    /// The unit's money seam: notes every posting it is asked for.
    #[derive(Default)]
    struct Seam(Mutex<Vec<String>>);

    impl MoneySeam for Seam {
        fn checkpoint(&self, _: &UnitCtx, _: &[UnitCount]) -> Checkpoint {
            self.0.lock().unwrap().push("checkpoint".into());
            Checkpoint::Continue
        }
        fn cancelled(&self, _: &UnitCtx, _: &CancelBill) {
            self.0.lock().unwrap().push("cancelled".into());
        }
        fn finished(&self, _: &UnitCtx) {
            self.0.lock().unwrap().push("finished".into());
        }
        fn served(&self, _: &UnitCtx, member: &str, _: &str) {
            self.0.lock().unwrap().push(format!("served {member}"));
        }
        fn dialled(&self, _: &UnitCtx) {
            self.0.lock().unwrap().push("dialled".into());
        }
        fn abandoned(&self, _: &UnitCtx, _: Ended) {
            self.0.lock().unwrap().push("abandoned".into());
        }
    }

    /// The audit chain: (action, principal) per row written.
    #[derive(Default)]
    struct Audits(Mutex<Vec<(String, String)>>);

    impl AuditSink for Audits {
        fn record(&self, action: &str, _: &str, _: &'static str, principal: &str) {
            self.0
                .lock()
                .unwrap()
                .push((action.into(), principal.into()));
        }
    }

    fn ctx(key: u64) -> UnitCtx {
        UnitCtx {
            call: CallId::UNBOUND,
            key: UnitKey::new(key),
            origin: OriginKind::Client,
            session: None,
            generation: Generation::FIRST,
            admin_listener: false,
            kernel_verb_only: false,
        }
    }

    fn money(seam: &Arc<Seam>, audits: &Arc<Audits>) -> PortMoney {
        PortMoney::new(
            Arc::clone(seam) as Arc<dyn MoneySeam>,
            Arc::from(vec!["tokens".to_string()]),
            Arc::clone(audits) as Arc<dyn AuditSink>,
        )
    }

    /// A governed unit: billed through its own money seam and audit chain.
    fn governed(seam: &Arc<Seam>, audits: &Arc<Audits>) -> Unit {
        Unit {
            money: money(seam, audits),
            ctx: ctx(9),
            journal: None,
        }
    }

    fn driver_of(plane: &Arc<Recording>) -> PortDriver {
        PortDriver::new(
            Arc::clone(plane) as Arc<dyn PlanePort>,
            Arc::new(KernelServices::new()),
            Caller::for_test(Arc::from("carrier-plane"), KindCode::Plane),
            Arc::new(CoreRefusals::new()),
            &|_| None,
        )
        .unwrap()
    }

    /// The caller's credential in every carrier core withholds (`CLIENT_CREDENTIAL_FIELDS`), in
    /// mixed case, beside the fields the plane may see, which carry exact bytes (not UTF-8, a
    /// repeated name, a mixed-case name).
    fn presented() -> Vec<(String, Vec<u8>)> {
        let mut fields = vec![("Accept".to_owned(), b"application/json".to_vec())];
        for (n, name) in CLIENT_CREDENTIAL_FIELDS.iter().enumerate() {
            let name = if n % 2 == 0 {
                name.to_ascii_uppercase()
            } else {
                (*name).to_owned()
            };
            let mut value = b"Bearer ".to_vec();
            value.extend_from_slice(SECRET);
            fields.push((name, value));
        }
        fields.push(("x-trace".to_owned(), b"t-1 \x00\xff raw".to_vec()));
        fields.push(("X-Trace".to_owned(), b"second".to_vec()));
        fields
    }

    /// What of [`presented`] a plane may see, exactly as it arrived and in order.
    fn permitted() -> Vec<(String, Vec<u8>)> {
        vec![
            ("Accept".to_owned(), b"application/json".to_vec()),
            ("x-trace".to_owned(), b"t-1 \x00\xff raw".to_vec()),
            ("X-Trace".to_owned(), b"second".to_vec()),
        ]
    }

    fn anonymous() -> Credentials<'static> {
        Credentials {
            bearer: None,
            principal: Principal::Anonymous,
            operator: false,
            signed: None,
        }
    }

    /// A caller the data chain verified as `key`, who presented its credential as a bearer.
    fn keyed(key: &'static str) -> Credentials<'static> {
        Credentials {
            bearer: Some(Presented::new("caller-secret-never-lent")),
            principal: Principal::Verified(Subject::Shared(Arc::from(key))),
            operator: false,
            signed: None,
        }
    }

    fn serve_in(
        budget: &Arc<ProcessAdmission>,
        route: u32,
        path: &str,
        creds: Credentials<'static>,
        unit: Option<Unit>,
    ) -> ServeIn<'static> {
        ServeIn {
            invocation: None,
            request: budget.try_enter(AdmissionClass::Data).unwrap(),
            admission: None,
            route,
            http: HttpIn::new(
                HttpHead::Text {
                    method: "POST".into(),
                    path: path.into(),
                    query: String::new(),
                    headers: presented(),
                },
                bytes::Bytes::from_static(b"go"),
                1,
            ),
            creds,
            audience: "",
            now_s: 0,
            unit,
            upstream: None,
            client: None,
            carrier: None,
            intents: Arc::new(NoIntents),
            models: vec!["m-a".to_owned(), "m-b".to_owned()],
        }
    }

    fn core() -> tokio::runtime::Runtime {
        crate::rt::current_thread().enable_all().build().unwrap()
    }

    /// No crossing was handed a credential carrier, nor the credential's bytes anywhere.
    fn lent_no_credential(crossed: &[Crossed], case: &str) {
        assert!(!crossed.is_empty(), "{case}: the plane was crossed");
        for c in crossed {
            assert!(
                !c.holds(SECRET),
                "{case}: the {} crossing was handed the caller's credential: {c:?}",
                c.call
            );
            for (name, _) in &c.headers {
                assert!(
                    !CLIENT_CREDENTIAL_FIELDS
                        .iter()
                        .any(|field| field.eq_ignore_ascii_case(name)),
                    "{case}: the {} crossing was lent the carrier `{name}`",
                    c.call
                );
            }
        }
    }

    /// The identity records are exactly one ID_SUBJECT naming `subject`, and nothing else.
    fn exactly_the_subject(identity: &[u8], subject: &str, case: &str) {
        assert_eq!(identity, subject_identity(subject).as_slice(), "{case}");
        let mut records = Records::new(identity);
        let only = records.next().unwrap().unwrap();
        assert_eq!(
            (only.tag, only.text().unwrap()),
            (g::ID_SUBJECT, subject),
            "{case}"
        );
        assert!(records.next().is_none(), "{case}: one record only");
    }

    /// OWED-095 E:29 (cut-root/TESTS.tsv:112): a native public route (AUTH_PUBLIC) is admitted
    /// without the data chain: the plane's serve is handed no identity, no ticket record and none
    /// of the caller's credential carriers (authorization, cookie, proxy-authorization and every
    /// other `CLIENT_CREDENTIAL_FIELDS` field), whether the caller presented nothing or a
    /// credential the chain verified elsewhere; its other fields reach it unchanged. Once the
    /// instance is withdrawn (its plane states no route), the route is not served: the port
    /// answers no route and the plane is never crossed.
    #[test]
    fn a_public_route_is_served_by_the_planes_serve_without_a_credential() {
        let plane = Recording::new(vec![route(PUBLIC, 0, AUTH_PUBLIC, "/hook")]);
        let driver = driver_of(&plane);
        let budget = ProcessAdmission::with_limits(4, 64, 8);
        for (case, creds) in [("no credential", anonymous()), ("a key", keyed("key-alice"))] {
            let served = core().block_on(driver.serve(serve_in(&budget, PUBLIC, "/hook", creds, None)));
            assert!(
                !matches!(served, Err(ServeError::NoRoute | ServeError::Cancelled)),
                "{case}: the public route is served"
            );
            let crossed = plane.take();
            let request = crossed
                .iter()
                .find(|c| c.call == "request")
                .unwrap_or_else(|| panic!("{case}: the plane's serve ran"));
            assert_eq!(request.auth, AUTH_PUBLIC, "{case}");
            assert!(request.identity.is_empty(), "{case}: no identity is handed");
            assert!(request.ticket_record.is_empty(), "{case}");
            assert_eq!(request.body, b"go", "{case}");
            lent_no_credential(&crossed, case);
            for c in &crossed {
                assert_eq!(c.headers, permitted(), "{case}: {} crossing", c.call);
            }
        }
        let withdrawn = Recording::new(Vec::new());
        let driver = driver_of(&withdrawn);
        let served = core().block_on(driver.serve(serve_in(
            &budget,
            PUBLIC,
            "/hook",
            anonymous(),
            None,
        )));
        assert!(
            matches!(served, Err(ServeError::NoRoute)),
            "a withdrawn instance's public route is not served"
        );
        assert!(withdrawn.take().is_empty(), "nothing reached the plane");
        assert_eq!(budget.used(), (0, 0), "every request's count was released");
    }

    /// OWED-095 F:126 (cut-root/TESTS.tsv:395): a native catalog route (ROUTE_CATALOG) is
    /// rendered by core (`render(RENDER_CATALOG)` over core's own list): the plane is never lent
    /// a caller credential field, keeps every permitted field's exact bytes in order, runs no
    /// session, and nothing is charged, even when a unit is handed in.
    #[test]
    fn a_catalog_never_lends_never_kept_fields_and_preserves_permitted_field_bytes() {
        let plane = Recording::new(vec![route(
            CATALOG,
            ROUTE_CATALOG,
            AUTH_PRINCIPAL,
            "/v1/models",
        )]);
        let driver = driver_of(&plane);
        let budget = ProcessAdmission::with_limits(4, 64, 8);
        let seam = Arc::new(Seam::default());
        let audits = Arc::new(Audits::default());
        for (case, unit) in [
            ("no unit", None),
            ("a unit", Some(governed(&seam, &audits))),
        ] {
            let served = core().block_on(driver.serve(serve_in(
                &budget,
                CATALOG,
                "/v1/models",
                keyed("key-alice"),
                unit,
            )));
            let Ok(Served::Ran(ran)) = served else {
                panic!("{case}: the catalog was not rendered");
            };
            assert!(
                matches!(ran.client.first(), Some(ToClient::Head { status: 200, .. })),
                "{case}: the plane's rendering is the answer"
            );
            assert!(matches!(ran.client.last(), Some(ToClient::End)), "{case}");
            assert_eq!((ran.member, ran.attempts), (None, 0), "{case}: nothing walked");
            let crossed = plane.take();
            assert_eq!(crossed.len(), 1, "{case}: one render, no session: {crossed:?}");
            let render = &crossed[0];
            assert_eq!((render.call, render.what), ("render", RENDER_CATALOG), "{case}");
            assert!(
                render.arg.windows(3).any(|w| w == b"m-a")
                    && render.arg.windows(3).any(|w| w == b"m-b"),
                "{case}: core's list is what is rendered"
            );
            assert_eq!(render.headers, permitted(), "{case}: permitted bytes kept");
            lent_no_credential(&crossed, case);
        }
        assert!(seam.0.lock().unwrap().is_empty(), "the catalog charged nothing");
        assert!(audits.0.lock().unwrap().is_empty(), "the catalog booked nothing");
        assert_eq!(budget.used(), (0, 0));
    }

    /// OWED-095 F:138 (cut-root/TESTS.tsv:407): a native line is handed no head field at all, so
    /// no external field (a forged session field, a credential) survives into it: whatever the
    /// line's bytes say, they are its body, and the only session id the plane is handed is the
    /// host line carrier's own (`PlaneIn.carrier`), with the carrier's principal as its identity.
    #[test]
    fn only_the_host_line_carrier_adds_a_session_after_external_fields_are_filtered() {
        let plane = Recording::new(vec![route(LINE, ROUTE_LINE, AUTH_PRINCIPAL, "/line")]);
        let seat = PortSeat {
            public_url: None,
            image: Arc::new(
                crate::plane_driver::image_identity::PlaneImageIdentity::new(
                    "line-plane".into(),
                    None,
                )
                .unwrap(),
            ),
            instance: "line-plane".into(),
            request_routes: Arc::new(
                crate::plane_driver::request_admission::RequestRoutes::new(
                    "line-plane",
                    None,
                    None,
                    None,
                )
                .unwrap(),
            ),
            channel_budget: crate::channels::budget::ChannelBudget::new().instance(),
            driver: Arc::new(driver_of(&plane)),
            audience: None,
            intents: Arc::new(NoIntents),
            who: Namespace {
                plugin: Arc::from("line-plane"),
                name: Arc::from("line-plane"),
                instance: 1,
                slot: 1,
            },
            upstream: None,
            carrier: None,
        };
        let mut line = b"x-busbar-session: forged-session\r\nauthorization: Bearer ".to_vec();
        line.extend_from_slice(SECRET);
        line.extend_from_slice(b"\r\n{\"op\":1}");
        let carrier = NonZeroU64::new(41).unwrap();
        for authenticated in [true, false] {
            let from = LineCaller {
                principal: Arc::from("key-alice"),
                authenticated,
            };
            let input = crate::plane_driver::SessionInput {
                bytes: line.clone(),
                custody: None,
            };
            let _ = core().block_on(seat.answer_line(carrier, 9, input, &from));
            let crossed = plane.take();
            assert!(!crossed.is_empty(), "authenticated={authenticated}: crossed");
            for c in &crossed {
                assert!(
                    c.headers.is_empty(),
                    "authenticated={authenticated}: a line is lent no field: {c:?}"
                );
                assert_eq!(
                    (c.route, c.carrier),
                    (LINE, carrier.get()),
                    "authenticated={authenticated}: the host carrier's id is the session"
                );
                assert!(c.ticket_record.is_empty());
            }
            let request = crossed.iter().find(|c| c.call == "request");
            if authenticated {
                let request = request.expect("an authenticated line is served");
                assert_eq!(request.body, line, "the line's bytes are its body, unchanged");
                exactly_the_subject(&request.identity, "key-alice", "line");
            } else {
                assert!(
                    request.is_none(),
                    "an unauthenticated carrier's line is refused before its serve"
                );
                assert!(crossed.iter().all(|c| c.identity.is_empty()));
            }
        }
    }

    /// OWED-095 D:84 (cut/TESTS.tsv:641): the port lends a plane no caller reference. On a
    /// governed unit and on an ungoverned request alike, the plane's request is handed the
    /// verified identity records (one ID_SUBJECT, LEDGER S-C8) and nothing else of the caller:
    /// no credential carrier, no credential bytes, no ticket record. (The dialect reaches the
    /// plane in `TargetIn`: port_upstream_tests `a_candidate_is_the_plane_s_target_with_its_params`.)
    #[test]
    fn every_piece_lends_the_units_claim_dialect_and_caller_reference() {
        let plane = Recording::new(vec![route(CLAIM, 0, AUTH_PRINCIPAL, "/claim")]);
        let driver = driver_of(&plane);
        let budget = ProcessAdmission::with_limits(4, 64, 8);
        let seam = Arc::new(Seam::default());
        let audits = Arc::new(Audits::default());
        let mut handed = Vec::new();
        for (case, unit) in [
            ("ungoverned", None),
            ("governed", Some(governed(&seam, &audits))),
        ] {
            let _ = core().block_on(driver.serve(serve_in(
                &budget,
                CLAIM,
                "/claim",
                keyed("key-alice"),
                unit,
            )));
            let crossed = plane.take();
            lent_no_credential(&crossed, case);
            let request = crossed
                .iter()
                .find(|c| c.call == "request")
                .unwrap_or_else(|| panic!("{case}: the plane's request ran"))
                .clone();
            assert_eq!(request.auth, AUTH_PRINCIPAL, "{case}");
            exactly_the_subject(&request.identity, "key-alice", case);
            assert!(request.ticket_record.is_empty(), "{case}");
            assert_eq!(request.headers, permitted(), "{case}");
            handed.push(request);
        }
        assert_eq!(
            handed[0], handed[1],
            "a governed and an ungoverned unit hand the plane the same caller inputs"
        );
    }

    /// OWED-095 D:91 (cut/TESTS.tsv:648): a unit admitted with no caller (an open route, no
    /// credential verified) is handed the identity as absent: empty identity records, no ticket
    /// record, no credential field, governed or not.
    #[test]
    fn a_unit_lent_no_caller_reference_frames_it_absent() {
        let plane = Recording::new(vec![route(OPEN, 0, AUTH_OPTIONAL, "/open")]);
        let driver = driver_of(&plane);
        let budget = ProcessAdmission::with_limits(4, 64, 8);
        let seam = Arc::new(Seam::default());
        let audits = Arc::new(Audits::default());
        for (case, unit) in [
            ("ungoverned", None),
            ("governed", Some(governed(&seam, &audits))),
        ] {
            let _ = core().block_on(driver.serve(serve_in(&budget, OPEN, "/open", anonymous(), unit)));
            let crossed = plane.take();
            lent_no_credential(&crossed, case);
            let request = crossed
                .iter()
                .find(|c| c.call == "request")
                .unwrap_or_else(|| panic!("{case}: the plane's request ran"));
            assert_eq!(request.auth, AUTH_OPTIONAL, "{case}");
            assert!(request.identity.is_empty(), "{case}: the caller is absent");
            assert!(request.ticket_record.is_empty(), "{case}");
            assert_eq!(request.headers, permitted(), "{case}");
        }
    }

    /// A plane whose one session answers 200 at once and, at its end, writes one AUDIT row.
    struct Audited;

    impl Calls for Audited {
        type Session = ();

        fn request(
            &self,
            _: &PlaneIn<'_>,
            _: &[u8],
            sink: &mut dyn FnMut(PlaneOut<'_>),
        ) -> Result<(), PortError> {
            sink(PlaneOut::Respond { status: 200 });
            sink(PlaneOut::End);
            Ok(())
        }
        fn piece(
            &self,
            _: &mut (),
            _: u32,
            _: u32,
            _: u32,
            _: &[u8],
            _: &mut dyn FnMut(PlaneOut<'_>),
        ) -> Result<(), PortError> {
            Err(refused())
        }
        fn rewrite(
            &self,
            _: &mut (),
            _: &[u8],
            _: &mut dyn FnMut(PlaneOut<'_>),
        ) -> Result<(), PortError> {
            Err(refused())
        }
        fn end(&self, _: (), sink: &mut dyn FnMut(PlaneOut<'_>)) -> Result<(), PortError> {
            sink(PlaneOut::Audit {
                verdict: AUDIT_APPLIED,
                action: "acted",
                resource: "r",
            });
            Ok(())
        }
        fn probe(&self, _: &TargetIn<'_>, _: &mut dyn FnMut(PlaneOut<'_>)) -> Result<(), PortError> {
            Err(refused())
        }
        fn render(
            &self,
            _: &PlaneIn<'_>,
            _: u32,
            _: &[u8],
            _: &mut dyn FnMut(PlaneOut<'_>),
        ) -> Result<(), PortError> {
            Err(refused())
        }
        fn upstream(
            &self,
            _: &mut (),
            _: &TargetIn<'_>,
            _: &mut dyn FnMut(PlaneOut<'_>),
        ) -> Result<(), PortError> {
            Err(refused())
        }
    }

    struct Quiet;

    impl Effects for Quiet {
        fn emit(&self, _: u64, _: &[u8]) {}
    }

    /// OWED-095 G:53 (cut-root/TESTS.tsv:508): the audit subject a unit's rows are sealed under
    /// is the principal the auth step resolved for that request (the subject `admit` handed the
    /// plane, which `PortDriver::serve` hands the books), and for a request no credential was
    /// verified for (an open chain) the anonymous actor: never another request's key, never one
    /// invented. Both books are the production ones (a governed unit's `UnitBooks`, an unbilled
    /// request's `AuditOnly`), driven by `run_session`.
    #[test]
    fn the_loop_attributes_the_identity_the_door_resolved_and_invents_none() {
        let refusals = CoreRefusals::new();
        let resolver = Resolver::new(&NoIntents, None);
        for (case, class, creds, expected) in [
            ("alice", AUTH_PRINCIPAL, keyed("key-alice"), "key-alice"),
            ("bob", AUTH_PRINCIPAL, keyed("key-bob"), "key-bob"),
            (
                "open chain",
                AUTH_OPTIONAL,
                anonymous(),
                crate::auth::native_chain::ANONYMOUS,
            ),
        ] {
            let admitted = finish(admit(7, class, &creds, &NoTickets, &refusals, "aud", 100))
                .unwrap_or_else(|_| panic!("{case}: admitted"));
            // What `PortDriver::serve` hands the books: the verified subject, else none.
            let principal = match &creds.principal {
                Principal::Verified(subject) => Some(subject.as_str()),
                _ => None,
            };
            assert_eq!(
                principal,
                admitted.identity.as_ref().map(|i| i.subject()),
                "{case}: the books' subject is the identity the plane was handed"
            );
            let req = PlaneIn {
                route: 7,
                flags: 0,
                auth: admitted.auth,
                method: "POST",
                path: "/x",
                query: "",
                headers: &[],
                identity: admitted.identity_records(),
                request_id: 1,
                carrier: 0,
                work: "",
                ticket_record: admitted.ticket_record(),
            };
            let seam = Arc::new(Seam::default());
            let audits = Arc::new(Audits::default());
            let money = money(&seam, &audits);
            let unit = ctx(11);
            let unit_books = UnitBooks::new(&money, &unit, principal);
            let unbilled = Arc::new(Audits::default());
            let audit_only = AuditOnly {
                sink: &*unbilled,
                principal,
            };
            for (books, sink, which) in [
                (&unit_books as &dyn Books, &audits, "governed unit"),
                (&audit_only as &dyn Books, &unbilled, "unbilled request"),
            ] {
                let drive: Drive<'_> = Drive {
                    resolver: &resolver,
                    members: None,
                    send: None,
                    dialect: "",
                    refusals: &refusals,
                    effects: &Quiet,
                    books,
                    carrier: None,
                };
                finish(run_session(&Audited, &req, b"", drive))
                    .unwrap_or_else(|_| panic!("{case} {which}: the session ran"));
                assert_eq!(
                    *sink.0.lock().unwrap(),
                    vec![("acted".to_owned(), expected.to_owned())],
                    "{case} {which}: the row is sealed under the resolved principal"
                );
            }
        }
    }

    const PROVIDERS: &str = "p:\n  protocol: wire-a\n  base_url: https://upstream.example/api\n  required_option: catalog\n";
    const SCHEMA: &str = r#"{"type":"object","properties":{"required_option":{"type":"string"}},"required":["required_option"],"additionalProperties":false}"#;
    const MODELS: &str = "providers:\n  p:\n    api_key: {module: fixture-secret, settings: {slot: lane-key}}\nmodels:\n  m0:\n    provider: p\n    upstream_model: wire-model-a\n  m1:\n    provider: p\n    upstream_model: wire-model-b\n";

    /// Each (selector, member) of a deployment's catalog with the credential mode it resolved to.
    fn modes(pools: &str) -> Vec<(&'static str, &'static str, UpstreamCreds)> {
        let grammar = crate::config::Grammar::empty();
        let definitions = crate::config::providers::catalog_from_str(PROVIDERS, &grammar)
            .expect("catalog core grammar");
        let deploy = crate::config::deploy_from_yaml_str(&format!("{MODELS}{pools}"), &grammar)
            .expect("deployment core grammar");
        let planes = [crate::plane_driver::provider_catalog::ProviderPlane {
            instance: "chat".into(),
            image: "image-chat".into(),
            dialects: vec!["wire-a".to_owned()],
            schema: SCHEMA.into(),
        }];
        let resolved = crate::config::resolve_with_provider_planes(&deploy, &definitions, &planes)
            .unwrap_or_else(|errors| panic!("{errors:?}"));
        let plan = &resolved.catalogs["chat"];
        [
            ("inherits", "m0"),
            ("owns", "m1"),
            ("m0", "m0"),
            ("m1", "m1"),
        ]
        .into_iter()
        .map(|(selector, member)| {
            let key = plan.select(selector).unwrap_or_else(|| panic!("{selector}"));
            let target = plan
                .target(key, &format!("chat\u{1f}{member}"))
                .unwrap_or_else(|| panic!("{selector} {member}"));
            (selector, member, target.credential_mode)
        })
        .collect()
    }

    /// OWED-095 G:34 (cut-root/TESTS.tsv:489): the all-pools `pools.upstream_credentials:
    /// passthrough` default reaches a pool that states none of its own and every direct-model
    /// route; a pool's own `own` overrides it. With no default every member gets its own
    /// credential, and a pool's own `passthrough` reaches its members only.
    #[test]
    fn the_all_pools_credential_default_reaches_every_pool_without_its_own_and_every_direct_route() {
        use UpstreamCreds::{Own, Passthrough};
        assert_eq!(
            modes("pools:\n  upstream_credentials: passthrough\n  inherits:\n    members: [m0]\n  owns:\n    members: [m1]\n    upstream_credentials: own\n"),
            vec![
                ("inherits", "m0", Passthrough),
                ("owns", "m1", Own),
                ("m0", "m0", Passthrough),
                ("m1", "m1", Passthrough),
            ],
            "the default reaches every pool without its own and every direct route"
        );
        assert_eq!(
            modes("pools:\n  inherits:\n    members: [m0]\n  owns:\n    members: [m1]\n    upstream_credentials: passthrough\n"),
            vec![
                ("inherits", "m0", Own),
                ("owns", "m1", Passthrough),
                ("m0", "m0", Own),
                ("m1", "m1", Own),
            ],
            "with no default every member gets its own credential; a pool's own passthrough stays its own"
        );
    }
}
