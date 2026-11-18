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
