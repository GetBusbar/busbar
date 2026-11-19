// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! ROUTE_ADMIN on the admin listener: which of a plane's admin routes a request names, and the answer the client
//! items make. The plane itself is an ffi handle, so the session runs in the image suite (W2-SW-PLANE e2e).

use busbar_contract::route::{METHOD_GET, METHOD_POST};
use busbar_plugin_abi::plane::{AUTH_OPERATOR, ROUTE_ADMIN};

use super::*;

fn admin(route: u32, methods: u32, pattern: &str) -> Mounted {
    Mounted {
        record: crate::auth::route_record::RouteRecord::stated(
            crate::auth::route_record::RouteClass::Admin,
            crate::auth::route_record::Who::OPERATOR,
            crate::auth::route_record::Scope::none(),
            crate::auth::route_record::Money::None,
        ),
        route,
        methods,
        flags: ROUTE_ADMIN,
        auth: AUTH_OPERATOR,
        effective: AUTH_OPERATOR,
        pattern: pattern.into(),
        cred_header: None,
        resource_kinds: Default::default(),
        catalog: false,
    }
}

#[test]
fn a_request_names_the_admin_route_its_method_and_path_match() {
    let routes = [
        admin(1, METHOD_GET | METHOD_POST, "/admin/connections/{id}"),
        admin(2, METHOD_GET, "/admin/health"),
    ];
    assert_eq!(
        matching(&routes, "GET", "/admin/connections/c1").map(|m| m.route),
        Some(1)
    );
    assert_eq!(
        matching(&routes, "POST", "/admin/connections/c1").map(|m| m.route),
        Some(1)
    );
    assert_eq!(
        matching(&routes, "GET", "/admin/health").map(|m| m.route),
        Some(2)
    );
    // The method is not in the route's mask, the path is another's, a segment is missing or extra.
    assert_eq!(matching(&routes, "POST", "/admin/health"), None);
    assert_eq!(matching(&routes, "DELETE", "/admin/connections/c1"), None);
    assert_eq!(matching(&routes, "GET", "/admin/connections"), None);
    assert_eq!(matching(&routes, "GET", "/admin/connections/c1/x"), None);
    assert_eq!(matching(&routes, "GET", "/v1/models"), None);
}

#[test]
fn a_method_outside_the_vocabulary_matches_no_route() {
    let routes = [admin(1, u32::MAX, "/admin/health")];
    assert_eq!(matching(&routes, "BREW", "/admin/health"), None);
}

#[test]
fn the_client_items_make_one_answer_and_no_head_is_a_bad_gateway() {
    let items = vec![
        ToClient::Head {
            status: 202,
            fields: vec![(b"content-type".to_vec(), b"application/json".to_vec())],
        },
        ToClient::Body(b"{\"a\":".to_vec()),
        ToClient::Msg {
            flags: 0,
            bytes: b"1}".to_vec(),
        },
        ToClient::End,
    ];
    let (status, fields, body) = joined(items);
    assert_eq!(status, 202);
    assert_eq!(
        fields,
        vec![(b"content-type".to_vec(), b"application/json".to_vec())]
    );
    assert_eq!(body, b"{\"a\":1}");
    assert_eq!(joined(vec![ToClient::End]), (502, Vec::new(), Vec::new()));
}

#[tokio::test]
async fn with_no_plane_installed_no_admin_route_is_answered() {
    use crate::limits::process_admission::{AdmissionClass, ProcessAdmission};
    let request = AdminRequest {
        request: ProcessAdmission::new(2)
            .try_enter(AdmissionClass::Operator)
            .unwrap(),
        method: "GET".into(),
        path: "/admin/health".into(),
        query: String::new(),
        headers: axum::http::HeaderMap::new(),
        consumed: None,
        principal: crate::auth::AuthPrincipal(None),
        body: bytes::Bytes::new(),
        request_id: 1,
        now_s: 1,
    };
    assert!(Box::pin(answer(&[], request)).await.is_none());
}

/// ci/owed/cut/SECURITY-OWED.tsv `a_door_plane_admin_route_sees_no_consumed_credential_and_its_row_names_the_actor`,
/// the credential half. The admin listener copies the request's head fields into the request it
/// hands a native plane's admin route. The credential the operator chain judged must not be among
/// them, in any case and however many times it was sent; neither may a session cookie or a proxy
/// credential. Everything else, the plane's own fields included, is handed on untouched and in
/// order. (On the data path the same rule is `auth::native_data::withheld_carriers`.)
#[test]
fn a_planes_admin_route_is_handed_no_credential_the_admin_gate_read() {
    const SECRET: &[u8] = b"Bearer operator-secret-do-not-forward";
    let field = |name: &str, value: &[u8]| (name.to_owned(), value.to_vec());
    let handed = plane_headers(vec![
        field("content-type", b"application/json"),
        field("authorization", SECRET),
        field("Authorization", SECRET),
        field("AUTHORIZATION", SECRET),
        field("proxy-authorization", SECRET),
        field(
            "cookie",
            b"busbar_admin_session=operator-secret-do-not-forward",
        ),
        field("x-admin-token", b"operator-secret-do-not-forward"),
        field("x-plane-own-field", b"kept"),
        field("accept", b"*/*"),
    ]);
    for (name, value) in &handed {
        assert!(
            !value
                .windows(b"operator-secret-do-not-forward".len())
                .any(|window| window == b"operator-secret-do-not-forward"),
            "the plane was handed the operator's credential in `{name}`"
        );
    }
    assert_eq!(
        handed,
        vec![
            field("content-type", b"application/json"),
            field("x-plane-own-field", b"kept"),
            field("accept", b"*/*"),
        ],
        "every other field is handed on untouched and in order"
    );
}

/// A plane with one ROUTE_ADMIN route that notes, from inside its `request` crossing, the head
/// fields and the identity it was handed, then refuses (a refused crossing is rendered 503).
mod admitted {
    use std::sync::{Arc, Mutex};

    use busbar_contract::kinds::codes::KindCode;
    use busbar_contract::route::METHOD_POST;
    use busbar_contract::services::Caller;
    use busbar_plugin_abi::fail::FaultReason;
    use busbar_plugin_abi::host_side::caller::BoxFut;
    use busbar_plugin_abi::plane::{
        AUTH_OPERATOR, CALLERS_SHARED, MONEY_NONE, ROUTE_ADMIN, SCOPE_NONE,
    };
    use busbar_ports::plane::{
        PlaneIn, PlaneOut, PlanePort, PlaneSession, RouteInfo, TargetIn, UsageClass,
    };
    use busbar_ports::{CallCx, PortError};

    use crate::host_services::KernelServices;
    use crate::plane_driver::port::{PortDriver, PortSeat};
    use crate::plane_driver::port_intents::{IntentHost, Looked, Namespace};
    use crate::plugin_records::{CommitOp, CommitOutcome, RecordsDenied, Scope};
    use crate::refusal::CoreRefusals;

    /// What the plane's `request` crossing was handed: its head fields and its identity records.
    pub(super) type Handed = Mutex<Option<(Vec<(String, Vec<u8>)>, Vec<u8>)>>;

    pub(super) struct AdminPlane {
        routes: [RouteInfo; 1],
        pub(super) handed: Handed,
    }

    fn refused() -> PortError {
        PortError::Refused {
            code: 1,
            text: "refused".into(),
            error: None,
        }
    }

    impl PlanePort for AdminPlane {
        fn route_admission(&self, _: u32) -> Option<(u32, u32, u32, &str)> {
            Some((SCOPE_NONE, MONEY_NONE, CALLERS_SHARED, ""))
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
            Some("{}")
        }
        fn charge(&self, _: FaultReason) {}
        fn request(
            &self,
            req: &PlaneIn<'_>,
            _: &[u8],
            _: &mut dyn FnMut(PlaneOut<'_>),
        ) -> Result<PlaneSession, PortError> {
            let headers = req
                .headers
                .iter()
                .map(|pair| (pair.name.get().to_owned(), pair.value.get().to_vec()))
                .collect();
            *self.handed.lock().unwrap() = Some((headers, req.identity.to_vec()));
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
            _: &PlaneIn<'_>,
            _: u32,
            _: &[u8],
            sink: &mut dyn FnMut(PlaneOut<'_>),
        ) -> Result<(), PortError> {
            sink(PlaneOut::Respond { status: 503 });
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

    /// A host with no store: an admin route here states no intent.
    pub(super) struct NoIntents;

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

    /// One installed plane instance whose admin route is `POST pattern`, and the plane.
    pub(super) fn seat(pattern: &str) -> (PortSeat, Arc<AdminPlane>) {
        let plane = Arc::new(AdminPlane {
            routes: [RouteInfo {
                route: 7,
                methods: METHOD_POST,
                flags: ROUTE_ADMIN,
                auth: AUTH_OPERATOR,
                pattern: pattern.into(),
                cred_header: None,
                resource_kinds: Default::default(),
            }],
            handed: Mutex::new(None),
        });
        let driver = PortDriver::new(
            Arc::clone(&plane) as Arc<dyn PlanePort>,
            Arc::new(KernelServices::new()),
            Caller::for_test(Arc::from("admin-plane"), KindCode::Plane),
            Arc::new(CoreRefusals::new()),
            &|_| None,
        )
        .unwrap();
        let seat = PortSeat {
            public_url: None,
            image: Arc::new(
                crate::plane_driver::image_identity::PlaneImageIdentity::new(
                    "admin-plane".into(),
                    None,
                )
                .unwrap(),
            ),
            instance: "admin-plane".into(),
            request_routes: Arc::new(
                crate::plane_driver::request_admission::RequestRoutes::new(
                    "admin-plane",
                    None,
                    None,
                    None,
                )
                .unwrap(),
            ),
            channel_budget: crate::channels::budget::ChannelBudget::new().instance(),
            driver: Arc::new(driver),
            audience: None,
            intents: Arc::new(NoIntents),
            who: Namespace {
                plugin: Arc::from("admin-plane"),
                name: Arc::from("admin-plane"),
                instance: 1,
                slot: 1,
            },
            upstream: None,
            carrier: None,
        };
        (seat, plane)
    }
}

/// PROOF-053 (LEDGER S-C3; ci/owed/cut/SECURITY-OWED.tsv
/// `a_door_plane_admin_route_sees_no_consumed_credential_and_its_row_names_the_actor`): an admin
/// request the operator chain admitted reaches the native plane's admin route through [`answer`]
/// (a real `PortDriver::serve`, the plane faked at its port) holding none of the carriers the admin
/// gate consumed, a gate-declared carrier outside the floor included, and served as the principal
/// the gate admitted. The identity records the plane is handed are built from the same
/// `Credentials.principal` that `PortDriver::serve` makes the session's subject, the principal
/// every AUDIT row the route states is booked under (`port_serve::AuditOnly`; booking under a
/// principal is pinned in `port_serve_tests`). An anonymous subject here writes the operator's
/// admin actions to the audit chain as `anonymous`.
#[tokio::test]
async fn an_admitted_admin_request_reaches_the_plane_without_the_consumed_credential_as_its_principal(
) {
    use crate::limits::process_admission::{AdmissionClass, ProcessAdmission};
    use axum::http::{HeaderMap, HeaderName, HeaderValue};

    const SECRET: &str = "operator-secret-do-not-forward";
    // A carrier the configured admin gate reads a credential from that is not on the floor list.
    let gate_carrier = HeaderName::from_static("x-busbar-operator-key");
    let mut headers = HeaderMap::new();
    headers.append("content-type", HeaderValue::from_static("application/json"));
    headers.append(
        "authorization",
        HeaderValue::from_str(&format!("Bearer {SECRET}")).unwrap(),
    );
    headers.append(gate_carrier.clone(), HeaderValue::from_static(SECRET));
    headers.append(gate_carrier.clone(), HeaderValue::from_static(SECRET));
    headers.append("x-plane-own-field", HeaderValue::from_static("kept"));
    let consumed = crate::auth::ConsumedCredentials::carrying(&[
        axum::http::header::AUTHORIZATION,
        gate_carrier,
    ]);

    let (seat, plane) = admitted::seat("/admin/plane/things");
    let request = AdminRequest {
        request: ProcessAdmission::new(2)
            .try_enter(AdmissionClass::Operator)
            .unwrap(),
        method: "POST".into(),
        path: "/admin/plane/things".into(),
        query: String::new(),
        headers,
        consumed: Some(consumed),
        principal: crate::auth::AuthPrincipal(Some(busbar_contract::auth::Principal::from_id(
            "operator-alice",
        ))),
        body: bytes::Bytes::new(),
        request_id: 9,
        now_s: 1,
    };
    let answered = Box::pin(answer(std::slice::from_ref(&seat), request)).await;
    assert!(answered.is_some(), "the plane's admin route answered");

    let (mut handed, identity) = plane
        .handed
        .lock()
        .unwrap()
        .take()
        .expect("the admitted request reached the plane");
    for (name, value) in &handed {
        assert!(
            !value
                .windows(SECRET.len())
                .any(|window| window == SECRET.as_bytes()),
            "the plane was handed the operator's credential in `{name}`"
        );
    }
    handed.sort();
    assert_eq!(
        handed,
        vec![
            ("content-type".to_owned(), b"application/json".to_vec()),
            ("x-plane-own-field".to_owned(), b"kept".to_vec()),
        ],
        "only the consumed carriers are withheld; every other field is handed on untouched"
    );
    assert_eq!(
        identity,
        crate::plane_driver::port_auth::subject_identity("operator-alice"),
        "the admin route is served as the principal the admin gate admitted, not as anonymous"
    );
}
