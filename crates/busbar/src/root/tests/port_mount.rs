// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! PLANE-BOOT-MOUNT: what the HTTP mount of a MIN-3 plane's data routes makes of a route table and of the
//! session's client items. The plane itself is an ffi handle, so the request path runs in the image suite
//! (W2-SW-PLANE e2e); these are the pure seams between axum and `PortDriver::serve`.

use axum::http::{HeaderMap, HeaderValue};
use busbar_contract::abi::mechanism::route::{RouteAuth, RouteMethod};
use busbar_contract::abi::transport::route::{
    METHOD_DELETE, METHOD_GET, METHOD_HEAD, METHOD_PATCH, METHOD_POST, METHOD_PUT,
};
use busbar_kernel::plane_driver::port_session::ToClient;
use busbar_plugin_abi::plane::{AUTH_OPTIONAL, AUTH_PRINCIPAL, AUTH_PUBLIC, AUTH_TICKET};

use super::*;

#[test]
fn the_method_mask_mounts_the_five_verbs_and_drops_the_rest() {
    let all = METHOD_GET | METHOD_HEAD | METHOD_POST | METHOD_PUT | METHOD_PATCH | METHOD_DELETE;
    assert_eq!(
        methods_of(all),
        [
            RouteMethod::Get,
            RouteMethod::Post,
            RouteMethod::Put,
            RouteMethod::Patch,
            RouteMethod::Delete
        ]
    );
    assert_eq!(methods_of(METHOD_HEAD), []);
    assert_eq!(methods_of(METHOD_POST), [RouteMethod::Post]);
}

#[test]
fn only_a_principal_only_route_is_behind_the_data_auth_chain() {
    assert_eq!(auth_of(AUTH_PRINCIPAL), RouteAuth::Key);
    // Core classifies these itself, per request (§12.11): the data chain must not refuse them first.
    for classes in [
        AUTH_OPTIONAL,
        AUTH_PUBLIC,
        AUTH_TICKET,
        AUTH_PRINCIPAL | AUTH_TICKET,
        AUTH_PRINCIPAL | AUTH_OPTIONAL,
    ] {
        assert_eq!(auth_of(classes), RouteAuth::None, "{classes:#x}");
    }
}

#[test]
fn the_route_credential_header_wins_over_authorization() {
    let mut h = HeaderMap::new();
    h.insert("authorization", HeaderValue::from_static("Bearer tok-a"));
    h.insert("x-api-key", HeaderValue::from_static("tok-b"));
    assert_eq!(bearer_of(&h, None).as_deref(), Some("tok-a"));
    assert_eq!(bearer_of(&h, Some("x-api-key")).as_deref(), Some("tok-b"));
    assert_eq!(bearer_of(&h, Some("x-missing")), None);
    h.insert("authorization", HeaderValue::from_static("Basic abc"));
    assert_eq!(bearer_of(&h, None), None);
}

#[test]
fn client_items_become_one_response_in_the_order_the_plane_wrote_them() {
    let items = vec![
        ToClient::Head {
            status: 201,
            fields: vec![(b"content-type".to_vec(), b"text/plain".to_vec())],
        },
        ToClient::Body(b"he".to_vec()),
        ToClient::Msg {
            flags: 0,
            bytes: b"llo".to_vec(),
        },
        ToClient::End,
    ];
    let (status, fields, body) = port_admin::joined(items);
    assert_eq!(status, 201);
    assert_eq!(fields, [(b"content-type".to_vec(), b"text/plain".to_vec())]);
    assert_eq!(body, b"hello");
}

#[test]
fn a_session_that_wrote_no_head_is_a_gateway_failure_not_a_200() {
    let (status, fields, body) =
        port_admin::joined(vec![ToClient::Body(b"x".to_vec()), ToClient::End]);
    assert_eq!((status, fields.len(), body), (502, 0, Vec::new()));
}

mod optional_principal {
    use busbar_contract::auth::Principal;
    use busbar_kernel::auth::IdentityRefusal;
    use busbar_kernel::governance::GovCtx;

    use super::super::*;

    fn principal(id: &str) -> busbar_kernel::auth::AuthPrincipal {
        busbar_kernel::auth::AuthPrincipal(Some(Principal {
            id: id.into(),
            name: None,
            roles: Vec::new(),
            ttl_secs: None,
        }))
    }

    #[test]
    fn a_credential_the_chain_identifies_is_the_verified_principal() {
        assert_eq!(
            seen_of(Ok((principal("alice"), GovCtx::default()))),
            Seen::Verified("alice".into())
        );
    }

    #[test]
    fn an_open_chain_or_no_identity_is_anonymous_and_a_refused_credential_is_rejected() {
        assert_eq!(
            seen_of(Ok((
                busbar_kernel::auth::AuthPrincipal(None),
                GovCtx::default()
            ))),
            Seen::Anonymous
        );
        assert_eq!(seen_of(Err(IdentityRefusal::Denied)), Seen::Rejected);
        assert_eq!(seen_of(Err(IdentityRefusal::NoGrant)), Seen::Rejected);
    }

    #[test]
    fn a_route_the_data_chain_does_not_gate_resolves_the_credential_itself() {
        use busbar_plugin_abi::plane::{AUTH_OPTIONAL, AUTH_PRINCIPAL, AUTH_PUBLIC, AUTH_TICKET};
        // OPTIONAL takes the principal when a credential names one; PRINCIPAL beside another class is chosen per
        // request (a ticket or a key), so the key must be resolved here, as the chain does not gate the route.
        assert!(resolves_credential(AUTH_OPTIONAL));
        assert!(resolves_credential(AUTH_OPTIONAL | AUTH_PUBLIC));
        assert!(resolves_credential(AUTH_PRINCIPAL | AUTH_OPTIONAL));
        assert!(resolves_credential(AUTH_PRINCIPAL | AUTH_TICKET));
        // PRINCIPAL alone runs behind the data chain (`auth_of`); PUBLIC and TICKET never need a key.
        assert!(!resolves_credential(AUTH_PRINCIPAL));
        assert!(!resolves_credential(AUTH_PUBLIC));
        assert!(!resolves_credential(AUTH_TICKET));
        assert!(!resolves_credential(AUTH_PUBLIC | AUTH_TICKET));
    }
}

mod signed_ingress {
    use std::sync::atomic::{AtomicBool, Ordering};

    use busbar_contract::secret_ref::SecretRef;
    use busbar_kernel::plane_driver::port_routes::Mounted;
    use busbar_kernel::plane_grants::{IngressVerifier, ReplayGuard};
    use busbar_kernel::plugin_records::RecordsDenied;
    use busbar_plugin_abi::host_side::caller::{BoxFut, Caller};
    use busbar_plugin_abi::plane::{AUTH_PRINCIPAL, AUTH_SIGNED_INGRESS};
    use busbar_plugin_abi::types::Pair;

    use super::super::*;

    struct Verifier(bool);
    impl IngressVerifier for Verifier {
        fn verify<'a>(
            &'a self,
            _: &'a SecretRef,
            _: &'a [Pair<'a>],
            _: &'a [u8],
            _: u64,
        ) -> BoxFut<'a, bool> {
            Box::pin(core::future::ready(self.0))
        }
    }

    struct Guard(AtomicBool);
    impl ReplayGuard for Guard {
        fn claim<'a>(
            &'a self,
            _: &'a Caller<'_>,
            _: &'a [u8],
            _: u64,
        ) -> BoxFut<'a, Result<bool, RecordsDenied>> {
            Box::pin(core::future::ready(Ok(self
                .0
                .swap(false, Ordering::SeqCst))))
        }
    }

    fn route(effective: u32) -> Mounted {
        Mounted {
            route: 4,
            methods: 0,
            flags: 0,
            auth: effective,
            effective,
            pattern: "/hooks/in".into(),
            cred_header: None,
            catalog: false,
        }
    }

    fn ingress(verified: bool, secret: bool) -> Ingress {
        Ingress {
            verifier: Arc::new(Verifier(verified)),
            replay: Arc::new(Guard(AtomicBool::new(true))),
            secrets: Arc::new(move |_: &str, _: u32| secret.then_some(SecretRef::None)),
        }
    }

    fn who() -> busbar_kernel::plane_driver::port_intents::Namespace {
        busbar_kernel::plane_driver::port_intents::Namespace {
            plugin: "plane-x".into(),
            name: "x".into(),
            instance: 1,
            slot: 0,
        }
    }

    async fn check(ingress: &Ingress, effective: u32) -> Option<bool> {
        signed_of(ingress, &who(), &route(effective), &[], b"{}", 1_000).await
    }

    #[tokio::test]
    async fn a_route_that_is_not_signed_ingress_runs_no_check() {
        assert_eq!(check(&ingress(true, true), AUTH_PRINCIPAL).await, None);
    }

    #[tokio::test]
    async fn a_verified_first_sighting_is_admitted_and_its_replay_is_not() {
        let ingress = ingress(true, true);
        assert_eq!(check(&ingress, AUTH_SIGNED_INGRESS).await, Some(true));
        assert_eq!(
            check(&ingress, AUTH_SIGNED_INGRESS).await,
            Some(false),
            "the same signed request is replayed"
        );
    }

    #[tokio::test]
    async fn a_bad_signature_or_a_route_with_no_secret_is_not_admitted() {
        assert_eq!(
            check(&ingress(false, true), AUTH_SIGNED_INGRESS).await,
            Some(false)
        );
        assert_eq!(
            check(&ingress(true, false), AUTH_SIGNED_INGRESS).await,
            Some(false)
        );
    }
}
