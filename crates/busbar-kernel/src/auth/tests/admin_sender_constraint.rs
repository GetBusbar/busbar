// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;
use base64::Engine as _;
use busbar_contract::json;

fn jwt(cnf: json::Value) -> String {
    format!(
        "e30.{}.signature",
        base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(json::json!({"cnf": cnf}).to_string())
    )
}

#[test]
fn every_admin_bearer_occurrence_requires_its_sender_proof() {
    for confirmation in [
        json::json!({"jkt": "key-thumbprint"}),
        json::json!({"jkt": ""}),
        json::json!({"jkt": null}),
        json::json!({"jkt": 12}),
    ] {
        let token = jwt(confirmation);
        for carrier in ["authorization", "x-admin-token", "x-provider-token"] {
            let mut headers = HeaderMap::new();
            let name = HeaderName::from_bytes(carrier.as_bytes()).unwrap();
            headers.append(name.clone(), "opaque-first-occurrence".parse().unwrap());
            let value = if carrier == "authorization" {
                format!("bEaReR {token}")
            } else {
                token.clone()
            };
            headers.append(name, value.parse().unwrap());
            headers.insert(
                "dpop",
                "unverified-proof-does-not-authorize".parse().unwrap(),
            );
            assert!(downgraded_in(&headers, &[carrier.to_owned()]), "{carrier}");
        }
    }
}

#[test]
fn opaque_service_bearers_and_unbound_jwts_are_not_sender_downgrades() {
    for token in ["opaque-service-token".to_owned(), jwt(json::json!({}))] {
        let mut headers = HeaderMap::new();
        headers.insert(AUTHORIZATION, format!("Bearer {token}").parse().unwrap());
        headers.insert("x-admin-token", token.parse().unwrap());
        assert!(!downgraded_in(&headers, ["authorization", "x-admin-token"]));
    }
}

/// The native admin gate itself (`run_admin_chain`, the native operator arm): a provider that
/// identifies every caller is still refused when the presented credential is a DPoP-bound token
/// downgraded to a bearer, under `Authorization` or under the provider's own credential header.
mod native_gate {
    use super::jwt;
    use crate::auth::native_admin::{Invocation, NativeAdmin};
    use crate::auth::native_chain::{AuthInstance, AuthOwners, NativeChain, OpenedAuth};
    use crate::auth::native_policy::ChainPolicy;
    use crate::auth::verdicts::{VerdictPolicy, Verdicts};
    use crate::auth::{run_admin_chain, AdminCarried, ChainVerdict};
    use crate::inbound::request_snapshot::{ChargedRequestSnapshot, SnapshotInput};
    use crate::issued::IssuedCredentials;
    use crate::limits::process_admission::{AdmissionClass, ProcessAdmission};
    use crate::plane_driver::port_intents::Namespace;
    use crate::plane_grants::{KeyRefresh, ReplayGuard};
    use crate::plugin_records::RecordsDenied;
    use crate::state::{AppHandle, InvocationId};
    use axum::http::{header::AUTHORIZATION, HeaderMap};
    use busbar_contract::json;
    use busbar_contract::secure::SecureVec;
    use busbar_plugin_abi::host_side::caller::{BoxFut, Caller, InstanceLimits};
    use busbar_plugin_abi::records::{tag, Records, Reply, Writer};
    use busbar_ports::auth::{
        decode_verify_ok, AuthIn, AuthPort, LoginAnswer, LoginIn, OutboundAnswer, ServeIn,
        ServeOut, UpstreamIn, Verify, VerifyAnswer, VerifyOk,
    };
    use busbar_ports::{CallCx, PortError};
    use std::collections::{BTreeMap, BTreeSet};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;
    use std::time::Duration;

    const OPERATOR: &str = "provider-42";
    const PROVIDER_HEADER: &str = "x-provider-token";

    struct Owners;
    impl IssuedCredentials for Owners {
        fn lookup<'a>(&'a self, _: u64, _: &'a str, _: &'a str) -> BoxFut<'a, SecureVec> {
            panic!("an identity answer must not perform issued lookup");
        }
    }
    impl ReplayGuard for Owners {
        fn claim_until<'a>(
            &'a self,
            _: &'a Caller<'_>,
            _: &'a [u8],
            _: u64,
        ) -> BoxFut<'a, Result<bool, RecordsDenied>> {
            panic!("preparation never spends replay")
        }
        fn claim<'a>(
            &'a self,
            _: &'a Caller<'_>,
            _: &'a [u8],
            _: u64,
        ) -> BoxFut<'a, Result<bool, RecordsDenied>> {
            panic!("preparation never spends replay")
        }
    }

    /// A native operator verifier that identifies every caller as `client`, counting its calls.
    struct Operator {
        calls: AtomicUsize,
        cred_headers: [Box<str>; 1],
    }
    fn unsupported<'a, T: Send + 'a>() -> BoxFut<'a, Result<T, PortError>> {
        Box::pin(async {
            Err(PortError::Call(
                busbar_plugin_abi::fail::CallError::NotDeclared,
            ))
        })
    }
    impl AuthPort for Operator {
        fn facts(&self) -> u64 {
            0
        }
        fn cred_headers(&self) -> &[Box<str>] {
            &self.cred_headers
        }
        fn issued_kind(&self) -> Option<&str> {
            None
        }
        fn verify<'a>(&'a self, _: CallCx, _: &AuthIn<'_>, _: Option<&[u8]>) -> Verify<'a> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            let mut records = Reply::new();
            records.put_text(tag::ID_SUBJECT, "client").unwrap();
            let VerifyOk::Identity(identity) =
                decode_verify_ok(Records::new(records.as_bytes())).unwrap()
            else {
                panic!("identity");
            };
            Verify::Done(Ok(VerifyAnswer::Identity(identity)))
        }
        fn refresh<'a>(&'a self, _: CallCx) -> BoxFut<'a, Result<Option<u32>, PortError>> {
            unsupported()
        }
        fn login<'a>(
            &'a self,
            _: CallCx,
            _: LoginIn<'a>,
        ) -> BoxFut<'a, Result<LoginAnswer, PortError>> {
            unsupported()
        }
        fn outbound<'a>(
            &'a self,
            _: CallCx,
            _: &'a UpstreamIn<'a>,
        ) -> BoxFut<'a, Result<OutboundAnswer, PortError>> {
            unsupported()
        }
        fn serve<'a>(
            &'a self,
            _: CallCx,
            _: &'a ServeIn<'a>,
        ) -> BoxFut<'a, Result<ServeOut, PortError>> {
            unsupported()
        }
    }

    #[test]
    fn the_native_admin_gate_refuses_a_sender_constraint_downgrade() {
        let operator = Arc::new(Operator {
            calls: AtomicUsize::new(0),
            cred_headers: [PROVIDER_HEADER.into()],
        });
        let instance = Arc::new(AuthInstance {
            opened: OpenedAuth {
                who: Namespace {
                    plugin: "verified-image".into(),
                    name: OPERATOR.into(),
                    instance: 42,
                    slot: 4,
                },
                port: operator.clone(),
                methods: busbar_plugin_abi::auth::M_VERIFY,
                out_of_process: false,
                limits: InstanceLimits::default(),
            },
            keys: Arc::new(KeyRefresh::new(Duration::from_secs(30))),
            holds: Box::default(),
        });
        let owners = Arc::new(Owners);
        let chain = Arc::new(NativeChain::operator(
            vec![instance],
            ChainPolicy::new(7, Vec::new()),
            Arc::new(AuthOwners {
                issued: owners.clone(),
                replay: owners,
                cache: Arc::new(Verdicts::new(VerdictPolicy::DEFAULT)),
            }),
        ));
        let mut app = crate::inbound::native::tests::app();
        {
            let app = Arc::get_mut(&mut app).expect("the fixture app is not shared yet");
            app.admin_chain = vec![OPERATOR.into()];
            app.native_admin = Some(Arc::new(NativeAdmin::new(
                BTreeMap::from([(OPERATOR.to_owned(), chain)]),
                BTreeSet::new(),
            )));
        }
        let process = ProcessAdmission::new(2);
        let lease = process
            .try_enter(AdmissionClass::Operator)
            .expect("an operator request is admitted");
        let request = ChargedRequestSnapshot::capture(
            SnapshotInput {
                method: "GET",
                path: "/api/v1/admin/whoami",
                query: "",
                query_present: false,
                authority: "node",
                headers: std::iter::empty::<(&str, &[u8])>(),
                peer: "peer",
                tls_peer_cert: &[],
                body: b"",
                now_s: 1,
            },
            &lease,
        )
        .expect("the original request is charged");
        let invocation = Invocation {
            handle: Arc::new(AppHandle::new(app.clone())),
            selected: app,
            id: InvocationId::from_request_id(std::num::NonZeroU64::new(9).expect("non-zero")),
            cx: CallCx {
                deadline: std::time::Instant::now() + Duration::from_secs(30),
                request_id: 9,
                stack: Default::default(),
                mono_ns: 0,
            },
            request,
        };
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime");
        let judge = |headers: &HeaderMap| {
            let mut carried = AdminCarried::default();
            let (verdict, _) = runtime.block_on(run_admin_chain(
                &invocation.selected,
                invocation.request.method(),
                invocation.request.target(),
                headers,
                false,
                &mut carried,
                Some(&invocation),
            ));
            (verdict, carried)
        };

        // An opaque bearer: the same native operator identifies the caller, so the refusals below
        // are the sender constraint's, not a fixture that never identifies.
        let mut opaque = HeaderMap::new();
        opaque.insert(AUTHORIZATION, "Bearer opaque-admin".parse().unwrap());
        opaque.insert(PROVIDER_HEADER, "opaque-admin".parse().unwrap());
        let (verdict, carried) = judge(&opaque);
        let ChainVerdict::Identified { principal, .. } = &verdict else {
            panic!("an opaque bearer is identified by the native operator: {verdict:?}");
        };
        assert_eq!(principal.id, "client");
        assert!(carried.native.is_some(), "an identity is prepared");
        assert_eq!(operator.calls.load(Ordering::SeqCst), 1);

        let bound = jwt(json::json!({"jkt": "key-thumbprint"}));
        let mut under_authorization = HeaderMap::new();
        under_authorization.insert(AUTHORIZATION, format!("Bearer {bound}").parse().unwrap());
        under_authorization.insert("dpop", "unverified-proof".parse().unwrap());
        let mut under_provider_header = HeaderMap::new();
        under_provider_header.insert(PROVIDER_HEADER, bound.parse().unwrap());
        for (case, headers) in [
            ("authorization", under_authorization),
            (PROVIDER_HEADER, under_provider_header),
        ] {
            // The native arm judges the charged request, whose identity the provider already
            // answered (cached): only the presented headers differ from the identified call.
            let (verdict, carried) = judge(&headers);
            assert_eq!(verdict, ChainVerdict::Denied, "{case}");
            assert!(
                !carried.no_verdict,
                "{case}: a refusal, not a missing verdict"
            );
            assert!(carried.native.is_none(), "{case}: nothing is prepared");
            assert!(carried.strips.is_empty(), "{case}");
        }
        // The same request with the opaque bearer is still identified: the refusals were the
        // headers', not a provider that stopped identifying.
        let (verdict, _) = judge(&opaque);
        assert!(
            matches!(verdict, ChainVerdict::Identified { .. }),
            "{verdict:?}"
        );
    }
}

#[test]
fn explicit_dpop_presentations_remain_the_verifying_providers_responsibility() {
    let token = jwt(json::json!({"jkt": "key-thumbprint"}));
    let mut headers = HeaderMap::new();
    headers.insert(AUTHORIZATION, format!("DPoP {token}").parse().unwrap());
    // This guard does not identify or authorize that presentation, with or without a proof.
    assert!(!downgraded_in(&headers, ["authorization"]));
    headers.insert("x-admin-token", token.parse().unwrap());
    assert!(downgraded_in(&headers, ["authorization", "x-admin-token"]));
}
