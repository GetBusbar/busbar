// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The native operator arm of the admin chain takes the one admin admission permit before its
//! verifier runs (`run_admin_chain`, `admin_admission_permit` before `NativeAdmin::prepare`). With
//! that budget exhausted, a credential the native verifier would identify is refused fail-closed:
//! the verifier never runs, nothing is prepared for completion, BUSBAR-4008 is said, and the admin
//! door answers NO VERDICT (503 with `Retry-After`, SIGN-auth-kind 2026-10-30), never an identity.

use super::native_admin::{Invocation, NativeAdmin};
use super::native_chain::{AuthInstance, AuthOwners, NativeChain, OpenedAuth};
use super::native_policy::ChainPolicy;
use super::verdicts::{VerdictPolicy, Verdicts};
use super::*;
use crate::inbound::request_snapshot::{ChargedRequestSnapshot, SnapshotInput};
use crate::issued::IssuedCredentials;
use crate::limits::process_admission::{AdmissionClass, ProcessAdmission, RequestLease};
use crate::plane_driver::port_intents::Namespace;
use crate::plane_grants::{KeyRefresh, ReplayGuard};
use crate::plugin_records::RecordsDenied;
use crate::state::{AppHandle, InvocationId};
use busbar_contract::secure::SecureVec;
use busbar_plugin_abi::host_side::caller::{BoxFut, Caller, InstanceLimits};
use busbar_plugin_abi::records::{tag, Records, Reply, Writer};
use busbar_ports::auth::{
    decode_verify_ok, AuthIn, AuthPort, LoginAnswer, LoginIn, OutboundAnswer, ServeIn, ServeOut,
    UpstreamIn, Verify, VerifyAnswer, VerifyOk,
};
use busbar_ports::{CallCx, PortError};
use std::collections::{BTreeMap, BTreeSet};
use std::io::Write;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

/// The native operator position's configured name.
const OPERATOR: &str = "provider-42";

const ADMIN_SATURATED_TEXT: &str = "admin auth chain offload could not be started within 5s (16 \
     already in flight); an admin auth plugin is not returning. Denying (fail-closed) rather than \
     admitting unverified.";

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
        &[]
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

/// The app whose only admin position is the native operator, its verifier, the original charged
/// request and the lease that charges it.
fn native_operator_invocation() -> (Invocation, Arc<Operator>, RequestLease) {
    let operator = Arc::new(Operator {
        calls: AtomicUsize::new(0),
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
    (invocation, operator, lease)
}

/// One run of the admin chain for the invocation, as the admin door's authoritative entry runs it.
async fn judge(invocation: &Invocation) -> (ChainVerdict, AdminCarried) {
    let mut carried = AdminCarried::default();
    let (verdict, _) = run_admin_chain(
        &invocation.selected,
        invocation.request.method(),
        invocation.request.target(),
        &HeaderMap::new(),
        false,
        &mut carried,
        Some(invocation),
    )
    .await;
    (verdict, carried)
}

#[derive(Clone, Default)]
struct Said(Arc<Mutex<Vec<u8>>>);
impl Write for Said {
    fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(b);
        Ok(b.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[test]
fn the_native_operator_is_refused_under_a_saturated_admin_permit() {
    let (invocation, operator, _lease) = native_operator_invocation();

    // With the admin admission budget free, the same native operator identifies the caller: the
    // refusal below is the permit's, not a fixture that never identifies.
    let (verdict, carried) = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("runtime")
        .block_on(judge(&invocation));
    let ChainVerdict::Identified { principal, .. } = &verdict else {
        panic!("a free admin permit lets the native operator identify: {verdict:?}");
    };
    assert_eq!(principal.id, "client");
    assert!(!carried.no_verdict);
    assert!(carried.native.is_some(), "an identity is prepared");
    assert_eq!(operator.calls.load(Ordering::SeqCst), 1);

    // Every admin admission permit held: the native operator arm is refused before its verifier.
    let said = Said::default();
    let writer = said.clone();
    let subscriber = tracing_subscriber::fmt()
        .with_writer(move || writer.clone())
        .with_target(false)
        .with_ansi(false)
        .with_max_level(tracing::Level::DEBUG)
        .finish();
    let (verdict, carried) = tracing::subscriber::with_default(subscriber, || {
        tracing::callsite::rebuild_interest_cache();
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .start_paused(true)
            .build()
            .expect("runtime")
            .block_on(async {
                let held = ADMIN_ADMISSION_PERMITS
                    .acquire_many(ADMIN_ADMISSION_MAX_INFLIGHT as u32)
                    .await
                    .expect("the admin admission budget");
                let judged = judge(&invocation).await;
                drop(held);
                judged
            })
    });
    assert_eq!(verdict, ChainVerdict::Denied);
    assert!(carried.no_verdict, "the credential was never judged");
    assert!(
        carried.native.is_none(),
        "nothing is prepared for completion"
    );
    assert!(carried.strips.is_empty());
    assert_eq!(
        operator.calls.load(Ordering::SeqCst),
        1,
        "the native verifier never runs without an admin admission permit"
    );
    assert_eq!(
        admin_chain_outcome(verdict, carried.no_verdict),
        Err(VerifierUnavailable::NoVerdict),
        "the admin door answers no verdict, never an identity"
    );
    let text = String::from_utf8(said.0.lock().unwrap().clone()).unwrap();
    assert!(text.contains("diag=BUSBAR-4008"), "{text:?}");
    assert!(text.contains(ADMIN_SATURATED_TEXT), "{text:?}");
}
