// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use crate::auth::chain_run::{verify_cached, AuthServices, ChainInstance, IdentityPolicy, Verdict};
use crate::auth::verdicts::{VerdictPolicy, Verdicts};
use crate::issued::IssuedCredentials;
use crate::plane_grants::{KeyRefresh, ReplayGuard};
use crate::plugin_records::RecordsDenied;
use busbar_contract::secure::SecureVec;
use busbar_plugin_abi::host_side::caller::{BoxFut, CallStack, Caller};
use busbar_plugin_abi::records::{tag, Records, Reply, U64Rec, Writer};
use busbar_plugin_abi::types::KindCode;
use busbar_ports::auth::{
    decode_verify_ok, AuthIn, AuthPort, Identity, LoginAnswer, LoginIn, OutboundAnswer, ServeIn,
    ServeOut, UpstreamIn, Verify, VerifyAnswer, VerifyOk,
};
use busbar_ports::{CallCx, PortError};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::{Duration, Instant};

struct Checks {
    allow: AtomicBool,
    claims: AtomicUsize,
    issued: AtomicUsize,
    epoch: AtomicUsize,
}
impl IdentityPolicy for Checks {
    fn epoch(&self) -> u64 {
        self.epoch.load(Ordering::SeqCst) as u64
    }
    fn authorize(&self, _: u64, _: &Identity, _: &AuthIn<'_>) -> Result<(), u32> {
        if self.allow.load(Ordering::SeqCst) {
            Ok(())
        } else {
            Err(busbar_plugin_abi::fail::refused::R_POLICY)
        }
    }
}
impl IssuedCredentials for Checks {
    fn lookup<'a>(&'a self, _: u64, kind: &'a str, id: &'a str) -> BoxFut<'a, SecureVec> {
        assert_eq!((kind, id), ("sigv4", "key"));
        self.issued.fetch_add(1, Ordering::SeqCst);
        Box::pin(async {
            let mut value = SecureVec::new();
            value.extend_from_slice(b"secret");
            value
        })
    }
}
impl ReplayGuard for Checks {
    fn claim_until<'a>(
        &'a self,
        _: &'a Caller<'_>,
        _: &'a [u8],
        _: u64,
    ) -> BoxFut<'a, Result<bool, RecordsDenied>> {
        panic!("eager chain fixture must use its original relative replay policy")
    }
    fn claim<'a>(
        &'a self,
        _: &'a Caller<'_>,
        _: &'a [u8],
        _: u64,
    ) -> BoxFut<'a, Result<bool, RecordsDenied>> {
        assert!(
            self.allow.load(Ordering::SeqCst),
            "policy must precede replay"
        );
        let first = self.claims.fetch_add(1, Ordering::SeqCst) == 0;
        Box::pin(async move { Ok(first) })
    }
}
struct Port {
    calls: AtomicUsize,
    issued: bool,
    stale: bool,
    plain: bool,
    refreshes: AtomicUsize,
}
fn unsupported<'a, T: Send + 'a>() -> BoxFut<'a, Result<T, PortError>> {
    Box::pin(async {
        Err(PortError::Call(
            busbar_plugin_abi::fail::CallError::NotDeclared,
        ))
    })
}
impl AuthPort for Port {
    fn facts(&self) -> u64 {
        0
    }
    fn cred_headers(&self) -> &[Box<str>] {
        static HEADER: std::sync::LazyLock<Box<str>> =
            std::sync::LazyLock::new(|| Box::from("authorization"));
        if self.plain {
            std::slice::from_ref(&*HEADER)
        } else {
            &[]
        }
    }
    fn issued_kind(&self) -> Option<&str> {
        Some("sigv4")
    }
    fn verify<'a>(&'a self, _: CallCx, _: &AuthIn<'_>, issued: Option<&[u8]>) -> Verify<'a> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        if self.stale {
            return Verify::Done(Ok(VerifyAnswer::KeysStale));
        }
        if self.issued {
            if let Some(value) = issued {
                assert_eq!(value, b"secret");
            }
            return Verify::Done(Ok(VerifyAnswer::IssuedWanted("key".into())));
        }
        if self.plain {
            return Verify::Done(Ok(VerifyAnswer::Identity(Identity::from_ticket(
                "alice", "chat",
            ))));
        }
        let mut out = Reply::new();
        out.put_text(tag::ID_SUBJECT, "alice").unwrap();
        out.put_pod_tail(
            busbar_plugin_abi::auth::tag::REPLAY,
            &U64Rec { value: 60 },
            b"nonce",
        )
        .unwrap();
        let VerifyOk::Identity(id) = decode_verify_ok(Records::new(out.as_bytes())).unwrap() else {
            panic!("identity")
        };
        Verify::Done(Ok(VerifyAnswer::Identity(id)))
    }
    fn refresh<'a>(&'a self, _: CallCx) -> BoxFut<'a, Result<Option<u32>, PortError>> {
        Box::pin(async {
            self.refreshes.fetch_add(1, Ordering::SeqCst);
            tokio::task::yield_now().await;
            Ok(Some(60))
        })
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
fn request() -> AuthIn<'static> {
    AuthIn {
        method: "POST",
        path: "/",
        query: "",
        authority: "example",
        headers: &[],
        peer: "peer",
        tls_peer_cert: &[],
        body: b"body",
        now_s: 1000,
    }
}
fn cx() -> CallCx {
    CallCx {
        deadline: Instant::now() + Duration::from_secs(10),
        request_id: 1,
        stack: CallStack::default(),
    }
}
fn caller() -> Caller<'static> {
    Caller {
        plugin: "fixture",
        kind: KindCode::Auth,
        name: "auth",
        instance: 1,
        slot: 0,
        chain: 0,
        deadline: cx().deadline,
        stack: CallStack::default(),
        out_of_process: false,
        limits: Default::default(),
    }
}

#[tokio::test]
async fn preparation_shares_verification_without_policy_or_replay_admission() {
    let checks = Checks {
        allow: AtomicBool::new(false),
        claims: AtomicUsize::new(0),
        issued: AtomicUsize::new(0),
        epoch: AtomicUsize::new(1),
    };
    let services = AuthServices {
        issued: &checks,
        replay: &checks,
        policy: &checks,
    };
    let port = Port {
        calls: AtomicUsize::new(0),
        issued: false,
        stale: false,
        plain: true,
        refreshes: AtomicUsize::new(0),
    };
    let keys = KeyRefresh::new(Duration::from_secs(30));
    let who = caller();
    let instance = ChainInstance {
        id: 1,
        port: &port,
        caller: &who,
        keys: &keys,
        holds: &[],
    };
    let cache = Verdicts::new(VerdictPolicy::default());
    let req = super::Request::new(&request());
    for _ in 0..2 {
        assert!(matches!(
            super::prepare_owned(&services, &cache, instance, cx(), &req).await,
            Ok(Verdict::Identity(_))
        ));
    }
    assert_eq!(port.calls.load(Ordering::SeqCst), 1);
    assert_eq!(checks.claims.load(Ordering::SeqCst), 0);
    assert!(matches!(
        verify_cached(&services, &cache, instance, cx(), &request()).await,
        Ok(Verdict::PolicyRejected { .. })
    ));
    assert_eq!(port.calls.load(Ordering::SeqCst), 1);
    assert_eq!(checks.claims.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn denied_policy_does_not_consume_replay_and_successful_replay_is_uncached() {
    let checks = Checks {
        allow: AtomicBool::new(false),
        claims: AtomicUsize::new(0),
        issued: AtomicUsize::new(0),
        epoch: AtomicUsize::new(1),
    };
    let services = AuthServices {
        issued: &checks,
        replay: &checks,
        policy: &checks,
    };
    let port = Port {
        calls: AtomicUsize::new(0),
        issued: false,
        stale: false,
        plain: false,
        refreshes: AtomicUsize::new(0),
    };
    let keys = KeyRefresh::new(Duration::from_secs(30));
    let who = caller();
    let instance = ChainInstance {
        id: 1,
        port: &port,
        caller: &who,
        keys: &keys,
        holds: &[],
    };
    let cache = Verdicts::new(VerdictPolicy::default());
    let request = request();
    assert!(matches!(
        verify_cached(&services, &cache, instance, cx(), &request).await,
        Ok(Verdict::PolicyRejected { .. })
    ));
    assert_eq!(checks.claims.load(Ordering::SeqCst), 0);
    checks.allow.store(true, Ordering::SeqCst);
    assert!(matches!(
        verify_cached(&services, &cache, instance, cx(), &request).await,
        Ok(Verdict::Identity(_))
    ));
    assert!(
        matches!(verify_cached(&services, &cache, instance, cx(), &request).await, Ok(Verdict::Rejected { code, .. }) if code == busbar_plugin_abi::fail::refused::R_REPLAYED)
    );
    assert_eq!(checks.claims.load(Ordering::SeqCst), 2);
    assert_eq!(port.calls.load(Ordering::SeqCst), 3);
}

#[tokio::test]
async fn repeated_issued_wanted_performs_one_lookup_and_one_retry() {
    let checks = Checks {
        allow: AtomicBool::new(true),
        claims: AtomicUsize::new(0),
        issued: AtomicUsize::new(0),
        epoch: AtomicUsize::new(1),
    };
    let services = AuthServices {
        issued: &checks,
        replay: &checks,
        policy: &checks,
    };
    let port = Port {
        calls: AtomicUsize::new(0),
        issued: true,
        stale: false,
        plain: false,
        refreshes: AtomicUsize::new(0),
    };
    let keys = KeyRefresh::new(Duration::from_secs(30));
    let who = caller();
    let instance = ChainInstance {
        id: 1,
        port: &port,
        caller: &who,
        keys: &keys,
        holds: &[],
    };
    let cache = Verdicts::new(VerdictPolicy::default());
    assert!(matches!(
        verify_cached(&services, &cache, instance, cx(), &request()).await,
        Ok(Verdict::Rejected { .. })
    ));
    assert_eq!(checks.issued.load(Ordering::SeqCst), 1);
    assert_eq!(port.calls.load(Ordering::SeqCst), 2);
    assert_eq!(checks.claims.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn concurrent_stale_requests_share_refresh_and_each_retry_is_bounded() {
    let checks = Checks {
        allow: AtomicBool::new(true),
        claims: AtomicUsize::new(0),
        issued: AtomicUsize::new(0),
        epoch: AtomicUsize::new(1),
    };
    let services = AuthServices {
        issued: &checks,
        replay: &checks,
        policy: &checks,
    };
    let port = Port {
        calls: AtomicUsize::new(0),
        issued: false,
        stale: true,
        plain: false,
        refreshes: AtomicUsize::new(0),
    };
    let keys = KeyRefresh::new(Duration::from_secs(30));
    let who = caller();
    let instance = ChainInstance {
        id: 1,
        port: &port,
        caller: &who,
        keys: &keys,
        holds: &[],
    };
    let cache = Verdicts::new(VerdictPolicy::default());
    let req = request();
    let (a, b) = tokio::join!(
        verify_cached(&services, &cache, instance, cx(), &req),
        verify_cached(&services, &cache, instance, cx(), &req)
    );
    for outcome in [a, b] {
        assert!(
            matches!(outcome,Ok(Verdict::Rejected{code,..}) if code == busbar_plugin_abi::auth::BAD_CREDENTIAL)
        );
    }
    assert_eq!(port.calls.load(Ordering::SeqCst), 4);
    assert_eq!(port.refreshes.load(Ordering::SeqCst), 1);
    assert!(matches!(
        verify_cached(&services, &cache, instance, cx(), &req).await,
        Ok(Verdict::Rejected { .. })
    ));
    assert_eq!(port.calls.load(Ordering::SeqCst), 5);
    assert_eq!(port.refreshes.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn concurrent_replay_requests_compete_after_policy_and_only_one_admits() {
    let checks = Checks {
        allow: AtomicBool::new(true),
        claims: AtomicUsize::new(0),
        issued: AtomicUsize::new(0),
        epoch: AtomicUsize::new(1),
    };
    let services = AuthServices {
        issued: &checks,
        replay: &checks,
        policy: &checks,
    };
    let port = Port {
        calls: AtomicUsize::new(0),
        issued: false,
        stale: false,
        plain: false,
        refreshes: AtomicUsize::new(0),
    };
    let keys = KeyRefresh::new(Duration::from_secs(30));
    let who = caller();
    let instance = ChainInstance {
        id: 1,
        port: &port,
        caller: &who,
        keys: &keys,
        holds: &[],
    };
    let cache = Verdicts::new(VerdictPolicy::default());
    let req = request();
    let (a, b) = tokio::join!(
        verify_cached(&services, &cache, instance, cx(), &req),
        verify_cached(&services, &cache, instance, cx(), &req)
    );
    let outcomes = [a, b];
    assert_eq!(
        outcomes
            .iter()
            .filter(|x| matches!(x, Ok(Verdict::Identity(_))))
            .count(),
        1
    );
    assert_eq!(outcomes.iter().filter(|x| matches!(x,Ok(Verdict::Rejected{code,..}) if *code == busbar_plugin_abi::fail::refused::R_REPLAYED)).count(),1);
    assert_eq!(checks.claims.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn cache_hits_recheck_policy_and_new_policy_epochs_reverify() {
    let checks = Checks {
        allow: AtomicBool::new(true),
        claims: AtomicUsize::new(0),
        issued: AtomicUsize::new(0),
        epoch: AtomicUsize::new(1),
    };
    let services = AuthServices {
        issued: &checks,
        replay: &checks,
        policy: &checks,
    };
    let port = Port {
        calls: AtomicUsize::new(0),
        issued: false,
        stale: false,
        plain: true,
        refreshes: AtomicUsize::new(0),
    };
    let keys = KeyRefresh::new(Duration::from_secs(30));
    let who = caller();
    let instance = ChainInstance {
        id: 1,
        port: &port,
        caller: &who,
        keys: &keys,
        holds: &[],
    };
    let cache = Verdicts::new(VerdictPolicy::default());
    let req = request();
    assert!(matches!(
        verify_cached(&services, &cache, instance, cx(), &req).await,
        Ok(Verdict::Identity(_))
    ));
    assert!(matches!(
        verify_cached(&services, &cache, instance, cx(), &req).await,
        Ok(Verdict::Identity(_))
    ));
    assert_eq!(port.calls.load(Ordering::SeqCst), 1);
    checks.allow.store(false, Ordering::SeqCst);
    assert!(matches!(
        verify_cached(&services, &cache, instance, cx(), &req).await,
        Ok(Verdict::PolicyRejected { .. })
    ));
    assert_eq!(
        port.calls.load(Ordering::SeqCst),
        1,
        "a cached cryptographic verdict still goes through current policy"
    );
    checks.allow.store(true, Ordering::SeqCst);
    checks.epoch.store(2, Ordering::SeqCst);
    assert!(matches!(
        verify_cached(&services, &cache, instance, cx(), &req).await,
        Ok(Verdict::Identity(_))
    ));
    assert_eq!(
        port.calls.load(Ordering::SeqCst),
        2,
        "policy epoch is part of the cache key"
    );
}
