// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::native::{NativeCredential, NativeRouteBindings, SelectedCredential};
use busbar_contract::conn::OwnedHead;
use busbar_contract::dest::DestinationId;
use busbar_contract::secure::SecureVec;
use busbar_ports::auth::OutboundAnswer;

#[test]
fn native_selection_requires_exact_pool_member_and_destination() {
    let routes = NativeRouteBindings::new([
        (
            "pool-a".into(),
            "plane/model".into(),
            DestinationId::new(7),
            SelectedCredential::None,
        ),
        (
            "pool-b".into(),
            "plane/model".into(),
            DestinationId::new(8),
            SelectedCredential::None,
        ),
    ])
    .unwrap();
    assert!(routes
        .select("pool-a", "plane/model", DestinationId::new(7))
        .is_ok());
    assert!(routes
        .select("pool-a", "plane/model", DestinationId::new(8))
        .is_err());
    assert!(routes
        .select("pool-c", "plane/model", DestinationId::new(7))
        .is_err());
    assert!(routes
        .select("pool-a", "model", DestinationId::new(7))
        .is_err());
}

#[test]
fn native_credentials_seal_names_and_require_secure_transport() {
    let credential = NativeCredential::Direct(OutboundAnswer {
        headers: vec![(
            "AuThOrIzAtIoN".into(),
            SecureVec::from(&b"canary-secret"[..]),
        )],
        query: vec![("key".into(), SecureVec::from(&b"a &b"[..]))],
        cache_s: 60,
        grant_update: None,
    });
    assert!(credential.require_secure());
    assert!(credential.covers_header(b"authorization"));
    assert!(!credential.covers_header(b"x-other"));
    assert_eq!(credential.sealed_names(), ["authorization"]);
    let mut head = OwnedHead::with_capacity(2);
    credential.append_to(&mut head);
    let fields = head.view();
    assert_eq!(fields[0].1, b"canary-secret");
    assert_eq!(fields[1].1, b"key=a%20%26b");
}

#[test]
fn empty_native_answer_does_not_require_credential_transport() {
    let credential = NativeCredential::Direct(OutboundAnswer {
        headers: Vec::new(),
        query: Vec::new(),
        cache_s: 0,
        grant_update: None,
    });
    assert!(!credential.require_secure());
}

use super::native::{NativeBinding, NativeBindingSpec, SelectedRouteKey};
use crate::custody::{CredCache, CredPolicy};
use busbar_contract::config::UpstreamCreds;
use busbar_plugin_abi::host_side::caller::BoxFut;
use busbar_ports::auth::{
    AuthIn, AuthPort, LoginAnswer, LoginIn, ServeIn, ServeOut, UpstreamIn, Verify,
};
use busbar_ports::{CallCx, PortError};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// One call the port saw.
type SeenCall = (String, String, Option<String>, bool);

#[derive(Default)]
pub(crate) struct NativePort {
    pub(crate) calls: AtomicUsize,
    pub(crate) body_hashes: Mutex<Vec<Option<[u8; 32]>>>,
    seen: Mutex<Vec<SeenCall>>,
}
fn unsupported<'a, T: Send + 'a>() -> BoxFut<'a, Result<T, PortError>> {
    Box::pin(async {
        Err(PortError::Call(
            busbar_plugin_abi::fail::CallError::NotDeclared,
        ))
    })
}
impl AuthPort for NativePort {
    fn facts(&self) -> u64 {
        busbar_plugin_abi::auth::FB_NEEDS_BODY_HASH
    }
    fn cred_headers(&self) -> &[Box<str>] {
        &[]
    }
    fn issued_kind(&self) -> Option<&str> {
        None
    }
    fn verify<'a>(&'a self, _: CallCx, _: &AuthIn<'_>, _: Option<&[u8]>) -> Verify<'a> {
        Verify::Done(Err(PortError::Call(
            busbar_plugin_abi::fail::CallError::NotDeclared,
        )))
    }
    fn login<'a>(
        &'a self,
        _: CallCx,
        _: LoginIn<'a>,
    ) -> BoxFut<'a, Result<LoginAnswer, PortError>> {
        unsupported()
    }
    fn refresh<'a>(&'a self, _: CallCx) -> BoxFut<'a, Result<Option<u32>, PortError>> {
        unsupported()
    }
    fn serve<'a>(
        &'a self,
        _: CallCx,
        _: &'a ServeIn<'a>,
    ) -> BoxFut<'a, Result<ServeOut, PortError>> {
        unsupported()
    }
    fn outbound<'a>(
        &'a self,
        _: CallCx,
        req: &'a UpstreamIn<'a>,
    ) -> BoxFut<'a, Result<OutboundAnswer, PortError>> {
        Box::pin(async move {
            self.calls.fetch_add(1, Ordering::SeqCst);
            self.body_hashes.lock().unwrap().push(req.body_sha256);
            self.seen.lock().unwrap().push((
                req.method.into(),
                req.url.into(),
                req.scope.map(str::to_owned),
                req.body_sha256.is_some(),
            ));
            Ok(OutboundAnswer {
                headers: vec![(
                    "authorization".into(),
                    SecureVec::from(&b"native-canary"[..]),
                )],
                query: vec![("key".into(), SecureVec::from(&b"q &"[..]))],
                cache_s: 600,
                grant_update: None,
            })
        })
    }
}
fn cache() -> Arc<CredCache> {
    let mut policy = CredPolicy::DEFAULT;
    policy.min_mint_interval_s = 0;
    Arc::new(CredCache::new(
        policy,
        |_, _| crate::retry::Retry::Stop,
        |_, _| {},
    ))
}
pub(crate) fn native_binding(
    port: Arc<NativePort>,
    flags: u64,
    namespace: u64,
) -> Arc<NativeBinding> {
    Arc::new(NativeBinding::new(spec(flags, namespace), port, cache()).unwrap())
}
fn spec(flags: u64, namespace: u64) -> NativeBindingSpec {
    NativeBindingSpec {
        key: SelectedRouteKey {
            plane: "plane".into(),
            pool: "p".into(),
            member: "m0".into(),
        },
        destination: DestinationId::new(1),
        upstream: "upstream".into(),
        auth_instance: 21,
        credential_namespace: namespace,
        style_flags: flags,
        mode: UpstreamCreds::Own,
        cache_max_s: Some(30),
    }
}
fn cx() -> CallCx {
    CallCx {
        deadline: Instant::now() + Duration::from_secs(10),
        request_id: 1,
        stack: Default::default(),
        mono_ns: 0,
    }
}
fn input(scope: Option<&str>) -> UpstreamIn<'_> {
    UpstreamIn {
        method: "POST",
        url: "https://upstream/actual",
        headers: &[],
        body_sha256: Some([1; 32]),
        caller_cred: &[],
        scope,
        caller_grant: None,
        min_valid_s: 0,
    }
}

#[test]
fn native_scope_cache_key_preserves_sha256_bytes_and_identity() {
    let port = Arc::new(NativePort::default());
    let binding = native_binding(Arc::clone(&port), busbar_plugin_abi::auth::STYLE_SCOPE, 3);
    for (scope, digest) in [
        (
            "",
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        ),
        (
            "abc",
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
        ),
        (
            "é\0a",
            "2abae60aa04ead065b9e11ba3ef9a2291cb04c13a7ae09fac214d46b8db68d9f",
        ),
    ] {
        let key = binding.cache_key(Some(scope));
        assert_eq!(key.scope.as_slice(), hex::decode(digest).unwrap());
        assert_eq!(
            (key.auth_instance, key.upstream, key.caller),
            (21, 3, [0; 32])
        );
    }
    assert_eq!(binding.cache_key(None).scope, [0; 32]);
    assert_ne!(binding.cache_key(None), binding.cache_key(Some("")));
    let unscoped = native_binding(port, 0, 3);
    assert_eq!(unscoped.cache_key(Some("abc")), binding.cache_key(None));
}

#[tokio::test]
async fn shared_native_mints_once_and_clamps_before_publication() {
    let port = Arc::new(NativePort::default());
    let binding = native_binding(Arc::clone(&port), 0, 3);
    for scope in [Some("a"), Some("b")] {
        let answer = binding.credential(cx(), &input(scope)).await.unwrap();
        assert!(matches!(answer, NativeCredential::Shared(_)));
        assert_eq!(answer.answer().cache_s, 30);
    }
    assert_eq!(port.calls.load(Ordering::SeqCst), 1);
    assert_eq!(
        port.seen.lock().unwrap()[0],
        ("POST".into(), "https://upstream/actual".into(), None, true)
    );
    let key = binding.cache_key(Some("discarded"));
    assert_eq!(
        (key.auth_instance, key.upstream, key.scope, key.caller),
        (21, 3, [0; 32], [0; 32])
    );
}

#[tokio::test]
async fn scoped_and_per_request_native_credentials_do_not_alias() {
    use busbar_plugin_abi::auth::{STYLE_PER_REQUEST, STYLE_SCOPE};
    let port = Arc::new(NativePort::default());
    let binding = native_binding(Arc::clone(&port), STYLE_SCOPE, 3);
    binding.credential(cx(), &input(Some("a"))).await.unwrap();
    binding.credential(cx(), &input(Some("b"))).await.unwrap();
    assert_ne!(binding.cache_key(Some("a")), binding.cache_key(Some("b")));
    assert_eq!(port.calls.load(Ordering::SeqCst), 2);
    let direct = native_binding(Arc::clone(&port), STYLE_PER_REQUEST, 4);
    for _ in 0..2 {
        assert!(matches!(
            direct.credential(cx(), &input(None)).await.unwrap(),
            NativeCredential::Direct(_)
        ));
    }
    assert_eq!(port.calls.load(Ordering::SeqCst), 4);
}

#[test]
fn caller_and_passthrough_cannot_activate_without_authority_producers() {
    for mode in [UpstreamCreds::Connection, UpstreamCreds::Passthrough] {
        let mut spec = spec(0, 1);
        spec.mode = mode;
        assert!(NativeBinding::new(spec, Arc::new(NativePort::default()), cache()).is_err());
    }
    assert!(NativeBinding::new(
        spec(busbar_plugin_abi::auth::STYLE_CALLER, 1),
        Arc::new(NativePort::default()),
        cache()
    )
    .is_err());
}

#[tokio::test]
async fn two_route_policies_share_one_cache_without_sharing_credentials() {
    let port = Arc::new(NativePort::default());
    let cache = cache();
    let first = NativeBinding::new(spec(0, 1), port.clone(), Arc::clone(&cache)).unwrap();
    let mut other = spec(0, 2);
    other.key.pool = "other".into();
    other.cache_max_s = Some(7);
    let second = NativeBinding::new(other, port.clone(), cache).unwrap();
    assert_eq!(
        first
            .credential(cx(), &input(None))
            .await
            .unwrap()
            .answer()
            .cache_s,
        30
    );
    assert_eq!(
        second
            .credential(cx(), &input(None))
            .await
            .unwrap()
            .answer()
            .cache_s,
        7
    );
    first.credential(cx(), &input(None)).await.unwrap();
    second.credential(cx(), &input(None)).await.unwrap();
    assert_eq!(port.calls.load(Ordering::SeqCst), 2);
    assert_ne!(first.cache_key(None), second.cache_key(None));
}

#[tokio::test(start_paused = true)]
async fn configured_cap_expires_the_cached_native_value() {
    let port = Arc::new(NativePort::default());
    let mut policy = CredPolicy::DEFAULT;
    policy.min_mint_interval_s = 0;
    policy.refresh_ahead_s = 0;
    let cache = Arc::new(CredCache::new(
        policy,
        |_, _| crate::retry::Retry::Stop,
        |_, _| {},
    ));
    let mut spec = spec(0, 1);
    spec.cache_max_s = Some(2);
    let binding = NativeBinding::new(spec, port.clone(), cache).unwrap();
    binding.credential(cx(), &input(None)).await.unwrap();
    tokio::time::advance(Duration::from_secs(3)).await;
    binding.credential(cx(), &input(None)).await.unwrap();
    assert_eq!(
        port.calls.load(Ordering::SeqCst),
        2,
        "issuer's 600 seconds cannot bypass configured two-second cap"
    );
}
