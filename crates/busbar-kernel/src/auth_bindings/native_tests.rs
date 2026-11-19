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

// P095-11 (P093F-3): rotation, refresh failure, lapse and the owner-signed revocation rule on the native
// credential path. A scripted auth port stands for the source; a capturing report stands for the operator's log
// and audit trail.

use crate::refresh::Report;
use busbar_plugin_abi::fail::failed::F_UNAVAILABLE;
use busbar_plugin_abi::fail::refused::{R_DENIED, R_NOT_FOUND};
use std::collections::VecDeque;

/// One answer the scripted source gives.
#[derive(Clone, Copy)]
enum Answer {
    Value(&'static str),
    Outage,
    Definitive(u32),
}

/// An auth port that answers from a script, then repeats its last answer, under one header name.
struct ScriptedPort {
    header: &'static str,
    script: Mutex<VecDeque<Answer>>,
    last: Mutex<Answer>,
    calls: AtomicUsize,
}

fn scripted(header: &'static str, answers: &[Answer]) -> Arc<ScriptedPort> {
    Arc::new(ScriptedPort {
        header,
        script: Mutex::new(answers.iter().copied().collect()),
        last: Mutex::new(answers[0]),
        calls: AtomicUsize::new(0),
    })
}

impl ScriptedPort {
    fn then(&self, answers: &[Answer]) {
        self.script.lock().unwrap().extend(answers.iter().copied());
    }
    fn calls(&self) -> usize {
        self.calls.load(Ordering::SeqCst)
    }
    fn next(&self) -> Answer {
        let mut last = self.last.lock().unwrap();
        if let Some(answer) = self.script.lock().unwrap().pop_front() {
            *last = answer;
        }
        *last
    }
}

impl AuthPort for ScriptedPort {
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
        _: &'a UpstreamIn<'a>,
    ) -> BoxFut<'a, Result<OutboundAnswer, PortError>> {
        Box::pin(async move {
            self.calls.fetch_add(1, Ordering::SeqCst);
            match self.next() {
                Answer::Value(value) => Ok(OutboundAnswer {
                    headers: vec![(self.header.into(), SecureVec::from(value.as_bytes()))],
                    query: Vec::new(),
                    cache_s: 600,
                    grant_update: None,
                }),
                Answer::Outage => Err(PortError::Failed {
                    code: F_UNAVAILABLE,
                    text: "scripted outage".into(),
                    retry_after_s: None,
                    backend_status: None,
                    error: None,
                }),
                Answer::Definitive(code) => Err(PortError::Refused {
                    code,
                    text: "scripted definitive answer".into(),
                    error: None,
                }),
            }
        })
    }
}

/// One line a binding reported.
#[derive(Debug, Clone)]
struct Line {
    code: Option<u16>,
    level: tracing::Level,
    fields: Vec<(&'static str, String)>,
}

impl Line {
    fn field(&self, name: &str) -> Option<&str> {
        self.fields
            .iter()
            .find(|(k, _)| *k == name)
            .map(|(_, v)| v.as_str())
    }
}

/// A report that keeps what it is told.
#[derive(Default)]
struct Captured {
    lines: Mutex<Vec<Line>>,
    audits: Mutex<Vec<(String, String, &'static str)>>,
}

impl Captured {
    fn leak() -> &'static Captured {
        Box::leak(Box::default())
    }
    /// The lines coded `code` at INFO or louder.
    fn coded(&self, code: u16) -> Vec<Line> {
        self.lines
            .lock()
            .unwrap()
            .iter()
            .filter(|l| l.code == Some(code) && l.level != tracing::Level::DEBUG)
            .cloned()
            .collect()
    }
    /// The lines coded `code` held back at debug.
    fn quiet(&self, code: u16) -> Vec<Line> {
        self.lines
            .lock()
            .unwrap()
            .iter()
            .filter(|l| l.code == Some(code) && l.level == tracing::Level::DEBUG)
            .cloned()
            .collect()
    }
    fn infos(&self) -> Vec<Line> {
        self.lines
            .lock()
            .unwrap()
            .iter()
            .filter(|l| l.code.is_none())
            .cloned()
            .collect()
    }
    fn all(&self) -> String {
        format!("{:?}", self.lines.lock().unwrap())
    }
    fn audits(&self) -> Vec<(String, String, &'static str)> {
        self.audits.lock().unwrap().clone()
    }
}

impl Report for Captured {
    fn diag(
        &self,
        diag: &'static crate::diagnostics::Diagnostic,
        level: tracing::Level,
        message: &str,
        fields: &[(&'static str, String)],
    ) {
        let mut fields = fields.to_vec();
        fields.push(("message", message.to_string()));
        self.lines.lock().unwrap().push(Line {
            code: Some(diag.code),
            level,
            fields,
        });
    }
    fn info(&self, message: &str, fields: &[(&'static str, String)]) {
        let mut fields = fields.to_vec();
        fields.push(("message", message.to_string()));
        self.lines.lock().unwrap().push(Line {
            code: None,
            level: tracing::Level::INFO,
            fields,
        });
    }
    fn audit(&self, action: &str, resource: &str, outcome: &'static str) {
        self.audits
            .lock()
            .unwrap()
            .push((action.to_string(), resource.to_string(), outcome));
    }
}

/// A cache whose held values go stale `refresh_ahead_s` before they expire and whose failure window for a streak
/// of `n` is `n` × 500 ms (so a reset streak shows in the next report's `retry_in_ms`).
fn lease_cache(refresh_ahead_s: u32) -> Arc<CredCache> {
    let mut policy = CredPolicy::DEFAULT;
    policy.min_mint_interval_s = 0;
    policy.refresh_ahead_s = refresh_ahead_s;
    Arc::new(CredCache::new(
        policy,
        |streak, _| crate::retry::Retry::After(Duration::from_millis(500) * streak),
        |_, _| {},
    ))
}

/// A binding on member `member` of auth instance 21 (the source), capped at 30 s, reporting to `report`.
fn reported(
    port: Arc<ScriptedPort>,
    cache: Arc<CredCache>,
    member: &str,
    namespace: u64,
    report: &'static Captured,
) -> NativeBinding {
    let mut spec = spec(0, namespace);
    spec.key.member = member.into();
    NativeBinding::reporting(spec, port, cache, report).unwrap()
}

/// What the binding presents now: the header value it would append, or None when it presents nothing.
async fn presented(binding: &NativeBinding) -> Option<Vec<(String, Vec<u8>)>> {
    let credential = binding.credential(cx(), &input(None)).await.ok()?;
    let mut head = OwnedHead::with_capacity(1);
    credential.append_to(&mut head);
    Some(
        head.view()
            .into_iter()
            .map(|(n, v)| (n.to_string(), v.to_vec()))
            .collect(),
    )
}

/// Let the cache's detached mints and timers run.
async fn settle() {
    for _ in 0..8 {
        tokio::task::yield_now().await;
    }
}

fn header(name: &str, value: &str) -> Option<Vec<(String, Vec<u8>)>> {
    Some(vec![(name.to_string(), value.as_bytes().to_vec())])
}

// TESTS.tsv:307
#[tokio::test(start_paused = true)]
async fn a_rotated_secret_is_presented_on_the_first_hop_after_the_next_refresh() {
    let port = scripted("authorization", &[Answer::Value("v1")]);
    let binding = reported(Arc::clone(&port), lease_cache(0), "m0", 1, Captured::leak());
    assert_eq!(presented(&binding).await, header("authorization", "v1"));
    port.then(&[Answer::Value("v2")]);
    tokio::time::advance(Duration::from_secs(29)).await;
    assert_eq!(
        presented(&binding).await,
        header("authorization", "v1"),
        "inside the 30 s cap the held value is presented"
    );
    assert_eq!(port.calls(), 1, "and nothing is re-minted");
    tokio::time::advance(Duration::from_secs(2)).await;
    assert_eq!(
        presented(&binding).await,
        header("authorization", "v2"),
        "the first hop after the cap presents the rotated value"
    );
    assert_eq!(port.calls(), 2);
    for _ in 0..3 {
        assert_eq!(presented(&binding).await, header("authorization", "v2"));
    }
    assert_eq!(port.calls(), 2, "an unchanged value is not re-minted");
}

// TESTS.tsv:308
#[tokio::test(start_paused = true)]
async fn a_rotated_header_credential_is_presented_in_the_same_header() {
    let port = scripted("X-Api-Key", &[Answer::Value("key-1")]);
    let binding = reported(Arc::clone(&port), lease_cache(0), "m0", 1, Captured::leak());
    assert_eq!(presented(&binding).await, header("X-Api-Key", "key-1"));
    port.then(&[Answer::Value("key-2")]);
    tokio::time::advance(Duration::from_secs(31)).await;
    let rotated = binding.credential(cx(), &input(None)).await.unwrap();
    assert!(rotated.covers_header(b"x-api-key"));
    assert!(!rotated.covers_header(b"authorization"));
    assert_eq!(rotated.sealed_names(), ["x-api-key"]);
    let mut head = OwnedHead::with_capacity(1);
    rotated.append_to(&mut head);
    assert_eq!(
        head.view(),
        [("X-Api-Key", &b"key-2"[..])],
        "the re-minted value keeps its header, and nothing moves to the query"
    );
    assert_eq!(port.calls(), 2);
}

// TESTS.tsv:336
#[tokio::test(start_paused = true)]
async fn a_refresh_failure_emits_8026_once_per_streak_window_and_audits_degraded() {
    let report = Captured::leak();
    let port = scripted(
        "authorization",
        &[Answer::Value("ta4-SECRET-VALUE"), Answer::Outage],
    );
    let binding = reported(Arc::clone(&port), lease_cache(10), "ta4-member", 1, report);
    assert_eq!(
        presented(&binding).await,
        header("authorization", "ta4-SECRET-VALUE")
    );
    for s in [21, 1, 1, 28] {
        tokio::time::advance(Duration::from_secs(s)).await;
        presented(&binding).await;
        settle().await;
    }
    let warned = report.coded(8026);
    assert_eq!(warned.len(), 1, "one per streak window: {}", report.all());
    assert_eq!(warned[0].level, tracing::Level::WARN);
    assert_eq!(warned[0].field("member"), Some("ta4-member"));
    assert_eq!(warned[0].field("reference"), Some("auth:21"));
    assert_eq!(
        warned[0].field("error_kind"),
        Some(F_UNAVAILABLE.to_string().as_str())
    );
    assert_eq!(warned[0].field("cause"), Some("resolve"));
    assert_eq!(warned[0].field("failures"), Some("1"));
    for field in ["retry_in_ms", "expires_in_ms", "style", "others"] {
        assert!(warned[0].field(field).is_some(), "{field} missing");
    }
    assert!(
        !report.quiet(8026).is_empty(),
        "the later failures are held back: {}",
        report.all()
    );
    assert_eq!(
        report.audits(),
        vec![(
            "upstream_credential.refresh".to_string(),
            "member:plane/p/ta4-member".to_string(),
            "degraded"
        )],
        "the audit follows the report's cadence"
    );
    tokio::time::advance(Duration::from_secs(61)).await;
    presented(&binding).await;
    settle().await;
    assert_eq!(report.coded(8026).len(), 2, "again after a minute");
    assert_eq!(report.audits().len(), 2);

    let seen = format!("{}{:?}", report.all(), report.audits());
    let plain = busbar_contract::crypto::sha256(b"ta4-SECRET-VALUE");
    for leaked in [
        "ta4-SECRET-VALUE".to_string(),
        hex::encode(plain),
        busbar_contract::media::base64_encode(&plain),
    ] {
        assert!(!seen.contains(&leaked), "a report carries {leaked}: {seen}");
    }
}

// TESTS.tsv:337
#[tokio::test(start_paused = true)]
async fn a_lapse_emits_8027_once_and_audits_rejected() {
    let report = Captured::leak();
    let port = scripted("authorization", &[Answer::Value("v1"), Answer::Outage]);
    let binding = reported(Arc::clone(&port), lease_cache(10), "ta5", 1, report);
    assert_eq!(presented(&binding).await, header("authorization", "v1"));
    tokio::time::advance(Duration::from_secs(21)).await;
    assert_eq!(
        presented(&binding).await,
        header("authorization", "v1"),
        "an outage keeps the held value"
    );
    settle().await;
    assert_eq!(report.coded(8026).len(), 1, "{}", report.all());
    assert!(report.coded(8027).is_empty(), "not yet");
    tokio::time::advance(Duration::from_secs(10)).await;
    settle().await;
    tokio::time::advance(Duration::from_secs(5)).await;
    settle().await;
    let lapsed = report.coded(8027);
    assert_eq!(
        lapsed.len(),
        1,
        "once per lapse, with no hop: {}",
        report.all()
    );
    assert_eq!(lapsed[0].level, tracing::Level::ERROR);
    assert_eq!(lapsed[0].field("cause"), Some("lease-expired"));
    assert_eq!(lapsed[0].field("member"), Some("ta5"));
    assert_eq!(
        report.audits().last(),
        Some(&(
            "upstream_credential.refresh".to_string(),
            "member:plane/p/ta5".to_string(),
            "rejected"
        ))
    );
    assert_eq!(presented(&binding).await, None, "never past its expiry");
    settle().await;
    assert_eq!(report.coded(8027).len(), 1, "still once");
}

// TESTS.tsv:338
#[tokio::test(start_paused = true)]
async fn recovery_after_failures_audits_applied_and_resets_the_schedule() {
    let report = Captured::leak();
    let port = scripted(
        "authorization",
        &[Answer::Outage, Answer::Outage, Answer::Value("v1")],
    );
    let binding = reported(Arc::clone(&port), lease_cache(10), "ta6", 1, report);
    assert_eq!(presented(&binding).await, None);
    tokio::time::advance(Duration::from_secs(1)).await;
    assert_eq!(presented(&binding).await, None);
    let failures: Vec<_> = report
        .coded(8026)
        .into_iter()
        .chain(report.quiet(8026))
        .map(|l| l.field("failures").map(str::to_owned))
        .collect();
    assert_eq!(
        failures,
        [Some("1".to_string()), Some("2".to_string())],
        "{}",
        report.all()
    );
    tokio::time::advance(Duration::from_secs(2)).await;
    assert_eq!(presented(&binding).await, header("authorization", "v1"));
    assert_eq!(report.infos().len(), 1, "one recovery line");
    assert_eq!(report.infos()[0].field("member"), Some("ta6"));
    assert_eq!(report.audits().last().map(|a| a.2), Some("applied"));
    assert_eq!(presented(&binding).await, header("authorization", "v1"));
    assert_eq!(report.infos().len(), 1, "a hit is not a recovery");
    port.then(&[Answer::Outage]);
    tokio::time::advance(Duration::from_secs(21)).await;
    presented(&binding).await;
    settle().await;
    let last = report.quiet(8026).last().cloned().expect("a later failure");
    assert_eq!(last.field("failures"), Some("1"), "the streak restarted");
    assert_eq!(
        last.field("retry_in_ms"),
        Some("500"),
        "and so did the schedule"
    );
}

// TESTS.tsv:340: the owner-signed rule (2026-11-12, T-A1).
#[tokio::test(start_paused = true)]
async fn a_definitive_answer_drops_after_one_confirming_reread_and_an_outage_keeps() {
    for code in [R_NOT_FOUND, R_DENIED] {
        let report = Captured::leak();
        let port = scripted(
            "authorization",
            &[Answer::Value("v1"), Answer::Definitive(code)],
        );
        let binding = reported(Arc::clone(&port), lease_cache(10), "b1-def", 1, report);
        assert_eq!(presented(&binding).await, header("authorization", "v1"));
        tokio::time::advance(Duration::from_secs(21)).await;
        presented(&binding).await;
        settle().await;
        assert_eq!(port.calls(), 2, "the first definitive answer");
        assert_eq!(
            presented(&binding).await,
            header("authorization", "v1"),
            "kept until a re-read confirms it"
        );
        settle().await;
        assert!(report.coded(8027).is_empty(), "a re-read inside one second confirms nothing");
        tokio::time::advance(Duration::from_secs(1)).await;
        presented(&binding).await;
        settle().await;
        assert_eq!(
            presented(&binding).await,
            None,
            "dropped at once on the confirming answer, well before its expiry"
        );
        let revoked = report.coded(8027);
        assert_eq!(revoked.len(), 1, "{}", report.all());
        assert_eq!(revoked[0].level, tracing::Level::ERROR);
        assert_eq!(revoked[0].field("cause"), Some("revoked-at-source"));
        assert_eq!(
            revoked[0].field("error_kind"),
            Some(code.to_string().as_str())
        );
        assert_eq!(report.audits().last().map(|a| a.2), Some("rejected"));
        port.then(&[Answer::Value("v2")]);
        assert_eq!(
            presented(&binding).await,
            header("authorization", "v2"),
            "the first refresh that succeeds presents it again"
        );
        assert_eq!(report.audits().last().map(|a| a.2), Some("applied"));
    }

    let report = Captured::leak();
    let mixed = scripted(
        "authorization",
        &[
            Answer::Value("v1"),
            Answer::Definitive(R_DENIED),
            Answer::Definitive(R_NOT_FOUND),
        ],
    );
    let binding = reported(Arc::clone(&mixed), lease_cache(10), "b1-mixed", 1, report);
    presented(&binding).await;
    tokio::time::advance(Duration::from_secs(21)).await;
    presented(&binding).await;
    settle().await;
    tokio::time::advance(Duration::from_secs(1)).await;
    presented(&binding).await;
    settle().await;
    assert_eq!(mixed.calls(), 3);
    assert_eq!(
        presented(&binding).await,
        header("authorization", "v1"),
        "a different answer is not a confirmation: it is confirmed afresh"
    );
    assert!(report.coded(8027).is_empty(), "{}", report.all());

    let report = Captured::leak();
    let blip = scripted(
        "authorization",
        &[
            Answer::Value("v1"),
            Answer::Definitive(R_NOT_FOUND),
            Answer::Value("v1"),
        ],
    );
    let binding = reported(Arc::clone(&blip), lease_cache(10), "b1-blip", 1, report);
    presented(&binding).await;
    tokio::time::advance(Duration::from_secs(21)).await;
    presented(&binding).await;
    settle().await;
    tokio::time::advance(Duration::from_secs(1)).await;
    presented(&binding).await;
    settle().await;
    tokio::time::advance(Duration::from_secs(1)).await;
    assert_eq!(
        presented(&binding).await,
        header("authorization", "v1"),
        "a blip never drops"
    );
    assert!(report.coded(8027).is_empty(), "{}", report.all());

    let report = Captured::leak();
    let outage = scripted("authorization", &[Answer::Value("v1"), Answer::Outage]);
    let binding = reported(Arc::clone(&outage), lease_cache(10), "b1-outage", 1, report);
    presented(&binding).await;
    tokio::time::advance(Duration::from_secs(21)).await;
    for _ in 0..3 {
        presented(&binding).await;
        settle().await;
        tokio::time::advance(Duration::from_secs(2)).await;
    }
    assert!(outage.calls() >= 3, "the outage was read: {}", outage.calls());
    assert_eq!(
        presented(&binding).await,
        header("authorization", "v1"),
        "outages keep it"
    );
    assert!(report.coded(8027).is_empty(), "{}", report.all());
}

// TESTS.tsv:343: many members on one source report once a minute, the rest counted.
#[tokio::test(start_paused = true)]
async fn members_failing_on_one_source_report_once_and_count_the_others() {
    let report = Captured::leak();
    let cache = lease_cache(10);
    let members: Vec<_> = (0..5_u64)
        .map(|i| {
            reported(
                scripted("authorization", &[Answer::Outage]),
                Arc::clone(&cache),
                &format!("m5-{i}"),
                i + 1,
                report,
            )
        })
        .collect();
    for binding in &members {
        assert_eq!(presented(binding).await, None);
    }
    assert_eq!(report.coded(8026).len(), 1, "{}", report.all());
    assert_eq!(report.quiet(8026).len(), 4, "the rest at debug");
    assert_eq!(report.audits().len(), 1);
    tokio::time::advance(Duration::from_secs(61)).await;
    presented(&members[1]).await;
    let again = report.coded(8026);
    assert_eq!(again.len(), 2);
    assert_eq!(again[1].field("member"), Some("m5-1"));
    assert_eq!(
        again[1].field("others"),
        Some("4"),
        "the held-back members are counted"
    );
}
