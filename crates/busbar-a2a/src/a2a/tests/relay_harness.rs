// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE HARNESS THE RELAY'S TESTS SHARE: a real router, a real audience-bound busbar token, and a
//! recording seam in place of a socket.
//!
//! ONE harness rather than one per test file, and that is a security property rather than tidiness.
//! The adversarial no-leak scan and the streaming tests must drive the SAME production ingress; a
//! second harness is a second thing that can stop matching what the router actually does, and the
//! defect this whole area exists to catch — a relay that behaves when a test calls it and forwards
//! the caller's credential when axum calls it — is invisible to any test that does not go through
//! the real router.
//!
//! ## Why the recording seam stands in for the socket
//!
//! `tests/transport_tests.rs` states why the transport tests stop at the transport seam: a test
//! server binds to loopback, loopback is INTERNAL, and the SSRF guard refuses it with no override —
//! adding a "test addresses are fine" escape hatch to the guard would be a hole in production to
//! make a test pass. So the recording seam stands in for the socket here, and the socket-level half
//! of the claim is discharged in `transport_tests.rs` against the real client.

use crate::testkit::engine_boot::engine;
use crate::testkit::TestAppA2aExt;
use busbar_substrate::testkit::engine_kit::{GovKit, HookEnvHandle};
use busbar_substrate::testkit::engine_kit_plus::EngineAppPlus;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use crate::a2a::fetch::{HttpResponse, Resolver};
use crate::a2a::registry::AgentRegistration;
use crate::a2a::relay::{ChunkFlow, RelaySeam, RelayTransport, StreamHead};

/// The audience this deployment binds, derived from the public URL below by `serve::canonical_uri`.
pub(super) const PUBLIC_URL: &str = "https://busbar.example";
pub(super) const AUDIENCE: &str = "https://busbar.example/a2a";

/// The backend agent's real A2A endpoint. In the RFC 6761 `.test` TLD, so nothing can resolve it by
/// accident and any address it "has" came from the resolver this test installed.
pub(super) const BACKEND: &str = "https://backend.agent.test/a2a";
/// A SECOND registered agent, for the confused-deputy tests: the caller holds no grant on it.
pub(super) const OTHER_BACKEND: &str = "https://payments.agent.test/a2a";

/// The address the guard is told the backend resolves to. Public, so the SSRF guard admits it.
pub(super) const BACKEND_ADDR: IpAddr = IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34));

/// THE CREDENTIAL BUSBAR LEGITIMATELY PRESENTS TO THE BACKEND. Distinctive, and the control in
/// `relay_tests` requires the scanner to find it.
pub(super) const LEASED: &str = "leased-outbound-cred-BUSBAR-PRESENTS-THIS-7f3a";

// ══ THE RECORDING SEAM ═══════════════════════════════════════════════════════════════════════════

/// One request the relay asked to have sent, as it asked.
#[derive(Clone, Debug, Default)]
pub(super) struct Recorded {
    /// THE REQUEST LINE'S VERB. Recorded because A2A's HTTP+JSON binding reads with `GET` and
    /// withdraws with `DELETE`, so "busbar issued this operation" is a claim about the verb as much
    /// as about the path — and a client that spelled every operation as a `POST` would look correct
    /// in a log that only kept the URL.
    pub(super) http_method: String,
    pub(super) url: String,
    pub(super) addr: Option<IpAddr>,
    pub(super) headers: Vec<(String, String)>,
    pub(super) body: Vec<u8>,
    /// Whether the relay asked for a STREAM. Recorded so a test can assert that a `message/stream`
    /// went out as a streaming hop and a `message/send` did not.
    pub(super) streaming: bool,
}

impl Recorded {
    /// EVERY byte this request would put on the wire: URL, then each header name and value, then
    /// the body. The haystack the sentinel scan searches.
    pub(super) fn wire(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(self.http_method.as_bytes());
        out.extend_from_slice(self.url.as_bytes());
        for (n, v) in &self.headers {
            out.extend_from_slice(n.as_bytes());
            out.extend_from_slice(v.as_bytes());
        }
        out.extend_from_slice(&self.body);
        out
    }
}

/// What the recording transport does when the relay reaches it.
#[derive(Clone)]
pub(super) enum Outcome {
    /// A real HTTP answer: status and body, VERBATIM, whatever was asked. The literal fixture, for
    /// a test that serves exactly one request or that is asserting something about a `id` the
    /// backend chose — see [`super::response_id_tests`], where an answer naming another request is
    /// the whole subject.
    Answers(u16, String),
    /// The same, from a backend that ANSWERS THE REQUEST IT WAS ASKED: the canned body's JSON-RPC
    /// `id` is replaced, per call, by the `id` of the request that reached the transport.
    ///
    /// For a test that makes MORE THAN ONE call against one fixture. A canned document pinned to a
    /// single hardcoded `id` is an answer to one request being served to all of them, and now that
    /// the relay correlates, the second call is correctly refused `502` — a red test that says
    /// nothing about busbar and everything about the fixture. The lesson is [`backend_ok_for`]'s,
    /// paid for a second time: a fixture that agrees only with itself proves nothing.
    AnswersCorrelated(u16, String),
    /// The hop failed at the transport, the way a refused connection or a TLS refusal does.
    Fails(String),
    /// A real SSE stream: these frames, in order, one chunk each.
    Streams(Vec<String>),
    /// A stream request answered with a single JSON document — legal for a task the backend
    /// finished instantly.
    StreamAnsweredUnary(String),
    /// A backend that answers each UNARY hop IN TURN, the last body repeating once the list runs
    /// out.
    ///
    /// The addressed verbs need TWO hops against ONE backend — a submission that opens the task and
    /// then the read or the cancel that names it — and the two answers are DIFFERENT MESSAGE TYPES
    /// on the gRPC binding (`SendMessageResponse`, then `Task`). A fixture that served one body to
    /// both would make the second hop's answer undecodable, and a test that then asserted only on
    /// the request would silently stop covering the answer half.
    AnswersInTurn(u16, Vec<String>, Arc<AtomicUsize>),
    /// PER-BACKEND answers, matched by URL HOST substring, each correlated to the request's own
    /// JSON-RPC `id` — the twin-pool fixture: one recording seam fronting two backends that behave
    /// differently, which is the only way "the caller got the TWIN's answer and the dead member
    /// was never touched again" can be asserted on outputs. A hop whose host matches no entry
    /// panics: a pool test reaching an unplanned backend is the defect, not a default.
    AnswersByHost(Vec<(String, u16, String)>),
    /// A backend that answers a UNARY hop with one document and a STREAMING hop with these frames.
    ///
    /// One fixture rather than two harnesses, because the tests that need it are the ones that OPEN
    /// a task with a submission and then SUBSCRIBE to it — two hops of different shapes against one
    /// backend, which is what a resubscribe actually is. A fixture that could only do one of them
    /// forced the subscribe tests to stand up a second deployment, and a task opened in one
    /// deployment is not addressable in another.
    AnswersThenStreams(u16, String, Vec<String>),
}

/// [`Outcome::AnswersInTurn`] with its own counter. A constructor rather than a literal so a test
/// cannot accidentally share one counter between two harnesses.
pub(super) fn in_turn(status: u16, replies: Vec<String>) -> Outcome {
    Outcome::AnswersInTurn(status, replies, Arc::new(AtomicUsize::new(0)))
}

pub(super) struct RecordingResolver {
    pub(super) lookups: Arc<AtomicUsize>,
}

impl Resolver for RecordingResolver {
    fn resolve(&self, _host: &str) -> Result<Vec<IpAddr>, String> {
        self.lookups.fetch_add(1, Ordering::SeqCst);
        Ok(vec![BACKEND_ADDR])
    }
}

pub(super) struct RecordingTransport {
    pub(super) log: Arc<Mutex<Vec<Recorded>>>,
    pub(super) outcome: Outcome,
}

impl RecordingTransport {
    fn record(
        &self,
        http_method: &str,
        url: &url::Url,
        addr: IpAddr,
        headers: &[(String, String)],
        body: &[u8],
        streaming: bool,
    ) {
        self.log
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .push(Recorded {
                http_method: http_method.to_string(),
                url: url.to_string(),
                addr: Some(addr),
                headers: headers.to_vec(),
                body: body.to_vec(),
                streaming,
            });
    }
}

impl RelayTransport for RecordingTransport {
    fn send(
        &self,
        http_method: &str,
        url: &url::Url,
        addr: IpAddr,
        headers: &[(String, String)],
        body: &[u8],
    ) -> Result<HttpResponse, String> {
        self.record(http_method, url, addr, headers, body, false);
        match &self.outcome {
            Outcome::Answers(status, reply) => Ok(HttpResponse {
                status: *status,
                location: None,
                body: reply.clone().into_bytes(),
                peer_spki: None,
                client_identity_offered: false,
            }),
            Outcome::AnswersCorrelated(status, reply) => Ok(HttpResponse {
                status: *status,
                location: None,
                body: correlated(reply, body).into_bytes(),
                peer_spki: None,
                client_identity_offered: false,
            }),
            Outcome::Fails(err) => Err(err.clone()),
            Outcome::AnswersByHost(hosts) => {
                let host = url.host_str().unwrap_or_default().to_string();
                let (_, status, reply) = hosts
                    .iter()
                    .find(|(needle, _, _)| host.contains(needle.as_str()))
                    .unwrap_or_else(|| panic!("no planned answer for backend host `{host}`"));
                Ok(HttpResponse {
                    status: *status,
                    location: None,
                    body: correlated(reply, body).into_bytes(),
                    peer_spki: None,
                    client_identity_offered: false,
                })
            }
            Outcome::AnswersInTurn(status, replies, seen) => {
                let n = seen.fetch_add(1, Ordering::SeqCst);
                let reply = replies
                    .get(n)
                    .or_else(|| replies.last())
                    .expect("an `AnswersInTurn` fixture with no answers answers nothing");
                Ok(HttpResponse {
                    status: *status,
                    location: None,
                    body: correlated(reply, body).into_bytes(),
                    peer_spki: None,
                    client_identity_offered: false,
                })
            }
            Outcome::AnswersThenStreams(status, reply, _) => Ok(HttpResponse {
                status: *status,
                location: None,
                body: correlated(reply, body).into_bytes(),
                peer_spki: None,
                client_identity_offered: false,
            }),
            Outcome::Streams(_) | Outcome::StreamAnsweredUnary(_) => {
                panic!("a streaming fixture was reached through the UNARY hop")
            }
        }
    }

    fn post_stream(
        &self,
        url: &url::Url,
        addr: IpAddr,
        headers: &[(String, String)],
        body: &[u8],
        on_chunk: &mut (dyn FnMut(&[u8]) -> ChunkFlow + Send),
    ) -> Result<StreamHead, String> {
        self.record("POST", url, addr, headers, body, true);
        match &self.outcome {
            Outcome::Fails(err) => Err(err.clone()),
            Outcome::AnswersThenStreams(_, _, frames) | Outcome::Streams(frames) => {
                // THE SINK IS CALLED ON A BARE BLOCKING THREAD, exactly as production calls it.
                //
                // Production's `ReqwestTransport::post_stream` rides `seam::hostless().stream`,
                // whose pump (the engine's egress pump) invokes `on_chunk` synchronously
                // on the calling thread — a plain `spawn_blocking` thread, NO runtime context.
                // This fixture matches that context by doing the same. An earlier revision wrapped
                // this loop in a nested current-thread `Runtime::block_on` to mirror the transport
                // of its day (`on_a_dedicated_runtime`, whose only remaining production caller is
                // the resolver's name lookup) — a context production's sink no longer runs in, and
                // the one place in the tree with the nested-runtime shape implicated by the
                // FLAKE-a2a-sse-relay-hang investigation. A fixture that is HARDER to satisfy than
                // production is as wrong as one that is easier: both certify a context nobody runs.
                for frame in frames {
                    if on_chunk(frame.as_bytes()) == ChunkFlow::Stop {
                        break;
                    }
                }
                Ok(StreamHead {
                    status: 200,
                    content_type: "text/event-stream".to_string(),
                    body: Vec::new(),
                })
            }
            Outcome::StreamAnsweredUnary(body) | Outcome::Answers(200, body) => Ok(StreamHead {
                status: 200,
                content_type: "application/json".to_string(),
                body: body.clone().into_bytes(),
            }),
            Outcome::Answers(status, doc) => Ok(StreamHead {
                status: *status,
                content_type: "application/json".to_string(),
                body: doc.clone().into_bytes(),
            }),
            Outcome::AnswersInTurn(status, replies, _) => Ok(StreamHead {
                status: *status,
                content_type: "application/json".to_string(),
                body: replies.last().cloned().unwrap_or_default().into_bytes(),
            }),
            Outcome::AnswersCorrelated(status, doc) => Ok(StreamHead {
                status: *status,
                content_type: "application/json".to_string(),
                body: correlated(doc, body).into_bytes(),
            }),
            Outcome::AnswersByHost(hosts) => {
                let host = url.host_str().unwrap_or_default().to_string();
                let (_, status, reply) = hosts
                    .iter()
                    .find(|(needle, _, _)| host.contains(needle.as_str()))
                    .unwrap_or_else(|| panic!("no planned answer for backend host `{host}`"));
                Ok(StreamHead {
                    status: *status,
                    content_type: "application/json".to_string(),
                    body: correlated(reply, body).into_bytes(),
                })
            }
        }
    }
}

/// THE CANNED ANSWER, MADE INTO AN ANSWER TO *THIS* REQUEST: the reply's JSON-RPC `id` is replaced
/// with the one on the request that just arrived.
///
/// A request that is not JSON, or that has no `id`, leaves the reply exactly as written — a fixture
/// that deliberately serves a malformed hop keeps serving it.
fn correlated(reply: &str, request: &[u8]) -> String {
    let Some(id) = serde_json::from_slice::<serde_json::Value>(request)
        .ok()
        .and_then(|r| r.get("id").cloned())
    else {
        return reply.to_string();
    };
    let Ok(mut doc) = serde_json::from_str::<serde_json::Value>(reply) else {
        return reply.to_string();
    };
    let Some(obj) = doc.as_object_mut() else {
        return reply.to_string();
    };
    obj.insert("id".to_string(), id);
    doc.to_string()
}

pub(super) struct RecordingSeam {
    pub(super) resolver: RecordingResolver,
    pub(super) transport: RecordingTransport,
}

impl RelaySeam for RecordingSeam {
    fn resolver(&self) -> &dyn Resolver {
        &self.resolver
    }
    fn transport(&self) -> &dyn RelayTransport {
        &self.transport
    }
}

// ══ THE SENTINEL SCAN ════════════════════════════════════════════════════════════════════════════

/// Encodings a secret could plausibly be smuggled in. A scan that only looked for the plaintext
/// would be defeated by `base64` and would say so with a green tick.
pub(super) fn encodings(secret: &str) -> Vec<(&'static str, Vec<u8>)> {
    use base64::Engine as _;
    use sha2::Digest as _;
    let mut v = vec![
        ("plain", secret.as_bytes().to_vec()),
        (
            "base64",
            base64::engine::general_purpose::STANDARD
                .encode(secret)
                .into_bytes(),
        ),
        (
            "base64url-nopad",
            base64::engine::general_purpose::URL_SAFE_NO_PAD
                .encode(secret)
                .into_bytes(),
        ),
        ("hex", hex::encode(secret).into_bytes()),
    ];
    // sha256, because "we only sent a hash of it" is still sending a value derived from a
    // credential to a party that has no business holding one.
    let mut h = sha2::Sha256::new();
    h.update(secret.as_bytes());
    v.push(("sha256-hex", hex::encode(h.finalize()).into_bytes()));
    v
}

pub(super) fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty() && haystack.windows(needle.len()).any(|w| w == needle)
}

// ══ THE HARNESS ══════════════════════════════════════════════════════════════════════════════════

/// The card the registration has cached. One skill and BOTH capabilities, so the catalogue matches
/// an envelope that names none and does not exclude a streaming one.
pub(super) fn a_card() -> serde_json::Value {
    serde_json::json!({
        "protocolVersion": "0.3.0",
        "name": "planner",
        "defaultInputModes": ["application/json"],
        "defaultOutputModes": ["application/json"],
        "capabilities": { "streaming": true, "pushNotifications": true },
        "skills": [{ "id": "plan", "name": "Plan" }]
    })
}

/// THE SAME CARD, DECLARING WHICH OF A2A'S THREE BINDINGS THIS AGENT SERVES.
///
/// `supportedInterfaces` is the member A2A defines for it and the one `relay::binding_of` reads.
/// A card that declares NONE is [`a_card`] above and means JSON-RPC, which is A2A's own default —
/// so every existing harness caller keeps building exactly the deployment it always built.
pub(super) fn a_card_on(binding: &str) -> serde_json::Value {
    let mut card = a_card();
    card["supportedInterfaces"] = serde_json::json!([{
        "url": BACKEND,
        "protocolBinding": binding,
    }]);
    card
}

/// Lift a registration to APPROVED against the card it has cached, the way the `connect`/approve
/// verb pair does — nothing here invents a trust state of its own.
pub(super) fn approve(reg: &mut AgentRegistration) {
    approve_card(reg, a_card());
}

/// The same, against a card that declares a binding.
pub(super) fn approve_card(reg: &mut AgentRegistration, card: serde_json::Value) {
    let digests = crate::a2a::card::skill_digests(&card).expect("digests");
    let sighting = busbar_substrate::trust::Sighting::Seen(busbar_substrate::trust::Observation {
        pin: Some(crate::a2a::pin::CardPin::JwsIssuerKey {
            issuer_key: "KEY".to_string(),
            card_fingerprint: "sha256/CARD".to_string(),
        }),
        capabilities: digests,
    });
    crate::a2a::pin::approve_registration(&mut reg.approval, &sighting, None).expect("approve");
    reg.sighting = sighting;
    reg.cached_card = Some(card);
}

/// A file holding the leased outbound credential. A file rather than an environment variable
/// because tests run in parallel in one process and `set_var` is process-wide.
pub(super) fn secret_file() -> std::path::PathBuf {
    let path = std::env::temp_dir().join(format!(
        "busbar-a2a-relay-cred-{}-{:?}.txt",
        std::process::id(),
        std::thread::current().id()
    ));
    std::fs::write(&path, LEASED).expect("write the leased credential");
    path
}

pub(super) fn agent_cfg(url: &str, with_credential: bool) -> crate::a2a::config::AgentDefCfg {
    crate::a2a::config::AgentDefCfg {
        url: url.to_string(),
        pin: crate::a2a::config::AgentPinCfg {
            mechanism: crate::a2a::config::PinMechanism::Unpinned,
            key: None,
            fingerprint: None,
        },
        reverify_ttl: None,
        recovery_backoff: None,
        protocol_version: None,
        allow_private: false,
        upstream_credentials: None,
        upstream_credential: with_credential.then(|| crate::a2a::creds::OutboundCredential {
            secret: busbar_secret_ref::SecretRef::file(secret_file().to_string_lossy().to_string()),
            placement: crate::a2a::creds::CredentialPlacement::Bearer,
            lease_ttl_ms: 600_000,
        }),
        egress_scopes: Vec::new(),
        client_identity: None,
        hooks: Vec::new(),
    }
}

/// Everything one relayed call needs, standing up.
pub(super) struct Harness {
    pub(super) addr: std::net::SocketAddr,
    /// The caller's busbar key: a REAL audience-bound token this deployment's verifier accepts.
    pub(super) bearer: String,
    pub(super) log: Arc<Mutex<Vec<Recorded>>>,
    pub(super) lookups: Arc<AtomicUsize>,
    pub(super) gov: Arc<dyn GovKit>,
    pub(super) plane: Arc<crate::a2a::plane::A2aPlane>,
    /// The built App, kept so the pool batteries can read the plane breaker cells directly.
    pub(super) app: Arc<dyn EngineAppPlus>,
    server: tokio::task::JoinHandle<()>,
}

impl Harness {
    /// Every byte the relay asked to send, across every recorded request.
    pub(super) fn all_wire(&self) -> Vec<u8> {
        let log = self.log.lock().unwrap_or_else(|e| e.into_inner());
        let mut out = Vec::new();
        for r in log.iter() {
            out.extend_from_slice(&r.wire());
        }
        out
    }

    pub(super) fn sent(&self) -> Vec<Recorded> {
        self.log.lock().unwrap_or_else(|e| e.into_inner()).clone()
    }
}

impl Drop for Harness {
    fn drop(&mut self) {
        self.server.abort();
    }
}

/// The default harness: one agent (`planner`), granted to the caller.
pub(super) async fn harness(outcome: Outcome, with_credential: bool) -> Harness {
    harness_granting(outcome, with_credential, &["planner"]).await
}

/// THE SAME DEPLOYMENT, WITH THE BACKEND'S CARD DECLARING `binding`.
///
/// The ONLY difference from [`harness`] is the card each registration has cached — no second router,
/// no second seam, no second ingress. That is the claim the whole binding block rests on: arming a
/// leg is re-framing, so a test that changes one member of one card and finds a different request on
/// the wire is a test that has proved the framing is the only thing that varied.
pub(super) async fn harness_on(outcome: Outcome, binding: &str) -> Harness {
    let h = harness_granting(outcome, false, &["planner"]).await;
    let card = a_card_on(binding);
    h.plane.with_registrations_mut(|regs| {
        for reg in regs.iter_mut() {
            approve_card(reg, card.clone());
        }
    });
    h
}

/// THE OPERATOR'S HOOK ATTACHMENT for a harness that wants one: the loaded plugin env, the
/// `hooks:` DEFINITIONS, and the section-level `agents.hooks:` list they are attached by.
///
/// Optional rather than a defaulted field so that every existing harness caller builds the SAME
/// deployment it always did — a fixture that quietly gains a gate is a fixture whose other tests
/// start proving something else.
pub(super) struct Gates {
    /// The loaded hook-plugin environment, from the engine kit's `hook_env`.
    pub(super) env: HookEnvHandle,
    /// The `hooks:` definitions as config documents, parsed by the engine's own grammar at build.
    pub(super) hooks: Vec<(String, serde_json::Value)>,
    pub(super) attach: Vec<String>,
}

/// A harness whose caller is granted exactly `granted`. Two agents are always REGISTERED —
/// `planner` and `payments` — so a test can point a caller at one it holds no grant on.
pub(super) async fn harness_granting(
    outcome: Outcome,
    with_credential: bool,
    granted: &[&str],
) -> Harness {
    harness_gated(outcome, with_credential, granted, None).await
}

/// The same harness with an operator's `agents.hooks:` attach applied, resolved through the real
/// resolver by the same `TestApp` build every other harness caller uses.
pub(super) async fn harness_gated(
    outcome: Outcome,
    with_credential: bool,
    granted: &[&str],
    gates: Option<Gates>,
) -> Harness {
    harness_full(
        outcome,
        with_credential,
        granted,
        gates,
        &[("planner", BACKEND), ("payments", OTHER_BACKEND)],
        &[],
    )
    .await
}

/// The fully-general constructor: the AGENT DEFINITIONS and `agent_pools:` declarations are the
/// caller's. Every narrower constructor above builds exactly the deployment it always built by
/// passing the historical two-agent set and no pools.
pub(super) async fn harness_full(
    outcome: Outcome,
    with_credential: bool,
    granted: &[&str],
    gates: Option<Gates>,
    defs: &[(&str, &str)],
    pools: &[(&str, &[&str])],
) -> Harness {
    use busbar_substrate::governance::signing::{TokenSigner, TokenVerifier, DEFAULT_KID};
    use busbar_substrate::governance::NewKeySpec;
    engine().metrics_init();

    let store: Arc<dyn busbar_api::Store> = Arc::new(busbar_store_memory::MemoryStore::new());
    // Two handles on the SAME key material: one inside the governance registry (which consumes it)
    // and one for the test to mint the caller's audience-bound token with, so the verifier busbar
    // runs is verifying a token this test really minted.
    let signer = TokenSigner::from_secret_bytes(&[13u8; 32], DEFAULT_KID);
    let gov = engine()
        .governance(
            store,
            None,
            Some(TokenSigner::from_secret_bytes(&[13u8; 32], DEFAULT_KID)),
        )
        .expect("gov");
    let (key, plain) = gov
        .mint_signed(
            NewKeySpec {
                name: "external-agent".to_string(),
                allowed_pools: None,
                group: None,
                labels: Default::default(),
                ..Default::default()
            },
            2_000_000_000,
            busbar_substrate::store::now(),
        )
        .expect("mint");
    let generation = TokenVerifier::single(signer.kid(), signer.verifying_key())
        .verify(plain.as_str(), busbar_substrate::store::now(), None)
        .expect("the plain token verifies")
        .generation;
    // THE GRANT. `agent:<id>` is what `inbound::authorize`, the catalogue and the EGRESS gate all
    // ask about, and a test that wants to prove the third is separable hands it a narrower list.
    let mut scoped = key.clone();
    scoped.allowed_scopes = Some(
        granted
            .iter()
            .map(|a| busbar_api::ScopeRef {
                kind: crate::a2a::inbound::SCOPE_KIND_AGENT.to_string(),
                value: (*a).to_string(),
            })
            .collect(),
    );
    gov.store().put_key(&scoped).expect("put");
    gov.refresh().expect("refresh");

    let bearer = signer.mint_for_audience(
        &key.id,
        2_000_000_000,
        generation.as_deref(),
        AUDIENCE,
        Some("external-agent-1"),
    );

    let mut builder = engine()
        .new_app_plus()
        .public_url(PUBLIC_URL)
        .keys_chain()
        .governance(Arc::clone(&gov));
    for (name, url) in defs {
        builder = builder.agent_def(name, agent_cfg(url, with_credential));
    }
    for (pool, members) in pools {
        builder = builder.agent_pool(pool, members);
    }
    if let Some(g) = gates {
        builder = builder
            .hook_env(g.env)
            .agents_hooks(&g.attach.iter().map(String::as_str).collect::<Vec<_>>());
        for (name, cfg) in g.hooks {
            builder = builder.hook(&name, cfg);
        }
    }
    let app = builder.build();
    // The front door writes the A2A task chain through the process-wide `TASKS` registry; the plane
    // owns it now and mints each chain's `seq`/`prev_hash` on `submit`/`transition` regardless of any
    // attached sink (this harness does not boot through `a2a_hydrate` and keeps nothing durable), so
    // there is no longer a process-wide stream to register here.

    let plane = crate::a2a::runtime_arc(app.as_ref()).expect("the plane exists");
    plane.with_registrations_mut(|regs| {
        for reg in regs.iter_mut() {
            approve(reg);
        }
    });

    let log: Arc<Mutex<Vec<Recorded>>> = Arc::new(Mutex::new(Vec::new()));
    let lookups = Arc::new(AtomicUsize::new(0));
    plane.set_relay_seam(Arc::new(RecordingSeam {
        resolver: RecordingResolver {
            lookups: Arc::clone(&lookups),
        },
        transport: RecordingTransport {
            log: Arc::clone(&log),
            outcome,
        },
    }));

    let router = Arc::clone(&app).router();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });

    Harness {
        addr,
        bearer,
        log,
        lookups,
        gov,
        plane,
        app,
        server,
    }
}

/// The A2A envelope a caller sends. Distinctive body content, so the scan is looking at a request
/// that carried something.
pub(super) fn envelope() -> serde_json::Value {
    serde_json::json!({
        "jsonrpc": "2.0",
        "id": 7,
        "method": "message/send",
        "params": {
            "message": {
                "role": "user",
                "contextId": "ctx-abc",
                "parts": [{ "kind": "text", "text": "PLAN THE MIGRATION" }]
            }
        }
    })
}

/// What a healthy backend answers: a Task envelope of its own, with ITS OWN ids — correlated to the
/// JSON-RPC request id in [`envelope`].
pub(super) fn backend_ok() -> String {
    backend_ok_for(serde_json::json!(7))
}

/// The same answer under an explicit JSON-RPC `id`.
///
/// It has to be explicit because the relay now CORRELATES the backend's answer to the request it
/// sent, and this harness serves envelopes with two different ids: `envelope()` sends `7` and the
/// streaming tests send `11`. A fixture answering `7` to a request that sent `11` is not a healthy
/// backend, it is the defect — and it was in this file, unnoticed, until the correlation landed and
/// `relay_stream_tests::a_stream_request_answered_with_one_document_comes_back_as_a_document` went
/// red. The lesson is the one the request side already paid for: a fixture that agrees with nothing
/// but itself proves nothing.
pub(super) fn backend_ok_for(id: serde_json::Value) -> String {
    serde_json::json!({
        "jsonrpc": "2.0",
        "id": id,
        "result": {
            "id": "BACKEND-OWN-TASK-ID",
            "contextId": "BACKEND-OWN-CONTEXT",
            "kind": "task",
            "status": { "state": "completed" },
            "artifacts": [{ "artifactId": "a1", "parts": [{ "kind": "text", "text": "THE PLAN" }] }]
        }
    })
    .to_string()
}

/// POST one envelope to one agent and read the JSON answer.
pub(super) async fn call_agent(
    h: &Harness,
    agent: &str,
    body: &serde_json::Value,
) -> (u16, serde_json::Value) {
    let resp = reqwest::Client::new()
        .post(format!("http://{}/a2a/agents/{agent}", h.addr))
        .header("authorization", format!("Bearer {}", h.bearer))
        .header("content-type", "application/json")
        .json(body)
        .send()
        .await
        .expect("the call completes");
    let status = resp.status().as_u16();
    (status, resp.json().await.unwrap_or(serde_json::Value::Null))
}

pub(super) async fn call(h: &Harness) -> (u16, serde_json::Value) {
    call_agent(h, "planner", &envelope()).await
}

/// POST one envelope and read the answer as RAW BYTES plus its content type — the shape a streamed
/// answer has to be read in, because it is not JSON.
pub(super) async fn call_raw(
    h: &Harness,
    agent: &str,
    body: &serde_json::Value,
) -> (u16, String, String) {
    let resp = reqwest::Client::new()
        .post(format!("http://{}/a2a/agents/{agent}", h.addr))
        .header("authorization", format!("Bearer {}", h.bearer))
        .header("content-type", "application/json")
        .json(body)
        .send()
        .await
        .expect("the call completes");
    let status = resp.status().as_u16();
    let ct = resp
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default()
        .to_string();
    (status, ct, resp.text().await.unwrap_or_default())
}
