// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! W1-K10's shared rig for its conformance arms (C-ENTITLE, C-MINT, C-SIGN, C-CONNECT, C-MCP-CONNECT,
//! C-LOGIN-PKCE, C-TRUST-VERIFY, C-REPLAY): the kernel's own plugin records over core's in-tree in-memory store
//! (the contract busbar-store-memory serves), a fake `oauth-connection`-style auth instance with a fake
//! authorization server, the configured upstream table, and the production intent host (`KernelIntents`) over
//! K10's services, so a plane answer resolves exactly as a served plane's does.

#[path = "../../busbar-kernel/src/tests/memory_backend.rs"]
mod memory_backend;

use std::collections::{BTreeMap, HashMap};
use std::sync::{Arc, Mutex};

use busbar_contract::crypto::LocalSigner;
use busbar_contract::secure::SecureVec;
use busbar_kernel::channels::SessionSignals;
use busbar_kernel::connections::{ConnectLogins, StoreConnections};
use busbar_kernel::persistence::facade::{CoreStore, Limits};
use busbar_kernel::persistence::startup::{Progress, Startup};
use busbar_kernel::plane_driver::port_intents::{Intent, KernelIntents, Lent, Namespace, Resolver};
use busbar_kernel::plane_driver::port_services::Services;
use busbar_kernel::plane_grants::{CoreJwsSigner, GrantResolver, RequestGrants, SealedTickets};
use busbar_kernel::plugin_records::StoreRecords;
use busbar_kernel::push::StorePushQueue;
use busbar_kernel::upstreams::{UpstreamAuth, UpstreamDef, UpstreamTls, Upstreams};
use busbar_plugin_abi::auth::{FB_LOGIN_REDIRECT, SECURITY_CHECK};
use busbar_plugin_abi::fail::refused::R_UNSUPPORTED;
use busbar_plugin_abi::host_side::caller::{BoxFut, CallStack, Caller, InstanceLimits};
use busbar_plugin_abi::types::KindCode;
use busbar_ports::auth::{
    AuthIn, AuthPort, LoginAnswer, LoginIn, OutboundAnswer, ServeIn, ServeOut, UpstreamIn, Verify,
};
use busbar_ports::{CallCx, PortError};

/// `server.public_url`.
pub const PUBLIC: &str = "https://busbar.example";
/// The `connection` upstream's `redirect_uri` path, where K10 serves the callback.
pub const CALLBACK: &str = "/oauth/github/callback";
/// The configured upstream with a `connection` form.
pub const CONNECTED: &str = "github";
/// The grant the fake authorization server issues on COMPLETE.
pub const GRANT: &[u8] = b"gho_refresh-token-1";
/// The plane instance the arms run as.
const PLANE_PLUGIN: &str = "plane-mcp";
const PLANE_NAME: &str = "tools";
/// The verified principal.
pub const SUBJECT: &str = "alice";

pub fn runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .expect("a test runtime")
}

/// A fresh in-memory core store, admitted.
pub async fn store() -> Arc<CoreStore> {
    let mut startup = Startup::new(
        Arc::new(memory_backend::MemoryBackend::default()),
        Limits {
            pending_operations: 64,
            conflict_retries: 8,
            scan_items: 128,
            scan_bytes: 1024 * 1024,
        },
        true,
    )
    .expect("store authority");
    loop {
        match startup.advance().await.expect("store startup") {
            Progress::Advanced => {}
            Progress::Admitted => break,
            other => panic!("the store did not admit: {other:?}"),
        }
    }
    startup.store().expect("the admitted store")
}

pub fn plane() -> Caller<'static> {
    Caller {
        plugin: PLANE_PLUGIN,
        kind: KindCode::Plane,
        name: PLANE_NAME,
        instance: 1,
        slot: 0,
        chain: 1,
        deadline: std::time::Instant::now() + std::time::Duration::from_secs(30),
        stack: CallStack::default(),
        out_of_process: false,
        limits: InstanceLimits::default(),
    }
}

/// What the fake authorization plugin was handed.
#[derive(Default, Clone)]
pub struct Seen {
    pub challenge: Option<String>,
    pub begin_nonce: Option<String>,
    pub state_key: Option<String>,
    pub redirect_uri: Option<String>,
    pub verifier: Option<String>,
    pub complete_nonce: Option<String>,
    /// Every STATE the plugin answered, and every STATE core handed back.
    pub states: Vec<Vec<u8>>,
}

fn refused(code: u32) -> PortError {
    PortError::Refused {
        code,
        text: "refused".into(),
        error: None,
    }
}

fn unsupported<'a, T: Send + 'a>() -> BoxFut<'a, Result<T, PortError>> {
    Box::pin(async { Err(refused(R_UNSUPPORTED)) })
}

/// An `oauth-connection`-style auth instance (auth-oauth's `login` with L_CONNECT): BEGIN answers the
/// authorization URL with exactly the challenge and state core passed; COMPLETE answers the GRANT, or
/// SECURITY_CHECK when the callback's `iss` is not the issuer's. It mints nothing itself.
pub struct FakeOauth {
    facts: u64,
    pub seen: Arc<Mutex<Seen>>,
}

impl AuthPort for FakeOauth {
    fn facts(&self) -> u64 {
        self.facts
    }

    fn cred_headers(&self) -> &[Box<str>] {
        &[]
    }

    fn issued_kind(&self) -> Option<&str> {
        None
    }

    fn verify<'a>(&'a self, _cx: CallCx, _req: &AuthIn<'_>, _issued: Option<&[u8]>) -> Verify<'a> {
        Verify::Done(Err(refused(R_UNSUPPORTED)))
    }

    fn login<'a>(
        &'a self,
        _cx: CallCx,
        step: LoginIn<'a>,
    ) -> BoxFut<'a, Result<LoginAnswer, PortError>> {
        let mut seen = self.seen.lock().unwrap_or_else(|e| e.into_inner());
        let answer = match step {
            LoginIn::Begin {
                redirect_uri,
                state_key,
                code_challenge,
                nonce,
                ..
            } => {
                seen.challenge = Some(code_challenge.to_owned());
                seen.begin_nonce = Some(nonce.to_owned());
                seen.state_key = Some(state_key.to_owned());
                seen.redirect_uri = Some(redirect_uri.to_owned());
                let state = b"iss=https://as.example;resource=https://api.github.example".to_vec();
                seen.states.push(state.clone());
                Ok(LoginAnswer::Redirect {
                    url: format!(
                        "https://as.example/authorize?response_type=code&code_challenge={code_challenge}\
                         &code_challenge_method=S256&state={state_key}&redirect_uri={redirect_uri}\
                         &resource=https://api.github.example"
                    )
                    .into(),
                    state: SecureVec::from(state),
                })
            }
            LoginIn::Complete {
                callback_query,
                state,
                code_verifier,
                nonce,
                ..
            } => {
                seen.verifier = Some(code_verifier.to_owned());
                seen.complete_nonce = Some(nonce.to_owned());
                seen.states.push(state.to_vec());
                if callback_query.contains("iss=https://as.example") {
                    Ok(LoginAnswer::Grant(SecureVec::from(GRANT)))
                } else {
                    Err(refused(SECURITY_CHECK))
                }
            }
            LoginIn::Credential { .. } => Err(refused(R_UNSUPPORTED)),
        };
        Box::pin(async move { answer })
    }

    fn outbound<'a>(
        &'a self,
        _cx: CallCx,
        _req: &'a UpstreamIn<'a>,
    ) -> BoxFut<'a, Result<OutboundAnswer, PortError>> {
        unsupported()
    }

    fn refresh<'a>(&'a self, _cx: CallCx) -> BoxFut<'a, Result<Option<u32>, PortError>> {
        unsupported()
    }

    fn serve<'a>(
        &'a self,
        _cx: CallCx,
        _req: &'a ServeIn<'a>,
    ) -> BoxFut<'a, Result<ServeOut, PortError>> {
        unsupported()
    }
}

struct Logins(BTreeMap<&'static str, Arc<dyn AuthPort>>);

impl ConnectLogins for Logins {
    fn port(&self, instance: &str) -> Option<Arc<dyn AuthPort>> {
        self.0.get(instance).cloned()
    }
}

struct Table(BTreeMap<&'static str, Arc<UpstreamDef>>);

impl Upstreams for Table {
    fn get(&self, name: &str) -> Option<Arc<UpstreamDef>> {
        self.0.get(name).cloned()
    }
}

fn upstream(name: &str, auth: Option<UpstreamAuth>) -> Arc<UpstreamDef> {
    Arc::new(UpstreamDef {
        name: name.into(),
        resource: None,
        allow_private: false,
        url: Some(format!("https://{name}.example").into()),
        command: None,
        tls: UpstreamTls {
            pin_spki: Vec::new(),
            client_identity: None,
            trust: None,
        },
        auth,
    })
}

/// The deployment: one store, the upstream table and the opened auth instances, shared by every replica.
pub struct Deployment {
    pub store: Arc<CoreStore>,
    upstreams: Arc<dyn Upstreams>,
    logins: Arc<dyn ConnectLogins>,
    pub seen: Arc<Mutex<Seen>>,
}

impl Deployment {
    pub async fn new() -> Self {
        let seen = Arc::new(Mutex::new(Seen::default()));
        let oauth: Arc<dyn AuthPort> = Arc::new(FakeOauth {
            facts: FB_LOGIN_REDIRECT,
            seen: Arc::clone(&seen),
        });
        let mut ports = BTreeMap::new();
        ports.insert("github-connection", oauth);
        let mut table = BTreeMap::new();
        table.insert(
            CONNECTED,
            upstream(
                CONNECTED,
                Some(UpstreamAuth {
                    instance: "github-connection".into(),
                    cache_max_s: None,
                    connect_callback: Some(CALLBACK.into()),
                    caller: true,
                    scoped: false,
                    per_request: false,
                }),
            ),
        );
        table.insert("public", upstream("public", None));
        Self {
            store: store().await,
            upstreams: Arc::new(Table(table)),
            logins: Arc::new(Logins(ports)),
            seen,
        }
    }

    /// One replica's caller connections (core's at-rest key, shared by every replica).
    pub fn connections(&self) -> StoreConnections<StoreRecords> {
        StoreConnections::new(
            StoreRecords::new(Arc::clone(&self.store)),
            &[0x5a; 32],
            Arc::clone(&self.upstreams),
            Arc::clone(&self.logins),
            PUBLIC,
        )
        .expect("a 32-byte at-rest key")
    }

    pub fn seen(&self) -> Seen {
        self.seen.lock().unwrap_or_else(|e| e.into_inner()).clone()
    }

    /// The production intent host of plane instance (`PLANE_PLUGIN`, `PLANE_NAME`) over K10's services: ENTITLE
    /// grants `chat`, MINT seals with a host key, SIGN uses an Ed25519 host signer, CONNECT runs `connections`.
    pub fn intents(
        &self,
        rt: &tokio::runtime::Runtime,
        connections: Arc<StoreConnections<StoreRecords>>,
    ) -> KernelIntents<StoreRecords> {
        let tickets = SealedTickets::new(
            StoreRecords::new(Arc::clone(&self.store)),
            &[7u8; 32],
            busbar_kernel::store::now,
        )
        .expect("a 32-byte host key");
        let signer = LocalSigner::from_seed(&[3u8; 32]).expect("an Ed25519 seed");
        let services = Services {
            entitlements: Some(Arc::new(RequestGrants::new(Chat))),
            tickets: Some(Arc::new(tickets)),
            signer: Some(Arc::new(CoreJwsSigner::new(Arc::new(signer)))),
            connections: Some(connections),
            ..Services::default()
        };
        KernelIntents::new(
            Arc::new(StoreRecords::new(Arc::clone(&self.store))),
            // The one push queue (arch lints section 3.1): durable rows in this deployment's store.
            Arc::new(StorePushQueue::new(
                Arc::clone(&self.store),
                Arc::new(busbar_kernel::retry::Policy::default()),
            )),
            Arc::new(NoSignals),
            Namespace {
                plugin: Arc::from(PLANE_PLUGIN),
                name: Arc::from(PLANE_NAME),
                instance: 1,
                slot: 0,
            },
            rt.handle().clone(),
        )
        .with_services(services)
    }
}

/// ENTITLE's grant set: every principal holds `chat`.
struct Chat;

impl GrantResolver for Chat {
    fn grants(&self, _identity: &[u8], sink: &mut dyn FnMut(&str)) {
        sink("chat");
    }
}

struct NoSignals;

impl SessionSignals for NoSignals {
    fn signal(
        &self,
        _instance: u64,
        _key: &[u8],
        _subject: Option<[u8; 32]>,
        _flags: u32,
        _bytes: &[u8],
    ) -> u32 {
        0
    }
}

/// A delivered result piece, copied out of the resolver's lent pieces for the cases to read.
pub(crate) struct Piece {
    pub(crate) flags: u32,
    pub(crate) bytes: Vec<u8>,
}

/// One plane answer with a CONNECT, a SIGN, a MINT, an ENTITLE and a LOOKUP (after the STORE it reads), stated
/// in the reverse of the §8.6 delivery order, resolved by core as the verified `SUBJECT`. Called off the runtime
/// (the production host blocks on it, as it does from `spawn_blocking`).
pub fn resolve(host: &KernelIntents<StoreRecords>, connect_op: u32) -> Vec<Piece> {
    let mut lent = Lent::default();
    let answer = vec![
        Intent::Connect {
            check: 5,
            op: connect_op,
            upstream: lent.put(CONNECTED.as_bytes()),
            return_to: Some(lent.put(b"/settings/connections")),
        },
        Intent::Sign {
            check: 4,
            flags: busbar_plugin_abi::plane::SIGN_JWS_COMPACT,
            payload: lent.put(br#"{"name":"agent-card"}"#),
        },
        Intent::Mint {
            check: 3,
            flags: busbar_plugin_abi::plane::MINT_ONCE,
            ttl_s: 60,
            scope: Some(lent.put(b"realtime")),
            audience: Some(lent.put(b"calls")),
            prefix: Some(lent.put(b"ek_")),
            record: None,
        },
        Intent::Entitle {
            check: 2,
            grant: lent.put(b"chat"),
        },
        Intent::Store {
            flags: 0,
            ttl_s: 0,
            key: lent.put(b"k"),
            value: lent.put(b"v"),
        },
        Intent::Lookup {
            flags: 0,
            limit: 1,
            key: lent.put(b"k"),
        },
    ];
    let identity = b"identity-records".as_slice();
    let resolver = Resolver::new(host, None).with_principal(SUBJECT, identity);
    resolver
        .resolve(&answer, &lent, &mut HashMap::new(), &mut Default::default())
        .into_iter()
        .map(|p| Piece {
            flags: p.flags,
            bytes: p.bytes.as_bytes().to_vec(),
        })
        .collect()
}

/// The FROM_CORE piece flags in delivery order.
pub fn order(pieces: &[Piece]) -> Vec<u32> {
    pieces.iter().map(|p| p.flags).collect()
}

/// The §8.6 order of the result kinds this answer produces.
pub fn if_order() -> Vec<u32> {
    use busbar_plugin_abi::plane::{P_CONNECT, P_ENTITLE, P_LOOKUP, P_MINTED, P_SIGNED};
    vec![P_LOOKUP, P_ENTITLE, P_MINTED, P_SIGNED, P_CONNECT]
}

/// The bytes of the one piece with `flags`.
pub fn piece(pieces: &[Piece], flags: u32) -> &[u8] {
    &pieces
        .iter()
        .find(|p| p.flags == flags)
        .unwrap_or_else(|| panic!("a piece with flags {flags:#x}"))
        .bytes
}

/// The (pod, tail) of every record of `tag` in `bytes`.
pub fn records_of<T: busbar_plugin_abi::records::Pod>(bytes: &[u8], tag: u16) -> Vec<(T, Vec<u8>)> {
    busbar_plugin_abi::records::Records::new(bytes)
        .map(|rec| rec.expect("well-framed records"))
        .filter(|rec| rec.tag == tag)
        .map(|rec| {
            let (pod, tail) = rec.pod_tail::<T>().expect("the record's pod");
            (pod, tail.to_vec())
        })
        .collect()
}

/// Runs BEGIN through `connections` and the browser's return on the callback path, as the authorization server
/// redirects it; answers the callback's result.
pub fn connect(
    rt: &tokio::runtime::Runtime,
    deployment: &Deployment,
    connections: &StoreConnections<StoreRecords>,
    query_extra: &str,
) -> busbar_kernel::connections::CallbackAnswer {
    let who = plane();
    rt.block_on(connections.begin(&who, SUBJECT, CONNECTED, None))
        .expect("BEGIN answers the authorization URL");
    let state = deployment.seen().state_key.expect("BEGIN ran");
    rt.block_on(connections.callback(CALLBACK, &format!("code=c0de{query_extra}&state={state}")))
}

fn encode(bytes: &[u8], alphabet: &[u8; 64], pad: bool) -> String {
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let n = chunk
            .iter()
            .enumerate()
            .fold(0u32, |acc, (i, &b)| acc | u32::from(b) << (16 - 8 * i));
        for i in 0..4 {
            if i <= chunk.len() {
                let index = usize::try_from((n >> (18 - 6 * i)) & 63).expect("< 64");
                out.push(char::from(alphabet[index]));
            } else if pad {
                out.push('=');
            }
        }
    }
    out
}

/// base64 (RFC 4648 §4, padded).
pub fn b64(bytes: &[u8]) -> String {
    encode(
        bytes,
        b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/",
        true,
    )
}

/// base64url (RFC 4648 §5, unpadded).
pub fn b64url(bytes: &[u8]) -> String {
    encode(
        bytes,
        b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_",
        false,
    )
}
