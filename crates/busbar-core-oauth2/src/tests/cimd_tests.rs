// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE DOCUMENT CHECKS, adversarially. The flow test proves a GOOD document admits a client end
//! to end; every test here is a document that must NOT, each aimed at the specific escalation its
//! member exists to close. These are busbar's own checks (the tree pins `oauth-as` 1.0.0, which
//! ships a CIMD validator behind an off-by-default `cimd` feature this tree does not enable —
//! see the TODO in [`super`]), so they are the whole of the enforcement today and must each be
//! held red-able on their own.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use oauth_as::client::{ClientAuth, ClientId};
use oauth_as::scope::ScopeSet;
use oauth_as::store::{MemoryStorage, Storage as _};

use super::{
    document_need, is_cimd_client_id, materialize, CimdFetch, CimdStore, ConnectorFetch,
    DOCUMENT_NEED, FETCH_TIMEOUT, MAX_DOCUMENT_BYTES,
};

const URL: &str = "https://client.example/oauth-client";

fn ceiling() -> ScopeSet {
    ScopeSet::from_tokens(["read"]).expect("scope")
}

/// A well-formed document, which each refusal test below breaks in exactly one way — so a refusal
/// is about the broken member and not about a second defect the test never meant to have.
fn document() -> serde_json::Value {
    serde_json::json!({
        "client_id": URL,
        "redirect_uris": ["http://127.0.0.1:9999/cb"],
        "token_endpoint_auth_method": "none",
        "client_name": "an agent",
        "scope": "read",
    })
}

fn materialized(doc: &serde_json::Value) -> Result<oauth_as::client::Client, String> {
    materialize(
        URL,
        &serde_json::to_vec(doc).expect("serialises"),
        &ceiling(),
    )
}

/// The well-formed document materialises, and what it materialises is a PUBLIC client under the
/// operator's ceiling. Without this, every refusal below could be a validator that refuses
/// everything.
#[test]
fn a_well_formed_document_materialises_a_public_client_under_the_ceiling() {
    let client = materialized(&document()).expect("a well-formed document materialises");
    assert_eq!(client.client_id.as_str(), URL);
    assert!(matches!(client.auth, ClientAuth::Public));
    assert_eq!(client.allowed_scopes, ceiling());
    assert_eq!(
        client.redirect_uris,
        vec!["http://127.0.0.1:9999/cb".to_string()]
    );
    assert!(
        client.registration.is_none(),
        "a document client is not a stored dynamic registration; there is nothing to manage"
    );
}

/// THE BINDING CHECK. A document whose `client_id` is not the URL it was fetched from is any
/// attacker-controlled HTTPS URL claiming to be any client, which is the whole mechanism defeated.
#[test]
fn a_document_claiming_a_different_client_id_is_refused() {
    let mut doc = document();
    doc["client_id"] = serde_json::json!("https://other.example/victim");
    materialized(&doc).expect_err("a document may only describe the URL it lives at");

    let mut doc = document();
    doc.as_object_mut().expect("object").remove("client_id");
    materialized(&doc).expect_err("a document with no client_id describes nobody");
}

/// THE CEILING IS THE OPERATOR'S. A document asking past `default_grant` is REFUSED — not
/// narrowed — exactly as a DCR registrant is, because the two mechanisms share one ceiling.
#[test]
fn a_document_asking_past_the_default_grant_is_refused() {
    let mut doc = document();
    doc["scope"] = serde_json::json!("read write admin");
    materialized(&doc).expect_err("a self-identified client cannot widen its own grant");
}

/// A CIMD client is PUBLIC by construction: a secret-bearing auth method names a credential
/// nobody could have pre-shared, so believing it would make the URL's owner confidential by
/// self-declaration.
#[test]
fn a_document_asking_for_a_secret_bearing_auth_method_is_refused() {
    let mut doc = document();
    doc["token_endpoint_auth_method"] = serde_json::json!("client_secret_basic");
    materialized(&doc).expect_err("a metadata-document client cannot hold a secret");
}

/// THE GRANT ESCALATION, same as registration's: `client_credentials` mints a token with no
/// resource owner in the loop, so a document that could ask for it converts "I exist at a URL"
/// into "I am authorised".
#[test]
fn a_document_asking_for_client_credentials_is_refused() {
    let mut doc = document();
    doc["grant_types"] = serde_json::json!(["authorization_code", "client_credentials"]);
    materialized(&doc).expect_err("a self-identified client cannot mint unconsented tokens");
}

/// The consent screen must not be made to lie: the SAME impersonation refusal the registration
/// policy applies holds for a document's `client_name`.
#[test]
fn a_document_impersonating_the_deployment_is_refused() {
    let mut doc = document();
    doc["client_name"] = serde_json::json!("Busbar Gateway");
    materialized(&doc).expect_err("a client naming itself after the deployment is phishing");
}

/// The redirect URIs are the document's or there are none: absent, empty, and fragment-carrying
/// lists are refused, because they are what `oauth-as` exact-matches the request against.
#[test]
fn a_document_without_usable_redirect_uris_is_refused() {
    let mut doc = document();
    doc.as_object_mut().expect("object").remove("redirect_uris");
    materialized(&doc).expect_err("no redirect_uris means nowhere a code may be sent");

    let mut doc = document();
    doc["redirect_uris"] = serde_json::json!([]);
    materialized(&doc).expect_err("an empty redirect_uris list is the same absence");

    let mut doc = document();
    doc["redirect_uris"] = serde_json::json!(["http://127.0.0.1:9999/cb#frag"]);
    materialized(&doc).expect_err("RFC 6749 §3.1.2: a redirection endpoint carries no fragment");
}

/// A redirect URI with a `\` or a userinfo names two hosts — the one a `/`-splitting reader shows on
/// the consent screen and the one the browser sends the code to — so the document is refused. RED on
/// the check that refused only a fragment and whitespace. A `@` in the path is not a userinfo.
#[test]
fn a_redirect_uri_with_a_backslash_or_a_userinfo_is_refused() {
    for uri in [
        "https://evil.example\\@trusted.example/cb",
        "https://trusted.example@evil.example/cb",
        "https://u:p@trusted.example/cb",
    ] {
        let mut doc = document();
        doc["redirect_uris"] = serde_json::json!([uri]);
        materialized(&doc).expect_err(uri);
    }
    let mut doc = document();
    doc["redirect_uris"] = serde_json::json!(["http://127.0.0.1:9999/cb/@me"]);
    materialized(&doc).expect("a `@` in the path is not a userinfo");
}

/// What is a metadata-document `client_id` at all: HTTPS, parseable, fragment-free. Everything
/// else stays an ordinary opaque identifier and never reaches the fetch.
#[test]
fn only_a_fragment_free_https_url_names_a_document() {
    assert!(is_cimd_client_id(URL));
    assert!(!is_cimd_client_id("flow-test-client"), "an opaque id");
    assert!(
        !is_cimd_client_id("http://client.example/oauth-client"),
        "plaintext cannot bind a document to its owner"
    );
    assert!(!is_cimd_client_id("https://client.example/doc#frag"));
    assert!(!is_cimd_client_id("https://"), "no host");
}

/// A fetch stub that records whether it was consulted at all.
struct Recording {
    called: AtomicBool,
    answer: Result<Vec<u8>, String>,
}

impl Recording {
    fn refusing() -> Arc<Self> {
        Arc::new(Self {
            called: AtomicBool::new(false),
            answer: Err("refused".to_string()),
        })
    }
}

impl CimdFetch for Recording {
    fn fetch<'a>(
        &'a self,
        _url: &'a str,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<Vec<u8>, String>> + Send + 'a>>
    {
        self.called.store(true, Ordering::SeqCst);
        let answer = self.answer.clone();
        Box::pin(async move { answer })
    }
}

/// THE PRECEDENCE AND THE GATE, at the store seam: a STORED client is answered without any fetch
/// (whatever its id looks like), an opaque unknown id is `None` without any fetch, and a failed
/// fetch is `None` — the same answer an unknown client gets, never an error an attacker can mint.
#[tokio::test]
async fn the_store_wins_and_every_cimd_failure_reads_as_an_unknown_client() {
    let fetch = Recording::refusing();
    let handle: Arc<Recording> = Arc::clone(&fetch);
    let store = CimdStore::new(MemoryStorage::new(), ceiling(), handle, Vec::new());

    // An opaque id misses without consulting the fetch.
    let missed = store
        .get_client(&ClientId::new("flow-test-client"))
        .await
        .expect("a miss is not an error");
    assert!(missed.is_none());
    assert!(
        !fetch.called.load(Ordering::SeqCst),
        "an opaque id is not a document URL and must never reach the fetch"
    );

    // A stored client whose id IS a URL is answered from the store, not fetched: what the
    // operator or the registration endpoint wrote cannot be overridden by what a URL serves.
    let stored = materialized(&document()).expect("valid");
    store.put_client(stored).await.expect("put");
    let found = store
        .get_client(&ClientId::new(URL))
        .await
        .expect("a hit is not an error")
        .expect("the stored client is found");
    assert_eq!(found.client_id.as_str(), URL);
    assert!(
        !fetch.called.load(Ordering::SeqCst),
        "a stored client answers without a fetch"
    );

    // A URL-shaped id that is NOT stored consults the fetch, and a refused fetch is an unknown
    // client — `Ok(None)`, indistinguishable from any other unknown id.
    let unknown = store
        .get_client(&ClientId::new("https://elsewhere.example/client"))
        .await
        .expect("a refused fetch is not a storage error");
    assert!(unknown.is_none());
    assert!(fetch.called.load(Ordering::SeqCst));
}

// ═════════════════════════════════════════════════════════════════════════════════════════════
// THE PRODUCTION FETCH ITSELF: one GET over the document need on the root Connector. The guard is
// the connector's (`busbar-core-connector/src/guard.rs`, proven there); what is proven HERE is the
// wiring that puts every fetch in front of it — the need it declares (outbound, `https`, the
// `open-web` class, no configured target), the URL it opens verbatim, and that this crate decides
// no destination itself: a refusal comes from the table or not at all. The table below is a
// recording stand-in for the connector, so no socket is opened.
// ═════════════════════════════════════════════════════════════════════════════════════════════

use std::sync::Mutex;
use std::task::{Context, Poll};

use busbar_contract::abi::host::conn::connector::{DIRECTION_OUTBOUND, EGRESS_OPEN_WEB};
use busbar_contract::abi::mechanism::rendering::ReadNeed;
use busbar_contract::conn::{
    ConnError, ConnId, Conns, DeclaredConns, InstanceId, NeedId, OpenDesc, Piece, PieceKind,
    PollConns, Ticket,
};
use busbar_contract::ids::StreamId;
use busbar_contract::transport::ConnFacts;

const OWNER: InstanceId = InstanceId(0);

/// What one exchange answers: the open's verdict, then the pieces, in order.
struct Script {
    open: Result<(), ConnError>,
    pieces: Vec<(PieceKind, Option<u32>, Vec<u8>)>,
}

/// One need the fetch declared: owner, need, spec, configured target.
type Declared = (InstanceId, NeedId, ReadNeed, Option<String>);

/// One open the fetch made: owner, need, target, method, head target.
type Opened = (InstanceId, NeedId, String, Vec<u8>, Vec<u8>);

/// A connection table that records what the fetch asked of it and answers from a [`Script`].
#[derive(Default)]
struct Recorder {
    script: Mutex<Option<Script>>,
    declared: Mutex<Vec<Declared>>,
    opened: Mutex<Vec<Opened>>,
    closed: Mutex<Vec<ConnId>>,
    refuse_declare: bool,
}

impl Recorder {
    fn answering(
        open: Result<(), ConnError>,
        pieces: Vec<(PieceKind, Option<u32>, Vec<u8>)>,
    ) -> Arc<Self> {
        Arc::new(Self {
            script: Mutex::new(Some(Script { open, pieces })),
            ..Self::default()
        })
    }

    fn ok(status: u32, body: &[u8]) -> Arc<Self> {
        Self::answering(
            Ok(()),
            vec![
                (
                    PieceKind::Fields,
                    Some(status),
                    b"content-type: application/json\r\n".to_vec(),
                ),
                (PieceKind::Body, None, body.to_vec()),
                (PieceKind::Completion, None, Vec::new()),
            ],
        )
    }
}

impl Conns for Recorder {
    fn open(
        &self,
        caller: InstanceId,
        need: NeedId,
        desc: &OpenDesc<'_>,
    ) -> Result<ConnId, ConnError> {
        self.opened.lock().unwrap().push((
            caller,
            need,
            desc.target.to_string(),
            desc.method.to_vec(),
            desc.head_target.to_vec(),
        ));
        let script = self.script.lock().unwrap();
        script
            .as_ref()
            .map_or(Err(ConnError::Refused), |s| s.open)
            .map(|()| ConnId(7))
    }
    fn write(
        &self,
        _: InstanceId,
        _: ConnId,
        _: &[u8],
        _: bool,
        _: bool,
    ) -> Result<usize, ConnError> {
        Err(ConnError::Closed)
    }
    fn read(&self, _: InstanceId, _: ConnId, _: Ticket, _: &mut [u8]) -> Result<Piece, ConnError> {
        Err(ConnError::Closed)
    }
    fn wait(&self, _: InstanceId, _: &[ConnId], _: Ticket) -> Result<usize, ConnError> {
        Err(ConnError::Closed)
    }
    fn facts(&self, _: InstanceId, _: ConnId) -> Result<ConnFacts, ConnError> {
        Err(ConnError::Closed)
    }
    fn close(&self, _: InstanceId, conn: ConnId) -> Result<(), ConnError> {
        self.closed.lock().unwrap().push(conn);
        Ok(())
    }
}

impl DeclaredConns for Recorder {
    fn declare(
        &self,
        owner: InstanceId,
        need: NeedId,
        spec: &ReadNeed,
        target: Option<&str>,
        _: Option<&str>,
    ) -> Result<(), ConnError> {
        self.declared
            .lock()
            .unwrap()
            .push((owner, need, spec.clone(), target.map(str::to_string)));
        if self.refuse_declare {
            Err(ConnError::Refused)
        } else {
            Ok(())
        }
    }
    fn declared(&self, owner: InstanceId, need: NeedId) -> Option<Result<(), ConnError>> {
        let declared = self.declared.lock().unwrap();
        declared
            .iter()
            .any(|(o, n, _, _)| *o == owner && *n == need)
            .then_some(if self.refuse_declare {
                Err(ConnError::Refused)
            } else {
                Ok(())
            })
    }
    fn serves_scheme(&self, _: &str) -> bool {
        true
    }
}

impl PollConns for Recorder {
    fn poll_read(
        &self,
        _: InstanceId,
        _: ConnId,
        _: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<Result<Piece, ConnError>> {
        let mut script = self.script.lock().unwrap();
        let Some(script) = script.as_mut() else {
            return Poll::Ready(Err(ConnError::Closed));
        };
        if script.pieces.is_empty() {
            return Poll::Ready(Err(ConnError::Closed));
        }
        let (kind, status_code, bytes) = script.pieces.remove(0);
        buf[..bytes.len()].copy_from_slice(&bytes);
        Poll::Ready(Ok(Piece {
            kind,
            stream: StreamId(0),
            len: bytes.len(),
            end: true,
            status: None,
            status_code,
            status_namespace: None,
            retry_after_secs: None,
            reason: None,
        }))
    }
}

thread_local! {
    /// The table the next `fetch_over` hands the fetch: `ConnectorFetch` reads its table through
    /// a plain `fn`, as production's `Connections::table` is one.
    static TABLE: std::cell::RefCell<Option<Arc<Recorder>>> = const { std::cell::RefCell::new(None) };
}

fn current_table() -> Option<crate::Table> {
    TABLE.with(|t| {
        t.borrow().as_ref().map(|r| crate::Table {
            owner: OWNER,
            declared: Arc::clone(r) as Arc<dyn DeclaredConns>,
            conns: Arc::clone(r) as Arc<dyn PollConns>,
        })
    })
}

/// Fetch `url` over `table` through the PRODUCTION fetch.
async fn fetch_over(table: &Arc<Recorder>, url: &str) -> Result<Vec<u8>, String> {
    TABLE.with(|t| *t.borrow_mut() = Some(Arc::clone(table)));
    let got = ConnectorFetch {
        table: current_table,
    }
    .fetch(url)
    .await;
    TABLE.with(|t| *t.borrow_mut() = None);
    got
}

/// THE NEED THE FETCH DECLARES, asserted rather than assumed: outbound, over `https`, in the
/// `open-web` class (public HTTPS only, private and metadata refused by the connector's guard),
/// with no configured target (a configured target would lift the dial into operator
/// infrastructure, where private addresses are allowed) and no auth.
#[test]
fn the_document_need_is_outbound_https_in_the_open_web_class() {
    let need = document_need();
    assert_eq!(need.direction, DIRECTION_OUTBOUND);
    assert_eq!(need.transport, "https");
    assert_eq!(
        need.egress_class, EGRESS_OPEN_WEB,
        "a CIMD `client_id` is a stranger's URL: its dial is judged as request data, public HTTPS \
         only"
    );
    assert!(
        need.target_from.is_empty(),
        "a configured target is judged as operator infrastructure, where private addresses pass"
    );
    assert!(need.auth.is_empty() && need.trust_from.is_empty());
    assert_eq!(MAX_DOCUMENT_BYTES, 5 * 1024);
    assert_eq!(FETCH_TIMEOUT, std::time::Duration::from_secs(10));
}

/// THE FETCH IS THE CONNECTOR'S: it declares the document need on the table under the table's
/// owner, opens the `client_id` URL VERBATIM as a GET for its path, reads the document, and closes
/// the connection.
#[tokio::test]
async fn the_fetch_declares_its_need_and_opens_the_client_id_on_the_table() {
    let table = Recorder::ok(200, br#"{"client_id":"x"}"#);
    let body = fetch_over(&table, URL)
        .await
        .expect("a 200 document is fetched");
    assert_eq!(body, br#"{"client_id":"x"}"#);

    let declared = table.declared.lock().unwrap();
    assert_eq!(declared.len(), 1, "the need is declared once");
    assert_eq!(declared[0].0, OWNER);
    assert_eq!(declared[0].1, DOCUMENT_NEED);
    assert_eq!(declared[0].2, document_need());
    assert_eq!(declared[0].3, None, "no configured target");

    let opened = table.opened.lock().unwrap();
    assert_eq!(opened.len(), 1);
    assert_eq!(opened[0].0, OWNER);
    assert_eq!(opened[0].1, DOCUMENT_NEED);
    assert_eq!(
        opened[0].2, URL,
        "the URL is opened exactly as the request spelled it"
    );
    assert_eq!(opened[0].3, b"GET");
    assert_eq!(opened[0].4, b"/oauth-client");
    assert_eq!(
        *table.closed.lock().unwrap(),
        vec![ConnId(7)],
        "the connection is closed"
    );
}

/// NO DESTINATION IS JUDGED HERE. The addresses the old local guard refused reach the TABLE, whose
/// guard decides: the connector refusing the open is the refusal, and the client is unknown. A
/// local check put back in front of the table would leave these unopened, and this goes red.
#[tokio::test]
async fn every_destination_is_the_tables_to_refuse() {
    for client_id in [
        "https://localhost/oauth-client",
        "https://127.0.0.1/oauth-client",
        "https://[::1]/oauth-client",
        "https://169.254.169.254/latest/meta-data/iam/security-credentials/",
        "https://metadata.google.internal/computeMetadata/v1/",
        "https://100.64.1.1/oauth-client",
    ] {
        let table = Recorder::answering(Err(ConnError::Refused), Vec::new());
        let why = fetch_over(&table, client_id)
            .await
            .expect_err("the connector refused the open");
        assert!(
            why.contains(ConnError::Refused.text()),
            "{client_id}: {why}"
        );
        let opened = table.opened.lock().unwrap();
        assert_eq!(
            opened.iter().map(|o| o.2.as_str()).collect::<Vec<_>>(),
            vec![client_id],
            "`{client_id}` must be put to the connector's guard, not judged here"
        );
    }
}

/// A table that will not carry the need (no transport serves `https`) refuses at declaration, and
/// nothing is opened; with no table at all, the fetch fails closed.
#[tokio::test]
async fn no_carried_need_and_no_table_both_fail_closed() {
    let table = Arc::new(Recorder {
        refuse_declare: true,
        ..Recorder::default()
    });
    fetch_over(&table, URL)
        .await
        .expect_err("the need was refused");
    assert!(table.opened.lock().unwrap().is_empty());

    let why = super::unconnected()
        .fetch(URL)
        .await
        .expect_err("no table, no fetch");
    assert!(why.contains("no connection table"), "{why}");
}

/// THE ANSWER'S BOUNDS: a redirect is refused (the document lives at its `client_id`), a non-2xx
/// is refused, and a body past the document ceiling is refused while it arrives. Each one still
/// closes the connection.
#[tokio::test]
async fn redirects_failures_and_oversized_documents_are_refused() {
    let big = vec![b'x'; MAX_DOCUMENT_BYTES + 1];
    for (table, expected) in [
        (Recorder::ok(302, b""), "a redirect"),
        (Recorder::ok(404, b""), "HTTP 404"),
        (Recorder::ok(200, &big), "document ceiling"),
    ] {
        let why = fetch_over(&table, URL).await.expect_err("refused");
        assert!(why.contains(expected), "expected `{expected}`: {why}");
        assert_eq!(*table.closed.lock().unwrap(), vec![ConnId(7)]);
    }
    // At the ceiling exactly, the document is kept.
    let at = vec![b'x'; MAX_DOCUMENT_BYTES];
    assert_eq!(
        fetch_over(&Recorder::ok(200, &at), URL)
            .await
            .unwrap()
            .len(),
        MAX_DOCUMENT_BYTES
    );
}
