// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! **THE MINT THROUGH THE PLUGIN'S OWN NEED, OVER THE ONE LOADER** (THE DESIGN §5, §6.5, §11; TODO
//! row 22): the linked door is bound through the loader's one load on a connection table, its
//! instance opened over a binding's settings (so its `open-web` need is declared pinned to that
//! binding's `token_url`), its tick schedule run on its driver ticket. The binding presents NOTHING
//! until the first mint lands (PENDING, never an empty answer), the minted bearer once it has, and
//! the refreshed bearer once the short-lived first token is re-minted ahead of its expiry: the
//! oracle cell `egress.auth|oauth-cc|mint-refresh`'s shape (first token `expires_in: 2`, so the
//! refresh lands after one second, and the second upstream request carries it).
//!
//! The connection table is a scripted double (the request each open carried, a token endpoint's
//! reply per open): the token request is asserted as 1.5.5 POSTed it — the endpoint, `POST`, its
//! path, the form's content type and the form body, field order and encoding included.

use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use busbar_contract::abi::host::conn::connector::{DIRECTION_OUTBOUND, EGRESS_OPEN_WEB};
use busbar_contract::abi::mechanism::rendering::ReadNeed;
use busbar_contract::auth_calls::{Fields, FieldsRequest, OutboundAuth};
use busbar_contract::conn::{
    ConnError, ConnId, ConnSlab, Conns, DeclaredConns, InstanceId, NeedId, OpenDesc, Piece,
    PieceKind,
};
use busbar_contract::ids::StreamId;
use busbar_contract::transport::ConnFacts;
use busbar_plugin_loader::dispatch::auth_outbound::OutboundInstance;
use busbar_plugin_loader::dispatch::kinds::auth::Auth;
use busbar_plugin_loader::dispatch::{
    load_linked, Bind, DispatchConfig, Dispatcher, LinkedRow, NoSink,
};

const TOKEN_URL: &str = "https://login.example.com/tenant/oauth2/v2.0/token";
const SCOPE: &str = "https://cognitiveservices.azure.com/.default";
const CREDENTIAL: &str = "oracle-client-0001:oracle:secret:with:colons";

/// What one open carried: the need, the target, the method, the head target, the fields, the body.
type Opened = (u32, String, String, String, Vec<(String, String)>, String);

/// Each open's reply, piece by piece, with its bytes.
type Replies = HashMap<ConnId, VecDeque<(Piece, Vec<u8>)>>;

/// A connection table whose needs are framed: each open is recorded and answered by the token
/// endpoint's next reply (`expires_in` 2, then 3600), one piece per read.
#[derive(Default)]
struct TokenEndpoint {
    slab: ConnSlab<()>,
    declared: Mutex<Vec<(u32, ReadNeed, Option<String>)>>,
    opened: Mutex<Vec<Opened>>,
    replies: Mutex<Replies>,
}

fn piece(kind: PieceKind, len: usize, status: Option<u32>) -> Piece {
    Piece {
        kind,
        stream: StreamId(0),
        len,
        end: kind != PieceKind::Fields,
        status: None,
        status_code: status,
        status_namespace: None,
        retry_after_secs: None,
        reason: None,
    }
}

impl DeclaredConns for TokenEndpoint {
    fn declare(
        &self,
        owner: InstanceId,
        need: NeedId,
        spec: &ReadNeed,
        target: Option<&str>,
    ) -> Result<(), ConnError> {
        self.declared
            .lock()
            .unwrap()
            .push((need.0, spec.clone(), target.map(str::to_owned)));
        // A `target_from` that resolved to nothing is refused, as the connector refuses it.
        if !spec.target_from.is_empty() && target.is_none() {
            return Err(ConnError::Refused);
        }
        self.slab.declare(owner, need);
        Ok(())
    }
    fn declared(&self, owner: InstanceId, need: NeedId) -> Option<Result<(), ConnError>> {
        self.slab.check_need(owner, need).ok().map(Ok)
    }
    fn framed(&self, _: InstanceId, _: NeedId) -> bool {
        true
    }
    fn serves_scheme(&self, scheme: &str) -> bool {
        scheme == "http"
    }
}

impl Conns for TokenEndpoint {
    fn open(
        &self,
        caller: InstanceId,
        need: NeedId,
        desc: &OpenDesc<'_>,
    ) -> Result<ConnId, ConnError> {
        self.slab.check_need(caller, need)?;
        let mut opened = self.opened.lock().unwrap();
        opened.push((
            need.0,
            desc.target.to_owned(),
            String::from_utf8_lossy(desc.method).into_owned(),
            String::from_utf8_lossy(desc.head_target).into_owned(),
            desc.fields
                .iter()
                .map(|(n, v)| ((*n).to_owned(), String::from_utf8_lossy(v).into_owned()))
                .collect(),
            String::from_utf8_lossy(desc.body).into_owned(),
        ));
        let n = opened.len();
        let body = format!(
            r#"{{"access_token":"oracle-minted-{n}","expires_in":{},"token_type":"Bearer"}}"#,
            if n == 1 { 2 } else { 3600 }
        );
        let id = self.slab.insert(caller, need, ())?;
        self.replies.lock().unwrap().insert(
            id,
            VecDeque::from([
                (piece(PieceKind::Fields, 0, Some(200)), Vec::new()),
                (piece(PieceKind::Body, body.len(), None), body.into_bytes()),
                (piece(PieceKind::Completion, 0, None), Vec::new()),
            ]),
        );
        Ok(id)
    }
    fn write(&self, _: InstanceId, _: ConnId, b: &[u8], _: bool) -> Result<usize, ConnError> {
        Ok(b.len())
    }
    fn read(&self, c: InstanceId, id: ConnId, _: u64, buf: &mut [u8]) -> Result<Piece, ConnError> {
        self.slab.get(c, id)?;
        let (p, bytes) = self
            .replies
            .lock()
            .unwrap()
            .get_mut(&id)
            .and_then(VecDeque::pop_front)
            .ok_or(ConnError::Closed)?;
        buf[..bytes.len()].copy_from_slice(&bytes);
        Ok(p)
    }
    fn wait(&self, _: InstanceId, _: &[ConnId], _: u64) -> Result<usize, ConnError> {
        Err(ConnError::Pending)
    }
    fn facts(&self, _: InstanceId, _: ConnId) -> Result<ConnFacts, ConnError> {
        Err(ConnError::Closed)
    }
    fn close(&self, c: InstanceId, id: ConnId) -> Result<(), ConnError> {
        self.replies.lock().unwrap().remove(&id);
        self.slab.remove(c, id).map(|_| ())
    }
}

/// The authorization one `fields` answer presents, if any.
fn presented(answer: &Fields) -> Option<String> {
    match answer {
        Fields::Ready(fields) => fields.iter().find_map(|f| {
            (f.name == b"authorization")
                .then(|| String::from_utf8_lossy(f.value.expose_secret()).into_owned())
        }),
        _ => None,
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_binding_presents_its_minted_bearer_then_the_refreshed_one() {
    let table = Arc::new(TokenEndpoint::default());
    let dispatcher = Arc::new(Dispatcher::new(DispatchConfig::default()));
    let row = LinkedRow::of(busbar_auth_oauth::door).expect("the door states its Statement");
    let plugin = load_linked::<Auth>(
        &row,
        Bind {
            instance: Arc::from("busbar-auth-oauth"),
            max_inflight_cap: 64,
            sink: Arc::new(NoSink),
            dispatcher: dispatcher.adopter(),
            conns: Some(Arc::clone(&table) as Arc<dyn DeclaredConns>),
        },
    )
    .expect("the linked door binds on the connection table");
    assert!(
        plugin.targets_from_settings(),
        "its needs take their target from the binding's settings"
    );

    // THE INSTANCE, OPENED OVER THE BINDING'S SETTINGS: its token_url need is declared pinned to
    // the binding's endpoint, `open-web`, over the http transport.
    let settings = serde_json::json!({ "token_url": TOKEN_URL, "scope": SCOPE });
    let instance = Arc::new(
        OutboundInstance::open_with(
            plugin,
            Arc::clone(&dispatcher),
            0,
            &serde_json::to_vec(&settings).expect("json"),
        )
        .expect("the instance opens"),
    );
    {
        let declared = table.declared.lock().unwrap();
        let token_url = declared
            .iter()
            .find(|(need, _, _)| *need == 0)
            .expect("the token_url need is declared");
        assert_eq!(token_url.1.direction, DIRECTION_OUTBOUND);
        assert_eq!(token_url.1.egress_class, EGRESS_OPEN_WEB);
        assert_eq!(token_url.1.transport, "http");
        assert_eq!(token_url.1.target_from, "settings.token_url");
        assert_eq!(token_url.2.as_deref(), Some(TOKEN_URL), "pinned to it");
    }
    let handle = instance
        .open_outbound("oauth-client-credentials", CREDENTIAL.as_bytes(), &settings)
        .expect("the binding opens");

    // BEFORE THE FIRST MINT: not ready. On the spot the call is refused (the host submits it on a
    // ticket); nothing is presented empty.
    let request = FieldsRequest::default();
    assert!(
        instance.fields_now(handle, &request).is_none(),
        "nothing minted yet: no answer on the spot"
    );

    // THE TICK SCHEDULE: the first mint lands, and the waiting call presents it.
    tokio::spawn(Arc::clone(&instance).ticks());
    let first = tokio::time::timeout(
        Duration::from_secs(10),
        instance.fields(handle, FieldsRequest::default(), 0),
    )
    .await
    .expect("the first mint lands");
    assert_eq!(
        presented(&first).as_deref(),
        Some("Bearer oracle-minted-1"),
        "the first upstream request carries the first token: {first:?}"
    );
    assert_eq!(
        presented(
            &instance
                .fields_now(handle, &request)
                .expect("ready on the spot")
        )
        .as_deref(),
        Some("Bearer oracle-minted-1"),
        "the cached bearer answers in place, one call"
    );

    // THE REFRESH AHEAD OF EXPIRY: `expires_in: 2` re-mints after one second (1.5.5's
    // `next_refresh_secs`), and the next request carries the refreshed token.
    let refreshed = tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            if let Some(answer) = instance.fields_now(handle, &request) {
                if presented(&answer).as_deref() == Some("Bearer oracle-minted-2") {
                    return answer;
                }
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .expect("the refresh lands");
    assert_eq!(
        presented(&refreshed).as_deref(),
        Some("Bearer oracle-minted-2")
    );

    // THE TOKEN REQUESTS, as 1.5.5 POSTed them: the mint, then the refresh, byte for byte.
    let opened = table.opened.lock().unwrap();
    assert_eq!(opened.len(), 2, "the mint and the refresh: {opened:?}");
    let form = "grant_type=client_credentials&client_id=oracle-client-0001&client_secret=\
                oracle%3Asecret%3Awith%3Acolons&scope=https%3A%2F%2Fcognitiveservices.azure.com\
                %2F.default";
    for sent in opened.iter() {
        assert_eq!(
            sent,
            &(
                0,
                TOKEN_URL.to_string(),
                "POST".to_string(),
                "/tenant/oauth2/v2.0/token".to_string(),
                vec![(
                    "content-type".to_string(),
                    "application/x-www-form-urlencoded".to_string()
                )],
                form.to_string(),
            )
        );
    }
}
