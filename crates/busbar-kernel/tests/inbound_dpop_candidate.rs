// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE DPoP-PROVEN CANDIDATE, held to the old path (`BUSBAR-1.6.0.md` THE DESIGN §6, "Auth points
//! and guest lists", step 4, l.962; RFC 9449), in a binary of its own: the cell stands in the
//! authorization server's seam (`oauth_as::seam`), which is once per process, and the kernel's own
//! test binary never registers one (`oauth_as/seam.rs`). Every item it reaches is the kernel's
//! public surface under `test-support`.

use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::sync::Mutex;

use busbar_contract::abi::auth::{AuthPoints, POINT_HEAD, POINT_HEAD_BODY, POINT_PEER};
use busbar_contract::abi::host::service::{UnitRef, FLOW_CONTINUE, FLOW_STOP, REFUSE_STOPPED};
use busbar_contract::abi::transport::route::{METHOD_POST, PATH_EXACT};
use busbar_contract::auth_calls::{
    AuthCalls, Verified, VerifiedIdentity, VerifyAnswer, VerifyRequest, Verifying,
};
use busbar_kernel::config::{RoleBindingCfg, RoleBindings};
use busbar_kernel::guest::{Claimant, GuestList, Line, LineAuth, Route};
use busbar_kernel::inbound::{self as kin, Inbound};
use busbar_kernel::oauth_as::seam::{install_as_plane_seam, AsPlaneSeam};
use busbar_kernel::state::App;

const OWNER: u64 = 7;
const GEN: u64 = 3;
const MESSAGES: &str = "/v1/messages";
/// The role the scripted identity carries, bound under the auth's name.
const ROLE: &str = "member";
/// The line's handle id, from the line half of the ref-id space.
const LINE_ID: u64 = 7_000;

/// The proof the test authorization server's DPoP verification accepts; any other is refused.
const GOOD_PROOF: &str = "proof.that.verifies";

/// The authorization server's seam, as this test binary stands it in: only its DPoP verification
/// answers (a presentation whose proof is [`GOOD_PROOF`]); it mounts nothing and builds and
/// accepts no `oauth_as:` block, as an unregistered seam does.
fn stand_in_as_seam() {
    static ONCE: std::sync::Once = std::sync::Once::new();
    ONCE.call_once(|| {
        install_as_plane_seam(AsPlaneSeam {
            check: |_| Err("no oauth_as: block in this test binary".to_string()),
            build: |_, _, _, _, _| Err("no oauth_as: block in this test binary".to_string()),
            mount: |router, _| router,
            verify_dpop: |_, presented| Box::pin(async move { presented.proof == GOOD_PROOF }),
        });
    });
}

/// A `verify` answered before anything crossed.
struct Answered(Option<VerifyAnswer>);

impl Future for Answered {
    type Output = VerifyAnswer;
    fn poll(
        mut self: Pin<&mut Self>,
        _: &mut std::task::Context<'_>,
    ) -> std::task::Poll<VerifyAnswer> {
        std::task::Poll::Ready(self.0.take().expect("polled once"))
    }
}

impl Verifying for Answered {
    fn settled(&mut self) -> Option<VerifyAnswer> {
        self.0.take()
    }
}

/// An identity carrying [`ROLE`], which the app binds: it earns a governance key.
fn identity(subject: &str, credential: &str) -> Verified {
    Verified::Identity(VerifiedIdentity {
        subject: subject.to_string(),
        credential: Some(busbar_contract::redacted::Secret::new(
            credential.to_string(),
        )),
        groups: vec![ROLE.to_string()],
        ..VerifiedIdentity::default()
    })
}

/// A plugin auth that identifies exactly the candidate credential it expects, rejects any other
/// (none included), and keeps every candidate it was lent.
struct Holder {
    expected: Vec<u8>,
    lent: Mutex<Vec<Option<Vec<u8>>>>,
}

impl AuthCalls for Holder {
    fn name(&self) -> &str {
        "holder"
    }
    fn facts(&self) -> u32 {
        0
    }
    fn inbound_points(&self) -> AuthPoints {
        AuthPoints::HEAD
    }
    fn verify_now(&self, _: &VerifyRequest) -> Option<VerifyAnswer> {
        None
    }
    fn verify(&self, request: VerifyRequest) -> Box<dyn Verifying> {
        let lent = request
            .credential
            .as_ref()
            .map(|c| c.expose(&busbar_kernel::seal::lend()).clone());
        let verified = if lent.as_deref() == Some(self.expected.as_slice()) {
            identity("holder", "k")
        } else {
            Verified::Reject
        };
        self.lent.lock().unwrap().push(lent);
        Box::new(Answered(Some(VerifyAnswer::from(verified))))
    }
    fn refresh(&self) -> Result<u64, String> {
        Ok(0)
    }
}

/// A JWS-shaped token over `claims`, never signature-checked by what reads it here.
fn jwt(claims: &serde_json::Value) -> String {
    use base64::Engine as _;
    let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD;
    format!(
        "{}.{}.c2ln",
        b64.encode(r#"{"alg":"ES256","typ":"at+jwt"}"#),
        b64.encode(claims.to_string())
    )
}

/// A refusal's bytes as a client reads them off the old path: the status, the fields a refusal's
/// meaning rides on, the body.
type Read = (u16, Option<Vec<u8>>, Option<Vec<u8>>, Vec<u8>);

fn read_refusal(r: &kin::Refusal) -> Read {
    let field = |n: &str| {
        r.fields
            .iter()
            .find(|(f, _)| f.eq_ignore_ascii_case(n))
            .map(|(_, v)| v.clone())
    };
    (
        r.status,
        field("www-authenticate"),
        field("content-type"),
        r.body.clone(),
    )
}

/// The OLD PATH's answer (the router, its auth middleware around it) to a POST on `path` carrying
/// `headers`, over `app`.
async fn old_path(app: Arc<App>, path: &str, headers: &[(&str, String)]) -> Read {
    busbar_kernel::snapshot::init();
    let router = busbar_kernel::build_router(app);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let serving = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    let mut req = reqwest::Client::new()
        .post(format!("http://{addr}{path}"))
        .body("{}");
    for (n, v) in headers {
        req = req.header(*n, v);
    }
    let resp = req.send().await.unwrap();
    let field = |n: &str| resp.headers().get(n).map(|v| v.as_bytes().to_vec());
    let (status, challenge, content_type) = (
        resp.status().as_u16(),
        field("www-authenticate"),
        field("content-type"),
    );
    let body = resp.bytes().await.unwrap().to_vec();
    serving.abort();
    (status, challenge, content_type, body)
}

/// The kernel side holding the data listener's one line at `MESSAGES` (POST, the chain `a`, the
/// head point), `a` opened as `holder`, for `OWNER` at `GEN` over `app`.
fn side(app: Arc<App>, holder: &Arc<Holder>) -> Arc<Inbound> {
    let next = Arc::new(AtomicU64::new(100));
    let inbound = Inbound::new(
        kin::Seals {
            mint: Arc::new(move || next.fetch_add(1, Ordering::SeqCst)),
            mac: Arc::new(|t: &kin::UnitTag| Some(t.unit ^ t.secret[0])),
        },
        Arc::new(|f: Pin<Box<dyn Future<Output = ()> + Send>>| {
            std::thread::spawn(move || futures::executor::block_on(f));
        }),
        Arc::new(|_: &kin::RefusedUnit| {}),
    );
    let mut auths = std::collections::HashMap::new();
    let calls = Arc::clone(holder) as Arc<dyn AuthCalls>;
    auths.insert("a".to_string(), calls);
    let line = Line {
        route: Route {
            methods: METHOD_POST,
            path_form: PATH_EXACT,
            path: MESSAGES.to_string(),
            fields: Vec::new(),
            rung: 0,
        },
        claimant: Claimant::Plane("plane".to_string()),
        dialect: 0,
        auth: LineAuth::Chain(vec!["a".to_string()], AuthPoints::HEAD),
        upgrade: None,
        offered: AuthPoints(POINT_PEER | POINT_HEAD | POINT_HEAD_BODY),
    };
    inbound
        .install(
            OWNER,
            GEN,
            kin::Listener {
                guests: GuestList::seal(vec![line]).expect("the list seals"),
                auths,
                body_limit: 16,
                app,
                door_refusals: Vec::new(),
                ids: vec![LINE_ID],
                signed_ingress: Arc::new(|_: &App, _: &str| false),
                admission: None,
                door_refuser: None,
            },
        )
        .expect("installed");
    inbound
}

/// RED (/status row 192 C; RFC 9449, the old chain's candidate): once a DPoP-bound token's proof
/// verified, the plugin auth positions are lent THAT token as the candidate credential, as the old
/// chain lent it: the auth sees the same candidate on both paths and the request gets the same
/// verdict; a proof that does not verify is refused with the same bytes on both.
#[tokio::test]
async fn red_a_dpop_proven_token_is_the_candidate_a_plugin_auth_is_lent() {
    stand_in_as_seam();
    let token = jwt(&serde_json::json!({ "sub": "a", "cnf": { "jkt": "abc" } }));
    let authorization = format!("DPoP {token}");
    for (proof, admitted) in [(GOOD_PROOF, true), ("proof.that.fails", false)] {
        let holder = Arc::new(Holder {
            expected: token.as_bytes().to_vec(),
            lent: Mutex::default(),
        });
        let mut roles = std::collections::BTreeMap::new();
        roles.insert(ROLE.to_string(), RoleBindingCfg::default());
        let mut bound = RoleBindings::new();
        bound.insert("a".to_string(), roles);
        let calls = Arc::clone(&holder) as Arc<dyn AuthCalls>;
        let chain = vec![("a".to_string(), calls)];
        let auth = busbar_kernel::auth::AuthMiddleware::from_doors_for_test(chain);
        let app = busbar_kernel::test_support::TestApp::new()
            .auth(Arc::new(auth))
            .role_bindings(bound)
            .oauth_as_plane(Arc::new(()))
            .build();
        let want = old_path(
            Arc::clone(&app),
            MESSAGES,
            &[
                ("authorization", authorization.clone()),
                ("dpop", proof.to_string()),
            ],
        )
        .await;
        let old_lent = std::mem::take(&mut *holder.lent.lock().unwrap());
        let inbound = side(app, &holder);
        let head = kin::Head {
            method: "POST".to_string(),
            target: MESSAGES.to_string(),
            authority: "a.example".to_string(),
            query: None,
            fields: vec![
                (
                    "authorization".to_string(),
                    authorization.as_bytes().to_vec(),
                ),
                ("dpop".to_string(), proof.as_bytes().to_vec()),
            ],
        };
        let ans = inbound
            .auth_call(
                kin::Call {
                    owner: OWNER,
                    generation: GEN,
                    auth: LINE_ID,
                    unit: UnitRef::NONE,
                    point: POINT_HEAD,
                    conn: 1,
                    framing: 1,
                    head,
                    body: None,
                    deadline: None,
                },
                Box::new(|_: Result<kin::Answer, &'static str>| {
                    panic!("every scripted verify answers at once")
                }),
            )
            .expect("answered at once")
            .unwrap();
        let new_lent = std::mem::take(&mut *holder.lent.lock().unwrap());
        assert_eq!(
            new_lent, old_lent,
            "the candidate the auth was lent (proof {proof})"
        );
        if admitted {
            assert_eq!(old_lent, vec![Some(token.as_bytes().to_vec())]);
            assert_ne!(want.0, 401, "the old path admitted it: {want:?}");
            assert_eq!(ans.flow, FLOW_CONTINUE, "the old path admitted it");
        } else {
            assert_eq!(ans.flow, FLOW_STOP);
            let got = inbound
                .refuse(kin::Refuse {
                    owner: OWNER,
                    generation: GEN,
                    unit: ans.unit,
                    cause: REFUSE_STOPPED,
                    line: 0,
                    request: None,
                })
                .expect("refused");
            assert_eq!(read_refusal(&got), want, "the same refusal");
        }
    }
}
