// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Exercise the actual inbound host's two-point dispatch, not its decision helpers.
use super::*;
use crate::guest::{Claimant, Route};
use busbar_contract::abi::auth::{AuthPoints, POINT_HEAD};
use busbar_contract::abi::transport::route::{METHOD_POST, PATH_EXACT};
use busbar_contract::auth_calls::Verifying;
use std::sync::atomic::{AtomicU64, Ordering};

#[derive(Clone, Debug, PartialEq, Eq)]
struct Seen {
    name: &'static str,
    point: AuthPoint,
    unit: u64,
    body: Option<Vec<u8>>,
}

struct Probe {
    name: &'static str,
    points: AuthPoints,
    answer: Verified,
    faulted: bool,
    pending: bool,
    seen: Arc<Mutex<Vec<Seen>>>,
}

struct Reply {
    answer: Option<VerifyAnswer>,
    faulted: bool,
}
impl Future for Reply {
    type Output = VerifyAnswer;
    fn poll(
        mut self: Pin<&mut Self>,
        _: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Self::Output> {
        self.answer
            .take()
            .map_or(std::task::Poll::Pending, std::task::Poll::Ready)
    }
}
impl Verifying for Reply {
    fn settled(&mut self) -> Option<VerifyAnswer> {
        self.answer.take()
    }
    fn faulted(&self) -> bool {
        self.faulted
    }
}
impl AuthCalls for Probe {
    fn name(&self) -> &str {
        self.name
    }
    fn facts(&self) -> u32 {
        0
    }
    fn inbound_points(&self) -> AuthPoints {
        self.points
    }
    fn verify_now(&self, _: &VerifyRequest) -> Option<VerifyAnswer> {
        None
    }
    fn verify(&self, request: VerifyRequest) -> Box<dyn Verifying> {
        self.seen.lock().unwrap().push(Seen {
            name: self.name,
            point: request.point,
            unit: request.unit,
            body: request.body.clone(),
        });
        Box::new(Reply {
            answer: (!self.pending).then(|| VerifyAnswer::from(self.answer.clone())),
            faulted: self.faulted,
        })
    }
    fn refresh(&self) -> Result<u64, String> {
        Ok(0)
    }
}

fn probe(
    name: &'static str,
    points: AuthPoints,
    answer: Verified,
    seen: &Arc<Mutex<Vec<Seen>>>,
) -> Arc<Probe> {
    Arc::new(Probe {
        name,
        points,
        answer,
        faulted: false,
        pending: false,
        seen: seen.clone(),
    })
}

const OWNER: u64 = 7;
const GEN: u64 = 3;
const MESSAGES: &str = "/v1/messages";
const SIGNED_LINE: &str = "x-signed-credential";
struct Kit {
    inbound: Arc<Inbound>,
}
fn test_mac(t: &UnitTag) -> Option<u64> {
    let mut h: u64 = 0x9e37_79b9_7f4a_7c15;
    for v in [
        t.secret[0],
        t.secret[1],
        t.generation,
        t.owner,
        u64::from(t.line),
        t.unit,
    ] {
        h = (h ^ v).wrapping_mul(0x0100_0000_01b3).rotate_left(29);
    }
    Some(h)
}

fn identity(subject: &str, credential: &str) -> Verified {
    Verified::Identity(VerifiedIdentity {
        subject: subject.to_string(),
        credential: Some(Secret::new(credential.to_string())),
        ..VerifiedIdentity::default()
    })
}

fn signed_head() -> Head {
    Head {
        method: "POST".into(),
        target: MESSAGES.into(),
        authority: "a.example".into(),
        query: None,
        fields: vec![(SIGNED_LINE.into(), b"signature".to_vec())],
    }
}
impl Kit {
    fn id(&self, path: &str) -> u64 {
        assert_eq!(path, MESSAGES);
        self.inbound.specs_at(OWNER, 71, GEN).unwrap()[0].auth
    }
    fn hand_in(&self, path: &str, line_path: &str, unit: UnitRef, head: Head) -> (u32, UnitRef) {
        assert_eq!(line_path, MESSAGES);
        self.inbound
            .hand_in(HandIn {
                owner: OWNER,
                generation: GEN,
                auth: self.id(path),
                unit,
                line: 0,
                conn: 1,
                stream: 1,
                framing: Some(1),
                head,
            })
            .unwrap()
    }
    async fn call_async(
        &self,
        path: &str,
        unit: UnitRef,
        point: u32,
        head: Head,
    ) -> Result<Answer, &'static str> {
        let (sent, received) = tokio::sync::oneshot::channel();
        let answer = self.inbound.auth_call(
            Call {
                owner: OWNER,
                generation: GEN,
                auth: self.id(path),
                unit,
                point,
                conn: 1,
                stream: 1,
                framing: 1,
                head,
                body: (point == POINT_HEAD_BODY).then(|| b"{}".to_vec()),
                deadline: None,
            },
            Box::new(move |answer| {
                let _ = sent.send(answer);
            }),
        );
        match answer {
            Some(answer) => answer,
            None => received.await.expect("the asynchronous auth call answers"),
        }
    }
}
fn mixed(reader: Arc<Probe>, providers: &[Arc<Probe>]) -> Kit {
    let registry: Arc<dyn busbar_contract::plugin_rows::PluginRows> =
        Arc::new(busbar_plugin_loader::registry::PluginRegistry::empty());
    let secret_resolver = Arc::new(crate::config::secret::SecretResolver::builtins_only());
    let admin_modules = Arc::new(
        crate::auth::AdminAuthChain::build(
            &crate::config::AuthCfg::default_none(),
            &registry,
            &secret_resolver,
        )
        .expect("the configured empty admin chain needs no provider"),
    );
    let app = Arc::new(crate::state::App::from_test_parts(crate::state::AppParts {
        fallback_runtime_key: "",
        serve_tables: Default::default(),
        root_rules: Arc::new(crate::appbuild::AcceptAll),
        config_projection: Default::default(),
        config_tables: Default::default(),
        store: Arc::new(crate::store::HealthState::new(Vec::new())),
        limits: Default::default(),
        session_store: Arc::new(crate::session::SessionStore::new(1024, None)),
        incremental_scan: Default::default(),
        plane_pools: Default::default(),
        auth: Arc::new(crate::auth::AuthMiddleware::inbound_reader_fixture(
            reader,
            SIGNED_LINE,
        )),
        rewrite_hooks: Default::default(),
        tap_hooks: Default::default(),
        tap_hooks_candidate: Default::default(),
        tap_hooks_routing: Default::default(),
        tap_hooks_response: Default::default(),
        global_gates: Default::default(),
        pool_orderings: Default::default(),
        pool_decision_gates: Default::default(),
        pool_rewrite_chains: Default::default(),
        plane_gates: Default::default(),
        plane_rewrites: Default::default(),
        hook_env: crate::hooks::HookEnv::new(registry, secret_resolver.clone()).unwrap(),
        hook_registry: Default::default(),
        requested_signals: Default::default(),
        any_content_hook: Default::default(),
        global_hooks: Default::default(),
        base_hook_names: Default::default(),
        groups_registry: Default::default(),
        base_group_names: Default::default(),
        identity_providers: Default::default(),
        export_defs: Default::default(),
        admin: Default::default(),
        admin_chain: Default::default(),
        admin_modules,
        public_url: Default::default(),
        oauth_as: Default::default(),
        demotion_record: Default::default(),
        amendments: Default::default(),
        planes: Default::default(),
        plane_slots: Default::default(),
        plane_sections: Default::default(),
        auth_scope_caps: Default::default(),
        role_bindings: Default::default(),
        config_path: Default::default(),
        providers_path: Default::default(),
        overlay_path: Default::default(),
        config_version: Default::default(),
        max_keys_per_principal: Default::default(),
        max_auto_provisioned_groups: Default::default(),
        governance: None,
        secret_resolver,
        cost: Arc::new(crate::cost::CostModel::flat(1)),
        plugins_dir: Default::default(),
        plugins_cfg: Default::default(),
        plugin_admission: Default::default(),
        self_key_ttl_secs: crate::governance::mint_policy::DEFAULT_KEY_TTL_SECS,
        mint_policy: Default::default(),
        request_id_counter: Arc::new(std::sync::atomic::AtomicU64::new(1)),
        plugin_routes: Arc::new(crate::plugin_routes::PluginRouteTable::empty()),
        boot_route_paths: Default::default(),
        planes_awaiting_restart: Default::default(),
    }));

    let mut names: Vec<_> = providers.iter().map(|p| p.name.to_string()).collect();
    names.push(crate::config::KEYS_MODULE.into());
    let listener = Listener {
        guests: GuestList::seal(vec![Line {
            route: Route {
                methods: METHOD_POST,
                path_form: PATH_EXACT,
                path: MESSAGES.into(),
                fields: Vec::new(),
                rung: 0,
            },
            claimant: Claimant::Clean("reader-fallback-fixture".into()),
            dialect: 0,
            auth: LineAuth::Chain(names, AuthPoints(POINT_HEAD | POINT_HEAD_BODY)),
            upgrade: None,
            offered: AuthPoints(POINT_HEAD | POINT_HEAD_BODY),
        }])
        .unwrap(),
        auths: providers
            .iter()
            .map(|p| (p.name.to_string(), p.clone() as Arc<dyn AuthCalls>))
            .collect(),
        body_limit: 16,
        app,
        door_refusals: Vec::new(),
        ids: vec![7000],
        signed_ingress: Arc::new(|_, _| true),
        scope: None,
    };
    let next = Arc::new(AtomicU64::new(100));
    let inbound = Inbound::new(
        Seals {
            mint: Arc::new(move || next.fetch_add(1, Ordering::SeqCst)),
            mac: Arc::new(test_mac),
        },
        Arc::new(|work| {
            tokio::spawn(work);
        }),
        Arc::new(|_| {}),
    );
    inbound.install_at(OWNER, 71, GEN, listener).unwrap();
    inbound.framing_started(OWNER, 71, 1, GEN).unwrap();
    inbound.grant_stream(OWNER, 1, 1, GEN).unwrap();
    Kit { inbound }
}

async fn two_points(k: &Kit, seen: &Arc<Mutex<Vec<Seen>>>) -> Answer {
    let head = signed_head();
    let waiting = k
        .call_async(MESSAGES, UnitRef::NONE, POINT_HEAD, head.clone())
        .await
        .unwrap();
    assert_eq!(waiting.flow, FLOW_CONTINUE);
    assert!(
        seen.lock().unwrap().is_empty(),
        "HEAD cannot run ahead of the selected signed reader"
    );
    assert_eq!(
        k.hand_in(MESSAGES, MESSAGES, waiting.unit, head.clone()).0,
        FLOW_STOP
    );
    let answer = k
        .call_async(MESSAGES, waiting.unit, POINT_HEAD_BODY, head)
        .await
        .unwrap();
    assert_eq!(
        answer.unit, waiting.unit,
        "one unit spans both actual host crossings"
    );
    answer
}

fn expected(name: &'static str, point: AuthPoint, unit: u64) -> Seen {
    Seen {
        name,
        point,
        unit,
        body: (point == AuthPoint::HeadBody).then(|| b"{}".to_vec()),
    }
}

#[tokio::test]
async fn reader_pass_resumes_head_identity_on_the_same_unit_without_lending_the_body() {
    let seen = Arc::default();
    let reader = probe("reader", AuthPoints::HEAD_BODY, Verified::Pass, &seen);
    let head = probe(
        "head",
        AuthPoints::HEAD,
        identity("oidc", "credential"),
        &seen,
    );
    let body = probe("body", AuthPoints::HEAD_BODY, Verified::Reject, &seen);
    let k = mixed(reader, &[head, body]);
    let answer = two_points(&k, &seen).await;
    assert_eq!(answer.flow, FLOW_CONTINUE);
    assert_eq!(
        k.inbound.admitted(answer.unit.id).unwrap().identity.subject,
        "oidc"
    );
    assert_eq!(
        *seen.lock().unwrap(),
        vec![
            expected("reader", AuthPoint::HeadBody, answer.unit.id),
            expected("head", AuthPoint::Head, answer.unit.id)
        ]
    );
    let head = signed_head().stripped(&answer.strips).unwrap();
    assert_eq!(
        k.hand_in(MESSAGES, MESSAGES, answer.unit, head.clone()).0,
        FLOW_CONTINUE
    );
    assert!(k.inbound.claim_request(OWNER, 1, 1, &head).is_ok());
}

#[tokio::test]
async fn reader_pass_resumes_head_denial_before_any_later_body_identity() {
    let seen = Arc::default();
    let reader = probe("reader", AuthPoints::HEAD_BODY, Verified::Pass, &seen);
    let head = probe("head", AuthPoints::HEAD, Verified::Reject, &seen);
    let body = probe(
        "body",
        AuthPoints::HEAD_BODY,
        identity("later", "credential"),
        &seen,
    );
    let k = mixed(reader, &[head, body]);
    let answer = two_points(&k, &seen).await;
    assert_eq!(answer.flow, FLOW_STOP);
    assert!(k.inbound.admitted(answer.unit.id).is_none());
    assert_eq!(
        *seen.lock().unwrap(),
        vec![
            expected("reader", AuthPoint::HeadBody, answer.unit.id),
            expected("head", AuthPoint::Head, answer.unit.id)
        ]
    );
}

#[tokio::test]
async fn reader_and_head_pass_preserve_order_and_deliver_the_body_only_to_the_body_provider() {
    let seen = Arc::default();
    let reader = probe("reader", AuthPoints::HEAD_BODY, Verified::Pass, &seen);
    let head = probe("head", AuthPoints::HEAD, Verified::Pass, &seen);
    let body = probe(
        "body",
        AuthPoints::HEAD_BODY,
        identity("body", "credential"),
        &seen,
    );
    let k = mixed(reader, &[head, body]);
    let answer = two_points(&k, &seen).await;
    assert_eq!(answer.flow, FLOW_CONTINUE);
    assert_eq!(
        k.inbound.admitted(answer.unit.id).unwrap().identity.subject,
        "body"
    );
    let trace = vec![
        expected("reader", AuthPoint::HeadBody, answer.unit.id),
        expected("head", AuthPoint::Head, answer.unit.id),
        expected("body", AuthPoint::HeadBody, answer.unit.id),
    ];
    assert_eq!(*seen.lock().unwrap(), trace);
    let again = k
        .call_async(MESSAGES, answer.unit, POINT_HEAD_BODY, signed_head())
        .await
        .unwrap();
    assert_eq!(again.unit, answer.unit);
    assert_eq!(again.flow, FLOW_CONTINUE);
    assert_eq!(
        *seen.lock().unwrap(),
        trace,
        "answered HEAD providers and settled reader are never repeated"
    );
}

#[tokio::test]
async fn a_final_signed_reader_verdict_still_preempts_head_and_body_providers() {
    let seen = Arc::default();
    let reader = probe("reader", AuthPoints::HEAD_BODY, Verified::Reject, &seen);
    let head = probe(
        "head",
        AuthPoints::HEAD,
        identity("head", "credential"),
        &seen,
    );
    let body = probe(
        "body",
        AuthPoints::HEAD_BODY,
        identity("body", "credential"),
        &seen,
    );
    let k = mixed(reader, &[head, body]);
    let answer = two_points(&k, &seen).await;
    assert_eq!(answer.flow, FLOW_STOP);
    assert_eq!(
        *seen.lock().unwrap(),
        vec![expected("reader", AuthPoint::HeadBody, answer.unit.id)]
    );
}

#[tokio::test]
async fn a_faulted_signed_reader_pass_cannot_release_the_head_chain() {
    let seen = Arc::default();
    let mut reader = probe("reader", AuthPoints::HEAD_BODY, Verified::Pass, &seen);
    Arc::get_mut(&mut reader).unwrap().faulted = true;
    let head = probe(
        "head",
        AuthPoints::HEAD,
        identity("head", "credential"),
        &seen,
    );
    let k = mixed(reader, &[head]);
    let answer = two_points(&k, &seen).await;
    assert_eq!(answer.flow, FLOW_STOP);
    assert_eq!(
        *seen.lock().unwrap(),
        vec![expected("reader", AuthPoint::HeadBody, answer.unit.id)]
    );
}

#[tokio::test]
async fn a_pending_fallback_head_obeys_the_original_operation_deadline_and_cannot_admit() {
    let seen = Arc::default();
    let reader = probe("reader", AuthPoints::HEAD_BODY, Verified::Pass, &seen);
    let mut head = probe("head", AuthPoints::HEAD, Verified::Pass, &seen);
    Arc::get_mut(&mut head).unwrap().pending = true;
    let body = probe(
        "body",
        AuthPoints::HEAD_BODY,
        identity("body", "credential"),
        &seen,
    );
    let k = mixed(reader, &[head, body]);
    let deadline = std::time::Instant::now() + std::time::Duration::from_millis(50);
    let waiting = k
        .inbound
        .auth_call(
            Call {
                owner: OWNER,
                generation: GEN,
                auth: k.id(MESSAGES),
                unit: UnitRef::NONE,
                point: POINT_HEAD,
                conn: 1,
                stream: 1,
                framing: 1,
                head: signed_head(),
                body: None,
                deadline: Some(deadline),
            },
            Box::new(|_| panic!("the body reader has not started")),
        )
        .expect("HEAD reserves the reader synchronously")
        .unwrap();
    let (sent, received) = tokio::sync::oneshot::channel();
    let immediate = k.inbound.auth_call(
        Call {
            owner: OWNER,
            generation: GEN,
            auth: k.id(MESSAGES),
            unit: waiting.unit,
            point: POINT_HEAD_BODY,
            conn: 1,
            stream: 1,
            framing: 1,
            head: signed_head(),
            body: Some(b"{}".to_vec()),
            deadline: Some(deadline),
        },
        Box::new(move |answer| {
            let _ = sent.send(answer);
        }),
    );
    assert!(
        immediate.is_none(),
        "the real host retains the pending verifier"
    );
    let answer = tokio::time::timeout(std::time::Duration::from_secs(1), received)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert_eq!(answer.flow, FLOW_STOP);
    assert_eq!(answer.unit, waiting.unit);
    assert!(k.inbound.admitted(answer.unit.id).is_none());
    assert_eq!(
        *seen.lock().unwrap(),
        vec![
            expected("reader", AuthPoint::HeadBody, answer.unit.id),
            expected("head", AuthPoint::Head, answer.unit.id)
        ]
    );
}

#[tokio::test]
async fn a_faulted_fallback_head_pass_denies_before_the_body_provider() {
    let seen = Arc::default();
    let reader = probe("reader", AuthPoints::HEAD_BODY, Verified::Pass, &seen);
    let mut head = probe("head", AuthPoints::HEAD, Verified::Pass, &seen);
    Arc::get_mut(&mut head).unwrap().faulted = true;
    let body = probe(
        "body",
        AuthPoints::HEAD_BODY,
        identity("body", "credential"),
        &seen,
    );
    let k = mixed(reader, &[head, body]);
    let answer = two_points(&k, &seen).await;
    assert_eq!(answer.flow, FLOW_STOP);
    assert!(k.inbound.admitted(answer.unit.id).is_none());
    assert_eq!(
        *seen.lock().unwrap(),
        vec![
            expected("reader", AuthPoint::HeadBody, answer.unit.id),
            expected("head", AuthPoint::Head, answer.unit.id)
        ]
    );
}
