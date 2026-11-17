// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! A unit ref's freshness is a nonce, not key material (ENTROPY-IDS): the mint names no OS
//! entropy, and an adoption re-mint still refuses the pre-adoption ref under the same owner.
use super::*;
use crate::guest::{Claimant, Route};
use busbar_contract::abi::auth::{AuthPoints, POINT_HEAD};
use busbar_contract::abi::transport::route::{METHOD_POST, PATH_EXACT};
use busbar_contract::auth_calls::Verifying;
use busbar_contract::framing_scope::AdoptionSource;
use std::sync::atomic::{AtomicU64, Ordering};

#[test]
fn inbound_mint_names_no_os_entropy() {
    let source = include_str!("../inbound.rs");
    let code: String = source
        .lines()
        .map(|line| line.split("//").next().unwrap_or(""))
        .collect::<Vec<_>>()
        .join("\n");
    for needle in [
        "getrandom",
        "rand::",
        "rand_core",
        "OsRng",
        "busbar_crypto::random",
        "random_fill",
    ] {
        let hits: Vec<usize> = code
            .lines()
            .enumerate()
            .filter(|(_, line)| line.contains(needle))
            .map(|(n, _)| n + 1)
            .collect();
        assert!(
            hits.is_empty(),
            "inbound.rs draws OS entropy per mint (`{needle}` at lines {hits:?}); \
             a unit nonce is a counter (door::unit_nonce)"
        );
    }
}

struct Probe {
    name: &'static str,
    points: AuthPoints,
    answer: Verified,
}

struct Reply(Option<VerifyAnswer>);
impl Future for Reply {
    type Output = VerifyAnswer;
    fn poll(
        mut self: Pin<&mut Self>,
        _: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Self::Output> {
        self.0
            .take()
            .map_or(std::task::Poll::Pending, std::task::Poll::Ready)
    }
}
impl Verifying for Reply {
    fn settled(&mut self) -> Option<VerifyAnswer> {
        self.0.take()
    }
    fn faulted(&self) -> bool {
        false
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
    fn verify(&self, _: VerifyRequest) -> Box<dyn Verifying> {
        Box::new(Reply(Some(VerifyAnswer::from(self.answer.clone()))))
    }
    fn refresh(&self) -> Result<u64, String> {
        Ok(0)
    }
}

const OWNER: u64 = 7;
const GEN: u64 = 3;
const LISTENER: u64 = 71;
const MESSAGES: &str = "/v1/messages";
const SIGNED_LINE: &str = "x-signed-credential";

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

fn signed_head() -> Head {
    Head {
        method: "POST".into(),
        target: MESSAGES.into(),
        authority: "a.example".into(),
        query: None,
        fields: vec![(SIGNED_LINE.into(), b"signature".to_vec())],
    }
}

fn probe(name: &'static str, points: AuthPoints, answer: Verified) -> (String, Arc<dyn AuthCalls>) {
    (
        name.to_string(),
        Arc::new(Probe {
            name,
            points,
            answer,
        }),
    )
}

/// The reader-fallback host (`inbound_reader_fallback.rs`): a signed reader that passes, a HEAD
/// provider that names an identity and a body provider that would reject.
fn host(mac: UnitMac) -> Arc<Inbound> {
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
    let (_, reader) = probe("reader", AuthPoints::HEAD_BODY, Verified::Pass);
    let app = Arc::new(crate::state::App::from_test_parts(crate::state::AppParts {
        fallback_runtime_key: "",
        serve_tables: Default::default(),
        port_seats: Default::default(),
        exports: Default::default(),
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
        auth_instances: Default::default(),
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
    let providers = [
        probe(
            "head",
            AuthPoints::HEAD,
            Verified::Identity(VerifiedIdentity {
                subject: "oidc".to_string(),
                credential: Some(Secret::new("credential".to_string())),
                ..VerifiedIdentity::default()
            }),
        ),
        probe("body", AuthPoints::HEAD_BODY, Verified::Reject),
    ];
    let mut names: Vec<String> = providers.iter().map(|(name, _)| name.clone()).collect();
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
            claimant: Claimant::Clean("nonce-fixture".into()),
            dialect: 0,
            auth: LineAuth::Chain(names, AuthPoints(POINT_HEAD | POINT_HEAD_BODY)),
            upgrade: None,
            offered: AuthPoints(POINT_HEAD | POINT_HEAD_BODY),
        }])
        .unwrap(),
        auths: providers.into_iter().collect(),
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
            mac,
        },
        Arc::new(|work| {
            tokio::spawn(work);
        }),
        Arc::new(|_| {}),
    );
    inbound.install_at(OWNER, LISTENER, GEN, listener).unwrap();
    inbound.framing_started(OWNER, LISTENER, 1, GEN).unwrap();
    inbound.grant_stream(OWNER, 1, 1, GEN).unwrap();
    inbound
}

fn auth_id(inbound: &Inbound) -> u64 {
    inbound.specs_at(OWNER, LISTENER, GEN).unwrap()[0].auth
}

async fn call_at(
    inbound: &Arc<Inbound>,
    unit: UnitRef,
    point: u32,
    framing: u64,
    conn: u64,
) -> Result<Answer, &'static str> {
    let (sent, received) = tokio::sync::oneshot::channel();
    let answer = inbound.auth_call(
        Call {
            owner: OWNER,
            generation: GEN,
            auth: auth_id(inbound),
            unit,
            point,
            conn,
            stream: 1,
            framing,
            head: signed_head(),
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

/// Same-owner adoption: the unit id and owner are unchanged, so only the re-minted nonce
/// separates the pre-adoption ref from the adopted one.
#[tokio::test]
async fn same_owner_adoption_refuses_old_ref() {
    let inbound = host(Arc::new(test_mac));
    let waiting = call_at(&inbound, UnitRef::NONE, POINT_HEAD, 1, 1)
        .await
        .unwrap();
    assert_eq!(waiting.flow, FLOW_CONTINUE);
    let hand_in = |unit, head| {
        inbound.hand_in(HandIn {
            owner: OWNER,
            generation: GEN,
            auth: auth_id(&inbound),
            unit,
            line: 0,
            conn: 1,
            stream: 1,
            framing: Some(1),
            head,
        })
    };
    assert_eq!(hand_in(waiting.unit, signed_head()).unwrap().0, FLOW_STOP);
    let admitted = call_at(&inbound, waiting.unit, POINT_HEAD_BODY, 1, 1)
        .await
        .unwrap();
    assert_eq!(admitted.flow, FLOW_CONTINUE);
    let old = admitted.unit;
    let head = signed_head().stripped_for_test(&admitted.strips).unwrap();
    assert_eq!(hand_in(old, head.clone()), Ok((FLOW_CONTINUE, old)));
    inbound.claim_request(OWNER, 1, 1, &head).unwrap();

    let n0 = inbound.unit_secret(OWNER, old.id).unwrap().0;
    inbound.framing_detached(OWNER, 1).unwrap();
    let source = AdoptionSource {
        owner: OWNER,
        listener: LISTENER,
        leg: 1,
        conn: 1,
    };
    let staged = inbound.framing_adopting(source, OWNER, 19).unwrap();
    inbound.framing_adopted(OWNER, 19, 803).unwrap();
    assert_ne!(
        inbound.unit_secret(OWNER, old.id).unwrap().0,
        n0,
        "adoption re-mints the nonce"
    );
    assert_eq!(staged.session.unit.id, old.id);
    assert_ne!(staged.session.unit.mac, old.mac);

    assert!(
        matches!(
            call_at(&inbound, old, POINT_HEAD_BODY, 19, 803).await,
            Err(UNIT_FOREIGN)
        ),
        "the pre-adoption ref loses authority under the same owner"
    );
    let current = call_at(&inbound, staged.session.unit, POINT_HEAD_BODY, 19, 803)
        .await
        .unwrap();
    assert_eq!(current.unit, staged.session.unit);
    assert_eq!(current.flow, FLOW_CONTINUE);
}

/// Two hosts in one process mint concurrently: every nonce is distinct and carries this boot's
/// node. Counter values are never asserted, so parallel tests that mint op ids or units cannot
/// break it.
#[tokio::test]
async fn unit_nonces_distinct_across_inbounds() {
    const MINTS: usize = 10_000;
    let recording = || {
        let seen: Arc<Mutex<Vec<[u64; 2]>>> = Arc::default();
        let into = Arc::clone(&seen);
        let mac: UnitMac = Arc::new(move |t: &UnitTag| {
            into.lock().unwrap().push(t.secret);
            test_mac(t)
        });
        (host(mac), seen)
    };
    let hosts = [recording(), recording()];
    std::thread::scope(|scope| {
        for (inbound, _) in &hosts {
            let table = inbound.table_at(OWNER, LISTENER, GEN).unwrap();
            scope.spawn(move || {
                let binding = RequestBinding {
                    conn: 1,
                    stream: 1,
                    framing: None,
                };
                for _ in 0..MINTS {
                    inbound
                        .mint(OWNER, GEN, 0, &Arc::from([]), binding, Arc::clone(&table))
                        .unwrap();
                }
            });
        }
    });
    let mut all = foldhash::HashSet::default();
    for (_, seen) in &hosts {
        let seen = seen.lock().unwrap();
        assert_eq!(seen.len(), MINTS);
        for nonce in seen.iter() {
            assert_eq!(nonce[0], crate::door::node(), "word 0 is this boot's node");
            assert!(all.insert(*nonce), "a nonce repeats: {nonce:?}");
        }
    }
    assert_eq!(all.len(), 2 * MINTS);
}

#[cfg(not(target_env = "msvc"))]
#[path = "inbound_table_cost.rs"]
mod table_cost;
