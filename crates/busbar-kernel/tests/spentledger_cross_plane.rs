// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! ONE APPROVAL, REDEEMED ONCE — across a restart, and across a fleet.
//!
//! Every case drives the SERVED path: a real `App` configured from a deploy document the way an
//! operator writes one, its real router on a real socket, and a caller presenting an access token to
//! the plane's front door. The plane is the linked one that owns the `tools:` section, read back from
//! the test-linked registry (`tests/linked/mod.rs`); this file names no plane crate, type or key.
//! The request frame is the plane's own (`TestPlaneSeam::served_call`), so its wire is spelled where
//! it is defined and nowhere here.
//!
//! What the operator gates is a PROMPT on a registration: one round of confirmation before it
//! renders. The ask, the seal, the redemption and the spent-approval ledger are the one gate every
//! gated capability on that plane rides — a prompt and a tool are one grammar on two paths — and a
//! prompt renders from the operator's own config, so the served answer is itself the witness that a
//! redemption was carried out: the rendered text, or the refusal.
//!
//! ## The two shapes an in-process ledger cannot refuse
//!
//! Everything about a sealed continuation state except single use rides inside the blob: who it was
//! minted for, which request, which round, until when. Single use cannot, because the second
//! presentation of a redeemed approval is byte-identical to the first and is perfectly valid. Only a
//! RECORD THAT THE FIRST HAPPENED tells them apart, and where that record lives decides which
//! double-redemptions it can refuse:
//!
//! * **A RESTART.** The record was in process memory, so a restart lost it while the approval —
//!   which has its own, longer, life — was still openable.
//! * **A FLEET.** Two nodes of one deployment share `auth.signing_key`, because that is what lets
//!   one logical exchange span requests different nodes serve. Sharing the key shares the SEAL. With
//!   the ledger unshared, one approval was redeemable once PER NODE, and the second redemption is
//!   not a race or a timing trick — it is an ordinary sequential request that a load balancer sends
//!   somewhere else. On a capability an operator gated because it moves money, that is the defect the
//!   gate exists to stop, multiplied by the size of the fleet.
//!
//! ## Judged through the served door, and through the real plugin
//!
//! A test against the ledger's `spend` would prove the ledger and say nothing about whether the gate
//! consults it, which is exactly the shape of "a complete subsystem with no production caller" this
//! tree has already paid for once. So every case below asks and redeems through the front door a
//! caller uses, and reads the answer the caller reads.
//!
//! And the shared ledger is the genuine `busbar-store-example-plugin` cdylib in its durable mode,
//! `dlopen`ed once PER NODE through `busbar_plugin_loader::load_store`. Two `dlopen`s of one file is
//! what two nodes of a fleet are; a `dlopen`, a drop, and a second `dlopen` is what a restart is. An
//! in-process `Store` double would be green against an ABI that carried no variant for this method
//! at all, which is precisely how ten store methods were dropped at this seam earlier in the same
//! release.

mod linked;

use busbar_kernel::config::RootCfg;
use busbar_kernel::governance::signing::{TokenSigner, TokenVerifier, DEFAULT_KID};
use busbar_kernel::governance::{GovState, MemoryStore, NewKeySpec};
use busbar_kernel::plane::registry::{BuildCtx, PlaneDecl};
use busbar_kernel::test_support::plugin_store::{durable_cfg, open_plugin};
use busbar_kernel::test_support::TestApp;
use std::any::Any;
use std::sync::Arc;

/// THE FLEET-SHARED SECRET. One key for every node below — that is the premise, not a shortcut: it
/// is what makes an approval minted on one node openable on another, and therefore what makes the
/// unshared ledger a defect rather than a curiosity.
const KEY: [u8; 32] = [11u8; 32];
/// The host of the plane's canonical URI: the audience the caller's token is bound to.
const HOST: &str = "gateway.example.com";
/// The operator's registration, and the prompt on it they gate behind a confirmation.
const SERVER: &str = "bank";
const PROMPT: &str = "transfer";
/// What the gated prompt renders — the answer a dispatched redemption carries back.
const RENDERED: &str = "Transfer 10 to alice";
/// The audit reason of the one refusal these cases are about — a spent approval, specifically.
const ALREADY_SPENT: &str = "state_already_spent";

/// The linked plane that owns the `tools:` section and serves the front door.
fn door() -> &'static PlaneDecl {
    linked::owning("tools")
}

/// The plane's canonical URI — the audience a caller's token must be bound to.
fn canonical() -> String {
    format!("https://{HOST}/{}", door().key)
}

/// The deploy document's plane sections: the front door, and ONE registration whose one prompt the
/// operator gates behind one round of confirmation — the whole scenario single use exists for.
fn sections() -> String {
    format!(
        "{door}:\n  canonical_uri: \"{canonical}\"\n  \
         authorization_servers: [\"https://login.example.com\"]\n\
         tools:\n  {SERVER}:\n    url: \"https://{SERVER}.example/rpc\"\n    \
         pin: {{ mechanism: pinned_pubkey, key: \"sha256/PEER=\" }}\n    \
         prompts_allow:\n      {PROMPT}:\n        template: \"{RENDERED}\"\n        \
         ask_caller:\n          - confirm: {{ method: \"elicitation/create\", \
         params: {{ message: \"Confirm the transfer\" }} }}\n",
        door = linked::door_section(door()),
        canonical = canonical(),
    )
}

/// The deploy document carrying [`sections`], parsed and RESOLVED the way boot and `--validate` do —
/// the plane sections are lowered by the planes' own hooks, never by a plane type named here.
fn resolved() -> RootCfg {
    linked::install();
    let yaml = format!(
        "providers:\n  acme: {{ api_key: none }}\nmodels:\n  m: {{ provider: acme }}\n{}",
        sections()
    );
    let deploy = busbar_kernel::config::deploy_from_yaml_str(&yaml).expect("the document parses");
    let mut defs = std::collections::HashMap::new();
    defs.insert(
        "acme".to_string(),
        serde_yaml::from_str(&format!(
            "protocol: {}\nbase_url: https://api.example.com\n",
            busbar_kernel::proto::residual_default_dialect().expect("a residual-default dialect")
        ))
        .expect("provider def"),
    );
    busbar_kernel::config::resolve(&deploy, &defs)
        .unwrap_or_else(|e| panic!("the document resolves: {e:?}"))
}

/// The door plane's per-generation runtime (the catalogue of the registration above), built by its
/// OWN `build_runtime` hook from the resolved section — the same call `build_dispatch` makes.
///
/// ONE build serves every node of a fleet below. The catalogue generation a sealed state binds is a
/// counter each process starts at the same value when it boots the same config; one test process
/// cannot start it twice, so its nodes share the one snapshot a fleet's nodes each hold an identical
/// copy of. The spent-approval ledger is the `App`'s, never this runtime's, so sharing it shares
/// nothing these cases are about.
fn door_runtime(cfg: &RootCfg) -> Arc<dyn Any + Send + Sync> {
    let build_runtime = door()
        .build_runtime
        .expect("the door plane builds a per-generation runtime from its section");
    build_runtime(cfg.tool_defs.as_any(), None)
}

/// Configure a `TestApp` with every plane `cfg` configures, the way the kernel's own
/// `build_dispatch` does: each linked plane's object built by its OWN `build` hook from the resolved
/// document, every path it claims mounted, the admission it declares bound — and the door plane's
/// `runtime` in its per-generation slot.
fn configured(mut app: TestApp, cfg: &RootCfg, runtime: &Arc<dyn Any + Send + Sync>) -> TestApp {
    for decl in linked::planes()
        .iter()
        .copied()
        .filter(|d| cfg.plane_sections.contains(d.config_section))
    {
        let ctx = BuildCtx {
            endpoint_slot: cfg.endpoint_resources.get(decl.config_section).cloned(),
            agent_defs: cfg.agent_defs.as_any(),
            public_url: None,
            prior: None,
        };
        let Some(obj) = (decl.build)(&ctx) else {
            continue;
        };
        for (path, wire) in (decl.claims)(&*obj) {
            app.mount_plane(decl.key, &path, wire);
        }
        if let Some(admission) = (decl.admission)(&*obj) {
            app.admit_plane(decl.key, admission);
        }
        app.install_plane_runtime(decl.key, obj);
    }
    app.install_plane_runtime(
        busbar_kernel::plane_host::runtime_slot_key(door().key),
        Arc::clone(runtime),
    );
    app
}

/// The path the door plane claims for its JSON-RPC front door on a configured `App`.
fn front_door(cfg: &RootCfg, runtime: &Arc<dyn Any + Send + Sync>) -> String {
    let app = configured(TestApp::new(), cfg, runtime).build();
    let slot = app
        .plane_slot(door().key)
        .expect("the configured door plane holds its slot")
        .clone();
    (door().claims)(&*slot)
        .into_iter()
        .find(|(_, wire)| *wire == busbar_kernel::plane::WIRE_JSONRPC)
        .map(|(path, _)| path)
        .expect("the door plane claims a JSON-RPC front door")
}

/// THE DEPLOYMENT: the key registry every node reads, and the caller's token — bound to the plane's
/// canonical URI, so the front door admits it. One registry, because every node of a fleet admits
/// the same callers; it is NOT the durable ledger (a `MemoryStore` keeps no spent approvals), so
/// sharing it shares nothing the cases below are about.
struct Fleet {
    registry: Arc<MemoryStore>,
    token: String,
    cfg: RootCfg,
    runtime: Arc<dyn Any + Send + Sync>,
    door: String,
}

impl Fleet {
    fn new() -> Self {
        busbar_kernel::metrics::init();
        let registry = Arc::new(MemoryStore::new());
        let signer = TokenSigner::from_secret_bytes(&KEY, DEFAULT_KID);
        let gov = GovState::new_with_signer(registry.clone(), None, Some(signer))
            .expect("a governance state with the fleet's signer");
        // An UNRESTRICTED key: `allowed_scopes: None` is the wildcard, so the only thing that can
        // turn a redemption away is the gate itself, never a grant.
        let (key, plain) = gov
            .mint_signed(
                NewKeySpec {
                    name: "treasury-ops".to_string(),
                    ..Default::default()
                },
                2_000_000_000,
                1_000_000_000,
            )
            .expect("a signed key");
        let signer = TokenSigner::from_secret_bytes(&KEY, DEFAULT_KID);
        let generation = TokenVerifier::single(signer.kid(), signer.verifying_key())
            .verify(plain.as_str(), 1_000_000_000, None)
            .expect("plain claims")
            .generation;
        let token = signer.mint_for_audience(
            &key.id,
            2_000_000_000,
            generation.as_deref(),
            &canonical(),
            Some("client-1"),
        );
        let cfg = resolved();
        let runtime = door_runtime(&cfg);
        let door = front_door(&cfg, &runtime);
        Fleet {
            registry,
            token,
            cfg,
            runtime,
            door,
        }
    }

    /// ONE NODE of the deployment: its own `App`, its own in-process spent-approval ledger, the
    /// fleet's signing key and key registry, and — when `store` is `Some` — its own handle on the
    /// durable store the approvals are recorded in. Served on its own socket.
    async fn node(&self, store: Option<Arc<dyn busbar_api::Store>>) -> Node {
        let gov = GovState::new_with_signer(
            self.registry.clone(),
            None,
            Some(TokenSigner::from_secret_bytes(&KEY, DEFAULT_KID)),
        )
        .expect("the node's governance state");
        let mut app = TestApp::new().keys_chain().governance(Arc::new(gov));
        if let Some(store) = store {
            app = app.durable_store(store);
        }
        let router = busbar_kernel::build_router(configured(app, &self.cfg, &self.runtime).build());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let task = tokio::spawn(async move {
            let _ = axum::serve(listener, router).await;
        });
        Node {
            url: format!("http://{addr}{}", self.door),
            token: self.token.clone(),
            task,
        }
    }
}

/// A served node. Dropping it stops serving and drops its `App` — and with it the node's handle on
/// the durable store, so the plugin library unloads.
struct Node {
    url: String,
    token: String,
    task: tokio::task::JoinHandle<()>,
}

impl Drop for Node {
    fn drop(&mut self) {
        self.task.abort();
    }
}

/// One served answer: the HTTP status and the JSON-RPC body.
type Answer = (u16, serde_json::Value);

impl Node {
    /// One call of the gated prompt through this node's front door, framed by the plane itself.
    async fn call(&self, params: serde_json::Value) -> Answer {
        let frame = linked::seam(door())
            .served_call
            .expect("the door plane frames its own served calls");
        let (headers, body) = frame("prompts/get", params);
        let resp = reqwest::Client::new()
            .post(&self.url)
            .headers(headers)
            .bearer_auth(&self.token)
            .json(&body)
            .send()
            .await
            .expect("the call completes");
        let status = resp.status().as_u16();
        (status, resp.json().await.unwrap_or_default())
    }

    /// Ask this node for an approval — the opening round, which mints the sealed state.
    async fn ask(&self) -> String {
        let (status, body) = self.call(serde_json::json!({ "name": gated() })).await;
        assert_eq!(
            status, 200,
            "the opening round must ask, not refuse: {body}"
        );
        assert!(
            body.pointer("/result/messages").is_none(),
            "the opening round must not render the gated prompt: {body}"
        );
        body.pointer("/result/requestState")
            .and_then(|v| v.as_str())
            .unwrap_or_else(|| panic!("the opening round must issue continuation state: {body}"))
            .to_string()
    }

    /// Present `state` to this node as the answered confirmation — the redemption.
    async fn redeem(&self, state: &str) -> Answer {
        self.call(serde_json::json!({
            "name": gated(),
            "requestState": state,
            "inputResponses": { "confirm": { "action": "accept", "content": {} } },
        }))
        .await
    }
}

/// The gated prompt's name as a caller addresses it: namespaced by its registration.
fn gated() -> String {
    format!("{SERVER}_{PROMPT}")
}

/// `true` when a redemption DISPATCHED: the served answer is the gated prompt, rendered.
fn proceeded(answer: &Answer) -> bool {
    answer.0 == 200 && answer.1.pointer("/result/messages/0/content/text") == Some(&RENDERED.into())
}

/// `true` when the answer was the already-spent refusal specifically, not merely any refusal. A
/// looser assertion would be satisfied by a gate that refused the SECOND redemption for the wrong
/// reason — a lapsed clock, a generation bump — and would go on passing if the ledger were removed.
fn refused_as_spent(answer: &Answer) -> bool {
    answer.0 == 400
        && answer
            .1
            .pointer("/error/data/reason")
            .and_then(|r| r.as_str())
            == Some(ALREADY_SPENT)
}

/// THE FLEET CASE. Node A mints and redeems; node B — same signing key, same shared store, its own
/// process state — must refuse the same approval.
#[tokio::test]
async fn a_second_fleet_node_cannot_redeem_an_approval_the_first_already_spent() {
    let fleet = Fleet::new();
    let (file, cfg) = durable_cfg("askstate-fleet");
    let node_a = fleet.node(Some(open_plugin(&cfg))).await;
    let node_b = fleet.node(Some(open_plugin(&cfg))).await;

    let state = node_a.ask().await;
    let first = node_a.redeem(&state).await;
    assert!(
        proceeded(&first),
        "the FIRST redemption must dispatch, or nothing below is about single use: {first:?}"
    );

    // The seal is the deployment's, not the node's: node B opens it and every field verifies. That
    // is the premise of the fleet, and it is why the ledger is the only thing standing between one
    // approval and a second execution.
    let second = node_b.redeem(&state).await;
    assert!(
        refused_as_spent(&second),
        "a second node of the same deployment redeemed an approval that was already spent. The \
         nodes share the signing key, so they share the seal — every check but this one passes on \
         both — which means one operator confirmation was carried out once per node. On a \
         capability gated because it moves money that is the whole defect the gate exists to \
         stop. Got {second:?}; the shared ledger at {} holds: {}",
        file.display(),
        std::fs::read_to_string(&file).unwrap_or_else(|_| "<no file at all>".into())
    );

    // The BYTES the shared ledger actually kept, so a release report can quote evidence rather than
    // quote an assertion that passed.
    eprintln!(
        "SHARED SPENT-APPROVAL LEDGER {}:\n{}",
        file.display(),
        std::fs::read_to_string(&file).expect("the plugin's on-disk state")
    );
}

/// THE RESTART CASE. The node that spent the approval is gone — its ledger and its store handle both
/// — and a fresh one comes up on the same store while the approval is still inside its own window.
#[tokio::test]
async fn a_restarted_node_cannot_redeem_an_approval_the_previous_process_spent() {
    let fleet = Fleet::new();
    let (_file, cfg) = durable_cfg("askstate-restart");

    let state = {
        let before = fleet.node(Some(open_plugin(&cfg))).await;
        let state = before.ask().await;
        let first = before.redeem(&state).await;
        assert!(
            proceeded(&first),
            "the first redemption must dispatch: {first:?}"
        );
        state
        // `before` is dropped here, which stops it serving and drops its store handle — so the read
        // below cannot be answered out of anything the first process kept in RAM.
    };

    let after = fleet.node(Some(open_plugin(&cfg))).await;
    let second = after.redeem(&state).await;
    assert!(
        refused_as_spent(&second),
        "a restart handed a spent approval back. The state has not lapsed — it outlives a process \
         restart by design, and being openable is exactly the point — so the only thing that \
         changed is that the process that recorded the redemption is no longer running: {second:?}"
    );
}

/// THE CONTROL, and it is load-bearing: a DIFFERENT approval, on a node that has already spent one,
/// still dispatches. A ledger that refused everything would satisfy both cases above and would have
/// deleted the feature.
#[tokio::test]
async fn a_fresh_approval_is_not_refused_by_a_ledger_holding_another() {
    let fleet = Fleet::new();
    let (_file, cfg) = durable_cfg("askstate-distinct");
    let node_a = fleet.node(Some(open_plugin(&cfg))).await;
    let node_b = fleet.node(Some(open_plugin(&cfg))).await;

    let first = node_a.ask().await;
    let spent = node_a.redeem(&first).await;
    assert!(
        proceeded(&spent),
        "the first approval dispatches: {spent:?}"
    );

    let second = node_a.ask().await;
    assert_ne!(
        first, second,
        "two mints must differ, or this case is re-presenting the same approval"
    );
    let answer = node_b.redeem(&second).await;
    assert!(
        proceeded(&answer),
        "a second, freshly minted approval is not the one that was spent, and refusing it would \
         mean the shared ledger had become a blanket refusal of every confirmation after the first: \
         {answer:?}"
    );
}

/// AND ONE NODE STILL REFUSES ITS OWN REPLAY WITHOUT ASKING THE STORE. The local half is not
/// decoration: it is what keeps the obvious replay off the store's round trip, and it is the whole
/// gate for a deployment that configures no store at all.
#[tokio::test]
async fn a_node_refuses_its_own_replay_with_no_durable_store_configured() {
    let fleet = Fleet::new();
    let solo = fleet.node(None).await;
    let state = solo.ask().await;
    let first = solo.redeem(&state).await;
    assert!(
        proceeded(&first),
        "the first redemption dispatches: {first:?}"
    );
    let second = solo.redeem(&state).await;
    assert!(
        refused_as_spent(&second),
        "single use per node, for the life of the process, is the pre-existing property and must \
         survive the change that shares it: {second:?}"
    );
}

/// THE PERMANENT NEGATIVE. Two nodes that share the signing key and share NO store DO both redeem —
/// which is the documented `store: memory` posture stated out loud rather than discovered.
///
/// This case exists because without it every case above is equally consistent with a gate that
/// refuses a second redemption for some reason that has nothing to do with the shared ledger. It is
/// the one arrangement in which the ledger is provably the thing doing the work: change nothing but
/// whether the two nodes share a store, and the answer changes.
///
/// It is not a defect being enshrined. A deployment with no durable store has no shared anything,
/// and the honest thing for a gateway to do about a property it cannot provide is to say so where an
/// operator will find it.
#[tokio::test]
async fn two_nodes_sharing_no_store_each_redeem_once_which_is_the_documented_ram_posture() {
    let fleet = Fleet::new();
    let node_a = fleet.node(None).await;
    let node_b = fleet.node(None).await;
    let state = node_a.ask().await;
    let first = node_a.redeem(&state).await;
    assert!(
        proceeded(&first),
        "node A's redemption dispatches: {first:?}"
    );
    let second = node_b.redeem(&state).await;
    assert!(
        proceeded(&second),
        "with no shared ledger there is nothing for node B to consult, and this is the behaviour \
         the durable ledger exists to change — a durability test that has never seen the \
         NON-durable arrangement has proven nothing about which half is doing the work: {second:?}"
    );
}

/// AND THE RAM DEFAULT IS THE SAME ARRANGEMENT. `busbar-store-memory` implements none of this, so
/// attaching it is indistinguishable from attaching nothing — which is also the exact shape of every
/// already-signed store plugin built before this method existed.
#[tokio::test]
async fn the_memory_store_shares_no_ledger_which_is_the_documented_contract() {
    let fleet = Fleet::new();
    let node_a = fleet.node(Some(Arc::new(MemoryStore::new()))).await;
    let node_b = fleet.node(Some(Arc::new(MemoryStore::new()))).await;

    let state = node_a.ask().await;
    let first = node_a.redeem(&state).await;
    assert!(
        proceeded(&first),
        "node A's redemption dispatches: {first:?}"
    );
    let second = node_b.redeem(&state).await;
    assert!(
        proceeded(&second),
        "the RAM default accepts the redemption and keeps nothing, which is why a deployment that \
         wants this property across a fleet has to configure a durable store: {second:?}"
    );
}
