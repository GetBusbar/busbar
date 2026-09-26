// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THIS PLANE'S SERVED-LEG WITNESSES — an inbound A2A call driven through the real router and
//! whatever runner the host has registered for this plane's capability key, each witness asserting
//! ONE capability or ONE loop step on what came out.
//!
//! ## Why they live here and run elsewhere
//!
//! In a deployment the inbound call is served by the composition root's kernel-loop rider: the root
//! registers it under [`crate::PLANE_KEY`] at boot, and `run_gauntlet` hands this plane's `drive`
//! (the whole of `invoke_inner`) to it. That rider lives in the binary crate, which this crate
//! cannot link, so in THIS crate's own test binary the same call runs `run_gauntlet`'s inline
//! verify-then-`drive` fallback. The witnesses are therefore compiled under `test-support` and
//! exported through [`crate::testkit::SERVED`]: the binary crate's test build links this crate,
//! installs its real rider, runs every witness, and checks that this plane's `drive` actually ran
//! inside the loop the number of times the witness says it should. The composition root names no
//! plane to do it — it reads the table its build script generated from the manifest.
//!
//! ## What a witness returns
//!
//! The number of units it expects the served path to have carried into this plane's `drive`: every
//! request the authenticated front door handed to `invoke`. A request the ingress refuses before the
//! handler (no credential, a forged one) is not a unit and is not counted — which is exactly what
//! the caller checks.
//!
//! They drive the SAME harness the relay's own batteries drive (`relay_harness`), so the served
//! witnesses and the plane's tests cannot drift onto two deployments.

use super::relay_harness::*;
use crate::a2a::fetch::{HttpResponse, Resolver};
use crate::a2a::relay::{ChunkFlow, RelaySeam, RelayTransport, StreamHead};
use std::future::Future;
use std::net::{IpAddr, Ipv4Addr};
use std::pin::Pin;
use std::sync::atomic::Ordering;
use std::sync::Arc;

/// One served-leg witness: drive the served path, assert, and return the number of units the
/// served path must have carried into this plane's `drive`.
pub type Witness = fn() -> Pin<Box<dyn Future<Output = u64>>>;

/// THE WITNESS TABLE, keyed by the loop step (`qa/teller-steps.json`) or the core capability
/// (`qa/capability-equality.json`) each one proves on the served path.
pub(crate) const WITNESSES: &[(&str, Witness)] = &[
    ("arrival", || Box::pin(a_served_call_arrives_as_one_unit())),
    ("decode", || {
        Box::pin(a_body_that_is_not_json_is_refused_by_the_units_own_parse())
    }),
    ("authenticate", || {
        Box::pin(a_caller_without_a_credential_never_becomes_a_unit())
    }),
    ("verify", || {
        Box::pin(a_metadata_address_is_refused_before_the_socket())
    }),
    ("approve", || {
        Box::pin(a_grant_on_one_agent_does_not_reach_another())
    }),
    ("admit", || {
        Box::pin(a_caller_over_its_limit_is_refused_before_the_hop())
    }),
    ("route", || {
        Box::pin(a_failed_hop_is_answered_inside_the_unit())
    }),
    ("meter", || {
        Box::pin(a_served_hop_meters_exactly_one_request())
    }),
    ("audit", || Box::pin(a_served_hop_is_audited_once())),
    ("exit", || Box::pin(a_failed_hop_ends_the_task_once())),
    ("audit-chain", || {
        Box::pin(the_served_tasks_chain_verifies_from_its_genesis())
    }),
    ("governance-budget", || {
        Box::pin(a_served_hop_is_charged_to_the_presenting_key())
    }),
    ("metrics", || {
        Box::pin(a_served_hop_counts_an_upstream_attempt())
    }),
    ("trust-pinning", || {
        Box::pin(a_demoted_registration_is_not_served())
    }),
    ("net-guard", || {
        Box::pin(the_judged_address_is_the_one_dialled())
    }),
    ("catalogue", || {
        Box::pin(a_caller_granted_no_agent_reaches_none())
    }),
];

// ── FIXTURES ────────────────────────────────────────────────────────────────────────────────────

/// The default deployment (`planner` granted to the caller), after the cross-plane seams are in.
async fn deployment(outcome: Outcome) -> Harness {
    crate::testkit::install_test_seams();
    harness(outcome, false).await
}

/// POST raw bytes to `planner`'s front door, with `bearer` (or none); `(status, JSON answer)`.
async fn post_raw(h: &Harness, body: &str, bearer: Option<&str>) -> (u16, serde_json::Value) {
    let mut req = reqwest::Client::new()
        .post(format!("http://{}/a2a/agents/planner", h.addr))
        .header("content-type", "application/json")
        .body(body.to_string());
    if let Some(token) = bearer {
        req = req.header("authorization", format!("Bearer {token}"));
    }
    let resp = req.send().await.expect("the call completes");
    let status = resp.status().as_u16();
    (status, resp.json().await.unwrap_or(serde_json::Value::Null))
}

/// The admission count `key`'s own ledger holds, through the one pricing function (a billed card, no
/// flat fee of its own — the count is what is read, not a price).
fn requests_charged_to(h: &Harness, key: &busbar_contract::records::VirtualKey) -> u64 {
    let cost = crate::testkit::engine_boot::engine().cost_parts(
        Some(&std::collections::BTreeMap::new()),
        1,
        &std::collections::BTreeMap::new(),
    );
    h.gov.flush_budgets();
    h.gov
        .usage_for(&*cost, &key.id, busbar_substrate_values::store::now())
        .expect("the key's usage reads back")
        .map_or(0, |u| u.requests)
}

/// The caller's key in a harness's own governance registry (the one key it minted).
fn caller_of(h: &Harness) -> busbar_contract::records::VirtualKey {
    h.gov
        .all_keys()
        .expect("the keys read back")
        .into_iter()
        .find(|k| k.name == "external-agent")
        .expect("the caller's key")
}

/// The task id a refusal names (`google.rpc.ResourceInfo` inside `error.data`).
fn task_named_by(body: &serde_json::Value) -> String {
    body.pointer("/error/data")
        .and_then(serde_json::Value::as_array)
        .into_iter()
        .flatten()
        .find(|e| e["@type"] == "type.googleapis.com/google.rpc.ResourceInfo")
        .and_then(|e| e["resourceName"].as_str())
        .unwrap_or_default()
        .to_string()
}

/// A resolver answering the cloud metadata address for every name.
struct MetadataResolver;

impl Resolver for MetadataResolver {
    fn resolve(&self, _host: &str) -> Result<Vec<IpAddr>, String> {
        Ok(vec![IpAddr::V4(Ipv4Addr::new(169, 254, 169, 254))])
    }
}

/// A transport that must never be reached.
struct NeverDialled;

impl RelayTransport for NeverDialled {
    fn send(
        &self,
        _m: &str,
        _u: &url::Url,
        _a: IpAddr,
        _h: &[(String, String)],
        _b: &[u8],
    ) -> Result<HttpResponse, String> {
        panic!("the transport must never be reached for a refused target");
    }
    fn post_stream(
        &self,
        _u: &url::Url,
        _a: IpAddr,
        _h: &[(String, String)],
        _b: &[u8],
        _c: &mut (dyn FnMut(&[u8]) -> ChunkFlow + Send),
    ) -> Result<StreamHead, String> {
        panic!("the transport must never be reached for a refused target");
    }
}

/// The relay seam of a deployment whose backend name resolves to the metadata address.
struct MetadataSeam;

impl RelaySeam for MetadataSeam {
    fn resolver(&self) -> &dyn Resolver {
        &MetadataResolver
    }
    fn transport(&self) -> &dyn RelayTransport {
        &NeverDialled
    }
}

// ── THE LOOP STEPS ──────────────────────────────────────────────────────────────────────────────

/// ARRIVAL: one inbound call is one unit, and it is relayed to the backend agent once.
async fn a_served_call_arrives_as_one_unit() -> u64 {
    let h = deployment(Outcome::Answers(200, backend_ok())).await;
    let (status, body) = call(&h).await;
    assert_eq!(status, 200, "the admitted call is served: {body}");
    let sent = h.sent();
    assert_eq!(sent.len(), 1, "exactly one hop was made");
    assert_eq!(sent[0].url, BACKEND, "to the backend agent");
    1
}

/// DECODE: a body that is not JSON is refused by the unit's own parse, with the parse error's code,
/// and nothing is relayed.
async fn a_body_that_is_not_json_is_refused_by_the_units_own_parse() -> u64 {
    let h = deployment(Outcome::Answers(200, backend_ok())).await;
    let (_status, body) = post_raw(&h, "{not json", Some(&h.caller_token)).await;
    assert_eq!(
        body.pointer("/error/code").and_then(|v| v.as_i64()),
        Some(-32700),
        "a body that is not JSON is the parse error: {body}"
    );
    assert!(h.sent().is_empty(), "and nothing was relayed");
    1
}

/// AUTHENTICATE: a call with no credential and a call with a forged one are refused before the
/// handler; the audience-bound caller is served.
async fn a_caller_without_a_credential_never_becomes_a_unit() -> u64 {
    let h = deployment(Outcome::Answers(200, backend_ok())).await;
    let good = envelope().to_string();
    for bearer in [None, Some("not-a-busbar-token")] {
        let (status, body) = post_raw(&h, &good, bearer).await;
        assert_eq!(
            status, 401,
            "a caller the chain cannot authenticate ({bearer:?}) is refused: {body}"
        );
    }
    assert!(h.sent().is_empty(), "no unauthenticated call was relayed");
    let (status, body) = call(&h).await;
    assert_eq!(status, 200, "the authenticated caller is served: {body}");
    assert_eq!(h.sent().len(), 1);
    1
}

/// VERIFY: a backend whose name resolves to the cloud metadata address is refused by the guard, and
/// the transport is never reached.
async fn a_metadata_address_is_refused_before_the_socket() -> u64 {
    let h = deployment(Outcome::Answers(200, backend_ok())).await;
    h.plane.set_relay_seam(Arc::new(MetadataSeam));
    let (status, body) = call(&h).await;
    assert_ne!(status, 200, "a metadata target is never served: {body}");
    assert!(
        body.get("error").is_some(),
        "and the refusal is an error the caller reads: {body}"
    );
    1
}

/// APPROVE: a caller granted `planner` and not `payments` is refused at `payments` with no hop, and
/// still reaches `planner`.
async fn a_grant_on_one_agent_does_not_reach_another() -> u64 {
    crate::testkit::install_test_seams();
    let h = harness_granting(Outcome::Answers(200, backend_ok()), true, &["planner"]).await;
    let (status, body) = call_agent(&h, "payments", &envelope()).await;
    assert!(
        (400..500).contains(&status),
        "no grant on `payments` is a refusal: {status} {body}"
    );
    assert!(h.sent().is_empty(), "and no hop was made toward it");
    assert!(
        !contains(&h.all_wire(), LEASED.as_bytes()),
        "and busbar's own credential for it was never spent"
    );
    let (status, body) = call_agent(&h, "planner", &envelope()).await;
    assert_eq!(status, 200, "the granted agent is reached: {body}");
    assert_eq!(h.sent().len(), 1);
    2
}

/// ADMIT: a caller whose group allows one request a day (the limit written the way an operator
/// writes it) is served once and refused the second time with a `429`, and the refused call makes no
/// hop.
async fn a_caller_over_its_limit_is_refused_before_the_hop() -> u64 {
    crate::testkit::install_test_seams();
    let limits = vec![serde_yaml::from_str("{ requests: 1, per: day }").expect("a group limit")];
    let h = harness_priced(Outcome::AnswersCorrelated(200, backend_ok()), None, limits).await;
    let (status, body) = call(&h).await;
    assert_eq!(status, 200, "within the limit the call is served: {body}");
    assert_eq!(h.sent().len(), 1);
    let (status, body) = call(&h).await;
    assert_eq!(status, 429, "over the limit the call is refused: {body}");
    assert_eq!(h.sent().len(), 1, "and the refused call made no hop");
    2
}

/// ROUTE: a hop the transport cannot complete is answered, inside the unit, as the upstream's fault
/// (`502`, `-32006`) — never a silent empty task.
async fn a_failed_hop_is_answered_inside_the_unit() -> u64 {
    let h = deployment(Outcome::Fails("connection refused".to_string())).await;
    let (status, body) = call(&h).await;
    assert_eq!(status, 502, "a failed hop is an upstream fault: {body}");
    assert_eq!(
        body.pointer("/error/code").and_then(|v| v.as_i64()),
        Some(-32006),
        "{body}"
    );
    assert!(body.pointer("/result").is_none(), "and no result: {body}");
    assert_eq!(h.sent().len(), 1, "the one hop was attempted once");
    1
}

/// METER: one served hop writes exactly ONE metering row and charges exactly ONE request to the
/// key that presented it.
async fn a_served_hop_meters_exactly_one_request() -> u64 {
    crate::testkit::install_test_seams();
    let h = harness_billed(Outcome::Answers(200, backend_ok()), false).await;
    let (status, body) = call(&h).await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(
        h.gov.flush_metering(),
        1,
        "the hop is metered exactly once, and not a second time by the relay"
    );
    assert_eq!(
        requests_charged_to(&h, &caller_of(&h)),
        1,
        "one request charged for one hop"
    );
    1
}

/// AUDIT: the served hop lands exactly ONE `agent.call` row, applied, in the admin audit ring for
/// the calling principal.
async fn a_served_hop_is_audited_once() -> u64 {
    let engine = crate::testkit::engine_boot::engine();
    let h = deployment(Outcome::Answers(200, backend_ok())).await;
    let before = engine.audit_high_water_seq();
    let (status, body) = call(&h).await;
    assert_eq!(status, 200, "{body}");
    let caller = caller_of(&h);
    let rows: Vec<_> = engine
        .audit_entries()
        .into_iter()
        .filter(|e| {
            e.seq > before
                && e.action == crate::a2a::receive::AUDIT_ACTION
                && e.principal == caller.id
        })
        .collect();
    assert_eq!(rows.len(), 1, "exactly one audit row for the hop: {rows:?}");
    assert_eq!(rows[0].resource, "agent:planner", "{rows:?}");
    assert_eq!(
        rows[0].outcome,
        busbar_contract::vocab::OUTCOME_APPLIED,
        "{rows:?}"
    );
    1
}

/// EXIT: a hop that can never complete ends the task ONCE, as `failed` — not left `submitted`.
async fn a_failed_hop_ends_the_task_once() -> u64 {
    let h = deployment(Outcome::Fails("connection refused".to_string())).await;
    let (status, body) = call(&h).await;
    assert_eq!(status, 502, "{body}");
    let id = task_named_by(&body);
    assert!(!id.is_empty(), "the refusal names the task: {body}");
    let task = crate::taskstore::TASKS
        .get_unscoped(&id)
        .expect("the task busbar opened is in the working set");
    assert_eq!(task.state, "failed", "one terminal, and it is `failed`");
    assert_eq!(h.sent().len(), 1, "one hop, one end");
    1
}

// ── THE CORE CAPABILITIES ───────────────────────────────────────────────────────────────────────

/// AUDIT-CHAIN: the task the served call opened leaves a hash chain that recomputes, opening at a
/// genesis `task.submitted` with no predecessor and carrying the delegation.
async fn the_served_tasks_chain_verifies_from_its_genesis() -> u64 {
    crate::testkit::install_test_seams();
    let (ledger, _guard) = with_ledger().await;
    let h = harness(Outcome::Answers(200, backend_ok()), false).await;
    let (status, body) = call(&h).await;
    assert_eq!(status, 200, "{body}");
    let id = body
        .pointer("/result/id")
        .and_then(|v| v.as_str())
        .expect("the answer names busbar's task")
        .to_string();
    let events = await_chain_with(&ledger, &id, busbar_contract::vocab::EV_DELEGATED).await;
    crate::taskstore::TASKS.clear_sink_for_test();
    crate::taskstore::verify_chain(&events).expect("the per-task chain recomputes");
    assert_eq!(
        events.first().map(|e| e.kind.as_str()),
        Some(busbar_contract::vocab::EV_SUBMITTED),
        "{events:?}"
    );
    assert_eq!(events[0].seq, 1, "the chain opens at seq 1");
    assert!(
        events[0].prev_hash.is_empty(),
        "a genesis event links to nothing"
    );
    1
}

/// GOVERNANCE-BUDGET: the served hop's spend is attributed to the PRESENTING key — its own ledger
/// carries the request, and another key of the same registry carries nothing.
async fn a_served_hop_is_charged_to_the_presenting_key() -> u64 {
    crate::testkit::install_test_seams();
    let h = harness_billed(Outcome::Answers(200, backend_ok()), false).await;
    let (bystander, _secret) = h
        .gov
        .create_key(Default::default(), busbar_substrate_values::store::now())
        .expect("a second key");
    let (status, body) = call(&h).await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(
        requests_charged_to(&h, &caller_of(&h)),
        1,
        "the hop is charged to the key that presented it"
    );
    assert_eq!(
        requests_charged_to(&h, &bystander),
        0,
        "and to no other key"
    );
    1
}

/// METRICS: the served hop appears on the real exposition as an upstream attempt naming the agent
/// it was issued to (a registration name no other witness or battery uses).
async fn a_served_hop_counts_an_upstream_attempt() -> u64 {
    const AGENT: &str = "servedwitnessmetrics";
    crate::testkit::install_test_seams();
    let h = harness_full(
        Outcome::AnswersCorrelated(200, backend_ok()),
        false,
        &[AGENT],
        None,
        &[(AGENT, BACKEND)],
        &[],
        false,
    )
    .await;
    let (status, body) = call_agent(&h, AGENT, &envelope()).await;
    assert_eq!(status, 200, "{body}");
    let (code, exposition) = crate::testkit::engine_boot::engine().scrape_exposition();
    assert_eq!(code, 200, "the exporter serves the exposition");
    let want = format!("pool=\"{AGENT}\"");
    assert!(
        exposition
            .lines()
            .any(|l| { l.starts_with("busbar_upstream_attempts_total") && l.contains(&want) }),
        "the served hop is on the exposition under its agent:\n{exposition}"
    );
    1
}

/// TRUST-PINNING: a registration the operator suspended is not served — `503`, and no hop.
async fn a_demoted_registration_is_not_served() -> u64 {
    let h = deployment(Outcome::Answers(200, backend_ok())).await;
    h.plane.with_registrations_mut(|regs| {
        for reg in regs.iter_mut() {
            reg.approval.suspend("the served witness suspends it");
        }
    });
    let (status, body) = call(&h).await;
    assert_eq!(status, 503, "a demoted agent is not serving: {body}");
    assert!(h.sent().is_empty(), "no hop for a suspended registration");
    1
}

/// NET-GUARD: the backend name is resolved exactly once, through the guard, and the transport is
/// handed the address the guard judged.
async fn the_judged_address_is_the_one_dialled() -> u64 {
    let h = deployment(Outcome::Answers(200, backend_ok())).await;
    let (status, body) = call(&h).await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(
        h.lookups.load(Ordering::SeqCst),
        1,
        "the name is looked up once, by the guard"
    );
    assert_eq!(
        h.sent()[0].addr,
        Some(BACKEND_ADDR),
        "the transport dials the judged address"
    );
    1
}

/// CATALOGUE: a caller granted no agent has nothing it may reach — the call is refused and nothing
/// is relayed.
async fn a_caller_granted_no_agent_reaches_none() -> u64 {
    crate::testkit::install_test_seams();
    let h = harness_granting(Outcome::Answers(200, backend_ok()), false, &[]).await;
    let (status, body) = call(&h).await;
    assert!(
        (400..500).contains(&status),
        "an agent outside the caller's catalogue is not served: {status} {body}"
    );
    assert!(h.sent().is_empty(), "and nothing was relayed");
    1
}
