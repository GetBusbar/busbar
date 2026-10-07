// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The kernel's `verify.*`, `content.scan` and `hook.call`: the caller's own verify cache, and the
//! hook stage of the unit the crossing serves, run over the hooks its route leg bound (its pool,
//! its generation), never over anything the plane names.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::time::Duration;

use busbar_contract::abi::mechanism::KindCode;
use busbar_contract::hooks::{
    BudgetBucketState, Candidate, PolicyResult, RewriteReply, RoutingContext, RoutingDecision,
    RoutingPolicy, RoutingRequest, TransformOutcome,
};

use super::*;
use crate::config::PolicyOnError;
use crate::hooks::ResolvedPolicy;
use crate::host_units::UnitRecord;
use crate::plane_driver::{
    Bind, BoundHooks, CallerFacts, CallerKey, GatedHooks, HookBinder, HookOrder, RoutedScope,
    SessionStage, UnitHooks, CONTENT_ROLE, GATE_UNAVAILABLE, GATE_UNAVAILABLE_STATUS,
};

fn caller(instance: &str) -> Caller {
    Caller {
        instance: Arc::from(instance),
        plugin: Arc::from("the-plugin"),
        kind: KindCode::Plane,
    }
}

fn services(clock: &Arc<AtomicU64>) -> KernelServices {
    let c = Arc::clone(clock);
    let s = KernelServices::new().with_wall_clock(Arc::new(move || c.load(Ordering::SeqCst)));
    s.admit("inst", InstanceFacts::default()).unwrap();
    s.admit("other", InstanceFacts::default()).unwrap();
    s
}

/// A [`Later`] answered into a channel the test awaits.
fn answered() -> (Later, tokio::sync::oneshot::Receiver<Stored>) {
    let (tx, rx) = tokio::sync::oneshot::channel();
    (
        Box::new(move |s| {
            let _sent = tx.send(s);
        }),
        rx,
    )
}

fn now(r: Ran) -> Stored {
    match r {
        Ran::Now(s) => s,
        Ran::Later => panic!("the answer pended"),
    }
}

// ── verify ───────────────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn verify_is_the_callers_own_cache_hit_lead_or_follow() {
    let clock = Arc::new(AtomicU64::new(1_000));
    let s = services(&clock);
    let me = caller("inst");
    assert_eq!(
        now(s.verify_lookup(&me, b"card", answered().0)).value,
        svc::VERIFY_LEAD
    );
    let (later, follower) = answered();
    assert!(matches!(s.verify_lookup(&me, b"card", later), Ran::Later));
    assert_eq!(
        s.verify_store(&me, b"card", b"ok", 0).outcome,
        Outcome::Ready
    );
    let followed = follower.await.unwrap();
    assert_eq!(
        (followed.value, followed.bytes),
        (svc::VERIFY_FOLLOW, b"ok".to_vec())
    );
    let hit = now(s.verify_lookup(&me, b"card", answered().0));
    assert_eq!((hit.value, hit.bytes), (svc::VERIFY_HIT, b"ok".to_vec()));
    // Another instance never reads it.
    assert_eq!(
        now(s.verify_lookup(&caller("other"), b"card", answered().0)).value,
        svc::VERIFY_LEAD
    );
}

/// RED: an instance the kernel never admitted reaches no cache.
#[test]
fn verify_from_an_instance_never_admitted_is_refused() {
    let s = services(&Arc::new(AtomicU64::new(0)));
    let stranger = caller("stranger");
    let r = now(s.verify_lookup(&stranger, b"k", Box::new(|_| {})));
    assert_eq!((r.outcome, r.error), (Outcome::Refused, NOT_ADMITTED));
    let r = s.verify_store(&stranger, b"k", b"v", 0);
    assert_eq!((r.outcome, r.error), (Outcome::Refused, NOT_ADMITTED));
}

/// RED: a leader that never stores loses its lead at the tick, to its first follower.
#[tokio::test]
async fn the_verify_tick_hands_a_lapsed_lead_to_a_follower() {
    let clock = Arc::new(AtomicU64::new(0));
    let s = services(&clock);
    let me = caller("inst");
    let _ = now(s.verify_lookup(&me, b"k", answered().0));
    let (later, follower) = answered();
    assert!(matches!(s.verify_lookup(&me, b"k", later), Ran::Later));
    clock.store(crate::host_verify::LEAD_MS, Ordering::SeqCst);
    s.verify_tick();
    assert_eq!(follower.await.unwrap().value, svc::VERIFY_LEAD);
}

// ── the hook stage ───────────────────────────────────────────────────────────────────────────

/// A hook that rejects any request whose prompt carries `secret` (status 451), records the pool it
/// was asked over, and as a rewrite hook rewrites to `word` (abstaining when `word` is empty).
struct Screen {
    name: &'static str,
    word: &'static str,
    pools: Mutex<Vec<String>>,
}

impl Screen {
    fn new(name: &'static str, word: &'static str) -> Arc<Self> {
        Arc::new(Self {
            name,
            word,
            pools: Mutex::default(),
        })
    }
}

fn carries_secret(req: &RoutingRequest<'_>) -> bool {
    req.prompt
        .as_ref()
        .is_some_and(|p| p.messages.iter().any(|(_, t)| t.contains("secret")))
}

#[async_trait::async_trait]
impl RoutingPolicy for Screen {
    async fn decide(
        &self,
        req: &RoutingRequest<'_>,
        _: &[Candidate<'_>],
        ctx: &RoutingContext<'_>,
        _: Duration,
    ) -> PolicyResult {
        self.pools.lock().unwrap().push(ctx.pool.to_string());
        Ok(if carries_secret(req) {
            RoutingDecision::Reject {
                status: 451,
                message: "screened".into(),
            }
        } else {
            RoutingDecision::Abstain
        })
    }

    async fn transform(&self, req: &RoutingRequest<'_>, _: Duration) -> TransformOutcome {
        if carries_secret(req) {
            return TransformOutcome::Reject {
                status: 409,
                message: "no".into(),
            };
        }
        if self.word.is_empty() {
            return TransformOutcome::Abstain;
        }
        TransformOutcome::Rewrite(RewriteReply {
            messages: vec![serde_json::json!(self.word)],
            tools: Vec::new(),
        })
    }

    fn name(&self) -> &'static str {
        self.name
    }
}

/// A gate whose backend is down.
struct Down;

#[async_trait::async_trait]
impl RoutingPolicy for Down {
    async fn decide(
        &self,
        _: &RoutingRequest<'_>,
        _: &[Candidate<'_>],
        _: &RoutingContext<'_>,
        _: Duration,
    ) -> PolicyResult {
        Err("down".into())
    }

    fn name(&self) -> &'static str {
        "down"
    }
}

struct NoCaller;

impl CallerFacts for NoCaller {
    fn key(&self, _: &str) -> Option<CallerKey> {
        None
    }
    fn in_groups(&self, _: Option<&str>, _: &[String]) -> bool {
        true
    }
    fn rate_headroom(&self, _: &str, _: &str) -> Option<f64> {
        None
    }
    fn budget(&self, _: &str) -> Vec<BudgetBucketState> {
        Vec::new()
    }
    fn hook_read(&self, _: &str, _: Option<&str>, _: &str, _: bool) {}
}

fn gate(policy: Arc<dyn RoutingPolicy>, on_error: PolicyOnError) -> (u16, ResolvedPolicy) {
    (
        0,
        ResolvedPolicy::Policy {
            policy,
            on_error,
            on_error_chain: Vec::new(),
            timeout: Duration::from_secs(5),
            send_prompt: true,
            send_user: false,
            on_empty: PolicyOnError::Reject,
        },
    )
}

/// The generation's hooks: the global `gates` and `rewrites`, and a `pool-a`-only gate.
fn hooks(
    gates: Vec<(u16, ResolvedPolicy)>,
    rewrites: Vec<Arc<dyn RoutingPolicy>>,
    pool_a: Option<Arc<dyn RoutingPolicy>>,
) -> BoundHooks {
    let mut pool_gates = HashMap::new();
    if let Some(p) = pool_a {
        pool_gates.insert("pool-a".to_string(), vec![gate(p, PolicyOnError::Weighted)]);
    }
    BoundHooks {
        rewrites: rewrites
            .into_iter()
            .map(|h| (Duration::from_secs(5), h))
            .collect(),
        gates,
        pool_rewrites: HashMap::new(),
        pool_gates,
        pool_policies: HashMap::new(),
        taps: crate::plane_driver::StageTaps::default(),
        requested: crate::hooks::RequestedSignals::default(),
        next_request_id: Arc::new(|| 7),
        caller: Arc::new(NoCaller),
        dialects: vec!["d0".into()],
    }
}

/// Unit `unit` in flight on `instance`, its stage over `pool` bound by `binder`.
fn staged(s: &KernelServices, unit: u64, instance: &str, pool: &str, binder: Arc<dyn HookBinder>) {
    let scope = RoutedScope {
        pool: pool.to_string(),
        container: pool.to_string(),
    };
    staged_over(s, (unit, instance), scope, binder);
}

/// Unit `unit` in flight on `instance`, its stage over the route `scope` bound by `binder`.
fn staged_over(
    s: &KernelServices,
    (unit, instance): (u64, &str),
    scope: RoutedScope,
    binder: Arc<dyn HookBinder>,
) {
    s.units().admitted(
        unit,
        UnitRecord {
            principal: None,
            depth: 0,
        },
    );
    let stage = SessionStage::new(
        Arc::from(instance),
        tokio::runtime::Handle::current(),
        Some(binder),
        (scope, None, "d0".to_string()),
    );
    assert!(s.units().staged(unit, Arc::new(stage)));
}

fn ask(stage: u32, from: u32, text: &str) -> HookAsk {
    HookAsk {
        stage,
        from,
        system: None,
        messages: vec![("user".into(), text.into())],
    }
}

async fn call(s: &KernelServices, unit: Option<u64>, a: HookAsk) -> Stored {
    let (later, rx) = answered();
    match s.hook_call(&caller("inst"), unit, a, later) {
        Ran::Now(stored) => stored,
        Ran::Later => rx.await.unwrap(),
    }
}

async fn scan(s: &KernelServices, unit: Option<u64>, content: &[u8]) -> Stored {
    let (later, rx) = answered();
    match s.content_scan(&caller("inst"), unit, content, later) {
        Ran::Now(stored) => stored,
        Ran::Later => rx.await.unwrap(),
    }
}

#[tokio::test]
async fn content_scan_passes_or_blocks_through_the_units_gates() {
    let s = services(&Arc::new(AtomicU64::new(0)));
    let screen = Screen::new("screen", "");
    staged(
        &s,
        1,
        "inst",
        "pool-z",
        Arc::new(hooks(
            vec![gate(screen.clone(), PolicyOnError::Weighted)],
            vec![],
            None,
        )),
    );
    let pass = scan(&s, Some(1), b"a tool result").await;
    assert_eq!(
        (pass.outcome, pass.value),
        (Outcome::Ready, svc::CONTENT_PASS)
    );
    let block = scan(&s, Some(1), b"the secret").await;
    assert_eq!(
        (block.outcome, block.value),
        (Outcome::Ready, svc::CONTENT_BLOCK)
    );
    assert!(block.bytes.is_empty(), "a gate rewrites nothing");
    assert_eq!(CONTENT_ROLE, "content");
}

#[tokio::test]
async fn a_gate_stops_with_its_clamped_status_and_words_and_passes_otherwise() {
    let s = services(&Arc::new(AtomicU64::new(0)));
    let screen = Screen::new("screen", "");
    staged(
        &s,
        1,
        "inst",
        "pool-z",
        Arc::new(hooks(
            vec![gate(screen, PolicyOnError::Weighted)],
            vec![],
            None,
        )),
    );
    let pass = call(&s, Some(1), ask(svc::HOOK_GATE, 0, "hello")).await;
    assert_eq!((pass.outcome, pass.value), (Outcome::Ready, 0));
    let stop = call(&s, Some(1), ask(svc::HOOK_GATE, 0, "a secret")).await;
    assert_eq!((stop.value, stop.bytes.as_slice()), (451, &b"screened"[..]));
}

/// A gate that cannot answer decides by its own `on_error`: `reject` stops (RED), anything else
/// passes.
#[tokio::test]
async fn a_gate_that_cannot_answer_decides_by_its_on_error() {
    let s = services(&Arc::new(AtomicU64::new(0)));
    staged(
        &s,
        1,
        "inst",
        "",
        Arc::new(hooks(
            vec![gate(Arc::new(Down), PolicyOnError::Reject)],
            vec![],
            None,
        )),
    );
    staged(
        &s,
        2,
        "inst",
        "",
        Arc::new(hooks(
            vec![gate(Arc::new(Down), PolicyOnError::Weighted)],
            vec![],
            None,
        )),
    );
    let stop = call(&s, Some(1), ask(svc::HOOK_GATE, 0, "x")).await;
    assert_eq!(
        (stop.value, stop.bytes),
        (
            u64::from(GATE_UNAVAILABLE_STATUS),
            GATE_UNAVAILABLE.as_bytes().to_vec()
        )
    );
    assert_eq!(
        call(&s, Some(2), ask(svc::HOOK_GATE, 0, "x")).await.value,
        0
    );
}

/// The rewrite chain answers the first rewriting hook as `1 + i` with its rewrite; the plane
/// resumes from there; a reject stops it.
#[tokio::test]
async fn the_rewrite_chain_resumes_after_each_rewrite() {
    let s = services(&Arc::new(AtomicU64::new(0)));
    staged(
        &s,
        1,
        "inst",
        "",
        Arc::new(hooks(
            vec![],
            vec![Screen::new("quiet", ""), Screen::new("rw", "shorter")],
            None,
        )),
    );
    let first = call(&s, Some(1), ask(svc::HOOK_REWRITE, 0, "long")).await;
    assert_eq!(first.value, 2, "hook 1 rewrote");
    let doc: serde_json::Value = serde_json::from_slice(&first.bytes).unwrap();
    assert_eq!(
        doc,
        serde_json::json!({"messages": ["shorter"], "tools": []})
    );
    let done = call(&s, Some(1), ask(svc::HOOK_REWRITE, 2, "shorter")).await;
    assert_eq!(done.value, 0, "no hook after it rewrote");
    let stop = call(&s, Some(1), ask(svc::HOOK_REWRITE, 0, "secret")).await;
    assert_eq!((stop.value, stop.bytes.as_slice()), (409, &b"no"[..]));
}

/// SECURITY (RED): the gates are the unit's own pool's, from what the kernel recorded: a
/// `pool-a` gate stops a `pool-a` unit and never a `pool-b` one, whatever the prompt says.
#[tokio::test]
async fn the_gate_scope_is_the_units_recorded_pool() {
    let s = services(&Arc::new(AtomicU64::new(0)));
    let screen = Screen::new("pool-gate", "");
    let binder: Arc<dyn HookBinder> = Arc::new(hooks(vec![], vec![], Some(screen.clone())));
    staged(&s, 1, "inst", "pool-a", Arc::clone(&binder));
    staged(&s, 2, "inst", "pool-b", binder);
    assert_eq!(
        call(&s, Some(1), ask(svc::HOOK_GATE, 0, "pool-b secret"))
            .await
            .value,
        451
    );
    assert_eq!(
        call(&s, Some(2), ask(svc::HOOK_GATE, 0, "pool-a secret"))
            .await
            .value,
        0
    );
    assert_eq!(*screen.pools.lock().unwrap(), vec!["pool-a".to_string()]);
}

/// A binder that binds a stricter generation each time it is asked.
struct Generations {
    binds: AtomicUsize,
    first: BoundHooks,
    later: BoundHooks,
}

impl HookBinder for Generations {
    fn bind(&self, bind: &Bind<'_>) -> Option<UnitHooks> {
        if self.binds.fetch_add(1, Ordering::SeqCst) == 0 {
            self.first.bind(bind)
        } else {
            self.later.bind(bind)
        }
    }
}

/// RED: a unit's stage binds once; every later call (a resumed chain included) runs over that
/// binding, never a later generation's.
#[tokio::test]
async fn a_units_stage_stays_pinned_to_the_generation_it_bound() {
    let s = services(&Arc::new(AtomicU64::new(0)));
    let gens = Arc::new(Generations {
        binds: AtomicUsize::new(0),
        first: hooks(vec![], vec![Screen::new("rw", "v1")], None),
        later: hooks(
            vec![gate(Screen::new("strict", ""), PolicyOnError::Weighted)],
            vec![Screen::new("rw", "v2")],
            None,
        ),
    });
    staged(&s, 1, "inst", "", gens.clone());
    let first = call(&s, Some(1), ask(svc::HOOK_REWRITE, 0, "x")).await;
    assert_eq!(first.value, 1);
    assert!(String::from_utf8_lossy(&first.bytes).contains("v1"));
    assert_eq!(
        call(&s, Some(1), ask(svc::HOOK_GATE, 0, "secret"))
            .await
            .value,
        0
    );
    assert_eq!(
        call(&s, Some(1), ask(svc::HOOK_REWRITE, 1, "v1"))
            .await
            .value,
        0
    );
    assert_eq!(gens.binds.load(Ordering::SeqCst), 1);
}

/// RED, one arm each: no unit served, a unit not in flight, a unit whose stage is not stated yet,
/// and another instance's unit are each refused before any hook runs.
#[tokio::test]
async fn the_stage_refuses_every_unit_it_does_not_hold() {
    let s = services(&Arc::new(AtomicU64::new(0)));
    let screen = Screen::new("screen", "");
    let binder: Arc<dyn HookBinder> = Arc::new(hooks(
        vec![gate(screen.clone(), PolicyOnError::Weighted)],
        vec![],
        None,
    ));
    staged(&s, 3, "other", "", Arc::clone(&binder));
    s.units().admitted(
        4,
        UnitRecord {
            principal: None,
            depth: 0,
        },
    );
    for (unit, why) in [
        (None, STAGE_NO_UNIT),
        (Some(9), STAGE_NO_UNIT),
        (Some(4), STAGE_NOT_BOUND),
        (Some(3), STAGE_NOT_YOURS),
    ] {
        let r = call(&s, unit, ask(svc::HOOK_GATE, 0, "secret")).await;
        assert_eq!((r.outcome, r.error), (Outcome::Refused, why), "{unit:?}");
        let r = scan(&s, unit, b"secret").await;
        assert_eq!((r.outcome, r.error), (Outcome::Refused, why), "{unit:?}");
    }
    let r = now(s.hook_call(
        &caller("stranger"),
        Some(3),
        ask(svc::HOOK_GATE, 0, "x"),
        answered().0,
    ));
    assert_eq!((r.outcome, r.error), (Outcome::Refused, NOT_ADMITTED));
    assert!(screen.pools.lock().unwrap().is_empty(), "no hook ran");
    // A unit that ended takes its stage with it, and a stage stated for it after is dropped.
    s.units().ended(3);
    assert!(s.units().stage(3).is_none());
    let late = SessionStage::new(
        Arc::from("other"),
        tokio::runtime::Handle::current(),
        None,
        (RoutedScope::default(), None, String::new()),
    );
    assert!(!s.units().staged(3, Arc::new(late)));
}

/// With no hook bound, a gate passes and a chain is unchanged: a unit no hook binds pays nothing.
#[tokio::test]
async fn a_unit_no_hook_binds_passes_unchanged() {
    let s = services(&Arc::new(AtomicU64::new(0)));
    s.units().admitted(
        1,
        UnitRecord {
            principal: None,
            depth: 0,
        },
    );
    assert!(s.units().staged(
        1,
        Arc::new(SessionStage::new(
            Arc::from("inst"),
            tokio::runtime::Handle::current(),
            None,
            (RoutedScope::default(), None, String::new()),
        ))
    ));
    assert_eq!(
        call(&s, Some(1), ask(svc::HOOK_GATE, 0, "secret"))
            .await
            .value,
        0
    );
    assert_eq!(
        call(&s, Some(1), ask(svc::HOOK_REWRITE, 0, "x"))
            .await
            .value,
        0
    );
    assert_eq!(scan(&s, Some(1), b"secret").await.value, svc::CONTENT_PASS);
}

/// A gate-first binder: `screen` is attached to the entry `srv-a` only; the routed order binds a
/// gate that blocks everything, so a stage that bound the wrong order would block both units.
struct EntryGates {
    screen: Arc<Screen>,
    routed: BoundHooks,
}

impl HookBinder for EntryGates {
    fn order(&self) -> HookOrder {
        HookOrder::Gated
    }

    fn bind(&self, bind: &Bind<'_>) -> Option<UnitHooks> {
        self.routed.bind(bind)
    }

    fn bind_gated(&self, container: &str, _: Option<&str>) -> Option<GatedHooks> {
        (container == "srv-a").then(|| GatedHooks {
            request_id: 9,
            gates: vec![gate(self.screen.clone(), PolicyOnError::Weighted)],
            rewrites: Vec::new(),
            key: None,
            scan: None,
        })
    }
}

/// RED: a gate-first plane's unit runs its in-session content through the hooks attached to the
/// entry its route resolved (its container), as its request stage does; another entry's unit
/// passes, and the routed order's hooks are never bound.
#[tokio::test]
async fn a_gate_first_units_stage_is_its_entrys_hooks() {
    let s = services(&Arc::new(AtomicU64::new(0)));
    let screen = Screen::new("entry-gate", "");
    let everything = Screen::new("routed-gate", "");
    let binder: Arc<dyn HookBinder> = Arc::new(EntryGates {
        screen: screen.clone(),
        routed: hooks(
            vec![gate(everything.clone(), PolicyOnError::Weighted)],
            vec![],
            None,
        ),
    });
    for (unit, container) in [(1, "srv-a"), (2, "srv-b")] {
        let scope = RoutedScope {
            pool: format!("lane-{container}"),
            container: container.to_string(),
        };
        staged_over(&s, (unit, "inst"), scope, Arc::clone(&binder));
    }
    let blocked = scan(&s, Some(1), b"the secret").await;
    assert_eq!(
        (blocked.outcome, blocked.value),
        (Outcome::Ready, svc::CONTENT_BLOCK)
    );
    assert_eq!(
        call(&s, Some(1), ask(svc::HOOK_GATE, 0, "a secret"))
            .await
            .value,
        451
    );
    let other = scan(&s, Some(2), b"the secret").await;
    assert_eq!(
        (other.outcome, other.value),
        (Outcome::Ready, svc::CONTENT_PASS)
    );
    assert_eq!(
        *screen.pools.lock().unwrap(),
        vec!["srv-a".to_string(), "srv-a".to_string()],
        "the entry's gate is asked over its container"
    );
    assert!(
        everything.pools.lock().unwrap().is_empty(),
        "a gate-first stage never binds the routed order"
    );
}
