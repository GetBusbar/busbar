//! Tests for `egress_bindings.rs`. Lifted out of the implementation file so its line count measures
//! implementation and nothing else; still a direct child module, so `use super::*` reaches the
//! private items it always did.
//!
//! Every cell here drives a binding through the EGRESS UNIT'S OWN PORT — `&dyn Capacity`, `&dyn
//! Clock`, `&dyn Telemetry`, `&dyn Journal`, `&dyn EgressAuth` — never through the concrete type.
//! That is the same shape the breaker adapter's cells take and it is load-bearing for the same
//! reason: a binding asserted against its own inherent methods proves the methods, and what the
//! walk will actually call is the trait.

use super::*;
use busbar_contract::LaneId;
use busbar_substrate::plane_host::{
    AuthStyleInput, ClientSettingsInput, FailoverInput, LaneInput, OnExhaustedInput,
    PlaneBuildInput, PoolInput, PoolMemberInput,
};

// ── fixtures ────────────────────────────────────────────────────────────────────────────────────

/// A lane as a boot fixture declares one, on a named dialect with a named credential.
fn lane(model: &str, protocol: &str, key: &str, max_concurrent: usize) -> LaneInput {
    LaneInput {
        model: model.to_string(),
        provider: "acme".to_string(),
        protocol: protocol.to_string(),
        base_url: "https://upstream.invalid".to_string(),
        path: None,
        path_base: None,
        upstream_model: None,
        api_key: busbar_api::Redacted::new(key.to_string()),
        auth_style: AuthStyleInput::Default,
        scope: None,
        token_url: None,
        subject: None,
        error_map: std::collections::HashMap::new(),
        health: None,
        allow_metadata_hosts: Vec::new(),
        context_max: None,
        lane_default_max_tokens: None,
        attempt_timeout_ms: None,
        reasoning: false,
        prompt_caching: false,
        max_concurrent,
        limited: false,
        budget: -1,
    }
}

/// A build carrier holding these lanes and one pool over all of them.
fn input(lanes: Vec<LaneInput>) -> PlaneBuildInput {
    let members = lanes
        .iter()
        .enumerate()
        .map(|(idx, l)| PoolMemberInput {
            model: l.model.clone(),
            lane_idx: idx,
            weight: 1,
            reasoning: None,
            attempt_timeout_ms: None,
            tier: None,
            cost_per_mtok: None,
            tags: Vec::new(),
        })
        .collect();
    PlaneBuildInput {
        lanes,
        pools: vec![PoolInput {
            name: "pool".to_string(),
            members,
            failover: None,
            affinity: None,
            on_exhausted: OnExhaustedInput::Status503,
            upstream_credentials: None,
            breaker: None,
        }],
        upstream_credentials: UpstreamCreds::default(),
        allow_metadata_hosts: Vec::new(),
        allow_all_metadata: false,
        blocked_metadata_hosts: Vec::new(),
        client_settings: ClientSettingsInput {
            upstream_request_timeout_secs: 600,
            pool_max_idle_per_host: 4,
            pool_idle_timeout_secs: 300,
            http1_only: false,
            h2_prior_knowledge: false,
        },
        global_default_max_tokens: 4_096,
        reasoning_budgets: [1_024, 4_096, 8_192, 16_384],
        default_failover: Some(FailoverInput {
            timeout_secs: 120,
            exclusions: None,
            max_hops: 3,
        }),
    }
}

/// A lane-name seater, leaking once per distinct name exactly as the root's interner does at boot.
fn seater() -> impl FnMut(&str) -> &'static str {
    let mut seen: std::collections::HashMap<String, &'static str> =
        std::collections::HashMap::new();
    move |name: &str| {
        *seen
            .entry(name.to_string())
            .or_insert_with(|| Box::leak(name.to_string().into_boxed_str()))
    }
}

/// A verified destination on one lane, as the trust unit seals one.
fn sealed(lane: &'static str) -> VerifiedDestination {
    VerifiedDestination::seal(
        &busbar_caps::TrustToken::mint(&busbar_caps::KernelSeal::acquire_for_kernel()),
        busbar_contract::DestinationFacts::Upstream {
            transport: "http",
            address: busbar_contract::UpstreamAddress::Socket {
                authority: "upstream.invalid",
                sni: None,
                extras: &[],
            },
            lane: LaneId::new(lane),
        },
        "http",
        None,
    )
}

// ── the pool's own concurrency ──────────────────────────────────────────────────────────────────

/// A lane store whose members' semaphores are the store's own, so a permit taken through the unit's
/// port is a permit the store has counted.
fn a_store(lane_caps: &[usize]) -> Arc<dyn LaneRuntime> {
    Arc::new(busbar_core::store::HealthState::new(
        lane_caps
            .iter()
            .enumerate()
            .map(|(idx, &max)| {
                busbar_core::store::LaneData::for_test(&format!("lane-{idx}"), "acme", max)
            })
            .collect(),
    ))
}

/// The permit count an UNBOUNDED member carries — the store's own sentinel, which is what makes it
/// never at capacity and therefore never something a waiter waits on.
const UNBOUNDED: usize = tokio::sync::Semaphore::MAX_PERMITS;

/// The permit the unit takes IS the permit the store counts.
///
/// Taken through `&dyn Capacity`, exhausting the member's declared cap; the store then refuses the
/// next taker on its own path. Two permit books over one upstream would each say the cap was free,
/// which is the regression this forward exists to make impossible.
#[tokio::test]
async fn a_slot_taken_through_the_port_is_a_slot_the_store_has_counted() {
    let store = a_store(&[1]);
    let capacity = LaneCapacity::new(Arc::clone(&store));
    let port: &dyn Capacity = &capacity;
    let dest = destination_for(0);

    let held = port.try_acquire(dest).expect("the member's one slot");
    assert_eq!(held.destination(), dest);
    assert!(
        store.try_acquire(0).is_none(),
        "the store must see its own slot as taken, because it is the same slot"
    );

    drop(held);
    assert!(
        store.try_acquire(0).is_some(),
        "dropping the handle frees the store's slot; nothing here calls a release verb"
    );
}

/// The bounded wait resolves on the member whose slot freed, and hands that member's slot over.
///
/// The store hands one freed slot to one waiter; this drives that through the port with two members
/// at capacity and frees exactly one. The answer names the member that freed, not the first member
/// asked about — a wait that answered with the wrong member would dispatch onto an upstream that is
/// still saturated.
#[tokio::test]
async fn the_bounded_wait_answers_with_the_member_whose_slot_freed() {
    let store = a_store(&[1, 1]);
    let capacity = LaneCapacity::new(Arc::clone(&store));
    let port: &dyn Capacity = &capacity;

    let first = store.try_acquire(0).expect("member 0's one slot");
    let second = store.try_acquire(1).expect("member 1's one slot");

    let members = [destination_for(0), destination_for(1)];
    let waiting = port.acquire_any(&members);
    drop(second);

    let (destination, permit) = waiting.await.expect("the freed slot reaches the waiter");
    assert_eq!(
        destination,
        destination_for(1),
        "the wait answers with the member that freed a slot"
    );
    assert_eq!(permit.destination(), destination_for(1));
    drop(first);
}

/// A set with nothing to wait on resolves rather than parking forever.
///
/// An unbounded member counts nothing, so there is no slot for it to free and no queue for a waiter
/// to join. The port answers `None` — the terminal that asked then sheds — rather than holding the
/// one blocking await in the unit open on a wait that can never complete.
#[tokio::test]
async fn a_wait_on_members_that_count_nothing_resolves_instead_of_parking() {
    let store = a_store(&[UNBOUNDED]);
    let capacity = LaneCapacity::new(store);
    let port: &dyn Capacity = &capacity;

    assert!(
        port.acquire_any(&[destination_for(0)]).await.is_none(),
        "a member with no queue is not something a waiter can wait on"
    );
}

// ── the clock ───────────────────────────────────────────────────────────────────────────────────

/// The two readings agree with each other and the sleep is at least what was asked for.
///
/// Both readings are of one clock, so a deadline stated in seconds and a wait bounded in
/// milliseconds cannot disagree about when now is — which is what a walk that checks a
/// second-granular deadline before every attempt and then parks for a few hundred milliseconds
/// depends on.
#[tokio::test]
async fn the_two_readings_are_of_one_clock_and_the_sleep_is_never_short() {
    let clock: &dyn Clock = &NodeClock;

    let secs = clock.now_secs();
    let millis = clock.now_millis();
    assert_eq!(
        u128::from(secs),
        millis / 1_000,
        "the seconds reading must be the milliseconds reading, in seconds"
    );

    let before = clock.now_millis();
    clock.sleep(25).await;
    assert!(
        clock.now_millis() - before >= 25,
        "a wait completes no earlier than it was asked to"
    );
}

// ── the counters ────────────────────────────────────────────────────────────────────────────────

/// A host that keeps what it was told, so a cell can ask whether the emit reached it with the label
/// space intact.
#[derive(Debug, Default)]
struct RecordingHost(Mutex<Vec<String>>);

impl RecordingHost {
    fn emits(&self) -> Vec<String> {
        self.0.lock().unwrap_or_else(|p| p.into_inner()).clone()
    }
    fn push(&self, line: String) {
        self.0.lock().unwrap_or_else(|p| p.into_inner()).push(line);
    }
}

impl TelemetryHost for RecordingHost {
    fn request_finished(
        &self,
        _plane: &str,
        _ingress_protocol: &str,
        _pool: &str,
        _outcome: &'static str,
        _seconds: f64,
    ) {
    }
    fn telemetry_upstream_attempt(&self, pool_label: &str, lane: usize) {
        self.push(format!("attempt {pool_label} {lane}"));
    }
    fn telemetry_upstream_failure(&self, pool_label: &str, lane: usize, disposition: &'static str) {
        self.push(format!("failure {pool_label} {lane} {disposition}"));
    }
    fn telemetry_breaker_trip(&self, pool_label: &str, lane: usize) {
        self.push(format!("trip {pool_label} {lane}"));
    }
    fn telemetry_failover(&self, pool_label: &str, reason: &'static str) {
        self.push(format!("failover {pool_label} {reason}"));
    }
    fn telemetry_translation(&self, _from: &str, _to: &str) {}
    fn pool_label<'a>(&self, model: &'a str) -> &'a str {
        model
    }
}

/// Every counter the walk moves reaches the host, with the member in the label space the shipping
/// series already carries.
///
/// The member crosses as the lane index it has always been. This re-points the emitter, not the
/// series: a metric that changed its label space at a re-pointing would break every dashboard
/// reading it while looking, in a diff, like an ordinary edit.
#[test]
fn every_counter_reaches_the_host_in_the_label_space_the_series_already_has() {
    let host = Arc::new(RecordingHost::default());
    let telemetry = HostTelemetry::new(
        Arc::clone(&host) as Arc<dyn TelemetryHost>,
        Arc::new(PoolQueueDepth::new()),
    );
    let port: &dyn Telemetry = &telemetry;

    port.upstream_attempt("pool", destination_for(3));
    port.upstream_failure(
        "pool",
        destination_for(3),
        busbar_unit_egress::ports::disposition::TRANSIENT,
    );
    port.failover("pool", busbar_unit_egress::ports::net::TIMEOUT);
    port.breaker_trip("pool", destination_for(3));

    assert_eq!(
        host.emits(),
        vec![
            "attempt pool 3".to_string(),
            "failure pool 3 transient_upstream".to_string(),
            "failover pool timeout".to_string(),
            "trip pool 3".to_string(),
        ]
    );
}

/// The wait gauge is a DEPTH, and the balanced pair the unit's terminal makes on every exit reads
/// back as one.
///
/// The previous release published this by reading a live depth at scrape time rather than by
/// accumulating a delta, so the pair has to land somewhere readable as a number. It does, it
/// balances, and it never reads negative — a depth that went negative would put an unbalanced pair
/// on a dashboard instead of leaving the number readable.
#[test]
fn the_wait_gauge_reads_the_live_depth_and_never_goes_under() {
    let depth = Arc::new(PoolQueueDepth::new());
    let telemetry = HostTelemetry::new(
        Arc::new(RecordingHost::default()) as Arc<dyn TelemetryHost>,
        Arc::clone(&depth),
    );
    let port: &dyn Telemetry = &telemetry;

    assert_eq!(depth.depth("pool"), 0);
    port.queued("pool", 1);
    port.queued("pool", 1);
    assert_eq!(depth.depth("pool"), 2, "two parked requests read as two");
    port.queued("pool", -1);
    port.queued("pool", -1);
    assert_eq!(depth.depth("pool"), 0, "the pair balances on every exit");
    port.queued("pool", -1);
    assert_eq!(depth.depth("pool"), 0, "and it never reads under zero");
    assert_eq!(
        depth.depth("another-pool"),
        0,
        "a pool nothing ever parked in reads as empty rather than as absent"
    );
}

// ── the write-ahead journal ─────────────────────────────────────────────────────────────────────

/// One dispatch as the walk records it.
fn a_dispatch() -> Dispatched {
    Dispatched {
        leg: 1,
        attempt: 2,
        pool: "pool".to_string(),
        destination: destination_for(4),
        lane: Some(LaneId::new("fast")),
    }
}

/// A dispatch and its abandonment are DIFFERENT records, not one record and an absence.
///
/// The design requires an abandoned attempt to be explicit rather than inferred from a missing
/// settle, and a reader that had to infer it would have to know what a settle looks like. The two
/// bodies differ, and they differ in exactly one field — everything identifying WHICH dispatch this
/// was is the same on both, which is what lets a reader pair them.
#[test]
fn an_abandoned_dispatch_is_its_own_record_and_not_a_missing_one() {
    let record = a_dispatch();
    let dispatched = dispatch_body(&record, DISPATCHED);
    let abandoned = dispatch_body(&record, ABANDONED);

    assert_ne!(
        dispatched, abandoned,
        "the two must be distinguishable on the chain"
    );
    // Everything before the marker, which is the last field and is length-prefixed like every
    // other text one — so the eight prefix bytes come off with it.
    let shared = dispatched.len() - DISPATCHED.len() - 8;
    assert_eq!(
        dispatched[..shared],
        abandoned[..abandoned.len() - ABANDONED.len() - 8],
        "everything naming WHICH dispatch this was is identical on both, so a reader can pair them"
    );
}

/// The record carries what identifies the dispatch and nothing about what was in it.
///
/// Content is not here for the same reason it is not in a sealed audit record: the journal is a
/// financial record exempt from erasure, so anything put in it can never be taken out. The cell
/// states that as a property of the body rather than as a comment above it.
#[test]
fn the_dispatch_record_names_the_dispatch_and_carries_no_content() {
    let record = a_dispatch();
    let body = dispatch_body(&record, DISPATCHED);

    let text = String::from_utf8_lossy(&body).to_string();
    assert!(text.contains("pool"), "the cell it is recorded against");
    assert!(text.contains("fast"), "the lane it was sealed on");
    // The leg, the attempt and the member are fixed-width numbers, so they are asserted by the
    // body's own length rather than by looking for digits in bytes that are not text.
    assert_eq!(
        body.len(),
        8 + 8                       // leg, attempt
            + 8 + "pool".len()      // the cell, length-prefixed
            + 8                     // the member
            + 8 + "fast".len()      // the lane, length-prefixed
            + 8 + DISPATCHED.len(), // the marker, length-prefixed
        "the record is exactly the six fields; a seventh would be content"
    );
}

// ── the credential that decorates an outbound request ───────────────────────────────────────────

/// Two protocols this build declares whose schemes decorate DIFFERENTLY, chosen by asking the
/// declarations rather than by naming any of them.
///
/// The cell below is about a binding that has no arm for any provider, so the cell must have none
/// either: a fixture that spelled two dialect names would be proving the binding over the two the
/// author happened to pick, and would have to be edited every time the set of declared dialects
/// changed. This asks the registry for what it declares and takes the first two that answer
/// differently.
fn two_differently_decorating_declarations() -> (&'static str, &'static str) {
    let field_names = |protocol: &str| {
        let provider = busbar_substrate::egress_auth::resolve(protocol, None);
        let ctx = busbar_substrate::proto::SigningContext {
            host: "",
            canonical_uri: "",
            body: b"",
            timestamp_epoch: 0,
            upstream_creds: UpstreamCreds::default(),
        };
        provider.is_lane_constant().then(|| {
            provider
                .headers_for("probe", &ctx)
                .into_iter()
                .map(|(name, _)| name.as_str().to_string())
                .collect::<Vec<_>>()
        })
    };
    let mut declared: Vec<(&'static str, Vec<String>)> = busbar_llm::DECLS
        .iter()
        .filter_map(|decl| field_names(decl.name).map(|fields| (decl.name, fields)))
        .filter(|(_, fields)| !fields.is_empty())
        .collect();
    declared.dedup_by(|a, b| a.1 == b.1);
    assert!(
        declared.len() >= 2,
        "this build must declare at least two schemes that decorate differently"
    );
    let second = declared.pop().expect("two").0;
    let first = declared.remove(0).0;
    (first, second)
}

/// The decoration is the DIALECT'S declared scheme, resolved once, keyed by the lane's own secret.
///
/// Two lanes on two dialects with two different keys, decorated through one binding with no arm for
/// either — and the cell names neither dialect, because it asks the same declarations the binding
/// asks. Each comes back decorated with the fields its own dialect declares, carrying its own key.
#[test]
fn each_lane_is_decorated_by_its_own_declared_scheme_with_its_own_secret() {
    busbar_substrate::proto::register_test_protocols(busbar_llm::DECLS);
    let (one, another) = two_differently_decorating_declarations();
    let carrier = input(vec![
        lane("fast", one, "key-fast", 4),
        lane("other", another, "key-other", 4),
    ]);
    let mut seat = seater();
    let auth = DeclaredEgressAuth::resolve(&carrier, &mut seat);
    let port: &dyn EgressAuth = &auth;

    let decorate = |lane_name: &'static str| {
        let dest = sealed(lane_name);
        let mut request = OutboundRequest {
            fields: Vec::new(),
            body: b"{}",
            scheme: busbar_contract::SchemeKey::new("declared"),
            body_signature: None,
        };
        port.decorate(&dest, &mut request)
            .expect("a declared scheme decorates");
        request
            .fields
            .into_iter()
            .map(|(name, value)| (name, String::from_utf8_lossy(&value).to_string()))
            .collect::<Vec<_>>()
    };

    let fast = decorate("fast");
    let other = decorate("other");

    assert!(
        !fast.is_empty() && !other.is_empty(),
        "both declarations name a scheme and both decorated"
    );
    assert!(
        fast.iter().any(|(_, v)| v.contains("key-fast")),
        "the lane's OWN secret is what was substituted, got {fast:?}"
    );
    assert!(
        other.iter().any(|(_, v)| v.contains("key-other")),
        "and the other lane's own, got {other:?}"
    );
    assert_ne!(
        fast.iter().map(|(n, _)| n.clone()).collect::<Vec<_>>(),
        other.iter().map(|(n, _)| n.clone()).collect::<Vec<_>>(),
        "two declarations naming different schemes decorate with different fields, and the binding \
         was told neither name"
    );
}

/// A destination this node holds no credential for is REFUSED, not decorated with nothing.
///
/// An undecorated request to an upstream that requires a credential is a guaranteed refusal wearing
/// the shape of a transient one, and it would reach the breaker as the destination's fault — a
/// healthy upstream benched by a configuration mistake this node could see.
#[test]
fn a_destination_with_no_declared_credential_is_refused_rather_than_sent_bare() {
    busbar_substrate::proto::register_test_protocols(busbar_llm::DECLS);
    let (declared, _) = two_differently_decorating_declarations();
    let carrier = input(vec![lane("fast", declared, "key-fast", 4)]);
    let mut seat = seater();
    let auth = DeclaredEgressAuth::resolve(&carrier, &mut seat);
    let port: &dyn EgressAuth = &auth;

    let dest = sealed("nobody-declared-this");
    let mut request = OutboundRequest {
        fields: Vec::new(),
        body: b"{}",
        scheme: busbar_contract::SchemeKey::new("declared"),
        body_signature: None,
    };

    assert_eq!(
        port.decorate(&dest, &mut request),
        Err(DecorationRefused),
        "a lane this node holds no credential for cannot be decorated"
    );
    assert!(
        request.fields.is_empty(),
        "and nothing was added on the way to refusing"
    );
}

/// The record is on THE chain — the one this node keeps, in the one order — and the journal's head
/// moves for it.
///
/// Driven through `&dyn Journal`, over the real book a process settles onto. That is the whole
/// claim this binding makes: not that a record is written somewhere, but that a dispatch and the
/// settlement that follows it are on the same chain, so an auditor can say which came first without
/// asking two units that never agreed on a clock.
#[test]
fn a_dispatch_lands_on_the_one_chain_this_node_keeps() {
    let book = super::super::durability::node_book();
    let token = DurabilityToken::mint(&busbar_caps::KernelSeal::acquire_for_kernel());

    let head_before = book
        .durability
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .journal
        .head_hex();

    let journal = ChainJournal::new(&book.durability, &token);
    let port: &dyn Journal = &journal;
    let record = a_dispatch();

    port.dispatched(&record)
        .expect("a memory-buffered chain takes the record");
    let head_after_dispatch = book
        .durability
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .journal
        .head_hex();
    assert_ne!(
        head_before, head_after_dispatch,
        "the head moved, so the record is ON the chain and not beside it"
    );

    port.abandoned(&record);
    assert_ne!(
        head_after_dispatch,
        book.durability
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .journal
            .head_hex(),
        "an abandonment is its own record on the same chain, in the order it happened"
    );
}
