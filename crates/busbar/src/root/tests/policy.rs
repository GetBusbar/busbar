//! Tests for `policy.rs`. Lifted out of the implementation file so its line count
//! measures implementation and nothing else; still a direct child module, so `use
//! super::*` reaches the private items it always did.

use super::*;
use busbar_unit_scope::required_scope;

const POOL: &str = "pool-main";
const LANE_A: &str = "lane-a";
const LANE_B: &str = "lane-b";

fn a_configured_card() -> MeterPolicyConfig {
    MeterPolicyConfig {
        pools: vec![PoolExpansion {
            pool: POOL.into(),
            lanes: vec![LANE_A.into(), LANE_B.into()],
        }],
        prices: vec![
            LanePrice {
                lane: LANE_A.into(),
                price: 900,
            },
            LanePrice {
                lane: LANE_B.into(),
                price: 100,
            },
        ],
        ..MeterPolicyConfig::default()
    }
}

/// **The hazard**, shown as the difference it makes. Under the configured policy a pool name
/// stands for its member lanes, so a request that went to either of them belongs to the pool.
/// Under the unit's own default the same lookup answers only the pool's own name, which no lane
/// is called, so every pooled request reads as a mismatch.
#[test]
fn a_pool_expands_to_its_lanes_and_the_default_expands_to_nothing() {
    let configured = build(&a_configured_card());
    let expansion = configured.policy().expansion_of(POOL);
    assert_eq!(expansion, BTreeSet::from([LANE_A, LANE_B]));
    assert!(expansion.contains(LANE_A));

    let defaulted = MeterPolicy::default();
    assert_eq!(defaulted.expansion_of(POOL), BTreeSet::from([POOL]));
    assert!(
        !defaulted.expansion_of(POOL).contains(LANE_A),
        "an empty expansion turns set membership into string equality"
    );
}

/// A plain lane name needs no configuration and stands for itself, on either policy. That is
/// what makes the empty default look harmless until a pool is involved.
#[test]
fn a_lane_name_stands_for_itself_without_being_declared() {
    let configured = build(&a_configured_card());
    assert_eq!(
        configured.policy().expansion_of("some-undeclared-lane"),
        BTreeSet::from(["some-undeclared-lane"])
    );
}

/// The prices come off the card. They decide only which reading wins when the legs disagree, so
/// the value that matters is the ordering, not the magnitude.
#[test]
fn lane_prices_come_from_the_card() {
    let policy = build(&a_configured_card());
    assert_eq!(policy.policy().lane_prices.get(LANE_A), Some(&900));
    assert_eq!(policy.policy().lane_prices.get(LANE_B), Some(&100));
    assert!(
        !policy.policy().lane_prices.contains_key("unpriced-lane"),
        "an unpriced lane has no entry and sorts as cheapest, which is the conservative way"
    );
}

/// The tolerances fall back to the unit's own figures, and that is right: those ARE the design's
/// numbers, and a deployment that sets neither is asking for them. The expansions are the ones
/// that must not fall back, which is the distinction this test draws.
#[test]
fn the_tolerances_fall_back_but_the_expansions_do_not() {
    let policy = build(&a_configured_card());
    let defaults = MeterPolicy::default();
    assert_eq!(
        policy.policy().variance_tolerance_bp,
        defaults.variance_tolerance_bp
    );
    assert_eq!(
        policy.policy().locator_floor_ratio,
        defaults.locator_floor_ratio
    );
    assert_ne!(policy.policy().lane_expansions, defaults.lane_expansions);
}

/// A deployment that sets them gets what it set.
#[test]
fn a_declared_tolerance_overrides_the_units_figure() {
    let cfg = MeterPolicyConfig {
        variance_tolerance_bp: Some(25),
        locator_floor_ratio: Some(8),
        ..a_configured_card()
    };
    let policy = build(&cfg);
    assert_eq!(policy.policy().variance_tolerance_bp, 25);
    assert_eq!(policy.policy().locator_floor_ratio, 8);
}

/// A card may tighten a tolerance and never widen one. The unit enforces that; this checks that
/// the entries reach it at all, since a tightening that never arrives is the same as no
/// tightening.
#[test]
fn a_class_tightening_reaches_the_unit_and_a_loosening_is_ignored() {
    let cfg = MeterPolicyConfig {
        variance_tolerance_bp: Some(100),
        class_tolerances_bp: BTreeMap::from([
            ("tight-class".to_string(), 10),
            ("loose-class".to_string(), 500),
        ]),
        ..a_configured_card()
    };
    let policy = build(&cfg);
    assert_eq!(policy.policy().tolerance_bp("tight-class"), 10);
    assert_eq!(
        policy.policy().tolerance_bp("loose-class"),
        100,
        "a card may tighten a tolerance and never widen one"
    );
}

/// The boot check: a configured pool with no expansion is nameable while the pool is still in
/// scope, rather than turning up later as a disputed posting that names nothing.
#[test]
fn a_pool_with_no_expansion_is_named_at_boot() {
    let cfg = MeterPolicyConfig {
        pools: vec![
            PoolExpansion {
                pool: POOL.into(),
                lanes: vec![LANE_A.into()],
            },
            PoolExpansion {
                pool: "pool-empty".into(),
                lanes: vec![],
            },
        ],
        ..MeterPolicyConfig::default()
    };
    let policy = build(&cfg);
    assert_eq!(pools_without_expansion(&cfg, &policy), vec!["pool-empty"]);
}

/// And a fully configured deployment names none.
#[test]
fn a_configured_deployment_has_no_unexpanded_pool() {
    let cfg = a_configured_card();
    let policy = build(&cfg);
    assert!(pools_without_expansion(&cfg, &policy).is_empty());
}

/// **The hazard**, on the transport axis: a client built from the crate's own `Default` ignores
/// what the operator wrote. A deployment that caps request bodies at 1 KiB gets a transport that
/// buffers 32 MiB, and the door and the transport then disagree about which bodies exist. Every
/// field is checked, not just the cap, because the four beside it are operator knobs too and a
/// mapping that forgot one would be invisible until the deployment that set it.
#[test]
fn the_transport_client_reads_the_operators_limits_and_not_a_default() {
    let limits = LimitsResolved {
        request_body_max_bytes: 1024,
        pool_max_idle_per_host: 7,
        pool_idle_timeout_secs: 11,
        upstream_http1_only: true,
        upstream_h2_prior_knowledge: false,
        ..LimitsResolved::default()
    };
    let settings = client_settings(&limits);
    assert_eq!(settings.request_body_max_bytes, 1024);
    assert_eq!(settings.pool_max_idle_per_host, 7);
    assert_eq!(settings.pool_idle_timeout_secs, 11);
    assert!(settings.upstream_http1_only);
    assert!(!settings.upstream_h2_prior_knowledge);
}

/// And a deployment that set nothing is left where it was: the resolved default body cap is the
/// same 32 MiB the transport's own `Default` carries, so wiring the knob through cannot move a
/// deployment that never touched it.
#[test]
fn an_unset_body_cap_resolves_to_the_transport_default() {
    let settings = client_settings(&LimitsResolved::default());
    assert_eq!(
        settings.request_body_max_bytes,
        ClientSettings::default().request_body_max_bytes
    );
    assert_eq!(
        settings.request_body_max_bytes,
        busbar_transport_http::DEFAULT_REQUEST_BODY_MAX_BYTES
    );
}

/// **Silence is a refusal.** The pair nobody wrote an entry for answers nothing, and the scope
/// unit reads nothing as "not authorized". A view that answered a scope here would open every
/// operation class the policy forgot to mention.
#[test]
fn a_pair_the_policy_is_silent_about_is_refused() {
    let policy = ScopePolicy::new();
    assert!(policy.is_empty());
    assert_eq!(
        required_scope(
            ClaimKey::new("some-claim"),
            OpClassId::new("some-op"),
            &policy
        ),
        None
    );
}

/// A declared pair answers what it was declared as, and nothing near it answers by association.
#[test]
fn only_the_declared_pair_answers() {
    let claim = ClaimKey::new("claim-one");
    let other_claim = ClaimKey::new("claim-two");
    let op = OpClassId::new("op-read");
    let other_op = OpClassId::new("op-write");

    let policy = ScopePolicy::new().declaring(claim, op, Scope::ReadOnly);

    assert_eq!(policy.len(), 1);
    assert_eq!(required_scope(claim, op, &policy), Some(Scope::ReadOnly));
    // The same claim's other operation class, and the other claim's same operation class,
    // are both silent. The lookup key is the PAIR, and neither half implies the other.
    assert_eq!(required_scope(claim, other_op, &policy), None);
    assert_eq!(required_scope(other_claim, op, &policy), None);
}

/// Both rungs are expressible, and a mutation declared as full stays full. The two-rung chain
/// is strict: read-only does not satisfy full.
#[test]
fn both_rungs_are_declarable_and_the_chain_is_strict() {
    let claim = ClaimKey::new("claim");
    let read = OpClassId::new("op-read");
    let write = OpClassId::new("op-write");

    let policy = ScopePolicy::new()
        .declaring(claim, read, Scope::ReadOnly)
        .declaring(claim, write, Scope::Full);

    assert_eq!(required_scope(claim, read, &policy), Some(Scope::ReadOnly));
    assert_eq!(required_scope(claim, write, &policy), Some(Scope::Full));
}

/// A later declaration of the same pair replaces the earlier one rather than accumulating, so a
/// policy has one answer per pair and a reload cannot leave two.
#[test]
fn redeclaring_a_pair_replaces_it() {
    let claim = ClaimKey::new("claim");
    let op = OpClassId::new("op");
    let policy = ScopePolicy::new()
        .declaring(claim, op, Scope::ReadOnly)
        .declaring(claim, op, Scope::Full);

    assert_eq!(policy.len(), 1);
    assert_eq!(required_scope(claim, op, &policy), Some(Scope::Full));
}

// ─────────────────────────────────────────────────────────────────────
// The group table
// ─────────────────────────────────────────────────────────────────────

use busbar_substrate::config::groups::{LimitCfg, LimitWindow};

fn limit(metric: LimitMetric, amount: u64, per: Option<LimitWindow>) -> LimitCfg {
    LimitCfg {
        metric,
        amount,
        per,
        scope: None,
        on_exhaust: None,
        downgrade_to: None,
    }
}

fn configured(name: &str, limits: Vec<LimitCfg>) -> (String, GroupCfg) {
    (
        name.to_string(),
        GroupCfg {
            parent: None,
            enabled: true,
            limits,
            child_default: None,
        },
    )
}

/// A group's `concurrent` limit reaches the table as the gauge's cap, and its window limits
/// reach it as the bucket the ledger already writes. Both halves, because a table carrying one
/// of them is a table that enforces half of what the operator wrote.
#[test]
fn a_configured_group_resolves_to_its_cap_and_its_bucket() {
    let groups = BTreeMap::from([configured(
        "team",
        vec![
            limit(LimitMetric::Concurrent, 1, None),
            limit(LimitMetric::Requests, 40, Some(LimitWindow::Minute)),
        ],
    )]);
    let table = group_table(&groups, &BTreeMap::new());
    let resolved = &table.groups()[0];
    assert_eq!(resolved.concurrent_cap, Some(1));
    assert_eq!(resolved.buckets.len(), 1);
    assert_eq!(resolved.buckets[0].bucket_id, "group:team@minute");
    assert_eq!(resolved.buckets[0].requests_cap, Some(40));
}

/// One metric written twice for one window keeps the tighter amount, which is the same
/// most-restrictive-wins the chain applies between groups. Written loosest-first on purpose: a
/// projection that simply overwrote would answer with the last one instead.
#[test]
fn a_metric_written_twice_keeps_the_tighter_amount() {
    let groups = BTreeMap::from([configured(
        "team",
        vec![
            limit(LimitMetric::Requests, 40, Some(LimitWindow::Minute)),
            limit(LimitMetric::Requests, 10, Some(LimitWindow::Minute)),
            limit(LimitMetric::Concurrent, 8, None),
            limit(LimitMetric::Concurrent, 2, None),
        ],
    )]);
    let table = group_table(&groups, &BTreeMap::new());
    let resolved = &table.groups()[0];
    assert_eq!(resolved.buckets[0].requests_cap, Some(10));
    assert_eq!(resolved.concurrent_cap, Some(2));
}

/// A pool-scoped limit accounts on a row of its own and participates only in its own pool's
/// traffic. Two scoped budgets are two ledger rows, never one shared one.
#[test]
fn a_pool_scoped_limit_gets_its_own_row() {
    let mut cheap = limit(LimitMetric::Budget, 500, Some(LimitWindow::Month));
    cheap.scope = Some(busbar_contract::store::ScopeRef::pool("value"));
    let mut dear = limit(LimitMetric::Budget, 500, Some(LimitWindow::Month));
    dear.scope = Some(busbar_contract::store::ScopeRef::pool("frontier"));
    let groups = BTreeMap::from([configured("team", vec![cheap, dear])]);
    let table = group_table(&groups, &BTreeMap::new());
    let buckets = &table.groups()[0].buckets;
    assert_eq!(buckets.len(), 2);
    assert_eq!(buckets[0].bucket_id, "group:team@month#pool:value");
    assert_eq!(buckets[1].bucket_id, "group:team@month#pool:frontier");
    let chain = table
        .chain_for("vk_one", Some("team"))
        .expect("the group is in the table");
    assert_eq!(chain.pool_filtered("value").len(), 2, "attribution + value");
    assert_eq!(chain.pool_filtered("other").len(), 1, "attribution alone");
}

/// The parent chain is walked by index, and the index is a position in the name-ordered table
/// rather than in whatever order configuration happened to be written.
#[test]
fn a_parent_resolves_to_its_position_in_the_table() {
    let child = GroupCfg {
        parent: Some("zztop".to_string()),
        enabled: true,
        limits: vec![limit(LimitMetric::Concurrent, 3, None)],
        child_default: None,
    };
    let groups = BTreeMap::from([
        ("aaa".to_string(), child),
        configured("zztop", vec![limit(LimitMetric::Concurrent, 1, None)]),
    ]);
    let table = group_table(&groups, &BTreeMap::new());
    let chain = table.chain_for("vk_one", Some("aaa")).expect("configured");
    let names: Vec<&str> = chain.groups().iter().map(|g| g.name.as_str()).collect();
    assert_eq!(names, vec!["aaa", "zztop"], "innermost first, to the root");
}

/// The interned name rides on the group it names, and a group nobody interned carries none —
/// which the door reads as a group it counts without naming.
#[test]
fn the_interned_name_rides_on_the_group_it_names() {
    let groups = BTreeMap::from([
        configured("named", vec![limit(LimitMetric::Concurrent, 1, None)]),
        configured("unnamed", vec![limit(LimitMetric::Concurrent, 1, None)]),
    ]);
    let ids = BTreeMap::from([("named".to_string(), "named")]);
    let table = group_table(&groups, &ids);
    let by_name = |n: &str| table.groups()[table.index_of(n).expect("configured")].lease_id;
    assert_eq!(by_name("named"), Some("named"));
    assert_eq!(by_name("unnamed"), None);
}

/// A principal bound to a group this node does not have is fail-closed at the chain, never a
/// chain that quietly enforces nothing.
#[test]
fn a_group_this_node_does_not_have_is_fail_closed() {
    let table = group_table(&BTreeMap::new(), &BTreeMap::new());
    assert!(table.chain_for("vk_one", Some("ghost")).is_err());
    assert!(
        table.chain_for("vk_one", None).is_ok(),
        "a principal bound to no group walks its attribution bucket alone"
    );
}
