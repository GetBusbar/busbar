// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE ROUTE A DOOR PLANE'S UNIT TAKES (ARCHITECT Q-SW6 amended by Q-FL3, 2026-10-02): a POOL route
//! names a pool of the section's reserved `pools` sub-key and walks its members under that pool's
//! label; a DIRECT route names one of the section's entries and walks it alone under 1.5.5's empty
//! pool label; anything else, or no name, is unknown.

use busbar_contract::abi::plane::{ROUTE_DIRECT, ROUTE_POOL};

use super::DoorPools;

fn pools(yaml: &str) -> DoorPools {
    DoorPools::of(&serde_yaml::from_str(yaml).expect("yaml")).expect("the pools")
}

fn routed(p: &DoorPools, class: u8, named: Option<&str>) -> Option<(String, Vec<String>)> {
    p.resolve(class, named.map(str::as_bytes))
}

fn owned(label: &str, members: &[&str]) -> Option<(String, Vec<String>)> {
    Some((
        label.to_string(),
        members.iter().map(|m| (*m).to_string()).collect(),
    ))
}

const SECTION: &str = "a: {}\nb: {}\nhooks: [h]\nupstream_credentials: own\n\
     pools:\n  both:\n    members: [a, {name: b}]";

#[test]
fn a_pool_route_walks_its_named_pools_members_under_its_label() {
    let p = pools(SECTION);
    assert_eq!(
        routed(&p, ROUTE_POOL, Some("both")),
        owned("both", &["a", "b"])
    );
    assert_eq!(
        routed(&p, ROUTE_POOL, Some("a")),
        None,
        "an entry is no pool"
    );
    assert_eq!(routed(&p, ROUTE_POOL, Some("nowhere")), None, "unknown");
    assert_eq!(routed(&p, ROUTE_POOL, None), None, "none named");
}

/// RED (ARCHITECT timeout ruling; R2-G "per-member ... timeout"): an entry's reserved `timeout:` is
/// its member's attempt bound, read for every entry alike — a section's own entries and a
/// model-serving section's `models` entries; an entry that writes none has no bound of its own.
#[test]
fn an_entrys_timeout_is_its_members_attempt_bound() {
    let p = pools("a: { timeout: 10s }\nb: {}\npools:\n  both:\n    members: [a, b]");
    assert_eq!(p.timeout_ms("a"), Some(10_000));
    assert_eq!(
        p.timeout_ms("b"),
        None,
        "none written: the walk's own budget"
    );
    assert_eq!(p.timeout_ms("both"), None, "a pool is no entry");
    let m = pools("models:\n  m1: { provider: p, timeout: 2m }\n  m2: { provider: p }");
    assert_eq!(m.timeout_ms("m1"), Some(120_000));
    assert_eq!(m.timeout_ms("m2"), None);
}

#[test]
fn a_direct_route_walks_its_entry_alone_under_the_empty_label() {
    let p = pools(SECTION);
    assert_eq!(routed(&p, ROUTE_DIRECT, Some("a")), owned("", &["a"]));
    assert_eq!(
        routed(&p, ROUTE_DIRECT, Some("both")),
        None,
        "a pool is no entry"
    );
    for reserved in ["hooks", "upstream_credentials", "pools"] {
        assert_eq!(routed(&p, ROUTE_DIRECT, Some(reserved)), None, "{reserved}");
    }
    assert_eq!(routed(&p, ROUTE_DIRECT, None), None, "none named");
}

#[test]
fn a_model_serving_sections_entries_are_its_models() {
    let p = pools("models:\n  m: {provider: p}\nhooks: []");
    assert_eq!(routed(&p, ROUTE_DIRECT, Some("m")), owned("", &["m"]));
    assert_eq!(
        routed(&p, ROUTE_DIRECT, Some("models")),
        None,
        "the map is no entry"
    );
}

#[test]
fn a_name_that_is_not_text_or_a_class_unknown_routes_nowhere() {
    let p = pools("m: {}");
    assert_eq!(p.resolve(ROUTE_DIRECT, Some(&[0xff, 0xfe])), None);
    assert_eq!(p.resolve(ROUTE_DIRECT + 1, Some(b"m")), None);
}

/// THE GRANT IS JUDGED OVER THE ROUTE AS NAMED, BEFORE ITS DESTINATION (FOLD-LLM, 2026-10-02; 1.5.5's
/// order: the pool's ACL, then its fallback pool's, and only then an unknown pool's no_destination).
#[test]
fn the_grant_is_judged_over_the_named_pool_then_its_fallback() {
    use busbar_contract::records::{ScopeRef, VirtualKey};
    let p = pools(
        "a: {}\nb: {}\npools:\n  hot:\n    members: [a]\n    on_exhausted: {fallback_pool: cold}\n\
         \x20 cold:\n    members: [b]",
    );
    let key = |scopes: Option<&[&str]>| VirtualKey {
        allowed_scopes: scopes.map(|s| s.iter().map(|n| ScopeRef::pool(*n)).collect()),
        ..VirtualKey::default()
    };
    let granted = |k: Option<&VirtualKey>, class: u8, named: &str| {
        p.granted(Some("pool"), k, class, Some(named.as_bytes()))
    };
    assert!(
        granted(None, ROUTE_POOL, "hot"),
        "ungoverned: nothing to enforce"
    );
    assert!(
        granted(Some(&key(None)), ROUTE_POOL, "hot"),
        "an omitted grant is every pool"
    );
    assert!(
        !granted(Some(&key(Some(&["hot"]))), ROUTE_POOL, "hot"),
        "its fallback is not granted"
    );
    assert!(granted(
        Some(&key(Some(&["hot", "cold"]))),
        ROUTE_POOL,
        "hot"
    ));
    assert!(
        !granted(Some(&key(Some(&[]))), ROUTE_POOL, "hot"),
        "an empty grant is none"
    );
    assert!(
        granted(Some(&key(Some(&["a"]))), ROUTE_DIRECT, "a"),
        "a direct route names its entry"
    );
    assert!(
        !granted(Some(&key(Some(&["hot"]))), ROUTE_POOL, "nowhere"),
        "an unknown pool is refused by its grant first"
    );
    assert!(granted(
        Some(&key(Some(&["nowhere"]))),
        ROUTE_POOL,
        "nowhere"
    ));
    assert!(
        p.granted(None, Some(&key(Some(&["hot"]))), ROUTE_POOL, Some(b"cold")),
        "a plane with no scope kind scopes nothing"
    );
}

/// LEGACY the retiring engine crate's `src/engine/tests/ingress_integration_tests.rs::test_adhoc_governance_pool_acl_403_via_router`
/// (coverage map v2 row 463). 1.5.5: the ad-hoc (direct) route runs the same governance guard,
/// keyed on the resolved MODEL: a key allowed only on `other-pool` that names the configured model
/// directly is refused 403 (a permission refusal, the dialect's own `permission_error` envelope).
///
/// Held here on the door's grant over a direct route and the refusal the seat answers for it: the
/// grant is denied, the seat refuses it as `ScopeDenied`, and the driver's status for that reason
/// is 403 (the plane renders it as its dialect's permission refusal; its own suite holds that).
///
/// RED: a direct route escapes the key's pool grant (the model served to a key scoped elsewhere),
/// or its refusal stops being a 403.
#[test]
fn test_adhoc_governance_pool_acl_403_via_router() {
    use busbar_contract::records::{ScopeRef, VirtualKey};
    let p = pools("models:\n  configured-model: {provider: p}\npools:\n  other-pool:\n    members: [configured-model]");
    let elsewhere = VirtualKey {
        allowed_scopes: Some(vec![ScopeRef::pool("other-pool")]),
        ..VirtualKey::default()
    };
    assert!(
        !p.granted(
            Some("pool"),
            Some(&elsewhere),
            ROUTE_DIRECT,
            Some(b"configured-model")
        ),
        "a key allowed only on `other-pool` may not name the configured model directly"
    );
    assert!(
        p.granted(
            Some("pool"),
            Some(&elsewhere),
            ROUTE_POOL,
            Some(b"other-pool")
        ),
        "the same key is served on the pool it is granted"
    );
    assert_eq!(
        busbar_kernel::plane_driver::refusal_status(busbar_contract::caps::ReasonCode::ScopeDenied),
        403,
        "ad-hoc governance pool-ACL => 403"
    );
}

/// A POOL OF NAMED DEFINITIONS, ITS MEMBERS EACH ON THEIR OWN GRANT (QP2, coordinator 2026-10-07):
/// its route's grant is the caller's grant on the member the unit is ADDRESSED to (its stated trust
/// counterparty), judged before anything is charged, as predev's admission judged it; a
/// counterparty that names no member of the pool, or none stated, leaves the members to the plane.
/// RED before the judge: every caller passes a member-granted pool route.
#[test]
fn a_member_granted_pool_route_is_judged_on_the_member_it_is_addressed_to() {
    use busbar_contract::records::{ScopeRef, VirtualKey};
    let p = pools(
        "a: {}\nb: {}\npools:\n  twins:\n    members: [{name: a, tier: 0}, {name: b, tier: 1}]\n\
         \x20   member_granted: true",
    );
    let key = |scopes: &[&str]| VirtualKey {
        allowed_scopes: Some(
            scopes
                .iter()
                .map(|n| ScopeRef {
                    kind: "seat".to_string(),
                    value: (*n).to_string(),
                })
                .collect(),
        ),
        ..VirtualKey::default()
    };
    let granted = |k: &VirtualKey, counterparty: Option<&str>| {
        p.granted_to(
            Some("seat"),
            Some(k),
            (ROUTE_POOL, Some(b"twins".as_slice())),
            counterparty.map(str::as_bytes),
        )
    };
    assert!(
        granted(&key(&["a"]), Some("a")),
        "granted the member it addressed"
    );
    assert!(
        !granted(&key(&["b"]), Some("a")),
        "a twin's grant is not the addressed member's"
    );
    assert!(
        !granted(&key(&[]), Some("b")),
        "an empty grant reaches no member"
    );
    assert!(
        granted(&key(&[]), None),
        "no counterparty stated: the members are the plane's to judge"
    );
    assert!(
        granted(&key(&[]), Some("elsewhere")),
        "a counterparty outside the pool names no member of it"
    );
    assert!(
        p.granted_to(
            None,
            Some(&key(&[])),
            (ROUTE_POOL, Some(b"twins".as_slice())),
            Some(b"a")
        ),
        "a plane with no scope kind scopes nothing"
    );
}

/// THE MEMBER'S TIER (the core-owned per-member `tier`, `BUSBAR-1.6.0.md` l.4196 (b), R2-G
/// l.4285): read off a member written `{name, tier}`, and `0` for a member that writes no tier, a
/// bare name or a `{name}` object alike (the reserved `tier` sub-key is optional, l.552-554); a
/// pool's entries are its members' names either way.
#[test]
fn a_pool_members_tier_is_read_off_its_member() {
    let p = pools(
        "a: {}\nb: {}\nc: {}\nd: {}\npools:\n  t:\n    \
         members: [{name: b, tier: 2}, a, {name: c, tier: 1}, {name: d}]",
    );
    assert_eq!(
        routed(&p, ROUTE_POOL, Some("t")),
        owned("t", &["b", "a", "c", "d"])
    );
    assert_eq!(
        (
            p.tier("t", 0),
            p.tier("t", 1),
            p.tier("t", 2),
            p.tier("t", 3)
        ),
        (2, 0, 1, 0)
    );
    assert_eq!(p.tier("absent", 0), 0);
}

/// A BAD CORE-OWNED TIER IS REFUSED, NEVER READ AS `0` (no-float-money count-read finding on
/// `members`, coordinator ruling): a member that writes a `tier` whose value is no integer,
/// negative or wider than `u32` is refused by the section build at config time rather than routed
/// at the top tier. A member that writes NO tier states none and builds at tier `0`
/// (`a_pool_members_tier_is_read_off_its_member`): `{name: b}` is the member spelling the route
/// tests' `SECTION` writes, and refusing it would refuse a section the build has always taken. RED
/// before the refusal: each of these built, at tier `0`.
#[test]
fn a_member_with_a_bad_tier_is_refused_at_the_section_build() {
    for (what, member) in [
        ("a word", "{name: a, tier: minus}"),
        ("a negative", "{name: a, tier: -1}"),
        ("a float", "{name: a, tier: 1.5}"),
        ("wider than u32", "{name: a, tier: 4294967296}"),
    ] {
        let section: serde_yaml::Value =
            serde_yaml::from_str(&format!("a: {{}}\npools:\n  u:\n    members: [{member}]"))
                .expect("yaml");
        let refused = DoorPools::of(&section)
            .err()
            .unwrap_or_else(|| panic!("{what}: a member written {member} built"));
        assert!(
            refused.contains("pool 'u'") && refused.contains("member 'a'"),
            "{what}: the refusal names the pool and member: {refused}"
        );
    }
}

/// A NAMED-DEFINITION SECTION'S POOLS, AS THE ROOT HANDS THEM: each member written `{name, tier}`,
/// its tier its declared index (the pool is ORDERED, its first member the primary), so the walk
/// takes the members in the order declared; the plane is handed each member's bare name (the tier
/// is core-owned). RED before the tier: every member written bare, all at tier `0`, rotated.
#[test]
fn named_definition_pools_are_tiered_in_declared_order_and_the_plane_sees_bare_names() {
    let stated: std::collections::BTreeMap<String, busbar_kernel::config::pools::CandidatePoolCfg> =
        [(
            "twins".to_string(),
            busbar_kernel::config::pools::CandidatePoolCfg {
                members: vec!["b".to_string(), "a".to_string()],
                repeatable: vec!["read".to_string()],
                breaker: None,
            },
        )]
        .into();
    let mut section: serde_yaml::Value = serde_yaml::from_str("a: {}\nb: {}").expect("yaml");
    crate::root::serve::pools_into(&mut section, &stated);
    let p = DoorPools::of(&section).expect("the pools");
    assert_eq!(
        routed(&p, ROUTE_POOL, Some("twins")),
        owned("twins", &["b", "a"])
    );
    assert_eq!((p.tier("twins", 0), p.tier("twins", 1)), (0, 1));
    let handed = crate::root::serve::plane_settings(&section);
    let pool = &handed["pools"]["twins"];
    assert_eq!(
        pool["members"],
        serde_yaml::from_str::<serde_yaml::Value>("[b, a]").expect("yaml"),
        "the plane is handed bare names"
    );
    assert_eq!(
        pool["repeatable"],
        serde_yaml::from_str::<serde_yaml::Value>("[read]").expect("yaml")
    );
    assert_eq!(pool["member_granted"], serde_yaml::Value::Bool(true));
    assert_eq!(handed["a"], section["a"], "every other key as written");
}

/// A PLANE'S POOL CARRIES ITS `breaker:` BLOCK TO ITS DOOR'S EGRESS, AND ONLY THERE (BUSBAR-1.6.0.md
/// THE DESIGN §1: "Any plugin gets all functionality"; §5: the breaker is the host's valve). The
/// root writes the pool's block beside its members, the door's egress reads it back as the same
/// block, and the plane is handed its section without it — byte-identical to a pool that states
/// none. A pool with no block reads `None`, the defaults every default config runs under.
#[test]
fn a_planes_pool_breaker_block_reaches_its_egress_and_never_the_plane() {
    let block = busbar_kernel::config::BreakerCfg {
        base_cooldown_secs: 30,
        max_cooldown_secs: 300,
        ..Default::default()
    };
    let stated: std::collections::BTreeMap<String, busbar_kernel::failover::CandidatePoolCfg> = [
        (
            "tuned".to_string(),
            busbar_kernel::failover::CandidatePoolCfg {
                members: vec!["a".to_string(), "b".to_string()],
                repeatable: Vec::new(),
                breaker: Some(block.clone()),
            },
        ),
        (
            "plain".to_string(),
            busbar_kernel::failover::CandidatePoolCfg {
                members: vec!["a".to_string(), "b".to_string()],
                repeatable: Vec::new(),
                breaker: None,
            },
        ),
    ]
    .into();
    let mut section: serde_yaml::Value = serde_yaml::from_str("a: {}\nb: {}").expect("yaml");
    crate::root::serve::pools_into(&mut section, &stated);
    let p = DoorPools::of(&section).expect("the pools");
    assert_eq!(
        p.breaker("tuned"),
        Some(&block),
        "the pool's own block, as stated"
    );
    assert_eq!(p.breaker("plain"), None, "no block: the defaults");
    let handed = crate::root::serve::plane_settings(&section);
    assert_eq!(
        handed["pools"]["tuned"], handed["pools"]["plain"],
        "the plane is handed the same pool whether or not the host tunes its breaker"
    );
}

/// AN ANONYMOUS UNIT NEVER REACHES A BILLED PATH (ARCHITECT P3 (a)): with no key it is admitted only
/// on an open line, and then as anonymous (a zero hold, no money); every other unkeyed unit is
/// refused; a keyed unit is the only one admitted onto the book.
#[test]
fn an_anonymous_unit_never_reaches_a_billed_path() {
    use super::Admission;
    use busbar_contract::records::VirtualKey;
    let key = std::sync::Arc::new(VirtualKey::default());
    assert_eq!(super::admission(None, true), Admission::Anonymous);
    assert_eq!(super::admission(None, false), Admission::Refused);
    assert_eq!(super::admission(Some(&key), true), Admission::Keyed);
    assert_eq!(super::admission(Some(&key), false), Admission::Keyed);
}

/// A DOOR PLANE'S FACTS name its fee units by their index among its billable classes; a fee unit
/// that is no billable class indexes nothing.
#[test]
fn the_door_facts_index_the_fee_units_among_the_billable_classes() {
    let f = super::door_facts(
        "p",
        &["grant"],
        &["a", "fee", "b"],
        &["fee", "nowhere"],
        "audit",
        Vec::new(),
    );
    assert_eq!(f.plane, "p");
    assert_eq!(f.scope_kind.as_deref(), Some("grant"));
    assert_eq!(&*f.fee_units, &[1]);
    assert_eq!(f.classes.len(), 3);
    assert_eq!(
        super::door_facts("p", &[], &[], &[], "a", Vec::new()).scope_kind,
        None
    );
}

/// A ROUTE'S EGRESS POOL: a pool route walks its own label; a direct route its entry's own cell,
/// named by (plane key, entry), never 1.5.5's shared empty cell.
#[test]
fn a_direct_route_walks_its_entrys_own_cell_and_a_pool_route_its_label() {
    let sep = busbar_kernel::governance::PLANE_LANE_SEP;
    assert_eq!(
        super::egress_pool("p", &(String::new(), vec!["m".to_string()])),
        format!("p{sep}m")
    );
    assert_eq!(
        super::egress_pool("p", &("both".to_string(), vec!["a".to_string()])),
        "both"
    );
}

/// A BLOCKED ADMISSION IS THE REFUSAL THE BUDGET UNIT'S OWN DOOR NAMES: a spend cap and a missing
/// group are over budget, every count cap a rate limit with its window's wait, a frozen group
/// frozen.
#[test]
fn a_blocked_admission_renders_as_the_budget_units_door_does() {
    use busbar_contract::caps::ReasonCode;
    use busbar_kernel::governance::LimitBlocked;
    let limit = |metric: &'static str, retry_after| LimitBlocked::Limit {
        group: "g".into(),
        metric,
        window: Some("day"),
        pool: None,
        downgrade_to: None,
        retry_after,
    };
    let budget = super::refusal_for(&limit("budget", Some(30)));
    assert_eq!(budget.reason(), ReasonCode::OverBudget);
    assert_eq!(budget.retry_after_secs(), Some(30));
    for metric in ["requests", "tokens", "concurrent"] {
        assert_eq!(
            super::refusal_for(&limit(metric, None)).reason(),
            ReasonCode::RateLimited,
            "{metric}"
        );
    }
    assert_eq!(
        super::refusal_for(&LimitBlocked::Disabled("g".into())).reason(),
        ReasonCode::GroupFrozen
    );
    assert_eq!(
        super::refusal_for(&LimitBlocked::MissingGroup("g".into())).reason(),
        ReasonCode::OverBudget
    );
}

/// A UNIT'S PRINCIPAL IS ON THE HOST'S UNIT RECORDS FOR ITS LIFE (so a host service the plane calls
/// inside its crossings, `entitlement.check`, answers for it): written once authenticate passes,
/// struck when its steps drop; a refused unit writes none.
#[test]
fn a_units_principal_is_recorded_from_authenticate_until_its_steps_drop() {
    use busbar_contract::caps::PrincipalId;
    use busbar_kernel::host_units::UnitRecords;
    use busbar_kernel::plane_driver::DriverSteps;
    use busbar_kernel::teller::UnitCtx;
    let facts = super::door_facts("p", &[], &[], &[], "a", Vec::new());
    let pools = DoorPools::default();
    let records = std::sync::Arc::new(UnitRecords::default());
    let key = std::sync::Arc::new(busbar_contract::records::VirtualKey {
        id: "vk_one".into(),
        ..Default::default()
    });
    let ctx = |n: u64| UnitCtx {
        call: busbar_contract::caps::CallId::UNBOUND,
        key: busbar_contract::UnitKey::new(n),
        origin: busbar_contract::caps::OriginKind::Client,
        session: None,
        generation: busbar_kernel::registry::Generation::FIRST,
        admin_listener: false,
        kernel_verb_only: false,
    };
    let steps = |caller_key: Option<std::sync::Arc<busbar_contract::records::VirtualKey>>| {
        super::DoorSteps::new(
            &facts,
            &pools,
            std::sync::Arc::new(|_: &str| None),
            busbar_kernel::test_support::TestApp::new().build(),
            None,
            super::DoorCaller {
                principal: PrincipalId::new("vk_one"),
                key: caller_key,
                open: false,
                arrived: 0,
                records: Some(std::sync::Arc::clone(&records)),
                depth: 0,
                credential: None,
            },
        )
    };
    let keyed = steps(Some(std::sync::Arc::clone(&key)));
    assert!(records.get(7).is_none(), "nothing before authenticate");
    let _ = keyed.authenticate(&ctx(7));
    let held = records.get(7).expect("recorded at authenticate");
    assert_eq!(
        held.principal.as_ref().map(|k| k.id.as_str()),
        Some("vk_one")
    );
    drop(keyed);
    assert!(records.get(7).is_none(), "struck when its steps drop");

    let unkeyed = steps(None);
    let _ = unkeyed.authenticate(&ctx(8));
    assert!(records.get(8).is_none(), "a refused unit writes no record");
}

// ── budget downgrade (`on_exhaust: downgrade`, 1.5.5 `ingress::admit_check`) ──────────────────────

/// A budget limit on `pool` that downgrades to `to` once `amount` minor units are spent in a day.
fn downgrading(pool: &str, amount: u64, to: &str) -> busbar_kernel::config::groups::LimitCfg {
    use busbar_kernel::config::groups::{LimitCfg, LimitMetric, LimitWindow, OnExhaust};
    LimitCfg {
        metric: LimitMetric::Budget,
        amount,
        per: Some(LimitWindow::Day),
        scope: Some(busbar_contract::records::ScopeRef::pool(pool)),
        on_exhaust: Some(OnExhaust::Downgrade),
        downgrade_to: Some(busbar_contract::records::ScopeRef::pool(to)),
        admission: None,
        on_exhaustion: None,
    }
}

/// A governed generation whose group `team` holds `limits` at a flat 10-minor-unit fee per request,
/// and a key in that group granted `allowed_pools` (`None`: every pool).
fn downgrade_book(
    limits: Vec<busbar_kernel::config::groups::LimitCfg>,
    allowed_pools: Option<Vec<String>>,
) -> (
    std::sync::Arc<busbar_kernel::state::App>,
    std::sync::Arc<busbar_contract::records::VirtualKey>,
) {
    use busbar_kernel::test_support::engine_kit::{EngineTestKit as _, CORE_ENGINE_KIT};
    let gov = CORE_ENGINE_KIT
        .governance(CORE_ENGINE_KIT.scratch_store(), None, None)
        .expect("governance");
    let groups = std::collections::BTreeMap::from([(
        "team".to_string(),
        busbar_kernel::config::groups::GroupCfg {
            parent: None,
            enabled: true,
            limits,
            ..Default::default()
        },
    )]);
    let cost = CORE_ENGINE_KIT.cost_parts(None, 10, &groups);
    let (key, _secret) = gov
        .create_key(
            busbar_kernel::governance::NewKeySpec {
                name: "dev".to_string(),
                allowed_pools,
                group: Some("team".to_string()),
                ..Default::default()
            },
            1_700_000_000,
        )
        .expect("a key");
    let app = busbar_kernel::test_support::TestApp::new()
        .governance_kit(gov)
        .keys_chain()
        .cost_kit(cost)
        .build();
    (app, std::sync::Arc::new(key))
}

/// What one keyed unit of the plane serving the `pools` map did at its `$` door, routed to `pool`:
/// its admission (`Ok(())`, or the refusal's reason and words), the route its walk takes, and the
/// pool a downgrade sent it to.
struct Charged {
    admitted: Result<(), (busbar_contract::caps::ReasonCode, Option<String>)>,
    routed: Option<(String, Vec<String>)>,
    downgraded: Option<String>,
}

fn charge_once(
    app: &std::sync::Arc<busbar_kernel::state::App>,
    key: &std::sync::Arc<busbar_contract::records::VirtualKey>,
    pools: &DoorPools,
    pool: &str,
    unit: u64,
) -> Charged {
    charge_once_at(app, key, pools, pool, unit, busbar_kernel::store::now())
}

/// [`charge_once`], the unit having arrived at `arrived` (epoch seconds): the instant the door
/// hands its money steps (`DoorCaller::arrived`, the node's one arrival reading).
fn charge_once_at(
    app: &std::sync::Arc<busbar_kernel::state::App>,
    key: &std::sync::Arc<busbar_contract::records::VirtualKey>,
    pools: &DoorPools,
    pool: &str,
    unit: u64,
    arrived: u64,
) -> Charged {
    use busbar_kernel::plane_driver::{DriverSteps as _, EndPost, PlaneMoney};
    let facts = super::door_facts("", &["pool"], &[], &[], "door", Vec::new());
    let gov = std::sync::Arc::clone(app.governance.as_ref().expect("a governed generation"));
    let post = std::sync::Arc::new(crate::root::plane_node::NodeEndPost::new(
        std::sync::Arc::new(crate::root::plane_node::Node::new()),
    ));
    let money = PlaneMoney::new(gov, post as std::sync::Arc<dyn EndPost>);
    let steps = super::DoorSteps::new(
        &facts,
        pools,
        std::sync::Arc::new(|_: &str| None),
        std::sync::Arc::clone(app),
        Some(&money),
        super::DoorCaller {
            principal: busbar_contract::caps::PrincipalId::new(key.id.as_str()),
            key: Some(std::sync::Arc::clone(key)),
            open: false,
            arrived,
            records: None,
            depth: 0,
            credential: None,
        },
    );
    steps.lock().routed = pools.resolve(ROUTE_POOL, Some(pool.as_bytes()));
    let ctx = busbar_kernel::teller::UnitCtx {
        call: busbar_contract::caps::CallId::UNBOUND,
        key: busbar_contract::UnitKey::new(unit),
        origin: busbar_contract::caps::OriginKind::Client,
        session: None,
        generation: busbar_kernel::registry::Generation::FIRST,
        admin_listener: false,
        kernel_verb_only: false,
    };
    let admitted = steps
        .charge(&ctx, key)
        .map(|_| ())
        .map_err(|refusal| (refusal.reason(), steps.refused_words().1));
    Charged {
        admitted,
        routed: steps.routed(),
        downgraded: steps.downgraded(),
    }
}

const DOWNGRADE_SECTION: &str = "models:\n  big: {}\n  small: {}\n  tiny: {}\n\
     pools:\n  frontier:\n    members: [big]\n  value:\n    members: [small]\n\
     \x20 first:\n    members: [big]\n  second:\n    members: [small]\n  third:\n    members: [tiny]";

/// BUDGET DOWNGRADE ON THE DOOR PATH (1.5.5 `test_budget_exhaustion_downgrades_pool`): exhausting
/// the `frontier` budget re-admits the unit through `value` instead of refusing it; the charge lands
/// there and the unit's walk routes over `value`'s members. RED: a door that refuses a budget block
/// carrying `downgrade_to` answers the third unit `OverBudget` and never re-pools it.
#[test]
fn an_exhausted_budget_re_pools_the_unit_through_its_downgrade_pool() {
    let (app, key) = downgrade_book(vec![downgrading("frontier", 25, "value")], None);
    let pools = pools(DOWNGRADE_SECTION);
    // fee 10, cap 25: two frontier admissions spend 20; the third would reach 30.
    for unit in 1..=2 {
        let charged = charge_once(&app, &key, &pools, "frontier", unit);
        assert_eq!(
            charged.admitted,
            Ok(()),
            "unit {unit} is under the frontier cap"
        );
        assert_eq!(charged.downgraded, None, "no downgrade while under the cap");
        assert_eq!(charged.routed, owned("frontier", &["big"]));
    }
    let charged = charge_once(&app, &key, &pools, "frontier", 3);
    assert_eq!(charged.admitted, Ok(()), "downgraded, not refused");
    assert_eq!(
        charged.downgraded.as_deref(),
        Some("value"),
        "the charge landed on the downgrade pool"
    );
    assert_eq!(
        charged.routed,
        owned("value", &["small"]),
        "the walk follows the charge to the downgrade pool"
    );
}

/// A DOWNGRADE CYCLE TERMINATES (1.5.5 `test_downgrade_cycle_terminates_via_the_revisit_guard`):
/// `first` -> `second` -> `third` -> `second` walks to `third` and stops at the revisit, refusing
/// with `third`'s bucket named in the previous release's words; a guard that refused one hop early
/// names `second`.
#[test]
fn a_downgrade_cycle_ends_in_the_plain_refusal_naming_the_last_pool_walked() {
    let (app, key) = downgrade_book(
        vec![
            downgrading("first", 10, "second"),
            downgrading("second", 0, "third"),
            downgrading("third", 0, "second"),
        ],
        None,
    );
    let pools = pools(DOWNGRADE_SECTION);
    let first = charge_once(&app, &key, &pools, "first", 1);
    assert_eq!(first.admitted, Ok(()), "under the first pool's cap");
    assert_eq!(first.downgraded, None);
    let second = charge_once(&app, &key, &pools, "first", 2);
    let (reason, words) = second
        .admitted
        .expect_err("a cyclic downgrade chain ends in a refusal");
    assert_eq!(reason, busbar_contract::caps::ReasonCode::OverBudget);
    let words = words.expect("the plane serving the `pools` map renders 1.5.5's words");
    assert!(
        words.contains("pool 'third'"),
        "the chain walked first -> second -> third before the revisit guard: {words}"
    );
    assert_eq!(
        second.downgraded, None,
        "a refused unit is re-pooled nowhere"
    );
}

/// A DOWNGRADE NEVER BYPASSES THE KEY'S POOL GRANT (1.5.5 `test_downgrade_never_bypasses_pool_acl`):
/// a key granted only `frontier` is refused the plain budget refusal, never routed into `value`.
#[test]
fn a_downgrade_never_routes_a_key_into_a_pool_it_may_not_use() {
    let (app, key) = downgrade_book(
        vec![downgrading("frontier", 25, "value")],
        Some(vec!["frontier".to_string()]),
    );
    let pools = pools(DOWNGRADE_SECTION);
    for unit in 1..=2 {
        assert_eq!(
            charge_once(&app, &key, &pools, "frontier", unit).admitted,
            Ok(())
        );
    }
    let charged = charge_once(&app, &key, &pools, "frontier", 3);
    assert_eq!(
        charged.admitted.map_err(|(reason, _)| reason),
        Err(busbar_contract::caps::ReasonCode::OverBudget),
        "the plain budget refusal, not a leaked pool"
    );
    assert_eq!(charged.downgraded, None);
    assert_eq!(
        charged.routed,
        owned("frontier", &["big"]),
        "the route is unchanged"
    );
}

// ── the members' routes (THE DESIGN §6 steps 2-3) ──────────────────────────────────────────────

/// The decisions-shaped plane facts: one dialect `d` whose default style is `bearer`, one outbound
/// need naming `bearer`.
fn styled() -> crate::root::loader::dispatch::kinds::plane::ServedFacts {
    use busbar_contract::abi::host::conn::connector::DIRECTION_OUTBOUND;
    crate::root::loader::dispatch::kinds::plane::ServedFacts {
        need_auths: vec![(DIRECTION_OUTBOUND, "bearer")],
        dialects: vec!["d"],
        dialect_auth: vec![(0, "bearer", b"")],
        ..Default::default()
    }
}

fn provider(protocol: &str, style: Option<&str>) -> super::ProviderRoute {
    super::ProviderRoute {
        base_url: "http://127.0.0.1:9".to_string(),
        userinfo: None,
        protocol: protocol.to_string(),
        error_map: Default::default(),
        credential: busbar_contract::secret_ref::SecretRef::none(),
        style: style.map(str::to_string),
        params: super::StyleParams::default(),
        metadata: busbar_kernel::config_validate::MetadataPosture::default(),
    }
}

/// The routes `section`'s members resolve to over `providers` for a plane stating `facts`, or why
/// the load is refused.
fn resolve_for(
    facts: &crate::root::loader::dispatch::kinds::plane::ServedFacts,
    section: &str,
    providers: &[(&str, super::ProviderRoute)],
) -> Result<std::collections::BTreeMap<String, busbar_kernel::plane_driver::MemberRoute>, String> {
    resolve_over(section, providers, facts)
}

/// [`resolve`], over the plane facts `served`.
fn resolve_over(
    section: &str,
    providers: &[(&str, super::ProviderRoute)],
    served: &crate::root::loader::dispatch::kinds::plane::ServedFacts,
) -> Result<std::collections::BTreeMap<String, busbar_kernel::plane_driver::MemberRoute>, String> {
    resolve_upgrading(section, providers, served, Vec::new())
}

/// [`resolve_over`], with `upgrades` the linked claims that open at an upgrade.
fn resolve_upgrading(
    section: &str,
    providers: &[(&str, super::ProviderRoute)],
    served: &crate::root::loader::dispatch::kinds::plane::ServedFacts,
    upgrades: Vec<&'static str>,
) -> Result<std::collections::BTreeMap<String, busbar_kernel::plane_driver::MemberRoute>, String> {
    let section: serde_yaml::Value = serde_yaml::from_str(section).expect("yaml");
    let providers = providers
        .iter()
        .map(|(n, p)| ((*n).to_string(), p.clone()))
        .collect();
    let dispatcher = std::sync::Arc::new(crate::root::loader::dispatch::Dispatcher::new(
        crate::root::loader::dispatch::DispatchConfig::default(),
    ));
    crate::root::connector::install_io(&dispatcher);
    // The host lends the dispatcher its seal (Part 2 #54), as the root does at boot.
    let _ = dispatcher.lend_seal(busbar_kernel::seal::lend());
    let auths = super::OutboundAuths::new(
        dispatcher,
        crate::LINKED.auths,
        None,
        crate::root::loader::dispatch::ConnTable::NoNeeds,
    );
    let secrets: std::sync::Arc<dyn busbar_contract::secret::SecretResolve> =
        std::sync::Arc::new(busbar_kernel::config::secret::SecretResolver::builtins_only());
    let conns: std::sync::Arc<dyn busbar_contract::conn::PollConns> =
        std::sync::Arc::new(busbar_core_connector::Connector::new());
    let reach = super::DoorReach {
        providers: &providers,
        secrets: std::sync::Arc::clone(&secrets),
        auths: std::sync::Arc::new(auths),
        conns,
        stream_ceiling_secs: 1,
        catalog: None,
        models: None,
        upgrades,
    };
    super::member_routes(
        &section,
        &DoorPools::of(&section).expect("the pools"),
        served,
        &reach,
        &busbar_contract::config_time::ConfigScope::config_time(),
    )
}

/// SEAM-L(n), `spelled_for`: a need over a framer composed over the base URL's carrier dials the
/// same authority and path in that framer's scheme, its secured form for a secured base; a need
/// over any other transport, or a base in no upgradable scheme, dials the base as written.
#[test]
fn a_need_over_an_upgrade_framer_spells_the_base_url_in_its_scheme() {
    let upgrades = ["ws"];
    assert_eq!(
        super::spelled_for("https://api.example/v1", "ws", &upgrades).as_deref(),
        Some("wss://api.example/v1")
    );
    assert_eq!(
        super::spelled_for("http://127.0.0.1:9/v1", "ws", &upgrades).as_deref(),
        Some("ws://127.0.0.1:9/v1")
    );
    assert_eq!(
        super::spelled_for("https://api.example", "http", &upgrades),
        None
    );
    assert_eq!(super::spelled_for("https://api.example", "ws", &[]), None);
    assert_eq!(super::spelled_for("unix:///sock", "ws", &upgrades), None);
}

/// SEAM-L(n), THE MEMBER'S ROUTE: a member bound over an upgrade framer's need dials that need at
/// its base URL in the framer's scheme, its own (http) need at the base as written. RED: the route
/// carried the provider's base URL alone, so the framer's need dialled https. The bearer style is the
/// linked header auth plugin's, so the leg runs where it is linked.
#[cfg(feature = "auth-header")]
#[test]
fn a_member_bound_over_an_upgrade_need_dials_its_spelled_base() {
    use busbar_contract::abi::host::conn::connector::DIRECTION_OUTBOUND;
    let served = crate::root::loader::dispatch::kinds::plane::ServedFacts {
        need_auths: vec![
            (DIRECTION_OUTBOUND, "bearer"),
            (DIRECTION_OUTBOUND, "bearer"),
        ],
        need_transports: vec!["http", "ws"],
        ..styled()
    };
    let routes = resolve_upgrading(
        "models: {m: {provider: p}}",
        &[("p", provider("d", None))],
        &served,
        vec!["ws"],
    )
    .expect("the member resolves");
    let route = &routes["m"];
    let base = route.base_url.clone();
    let spelled = base.replacen("http://", "ws://", 1);
    assert!(base.starts_with("http://"), "{base}");
    assert_eq!(route.ride(0).map(|r| r.base_url), Some(base.as_str()));
    assert_eq!(route.ride(2).map(|r| r.base_url), Some(spelled.as_str()));
}

/// MULTI-NEED (ARCHITECT Q-L5B-NEEDS 2026-10-03): a member binds EVERY outbound need its style
/// names, one per transport, the first as its own and the rest riding beside it, each opened when
/// a far request names it. The bearer style is the linked header auth plugin's, so the leg runs
/// where it is linked (single-plane rows link none).
#[cfg(feature = "auth-header")]
#[test]
fn a_member_binds_every_need_its_style_names_one_per_transport() {
    use busbar_contract::abi::host::conn::connector::{DIRECTION_INBOUND, DIRECTION_OUTBOUND};
    let served = crate::root::loader::dispatch::kinds::plane::ServedFacts {
        need_auths: vec![
            (DIRECTION_INBOUND, "bearer"),
            (DIRECTION_OUTBOUND, "bearer"),
            (DIRECTION_OUTBOUND, "bearer"),
            (DIRECTION_OUTBOUND, "api-key"),
        ],
        need_transports: vec!["ws", "ws", "http", "ws"],
        ..styled()
    };
    let routes = resolve_over(
        "models: {m: {provider: p}}",
        &[("p", provider("d", None))],
        &served,
    )
    .expect("the member resolves");
    let route = &routes["m"];
    assert_eq!(route.need.0, 1, "its first bound need is its own");
    let rides: Vec<u32> = route.rides.iter().map(|(n, _)| n.0).collect();
    assert_eq!(
        rides,
        [2],
        "the http need rides beside it; the api-key need is not its style"
    );
    assert_eq!(route.ride(3).map(|r| r.need.0), Some(2));
    assert_eq!(route.ride(0).map(|r| r.need.0), Some(1));
    assert!(
        route.ride(4).is_none(),
        "a need its style does not name is no ride"
    );
}

/// The routes `section`'s members resolve to over `providers`, or why the load is refused.
fn resolve(
    section: &str,
    providers: &[(&str, super::ProviderRoute)],
) -> Result<std::collections::BTreeMap<String, busbar_kernel::plane_driver::MemberRoute>, String> {
    resolve_for(&styled(), section, providers)
}

// The positive binding proof needs a bearer-serving auth plugin LINKED (the default distribution's
// `busbar-auth-header`); the member cannot bind to a style no linked/dropped-in plugin serves. A
// `--no-default-features` build without `auth-header` links none, so the bind is refused there (the
// sibling test proves that refusal), exactly as 1.5.5 bound only when a credential source was present.
#[cfg(feature = "auth-header")]
#[test]
fn a_member_is_bound_under_its_dialects_default_style_on_the_need_that_style_names() {
    let routes = resolve("models: {m: {provider: p}}", &[("p", provider("d", None))])
        .expect("the member resolves");
    let route = &routes["m"];
    assert_eq!(route.need.0, 0);
    assert_eq!(route.provider, "p");
    assert_eq!(route.base_url, "http://127.0.0.1:9");
    assert!(
        route.auth.is_some(),
        "its credential is bound by the plugin serving `bearer`"
    );
}

/// ROW 74 (F25): a provider whose `base_url` spells `user:pass@` is reached at the host after it,
/// as 1.5.5 reached it (v1.5.5 `crates/busbar/src/proxy/egress.rs:18`). The provider's route is
/// the one entry every member's route, sealed reach, binding and dial reads its base from, so the
/// userinfo is stripped HERE and nothing downstream (the connector refuses a dial target spelling
/// one, fail-closed) ever sees it. RED before the fix: the route carried the base as written, and
/// the member's dial was refused.
#[test]
fn a_provider_base_url_with_userinfo_is_reached_at_its_stripped_authority() {
    let provider: busbar_kernel::config::ProviderCfg = serde_yaml::from_str(
        "{protocol: d, base_url: 'https://svcuser:hunter2-P4ss@api.example.com:8443/v1', \
         api_key: none, error_map: {}}",
    )
    .expect("a provider entry");
    let routes = super::provider_routes(
        &std::collections::HashMap::from([(
            "p".to_string(),
            busbar_kernel::config::ResolvedProvider::from(provider),
        )]),
        &busbar_kernel::config_validate::MetadataPosture::default(),
    );
    let route = &routes["p"];
    assert_eq!(route.base_url, "https://api.example.com:8443/v1");
    assert!(
        route.userinfo.is_some(),
        "the userinfo is held, opaque, for the member's attempts to present as 1.5.5 did"
    );
    let shown = format!("{route:?}");
    assert!(
        !shown.contains("hunter2") && !shown.contains("svcuser"),
        "the route kept the planted spelling: {shown}"
    );
}

/// ROW 74 (F25), THE DOOR PATH HOLDS NO USERINFO BYTES IN A KERNEL TYPE: a member whose provider's
/// base URL spells `user:pass@` is sealed with the stripped base on its route (the kernel's
/// `MemberRoute` has no field for the userinfo), and the Basic value reaches its attempts only
/// through the binding's handle, which the root wrapped ([`crate::root::userinfo::lead_with`]):
/// first when the style's credential rides another field, displaced when it is `authorization`,
/// as 1.5.5's reqwest build sent it. The bearer and api-key styles are the linked header plugin's.
#[cfg(feature = "auth-header")]
#[test]
fn a_members_base_url_userinfo_reaches_its_attempts_only_through_its_binding() {
    use busbar_contract::abi::host::conn::connector::DIRECTION_OUTBOUND;
    use busbar_contract::auth_calls::{Fields, FieldsRequest};
    const WRITTEN: &str = "https://svcuser:hunter2-P4ss@api.example.com/v1";
    let key_file =
        std::env::temp_dir().join(format!("busbar-door-steps-row74-{}", std::process::id()));
    std::fs::write(&key_file, "sk-row74").expect("the key");
    let expected = {
        use base64::Engine as _;
        format!(
            "Basic {}",
            base64::engine::general_purpose::STANDARD.encode("svcuser:hunter2-P4ss")
        )
    };
    for (style, led) in [("api-key", true), ("bearer", false)] {
        let provider = super::ProviderRoute {
            base_url: busbar_kernel_egress::trust::net::strip_userinfo(WRITTEN).into_owned(),
            userinfo: crate::root::userinfo::UserinfoBasic::of(WRITTEN),
            protocol: "d".to_string(),
            error_map: Default::default(),
            credential: busbar_contract::secret_ref::SecretRef::file(
                key_file.display().to_string(),
            ),
            style: Some(style.to_string()),
            params: super::StyleParams::default(),
            metadata: busbar_kernel::config_validate::MetadataPosture::default(),
        };
        let facts = crate::root::loader::dispatch::kinds::plane::ServedFacts {
            need_auths: vec![(DIRECTION_OUTBOUND, style)],
            dialects: vec!["d"],
            ..Default::default()
        };
        let routes = resolve_for(&facts, "models: {m: {provider: p}}", &[("p", provider)])
            .expect("the member resolves");
        let route = &routes["m"];
        assert_eq!(route.base_url, "https://api.example.com/v1");
        let binding = route.auth.as_ref().expect("its credential is bound");
        let Some(Fields::Ready(fields)) = binding
            .auth
            .fields_now(binding.handle, &FieldsRequest::default())
        else {
            panic!("the {style} binding answers on the spot");
        };
        let fields: Vec<(String, String)> = fields
            .iter()
            .map(|f| {
                (
                    String::from_utf8_lossy(&f.name).to_ascii_lowercase(),
                    String::from_utf8_lossy(f.value.expose(&busbar_kernel::seal::lend()))
                        .into_owned(),
                )
            })
            .collect();
        if led {
            assert_eq!(
                fields[0],
                ("authorization".to_string(), expected.clone()),
                "a credential under another field leaves the Basic value first: {fields:?}"
            );
            assert!(fields[1..].iter().all(|(n, _)| n != "authorization"));
        } else {
            assert!(
                fields
                    .iter()
                    .all(|(n, v)| n != "authorization" || !v.starts_with("Basic ")),
                "an authorization credential displaces the Basic value: {fields:?}"
            );
        }
    }
    let _ = std::fs::remove_file(&key_file);
}

/// A MEMBER WHOSE OWN PROTOCOL STATES NO DEFAULT STYLE rides its provider protocol's default (the
/// envelope ruling, ARCHITECT 2026-10-14: a model a plane serves over another dialect's
/// envelope is credentialed by its provider). RED: the member's own protocol alone was looked up,
/// so the load was refused as styleless.
#[cfg(feature = "auth-header")]
#[test]
fn a_member_whose_protocol_states_no_default_style_rides_its_providers() {
    let routes = resolve(
        "models: {m: {provider: p, protocol: x-envelope}}",
        &[("p", provider("d", None))],
    )
    .expect("the member resolves under its provider's default style");
    assert!(
        routes["m"].auth.is_some(),
        "bound by the plugin serving `bearer`"
    );
    let styleless = resolve(
        "models: {m: {provider: p, protocol: x-envelope}}",
        &[("p", provider("x", None))],
    );
    assert!(
        styleless.as_ref().is_err_and(|e| e.contains("no `auth:`")),
        "neither the member's protocol nor its provider's states a default: {:?}",
        styleless.err()
    );
}

#[test]
fn a_member_that_cannot_be_reached_refuses_the_load_naming_it() {
    let unknown = resolve("models: {m: {provider: q}}", &[("p", provider("d", None))]);
    assert!(
        unknown
            .as_ref()
            .is_err_and(|e| e.contains("'m'") && e.contains("'q'")),
        "{:?}",
        unknown.err()
    );
    // A dialect the plane states no default for, and no `auth:`: no style.
    let styleless = resolve("models: {m: {provider: p}}", &[("p", provider("x", None))]);
    assert!(
        styleless.as_ref().is_err_and(|e| e.contains("no `auth:`")),
        "{:?}",
        styleless.err()
    );
    // A style no outbound need names.
    let unmatched = resolve(
        "models: {m: {provider: p}}",
        &[("p", provider("d", Some("api-key")))],
    );
    assert!(
        unmatched.as_ref().is_err_and(|e| e.contains("api-key")),
        "{:?}",
        unmatched.err()
    );
}

/// A MEMBER'S BINDING IS OPENED WITH ITS DIALECT'S PARAMETERS (ARCHITECT RULING 2026-10-03,
/// Q-L6-AUTHPARAMS): the params object, a host directive resolved from the provider's base URL
/// (the label after a named one, when it reads as a dashed name ending in a number), the
/// provider's own settings over it; no params hands the provider's settings as they are.
#[test]
fn a_members_binding_is_opened_with_its_dialects_parameters_under_the_providers_own() {
    use super::sealed_settings;
    let params = br#"{"service":"svc","content_type":"application/json","region":{"host_label_after":["svc-runtime","svc-runtime-fips","svc"],"default":"us-east-1","unread":"w"}}"#;
    let region = |base_url: &str| {
        sealed_settings(params, base_url, &serde_json::json!({})).expect("the parameters seal")
            ["region"]
            .clone()
    };
    for (base_url, want) in [
        ("https://svc-runtime.eu-west-1.amazonaws.com", "eu-west-1"),
        (
            "https://svc-runtime-fips.us-gov-west-1.amazonaws.com/",
            "us-gov-west-1",
        ),
        (
            "https://vpce-0abc-1xyz.svc-runtime.ap-southeast-2.vpce.amazonaws.com:443/x",
            "ap-southeast-2",
        ),
        ("https://svc.ca-central-1.amazonaws.com", "ca-central-1"),
        // No label reads: the default.
        ("https://svc-runtime.amazonaws.com", "us-east-1"),
        ("http://127.0.0.1:9000", "us-east-1"),
        ("https://svc-runtime.eu-west.amazonaws.com", "us-east-1"),
    ] {
        assert_eq!(region(base_url), serde_json::json!(want), "{base_url}");
    }
    let sealed = sealed_settings(
        params,
        "https://svc-runtime.eu-west-1.amazonaws.com",
        &serde_json::json!({ "service": "own", "scope": "s" }),
    )
    .expect("the parameters seal");
    assert_eq!(
        sealed["service"], "own",
        "the provider's own setting stands"
    );
    assert_eq!(sealed["scope"], "s");
    assert_eq!(sealed["content_type"], "application/json");
    assert!(
        sealed.get("region_unread").is_none(),
        "a host whose region reads hands on no warning"
    );
    let defaulted = sealed_settings(params, "http://127.0.0.1:9000", &serde_json::json!({}))
        .expect("the parameters seal");
    assert_eq!(defaulted["region"], "us-east-1");
    assert_eq!(
        defaulted["region_unread"], "w",
        "the warning travels with the default"
    );
    let own = serde_json::json!({ "token_url": "https://t" });
    assert_eq!(sealed_settings(b"", "https://x", &own), Ok(own));
    assert!(sealed_settings(b"[1]", "https://x", &serde_json::json!({})).is_err());
}

/// THE SIGNING REGION IS THE DIALLED HOST'S. The dialling stack ends a web URL's authority at a
/// `\` as at a `/`, so `https://svc-runtime.us-west-2.amazonaws.com\@svc-runtime.eu-west-1...`
/// dials `us-west-2`, and the region the request is signed for must be read off that same host
/// (v1.5.5's `host_from_base` folded the `\` first). RED before the one authority split: the
/// region was read past the `\`, off the text after the `@`, and the signature named a region
/// the request never reached.
#[test]
fn the_signing_region_is_read_off_the_host_the_request_dials() {
    use super::sealed_settings;
    let params = br#"{"region":{"host_label_after":["svc-runtime"],"default":"us-east-1"}}"#;
    for base_url in [
        "https://svc-runtime.us-west-2.amazonaws.com\\@svc-runtime.eu-west-1.amazonaws.com/",
        "https://svc-runtime.us-west-2.amazonaws.com\\x@svc-runtime.eu-west-1.amazonaws.com",
    ] {
        let dialled = busbar_contract::net::url_host(base_url).expect("the base URL reads a host");
        assert_eq!(dialled, "svc-runtime.us-west-2.amazonaws.com", "{base_url}");
        let sealed =
            sealed_settings(params, base_url, &serde_json::json!({})).expect("the parameters seal");
        assert_eq!(
            sealed["region"], "us-west-2",
            "{base_url}: the region is the dialled host's"
        );
    }
}

// ── the minted credential of a member bound under an OAuth grant ─────────────────

/// One open's head fields: `(name, value)`, in the order received.
type HeadFields = Vec<(String, Vec<u8>)>;

/// A connection table standing in for the token endpoint: framed needs, each declaration and each
/// open recorded, each open answered by the endpoint's next reply (`expires_in` 2, then 3600), one
/// piece per read.
#[derive(Default)]
pub(crate) struct TokenEndpoint {
    slab: busbar_contract::conn::ConnSlab<()>,
    declared: std::sync::Mutex<Vec<(u32, u32, Option<String>)>>,
    opened: std::sync::Mutex<Vec<Opened>>,
    /// Each open's head fields, as the table received them.
    fields: std::sync::Mutex<Vec<HeadFields>>,
    replies: std::sync::Mutex<Replies>,
    /// The reply body to a request body, when the endpoint answers by what it was asked (an RFC
    /// 8693 exchange's token names its scope); `None` = the minted replies above.
    answer: Option<fn(&str) -> String>,
    /// How many exchanges the plugin closed: it closes each one once it has read the token, the
    /// event a test waits on for a mint (never the wall clock, Law 8; row 176).
    closes: std::sync::Mutex<usize>,
    /// Told on each close.
    closing: tokio::sync::Notify,
}

impl TokenEndpoint {
    /// Until the plugin has closed `n` exchanges with this endpoint: the `n`th mint has read its
    /// token, which the plugin stores in the same crossing, AFTER the close. So a read made on the
    /// waiter's own thread (`fields_now`) can still see the cell before the store; a `fields` ask,
    /// which crosses on the instance's dispatcher worker behind that crossing, cannot.
    async fn closed(&self, n: usize) {
        loop {
            let notified = self.closing.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            if *self.closes.lock().unwrap() >= n {
                return;
            }
            notified.await;
        }
    }
}

/// What one open carried: the need, the target, the head target, the body.
type Opened = (u32, String, Vec<u8>, String);

/// Each open's reply, piece by piece, with its bytes.
type Replies = std::collections::HashMap<
    busbar_contract::conn::ConnId,
    std::collections::VecDeque<(busbar_contract::conn::Piece, Vec<u8>)>,
>;

fn reply_piece(kind: busbar_contract::conn::PieceKind, len: usize) -> busbar_contract::conn::Piece {
    use busbar_contract::conn::PieceKind;
    busbar_contract::conn::Piece {
        kind,
        stream: busbar_contract::ids::StreamId(0),
        len,
        end: kind != PieceKind::Fields,
        status: None,
        status_code: (kind == PieceKind::Fields).then_some(200),
        status_namespace: None,
        retry_after_secs: None,
        fault: None,
        reason: None,
        declared_len: None,
    }
}

impl busbar_contract::conn::DeclaredConns for TokenEndpoint {
    fn declare(
        &self,
        owner: busbar_contract::conn::InstanceId,
        need: busbar_contract::conn::NeedId,
        spec: &busbar_contract::abi::mechanism::rendering::ReadNeed,
        target: Option<&str>,
        _trust: Option<&str>,
    ) -> Result<(), busbar_contract::conn::ConnError> {
        self.declared
            .lock()
            .unwrap()
            .push((need.0, spec.egress_class, target.map(str::to_owned)));
        if !spec.target_from.is_empty() && target.is_none() {
            return Err(busbar_contract::conn::ConnError::Refused);
        }
        self.slab.declare(owner, need);
        Ok(())
    }
    fn declared(
        &self,
        owner: busbar_contract::conn::InstanceId,
        need: busbar_contract::conn::NeedId,
    ) -> Option<Result<(), busbar_contract::conn::ConnError>> {
        self.slab.check_need(owner, need).ok().map(Ok)
    }
    fn framed(
        &self,
        _: busbar_contract::conn::InstanceId,
        _: busbar_contract::conn::NeedId,
    ) -> bool {
        true
    }
    fn serves_scheme(&self, _: &str) -> bool {
        true
    }
}

impl busbar_contract::conn::Conns for TokenEndpoint {
    fn open(
        &self,
        caller: busbar_contract::conn::InstanceId,
        need: busbar_contract::conn::NeedId,
        desc: &busbar_contract::conn::OpenDesc<'_>,
    ) -> Result<busbar_contract::conn::ConnId, busbar_contract::conn::ConnError> {
        use busbar_contract::conn::PieceKind;
        self.slab.check_need(caller, need)?;
        self.fields.lock().unwrap().push(
            desc.fields
                .iter()
                .map(|(n, v)| ((*n).to_string(), v.to_vec()))
                .collect(),
        );
        let mut opened = self.opened.lock().unwrap();
        opened.push((
            need.0,
            desc.target.to_owned(),
            desc.head_target.to_vec(),
            String::from_utf8_lossy(&desc.body).into_owned(),
        ));
        let n = opened.len();
        let body = match self.answer {
            Some(answer) => answer(&opened[n - 1].3),
            // The first token lives 10 s, so the plugin re-mints it at about half its life (its
            // short-token rule): the window in which the first bearer is presented is seconds
            // wide, not the one second a 2 s token left a loaded test thread to observe it in.
            None => format!(
                r#"{{"access_token":"oracle-minted-{n}","expires_in":{}}}"#,
                if n == 1 { 10 } else { 3600 }
            ),
        };
        let id = self.slab.insert(caller, need, ())?;
        self.replies.lock().unwrap().insert(
            id,
            std::collections::VecDeque::from([
                (reply_piece(PieceKind::Fields, 0), Vec::new()),
                (reply_piece(PieceKind::Body, body.len()), body.into_bytes()),
                (reply_piece(PieceKind::Completion, 0), Vec::new()),
            ]),
        );
        Ok(id)
    }
    fn write(
        &self,
        _: busbar_contract::conn::InstanceId,
        _: busbar_contract::conn::ConnId,
        b: &[u8],
        _: bool,
        _: bool,
    ) -> Result<usize, busbar_contract::conn::ConnError> {
        Ok(b.len())
    }
    fn read(
        &self,
        c: busbar_contract::conn::InstanceId,
        id: busbar_contract::conn::ConnId,
        _: u64,
        buf: &mut [u8],
    ) -> Result<busbar_contract::conn::Piece, busbar_contract::conn::ConnError> {
        self.slab.get(c, id)?;
        let (p, bytes) = self
            .replies
            .lock()
            .unwrap()
            .get_mut(&id)
            .and_then(std::collections::VecDeque::pop_front)
            .ok_or(busbar_contract::conn::ConnError::Closed)?;
        buf[..bytes.len()].copy_from_slice(&bytes);
        Ok(p)
    }
    fn wait(
        &self,
        _: busbar_contract::conn::InstanceId,
        _: &[busbar_contract::conn::ConnId],
        _: u64,
    ) -> Result<usize, busbar_contract::conn::ConnError> {
        Err(busbar_contract::conn::ConnError::Pending)
    }
    fn facts(
        &self,
        _: busbar_contract::conn::InstanceId,
        _: busbar_contract::conn::ConnId,
    ) -> Result<busbar_contract::transport::ConnFacts, busbar_contract::conn::ConnError> {
        Err(busbar_contract::conn::ConnError::Closed)
    }
    fn close(
        &self,
        c: busbar_contract::conn::InstanceId,
        id: busbar_contract::conn::ConnId,
    ) -> Result<(), busbar_contract::conn::ConnError> {
        self.replies.lock().unwrap().remove(&id);
        let closed = self.slab.remove(c, id).map(|_| ());
        *self.closes.lock().unwrap() += 1;
        self.closing.notify_waiters();
        closed
    }
}

/// The authorization a `fields` answer presents.
fn presented(answer: Option<&busbar_contract::auth_calls::Fields>) -> Option<String> {
    match answer? {
        busbar_contract::auth_calls::Fields::Ready(fields) => fields.iter().find_map(|f| {
            (f.name == b"authorization").then(|| {
                String::from_utf8_lossy(f.value.expose(&busbar_kernel::seal::lend())).into_owned()
            })
        }),
        _ => None,
    }
}

/// The linked auth plugin that serves both mint styles (`oauth-client-credentials`, `jwt-bearer`),
/// its mint connections declared and opened over `table`, on a dispatcher serving the host services
/// the root's own does at boot (`root::dispatch::dispatcher`: [`crate::root::serve::LateServices`],
/// whose `clock.now` is the kernel's clock before any install). ROW 176: a dispatcher serving none
/// refuses the plugin's `clock.now`, so its `drive` clock never moves past its last `tick`; a mint
/// that lands on a `drive` (its binding opened after the first `tick`) then never comes due for its
/// refresh until the next `tick`, half a minute on.
fn linked_mint_plugin(table: &std::sync::Arc<TokenEndpoint>) -> super::OutboundAuths {
    let dispatcher = std::sync::Arc::new(crate::root::loader::dispatch::Dispatcher::with_services(
        crate::root::loader::dispatch::DispatchConfig::default(),
        crate::root::serve::LateServices::new(),
    ));
    assert!(
        dispatcher.host_services().is_some(),
        "the plugin's clock is the host's: a dispatcher serving no host services answers no \
         `clock.now`"
    );
    crate::root::connector::install_io(&dispatcher);
    // The host lends the dispatcher its seal (Part 2 #54), as the root does at boot.
    let _ = dispatcher.lend_seal(busbar_kernel::seal::lend());
    // The row's canonical name is its key.
    let name = "busbar-auth-oauth";
    let linked: [busbar_kernel::preflight::LinkedAuth; 1] = [(name, name, busbar_auth_oauth::door)];
    super::OutboundAuths::new(
        dispatcher,
        &linked,
        None,
        crate::root::loader::dispatch::ConnTable::Host(std::sync::Arc::clone(table)
            as std::sync::Arc<dyn busbar_contract::conn::DeclaredConns>),
    )
}

/// THE MEMBER UNDER `auth: oauth-client-credentials`, BOUND BY THE COMPOSITION (THE DESIGN §6 steps
/// 2-3, §5, §6.5): the auth plugin serving the style is opened over the provider's own settings,
/// so its `loopback-allowed` mint need is declared pinned to the provider's `token_url`; its tick schedule runs
/// without anyone driving it; the member's binding presents nothing until the first mint lands,
/// then the minted bearer, then the refreshed one ahead of the first token's expiry (the oracle
/// cell `egress.auth|oauth-cc|mint-refresh`: the second upstream request carries the refreshed
/// authorization).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_member_under_an_oauth_grant_presents_its_minted_then_refreshed_bearer() {
    use busbar_contract::abi::host::conn::connector::{
        DIRECTION_OUTBOUND, EGRESS_OPERATOR_INFRASTRUCTURE,
    };
    use busbar_contract::auth_calls::FieldsRequest;
    const TOKEN_URL: &str = "https://login.example.com/tenant/oauth2/v2.0/token";
    let basic = {
        use base64::Engine as _;
        format!(
            "Basic {}",
            base64::engine::general_purpose::STANDARD.encode("svcuser:hunter2-P4ss")
        )
    };
    // The endpoint as written, plain and spelling a userinfo (row 74, F25).
    for written in [
        TOKEN_URL.to_string(),
        TOKEN_URL.replacen("://", "://svcuser:hunter2-P4ss@", 1),
    ] {
        let key_file =
            std::env::temp_dir().join(format!("busbar-door-steps-oauth-{}", std::process::id()));
        std::fs::write(&key_file, "oracle-client-0001:oracle:secret:with:colons").expect("key");
        let providers: std::collections::BTreeMap<String, super::ProviderRoute> = [(
            "p".to_string(),
            super::ProviderRoute {
                base_url: "http://127.0.0.1:9".to_string(),
                userinfo: None,
                protocol: "d".to_string(),
                error_map: Default::default(),
                credential: busbar_contract::secret_ref::SecretRef::file(
                    key_file.display().to_string(),
                ),
                style: Some("oauth-client-credentials".to_string()),
                params: super::StyleParams {
                    token_url: Some(written.clone()),
                    scope: Some("https://cognitiveservices.azure.com/.default".to_string()),
                    ..super::StyleParams::default()
                },
                metadata: busbar_kernel::config_validate::MetadataPosture::default(),
            },
        )]
        .into();
        let table = std::sync::Arc::new(TokenEndpoint::default());
        let secrets: std::sync::Arc<dyn busbar_contract::secret::SecretResolve> =
            std::sync::Arc::new(busbar_kernel::config::secret::SecretResolver::builtins_only());
        let reach = super::DoorReach {
            providers: &providers,
            secrets: std::sync::Arc::clone(&secrets),
            auths: std::sync::Arc::new(linked_mint_plugin(&table)),
            conns: std::sync::Arc::new(busbar_core_connector::Connector::new()),
            stream_ceiling_secs: 1,
            catalog: None,
            models: None,
            upgrades: Vec::new(),
        };
        let section: serde_yaml::Value =
            serde_yaml::from_str("models: {m: {provider: p}}").expect("yaml");
        let facts = crate::root::loader::dispatch::kinds::plane::ServedFacts {
            need_auths: vec![(DIRECTION_OUTBOUND, "oauth-client-credentials")],
            dialects: vec!["d"],
            ..Default::default()
        };
        let routes = super::member_routes(
            &section,
            &DoorPools::of(&section).expect("the pools"),
            &facts,
            &reach,
            &busbar_contract::config_time::ConfigScope::config_time(),
        )
        .expect("the member resolves");
        let _ = std::fs::remove_file(&key_file);
        let binding = routes["m"].auth.clone().expect("its credential is bound");
        assert!(
            table.declared.lock().unwrap().contains(&(
                0,
                EGRESS_OPERATOR_INFRASTRUCTURE,
                Some(TOKEN_URL.to_string())
            )),
            "the plugin's operator-infrastructure need (ARCHITECT D1 2026-10-05, MINT CLASS (B)), \
             pinned to the provider's token_url: {:?}",
            table.declared.lock().unwrap()
        );

        // Before the first mint lands a request carries no credential, as 1.5.5's bearer sent none
        // in its boot window (v1.5.5 `egress_auth/bearer_token.rs:84-98`); once it lands, every
        // request carries it.
        // Each wait is on the endpoint's close of the mint's exchange (the plugin stores the token in
        // that same crossing), never on the wall clock (Law 8; row 176). HANG_GUARD only turns a
        // mint that never lands into a failure rather than a hung suite.
        const HANG_GUARD: std::time::Duration = std::time::Duration::from_secs(120);
        let first = tokio::time::timeout(HANG_GUARD, async {
            table.closed(1).await;
            loop {
                let now = binding
                    .auth
                    .fields_now(binding.handle, &FieldsRequest::default());
                match presented(now.as_ref()).as_deref() {
                    Some("Bearer oracle-minted-1") => return,
                    None => {}
                    other => panic!("only the first minted bearer, or none yet: {other:?}"),
                }
                tokio::task::yield_now().await;
            }
        })
        .await;
        assert!(first.is_ok(), "the first minted bearer is presented");
        // The refresh lands ahead of the first token's expiry; the next request carries it.
        let refreshed = tokio::time::timeout(HANG_GUARD, async {
            table.closed(2).await;
            loop {
                let now = binding
                    .auth
                    .fields_now(binding.handle, &FieldsRequest::default());
                if presented(now.as_ref()).as_deref() == Some("Bearer oracle-minted-2") {
                    return;
                }
                tokio::task::yield_now().await;
            }
        })
        .await;
        assert!(refreshed.is_ok(), "the refreshed bearer is presented");
        let opened = table.opened.lock().unwrap();
        assert_eq!(opened.len(), 2, "the mint and the refresh: {opened:?}");
        assert!(opened.iter().all(|(need, target, words, _)| *need == 0
            && target == TOKEN_URL
            && words == b"/tenant/oauth2/v2.0/token"));
        assert_eq!(
            opened[1].3,
            "grant_type=client_credentials&client_id=oracle-client-0001&client_secret=\
             oracle%3Asecret%3Awith%3Acolons&scope=https%3A%2F%2Fcognitiveservices.azure.com%2F.default"
        );
        drop(opened);
        // ROW 74 (F25): the endpoint as the plugin was handed it is the stripped one (its need is
        // pinned there and its mint dialled there, above), and a `user:pass@` the operator wrote rides
        // each mint FIRST as `authorization: Basic`, as 1.5.5's reqwest POST sent it (v1.5.5
        // `oauth_client_credentials.rs:119-126` in its egress-auth tree); a plain endpoint's mint
        // carries none.
        let fields = table.fields.lock().unwrap();
        assert_eq!(fields.len(), 2);
        for head in fields.iter() {
            let lead = head.first().map(|(n, v)| (n.as_str(), v.as_slice()));
            if written == TOKEN_URL {
                assert!(
                    !head
                        .iter()
                        .any(|(n, _)| n.eq_ignore_ascii_case("authorization")),
                    "a plain endpoint's mint presents no authorization: {head:?}"
                );
            } else {
                assert_eq!(lead, Some(("authorization", basic.as_bytes())), "{head:?}");
            }
            assert!(
                head.iter()
                    .all(|(_, v)| !String::from_utf8_lossy(v).contains("hunter2")),
                "the userinfo rides only as its Basic value: {head:?}"
            );
        }
    }
}

/// A test-only 2048-bit PKCS#8 RSA private key (generated for the kernel's `jwt_bearer` tests and
/// granting no real access), so the serving plugin can sign the assertion it mints with.
const TEST_SA_KEY_PEM: &str = "-----BEGIN PRIVATE KEY-----\n\
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCu2RTBghXyuvqd\n\
v/4AIq1NcPzdRUCr0wyjEH35avOM9vSW+fuira0UtCQcyTHJZswoJqgwcdO2SRav\n\
/QMZhnjB/sCzuvHrbILd/T0nK19Fdld/wKMQlQlqz94OpS5b0J/nEc7/IOTxszbq\n\
4B2geG7lJc5wm3dMjKwr7IPbnWs5fMEVyZFaFsctrejOTURx8duff8eM2L+Lf5No\n\
H2k0h+6blyDTq1Iu+9UM5/AfycgvdhPlcKCL1VZq9+YY5zW5GuXj997TnEWEeiam\n\
ZfaHklhdSX3zzSUkShqayzaxX6YRdlUvE6yEIkjq/AVRVrMZDynyD7J0nsyjykhx\n\
WVh79c5fAgMBAAECggEALHaz2onUPwfhl6AtXadz3s+u3i4wRgHDouwcvQK/sMdU\n\
Z9hmb3YvH6a30EIx0P+9RzCdcMRhjGeFx3dWBHW3282G/624u5+6n+04Ue+rqKRx\n\
l+FLFnpwDKOT2rGS2nJxV3el5iddUUG743rezeISgV9d4jEG44aaegkJdx3PGKz/\n\
E76BIyi9H4oUgiqIyPW2trPEeg5n/1oVMHLGDBhotuM7VPUCegh/J3e1jSxcYvi8\n\
0CutgOLynZAS1xSatbbp8nWrUSRHOUYrgE9OYbS7TSgGz1PjzdcmLEsHEGcor0wm\n\
cT4oePDjZmuxICFBSg96Ffb82t6UGXC7xLQbglsfQQKBgQDlBOBtVQafWVJiEj83\n\
fG2YfKTMx1neGO/6ftBMn7XUt4D/AbL0Kx0/Z5lfxm2cixlxcGWT6e96CmZmEsyA\n\
RFSyuG/bvbTF1c0vaKXcjghtPH5TaB6MjgP3VmjOHR5V5o3JMQX0Xayxf/kBP//f\n\
wfolsPUM5hcB7pMjVDQz0OZacQKBgQDDcm0i42UA1wrh4XUTNAbVHfacTm/zBhVB\n\
zvtEC3WGkBCRdU9JSwFAJitPmxrVS3+w2fxO47IiSngeQEyC2neew/H5FrWSNs+L\n\
xV9Jystubq6oTCulEGBP4gb99FkDY2RToNYOjVrEQDsmiijv3CeZyHnes0/8uMQq\n\
5ekEveH9zwKBgBZvR9zt+1wYz+0zhGXXFpVdgHde//q1zqxnR9h5vMI9x7EzZWht\n\
4MuZRnkPYyV2quNl801uGTuHUUimhsn556IqVyrbhp3qt9LxGW5lq4Wn62gYRwXV\n\
06WjHVkzmQkpMLKIzuCFXKl2s9nffx1YTzzp/Ndqos5ZpKhNU1/QEwDBAoGAfVvA\n\
WldFqmNDbJwCTp3ZIAqG6bx5m4O0ULBkg0FiUTvIFLQMdbMxCycwMnAGpvY04Yb/\n\
iM4MrGfdYXHWYTuk6+U8J4sETNLxDfI7awYysxM03Wd1uvqk+7e6ylpWWZD/gZAw\n\
m8bYh/W2usJ0/VvU3pMyb7/NNwh/chBjBBKSiAsCgYEAsTCMDD6CYdncyFWMtWpK\n\
vaTrTko3xPDigybk5520jK5UkEaZr0meRn1CFYFAnfUs0sKB4EbWkcmkZOayPPtQ\n\
su3l06s8o+WrP8Bp2GikIg+jVz9sdz9Vph0Vr0VOPwdBKbWUT4As0r6Muceq+sH6\n\
oy3z0wnL4GXkIelYmU1zCk0=\n\
-----END PRIVATE KEY-----\n";

/// A member under `auth: jwt-bearer` whose service account names `token_uri`, sealed by the
/// composition over `table` with `metadata` as the provider's posture: its routes, or why the load
/// is refused.
fn jwt_bearer_routes(
    token_uri: &str,
    metadata: busbar_kernel::config_validate::MetadataPosture,
    table: &std::sync::Arc<TokenEndpoint>,
) -> Result<std::collections::BTreeMap<String, busbar_kernel::plane_driver::MemberRoute>, String> {
    use busbar_contract::abi::host::conn::connector::DIRECTION_OUTBOUND;
    let sa = serde_json::json!({
        "client_email": "svc@proj.iam.gserviceaccount.com",
        "private_key": TEST_SA_KEY_PEM,
        "token_uri": token_uri,
    });
    let key_file = std::env::temp_dir().join(format!(
        "busbar-door-steps-jwt-{}-{}",
        std::process::id(),
        token_uri.len()
    ));
    std::fs::write(&key_file, sa.to_string()).expect("key");
    let providers: std::collections::BTreeMap<String, super::ProviderRoute> = [(
        "p".to_string(),
        super::ProviderRoute {
            base_url: "http://127.0.0.1:9".to_string(),
            userinfo: None,
            protocol: "d".to_string(),
            error_map: Default::default(),
            credential: busbar_contract::secret_ref::SecretRef::file(
                key_file.display().to_string(),
            ),
            style: Some("jwt-bearer".to_string()),
            params: super::StyleParams::default(),
            metadata,
        },
    )]
    .into();
    let secrets: std::sync::Arc<dyn busbar_contract::secret::SecretResolve> =
        std::sync::Arc::new(busbar_kernel::config::secret::SecretResolver::builtins_only());
    let reach = super::DoorReach {
        providers: &providers,
        secrets: std::sync::Arc::clone(&secrets),
        auths: std::sync::Arc::new(linked_mint_plugin(table)),
        conns: std::sync::Arc::new(busbar_core_connector::Connector::new()),
        stream_ceiling_secs: 1,
        catalog: None,
        models: None,
        upgrades: Vec::new(),
    };
    let section: serde_yaml::Value =
        serde_yaml::from_str("models: {m: {provider: p}}").expect("yaml");
    let facts = crate::root::loader::dispatch::kinds::plane::ServedFacts {
        need_auths: vec![(DIRECTION_OUTBOUND, "jwt-bearer")],
        dialects: vec!["d"],
        ..Default::default()
    };
    let routes = super::member_routes(
        &section,
        &DoorPools::of(&section).expect("the pools"),
        &facts,
        &reach,
        &busbar_contract::config_time::ConfigScope::config_time(),
    );
    let _ = std::fs::remove_file(&key_file);
    routes
}

/// RED (ARCHITECT 2026-10-04 parity ruling, THE DESIGN §5 `loopback-allowed`: "auth mint endpoints
/// (`token_url`, `token_uri`)"; the oracle cell `egress.auth|jwt-bearer|mint-refresh`): THE MEMBER
/// UNDER `auth: jwt-bearer` MINTS AT ITS SERVICE ACCOUNT'S `token_uri`. The serving plugin's
/// `settings.token_uri` need is declared pinned to the endpoint the service account names (the
/// seal fills it from the resolved credential), the first request carries the bearer minted there,
/// and the mint is 1.5.5's RFC 7523 POST (`egress_auth/jwt_bearer.rs:172-178`, v1.5.5).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_member_under_jwt_bearer_mints_at_its_service_accounts_token_uri() {
    use busbar_contract::auth_calls::FieldsRequest;
    const TOKEN_URI: &str = "https://oauth2.example.com/token";
    let table = std::sync::Arc::new(TokenEndpoint::default());
    let routes = jwt_bearer_routes(
        TOKEN_URI,
        busbar_kernel::config_validate::MetadataPosture::default(),
        &table,
    )
    .expect("the member resolves");
    let binding = routes["m"].auth.clone().expect("its credential is bound");
    assert!(
        table
            .declared
            .lock()
            .unwrap()
            .iter()
            .any(|(_, _, target)| target.as_deref() == Some(TOKEN_URI)),
        "the plugin's mint need, pinned to the service account's token_uri: {:?}",
        table.declared.lock().unwrap()
    );
    // A bearer minted at the token_uri is presented once the first mint lands (asked for on
    // the spot, so the cell reads the same whether a pre-mint call waits or answers no header).
    let minted = tokio::time::timeout(std::time::Duration::from_secs(10), async {
        loop {
            let now = binding
                .auth
                .fields_now(binding.handle, &FieldsRequest::default());
            if presented(now.as_ref()).is_some_and(|a| a.starts_with("Bearer oracle-minted-")) {
                return;
            }
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }
    })
    .await;
    assert!(
        minted.is_ok(),
        "a bearer minted at the token_uri is presented"
    );
    let opened = table.opened.lock().unwrap();
    let (_, target, words, body) = &opened[0];
    assert_eq!(target, TOKEN_URI);
    assert_eq!(words, b"/token");
    assert!(
        body.starts_with(
            "grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Ajwt-bearer&assertion="
        ),
        "1.5.5's RFC 7523 form: {body}"
    );
}

/// ROW 74 (F25), `jwt-bearer`: 1.5.5 POSTed the signed assertion with reqwest to the service
/// account's `token_uri` as written (v1.5.5 `crates/busbar/src/egress_auth/jwt_bearer.rs:175-181`),
/// whose builder took a `user:pass@` out of the URL and sent it FIRST as `authorization: Basic` (the
/// form names no `authorization`). A service account whose `token_uri` spells one, served on the
/// DOOR path: the plane's side of the seal (the member's route, the declared need) carries no
/// userinfo; the assertion's `aud` is the raw `token_uri`, as 1.5.5 signed it; and the mint POSTs
/// to the stripped endpoint, led by the Basic value, with no field carrying the userinfo in clear.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_service_account_token_uri_userinfo_rides_the_mint_as_1_5_5_sent_it() {
    use base64::Engine as _;
    use busbar_contract::auth_calls::FieldsRequest;
    const TOKEN_URI: &str = "https://oauth2.example.com/token";
    let written = TOKEN_URI.replacen("://", "://svcuser:hunter2-P4ss@", 1);
    let table = std::sync::Arc::new(TokenEndpoint::default());
    let routes = jwt_bearer_routes(
        &written,
        busbar_kernel::config_validate::MetadataPosture::default(),
        &table,
    )
    .expect("a token_uri spelling a userinfo seals, as 1.5.5 accepted it");
    let binding = routes["m"].auth.clone().expect("its credential is bound");
    assert!(
        table
            .declared
            .lock()
            .unwrap()
            .iter()
            .any(|(_, _, target)| target.as_deref() == Some(TOKEN_URI)),
        "the mint need is pinned to the stripped endpoint: {:?}",
        table.declared.lock().unwrap()
    );
    let minted = tokio::time::timeout(std::time::Duration::from_secs(10), async {
        loop {
            let now = binding
                .auth
                .fields_now(binding.handle, &FieldsRequest::default());
            if presented(now.as_ref()).is_some_and(|a| a.starts_with("Bearer oracle-minted-")) {
                return;
            }
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }
    })
    .await;
    assert!(minted.is_ok(), "a bearer minted at the stripped endpoint");
    assert_eq!(table.opened.lock().unwrap()[0].1, TOKEN_URI);
    let basic = format!(
        "Basic {}",
        base64::engine::general_purpose::STANDARD.encode("svcuser:hunter2-P4ss")
    );
    let fields = table.fields.lock().unwrap();
    let head = &fields[0];
    assert_eq!(
        head.first().map(|(n, v)| (n.as_str(), v.as_slice())),
        Some(("authorization", basic.as_bytes())),
        "{head:?}"
    );
    assert!(
        head.iter()
            .all(|(_, v)| !String::from_utf8_lossy(v).contains("hunter2")),
        "{head:?}"
    );
    drop(fields);
    // (1) Nothing the plane's side of the seal holds carries the userinfo: the member's sealed
    // route (its base and every base a framer spells it in) and the need the minting plugin
    // declared over its settings. The service account itself goes to the auth plugin alone.
    let route = &routes["m"];
    assert!(
        !route.base_url.contains("svcuser")
            && route
                .spelled
                .iter()
                .all(|(_, url)| !url.contains("svcuser")),
        "the member's route carries no userinfo"
    );
    assert!(
        table
            .declared
            .lock()
            .unwrap()
            .iter()
            .all(|(_, _, target)| !matches!(target, Some(t) if t.contains("svcuser"))),
        "no declared need carries the userinfo: {:?}",
        table.declared.lock().unwrap()
    );
    // (2) The assertion's `aud` is the service account's `token_uri` AS WRITTEN, userinfo and all:
    // 1.5.5 signed it over the raw endpoint (v1.5.5 `crates/busbar/src/egress_auth/jwt_bearer.rs:
    // 152-159`, `jwt_claims_json(.., &self.token_uri, ..)`), and only the POST's URL lost it.
    let body = table.opened.lock().unwrap()[0].3.clone();
    let assertion = body
        .split('&')
        .find_map(|pair| pair.strip_prefix("assertion="))
        .expect("the RFC 7523 form carries the assertion");
    let claims = assertion.split('.').nth(1).expect("a compact JWT");
    let claims: serde_json::Value = serde_json::from_slice(
        &base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(claims)
            .expect("base64url claims"),
    )
    .expect("JSON claims");
    assert_eq!(
        claims["aud"],
        written.as_str(),
        "the aud is the raw token_uri, as 1.5.5 signed it"
    );
}

/// RED (1.5.5 `main.rs:2960-2966` over `egress_auth/jwt_bearer.rs::validate_token_uri`, v1.5.5): A
/// SERVICE ACCOUNT'S `token_uri` IS JUDGED AT THE SEAL, in 1.5.5's words — plaintext to a public
/// host and a cloud-metadata host are refused, naming the provider; the provider's metadata posture
/// carves the metadata host back out, as 1.5.5's did.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_service_account_token_uri_is_judged_at_the_seal_in_1_5_5s_words() {
    use busbar_kernel::config_validate::MetadataPosture;
    let table = std::sync::Arc::new(TokenEndpoint::default());
    let Err(plaintext) = jwt_bearer_routes(
        "http://oauth2.example.com/token",
        MetadataPosture::default(),
        &table,
    ) else {
        panic!("plaintext to a public host is refused");
    };
    assert_eq!(
        plaintext,
        "provider 'p' (jwt-bearer auth): service-account token_uri must use https for a public \
         host (got 'http://oauth2.example.com/token'); it receives the signed JWT assertion, so \
         plaintext http is permitted only for a private/loopback endpoint"
    );
    let Err(metadata) = jwt_bearer_routes(
        "https://169.254.169.254/token",
        MetadataPosture::default(),
        &table,
    ) else {
        panic!("a metadata host is refused");
    };
    assert!(
        metadata.starts_with(
            "provider 'p' (jwt-bearer auth): service-account token_uri \
             'https://169.254.169.254/token' targets a blocked cloud-metadata host"
        ),
        "{metadata}"
    );
    let allowed = MetadataPosture {
        allow_overrides: vec!["169.254.169.254".to_string()],
        ..MetadataPosture::default()
    };
    assert!(
        jwt_bearer_routes("https://169.254.169.254/token", allowed, &table).is_ok(),
        "the provider's allow-override carves the host back out"
    );
}

/// A REGISTRATION SECTION'S MEMBERS (ARCHITECT Q-L3B-ROUTES): where the plane's need states a
/// member-target path (`settings.*.<key>`), each registration is a member reached at its own
/// `<key>` on that need, its metering rows naming the registration, with no provider and no auth
/// binding. A registration that states no target has no route; the reserved words are no member.
#[test]
fn a_registration_member_is_reached_at_its_own_target() {
    use busbar_contract::abi::host::conn::connector::DIRECTION_OUTBOUND;
    let facts = crate::root::loader::dispatch::kinds::plane::ServedFacts {
        need_auths: vec![(DIRECTION_OUTBOUND, "")],
        need_targets: vec!["settings.*.url"],
        ..Default::default()
    };
    let routes = resolve_for(
        &facts,
        "fs: {url: \"http://127.0.0.1:7/rpc\"}\nlocal: {command: run}\nhooks: [h]\n",
        &[],
    )
    .expect("the registrations resolve");
    assert_eq!(routes.keys().collect::<Vec<_>>(), ["fs"]);
    let fs = &routes["fs"];
    assert_eq!(fs.need.0, 0);
    assert_eq!(
        fs.base_url, "http://127.0.0.1:7",
        "its URL's origin; the plane spells the path"
    );
    assert_eq!(fs.provider, "fs");
    assert!(fs.auth.is_none());
    // A plane whose need states no member target reaches no registration.
    let none = resolve_for(&styled(), "fs: {url: \"http://127.0.0.1:7/rpc\"}\n", &[])
        .expect("nothing to resolve");
    assert!(none.is_empty());
}

/// THE TOOL DOOR, SERVED END TO END (the fold's flip; BUSBAR-1.6.0.md Part 3 section 12,
/// "The switch") — the tool plane's root leg (`qa/teller-steps.json`): a
/// `tools/call` the tool door claims reaches that plane's driver through its route on the data
/// router (mounted at the router's construction), behind the deployment's auth gate, is admitted
/// and charged by the money steps, crosses the plane's door (`arrive`, the ATTEMPT, the far end's
/// answer), leaves through the host chokepoint (the plane's egress walk over the process's
/// connector) to a real tool server on loopback, and comes back a served 200 whose money record is
/// posted: the governance ledger holds the admitted request and the node's book the unit's one line
/// with the tool call the plane reported. The plane is the tool plane's own door, linked (compiled
/// in) and bound through the loader's one load, its need declared on the connector, exactly as its
/// linked row binds it. The dropped-in fold of the same door is the plane crate's own
/// conformance suite (`tests/conformance.rs`, one transcript through both loads).
#[cfg(all(linked_axis_plane_door, linked_section_pools))]
pub(crate) mod tool_door {
    use std::collections::BTreeMap;
    use std::sync::Arc;

    use axum::http::StatusCode;
    use busbar_contract::abi::mechanism::door::DoorFn;
    use busbar_contract::caps::ReasonCode;
    use busbar_contract::conn::{DeclaredConns, PollConns};
    use busbar_kernel::cost::CostModel;
    use busbar_kernel::governance::signing::{TokenSigner, DEFAULT_KID};
    use busbar_kernel::governance::{GovState, MemoryStore, NewKeySpec, PLANE_LANE_SEP};
    use busbar_kernel::plane_driver::{refusal_status, EndPost, PlaneMoney};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    use crate::root::loader::dispatch::kinds::plane::Plane;
    use crate::root::loader::dispatch::{
        load_linked, Bind, DispatchConfig, Dispatcher, LinkedRow, NoSink,
    };
    use crate::root::plane_node::{Node, NodeEndPost};
    use crate::root::serve::planes_tests::{composed_services, money, Published, PUBLISHING};
    use crate::root::serve::{compose_planes, door_routes};

    /// The deployment's dated card history the served unit is pinned to at its door: one entry, no
    /// price (billing off: the counts are the unit's fact and price at nothing).
    static CARD: std::sync::LazyLock<crate::root::kernel::RootHistory> =
        std::sync::LazyLock::new(|| {
            let holder = crate::root::kernel::RootHistory::default();
            holder.apply(
                crate::root::kernel::card_from_config(
                    std::iter::empty::<(&str, busbar_contract::billing::RawTierRates)>(),
                    0,
                    true,
                ),
                1_000,
            );
            holder
        });

    /// The governance book's admin token.
    pub(crate) const ADMIN_TOKEN: &str = "admintok";

    /// The deployment's public base URL: the door claims its routes under it.
    pub(crate) const PUBLIC_URL: &str = "http://127.0.0.1";

    /// The plane's wire words that its Statement does not carry, as DATA
    /// (`tests/fixtures/tool_door_wire.txt`): one `key = value` per line, `#` a comment.
    pub(crate) fn surface(key: &str) -> &'static str {
        include_str!("fixtures/tool_door_wire.txt")
            .lines()
            .map(str::trim)
            .filter(|l| !l.is_empty() && !l.starts_with('#'))
            .find_map(|l| {
                let (k, v) = l.split_once('=')?;
                (k.trim() == key).then(|| v.trim())
            })
            .unwrap_or_else(|| panic!("fixtures/tool_door_wire.txt has no `{key}` row"))
    }

    /// A fixture sentence with its `{PLANE}` filled: the plane's own key (`plane_key`), upper-cased,
    /// as the plane's sentences spell it.
    pub(crate) fn sentence(key: &str) -> String {
        surface(key).replace("{PLANE}", &surface("plane_key").to_ascii_uppercase())
    }

    /// The section the tool door owns beside its settings: its endpoint block, as the fixture
    /// states it (the root spells no plane's section).
    pub(crate) fn endpoint_section() -> &'static str {
        surface("endpoint_section")
    }

    /// The door's one endpoint (its endpoint section's fixed path).
    fn endpoint() -> String {
        format!("/{}", endpoint_section())
    }

    /// The revision the door speaks, as a request states it.
    pub(crate) fn protocol_version() -> &'static str {
        surface("protocol_version")
    }

    /// THE TOOL DOOR: of the linked plane doors, the one whose Statement owns the endpoint section
    /// the fixture names (found by binding each, once).
    pub(crate) fn line_door() -> DoorFn {
        static DOOR: std::sync::OnceLock<DoorFn> = std::sync::OnceLock::new();
        *DOOR.get_or_init(|| {
            let section = endpoint_section();
            let dispatcher = Arc::new(Dispatcher::new(DispatchConfig::default()));
            crate::root::connector::install_io(&dispatcher);
            // The host lends the dispatcher its seal (Part 2 #54), as the root does at boot.
            let _ = dispatcher.lend_seal(busbar_kernel::seal::lend());
            crate::LINKED
                .plane_doors
                .iter()
                .copied()
                .find(|&door| {
                    let Ok(row) = LinkedRow::of(door) else {
                        return false;
                    };
                    load_linked::<Plane>(
                        &row,
                        Bind {
                            instance: Arc::from("line-door-probe"),
                            max_inflight_cap: 64,
                            sink: Arc::new(NoSink),
                            dispatcher: dispatcher.adopter(),
                            conns: crate::root::loader::dispatch::ConnTable::Probe,
                        },
                    )
                    .is_ok_and(|plane| plane.served().owns.contains(&section))
                })
                .expect("a linked plane door owns the endpoint section")
        })
    }

    /// A stateless-revision `tools/call` of the one approved tool.
    pub(crate) const CALL: &str = r#"{"jsonrpc":"2.0","id":30,"method":"tools/call","params":{"name":"fs_read_file","arguments":{},"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":{}}}}"#;

    /// A stateless-revision `tools/list`: the plane's own to answer.
    const LIST: &str = r#"{"jsonrpc":"2.0","id":9,"method":"tools/list","params":{"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":{}}}}"#;

    /// The tool server's answer: a tool result.
    const ANSWER: &str = r#"{"jsonrpc":"2.0","id":0,"result":{"content":[{"type":"text","text":"from the server"}]}}"#;

    /// The `tools:` section: one server on loopback at `port`, one approved tool.
    pub(crate) fn section(port: u16) -> serde_yaml::Value {
        serde_yaml::from_str(&format!(
            "fs:\n  url: \"http://127.0.0.1:{port}/rpc\"\n  pin: {{ mechanism: pinned_pubkey, key: \"sha256/K=\" }}\n  \
         tools_allow:\n    read_file: {{ schema_hash: \"{}\" }}\n",
            tool_digest()
        ))
        .expect("a section")
    }

    /// The one tool the test server serves, as its `tools/list` states it: what verify-on-call
    /// fetches before a call, and what the section approves.
    pub(crate) const TOOL_DESCRIPTION: &str = "reads a file from disk";

    /// That tool's input schema.
    pub(crate) fn tool_schema() -> serde_json::Value {
        serde_json::json!({"type": "object", "properties": {"path": {"type": "string"}}})
    }

    /// That tool's digest: the approval the section writes.
    pub(crate) fn tool_digest() -> String {
        surface("tool_digest").to_string()
    }

    /// That tool, listed.
    pub(crate) fn tool_listing() -> serde_json::Value {
        serde_json::json!([
            {"name": "read_file", "description": TOOL_DESCRIPTION, "inputSchema": tool_schema()}
        ])
    }

    /// A POST of `body` (a `tools/call`) to the door's endpoint on `router`, with `token` as its bearer
    /// or with none: the response's status and body.
    pub(crate) async fn send(
        router: &axum::Router,
        token: Option<&str>,
        body: &str,
    ) -> (StatusCode, Vec<u8>) {
        send_as(router, token, body, "tools/call", Some("fs_read_file")).await
    }

    /// A POST of `body` naming `method` (and the tool `name`, where it names one) to the door's
    /// endpoint: the response's status and body.
    pub(crate) async fn send_as(
        router: &axum::Router,
        token: Option<&str>,
        body: &str,
        method: &str,
        name: Option<&str>,
    ) -> (StatusCode, Vec<u8>) {
        let (status, _, body) = send_headed(router, token, body, method, name).await;
        (status, body)
    }

    /// [`send_as`], with the response's head fields.
    pub(crate) async fn send_headed(
        router: &axum::Router,
        token: Option<&str>,
        body: &str,
        method: &str,
        name: Option<&str>,
    ) -> (StatusCode, axum::http::HeaderMap, Vec<u8>) {
        use tower::ServiceExt as _;
        let mut req = axum::http::Request::builder()
            .method("POST")
            .uri(endpoint())
            .header("content-type", "application/json")
            .header("accept", "application/json")
            .header(surface("protocol_header"), protocol_version())
            .header(surface("method_header"), method);
        if let Some(name) = name {
            req = req.header(surface("name_header"), name);
        }
        if let Some(token) = token {
            req = req.header("authorization", format!("Bearer {token}"));
        }
        let req = req
            .body(axum::body::Body::from(body.to_string()))
            .expect("a request");
        let response = router
            .clone()
            .oneshot(req)
            .await
            .expect("the router answers");
        let status = response.status();
        let headers = response.headers().clone();
        let bytes = axum::body::to_bytes(response.into_body(), 1 << 16)
            .await
            .expect("the body");
        (status, headers, bytes.to_vec())
    }

    /// A tool server on loopback answering every request with [`ANSWER`]; what it was sent comes back
    /// on the channel, one request per connection.
    pub(crate) async fn tool_server() -> (u16, tokio::sync::mpsc::UnboundedReceiver<String>) {
        tool_server_listing(Arc::new(std::sync::Mutex::new(tool_listing()))).await
    }

    /// [`tool_server`], answering a `tools/list` with the tool list `tools` holds when it is asked
    /// (the list may change under it: the rug-pull).
    pub(crate) async fn tool_server_listing(
        tools: Arc<std::sync::Mutex<serde_json::Value>>,
    ) -> (u16, tokio::sync::mpsc::UnboundedReceiver<String>) {
        tool_server_answering(Arc::new(move |request: &str| {
            if request.contains("\"tools/list\"") {
                let list = tools.lock().map(|t| t.clone()).unwrap_or_default();
                serde_json::json!({"jsonrpc": "2.0", "id": 1, "result": {"tools": list}})
                    .to_string()
            } else {
                ANSWER.to_string()
            }
        }))
        .await
    }

    /// A tool server on loopback answering each request (its head and body, as text) with what
    /// `answer` makes of it; every request is heard.
    pub(crate) async fn tool_server_answering(
        answer: Arc<dyn Fn(&str) -> String + Send + Sync>,
    ) -> (u16, tokio::sync::mpsc::UnboundedReceiver<String>) {
        tool_server_replying(Arc::new(move |request: &str| (200, answer(request)))).await
    }

    /// What a test server answers a request with: its status and body. Status [`STALL`] answers
    /// nothing: the request is taken and the connection held open, unanswered.
    pub(crate) type Replies = Arc<dyn Fn(&str) -> (u16, String) + Send + Sync>;

    /// The status a [`Replies`] answers with to take a request and never answer it: a stalled server.
    pub(crate) const STALL: u16 = 0;

    /// A tool server on loopback answering each request with the status and body `answer` makes of
    /// it; every request is heard.
    pub(crate) async fn tool_server_replying(
        answer: Replies,
    ) -> (u16, tokio::sync::mpsc::UnboundedReceiver<String>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("a loopback port");
        let port = listener.local_addr().expect("its address").port();
        let (sent, heard) = tokio::sync::mpsc::unbounded_channel();
        tokio::spawn(async move {
            while let Ok((mut socket, _)) = listener.accept().await {
                let sent = sent.clone();
                let answer = Arc::clone(&answer);
                tokio::spawn(async move {
                    let mut buf = vec![0u8; 16 * 1024];
                    let mut got = Vec::new();
                    // The head, then the body its content-length states.
                    loop {
                        let Ok(n) = socket.read(&mut buf).await else {
                            return;
                        };
                        if n == 0 {
                            return;
                        }
                        got.extend_from_slice(&buf[..n]);
                        let text = String::from_utf8_lossy(&got).to_string();
                        if let Some(at) = text.find("\r\n\r\n") {
                            let length = text[..at]
                                .lines()
                                .find_map(|l| {
                                    let (name, value) = l.split_once(':')?;
                                    name.eq_ignore_ascii_case("content-length")
                                        .then(|| value.trim().parse::<usize>().ok())
                                        .flatten()
                                })
                                .unwrap_or(0);
                            if got.len() >= at + 4 + length {
                                let _ = sent.send(text);
                                break;
                            }
                        }
                    }
                    let (status, answer) = answer(&String::from_utf8_lossy(&got));
                    if status == STALL {
                        tokio::time::sleep(std::time::Duration::from_secs(120)).await;
                        drop(socket);
                        return;
                    }
                    let reply = format!(
                        "HTTP/1.1 {status} X\r\ncontent-type: application/json\r\ncontent-length: {}\r\n\
                         connection: close\r\n\r\n{answer}",
                        answer.len()
                    );
                    let _ = socket.write_all(reply.as_bytes()).await;
                    let _ = socket.shutdown().await;
                });
            }
        });
        (port, heard)
    }

    /// A loopback port nothing listens on (bound, then released): a server that is down.
    async fn down_port() -> u16 {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("a loopback port");
        listener.local_addr().expect("its address").port()
    }

    /// THE COMPOSED MCP DOOR, served: the data router built with its routes, the governance book with
    /// one minted key, the money steps and the node's book the unit settles on.
    pub(crate) struct Rig {
        pub(crate) router: axum::Router,
        /// The admin router, with the door's stated admin routes mounted.
        pub(crate) admin: axum::Router,
        pub(crate) gov: Arc<GovState>,
        pub(crate) app: Arc<busbar_kernel::state::App>,
        pub(crate) key: Arc<busbar_contract::records::VirtualKey>,
        pub(crate) token: String,
        money_steps: Arc<PlaneMoney>,
        post: Arc<NodeEndPost>,
        pub(crate) book: crate::root::durability::NodeBook,
        pub(crate) plane_key: String,
        /// The record store the kernel's services persist the plane's records in.
        pub(crate) store: Arc<busbar_kernel::governance::MemoryStore>,
        /// The token endpoint the auth plugins' own needs reach: each RFC 8693 exchange is answered
        /// `tok-<its scope, as the form carried it>`, and every request is recorded.
        pub(crate) tokens: Arc<super::TokenEndpoint>,
        /// The door's routes the data router was built with: `(path, method, admission bar)`.
        pub(crate) door_table: Vec<(
            String,
            String,
            busbar_contract::abi::mechanism::route::RouteAuth,
        )>,
        /// The door, as bound: what a new generation is published through (`refresh`).
        pub(crate) plane: crate::root::boot::DoorPlane,
        /// How far the kernel's monotonic clock (`clock.now`) reads ahead of the runtime's.
        pub(crate) clock: Arc<std::sync::atomic::AtomicU64>,
        /// How far the kernel's wall clock reads ahead of the system's, in milliseconds.
        pub(crate) wall: Arc<std::sync::atomic::AtomicU64>,
        /// What a config apply refreshes the served door onto (`DoorApply::apply`).
        pub(crate) live: Arc<crate::root::serve::DoorApply>,
    }

    impl Rig {
        /// The mcp door composed as `instance`, its one server routed to `port` on loopback, its key's
        /// pool grant `allowed_pools` (`None` = every scope).
        fn new(instance: &'static str, port: u16, allowed_pools: Option<Vec<String>>) -> Self {
            Self::with(
                instance,
                port,
                allowed_pools,
                None,
                None,
                Footing::own(),
                &|app| app,
            )
        }

        /// [`Self::new`], its kernel `App` configured further by `configure` before it is built.
        pub(crate) fn with(
            instance: &'static str,
            port: u16,
            allowed_pools: Option<Vec<String>>,
            block: Option<serde_yaml::Value>,
            tools: Option<serde_yaml::Value>,
            footing: Footing<'_>,
            configure: &dyn Fn(
                busbar_kernel::test_support::TestApp,
            ) -> busbar_kernel::test_support::TestApp,
        ) -> Self {
            Self::try_with(
                instance,
                port,
                allowed_pools,
                block,
                tools,
                footing,
                configure,
            )
            .unwrap_or_else(|e| panic!("the door plane composes: {e}"))
        }

        /// [`Self::with`], the composition's refusal answered rather than panicked on: what the
        /// root's boot refuses with (`main.rs` dies on it), the operator's text.
        pub(crate) fn try_with(
            instance: &'static str,
            port: u16,
            allowed_pools: Option<Vec<String>>,
            block: Option<serde_yaml::Value>,
            tools: Option<serde_yaml::Value>,
            footing: Footing<'_>,
            configure: &dyn Fn(
                busbar_kernel::test_support::TestApp,
            ) -> busbar_kernel::test_support::TestApp,
        ) -> Result<Self, String> {
            // THE CONNECTOR, over every linked transport door (the default distribution links the
            // http framer's door), its dials judged by a destination guard that admits loopback. The
            // same guard is the kernel's `dest.judge` (as `root::serve::kernel_services` composes
            // it), and the deployment blocks one extra host ([`BLOCKED_HOST`]).
            let judge = crate::root::connector::guard_for(&busbar_kernel::config::Destinations {
                block_private_addresses: footing.guarded,
                blocked: vec![BLOCKED_HOST.to_string()],
                ..Default::default()
            })
            .expect("the guard");
            // The process's host services: the kernel's composed services the dispatcher answers the
            // door's service calls with (`entitlement.check` over the unit's recorded principal), the
            // same ones the plane is admitted to, composed whole: a record store (the plane's chained
            // call record is appended to its journal there) and the pool its store calls run on.
            // THE MONEY: a signing governance book with one minted key, the node's book bound.
            let signer = TokenSigner::from_secret_bytes(&[7u8; 32], DEFAULT_KID);
            let gov = Arc::new(
                GovState::new_with_signer(
                    Arc::new(MemoryStore::new()),
                    Some(ADMIN_TOKEN.to_string()),
                    Some(signer),
                )
                .expect("governance"),
            );
            // A fleet node reads the first node's book: one key registry, one signing key.
            let (gov, key, token) = match footing.book {
                Some(first) => (
                    Arc::clone(&first.gov),
                    Arc::clone(&first.key),
                    first.token.clone(),
                ),
                None => {
                    let (key, token) = gov
                        .mint_signed(
                            NewKeySpec {
                                name: "agent".to_string(),
                                allowed_pools,
                                ..Default::default()
                            },
                            4_000_000_000,
                            1_700_000_000,
                        )
                        .expect("mint");
                    gov.hydrate_budgets(&CostModel::flat(1), 0)
                        .expect("hydrate");
                    (
                        gov,
                        Arc::new(key),
                        token.expose(&busbar_kernel::seal::lend()).to_string(),
                    )
                }
            };
            let clock = Arc::new(std::sync::atomic::AtomicU64::new(0));
            let wall = Arc::new(std::sync::atomic::AtomicU64::new(0));
            let (late, store) = records_composed(
                footing.ledger,
                Arc::clone(&gov),
                (&clock, &wall),
                Arc::clone(&judge) as Arc<dyn busbar_kernel::host_services::DestJudge>,
            );
            let dispatcher = Arc::new(Dispatcher::with_services(
                DispatchConfig::default(),
                Arc::new(Clocked {
                    inner: Arc::clone(&late) as Arc<dyn busbar_contract::services::HostServices>,
                    wall: Arc::clone(&wall),
                }),
            ));
            // The transport doors bind on this dispatcher and reach its host services (the clock
            // the program carrier supervises a member's program by), as main.rs hands the process's
            // one dispatcher to `root::doors` before any door binds.
            crate::root::doors::install_dispatcher(Arc::clone(&dispatcher));
            crate::root::connector::install_io(&dispatcher);
            // The host lends the dispatcher its seal (Part 2 #54), as the root does at boot.
            let _ = dispatcher.lend_seal(busbar_kernel::seal::lend());
            // Its connection reads through a ticket (the door's `exchange`) wake on the dispatcher.
            let connector = busbar_core_connector::process::build_with_secrets(
                || {
                    crate::root::connector::entries(
                        crate::LINKED_TRANSPORT_DOORS,
                        &busbar_contract::transport::TransportSettings::default(),
                    )
                },
                judge,
                &[],
                dispatcher.conn_waker(),
                busbar_core_connector::pool::PoolPosture::NONE,
                busbar_kernel::config::secret::resolve_linked_string_at_config,
            )
            .expect("the connector builds");
            let plane = bound(
                instance,
                &dispatcher,
                crate::root::loader::dispatch::ConnTable::Host(
                    Arc::clone(&connector) as Arc<dyn DeclaredConns>
                ),
            );
            let caller = plane.instance();
            let section_key = plane.served().section;
            assert_eq!(
                section_key,
                surface("section"),
                "the door opens with the section its grammar reads"
            );

            let node = Arc::new(Node::new());
            let book = crate::root::durability::node_book_over(Box::new(|| CARD.pin()));
            node.bind_book(Arc::clone(&book.durability));
            let post = Arc::new(NodeEndPost::new(Arc::clone(&node)));
            let site = Arc::clone(&post);
            let book_money = Arc::clone(&gov);
            let plane_money = move || {
                Arc::new(PlaneMoney::new(
                    Arc::clone(&book_money),
                    Arc::clone(&site) as Arc<dyn EndPost>,
                ))
            };

            // THE COMPOSITION: the door opened with its `tools:` section and the deployment's public
            // base URL, driven, its egress sealed as production seals it (ARCHITECT Q-L3B-ROUTES): the
            // one server's member route is read off its own registration (`url`, the door's need's
            // member target), no provider and no auth binding (the server takes no credential).
            let mut sections = BTreeMap::new();
            // Its endpoint block, when the deployment writes one, under the section it owns.
            if let Some(block) = block {
                sections.insert(plane.served().owns[0], block);
            }
            sections.insert(section_key, tools.unwrap_or_else(|| section(port)));
            let providers = BTreeMap::new();
            let secrets: std::sync::Arc<dyn busbar_contract::secret::SecretResolve> =
                std::sync::Arc::new(busbar_kernel::config::secret::SecretResolver::builtins_only());
            // The build's linked auth rows, and the OAuth plugin (a dropped-in plugin in a
            // deployment) a token-exchange registration's style is served by. Its own need (the
            // `open-web` token endpoint, connection security only) reaches a table standing in for
            // the authorization server.
            let mut linked = crate::LINKED.auths.to_vec();
            let name = "busbar-auth-oauth";
            linked.push((name, name, busbar_auth_oauth::door));
            let tokens = Arc::new(super::TokenEndpoint {
                answer: Some(|body: &str| {
                    let scope = body
                        .split('&')
                        .find_map(|pair| pair.strip_prefix("scope="))
                        .unwrap_or_default();
                    format!(r#"{{"access_token":"tok-{scope}","expires_in":3600}}"#)
                }),
                ..super::TokenEndpoint::default()
            });
            let auths = crate::root::door_steps::OutboundAuths::new(
                Arc::clone(&dispatcher),
                &linked,
                None,
                crate::root::loader::dispatch::ConnTable::Host(
                    Arc::clone(&tokens) as Arc<dyn DeclaredConns>
                ),
            );
            let reach = crate::root::door_steps::DoorReach {
                providers: &providers,
                secrets: std::sync::Arc::clone(&secrets),
                auths: Arc::new(auths),
                conns: Arc::clone(&connector) as Arc<dyn PollConns>,
                models: None,
                stream_ceiling_secs: 600,
                catalog: None,
                upgrades: Vec::new(),
            };
            let egress = crate::root::serve::DoorEgress {
                reach: &reach,
                journal: Arc::clone(&post) as Arc<dyn busbar_kernel_egress::ports::Journal>,
            };
            let doors = [(instance.to_string(), plane)];
            // THE KERNEL'S HOOK STAGE over this rig's generation (the App built below): the plane's
            // tail states its hook order, and the stage binds the deployment's per-entry hooks.
            let live_app: Arc<std::sync::OnceLock<Arc<busbar_kernel::state::App>>> = Arc::default();
            let stage = crate::root::serve::HookStage {
                host: {
                    let live_app = Arc::clone(&live_app);
                    Arc::new(move || {
                        busbar_kernel::plane_driver::engine_host(
                            live_app
                                .get()
                                .expect("the rig's App is built before any unit"),
                        )
                    })
                },
                gov: Arc::clone(&gov),
                journal: None,
            };
            let mut served = compose_planes(
                &doors,
                &dispatcher,
                &late,
                &sections,
                Some(PUBLIC_URL),
                &plane_money,
                Some(&egress),
                Some(&stage),
            )?;
            let _ = caller;
            let composed = &mut served.planes[0];
            assert!(
                composed.live.current().egress.is_some(),
                "its egress is sealed"
            );
            let money_steps = Arc::clone(&composed.money);
            let live = Arc::clone(&composed.live);
            let plane_key = composed.facts.plane.clone();
            served.post = Some(Arc::clone(&post));
            let app = configure(
                busbar_kernel::test_support::TestApp::new()
                    .keys_chain()
                    .governance(Arc::clone(&gov))
                    .cost(CostModel::flat(1)),
            )
            .build();
            let _ = live_app.set(Arc::clone(&app));
            // The kernel re-resolves each unit's principal over this generation, as the root
            // attaches it over its live snapshot.
            if let Some(kernel) = late.kernel() {
                let _attached = kernel
                    .attach_standing(busbar_kernel::plane_driver::standing_over(Arc::clone(&app)));
            }
            // Its tick schedule and ready-session fan-out, as the process spawns them.
            served.spawn_ticks();
            let [(_, plane)] = doors;
            // THE DATA ROUTER, BUILT WITH THE DOOR'S ROUTES (its construction, no static).
            let doors = door_routes(served, || CARD.pin(), &[], &[]).expect("its claims mount");
            let door_table = doors
                .iter()
                .map(|d| (d.path.clone(), d.method.as_str().to_string(), d.auth))
                .collect();
            let (router, admin, _handle) = busbar_kernel::build_split_routers_serving(
                Arc::clone(&app),
                doors,
                1 << 20,
                0,
                false,
            );
            Ok(Rig {
                router,
                admin,
                gov,
                app,
                key,
                token,
                money_steps,
                post,
                book,
                plane_key,
                store,
                tokens,
                door_table,
                plane,
                clock,
                wall,
                live,
            })
        }

        /// The key's admitted requests on the governance ledger.
        pub(crate) fn admitted(&self) -> u64 {
            self.gov
                .usage_for(&self.app.cost, &self.key.id, busbar_kernel::store::now())
                .expect("a read")
                .expect("the key exists")
                .requests
        }

        /// Every unit closed on the money steps and the node (one terminal, no unit left open).
        pub(crate) fn all_ended(&self) -> bool {
            self.money_steps.open_units() == 0 && self.post.open_units() == 0
        }
    }

    /// [`Rig::with`], for a sibling module.
    pub(crate) fn rig_with(
        instance: &'static str,
        port: u16,
        allowed_pools: Option<Vec<String>>,
        configure: &dyn Fn(
            busbar_kernel::test_support::TestApp,
        ) -> busbar_kernel::test_support::TestApp,
    ) -> Rig {
        Rig::with(
            instance,
            port,
            allowed_pools,
            None,
            None,
            Footing::own(),
            configure,
        )
    }

    /// [`Rig::with`] over the `tools:` section `tools`, standing on `footing`, for a sibling module.
    pub(crate) fn rig_on(
        instance: &'static str,
        port: u16,
        tools: serde_yaml::Value,
        footing: Footing<'_>,
    ) -> Rig {
        Rig::with(instance, port, None, None, Some(tools), footing, &|app| app)
    }

    /// [`Rig::with`] over the `tools:` section `tools`, for a sibling module.
    pub(crate) fn rig_tools(
        instance: &'static str,
        port: u16,
        tools: serde_yaml::Value,
        configure: &dyn Fn(
            busbar_kernel::test_support::TestApp,
        ) -> busbar_kernel::test_support::TestApp,
    ) -> Rig {
        Rig::with(
            instance,
            port,
            None,
            None,
            Some(tools),
            Footing::own(),
            configure,
        )
    }

    /// [`rig_tools`], the composition's refusal answered: what the boot would refuse with.
    pub(crate) fn try_rig_tools(
        instance: &'static str,
        port: u16,
        tools: serde_yaml::Value,
    ) -> Result<Rig, String> {
        Rig::try_with(
            instance,
            port,
            None,
            None,
            Some(tools),
            Footing::own(),
            &|app| app,
        )
    }

    /// The kernel's host services composed whole for a door plane that writes records: a record store
    /// (an in-memory store: its typed record rows and its plane-record slots, where a chained kind's
    /// journal persists), the runtime's blocking pool the store calls run on, and `dest`, the
    /// deployment's one destination judge, installed as the process's late services.
    fn records_composed(
        ledger: Ledger,
        signer: Arc<GovState>,
        (clock, wall): (
            &Arc<std::sync::atomic::AtomicU64>,
            &Arc<std::sync::atomic::AtomicU64>,
        ),
        dest: Arc<dyn busbar_kernel::host_services::DestJudge>,
    ) -> (
        Arc<crate::root::serve::LateServices>,
        Arc<busbar_kernel::governance::MemoryStore>,
    ) {
        let store = Arc::new(busbar_kernel::governance::MemoryStore::new());
        let (origin, ahead) = (std::time::Instant::now(), Arc::clone(clock));
        let wall_ahead = Arc::clone(wall);
        let kernel = busbar_kernel::host_services::KernelServices::new()
            .with_dest_judge(dest)
            .with_mono_clock(Arc::new(move || {
                u64::try_from(origin.elapsed().as_nanos())
                    .unwrap_or(u64::MAX)
                    .saturating_add(ahead.load(std::sync::atomic::Ordering::SeqCst))
            }))
            .with_wall_clock(Arc::new(move || {
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
                    .saturating_add(wall_ahead.load(std::sync::atomic::Ordering::SeqCst))
            }))
            .with_signer(signer)
            .with_pool(Arc::new(busbar_kernel::host_services::BlockingPool::new(
                tokio::runtime::Handle::current(),
                busbar_kernel::host_records::QUEUE_CAP,
            )));
        let kernel = Arc::new(match ledger {
            Ledger::Memory => kernel.with_records(Arc::new(StoreRows(Arc::clone(&store)))),
            Ledger::Store(claims) => {
                kernel.with_records(Arc::new(ClaimsIn(Arc::new(Rows::default()), claims)))
            }
            Ledger::Rows(rows, max_live) => kernel
                .with_work_bounds(busbar_kernel::host_work::WorkBounds {
                    max_live,
                    ..Default::default()
                })
                .with_records(Arc::new(ClaimsIn(rows, Arc::clone(&store) as _))),
            Ledger::Unbound => kernel,
        });
        let late = crate::root::serve::LateServices::new();
        late.install_kernel(Arc::clone(&kernel), kernel)
            .expect("installed once");
        (late, store)
    }

    /// The host services as the door reads them, the wall clock `clock.now` answers read `wall`
    /// milliseconds ahead, as the kernel's work book reads it: every other service is `inner`'s.
    struct Clocked {
        inner: Arc<dyn busbar_contract::services::HostServices>,
        wall: Arc<std::sync::atomic::AtomicU64>,
    }

    impl busbar_contract::services::HostServices for Clocked {
        fn now(&self) -> busbar_contract::services::Reading {
            let mut reading = self.inner.now();
            let ahead = self.wall.load(std::sync::atomic::Ordering::SeqCst);
            reading.wall_ns = reading
                .wall_ns
                .saturating_add(ahead.saturating_mul(1_000_000));
            reading
        }
        fn dest_judge(
            &self,
            dest: &str,
            class: u32,
            flags: u32,
            later: Option<busbar_contract::services::Later>,
        ) -> busbar_contract::services::Ran {
            self.inner.dest_judge(dest, class, flags, later)
        }
        fn records_get(
            &self,
            caller: &busbar_contract::services::Caller,
            kind: &str,
            key: &[u8],
            later: busbar_contract::services::Later,
        ) -> busbar_contract::services::Ran {
            self.inner.records_get(caller, kind, key, later)
        }
        fn records_list(
            &self,
            caller: &busbar_contract::services::Caller,
            list: busbar_contract::services::RecordsList,
            later: busbar_contract::services::Later,
        ) -> busbar_contract::services::Ran {
            self.inner.records_list(caller, list, later)
        }
        fn records_claim(
            &self,
            caller: &busbar_contract::services::Caller,
            kind: &str,
            key: &[u8],
            ttl_ms: u64,
            later: busbar_contract::services::Later,
        ) -> busbar_contract::services::Ran {
            self.inner.records_claim(caller, kind, key, ttl_ms, later)
        }
        fn sign(
            &self,
            caller: &busbar_contract::services::Caller,
            data: &[u8],
        ) -> busbar_contract::services::Stored {
            self.inner.sign(caller, data)
        }
        fn trust_sight(
            &self,
            caller: &busbar_contract::services::Caller,
            counterparty: &str,
            hash: &str,
            later: busbar_contract::services::Later,
        ) -> busbar_contract::services::Ran {
            self.inner.trust_sight(caller, counterparty, hash, later)
        }
        fn trust_unreached(
            &self,
            caller: &busbar_contract::services::Caller,
            counterparty: &str,
        ) -> busbar_contract::services::Stored {
            self.inner.trust_unreached(caller, counterparty)
        }
        fn trust_sight_item(
            &self,
            caller: &busbar_contract::services::Caller,
            counterparty: &str,
            item: &str,
            digest: &str,
        ) -> busbar_contract::services::Stored {
            self.inner
                .trust_sight_item(caller, counterparty, item, digest)
        }
        fn trust_decide(
            &self,
            caller: &busbar_contract::services::Caller,
            key: busbar_contract::services::TrustKeyRef<'_>,
            expected: Option<&str>,
            approve: bool,
        ) -> busbar_contract::services::Stored {
            self.inner.trust_decide(caller, key, expected, approve)
        }
        fn trust_state(
            &self,
            caller: &busbar_contract::services::Caller,
            counterparty: &str,
        ) -> busbar_contract::services::Stored {
            self.inner.trust_state(caller, counterparty)
        }
        fn trust_serves(
            &self,
            caller: &busbar_contract::services::Caller,
            counterparty: &str,
            item: Option<&str>,
            digest: Option<&str>,
        ) -> busbar_contract::services::Stored {
            self.inner.trust_serves(caller, counterparty, item, digest)
        }
        fn trust_due(
            &self,
            caller: &busbar_contract::services::Caller,
        ) -> busbar_contract::services::Stored {
            self.inner.trust_due(caller)
        }
        fn trust_verify(
            &self,
            caller: &busbar_contract::services::Caller,
            counterparty: &str,
            payload: &[u8],
            signatures: &[u8],
        ) -> busbar_contract::services::Stored {
            self.inner
                .trust_verify(caller, counterparty, payload, signatures)
        }
        fn entitlement_check(
            &self,
            caller: &busbar_contract::services::Caller,
            unit: Option<u64>,
            target: &str,
        ) -> busbar_contract::services::Stored {
            self.inner.entitlement_check(caller, unit, target)
        }
        fn session_emit(
            &self,
            caller: &busbar_contract::services::Caller,
            session: u64,
            bytes: &[u8],
        ) -> busbar_contract::services::Stored {
            self.inner.session_emit(caller, session, bytes)
        }
        fn random_fill(&self, len: u64) -> busbar_contract::services::Stored {
            self.inner.random_fill(len)
        }
        fn records_secret(
            &self,
            kind: &str,
            id: &str,
            later: busbar_contract::services::Later,
        ) -> busbar_contract::services::Ran {
            self.inner.records_secret(kind, id, later)
        }
        fn unit_nest(
            &self,
            caller: &busbar_contract::services::Caller,
            unit: Option<u64>,
            ask: busbar_contract::services::NestAsk,
            later: busbar_contract::services::Later,
        ) -> busbar_contract::services::Ran {
            self.inner.unit_nest(caller, unit, ask, later)
        }
        fn work_open(
            &self,
            caller: &busbar_contract::services::Caller,
            unit: Option<u64>,
            kind: &str,
            record: &[u8],
            later: busbar_contract::services::Later,
        ) -> busbar_contract::services::Ran {
            self.inner.work_open(caller, unit, kind, record, later)
        }
        fn work_find(
            &self,
            caller: &busbar_contract::services::Caller,
            unit: Option<u64>,
            reference: &[u8],
            later: busbar_contract::services::Later,
        ) -> busbar_contract::services::Ran {
            self.inner.work_find(caller, unit, reference, later)
        }
        fn work_settle(
            &self,
            caller: &busbar_contract::services::Caller,
            unit: Option<u64>,
            handle: u64,
            record: &[u8],
            later: busbar_contract::services::Later,
        ) -> busbar_contract::services::Ran {
            self.inner.work_settle(caller, unit, handle, record, later)
        }
        fn work_resume(
            &self,
            caller: &busbar_contract::services::Caller,
            unit: Option<u64>,
            handle: u64,
            later: busbar_contract::services::Later,
        ) -> busbar_contract::services::Ran {
            self.inner.work_resume(caller, unit, handle, later)
        }
        fn disk_append(
            &self,
            dest: &busbar_contract::services::DiskDest,
            bytes: Vec<u8>,
            later: busbar_contract::services::Later,
        ) -> busbar_contract::services::Ran {
            self.inner.disk_append(dest, bytes, later)
        }
        fn verify_lookup(
            &self,
            caller: &busbar_contract::services::Caller,
            key: &[u8],
            later: busbar_contract::services::Later,
        ) -> busbar_contract::services::Ran {
            self.inner.verify_lookup(caller, key, later)
        }
        fn verify_store(
            &self,
            caller: &busbar_contract::services::Caller,
            key: &[u8],
            entry: &[u8],
            ttl_ms: u64,
        ) -> busbar_contract::services::Stored {
            self.inner.verify_store(caller, key, entry, ttl_ms)
        }
        fn content_scan(
            &self,
            caller: &busbar_contract::services::Caller,
            unit: Option<u64>,
            content: &[u8],
            later: busbar_contract::services::Later,
        ) -> busbar_contract::services::Ran {
            self.inner.content_scan(caller, unit, content, later)
        }
        fn hook_call(
            &self,
            caller: &busbar_contract::services::Caller,
            unit: Option<u64>,
            ask: busbar_contract::services::HookAsk,
            later: busbar_contract::services::Later,
        ) -> busbar_contract::services::Ran {
            self.inner.hook_call(caller, unit, ask, later)
        }
        fn snapshot_read(
            &self,
            caller: &busbar_contract::services::Caller,
            scope: u32,
        ) -> busbar_contract::services::Snapshot {
            self.inner.snapshot_read(caller, scope)
        }
    }

    /// What a rig stands on: the record store its host services bind, and whose governance book it
    /// reads (its own, or a first node's: a fleet).
    pub(crate) struct Footing<'a> {
        pub(crate) ledger: Ledger,
        pub(crate) book: Option<&'a Rig>,
        /// The connector's destination guard refuses private addresses (a deployment's
        /// `destinations.block_private_addresses`); `false` admits loopback, where the test servers
        /// listen.
        pub(crate) guarded: bool,
    }

    impl Footing<'_> {
        /// Its own in-memory store and its own book.
        pub(crate) fn own() -> Self {
            Footing {
                ledger: Ledger::Memory,
                book: None,
                guarded: false,
            }
        }
    }

    /// A public-looking host the rig's deployment refuses by its own rules alone
    /// (`security.blocked_metadata_hosts`): no address rule refuses it, so only the deployment's
    /// destination judge can.
    pub(crate) const BLOCKED_HOST: &str = "blocked.example";

    /// The record store a rig's host services bind.
    pub(crate) enum Ledger {
        /// A fresh in-memory store (the rig's own).
        Memory,
        /// The given store: a handle on a durable journal (a restart or a fleet node).
        Store(Arc<dyn busbar_contract::records::RecordStore>),
        /// The given typed rows, which the nodes of one deployment and the successive processes of
        /// one node share (their work handles and their plugins' records), the host keeping at most
        /// the given number of live work handles.
        Rows(Arc<Rows>, usize),
        /// None: the host binds no store.
        Unbound,
    }

    /// The rig's in-memory store's own typed record rows, for the records services: what a door
    /// writes through them (a chained kind's sealed records included) is read back off the store.
    struct StoreRows(Arc<busbar_kernel::governance::MemoryStore>);

    impl busbar_kernel::host_records::RecordRows for StoreRows {
        fn claim(
            &self,
            kind: &str,
            token: &str,
            expires_at: u64,
            now: u64,
        ) -> Result<bool, busbar_contract::kinds::StoreError> {
            busbar_contract::records::RecordStore::redeem_plane_token(
                &*self.0, kind, token, expires_at, now,
            )
            .map_err(|e| busbar_contract::kinds::StoreError::Rejected(e.0))
        }
        fn record_put(
            &self,
            schema: busbar_contract::ids::RecordSchemaId,
            key: &[u8],
            value: &busbar_contract::kinds::RecordBytes,
        ) -> Result<(), busbar_contract::kinds::StoreError> {
            self.0.record_put(schema, key, value)
        }

        fn record_get(
            &self,
            schema: busbar_contract::ids::RecordSchemaId,
            key: &[u8],
        ) -> Result<Option<busbar_contract::kinds::RecordBytes>, busbar_contract::kinds::StoreError>
        {
            self.0.record_get(schema, key)
        }

        fn record_scan(
            &self,
            schema: busbar_contract::ids::RecordSchemaId,
            prefix: &[u8],
            limit: u32,
        ) -> Result<
            Vec<(Vec<u8>, busbar_contract::kinds::RecordBytes)>,
            busbar_contract::kinds::StoreError,
        > {
            self.0.record_scan(schema, prefix, limit)
        }
    }

    /// `rows`, every claim but a chained record's position claim redeemed in `claims`: a node whose
    /// typed records are its own and whose claims are the deployment's.
    struct ClaimsIn(Arc<Rows>, Arc<dyn busbar_contract::records::RecordStore>);

    impl busbar_kernel::host_records::RecordRows for ClaimsIn {
        fn claim(
            &self,
            kind: &str,
            token: &str,
            expires_at: u64,
            now: u64,
        ) -> Result<bool, busbar_contract::kinds::StoreError> {
            if kind == busbar_kernel::host_records::CLAIM_KIND {
                return busbar_kernel::host_records::RecordRows::claim(
                    &*self.0, kind, token, expires_at, now,
                );
            }
            busbar_contract::records::RecordStore::redeem_plane_token(
                &*self.1, kind, token, expires_at, now,
            )
            .map_err(|e| busbar_contract::kinds::StoreError::Rejected(e.0))
        }
        fn record_put(
            &self,
            schema: busbar_contract::ids::RecordSchemaId,
            key: &[u8],
            value: &busbar_contract::kinds::RecordBytes,
        ) -> Result<(), busbar_contract::kinds::StoreError> {
            busbar_kernel::host_records::RecordRows::record_put(&*self.0, schema, key, value)
        }

        fn record_get(
            &self,
            schema: busbar_contract::ids::RecordSchemaId,
            key: &[u8],
        ) -> Result<Option<busbar_contract::kinds::RecordBytes>, busbar_contract::kinds::StoreError>
        {
            busbar_kernel::host_records::RecordRows::record_get(&*self.0, schema, key)
        }

        fn record_scan(
            &self,
            schema: busbar_contract::ids::RecordSchemaId,
            prefix: &[u8],
            limit: u32,
        ) -> Result<
            Vec<(Vec<u8>, busbar_contract::kinds::RecordBytes)>,
            busbar_contract::kinds::StoreError,
        > {
            busbar_kernel::host_records::RecordRows::record_scan(&*self.0, schema, prefix, limit)
        }
    }

    /// Typed record rows in memory: the store kind's record slots, for the records services; and
    /// how many writes of a settled work handle the store refuses next.
    #[derive(Default)]
    pub(crate) struct Rows(
        pub(crate)  std::sync::Mutex<
            BTreeMap<
                (busbar_contract::ids::RecordSchemaId, Vec<u8>),
                busbar_contract::kinds::RecordBytes,
            >,
        >,
        pub(crate) std::sync::atomic::AtomicU32,
    );

    impl busbar_kernel::host_records::RecordRows for Rows {
        /// One writer in this test: every claim is the first.
        fn claim(
            &self,
            _kind: &str,
            _token: &str,
            _expires_at: u64,
            _now: u64,
        ) -> Result<bool, busbar_contract::kinds::StoreError> {
            Ok(true)
        }
        fn record_put(
            &self,
            schema: busbar_contract::ids::RecordSchemaId,
            key: &[u8],
            value: &busbar_contract::kinds::RecordBytes,
        ) -> Result<(), busbar_contract::kinds::StoreError> {
            let settles = schema == busbar_kernel::host_work::WORK_SCHEMA
                && value.as_slice().get(1)
                    == Some(&busbar_contract::abi::host::service::WORK_SETTLED);
            let refused = settles
                && self
                    .1
                    .fetch_update(
                        std::sync::atomic::Ordering::SeqCst,
                        std::sync::atomic::Ordering::SeqCst,
                        |n| n.checked_sub(1),
                    )
                    .is_ok();
            if refused {
                return Err(busbar_contract::kinds::StoreError::Unavailable);
            }
            self.0
                .lock()
                .expect("unpoisoned")
                .insert((schema, key.to_vec()), value.clone());
            Ok(())
        }

        fn record_get(
            &self,
            schema: busbar_contract::ids::RecordSchemaId,
            key: &[u8],
        ) -> Result<Option<busbar_contract::kinds::RecordBytes>, busbar_contract::kinds::StoreError>
        {
            Ok(self
                .0
                .lock()
                .expect("unpoisoned")
                .get(&(schema, key.to_vec()))
                .cloned())
        }

        fn record_scan(
            &self,
            schema: busbar_contract::ids::RecordSchemaId,
            prefix: &[u8],
            limit: u32,
        ) -> Result<
            Vec<(Vec<u8>, busbar_contract::kinds::RecordBytes)>,
            busbar_contract::kinds::StoreError,
        > {
            let rows = self.0.lock().expect("unpoisoned");
            let found = rows
                .iter()
                .filter(|((s, k), _)| *s == schema && k.starts_with(prefix))
                .map(|((_, k), v)| (k.clone(), v.clone()));
            Ok(if limit == 0 {
                found.collect()
            } else {
                found.take(limit as usize).collect()
            })
        }
    }

    /// The mcp door, linked, bound through the loader's one load on `dispatcher`, its need declared on
    /// `conns` (`ConnTable::Probe`: declared on none).
    fn bound(
        instance: &str,
        dispatcher: &Arc<Dispatcher>,
        conns: crate::root::loader::dispatch::ConnTable,
    ) -> crate::root::boot::DoorPlane {
        let row = LinkedRow::of(line_door()).expect("the door states its Statement");
        Arc::new(
            load_linked::<Plane>(
                &row,
                Bind {
                    instance: Arc::from(instance),
                    max_inflight_cap: 64,
                    sink: Arc::new(NoSink),
                    dispatcher: dispatcher.adopter(),
                    conns,
                },
            )
            .expect("the linked door binds"),
        )
    }

    /// THE EXIT TEST (steps arrival, route, meter, exit): a keyed caller's `tools/call` arrives as one
    /// unit, is SERVED through the mcp door, 200, the server's tool result relayed to the caller under
    /// the caller's own id, exactly one request metered and the unit's money posted on both books, every
    /// unit ended once.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_tools_call_is_served_through_the_tool_door_and_its_money_posted() {
        let _one = PUBLISHING.lock().await;
        let instance = "serve-door-tools-served";
        let _published = Published(instance);
        let (port, mut heard) = tool_server().await;
        let rig = Rig::new(instance, port, None);

        let (status, body) = send(&rig.router, Some(&rig.token), CALL).await;
        assert_eq!(
            status,
            StatusCode::OK,
            "served through the door: {}",
            String::from_utf8_lossy(&body)
        );
        let body: serde_json::Value = serde_json::from_slice(&body).expect("a JSON-RPC answer");
        assert_eq!(body["id"], 30, "answered under the caller's own id: {body}");
        assert_eq!(
            body["result"]["content"][0]["text"], "from the server",
            "the server's tool result, relayed: {body}"
        );

        // VERIFY-ON-CALL: the server's live tool list was fetched first, over the door's own need.
        let verify = heard
            .recv()
            .await
            .expect("the server was asked for its tool list");
        assert!(verify.starts_with("POST /rpc "), "{verify}");
        assert!(
            verify.contains("\"tools/list\""),
            "the verify fetch: {verify}"
        );
        // THE SERVER HEARD THE PLANE'S REQUEST, through the connector, at its registered path.
        let head = heard.recv().await.expect("the server was dialled");
        assert!(head.starts_with("POST /rpc "), "{head}");
        assert!(head.contains("\"tools/call\""), "the relayed call: {head}");

        // THE MONEY RECORD: the request admitted on the governance ledger, the unit's facts closed on
        // the money steps and the node, and its one line on the node's book carrying the tool call the
        // plane reported, under the (plane key, entry) it was served by.
        assert_eq!(rig.admitted(), 1, "one admitted request");
        assert!(rig.all_ended(), "its facts closed at its end");

        // THE CALL LOG, CHAINED (audit-chain): the call's one record is appended to the plane's call
        // chain in the kernel's record store, sealed by the host when the write-behind flushes it.
        {
            let (_, chained) = crate::root::serve::planes_tests::chained_records(
                &rig.store,
                surface("record_kind_call"),
                busbar_contract::abi::plane::RecordChain {
                    kind: 0,
                    framing: busbar_contract::abi::plane::CHAIN_LENGTH_PREFIXED,
                    flags: busbar_contract::abi::plane::CHAIN_DIGESTS_SCOPE,
                    _reserved: 0,
                },
                1,
            );
            assert_eq!(
                chained.len(),
                1,
                "the call's one chained record: {chained:?}"
            );
        }
        let rows = rig.book.durability.lock().expect("unpoisoned").read_back();
        // The unit's lane is the published tool it called (SEAM-L(j)), as predev ledgered a call.
        let lane = format!("{}{PLANE_LANE_SEP}fs_read_file", rig.plane_key);
        let lines: Vec<_> = rows
            .iter()
            .filter(|p| p.counts.as_ref().is_some_and(|c| c.lane == lane))
            .collect();
        assert_eq!(
            lines.len(),
            1,
            "the unit's one line on the node's book: {rows:?}"
        );
        let counts = lines[0].counts.as_ref().expect("its counts");
        assert_eq!(
            lines[0].refusal, None,
            "its classes resolve: {:?}",
            lines[0]
        );
        assert_eq!(
            counts.classes.get(surface("class_tool_calls")).copied(),
            Some(1),
            "the one tool call the plane reported: {counts:?}"
        );
        // THE BYTE CLASS, STATED (THE DESIGN §7, "The plane reports; the kernel writes"; Law 6): the
        // length of the document the server answered with, the plane's second declared class.
        assert_eq!(
            counts.classes.get(surface("class_bytes")).copied(),
            Some(ANSWER.len() as u64),
            "the bytes of the server's answer the plane reported: {counts:?}"
        );
    }

    /// THE AUTHENTICATE STEP: an unkeyed caller on the door's endpoint (it takes a credential) is
    /// refused before anything is charged or dialled, the kernel's reason rendered by the plane.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn an_unkeyed_tools_call_is_refused_before_anything_is_charged_or_dialled() {
        let _one = PUBLISHING.lock().await;
        let instance = "serve-door-tools-unkeyed";
        let _published = Published(instance);
        let (port, mut heard) = tool_server().await;
        let rig = Rig::new(instance, port, None);

        let (status, body) = send(&rig.router, None, CALL).await;
        let refused = u16::try_from(refusal_status(ReasonCode::Unauthenticated)).expect("a status");
        assert_eq!(
            status.as_u16(),
            refused,
            "{}",
            String::from_utf8_lossy(&body)
        );
        assert_eq!(rig.admitted(), 0, "nothing charged");
        assert!(heard.try_recv().is_err(), "nothing dialled");
        assert!(rig.all_ended(), "no unit left open");
    }

    /// THE DECODE STEP: a body that is not JSON is refused by the plane's own decode, in its own
    /// words, before the unit is admitted: nothing charged, nothing dialled.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_body_that_does_not_decode_is_refused_before_it_is_admitted() {
        let _one = PUBLISHING.lock().await;
        let instance = "serve-door-tools-undecodable";
        let _published = Published(instance);
        let (port, mut heard) = tool_server().await;
        let rig = Rig::new(instance, port, None);

        let (status, body) = send(&rig.router, Some(&rig.token), "{not json").await;
        assert_eq!(
            status,
            StatusCode::BAD_REQUEST,
            "the status the plane's decode stated: {}",
            String::from_utf8_lossy(&body)
        );
        let body: serde_json::Value = serde_json::from_slice(&body).expect("the plane's JSON-RPC");
        assert_eq!(
            body["error"]["code"],
            busbar_contract::jsonrpc::PARSE_ERROR,
            "the plane's own words for the arrival it refused (REFUSAL_ARRIVE): {body}"
        );
        assert_eq!(rig.admitted(), 0, "nothing charged");
        assert!(heard.try_recv().is_err(), "nothing dialled");
    }

    /// THE APPROVE STEP: a caller whose grant holds no scope of the plane's (an explicit empty pool
    /// grant: no scopes, never all) is refused before it is charged or dialled, in the served
    /// engine's words (BUSBAR-1.6.0.md Part 3 section 12: a new plane's statuses equal current
    /// predev): `404`, the sentence an unknown tool gets, `data.reason` `not_granted`
    /// (scripts/mcp-subject/h2-verify-refusal.sh holds predev to the same).
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_tools_call_outside_the_callers_grant_is_refused_before_it_dials() {
        let _one = PUBLISHING.lock().await;
        let instance = "serve-door-tools-ungranted";
        let _published = Published(instance);
        let (port, mut heard) = tool_server().await;
        let rig = Rig::new(instance, port, Some(Vec::new()));

        let (status, body) = send(&rig.router, Some(&rig.token), CALL).await;
        assert_eq!(status.as_u16(), 404, "{}", String::from_utf8_lossy(&body));
        let body: serde_json::Value = serde_json::from_slice(&body).expect("JSON-RPC");
        assert_eq!(body["error"]["data"]["reason"], "not_granted", "{body}");
        assert_eq!(body["id"], 30, "the caller's id: {body}");
        assert_eq!(rig.admitted(), 0, "nothing charged");
        assert!(heard.try_recv().is_err(), "nothing dialled");
        assert!(rig.all_ended(), "no unit left open");
    }

    /// THE ROUTE STEP: a call whose server is down ends inside its own unit — answered as an
    /// upstream failure (ARCHITECT Q3 (c): the re-fetch that could not reach the server is reported
    /// to the kernel as unreachable and the call fails as the tool error), never served, every unit
    /// ended once.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_tools_call_to_a_server_that_is_down_ends_inside_its_unit() {
        let _one = PUBLISHING.lock().await;
        let instance = "serve-door-tools-down";
        let _published = Published(instance);
        let port = down_port().await;
        let rig = Rig::new(instance, port, None);

        let (status, body) = send(&rig.router, Some(&rig.token), CALL).await;
        let answer: serde_json::Value = serde_json::from_slice(&body).expect("a JSON-RPC answer");
        assert_eq!(status, StatusCode::OK, "{answer}");
        assert_eq!(
            answer["result"]["isError"], true,
            "an upstream failure: {answer}"
        );
        assert!(rig.all_ended(), "the unit ended inside itself");
    }

    /// UPSTREAM CREDENTIALS FROM THE REGISTRATION (ARCHITECT round 4 Q-L3B-SURFACES (d)): a
    /// `upstream_credentials: passthrough` registration's member is bound to the kernel's
    /// caller-credential lending, so the server hears the caller's own verified credential as its
    /// bearer; a registration that states none hears no credential at all.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_passthrough_registration_presents_the_callers_credential_and_no_other() {
        let _one = PUBLISHING.lock().await;
        let tools = |port: u16, mode: &str| -> serde_yaml::Value {
            serde_yaml::from_str(&format!(
                "fs:\n  url: \"http://127.0.0.1:{port}/rpc\"\n  \
                 pin: {{ mechanism: pinned_pubkey, key: \"sha256/K=\" }}\n{mode}  \
                 tools_allow:\n    read_file: {{ schema_hash: \"{}\" }}\n",
                tool_digest()
            ))
            .expect("a section")
        };
        let instance = "door-passthrough";
        let _published = Published(instance);
        for (mode, lends) in [("  upstream_credentials: passthrough\n", true), ("", false)] {
            let (port, mut heard) = tool_server().await;
            let rig = Rig::with(
                instance,
                port,
                None,
                None,
                Some(tools(port, mode)),
                Footing::own(),
                &|app| app,
            );
            let (status, body) = send(&rig.router, Some(&rig.token), CALL).await;
            assert_eq!(status, StatusCode::OK, "{}", String::from_utf8_lossy(&body));
            let (mut call, mut list) = (None, None);
            while let Ok(r) = heard.try_recv() {
                if r.contains("\"tools/call\"") {
                    call = Some(r);
                } else if r.contains("\"tools/list\"") {
                    list = Some(r);
                }
            }
            let bearer = format!("authorization: bearer {}", rig.token.to_ascii_lowercase());
            // The relayed call, and the door's own verify-on-call fetch made inside the caller's
            // unit (ARCHITECT round 5 Q-L3B-DOOR-EXCHANGE: it carries the member's binding, so a
            // passthrough member's is lent the unit's caller credential).
            for (what, heard) in [("call", call), ("verify-on-call list", list)] {
                let heard = heard
                    .unwrap_or_else(|| panic!("{mode:?}: the server heard the {what}"))
                    .to_ascii_lowercase();
                assert_eq!(heard.contains(&bearer), lends, "{mode:?} {what}: {heard}");
                if !lends {
                    assert!(
                        !heard.contains("authorization:"),
                        "{what}: no credential at all: {heard}"
                    );
                }
            }
        }
    }

    /// The caller key's grants become exactly `scopes` (`(grant kind row, value)`, the kinds read
    /// from the wire fixture), on the governance book the gate resolves it from.
    fn grant(rig: &Rig, scopes: &[(&str, &str)]) {
        let mut key = (*rig.key).clone();
        key.allowed_scopes = Some(
            scopes
                .iter()
                .map(|(kind, value)| busbar_contract::records::ScopeRef {
                    kind: surface(kind).to_string(),
                    value: (*value).to_string(),
                })
                .collect(),
        );
        rig.gov.store().put_key(&key).expect("the key is stored");
        rig.gov.refresh().expect("the book refreshes");
    }

    /// The raw (form-encoded) value of `key` in a form body.
    pub(crate) fn form_value(body: &str, key: &str) -> String {
        body.split('&')
            .find_map(|pair| pair.strip_prefix(&format!("{key}=")))
            .unwrap_or_default()
            .to_string()
    }

    /// Every token request the rig's token endpoint was sent: `(target, form body)`.
    pub(crate) fn exchanges(rig: &Rig) -> Vec<(String, String)> {
        rig.tokens
            .opened
            .lock()
            .expect("unpoisoned")
            .iter()
            .map(|(_, target, _, body)| (target.clone(), body.clone()))
            .collect()
    }

    /// The tool server's three tools, listed as the token-exchange section approves them.
    pub(crate) fn three_tools() -> serde_json::Value {
        serde_json::json!([
            {"name": "read_file", "description": TOOL_DESCRIPTION, "inputSchema": tool_schema()},
            {"name": "write_file", "description": "writes a file to disk", "inputSchema": tool_schema()},
            {"name": "stat", "description": "reads a file's metadata", "inputSchema": tool_schema()},
        ])
    }

    /// The environment variable a token-exchange registration names busbar's own subject token by.
    const SUBJECT_VAR: &str = "BUSBAR_DOOR_EXCHANGE_TEST_SUBJECT";

    /// The token endpoint a token-exchange registration names (the rig's token table answers it:
    /// an `open-web` need dials over connection security only).
    pub(crate) const TOKEN_URL: &str = "https://as.example/token";

    /// A `token_exchange:` registration on loopback `port` (`aud:` the server's origin), three
    /// approved tools.
    fn exchange_section(port: u16) -> serde_yaml::Value {
        serde_yaml::from_str(&format!(
            "fs:\n  url: \"http://127.0.0.1:{port}/rpc\"\n  \
             pin: {{ mechanism: pinned_pubkey, key: \"sha256/K=\" }}\n  \
             allow_private: true\n  aud: \"http://127.0.0.1:{port}\"\n  \
             token_exchange:\n    token_url: \"{TOKEN_URL}\"\n    \
             subject_token: {{ env: {SUBJECT_VAR} }}\n  \
             tools_allow:\n    read_file: {{ schema_hash: \"{}\" }}\n    \
             write_file: {{ schema_hash: \"{}\" }}\n    stat: {{ schema_hash: \"{}\" }}\n",
            tool_digest(),
            surface("write_digest"),
            surface("stat_digest"),
        ))
        .expect("a section")
    }

    /// THE TOKEN EXCHANGE (ARCHITECT round 5 Q-L3B-EXCHANGE (B), Q-L3B-DOOR-EXCHANGE): a
    /// `token_exchange:` registration's member is bound to the RFC 8693 style, so the relayed call
    /// presents the token busbar's own subject token was exchanged for under the CALLER's down-scope
    /// — exactly its tool grants on the server, or for a wildcard grant exactly the tool called —
    /// and the door's own verify-on-call fetch presents the token exchanged for the registration's
    /// approved set. Each exchange is the previous release's request (busbar's subject token, never
    /// the caller's; the `aud:` as the RFC 8707 resource); the host's scope field never reaches the
    /// server.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_token_exchange_registration_presents_the_token_exchanged_for_the_callers_down_scope()
    {
        let _one = PUBLISHING.lock().await;
        std::env::set_var(SUBJECT_VAR, "busbar-own-subject-token");
        let granted: &[(&str, &str)] = &[
            ("scope_server", "fs"),
            ("scope_tool", "fs_read_file"),
            ("scope_tool", "fs_write_file"),
            ("scope_tool", "git_log"),
        ];
        for (instance, grants, down_scope) in [
            (
                "door-exchange-granted",
                Some(granted),
                "fs_read_file+fs_write_file",
            ),
            ("door-exchange-wildcard", None, "fs_read_file"),
        ] {
            let _published = Published(instance);
            let (port, mut heard) =
                tool_server_listing(Arc::new(std::sync::Mutex::new(three_tools()))).await;
            let rig = rig_tools(instance, port, exchange_section(port), &|app| app);
            if let Some(grants) = grants {
                grant(&rig, grants);
            }
            let (status, body) = send(&rig.router, Some(&rig.token), CALL).await;
            assert_eq!(
                status,
                StatusCode::OK,
                "{instance}: {}",
                String::from_utf8_lossy(&body)
            );
            let (mut call, mut list) = (None, None);
            while let Ok(r) = heard.try_recv() {
                if r.contains("\"tools/call\"") {
                    call = Some(r.to_ascii_lowercase());
                } else if r.contains("\"tools/list\"") {
                    list = Some(r.to_ascii_lowercase());
                }
            }
            let call = call.expect("the server heard the call");
            assert!(
                call.contains(&format!("authorization: bearer tok-{down_scope}")),
                "{instance}: the call presents the token for the caller's down-scope: {call}"
            );
            let list = list.expect("the server heard the verify-on-call list");
            assert!(
                list.contains("authorization: bearer tok-fs_read_file+fs_stat+fs_write_file"),
                "{instance}: the door's own fetch presents the registration's token: {list}"
            );
            let field = busbar_contract::abi::auth::SCOPE_REQUEST_FIELD;
            assert!(
                !call.contains(field) && !list.contains(field),
                "the host's scope field never reaches the server"
            );
            let exchanges = exchanges(&rig);
            let scopes: Vec<String> = exchanges
                .iter()
                .map(|(_, r)| form_value(r, "scope"))
                .collect();
            assert_eq!(
                scopes,
                ["fs_read_file+fs_stat+fs_write_file", down_scope],
                "{instance}: one exchange per scope"
            );
            for (target, r) in &exchanges {
                assert_eq!(target, TOKEN_URL);
                assert_eq!(
                    form_value(r, "grant_type"),
                    "urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Atoken-exchange"
                );
                assert_eq!(
                    form_value(r, "requested_token_type"),
                    "urn%3Aietf%3Aparams%3Aoauth%3Atoken-type%3Aaccess_token"
                );
                assert_eq!(form_value(r, "subject_token"), "busbar-own-subject-token");
                assert_eq!(
                    form_value(r, "resource"),
                    format!("http%3A%2F%2F127.0.0.1%3A{port}")
                );
                assert!(
                    !r.contains(&rig.token),
                    "the caller's credential never reaches the authorization server"
                );
            }
            assert!(rig.all_ended(), "every unit ended");
        }
    }

    /// TOOL POOLS THROUGH THE ONE WALK (ARCHITECT round 4 Q-L3B-SURFACES (h)): a call to a pooled
    /// server routes over its pool, so a primary that answers with a failure is failed over to its
    /// verified twin by the kernel's walk when the pool names the tool `repeatable:`, and the caller
    /// hears the twin; a tool the pool does not name is performed at most once: the primary's
    /// failure is the answer, and the twin never hears the call.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_tool_pool_fails_over_through_the_one_walk_and_repeats_only_what_it_names() {
        let _one = PUBLISHING.lock().await;
        let listing = || {
            serde_json::json!({"jsonrpc": "2.0", "id": 1, "result": {"tools": tool_listing()}})
                .to_string()
        };
        let calls = |heard: &mut tokio::sync::mpsc::UnboundedReceiver<String>| {
            let mut n = 0;
            while let Ok(r) = heard.try_recv() {
                n += usize::from(r.contains("\"tools/call\""));
            }
            n
        };
        let tools = |bad: u16, good: u16, repeatable: &str| -> serde_yaml::Value {
            let d = tool_digest();
            serde_yaml::from_str(&format!(
                "fs:\n  url: \"http://127.0.0.1:{bad}/rpc\"\n  \
                 pin: {{ mechanism: pinned_pubkey, key: \"sha256/K=\" }}\n  \
                 tools_allow:\n    read_file: {{ schema_hash: \"{d}\" }}\n\
                 fs2:\n  url: \"http://127.0.0.1:{good}/rpc\"\n  \
                 pin: {{ mechanism: pinned_pubkey, key: \"sha256/K=\" }}\n  \
                 tools_allow:\n    read_file: {{ schema_hash: \"{d}\" }}\n\
                 pools:\n  twins: {{ members: [fs, fs2], repeatable: [{repeatable}], \
                 member_granted: true }}\n"
            ))
            .expect("a section")
        };
        let instance = "door-tool-pool";
        let _published = Published(instance);
        for (repeatable, twin_answers) in [("read_file", true), ("", false)] {
            let (bad, mut bad_heard) = tool_server_replying(Arc::new(move |r: &str| {
                if r.contains("\"tools/list\"") {
                    (200, listing())
                } else {
                    (503, "{}".to_string())
                }
            }))
            .await;
            let (good, mut good_heard) = tool_server().await;
            let rig = Rig::with(
                instance,
                bad,
                None,
                None,
                Some(tools(bad, good, repeatable)),
                Footing::own(),
                &|app| app,
            );
            let (status, body) = send(&rig.router, Some(&rig.token), CALL).await;
            let body = String::from_utf8_lossy(&body).to_string();
            assert_eq!(
                body.contains("from the server"),
                twin_answers,
                "repeatable [{repeatable}]: {status} {body}"
            );
            assert_eq!(calls(&mut bad_heard), 1, "the primary is called once");
            assert_eq!(
                calls(&mut good_heard),
                usize::from(twin_answers),
                "the twin hears the call only when the pool repeats the tool"
            );
            assert!(rig.all_ended(), "the unit ended inside itself");
        }
    }

    /// VERIFY-ON-CALL (the rug-pull defence on the call path, the served engine's): a call whose
    /// server's last look is older than its `verify_ttl` fetches the live tool list first and is
    /// judged against it. Within the bound the look is reused (one fetch for two calls); a schema
    /// moved under the approval refuses the next call as quarantined before it is sent, with no
    /// operator present; a server that cannot be reached at the fetch refuses fail-closed.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn verify_on_call_judges_the_live_list_reuses_a_fresh_look_and_fails_closed() {
        let _one = PUBLISHING.lock().await;
        let tools = |port: u16, ttl: &str| -> serde_yaml::Value {
            serde_yaml::from_str(&format!(
                "fs:\n  url: \"http://127.0.0.1:{port}/rpc\"\n  \
                 pin: {{ mechanism: pinned_pubkey, key: \"sha256/K=\" }}\n  verify_ttl: {ttl}\n  \
                 tools_allow:\n    read_file: {{ schema_hash: \"{}\" }}\n",
                tool_digest()
            ))
            .expect("a section")
        };
        let drain = |heard: &mut tokio::sync::mpsc::UnboundedReceiver<String>| {
            let mut got = Vec::new();
            while let Ok(r) = heard.try_recv() {
                got.push(if r.contains("\"tools/list\"") {
                    "list"
                } else if r.contains("\"tools/call\"") {
                    "call"
                } else {
                    "other"
                });
            }
            got
        };

        // ── A FRESH LOOK IS REUSED within `verify_ttl` ───────────────────────────────────────────
        // One instance name for the three compositions: each publishes over the one before.
        let instance = "door-verify-on-call";
        let _published = Published(instance);
        let (port, mut heard) = tool_server().await;
        let rig = Rig::with(
            instance,
            port,
            None,
            None,
            Some(tools(port, "1h")),
            Footing::own(),
            &|app| app,
        );
        for _ in 0..2 {
            let (status, body) = send(&rig.router, Some(&rig.token), CALL).await;
            assert_eq!(status, StatusCode::OK, "{}", String::from_utf8_lossy(&body));
        }
        assert_eq!(
            drain(&mut heard),
            vec!["list", "call", "call"],
            "one fetch, two calls"
        );
        drop(rig);

        // ── THE RUG-PULL ON THE CALL PATH: strict-live (`0s`) ─────────────────────────────────────
        let listed = Arc::new(std::sync::Mutex::new(tool_listing()));
        let (port, mut heard) = tool_server_listing(Arc::clone(&listed)).await;
        let rig = Rig::with(
            instance,
            port,
            None,
            None,
            Some(tools(port, "0s")),
            Footing::own(),
            &|app| app,
        );
        let (status, _) = send(&rig.router, Some(&rig.token), CALL).await;
        assert_eq!(
            status,
            StatusCode::OK,
            "the control: the approved list serves"
        );
        *listed.lock().expect("the list") = serde_json::json!([
            {"name": "read_file", "description": TOOL_DESCRIPTION,
             "inputSchema": {"type": "object", "properties": {"path": {"type": "string"}, "exfil": {"type": "string"}}}}
        ]);
        let (status, body) = send(&rig.router, Some(&rig.token), CALL).await;
        assert_eq!(status.as_u16(), 403, "{}", String::from_utf8_lossy(&body));
        let body: serde_json::Value = serde_json::from_slice(&body).expect("JSON-RPC");
        assert_eq!(body["error"]["data"]["reason"], "quarantined", "{body}");
        assert_eq!(
            drain(&mut heard),
            vec!["list", "call", "list"],
            "the drifted call was refused before it was sent"
        );
        drop(rig);

        // ── FAIL CLOSED: the server cannot be reached at the fetch: reported to the kernel as
        // unreachable, and the call fails as an upstream failure, never sent (ARCHITECT Q3 (c)) ──
        let port = down_port().await;
        let rig = Rig::with(
            instance,
            port,
            None,
            None,
            Some(tools(port, "0s")),
            Footing::own(),
            &|app| app,
        );
        let (status, body) = send(&rig.router, Some(&rig.token), CALL).await;
        assert_eq!(status.as_u16(), 200, "{}", String::from_utf8_lossy(&body));
        let body: serde_json::Value = serde_json::from_slice(&body).expect("JSON-RPC");
        assert_eq!(
            body["result"]["isError"], true,
            "an upstream failure: {body}"
        );
        assert!(rig.all_ended(), "the refused unit ended");
    }

    /// THE RE-CHECK HONOURS THE REGISTRATION'S `timeout:` (ARCHITECT ruling on `timeout:`): an
    /// upstream that accepts the tool-list fetch and never answers it is given up on at the operator's
    /// one-second budget, not at a fixed thirty, and the call fails as an upstream failure, never
    /// sent (ARCHITECT Q3 (c), as the unreachable fetch above), well inside the budget the caller is
    /// waiting on.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn the_tool_list_re_check_gives_up_at_the_registrations_timeout() {
        let _one = PUBLISHING.lock().await;
        let instance = "door-verify-timeout";
        let _published = Published(instance);
        // A server that takes every connection and answers nothing on it.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("a loopback port");
        let port = listener.local_addr().expect("its address").port();
        tokio::spawn(async move {
            let mut held = Vec::new();
            while let Ok((socket, _)) = listener.accept().await {
                held.push(socket);
            }
        });
        let section: serde_yaml::Value = serde_yaml::from_str(&format!(
            "fs:\n  url: \"http://127.0.0.1:{port}/rpc\"\n  \
             pin: {{ mechanism: pinned_pubkey, key: \"sha256/K=\" }}\n  verify_ttl: 0s\n  \
             timeout: 1s\n  tools_allow:\n    read_file: {{ schema_hash: \"{}\" }}\n",
            tool_digest()
        ))
        .expect("a section");
        let rig = Rig::with(
            instance,
            port,
            None,
            None,
            Some(section),
            Footing::own(),
            &|app| app,
        );
        // Bounded here so the RED is a named failure, not the harness's slow-test kill: before the
        // budget was honoured, the fetch to a server that never answers did not return at all.
        let (status, body) = tokio::time::timeout(
            std::time::Duration::from_secs(10),
            send(&rig.router, Some(&rig.token), CALL),
        )
        .await
        .expect("the re-check gave up inside 10s: the registration's `timeout: 1s` is its budget");
        assert_eq!(status.as_u16(), 200, "{}", String::from_utf8_lossy(&body));
        let body: serde_json::Value = serde_json::from_slice(&body).expect("JSON-RPC");
        assert_eq!(
            body["result"]["isError"], true,
            "an upstream failure: {body}"
        );
        assert!(rig.all_ended(), "the refused unit ended");
    }

    /// THE ARGUMENT GUARD (the served engine's argguard): a URL a call's arguments carry to a cloud
    /// metadata endpoint is refused before the call is sent, in the guard's words, with the field it
    /// was found at; the same call carrying an external URL is served.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_metadata_url_in_the_arguments_is_refused_before_the_call_is_sent() {
        let _one = PUBLISHING.lock().await;
        let instance = "serve-door-tools-argguard";
        let _published = Published(instance);
        let (port, mut heard) = tool_server().await;
        let rig = Rig::new(instance, port, None);
        let call = |url: &str| {
            serde_json::json!({
                "jsonrpc": "2.0", "id": 31, "method": "tools/call",
                "params": {
                    "name": "fs_read_file",
                    "arguments": { "path": "notes.txt", "fetch": url },
                    "_meta": {
                        "io.modelcontextprotocol/protocolVersion": protocol_version(),
                        "io.modelcontextprotocol/clientCapabilities": {}
                    }
                }
            })
            .to_string()
        };
        let (status, body) = send(
            &rig.router,
            Some(&rig.token),
            &call("http://169.254.169.254/latest/meta-data/"),
        )
        .await;
        assert_eq!(status.as_u16(), 403, "{}", String::from_utf8_lossy(&body));
        let body: serde_json::Value = serde_json::from_slice(&body).expect("JSON-RPC");
        assert_eq!(body["error"]["code"], -32000, "{body}");
        assert_eq!(
            body["error"]["data"]["reason"], "tool_argument_refused",
            "{body}"
        );
        let message = body["error"]["message"].as_str().unwrap_or_default();
        assert!(
            message.starts_with("tool argument /fetch carries a URL the schema does not declare"),
            "{message}"
        );
        let mut wire = Vec::new();
        while let Ok(r) = heard.try_recv() {
            wire.push(r);
        }
        assert!(
            wire.iter().all(|r| !r.contains("\"tools/call\"")),
            "the refused call never reached the wire: {wire:?}"
        );
        let (status, body) = send(
            &rig.router,
            Some(&rig.token),
            &call("https://docs.example.com/notes"),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{}", String::from_utf8_lossy(&body));
    }

    /// A `tools/call` of the rig's one tool whose undeclared `fetch` argument carries `url`.
    fn fetching(url: &str) -> String {
        serde_json::json!({
            "jsonrpc": "2.0", "id": 32, "method": "tools/call",
            "params": {
                "name": "fs_read_file",
                "arguments": { "path": "notes.txt", "fetch": url },
                "_meta": {
                    "io.modelcontextprotocol/protocolVersion": protocol_version(),
                    "io.modelcontextprotocol/clientCapabilities": {}
                }
            }
        })
        .to_string()
    }

    /// Each URL in `urls`, carried in a call's arguments, is refused before the call is sent, with
    /// the argument guard's bytes (403, JSON-RPC -32000, `tool_argument_refused`); then a public
    /// URL in the same field is served.
    async fn refused_in_the_arguments(instance: &'static str, urls: &[&str]) {
        let (port, mut heard) = tool_server().await;
        let rig = Rig::new(instance, port, None);
        for url in urls {
            let (status, body) = send(&rig.router, Some(&rig.token), &fetching(url)).await;
            let shown = String::from_utf8_lossy(&body);
            assert_eq!(status.as_u16(), 403, "`{url}` must be refused: {shown}");
            let body: serde_json::Value = serde_json::from_slice(&body).expect("JSON-RPC");
            assert_eq!(body["error"]["code"], -32000, "`{url}`: {body}");
            assert_eq!(
                body["error"]["data"]["reason"], "tool_argument_refused",
                "`{url}`: {body}"
            );
        }
        let mut wire = Vec::new();
        while let Ok(r) = heard.try_recv() {
            wire.push(r);
        }
        assert!(
            wire.iter().all(|r| !r.contains("\"tools/call\"")),
            "no refused call reached the wire: {wire:?}"
        );
        let (status, body) = send(
            &rig.router,
            Some(&rig.token),
            &fetching("https://docs.example.com/notes"),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{}", String::from_utf8_lossy(&body));
    }

    /// THE ARGUMENT GUARD ASKS THE KERNEL'S `dest.judge` (THE DESIGN §11 host services B.3 item
    /// 11): a host the deployment's own egress rules refuse ([`BLOCKED_HOST`], a
    /// `security.blocked_metadata_hosts` entry no address rule would refuse) is refused when a
    /// call's arguments name it. A guard deciding in the plane admits it.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_host_the_deployment_refuses_is_refused_in_the_arguments() {
        let _one = PUBLISHING.lock().await;
        let instance = "serve-door-tools-destjudge-blocked";
        let _published = Published(instance);
        let (plain, secure) = (
            format!("http://{BLOCKED_HOST}/x"),
            format!("https://{BLOCKED_HOST}:8443/y"),
        );
        refused_in_the_arguments(instance, &[&plain, &secure]).await;
    }

    /// The addresses the connector's guard refuses as internal are refused in a call's arguments
    /// too, by that same judgement (`dest.judge`, private reach refused for a registration that
    /// was granted none): benchmarking, IETF protocol assignments, "this network", the mapped,
    /// scoped and link-local IPv6 spellings, multicast and broadcast.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn every_internal_address_the_guard_refuses_is_refused_in_the_arguments() {
        let _one = PUBLISHING.lock().await;
        let instance = "serve-door-tools-destjudge-internal";
        let _published = Published(instance);
        refused_in_the_arguments(
            instance,
            &[
                "http://198.18.0.1/x",
                "http://192.0.0.8/x",
                "http://0.1.2.3/x",
                "http://[::ffff:198.18.0.1]/x",
                "http://[::1%25lo]/x",
                "http://[fe80::1%25eth0]/x",
                "http://224.0.0.1/x",
                "http://255.255.255.255/x",
                "http://[ff02::1]/x",
            ],
        )
        .await;
    }

    /// The SSRF guard bypass's odd host spellings (HIGH), each beside the plain ASCII host a URL
    /// client dials it as: full-width `ｌｏｃａｌｈｏｓｔ`, circled-digit `①②⑦.0.0.1` and
    /// `①⑥⑨.②⑤④.①⑥⑨.②⑤④`, `LOCALHOST。` with its ideographic full stop, and the full-width spellings
    /// of `0x7f.1` and `017700000001`.
    const ODD_HOSTS: [(&str, &str); 6] = [
        (
            "\u{ff4c}\u{ff4f}\u{ff43}\u{ff41}\u{ff4c}\u{ff48}\u{ff4f}\u{ff53}\u{ff54}",
            "localhost",
        ),
        ("\u{2460}\u{2461}\u{2466}.0.0.1", "127.0.0.1"),
        (
            "\u{2460}\u{2465}\u{2468}.\u{2461}\u{2464}\u{2463}.\u{2460}\u{2465}\u{2468}.\u{2461}\u{2464}\u{2463}",
            "169.254.169.254",
        ),
        ("LOCALHOST\u{3002}", "localhost"),
        ("\u{ff10}\u{ff58}\u{ff17}\u{ff46}\u{ff0e}\u{ff11}", "0x7f.1"),
        (
            "\u{ff10}\u{ff11}\u{ff17}\u{ff17}\u{ff10}\u{ff10}\u{ff10}\u{ff10}\u{ff10}\u{ff10}\u{ff10}\u{ff11}",
            "017700000001",
        ),
    ];

    /// Each of [`ODD_HOSTS`] spelt into a URL by every one of `spellings`, carried in a call's
    /// arguments, is refused exactly as its plain ASCII host spelt the same way is refused (the same
    /// status, JSON-RPC code, reason and sentence); each of `zero` (a host `url` dials as
    /// `0.0.0.0`) is refused; nothing refused reaches the wire; and a public IDN URL is served.
    async fn odd_hosts_refused_as_their_ascii_hosts(
        instance: &'static str,
        spellings: &[fn(&str) -> String],
        zero: &[&str],
    ) {
        let (port, mut heard) = tool_server().await;
        let rig = Rig::new(instance, port, None);
        let refusal = |status: StatusCode, body: &[u8], url: &str| {
            let shown = String::from_utf8_lossy(body);
            assert_eq!(status.as_u16(), 403, "`{url}` must be refused: {shown}");
            let body: serde_json::Value = serde_json::from_slice(body).expect("JSON-RPC");
            assert_eq!(
                body["error"]["data"]["reason"], "tool_argument_refused",
                "`{url}`: {body}"
            );
            (
                body["error"]["code"].clone(),
                body["error"]["data"]["reason"].clone(),
                body["error"]["message"].clone(),
            )
        };
        for (odd, plain) in ODD_HOSTS {
            for spell in spellings {
                let (odd_url, plain_url) = (spell(odd), spell(plain));
                let (status, body) = send(&rig.router, Some(&rig.token), &fetching(&odd_url)).await;
                let odd_refusal = refusal(status, &body, &odd_url);
                let (status, body) =
                    send(&rig.router, Some(&rig.token), &fetching(&plain_url)).await;
                let plain_refusal = refusal(status, &body, &plain_url);
                assert_eq!(
                    odd_refusal, plain_refusal,
                    "`{odd_url}` beside `{plain_url}`"
                );
            }
        }
        for url in zero {
            let (status, body) = send(&rig.router, Some(&rig.token), &fetching(url)).await;
            refusal(status, &body, url);
        }
        let mut wire = Vec::new();
        while let Ok(r) = heard.try_recv() {
            wire.push(r);
        }
        assert!(
            wire.iter().all(|r| !r.contains("\"tools/call\"")),
            "no refused call reached the wire: {wire:?}"
        );
        // GREEN control: a public IDN host is its punycode name, and served.
        let (status, body) = send(
            &rig.router,
            Some(&rig.token),
            &fetching("https://b\u{fc}cher.example/notes"),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{}", String::from_utf8_lossy(&body));
    }

    /// RED (HIGH, the SSRF guard bypass): the argument guard refuses an `http://` URL whose host is
    /// an odd spelling exactly as it refuses the plain ASCII host a URL client dials it as, and
    /// refuses `http://0x/` (`url` dials it as `0.0.0.0`). On the guard that compared hosts only
    /// ASCII-lowercased each odd spelling was admitted and sent, and the upstream fetched loopback
    /// or the metadata address.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn an_odd_host_spelling_in_the_arguments_is_refused_as_its_ascii_host() {
        let _one = PUBLISHING.lock().await;
        let instance = "serve-door-tools-destjudge-odd-hosts";
        let _published = Published(instance);
        odd_hosts_refused_as_their_ascii_hosts(
            instance,
            &[|h| format!("http://{h}/latest/meta-data/")],
            &["http://0x/latest/meta-data/"],
        )
        .await;
    }

    /// A UNIT THE PLANE ANSWERS ITSELF (ARCHITECT Q-L3B-LOCAL): a keyed `tools/list` names no entry,
    /// is admitted with no route walk and answered 200 by the plane from its catalogue — nothing
    /// charged (only far-end-reported units bill), nothing dialled, every unit ended.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_listing_is_answered_by_the_plane_with_no_walk_and_no_charge() {
        let _one = PUBLISHING.lock().await;
        let instance = "serve-door-tools-local";
        let _published = Published(instance);
        let (port, mut heard) = tool_server().await;
        let rig = Rig::new(instance, port, None);

        let (status, body) = send_as(&rig.router, Some(&rig.token), LIST, "tools/list", None).await;
        assert_eq!(
            status,
            StatusCode::OK,
            "answered by the plane: {}",
            String::from_utf8_lossy(&body)
        );
        let body: serde_json::Value = serde_json::from_slice(&body).expect("a JSON-RPC answer");
        assert_eq!(body["id"], 9, "{body}");
        assert_eq!(
            body["result"]["tools"][0]["name"], "fs_read_file",
            "the catalogue's one tool: {body}"
        );
        assert_eq!(rig.admitted(), 0, "a local answer charges nothing");
        assert!(heard.try_recv().is_err(), "nothing dialled");
        assert!(rig.all_ended(), "every unit ended");
    }

    /// THE PROTECTED-RESOURCE DOCUMENT (ARCHITECT Q-L3B-RFC9728, predev's plain document): the door
    /// states its facts (its audience, and its `mcp:` block's authorization servers and scopes) and
    /// the kernel's RFC 9728 renderer answers an anonymous GET at its metadata path, cacheable — not
    /// a unit: nothing admitted, no unit opened on the money steps or the node, nothing dialled.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn the_metadata_document_is_rendered_from_the_doors_facts_and_is_no_unit() {
        use tower::ServiceExt as _;
        let _one = PUBLISHING.lock().await;
        let instance = "serve-door-tools-metadata";
        let _published = Published(instance);
        let (port, mut heard) = tool_server().await;
        let block: serde_yaml::Value = serde_yaml::from_str(&format!(
            "canonical_uri: \"http://127.0.0.1{}\"\n\
                 authorization_servers: [\"https://login.example.com\"]\n\
                 scopes_supported: [\"tools:call\"]\n",
            endpoint()
        ))
        .expect("a block");
        let rig = Rig::with(
            instance,
            port,
            None,
            Some(block),
            None,
            Footing::own(),
            &|app| app,
        );
        let req = axum::http::Request::builder()
            .method("GET")
            .uri(format!(
                "/.well-known/oauth-protected-resource{}",
                endpoint()
            ))
            .body(axum::body::Body::empty())
            .expect("a request");
        let response = rig.router.clone().oneshot(req).await.expect("answers");
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response
                .headers()
                .get("cache-control")
                .and_then(|v| v.to_str().ok()),
            Some("public, max-age=3600")
        );
        let bytes = axum::body::to_bytes(response.into_body(), 1 << 16)
            .await
            .expect("the body");
        let doc: serde_json::Value = serde_json::from_slice(&bytes).expect("a JSON document");
        assert_eq!(
            doc,
            serde_json::json!({
                "resource": format!("http://127.0.0.1{}", endpoint()),
                "authorization_servers": ["https://login.example.com"],
                "scopes_supported": ["tools:call"],
                "bearer_methods_supported": ["header"],
            })
        );
        assert_eq!(rig.admitted(), 0, "nothing admitted");
        assert!(rig.all_ended(), "no unit was opened");
        assert!(heard.try_recv().is_err(), "nothing dialled");
    }

    /// THE CLAIM: without a public base URL the door opens and claims nothing; with one its endpoint
    /// is claimed.
    #[tokio::test]
    async fn the_tool_door_claims_its_endpoint_only_under_a_public_url() {
        let _one = PUBLISHING.lock().await;
        let compose = |instance: &'static str, public_url: Option<&str>| {
            let dispatcher = Arc::new(Dispatcher::new(DispatchConfig::default()));
            crate::root::connector::install_io(&dispatcher);
            // The host lends the dispatcher its seal (Part 2 #54), as the root does at boot.
            let _ = dispatcher.lend_seal(busbar_kernel::seal::lend());
            let plane = bound(
                instance,
                &dispatcher,
                crate::root::loader::dispatch::ConnTable::Probe,
            );
            let mut sections = BTreeMap::new();
            sections.insert(plane.served().section, section(9));
            compose_planes(
                &[(instance.to_string(), plane)],
                &dispatcher,
                &composed_services(),
                &sections,
                public_url,
                &money,
                None,
                None,
            )
            .expect("the door plane composes")
        };
        {
            // One instance's admin routes on the admin table at a time: this one is withdrawn first.
            let bare = "serve-door-tools-claims-bare";
            let _bare = Published(bare);
            let served = compose(bare, None);
            assert!(
                served.planes[0].snapshot.claims.is_empty(),
                "no public base URL, no claim"
            );
        }
        {
            // ITS OWN ENDPOINT BLOCK, no public base URL (ARCHITECT Q-L3B-AUD, predev's rule): the door
            // reads its `mcp:` block beside its settings and states its claims under the canonical URI.
            let block = "serve-door-tools-claims-block";
            let _block = Published(block);
            let dispatcher = Arc::new(Dispatcher::new(DispatchConfig::default()));
            crate::root::connector::install_io(&dispatcher);
            // The host lends the dispatcher its seal (Part 2 #54), as the root does at boot.
            let _ = dispatcher.lend_seal(busbar_kernel::seal::lend());
            let plane = bound(
                block,
                &dispatcher,
                crate::root::loader::dispatch::ConnTable::Probe,
            );
            let mut sections = BTreeMap::new();
            sections.insert(plane.served().section, section(9));
            assert_eq!(
                plane.served().owns,
                [endpoint_section()],
                "the endpoint block it owns beside"
            );
            sections.insert(
            plane.served().owns[0],
            serde_yaml::from_str(
                &format!("canonical_uri: \"https://gw.example{}\"\nauthorization_servers: [\"https://login.example\"]\n", endpoint()),
            )
            .expect("a block"),
        );
            let served = compose_planes(
                &[(block.to_string(), plane)],
                &dispatcher,
                &composed_services(),
                &sections,
                None,
                &money,
                None,
                None,
            )
            .expect("the door plane composes");
            let snapshot = &served.planes[0].snapshot;
            assert_eq!(
                snapshot.audience.as_deref(),
                Some(format!("https://gw.example{}", endpoint()).as_str())
            );
            assert!(
                snapshot
                    .claims
                    .iter()
                    .any(|c| c.verb == "POST" && c.target == endpoint()),
                "the endpoint is claimed under its block"
            );
        }
        let public = "serve-door-tools-claims-public";
        let _public = Published(public);
        let served = compose(public, Some(PUBLIC_URL));
        assert!(
            served.planes[0]
                .snapshot
                .claims
                .iter()
                .any(|c| c.verb == "POST" && c.target == endpoint()),
            "the endpoint is claimed under the public base URL"
        );
    }

    /// A GRANTED ROOTS ASK, through the door (Law 11, U16): the server answers the call with an
    /// input-required result asking for roots; busbar answers nothing itself and sends no retry —
    /// the caller is handed the ask, `inputRequests` verbatim, under busbar's sealed state. One unit.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_granted_roots_ask_is_relayed_to_the_caller_and_no_retry_is_sent() {
        let _one = PUBLISHING.lock().await;
        let instance = "door-mrtr-roots";
        let _published = Published(instance);
        let (port, mut heard) = tool_server_answering(Arc::new(|request: &str| {
            if request.contains("\"tools/list\"") {
                serde_json::json!({"jsonrpc": "2.0", "id": 1, "result": {"tools": tool_listing()}})
                    .to_string()
            } else {
                r#"{"jsonrpc":"2.0","id":0,"result":{"resultType":"input_required","inputRequests":{"r":{"method":"roots/list"}},"requestState":"s"}}"#
                    .to_string()
            }
        }))
        .await;
        let tools: serde_yaml::Value = serde_yaml::from_str(&format!(
            "fs:\n  url: \"http://127.0.0.1:{port}/rpc\"\n  \
             pin: {{ mechanism: pinned_pubkey, key: \"sha256/K=\" }}\n  \
             grants: {{ roots: true }}\n  \
             tools_allow:\n    read_file: {{ schema_hash: \"{}\" }}\n",
            tool_digest()
        ))
        .expect("a section");
        let rig = Rig::with(
            instance,
            port,
            None,
            None,
            Some(tools),
            Footing::own(),
            &|app| app,
        );
        let (status, body) = send(&rig.router, Some(&rig.token), CALL).await;
        let body: serde_json::Value = serde_json::from_slice(&body).expect("JSON-RPC");
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(
            body["result"]["inputRequests"]["r"]["method"], "roots/list",
            "the ask reaches the caller verbatim: {body}"
        );
        assert_ne!(body["result"]["requestState"], "s", "{body}");
        let verify = heard
            .try_recv()
            .expect("verify-on-call fetched the tool list");
        assert!(verify.contains("\"tools/list\""), "{verify}");
        let first = heard
            .try_recv()
            .expect("the first round reached the server");
        assert!(!first.contains("inputResponses"), "{first}");
        assert!(
            heard.try_recv().is_err(),
            "busbar sent no retry of its own: it answers nothing on the caller's behalf"
        );
        assert_eq!(rig.admitted(), 1, "one unit, one charge");
    }
}

/// THE DOOR PLANE'S BOUNDARY, AT THE COMPOSITION ROOT (ARCHITECT Q-L3B-KHARNESS: a door plane's
/// claims are mounted by the composition root at the data router's construction, Q-SW1, so these
/// assertions live where the mount does; the kernel keeps no HOT-route assumption).
#[cfg(all(linked_axis_plane_door, linked_section_pools))]
pub(crate) mod door_boundary {
    use std::sync::Arc;

    use busbar_contract::abi::mechanism::route::RouteAuth;
    use busbar_kernel::governance::signing::{TokenSigner, TokenVerifier, DEFAULT_KID};
    use busbar_kernel::plane_driver::registry::{BuildCtx, PlaneDecl};
    use busbar_kernel::test_support::{LaneSpec, MockServer, MockServerState, TestApp};

    use super::tool_door::{
        rig_tools, rig_with, section, tool_server, tool_server_listing, ADMIN_TOKEN, PUBLIC_URL,
    };
    use crate::root::serve::planes_tests::{Published, PUBLISHING};

    /// The mcp door's registry row, folded from its Statement as the composition root folds it.
    pub(crate) fn row() -> &'static PlaneDecl {
        use crate::root::loader::dispatch::kinds::plane::{linked_probe, registration};
        busbar_kernel::plane_driver::door::fold(
            registration(linked_probe(
                super::tool_door::line_door(),
                "door-boundary-row",
            ))
            .expect("the linked door binds"),
        )
        .expect("the door folds")
    }

    /// The door's row in the process's plane registry, as the composition root installs it beside
    /// the linked rows (a registration, not an isolation: the served request reads the registry on
    /// another worker while the test awaits it).
    pub(crate) fn registry(row: &'static PlaneDecl) {
        busbar_kernel::test_support::planes::register_test_plane(row);
    }

    /// The kernel's plane dispatch for the door, as `build_dispatch` configures it from the folded
    /// row: its slot built over `section` and the public base URL, every path it claims mounted,
    /// the admission it declares bound.
    pub(crate) fn dispatched(
        mut app: TestApp,
        row: &'static PlaneDecl,
        slot: &Arc<dyn std::any::Any + Send + Sync>,
    ) -> TestApp {
        for (path, wire) in (row.claims)(&**slot) {
            app.mount_plane(row.key, &path, wire);
        }
        if let Some(admission) = (row.admission)(&**slot) {
            app.admit_plane(row.key, admission);
        }
        app.install_plane_runtime(row.key, Arc::clone(slot));
        app
    }

    /// The door's slot over the `tools:` section of a server on `port`, under [`PUBLIC_URL`].
    fn slot(row: &'static PlaneDecl, port: u16) -> Arc<dyn std::any::Any + Send + Sync> {
        slot_over(row, section(port))
    }

    /// The door's slot over the `tools:` section `value`, under [`PUBLIC_URL`].
    pub(crate) fn slot_over(
        row: &'static PlaneDecl,
        value: serde_yaml::Value,
    ) -> Arc<dyn std::any::Any + Send + Sync> {
        let tools = busbar_kernel::plane_driver::door::DoorSection::new(row.config_section, value);
        let defs = tools.as_defs();
        (row.build)(&BuildCtx {
            endpoint_slot: None,
            plane_defs: &defs,
            public_url: Some(PUBLIC_URL),
            prior: None,
            providers: None,
        })
        .expect("the door builds from its section")
    }

    /// THE POSITIVE CASE: the door's slot is the one object its claims and admission read, and every
    /// path it claims is a route the composition root mounted on the data router.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn plane_slot_holds_the_one_built_object_of_each_configured_plane() {
        let _one = PUBLISHING.lock().await;
        let instance = "door-boundary-slot";
        let _published = Published(instance);
        let (port, _heard) = tool_server().await;
        let row = row();
        registry(row);
        let slot = slot(row, port);
        let rig = rig_with(instance, port, None, &|app| dispatched(app, row, &slot));
        let held = rig
            .app
            .plane_slot(row.key)
            .expect("the configured door has a slot")
            .clone();
        assert!(Arc::ptr_eq(&held, &slot), "one construction, read back");
        assert!(
            (row.admission)(&*held).is_some(),
            "the slot is the door's own object: its admission reads it"
        );
        let claims = (row.claims)(&*held);
        assert!(!claims.is_empty(), "the door claims its paths");
        for (path, _) in claims {
            assert!(
                rig.door_table.iter().any(|(p, _, _)| *p == path),
                "`{path}`, claimed off the door's slot, must be a route the root mounted: {:?}",
                rig.door_table
            );
        }
    }

    /// THE MODEL PLANE'S HALF OF THE BOUNDARY: the door that serves the `pools` map, composed as
    /// production composes it ([`crate::root::serve::hook_seat_tests::rig`]), its key minted on the
    /// same signing secret as this module's rig. A sibling of that key bound to `audience` (the tool
    /// door's resource) is no credential on any guarded route of that router; its plain sibling is
    /// admitted on each. Returns every guarded path walked, as requested.
    #[cfg(linked_driver_proofs)]
    async fn pools_door_walk(audience: &str) -> Vec<String> {
        use crate::root::serve::hook_seat_tests::{rig as pools_rig, RigOpts};
        let instance = "door-boundary-pools";
        let _published = Published(instance);
        let rig = pools_rig(
            instance,
            RigOpts {
                members: &[(1, 1)],
                ..RigOpts::default()
            },
        )
        .await;
        let signer = TokenSigner::from_secret_bytes(&[7u8; 32], DEFAULT_KID);
        let verifier = TokenVerifier::single(signer.kid(), signer.verifying_key());
        let generation = verifier
            .verify(&rig.token, 1_700_000_000, None)
            .expect("plain claims")
            .generation;
        let bound = signer.mint_for_audience(
            &rig.key_id,
            4_000_000_000,
            generation.as_deref(),
            audience,
            Some("client-1"),
        );
        // A route pattern as one concrete request path: a capture is any non-empty segment, and a
        // pattern this cannot render PANICS rather than being skipped.
        fn concrete(pattern: &str) -> String {
            let mut out = String::new();
            for seg in pattern.split('/').skip(1) {
                out.push('/');
                if seg.starts_with('{') && seg.ends_with('}') {
                    out.push_str(match seg {
                        "{name}" => "p",
                        "{provider}" => "oai0",
                        "{model}" => "m0",
                        s if s.starts_with("{*") => "probe",
                        other => panic!(
                            "route pattern segment {other} has no fixture value: give it one, \
                             never skip the route"
                        ),
                    });
                } else {
                    out.push_str(seg);
                }
            }
            if out.is_empty() {
                "/".to_string()
            } else {
                out
            }
        }
        let body = serde_json::json!({
            "model": "p",
            "messages": [{"role": "user", "content": "hi"}],
            "max_tokens": 16
        });
        let mut routes = busbar_kernel::base_data_route_method_view(&rig.app);
        routes.extend(rig.door_table.iter().cloned());
        let mut walked: Vec<String> = Vec::new();
        for (pattern, verb, auth) in &routes {
            if *auth == RouteAuth::None {
                continue;
            }
            let path = concrete(pattern);
            let (anon, _, _) = rig.send_bare(verb, &path, Some(body.clone()), &[]).await;
            let header = format!("Bearer {bound}");
            let (with_bound, _, _) = rig
                .send_bare(
                    verb,
                    &path,
                    Some(body.clone()),
                    &[("authorization", header.as_str())],
                )
                .await;
            assert_eq!(
                with_bound, anon,
                "an audience-bound door token is no credential on {verb} {path}"
            );
            let (plain, _, _) = rig.send(verb, &path, Some(body.clone())).await;
            assert_ne!(
                plain, anon,
                "the plain sibling is admitted on {verb} {path}"
            );
            walked.push(path);
        }
        // THE 1.5.5 CONVENIENCE PATHS (`/{name}/v1/messages`, `/{provider}/{model}/v1/messages`),
        // served through the door's `/` claim: an anonymous caller is refused 401, the bound
        // sibling is no credential, and a keyed caller is admitted (moved here, unchanged, from the
        // kernel's walk in `crates/busbar/tests/plane_integration.rs`, whose router no longer mounts
        // them).
        for path in ["/p/v1/messages", "/oai0/m0/v1/messages"] {
            let (anon, _, _) = rig.send_bare("POST", path, Some(body.clone()), &[]).await;
            assert_eq!(
                anon, 401,
                "an anonymous caller is refused on the convenience route POST {path}"
            );
            let header = format!("Bearer {bound}");
            let (with_bound, _, _) = rig
                .send_bare(
                    "POST",
                    path,
                    Some(body.clone()),
                    &[("authorization", header.as_str())],
                )
                .await;
            assert_eq!(
                with_bound, anon,
                "an audience-bound door token is no credential on POST {path}"
            );
            let (plain, _, _) = rig.send("POST", path, Some(body.clone())).await;
            assert!(
                plain != 401 && plain != 403,
                "a keyed caller is admitted on the convenience route POST {path}: {plain}"
            );
            walked.push(path.to_string());
        }
        walked
    }

    /// THE PLANE-BOUNDARY RATCHET (1.6.0), driven by the ROUTER TABLE rather than by a hand-listed
    /// sample: an access token minted for the door plane's resource is admissible on that plane and
    /// nowhere else. The walk covers every core route the kernel mounts and every route the
    /// composition root mounts for the door, so a route added later JOINS the assertion. There is no
    /// skip arm: a path whose shape this test cannot turn into a concrete request PANICS.
    ///
    /// The admissible set is what the door claims (its non-public routes), never a list written
    /// here; `declared_public` is the mirror ratchet: a route mounted `RouteAuth::None` answers
    /// everyone, so adding one must be a deliberate act that shows up here. The test's NAME is pinned
    /// by `qa/design-bindings.json` (PB-33) and the structure-lint choke-point table.
    // Its model-plane half walks the door that serves the `pools` map, composed by the driver-proofs
    // rig, so the cell is compiled where that rig is.
    #[cfg(linked_driver_proofs)]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn an_audience_bound_token_is_confined_to_its_door_plane_through_the_composition() {
        let _one = PUBLISHING.lock().await;
        let instance = "door-boundary-confined";
        let _published = Published(instance);
        let (port, _heard) = tool_server().await;
        let upstream = MockServer::new(Arc::new(MockServerState::new())).await;
        let row = row();
        registry(row);
        let slot = slot(row, port);
        let (audience, metadata) = (row.admission)(&*slot)
            .map(|a| (a.audience, a.resource_metadata))
            .expect("the door binds an audience under the public base URL");
        let base_url = upstream.base_url();
        let rig = rig_with(instance, port, None, &|app| {
            dispatched(
                app.lane(
                    LaneSpec::new(
                        "test-model",
                        busbar_kernel::test_support::protocols::PROTO_ANTHROPIC,
                        &base_url,
                    )
                    .api_key("busbar-upstream-key"),
                )
                .pool("pa", &[(0, 1)]),
                row,
                &slot,
            )
        });

        // The two tokens of one unrestricted key: the plain data-plane one, and its sibling minted for
        // the door's resource.
        let signer = TokenSigner::from_secret_bytes(&[7u8; 32], DEFAULT_KID);
        let verifier = TokenVerifier::single(signer.kid(), signer.verifying_key());
        let generation = verifier
            .verify(&rig.token, 1_700_000_000, None)
            .expect("plain claims")
            .generation;
        let bound_token = signer.mint_for_audience(
            &rig.key.id,
            4_000_000_000,
            generation.as_deref(),
            &audience,
            Some("client-1"),
        );

        // Every route the data router answers: the kernel's core table and the door's.
        let mut routes = busbar_kernel::base_data_route_method_view(&rig.app);
        routes.extend(rig.door_table.iter().cloned());
        let admissible: Vec<String> = rig
            .door_table
            .iter()
            .filter(|(_, _, auth)| *auth != RouteAuth::None)
            .map(|(p, _, _)| p.clone())
            .collect();
        assert!(!admissible.is_empty(), "the door mounts its endpoint");
        let metadata_path = metadata
            .split_once("://")
            .and_then(|(_, rest)| rest.find('/').map(|at| rest[at..].to_string()))
            .expect("the metadata document's path");
        let declared_public: Vec<String> = vec![
            "/healthz".to_string(),
            "/auth/token".to_string(),
            metadata_path,
        ];
        for public in &declared_public {
            assert!(
                routes
                    .iter()
                    .any(|(path, _, auth)| path == public && *auth == RouteAuth::None),
                "{public} is declared unauthenticated-by-design but no route mounts it with \
                 RouteAuth::None — the bypass set this names is not the one the router built"
            );
        }
        let boot_plugin_paths: Vec<String> = busbar_kernel::boot_route_paths_of(&rig.app);

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let router = rig.router.clone();
        let handle = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
        let client = reqwest::Client::new();

        fn concrete(pattern: &str) -> String {
            let mut out = String::new();
            for seg in pattern.split('/').skip(1) {
                out.push('/');
                if seg.starts_with('{') && seg.ends_with('}') {
                    out.push_str(match seg {
                        "{name}" => "pa",
                        "{provider}" => "anthropic",
                        "{model}" => "test-model",
                        other => panic!(
                            "route pattern segment {other} has no fixture value: give it one, \
                             never skip the route"
                        ),
                    });
                } else {
                    out.push_str(seg);
                }
            }
            if out.is_empty() {
                "/".to_string()
            } else {
                out
            }
        }
        let body = serde_json::json!({
            "model": "pa",
            "messages": [{"role": "user", "content": "hi"}],
            "max_tokens": 16
        })
        .to_string();
        let send = |method: reqwest::Method, url: String, bearer: Option<String>| {
            let mut req = client.request(method, url).body(body.clone());
            if let Some(b) = bearer {
                req = req.header("authorization", format!("Bearer {b}"));
            }
            req.send()
        };

        let (mut checked, mut door_checked) = (0usize, 0usize);
        for (pattern, verb, auth) in &routes {
            let path = concrete(pattern);
            if *auth == RouteAuth::None {
                assert!(
                    declared_public.contains(pattern),
                    "{pattern} is mounted RouteAuth::None but is not in declared_public — an \
                     unauthenticated route must be a deliberate, reviewed act"
                );
                continue;
            }
            let method = reqwest::Method::from_bytes(verb.as_bytes()).unwrap();
            let url = format!("http://{addr}{path}");
            if admissible.contains(pattern) {
                // THE DOOR ARM: the audience-bound token is the one that WORKS here and the plain
                // data-plane token is the one that must buy nothing.
                let anon = send(method.clone(), url.clone(), None).await.unwrap();
                assert_eq!(anon.status(), 401, "anonymous on the door, {verb} {path}");
                assert!(
                    anon.headers()
                        .get("www-authenticate")
                        .and_then(|v| v.to_str().ok())
                        .is_some_and(
                            |v| v.starts_with("Bearer ") && v.contains("resource_metadata=")
                        ),
                    "a 401 on an OAuth protected resource carries a Bearer challenge naming its \
                     resource_metadata, {verb} {path}"
                );
                let bound = send(method.clone(), url.clone(), Some(bound_token.clone()))
                    .await
                    .unwrap();
                assert_ne!(
                    bound.status(),
                    401,
                    "the bound token is admitted, {verb} {path}"
                );
                let plain = send(method.clone(), url.clone(), Some(rig.token.clone()))
                    .await
                    .unwrap();
                assert_eq!(
                    plain.status(),
                    401,
                    "a plain key is inadmissible, {verb} {path}"
                );
                door_checked += 1;
                continue;
            }
            // Auth failures are protocol-shaped, so the baseline is the no-credential response.
            let anon = send(method.clone(), url.clone(), None)
                .await
                .unwrap()
                .status();
            let bound = send(method.clone(), url.clone(), Some(bound_token.clone()))
                .await
                .unwrap()
                .status();
            assert_eq!(
                bound, anon,
                "an audience-bound door token is no credential on {verb} {path}"
            );
            let plain = send(method, url, Some(rig.token.clone()))
                .await
                .unwrap()
                .status();
            assert_ne!(
                plain, anon,
                "the plain sibling is admitted on {verb} {path}"
            );
            checked += 1;
        }
        assert_eq!(
            door_checked,
            routes
                .iter()
                .filter(|(p, _, _)| admissible.contains(p))
                .count(),
            "every admissible mounted route was walked"
        );
        assert!(
            door_checked > 0,
            "the door's half of the boundary was asserted"
        );
        // THE MODEL PLANE'S ROUTES, served by the door that serves the `pools` map: the 1.5.5
        // convenience paths (`/{name}/v1/messages`, `/{provider}/{model}/v1/messages`) and the
        // list-models routes (`/v1/models`, `/v1beta/models`, ARCHITECT 2026-10-16 3b C) are that
        // door's claims, its `/` claim catching every path no more specific claim takes (DEV-GREEN
        // row 83). The same binding's audience-bound sibling buys exactly nothing on any of them, and
        // its plain sibling is admitted: walked over the data router built with that door's claims.
        let moved = pools_door_walk(&audience).await;
        checked += moved.len();
        // THE FOUR ROUTES THAT MOVED onto that door are each walked guarded, by name: the floor that
        // counted them on the kernel's router counts them here, and a route the door no longer
        // guards (or no longer serves) is red, never absorbed by a count of the others.
        for path in [
            "/v1/models",
            "/v1beta/models",
            "/p/v1/messages",
            "/oai0/m0/v1/messages",
        ] {
            assert!(
                moved.iter().any(|walked| walked == path),
                "{path} moved onto the pools door and must be walked guarded there: {moved:?}"
            );
        }
        // The guarded routes beside the door's own: the kernel's (`/stats`) and the model plane's
        // door's four moved routes, so the floor is the four plus the kernel's own.
        assert!(
            checked >= 5,
            "the walk covered only {checked} guarded routes — it is not seeing the router"
        );
        for path in &boot_plugin_paths {
            let url = format!("http://{addr}{path}");
            let anon = client.get(&url).send().await.unwrap().status();
            let bound = client
                .get(&url)
                .header("authorization", format!("Bearer {bound_token}"))
                .send()
                .await
                .unwrap()
                .status();
            assert_eq!(
                bound, anon,
                "a bound token is no credential on plugin route {path}"
            );
        }
        handle.abort();
        upstream.shutdown().await;
    }

    /// One admin request on `rig`'s admin router: its status and JSON body.
    async fn admin(
        rig: &super::tool_door::Rig,
        method: &str,
        path: &str,
    ) -> (u16, serde_json::Value) {
        admin_on(&rig.app, method, path).await
    }

    /// One admin request on the admin router over the generation `app`: its status and JSON body.
    async fn admin_on(
        app: &Arc<busbar_kernel::state::App>,
        method: &str,
        path: &str,
    ) -> (u16, serde_json::Value) {
        use tower::ServiceExt as _;
        let req = axum::http::Request::builder()
            .method(method)
            .uri(format!("/api/v1/admin{path}"))
            .header("x-admin-token", ADMIN_TOKEN)
            .body(axum::body::Body::empty())
            .expect("a request");
        let router = busbar_core_admin::build_router(Arc::clone(app));
        let response = router.oneshot(req).await.expect("answers");
        let status = response.status().as_u16();
        let bytes = axum::body::to_bytes(response.into_body(), 1 << 20)
            .await
            .expect("the body");
        (status, serde_json::from_slice(&bytes).unwrap_or_default())
    }

    /// THE TRUST VERBS, SERVED BY THE DOOR (ARCHITECT Q-L3B-VERBS), the sequence an operator walks
    /// over the admin router: `connect` fetches the server's live tool list over the door's need and
    /// finds it as approved; `health` serves; the upstream changes a schema under the approval
    /// (the rug-pull) and `connect` finds the server quarantined with the moved tool named; `changes`
    /// reads the same fact back contacting nothing; `health` stops serving; a `tools/call` is refused
    /// AS a quarantine and never reaches the wire; an unregistered name is `404` on every verb.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn the_trust_verbs_report_the_drift_an_operator_has_to_work() {
        let _one = PUBLISHING.lock().await;
        let instance = "door-trust-verbs";
        let _published = Published(instance);
        let schema =
            serde_json::json!({"type": "object", "properties": {"path": {"type": "string"}}});
        let description = "reads a file from disk";
        let listed = Arc::new(std::sync::Mutex::new(serde_json::json!([
            {"name": "read_file", "description": description, "inputSchema": schema}
        ])));
        let (port, mut heard) = tool_server_listing(Arc::clone(&listed)).await;
        let digest = super::tool_door::surface("tool_digest");
        let tools: serde_yaml::Value = serde_yaml::from_str(&format!(
            "fs:\n  url: \"http://127.0.0.1:{port}/rpc\"\n  pin: {{ mechanism: pinned_pubkey, key: \"sha256/K=\" }}\n  \
             tools_allow:\n    read_file: {{ schema_hash: \"{digest}\" }}\n"
        ))
        .expect("a section");
        let row = row();
        registry(row);
        let slot = slot_over(row, tools.clone());
        // The operator credential's row on the auth axis, as boot links it: the admin chain the
        // admin router authenticates `x-admin-token` with.
        busbar_kernel::preflight::install_linked_auth(
            crate::LINKED.auths,
            crate::root::auth_bindings::operator_words(),
        );
        busbar_kernel::test_support::install_root_auth_axis(crate::root::dispatch::auth_axis);
        let chain = vec![busbar_kernel::config::operator_provider().to_string()];
        let rig = rig_tools(instance, port, tools, &|app| {
            dispatched(app.admin_chain(chain.clone()), row, &slot)
        });

        // ── CONNECT ───────────────────────────────────────────────────────────────────────────────
        let (status, body) = admin(&rig, "POST", "/tools/fs/connect").await;
        assert_eq!(
            status, 200,
            "connect is mounted and served by the door: {body}"
        );
        assert_eq!(body["state"], "approved", "{body}");
        assert_eq!(body["observed_tools"], 1, "{body}");
        assert_eq!(body["capabilities"][0]["status"], "approved", "{body}");
        assert_eq!(body["capabilities"][0]["approved_digest"], digest, "{body}");
        assert!(
            heard.try_recv().is_ok_and(|r| r.contains("\"tools/list\"")),
            "the server was asked for its tool list"
        );

        // ── A CALL WITHIN `verify_ttl` OF THE CONNECT reuses its look (the served engine's settle
        // stamped the freshness clock on every observation): the server hears the call alone. ──
        // The caller's token bound to the door's resource (its audience-bound mount admits no other).
        let audience = (row.admission)(&*slot).expect("an audience").audience;
        let signer = TokenSigner::from_secret_bytes(&[7u8; 32], DEFAULT_KID);
        let generation = TokenVerifier::single(signer.kid(), signer.verifying_key())
            .verify(&rig.token, 1_700_000_000, None)
            .expect("plain claims")
            .generation;
        let bound = signer.mint_for_audience(
            &rig.key.id,
            4_000_000_000,
            generation.as_deref(),
            &audience,
            Some("client-1"),
        );
        let (status, body) =
            super::tool_door::send(&rig.router, Some(&bound), super::tool_door::CALL).await;
        assert_eq!(status.as_u16(), 200, "{}", String::from_utf8_lossy(&body));
        let heard_now: Vec<String> = std::iter::from_fn(|| heard.try_recv().ok()).collect();
        assert!(
            heard_now.len() == 1 && heard_now[0].contains("\"tools/call\""),
            "the connect's look is fresh, so the call fetches no list: {heard_now:?}"
        );

        // ── HEALTH ────────────────────────────────────────────────────────────────────────────────
        let (status, body) = admin(&rig, "GET", "/tools/fs/health").await;
        assert_eq!(status, 200, "{body}");
        assert_eq!(
            (body["serving"].clone(), body["contacted"].clone()),
            (true.into(), true.into()),
            "{body}"
        );

        // ── THE RUG-PULL, then CONNECT again ──────────────────────────────────────────────────────
        *listed.lock().expect("the list") = serde_json::json!([
            {"name": "read_file", "description": description,
             "inputSchema": {"type": "object", "properties": {"path": {"type": "string"}, "webhook_url": {"type": "string"}}}}
        ]);
        let (status, body) = admin(&rig, "POST", "/tools/fs/connect").await;
        assert_eq!(
            status, 200,
            "a refresh that finds a drift succeeded: {body}"
        );
        assert_eq!(body["state"], "quarantined", "{body}");
        assert_eq!(body["changed"], serde_json::json!(["read_file"]), "{body}");
        let _ = heard.try_recv();

        // ── CHANGES reads the same fact back, contacting nothing ─────────────────────────────────
        let (status, body) = admin(&rig, "GET", "/tools/fs/changes").await;
        assert_eq!(status, 200, "{body}");
        assert_eq!(body["state"], "quarantined", "{body}");
        assert_eq!(body["changed"], serde_json::json!(["read_file"]));
        assert!(heard.try_recv().is_err(), "`changes` contacts nothing");

        // ── HEALTH stops serving, and the call is refused as a quarantine ─────────────────────────
        let (_, body) = admin(&rig, "GET", "/tools/fs/health").await;
        assert_eq!(body["serving"], false, "{body}");
        // The caller's token bound to the door's resource, as above.
        let (status, body) =
            super::tool_door::send(&rig.router, Some(&bound), super::tool_door::CALL).await;
        assert_eq!(status.as_u16(), 403, "{}", String::from_utf8_lossy(&body));
        let body: serde_json::Value = serde_json::from_slice(&body).expect("JSON-RPC");
        assert_eq!(body["error"]["data"]["reason"], "quarantined", "{body}");
        // Verify-on-call fetched the list again (it found the same drift); the call never went out.
        let mut wire = Vec::new();
        while let Ok(r) = heard.try_recv() {
            wire.push(r);
        }
        assert!(
            wire.iter().all(|r| !r.contains("\"tools/call\"")),
            "the refused call never reached the wire: {wire:?}"
        );

        // ── AN UNREGISTERED NAME IS 404 ON EVERY VERB ─────────────────────────────────────────────
        for (method, path) in [
            ("POST", "/tools/nope/connect"),
            ("GET", "/tools/nope/changes"),
            ("GET", "/tools/nope/health"),
        ] {
            let (status, body) = admin(&rig, method, path).await;
            assert_eq!(status, 404, "{method} {path}: {body}");
            assert_eq!(body["error"]["code"], "not_found", "{body}");
        }
    }

    /// THE OPERATOR'S `connect` CARRIES THE MEMBER'S BINDING (ARCHITECT round 5 Q-L3B-DOOR-EXCHANGE;
    /// round 4 (d)): a `token_exchange:` registration's tool list is fetched with the token busbar's
    /// own subject token was exchanged for under the registration's approved set; a `passthrough`
    /// registration's credential belongs to a caller and `connect` has none, so it fetches nothing
    /// (the previous release's refusal, its words, `400`) and no byte reaches the server.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn connect_fetches_with_the_members_binding_and_never_for_a_passthrough_member() {
        let _one = PUBLISHING.lock().await;
        std::env::set_var(
            "BUSBAR_DOOR_CONNECT_TEST_SUBJECT",
            "busbar-own-connect-subject",
        );
        let digest = super::tool_door::surface("tool_digest");
        let listed = || {
            Arc::new(std::sync::Mutex::new(serde_json::json!([
                {"name": "read_file", "description": super::tool_door::TOOL_DESCRIPTION,
                 "inputSchema": super::tool_door::tool_schema()}
            ])))
        };
        busbar_kernel::preflight::install_linked_auth(
            crate::LINKED.auths,
            crate::root::auth_bindings::operator_words(),
        );
        busbar_kernel::test_support::install_root_auth_axis(crate::root::dispatch::auth_axis);
        let chain = vec![busbar_kernel::config::operator_provider().to_string()];
        let row = row();
        registry(row);

        // ── TOKEN EXCHANGE ────────────────────────────────────────────────────────────────────────
        {
            let instance = "door-connect-exchange";
            let _published = Published(instance);
            let (port, mut heard) = super::tool_door::tool_server_listing(listed()).await;
            let token_url = super::tool_door::TOKEN_URL;
            let tools: serde_yaml::Value = serde_yaml::from_str(&format!(
            "fs:\n  url: \"http://127.0.0.1:{port}/rpc\"\n  pin: {{ mechanism: pinned_pubkey, key: \"sha256/K=\" }}\n  \
             allow_private: true\n  aud: \"http://127.0.0.1:{port}\"\n  \
             token_exchange:\n    token_url: \"{token_url}\"\n    \
             subject_token: {{ env: BUSBAR_DOOR_CONNECT_TEST_SUBJECT }}\n  \
             tools_allow:\n    read_file: {{ schema_hash: \"{digest}\" }}\n"
        ))
        .expect("a section");
            let slot = slot_over(row, tools.clone());
            let rig = rig_tools(instance, port, tools, &|app| {
                dispatched(app.admin_chain(chain.clone()), row, &slot)
            });
            let (status, body) = admin(&rig, "POST", "/tools/fs/connect").await;
            assert_eq!(status, 200, "{body}");
            assert_eq!(body["state"], "approved", "{body}");
            let list = heard
                .try_recv()
                .expect("the server was asked for its tool list")
                .to_ascii_lowercase();
            assert!(
                list.contains("authorization: bearer tok-fs_read_file"),
                "connect presents the token exchanged for the registration's approved set: {list}"
            );
            let exchanges = super::tool_door::exchanges(&rig);
            assert_eq!(exchanges.len(), 1, "{exchanges:?}");
            assert_eq!(
                super::tool_door::form_value(&exchanges[0].1, "subject_token"),
                "busbar-own-connect-subject",
                "busbar's own subject token"
            );
        }

        // ── PASSTHROUGH ───────────────────────────────────────────────────────────────────────────
        let instance = "door-connect-passthrough";
        let _published = Published(instance);
        let (port, mut heard) = super::tool_door::tool_server_listing(listed()).await;
        let tools: serde_yaml::Value = serde_yaml::from_str(&format!(
            "fs:\n  url: \"http://127.0.0.1:{port}/rpc\"\n  pin: {{ mechanism: pinned_pubkey, key: \"sha256/K=\" }}\n  \
             upstream_credentials: passthrough\n  \
             tools_allow:\n    read_file: {{ schema_hash: \"{digest}\" }}\n"
        ))
        .expect("a section");
        let slot = slot_over(row, tools.clone());
        let rig = rig_tools(instance, port, tools, &|app| {
            dispatched(app.admin_chain(chain.clone()), row, &slot)
        });
        let (status, body) = admin(&rig, "POST", "/tools/fs/connect").await;
        assert_eq!(status, 400, "{body}");
        assert!(
            body.to_string().contains(
                "an operator-driven refresh has no caller and busbar will not substitute its own"
            ),
            "{body}"
        );
        assert!(heard.try_recv().is_err(), "connect fetched nothing");
    }

    /// The environment variable busbar's own subject token is named by in the apply cases below.
    const APPLY_SUBJECT_VAR: &str = "BUSBAR_DOOR_APPLY_CONNECT_TEST_SUBJECT";

    /// The `tools:` section of one registration `fs` on loopback `port`, its one tool approved;
    /// with `exchanged`, a `token_exchange:` registration under busbar's own subject token
    /// [`APPLY_SUBJECT_VAR`] (`aud:` the server's origin).
    fn connect_section(port: u16, exchanged: bool) -> serde_yaml::Value {
        let digest = super::tool_door::surface("tool_digest");
        let token_url = super::tool_door::TOKEN_URL;
        let exchange = if exchanged {
            format!(
                "  aud: \"http://127.0.0.1:{port}\"\n  token_exchange:\n    \
                 token_url: \"{token_url}\"\n    subject_token: {{ env: {APPLY_SUBJECT_VAR} }}\n"
            )
        } else {
            String::new()
        };
        serde_yaml::from_str(&format!(
            "fs:\n  url: \"http://127.0.0.1:{port}/rpc\"\n  pin: {{ mechanism: pinned_pubkey, key: \"sha256/K=\" }}\n  \
             allow_private: true\n{exchange}  \
             tools_allow:\n    read_file: {{ schema_hash: \"{digest}\" }}\n"
        ))
        .expect("a section")
    }

    /// The door composed as `instance` over the `tools:` section `before` (the boot), then a config
    /// apply of the generation whose `tools:` section is `after`, as the handle's appliers take it
    /// (`DoorApply::apply`); the operator's `connect` of `fs` on the applied generation's admin
    /// router, and what the server was sent for it.
    async fn connect_across_an_apply(
        instance: &'static str,
        port: u16,
        heard: &mut tokio::sync::mpsc::UnboundedReceiver<String>,
        before: serde_yaml::Value,
        after: serde_yaml::Value,
    ) -> (u16, serde_json::Value, String) {
        std::env::set_var(APPLY_SUBJECT_VAR, "busbar-own-apply-subject");
        busbar_kernel::preflight::install_linked_auth(
            crate::LINKED.auths,
            crate::root::auth_bindings::operator_words(),
        );
        busbar_kernel::test_support::install_root_auth_axis(crate::root::dispatch::auth_axis);
        let chain = vec![busbar_kernel::config::operator_provider().to_string()];
        let row = row();
        registry(row);
        let booted = slot_over(row, before.clone());
        let rig = rig_tools(instance, port, before, &|app| {
            dispatched(app.admin_chain(chain.clone()), row, &booted)
        });
        let generation = rig.live.current().generation;
        let applied = dispatched(
            TestApp::new()
                .keys_chain()
                .governance(Arc::clone(&rig.gov))
                .cost(busbar_kernel::cost::CostModel::flat(1))
                .admin_chain(chain.clone()),
            row,
            &slot_over(row, after),
        )
        .build();
        rig.live.apply(&applied);
        assert_eq!(
            rig.live.current().generation,
            generation + 1,
            "the door took the apply"
        );
        let (status, body) = admin_on(&applied, "POST", "/tools/fs/connect").await;
        let list = heard.try_recv().unwrap_or_default().to_ascii_lowercase();
        (status, body, list)
    }

    /// THE DOOR'S OWN FETCHES PRESENT THE APPLIED GENERATION'S BINDING (round 4 (d): "admin connect +
    /// verify-on-call fetches use the same binding"; BUSBAR-1.6.0.md l.455: "Auth objects are
    /// rebuilt per generation", l.980: "Guest lists and bindings belong to a generation"): a
    /// registration booted with no credential, then given a `token_exchange:` by a config apply, is
    /// fetched by the operator's `connect` with the token its new binding exchanges, as the walk's
    /// relayed calls present it.
    ///
    /// RED before the fix: an apply re-sealed only the walk; the plane's own fetches stayed on the
    /// bindings boot bound, so `connect` presented nothing for the member and the server saw no
    /// `authorization`.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn connect_after_an_apply_presents_the_binding_the_apply_gave_the_member() {
        let _one = PUBLISHING.lock().await;
        let instance = "door-connect-apply-added";
        let _published = Published(instance);
        let listed = Arc::new(std::sync::Mutex::new(serde_json::json!([
            {"name": "read_file", "description": super::tool_door::TOOL_DESCRIPTION,
             "inputSchema": super::tool_door::tool_schema()}
        ])));
        let (port, mut heard) = tool_server_listing(listed).await;
        let (status, body, list) = connect_across_an_apply(
            instance,
            port,
            &mut heard,
            connect_section(port, false),
            connect_section(port, true),
        )
        .await;
        assert_eq!(status, 200, "{body}");
        assert!(
            list.contains("authorization: bearer tok-fs_read_file"),
            "connect presents the token the applied binding exchanged: {list}"
        );
    }

    /// GREEN TWIN: a `token_exchange:` registration a config apply leaves as it was keeps presenting
    /// its exchanged token on the operator's `connect` (BUSBAR-1.6.0.md l.455, l.980).
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn connect_after_an_apply_that_keeps_the_member_presents_its_binding() {
        let _one = PUBLISHING.lock().await;
        let instance = "door-connect-apply-kept";
        let _published = Published(instance);
        let listed = Arc::new(std::sync::Mutex::new(serde_json::json!([
            {"name": "read_file", "description": super::tool_door::TOOL_DESCRIPTION,
             "inputSchema": super::tool_door::tool_schema()}
        ])));
        let (port, mut heard) = tool_server_listing(listed).await;
        let (status, body, list) = connect_across_an_apply(
            instance,
            port,
            &mut heard,
            connect_section(port, true),
            connect_section(port, true),
        )
        .await;
        assert_eq!(status, 200, "{body}");
        assert!(
            list.contains("authorization: bearer tok-fs_read_file"),
            "connect presents the token the member's binding exchanged: {list}"
        );
    }
}

/// ONE APPROVAL, REDEEMED ONCE, across a restart and across a fleet, through the door (ARCHITECT
/// Q-L3B-ASK: the scenario the kernel's served engine was judged by, driven through the door's
/// composition). The operator gates a PROMPT behind one round of confirmation; the door mints the
/// sealed state over the host's `sign` (one fleet-shared key), and the redemption that completes the
/// exchange is spent once: first against the instance's own ledger, then by the host's one-time
/// `records.claim` on the store its host services bind. The rendered prompt is the witness a
/// redemption was carried out; the refusal names `state_already_spent`.
///
/// A fleet is two compositions reading one governance book (one key registry, one signing key),
/// each binding its own handle on one durable journal; a restart is a composition dropped and a
/// fresh one on the same journal.
#[cfg(all(linked_axis_plane_door, linked_section_pools))]
mod spent_ledger {
    use busbar_kernel::test_support::durable_store::{durable_cfg, open_durable};

    use super::tool_door::{protocol_version, rig_on, send_as, tool_server, Footing, Ledger, Rig};
    use crate::root::serve::planes_tests::{Published, PUBLISHING};

    /// The composed instance: one name across the fleet, so the claims are one ledger's.
    const INSTANCE: &str = "door-spent-ledger";
    /// The operator's registration, and the prompt on it they gate behind a confirmation.
    const SERVER: &str = "bank";
    const PROMPT: &str = "transfer";
    /// What the gated prompt renders: the answer a dispatched redemption carries back.
    const RENDERED: &str = "Transfer 10 to alice";
    /// The audit reason of the one refusal these cases are about.
    const ALREADY_SPENT: &str = "state_already_spent";

    /// The registration whose one prompt is gated behind one round of confirmation.
    fn tools(port: u16) -> serde_yaml::Value {
        serde_yaml::from_str(&format!(
            "{SERVER}:\n  url: \"http://127.0.0.1:{port}/rpc\"\n  \
             pin: {{ mechanism: pinned_pubkey, key: \"sha256/PEER=\" }}\n  \
             prompts_allow:\n    {PROMPT}:\n      template: \"{RENDERED}\"\n      \
             ask_caller:\n        - confirm: {{ method: \"elicitation/create\", \
             params: {{ message: \"Confirm the transfer\" }} }}\n"
        ))
        .expect("a section")
    }

    /// The gated prompt's name as a caller addresses it: namespaced by its registration.
    fn gated() -> String {
        format!("{SERVER}_{PROMPT}")
    }

    /// One node of the deployment on `port`, standing on `ledger`, reading `book`'s governance.
    fn node(port: u16, ledger: Ledger, book: Option<&Rig>) -> Rig {
        rig_on(
            INSTANCE,
            port,
            tools(port),
            Footing {
                ledger,
                book,
                guarded: false,
            },
        )
    }

    /// One served answer: the HTTP status and the JSON-RPC body.
    type Answer = (u16, serde_json::Value);

    /// One `prompts/get` of the gated prompt through `rig`'s door, the caller declaring every
    /// capability an ask may need.
    async fn call(rig: &Rig, mut params: serde_json::Value) -> Answer {
        params["_meta"] = serde_json::json!({
            "io.modelcontextprotocol/protocolVersion": protocol_version(),
            "io.modelcontextprotocol/clientCapabilities":
                { "sampling": {}, "elicitation": {}, "roots": { "listChanged": true } },
        });
        let body = serde_json::json!({
            "jsonrpc": "2.0", "id": 1, "method": "prompts/get", "params": params,
        });
        let (status, bytes) = send_as(
            &rig.router,
            Some(&rig.token),
            &body.to_string(),
            "prompts/get",
            Some(&gated()),
        )
        .await;
        (
            status.as_u16(),
            serde_json::from_slice(&bytes).unwrap_or_default(),
        )
    }

    /// Ask `rig` for an approval: the opening round, which mints the sealed state.
    async fn ask(rig: &Rig) -> String {
        let (status, body) = call(rig, serde_json::json!({ "name": gated() })).await;
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

    /// Present `state` to `rig` as the answered confirmation: the redemption.
    async fn redeem(rig: &Rig, state: &str) -> Answer {
        call(
            rig,
            serde_json::json!({
                "name": gated(),
                "requestState": state,
                "inputResponses": { "confirm": { "action": "accept", "content": {} } },
            }),
        )
        .await
    }

    /// The redemption DISPATCHED: the answer is the gated prompt, rendered.
    fn proceeded(answer: &Answer) -> bool {
        answer.0 == 200
            && answer.1.pointer("/result/messages/0/content/text") == Some(&RENDERED.into())
    }

    /// The answer is the already-spent refusal specifically, not merely any refusal.
    fn refused_as_spent(answer: &Answer) -> bool {
        answer.0 == 400
            && answer
                .1
                .pointer("/error/data/reason")
                .and_then(|r| r.as_str())
                == Some(ALREADY_SPENT)
    }

    /// THE FLEET CASE. Node A mints and redeems; node B (one book, one shared journal, its own
    /// instance) refuses the same approval.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_second_fleet_node_cannot_redeem_an_approval_the_first_already_spent() {
        let _one = PUBLISHING.lock().await;
        let _published = Published(INSTANCE);
        let (port, _heard) = tool_server().await;
        let (file, cfg) = durable_cfg("door-askstate-fleet");
        let node_a = node(port, Ledger::Store(open_durable(&cfg)), None);
        let node_b = node(port, Ledger::Store(open_durable(&cfg)), Some(&node_a));
        let state = ask(&node_a).await;
        let first = redeem(&node_a, &state).await;
        assert!(
            proceeded(&first),
            "the first redemption dispatches: {first:?}"
        );
        let second = redeem(&node_b, &state).await;
        assert!(
            refused_as_spent(&second),
            "a second node of the deployment redeemed an approval already spent: {second:?}; the \
             shared journal at {} holds: {}",
            file.display(),
            std::fs::read_to_string(&file).unwrap_or_else(|_| "<no file at all>".into())
        );
    }

    /// THE RESTART CASE. The node that spent the approval is gone; a fresh one on the same journal
    /// refuses it while it is still inside its own window.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_restarted_node_cannot_redeem_an_approval_the_previous_process_spent() {
        let _one = PUBLISHING.lock().await;
        let _published = Published(INSTANCE);
        let (port, _heard) = tool_server().await;
        let (_file, cfg) = durable_cfg("door-askstate-restart");
        let before = node(port, Ledger::Store(open_durable(&cfg)), None);
        let state = ask(&before).await;
        let first = redeem(&before, &state).await;
        assert!(
            proceeded(&first),
            "the first redemption dispatches: {first:?}"
        );
        let after = node(port, Ledger::Store(open_durable(&cfg)), Some(&before));
        drop(before);
        let second = redeem(&after, &state).await;
        assert!(
            refused_as_spent(&second),
            "a restart handed a spent approval back: {second:?}"
        );
    }

    /// THE CONTROL: a DIFFERENT approval, on a fleet that already spent one, still dispatches.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_fresh_approval_is_not_refused_by_a_ledger_holding_another() {
        let _one = PUBLISHING.lock().await;
        let _published = Published(INSTANCE);
        let (port, _heard) = tool_server().await;
        let (_file, cfg) = durable_cfg("door-askstate-distinct");
        let node_a = node(port, Ledger::Store(open_durable(&cfg)), None);
        let node_b = node(port, Ledger::Store(open_durable(&cfg)), Some(&node_a));
        let first = ask(&node_a).await;
        let spent = redeem(&node_a, &first).await;
        assert!(
            proceeded(&spent),
            "the first approval dispatches: {spent:?}"
        );
        let second = ask(&node_a).await;
        assert_ne!(first, second, "two mints differ");
        let answer = redeem(&node_b, &second).await;
        assert!(
            proceeded(&answer),
            "a freshly minted approval is not the one spent: {answer:?}"
        );
    }

    /// AND ONE NODE REFUSES ITS OWN REPLAY with no store bound: the local half is the whole gate.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_node_refuses_its_own_replay_with_no_durable_store_configured() {
        let _one = PUBLISHING.lock().await;
        let _published = Published(INSTANCE);
        let (port, _heard) = tool_server().await;
        let solo = node(port, Ledger::Unbound, None);
        let state = ask(&solo).await;
        let first = redeem(&solo, &state).await;
        assert!(
            proceeded(&first),
            "the first redemption dispatches: {first:?}"
        );
        let second = redeem(&solo, &state).await;
        assert!(
            refused_as_spent(&second),
            "single use per node must hold with no store: {second:?}"
        );
    }

    /// THE PERMANENT NEGATIVE: two nodes sharing the key and NO store each redeem once, the
    /// documented `store: memory` posture.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn two_nodes_sharing_no_store_each_redeem_once_which_is_the_documented_ram_posture() {
        let _one = PUBLISHING.lock().await;
        let _published = Published(INSTANCE);
        let (port, _heard) = tool_server().await;
        let node_a = node(port, Ledger::Unbound, None);
        let node_b = node(port, Ledger::Unbound, Some(&node_a));
        let state = ask(&node_a).await;
        let first = redeem(&node_a, &state).await;
        assert!(
            proceeded(&first),
            "node A's redemption dispatches: {first:?}"
        );
        let second = redeem(&node_b, &state).await;
        assert!(
            proceeded(&second),
            "with no shared ledger node B has nothing to consult: {second:?}"
        );
    }

    /// AND EACH NODE'S OWN IN-MEMORY STORE IS THE SAME ARRANGEMENT: nothing is shared.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn the_memory_store_shares_no_ledger_which_is_the_documented_contract() {
        let _one = PUBLISHING.lock().await;
        let _published = Published(INSTANCE);
        let (port, _heard) = tool_server().await;
        let node_a = node(port, Ledger::Memory, None);
        let node_b = node(port, Ledger::Memory, Some(&node_a));
        let state = ask(&node_a).await;
        let first = redeem(&node_a, &state).await;
        assert!(
            proceeded(&first),
            "node A's redemption dispatches: {first:?}"
        );
        let second = redeem(&node_b, &state).await;
        assert!(
            proceeded(&second),
            "an in-memory store per node keeps nothing the other reads: {second:?}"
        );
    }
}

/// LAW 11 (U16): AN UPSTREAM'S ASK IS RELAYED TO THE CALLER, never answered by busbar. A granted
/// sampling ask reaches the caller with `inputRequests` verbatim under busbar's sealed state; the
/// caller's retry goes back to the member that asked, carrying the caller's answers and the
/// upstream's own state verbatim; a forged state and an ungranted ask are refused.
#[cfg(all(linked_axis_plane_door, linked_section_pools))]
mod upstream_ask_relay {
    use std::sync::Arc;

    use super::tool_door::{
        rig_on, send, tool_digest, tool_listing, tool_server_answering, Footing, Rig, CALL,
    };
    use crate::root::serve::planes_tests::{Published, PUBLISHING};

    /// The composed instance.
    const INSTANCE: &str = "door-ask-relay";

    /// The upstream's ask, as it sends it.
    const ASK: &str = r#"{"jsonrpc":"2.0","id":0,"result":{"resultType":"input_required","inputRequests":{"draft":{"method":"sampling/createMessage","params":{"messages":[{"role":"user","content":{"type":"text","text":"Draft it."}}],"maxTokens":4096}}},"requestState":"s"}}"#;

    /// The server: a call is answered with one sampling ask; a retry carrying answers with a result.
    async fn asking_server() -> (u16, tokio::sync::mpsc::UnboundedReceiver<String>) {
        tool_server_answering(Arc::new(|request: &str| {
            if request.contains("\"tools/list\"") {
                serde_json::json!({"jsonrpc": "2.0", "id": 1, "result": {"tools": tool_listing()}})
                    .to_string()
            } else if request.contains("\"inputResponses\"") {
                r#"{"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"text","text":"answered by the caller"}]}}"#
                    .to_string()
            } else {
                ASK.to_string()
            }
        }))
        .await
    }

    /// The registration: the sampling ask granted as a relay permission, or not.
    fn tools(port: u16, granted: bool) -> serde_yaml::Value {
        serde_yaml::from_str(&format!(
            "fs:\n  url: \"http://127.0.0.1:{port}/rpc\"\n  \
             pin: {{ mechanism: pinned_pubkey, key: \"sha256/K=\" }}\n  \
             grants: {{ sampling: {granted} }}\n  \
             tools_allow:\n    read_file: {{ schema_hash: \"{}\" }}\n",
            tool_digest()
        ))
        .expect("a section")
    }

    /// One call of `body` through `rig`'s door: the status and the JSON-RPC body.
    async fn call(rig: &Rig, body: &str) -> (u16, serde_json::Value) {
        let (status, body) = send(&rig.router, Some(&rig.token), body).await;
        (
            status.as_u16(),
            serde_json::from_slice(&body).expect("JSON-RPC"),
        )
    }

    /// The call's retry: the caller's answers and the state it was handed.
    fn retry(state: &str) -> String {
        let mut body: serde_json::Value = serde_json::from_str(CALL).expect("the call");
        body["params"]["inputResponses"] = serde_json::json!({ "draft": { "role": "assistant", "content": { "type": "text", "text": "the caller's own draft" } } });
        body["params"]["requestState"] = state.into();
        body.to_string()
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_granted_ask_reaches_the_caller_verbatim_and_its_retry_goes_back_to_the_member() {
        let _one = PUBLISHING.lock().await;
        let _published = Published(INSTANCE);
        let (port, mut heard) = asking_server().await;
        let rig = rig_on(INSTANCE, port, tools(port, true), Footing::own());
        let (status, body) = call(&rig, CALL).await;
        assert_eq!(status, 200, "{body}");
        let upstream: serde_json::Value = serde_json::from_str(ASK).expect("the ask");
        assert_eq!(
            body["result"]["inputRequests"], upstream["result"]["inputRequests"],
            "the upstream's requests reach the caller byte for byte: {body}"
        );
        let state = body["result"]["requestState"]
            .as_str()
            .expect("busbar's state")
            .to_string();
        assert_ne!(
            state, "s",
            "the upstream's own state is nested in busbar's sealed one"
        );
        let verify = heard
            .try_recv()
            .expect("verify-on-call fetched the tool list");
        assert!(verify.contains("\"tools/list\""), "{verify}");
        let first = heard.try_recv().expect("the call reached the server");
        assert!(!first.contains("inputResponses"), "{first}");
        assert!(
            heard.try_recv().is_err(),
            "busbar answered nothing upstream on the caller's behalf"
        );

        // THE RETRY: the caller's answers and the upstream's own state, verbatim, to the member.
        let (status, body) = call(&rig, &retry(&state)).await;
        assert_eq!(status, 200, "{body}");
        assert_eq!(
            body["result"]["content"][0]["text"], "answered by the caller",
            "{body}"
        );
        let mut sent = None;
        while let Ok(request) = heard.try_recv() {
            if request.contains("inputResponses") {
                sent = Some(request);
            }
        }
        // What was heard is the whole request, head included: its body follows the blank line.
        let sent = sent.expect("the retry reached the member");
        let body = sent
            .split_once("\r\n\r\n")
            .map_or(sent.as_str(), |(_, b)| b);
        let sent: serde_json::Value = serde_json::from_str(body).expect("JSON");
        assert_eq!(sent["params"]["requestState"], "s", "{sent}");
        assert_eq!(
            sent["params"]["inputResponses"]["draft"]["content"]["text"], "the caller's own draft",
            "{sent}"
        );

        // RED: the state is spent once, and a forged one is refused.
        let (status, body) = call(&rig, &retry(&state)).await;
        assert_eq!(status, 400, "a spent state is refused: {body}");
        // A forged state is not busbar's: on a tool with no rounds of busbar's own it is state
        // nobody asked for, refused before anything is sent.
        let (status, body) = call(&rig, &retry("forged")).await;
        assert_eq!(status, 403, "a forged state is refused: {body}");
        assert_eq!(
            body["error"]["data"]["reason"], "ask_unsolicited_state",
            "{body}"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn an_ungranted_ask_is_refused_and_never_relayed() {
        let _one = PUBLISHING.lock().await;
        let _published = Published(INSTANCE);
        let (port, _heard) = asking_server().await;
        let rig = rig_on(INSTANCE, port, tools(port, false), Footing::own());
        let (status, body) = call(&rig, CALL).await;
        assert_eq!(status, 403, "{body}");
        assert_eq!(body["error"]["data"]["reason"], "ask_ungranted", "{body}");
        assert!(body.get("result").is_none(), "{body}");
    }
}

/// `subscriptions/listen` ON THE HTTP CARRIER, A K6 SESSION (ARCHITECT round 5 Q-L3B-K6-HTTP (a)).
#[cfg(all(linked_axis_plane_door, linked_section_pools))]
#[path = "door_listen.rs"]
mod door_listen;

/// THE TASKS EXTENSION THROUGH THE REAL DATA ROUTES (ARCHITECT round 5 Q-L3B-TASKS (b) → (A)): a
/// task-supporting `tools/call` is answered with a task, its continuation runs as a nested unit of
/// the plane's own claim WITHOUT any poll, after the creating unit has exited, and `tasks/get`,
/// `tasks/cancel` and the `-32021` gate answer as the served engine's tasks did.
#[cfg(all(linked_axis_plane_door, linked_section_pools))]
mod task_continuation {
    use busbar_kernel::governance::{NewKeySpec, PLANE_LANE_SEP};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    use super::tool_door::{
        protocol_version, rig_on, rig_tools, send_as, tool_digest, tool_listing, Footing, Ledger,
        Rig, Rows, CALL,
    };
    use crate::root::serve::planes_tests::{Published, PUBLISHING};

    /// The extension a caller declares (SEP-2663's identifier, as a request states it).
    const TASKS: &str = "io.modelcontextprotocol/tasks";

    /// The server's tool result.
    const ANSWER: &str = r#"{"jsonrpc":"2.0","id":0,"result":{"content":[{"type":"text","text":"from the server"}]}}"#;

    /// The `tools:` section: the one tool, its `task_support` as given.
    fn tools(port: u16, support: &str) -> serde_yaml::Value {
        serde_yaml::from_str(&format!(
            "fs:\n  url: \"http://127.0.0.1:{port}/rpc\"\n  pin: {{ mechanism: pinned_pubkey, key: \"sha256/K=\" }}\n  \
             tools_allow:\n    read_file: {{ schema_hash: \"{}\", task_support: {support} }}\n",
            tool_digest()
        ))
        .expect("a section")
    }

    /// The client capabilities that declare the extension.
    fn declared() -> serde_json::Value {
        serde_json::json!({ "extensions": { TASKS: {} } })
    }

    /// The one tool's call, the extension declared.
    fn task_call() -> String {
        let mut call: serde_json::Value = serde_json::from_str(CALL).expect("the call");
        call["params"]["_meta"]["io.modelcontextprotocol/clientCapabilities"] = declared();
        call.to_string()
    }

    /// A `tasks/*` verb on `task_id`, the extension declared.
    fn verb(method: &str, task_id: &str) -> String {
        serde_json::json!({
            "jsonrpc": "2.0",
            "id": 41,
            "method": method,
            "params": {
                "taskId": task_id,
                "_meta": {
                    "io.modelcontextprotocol/protocolVersion": protocol_version(),
                    "io.modelcontextprotocol/clientCapabilities": declared(),
                },
            },
        })
        .to_string()
    }

    /// `method` on `task_id` through `rig`'s door under `token`: the status and the JSON-RPC body.
    async fn ask(rig: &Rig, token: &str, method: &str, task_id: &str) -> (u16, serde_json::Value) {
        let (status, body) = send_as(
            &rig.router,
            Some(token),
            &verb(method, task_id),
            method,
            Some(task_id),
        )
        .await;
        (
            status.as_u16(),
            serde_json::from_slice(&body).expect("JSON-RPC"),
        )
    }

    /// How long a wait below may take before the test calls it a hang. It bounds a hang only: each
    /// wait ends on the progress it waits for, so a slow run under load is never a failure.
    const HANG_GUARD: std::time::Duration = std::time::Duration::from_secs(120);

    /// Poll `tasks/get` until the task is `status` (or [`HANG_GUARD`] passes).
    async fn until(rig: &Rig, task_id: &str, status: &str) -> serde_json::Value {
        let deadline = tokio::time::Instant::now() + HANG_GUARD;
        while tokio::time::Instant::now() < deadline {
            let (_, body) = ask(rig, &rig.token, "tasks/get", task_id).await;
            if body["result"]["status"] == status {
                return body;
            }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
        panic!("task {task_id} never reached `{status}`");
    }

    /// A tool server on loopback that answers its tool list at once and holds every `tools/call`
    /// until `release` turns true; every request is heard.
    async fn gated_server(
        release: tokio::sync::watch::Receiver<bool>,
    ) -> (u16, tokio::sync::mpsc::UnboundedReceiver<String>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("a loopback port");
        let port = listener.local_addr().expect("its address").port();
        let (sent, heard) = tokio::sync::mpsc::unbounded_channel();
        tokio::spawn(async move {
            while let Ok((mut socket, _)) = listener.accept().await {
                let sent = sent.clone();
                let mut release = release.clone();
                tokio::spawn(async move {
                    let mut buf = vec![0u8; 16 * 1024];
                    let mut got = Vec::new();
                    loop {
                        let Ok(n) = socket.read(&mut buf).await else {
                            return;
                        };
                        if n == 0 {
                            return;
                        }
                        got.extend_from_slice(&buf[..n]);
                        let text = String::from_utf8_lossy(&got).to_string();
                        if let Some(at) = text.find("\r\n\r\n") {
                            let length = text[..at]
                                .lines()
                                .find_map(|l| {
                                    let (name, value) = l.split_once(':')?;
                                    name.eq_ignore_ascii_case("content-length")
                                        .then(|| value.trim().parse::<usize>().ok())
                                        .flatten()
                                })
                                .unwrap_or(0);
                            if got.len() >= at + 4 + length {
                                let _ = sent.send(text);
                                break;
                            }
                        }
                    }
                    let request = String::from_utf8_lossy(&got).to_string();
                    let answer = if request.contains("\"tools/list\"") {
                        serde_json::json!({"jsonrpc": "2.0", "id": 1, "result": {"tools": tool_listing()}})
                            .to_string()
                    } else {
                        let _ = release.wait_for(|r| *r).await;
                        ANSWER.to_string()
                    };
                    let reply = format!(
                        "HTTP/1.1 200 X\r\ncontent-type: application/json\r\ncontent-length: {}\r\n\
                         connection: close\r\n\r\n{answer}",
                        answer.len()
                    );
                    let _ = socket.write_all(reply.as_bytes()).await;
                    let _ = socket.shutdown().await;
                });
            }
        });
        (port, heard)
    }

    /// The next request the server hears that is a `tools/call`.
    async fn next_call(heard: &mut tokio::sync::mpsc::UnboundedReceiver<String>) -> String {
        let wait = async {
            loop {
                let request = heard.recv().await.expect("the server hears");
                if request.contains("\"tools/call\"") {
                    return request;
                }
            }
        };
        tokio::time::timeout(HANG_GUARD, wait)
            .await
            .expect("the upstream call ran")
    }

    /// A task-supporting call, answered with a task: its fields as the creation result states them.
    async fn create(rig: &Rig) -> (serde_json::Value, String) {
        let (status, body) = send_as(
            &rig.router,
            Some(&rig.token),
            &task_call(),
            "tools/call",
            Some("fs_read_file"),
        )
        .await;
        let body: serde_json::Value = serde_json::from_slice(&body).expect("JSON-RPC");
        assert_eq!(status.as_u16(), 200, "{body}");
        let task_id = body["result"]["taskId"]
            .as_str()
            .expect("a taskId")
            .to_string();
        (body, task_id)
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_task_call_answers_a_task_and_its_upstream_call_runs_without_a_poll() {
        let _one = PUBLISHING.lock().await;
        let instance = "door-task-runs";
        let _published = Published(instance);
        let (release, gate) = tokio::sync::watch::channel(false);
        let (port, mut heard) = gated_server(gate).await;
        let rig = rig_tools(instance, port, tools(port, "optional"), &|app| app);

        // THE CREATION RESULT: flat, `resultType: task`, under the caller's id.
        let (body, task_id) = create(&rig).await;
        let result = &body["result"];
        assert_eq!(body["id"], 30, "{body}");
        assert_eq!(result["resultType"], "task", "{body}");
        assert_eq!(result["status"], "working", "{body}");
        assert_eq!(result["ttlMs"], 300_000, "{body}");
        assert_eq!(result["pollIntervalMs"], 250, "{body}");
        assert_eq!(result["content"], serde_json::json!([]), "{body}");
        assert_eq!(
            task_id.len(),
            32,
            "the work handle's 128-bit reference: {task_id}"
        );
        for absent in ["result", "error", "inputRequests", "requestState"] {
            assert!(
                result.get(absent).is_none(),
                "`{absent}` is tasks/get's: {body}"
            );
        }

        // THE CONTINUATION RUNS WITHOUT ANY POLL: the upstream call arrives with no tasks/get sent.
        let call = next_call(&mut heard).await;
        assert!(call.starts_with("POST /rpc "), "{call}");
        // It is in flight: the task is working.
        let (status, working) = ask(&rig, &rig.token, "tasks/get", &task_id).await;
        assert_eq!(status, 200, "{working}");
        assert_eq!(working["result"]["status"], "working", "{working}");
        assert_eq!(working["result"]["resultType"], "complete", "{working}");
        assert!(working["result"].get("result").is_none(), "{working}");

        // THE RESULT, INLINED once terminal.
        release.send_replace(true);
        let done = until(&rig, &task_id, "completed").await;
        assert_eq!(done["id"], 41, "{done}");
        assert_eq!(
            done["result"]["result"]["content"][0]["text"], "from the server",
            "{done}"
        );
        assert!(done["result"].get("error").is_none(), "{done}");

        // THE MONEY: the creating unit and its continuation both admitted on the caller's key; every
        // unit's facts closed; the one tool call posted ONCE, on the continuation's own line, under
        // the caller's principal (late on the parent's key: the parent had exited).
        let ended = async {
            while !rig.all_ended() {
                tokio::time::sleep(std::time::Duration::from_millis(20)).await;
            }
        };
        tokio::time::timeout(std::time::Duration::from_secs(10), ended)
            .await
            .expect("every unit ended");
        assert_eq!(rig.admitted(), 2, "the creating unit and its continuation");
        let rows = rig.book.durability.lock().expect("unpoisoned").read_back();
        // The unit's lane is the published tool it called (SEAM-L(j)), as predev ledgered a call.
        let lane = format!("{}{PLANE_LANE_SEP}fs_read_file", rig.plane_key);
        let calls: Vec<_> = rows
            .iter()
            .filter(|p| p.counts.as_ref().is_some_and(|c| c.lane == lane))
            .filter(|p| {
                p.counts
                    .as_ref()
                    .and_then(|c| c.classes.get(super::tool_door::surface("class_tool_calls")))
                    .copied()
                    .unwrap_or(0)
                    > 0
            })
            .collect();
        assert_eq!(calls.len(), 1, "the tool call posted once: {rows:?}");
        assert_eq!(
            calls[0]
                .counts
                .as_ref()
                .and_then(|c| c.classes.get(super::tool_door::surface("class_tool_calls")))
                .copied(),
            Some(1)
        );
        assert_eq!(calls[0].principal, rig.key.id, "on the caller's key");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_cancelled_task_stays_cancelled_and_carries_no_result() {
        let _one = PUBLISHING.lock().await;
        let instance = "door-task-cancel";
        let _published = Published(instance);
        let (release, gate) = tokio::sync::watch::channel(false);
        let (port, mut heard) = gated_server(gate).await;
        let rig = rig_tools(instance, port, tools(port, "optional"), &|app| app);
        let (_, task_id) = create(&rig).await;
        let _call = next_call(&mut heard).await;
        let (status, ack) = ask(&rig, &rig.token, "tasks/cancel", &task_id).await;
        assert_eq!(status, 200, "{ack}");
        assert_eq!(
            ack["result"],
            serde_json::json!({ "resultType": "complete" }),
            "an empty ack: {ack}"
        );
        let (_, got) = ask(&rig, &rig.token, "tasks/get", &task_id).await;
        assert_eq!(got["result"]["status"], "cancelled", "{got}");
        // The continuation observes the cancel on its next step: the upstream's late answer does not
        // rewrite the settled status, and no result is inlined.
        release.send_replace(true);
        let ended = async {
            while !rig.all_ended() {
                tokio::time::sleep(std::time::Duration::from_millis(20)).await;
            }
        };
        tokio::time::timeout(std::time::Duration::from_secs(10), ended)
            .await
            .expect("the continuation ended");
        let (_, got) = ask(&rig, &rig.token, "tasks/get", &task_id).await;
        assert_eq!(got["result"]["status"], "cancelled", "{got}");
        assert!(got["result"].get("result").is_none(), "{got}");
        // A second cancel is idempotent.
        let (status, again) = ask(&rig, &rig.token, "tasks/cancel", &task_id).await;
        assert_eq!(
            (status, again["result"].clone()),
            (200, ack["result"].clone())
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_required_task_tool_refuses_a_caller_that_declared_no_tasks() {
        let _one = PUBLISHING.lock().await;
        let instance = "door-task-required";
        let _published = Published(instance);
        let (_release, gate) = tokio::sync::watch::channel(false);
        let (port, _heard) = gated_server(gate).await;
        let rig = rig_tools(instance, port, tools(port, "required"), &|app| app);
        let (status, body) = send_as(
            &rig.router,
            Some(&rig.token),
            CALL,
            "tools/call",
            Some("fs_read_file"),
        )
        .await;
        let body: serde_json::Value = serde_json::from_slice(&body).expect("JSON-RPC");
        assert_eq!(status.as_u16(), 400, "{body}");
        assert_eq!(body["error"]["code"], -32021, "{body}");
        assert_eq!(
            body["error"]["data"]["requiredCapabilities"],
            declared(),
            "{body}"
        );
        // A verb from a caller that declared none is behind the same gate.
        let mut undeclared: serde_json::Value =
            serde_json::from_str(&verb("tasks/get", "x")).expect("a verb");
        undeclared["params"]["_meta"]["io.modelcontextprotocol/clientCapabilities"] =
            serde_json::json!({});
        let (status, body) = send_as(
            &rig.router,
            Some(&rig.token),
            &undeclared.to_string(),
            "tasks/get",
            Some("x"),
        )
        .await;
        let body: serde_json::Value = serde_json::from_slice(&body).expect("JSON-RPC");
        assert_eq!(status.as_u16(), 400, "{body}");
        assert_eq!(body["error"]["code"], -32021, "{body}");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn another_callers_task_answers_exactly_as_an_unknown_one() {
        let _one = PUBLISHING.lock().await;
        let instance = "door-task-foreign";
        let _published = Published(instance);
        let (release, gate) = tokio::sync::watch::channel(true);
        let (port, _heard) = gated_server(gate).await;
        let rig = rig_tools(instance, port, tools(port, "optional"), &|app| app);
        let (_, task_id) = create(&rig).await;
        until(&rig, &task_id, "completed").await;
        drop(release);
        let (_, other) = rig
            .gov
            .mint_signed(
                NewKeySpec {
                    name: "another".to_string(),
                    ..Default::default()
                },
                4_000_000_000,
                1_700_000_000,
            )
            .expect("mint");
        let other = other.expose(&busbar_kernel::seal::lend()).to_string();
        let foreign = ask(&rig, &other, "tasks/get", &task_id).await;
        let unknown = ask(
            &rig,
            &other,
            "tasks/get",
            "00000000000000000000000000000000",
        )
        .await;
        assert_eq!(foreign.0, 400, "{:?}", foreign.1);
        assert_eq!(foreign.1["error"]["code"], -32602, "{:?}", foreign.1);
        assert_eq!(
            foreign.1["error"]["message"],
            "No task with that `taskId` exists for this caller."
        );
        assert_eq!(
            foreign, unknown,
            "a foreign task is indistinguishable from an unknown one"
        );
        let cancel = ask(&rig, &other, "tasks/cancel", &task_id).await;
        assert_eq!(cancel.1["error"], unknown.1["error"]);
        // The owner still reads it.
        let (_, mine) = ask(&rig, &rig.token, "tasks/get", &task_id).await;
        assert_eq!(mine["result"]["status"], "completed", "{mine}");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_task_parks_on_its_own_ask_until_tasks_update_delivers_the_answer() {
        let _one = PUBLISHING.lock().await;
        let instance = "door-task-ask";
        let _published = Published(instance);
        let (_release, gate) = tokio::sync::watch::channel(true);
        let (port, mut heard) = gated_server(gate).await;
        let section: serde_yaml::Value = serde_yaml::from_str(&format!(
            "fs:\n  url: \"http://127.0.0.1:{port}/rpc\"\n  pin: {{ mechanism: pinned_pubkey, key: \"sha256/K=\" }}\n  \
             tools_allow:\n    read_file:\n      schema_hash: \"{}\"\n      task_support: optional\n      \
             task_ask_caller:\n        - confirm: {{ method: elicitation/create, params: {{ message: \"Go?\" }} }}\n",
            tool_digest()
        ))
        .expect("a section");
        let rig = rig_tools(instance, port, section, &|app| app);
        let mut call: serde_json::Value = serde_json::from_str(&task_call()).expect("the call");
        call["params"]["_meta"]["io.modelcontextprotocol/clientCapabilities"]["elicitation"] =
            serde_json::json!({});
        let (status, body) = send_as(
            &rig.router,
            Some(&rig.token),
            &call.to_string(),
            "tools/call",
            Some("fs_read_file"),
        )
        .await;
        let body: serde_json::Value = serde_json::from_slice(&body).expect("JSON-RPC");
        assert_eq!(status.as_u16(), 200, "{body}");
        let task_id = body["result"]["taskId"]
            .as_str()
            .expect("a task")
            .to_string();
        let parked = until(&rig, &task_id, "input_required").await;
        assert_eq!(
            parked["result"]["inputRequests"]["confirm"]["method"], "elicitation/create",
            "{parked}"
        );
        // Parked: nothing went upstream but the verify fetch.
        while let Ok(request) = heard.try_recv() {
            assert!(!request.contains("\"tools/call\""), "{request}");
        }
        let mut update: serde_json::Value =
            serde_json::from_str(&verb("tasks/update", &task_id)).expect("a verb");
        update["params"]["inputResponses"] =
            serde_json::json!({ "confirm": { "action": "accept" } });
        let (status, ack) = send_as(
            &rig.router,
            Some(&rig.token),
            &update.to_string(),
            "tasks/update",
            Some(&task_id),
        )
        .await;
        let ack: serde_json::Value = serde_json::from_slice(&ack).expect("JSON-RPC");
        assert_eq!(status.as_u16(), 200, "{ack}");
        assert_eq!(
            ack["result"],
            serde_json::json!({ "resultType": "complete" }),
            "{ack}"
        );
        // The answer became an argument of the call that went out.
        let call = next_call(&mut heard).await;
        assert!(call.contains("\"confirm\""), "{call}");
        let done = until(&rig, &task_id, "completed").await;
        assert_eq!(
            done["result"]["result"]["content"][0]["text"], "from the server",
            "{done}"
        );
    }

    /// The member's ask inside a task, as it sends it.
    const UPSTREAM_ASK: &str = r#"{"jsonrpc":"2.0","id":0,"result":{"resultType":"input_required","inputRequests":{"ok":{"method":"elicitation/create","params":{"message":"Publish it?","requestedSchema":{"type":"object","properties":{}}}}},"requestState":"theirs"}}"#;

    /// A member that asks its caller on the first call and answers the retry carrying answers.
    async fn asking_member() -> (u16, tokio::sync::mpsc::UnboundedReceiver<String>) {
        super::tool_door::tool_server_answering(std::sync::Arc::new(|request: &str| {
            if request.contains("\"tools/list\"") {
                serde_json::json!({"jsonrpc": "2.0", "id": 1, "result": {"tools": tool_listing()}})
                    .to_string()
            } else if request.contains("\"inputResponses\"") {
                r#"{"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"text","text":"answered by the caller"}]}}"#
                    .to_string()
            } else {
                UPSTREAM_ASK.to_string()
            }
        }))
        .await
    }

    /// The task tool's section, the elicitation ask granted as a relay permission or not.
    fn asking_tools(port: u16, granted: bool) -> serde_yaml::Value {
        serde_yaml::from_str(&format!(
            "fs:\n  url: \"http://127.0.0.1:{port}/rpc\"\n  pin: {{ mechanism: pinned_pubkey, key: \"sha256/K=\" }}\n  \
             grants: {{ elicitation: {granted} }}\n  \
             tools_allow:\n    read_file: {{ schema_hash: \"{}\", task_support: optional }}\n",
            tool_digest()
        ))
        .expect("a section")
    }

    /// LAW 11 ON THE TASK PATH (ARCHITECT Q6). RED against the deleted refusal ("a task's
    /// continuation has no caller waiting to relay the upstream's ask to"), which failed the task:
    /// the member's ask parks the task `input_required` with its `inputRequests` verbatim; the
    /// caller's `tasks/update` answer goes back to the SAME member as a new unit, with the caller's
    /// answers and the member's own state verbatim; the task completes with the member's result.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_members_ask_inside_a_task_reaches_the_caller_and_its_answer_reaches_the_member() {
        let _one = PUBLISHING.lock().await;
        let instance = "door-task-relay";
        let _published = Published(instance);
        let (port, mut heard) = asking_member().await;
        let rig = rig_tools(instance, port, asking_tools(port, true), &|app| app);
        let (_, task_id) = create(&rig).await;
        let parked = until(&rig, &task_id, "input_required").await;
        let sent: serde_json::Value = serde_json::from_str(UPSTREAM_ASK).expect("the ask");
        assert_eq!(
            parked["result"]["inputRequests"], sent["result"]["inputRequests"],
            "the member's requests reach the caller verbatim: {parked}"
        );
        assert!(parked["result"].get("requestState").is_none(), "{parked}");
        let first = next_call(&mut heard).await;
        assert!(!first.contains("inputResponses"), "{first}");

        let mut update: serde_json::Value =
            serde_json::from_str(&verb("tasks/update", &task_id)).expect("a verb");
        update["params"]["inputResponses"] =
            serde_json::json!({ "ok": { "action": "accept", "content": {} } });
        let (status, ack) = send_as(
            &rig.router,
            Some(&rig.token),
            &update.to_string(),
            "tasks/update",
            Some(&task_id),
        )
        .await;
        assert_eq!(status.as_u16(), 200, "{}", String::from_utf8_lossy(&ack));

        // THE RETRY reaches the member: the caller's answers and the member's own state, verbatim.
        let retry = next_call(&mut heard).await;
        let body = retry
            .split_once("\r\n\r\n")
            .map_or(retry.as_str(), |(_, b)| b);
        let retry: serde_json::Value = serde_json::from_str(body).expect("JSON");
        assert_eq!(retry["params"]["requestState"], "theirs", "{retry}");
        assert_eq!(
            retry["params"]["inputResponses"]["ok"]["action"], "accept",
            "{retry}"
        );
        assert!(
            retry["params"]["arguments"].get("ok").is_none(),
            "the member's answers never become arguments: {retry}"
        );
        let done = until(&rig, &task_id, "completed").await;
        assert_eq!(
            done["result"]["result"]["content"][0]["text"], "answered by the caller",
            "{done}"
        );
    }

    /// An ungranted ask inside a task is still refused (`ask_ungranted`, the operator's policy): the
    /// task fails in the refusal's words and nothing is relayed to the caller.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn an_ungranted_ask_inside_a_task_is_refused() {
        let _one = PUBLISHING.lock().await;
        let instance = "door-task-relay-ungranted";
        let _published = Published(instance);
        let (port, _heard) = asking_member().await;
        let rig = rig_tools(instance, port, asking_tools(port, false), &|app| app);
        let (_, task_id) = create(&rig).await;
        let failed = until(&rig, &task_id, "failed").await;
        assert!(
            failed["result"]["error"]["message"]
                .as_str()
                .is_some_and(|m| m.contains("grants.elicitation")),
            "{failed}"
        );
        assert!(failed["result"].get("inputRequests").is_none(), "{failed}");
    }

    // ── THE TASK STORE IS HOST RECORDS (BUSBAR-1.6.0.md §2; §1 "Admission bounds
    // live work; nothing evicts it") ────────────────────────────────────────────────────────────

    /// One node of a deployment of `instance` on `port`, standing on the typed rows `rows` its
    /// other nodes and processes share, its host keeping `max_live` live work handles, reading
    /// `book`'s governance.
    fn node(
        instance: &'static str,
        port: u16,
        rows: &std::sync::Arc<Rows>,
        max_live: usize,
        book: Option<&Rig>,
    ) -> Rig {
        rig_on(
            instance,
            port,
            tools(port, "optional"),
            Footing {
                ledger: Ledger::Rows(std::sync::Arc::clone(rows), max_live),
                book,
                guarded: false,
            },
        )
    }

    /// Every unit `rig` admitted has ended.
    async fn ended(rig: &Rig) {
        let ended = async {
            while !rig.all_ended() {
                tokio::time::sleep(std::time::Duration::from_millis(20)).await;
            }
        };
        tokio::time::timeout(std::time::Duration::from_secs(10), ended)
            .await
            .expect("every unit ended");
    }

    /// A LIVE TASK IS ANSWERED FROM THE HOST'S ROWS: created through one node (its call held at
    /// the server, so the task stays live), `tasks/get` through another node of the deployment
    /// answers it exactly as the creating node does, and never as an unknown task.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_live_task_created_on_one_node_is_answered_by_another() {
        let _one = PUBLISHING.lock().await;
        let instance = "door-task-fleet";
        let _published = Published(instance);
        let (_release, gate) = tokio::sync::watch::channel(false);
        let (port, mut heard) = gated_server(gate).await;
        let rows = std::sync::Arc::new(Rows::default());
        let a = node(instance, port, &rows, 4096, None);
        let b = node(instance, port, &rows, 4096, Some(&a));
        let (_, task_id) = create(&a).await;
        let _call = next_call(&mut heard).await;
        let (status, here) = ask(&a, &a.token, "tasks/get", &task_id).await;
        assert_eq!(status, 200, "{here}");
        assert_eq!(here["result"]["status"], "working", "{here}");
        // The other node reads the host's rows once the first node's writes reach them.
        let mut there = serde_json::Value::Null;
        for _ in 0..250 {
            there = ask(&b, &b.token, "tasks/get", &task_id).await.1;
            if there == here {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
        assert_eq!(
            there, here,
            "the other node answers the live task from the host's rows"
        );
    }

    /// THE HANDLES A GONE PROCESS LEFT ARE SETTLED: a process opens live work up to its host's
    /// bound and ends with it live; past the lease of their runs, the next process's task-creating
    /// call settles them `cancelled` and is admitted, where it would be refused at the bound.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn the_live_handles_a_gone_process_left_are_settled_and_a_new_task_is_admitted() {
        let _one = PUBLISHING.lock().await;
        let instance = "door-task-restart";
        let _published = Published(instance);
        let (_release, gate) = tokio::sync::watch::channel(false);
        let (port, _heard) = gated_server(gate).await;
        let rows = std::sync::Arc::new(Rows::default());
        let gone = node(instance, port, &rows, 2, None);
        let (_, first) = create(&gone).await;
        let (_, second) = create(&gone).await;
        let (status, refused) = send_as(
            &gone.router,
            Some(&gone.token),
            &task_call(),
            "tools/call",
            Some("fs_read_file"),
        )
        .await;
        assert_eq!(
            status.as_u16(),
            503,
            "at the bound of live work: {}",
            String::from_utf8_lossy(&refused)
        );
        // Its writes reach the shared rows; then its process ends, and the clock moves on.
        tokio::time::sleep(std::time::Duration::from_millis(300)).await;
        let next = node(instance, port, &rows, 2, Some(&gone));
        drop(gone);
        next.wall
            .fetch_add(3_600_000, std::sync::atomic::Ordering::SeqCst);
        let (status, body) = send_as(
            &next.router,
            Some(&next.token),
            &task_call(),
            "tools/call",
            Some("fs_read_file"),
        )
        .await;
        assert_eq!(
            status.as_u16(),
            200,
            "admitted: {}",
            String::from_utf8_lossy(&body)
        );
        for id in [&first, &second] {
            let (_, got) = ask(&next, &next.token, "tasks/get", id).await;
            assert_eq!(got["result"]["status"], "cancelled", "{got}");
        }
    }

    /// A SETTLE THE STORE REFUSES IS MADE AGAIN UNTIL IT LANDS: the store refuses the first two
    /// writes of a settled handle (the continuation's own settle, and the next create's); the
    /// handle is settled by a following create rather than left live for ever.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_settle_the_store_refuses_is_made_again_until_it_lands() {
        let _one = PUBLISHING.lock().await;
        let instance = "door-task-settle-retry";
        let _published = Published(instance);
        let (_release, gate) = tokio::sync::watch::channel(true);
        let (port, _heard) = gated_server(gate).await;
        let rows = std::sync::Arc::new(Rows::default());
        rows.1.store(2, std::sync::atomic::Ordering::SeqCst);
        let rig = node(instance, port, &rows, 4096, None);
        let (_, task_id) = create(&rig).await;
        ended(&rig).await;
        let reference =
            busbar_kernel::host_work::parse_reference(task_id.as_bytes()).expect("a reference");
        let key = (
            busbar_kernel::host_work::WORK_SCHEMA,
            busbar_kernel::host_work::work_key(instance, &reference),
        );
        let state = || {
            rows.0
                .lock()
                .expect("unpoisoned")
                .get(&key)
                .and_then(|row| row.as_slice().get(1).copied())
        };
        assert_eq!(
            state(),
            Some(busbar_contract::abi::host::service::WORK_LIVE),
            "the store refused the continuation's settle"
        );
        for _ in 0..2 {
            create(&rig).await;
            ended(&rig).await;
        }
        let mut settled = false;
        for _ in 0..250 {
            if state() == Some(busbar_contract::abi::host::service::WORK_SETTLED) {
                settled = true;
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
        assert!(settled, "the owed settle landed");
    }
}

/// THE HOOK PARITY BATTERY ON THE DRIVER (BUSBAR-1.6.0.md Part 3 section 12 "Hooks": the hook stages
/// run in the order the previous release used for that plane; the plane's tail states the gate-first
/// order, SEAM-4c). The served engine's mcp hook battery (busbar-mcp `hook_gate_tests`,
/// `hook_tap_tests`), each scenario driven through the door's composition: the same hook documents
/// (`kind: gate` on the hermetic test cdylib), the same attaches (`tools.hooks`, the section-level
/// list every server takes), the same verdicts, read off the far end the door dials.
#[cfg(all(linked_axis_plane_door, linked_section_pools))]
pub(crate) mod hook_parity {
    use super::tool_door::{send_as, surface, tool_server, Footing, Rig};
    use crate::root::serve::planes_tests::{Published, PUBLISHING};

    /// A `kind: gate` on the hermetic test cdylib, `prompt` the grant it holds (the served
    /// battery's `gate()` / `rewrite()` documents, as an operator writes them).
    pub(crate) fn gate(
        prompt: &str,
        settings: serde_json::Value,
    ) -> busbar_kernel::config::HookCfg {
        serde_json::from_value(serde_json::json!({
            "kind": "gate",
            "module": "test-hook",
            "timeout_ms": 10_000,
            "on_error": "weighted",
            "prompt": prompt,
            "user": "ro",
            "priority": 0,
            "settings": settings,
            "global": false,
            "default": false,
            "signals": [],
            "groups": [],
            "phase": [],
        }))
        .expect("a hook document")
    }

    /// The env whose `test-hook` is the kernel's in-process hook double (`prompt: rw`, `user: ro`;
    /// no test plugin, OWNER 2026-10-03): its `settings:` choose its answer.
    pub(crate) fn hook_env() -> busbar_kernel::hooks::HookEnv {
        busbar_kernel::test_support::test_hook_env(
            &["test-hook"],
            busbar_kernel::test_support::HookNeeds {
                prompt: busbar_contract::plugin_rows::NeedLevel::Rw,
                user: busbar_contract::plugin_rows::NeedLevel::Ro,
            },
        )
    }

    /// The door composed as `instance` against the server on `port`, `hooks` (name, document) all
    /// attached section-level (`tools.hooks`).
    pub(crate) fn rig(
        instance: &'static str,
        port: u16,
        hooks: Vec<(&'static str, busbar_kernel::config::HookCfg)>,
    ) -> Rig {
        let env = hook_env();
        // The door's folded row in the process's plane registry, as the composition root installs
        // it: the deployment's per-entry hooks are resolved under the plane it names.
        super::door_boundary::registry(super::door_boundary::row());
        Rig::with(
            instance,
            port,
            None,
            None,
            None,
            Footing::own(),
            &move |mut app| {
                if hooks.is_empty() {
                    return app;
                }
                // The section-level list is combined onto every registered server's own (the rig's
                // one server, `fs`, attaches none of its own).
                app.set_container_hooks(
                    surface("plane_key"),
                    vec![("fs".to_string(), Vec::new())],
                    hooks.iter().map(|(n, _)| (*n).to_string()).collect(),
                );
                let mut app = app.hook_env(env.clone());
                for (name, cfg) in &hooks {
                    app = app.hook(name, cfg.clone());
                }
                app
            },
        )
    }

    /// A `tools/call` of the one approved tool with `arguments`.
    pub(crate) fn call(arguments: serde_json::Value) -> String {
        serde_json::json!({
            "jsonrpc": "2.0", "id": 30, "method": "tools/call",
            "params": {
                "name": "fs_read_file", "arguments": arguments,
                "_meta": {
                    "io.modelcontextprotocol/protocolVersion": surface("protocol_version"),
                    "io.modelcontextprotocol/clientCapabilities": {},
                },
            },
        })
        .to_string()
    }

    /// The `tools/call` requests the server heard, as their raw bytes.
    pub(crate) fn calls_heard(
        heard: &mut tokio::sync::mpsc::UnboundedReceiver<String>,
    ) -> Vec<String> {
        std::iter::from_fn(|| heard.try_recv().ok())
            .filter(|r| r.contains("\"tools/call\""))
            .collect()
    }

    /// `tools.hooks: [reject-all]` refuses a tools/call with the hook's own status and words, the
    /// server never reached; the identical deployment with no hook serves it (the control).
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn tools_hooks_reject_all_rejects_a_tools_call() {
        let _one = PUBLISHING.lock().await;
        let instance = "door-hook-reject-all";
        let _published = Published(instance);
        let body = call(serde_json::json!({ "path": "/etc/hosts" }));

        let (port, mut heard) = tool_server().await;
        let control = rig(instance, port, Vec::new());
        let (status, answer) = send_as(
            &control.router,
            Some(&control.token),
            &body,
            "tools/call",
            Some("fs_read_file"),
        )
        .await;
        assert_eq!(status.as_u16(), 200, "{}", String::from_utf8_lossy(&answer));
        assert_eq!(
            calls_heard(&mut heard).len(),
            1,
            "the control reached the server"
        );
        drop(control);

        let gated = rig(
            instance,
            port,
            vec![(
                "reject-all",
                gate(
                    "ro",
                    serde_json::json!({
                        "raw_decide_reply": {"reject": {"status": 403, "message": "no tool calls today"}}
                    }),
                ),
            )],
        );
        let (status, answer) = send_as(
            &gated.router,
            Some(&gated.token),
            &body,
            "tools/call",
            Some("fs_read_file"),
        )
        .await;
        assert_eq!(status.as_u16(), 403, "{}", String::from_utf8_lossy(&answer));
        let answer: serde_json::Value = serde_json::from_slice(&answer).expect("JSON-RPC");
        assert_eq!(
            answer["error"]["message"], "no tool calls today",
            "{answer}"
        );
        assert!(
            calls_heard(&mut heard).is_empty(),
            "a gate that rejects after the call went out stopped nothing"
        );
    }

    /// What the gate sees is the call's ARGUMENTS: a screen keyed on a token found only inside
    /// them rejects, and a clean call is served.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn the_calls_content_reaches_the_gate() {
        let _one = PUBLISHING.lock().await;
        let instance = "door-hook-content";
        let _published = Published(instance);
        let (port, mut heard) = tool_server().await;
        let rig = rig(
            instance,
            port,
            vec![(
                "screen",
                gate(
                    "ro",
                    serde_json::json!({ "reject_if_contains": "/etc/shadow" }),
                ),
            )],
        );
        let (status, answer) = send_as(
            &rig.router,
            Some(&rig.token),
            &call(serde_json::json!({ "path": "/etc/hosts" })),
            "tools/call",
            Some("fs_read_file"),
        )
        .await;
        assert_eq!(status.as_u16(), 200, "{}", String::from_utf8_lossy(&answer));
        let (status, answer) = send_as(
            &rig.router,
            Some(&rig.token),
            &call(serde_json::json!({ "path": "/etc/shadow" })),
            "tools/call",
            Some("fs_read_file"),
        )
        .await;
        assert_eq!(
            status.as_u16(),
            403,
            "the gate's verdict was driven by the arguments: {}",
            String::from_utf8_lossy(&answer)
        );
        assert_eq!(
            calls_heard(&mut heard).len(),
            1,
            "only the clean call went out"
        );
    }

    /// A `prompt: rw` rewrite replaces the call's arguments before the server sees them: the
    /// caller's original value appears nowhere on the wire.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_rewrite_hook_edits_the_tool_call_arguments_before_they_go_upstream() {
        let _one = PUBLISHING.lock().await;
        let instance = "door-hook-rewrite";
        let _published = Published(instance);
        let (port, mut heard) = tool_server().await;
        let rig = rig(
            instance,
            port,
            vec![(
                "rewrite",
                gate(
                    "rw",
                    serde_json::json!({ "raw_transform_reply": {
                        "rewrite": { "messages": [
                            { "role": "user", "content": { "path": "/srv/rewritten-by-hook" } }
                        ] }
                    } }),
                ),
            )],
        );
        let (status, answer) = send_as(
            &rig.router,
            Some(&rig.token),
            &call(serde_json::json!({ "path": "/etc/hosts" })),
            "tools/call",
            Some("fs_read_file"),
        )
        .await;
        assert_eq!(status.as_u16(), 200, "{}", String::from_utf8_lossy(&answer));
        let wire = calls_heard(&mut heard);
        assert_eq!(wire.len(), 1, "one call went out");
        assert!(
            wire[0].contains("/srv/rewritten-by-hook") && !wire[0].contains("/etc/hosts"),
            "the server received the arguments the hook rewrote them to: {}",
            wire[0]
        );
    }

    /// A `prompt: rw` gate that screens may also reject (reject > rewrite), on the arguments, at
    /// its own status, before the server is reached.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_rewrite_gate_can_reject_on_the_arguments_it_screens() {
        let _one = PUBLISHING.lock().await;
        let instance = "door-hook-rw-screen";
        let _published = Published(instance);
        let (port, mut heard) = tool_server().await;
        let rig = rig(
            instance,
            port,
            vec![(
                "screen",
                gate(
                    "rw",
                    serde_json::json!({ "reject_if_contains": "/etc/shadow", "reject_status": 451 }),
                ),
            )],
        );
        let (status, _) = send_as(
            &rig.router,
            Some(&rig.token),
            &call(serde_json::json!({ "path": "/etc/hosts" })),
            "tools/call",
            Some("fs_read_file"),
        )
        .await;
        assert_eq!(status.as_u16(), 200, "clean arguments are served");
        let (status, answer) = send_as(
            &rig.router,
            Some(&rig.token),
            &call(serde_json::json!({ "path": "/etc/shadow" })),
            "tools/call",
            Some("fs_read_file"),
        )
        .await;
        assert_eq!(status.as_u16(), 451, "{}", String::from_utf8_lossy(&answer));
        assert_eq!(
            calls_heard(&mut heard).len(),
            1,
            "the rejected call never went out"
        );
    }

    /// A rewrite hook that panics is the seam's own failed verdict: `on_error: weighted` serves the
    /// call with the caller's original arguments; `on_error: reject` refuses it at the seam's
    /// required-hook status, nothing dispatched.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_hook_that_panics_is_the_seams_own_failed_verdict() {
        let _one = PUBLISHING.lock().await;
        let instance = "door-hook-panic";
        let _published = Published(instance);
        let body = call(serde_json::json!({ "path": "/etc/hosts" }));
        let (port, mut heard) = tool_server().await;
        let weighted = rig(
            instance,
            port,
            vec![(
                "panicky",
                gate("rw", serde_json::json!({ "panic_transform": true })),
            )],
        );
        let (status, answer) = send_as(
            &weighted.router,
            Some(&weighted.token),
            &body,
            "tools/call",
            Some("fs_read_file"),
        )
        .await;
        assert_eq!(status.as_u16(), 200, "{}", String::from_utf8_lossy(&answer));
        let wire = calls_heard(&mut heard);
        assert!(
            wire.len() == 1 && wire[0].contains("/etc/hosts"),
            "served with the caller's original arguments: {wire:?}"
        );
        drop(weighted);

        let mut required = gate("rw", serde_json::json!({ "panic_transform": true }));
        required.on_error =
            serde_json::from_value(serde_json::json!("reject")).expect("an on_error disposition");
        let required = rig(instance, port, vec![("panicky-required", required)]);
        let (status, body) = send_as(
            &required.router,
            Some(&required.token),
            &body,
            "tools/call",
            Some("fs_read_file"),
        )
        .await;
        assert_eq!(
            status.as_u16(),
            busbar_kernel::hooks::REQUIRED_HOOK_UNAVAILABLE_STATUS,
            "a load-bearing hook that panicked refuses the call: {}",
            String::from_utf8_lossy(&body)
        );
        assert!(calls_heard(&mut heard).is_empty(), "nothing was dispatched");
    }
}

/// A REGISTRATION THAT IS A PROGRAM (ARCHITECT round 5 Q-L3B-STDIO-UPSTREAM (A)), end to end through
/// the composed door and the real connector: the server is a program the operator names (`/bin/sh`
/// and its script, inline here), one long-lived child per registration, greeted once, its every
/// exchange — verify-on-call's tool list, the relayed call over the kernel's walk, the reply to its
/// own request — on that one child, correlated by id.
#[cfg(all(linked_axis_plane_door, linked_section_pools))]
pub(crate) mod program_member {
    use axum::http::StatusCode;

    use super::tool_door::{rig_tools, send, tool_digest, tool_listing, CALL};
    use crate::root::serve::planes_tests::{Published, PUBLISHING};

    /// The server, as a shell script: it answers the handshake, its tool list (after a log line of
    /// its own) and each call (after a request of its own, `ping`, which it counts the answers to),
    /// each call answered with its process id and what it has seen so far.
    pub(crate) fn script() -> String {
        let listing = tool_listing().to_string().replace('\'', "'\\''");
        format!(
            "inits=0; lists=0; calls=0; pongs=0\n\
             L='{listing}'\n\
             while IFS= read -r l; do\n\
               id=$(printf '%s' \"$l\" | sed -n 's/.*\"id\":\\([0-9]\\{{10,\\}}\\).*/\\1/p')\n\
               case \"$l\" in\n\
                 *'\"method\":\"initialize\"'*) inits=$((inits+1)); \
                   printf '{{\"jsonrpc\":\"2.0\",\"id\":%s,\"result\":{{\"protocolVersion\":\"2025-06-18\",\"capabilities\":{{\"tools\":{{}}}},\"serverInfo\":{{\"name\":\"s\",\"version\":\"1\"}}}}}}\\n' \"$id\" ;;\n\
                 *'\"method\":\"tools/list\"'*) lists=$((lists+1)); \
                   printf '{{\"jsonrpc\":\"2.0\",\"method\":\"notifications/message\",\"params\":{{\"level\":\"info\",\"data\":\"listing\"}}}}\\n'; \
                   printf '{{\"jsonrpc\":\"2.0\",\"id\":%s,\"result\":{{\"tools\":%s}}}}\\n' \"$id\" \"$L\" ;;\n\
                 *'\"method\":\"tools/call\"'*) calls=$((calls+1)); \
                   printf '{{\"jsonrpc\":\"2.0\",\"id\":\"srv-%s\",\"method\":\"ping\"}}\\n' \"$calls\"; \
                   printf '{{\"jsonrpc\":\"2.0\",\"id\":%s,\"result\":{{\"content\":[{{\"type\":\"text\",\"text\":\"from the server pid=%s inits=%s lists=%s calls=%s pongs=%s\"}}]}}}}\\n' \"$id\" \"$$\" \"$inits\" \"$lists\" \"$calls\" \"$pongs\" ;;\n\
                 *'\"result\":{{}}'*) pongs=$((pongs+1)) ;;\n\
               esac\n\
             done\n"
        )
    }

    /// The section: one registration that is the program above, its one tool approved.
    fn section() -> serde_yaml::Value {
        section_running(script())
    }

    /// The section: one registration whose program is `/bin/sh -c <script>`, its one tool approved.
    pub(crate) fn section_running(script: String) -> serde_yaml::Value {
        let mut fs = serde_yaml::Mapping::new();
        fs.insert("transport".into(), "stdio".into());
        fs.insert("command".into(), "/bin/sh".into());
        fs.insert(
            "args".into(),
            serde_yaml::Value::Sequence(vec!["-c".into(), script.into()]),
        );
        fs.insert(
            "pin".into(),
            serde_yaml::from_str("{ mechanism: pinned_pubkey, key: \"sha256/K=\" }").unwrap(),
        );
        fs.insert(
            "tools_allow".into(),
            serde_yaml::from_str(&format!(
                "{{ read_file: {{ schema_hash: \"{}\" }} }}",
                tool_digest()
            ))
            .unwrap(),
        );
        let mut tools = serde_yaml::Mapping::new();
        tools.insert("fs".into(), serde_yaml::Value::Mapping(fs));
        serde_yaml::Value::Mapping(tools)
    }

    /// The text of the tool result a call was answered with.
    fn text(body: &[u8]) -> String {
        let body: serde_json::Value = serde_json::from_slice(body).expect("a JSON-RPC answer");
        assert_eq!(body["id"], 30, "answered under the caller's own id: {body}");
        body["result"]["content"][0]["text"]
            .as_str()
            .unwrap_or_else(|| panic!("a tool result: {body}"))
            .to_string()
    }

    /// The `key=value` the server reported.
    fn fact<'t>(text: &'t str, key: &str) -> &'t str {
        text.split(' ')
            .find_map(|w| w.strip_prefix(key)?.strip_prefix('='))
            .unwrap_or_else(|| panic!("{key} in {text:?}"))
    }

    /// RED: the relayed `tools/call` is served by the registration's program, its answer relayed to
    /// the caller; the child was greeted once and asked its tool list (verify-on-call) on the same
    /// process; its own `ping` was answered on its input; and a second call reuses the same child
    /// (one process, one greeting).
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_program_registration_serves_the_call_and_a_second_call_reuses_its_child() {
        let _one = PUBLISHING.lock().await;
        let instance = "door-program-member";
        let _published = Published(instance);
        let rig = rig_tools(instance, 0, section(), &|app| app);

        let (status, body) = send(&rig.router, Some(&rig.token), CALL).await;
        assert_eq!(status, StatusCode::OK, "{}", String::from_utf8_lossy(&body));
        let first = text(&body);
        assert!(first.starts_with("from the server "), "{first}");
        assert_eq!(
            fact(&first, "inits"),
            "1",
            "greeted before the call: {first}"
        );
        assert_eq!(
            fact(&first, "lists"),
            "1",
            "verify-on-call on the child: {first}"
        );
        assert_eq!(fact(&first, "calls"), "1");

        let (status, body) = send(&rig.router, Some(&rig.token), CALL).await;
        assert_eq!(status, StatusCode::OK, "{}", String::from_utf8_lossy(&body));
        let second = text(&body);
        assert_eq!(
            fact(&second, "pid"),
            fact(&first, "pid"),
            "the second call reached the same child"
        );
        assert_eq!(fact(&second, "inits"), "1", "greeted once: {second}");
        assert_eq!(fact(&second, "calls"), "2");
        assert_eq!(
            fact(&second, "pongs"),
            "1",
            "the child's own request was answered once: {second}"
        );
    }
}

/// THE PROGRAM'S SUPERVISOR, END TO END (THE DESIGN §2, l.388: the program's supervisor is its
/// carrier transport's; 1.5.5's crash-loop policy): a registration whose program ends at once,
/// called over and over through the composed door and the real connector for longer than the whole
/// backoff (100 + 200 + 400 + 800 ms), is spawned exactly five times: the fifth end inside a minute
/// stops its restarts and every later call is refused without a spawn. The policy lives in the
/// program's carrier, keyed by the member's supervision key the connector hands each spawn. RED
/// with the connector's own supervisor deleted and the carrier's absent: every call spawns the
/// program anew.
#[cfg(all(linked_axis_plane_door, linked_section_pools))]
mod program_member_supervised {
    use super::program_member::section_running;
    use super::tool_door::{rig_tools, send, CALL};
    use crate::root::serve::planes_tests::{Published, PUBLISHING};

    /// The section: one registration whose program appends a line to `spawns` and ends.
    fn section(spawns: &std::path::Path) -> serde_yaml::Value {
        section_running(format!("echo spawned >> '{}'; exit 1", spawns.display()))
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_program_that_keeps_ending_is_spawned_five_times_then_refused() {
        let _one = PUBLISHING.lock().await;
        let instance = "door-program-supervised";
        let _published = Published(instance);
        let spawns =
            std::env::temp_dir().join(format!("busbar-{instance}-{}-spawns", std::process::id()));
        let _ = std::fs::remove_file(&spawns);
        let rig = rig_tools(instance, 0, section(&spawns), &|app| app);

        // Called every 150 ms for 3.6 s: well past the four backoffs (1.5 s), well inside a minute.
        for _ in 0..24 {
            let _ = send(&rig.router, Some(&rig.token), CALL).await;
            tokio::time::sleep(std::time::Duration::from_millis(150)).await;
        }
        let spawned = std::fs::read_to_string(&spawns)
            .unwrap_or_default()
            .lines()
            .count();
        let _ = std::fs::remove_file(&spawns);
        assert_eq!(
            spawned, 5,
            "five ends inside a minute stop the restarts: spawned {spawned} times"
        );
    }
}

/// LAW 11 FOR A STDIO CHILD (ARCHITECT Q6), end to end through the composed door and the real
/// connector. RED against the deleted reply ("no satisfier for that ask on the stdio leg ... not
/// proxied to busbar's caller"), which answered a granted ask on the caller's behalf: the child's
/// `sampling/createMessage`, read while its call is in flight, reaches the caller verbatim under
/// busbar's sealed state (correlated with `work.*`); the caller's retry writes its answer to the
/// child under the child's own id and the call the child still owed is answered; a partial answer,
/// a spent state and a forged one are refused; an ungranted ask is refused on the child's input.
#[cfg(all(linked_axis_plane_door, linked_section_pools))]
mod program_member_ask {
    use axum::http::StatusCode;

    use super::tool_door::{rig_tools, send, tool_digest, tool_listing, CALL};
    use crate::root::serve::planes_tests::{Published, PUBLISHING};

    /// The server, as a shell script: each call is held while it asks busbar's caller for a
    /// completion (`srv-ask-<n>`), and answered with what came back on its input (the text of the
    /// answer, or the reason it was refused).
    fn script() -> String {
        let listing = tool_listing().to_string().replace('\'', "'\\''");
        r#"calls=0; pending=""
L='__LISTING__'
while IFS= read -r l; do
  id=$(printf '%s' "$l" | sed -n 's/.*"id":\([0-9]\{10,\}\).*/\1/p')
  case "$l" in
    *'"method":"initialize"'*) printf '{"jsonrpc":"2.0","id":%s,"result":{"protocolVersion":"2025-06-18","capabilities":{"tools":{}},"serverInfo":{"name":"s","version":"1"}}}\n' "$id" ;;
    *'"method":"tools/list"'*) printf '{"jsonrpc":"2.0","id":%s,"result":{"tools":%s}}\n' "$id" "$L" ;;
    *'"method":"tools/call"'*) calls=$((calls+1)); pending=$id; printf '{"jsonrpc":"2.0","id":"srv-ask-%s","method":"sampling/createMessage","params":{"messages":[{"role":"user","content":{"type":"text","text":"Draft it."}}],"maxTokens":64}}\n' "$calls" ;;
    *'"srv-ask-'*) got=$(printf '%s' "$l" | sed -n 's/.*"text":"\([^"]*\)".*/\1/p'); [ -n "$got" ] || got=$(printf '%s' "$l" | sed -n 's/.*"reason":"\([^"]*\)".*/\1/p'); printf '{"jsonrpc":"2.0","id":%s,"result":{"content":[{"type":"text","text":"answered with %s"}]}}\n' "$pending" "$got" ;;
  esac
done
"#
        .replace("__LISTING__", &listing)
    }

    /// The section: one registration that is the program above, its one tool approved, the sampling
    /// ask granted as a relay permission or not.
    fn section(granted: bool) -> serde_yaml::Value {
        let mut fs = serde_yaml::Mapping::new();
        fs.insert("transport".into(), "stdio".into());
        fs.insert("command".into(), "/bin/sh".into());
        fs.insert(
            "args".into(),
            serde_yaml::Value::Sequence(vec!["-c".into(), script().into()]),
        );
        fs.insert(
            "pin".into(),
            serde_yaml::from_str("{ mechanism: pinned_pubkey, key: \"sha256/K=\" }").unwrap(),
        );
        fs.insert(
            "grants".into(),
            serde_yaml::from_str(&format!("{{ sampling: {granted} }}")).unwrap(),
        );
        fs.insert(
            "tools_allow".into(),
            serde_yaml::from_str(&format!(
                "{{ read_file: {{ schema_hash: \"{}\" }} }}",
                tool_digest()
            ))
            .unwrap(),
        );
        let mut tools = serde_yaml::Mapping::new();
        tools.insert("fs".into(), serde_yaml::Value::Mapping(fs));
        serde_yaml::Value::Mapping(tools)
    }

    /// One call of `body` through `rig`'s door: the status and the JSON-RPC body.
    async fn call(
        router: &axum::Router,
        token: &str,
        body: &str,
    ) -> (StatusCode, serde_json::Value) {
        let (status, body) = send(router, Some(token), body).await;
        (
            status,
            serde_json::from_slice(&body).expect("a JSON-RPC answer"),
        )
    }

    /// The call's retry: `answers` and the state it was handed.
    fn retry(answers: serde_json::Value, state: &str) -> String {
        let mut body: serde_json::Value = serde_json::from_str(CALL).expect("the call");
        body["params"]["inputResponses"] = answers;
        body["params"]["requestState"] = state.into();
        body.to_string()
    }

    /// The caller's completion.
    fn draft() -> serde_json::Value {
        serde_json::json!({ "role": "assistant", "content": { "type": "text", "text": "the callers own draft" }, "model": "m" })
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_childs_ask_reaches_the_caller_verbatim_and_its_answer_reaches_the_child() {
        let _one = PUBLISHING.lock().await;
        let instance = "door-program-ask";
        let _published = Published(instance);
        let rig = rig_tools(instance, 0, section(true), &|app| app);

        // THE ASK reaches the caller verbatim, under busbar's sealed state.
        let (status, body) = call(&rig.router, &rig.token, CALL).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["id"], 30, "{body}");
        assert_eq!(body["result"]["resultType"], "input_required", "{body}");
        assert_eq!(
            body["result"]["inputRequests"]["srv-ask-1"],
            serde_json::json!({"method": "sampling/createMessage", "params": {"messages": [{"role": "user", "content": {"type": "text", "text": "Draft it."}}], "maxTokens": 64}}),
            "the child's request, verbatim: {body}"
        );
        let state = body["result"]["requestState"]
            .as_str()
            .expect("busbar's sealed state")
            .to_string();

        // THE ANSWER reaches the child under its own id, and the call it owed is answered.
        let answered = retry(serde_json::json!({ "srv-ask-1": draft() }), &state);
        let (status, body) = call(&rig.router, &rig.token, &answered).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(
            body["result"]["content"][0]["text"], "answered with the callers own draft",
            "{body}"
        );

        // RED: a spent state, and a forged one, are refused.
        let (status, body) = call(&rig.router, &rig.token, &answered).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "a spent state: {body}");
        let (status, body) = call(
            &rig.router,
            &rig.token,
            &retry(serde_json::json!({ "srv-ask-1": draft() }), "forged"),
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN, "a forged state: {body}");
        assert_eq!(
            body["error"]["data"]["reason"], "ask_unsolicited_state",
            "{body}"
        );

        // RED: busbar answers none of the child's requests itself, so a retry that leaves one
        // unanswered is refused, unspent; the whole answer then goes through.
        let (status, body) = call(&rig.router, &rig.token, CALL).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        let state = body["result"]["requestState"]
            .as_str()
            .expect("busbar's sealed state")
            .to_string();
        assert!(
            body["result"]["inputRequests"].get("srv-ask-2").is_some(),
            "{body}"
        );
        let (status, body) = call(
            &rig.router,
            &rig.token,
            &retry(serde_json::json!({}), &state),
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
        assert_eq!(body["error"]["data"]["reason"], "ask_unanswered", "{body}");
        let (status, body) = call(
            &rig.router,
            &rig.token,
            &retry(serde_json::json!({ "srv-ask-2": draft() }), &state),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(
            body["result"]["content"][0]["text"], "answered with the callers own draft",
            "{body}"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn an_ungranted_childs_ask_is_refused_on_its_input_and_never_relayed() {
        let _one = PUBLISHING.lock().await;
        let instance = "door-program-ask-ungranted";
        let _published = Published(instance);
        let rig = rig_tools(instance, 0, section(false), &|app| app);
        let (status, body) = call(&rig.router, &rig.token, CALL).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert!(body["result"].get("inputRequests").is_none(), "{body}");
        assert_eq!(
            body["result"]["content"][0]["text"], "answered with ask_ungranted",
            "the child was refused on its input, by the operator's grant: {body}"
        );
    }
}

/// THE TRANSLATE CAP RIDES THE SETTINGS (row 155): the `limits` section a door plane is opened and
/// refreshed with carries the operator's `request_body_max_bytes`, the kernel's resolved value (its
/// 32 MiB default when the deployment names none), so the plane enforces the kernel's cap from its
/// own settings.
#[test]
fn the_limits_a_door_plane_is_handed_carry_the_operators_translate_cap() {
    let handed = |yaml: &str| {
        let deploy = busbar_kernel::config::deploy_from_yaml_str(yaml).expect("a deployment");
        let cfg = busbar_kernel::config::resolve(&deploy, &Default::default()).expect("resolves");
        super::kernel_sections(&cfg)["limits"]["request_body_max_bytes"].as_u64()
    };
    assert_eq!(
        handed("providers: {}\nmodels: {}\nlimits:\n  request_body_max_bytes: 131072\n"),
        Some(131_072)
    );
    assert_eq!(
        handed("providers: {}\nmodels: {}\n"),
        Some(busbar_contract::codec::TRANSLATE_BODY_MAX_BYTES_DEFAULT as u64)
    );
}

// ── `upstream_credential:` — busbar's own credential for a registration, refreshed once per lease ─

/// No provider: a registration is reached at its own target.
static NO_PROVIDERS: std::collections::BTreeMap<String, super::ProviderRoute> =
    std::collections::BTreeMap::new();

/// The door's reach over the build's linked auth plugins (`busbar-auth-header` serves `bearer`
/// and `api-key`) and the built-in secret modules.
fn own_reach() -> super::DoorReach<'static> {
    let dispatcher = std::sync::Arc::new(crate::root::loader::dispatch::Dispatcher::new(
        crate::root::loader::dispatch::DispatchConfig::default(),
    ));
    super::DoorReach {
        providers: &NO_PROVIDERS,
        secrets: std::sync::Arc::new(
            busbar_kernel::config::secret::SecretResolver::builtins_only(),
        ),
        auths: std::sync::Arc::new(super::OutboundAuths::new(
            dispatcher,
            crate::LINKED.auths,
            None,
            crate::root::loader::dispatch::ConnTable::NoNeeds,
        )),
        conns: std::sync::Arc::new(busbar_core_connector::Connector::new()),
        stream_ceiling_secs: 1,
        catalog: None,
        upgrades: Vec::new(),
        models: None,
    }
}

/// A secret file of this test's own (a file, not an env var: `set_var` is process-global and the
/// cells run in parallel), holding `value`.
fn own_secret(name: &str, value: &str) -> std::path::PathBuf {
    let path = std::env::temp_dir().join(format!(
        "busbar-door-steps-cred-{name}-{}",
        std::process::id()
    ));
    std::fs::write(&path, value).expect("write the test secret");
    path
}

/// ROTATE the secret at `path` to `value` the way an operator's secret store does: written aside,
/// then renamed over it, so a reader sees the old value or the new one, whole.
fn rotate(path: &std::path::Path, value: &str) {
    let aside = path.with_extension("rotating");
    std::fs::write(&aside, value).expect("write the rotated secret");
    std::fs::rename(&aside, path).expect("swap it in");
}

/// The registration `planner` stating `upstream_credential: {secret: {file: <path>}<placement>,
/// lease_ttl_ms: 60000}` (`placement` the YAML after the secret, or empty for none).
fn registration(path: &std::path::Path, placement: &str) -> serde_yaml::Value {
    serde_yaml::from_str(&format!(
        "url: 'https://agent.vendor/planner'\nupstream_credential: {{secret: {{file: '{}'}}{placement}, \
         lease_ttl_ms: 60000}}",
        path.display()
    ))
    .expect("yaml")
}

/// What a binding's handle `handle` presents on one request: each field, its name lower-cased.
fn presents(
    auth: &dyn busbar_contract::auth_calls::OutboundAuth,
    handle: u64,
) -> Vec<(String, String)> {
    match auth.fields_now(
        handle,
        &busbar_contract::auth_calls::FieldsRequest::default(),
    ) {
        Some(busbar_contract::auth_calls::Fields::Ready(fields)) => fields
            .iter()
            .map(|f| {
                (
                    String::from_utf8_lossy(&f.name).to_ascii_lowercase(),
                    String::from_utf8_lossy(f.value.expose(&busbar_kernel::seal::lend()))
                        .into_owned(),
                )
            })
            .collect(),
        other => panic!("a header binding answers on the spot: {other:?}"),
    }
}

/// Why the load was refused (a binding is not `Debug`: it holds an auth instance).
fn refused(bound: Result<Option<busbar_kernel::plane_driver::AuthBinding>, String>) -> String {
    match bound {
        Err(why) => why,
        Ok(_) => panic!("the load was not refused"),
    }
}

/// Ported from the deleted engine crate's `creds_tests::a_minted_lease_carries_the_secret_only_through_the_header_it_was_placed_at`:
/// `placement: bearer` (and no placement at all) binds the `bearer` style, so the secret is
/// presented only as `authorization: Bearer <secret>`, the trailing newline a file secret picks up
/// trimmed by the resolver (a header value with an embedded newline is a header-splitting bug).
/// RED: a registration stating no `upstream_credential` binds nothing, so nothing is presented.
#[test]
fn a_bearer_placement_presents_the_secret_only_as_the_bearer() {
    let path = own_secret("bearer", "s3cr3t-vendor-token\n");
    let reach = own_reach();
    for placement in [", placement: bearer", ""] {
        let binding = super::upstream_credential_binding(
            "planner",
            &registration(&path, placement),
            &reach,
            &busbar_contract::config_time::ConfigScope::config_time(),
        )
        .expect("it binds")
        .expect("an upstream credential is a binding");
        assert!(
            !binding.passthrough,
            "busbar's own credential, never the caller's"
        );
        let handle = binding
            .per_request
            .as_ref()
            .expect("a refreshed binding")
            .handle_now()
            .expect("it resolves");
        assert_eq!(
            presents(&*binding.auth, handle),
            vec![(
                "authorization".to_string(),
                "Bearer s3cr3t-vendor-token".to_string()
            )],
            "placement `{placement}`"
        );
    }
    let bare: serde_yaml::Value =
        serde_yaml::from_str("url: 'https://agent.vendor/planner'").expect("yaml");
    assert!(
        super::upstream_credential_binding(
            "planner",
            &bare,
            &reach,
            &busbar_contract::config_time::ConfigScope::config_time()
        )
        .expect("no block is no error")
        .is_none(),
        "no upstream_credential: nothing is bound, so nothing is presented"
    );
    let _ = std::fs::remove_file(&path);
}

/// Ported from the deleted engine crate's `creds_tests::a_named_header_placement_carries_the_value_verbatim`:
/// `placement: {header: X-API-Key}` binds the `api-key` style over that header, the secret
/// verbatim, and no `authorization`; a placement naming no header refuses the load.
#[test]
fn a_named_header_placement_presents_the_secret_verbatim_in_that_header() {
    let path = own_secret("apikey", "abc123");
    let reach = own_reach();
    let binding = super::upstream_credential_binding(
        "planner",
        &registration(&path, ", placement: {header: X-API-Key}"),
        &reach,
        &busbar_contract::config_time::ConfigScope::config_time(),
    )
    .expect("it binds")
    .expect("a binding");
    let handle = binding
        .per_request
        .as_ref()
        .expect("a refreshed binding")
        .handle_now()
        .expect("it resolves");
    assert_eq!(
        presents(&*binding.auth, handle),
        vec![("x-api-key".to_string(), "abc123".to_string())]
    );
    let err = refused(super::upstream_credential_binding(
        "planner",
        &registration(&path, ", placement: {header: ''}"),
        &reach,
        &busbar_contract::config_time::ConfigScope::config_time(),
    ));
    assert!(err.contains("member 'planner'"), "{err}");
    let _ = std::fs::remove_file(&path);
}

/// Ported from the deleted engine crate's `creds_tests::an_unresolvable_handle_fails_closed_and_names_the_agent`:
/// a secret that does not resolve when the generation is sealed refuses the load naming the member
/// (fail closed); one that stops resolving after it is refused from the next refresh on: the handle
/// answers none, hop after hop, and answers again once a refresh finds it back. A block stating no
/// lease (or a zero one) refuses the load naming the member too: the lease is how often the
/// credential is refreshed.
#[test]
fn an_unresolvable_credential_fails_closed_and_names_the_member() {
    let reach = own_reach();
    let missing = std::path::Path::new("/nonexistent/busbar/agent/secret");
    let err = refused(super::upstream_credential_binding(
        "planner",
        &registration(missing, ""),
        &reach,
        &busbar_contract::config_time::ConfigScope::config_time(),
    ));
    assert!(
        err.contains("member 'planner'") && err.contains("cannot resolve"),
        "{err}"
    );

    let path = own_secret("vanish", "tok");
    for lease in [None, Some(0_u64)] {
        let mut bare = registration(&path, "");
        let block = bare
            .get_mut(busbar_contract::section::UPSTREAM_CREDENTIAL_KEY)
            .and_then(serde_yaml::Value::as_mapping_mut)
            .expect("the block");
        let key = serde_yaml::Value::from(busbar_contract::section::CREDENTIAL_LEASE_TTL_KEY);
        match lease {
            None => {
                block.remove(&key);
            }
            Some(ms) => {
                block.insert(key, serde_yaml::Value::from(ms));
            }
        }
        let err = refused(super::upstream_credential_binding(
            "planner",
            &bare,
            &reach,
            &busbar_contract::config_time::ConfigScope::config_time(),
        ));
        assert!(
            err.contains("member 'planner'") && err.contains("lease_ttl_ms"),
            "{err}"
        );
    }
    let (_, per) = super::upstream_credential(
        "planner",
        &registration(&path, ""),
        &reach,
        &busbar_contract::config_time::ConfigScope::config_time(),
    )
    .expect("it binds")
    .expect("a binding");
    use busbar_contract::auth_calls::PerRequestHandle as _;
    let first = per
        .handle_now()
        .expect("it resolves while the file is there");
    std::fs::remove_file(&path).expect("remove it");
    assert_eq!(
        per.handle_now(),
        Some(first),
        "a hop before the next refresh presents what the last refresh left"
    );
    per.refresh(&busbar_contract::config_time::ConfigScope::config_time());
    for _ in 0..8 {
        assert_eq!(
            per.handle_now(),
            None,
            "gone: nothing is presented, hop after hop"
        );
    }
    std::fs::write(&path, "tok").expect("put it back");
    per.refresh(&busbar_contract::config_time::ConfigScope::config_time());
    assert!(
        per.handle_now().is_some(),
        "a refresh that finds it back serves it again"
    );
    let _ = std::fs::remove_file(&path);
}

/// A SECRET PASTED WHERE ITS REFERENCE BELONGS IS NEVER ECHOED (secret-hygiene Check 3; coordinator
/// ruling 2026-10-07: the refusal names the binding, member and key, never the value or a decoder
/// error over the secret input). Each `secret:` below carries a real-looking value in a shape the
/// reference decoder cannot read; every refusal names `member 'planner'` and
/// `upstream_credential.secret`, and none carries the value.
/// RED before the fix: the flow map `{sk-live-...}` is a map whose one KEY is the secret, and the
/// decoder's "unknown field `sk-live-...`" error rode into the refusal verbatim.
#[test]
fn a_secret_pasted_as_its_reference_is_never_echoed_in_the_refusal() {
    const SECRET: &str = "sk-live-4f9QzX7pL2mV8rT1";
    let reach = own_reach();
    for secret in [
        format!("{{{SECRET}}}"),
        format!("{{{SECRET}: {{file: /x}}}}"),
        SECRET.to_string(),
        format!("'{SECRET}'"),
        format!("{{env: {{{SECRET}: 1}}}}"),
        format!("{{file: [{SECRET}]}}"),
        format!("{{module: file, settings: {SECRET}}}"),
        format!("{{module: [{SECRET}]}}"),
    ] {
        let registration: serde_yaml::Value = serde_yaml::from_str(&format!(
            "url: 'https://agent.vendor/planner'\nupstream_credential: {{secret: {secret}}}"
        ))
        .expect("yaml");
        let err = refused(super::upstream_credential_binding(
            "planner",
            &registration,
            &reach,
            &busbar_contract::config_time::ConfigScope::config_time(),
        ));
        assert!(
            !err.contains(SECRET),
            "the refusal for `secret: {secret}` echoes the secret: {err}"
        );
        assert!(
            err.contains("member 'planner'") && err.contains("upstream_credential.secret"),
            "the refusal names the binding: {err}"
        );
    }
}

/// An `OutboundAuth` counting its `open_outbound` calls over the real one.
struct CountingOpens {
    inner: std::sync::Arc<dyn busbar_contract::auth_calls::OutboundAuth>,
    opened: std::sync::atomic::AtomicUsize,
}

impl busbar_contract::auth_calls::OutboundAuth for CountingOpens {
    fn open_outbound(
        &self,
        style: &str,
        credential: &[u8],
        settings: &serde_json::Value,
    ) -> Result<u64, String> {
        self.opened
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        self.inner.open_outbound(style, credential, settings)
    }

    fn fields_now(
        &self,
        handle: u64,
        request: &busbar_contract::auth_calls::FieldsRequest,
    ) -> Option<busbar_contract::auth_calls::Fields> {
        self.inner.fields_now(handle, request)
    }

    fn fields(
        &self,
        handle: u64,
        request: busbar_contract::auth_calls::FieldsRequest,
        deadline_ns: u64,
    ) -> Box<dyn busbar_contract::auth_calls::Fielding> {
        self.inner.fields(handle, request, deadline_ns)
    }
}

/// A `bearer` [`super::PerHop`] over the secret at `path`, opened by `auth` as the composition
/// opens it, its lease a minute (no cell waits on the refresher: each refreshes by hand).
fn per_hop(path: &std::path::Path, auth: std::sync::Arc<CountingOpens>) -> super::PerHop {
    per_hop_over(
        path,
        auth,
        std::sync::Arc::new(busbar_kernel::config::secret::SecretResolver::builtins_only()),
    )
}

/// [`per_hop`], its secret resolved through `secrets`.
fn per_hop_over(
    path: &std::path::Path,
    auth: std::sync::Arc<CountingOpens>,
    secrets: std::sync::Arc<dyn busbar_contract::secret::SecretResolve>,
) -> super::PerHop {
    let secret = busbar_contract::secret_ref::SecretRef::file(path.display().to_string());
    let value = secrets.resolve_string(&secret).expect("it resolves");
    let settings = serde_json::json!({});
    let handle = {
        use busbar_contract::auth_calls::OutboundAuth as _;
        auth.open_outbound("bearer", value.as_bytes(), &settings)
            .expect("it opens")
    };
    super::PerHop {
        secret,
        secrets,
        auth: auth as std::sync::Arc<dyn busbar_contract::auth_calls::OutboundAuth>,
        style: "bearer",
        header: None,
        lease: std::time::Duration::from_secs(60),
        held: arc_swap::ArcSwapOption::from_pointee(super::Held {
            digest: busbar_contract::abi::sdk::digest::sha256(value.as_bytes()),
            handle,
        }),
        refreshing: std::sync::Mutex::new(()),
    }
}

/// The real `bearer` auth instance the build links.
fn bearer_auth() -> std::sync::Arc<CountingOpens> {
    let (inner, _) = own_reach()
        .auths
        .serving("bearer", &serde_json::json!({}))
        .expect("a lookup")
        .expect("the linked header plugin serves `bearer`");
    std::sync::Arc::new(CountingOpens {
        inner,
        opened: std::sync::atomic::AtomicUsize::new(0),
    })
}

/// REFRESHED ONCE PER LEASE, OFF THE HOP (ARCHITECT ruling on #787): a hop after the secret's
/// source changed still presents what the last refresh left; the first hop after the next refresh
/// presents the NEW value, the refresh re-opening the binding exactly once for the rotation; an
/// unchanged secret never re-opens it, however many hops or refreshes ask (handles grow by
/// rotations, never by hops).
#[test]
fn a_rotated_secret_is_presented_on_the_first_hop_after_the_next_refresh() {
    use busbar_contract::auth_calls::PerRequestHandle as _;
    let path = own_secret("rotate", "old-token");
    let auth = bearer_auth();
    let per = per_hop(&path, std::sync::Arc::clone(&auth));
    let opens = || auth.opened.load(std::sync::atomic::Ordering::SeqCst);
    assert_eq!(opens(), 1, "the composition's one open");

    let first = per.handle_now().expect("it resolves");
    for _ in 0..16 {
        assert_eq!(
            per.handle_now(),
            Some(first),
            "the same handle hop after hop"
        );
    }
    assert_eq!(opens(), 1, "an unchanged secret never re-opens the binding");
    assert_eq!(
        presents(&*auth, first),
        vec![("authorization".to_string(), "Bearer old-token".to_string())]
    );

    per.refresh(&busbar_contract::config_time::ConfigScope::config_time());
    assert_eq!(
        opens(),
        1,
        "a refresh over an unchanged secret never re-opens the binding"
    );
    rotate(&path, "new-token");
    assert_eq!(
        per.handle_now(),
        Some(first),
        "a hop before the next refresh presents what the last refresh left"
    );
    per.refresh(&busbar_contract::config_time::ConfigScope::config_time());
    let next = per.handle_now().expect("it resolves");
    assert_ne!(
        next, first,
        "the refresh re-opened the binding for the rotation"
    );
    assert_eq!(opens(), 2, "one re-open for one rotation");
    assert_eq!(
        presents(&*auth, next),
        vec![("authorization".to_string(), "Bearer new-token".to_string())],
        "the first hop after the refresh presents the new value"
    );
    per.refresh(&busbar_contract::config_time::ConfigScope::config_time());
    assert_eq!(per.handle_now(), Some(next));
    assert_eq!(
        opens(),
        2,
        "and the new value, unchanged, never re-opens it"
    );
    let _ = std::fs::remove_file(&path);
}

/// A NAMED-HEADER BINDING RE-OPENED BY A ROTATION keeps its header: the binding holds the typed
/// placement (no settings bag), and the re-open after a rotation rebuilds the same
/// `{header: X-API-Key}` settings, so the new value is presented verbatim in that header and never
/// as `authorization`.
#[test]
fn a_rotated_header_credential_is_presented_in_the_same_header() {
    let path = own_secret("rotate-header", "key-old");
    let reach = own_reach();
    let (binding, per) = super::upstream_credential(
        "planner",
        &registration(&path, ", placement: {header: X-API-Key}"),
        &reach,
        &busbar_contract::config_time::ConfigScope::config_time(),
    )
    .expect("it binds")
    .expect("a binding");
    use busbar_contract::auth_calls::PerRequestHandle as _;
    let first = per.handle_now().expect("it resolves");
    assert_eq!(
        presents(&*binding.auth, first),
        vec![("x-api-key".to_string(), "key-old".to_string())]
    );
    rotate(&path, "key-new");
    per.refresh(&busbar_contract::config_time::ConfigScope::config_time());
    let next = per.handle_now().expect("it resolves");
    assert_ne!(next, first, "the rotation re-opened the binding");
    assert_eq!(
        presents(&*binding.auth, next),
        vec![("x-api-key".to_string(), "key-new".to_string())],
        "the re-open keeps the header placement"
    );
    let _ = std::fs::remove_file(&path);
}

/// HOPS RACING A ROTATION each present ONE COMPLETE VALUE, the old or the new, never a mix: the
/// handle a hop is given was opened over one whole value, and a refresh swaps it whole.
#[test]
fn hops_racing_a_rotation_each_present_one_whole_value() {
    use busbar_contract::auth_calls::PerRequestHandle as _;
    let path = own_secret("race", "value-old-0000000000");
    let auth = bearer_auth();
    let per = std::sync::Arc::new(per_hop(&path, std::sync::Arc::clone(&auth)));
    let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let hops: Vec<_> = (0..4)
        .map(|_| {
            let (per, auth, stop) = (
                std::sync::Arc::clone(&per),
                std::sync::Arc::clone(&auth),
                std::sync::Arc::clone(&stop),
            );
            std::thread::spawn(move || {
                let mut seen = std::collections::BTreeSet::new();
                while !stop.load(std::sync::atomic::Ordering::SeqCst) {
                    let Some(handle) = per.handle_now() else {
                        continue;
                    };
                    for (_, value) in presents(&*auth, handle) {
                        seen.insert(value);
                    }
                }
                seen
            })
        })
        .collect();
    for i in 0..64 {
        let value = if i % 2 == 0 {
            "value-new-1111111111"
        } else {
            "value-old-0000000000"
        };
        rotate(&path, value);
        per.refresh(&busbar_contract::config_time::ConfigScope::config_time());
        std::thread::sleep(std::time::Duration::from_millis(1));
    }
    stop.store(true, std::sync::atomic::Ordering::SeqCst);
    let whole = [
        "Bearer value-old-0000000000".to_string(),
        "Bearer value-new-1111111111".to_string(),
    ];
    for hop in hops {
        for value in hop.join().expect("a hop thread") {
            assert!(whole.contains(&value), "a mixed or partial value: {value}");
        }
    }
    let _ = std::fs::remove_file(&path);
}

/// A `SecretResolve` counting its resolutions over the built-in resolver.
struct CountingResolves {
    inner: busbar_kernel::config::secret::SecretResolver,
    resolved: std::sync::atomic::AtomicUsize,
}

impl busbar_contract::secret::SecretResolve for CountingResolves {
    fn resolve(&self, secret: &busbar_contract::secret_ref::SecretRef) -> Result<Vec<u8>, String> {
        self.resolved
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        busbar_contract::secret::SecretResolve::resolve(&self.inner, secret)
    }

    fn resolve_string(
        &self,
        secret: &busbar_contract::secret_ref::SecretRef,
    ) -> Result<String, String> {
        self.resolved
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        busbar_contract::secret::SecretResolve::resolve_string(&self.inner, secret)
    }
}

/// Whether `ask` answers within `budget`, asked on a thread of its own (a hop that blocks is
/// left parked there and reported as not answering).
fn answers_within<T: Send + 'static>(
    budget: std::time::Duration,
    ask: impl FnOnce() -> T + Send + 'static,
) -> Option<T> {
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let _ = tx.send(ask());
    });
    rx.recv_timeout(budget).ok()
}

/// A HOP RESOLVES NOTHING AND TAKES NO LOCK (ARCHITECT ruling on #787: a secret resolution blocks
/// its thread up to its deadline, `busbar_contract::secret::SecretCalls`, and is never made on the
/// request path): across many hops the resolver is asked nothing, and a hop answers while a
/// refresh holds the binding's own lock. Only a refresh resolves.
/// RED before the fix: `handle_now` re-resolved the secret on every hop (the count rose by one per
/// hop) under the binding's lock.
#[test]
fn a_hop_resolves_nothing_and_takes_no_lock() {
    use busbar_contract::auth_calls::PerRequestHandle as _;
    let path = own_secret("no-resolve", "steady-token");
    let resolver = std::sync::Arc::new(CountingResolves {
        inner: busbar_kernel::config::secret::SecretResolver::builtins_only(),
        resolved: std::sync::atomic::AtomicUsize::new(0),
    });
    let per = std::sync::Arc::new(per_hop_over(
        &path,
        bearer_auth(),
        std::sync::Arc::clone(&resolver)
            as std::sync::Arc<dyn busbar_contract::secret::SecretResolve>,
    ));
    let resolved = || resolver.resolved.load(std::sync::atomic::Ordering::SeqCst);
    let built = resolved();
    let first = per.handle_now().expect("it resolved at build");
    for _ in 0..256 {
        assert_eq!(per.handle_now(), Some(first));
    }
    assert_eq!(resolved(), built, "256 hops asked the resolver nothing");

    let held = per
        .refreshing
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let hop = std::sync::Arc::clone(&per);
    assert_eq!(
        answers_within(std::time::Duration::from_secs(5), move || hop.handle_now()),
        Some(Some(first)),
        "a hop answers while a refresh holds the binding's lock"
    );
    drop(held);

    per.refresh(&busbar_contract::config_time::ConfigScope::config_time());
    assert_eq!(resolved(), built + 1, "a refresh resolves, once");
    let _ = std::fs::remove_file(&path);
}

/// An `OutboundAuth` whose `open_outbound` parks until released, over the real one.
struct ParkedOpens {
    inner: std::sync::Arc<CountingOpens>,
    parked: std::sync::Mutex<Option<std::sync::mpsc::Receiver<()>>>,
    entered: std::sync::mpsc::SyncSender<()>,
}

impl busbar_contract::auth_calls::OutboundAuth for ParkedOpens {
    fn open_outbound(
        &self,
        style: &str,
        credential: &[u8],
        settings: &serde_json::Value,
    ) -> Result<u64, String> {
        let release = self
            .parked
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take();
        if let Some(release) = release {
            let _ = self.entered.send(());
            let _ = release.recv();
        }
        busbar_contract::auth_calls::OutboundAuth::open_outbound(
            &*self.inner,
            style,
            credential,
            settings,
        )
    }

    fn fields_now(
        &self,
        handle: u64,
        request: &busbar_contract::auth_calls::FieldsRequest,
    ) -> Option<busbar_contract::auth_calls::Fields> {
        busbar_contract::auth_calls::OutboundAuth::fields_now(&*self.inner, handle, request)
    }

    fn fields(
        &self,
        handle: u64,
        request: busbar_contract::auth_calls::FieldsRequest,
        deadline_ns: u64,
    ) -> Box<dyn busbar_contract::auth_calls::Fielding> {
        busbar_contract::auth_calls::OutboundAuth::fields(
            &*self.inner,
            handle,
            request,
            deadline_ns,
        )
    }
}

/// THE OPEN RUNS UNDER NO LOCK A HOP WAITS ON (ARCHITECT ruling on #787): while a refresh's
/// `open_outbound` for a rotated secret is parked inside the auth plugin, a hop answers at once with
/// the handle the last refresh left; once the open returns, the next hop presents the new handle.
/// RED before the fix: the re-open ran under the `held` mutex every hop locked, so the hop waited
/// out the open.
#[test]
fn an_open_runs_under_no_lock_a_hop_waits_on() {
    use busbar_contract::auth_calls::PerRequestHandle as _;
    let path = own_secret("parked-open", "token-before");
    let counting = bearer_auth();
    let (release_tx, release_rx) = std::sync::mpsc::channel();
    let (entered_tx, entered_rx) = std::sync::mpsc::sync_channel(1);
    let parked = std::sync::Arc::new(ParkedOpens {
        inner: std::sync::Arc::clone(&counting),
        parked: std::sync::Mutex::new(None),
        entered: entered_tx,
    });
    let mut per = per_hop(&path, std::sync::Arc::clone(&counting));
    per.auth = std::sync::Arc::clone(&parked)
        as std::sync::Arc<dyn busbar_contract::auth_calls::OutboundAuth>;
    let per = std::sync::Arc::new(per);
    let first = per.handle_now().expect("it resolved at build");

    rotate(&path, "token-after");
    *parked
        .parked
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(release_rx);
    let refreshing = std::sync::Arc::clone(&per);
    let refresh = std::thread::spawn(move || {
        refreshing.refresh(&busbar_contract::config_time::ConfigScope::config_time())
    });
    entered_rx
        .recv_timeout(std::time::Duration::from_secs(5))
        .expect("the refresh reached the auth plugin's open");

    let hop = std::sync::Arc::clone(&per);
    assert_eq!(
        answers_within(std::time::Duration::from_secs(5), move || hop.handle_now()),
        Some(Some(first)),
        "a hop answers, with the last refresh's handle, while the open is parked"
    );

    release_tx.send(()).expect("release the open");
    refresh.join().expect("the refresh");
    let next = per.handle_now().expect("the rotation bound");
    assert_ne!(
        next, first,
        "the hop after the open presents the new handle"
    );
    assert_eq!(
        presents(&*counting, next),
        vec![(
            "authorization".to_string(),
            "Bearer token-after".to_string()
        )]
    );
    let _ = std::fs::remove_file(&path);
}

/// Ported from the deleted engine crate's `creds_tests::the_lease_never_renders_the_secret_in_a_debug_line`:
/// the per-hop binding holds a reference and a digest, never the value, and its debug line shows
/// neither the value nor the digest.
#[test]
fn the_per_hop_binding_never_renders_the_secret_in_a_debug_line() {
    let path = own_secret("debug", "SUPER-SECRET-VALUE");
    let per = per_hop(&path, bearer_auth());
    let rendered = format!("{per:?}");
    assert!(
        !rendered.contains("SUPER-SECRET-VALUE"),
        "the binding rendered its secret: {rendered}"
    );
    let digest = busbar_contract::abi::sdk::digest::sha256(b"SUPER-SECRET-VALUE");
    let hex: String = digest.iter().map(|b| format!("{b:02x}")).collect();
    assert!(
        !rendered.contains(&hex) && !rendered.contains(&format!("{:?}", digest[0..4].to_vec())),
        "the binding rendered its digest: {rendered}"
    );
    assert!(rendered.contains("<redacted"), "{rendered}");
    assert!(
        !rendered.contains(&path.display().to_string()),
        "nor where the secret lives: {rendered}"
    );
    let _ = std::fs::remove_file(&path);
}
/// A REGISTRATION MEMBER RIDES EVERY MEMBER-TARGET NEED its plane states (ARCHITECT root ruling,
/// 2026-10-07, reusing the providers' rides, Q-L5B-NEEDS): its first is its own, each
/// other one rides beside it at the target the registration names there (another origin dials that
/// origin), and a far request naming any of them opens on it. A registration naming no target for
/// a need does not ride it. RED: only the first member-target need was bound, so a far request
/// naming the second had no destination.
#[test]
fn a_registration_member_rides_every_member_target_need() {
    use busbar_contract::abi::host::conn::connector::DIRECTION_OUTBOUND;
    let facts = crate::root::loader::dispatch::kinds::plane::ServedFacts {
        need_auths: vec![
            (DIRECTION_OUTBOUND, ""),
            (DIRECTION_OUTBOUND, ""),
            (DIRECTION_OUTBOUND, ""),
            (DIRECTION_OUTBOUND, ""),
        ],
        need_targets: vec!["", "settings.*.url", "settings.*.url", "settings.*.alt"],
        ..Default::default()
    };
    let routes = resolve_for(
        &facts,
        "fs: {url: \"http://127.0.0.1:7/rpc\", alt: \"http://127.0.0.1:8/x\"}\n\
         one: {url: \"http://127.0.0.1:9/rpc\"}\n",
        &[],
    )
    .expect("the registrations resolve");
    let fs = &routes["fs"];
    assert_eq!(fs.need.0, 1, "the first member-target need is its own");
    let rides: Vec<u32> = fs.rides.iter().map(|(n, _)| n.0).collect();
    assert_eq!(
        rides,
        [2, 3],
        "every other member-target need rides beside it"
    );
    assert_eq!(fs.ride(3).map(|r| r.need.0), Some(2));
    assert_eq!(
        fs.ride(3).map(|r| r.base_url),
        Some("http://127.0.0.1:7"),
        "the same target, the same origin"
    );
    assert_eq!(
        fs.ride(4).map(|r| r.base_url),
        Some("http://127.0.0.1:8"),
        "a need whose target is another origin dials that origin"
    );
    assert!(fs.ride(1).is_none(), "the open need is no member's");
    let one = &routes["one"];
    let rides: Vec<u32> = one.rides.iter().map(|(n, _)| n.0).collect();
    assert_eq!(
        rides,
        [2],
        "a registration naming no `alt` does not ride its need"
    );
}

/// A connection table that records what the composition seals on it: each need's anchors and
/// private reach, and each auth binding, by need, member and target. It opens nothing.
#[derive(Default)]
struct Sealing {
    anchored: std::sync::Mutex<Vec<(u32, String)>>,
    reached: std::sync::Mutex<Vec<(u32, String, String)>>,
    bound: std::sync::Mutex<Vec<(u32, String, String)>>,
}

impl busbar_contract::conn::Conns for Sealing {
    fn open(
        &self,
        _: busbar_contract::conn::InstanceId,
        _: busbar_contract::conn::NeedId,
        _: &busbar_contract::conn::OpenDesc<'_>,
    ) -> Result<busbar_contract::conn::ConnId, busbar_contract::conn::ConnError> {
        Err(busbar_contract::conn::ConnError::Refused)
    }
    fn write(
        &self,
        _: busbar_contract::conn::InstanceId,
        _: busbar_contract::conn::ConnId,
        _: &[u8],
        _: bool,
        _: bool,
    ) -> Result<usize, busbar_contract::conn::ConnError> {
        Err(busbar_contract::conn::ConnError::Closed)
    }
    fn read(
        &self,
        _: busbar_contract::conn::InstanceId,
        _: busbar_contract::conn::ConnId,
        _: u64,
        _: &mut [u8],
    ) -> Result<busbar_contract::conn::Piece, busbar_contract::conn::ConnError> {
        Err(busbar_contract::conn::ConnError::Closed)
    }
    fn wait(
        &self,
        _: busbar_contract::conn::InstanceId,
        _: &[busbar_contract::conn::ConnId],
        _: u64,
    ) -> Result<usize, busbar_contract::conn::ConnError> {
        Err(busbar_contract::conn::ConnError::Closed)
    }
    fn facts(
        &self,
        _: busbar_contract::conn::InstanceId,
        _: busbar_contract::conn::ConnId,
    ) -> Result<busbar_contract::transport::ConnFacts, busbar_contract::conn::ConnError> {
        Err(busbar_contract::conn::ConnError::Closed)
    }
    fn close(
        &self,
        _: busbar_contract::conn::InstanceId,
        _: busbar_contract::conn::ConnId,
    ) -> Result<(), busbar_contract::conn::ConnError> {
        Err(busbar_contract::conn::ConnError::Closed)
    }
}

impl busbar_contract::conn::PollConns for Sealing {
    fn poll_read(
        &self,
        _: busbar_contract::conn::InstanceId,
        _: busbar_contract::conn::ConnId,
        _: &mut std::task::Context<'_>,
        _: &mut [u8],
    ) -> std::task::Poll<Result<busbar_contract::conn::Piece, busbar_contract::conn::ConnError>>
    {
        std::task::Poll::Ready(Err(busbar_contract::conn::ConnError::Closed))
    }
    fn anchor(
        &self,
        _: busbar_contract::conn::InstanceId,
        need: busbar_contract::conn::NeedId,
        _: &str,
        target: &str,
        _: &busbar_contract::transport::trust::Anchors,
    ) -> Result<(), busbar_contract::conn::ConnError> {
        self.anchored
            .lock()
            .unwrap()
            .push((need.0, target.to_string()));
        Ok(())
    }
    fn seal_reach(
        &self,
        _: busbar_contract::conn::InstanceId,
        need: busbar_contract::conn::NeedId,
        member: &str,
        target: &str,
        reach: bool,
    ) -> Result<(), busbar_contract::conn::ConnError> {
        if reach {
            self.reached
                .lock()
                .unwrap()
                .push((need.0, member.to_string(), target.to_string()));
        }
        Ok(())
    }
}

impl busbar_contract::conn::DeclaredConns for Sealing {
    fn declare(
        &self,
        _: busbar_contract::conn::InstanceId,
        _: busbar_contract::conn::NeedId,
        _: &busbar_contract::abi::mechanism::rendering::ReadNeed,
        _: Option<&str>,
        _: Option<&str>,
    ) -> Result<(), busbar_contract::conn::ConnError> {
        Ok(())
    }
    fn declared(
        &self,
        _: busbar_contract::conn::InstanceId,
        _: busbar_contract::conn::NeedId,
    ) -> Option<Result<(), busbar_contract::conn::ConnError>> {
        Some(Ok(()))
    }
    fn serves_scheme(&self, _: &str) -> bool {
        true
    }
    fn bind_auth(
        &self,
        _: busbar_contract::conn::InstanceId,
        need: busbar_contract::conn::NeedId,
        member: &str,
        origin: &str,
        _: busbar_contract::conn::ConnAuth,
    ) {
        self.bound
            .lock()
            .unwrap()
            .push((need.0, member.to_string(), origin.to_string()));
    }
}

/// An auth binding that is only ever bound: it answers no fields.
struct Bound;

/// A fields answer that never arrives.
struct Never;

impl std::future::Future for Never {
    type Output = busbar_contract::auth_calls::Fields;
    fn poll(
        self: std::pin::Pin<&mut Self>,
        _: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Self::Output> {
        std::task::Poll::Pending
    }
}

impl busbar_contract::auth_calls::Fielding for Never {
    fn settled(&mut self) -> Option<busbar_contract::auth_calls::Fields> {
        None
    }
}

impl busbar_contract::auth_calls::OutboundAuth for Bound {
    fn open_outbound(&self, _: &str, _: &[u8], _: &serde_json::Value) -> Result<u64, String> {
        Ok(1)
    }
    fn fields_now(
        &self,
        _: u64,
        _: &busbar_contract::auth_calls::FieldsRequest,
    ) -> Option<busbar_contract::auth_calls::Fields> {
        None
    }
    fn fields(
        &self,
        _: u64,
        _: busbar_contract::auth_calls::FieldsRequest,
        _: u64,
    ) -> Box<dyn busbar_contract::auth_calls::Fielding> {
        Box::new(Never)
    }
}

/// THE MEMBER'S ANCHORS, REACH AND BINDING HOLD ON EVERY NEED IT RIDES (ARCHITECT root ruling,
/// 2026-10-07): the composition seals the registration's trust anchors and private reach on
/// its own need and on each need riding beside it, at the base each dials, and the door's own
/// requests on any member-target need it rides carry its auth binding. RED: only the member's own
/// need was sealed and bound, so a far request (or the door's own request) on its second
/// transport went out unpinned, unreached and unauthenticated.
#[test]
fn a_registration_members_anchors_reach_and_binding_hold_on_every_need_it_rides() {
    use busbar_contract::abi::host::conn::connector::DIRECTION_OUTBOUND;
    use busbar_kernel::plane_driver::{AuthBinding, MemberRoute, ResponseKeep};
    let served = crate::root::loader::dispatch::kinds::plane::ServedFacts {
        need_auths: vec![
            (DIRECTION_OUTBOUND, ""),
            (DIRECTION_OUTBOUND, ""),
            (DIRECTION_OUTBOUND, ""),
        ],
        need_targets: vec!["", "settings.*.url", "settings.*.url"],
        ..Default::default()
    };
    let route = MemberRoute {
        need: busbar_contract::conn::NeedId(1),
        base_url: "https://far.example".to_string(),
        auth: Some(AuthBinding {
            auth: std::sync::Arc::new(Bound),
            handle: 1,
            style_flags: 0,
            points: busbar_contract::abi::auth::AuthPoints(0),
            passthrough: false,
            per_request: None,
        }),
        provider: "fs".to_string(),
        keep: ResponseKeep::default(),
        rides: vec![(busbar_contract::conn::NeedId(2), ResponseKeep::default())],
        anchors: busbar_contract::transport::trust::Anchors {
            private_reach: true,
            ..Default::default()
        },
        spelled: Vec::new(),
    };
    let routes = std::collections::BTreeMap::from([("fs".to_string(), route)]);
    let table = std::sync::Arc::new(Sealing::default());
    let instance = busbar_contract::conn::InstanceId(7);
    super::bind_member_fetches(
        &served,
        &routes,
        instance,
        &*table,
        &std::sync::Arc::new(busbar_kernel::host_units::UnitRecords::default()),
    );
    assert_eq!(
        *table.bound.lock().unwrap(),
        [
            (1, "fs".to_string(), "https://far.example".to_string()),
            (2, "fs".to_string(), "https://far.example".to_string())
        ],
        "the door's own requests on either need carry the member's binding"
    );
    let section: serde_yaml::Value =
        serde_yaml::from_str("fs: {url: \"https://far.example/rpc\"}").expect("yaml");
    let facts = super::door_facts("p", &[], &[], &[], "audit", Vec::new());
    let node = std::sync::Arc::new(crate::root::plane_node::Node::new());
    let post = std::sync::Arc::new(crate::root::plane_node::NodeEndPost::new(node));
    super::compose_egress(
        &facts,
        &DoorPools::of(&section).expect("the pools"),
        instance,
        std::sync::Arc::clone(&table) as std::sync::Arc<dyn busbar_contract::conn::PollConns>,
        &routes,
        post as std::sync::Arc<dyn busbar_kernel_egress::ports::Journal>,
        std::sync::Arc::new(crate::root::egress_ports::NodeClock::new()),
        1,
    )
    .expect("the egress composes");
    assert_eq!(
        *table.anchored.lock().unwrap(),
        [
            (1, "https://far.example".to_string()),
            (2, "https://far.example".to_string())
        ],
        "the anchors are sealed on both needs"
    );
    assert_eq!(
        *table.reached.lock().unwrap(),
        [
            (1, "fs".to_string(), "https://far.example".to_string()),
            (2, "fs".to_string(), "https://far.example".to_string())
        ],
        "the registration's private reach is sealed on both needs"
    );
}

/// THE MODEL-SHAPED GUARD on the counter label rule: a section shaped as the model plane's is (a
/// `models` map, a named pool over two of its entries) yields, when its plane STATES its attempts'
/// labels, exactly the `(pool, lane)` pairs 1.5.5 counted (the golden cells
/// its direct-route request cell: a direct route, `pool` and `lane` both the model entry;
/// `route.529__failover__primary`: the pool `cap-fo`, each member entry its `lane`;
/// its upstream-down request cell: the failures family, the same pair). Stating
/// nothing keeps the kernel's qualified default, which is what a plane that states no label (and
/// predev's door) counts under.
#[test]
fn a_model_shaped_section_takes_the_stated_labels_the_previous_release_counted() {
    use busbar_kernel_egress::ports::StatedLabels;
    let p = pools(
        "models:\n  m-direct: {}\n  m-first: {}\n  m-second: {}\npools:\n  cap-fo:\n    members: [m-first, m-second]\n",
    );
    let bound = super::label_bound("p", &p, &[]);
    let stated = |pool: &str, lane: &str| StatedLabels {
        pool: Some(pool.to_string()),
        lane: Some(lane.to_string()),
    };
    // A DIRECT route: the walk keys it by the entry's own (qualified) pool.
    let direct = super::egress_pool(
        "p",
        &routed(&p, ROUTE_DIRECT, Some("m-direct")).expect("a direct route"),
    );
    let own = super::plane_lane("p", "m-direct");
    assert_eq!(
        bound.labels(
            &direct,
            (&direct, &own),
            Some(&stated("m-direct", "m-direct"))
        ),
        ("m-direct".to_string(), "m-direct".to_string(), false),
        "the golden direct-route request cell"
    );
    // A POOL route: the pool's label, each member entry its lane.
    let pooled = super::egress_pool(
        "p",
        &routed(&p, ROUTE_POOL, Some("cap-fo")).expect("a pool route"),
    );
    for member in ["m-first", "m-second"] {
        assert_eq!(
            bound.labels(
                &pooled,
                (&pooled, &super::plane_lane("p", member)),
                Some(&stated("cap-fo", member))
            ),
            ("cap-fo".to_string(), member.to_string(), false),
            "route.529__failover__primary: {member}"
        );
    }
    // Stated nothing: the kernel's own labels, unchanged.
    assert_eq!(
        bound.labels(&direct, (&direct, &own), None),
        (direct.clone(), own.clone(), false)
    );
    // A member of ANOTHER route is not this walk's to name.
    assert_eq!(
        bound.labels(&direct, (&direct, &own), Some(&stated("cap-fo", "m-first"))),
        (direct.clone(), own.clone(), true),
        "a direct route reaches no pool and no other entry"
    );
}

/// A fallback pool's labels and members are within its parent pool's reach (the walk spills
/// into it), and the plane's declared lane words are within every walk's.
#[test]
fn a_pools_reach_follows_its_fallback_and_the_declared_words() {
    use busbar_kernel_egress::ports::StatedLabels;
    let p = pools(
        "a: {}\nb: {}\npools:\n  first:\n    members: [a]\n    on_exhausted: { fallback_pool: spill }\n  spill:\n    members: [b]\n",
    );
    let bound = super::label_bound("p", &p, &["word".to_string()]);
    let stated = |pool: &str, lane: &str| StatedLabels {
        pool: Some(pool.to_string()),
        lane: Some(lane.to_string()),
    };
    assert_eq!(
        bound.labels("first", ("first", "own"), Some(&stated("spill", "b"))),
        ("spill".to_string(), "b".to_string(), false)
    );
    assert_eq!(
        bound.labels("first", ("first", "own"), Some(&stated("a", "word"))),
        ("a".to_string(), "word".to_string(), false)
    );
    assert_eq!(
        bound.labels("spill", ("spill", "own"), Some(&stated("first", "a"))),
        ("spill".to_string(), "own".to_string(), true),
        "a fallback pool does not reach back into the pool that spilled into it"
    );
}

/// A UNIT ITS PLANE ANSWERS AT ITS SCOPE'S ONE ENTRY (`ROUTE_SCOPE_LOCAL`, COORDINATOR ruling
/// 2026-10-07), plane-neutral: resolved on the caller's grant of the plane's scope kind exactly as
/// `ROUTE_SCOPE` is, then routed NOWHERE: the one entry the grant reaches is the steps' resolved
/// entry (lent to the plane), no route is sealed, and a pool the entry is a member of is never
/// read, where the same unit routed by scope walks that pool. Zero or several reachable entries
/// resolve none and are refused `no_destination` at admission, the several named in the refusal's
/// words. RED before the value: a scope-local unit resolved nothing and routed nowhere it could be
/// answered at.
#[test]
fn a_scope_local_unit_resolves_the_one_entry_the_grant_reaches_and_routes_nowhere() {
    use busbar_contract::abi::plane::{ROUTE_SCOPE, ROUTE_SCOPE_LOCAL};
    use busbar_contract::caps::{Admittance, Dial, OpClassId, PrincipalId, ReasonCode};
    use busbar_contract::records::{ScopeRef, VirtualKey};
    use busbar_kernel::plane_driver::DriverSteps;
    use busbar_kernel::teller::UnitCtx;
    use busbar_kernel::test_support::tokens;
    let facts = super::door_facts("p", &["seat"], &[], &[], "a", Vec::new());
    let p = pools("a: {}\nb: {}\npools:\n  both:\n    members: [a, b]\n    member_granted: true");
    let ctx = UnitCtx {
        call: busbar_contract::caps::CallId::UNBOUND,
        key: busbar_contract::UnitKey::new(1),
        origin: busbar_contract::caps::OriginKind::Client,
        session: None,
        generation: busbar_kernel::registry::Generation::FIRST,
        admin_listener: false,
        kernel_verb_only: false,
    };
    let principal = PrincipalId::new("vk_seat");
    let steps = |reach: &[&str]| {
        super::DoorSteps::new(
            &facts,
            &p,
            std::sync::Arc::new(|_: &str| None),
            busbar_kernel::test_support::TestApp::new().build(),
            None,
            super::DoorCaller {
                principal: principal.clone(),
                key: Some(std::sync::Arc::new(VirtualKey {
                    id: "vk_seat".into(),
                    allowed_scopes: Some(
                        reach
                            .iter()
                            .map(|n| ScopeRef {
                                kind: "seat".to_string(),
                                value: (*n).to_string(),
                            })
                            .collect(),
                    ),
                    ..VirtualKey::default()
                })),
                open: false,
                arrived: 0,
                records: None,
                depth: 0,
                credential: None,
            },
        )
    };
    let verified = |s: &super::DoorSteps<'_>, class: u8| {
        s.decoded(&ctx, OpClassId::new("op"), class, None);
        s.verify(&tokens::grant::<Dial>(), &ctx, &principal)
            .expect("verify proceeds")
    };

    // ONE reaches: resolved, nothing sealed, no route (its pool unread).
    let one = steps(&["a"]);
    let sealed = verified(&one, ROUTE_SCOPE_LOCAL);
    assert!(sealed.is_empty(), "no destination is sealed");
    assert_eq!(one.resolved(&ctx), Some(b"a".to_vec()), "the one entry");
    assert_eq!(
        one.scope_entry(),
        Some(b"a".to_vec()),
        "its gates bind the one entry"
    );
    assert_eq!(one.routed(), None, "routed nowhere: no pool, no walk");
    // The same reach routed by scope walks the pool its one entry is a member of.
    let relayed = steps(&["a"]);
    let _ = verified(&relayed, ROUTE_SCOPE);
    assert_eq!(relayed.resolved(&ctx), None);
    assert_eq!(
        relayed.scope_entry(),
        Some(b"a".to_vec()),
        "a relayed scope unit's gates bind the one entry its scope resolved to"
    );
    assert_eq!(
        relayed.routed().map(|(label, _)| label),
        Some("both".to_string()),
        "a relayed unit is widened to its entry's pool"
    );

    // ZERO and SEVERAL reach: none resolved, refused `no_destination` at admission.
    for reach in [&[][..], &["a", "b"][..]] {
        let s = steps(reach);
        let _ = verified(&s, ROUTE_SCOPE_LOCAL);
        assert_eq!(s.resolved(&ctx), None, "{reach:?}");
        assert_eq!(s.scope_entry(), None, "{reach:?}");
        let refused = s.admit(
            &tokens::grant::<Admittance>(),
            &ctx,
            &principal,
            &[],
            &busbar_contract::slice::GroupLeaseSlip::default(),
        );
        let Err(refused) = refused else {
            panic!("{reach:?}: refused at admission");
        };
        assert_eq!(refused.reason(), ReasonCode::NoDestination, "{reach:?}");
        assert_eq!(
            s.refusal_words(ReasonCode::NoDestination),
            Some(reach.join(", ").into_bytes()),
            "the reachable entries named in its words: {reach:?}"
        );
    }
}

/// A MODEL'S `protocol` OVERRIDE REACHES THE PLANE (#51): the section the root hands the plane
/// serving the `pools` map carries each model's own `protocol` where it names one, and nothing for a
/// model that names none (its provider's stands). RED: a root that drops the member hands the plane
/// no override, so the plane speaks the provider's dialect to that model.
#[test]
fn a_models_protocol_override_is_handed_to_the_plane() {
    let def: busbar_kernel::config::ProviderDef =
        serde_yaml::from_str("protocol: dialect-a\nbase_url: http://127.0.0.1:9\n").expect("a def");
    let defs = std::collections::HashMap::from([("p".to_string(), def)]);
    let deploy = busbar_kernel::config::deploy_from_yaml_str(
        "store: {module: memory}\nproviders:\n  p:\n    api_key: { env: BUSBAR_TEST_KEY }\n\
         models:\n  over:\n    provider: p\n    protocol: dialect-b\n  plain:\n    provider: p\n",
    )
    .expect("parses");
    let cfg = busbar_kernel::config::resolve(&deploy, &defs).expect("resolves");
    let sections = super::kernel_sections(&cfg);
    let models = sections
        .get(busbar_contract::section::RESERVED_MODELS_KEY)
        .expect("the models section");
    assert_eq!(
        models["over"]["protocol"].as_str(),
        Some("dialect-b"),
        "{models:?}"
    );
    assert!(
        models["plain"].get("protocol").is_none(),
        "a model naming no protocol states none: {models:?}"
    );
}

/// A self-signed CA as the PEM an operator writes.
fn a_ca_pem() -> String {
    let kp = rcgen::KeyPair::generate().expect("a key");
    let mut params = rcgen::CertificateParams::new(Vec::new()).expect("params");
    params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    params.self_signed(&kp).expect("the CA").pem()
}

/// THE ONE OWNED-ANCHOR RULE, as boot and the pre-swap apply check both judge it: an anchor a
/// configuration writes that is no trust anchor is refused, naming the key; a usable PEM, an
/// anchor not written, an empty one and a `settings.` path are no refusal.
/// RED before the fix: an apply judged nothing, so an `agent_push.ca` the boot refuses went live.
#[test]
fn an_owned_anchor_the_boot_would_refuse_is_refused_by_the_same_rule() {
    let paths = ["owned.agent_push.ca", "settings.*.client_identity"];
    let with = |ca: Option<&str>| {
        let mut sections: std::collections::BTreeMap<&'static str, serde_yaml::Value> =
            std::collections::BTreeMap::new();
        if let Some(ca) = ca {
            sections.insert(
                "agent_push",
                serde_yaml::from_str(&format!("ca: {}", serde_json::to_string(ca).unwrap()))
                    .expect("yaml"),
            );
        }
        super::owned_anchors_refusal(&paths, &sections)
    };
    for bad in [
        "not a certificate",
        "-----BEGIN CERTIFICATE-----\ngarbage\n-----END CERTIFICATE-----\n",
    ] {
        let err = with(Some(bad)).expect_err("refused");
        assert!(
            err.contains("`agent_push.ca` is not a usable trust anchor"),
            "{err}"
        );
    }
    let ca = a_ca_pem();
    assert_eq!(with(Some(&ca)), Ok(()), "a usable CA");
    assert_eq!(
        with(None),
        Ok(()),
        "an owned section the operator did not write"
    );
    assert_eq!(with(Some("")), Ok(()), "an empty anchor is not written");
    assert_eq!(
        super::owned_anchor_refusal("agent_push.ca", &ca),
        Ok(()),
        "the rule itself takes the CA"
    );
}

/// RESTART-TO-APPLY, THE ROOT'S HALF (u67 BLOCK 2 item 2; BUSBAR-1.6.0.md Law 7 l.547): the root's
/// rules name a door plane the boot left unopened as awaiting restart exactly when a configuration
/// writes its declaring section, and never a plane the boot opened (one it does not hold). The
/// list is sorted, so the answer that reports it is stable. RED before the fix: the rules held no
/// unopened plane, so an apply that first wrote one's section reported nothing.
#[test]
fn an_unopened_door_plane_is_awaiting_restart_once_a_configuration_writes_its_section() {
    use busbar_kernel::appbuild::RootRules as _;
    let deploy = busbar_kernel::config::deploy_from_yaml_str(
        "store: {module: memory}\nmodels: {}\nproviders: {}\n",
    )
    .expect("parses");
    let mut cfg = busbar_kernel::config::resolve(&deploy, &std::collections::HashMap::new())
        .expect("resolves");
    let rules = super::Rules::default();
    assert!(
        rules.planes_awaiting_restart(&cfg).is_empty(),
        "nothing held, nothing pending"
    );
    rules.hold_unopened(["zz-unopened-red", "aa-unopened-red"]);
    assert!(
        rules.planes_awaiting_restart(&cfg).is_empty(),
        "a configuration that writes neither section reports neither"
    );
    cfg.plane_sections.insert("zz-unopened-red");
    cfg.plane_sections.insert("opened-at-boot-red");
    assert_eq!(
        rules.planes_awaiting_restart(&cfg),
        vec!["zz-unopened-red"],
        "the written section of a plane the boot left unopened, and never one it opened"
    );
    cfg.plane_sections.insert("aa-unopened-red");
    assert_eq!(
        rules.planes_awaiting_restart(&cfg),
        vec!["aa-unopened-red", "zz-unopened-red"],
        "sorted"
    );
    assert!(
        rules.check(&cfg).is_ok(),
        "awaiting restart is not a refusal: the configuration is accepted and stored"
    );
}

/// A FIRST SECTION OF AN UNLOADED PLANE IS REFUSED, NAMED (u67 BLOCK 2 item 2, ruled (iv);
/// BUSBAR-1.6.0.md Law 7 l.547 and §6 item 8 l.980-982): a document whose root keys use a plane
/// door the boot did not load (its verb, or a section it marks selecting) is refused with the one pinned
/// sentence naming the section and the plane, whatever the plane states; a document that uses none
/// is not. RED before the fix: no rule judged it, and the parse refused the section as an unknown
/// field without saying the plane was not loaded or what to do.
#[test]
fn a_first_section_of_an_unloaded_plane_is_refused_naming_the_section_and_the_plane() {
    use busbar_kernel::appbuild::RootRules as _;
    let door = crate::root::loader::boot::Candidate {
        kind: busbar_contract::abi::mechanism::KindCode::Plane,
        name: "zz-unloaded-red".to_string(),
        version: "1.0.0".to_string(),
        aliases: Vec::new(),
        sugar: Vec::new(),
        verbs: vec!["zz_tools_red".to_string()],
        selecting: vec!["zz_selects_red".to_string()],
        schemes: Vec::new(),
        needs: Vec::new(),
        stated: Vec::new(),
        origin: crate::root::loader::boot::Origin::Dropped {
            file: "zz-unloaded-red.tar.gz".to_string(),
            bytes: std::sync::Arc::new(Vec::new()),
        },
        disk: false,
        orders: true,
    };
    let rules = super::Rules::default();
    assert_eq!(
        rules.unloaded_plane_refusal(&["providers", "zz_tools_red"]),
        None,
        "nothing held, nothing refused"
    );
    rules.hold_unloaded(vec![door]);
    assert_eq!(
        rules.unloaded_plane_refusal(&["providers", "models", "store"]),
        None,
        "a document that uses no unloaded plane is not refused"
    );
    assert_eq!(
        rules
            .unloaded_plane_refusal(&["providers", "zz_tools_red"])
            .as_deref(),
        Some(
            "`zz_tools_red:` is the section of the `zz-unloaded-red` plane, which this process did \
             not load because its configuration did not use it at start; a first `zz_tools_red:` \
             cannot take effect on a running process, so the change was refused and nothing was \
             changed: write it in the config file and restart."
        ),
        "the pinned sentence, naming the section and the plane"
    );
    assert!(
        rules
            .unloaded_plane_refusal(&["zz_selects_red"])
            .is_some_and(
                |r| r.starts_with("`zz_selects_red:` is the section of the `zz-unloaded-red`")
            ),
        "a section that selects the plane uses it as its verb does"
    );
}

/// A REQUIRED CONSUMED SECTION WRITTEN EMPTY STILL OPENS ITS PLANE (ARCHITECT row-82 ruling: a
/// written consumed|required key counts). The previous release required `models:` and accepted it
/// empty (v1.5.5 crates/busbar/src/config/mod.rs:2626-2632), answering from its catch-all; the
/// oracle's `neutrality|models-empty|surface` cell is that document. A plane that requires the
/// section opens on the declaring section the root hands it, so `models: {}` must still hand it the
/// pair. RED: the pair was handed only when either map had an entry, so the plane stayed unopened
/// and every path fell to the kernel's catch-all.
#[test]
fn a_required_section_written_empty_hands_the_plane_its_sections() {
    use busbar_contract::section::{RESERVED_MODELS_KEY, RESERVED_POOLS_KEY};
    use busbar_kernel::plane_driver::registry::{PlaneDecl, PlaneDeclaration};
    use busbar_kernel::test_support::planes::TestRegistryIsolation;
    use busbar_kernel::test_support::NEUTRAL_FALLBACK;
    static REQUIRES: PlaneDecl = PlaneDecl {
        declaration: PlaneDeclaration {
            key: "requires-the-consumed-section",
            required_config_sections: &[RESERVED_MODELS_KEY],
            ..NEUTRAL_FALLBACK.declaration
        },
        ..NEUTRAL_FALLBACK
    };
    let _registry = TestRegistryIsolation::seeded(&[&REQUIRES]);
    let deploy = busbar_kernel::config::deploy_from_yaml_str("providers: {}\nmodels: {}\n")
        .expect("a deployment");
    let cfg = busbar_kernel::config::resolve(&deploy, &Default::default()).expect("resolves");
    let sections = super::kernel_sections(&cfg);
    assert_eq!(
        sections.get(RESERVED_MODELS_KEY),
        Some(&serde_yaml::Value::Mapping(Default::default())),
        "the written, empty required section is handed as written: {sections:?}"
    );
    assert_eq!(
        sections.get(RESERVED_POOLS_KEY),
        Some(&serde_yaml::Value::Mapping(Default::default())),
        "and the declaring section beside it, so the plane opens: {sections:?}"
    );
}

// ── the admission window (#29, admission side) ────────────────────────────────────────────────

/// THE DOOR'S ADMISSION CHECK READS THE ARRIVAL'S WINDOW, NOT THE CLOCK (#29, admission side).
/// Door successor of `plane_node.rs::the_admission_check_reads_the_arrival_window_and_not_the_clock`
/// (legacy `ingress_integration_tests.rs::test_admit_check_uses_charged_at_window_not_clock`,
/// coverage map row 381), on the `$` door of the plane serving the `pools` map (`DoorSteps::charge`,
/// handed the unit's arrival as `serve.rs` hands it `node.arrived()`). 1.5.5 behaviour, as the
/// original pinned it: a key's group holds one 1-cent fee a day, and that fee was already charged
/// into a PAST day; a unit arriving in that past day is refused over budget (429) against the
/// window it arrived in, where the spend lives; a unit arriving now, in today's empty window, is
/// admitted.
///
/// RED: the door's check keyed off a fresh clock read, admitting the past-day unit against today's
/// empty window (its charge overshooting the cap of the day it arrived in).
#[test]
fn the_doors_admission_check_reads_the_arrival_window_and_not_the_clock() {
    use busbar_kernel::config::groups::{LimitCfg, LimitMetric, LimitWindow};
    use busbar_kernel::governance::SECS_PER_DAY;
    use busbar_kernel::test_support::engine_kit::{EngineTestKit as _, CORE_ENGINE_KIT};
    // The original's `budget_per_day(FEE_CENTS)` at its `FEE_CENTS = 1` flat fee.
    let gov = CORE_ENGINE_KIT
        .governance(CORE_ENGINE_KIT.scratch_store(), None, None)
        .expect("governance");
    let groups = std::collections::BTreeMap::from([(
        "team".to_string(),
        busbar_kernel::config::groups::GroupCfg {
            parent: None,
            enabled: true,
            limits: vec![LimitCfg {
                metric: LimitMetric::Budget,
                amount: 1,
                per: Some(LimitWindow::Day),
                scope: None,
                on_exhaust: None,
                downgrade_to: None,
                admission: None,
                on_exhaustion: None,
            }],
            ..Default::default()
        },
    )]);
    let cost = CORE_ENGINE_KIT.cost_parts(None, 1, &groups);
    let (key, _secret) = gov
        .create_key(
            busbar_kernel::governance::NewKeySpec {
                name: "dev".to_string(),
                group: Some("team".to_string()),
                ..Default::default()
            },
            1_700_000_000,
        )
        .expect("a key");
    let app = busbar_kernel::test_support::TestApp::new()
        .governance_kit(gov)
        .keys_chain()
        .cost_kit(cost)
        .build();
    let key = std::sync::Arc::new(key);
    let gov = std::sync::Arc::clone(app.governance.as_ref().expect("a governed generation"));

    // The original's `EPOCH`.
    let past_day: u64 = 1_700_000_000;
    assert_ne!(
        past_day / SECS_PER_DAY,
        busbar_kernel::store::now() / SECS_PER_DAY,
        "precondition: the arrival day is not today"
    );
    gov.try_admit(&app.cost, &key, "", past_day)
        .expect("the first request fits the cap exactly");
    assert_eq!(
        gov.derived_bucket_usage(&app.cost, "group:team@day", "day", true, past_day)
            .expect("usage read")
            .spend_cents,
        1,
        "precondition: the arrival day's window is at its cap"
    );

    let pools = pools(DOWNGRADE_SECTION);
    let refused = charge_once_at(&app, &key, &pools, "frontier", 1, past_day);
    let reason = refused
        .admitted
        .map_err(|(reason, _)| reason)
        .expect_err("the unit is refused against the window it arrived in, where the spend lives");
    assert_eq!(reason, busbar_contract::caps::ReasonCode::OverBudget);
    assert_eq!(
        busbar_kernel::plane_driver::refusal_status(reason),
        429,
        "an over-budget refusal answers 429"
    );
    let admitted = charge_once_at(
        &app,
        &key,
        &pools,
        "frontier",
        2,
        busbar_kernel::store::now(),
    );
    assert_eq!(
        admitted.admitted,
        Ok(()),
        "today's window is empty, so a unit arriving now is admitted"
    );
}

/// LEGACY the retired engine crate's `src/unit/tests/verify.rs::asking_whether_a_name_is_configured_allocates_nothing`
/// (coordinator ruling 2026-10-17: no-alloc is a Law). ASKING WHETHER A NAME IS CONFIGURED ALLOCATES
/// NOTHING: the destination guard asks it on every request, so the probe answers from the door's
/// own pools and entries as they are held, never from a projection built per call. Eight pools, so
/// an answer that allocates per pool cannot hide in a slack bound, and both answers are asked: a
/// name that is a pool, one that is an entry, and one that is nothing, because a probe that
/// allocated only on the miss would still allocate on the request path.
///
/// Measured on jemalloc's per-thread allocated-bytes counter, the binary's own allocator.
/// RED: a probe that builds a list of the configured names to search allocates on every call.
#[cfg(not(target_env = "msvc"))]
#[test]
fn asking_whether_a_name_is_configured_allocates_nothing() {
    use busbar_kernel::door::PoolView as _;
    use tikv_jemalloc_ctl::thread as jethread;
    let mut yaml = String::from("m: {}\npools:\n");
    for i in 0..8 {
        yaml.push_str(&format!("  p{i}:\n    members: [m]\n"));
    }
    let p = pools(&yaml);
    let app = busbar_kernel::test_support::TestApp::new().build();
    let view = super::DoorPoolView {
        pools: &p,
        key: None,
        app: &app,
    };
    let allocated = || {
        jethread::allocatedp::read()
            .map(|m| m.get())
            .expect("jemalloc's per-thread counter reads")
    };
    // Warm the counter's own read before the measured window.
    let _ = allocated();
    let before = allocated();
    let pool = view.is_configured(std::hint::black_box("p3"));
    let entry = view.is_configured(std::hint::black_box("m"));
    let miss = view.is_configured(std::hint::black_box("nothing-by-that-name"));
    let after = allocated();
    assert!(pool, "p3 is a configured pool");
    assert!(entry, "m is a configured entry");
    assert!(!miss, "nothing by that name is configured");
    assert_eq!(
        after - before,
        0,
        "a membership probe on the request path allocates nothing"
    );
}

/// A plane's trust keys whose pin, under mechanism `peer`, pins the far end's key.
const PEER_KEY_PIN: &[busbar_contract::plane::TrustKeyDecl] =
    &[busbar_contract::plane::TrustKeyDecl {
        key: "pin",
        role: busbar_contract::plane::TrustRole::Pin,
        fingerprint: false,
        default: None,
        mechanisms: &[busbar_contract::plane::PinMechanismDecl {
            token: "peer",
            root: true,
            peer_key: true,
        }],
    }];

/// The anchors the host reads off registration `fs` writing `pin: {mechanism: peer, key: <key>}`.
fn peer_pinned(key: &str) -> Result<busbar_contract::transport::trust::Anchors, String> {
    let served = crate::root::loader::dispatch::kinds::plane::ServedFacts {
        section: "upstreams",
        trust_keys: PEER_KEY_PIN.to_vec(),
        ..Default::default()
    };
    let registration: serde_yaml::Value = serde_yaml::from_str(&format!(
        "url: 'https://far.example/x'\npin: {{mechanism: peer, key: '{key}'}}"
    ))
    .expect("yaml");
    super::registration_anchors(
        "fs",
        &registration,
        busbar_contract::conn::NeedId(0),
        &served,
        &busbar_kernel::config::secret::SecretResolver::builtins_only(),
    )
}

/// A REGISTRATION'S PEER-KEY PIN IS READ TO ITS CANONICAL SPELLING by the host: the documented
/// `sha256/<base64>` and its plain base64 alias seal the same pin. RED: a pin that names no digest
/// (a stand-in such as `sha256/BASE=`) refuses the load in these exact words, naming the
/// registration and the field and stating the form; the value itself is not echoed. Before, it was
/// sealed as written and every connection to the far end was refused.
#[test]
fn red_a_peer_key_pin_naming_no_digest_refuses_the_load_naming_the_field_and_its_form() {
    let canonical = busbar_contract::transport::trust::key_pin(b"a subject public key info");
    let plain = canonical
        .strip_prefix("sha256/")
        .expect("tagged")
        .to_owned();
    for written in [&canonical, &plain] {
        let anchors = peer_pinned(written).expect("a pin of one digest reads");
        assert_eq!(
            anchors.key_pin.as_deref(),
            Some(canonical.as_str()),
            "{written}"
        );
    }
    for bad in ["sha256/BASE=", "sha1/AAAA", "not a pin"] {
        let refused = peer_pinned(bad).expect_err("refused");
        assert_eq!(
            refused,
            "`upstreams.fs`: `pin.key:` is not a key pin. Write `sha256/<base64>`: the standard, \
             padded base64 of the 32-byte SHA-256 digest of the far end's certificate \
             SubjectPublicKeyInfo (the plain `<base64>` of the same digest is also accepted).",
            "{bad}"
        );
        assert!(!refused.contains(bad), "the value is not echoed: {refused}");
    }
}

/// LAW 7 (BUSBAR-1.6.0.md Part 1: a plugin loads iff config uses it; ARCHITECT ruling 2026-10-20
/// on root#7 / loader#9): serving one configured outbound style binds the one linked auth row that
/// states it, and no other. Which row states a style is read off each row's static Statement
/// (reading, not loading), never by binding every row to ask.
#[test]
fn serving_a_style_binds_only_the_linked_row_that_states_it() {
    let dispatcher = std::sync::Arc::new(crate::root::loader::dispatch::Dispatcher::new(
        crate::root::loader::dispatch::DispatchConfig::default(),
    ));
    let _ = dispatcher.lend_seal(busbar_kernel::seal::lend());
    let linked = crate::LINKED.auths;
    assert!(
        linked.len() > 1,
        "the default build links more than one auth row: {}",
        linked.len()
    );
    let auths = super::OutboundAuths::new(
        dispatcher,
        linked,
        None,
        crate::root::loader::dispatch::ConnTable::NoNeeds,
    );
    let served = auths
        .serving("bearer", &serde_json::json!({}))
        .expect("the serving row opens");
    assert!(served.is_some(), "a linked row states `bearer`");
    let bound = auths
        .bound
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .clone();
    assert_eq!(
        bound.len(),
        1,
        "only the row serving the style is bound, once: {bound:?}"
    );
}

/// RED BEFORE THE TAIL WAS RENDERED WHOLE (ARCHITECT ruling 2026-10-20 on root#7 / loader#9: the
/// canonical rendering carries the whole kind tail, and the signed manifest is the no-dlopen
/// source): a dropped-in auth row's outbound styles are read from its SIGNED MANIFEST's rendering,
/// with no `dlopen` and no bind. Here its library is not a library at all. Before, the rendering
/// stated the tail's size alone, so the row was loaded to learn which style it states, and a row
/// that would not load stated none.
#[test]
fn a_dropped_rows_styles_are_read_from_its_signed_manifest_with_no_library_load() {
    use crate::root::loader::dispatch::kinds::auth::stated_facts;
    use crate::root::loader::sign::{
        sign, Manifest, SigningKey, TrustPolicy, FIRST_PARTY_PUBLISHER,
    };
    // A linked auth row's door stating an outbound style: its rendering is what its pack signs.
    let (style, door) = crate::LINKED
        .auths
        .iter()
        .find_map(|&(_, _, door)| {
            let facts = stated_facts(door).ok()?;
            facts.styles.first().map(|s| (s.name.clone(), door))
        })
        .expect("the default build links an auth row stating an outbound style");
    let stated = crate::root::loader::dispatch::rendering_of(door).expect("the door states itself");
    let key = SigningKey::from_bytes(&[0x4d; 32]);
    let lib: &[u8] = b"not a library: a style read never opens it";
    let m = sign(
        &key,
        Manifest {
            name: "busbar-auth-dropped-styles".into(),
            alias: "dropped-styles".into(),
            kind: "auth".into(),
            version: "1.0.0".into(),
            publisher: FIRST_PARTY_PUBLISHER.into(),
            abi_version: crate::root::loader::supported_abi("auth")[0],
            statement: Some(hex::encode(stated)),
            ..Default::default()
        },
        lib,
    );
    let dir = std::env::temp_dir().join(format!(
        "busbar-root-dropped-styles-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_nanos())
    ));
    std::fs::create_dir_all(&dir).expect("a scratch plugins directory");
    std::fs::write(
        dir.join("dropped-styles.tar.gz"),
        crate::root::loader::tarball::package(&m, "lib.so", lib).expect("it packs"),
    )
    .expect("the tarball is written");
    let policy = TrustPolicy {
        first_party_keys: vec![crate::root::loader::sign::FirstPartyKey::unnamed(
            key.verifying_key(),
        )],
        ..Default::default()
    };
    let registry = crate::root::loader::scan_and_validate(&dir, &policy).expect("the row scans");
    let _ = std::fs::remove_dir_all(&dir);
    let registry: &'static crate::root::loader::PluginRegistry = Box::leak(Box::new(registry));
    let dispatcher = std::sync::Arc::new(crate::root::loader::dispatch::Dispatcher::new(
        crate::root::loader::dispatch::DispatchConfig::default(),
    ));
    let auths = super::OutboundAuths::new(
        dispatcher,
        &[],
        Some(registry),
        crate::root::loader::dispatch::ConnTable::NoNeeds,
    );
    let stating: Vec<String> = auths.stating(&style).map(|r| r.name.clone()).collect();
    assert_eq!(
        stating,
        vec!["busbar-auth-dropped-styles".to_string()],
        "the dropped-in row states `{style}` by its signed manifest"
    );
    let bound = auths
        .bound
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .clone();
    assert_eq!(bound, Vec::<String>::new(), "a style read binds no row");
}

/// RED (arch-audit u29 F1; Q128 ruling (a)): a credential is read for its own token endpoint by its
/// style's DECLARED bit (`STYLE_ENDPOINT_FROM_CREDENTIAL`, `from_credential` here), never by the
/// style's name. A style that does not state the bit, even one named `jwt-bearer`, is handed its
/// credential unread; any word stating it has the service account's `token_uri` read, judged under
/// the provider's metadata posture in 1.5.5's words over its own word, and set.
#[test]
fn a_credential_endpoint_is_read_by_the_styles_bit_never_its_name() {
    let account = |uri: &str| {
        format!(r#"{{"client_email":"sa@example.com","private_key":"k","token_uri":"{uri}"}}"#)
    };
    let route = provider("p", Some("jwt-bearer"));
    let good = account("https://oauth2.example.com/token");
    let unread = super::sealed_params("p", "jwt-bearer", false, &route, good.as_bytes())
        .expect("a style stating no bit is never read");
    assert_eq!(unread.token_uri, None, "named jwt-bearer, stating no bit");
    let read = super::sealed_params("p", "x-any-assertion", true, &route, good.as_bytes())
        .expect("a judged endpoint");
    assert_eq!(
        read.token_uri.as_deref(),
        Some("https://oauth2.example.com/token"),
        "any word stating the bit has its credential's endpoint read"
    );
    let plaintext = account("http://oauth2.example.com/token");
    let refused = super::sealed_params("p", "jwt-bearer", true, &route, plaintext.as_bytes())
        .expect_err("a public plaintext token_uri is refused");
    assert!(
        refused.starts_with(
            "provider 'p' (jwt-bearer auth): service-account token_uri must use https for a public host"
        ),
        "1.5.5's words over the style's own word: {refused}"
    );
}
