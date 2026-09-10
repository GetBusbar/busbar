//! Tests for `pool_hydration.rs`. Lifted out of the implementation file so its line count measures
//! implementation and nothing else; still a direct child module, so `use super::*` reaches the
//! private items it always did.

use super::*;
use busbar_substrate::plane_host::{
    AuthStyleInput, ClientSettingsInput, EngineTablesView, LaneInput, PlaneBuildInput,
};

/// A lane as a boot fixture declares one: named, pointed somewhere, and carrying the two facts the
/// pool reads off it.
fn lane(model: &str, context_max: Option<usize>) -> LaneInput {
    LaneInput {
        model: model.to_string(),
        provider: "acme".to_string(),
        // A protocol this build declares, asked of the declarations rather than spelled: which
        // dialect a lane speaks is nothing the hydration reads, so a fixture that named one would
        // be pinning this cell to a dialect set that has changed twice already.
        protocol: busbar_llm::DECLS[0].name.to_string(),
        base_url: "https://upstream.invalid".to_string(),
        path: None,
        path_base: None,
        upstream_model: None,
        api_key: busbar_api::Redacted::new(String::new()),
        auth_style: AuthStyleInput::Default,
        scope: None,
        token_url: None,
        subject: None,
        error_map: std::collections::HashMap::new(),
        health: None,
        allow_metadata_hosts: Vec::new(),
        context_max,
        lane_default_max_tokens: None,
        attempt_timeout_ms: None,
        reasoning: false,
        prompt_caching: false,
        max_concurrent: 8,
        limited: false,
        budget: -1,
    }
}

/// A pool member as a boot fixture declares one.
fn member(
    model: &str,
    lane_idx: usize,
    weight: u32,
    attempt_timeout_ms: Option<u64>,
) -> PoolMemberInput {
    PoolMemberInput {
        model: model.to_string(),
        lane_idx,
        weight,
        reasoning: None,
        attempt_timeout_ms,
        tier: None,
        cost_per_mtok: None,
        tags: Vec::new(),
    }
}

/// THE BOOT FIXTURE: three lanes, two configured pools with different memberships, orders,
/// weights, terminals and blocklists, and one lane that belongs to no pool at all.
///
/// Every axis the hydration reads is varied at least once, because an equality over a fixture that
/// exercises one shape proves the hydration for that shape and nothing else. The second pool's
/// members are declared in the reverse of the lane table's order on purpose: a hydration that
/// sorted rather than read across would agree with the plane's lowering on the first pool and
/// disagree on the second.
fn boot_fixture() -> PlaneBuildInput {
    PlaneBuildInput {
        lanes: vec![
            lane("fast", Some(8_192)),
            lane("slow", Some(200_000)),
            lane("solo", None),
        ],
        pools: vec![
            PoolInput {
                name: "primary".to_string(),
                members: vec![
                    member("fast", 0, 7, None),
                    member("slow", 1, 3, Some(1_500)),
                ],
                failover: Some(FailoverInput {
                    timeout_secs: 45,
                    exclusions: Some(vec!["slow".to_string()]),
                    max_hops: 1,
                }),
                affinity: None,
                on_exhausted: OnExhaustedInput::Queue { max_ms: 2_000 },
                upstream_credentials: None,
                breaker: None,
            },
            PoolInput {
                name: "spill".to_string(),
                members: vec![member("slow", 1, 1, None), member("fast", 0, 1, None)],
                failover: None,
                affinity: None,
                on_exhausted: OnExhaustedInput::FallbackPool("primary".to_string()),
                upstream_credentials: None,
                breaker: None,
            },
        ],
        upstream_credentials: busbar_api::UpstreamCreds::default(),
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

/// A lane-name seater for a cell: leaks, once per distinct name, exactly as the root's own interner
/// does at boot. A test binary that interned a name per assertion would grow without bound; this
/// one holds what it seated, so the same name comes back as the same pointer.
fn seater() -> impl FnMut(&str) -> &'static str {
    let mut seen: std::collections::HashMap<String, &'static str> =
        std::collections::HashMap::new();
    move |name: &str| {
        *seen
            .entry(name.to_string())
            .or_insert_with(|| Box::leak(name.to_string().into_boxed_str()))
    }
}

/// The plane's own lowering of the same fixture, projected through the neutral tables view.
///
/// Driven through the plane's DECLARED build and view pointers rather than through anything this
/// root reimplements: the fixture goes in as the same carrier a boot hands over, the plane builds
/// the tables it would build at boot, and what comes back is the neutral projection the scrape and
/// discovery readers already consult. So the comparison below is against the shipping lowering,
/// not against a second reading of the same document by the same author.
fn plane_view<R>(input: &PlaneBuildInput, read: impl FnOnce(&dyn EngineTablesView) -> R) -> R {
    let build = busbar_llm::PLANE_DECL
        .build_runtime
        .expect("the llm plane declares its own runtime build");
    let view = busbar_llm::PLANE_DECL
        .viewer
        .expect("the llm plane declares its own tables view");
    let slot = build(input as &dyn std::any::Any, None);
    read(view(&*slot))
}

/// THE IDENTITY. Every configured pool in the boot fixture, hydrated for the egress unit, holds
/// exactly the members the plane's own lowering holds — same pools, same order within each pool,
/// same lane behind each member, same weight on each member.
///
/// This is the claim the next landing rests its whole byte-identity argument on: if the table the
/// unit walks is not the candidate set the shipping resolution yields, then every difference after
/// the swap is a difference in the pool and none of them is bisectable. Stated here, over the
/// plane's real lowering, so the claim is checked rather than asserted in prose.
#[test]
fn every_configured_pool_hydrates_to_the_candidate_set_the_plane_lowers() {
    let input = boot_fixture();
    let mut seat = seater();
    let table = hydrate(&input, &mut seat);

    plane_view(&input, |view| {
        let lowered: Vec<(String, Vec<usize>)> = view
            .pools()
            .into_iter()
            .map(|(name, members)| (name.to_string(), members))
            .collect();
        assert_eq!(
            lowered.len(),
            table.len(),
            "the hydration and the plane's lowering must hold the same number of pools"
        );

        for (name, _) in &lowered {
            let hydrated = table
                .get(name)
                .unwrap_or_else(|| panic!("the hydration holds no pool named '{name}'"));
            let lowered_members = view.pool_members(name);

            assert_eq!(
                hydrated
                    .members
                    .iter()
                    .map(|m| (lane_of_destination(m.destination), m.weight))
                    .collect::<Vec<_>>(),
                lowered_members,
                "pool '{name}': the hydrated membership must be the lowered membership, in order"
            );

            for (position, m) in hydrated.members.iter().enumerate() {
                let idx = lane_of_destination(m.destination);
                let lane = view
                    .lane_view(idx)
                    .unwrap_or_else(|| panic!("pool '{name}' member {position} names no lane"));
                assert_eq!(
                    m.name, lane.model,
                    "pool '{name}' member {position}: the member's own name must be the lane it \
                     resolves to, which is what a blocklist and a diagnostic say"
                );
            }
        }
    });
}

/// The per-member and per-pool settings the membership equality above does not reach: the member's
/// own attempt cap, the lane's context window, the walk's bound, the blocklist and the terminal.
///
/// Separate from the identity cell on purpose. That one is about WHICH members and in WHAT ORDER,
/// which is the half a divergence would be unbisectable without; this one is about what the walk
/// over them reads, which is the half that decides how long it runs and where it goes when it
/// cannot.
#[test]
fn a_pools_own_settings_cross_into_the_table_it_hydrates() {
    let input = boot_fixture();
    let mut seat = seater();
    let table = hydrate(&input, &mut seat);

    let primary = table.get("primary").expect("the fixture declares it");
    assert_eq!(primary.failover.timeout_secs, 45);
    assert_eq!(primary.failover.max_hops, 1);
    assert_eq!(
        primary.failover.exclusions,
        vec!["slow".to_string()],
        "a pool's own blocklist names its members by the name the member carries"
    );
    assert_eq!(
        primary.on_exhausted,
        OnExhausted::Queue { max_ms: 2_000 },
        "the terminal is the operator's, arm for arm"
    );
    assert_eq!(
        primary.members[1].attempt_timeout_ms,
        Some(1_500),
        "a member's own attempt cap overrides its lane's"
    );
    assert_eq!(
        primary.members[0].context_max,
        Some(8_192),
        "the context window is the LANE's fact, read across onto every pool that has the lane"
    );

    let spill = table.get("spill").expect("the fixture declares it");
    assert_eq!(
        (spill.failover.timeout_secs, spill.failover.max_hops),
        (120, 3),
        "a pool declaring no failover block takes the deployment-wide default the carrier holds"
    );
    assert!(
        spill.failover.exclusions.is_empty(),
        "a pool declaring no blocklist blocks nobody"
    );
    assert_eq!(
        spill.on_exhausted,
        OnExhausted::FallbackPool("primary".to_string())
    );
}

/// A destination that names no configured pool routes on the cell with no name, over the one lane
/// it names, at weight one — which is the shipping resolution's second arm, and the reason the
/// default cell is a pool the caller asks for rather than a row in the table.
#[test]
fn a_bare_destination_hydrates_to_the_default_cell_over_its_one_lane() {
    let input = boot_fixture();
    let mut seat = seater();

    let cell = default_cell_for(&input, "solo", &mut seat).expect("the fixture declares the lane");
    assert_eq!(cell.name, DEFAULT_CELL);
    assert_eq!(cell.members.len(), 1);
    assert_eq!(cell.members[0].destination, destination_of_lane(2));
    assert_eq!(cell.members[0].weight, 1);
    assert_eq!(cell.members[0].name, "solo");

    plane_view(&input, |view| {
        assert_eq!(
            view.model_index("solo"),
            Some(lane_of_destination(cell.members[0].destination)),
            "the default cell's one member must be the lane the plane's own direct-model index \
             resolves the same name to"
        );
    });

    assert!(
        default_cell_for(&input, "nobody-declared-this", &mut seat).is_none(),
        "a destination nobody configured is an absence, never a pool with no members"
    );
}
