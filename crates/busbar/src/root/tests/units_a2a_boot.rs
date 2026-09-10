//! Tests for `units_a2a_boot.rs`. Lifted out of the implementation file so its line count measures
//! implementation and nothing else; still a direct child module, so `use super::*` reaches the
//! private items it always did.

use super::*;
use busbar_unit_auth::chain::KEYS_MODULE;
use busbar_unit_cost::nano_rate;

/// One configured agent, at whatever posture a cell wants to state.
fn agent(name: &str, allow_private: bool, approved: bool) -> DeclaredAgent {
    DeclaredAgent {
        name: name.to_string(),
        host: format!("{name}.example.com"),
        allow_private,
        approved,
    }
}

// ═════════════════════════════════════════════════════════════════════════════════════════════════
//   EVERY BOOT-RESOLVED VALUE HAS A SOURCE NAMED FOR IT
// ═════════════════════════════════════════════════════════════════════════════════════════════════

/// **Every source r31g named as unresolved has a row, and every row names a place.**
///
/// The finding's own acceptance test. The ten unresolved bindings plus the audience were invisible
/// exactly because nothing had to account for them — the leg was only ever built by tests, and a
/// test supplies whatever it likes. This table is the accounting, and this cell is what keeps it
/// from rotting into a comment that was true once.
#[test]
fn every_source_the_finding_named_has_a_row_that_names_a_place() {
    for owed in [
        "guard",
        "pinned",
        "breaker",
        "door",
        "groups",
        "rates",
        "store",
        "auth",
        "expected_aud",
        "key_scopes",
    ] {
        let row = BOOT_SOURCES
            .iter()
            .find(|(name, _)| *name == owed)
            .unwrap_or_else(|| panic!("`{owed}` had no boot resolution and still has no row"));
        assert!(
            !row.1.is_empty(),
            "`{owed}` has a row and nothing in it, which is the same as having no row"
        );
        assert!(
            row.1.contains("config ") || row.1.contains("root:") || row.1.contains("not a boot"),
            "`{owed}`'s row must name a configuration key or a composition-root value, not \
             describe one: got `{}`",
            row.1
        );
    }
}

/// **And no row invents a configuration key.**
///
/// Every `config` row names a key this deployment's grammar already has. A row naming a key nobody
/// can write is a source that does not exist, dressed as one that does.
#[test]
fn no_row_names_a_configuration_key_this_grammar_does_not_have() {
    // The sections this deployment's grammar has, and which a row is allowed to name. A row that
    // said `config` and named something outside this list would be a source that does not exist,
    // dressed as one that does.
    const SECTIONS: &[&str] = &[
        "agents",
        "security.",
        "pools",
        "groups",
        "rate_card",
        "auth.chain",
        "public_url",
    ];
    let mut from_config = 0;
    for (name, where_) in BOOT_SOURCES {
        if !where_.starts_with("config ") {
            continue;
        }
        from_config += 1;
        assert!(
            SECTIONS.iter().any(|section| where_.contains(section)),
            "`{name}` says it comes from configuration and names no section of it: `{where_}`"
        );
    }
    assert!(
        from_config >= 5,
        "most of what this file resolves comes from configuration; a cell that walked one or two \
         rows would pass for a table that had stopped naming keys"
    );
}

// ═════════════════════════════════════════════════════════════════════════════════════════════════
//   THE GUARD FOLDS TO THE NARROWEST, NEVER THE WIDEST
// ═════════════════════════════════════════════════════════════════════════════════════════════════

/// **One agent kept off private addresses keeps the WHOLE leg off them.**
///
/// RED FIRST, and the red is the reason the fold goes this way. The leg carries ONE guard, because
/// the plane's destination facts do not yet name which agent a unit reaches. A fold that allowed
/// private when ANY agent did would let a request bound for an agent the operator deliberately kept
/// on the public internet reach a private address — an SSRF the configuration explicitly refused,
/// arrived at by a composition nobody looked at.
#[test]
fn one_agent_kept_off_private_addresses_keeps_the_whole_leg_off_them() {
    let mixed = [
        agent("internal", true, false),
        agent("partner", false, false),
    ];
    assert!(
        !narrowest_guard(&mixed).allow_private,
        "a leg-wide guard may not be looser than any agent's own configuration"
    );
}

/// **And a deployment whose every agent was told it could still gets it.**
///
/// The other half: a fold that refused everything would be a leg that cannot serve the deployment
/// the operator configured, which is a different failure and just as real.
#[test]
fn a_deployment_whose_every_agent_allows_private_gets_it() {
    let all = [agent("one", true, false), agent("two", true, false)];
    assert!(narrowest_guard(&all).allow_private);
}

/// **A deployment with NO agents allows nothing.**
///
/// The vacuous-truth trap, written down. "Every agent allows it" is true of no agents at all, and a
/// fold that stopped at the `all` would open the guard widest on exactly the deployment that
/// configured nothing.
#[test]
fn a_deployment_with_no_agents_allows_no_private_address() {
    assert!(!narrowest_guard(&[]).allow_private);
}

/// **The guard's other three bounds are not read off an agent.**
///
/// A redirect budget, a body cap and a timeout are properties of a FETCH, not of who is being
/// fronted; taking them from an agent entry would be inventing three configuration keys.
#[test]
fn the_guards_other_bounds_are_the_units_own() {
    let folded = narrowest_guard(&[agent("one", true, false)]);
    let declared = GuardPolicy::default();
    assert_eq!(folded.max_redirects, declared.max_redirects);
    assert_eq!(folded.max_body_bytes, declared.max_body_bytes);
    assert_eq!(folded.allow_plaintext, declared.allow_plaintext);
}

// ═════════════════════════════════════════════════════════════════════════════════════════════════
//   THE PIN LIST IS THE AGENTS WITH AN APPROVED FINGERPRINT
// ═════════════════════════════════════════════════════════════════════════════════════════════════

/// **An agent whose declared pin carries no fingerprint is NOT on the approved list.**
///
/// The distinction the pin module already makes and this composition must not lose: every agent
/// declares a trust root, and what makes one APPROVED is a fingerprint under it. A list that took
/// every agent with a `pin:` block would report a deployment as having approved every agent it
/// merely registered.
#[test]
fn only_an_agent_with_an_approved_fingerprint_is_pinned() {
    let agents = [
        agent("approved", false, true),
        agent("declared-only", false, false),
    ];
    assert_eq!(approved_pins(&agents), vec!["approved".to_string()]);
}

/// **And the list keeps configuration's own order.**
#[test]
fn the_pin_list_is_in_configuration_order() {
    let agents = [
        agent("zeta", false, true),
        agent("alpha", false, true),
        agent("mid", false, false),
    ];
    assert_eq!(
        approved_pins(&agents),
        vec!["zeta".to_string(), "alpha".to_string()]
    );
}

// ═════════════════════════════════════════════════════════════════════════════════════════════════
//   AN AGENT'S ADDRESS IS REDUCED TO ITS HOST
// ═════════════════════════════════════════════════════════════════════════════════════════════════

/// **The host of a declared address is the host, whatever else the operator wrote around it.**
///
/// The guard and the pool view work in hosts: a scheme is how to speak to an address and a port is
/// where, and neither is part of who. A registration carrying `https://agent.example.com:8443/rpc`
/// as its host would be a registration nothing ever matches — and an unmatched registration reads,
/// everywhere, as an agent this deployment does not have.
#[test]
fn an_agents_address_is_reduced_to_its_host() {
    for (declared, host) in [
        ("https://agent.example.com", "agent.example.com"),
        ("https://agent.example.com/", "agent.example.com"),
        ("https://agent.example.com:8443", "agent.example.com"),
        (
            "https://agent.example.com:8443/a2a/rpc",
            "agent.example.com",
        ),
        ("http://user:pass@agent.example.com/x", "agent.example.com"),
        ("agent.example.com", "agent.example.com"),
    ] {
        assert_eq!(host_of(declared), host, "`{declared}` names `{host}`");
    }
}

// ═════════════════════════════════════════════════════════════════════════════════════════════════
//   THE DOOR THIS DEPLOYMENT CONFIGURED
// ═════════════════════════════════════════════════════════════════════════════════════════════════

/// **A deployment that named no authentication position resolves the open door it asked for.**
#[test]
fn a_deployment_that_named_no_position_gets_the_door_it_configured() {
    assert!(chain_positions(&[]).is_empty());
    assert!(data_chain(&[])
        .expect("naming nothing is a posture, not a missing source")
        .is_open());
}

/// **And every named position travels to the builder with BOTH halves.**
///
/// The provider name and the module are two different things — two named providers may share one
/// module, and the NAME is the identity role bindings bind and scope ceilings key off. A composition
/// that carried only one of them would admit or refuse under an identity nobody wrote.
#[test]
fn a_named_position_travels_with_its_provider_and_its_module() {
    let declared = [
        config::AuthChainEntry::bare(KEYS_MODULE),
        config::AuthChainEntry::bare("corporate-idp"),
    ];
    assert_eq!(
        chain_positions(&declared),
        vec![
            ("keys".to_string(), "keys".to_string()),
            ("corporate-idp".to_string(), "corporate-idp".to_string()),
        ]
    );
}

/// **A configured position this composition cannot honour REFUSES the whole read.**
///
/// The end-to-end of the refusal, over the projection this file performs: a plugin-backed provider
/// is opened by the engine's own signed-plugin loader against its own registry, which the composed
/// leg reaches neither of. Dropping it would leave the deployment looking authenticated.
#[test]
fn a_position_this_composition_cannot_honour_refuses_the_read() {
    let declared = [config::AuthChainEntry::bare("corporate-idp")];
    let positions = chain_positions(&declared);
    let refusal = data_chain(
        &positions
            .iter()
            .map(|(provider, module)| ChainPosition { provider, module })
            .collect::<Vec<_>>(),
    )
    .expect_err("this composition has no module for that provider");
    assert!(format!("{refusal}").contains("corporate-idp"));
}

// ═════════════════════════════════════════════════════════════════════════════════════════════════
//   THE METER READS CONFIGURATION, NEVER A DEFAULT
// ═════════════════════════════════════════════════════════════════════════════════════════════════

/// **A configured pool reaches the metering policy with its lanes.**
///
/// The default this exists to refuse: an empty lane expansion turns the usage unit's set-membership
/// test into an equality test, and the symptom is a disputed posting rather than anything that names
/// the pool.
#[test]
fn a_configured_pool_reaches_the_metering_policy_with_its_lanes() {
    let mut expansions = BTreeMap::new();
    expansions.insert(
        "fast".to_string(),
        vec!["one".to_string(), "two".to_string()],
    );
    let built = meter_config(&expansions, &BTreeMap::new());
    assert_eq!(built.pools.len(), 1);
    assert_eq!(built.pools[0].pool, "fast");
    assert_eq!(
        built.pools[0].lanes,
        vec!["one".to_string(), "two".to_string()]
    );
}

/// **And a configured rate card reaches it as a comparable price per lane.**
///
/// The price is read for ONE thing — choosing the cheaper entry when the cross-check's three legs
/// disagree — so what it has to be is an ordering, and the arithmetic that produces it is the cost
/// unit's own conversion rather than a multiplication written here.
#[test]
fn a_configured_rate_card_reaches_the_metering_policy_as_a_price_per_lane() {
    let mut prices = BTreeMap::new();
    prices.insert("one".to_string(), 3.0);
    let built = meter_config(&BTreeMap::new(), &prices);
    assert_eq!(built.prices.len(), 1);
    assert_eq!(built.prices[0].lane, "one");
    assert_eq!(built.prices[0].price, u128::from(nano_rate(3.0)));
}

/// **Two boots on one configuration build ONE policy.**
///
/// The `pools:` section is a hashed map, so a policy built in iteration order is the same value
/// reached two ways — which is true, and is exactly the kind of true that stops being true the day
/// something downstream compares two boots. The projection sorts, and this is what says so.
#[test]
fn two_boots_on_one_configuration_build_one_metering_policy() {
    let mut expansions = BTreeMap::new();
    for name in ["zeta", "alpha", "mid"] {
        expansions.insert(name.to_string(), Vec::new());
    }
    let first = meter_config(&expansions, &BTreeMap::new());
    let second = meter_config(&expansions, &BTreeMap::new());
    assert_eq!(first.pools, second.pools);
    assert_eq!(
        first
            .pools
            .iter()
            .map(|p| p.pool.as_str())
            .collect::<Vec<_>>(),
        vec!["alpha", "mid", "zeta"],
        "the expansions are in name order, so one configuration is one policy on every boot"
    );
}

// ═════════════════════════════════════════════════════════════════════════════════════════════════
//   THE BREAKER IS ONE SET OF CELLS, READ AT TWO WIDTHS
// ═════════════════════════════════════════════════════════════════════════════════════════════════

/// The node's breaker cells, with a stated number of candidates in this plane's pool.
fn lanes_over(count: usize) -> AgentLanes {
    AgentLanes {
        adapter: crate::root::adapters::BreakerAdapter::with_diagnostics(
            crate::root::adapters::root_diagnostics(),
            crate::root::adapters::BreakerPolicy::new(),
        ),
        lanes: count,
    }
}

/// **A lane index outside this deployment's candidate list is REFUSED, not answered.**
///
/// The trust unit indexes a pool's candidates by position, and a position past the end names a
/// destination this deployment does not have. Answering `true` for it would admit a unit toward a
/// destination nobody configured; answering from the breaker's cells for it would be reading a cell
/// that belongs to no agent.
#[test]
fn a_lane_outside_this_deployments_candidates_is_refused() {
    use busbar_unit_trust::lane::BreakerView as _;
    let lanes = lanes_over(2);
    assert!(lanes.ready("agents", 0, 0));
    assert!(lanes.ready("agents", 1, 0));
    assert!(
        !lanes.ready("agents", 2, 0),
        "a third lane is a destination this deployment does not have"
    );
    assert!(lanes.try_admit("agents", 2, 0).is_err());
}

/// **A deployment with no agents admits nothing.**
#[test]
fn a_deployment_with_no_agents_admits_no_lane() {
    use busbar_unit_trust::lane::BreakerView as _;
    assert!(!lanes_over(0).ready("agents", 0, 0));
}

/// **The admission takes no half-open probe.**
///
/// The trait's own words are that `try_admit` is where a probe is actually taken. Taking one here
/// would spend a half-open budget the dispatch below is about to spend again — two dispatches'
/// worth of probe for one request, and a lane that reads recovered because the loop probed it rather
/// than because anything succeeded. So it answers from the same reading `ready` does, and this cell
/// is what says the two agree.
#[test]
fn the_admission_answers_from_the_same_reading_the_peek_does() {
    use busbar_unit_trust::lane::BreakerView as _;
    let lanes = lanes_over(1);
    for lane in 0..3 {
        assert_eq!(
            lanes.ready("agents", lane, 0),
            lanes.try_admit("agents", lane, 0).is_ok(),
            "lane {lane}: the peek and the admission are one reading of one set of cells"
        );
    }
}
