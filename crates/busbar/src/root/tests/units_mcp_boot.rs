//! Tests for `units_mcp_boot.rs`. Lifted out of the implementation file so its line count measures
//! implementation and nothing else; still a direct child module, so `use super::*` reaches the
//! private items it always did.

use super::*;

/// One configured server, at whatever posture a cell wants to state.
fn server(name: &str, allow_private: bool, spawns_child: bool) -> DeclaredServer {
    DeclaredServer {
        name: name.to_string(),
        host: if spawns_child {
            String::new()
        } else {
            format!("{name}.example.com")
        },
        allow_private,
        spawns_child,
    }
}

// ═════════════════════════════════════════════════════════════════════════════════════════════════
//   EVERY BOOT-RESOLVED VALUE HAS A SOURCE NAMED FOR IT
// ═════════════════════════════════════════════════════════════════════════════════════════════════

/// **Every binding the leg refuses boot over has a row here that names a place.**
///
/// The finding's own acceptance test. The leg's eighteen bindings were invisible exactly because
/// nothing had to account for them — the leg was only ever built by tests, and a test supplies
/// whatever it likes. This table is the accounting, and this cell is what keeps it from rotting into
/// a comment that was true once.
#[test]
fn every_source_the_leg_refuses_boot_over_has_a_row_that_names_a_place() {
    for owed in [
        "servers",
        "guard",
        "denylist",
        "breaker",
        "door",
        "groups",
        "pricer",
        "meter_policy",
        "scope_policy",
        "store",
        "auth",
        "auth_bindings",
        "durability",
        "chain",
        "key_scopes",
        "audience",
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
            row.1.contains("config ")
                || row.1.contains("root:")
                || row.1.contains("not a boot")
                || row.1.contains("NOT SOURCED"),
            "`{owed}`'s row must name a configuration key or a composition-root value, not \
             describe one: got `{}`",
            row.1
        );
    }
}

/// **Every binding the LEG names has a boot row, and the two tables cannot drift apart.**
///
/// The leg's `SOURCES` is one row per field of `McpBindings` and says where each WOULD come from;
/// this file's table says what the composition root actually goes and gets. A binding the leg
/// refuses boot over with nothing here to resolve it is a node that will not start, discovered by an
/// operator rather than by this cell.
///
/// The four the leg names and this file does not resolve are named here, each with the reason it is
/// not a boot value: they are per-ARRIVAL facts or the request's own coordinates, decided when a
/// request exists and not before.
#[test]
fn every_binding_the_leg_names_is_either_resolved_here_or_named_as_per_arrival() {
    // Decided when an arrival exists, not at boot: what the bytes are, when they landed, which
    // registration they name, the seam the answer goes back through, and the seal the kernel mints.
    const PER_ARRIVAL: &[&str] = &[
        "plane", "pools", "kinds", "prices", "records", "pool", "at", "dispatch", "origin",
    ];
    for (field, _) in crate::root::units_mcp_leg::SOURCES {
        let resolved = BOOT_SOURCES.iter().any(|(name, _)| name == field);
        assert!(
            resolved || PER_ARRIVAL.contains(field),
            "the leg refuses boot over `{field}` and nothing in this file resolves it, and it is \
             not named as a per-arrival fact either"
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
        "tools",
        "security.",
        "pools",
        "groups",
        "rate_card",
        "auth.chain",
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
        from_config >= 4,
        "most of what this file resolves comes from configuration; a cell that walked one or two \
         rows would pass for a table that had stopped naming keys"
    );
}

// ═════════════════════════════════════════════════════════════════════════════════════════════════
//   THE GUARD FOLDS TO THE NARROWEST, NEVER THE WIDEST
// ═════════════════════════════════════════════════════════════════════════════════════════════════

/// **One server kept off private addresses keeps the WHOLE leg off them.**
///
/// RED FIRST, and the red is the reason the fold goes this way. The leg carries ONE guard, because
/// the plane's destination facts do not yet name which server a unit reaches. A fold that allowed
/// private when ANY server did would let a request bound for a server the operator deliberately kept
/// on the public internet reach a private address — an SSRF the configuration explicitly refused,
/// arrived at by a composition nobody looked at.
#[test]
fn one_server_kept_off_private_addresses_keeps_the_whole_leg_off_them() {
    let mixed = [
        server("internal", true, false),
        server("partner", false, false),
    ];
    assert!(
        !narrowest_guard(&mixed).allow_private,
        "a leg-wide guard may not be looser than any server's own configuration"
    );
}

/// **And a deployment whose every dialled server was told it could still gets it.**
///
/// The other half: a fold that refused everything would be a leg that cannot serve the deployment
/// the operator configured, which is a different failure and just as real.
#[test]
fn a_deployment_whose_every_server_allows_private_gets_it() {
    let all = [server("one", true, false), server("two", true, false)];
    assert!(narrowest_guard(&all).allow_private);
}

/// **A deployment with NO servers allows nothing.**
///
/// The vacuous-truth trap, written down. "Every server allows it" is true of no servers at all, and
/// a fold that stopped at the `all` would open the guard widest on exactly the deployment that
/// configured nothing.
#[test]
fn a_deployment_with_no_servers_allows_no_private_address() {
    assert!(!narrowest_guard(&[]).allow_private);
}

/// **A SPAWNED registration does not vote on the guard, in either direction.**
///
/// RED FIRST, and it is the one place this fold differs from the sibling plane's. `allow_private:`
/// is a statement about an ADDRESS and this plane has registrations with none — the grammar refuses
/// a spawning transport a `url:` outright. Counting one in would let a child process the operator
/// left at the key's default close the guard for the dialled servers beside it, on a value that
/// governs no hop of its own; and the mirror of that, a deployment of nothing but child processes,
/// would read as "every server allows it" and open the guard widest on a set with no address in it.
#[test]
fn a_spawned_registration_does_not_vote_on_the_guard() {
    let dialled_open_child_default = [
        server("dialled", true, false),
        server("launched", false, true),
    ];
    assert!(
        narrowest_guard(&dialled_open_child_default).allow_private,
        "a child process carries no address, so its `allow_private:` may not narrow a dialled \
         server's"
    );

    let only_children = [server("one", true, true), server("two", true, true)];
    assert!(
        !narrowest_guard(&only_children).allow_private,
        "a deployment with no dialled server has nothing to allow, and `all of none` is exactly \
         the reading that would open the guard widest"
    );
}

/// **The guard's other three bounds are not read off a registration.**
///
/// A redirect budget, a body cap and a timeout are properties of a FETCH, not of who is being
/// reached; taking them from a `tools.<name>` entry would be inventing three configuration keys.
#[test]
fn the_guards_other_bounds_are_the_units_own() {
    let folded = narrowest_guard(&[server("one", true, false)]);
    let declared = GuardPolicy::default();
    assert_eq!(folded.max_redirects, declared.max_redirects);
    assert_eq!(folded.max_body_bytes, declared.max_body_bytes);
    assert_eq!(folded.allow_plaintext, declared.allow_plaintext);
}

// ═════════════════════════════════════════════════════════════════════════════════════════════════
//   A REGISTRATION'S ADDRESS IS REDUCED TO ITS HOST
// ═════════════════════════════════════════════════════════════════════════════════════════════════

/// **The host of a declared address is the host, whatever else the operator wrote around it.**
///
/// The guard and the pool view work in hosts: a scheme is how to speak to an address and a port is
/// where, and neither is part of who. A registration carrying `https://mcp.example.com:8443/rpc` as
/// its host would be a registration nothing ever matches — and an unmatched registration reads,
/// everywhere, as a server this deployment does not have.
#[test]
fn a_registrations_address_is_reduced_to_its_host() {
    for (declared, host) in [
        ("https://mcp.example.com", "mcp.example.com"),
        ("https://mcp.example.com/", "mcp.example.com"),
        ("https://mcp.example.com:8443", "mcp.example.com"),
        ("https://mcp.example.com:8443/mcp", "mcp.example.com"),
        ("http://user:pass@mcp.example.com/x", "mcp.example.com"),
        ("mcp.example.com", "mcp.example.com"),
    ] {
        assert_eq!(host_of(declared), host, "`{declared}` names `{host}`");
    }
}

// ═════════════════════════════════════════════════════════════════════════════════════════════════
//   THE CARRIER A REGISTRATION IS REACHED OVER IS ONE THIS PLANE DECLARES
// ═════════════════════════════════════════════════════════════════════════════════════════════════

/// **Both carriers this composition can name are ones the plane's own claim table declares.**
///
/// The arrival step refuses a unit whose transport no claim of this plane declares, so a
/// registration built on a carrier outside the table is a server nothing could ever answer from —
/// and the boot seal refuses exactly that, by name. This cell is the same promise on the way in.
#[test]
fn every_carrier_this_composition_names_is_one_the_plane_declares() {
    for spawns_child in [false, true] {
        let named = carrier(spawns_child);
        assert!(
            busbar_plane_mcp::claims::CLAIMS
                .iter()
                .any(|claim| claim.transport == named),
            "`{named}` is not a carrier this plane's claim table declares"
        );
    }
}

/// **A registration this node LAUNCHES is not reached over the network, and one it dials is.**
///
/// The absent-`transport:` reading is the config grammar's own — it validates such an entry as a
/// network registration — so a composition that read it the other way would build a registration
/// validated as one kind and reached as another.
#[test]
fn a_launched_registration_and_a_dialled_one_are_reached_over_different_carriers() {
    assert_eq!(carrier(true), busbar_plane_mcp::claims::TRANSPORT_STDIO);
    assert_eq!(carrier(false), busbar_plane_mcp::claims::TRANSPORT_HTTP);
    assert_ne!(carrier(true), carrier(false));
}

/// **A registration this node launches carries no host.**
///
/// The plane's own registration shape documents the empty string for exactly this case. Reading a
/// `url:` for it would key a network fact by an address no deployment configured — and the grammar
/// refuses a spawning entry a `url:` at all, so there would be nothing there to read.
#[test]
fn a_launched_registration_carries_no_host() {
    assert!(server("launched", false, true).host.is_empty());
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
        config::AuthChainEntry::bare(busbar_unit_auth::chain::KEYS_MODULE),
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
    assert_eq!(
        built.prices[0].price,
        u128::from(busbar_unit_cost::nano_rate(3.0))
    );
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
//   THE MONEY IS THE NODE'S ONE APPLY, NEVER A FIGURE THIS FILE READ
// ═════════════════════════════════════════════════════════════════════════════════════════════════

/// **The price an arriving unit is admitted against comes from the card holder, or it is absent.**
///
/// The two arms, and both of them matter. Before the boot's own rate resolution has happened there
/// is no apply to take a price from, and the honest answer is nothing at all — which the leg's
/// assembly refuses by name. The alternative is the failure this cell exists against: a zero fee
/// supplied here is a deployment served at a price nobody wrote down, and it boots clean.
///
/// It is deliberately not a read of a configured fee. The construction gate names the two crates
/// that may read one, and neither of them is the composition root.
#[test]
fn the_admission_price_is_the_holders_or_it_is_absent() {
    match crate::root::kernel::ROOT_CARD.pin_rates() {
        None => assert!(
            pricer().is_none(),
            "with no apply in place there is no price, and inventing one here would serve this \
             deployment at a fee nobody configured"
        ),
        Some(_) => assert!(
            pricer().is_some(),
            "an apply is in place and the door must price against the same one the card came from"
        ),
    }
}

/// **The row that says where it comes from names the holder and not a config key.**
///
/// The table is the reviewable half of the rule above: a row that named `per_request_fee` would be
/// the root claiming a reach the gate reserves to two other crates.
#[test]
fn the_price_row_names_the_holder_rather_than_a_fee_field() {
    let (_, where_) = BOOT_SOURCES
        .iter()
        .find(|(name, _)| *name == "pricer")
        .expect("the price an arriving unit is admitted against has a row");
    assert!(
        where_.contains("ROOT_CARD"),
        "the price comes from the process's own card holder: got `{where_}`"
    );
    assert!(
        !where_.starts_with("config "),
        "a fee read straight off a config field is a price derived where nobody can see it"
    );
}

// ═════════════════════════════════════════════════════════════════════════════════════════════════
//   THE BREAKER IS ONE SET OF CELLS, READ AT TWO WIDTHS
// ═════════════════════════════════════════════════════════════════════════════════════════════════

/// The node's breaker cells, with a stated number of candidates in this plane's pool.
fn lanes_over(count: usize) -> ServerLanes {
    ServerLanes {
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
/// that belongs to no server.
#[test]
fn a_lane_outside_this_deployments_candidates_is_refused() {
    use busbar_unit_trust::lane::BreakerView as _;
    let lanes = lanes_over(2);
    assert!(lanes.ready("tools", 0, 0));
    assert!(lanes.ready("tools", 1, 0));
    assert!(
        !lanes.ready("tools", 2, 0),
        "a third lane is a destination this deployment does not have"
    );
    assert!(lanes.try_admit("tools", 2, 0).is_err());
}

/// **A deployment with no servers admits nothing.**
#[test]
fn a_deployment_with_no_servers_admits_no_lane() {
    use busbar_unit_trust::lane::BreakerView as _;
    assert!(!lanes_over(0).ready("tools", 0, 0));
}

/// **The admission takes no half-open probe.**
///
/// The trait's own words are that `try_admit` is where a probe is actually taken. Taking one here
/// would spend a half-open budget the dispatch below is about to spend again — two dispatches' worth
/// of probe for one request, and a lane that reads recovered because the loop probed it rather than
/// because anything succeeded. So it answers from the same reading `ready` does, and this cell is
/// what says the two agree.
#[test]
fn the_admission_answers_from_the_same_reading_the_peek_does() {
    use busbar_unit_trust::lane::BreakerView as _;
    let lanes = lanes_over(1);
    for lane in 0..3 {
        assert_eq!(
            lanes.ready("tools", lane, 0),
            lanes.try_admit("tools", lane, 0).is_ok(),
            "lane {lane}: the peek and the admission are one reading of one set of cells"
        );
    }
}

// ═════════════════════════════════════════════════════════════════════════════════════════════════
//   A SECTION THAT IS NOT THIS PLANE'S IS NOT THIS PLANE'S
// ═════════════════════════════════════════════════════════════════════════════════════════════════

/// **A type-erased section this plane does not own registers nothing.**
///
/// The honest reading of a deployment with no `tools:` block: no registration, rather than a panic
/// or a fabricated one. It is also the arm a build with the plane compiled out takes, and a
/// composition that unwrapped here would turn a compiled-out plane into a boot crash.
#[test]
fn a_section_this_plane_does_not_own_registers_nothing() {
    assert!(declared_servers(&42_u32).is_empty());
}
