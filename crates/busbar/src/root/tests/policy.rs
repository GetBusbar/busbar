//! Tests for `policy.rs`. Lifted out of the implementation file so its line count
//! measures implementation and nothing else; still a direct child module, so `use
//! super::*` reaches the private items it always did.

use super::*;
use busbar_kernel_scope::required_scope;

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
        upstream_request_timeout_secs: 13,
        ..LimitsResolved::default()
    };
    let settings = client_settings(&limits);
    assert_eq!(settings.request_body_max_bytes, 1024);
    assert_eq!(settings.response_body_max_bytes, 1024);
    assert_eq!(settings.pool_max_idle_per_host, 7);
    assert_eq!(settings.pool_idle_timeout_secs, 11);
    assert!(settings.upstream_http1_only);
    assert!(!settings.upstream_h2_prior_knowledge);
    // The request timeout is the operator's too: a figure the transport hardcoded would
    // cut a slow upstream at a number nobody configured. 13 is neither the resolved default nor the
    // transport's own, so reading either instead of the operator's goes red here.
    assert_ne!(
        LimitsResolved::default().upstream_request_timeout_secs,
        13,
        "the fixture's timeout must differ from the resolved default"
    );
    assert_ne!(TransportSettings::default().request_timeout_secs, 13);
    assert_eq!(settings.request_timeout_secs, 13);
}

/// THE DEPRECATED ENV PINS STILL HOLD (1.5.5 honored them at its client build, over the config):
/// `BUSBAR_UPSTREAM_H2_PRIOR_KNOWLEDGE` set turns the http door's prior-knowledge key on whatever
/// `advanced.upstream_h2_prior_knowledge` says, `0` or empty turns it off, and unset leaves the
/// config's value; `BUSBAR_UPSTREAM_HTTP1_ONLY` the same for the http1-only key.
#[test]
fn the_deprecated_upstream_env_pins_win_over_the_config() {
    let limits = LimitsResolved::default();
    assert!(!limits.upstream_h2_prior_knowledge && !limits.upstream_http1_only);
    let under = |pairs: &'static [(&'static str, &'static str)], limits: &LimitsResolved| {
        client_settings_under(limits, |name| {
            pairs
                .iter()
                .find(|(n, _)| *n == name)
                .map(|(_, v)| std::ffi::OsString::from(v))
        })
    };
    let s = under(&[("BUSBAR_UPSTREAM_H2_PRIOR_KNOWLEDGE", "1")], &limits);
    assert!(s.upstream_h2_prior_knowledge && !s.upstream_http1_only);
    let s = under(&[("BUSBAR_UPSTREAM_HTTP1_ONLY", "true")], &limits);
    assert!(s.upstream_http1_only && !s.upstream_h2_prior_knowledge);
    let configured = LimitsResolved {
        upstream_h2_prior_knowledge: true,
        upstream_http1_only: true,
        ..LimitsResolved::default()
    };
    let s = under(
        &[
            ("BUSBAR_UPSTREAM_H2_PRIOR_KNOWLEDGE", "0"),
            ("BUSBAR_UPSTREAM_HTTP1_ONLY", ""),
        ],
        &configured,
    );
    assert!(!s.upstream_h2_prior_knowledge && !s.upstream_http1_only);
    let s = under(&[], &configured);
    assert!(s.upstream_h2_prior_knowledge && s.upstream_http1_only);
}

/// And a deployment that set nothing is left where it was: the resolved default body cap is the
/// same 32 MiB the transport's own `Default` carries, so wiring the knob through cannot move a
/// deployment that never touched it.
#[test]
fn an_unset_body_cap_resolves_to_the_transport_default() {
    let settings = client_settings(&LimitsResolved::default());
    assert_eq!(
        settings.request_body_max_bytes,
        TransportSettings::default().request_body_max_bytes
    );
    assert_eq!(
        settings.request_body_max_bytes,
        32 * 1024 * 1024,
        "the transport's own default body cap is the 32 MiB this deployment has always had"
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
