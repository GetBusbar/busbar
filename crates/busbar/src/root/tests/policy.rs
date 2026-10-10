//! Tests for `policy.rs`. Lifted out of the implementation file so its line count
//! measures implementation and nothing else; still a direct child module, so `use
//! super::*` reaches the private items it always did.

use super::*;
use busbar_kernel_scope::required_scope;

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
