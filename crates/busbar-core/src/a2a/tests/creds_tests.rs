// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Tests for the leased outbound delegation credential.
//!
//! The load-bearing one is `the_callers_credential_has_no_path_to_a_delegate`: it is a claim about
//! what CANNOT happen, which is the kind of claim a normal test cannot make, so it is made three
//! ways — the config value is refused at parse, the mint signature admits no caller credential, and
//! the module's production source is read for a forwarding call.

use super::*;
use crate::a2a::registry::AgentRegistration;
use crate::config::secret::SecretResolver;

/// Write a secret to a uniquely-named file and hand back a `file:` reference to it. A file rather
/// than an env var because `set_var` is process-global and these tests run in parallel with every
/// other test in the binary.
fn secret_file(name: &str, value: &str) -> SecretRef {
    let path = std::env::temp_dir().join(format!(
        "busbar-a2a-cred-{name}-{}-{:?}",
        std::process::id(),
        std::thread::current().id()
    ));
    std::fs::write(&path, value).expect("write the test secret");
    SecretRef::file(path.to_string_lossy().to_string())
}

fn registration_with(cred: Option<OutboundCredential>) -> AgentRegistration {
    let mut r = AgentRegistration::registered("planner", "https://a2a.vendor/planner");
    r.outbound_cred = cred;
    r
}

/// A key granted exactly `agent:planner`, which is what every mint below is authorised by.
///
/// There is no way to reach a mint without one, and that is the point of the type: the grant is the
/// inbound principal's authority for THIS backend, and a mint that could be reached without it is
/// busbar spending its own credential on behalf of a caller that never held the reach.
fn a_caller() -> busbar_api::VirtualKey {
    busbar_api::VirtualKey {
        id: "k-caller".to_string(),
        generation_hash: String::new(),
        name: "caller".to_string(),
        allowed_scopes: Some(vec![busbar_api::ScopeRef {
            kind: crate::a2a::inbound::SCOPE_KIND_AGENT.to_string(),
            value: "planner".to_string(),
        }]),
        enabled: true,
        created_at: 0,
        group: None,
        labels: std::collections::BTreeMap::new(),
        expires_at: None,
        deleted_at: None,
        revision: 1,
        ..Default::default()
    }
}

#[test]
fn a_minted_lease_carries_the_secret_only_through_the_header_it_was_placed_at() {
    let cred = OutboundCredential {
        secret: secret_file("bearer", "s3cr3t-vendor-token\n"),
        placement: CredentialPlacement::Bearer,
        lease_ttl_ms: 60_000,
    };
    let reg = registration_with(Some(cred));
    let lease = mint(
        &authorise_egress(&a_caller(), "planner", 0)
            .expect("the caller is granted `agent:planner`"),
        &reg,
        &SecretResolver::builtins_only(),
        1_000,
    )
    .expect("mint");

    assert_eq!(
        lease.expires_at_ms(),
        61_000,
        "the TTL is added to OUR clock"
    );
    assert_eq!(
        lease.agent_id(),
        "planner",
        "a lease knows what it was resolved FOR, which is what `header_for` compares against"
    );
    assert_eq!(
        lease.header_for("planner", 1_000).expect("live lease"),
        (
            "authorization".to_string(),
            // The trailing newline a file secret picks up is trimmed by the resolver, which matters
            // here: a header value with an embedded newline is a header-splitting bug.
            "Bearer s3cr3t-vendor-token".to_string()
        )
    );
}

#[test]
fn a_named_header_placement_carries_the_value_verbatim() {
    let cred = OutboundCredential {
        secret: secret_file("apikey", "abc123"),
        placement: CredentialPlacement::Header("x-api-key".to_string()),
        lease_ttl_ms: 60_000,
    };
    let reg = registration_with(Some(cred));
    let lease = mint(
        &authorise_egress(&a_caller(), "planner", 0)
            .expect("the caller is granted `agent:planner`"),
        &reg,
        &SecretResolver::builtins_only(),
        0,
    )
    .expect("mint");
    assert_eq!(
        lease.header_for("planner", 0).expect("live lease"),
        ("x-api-key".to_string(), "abc123".to_string())
    );
}

#[test]
fn a_lease_stops_working_at_its_expiry_rather_than_being_checked_by_the_caller() {
    let cred = OutboundCredential {
        secret: secret_file("expiry", "tok"),
        placement: CredentialPlacement::Bearer,
        lease_ttl_ms: 5_000,
    };
    let reg = registration_with(Some(cred));
    let lease = mint(
        &authorise_egress(&a_caller(), "planner", 0)
            .expect("the caller is granted `agent:planner`"),
        &reg,
        &SecretResolver::builtins_only(),
        1_000,
    )
    .expect("mint");

    assert!(lease.header_for("planner", 5_999).is_ok(), "still live");
    // Reaching the expiry IS expired: the lease says it is usable UNTIL this instant.
    assert_eq!(
        lease.header_for("planner", 6_000).expect_err("expired"),
        LeaseError::Expired {
            agent_id: "planner".to_string(),
            expired_at_ms: 6_000,
            now_ms: 6_000,
        }
    );
}

#[test]
fn a_lease_minted_for_one_agent_is_refused_on_a_hop_to_another() {
    // The SCOPING half of the lease. A resolved secret that carries no record of what it was resolved
    // FOR is one an unrelated code path can pick up and present somewhere else.
    let cred = OutboundCredential {
        secret: secret_file("scope", "tok"),
        placement: CredentialPlacement::Bearer,
        lease_ttl_ms: 60_000,
    };
    let reg = registration_with(Some(cred));
    let lease = mint(
        &authorise_egress(&a_caller(), "planner", 0)
            .expect("the caller is granted `agent:planner`"),
        &reg,
        &SecretResolver::builtins_only(),
        0,
    )
    .expect("mint");
    assert_eq!(
        lease.header_for("summarizer", 0).expect_err("wrong agent"),
        LeaseError::WrongAgent {
            minted_for: "planner".to_string(),
            used_for: "summarizer".to_string(),
        }
    );
}

#[test]
fn a_registration_with_no_credential_refuses_rather_than_delegating_unauthenticated() {
    let reg = registration_with(None);
    assert_eq!(
        mint(
            &authorise_egress(&a_caller(), "planner", 0)
                .expect("the caller is granted `agent:planner`"),
            &reg,
            &SecretResolver::builtins_only(),
            0,
        )
        .expect_err("no credential"),
        LeaseError::NotConfigured("planner".to_string())
    );
}

#[test]
fn an_unresolvable_handle_fails_closed_and_names_the_agent() {
    let cred = OutboundCredential {
        secret: SecretRef::file("/nonexistent/busbar/a2a/secret".to_string()),
        placement: CredentialPlacement::Bearer,
        lease_ttl_ms: 60_000,
    };
    let reg = registration_with(Some(cred));
    let err = mint(
        &authorise_egress(&a_caller(), "planner", 0)
            .expect("the caller is granted `agent:planner`"),
        &reg,
        &SecretResolver::builtins_only(),
        0,
    )
    .expect_err("unresolvable");
    assert!(
        matches!(err, LeaseError::Unresolved { ref agent_id, .. } if agent_id == "planner"),
        "got {err:?}"
    );
}

#[test]
fn the_lease_never_renders_the_secret_in_a_debug_line() {
    // A derived `Debug` would put a live vendor credential into any log line that debug-formats a
    // registration, which is how these leak in practice.
    let cred = OutboundCredential {
        secret: secret_file("debug", "SUPER-SECRET-VALUE"),
        placement: CredentialPlacement::Bearer,
        lease_ttl_ms: 60_000,
    };
    let reg = registration_with(Some(cred));
    let lease = mint(
        &authorise_egress(&a_caller(), "planner", 0)
            .expect("the caller is granted `agent:planner`"),
        &reg,
        &SecretResolver::builtins_only(),
        0,
    )
    .expect("mint");
    let rendered = format!("{lease:?}");
    assert!(
        !rendered.contains("SUPER-SECRET-VALUE"),
        "the lease rendered its secret: {rendered}"
    );
    assert!(rendered.contains("<redacted; present>"), "got {rendered}");

    // And the same must hold transitively through the registration that holds the HANDLE: a
    // `SecretRef` carries no secret material, so this is a check that it stayed that way.
    let reg_rendered = format!("{reg:?}");
    assert!(
        !reg_rendered.contains("SUPER-SECRET-VALUE"),
        "the registration rendered the secret: {reg_rendered}"
    );
}

#[test]
fn the_callers_credential_has_no_path_to_a_delegate() {
    // THE RULE, checked three ways because it is a claim about what cannot happen.
    //
    // (1) The config VALUE that would mean "forward the caller's credential" is refused at parse,
    //     with a message that says why rather than merely that it was refused.
    let def: crate::a2a::config::AgentDefCfg = serde_yaml::from_str(
        r#"
        url: https://a2a.vendor/planner
        pin: { mechanism: unpinned }
        upstream_credentials: passthrough
        "#,
    )
    .expect("the shape is legal; the VALUE is what is refused");
    let err = crate::a2a::config::validate_agent("planner", &def)
        .expect_err("passthrough must be refused on the agents: plane");
    assert!(
        err.contains("passthrough") && err.contains("delegates AS ITSELF"),
        "the refusal must explain itself, got: {err}"
    );

    // (2) `own` is accepted, so the refusal is about the value and not about the key existing.
    let own: crate::a2a::config::AgentDefCfg = serde_yaml::from_str(
        r#"
        url: https://a2a.vendor/planner
        pin: { mechanism: unpinned }
        upstream_credentials: own
        "#,
    )
    .expect("parse");
    crate::a2a::config::validate_agent("planner", &own).expect("`own` is the supported mode");

    // (3) The MINT SEAM admits no caller credential at all. Read the production source and require
    //     that the signature has not grown one — an argument is how forwarding would arrive, and an
    //     added argument is a change a reviewer sees only if something is looking.
    let source = std::fs::read_to_string(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/a2a/creds.rs"),
    )
    .expect("readable source");
    let code: String = source
        .lines()
        .filter(|l| !l.trim_start().starts_with("//") && !l.trim_start().starts_with("///"))
        .collect::<Vec<_>>()
        .join("\n");
    for forbidden in [
        "CallerToken",
        "caller_token",
        "inbound_credential",
        "caller_key",
    ] {
        assert!(
            !code.contains(forbidden),
            "`{forbidden}` appears in the outbound credential module. busbar delegates as itself; \
             the caller's credential must have no path to a delegate."
        );
    }
}

/// THE SECOND RULE, AND IT IS A DIFFERENT CLAIM: busbar's OWN credential is not spent on behalf of a
/// caller that is not itself authorised for the backend agent.
///
/// The test above would be entirely green against a relay that violates this one — every byte on the
/// hop would be busbar's own, and the caller would still have gained reach it does not hold. That is
/// the transitive confused deputy, and it exists only because busbar is both directions at once.
#[test]
fn busbars_own_credential_is_not_spent_for_a_caller_that_holds_no_grant_on_the_backend() {
    let cred = OutboundCredential {
        secret: secret_file("deputy", "BUSBARS-OWN-VENDOR-TOKEN"),
        placement: CredentialPlacement::Bearer,
        lease_ttl_ms: 60_000,
    };
    let reg = registration_with(Some(cred));
    let caller = a_caller(); // granted `agent:planner`, and nothing else

    // The granted agent authorises, and the lease is minted. The control: without it, the refusal
    // below would be equally green against a gate that refuses everything.
    let grant = authorise_egress(&caller, "planner", 0).expect("the granted agent authorises");
    assert!(mint(&grant, &reg, &SecretResolver::builtins_only(), 0).is_ok());

    // A DIFFERENT backend the same caller holds no grant on: no grant, therefore no mint, therefore
    // no credential. There is no second path to a lease — `mint` and `mint_from` both take the
    // witness, so this refusal is not one a call site can route around.
    let denied = authorise_egress(&caller, "payments", 0).expect_err("no grant, no credential");
    assert_eq!(
        denied,
        AgentEgressDenied::NoAgentGrant {
            caller: "k-caller".to_string(),
            agent_id: "payments".to_string(),
        }
    );

    // And the grant is not transferable between agents: reading the id off the grant is what makes
    // "authorise against one, mint against another" unexpressible rather than merely discouraged.
    let mut other = AgentRegistration::registered("payments", "https://a2a.vendor/payments");
    other.outbound_cred = reg.outbound_cred.clone();
    assert!(matches!(
        mint(&grant, &other, &SecretResolver::builtins_only(), 0),
        Err(LeaseError::WrongAgent { .. })
    ));
}

/// A WILDCARD PRINCIPAL (`allowed_scopes: None`) IS STILL A PRINCIPAL, and it is granted every
/// agent — which is `scope_allowed`'s frozen meaning for an OMITTED list and not something this
/// gate may reinterpret. Pinned so that a future edit "hardening" the gate by reading a wildcard as
/// the empty set does not silently break every small deployment.
#[test]
fn a_wildcard_principal_is_granted_every_agent_because_that_is_what_an_omitted_list_means() {
    let mut caller = a_caller();
    caller.allowed_scopes = None;
    assert!(authorise_egress(&caller, "planner", 0).is_ok());
    assert!(authorise_egress(&caller, "payments", 0).is_ok());

    // An EXPLICIT EMPTY list is the empty set, never "all".
    caller.allowed_scopes = Some(Vec::new());
    assert!(matches!(
        authorise_egress(&caller, "planner", 0),
        Err(AgentEgressDenied::NoAgentGrant { .. })
    ));
}
