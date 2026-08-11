// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The `agents:` section's grammar, and the value rules that make the object pin worth having.

use crate::a2a::config::{
    policy_for, validate_agent, validate_section_hooks, AgentDefCfg, AgentPinCfg, AgentsCfg,
    PinMechanism, DEFAULT_REVERIFY_TTL, RESERVED_AGENTS_SECTION_KEYS,
};
use crate::a2a::pin::CardPin;
use crate::config::named_map::NamedMapSection;

fn parse(yaml: &str) -> Result<AgentsCfg, String> {
    serde_yaml::from_str::<AgentsCfg>(yaml).map_err(|e| e.to_string())
}

fn signed(fingerprint: Option<&str>) -> AgentDefCfg {
    AgentDefCfg {
        url: "https://a2a.vendor/planner".to_string(),
        pin: AgentPinCfg {
            mechanism: PinMechanism::JwsIssuerKey,
            key: Some("MCowBQYDK2VwAyEA".to_string()),
            fingerprint: fingerprint.map(str::to_string),
        },
        reverify_ttl: None,
        recovery_backoff: None,
        protocol_version: None,
        upstream_credentials: None,
        upstream_credential: None,
        egress_scopes: Vec::new(),
        client_identity: None,
        hooks: Vec::new(),
    }
}

/// The shape the design specifies parses, field for field.
#[test]
fn the_designed_entry_parses_as_written() {
    let cfg = parse(
        r#"
hooks: [agent-sanitizer]
planner:
  url: "https://a2a.vendor/planner"
  pin:
    mechanism: jws_issuer_key
    key: "MCowBQYDK2VwAyEA"
    fingerprint: "sha256/CARD=="
  reverify_ttl: 6h
  upstream_credentials: own
  hooks: [dispatch-order]
"#,
    )
    .expect("the designed entry must parse");

    assert_eq!(cfg.all_agent_hooks, vec!["agent-sanitizer".to_string()]);
    let planner = cfg.agents.get("planner").expect("planner is registered");
    assert_eq!(planner.url, "https://a2a.vendor/planner");
    assert_eq!(planner.pin.mechanism, PinMechanism::JwsIssuerKey);
    assert_eq!(planner.pin.fingerprint.as_deref(), Some("sha256/CARD=="));
    assert_eq!(planner.reverify_ttl.as_deref(), Some("6h"));
    assert_eq!(planner.hooks, vec!["dispatch-order".to_string()]);
}

/// A typo'd key fails the parse rather than silently un-pinning an agent. This is the whole reason
/// the struct is `deny_unknown_fields`: `pinn:` accepted and ignored is a registration an operator
/// believes is pinned and is not.
#[test]
fn an_unknown_key_is_refused_rather_than_ignored() {
    let err = parse(
        r#"
planner:
  url: "https://a2a.vendor/planner"
  pin: { mechanism: unpinned }
  reverfy_ttl: 6h
"#,
    )
    .expect_err("a typo'd key must not parse");
    assert!(
        err.contains("reverfy_ttl"),
        "the error must name the offending key, got: {err}"
    );
}

/// A mechanism that needs material and carries none is refused. A pin with nothing to verify
/// against is not a pin, and it reads to an operator exactly like one that is.
#[test]
fn a_mechanism_that_needs_key_material_and_has_none_is_refused() {
    for mechanism in ["jws_issuer_key", "cert_spki", "mtls"] {
        let err = parse(&format!(
            "planner:\n  url: \"https://x/\"\n  pin: {{ mechanism: {mechanism} }}\n"
        ))
        .unwrap_err();
        assert!(
            err.contains("needs `pin.key:`"),
            "{mechanism} must be refused without key material, got: {err}"
        );
    }
}

/// The converse, and it is the half that is easy to leave out: `unpinned` carrying key material is
/// also refused. Material that is never verified against is protection an operator can see and
/// cannot rely on, which is worse than an honest absence.
#[test]
fn unpinned_carrying_key_material_is_refused() {
    let err = parse(
        r#"
planner:
  url: "https://x/"
  pin: { mechanism: unpinned, key: "MCowBQYDK2VwAyEA" }
"#,
    )
    .unwrap_err();
    assert!(err.contains("must not carry `pin.key:`"), "got: {err}");
}

/// `unpinned` with nothing else is legal to WRITE. The cap that stops it ever being approved lives
/// in the pin module, deliberately, and this test pins the division: config admits it, approval
/// refuses it.
#[test]
fn unpinned_is_registrable_here_and_refused_at_approval() {
    let cfg = parse("planner:\n  url: \"https://x/\"\n  pin: { mechanism: unpinned }\n")
        .expect("unpinned must be registrable");
    let def = cfg.agents.get("planner").unwrap();
    assert_eq!(
        crate::a2a::config::declared_pin(def),
        Some(CardPin::Unpinned)
    );
    assert!(
        !CardPin::Unpinned.is_a_root(),
        "the approval cap is the pin module's ruling, and it must still hold"
    );
}

/// A pin with a root but no fingerprint is the NORMAL state of a fresh registration, not an error:
/// the fingerprint is captured at `connect` and approved by a human. Nothing here invents one.
#[test]
fn a_root_without_a_fingerprint_is_pending_not_invalid() {
    let def = signed(None);
    validate_agent("planner", &def).expect("a fresh registration is valid");
    assert_eq!(
        crate::a2a::config::declared_pin(&def),
        None,
        "no fingerprint means nothing is declared yet; it must not be fabricated"
    );

    let approved = signed(Some("sha256/CARD=="));
    assert_eq!(
        crate::a2a::config::declared_pin(&approved),
        Some(CardPin::JwsIssuerKey {
            issuer_key: "MCowBQYDK2VwAyEA".to_string(),
            card_fingerprint: "sha256/CARD==".to_string(),
        })
    );
}

/// A URL with no scheme, or an empty one, fails at boot rather than at a delegation six hours later.
#[test]
fn a_url_without_a_scheme_fails_at_parse() {
    for url in ["", "   ", "a2a.vendor/planner", "ftp://a2a.vendor/"] {
        let mut def = signed(Some("f"));
        def.url = url.to_string();
        let err = validate_agent("planner", &def).expect_err(&format!("`{url}` must be refused"));
        assert!(err.contains("`url:`"), "got: {err}");
    }
}

/// Both durations are parsed at config time, so a nonsense cadence is an operator's boot error and
/// not a background job's runtime surprise.
#[test]
fn both_durations_are_validated_at_parse() {
    let mut def = signed(Some("f"));
    def.reverify_ttl = Some("6 hours".to_string());
    assert!(validate_agent("planner", &def)
        .unwrap_err()
        .contains("reverify_ttl"));

    let mut def = signed(Some("f"));
    def.recovery_backoff = Some("nope".to_string());
    assert!(validate_agent("planner", &def)
        .unwrap_err()
        .contains("recovery_backoff"));
}

/// The cadence an operator wrote is the cadence the decision uses, including the default.
#[test]
fn the_policy_is_the_operator_cadence_and_the_default_is_named() {
    let mut def = signed(Some("f"));
    def.reverify_ttl = Some("2h".to_string());
    def.recovery_backoff = Some("30m".to_string());
    let p = policy_for(&def, 999).unwrap();
    assert_eq!(p.ttl_ms, 2 * 3600 * 1000);
    assert_eq!(p.recovery_backoff_ms, 30 * 60 * 1000);

    let bare = signed(Some("f"));
    let p = policy_for(&bare, 7_000).unwrap();
    assert_eq!(
        p.ttl_ms,
        crate::admin::parse_duration_secs(DEFAULT_REVERIFY_TTL).unwrap() * 1000,
        "an absent ttl takes the named default, not zero"
    );
    assert_eq!(
        p.recovery_backoff_ms, 7_000,
        "an absent backoff takes the deployment default, not zero"
    );
}

/// A ZERO ttl would mean "re-verify on every glance", and a zero backoff would mean "believe a
/// recovery instantly". Both are legal to ask for; neither may be what an OMITTED field means.
#[test]
fn an_omitted_cadence_never_silently_means_zero() {
    let p = policy_for(&signed(Some("f")), 60_000).unwrap();
    assert!(p.ttl_ms > 0);
    assert!(p.recovery_backoff_ms > 0);
}

/// Reaching onto another plane is refused with a message that names the plane, not ignored.
#[test]
fn a_cross_plane_hook_reference_is_refused() {
    for bad in [
        "pools.fast",
        "agents.planner",
        "tools.search",
        "export.siem",
        "identity-providers.corp",
    ] {
        let mut def = signed(Some("f"));
        def.hooks = vec![bad.to_string()];
        let err =
            validate_agent("planner", &def).unwrap_err_display(&format!("`{bad}` must be refused"));
        assert!(
            err.contains("no entry on one plane may reference an entry on another"),
            "got: {err}"
        );
    }
    // And the section-level list is judged by the same rule, not a looser one.
    let err = validate_section_hooks(&["pools.fast".to_string()]).unwrap_err();
    assert!(err.contains("`agents.hooks`"), "got: {err}");
}

/// A bare name is what a hook reference is, and it is accepted.
#[test]
fn a_bare_hook_name_is_accepted_on_both_lists() {
    let mut def = signed(Some("f"));
    def.hooks = vec!["dispatch-order".to_string()];
    validate_agent("planner", &def).expect("a bare hook name is the legal form");
    validate_section_hooks(&["agent-sanitizer".to_string()]).expect("likewise at section level");
}

/// The reserved word space is IDENTICAL across planes. This is the assertion, not a comment: the
/// A2A section reserves exactly what the pool section reserves, even though A2A does not use both.
#[test]
fn the_reserved_section_words_are_identical_to_the_pool_planes() {
    assert_eq!(
        RESERVED_AGENTS_SECTION_KEYS,
        crate::config::RESERVED_POOLS_SECTION_KEYS,
        "a word reserved on one plane and free on another is exactly the surprise the rule exists \
         to prevent"
    );
}

/// An agent may not be NAMED by a reserved word, in either spelling.
#[test]
fn an_agent_may_not_be_named_by_a_reserved_word() {
    for reserved in RESERVED_AGENTS_SECTION_KEYS {
        let err = parse(&format!(
            "{reserved}:\n  url: \"https://x/\"\n  pin: {{ mechanism: unpinned }}\n"
        ))
        .unwrap_err();
        assert!(
            err.contains("RESERVED"),
            "`{reserved}` must be refused as an agent name, got: {err}"
        );
    }
}

/// The section-level reserved keys still WORK as knobs, which is what makes refusing them as names
/// meaningful rather than merely restrictive.
#[test]
fn the_reserved_words_still_function_as_section_knobs() {
    let cfg = parse(
        r#"
hooks: [a, b]
upstream_credentials: own
planner:
  url: "https://x/"
  pin: { mechanism: unpinned }
"#,
    )
    .unwrap();
    assert_eq!(cfg.all_agent_hooks, vec!["a".to_string(), "b".to_string()]);
    assert_eq!(
        cfg.all_agent_upstream_credentials,
        Some(crate::auth::UpstreamCreds::Own)
    );
    assert_eq!(cfg.agents.len(), 1, "the knobs are not agents");
}

/// THE CALLER'S CREDENTIAL IS NEVER FORWARDED TO A DELEGATE, and the section-level default is
/// refused as well as the per-entry value — a section default applies to every agent that never
/// spells the key, which is exactly the set a per-entry check cannot see.
#[test]
fn passthrough_is_refused_at_the_section_level_as_well_as_per_entry() {
    let err = parse(
        r#"
upstream_credentials: passthrough
planner:
  url: "https://x/"
  pin: { mechanism: unpinned }
"#,
    )
    .unwrap_err();
    assert!(
        err.contains("delegates AS ITSELF"),
        "the section-level refusal must explain itself, got: {err}"
    );

    let per_entry = parse(
        r#"
planner:
  url: "https://x/"
  pin: { mechanism: unpinned }
  upstream_credentials: passthrough
"#,
    )
    .unwrap_err();
    assert!(
        per_entry.contains("delegates AS ITSELF"),
        "the per-entry refusal must explain itself, got: {per_entry}"
    );

    // `own` is accepted in both places, so the refusal is about the VALUE and not about the key.
    parse(
        r#"
upstream_credentials: own
planner:
  url: "https://x/"
  pin: { mechanism: unpinned }
  upstream_credentials: own
"#,
    )
    .expect("`own` is the supported mode on both");
}

/// The LEASE is a field rather than an adjective, so a lease that could never be presented is
/// refused where the operator wrote it.
#[test]
fn a_zero_lease_ttl_is_refused_at_parse() {
    let err = parse(
        r#"
planner:
  url: "https://x/"
  pin: { mechanism: unpinned }
  upstream_credential:
    secret: { env: VENDOR_TOKEN }
    lease_ttl_ms: 0
"#,
    )
    .unwrap_err();
    assert!(err.contains("lease_ttl_ms"), "got: {err}");

    let cfg = parse(
        r#"
planner:
  url: "https://x/"
  pin: { mechanism: unpinned }
  upstream_credential:
    secret: { env: VENDOR_TOKEN }
    lease_ttl_ms: 60000
  egress_scopes: [orchestrator]
"#,
    )
    .expect("a positive TTL is legal");
    let def = &cfg.agents["planner"];
    let cred = def.upstream_credential.as_ref().expect("the handle");
    assert_eq!(cred.lease_ttl_ms, 60_000);
    assert_eq!(cred.secret.env_var(), Some("VENDOR_TOKEN"));
    assert_eq!(def.egress_scopes, vec!["orchestrator".to_string()]);
}

/// An empty egress scope grants nothing and READS as though it grants something.
#[test]
fn an_empty_egress_scope_is_refused() {
    let err = parse(
        r#"
planner:
  url: "https://x/"
  pin: { mechanism: unpinned }
  egress_scopes: ["  "]
"#,
    )
    .unwrap_err();
    assert!(err.contains("egress_scopes"), "got: {err}");
}

/// THE TWO PATHS RUN ONE GRAMMAR. The admin write path must reject exactly what the file rejects,
/// because the alternative — an API that accepts a definition the rebuild then drops — is a defect
/// this tree has already paid for once.
#[test]
fn the_admin_write_path_and_the_file_share_one_grammar() {
    let cases: [(&str, serde_json::Value); 4] = [
        (
            "a pin with no material",
            serde_json::json!({"url": "https://x/", "pin": {"mechanism": "jws_issuer_key"}}),
        ),
        (
            "unpinned carrying material",
            serde_json::json!({"url": "https://x/", "pin": {"mechanism": "unpinned", "key": "k"}}),
        ),
        (
            "a bad duration",
            serde_json::json!({"url": "https://x/", "pin": {"mechanism": "unpinned"},
                               "reverify_ttl": "soon"}),
        ),
        (
            "a cross-plane hook reference",
            serde_json::json!({"url": "https://x/", "pin": {"mechanism": "unpinned"},
                               "hooks": ["pools.fast"]}),
        ),
    ];
    for (what, def) in cases {
        assert!(
            NamedMapSection::Agents
                .validate_def("planner", &def)
                .is_err(),
            "the admin path must refuse {what}, as the file does"
        );
    }
    // And the legal one is legal on both.
    let good = serde_json::json!({"url": "https://x/", "pin": {"mechanism": "unpinned"}});
    NamedMapSection::Agents
        .validate_def("planner", &good)
        .expect("a legal definition must be legal on both paths");
}

/// The section is a real member of the named-map chassis, not a special case bolted beside it.
#[test]
fn the_section_is_a_first_class_member_of_the_chassis() {
    assert!(
        NamedMapSection::ALL.contains(&NamedMapSection::Agents),
        "a section missing from ALL is a section the router, the OpenAPI generator and the overlay \
         applier all silently skip"
    );
    assert_eq!(NamedMapSection::Agents.key(), "agents");
    assert_eq!(
        NamedMapSection::Agents.path_root(),
        format!("/{}", NamedMapSection::Agents.key())
    );
    assert!(
        !NamedMapSection::Agents.requires_module(),
        "an agent is a remote endpoint somebody else runs; there is no plugin behind it to name"
    );
    assert!(
        !NamedMapSection::Agents.has_trust_ceiling(),
        "the trust ceiling is an identity-provider concern; an agent's trust is its pin"
    );
}

/// An entry round-trips to a document and back unchanged, which is what the overlay's per-entry
/// PATCH merge needs: patching one field must not rewrite the rest of the entry.
#[test]
fn an_entry_round_trips_through_its_document_form() {
    let def = AgentDefCfg {
        url: "https://a2a.vendor/planner".to_string(),
        pin: AgentPinCfg {
            mechanism: PinMechanism::CertSpki,
            key: Some("sha256/SPKI==".to_string()),
            fingerprint: Some("sha256/CARD==".to_string()),
        },
        reverify_ttl: Some("15m".to_string()),
        recovery_backoff: Some("1h".to_string()),
        protocol_version: Some("1.0".to_string()),
        upstream_credentials: Some(crate::auth::UpstreamCreds::Own),
        upstream_credential: Some(crate::a2a::creds::OutboundCredential {
            secret: crate::config::SecretRef::env("VENDOR_TOKEN"),
            placement: crate::a2a::creds::CredentialPlacement::Header("x-api-key".to_string()),
            lease_ttl_ms: 60_000,
        }),
        egress_scopes: vec!["orchestrator".to_string()],
        // BOTH HALVES OF THE CLIENT IDENTITY, so the round trip covers the field that carries key
        // material: a `client_identity:` an admin PATCH silently dropped would leave a registration
        // unable to complete a handshake it completed a moment earlier.
        client_identity: Some(crate::a2a::config::ClientIdentityCfg {
            cert: crate::config::SecretRef::env("BUSBAR_CLIENT_CERT"),
            key: crate::config::SecretRef::env("BUSBAR_CLIENT_KEY"),
        }),
        hooks: vec!["dispatch-order".to_string()],
    };
    let doc = serde_json::to_value(&def).expect("an entry must project to a document");
    let back: AgentDefCfg =
        serde_json::from_value(doc).expect("and must parse back from that document");
    assert_eq!(back, def);
}

/// A helper that makes the cross-plane test read as one assertion rather than three lines.
trait UnwrapErrDisplay {
    fn unwrap_err_display(self, msg: &str) -> String;
}

impl UnwrapErrDisplay for Result<(), String> {
    fn unwrap_err_display(self, msg: &str) -> String {
        match self {
            Ok(()) => panic!("{msg}"),
            Err(e) => e,
        }
    }
}

// ── THE OUTBOUND CLIENT IDENTITY ─────────────────────────────────────────────────────────────────

/// The registration an operator writes for a peer behind mutual TLS, parsed field for field.
///
/// `cert:` and `key:` are SECRET REFERENCES in the ordinary `{module, settings}` grammar (here in
/// its `file:` sugar), which is the same spelling `tls.cert:` uses for busbar's inbound identity.
/// There is no spelling that puts a private key in the config file.
#[test]
fn an_mtls_registration_names_its_client_certificate_by_reference() {
    let cfg = parse(
        r#"
planner:
  url: "https://a2a.vendor/planner"
  pin:
    mechanism: mtls
    key: "sha256/SPKI=="
  client_identity:
    cert: { file: /run/secrets/busbar-client.crt }
    key: { file: /run/secrets/busbar-client.key }
"#,
    )
    .expect("an mtls registration with a client identity must parse");

    let planner = cfg.agents.get("planner").expect("planner is registered");
    let identity = planner
        .client_identity
        .as_ref()
        .expect("the client identity is carried through");
    assert_eq!(
        identity.cert.module,
        crate::config::secret::SECRET_MODULE_FILE
    );
    assert_eq!(
        identity.key.module,
        crate::config::secret::SECRET_MODULE_FILE
    );
    // The REFERENCE is what the config holds. Nothing here is key material, which is why the type
    // is safe to `Debug` and safe to serve back from the admin API.
    assert!(!format!("{identity:?}").contains("BEGIN"));
}

/// THE DEFECT, AT THE GRAMMAR LEVEL: `mtls` with nothing to present is refused at parse.
///
/// It used to be the only spelling available, and it produced a registration that could never
/// complete a handshake — the peer answers `CertificateRequired` and the fetch fails on a
/// re-verification tick hours later, at which point the message is a TLS alert rather than a
/// sentence about the config. Refused here, at boot, on the line the operator wrote.
#[test]
fn mtls_without_a_client_identity_is_refused_at_parse() {
    let err = parse(
        r#"
planner:
  url: "https://a2a.vendor/planner"
  pin:
    mechanism: mtls
    key: "sha256/SPKI=="
"#,
    )
    .expect_err("`mtls` with no client certificate must not parse");
    assert!(
        err.contains("`pin.mechanism: mtls` needs `client_identity:`")
            && err.contains("CertificateRequired"),
        "the refusal must name the missing key AND what the peer would have done: {err}"
    );
}

/// A client certificate over `http://` has no handshake to be presented in.
#[test]
fn a_client_identity_on_a_plaintext_endpoint_is_refused() {
    let err = parse(
        r#"
planner:
  url: "http://a2a.vendor/planner"
  pin:
    mechanism: cert_spki
    key: "sha256/SPKI=="
  client_identity:
    cert: { file: /run/secrets/c.crt }
    key: { file: /run/secrets/c.key }
"#,
    )
    .expect_err("a client certificate on a plaintext endpoint must not parse");
    assert!(
        err.contains("has no handshake to present it in"),
        "the refusal must say why the field cannot work here: {err}"
    );
}

/// A client certificate is legal under the OTHER mechanisms, and that is deliberate: a vendor may
/// demand one whatever it does about signing its card. Only `mtls` REQUIRES it.
#[test]
fn a_client_identity_is_legal_alongside_a_signed_card() {
    parse(
        r#"
planner:
  url: "https://a2a.vendor/planner"
  pin:
    mechanism: jws_issuer_key
    key: "MCowBQYDK2VwAyEA"
  client_identity:
    cert: { file: /run/secrets/c.crt }
    key: { file: /run/secrets/c.key }
"#,
    )
    .expect("a signed card behind a client-certificate-demanding endpoint must be spellable");
}

/// The admin write path runs the SAME rule. A grammar the file refuses and the API accepts is the
/// exact defect `validate_agent` was split out to prevent.
#[test]
fn the_admin_write_path_refuses_mtls_without_a_client_identity_too() {
    let mut def = signed(None);
    def.pin.mechanism = PinMechanism::Mtls;
    def.pin.key = Some("sha256/SPKI==".to_string());
    let err = validate_agent("planner", &def)
        .unwrap_err_display("the admin path must refuse what the file refuses");
    assert!(err.contains("needs `client_identity:`"), "{err}");
}
