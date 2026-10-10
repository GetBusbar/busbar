// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE DOOR PLANES' REGISTRY FOLD (ARCHITECT RULING 2026-10-03, Q-DEL-A2A-DECL): a registration a
//! door states becomes a registry row whose every word is the door's, whose section is judged by
//! the door's own `validate`, and whose named-map surface is generated from the row.

use std::sync::Arc;

use busbar_contract::plane::{PinMechanismDecl, TrustKeyDecl, TrustRole};
use busbar_contract::plane_calls::PlaneRegistration;

use super::*;

/// A 1.5.3 named-definition section, read off the frozen list (no literal here).
const NAMED: &str = busbar_kernel::plane::config::NAMED_MAP_SECTIONS[3];

/// A registration as a door states one: a named-definition section `fleet`, a pin and a cadence,
/// and a `validate` that refuses an entry without `url` in its own value-rule words and anything
/// that is not a mapping as a shape refusal.
fn registration(key: &'static str, section: &'static str) -> PlaneRegistration {
    PlaneRegistration {
        key,
        section,
        owns: Vec::new(),
        consumes: Vec::new(),
        admin_routes: Vec::new(),
        admin_openapi: None,
        secret_refs: vec!["settings.*.token.secret", "settings.*.env.*"],
        label: "Fleet",
        subject_noun: "fleet member",
        admin_noun: "member",
        audit_kind: "fleet_member",
        signing: Some(("fleet/signing/v1", "fleet-")),
        dialects: vec!["first", "second"],
        scope_kinds: vec!["member"],
        billable_classes: vec![("bytes", "byte")],
        fee_units: vec!["request"],
        record_kinds: vec!["member_row"],
        trust_keys: vec![
            TrustKeyDecl {
                key: "pin",
                role: TrustRole::Pin,
                fingerprint: true,
                default: None,
                mechanisms: &[PinMechanismDecl {
                    token: "unpinned",
                    root: false,
                    peer_key: false,
                }],
            },
            TrustKeyDecl {
                key: "reverify_ttl",
                role: TrustRole::ReverifyTtl,
                fingerprint: false,
                default: Some("5s"),
                mechanisms: &[],
            },
        ],
        caller_credential_refusal: Some("forwarding a caller credential is refused here"),
        fallback: false,
        validate: Arc::new(move |bytes: &[u8]| {
            if bytes.is_empty() {
                return Ok(());
            }
            // The blob is dealt as stage 3g deals it: `{<section>: <section as written>}`.
            let dealt: serde_json::Value =
                serde_json::from_slice(bytes).map_err(|e| e.to_string())?;
            let doc = dealt.get(section).cloned().unwrap_or_default();
            if doc.is_null() {
                return Ok(());
            }
            let Some(map) = doc.as_object() else {
                return Err("expected a map".to_string());
            };
            for (name, entry) in map {
                if name == "hooks" || name == "upstream_credentials" {
                    continue;
                }
                if !entry.is_object() {
                    return Err("invalid type: expected struct Member".to_string());
                }
                if entry.get("url").is_none() {
                    return Err(format!("`{section}.{name}`: `url:` must name the endpoint"));
                }
            }
            Ok(())
        }),
        facing: Arc::new(|_: &[u8], _: &[u8], public_url: Option<&str>| {
            Ok(busbar_contract::plane_calls::DoorFacing {
                claims: vec![
                    ("/fleet".to_string(), "first"),
                    ("/fleet/{id}".to_string(), "first"),
                    ("/.well-known/fleet".to_string(), "second"),
                ],
                admission: public_url
                    .map(|u| (format!("{u}/fleet"), format!("{u}/.well-known/fleet"))),
                listed: Vec::new(),
            })
        }),
    }
}

#[test]
fn a_door_registration_folds_into_a_row_every_word_of_which_is_the_doors() {
    let decl = fold(registration("door-fold-row", "door_fold_row")).expect("folds");
    assert_eq!(decl.key, "door-fold-row");
    assert_eq!(decl.config_section, "door_fold_row");
    assert_eq!(decl.scope_kinds, &["member"]);
    assert_eq!(
        (decl.subject_noun, decl.admin_noun, decl.audit_kind),
        ("fleet member", "member", "fleet_member")
    );
    assert_eq!(decl.card_signing_domain, Some("fleet/signing/v1"));
    assert_eq!(decl.card_kid_prefix, Some("fleet-"));
    assert_eq!(decl.billable_classes[0].class, "bytes");
    assert_eq!(decl.billable_classes[0].family, "byte");
    assert_eq!(decl.fee_units, &["request"]);
    assert_eq!(decl.record_kinds, &["member_row"]);
    assert_eq!(decl.trust_keys.len(), 2);
    assert_eq!(
        decl.caller_credential_refusal,
        Some("forwarding a caller credential is refused here")
    );
    assert_eq!((decl.wire_format_names)(), &["first", "second"]);
    assert!(decl.parse_section.is_some());
    assert!(
        decl.named_def_list.is_none() && decl.config_validate.is_none(),
        "a section that is no 1.5.3 named-definition map answers no named-map CRUD"
    );
    // Folding the same key again answers the first row.
    let again = fold(registration("door-fold-row", "door_fold_row")).expect("folds");
    assert!(std::ptr::eq(decl, again));
}

#[test]
fn a_registration_with_no_name_or_section_is_refused() {
    assert!(fold(registration("", "s")).is_err());
    assert!(fold(registration("door-fold-nosection", "")).is_err());
}

#[test]
fn the_section_is_judged_by_the_door_and_carried_as_written() {
    let decl = fold(registration("door-fold-parse", NAMED)).expect("folds");
    let parse = decl.parse_section.expect("a section parser");
    let bad: serde_yaml::Value = serde_yaml::from_str("zed: {pin: {mechanism: unpinned}}").unwrap();
    assert_eq!(
        parse(&bad).unwrap_err(),
        format!("`{NAMED}.zed`: `url:` must name the endpoint"),
        "the door's refusal, in its words"
    );
    let good: serde_yaml::Value = serde_yaml::from_str(
        "hooks: [audit]\nzed: {url: 'https://z', hooks: [gate]}\nalpha: {url: 'https://a'}\n",
    )
    .unwrap();
    let cfg = parse(&good).expect("the door accepts it");
    assert!(cfg.is_present());
    assert_eq!(
        cfg.def_names(),
        vec!["zed", "alpha"],
        "written order, reserved words skipped"
    );
    assert!(cfg.contains_def("alpha") && !cfg.contains_def("hooks"));
    let gates = cfg.container_gates();
    assert_eq!(gates.section_hooks, vec!["audit".to_string()]);
    assert_eq!(
        gates.containers,
        vec![
            ("zed".to_string(), vec!["gate".to_string()]),
            ("alpha".to_string(), Vec::new())
        ]
    );
    assert!(!(decl.default_section.expect("a default"))().is_present());
}

#[test]
fn a_registration_view_reads_the_kernel_owned_trust_keys() {
    let decl = fold(registration("door-fold-view", NAMED)).expect("folds");
    let keys = decl.trust_keys;
    let pinned: serde_yaml::Value = serde_yaml::from_str(
        "url: https://z\npin: {mechanism: jws, key: k, fingerprint: 'sha256:x'}\nreverify_ttl: 1m",
    )
    .unwrap();
    let v = view_of("zed", &pinned, keys);
    assert_eq!(v.name, "zed");
    assert_eq!(v.pin_mechanism.as_deref(), Some("jws"));
    assert_eq!(v.fingerprint_pinned, Some(true));
    assert_eq!(v.reverify_ttl.as_deref(), Some("1m"));
    let bare: serde_yaml::Value = serde_yaml::from_str("url: https://a").unwrap();
    let v = view_of("alpha", &bare, keys);
    assert_eq!(v.fingerprint_pinned, Some(false));
    assert_eq!(
        v.reverify_ttl.as_deref(),
        Some("5s"),
        "the declared default"
    );
    let v = view_of("alpha", &bare, &[]);
    assert_eq!(
        (v.pin_mechanism, v.fingerprint_pinned, v.reverify_ttl),
        (None, None, None),
        "a plane that declares no trust key shows none"
    );
}

#[test]
fn an_admin_write_is_judged_by_the_door_in_the_named_map_wording() {
    let decl = fold(registration("door-fold-write", NAMED)).expect("folds");
    let validate = decl.config_validate.expect("a write judge");
    assert_eq!(
        validate("zed", &serde_json::json!({"url": "https://z"})),
        Ok(())
    );
    assert_eq!(
        validate("zed", &serde_json::json!({"pin": {}})).unwrap_err(),
        format!("`{NAMED}.zed`: `url:` must name the endpoint"),
        "a value rule names its registration itself"
    );
    assert_eq!(
        validate("zed", &serde_json::json!("nope")).unwrap_err(),
        format!("invalid `{NAMED}.zed` definition: invalid type: expected struct Member"),
        "a shape refusal reads as the 1.5.3 named-map sentence"
    );
    let mut cfg = (decl.default_section.expect("a default"))();
    cfg.insert_def("zed", &serde_json::json!({"url": "https://z"}))
        .expect("inserts");
    assert_eq!(cfg.def_names(), vec!["zed"]);
    assert_eq!(
        cfg.entry_document("zed"),
        Some(serde_json::json!({"url": "https://z"}))
    );
}

#[test]
fn a_door_rows_claims_and_audience_are_what_its_open_faced_the_world_with() {
    let decl = fold(registration("door-fold-facing", NAMED)).expect("folds");
    let reg = registration("door-fold-facing", NAMED);
    let slot = DoorSlot {
        section: DoorSection::new(
            NAMED,
            serde_yaml::from_str("zed: {url: 'https://z'}").unwrap(),
        ),
        facing: (reg.facing)(b"{}", b"", Some("https://gw.example")).expect("faces"),
        opened: true,
    };
    assert_eq!(
        (decl.claims)(&slot),
        vec![
            ("/fleet".to_string(), "first"),
            ("/.well-known/fleet".to_string(), "second")
        ],
        "each claim mounts its literal prefix, once"
    );
    let adm = (decl.admission)(&slot).expect("an audience");
    assert_eq!(adm.audience, "https://gw.example/fleet");
    assert_eq!(
        adm.resource_metadata,
        "https://gw.example/.well-known/fleet"
    );
    let unbound = DoorSlot {
        facing: (reg.facing)(b"{}", b"", None).expect("faces"),
        ..slot
    };
    assert!(
        (decl.admission)(&unbound).is_none(),
        "no public base, no audience"
    );
    // R2, ADMITTED BY THE KEY CHAIN: a door that binds no audience still mounts its claims, and
    // the kernel's key-verify chain admits them; with no key chain there is no admission path at
    // all, and the boot is refused.
    assert!(
        !(decl.claims)(&unbound).is_empty(),
        "an unbound door mounts its claims"
    );
    let slots: std::collections::BTreeMap<&'static str, &dyn std::any::Any> =
        [(decl.key, &unbound as &dyn std::any::Any)]
            .into_iter()
            .collect();
    let keyed = crate::plane::registry::build_dispatch(&[decl], &slots, true);
    assert!(
        keyed.is_ok(),
        "the key chain admits a door claim: {keyed:?}"
    );
    let keyed = keyed.unwrap();
    assert!(
        keyed.admission_for("/fleet").is_none(),
        "admitted by the key chain, the claim binds no audience"
    );
    // RED ARM: no audience and no key chain is no admission path at all.
    let refused = crate::plane::registry::build_dispatch(&[decl], &slots, false)
        .expect_err("a door claim with no admission path refuses the boot");
    assert!(refused.contains("bound no admission"), "{refused}");
    assert!((decl.claims)(&"not a door slot").is_empty());
}

/// A DOOR'S OWNED SECTION (its endpoint block beside its verb, the Statement's non-declaring
/// section): the row owns it (`owned_config_sections`), carries it as written through its endpoint
/// hooks (`DoorOwned`, the door judges it at its open), and its build hands it to the door's facing
/// as `PlaneOpenIn::owned` does, one JSON object keyed by section name, beside the section the door
/// judged off the `tools:`-or-`agents:` carrier. A door that owns nothing has no endpoint hooks.
#[test]
fn a_doors_owned_section_is_carried_and_handed_to_its_facing() {
    let owned_key: &'static str = "door_fold_owned_block";
    let mut reg = registration("door-fold-owned", NAMED);
    reg.owns = vec![owned_key];
    reg.facing = Arc::new(|_: &[u8], owned: &[u8], _: Option<&str>| {
        let doc: serde_json::Value = serde_json::from_slice(owned).map_err(|e| e.to_string())?;
        let audience = doc["door_fold_owned_block"]["uri"]
            .as_str()
            .map(|u| (u.to_string(), format!("{u}/meta")));
        Ok(busbar_contract::plane_calls::DoorFacing {
            claims: Vec::new(),
            admission: audience,
            listed: Vec::new(),
        })
    });
    let decl = fold(reg).expect("folds");
    assert_eq!(decl.owned_config_sections, &[owned_key]);
    let block: serde_yaml::Value = serde_yaml::from_str("uri: 'https://gw.example/x'").unwrap();
    let parsed = (decl.parse_endpoint.expect("its endpoint parses"))(&block).expect("carried");
    assert!(parsed.is_present());
    let lowered = (decl.lower_endpoint.expect("and lowers"))(&*parsed).expect("as written");
    let section = DoorSection::new(
        NAMED,
        serde_yaml::from_str("zed: {url: 'https://z'}").unwrap(),
    );
    let ctx = BuildCtx {
        endpoint_slot: Some(lowered),
        agent_defs: &(),
        tool_defs: &section,
        public_url: None,
        prior: None,
    };
    let slot = (decl.build)(&ctx).expect("a slot");
    let adm = (decl.admission)(&*slot).expect("an audience from its owned block");
    assert_eq!(adm.audience, "https://gw.example/x");

    let plain = fold(registration("door-fold-owns-none", NAMED)).expect("folds");
    assert!(plain.owned_config_sections.is_empty());
    assert!(plain.parse_endpoint.is_none() && plain.lower_endpoint.is_none());
}

// ── /healthz WITH NO MODEL LANE (ARCHITECT 2026-10-07 K5-H1 ruling; PB-43, pending OWNER signature) ──
//
// A deployment with no model lane is ready iff a configured plane OPENED this generation. The open
// is the one the kernel records when a door row builds its generation's slot (`DoorSlot::opened`),
// driven here through the row's own `build` over a door whose open answers or refuses.

/// The `/healthz` handler's status and body on a LANE-LESS fixture that configures exactly
/// `sections`, with `door`'s slot for the generation built through its row's own `build` over a
/// present section (none when `door` is `None`).
fn lane_less_healthz(
    door: Option<&'static PlaneDecl>,
    sections: &[&'static str],
) -> (u16, Vec<u8>) {
    let seeded: Vec<&'static PlaneDecl> = door.into_iter().collect();
    let _isolated = crate::plane::registry::TestRegistryIsolation::seeded(&seeded);
    let mut fixture = crate::test_support::TestApp::new().plane_sections(sections);
    if let Some(decl) = door {
        let section = DoorSection::new(
            decl.config_section,
            serde_yaml::from_str("zed: {url: 'https://z'}").unwrap(),
        );
        let slot = (decl.build)(&BuildCtx {
            endpoint_slot: None,
            agent_defs: &(),
            tool_defs: &section,
            public_url: None,
            prior: None,
        })
        .expect("a configured door builds its generation's slot");
        fixture.install_plane_runtime(decl.key, slot);
    }
    let app = fixture.build();
    tokio::runtime::Builder::new_current_thread()
        .build()
        .unwrap()
        .block_on(async {
            let resp = crate::endpoints::healthz(crate::state::CurrentApp(app)).await;
            let status = resp.status().as_u16();
            let body = axum::body::to_bytes(resp.into_body(), 1024).await.unwrap();
            (status, body.to_vec())
        })
}

/// A door whose open answers for the generation.
fn opening_door(key: &'static str, section: &'static str) -> &'static PlaneDecl {
    fold(registration(key, section)).expect("folds")
}

/// A door whose open REFUSES for the generation (its section passed its `validate`).
fn refusing_door(key: &'static str, section: &'static str) -> &'static PlaneDecl {
    let mut reg = registration(key, section);
    reg.facing = Arc::new(|_: &[u8], _: &[u8], _: Option<&str>| {
        Err("the door refused to open this generation".to_string())
    });
    fold(reg).expect("folds")
}

/// RED on the 1.5.5 rule (503 whenever there is no lane): a tools-only deployment whose plane
/// opened is ready.
#[test]
fn healthz_with_no_model_lane_is_ready_when_a_configured_plane_opened() {
    let door = opening_door("door-healthz-opened", "door_healthz_opened");
    assert_eq!(
        lane_less_healthz(Some(door), &[door.config_section]),
        (200, b"ok".to_vec()),
        "a lane-less deployment whose configured plane opened this generation is ready"
    );
}

/// The same deployment, its plane's generation refused to open: not ready, in 1.5.5's words.
#[test]
fn healthz_with_no_model_lane_is_unready_when_the_planes_open_refused() {
    let door = refusing_door("door-healthz-refused", "door_healthz_refused");
    assert_eq!(
        lane_less_healthz(Some(door), &[door.config_section]),
        (503, b"no usable lanes".to_vec()),
        "a plane that is configured but did not open makes nothing ready"
    );
}

/// An empty deployment (no plane configured, no lane) stays unready, as in 1.5.5.
#[test]
fn healthz_with_no_plane_configured_stays_unready() {
    assert_eq!(
        lane_less_healthz(None, &[]),
        (503, b"no usable lanes".to_vec()),
        "with nothing configured /healthz answers 1.5.5's 503"
    );
}

/// THE NAMES A DOOR'S GENERATION LISTS (THE DESIGN section 2, `/v1/models`): read off its slot's
/// facing in its own order, filtered as its admission judges a direct route. Ungoverned sees every
/// name; a key granting the door's scope kind sees the names it grants; a key granting only another
/// kind sees none. A slot that lists nothing, or a slot of no folded door, adds nothing.
#[test]
fn a_doors_listed_names_are_scope_filtered_as_its_admission_judges() {
    use busbar_contract::records::{ScopeRef, VirtualKey};
    let mut reg = registration("door-fold-listed", NAMED);
    reg.facing = Arc::new(|_: &[u8], _: &[u8], _: Option<&str>| {
        Ok(busbar_contract::plane_calls::DoorFacing {
            listed: vec!["zeta".to_string(), "alpha".to_string()],
            ..Default::default()
        })
    });
    let facing = (reg.facing)(b"", b"", None).expect("faces");
    let decl = fold(reg).expect("folds");
    let slot = DoorSlot {
        section: DoorSection::new(NAMED, serde_yaml::Value::Null),
        facing,
        opened: true,
    };
    let slots: std::collections::BTreeMap<
        &'static str,
        std::sync::Arc<dyn std::any::Any + Send + Sync>,
    > = [(
        decl.key,
        std::sync::Arc::new(slot) as std::sync::Arc<dyn std::any::Any + Send + Sync>,
    )]
    .into_iter()
    .collect();
    assert_eq!(
        listed(&slots, None),
        ["zeta", "alpha"],
        "ungoverned, in its order"
    );
    let key = |scopes: Vec<ScopeRef>| VirtualKey {
        allowed_scopes: Some(scopes),
        ..Default::default()
    };
    let granted = key(vec![ScopeRef {
        kind: "member".to_string(),
        value: "alpha".to_string(),
    }]);
    assert_eq!(listed(&slots, Some(&granted)), ["alpha"]);
    let pools_only = key(vec![ScopeRef::pool("zeta")]);
    assert!(listed(&slots, Some(&pools_only)).is_empty());
    let empty: std::collections::BTreeMap<
        &'static str,
        std::sync::Arc<dyn std::any::Any + Send + Sync>,
    > = std::collections::BTreeMap::new();
    assert!(listed(&empty, None).is_empty());
}
