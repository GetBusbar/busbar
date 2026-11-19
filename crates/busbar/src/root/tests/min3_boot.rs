// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! PLANE-SERVICES: what the MIN-3 boot installs into each plane seat's intents. The plane itself is an ffi handle,
//! so the request path runs in the image suite (W2-SW-PLANE e2e); these are the seams the boot builds.

use std::time::{Duration, Instant};

use busbar_kernel::plane_grants::{TicketAdmitted, TicketDenied, TicketMint};
use busbar_plugin_abi::plane::DEST_INTERNAL;

use super::*;

#[test]
fn a_refused_compiled_image_refuses_boot_instead_of_falling_back() {
    use busbar_plugin_loader::refusal::{Refusal, RefusalCode};
    let rows = [super::super::linked::LinkedImage {
        alias: "fixture",
        admit: || {
            Err(Refusal::new(
                RefusalCode::Layout,
                "layout",
                "old",
                "current",
            ))
        },
    }];
    let refusal = admit_linked_images(&rows).err().expect("boot must refuse");
    assert!(refusal.contains("layout"), "{refusal}");
    assert!(refusal.contains("old"), "{refusal}");
    assert!(refusal.contains("current"), "{refusal}");
}

struct Open;

impl Tickets for Open {
    fn mint<'a>(
        &'a self,
        _: &'a LoaderCaller<'_>,
        _: TicketMint<'a>,
    ) -> BoxFut<'a, Result<(Box<str>, u64), RecordsDenied>> {
        Box::pin(core::future::ready(Ok(("bbt1.minted".into(), 99))))
    }

    fn is_ticket(&self, credential: &str) -> bool {
        credential.starts_with("bbt1.")
    }

    fn admit<'a>(
        &'a self,
        _: &'a LoaderCaller<'_>,
        _: &'a str,
        _: &'a str,
        _: u64,
    ) -> BoxFut<'a, Result<TicketAdmitted, TicketDenied>> {
        Box::pin(core::future::ready(Err(TicketDenied::Invalid)))
    }
}

fn observations() -> ObsCustody {
    ObsCustody::new(Arc::new(busbar_kernel::store::now_ms))
}

#[test]
fn every_seat_is_given_the_services_the_boot_can_build_and_no_more() {
    let services = plane_services(&observations(), Arc::new(Open), None);
    assert!(
        services.judge.is_some(),
        "JUDGE answers, fail closed without a judge"
    );
    assert!(
        services.observations.is_some(),
        "OBS_SCOPE and OBSERVE have their custody"
    );
    assert!(
        services.tickets.is_some(),
        "MINT has the ticket store the seat was built with"
    );
    // Not built at boot: each answers its fail-closed value until its owner installs it.
    assert!(services.entitlements.is_none());
    assert!(services.signer.is_none());
    assert!(services.connections.is_none());
    assert!(services.trust.is_none());
    assert!(services.media.is_none());
}

#[tokio::test]
async fn a_process_with_no_destination_judge_answers_internal_for_every_destination() {
    let judge = plane_services(&observations(), Arc::new(ClosedTickets), None)
        .judge
        .unwrap();
    let verdict = judge
        .judge("example.com", 0, 0, Instant::now() + Duration::from_secs(1))
        .await;
    assert_eq!(verdict, DEST_INTERNAL);
}

#[test]
fn tickets_are_shut_without_a_signing_key_and_open_with_one() {
    let records = BootstrapRecords;
    let shut = ticket_store(&records, None);
    assert!(
        !shut.is_ticket("bbt1.abc"),
        "no host key: nothing is a ticket"
    );
    let signing = SecureVec::from(&[7u8; 32][..]);
    let keyed = ticket_store(&records, Some(&signing));
    assert!(
        !keyed.is_ticket("Bearer-token"),
        "a credential that is not a ticket is never one"
    );
    let services = plane_services(&observations(), Arc::new(Open), None);
    let tickets = services.tickets.unwrap();
    assert!(tickets.is_ticket("bbt1.abc"));
    assert!(!tickets.is_ticket("Bearer-token"));
}

#[tokio::test]
async fn a_mint_with_no_ticket_store_is_unavailable_not_a_made_up_ticket() {
    let tickets = ClosedTickets;
    let who = busbar_kernel::plane_driver::port_intents::Namespace {
        plugin: "plane-x".into(),
        name: "x".into(),
        instance: 1,
        slot: 0,
    };
    let minted = tickets
        .mint(
            &who.caller(),
            TicketMint {
                subject: "alice",
                scope: "s",
                audience: "a",
                ttl_s: 60,
                once: false,
                prefix: "",
                record: &[],
            },
        )
        .await;
    assert!(matches!(minted, Err(RecordsDenied::Unavailable)));
    let admitted = tickets.admit(&who.caller(), "a", "bbt1.x", 1).await;
    assert!(matches!(admitted, Err(TicketDenied::Unavailable)));
}

#[test]
fn work_is_opened_only_for_a_target_on_the_instances_recovery_routes() {
    let matches = recovery_matcher(vec!["/v1/jobs/{id}".into(), "/v1/batches/{id}/poll".into()]);
    assert!(matches("/v1/jobs/42"));
    assert!(matches("/v1/jobs/42?cursor=7"));
    assert!(matches("/v1/batches/b1/poll"));
    assert!(!matches("/v1/jobs"));
    assert!(!matches("/v1/jobs/42/extra"));
    assert!(!matches("/v1/other"));
    assert!(!matches(""));
    assert!(!recovery_matcher(Vec::new())("/v1/jobs/42"));
}

fn plane(identity: &str, alias: &str) -> PlaneImage {
    PlaneImage {
        identity: identity.to_owned(),
        alias: alias.to_owned(),
    }
}

/// W2-SW-PLANE: every admitted MIN-3 plane image is one configured plane instance (the operator serves a plane by
/// serving it, IF §12.23 rule 1), named by its manifest alias (today's plane name, IF §12.10), configured with the
/// document's section of that name (its 1.5.x bag, which the plane's own `migrate` converts) or `{}`.
#[test]
fn each_admitted_plane_image_is_one_instance_named_by_its_alias_with_its_section() {
    let mut sections = std::collections::BTreeMap::new();
    sections.insert(
        "mcp",
        busbar_contract::yaml::from_str::<busbar_contract::yaml::Value>(
            "canonical_uri: https://tools.example\n",
        )
        .unwrap(),
    );
    let planes = plane_instances(
        &[
            plane("busbar-plane-mcp", "mcp"),
            plane("busbar-plane-x", ""),
        ],
        &sections,
        &Default::default(),
    )
    .unwrap();
    assert_eq!(planes.len(), 2);
    assert!(planes.iter().all(|p| matches!(p.kind, KindCode::Plane)));
    assert_eq!(
        (planes[0].identity.as_str(), planes[0].name.as_str()),
        ("busbar-plane-mcp", "mcp")
    );
    assert_eq!(
        audience_of(&planes[0].config).as_deref(),
        Some("https://tools.example"),
        "the plane's section reaches it, so its line session binds the audience it states"
    );
    assert_eq!(
        (planes[1].identity.as_str(), planes[1].name.as_str()),
        ("busbar-plane-x", "busbar-plane-x"),
        "an image with no alias is named by its identity"
    );
    assert_eq!(planes[1].config, b"{}");
}

#[test]
fn two_plane_images_answering_one_instance_name_are_refused() {
    let refusal = plane_instances(
        &[
            plane("busbar-plane-a", "dup"),
            plane("busbar-plane-b", "dup"),
        ],
        &std::collections::BTreeMap::new(),
        &Default::default(),
    )
    .err()
    .expect("one instance name, two images");
    assert!(refusal.contains("`dup`"), "{refusal}");
}

/// #297, TRANSPORT-SECURITY-POLICY §4 (AGREED 2026-11-16 ~19:05Z): a plane instance's acceptance is its own
/// section's `insecure_transport`, keyed (instance, instance); a plane whose section states none is verified TLS
/// only. The key is core's, so the bag the plane is bound from never carries it.
#[test]
fn a_plane_instance_s_accept_is_its_own_section_s_insecure_transport() {
    use busbar_plugin_abi::host_side::caller::Accept;
    let mut sections = std::collections::BTreeMap::new();
    sections.insert(
        "mcp",
        busbar_contract::yaml::from_str::<busbar_contract::yaml::Value>(
            "docs: { url: \"http://127.0.0.1:9000/mcp\" }\n",
        )
        .unwrap(),
    );
    let mut accepted = busbar_kernel::config::min3::InsecureTransportMap::new();
    accepted.insert(
        (Box::from("mcp"), Box::from("mcp")),
        busbar_kernel::config::min3::InsecureTransport {
            accept: Accept(Accept::PLAINTEXT),
            reason: "loopback test upstream".into(),
        },
    );
    let planes = plane_instances(
        &[
            plane("busbar-plane-mcp", "mcp"),
            plane("busbar-plane-a2a", "a2a"),
        ],
        &sections,
        &accepted,
    )
    .unwrap();
    assert_eq!(planes[0].limits.accept, Accept(Accept::PLAINTEXT));
    assert_eq!(
        planes[1].limits.accept,
        Accept::default(),
        "no insecure_transport in its section: verified TLS only"
    );
    assert!(
        !String::from_utf8_lossy(&planes[0].config).contains("insecure_transport"),
        "the plane's bag never carries core's key"
    );
}

/// K7: the boot's one upstream table is the config's `upstreams:` section, each entry typed with its binding
/// (IF §12.1), so every plane seat's walk and carrier compose over what the operator configured.
#[test]
fn the_boot_types_only_the_declared_registration_table() {
    use busbar_kernel::upstreams::Upstreams;
    let split = busbar_kernel::upstreams::declared(
        "plane",
        &busbar_contract::json::json!({
            "servers": {
                "docs": {"url": "https://docs.example/mcp", "auth": "corp-outbound"},
                "local": {"command": {"argv": ["/opt/mcp/server"]}},
            },
        }),
        &["/servers/*"],
        &busbar_kernel::plugin_config::upstream_anchor,
    )
    .expect("declared registrations parse");
    let table = split.definitions;
    assert_eq!(table.names().collect::<Vec<_>>(), ["docs", "local"]);
    let docs = table.get("docs").expect("docs is configured");
    assert_eq!(docs.url.as_deref(), Some("https://docs.example/mcp"));
    assert_eq!(
        docs.auth.as_ref().map(|auth| &*auth.instance),
        Some("corp-outbound")
    );
    assert!(table
        .get("local")
        .expect("local is configured")
        .command
        .is_some());
}

/// (sl3) on the MIN-3 path the recoverable gate knows the at-rest key while the store opens: the walk publishes
/// what `credentials.at_rest` resolved to through the open secret instances (2a) before the store's open (2b),
/// so a 1.5.5 store holding SigV4 credentials is admitted when a key is configured. With no block the gate
/// answers TEXT_ADD_KEY; a key that does not resolve answers the resolution's own text. One test: the verdict is
/// the process's.
#[tokio::test]
async fn the_recoverable_gate_sees_the_walks_at_rest_key_while_the_store_opens() {
    use crate::root::migrate::admit_for_host;
    let configured = SecretRef::None;
    let hex = "ab".repeat(32);
    let verdict = publish_at_rest(Some(&configured), |_, _| {
        let hex = hex.clone();
        async move { Ok(SecureVec::from(hex.into_bytes())) }
    })
    .await;
    assert_eq!(verdict, Ok(true));
    assert_eq!(
        admit_for_host(3),
        Ok(()),
        "a configured key admits the store's recoverable rows"
    );

    let verdict =
        publish_at_rest(None, |_, _| async { Err("nothing is resolved".to_owned()) }).await;
    assert_eq!(verdict, Ok(false));
    let no_key = admit_for_host(3).unwrap_err();
    assert!(no_key.contains("Set `auth.signing_key`"), "{no_key}");

    let verdict = publish_at_rest(Some(&configured), |what, _| async move {
        Err(format!("{what} could not be resolved (Denied)"))
    })
    .await;
    assert_eq!(
        verdict,
        Err("the signing key could not be resolved (Denied)".to_owned())
    );
    assert_eq!(
        admit_for_host(3),
        Err("CONFIG: the signing key could not be resolved (Denied)".to_owned())
    );
    assert_eq!(admit_for_host(0), Ok(()), "no recoverable row asks nothing");
}

#[test]
fn configured_secret_instances_use_bound_image_and_implicit_empty_settings() {
    use busbar_contract::plugin_settings::sugar_words::REWRITE_SUGAR;
    use busbar_kernel::config::grammar::SecretSource;
    use std::collections::BTreeMap;
    let mut sugars = busbar_contract::secret_ref::Sugars::default();
    sugars
        .declare(
            "fixture-secret",
            &[(REWRITE_SUGAR, "probe".into(), "key".into())],
        )
        .unwrap();
    let source = SecretSource {
        identity: "fixture-secret".into(),
        ref_schema: r#"{"type":"object"}"#.into(),
    };
    let grammar = busbar_kernel::config::Grammar::new(sugars, BTreeMap::new(), Vec::new())
        .with_secret_sources(BTreeMap::from([("fixture-secret".into(), source)]));
    let deploy = busbar_kernel::config::deploy_from_yaml_str(
        "store: {module: fixture-store, settings: {}}\nproviders: {}\nmodels: {}\n",
        &grammar,
    )
    .unwrap();
    let mut cfg = busbar_kernel::config::resolve(&deploy, &Default::default()).unwrap();
    cfg.grammar = busbar_kernel::config::grammar::GrammarField::bound(
        grammar.bind_secret_instances(&cfg.secrets).unwrap(),
    );
    let implicit = configured(&cfg, &[]).unwrap();
    let secret = implicit
        .iter()
        .find(|item| item.kind == KindCode::Secret)
        .unwrap();
    assert_eq!(secret.name, "probe");
    assert_eq!(secret.identity, "fixture-secret");
    assert_eq!(secret.config, b"{}");
    assert_eq!(
        crate::root::min3_candidate_secrets::reference_schemas(cfg.grammar().unwrap())[0]
            .0
            .as_ref(),
        "probe"
    );
}

#[test]
fn configured_hooks_join_the_typed_plan_with_their_exact_settings() {
    let grammar =
        busbar_kernel::config::Grammar::new(Default::default(), Default::default(), Vec::new());
    let deploy = busbar_kernel::config::deploy_from_yaml_str(
        "store: {module: fixture-store, settings: {}}\nproviders: {}\nmodels: {}\n",
        &grammar,
    )
    .unwrap();
    let mut cfg = busbar_kernel::config::resolve(&deploy, &Default::default()).unwrap();
    cfg.grammar = busbar_kernel::config::grammar::GrammarField::bound(grammar);
    cfg.hooks.insert(
        "guard".into(),
        busbar_contract::json::parse_str(
            r#"{"kind":"gate","module":"fixture-hook","settings":{"mode":"strict"}}"#,
        )
        .unwrap(),
    );
    let instances = configured(&cfg, &[]).unwrap();
    let hook = instances
        .iter()
        .find(|one| one.kind == KindCode::Hook)
        .expect("configured hook participates in the same typed boot plan");
    assert_eq!(hook.name, "guard");
    assert_eq!(hook.identity, "fixture-hook");
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&hook.config).unwrap(),
        serde_json::json!({"mode":"strict"})
    );
}

#[test]
fn configured_auth_uses_the_named_instance_and_only_its_plugin_settings() {
    let grammar =
        busbar_kernel::config::Grammar::new(Default::default(), Default::default(), Vec::new());
    let deploy = busbar_kernel::config::deploy_from_yaml_str(
        "store: {module: fixture-store, settings: {}}\nproviders: {}\nmodels: {}\n",
        &grammar,
    )
    .unwrap();
    let mut cfg = busbar_kernel::config::resolve(&deploy, &Default::default()).unwrap();
    cfg.grammar = busbar_kernel::config::grammar::GrammarField::bound(grammar);
    cfg.identity_providers.insert(
        "employees".into(),
        busbar_contract::json::parse_str(
            r#"{"module":"fixture-auth","settings":{"audience":"staff"},"max_admin_scope":"read-only"}"#,
        ).unwrap(),
    );
    let instances = configured(&cfg, &[]).unwrap();
    let auth = instances
        .iter()
        .find(|one| one.kind == KindCode::Auth)
        .expect("the real configured auth participates in the same typed boot plan");
    assert_eq!(auth.name, "employees");
    assert_eq!(auth.identity, "fixture-auth");
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&auth.config).unwrap(),
        serde_json::json!({"audience":"staff"})
    );
}

#[test]
fn every_named_export_enters_the_reserved_instance_plan_with_authoring_settings() {
    let grammar =
        busbar_kernel::config::Grammar::new(Default::default(), Default::default(), Vec::new());
    let deploy = busbar_kernel::config::deploy_from_yaml_str(
        "store: {module: fixture-store, settings: {}}\nproviders: {}\nmodels: {}\n",
        &grammar,
    )
    .unwrap();
    let mut cfg = busbar_kernel::config::resolve(&deploy, &Default::default()).unwrap();
    cfg.grammar = busbar_kernel::config::grammar::GrammarField::bound(grammar);
    for name in ["first", "second"] {
        cfg.export_defs.insert(
            name.into(),
            busbar_contract::yaml::from_str(
                "module: fixture-export\nsettings: {path: /var/log/busbar/export.jsonl}\n",
            )
            .unwrap(),
        );
    }
    let instances = configured(&cfg, &[]).unwrap();
    let exports: Vec<_> = instances
        .iter()
        .filter(|one| one.kind == KindCode::Export)
        .collect();
    assert_eq!(
        exports
            .iter()
            .map(|one| one.name.as_str())
            .collect::<Vec<_>>(),
        ["first", "second"]
    );
    for export in exports {
        assert_eq!(export.identity, "fixture-export");
        assert_eq!(
            busbar_contract::json::parse_value(&export.config).unwrap(),
            busbar_contract::json::json!({"path": "/var/log/busbar/export.jsonl"})
        );
    }
}

#[test]
fn actual_plane_settlement_has_its_core_owned_block_and_described_lift_authority() {
    let instance = Configured {
        kind: KindCode::Plane,
        identity: "image".to_owned(),
        name: "plane".to_owned(),
        config: b"{}".to_vec(),
        limits: Default::default(),
    };
    let described = busbar_plugin_loader::instance::Described {
        kind: KindCode::Plane,
        methods: 0,
        facts: 0,
        items: vec![(
            busbar_plugin_abi::records::tag::D_SECRET_PATH,
            b"/token".to_vec(),
        )],
        schema: None,
        metrics: Vec::new(),
    };
    let raw = busbar_plugin_loader::instance::Settled {
        config_json: SecureVec::from(&br#"{"token":"literal","display":"public"}"#[..]),
        core_cfg: Vec::new(),
        answered: true,
    };
    let answer = settlement::answer(7, &instance, &described, raw).unwrap();
    assert_eq!(answer.index, 7);
    assert_eq!(answer.path, ["plane"]);
    assert_eq!(answer.placement, busbar_migrate::BagPlacement::Block);
    assert_eq!(
        answer.allowed_lifts.into_iter().collect::<Vec<_>>(),
        ["/token"]
    );
    assert!(answer.settings.unwrap().as_str().contains("literal"));
}

#[test]
fn plugin_secret_paths_cannot_authorize_consumed_core_nonsecret_fields() {
    let instance = Configured {
        kind: KindCode::Plane,
        identity: "image".to_owned(),
        name: "plane".to_owned(),
        config: b"{}".to_vec(),
        limits: Default::default(),
    };
    let described = busbar_plugin_loader::instance::Described {
        kind: KindCode::Plane,
        methods: 0,
        facts: 0,
        items: vec![
            (
                busbar_plugin_abi::records::tag::D_UPSTREAM_PATH,
                b"/members/*".to_vec(),
            ),
            (
                busbar_plugin_abi::records::tag::D_SECRET_PATH,
                b"/members/x/url".to_vec(),
            ),
            (
                busbar_plugin_abi::records::tag::D_SECRET_PATH,
                b"/members/x/opaque".to_vec(),
            ),
        ],
        schema: None,
        metrics: Vec::new(),
    };
    let raw = busbar_plugin_loader::instance::Settled {
        config_json: SecureVec::from(&br#"{"members":{"x":{"url":"https://public","opaque":"plugin-secret","auth":{"bearer":"core-secret"}}}}"#[..]),
        core_cfg: Vec::new(),
        answered: true,
    };
    let answer = settlement::answer(7, &instance, &described, raw).unwrap();
    assert_eq!(
        answer.allowed_lifts.into_iter().collect::<Vec<_>>(),
        ["/members/x/auth/bearer", "/members/x/opaque"]
    );
}

/// LEGACY-KEYFILE-MARKER r2 §6: an auth binding's settled answer is filed as its `config:` object
/// at `auth.<name>`, the path core authors, never chosen by the plugin.
#[test]
fn an_auth_settlement_files_the_bindings_config_object() {
    let instance = Configured {
        kind: KindCode::Auth,
        identity: "busbar-auth-oauth".to_owned(),
        name: "p-outbound".to_owned(),
        config: br#"{"style":"jwt-bearer","credential":{"env":"SA"},"settings":{}}"#.to_vec(),
        limits: Default::default(),
    };
    let described = busbar_plugin_loader::instance::Described {
        kind: KindCode::Auth,
        methods: 0,
        facts: 0,
        items: vec![(
            busbar_plugin_abi::records::tag::D_SECRET_PATH,
            b"/credential".to_vec(),
        )],
        schema: None,
        metrics: Vec::new(),
    };
    let raw = busbar_plugin_loader::instance::Settled {
        config_json: SecureVec::from(
            &br#"{"style":"jwt-bearer","credential":{"file":"sa.json"},"settings":{}}"#[..],
        ),
        core_cfg: Vec::new(),
        answered: true,
    };
    let answer = settlement::answer(3, &instance, &described, raw).expect("auth settles");
    assert_eq!(answer.path, ["auth", "p-outbound"]);
    assert_eq!(answer.placement, busbar_migrate::BagPlacement::Config);
}

/// The step-5 writer files a Config placement under the binding's `config:` key, beside its
/// `module:`, and writes no `settings:` at the instance level.
#[test]
fn a_config_placement_writes_the_bindings_config_key() {
    let text = "config_version: 2\nauth:\n  p-outbound:\n    module: auth-oauth\n    config:\n      style: jwt-bearer\n      credential: {env: SA}\n";
    let settled = [busbar_migrate::Settled {
        index: 0,
        path: vec!["auth".into(), "p-outbound".into()],
        settings: Some(busbar_contract::secure::SecureString::from(
            r#"{"style":"jwt-bearer","credential":{"file":"sa.json"},"settings":{}}"#,
        )),
        core_cfg: Vec::new(),
        allowed_lifts: Default::default(),
        known_secrets: Vec::new(),
        placement: busbar_migrate::BagPlacement::Config,
    }];
    let applied = busbar_migrate::apply_settled(
        text,
        std::path::Path::new("config.yaml"),
        &settled,
        false,
        |_| None,
    )
    .expect("the binding's config is filed");
    let doc: busbar_contract::yaml::Value =
        busbar_contract::yaml::from_str(applied.text()).unwrap();
    let binding = busbar_contract::json::to_value(&doc).unwrap();
    assert_eq!(
        settlement::at(&binding, "/auth/p-outbound/config/credential/file")
            .and_then(|v| busbar_contract::json::JsonValueTrait::as_str(v)),
        Some("sa.json")
    );
    assert!(settlement::at(&binding, "/auth/p-outbound/settings").is_none());
    assert_eq!(
        settlement::at(&binding, "/auth/p-outbound/module")
            .and_then(|v| busbar_contract::json::JsonValueTrait::as_str(v)),
        Some("auth-oauth")
    );
}

fn keyfile_bound() -> busbar_contract::json::Value {
    busbar_contract::json::json!({
        "style": "jwt-bearer",
        "credential": {"env": "SA_KEY"},
        "settings": {"scope": "s", "client_secret": {"env": "CS"}}
    })
}

fn keyfile_guard(
    settled: &busbar_contract::json::Value,
    original: Option<&str>,
) -> Result<(), String> {
    let marked = ["/credential".to_owned()];
    settlement::guard_marked(
        "auth.p-outbound",
        &keyfile_bound(),
        settled,
        &["/credential", "/settings/client_secret"],
        &marked,
        &|pointer| {
            (pointer == "/credential")
                .then(|| original.map(busbar_contract::secure::SecureString::from))
                .flatten()
        },
        &|file| std::fs::metadata(file).is_ok_and(|meta| meta.is_file()),
    )
}

/// LEGACY-KEYFILE-MARKER r2 §5 with A-L3 and A-M2: a marked slot settles unchanged, or to
/// `{file: F}` naming the existing regular file its original reference resolved to. Anything else
/// is refused naming the instance and pointer, never a value.
#[test]
fn a_marked_credential_settles_only_to_its_own_existing_key_file() {
    use busbar_contract::json::json;
    let dir = crate::root::test_plugins::scratch("keyfile-marker-guard");
    let key = dir.join("sa.json");
    std::fs::write(&key, b"{}").unwrap();
    let other = dir.join("other.json");
    std::fs::write(&other, b"{}").unwrap();
    let key = key.to_str().unwrap();
    let other = other.to_str().unwrap();
    let with = |credential: busbar_contract::json::Value| {
        let mut bag = keyfile_bound();
        if let Some(object) = busbar_contract::json::JsonValueMutTrait::as_object_mut(&mut bag) {
            object.insert("credential", credential);
        }
        bag
    };
    assert_eq!(
        keyfile_guard(&keyfile_bound(), Some(key)),
        Ok(()),
        "unchanged"
    );
    assert_eq!(
        keyfile_guard(&with(json!({"file": key})), Some(key)),
        Ok(())
    );
    let dir_text = dir.to_str().unwrap();
    for (settled, original) in [
        (with(json!({"file": other})), Some(key)),
        (with(json!({"file": key})), None),
        (
            with(json!({"file": format!("{key}.missing")})),
            Some(&*format!("{key}.missing")),
        ),
        (with(json!({"file": dir_text})), Some(dir_text)),
        (with(json!({"file": "a\u{7}b"})), Some("a\u{7}b")),
        (with(json!({"file": key, "extra": 1})), Some(key)),
        (with(json!("-----BEGIN PRIVATE KEY-----")), Some(key)),
    ] {
        let refused = keyfile_guard(&settled, original).expect_err("refused");
        assert!(
            refused.contains("`auth.p-outbound`")
                && refused.contains("`/credential` was not converted to an existing key file"),
            "{refused}"
        );
        assert!(
            !refused.contains(key) && !refused.contains("BEGIN"),
            "{refused}"
        );
    }
}

/// §5 (B-B3) and B-S2: on a marked instance, an unmarked secret slot and every non-marked field
/// settle unchanged.
#[test]
fn a_marked_instance_changes_nothing_outside_its_marked_slots() {
    use busbar_contract::json::json;
    let mut secret = keyfile_bound();
    let mut field = keyfile_bound();
    let mut extra = keyfile_bound();
    if let Some(object) = busbar_contract::json::JsonValueMutTrait::as_object_mut(&mut secret) {
        object.insert(
            "settings",
            json!({"scope": "s", "client_secret": {"file": "/etc/hosts"}}),
        );
    }
    if let Some(object) = busbar_contract::json::JsonValueMutTrait::as_object_mut(&mut field) {
        object.insert(
            "settings",
            json!({"scope": "other", "client_secret": {"env": "CS"}}),
        );
    }
    if let Some(object) = busbar_contract::json::JsonValueMutTrait::as_object_mut(&mut extra) {
        object.insert("token_url", json!("https://elsewhere"));
    }
    for settled in [secret, field, extra] {
        let refused = keyfile_guard(&settled, None).expect_err("refused");
        assert!(refused.contains("`auth.p-outbound`"), "{refused}");
        assert!(
            !refused.contains("elsewhere") && !refused.contains("/etc/hosts"),
            "{refused}"
        );
    }
}
