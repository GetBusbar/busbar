// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;
use crate::root::loader::sign::{DiagnosticDecl, SigningKey};
use crate::root::loader::PluginRegistry;
use crate::root::test_plugins;

#[test]
fn a_linked_export_row_and_a_different_dropped_in_plugin_spelling_its_module_refuse_the_boot() {
    let release = test_plugins::key(7);
    let doors = crate::LINKED.export_doors.iter().map(|d| (d.name, d.alias));
    for (name, alias) in doors {
        let scan = || export_row_registry(alias, "k9e-dropped", alias, "busbar", &release, vec![]);
        let rows = || linked_exports(crate::LINKED.export_doors).expect("the linked export rows");

        let refused = scan()
            .link(rows())
            .expect_err("a linked row and a different dropped-in plugin claiming one module");
        assert!(
            refused.contains("claim conflict")
                && refused.contains(&format!("'{alias}'"))
                && refused.contains(name)
                && refused.contains("k9e-dropped"),
            "{alias}: {refused}"
        );

        let answering = |r: &PluginRegistry| r.resolve(alias).map(|p| p.manifest.name.clone());
        let alone = PluginRegistry::empty()
            .link(rows())
            .expect("the linked rows alone");
        assert_eq!(answering(&alone).as_deref(), Some(name), "{alias}");
        assert_eq!(
            answering(&scan()).as_deref(),
            Some("k9e-dropped"),
            "{alias}"
        );
    }
}

#[cfg(linked_axis_export_doors)]
#[test]
fn a_linked_export_declares_stating_needs_boots() {
    let doors = crate::LINKED.export_doors;
    let first = doors
        .first()
        .expect("an export door is linked under the axis");

    let restated = |needs: &str| -> Vec<crate::root::linked::LinkedDoorExport> {
        doors
            .iter()
            .map(|d| {
                let mut doc: serde_json::Value =
                    serde_json::from_str(d.declares).expect("the linked row's declares is JSON");
                doc["needs"] = serde_json::from_str(needs).expect("a needs value");
                crate::root::linked::LinkedDoorExport {
                    declares: Box::leak(doc.to_string().into_boxed_str()),
                    ..*d
                }
            })
            .collect()
    };
    let plain = linked_exports(doors).expect("the linked export rows");
    let networked = linked_exports(&restated(r#"["scheme-a", "scheme-b"]"#))
        .expect("a linked declares stating `needs` reads");
    assert_eq!(
        networked
            .iter()
            .map(|p| &p.manifest.declares)
            .collect::<Vec<_>>(),
        plain
            .iter()
            .map(|p| &p.manifest.declares)
            .collect::<Vec<_>>(),
        "the manifest section carries no needs"
    );
    PluginRegistry::empty()
        .link(networked)
        .expect("the rows link: the boot proceeds");

    let Err(refused) = linked_exports(&restated(r#""scheme-a""#)) else {
        panic!("a `needs` that is not a list must refuse the rows");
    };
    assert!(
        refused.contains(first.name) && refused.contains("`needs`"),
        "{refused}"
    );
}

#[cfg(linked_axis_export_doors)]
#[test]
fn a_linked_doors_former_name_resolves_its_module() {
    let d = crate::LINKED.export_doors.first().expect("an export door");
    let row = crate::root::linked::LinkedDoorExport {
        name: "x-current",
        alias: "x-current",
        former_names: &["x-old"],
        ..*d
    };
    let registry = PluginRegistry::empty()
        .link(linked_exports(&[row]).expect("the row reads"))
        .expect("the row links");
    let answered = registry.resolve("x-old").map(|p| p.manifest.name.clone());
    assert_eq!(answered.as_deref(), Some("x-current"));
}

#[test]
fn a_doors_words_are_its_former_names_then_its_alias_rewrites() {
    use busbar_contract::abi::mechanism::door::{REWRITE_ALIAS, REWRITE_SUGAR};
    let rewrites = vec![
        (REWRITE_SUGAR, "tok".to_string(), "token".to_string()),
        (REWRITE_ALIAS, "x-alias".to_string(), String::new()),
    ];
    assert_eq!(
        crate::root::linked::door_words(&["x-old"], &rewrites),
        ["x-old", "x-alias"]
    );
    assert!(crate::root::linked::door_words(&[], &[]).is_empty());
}

#[cfg(linked_axis_export_doors)]
#[test]
fn a_former_name_another_linked_door_answers_to_is_a_claim_conflict() {
    let d = crate::LINKED.export_doors.first().expect("an export door");
    let one = crate::root::linked::LinkedDoorExport {
        name: "x-first",
        alias: "x-first",
        former_names: &["x-alias"],
        ..*d
    };
    let two = crate::root::linked::LinkedDoorExport {
        name: "x-alias",
        alias: "x-alias",
        former_names: &[],
        ..*d
    };
    let refused = PluginRegistry::empty()
        .link(linked_exports(&[one, two]).expect("the rows read"))
        .expect_err("two doors answering to one word");
    assert!(
        refused.contains("claim conflict") && refused.contains("x-alias"),
        "{refused}"
    );
}

#[test]
fn a_host_series_and_its_derived_histogram_series_are_the_hosts() {
    assert!(host_series("busbar_request_duration_seconds_count"));
    assert!(!host_series("busbar_example_deliveries_total"));
}

fn declaring_registry(
    tag: &str,
    publisher: &str,
    signer: &SigningKey,
    decls: Vec<DiagnosticDecl>,
) -> PluginRegistry {
    let name = format!("s3-{tag}");
    export_row_registry(tag, &name, &name, publisher, signer, decls)
}

fn export_row_registry(
    tag: &str,
    name: &str,
    alias: &str,
    publisher: &str,
    signer: &SigningKey,
    decls: Vec<DiagnosticDecl>,
) -> PluginRegistry {
    let dir = test_plugins::scratch(&format!("root-s3-{tag}"));
    let mut manifest = test_plugins::manifest("export", name, publisher);
    manifest.alias = alias.into();
    manifest.declares.diagnostics = decls;
    let lib = b"a manifest-only row";
    std::fs::write(
        dir.join("s3.tar.gz"),
        test_plugins::signed(signer, manifest, lib),
    )
    .unwrap();
    let mut policy = test_plugins::release_policy(&test_plugins::key(7));
    policy.publishers = [(publisher.to_string(), signer.verifying_key())]
        .into_iter()
        .filter(|_| publisher != "busbar")
        .collect();
    let registry = test_plugins::boot_with(&dir, &policy);
    let _ = std::fs::remove_dir_all(&dir);
    registry
}

fn decl(code: u16, severity: &str) -> DiagnosticDecl {
    DiagnosticDecl {
        code,
        slug: format!("s3-code-{code}"),
        title: "A declared plugin code".into(),
        severity: severity.into(),
        summary: "The plugin raised it.".into(),
        action: "Read the plugin's docs.".into(),
        since: "1.6.0".into(),
    }
}

#[test]
fn a_first_party_plugins_declared_codes_join_the_catalogue_and_nothing_else_does() {
    use busbar_contract::diagnostic::{Class, Severity};
    use busbar_kernel::diagnostics::{Catalogue, REGISTRY};
    let release = test_plugins::key(7);
    assert!(
        Catalogue::NEUTRAL.by_code(6990).is_none(),
        "the witness code must be free"
    );
    let registry = declaring_registry("ok", "busbar", &release, vec![decl(6990, "actionable")]);
    let declared = declared_diagnostics(&registry, &[]).expect("a first-party declaration joins");
    assert_eq!(declared.len(), 1);
    let d = declared[0];
    assert_eq!(
        (d.code, d.class, d.severity, d.slug, d.retired),
        (
            6990,
            Class::Plugins,
            Severity::Actionable,
            "s3-code-6990",
            false
        )
    );
    assert_eq!(d.banner().to_string(), "BUSBAR-6990");

    let acme = test_plugins::key(8);
    let third = declaring_registry("third", "acme", &acme, vec![decl(6990, "actionable")]);
    let refused = declared_diagnostics(&third, &[]).expect_err("a third party is refused");
    assert!(refused.contains("not first-party"), "{refused}");

    let taken = REGISTRY[0].code;
    for (tag, bad) in [
        ("taken", decl(taken, "actionable")),
        ("class", decl(990, "actionable")),
        ("severity", decl(6991, "loud")),
    ] {
        let registry = declaring_registry(tag, "busbar", &release, vec![bad]);
        let refused = declared_diagnostics(&registry, &[]).expect_err(tag);
        assert!(refused.starts_with("plugin 's3-"), "{tag}: {refused}");
    }
}

#[test]
fn the_linked_store_and_ranking_hooks_are_rows_of_the_linked_tables() {
    let stores: Vec<_> = crate::LINKED.stores.iter().map(|s| s.1).collect();
    assert_eq!(stores, [true], "one linked store: ephemeral");
    assert_eq!(
        (crate::LINKED.stores[0].2)().magic(),
        busbar_contract::abi::mechanism::DOOR_MAGIC,
        "the linked store states its door"
    );
    let strategies = [
        busbar_kernel::config::STRATEGY_CHEAPEST,
        busbar_kernel::config::STRATEGY_FASTEST,
        busbar_kernel::config::STRATEGY_LEAST_BUSY,
        busbar_kernel::config::STRATEGY_USAGE,
    ];

    let words: Vec<Vec<String>> = crate::LINKED
        .hook_doors
        .iter()
        .map(|door| {
            let stated =
                crate::root::loader::dispatch::rendering_of(*door).expect("the door states");
            busbar_contract::abi::mechanism::rendering::read(&stated)
                .expect("the rendering reads")
                .mark_words
                .into_iter()
                .filter(|(class, _)| {
                    *class == busbar_contract::abi::mechanism::door::MARK_WORD_HOOK
                })
                .map(|(_, word)| word)
                .collect()
        })
        .collect();
    let want: Vec<Vec<String>> = if cfg!(linked_axis_hooks) {
        vec![strategies.iter().map(|s| s.to_string()).collect()]
    } else {
        Vec::new()
    };
    assert_eq!(words, want, "the ranking door claims every strategy word");
}

#[test]
fn a_key_two_doors_register_refuses_the_boot_naming_both() {
    assert!(refuse_a_key_two_doors_register(&[
        ("door-a".to_string(), "k1"),
        ("door-b".to_string(), "k2"),
    ])
    .is_ok());
    let refusal = refuse_a_key_two_doors_register(&[
        ("door-a".to_string(), "k1"),
        ("door-b".to_string(), "k1"),
    ])
    .expect_err("one axis, one owner");
    assert!(
        refusal.contains("door-a") && refusal.contains("door-b") && refusal.contains("k1"),
        "{refusal}"
    );
}

#[test]
fn a_door_rows_probe_binds_on_the_processs_one_dispatcher() {
    assert!(Arc::ptr_eq(
        &door_probe_dispatcher(),
        &crate::root::dispatch::dispatcher()
    ));
}

#[test]
fn the_admin_compiled_in_hooks_are_the_linked_hook_rows() {
    assert_eq!(
        crate::LINKED_HOOK_NAMES.len(),
        crate::LINKED.hook_doors.len(),
        "one printed name per linked hook row: {:?}",
        crate::LINKED_HOOK_NAMES
    );
    let mut seen = std::collections::HashSet::new();
    for name in crate::LINKED_HOOK_NAMES {
        assert!(
            !name.is_empty(),
            "a linked hook row's printed name is not empty"
        );
        assert!(
            seen.insert(*name),
            "`{name}` is printed for two linked hook rows"
        );
    }
    assert_eq!(
        cfg!(linked_axis_hooks),
        !crate::LINKED_HOOK_NAMES.is_empty(),
        "a build that links a hook row prints it"
    );
}
