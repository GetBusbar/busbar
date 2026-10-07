// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE ROOT'S LINKED TABLES: the export, diagnostic, egress, store, hook and secret axes, each a row a
//! dropped-in plugin of the same kind meets in one fold.
//!
//! The plane axis's HOT-lane both-ways proofs (the example plane fixture linked and dropped in, one
//! row and one serve) left with `busbar-plugin-example-plane` (P5, "delete plane-example"; Q128
//! audit). A plane is proven through its memory-ABI door, by its own repo's conformance run.

use super::*;
use crate::root::loader::sign::{DiagnosticDecl, SigningKey};
use crate::root::loader::PluginRegistry;
use crate::root::test_plugins;
use busbar_kernel::plane::registry::merged_boot_plane_decls;

/// THE KERNEL SERVES NO EXPORT MODULE OF ITS OWN (K9e-2: its last built-in became a linked sink),
/// so every module is a row of the axis. ARCHITECT Q-P4-12 (BUSBAR-1.6.0.md:106, "it refuses at boot
/// when two plugins claim the same thing"): a LINKED export row and a DIFFERENT dropped-in plugin
/// spelling its module refuse the boot, naming both plugins and the module. No door outranks the
/// other (compiled in = dropped in), so the ambiguity is never resolved by picking a winner. This
/// replaces the K9e-2-era rule that the linked row answered ahead. GREEN arm: the linked rows alone
/// answer their modules, and the dropped-in row alone answers its own.
#[test]
fn a_linked_export_row_and_a_different_dropped_in_plugin_spelling_its_module_refuse_the_boot() {
    let release = test_plugins::key(7);
    let doors = crate::LINKED.export_doors.iter().map(|d| (d.name, d.alias));
    for (name, alias) in doors {
        let scan = || export_row_registry(alias, "k9e-dropped", alias, "busbar", &release, vec![]);
        let rows = || linked_exports(crate::LINKED.export_doors).expect("the linked export rows");
        // RED ARM: both doors claim the module, as two different plugins.
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
        // GREEN: each door alone answers.
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

/// THE HOST'S METRIC CATALOG CANNOT DRIFT (K9a S1). Every `busbar_*` series constant the host's
/// metric modules define is in [`HOST_SERIES`], so a first-party plugin's claim on one is refused;
/// and a derived histogram series is the host's too. RED: drop an entry from the list and the
/// scan names it.
#[test]
fn the_host_series_catalog_holds_every_series_the_host_defines() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
    let sources = [
        "busbar-kernel/src/metrics/mod.rs",
        "busbar-kernel/src/telemetry.rs",
        "busbar-kernel/src/proxy/proxy_vocab.rs",
    ];
    let mut defined = Vec::new();
    for file in sources {
        let text = std::fs::read_to_string(root.join(file)).expect("read a metric module");
        // A `const NAME: &str =` followed (on its line or the next) by a `"busbar_…"` literal.
        let mut pending = false;
        for line in text.lines() {
            let decl = line.contains("const ") && line.contains(": &str =");
            if decl || pending {
                if let Some(start) = line.find("\"busbar_") {
                    let rest = &line[start + 1..];
                    defined.push(rest[..rest.find('"').expect("closed")].to_string());
                    pending = false;
                    continue;
                }
                pending = decl && line.trim_end().ends_with('=');
            }
        }
    }
    assert!(
        defined.len() >= HOST_SERIES.len(),
        "the scan found {defined:?}"
    );
    let missing: Vec<&String> = defined.iter().filter(|n| !host_series(n)).collect();
    assert!(
        missing.is_empty(),
        "host series missing from HOST_SERIES: {missing:?}"
    );
    assert!(host_series("busbar_request_duration_seconds_count"));
    assert!(!host_series("busbar_example_deliveries_total"));
}

/// A fresh `plugins/` directory holding one `kind: export` row signed by `signer` under `publisher`,
/// declaring `decls`, scanned under a posture holding the release key `[7; 32]` and allowlisting
/// any other signer as its publisher. Manifest-only: nothing here is loaded.
fn declaring_registry(
    tag: &str,
    publisher: &str,
    signer: &SigningKey,
    decls: Vec<DiagnosticDecl>,
) -> PluginRegistry {
    let name = format!("s3-{tag}");
    export_row_registry(tag, &name, &name, publisher, signer, decls)
}

/// [`declaring_registry`]'s row under the `name` and `alias` given.
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

/// **K9a S3 — PLUGIN DIAGNOSTICS join the catalogue.** A first-party plugin's declared code becomes
/// a catalogue entry one for one (its class from its thousands digit, its severity from its token),
/// so the host's fold resolves a diagnostic the plugin raises under it exactly as a built-in one.
/// RED ARMS: the same declaration from a third party is refused; a code the catalogue already holds
/// is refused (never shadowed); a class or severity that is not the host's is refused. (The loader's
/// both-ways test proves either door states the same declaration as first-party.)
#[test]
fn a_first_party_plugins_declared_codes_join_the_catalogue_and_nothing_else_does() {
    use busbar_contract::diagnostic::{Class, Severity};
    use busbar_kernel::diagnostics::{by_code, REGISTRY};
    let release = test_plugins::key(7);
    assert!(by_code(6990).is_none(), "the witness code must be free");
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

/// K5d (DECISIONS #2 rule (1), #40) — THE LINKED STORE AND THE RANKING HOOKS ARE ROWS OF THE ROOT'S
/// LINKED TABLES. The kernel names neither; `main` hands the `stores`/`hooks` tables to the kernel's
/// cold-kind axis (`root::linked::register_stores` -> `preflight::install_linked_rows`), which
/// registers them through `PluginRegistry::link` like any dropped-in row: the linked store is an
/// ephemeral in-process store that opens (a config names it; no row is a default, Q-STORE = (B));
/// the hook table is the linked ranking DOOR, whose Statement claims each built-in strategy word
/// (the root's hook axis binds it).
///
/// RED by deleting the `store-memory` / `hooks-ranking` rows of `[package.metadata.busbar.linked]`:
/// the tables carry no store (and no ranking row) to hand the kernel.
#[test]
fn the_linked_store_and_ranking_hooks_are_rows_of_the_linked_tables() {
    let stores: Vec<_> = crate::LINKED.stores.iter().map(|s| s.1).collect();
    assert_eq!(stores, [true], "one linked store: ephemeral");
    assert!(
        !(crate::LINKED.stores[0].2)().is_null(),
        "the linked store states its door"
    );
    let strategies = [
        busbar_kernel::config::STRATEGY_CHEAPEST,
        busbar_kernel::config::STRATEGY_FASTEST,
        busbar_kernel::config::STRATEGY_LEAST_BUSY,
        busbar_kernel::config::STRATEGY_USAGE,
    ];
    // Each linked hook door's claimed hook words (its Statement's `MARK_WORD_HOOK` marks).
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

/// WIRE-SECRET (THE DESIGN, "Plugins"; TODO step 28) — THE SECRET AXIS IS THE ROOT'S, OVER THE ONE
/// DISPATCHER. `env` and `file` are the linked secret plugins the root's axis answers for, by the
/// module alias their Statements declare; a reference resolves through the secret kind table on
/// `root::dispatch`'s dispatcher, on one shared instance, and the refusal text is the plugin's own
/// (1.5.5's). A module no plugin answers is refused.
///
/// RED by dropping a door from the linked table: `file` stops being linked.
#[test]
fn the_secret_axis_resolves_the_linked_sources_over_the_one_dispatcher() {
    use busbar_contract::secret::SecretAxis;
    let axis = super::link_secrets(crate::LINKED.secrets).expect("the linked secret doors state");
    assert!(axis.linked("env") && axis.linked("file") && !axis.answers("vault"));
    let env = axis.shared("env").expect("env opens");
    assert!(
        std::sync::Arc::ptr_eq(&env, &axis.shared("env").expect("env opens")),
        "one shared instance per linked plugin"
    );
    let var = "BUSBAR_WIRE_SECRET_ROOT_AXIS";
    std::env::set_var(var, "hunter2");
    let got = env
        .resolve(format!(r#"{{"key":"{var}"}}"#).as_bytes())
        .expect("a set variable resolves");
    assert_eq!(got.expose_secret().as_slice(), b"hunter2");
    std::env::remove_var(var);
    let refused = env
        .resolve(br#"{"key":"BUSBAR_WIRE_SECRET_ROOT_UNSET"}"#)
        .unwrap_err();
    assert_eq!(
        refused.text,
        "secret env:BUSBAR_WIRE_SECRET_ROOT_UNSET cannot resolve: environment variable \
         'BUSBAR_WIRE_SECRET_ROOT_UNSET' is unset"
    );
    assert!(axis.shared("vault").is_err());
}

/// A Rust-hook plane row keyed `key` (declaring section `key`), leaked for the table.
fn native(key: &'static str) -> &'static [PlaneDecl] {
    let declaration = PlaneDeclaration {
        key,
        fallback: false,
        config_section: key,
        scope_kinds: &[],
        subject_noun: key,
        admin_noun: key,
        audit_kind: key,
        card_signing_domain: None,
        card_kid_prefix: None,
        owned_config_sections: &[],
        billable_classes: &[],
        fee_units: &[],
        metric_families: &[],
        record_kinds: &[],
        required_config_sections: &[],
        trust_keys: &[],
        served_op_classes: &[],
        caller_credential_refusal: None,
    };
    let hooks = PlaneHooks {
        wire_format_names: || &[busbar_kernel::plane::WIRE_HTTP_JSON],
        ..HOT_PLANE_HOOKS
    };
    Box::leak(Box::new([PlaneDecl::assemble(declaration, hooks)]))
}

/// SEAM-L(s), THE PER-AXIS FOLD: a door row and a legacy row sharing a plane key — the door owns the
/// plane axis for it (the kernel's boot fold keeps the door's row), and the legacy row yields that
/// axis alone: a legacy row of another key is untouched, and nothing on any other axis is read here
/// (the legacy crate's other tables are its own). RED: the linked row came first and won the key,
/// so a plane flipped onto its door only when its legacy row left whole.
#[test]
fn a_door_owns_the_plane_axis_for_its_key_and_a_legacy_row_keeps_the_rest() {
    let legacy = &native("seam-l-shared")[0];
    let other = &native("seam-l-other")[0];
    let door = &native("seam-l-shared")[0];
    let rows = doors_own_their_plane_keys(vec![legacy, other, door], &[door]);
    assert_eq!(rows.len(), 2, "the legacy row yields the shared key");
    assert!(
        std::ptr::eq(rows[0], other),
        "a legacy row of another key stays"
    );
    assert!(std::ptr::eq(rows[1], door), "the door serves the plane");
    let folded = merged_boot_plane_decls(&rows, &[]);
    let shared = folded
        .iter()
        .find(|d| d.key == "seam-l-shared")
        .expect("the shared key is registered");
    assert!(
        std::ptr::eq(*shared, door),
        "the boot fold keeps the door's row"
    );
}

/// SEAM-L(s): a key two door rows both register on the same axis is a boot refusal naming both.
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

/// ONE DISPATCHER PER PROCESS: a door row's probe binds on the process's one dispatcher, so a door
/// in the build spawns no second set of `busbar-dispatch` threads (the boot test reads the count).
/// RED: the probe had a dispatcher of its own, built with the default shape.
#[test]
fn a_door_rows_probe_binds_on_the_processs_one_dispatcher() {
    assert!(Arc::ptr_eq(
        &door_probe_dispatcher(),
        &crate::root::dispatch::dispatcher()
    ));
}
