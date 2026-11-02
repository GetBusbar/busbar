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
fn the_secret_axis_resolves_the_linked_sources_over_the_one_dispatcher() {
    use busbar_contract::secret::SecretAxis;
    let axis = super::link_secrets(crate::LINKED.secrets, crate::LINKED.secret_declares)
        .expect("the linked secret doors state");
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
    assert_eq!(
        got.expose(&busbar_kernel::seal::lend()).as_slice(),
        b"hunter2"
    );
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

#[cfg(linked_axis_export_doors)]
#[test]
fn the_linked_scrape_sink_renders_the_recorder_snapshot_byte_identically() {
    let module = busbar_kernel_testkit::test_support::export_axis::scrape_module();
    let registry = PluginRegistry::empty()
        .link(linked_exports(crate::LINKED.export_doors).expect("the linked export rows"))
        .expect("the linked rows alone");
    assert!(
        !module.is_empty(),
        "the build links the scrape sink, so the frozen scrape module word is set"
    );
    assert!(
        registry.resolve(module).is_some(),
        "the linked export rows carry the scrape sink under `{module}`"
    );
    let sink = crate::root::loader::export_axis::ExportRows::new(
        &registry,
        crate::root::dispatch::dispatcher(),
    )
    .open(
        module,
        "export.metrics",
        &serde_json::json!({"buffer_seconds": 60}),
    )
    .expect("the scrape sink opens");

    let own = "# TYPE busbar_requests_total counter\n\
               busbar_requests_total{pool=\"a\\\"b\\\\c\\nd\",outcome=\"ok\"} 3\n\
               \n\
               # TYPE busbar_plane_request_duration_seconds summary\n\
               busbar_plane_request_duration_seconds{quantile=\"0.99\"} 0.0125\n\
               busbar_plane_request_duration_seconds_sum 1e-3\n\
               busbar_plane_request_duration_seconds_count 4\n\
               \n\
               # HELP busbar_request_duration_seconds request latency\n\
               # TYPE busbar_request_duration_seconds histogram\n\
               busbar_request_duration_seconds_bucket{le=\"0.5\"} 1\n\
               busbar_request_duration_seconds_bucket{le=\"+Inf\"} 2\n\
               busbar_request_duration_seconds_sum 0.75\n\
               busbar_request_duration_seconds_count 2\n\
               \n";
    let families = busbar_contract::export_calls::parse_families(own).expect("the text snapshots");
    let body = sink.scrape(&families).expect("the sink renders");
    assert_eq!(
        body,
        own.as_bytes(),
        "the scrape is the recorder's bytes, back"
    );
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

mod blocked_disk_resolver {
    use busbar_contract::abi::mechanism::call::Outcome;
    use busbar_contract::abi::sdk::life::{Held, Life, Refusal};
    use busbar_contract::abi::sdk::{Instance, Lent, Out, SafeSlot};
    use busbar_contract::abi::secret::{ResolveIn, ResolveOut};
    use std::sync::mpsc::{Receiver, Sender};
    use std::sync::Mutex;

    pub static HOLD: Mutex<Option<(Sender<()>, Receiver<()>)>> = Mutex::new(None);
    pub struct Source;
    impl Life for Source {
        const CANCEL: u32 = busbar_contract::abi::secret::cancel::ABORTED;
        fn open(_: &[u8], _: &[&[u8]], _: u64) -> Result<Self, Refusal> {
            Ok(Self)
        }
    }
    pub struct Resolve;
    impl SafeSlot for Resolve {
        type In = ResolveIn;
        type Out = ResolveOut;
        type State = Held<Source>;
        fn call(
            _: Instance<'_, Held<Source>>,
            input: Lent<'_, ResolveIn>,
            mut out: Out<'_, ResolveOut>,
        ) -> Outcome {
            let hold = HOLD.lock().unwrap().take().expect("one controlled resolve");
            let _ = hold.0.send(());
            let _ = hold.1.recv();
            busbar_contract::abi::sdk::cred::resolved(
                input,
                &mut out,
                busbar_contract::abi::sdk::cred::Held::new(b"resolved".to_vec()),
            )
        }
    }
    busbar_contract::plugin_door! {
        ops: busbar_contract::abi::secret::Ops,
        statement: busbar_contract::abi::sdk::door::statement("blocked-disk-source", "0", 1),
        lifecycle: life(Source),
        kind_ops: { resolve: busbar_contract::abi::sdk::Safe<Resolve> },
    }
}

#[test]
fn a_loaded_blocking_disk_resolver_leaves_the_roots_append_lane_running() {
    use crate::root::loader::secret_calls::SecretRows;
    use busbar_contract::abi::mechanism::call::Outcome;
    use busbar_contract::config_time::ConfigScope;
    use busbar_contract::secret::SecretAxis;
    use busbar_contract::services::{DiskDest, DiskRotate};

    let (entered_tx, entered) = std::sync::mpsc::channel();
    let (release, released) = std::sync::mpsc::channel();
    *blocked_disk_resolver::HOLD.lock().unwrap() = Some((entered_tx, released));
    struct Release(Option<std::sync::mpsc::Sender<()>>);
    impl Drop for Release {
        fn drop(&mut self) {
            if let Some(tx) = self.0.take() {
                let _ = tx.send(());
            }
        }
    }
    let release = Release(Some(release));
    let mut rows =
        SecretRows::new(crate::root::dispatch::dispatcher, || None).with_disk_lane(super::disk_run);
    rows.link(blocked_disk_resolver::door).unwrap();
    rows.declare_linked(blocked_disk_resolver::door, r#"{"disk":true}"#)
        .unwrap();
    let source = rows.shared("blocked-disk-source").unwrap();
    let resolver =
        std::thread::spawn(move || source.resolve_at_config(b"{}", &ConfigScope::config_time()));
    let held = entered.recv_timeout(std::time::Duration::from_secs(10));
    let path = std::env::temp_dir().join(format!(
        "busbar-resolver-append-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let (done_tx, done) = std::sync::mpsc::channel();
    let submitted = super::disk_lane().submit(
        DiskDest {
            key: "controlled-resolver".into(),
            path: path.display().to_string(),
            rotate_at: None,
            rotate: DiskRotate::Truncate,
        },
        b"still-appending\n".to_vec(),
        Box::new(move |report| {
            let _ = done_tx.send(report);
        }),
    );
    let completed_while_blocked = done.recv_timeout(std::time::Duration::from_secs(2));

    drop(release);
    let resolved = resolver.join().unwrap();
    if completed_while_blocked.is_err() {
        let _ = done.recv_timeout(std::time::Duration::from_secs(10));
    }
    let bytes = std::fs::read(&path);
    let _ = std::fs::remove_file(&path);
    held.expect("the loaded secret source entered its blocking resolve");
    assert!(
        submitted.is_ok(),
        "the append queue admits while resolve is blocked"
    );
    assert_eq!(
        completed_while_blocked
            .expect("append and its completion proceed before the resolver returns")
            .outcome,
        Outcome::Ready
    );
    assert!(resolved.is_ok(), "the released fixture resolves normally");
    assert_eq!(bytes.unwrap(), b"still-appending\n");
}
