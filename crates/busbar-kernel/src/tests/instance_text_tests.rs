// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE REFUSALS THAT NAME AN INSTANCE, held to the bytes 1.5.5 printed while the kernel stops
//! spelling the instance (Law 1; THE DESIGN §1: "refusal texts and `--validate` lists that name
//! instances are rendered from the plugins' rows, byte-identical to 1.5.5"). The store remedy is
//! rendered from the linked store row that states the `ephemeral` mark; the retired auth-chain words
//! come from the root legacy table.

/// 1.5.5's refusal for a plugin store named while the plugin subsystem is off
/// (v1.5.5:crates/busbar/src/main.rs:1843-1848), byte for byte.
#[test]
fn a_plugin_store_with_plugins_off_is_refused_in_1_5_5s_bytes() {
    let dir = crate::tests::tmp_plugin_dir("instance-text-off");
    let plugins = crate::config::PluginsCfg {
        enabled: false,
        dir: dir.to_string_lossy().into_owned(),
        ..Default::default()
    };
    let err = crate::plugins_preflight(
        Some(&crate::config::StoreCfg {
            module: "durable-kv".to_string(),
            settings: serde_json::Map::new(),
        }),
        None,
        &Default::default(),
        &Default::default(),
        &plugins,
        &Default::default(),
    )
    .unwrap_err();
    assert_eq!(
        err,
        format!(
            "store.module: 'durable-kv' requires the plugin subsystem, but plugins.enabled is \
             false (the default). Set plugins.enabled: true and place the signed 'durable-kv' \
             store plugin tarball in the plugins directory ('{}'), or set store.module: memory.",
            plugins.dir
        )
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// 1.5.5's refusal for a plugin store no directory row supplies
/// (v1.5.5:crates/busbar/src/main.rs:1966-1972): its words around the loadable list, byte for byte.
#[test]
fn a_missing_plugin_store_is_refused_in_1_5_5s_bytes() {
    let dir = crate::tests::tmp_plugin_dir("instance-text-missing");
    let plugins = crate::config::PluginsCfg {
        enabled: true,
        dir: dir.to_string_lossy().into_owned(),
        ..Default::default()
    };
    let err = crate::plugins_preflight(
        Some(&crate::config::StoreCfg {
            module: "durable-kv".to_string(),
            settings: serde_json::Map::new(),
        }),
        None,
        &Default::default(),
        &Default::default(),
        &plugins,
        &Default::default(),
    )
    .unwrap_err();
    let head = format!(
        "no plugin matching store.module: 'durable-kv' is installed in '{}' (plugins ARE \
         enabled; loadable: [",
        plugins.dir
    );
    let tail = "]). Two things to check: is the plugin subsystem enabled? (it is) — and is the \
                signed tarball actually IN the folder? Add it to plugins.fetch or drop the signed \
                tarball in the directory, or set store.module: memory.";
    assert!(err.starts_with(&head), "not 1.5.5's head:\n{err}");
    assert!(err.ends_with(tail), "not 1.5.5's tail:\n{err}");
    let _ = std::fs::remove_dir_all(&dir);
}

/// The kernel's own code spells none of the instances these refusals name: the memory store, the
/// retired static-token modules, the authorization-server plane's crate. A refusal naming one
/// renders it from a row (a linked row's key, the root legacy table), so the bytes above hold only
/// while the rows carry them.
#[test]
fn the_kernel_spells_no_instance_in_these_refusals() {
    let sources = [
        (
            "src/preflight.rs",
            include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/preflight.rs")),
        ),
        (
            "src/config_validate/mod.rs",
            include_str!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/src/config_validate/mod.rs"
            )),
        ),
        (
            "src/config/migrate.rs",
            include_str!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/src/config/migrate.rs"
            )),
        ),
        (
            "src/config/mod.rs",
            include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/config/mod.rs")),
        ),
        (
            "src/appbuild.rs",
            include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/appbuild.rs")),
        ),
    ];
    let spelled = [
        "store.module: memory",
        "\"static-tokens\"",
        "busbar-core-oauth2",
    ];
    let found: Vec<String> = sources
        .iter()
        .flat_map(|(path, src)| {
            spelled
                .iter()
                .filter(|w| src.contains(*w))
                .map(move |w| format!("{path} spells `{w}`"))
        })
        .collect();
    assert!(found.is_empty(), "{found:#?}");
}

/// 1.5.5's refusal for a reference to a secret module nothing linked answers, with no plugin
/// subsystem (v1.5.5:crates/busbar/src/config/secret.rs:101-106), byte for byte: the list is
/// rendered from the build's linked secret rows, in link order.
#[test]
fn an_unlinked_secret_module_with_no_plugins_is_refused_in_1_5_5s_bytes() {
    let err = crate::config::secret::SecretResolver::builtins_only()
        .resolve(&crate::config::SecretRef {
            module: "acme-vault".to_string(),
            settings: serde_json::Map::new(),
        })
        .unwrap_err();
    assert_eq!(
        err,
        "secret module 'acme-vault' is not a built-in (`env` / `file`) and the plugin subsystem \
         is not enabled, so no secret plugin can resolve secret module 'acme-vault'; a secret \
         that cannot resolve is a hard error (fail-closed)"
    );
}

/// The kernel's code spells no secret module in these refusals' lists.
#[test]
fn the_kernel_spells_no_secret_module_list() {
    for (path, src) in [
        (
            "src/preflight.rs",
            include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/preflight.rs")),
        ),
        (
            "src/config/secret.rs",
            include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/config/secret.rs")),
        ),
    ] {
        for list in ["(`env` | `file`)", "(`env` / `file`)"] {
            assert!(!src.contains(list), "{path} spells `{list}`");
        }
    }
}
