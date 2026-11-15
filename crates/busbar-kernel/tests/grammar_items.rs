// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! SECRET-SHORTHAND-BOOT MR-B2 (§3.6): plane sections and outbound auth styles are process-lifetime.
//! A read's grammar lists each one as phase 1 judged it against what this process registered at
//! start, and a document that writes one the read does not let count is refused before its typed
//! parse, naming the module and the cause, never as an unknown field.
//!
//! This binary installs a phase 1 double that judges: the section `fixture-plane` of a running
//! plane the read no longer admits, and the style `fixture-style` of an auth module admitted after
//! start.

use std::collections::BTreeMap;

use busbar_contract::secret_ref::Sugars;
use busbar_kernel::config::grammar::{
    Grammar, GrammarRefusal, Item, ItemKind, PhaseOneIn, Standing,
};
use busbar_kernel::config::EnvSubst;

const NOT_ADMITTED: &str = "\"fixture-plane.tar.gz\" is no longer in plugins.dir";

fn phase_one(_: &PhaseOneIn<'_>) -> Result<Grammar, GrammarRefusal> {
    Ok(
        Grammar::new(Sugars::default(), BTreeMap::new(), Vec::new()).with_items(vec![
            Item {
                kind: ItemKind::Section,
                name: "fixture-plane".into(),
                module: "fixture-plane-module".into(),
                image: "a".repeat(64),
                standing: Standing::NotAdmitted(NOT_ADMITTED.into()),
            },
            Item {
                kind: ItemKind::Style,
                name: "fixture-style".into(),
                module: "fixture-auth".into(),
                image: "b".repeat(64),
                standing: Standing::Unregistered,
            },
        ]),
    )
}

fn publish() {
    static ONCE: std::sync::Once = std::sync::Once::new();
    ONCE.call_once(|| {
        busbar_kernel::preflight::publish_root_rows(busbar_kernel::preflight::RootInstall {
            grammar: Some(phase_one),
            ..Default::default()
        });
    });
}

fn scratch(tag: &str, body: &str) -> std::path::PathBuf {
    let dir =
        std::env::temp_dir().join(format!("busbar-grammar-items-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("scratch dir");
    let config = dir.join("config.yaml");
    std::fs::write(
        &config,
        format!("models: {{}}\nauth:\n  admin_auth: []\n{body}"),
    )
    .expect("config");
    config
}

/// R16 (§3.6, audit E): a running plane whose module the read's `plugins:` block no longer admits
/// (its file removed, `enabled: false`, a trust or floor edit) refuses a read that writes its
/// section, naming the module and the cause. The running generation is not touched: the refusal
/// comes before the typed parse, so nothing is built.
#[test]
fn running_plane_made_inadmissible_refuses_reload_and_keeps_serving() {
    publish();
    let config = scratch(
        "not-admitted",
        "providers: {}\nfixture-plane:\n  entry: {}\n",
    );
    let refused = busbar_kernel::load_config_from_disk(&config, None, false, EnvSubst::Lenient)
        .map(|_| ())
        .expect_err("the section's module is not admitted by this read");
    assert!(
        refused.contains("`fixture-plane:` is the section of `fixture-plane-module`")
            && refused.contains("which this read's plugins: block does not admit")
            && refused.contains(NOT_ADMITTED)
            && refused.contains("the running process still serves the current generation"),
        "the refusal names the module and the cause: {refused}"
    );
    let _ = std::fs::remove_dir_all(config.parent().expect("scratch dir"));
}

/// R15 (§3.6, tie-break B3): an outbound auth style whose module was admitted after start cannot
/// be served by this process (its auth set is bound at start), so a read that names it gets the
/// restart refusal, not an unknown style.
#[test]
fn style_admitted_after_start_gets_the_restart_refusal() {
    publish();
    let config = scratch(
        "unregistered-style",
        "providers:\n  up:\n    base_url: https://up.example\n    auth: fixture-style\n",
    );
    let refused = busbar_kernel::load_config_from_disk(&config, None, false, EnvSubst::Lenient)
        .map(|_| ())
        .expect_err("the style's module was not registered at start");
    assert!(
        refused.contains("outbound auth style `fixture-style` is the style of `fixture-auth`")
            && refused.contains("which this process did not load at start")
            && refused.contains("write it in the config file and restart"),
        "the refusal is the restart refusal: {refused}"
    );
    let _ = std::fs::remove_dir_all(config.parent().expect("scratch dir"));
}
