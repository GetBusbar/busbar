// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! **`kind: auth`, BOTH WAYS — the auth kind's first both-ways witness at any tag** (DECISIONS #2
//! rule (1), K5; the #2 row records that the auth kind had none, v1.5.5 included).
//!
//! `auth-static-plugin` registered through the LINKED door (its `rlib`'s `BUSBAR_COLD_ENTRY`) and
//! the DROPPED-IN door (its `cdylib`, signed into `plugins/`) resolves to the byte-identical registry
//! row, and the module each door opens answers one script byte-identically — through `open_auth` (the
//! chain's verify seam) and `open_login` (the unified verify + login handle, with the payload schema
//! it reports). See [`super::both_ways`].
//!
//! The #2 row's ordered cost named an enveloped auth dispatch and a `dispatch_compiled_in` twin as
//! the way to reach the compiled-in half. The linked door makes neither necessary for THIS witness:
//! it reaches the compiled-in plugin through the same boundary functions the `cdylib` exports, so the
//! compiled-in and dropped-in halves are driven by one host-side load and compared on what the host
//! is handed. An observability envelope on the auth wire (#85 covered `export` only) is a separate
//! question this test does not answer.
//!
//! RED by planting the door bypass the axis replaces — linked rows handed to [`PluginRegistry::link`]
//! and never registered — which leaves the linked registry with no row for the name.

use super::both_ways::{both_doors, statement};
use busbar_api::{AuthModule, AuthPlugin};

/// The plugin's config: one accepted token and the identity it grants.
const CFG: &str = r#"{"token": "sekret", "id": "alice", "roles": ["platform"]}"#;

/// The candidates the script presents: the accepted token, a wrong one, none.
const CANDIDATES: [Option<&str>; 3] = [Some("sekret"), Some("not-the-token"), None];

/// The verify seam's transcript: the runtime identity, whether it is cacheable, and each verdict.
fn verify_script(module: &dyn AuthModule) -> String {
    let verdicts: Vec<String> = CANDIDATES
        .iter()
        .map(|c| format!("{c:?} -> {:?}", module.authenticate(*c)))
        .collect();
    format!(
        "name={} cacheable={}\n{}",
        module.name(),
        module.cacheable(),
        verdicts.join("\n")
    )
}

/// THE EXIT TEST: `auth-static-plugin` linked and dropped in registers the same row and opens a
/// module that verifies the same.
#[test]
fn a_linked_and_a_dropped_in_auth_module_register_byte_identical_rows() {
    let manifest = statement(
        "auth",
        "static-auth",
        "static",
        busbar_plugin::cold::AUTH_ABI_VERSION,
    );
    let Some([linked, dropped]) = both_doors(
        manifest,
        &busbar_auth_static_plugin::BUSBAR_COLD_ENTRY,
        "busbar_auth_static_plugin",
        |registry| {
            registry
                .open_auth("static", CFG)
                .expect("the auth module opens through its alias")
        },
        |opened| verify_script(opened.as_ref()),
    ) else {
        eprintln!("skip: auth-static-plugin cdylib not built");
        return;
    };
    assert!(
        !linked.0.starts_with("no row"),
        "the linked door registered no row: {}",
        linked.0
    );
    assert!(
        linked.1.contains("Identify"),
        "the linked module identified the accepted token: {}",
        linked.1
    );
    assert_eq!(linked, dropped, "the two doors must register one row");
}

/// The same both ways through the LOGIN handle: the payload schema `open_login` reports, and the
/// verify transcript of the unified handle.
#[test]
fn a_linked_and_a_dropped_in_login_handle_answer_identically() {
    let manifest = statement(
        "auth",
        "static-auth",
        "static",
        busbar_plugin::cold::AUTH_ABI_VERSION,
    );
    let Some([linked, dropped]) = both_doors(
        manifest,
        &busbar_auth_static_plugin::BUSBAR_COLD_ENTRY,
        "busbar_auth_static_plugin",
        |registry| {
            registry
                .open_login("static-auth", CFG)
                .expect("the login handle opens through its name")
        },
        |(handle, abi): &(Box<dyn AuthPlugin>, u32)| {
            let verdicts: Vec<String> = CANDIDATES
                .iter()
                .map(|c| format!("{c:?} -> {:?}", handle.authenticate(*c)))
                .collect();
            format!("abi={abi} name={}\n{}", handle.name(), verdicts.join("\n"))
        },
    ) else {
        eprintln!("skip: auth-static-plugin cdylib not built");
        return;
    };
    assert!(
        linked.1.contains("Identify"),
        "the linked handle identified the accepted token: {}",
        linked.1
    );
    assert_eq!(
        linked, dropped,
        "the two doors must hand back one login handle"
    );
}
