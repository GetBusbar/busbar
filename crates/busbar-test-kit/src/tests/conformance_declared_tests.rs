// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! A store's declared secret paths (`store_door!(…, secret_refs: …)`), as a plugin's suite proves
//! them: `{env: VAR}` at a declared field resolves as the kernel resolves it; anywhere else it is
//! refused; and the store's host lends nothing (the kernel already resolved the settings).

use std::sync::Arc;

use crate::dispatch::kinds::store::Store;
use crate::dispatch::{load_linked, Bind, DispatchConfig, Dispatcher, LinkedRow, NoSink};
use crate::store_v3::wrap::{Hooks, Wrapped};

struct Plain;

impl Hooks for Plain {}

mod declaring {
    use busbar_contract::abi::mechanism::call::AbiStr;
    use busbar_contract::abi::sdk::door::abi_str;

    const SECRET_REFS: &[AbiStr] = &[abi_str("dsn"), abi_str("replicas.*.password")];

    busbar_contract::store_door!(
        super::Wrapped<super::Plain>,
        "declaring-store",
        "0",
        8,
        secret_refs: SECRET_REFS
    );
}

mod silent {
    busbar_contract::store_door!(super::Wrapped<super::Plain>, "silent-store", "0", 8);
}

fn load(door: busbar_contract::abi::mechanism::door::DoorFn) -> crate::dispatch::Plugin<Store> {
    let d = Arc::new(Dispatcher::new(DispatchConfig::default()));
    load_linked::<Store>(
        &LinkedRow::of(door).expect("the store states its Statement"),
        Bind {
            instance: Arc::from("the-instance"),
            max_inflight_cap: 8,
            sink: Arc::new(NoSink),
            dispatcher: d.adopter(),
            conns: crate::dispatch::ConnTable::NoNeeds,
        },
    )
    .expect("the door loads")
}

fn env(_: &str, r: &busbar_contract::secret_ref::SecretRef) -> Result<String, String> {
    Ok(format!("resolved:{}", r.describe()))
}

#[test]
fn a_store_door_states_its_declared_secret_paths() {
    assert_eq!(
        load(declaring::door).secret_refs(),
        ["dsn".to_string(), "replicas.*.password".to_string()]
    );
    assert!(load(silent::door).secret_refs().is_empty());
}

#[test]
fn a_reference_at_a_declared_field_resolves_as_the_kernel_resolves_it() {
    let p = load(declaring::door);
    let settings = br#"{"dsn":{"env":"PG_DSN"},"replicas":[{"password":{"env":"R1"}}],"pool":4}"#;
    let out = super::settings_as_the_kernel_resolves(&p, settings, env).expect("declared");
    let v: serde_json::Value = serde_json::from_slice(&out).expect("json");
    assert!(
        v["dsn"]
            .as_str()
            .is_some_and(|s| s.starts_with("resolved:")),
        "{v}"
    );
    assert!(
        v["replicas"][0]["password"]
            .as_str()
            .is_some_and(|s| s.starts_with("resolved:")),
        "{v}"
    );
    assert_eq!(v["pool"], serde_json::json!(4));
}

#[test]
fn a_reference_at_an_undeclared_field_is_refused_as_the_kernel_refuses_it() {
    let e = super::settings_as_the_kernel_resolves(
        &load(silent::door),
        br#"{"dsn":{"env":"PG_DSN"}}"#,
        env,
    )
    .expect_err("undeclared");
    assert!(
        e.contains("settings.dsn") && e.contains("silent-store") && e.contains("did not declare"),
        "{e}"
    );
}

#[test]
fn the_store_host_lends_nothing_and_hands_the_settings_as_resolved() {
    let p = load(declaring::door);
    let settings = br#"{"dsn":"postgres://u:pw@h/db"}"#;
    assert_eq!(
        super::host_lends(&p, settings),
        (settings.to_vec(), Vec::new())
    );
}
