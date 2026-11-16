// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The migrate suite body (IF §14, round 31). Owned by the migrate agent: this is the only file it edits. There is
//! no `migrate` ABI method: a plugin migrates inside its `open`, so every step below is an `open_<kind>` through
//! the registry (bind, inline steps, `decode_settled`, `unbind_refs`), driven by [`super::harness::Harness`].
//!
//! The cases, in order:
//! 1. Open the older `bag` as its kind. `Settled { config, core_cfg }`: the open succeeds; the settled CONFIG
//!    equals `config` (canonical JSON compare; `None` = the bag was canonical already, so no CONFIG or an echo of
//!    the bag) and the CORE_CFG fragments equal `core_cfg` (section, name, JSON value). `Refused(code)`: the open
//!    fails REFUSED `code`, nothing is settled and the plugin wrote nothing.
//! 2. Fixed point: open the settled CONFIG (or the bag when none came back) again. It must open, answer no
//!    CONFIG, and write nothing (current data costs one marker read and no write; a read is not countable
//!    through `FakeNeeds`, a write is: `records()` is unchanged).
//! 3. Newer: the canonical settings with their version marker raised must answer REFUSED R_VERSION whose text
//!    starts `NEWER`, with no instance and nothing written. The marker is found generically, as the first of the
//!    conventional numeric version keys at the top level of the canonical settings; a plugin that keeps its
//!    version elsewhere (in its data, not its settings) has no settings-level case here and its own crate test
//!    covers it.

use std::sync::Arc;

use busbar_contract::json::{
    self as facade, JsonContainerTrait, JsonValueMutTrait, JsonValueTrait, Value,
};
use busbar_plugin_abi::fail::refused;
use busbar_plugin_abi::plugin::Plugin;

use super::harness::{status_code, Harness};
use super::MigrateExpect;
use crate::fake_needs::FakeNeeds;

/// The top-level numeric keys a settings bag conventionally carries its version in.
const VERSION_KEYS: [&str; 6] = [
    "version",
    "v",
    "config_version",
    "settings_version",
    "schema_version",
    "schema",
];

/// A version far above anything a plugin knows.
const NEWER: u64 = 1_000_000;

pub(super) fn run(
    plugin: &'static Plugin,
    bag: &[u8],
    needs: FakeNeeds,
    expect: MigrateExpect<'_>,
) {
    let harness = match Harness::admit(plugin, needs) {
        Ok(harness) => harness,
        Err(refusal) => panic!("migrate: the plugin image was refused at admission: {refusal:?}"),
    };
    install_kernel_sides(&harness);

    match expect {
        MigrateExpect::Refused(code) => refused_case(&harness, bag, code),
        MigrateExpect::Settled { config, core_cfg } => {
            let canonical = settled_case(&harness, bag, config, core_cfg);
            fixed_point_case(&harness, &canonical);
            newer_case(&harness, &canonical);
        }
    }
}

/// The kernel's sides some kinds' adapters need before their first open: the store seal (a test seal, behind the
/// `test-seal` feature) and the auth core (no issued credentials, every replay claim a first sighting).
fn install_kernel_sides(harness: &Harness) {
    #[cfg(feature = "test-seal")]
    harness.registry().set_store_seal(Box::new(|| {
        Box::new(busbar_contract::plugin::TestKernelSeal)
    }));
    harness
        .registry()
        .set_auth_core(Arc::new(AuthCore), std::time::Duration::from_secs(1));
}

struct AuthCore;

impl busbar_plugin_loader::adapters::auth::AuthCore for AuthCore {
    fn issued<'a>(
        &'a self,
        _auth_instance: u64,
        _kind: &'a str,
        _id: &'a str,
    ) -> busbar_plugin_abi::host_side::caller::BoxFut<'a, busbar_contract::secure::SecureVec> {
        Box::pin(async { busbar_contract::secure::SecureVec::new() })
    }

    fn claim<'a>(
        &'a self,
        _who: &'a busbar_plugin_abi::host_side::caller::Caller<'_>,
        _key: &'a [u8],
        _ttl_s: u64,
    ) -> busbar_plugin_abi::host_side::caller::BoxFut<'a, Option<bool>> {
        Box::pin(async { Some(true) })
    }
}

/// `bytes` as JSON in a canonical text (object members sorted by key), so two documents compare as the tree
/// they are, whatever order their members came in.
fn json(what: &str, bytes: &[u8]) -> String {
    match facade::parse_value(bytes) {
        Ok(value) => canon(&value),
        Err(e) => panic!("migrate: {what} is not JSON ({e}): {}", lossy(bytes)),
    }
}

fn canon(value: &Value) -> String {
    if let Some(members) = value.as_object() {
        let mut rows: Vec<(String, String)> = members
            .iter()
            .map(|(k, v)| (k.to_owned(), canon(v)))
            .collect();
        rows.sort();
        let rows: Vec<String> = rows
            .into_iter()
            .map(|(k, v)| format!("{}:{v}", facade::to_string(k.as_str()).unwrap_or_default()))
            .collect();
        return format!("{{{}}}", rows.join(","));
    }
    if let Some(items) = value.as_array() {
        let rows: Vec<String> = items.iter().map(canon).collect();
        return format!("[{}]", rows.join(","));
    }
    facade::to_string(value).unwrap_or_default()
}

fn lossy(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

fn refused_case(harness: &Harness, bag: &[u8], code: u32) {
    let before = harness.records();
    let answer = harness.open("migrate", bag);
    let Err(error) = answer else {
        panic!("migrate: the bag opened; the expected answer is REFUSED {code}");
    };
    assert_eq!(
        status_code(&error),
        Some(code),
        "migrate: the bag must be refused with code {code}, got {error:?}"
    );
    assert!(
        harness.settled("migrate").is_none(),
        "migrate: a refused open settled something"
    );
    assert_eq!(
        harness.records(),
        before,
        "migrate: a refused open wrote records"
    );
}

/// Case 1. Returns the canonical settings the next cases open: the settled CONFIG, or the bag.
fn settled_case(
    harness: &Harness,
    bag: &[u8],
    config: Option<&[u8]>,
    core_cfg: &[(u32, &str, &[u8])],
) -> Vec<u8> {
    let port = match harness.open("migrate", bag) {
        Ok(port) => port,
        Err(error) => panic!("migrate: the older bag did not open: {error:?}"),
    };
    drop(port);
    let settled = harness.settled("migrate");

    let canonical = match (config, &settled) {
        (Some(want), Some(got)) => {
            assert_eq!(
                json("the settled CONFIG", &got.config_json),
                json("the expected config", want),
                "migrate: the settled CONFIG differs from the expected canonical settings"
            );
            got.config_json.clone()
        }
        (Some(want), None) => panic!(
            "migrate: open answered no CONFIG; expected the converted settings {}",
            lossy(want)
        ),
        (None, Some(got)) => {
            assert_eq!(
                json("the settled CONFIG", &got.config_json),
                json("the bag", bag),
                "migrate: the bag is canonical, yet open settled a different CONFIG"
            );
            got.config_json.clone()
        }
        (None, None) => bag.to_vec(),
    };

    let mut got: Vec<(u32, String, String)> = settled
        .iter()
        .flat_map(|s| s.core_cfg.iter())
        .map(|c| {
            (
                c.section,
                c.name.to_string(),
                json("a settled CORE_CFG value", &c.value_json),
            )
        })
        .collect();
    let mut want: Vec<(u32, String, String)> = core_cfg
        .iter()
        .map(|(section, name, value)| {
            (
                *section,
                (*name).to_owned(),
                json("an expected CORE_CFG value", value),
            )
        })
        .collect();
    got.sort_by(|a, b| (a.0, &a.1).cmp(&(b.0, &b.1)));
    want.sort_by(|a, b| (a.0, &a.1).cmp(&(b.0, &b.1)));
    assert_eq!(
        got, want,
        "migrate: the settled CORE_CFG fragments differ from the expected (section, name, value) list"
    );
    canonical
}

/// Case 2: canonical settings are a fixed point, and a current open writes nothing.
fn fixed_point_case(harness: &Harness, canonical: &[u8]) {
    let records = harness.records();
    let port = match harness.open("migrate-again", canonical) {
        Ok(port) => port,
        Err(error) => panic!("migrate: the canonical settings did not open again: {error:?}"),
    };
    drop(port);
    if let Some(again) = harness.settled("migrate-again") {
        panic!(
            "migrate: the canonical settings are not a fixed point; open answered CONFIG {} again",
            lossy(&again.config_json)
        );
    }
    assert_eq!(
        harness.records(),
        records,
        "migrate: opening current settings wrote records (current data costs a marker read and no write)"
    );
}

/// The canonical settings with their version marker raised above anything the plugin knows, or None when the
/// settings carry no conventional numeric version key.
fn newer_of(canonical: &[u8]) -> Option<Vec<u8>> {
    let mut doc: Value = facade::parse_typed(canonical).ok()?;
    if !doc.is_object() {
        return None;
    }
    let key = VERSION_KEYS
        .into_iter()
        .find(|k| doc.get(*k).is_some_and(|v| v.is_u64()))?;
    *doc.get_mut(key)? = Value::from(NEWER);
    facade::to_vec(&doc).ok()
}

/// Case 3: data newer than the plugin refuses R_VERSION, text `NEWER`, no instance, no write.
fn newer_case(harness: &Harness, canonical: &[u8]) {
    let Some(newer) = newer_of(canonical) else {
        return;
    };
    let records = harness.records();
    let Err(error) = harness.open("migrate-newer", &newer) else {
        panic!(
            "migrate: settings marked newer than the plugin ({}) opened; expected REFUSED R_VERSION",
            lossy(&newer)
        );
    };
    assert_eq!(
        status_code(&error),
        Some(refused::R_VERSION),
        "migrate: newer settings must be refused R_VERSION, got {error:?}"
    );
    let busbar_plugin_loader::instance::OpenError::Config { text, .. } = &error else {
        panic!("migrate: newer settings must be a REFUSED answer, got {error:?}");
    };
    assert!(
        text.starts_with("NEWER"),
        "migrate: the R_VERSION text for newer data must start NEWER, got {text:?}"
    );
    assert!(
        harness.settled("migrate-newer").is_none(),
        "migrate: a refused newer open settled something"
    );
    assert_eq!(
        harness.records(),
        records,
        "migrate: a refused newer open wrote records"
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn newer_raises_the_first_conventional_version_key() {
        let newer = newer_of(br#"{"v":2,"timeout":5}"#).expect("a version key");
        let doc: Value = facade::parse_typed(&newer).expect("json");
        assert_eq!(doc.get("v").and_then(|v| v.as_u64()), Some(NEWER));
        assert_eq!(doc.get("timeout").and_then(|v| v.as_u64()), Some(5));
    }

    #[test]
    fn no_numeric_version_key_means_no_newer_case() {
        assert!(newer_of(br#"{"timeout":5}"#).is_none());
        assert!(newer_of(br#"{"version":"2"}"#).is_none());
        assert!(newer_of(b"[1]").is_none());
    }
}
