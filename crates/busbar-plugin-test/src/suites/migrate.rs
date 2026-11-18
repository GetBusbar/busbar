// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The migrate suite body (IF §14, round 31). Owned by the migrate agent: this is the only file it edits. There is
//! no `migrate` ABI method: a plugin migrates inside its `open`, so every step below is an `open_<kind>` through
//! the registry (bind, inline steps, `decode_settled`, `unbind_refs`), driven by [`super::harness::Harness`].
//!
//! The cases, in order:
//! 1. Open the case's `bag` as its kind with explicit purpose and limits. `Settled { config, core_cfg }`: the open
//!    succeeds; the settled CONFIG equals `config` (canonical JSON compare; `None` = unchanged bag: an equal echo, or
//!    no CONFIG, which a conversion settles as the bag, #432) and CORE_CFG fragments equal `core_cfg`. `Refused(code)`: the open
//!    fails REFUSED `code`, nothing is settled and the plugin wrote nothing.
//! 2. Fixed point: open the settled CONFIG (or the bag when none came back) again. It must open, answer either
//!    no CONFIG or an equal JSON-tree echo, no CORE_CFG, and write nothing (current data costs one marker read
//!    and no write; a read is not countable through `FakeNeeds`, a write is: `records()` is unchanged).
//! 3. Newer: the canonical settings with their version marker raised must answer REFUSED R_VERSION whose text
//!    starts `NEWER`, with no instance and nothing written. The marker is found generically, as the first of the
//!    conventional numeric version keys at the top level of the canonical settings; a plugin that keeps its
//!    version elsewhere (in its data, not its settings) has no settings-level case here and its own crate test
//!    covers it.

use busbar_contract::json::{
    self as facade, JsonContainerTrait, JsonValueMutTrait, JsonValueTrait, Value,
};
use busbar_plugin_abi::fail::refused;
use busbar_plugin_abi::plugin::Plugin;

use super::harness::{status_code, Harness, InstanceLimits, OpenError, OpenPurpose, OpenedPort};
use super::{MigrateCase, MigrateExpect};
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
    case: MigrateCase<'_>,
    legacy: &[&str],
    needs: FakeNeeds,
    expect: MigrateExpect<'_>,
) {
    let harness = match Harness::admit(plugin, needs) {
        Ok(harness) => harness,
        Err(refusal) => panic!("migrate: the plugin image was refused at admission: {refusal:?}"),
    };
    if !legacy.is_empty() {
        harness.mark_legacy("migrate", legacy);
    }

    match expect {
        MigrateExpect::Refused(code) => refused_case(&harness, &case, code),
        MigrateExpect::Settled { config, core_cfg } => {
            let canonical = settled_case(&harness, &case, config, core_cfg);
            let canonical = lifted(&harness, &canonical, core_cfg);
            let canonical = visible(&harness, &canonical);
            fixed_point_case(&harness, &canonical, case.limits);
            newer_case(&harness, &canonical, case.limits);
        }
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

fn open_case(
    harness: &Harness,
    name: &str,
    bag: &[u8],
    purpose: OpenPurpose,
    limits: InstanceLimits,
) -> Result<OpenedPort, OpenError> {
    let mut spec = harness.spec(name, bag);
    spec.purpose = purpose;
    spec.limits = limits;
    harness.open_spec(&spec)
}

fn refused_case(harness: &Harness, case: &MigrateCase<'_>, code: u32) {
    let before = harness.records();
    let answer = open_case(harness, "migrate", case.bag, case.purpose, case.limits);
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
    case: &MigrateCase<'_>,
    config: Option<&[u8]>,
    core_cfg: &[(u32, &str, &[u8])],
) -> Vec<u8> {
    let bag = case.bag;
    let port = match open_case(harness, "migrate", bag, case.purpose, case.limits) {
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
            got.config_json.to_vec()
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
            got.config_json.to_vec()
        }
        (None, None) if case.purpose == OpenPurpose::Canonical => bag.to_vec(),
        (None, None) => {
            panic!("migrate: a conversion settled nothing; core settles an unchanged bag (#432)")
        }
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

/// The canonical settings as core persists them after a conversion: every CORE_CFG(LIFT) slot's literal is
/// moved to a core-owned secret file and replaced by a `{"file": ..}` reference to it (busbar-migrate `settle`,
/// 10f464ae50, #441), so the next open binds a reference there, never the literal. Custody then answers the
/// literal for that slot. Settings with no lift are returned unchanged.
fn lifted(harness: &Harness, canonical: &[u8], core_cfg: &[(u32, &str, &[u8])]) -> Vec<u8> {
    use busbar_plugin_abi::records::core_cfg::LIFT;
    let pointers: Vec<String> = core_cfg
        .iter()
        .filter(|(section, _, _)| *section == LIFT)
        .map(|(_, _, value)| {
            facade::parse_value(value)
                .ok()
                .and_then(|v| v.as_str().map(str::to_owned))
                .unwrap_or_else(|| panic!("migrate: a LIFT value is not a JSON pointer string"))
        })
        .collect();
    if pointers.is_empty() {
        return canonical.to_vec();
    }
    let mut doc: Value = facade::parse_typed(canonical)
        .unwrap_or_else(|e| panic!("migrate: the canonical settings are not JSON ({e})"));
    for pointer in &pointers {
        let slot = facade::pointer_mut(&mut doc, pointer)
            .unwrap_or_else(|| panic!("migrate: the lift of {pointer} names no slot"));
        let Some(literal) = slot.as_str().map(str::to_owned) else {
            panic!("migrate: the lift of {pointer} names no string");
        };
        harness.needs().lifted(pointer, literal.as_bytes());
        *slot = facade::json!({ "file": format!("secrets/lifted{pointer}") });
    }
    facade::to_vec(&doc).unwrap_or_else(|e| panic!("migrate: the lifted settings ({e})"))
}

/// The members core takes out of a declared plane registration before the plane sees it (busbar-kernel
/// `upstreams::declared` `CORE_KEYS`, 39451a9603): core owns these and keeps them; the plane is handed the rest.
const CORE_REGISTRATION_KEYS: [&str; 7] = [
    "url",
    "command",
    "tls",
    "auth",
    "upstream_credentials",
    "allow_private",
    "resource",
];

/// The canonical settings as core hands them to every later open of a plane that declares D_UPSTREAM_PATH
/// registrations: each registration object under a declared `/<parent>/*` has its core-owned members removed
/// (the plane's `visible_bag`, root `min3_boot` `declared_planes` over busbar-kernel `upstreams::declared`).
/// Settings of an image that declares no registration path are returned unchanged.
fn visible(harness: &Harness, canonical: &[u8]) -> Vec<u8> {
    use busbar_plugin_abi::records::tag::D_UPSTREAM_PATH;
    let Some(described) = harness.registry().described(harness.identity()) else {
        return canonical.to_vec();
    };
    let parents: Vec<String> = described
        .paths(D_UPSTREAM_PATH)
        .filter_map(|path| path.strip_suffix("/*").map(str::to_owned))
        .collect();
    if parents.is_empty() {
        return canonical.to_vec();
    }
    let mut doc: Value = facade::parse_typed(canonical)
        .unwrap_or_else(|e| panic!("migrate: the canonical settings are not JSON ({e})"));
    for parent in &parents {
        let Some(members) =
            facade::pointer_mut(&mut doc, parent).and_then(|node| node.as_object_mut())
        else {
            continue;
        };
        for (_, member) in members.iter_mut() {
            if let Some(member) = member.as_object_mut() {
                for key in CORE_REGISTRATION_KEYS {
                    member.remove(&key);
                }
            }
        }
    }
    facade::to_vec(&doc).unwrap_or_else(|e| panic!("migrate: the visible settings ({e})"))
}

/// Case 2: canonical settings are a fixed point, and a current open writes nothing.
fn fixed_point_case(harness: &Harness, canonical: &[u8], limits: InstanceLimits) {
    let records = harness.records();
    let port = match open_case(
        harness,
        "migrate-again",
        canonical,
        OpenPurpose::Canonical,
        limits,
    ) {
        Ok(port) => port,
        Err(error) => panic!("migrate: the canonical settings did not open again: {error:?}"),
    };
    drop(port);
    if let Some(again) = harness.settled("migrate-again") {
        assert_eq!(
            json("the reopened CONFIG", &again.config_json),
            json("the canonical input", canonical),
            "migrate: the canonical settings are not a fixed point"
        );
        assert!(
            again.core_cfg.is_empty(),
            "migrate: canonical open answered CORE_CFG"
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
fn newer_case(harness: &Harness, canonical: &[u8], limits: InstanceLimits) {
    let Some(newer) = newer_of(canonical) else {
        return;
    };
    let records = harness.records();
    let Err(error) = open_case(
        harness,
        "migrate-newer",
        &newer,
        OpenPurpose::Canonical,
        limits,
    ) else {
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
    use busbar_plugin_abi::fail::Fail;
    use busbar_plugin_abi::host::Host;
    use busbar_plugin_abi::need::{need, ChainBytes};
    use busbar_plugin_abi::plugin::{Describe, Endpoints, Open};
    use busbar_plugin_abi::records::{settled, Full, Out};

    struct LimitsFixture;
    impl Open for LimitsFixture {
        async fn open(_h: &'static Host, config: ChainBytes) -> Result<Self, Fail> {
            let connection = need::open(
                "migration-limits.test:80",
                need::Tls::None,
                busbar_plugin_abi::need::egress::OPERATOR_INFRASTRUCTURE,
            )
            .await?;
            need::close(connection.conn, false).await?;
            let value: Value = config
                .with(facade::parse_typed)
                .map_err(|_| Fail::refused(refused::R_CONFIG))?;
            if value.get("v").and_then(Value::as_u64) != Some(2) {
                return Err(Fail::refused_because(
                    refused::R_VERSION,
                    "NEWER: fixture version",
                ));
            }
            Ok(Self)
        }
        fn check(_h: &Host, _config: &[u8], _ends: &mut Endpoints<'_>) -> Result<(), Fail> {
            Ok(())
        }
        fn describe(d: &mut Describe<'_>) {
            d.schema(r#"{"type":"object"}"#);
        }
        fn settled(&self, w: &mut Out<'_>) -> Result<(), Full> {
            settled::config(w, br#"{"v":2}"#)
        }
    }
    impl busbar_plugin_abi::Auth for LimitsFixture {}
    busbar_plugin_abi::plugin!(Auth, LimitsFixture, name: "fixture-migration-limits");

    #[test]
    fn explicit_limits_reach_initial_fixed_point_newer_and_refused_open_callers() {
        use super::super::harness::Accept;
        use crate::fake_needs::ConnScript;

        let mut needs = FakeNeeds::new();
        for _ in 0..4 {
            needs.conn("migration-limits.test:80", ConnScript::new().eof());
        }
        let harness = Harness::admit(PLUGIN.plugin(), needs).expect("fixture admission");
        let limits = InstanceLimits {
            timeout_ms: 1234,
            connect_timeout_ms: 234,
            max_inflight: 7,
            accept: Accept(Accept::PLAINTEXT),
        };
        let case = MigrateCase {
            bag: br#"{"v":2}"#,
            purpose: OpenPurpose::ConvertUnstamped,
            limits,
        };
        let canonical = settled_case(&harness, &case, None, &[]);
        fixed_point_case(&harness, &canonical, limits);
        newer_case(&harness, &canonical, limits);
        refused_case(
            &harness,
            &MigrateCase {
                bag: br#"{"v":3}"#,
                purpose: OpenPurpose::Canonical,
                limits,
            },
            refused::R_VERSION,
        );
        assert_eq!(
            harness.needs().open_limits(),
            vec![
                ("migrate".to_owned(), limits),
                ("migrate-again".to_owned(), limits),
                ("migrate-newer".to_owned(), limits),
                ("migrate".to_owned(), limits),
            ]
        );
    }

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
