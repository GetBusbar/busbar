// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use std::sync::Arc;

use busbar_contract::plugin_rows::{NeedLevel, PluginRows, Trust};
use busbar_contract::store_calls::StoreDoor;

use crate::{LinkedPlugin, PluginRegistry};

fn registry() -> PluginRegistry {
    let door = crate::actual_store::door;
    PluginRegistry::empty()
        .link(vec![LinkedPlugin::store("the-store", door, true)])
        .expect("the linked row registers")
}

#[test]
fn a_linked_store_row_reads_back_through_the_view() {
    let rows: &dyn PluginRows = &registry();
    let row = rows.resolve("the-store").expect("the row resolves by name");
    assert_eq!(
        (row.name.as_str(), row.alias.as_str()),
        ("the-store", "the-store")
    );
    assert_eq!(row.kind, busbar_contract::abi::mechanism::kind::STORE);
    assert_eq!(row.abi_version, busbar_contract::abi::store::ABI_VERSION);
    assert_eq!(row.file, crate::registry::LINKED_FILE);
    assert!(row.linked && row.in_process && row.ephemeral);
    assert!(matches!(row.trust, Trust::Trusted { .. }));
    assert_eq!(
        (row.needs_prompt, row.needs_user),
        (NeedLevel::No, NeedLevel::No)
    );
    assert_eq!(rows.linked(), vec![row]);
    assert!(rows.loadable().is_empty() && rows.skipped().is_empty());
}

#[test]
fn the_store_door_and_the_refusals_are_the_registrys() {
    let reg = registry();
    let rows: &dyn PluginRows = &reg;
    assert!(matches!(
        rows.store_door("the-store"),
        Ok(StoreDoor::Linked(_))
    ));
    assert_eq!(
        rows.store_door("nope").map(|_| ()).unwrap_err(),
        reg.store_door("nope").map(|_| ()).unwrap_err()
    );
    assert!(rows.resolve("nope").is_none() && rows.unresolved_reason("nope").is_none());
    assert_eq!(rows.secret_refusal("nope"), reg.secret_refusal("nope"));
}

struct Door;

impl busbar_contract::abi::sdk::auth_door::VerifyPlugin for Door {
    fn validate(settings: &[u8]) -> Result<(), busbar_contract::abi::sdk::life::Refusal> {
        busbar_contract::abi::sdk::auth_door::validate_by_opening::<Self>(settings)
    }

    fn open_refusing(
        _: &[u8],
        _: &[&[u8]],
    ) -> Result<Self, busbar_contract::abi::sdk::life::Refusal> {
        Ok(Self)
    }
    fn verify(
        &self,
        _: &busbar_contract::abi::sdk::auth_door::VerifyView<'_>,
    ) -> busbar_contract::abi::sdk::auth_door::Answer {
        busbar_contract::abi::sdk::auth_door::Verdict::Pass.into()
    }
}

const SECRET_REFS: &[busbar_contract::abi::mechanism::call::AbiStr] =
    &[busbar_contract::abi::sdk::door::abi_str("client_secret")];

const TAIL: &busbar_contract::abi::auth::AuthTail =
    &busbar_contract::abi::sdk::auth_door::verify_tail(
        0,
        busbar_contract::abi::auth::AuthPoints::HEAD,
    );

mod slotted {
    busbar_contract::auth_verify_door!(
        super::Door,
        busbar_contract::abi::sdk::auth_door::with_tail(
            busbar_contract::abi::mechanism::door::Statement {
                secret_refs: super::SECRET_REFS.as_ptr(),
                secret_refs_len: super::SECRET_REFS.len(),
                ..busbar_contract::abi::sdk::door::statement("slotted", "1.0.0", 4)
            },
            super::TAIL
        )
    );
}

mod unslotted {
    busbar_contract::auth_verify_door!(
        super::Door,
        busbar_contract::abi::sdk::auth_door::with_tail(
            busbar_contract::abi::sdk::door::statement("unslotted", "1.0.0", 4),
            super::TAIL
        )
    );
}

#[test]
fn secret_slots_are_the_secret_refs_the_statement_names() {
    let reg = PluginRegistry::empty()
        .link(vec![
            LinkedPlugin::auth_door("slotted", slotted::door),
            LinkedPlugin::auth_door("unslotted", unslotted::door),
        ])
        .expect("the linked doors register");
    let rows: &dyn PluginRows = &reg;
    assert_eq!(rows.secret_slots("slotted"), vec!["client_secret"]);
    assert!(rows.secret_slots("unslotted").is_empty());
    assert!(rows.secret_slots("nope").is_empty());
}

#[test]
fn the_root_gets_its_registry_back() {
    let rows: Arc<dyn PluginRows> = Arc::new(registry());
    let reg = crate::rows::registry_of(rows.as_ref()).expect("the view is a registry");
    assert!(reg.resolve("the-store").is_some());
    let owned = crate::rows::registry_arc(rows).expect("owned, too");
    assert!(owned.resolve("the-store").is_some());

    #[derive(Debug)]
    struct NotARegistry;
    impl PluginRows for NotARegistry {
        fn resolve(&self, _: &str) -> Option<busbar_contract::plugin_rows::Row> {
            None
        }
        fn unresolved_reason(&self, _: &str) -> Option<busbar_contract::plugin_rows::Skipped> {
            None
        }
        fn loadable(&self) -> Vec<busbar_contract::plugin_rows::Row> {
            Vec::new()
        }
        fn linked(&self) -> Vec<busbar_contract::plugin_rows::Row> {
            Vec::new()
        }
        fn skipped(&self) -> Vec<busbar_contract::plugin_rows::Skipped> {
            Vec::new()
        }
        fn store_door(&self, _: &str) -> Result<StoreDoor, String> {
            Err(String::new())
        }
        fn secret_refusal(&self, _: &str) -> String {
            String::new()
        }
        fn kind_refusal(&self, _: &str, _: &str, _: &str) -> String {
            String::new()
        }
        fn secret_slots(&self, _: &str) -> Vec<String> {
            Vec::new()
        }
        fn as_any(&self) -> &dyn std::any::Any {
            self
        }
        fn into_any(self: Arc<Self>) -> Arc<dyn std::any::Any + Send + Sync> {
            self
        }
    }
    assert!(crate::rows::registry_of(&NotARegistry).is_none());
}

mod referencing {
    const EXT: &[u8] = &busbar_contract::abi::mechanism::extensions::entry::<
        {
            busbar_contract::abi::mechanism::extensions::entry_len(
                busbar_contract::abi::mechanism::extensions::EXT_REFERENCE_FIELDS,
                br#"["base_url"]"#,
            )
        },
    >(
        busbar_contract::abi::mechanism::extensions::EXT_REFERENCE_FIELDS,
        br#"["base_url"]"#,
    );
    busbar_contract::auth_verify_door!(
        super::Door,
        busbar_contract::abi::sdk::auth_door::with_tail(
            busbar_contract::abi::mechanism::door::Statement {
                secret_refs: super::SECRET_REFS.as_ptr(),
                secret_refs_len: super::SECRET_REFS.len(),
                extensions: busbar_contract::abi::mechanism::extensions::statement_blob(EXT),
                ..busbar_contract::abi::sdk::door::statement("referencing", "1.0.0", 4)
            },
            super::TAIL
        )
    );
}

#[test]
fn reference_slots_are_the_reference_fields_the_statement_names() {
    let reg = PluginRegistry::empty()
        .link(vec![
            LinkedPlugin::auth_door("referencing", referencing::door),
            LinkedPlugin::auth_door("unslotted", unslotted::door),
        ])
        .expect("the linked doors register");
    let rows: &dyn PluginRows = &reg;
    assert_eq!(rows.reference_slots("referencing"), vec!["base_url"]);
    assert_eq!(rows.secret_slots("referencing"), vec!["client_secret"]);
    assert!(rows.reference_slots("unslotted").is_empty());
    assert!(rows.reference_slots("nope").is_empty());
}
