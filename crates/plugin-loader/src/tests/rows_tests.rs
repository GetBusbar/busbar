// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use busbar_contract::plugin_rows::PluginRows;

use crate::{LinkedPlugin, PluginRegistry};

#[test]
fn the_refusals_are_the_registrys() {
    let reg = PluginRegistry::empty();
    let rows: &dyn PluginRows = &reg;
    assert!(rows.resolve("nope").is_none() && rows.unresolved_reason("nope").is_none());
    assert_eq!(rows.secret_refusal("nope"), reg.secret_refusal("nope"));
}

struct Door;

impl busbar_contract::abi::sdk::auth_door::SyncVerifyPlugin for Door {
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

    fn reload(
        &self,
        _: &[u8],
        _: &[&[u8]],
    ) -> Result<u64, busbar_contract::abi::sdk::life::Refusal> {
        Ok(0)
    }
}

const SECRET_REFS: &[busbar_contract::abi::mechanism::call::AbiStr] =
    &[busbar_contract::abi::sdk::door::abi_str("client_secret")];

const TAIL: &busbar_contract::abi::auth::AuthTail =
    &busbar_contract::abi::sdk::auth_door::verify_tail(0, busbar_contract::route::AuthPoints::HEAD);

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
