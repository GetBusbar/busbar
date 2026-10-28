// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! A STUB PLUGIN whose settings schema declares some settings public, read the way the root reads
//! every plugin (owner ruling 2026-10-27, sensitive by default): exactly its `x-busbar-public`
//! settings are public; a schema declaring a credential public is refused naming the plugin; a
//! plugin with no schema has no row.

use super::*;

use busbar_contract::abi::mechanism::call::Outcome;
use busbar_contract::abi::sdk::life::{Held, Life, Refreshed, Refusal};
use busbar_contract::abi::sdk::{Instance, Lent, Out, SafeSlot};

/// The stub: a secret plugin that answers nothing.
pub struct Stub;

impl Life for Stub {
    const CANCEL: u32 = 0;
    fn open(_: &[u8], _: &[&[u8]], _: u64) -> Result<Self, Refusal> {
        Ok(Stub)
    }
    fn refresh(&self, _: &[u8], _: &[&[u8]], _: u64) -> Result<Refreshed, Refusal> {
        Ok(Refreshed::default())
    }
}

/// Its one kind op.
pub struct Resolve;

impl SafeSlot for Resolve {
    type In = busbar_contract::abi::secret::ResolveIn;
    type Out = busbar_contract::abi::secret::ResolveOut;
    type State = Held<Stub>;
    fn call(_: Instance<'_, Held<Stub>>, _: Lent<'_, Self::In>, _: Out<'_, Self::Out>) -> Outcome {
        Outcome::Refused
    }
}

mod plain {
    busbar_contract::plugin_door! {
        ops: busbar_contract::abi::secret::Ops,
        statement: busbar_contract::abi::sdk::door::statement("stub-plain", "1.6.0", 1),
        lifecycle: life(super::Stub),
        kind_ops: { resolve: busbar_contract::abi::sdk::Safe<super::Resolve> },
    }
}

fn stated(door: DoorFn) -> Vec<u8> {
    crate::dispatch::rendering_of(door).expect("the stub states itself")
}

#[test]
fn a_plugin_with_no_schema_has_no_row() {
    assert_eq!(public_settings(&stated(plain::door), &[]), Ok(None));
}

/// The stub's settings schema: `url` and `timeout_ms` declared public, its secret marked, one
/// setting undeclared (sensitive).
const SCHEMA: &[u8] = br#"{"type":"object","properties":{
    "url":{"type":"string","x-busbar-public":true},
    "timeout_ms":{"type":"integer","x-busbar-public":true},
    "client_secret":{"type":"string","x-busbar-secret":true},
    "audience":{"type":"string"}}}"#;

/// A schema that declares a credential-looking setting public.
const LEAKY: &[u8] =
    br#"{"type":"object","properties":{"api_token":{"type":"string","x-busbar-public":true}}}"#;

const fn schema(bytes: &'static [u8]) -> busbar_contract::abi::mechanism::call::Blob {
    busbar_contract::abi::mechanism::call::Blob {
        ptr: bytes.as_ptr(),
        len: bytes.len(),
        fmt: busbar_contract::abi::mechanism::call::BLOB_JSON,
        flags: 0,
    }
}

mod schematized {
    busbar_contract::plugin_door! {
        ops: busbar_contract::abi::secret::Ops,
        statement: busbar_contract::abi::mechanism::door::Statement {
            settings_schema: super::schema(super::SCHEMA),
            ..busbar_contract::abi::sdk::door::statement("stub-public", "1.6.0", 1)
        },
        lifecycle: life(super::Stub),
        kind_ops: { resolve: busbar_contract::abi::sdk::Safe<super::Resolve> },
    }
}

mod leaky {
    busbar_contract::plugin_door! {
        ops: busbar_contract::abi::secret::Ops,
        statement: busbar_contract::abi::mechanism::door::Statement {
            settings_schema: super::schema(super::LEAKY),
            ..busbar_contract::abi::sdk::door::statement("stub-leaky", "1.6.0", 1)
        },
        lifecycle: life(super::Stub),
        kind_ops: { resolve: busbar_contract::abi::sdk::Safe<super::Resolve> },
    }
}

/// SENSITIVE BY DEFAULT, ONE DECLARATION (owner ruling 2026-10-27): the stub's settings schema,
/// read off its Statement at load, makes exactly its `x-busbar-public` settings public; its secret
/// and its undeclared setting stay sensitive.
#[test]
fn a_stub_plugins_schema_declares_its_public_settings() {
    let facts = public_settings(&stated(schematized::door), &["stub-alias"])
        .expect("the schema reads")
        .expect("the stub declares public settings");
    assert_eq!(
        facts.public.iter().map(String::as_str).collect::<Vec<_>>(),
        ["timeout_ms", "url"]
    );
    assert_eq!(facts.words, ["stub-alias", "stub-public"]);
}

/// A stub whose schema declares a credential-looking setting public is refused at load, naming it,
/// by the same rule `plugin pack` holds a schema file to.
#[test]
fn a_stub_plugin_declaring_a_credential_public_is_refused() {
    let refused = public_settings(&stated(leaky::door), &[]).expect_err("refused");
    assert!(
        refused.starts_with(
            "plugin 'stub-leaky': its settings schema: field 'api_token' looks \
         like a credential"
        ),
        "{refused}"
    );
}
