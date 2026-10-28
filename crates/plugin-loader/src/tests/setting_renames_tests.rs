// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! A STUB PLUGIN that renamed one of its settings keys, read the way the root reads every plugin:
//! its Statement's `REWRITE_RENAMED`/`REWRITE_RENAMED_SINCE` read back under every word it answers
//! to. A rename declared badly is refused naming the plugin; a plugin that renames nothing has no
//! row.

use super::*;

use busbar_contract::abi::mechanism::call::Outcome;
use busbar_contract::abi::mechanism::door::{Rewrite, REWRITE_RENAMED, REWRITE_RENAMED_SINCE};
use busbar_contract::abi::sdk::door::abi_str;
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

/// The stub renamed `signing-secret` to `signing_secret` in 1.6.0.
const RENAMES: &[Rewrite] = &[
    Rewrite {
        class: REWRITE_RENAMED,
        from: abi_str("signing-secret"),
        to: abi_str("signing_secret"),
        ..Rewrite::ZERO
    },
    Rewrite {
        class: REWRITE_RENAMED_SINCE,
        from: abi_str("signing-secret"),
        to: abi_str("1.6.0"),
        ..Rewrite::ZERO
    },
];

/// The same rename with no release stated.
const UNDATED: &[Rewrite] = &[Rewrite {
    class: REWRITE_RENAMED,
    from: abi_str("signing-secret"),
    to: abi_str("signing_secret"),
    ..Rewrite::ZERO
}];

mod renaming {
    busbar_contract::plugin_door! {
        ops: busbar_contract::abi::secret::Ops,
        statement: busbar_contract::abi::mechanism::door::Statement {
            rewrites: super::RENAMES.as_ptr(),
            rewrites_len: super::RENAMES.len(),
            ..busbar_contract::abi::sdk::door::statement("stub-renames", "1.6.0", 1)
        },
        lifecycle: life(super::Stub),
        kind_ops: { resolve: busbar_contract::abi::sdk::Safe<super::Resolve> },
    }
}

mod undated {
    busbar_contract::plugin_door! {
        ops: busbar_contract::abi::secret::Ops,
        statement: busbar_contract::abi::mechanism::door::Statement {
            rewrites: super::UNDATED.as_ptr(),
            rewrites_len: super::UNDATED.len(),
            ..busbar_contract::abi::sdk::door::statement("stub-undated", "1.6.0", 1)
        },
        lifecycle: life(super::Stub),
        kind_ops: { resolve: busbar_contract::abi::sdk::Safe<super::Resolve> },
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
fn a_stub_plugins_rename_reads_back_under_every_word_it_answers_to() {
    assert_eq!(
        setting_renames(&stated(renaming::door), &["stub-alias"]),
        Ok(Some(SettingRenames {
            name: "stub-renames".into(),
            kind: KindCode::Secret,
            words: vec!["stub-alias".into(), "stub-renames".into()],
            renames: vec![(
                "signing-secret".into(),
                "signing_secret".into(),
                "1.6.0".into()
            )],
            public: BTreeSet::new(),
        }))
    );
}

#[test]
fn a_stub_plugins_undated_rename_is_refused_naming_it() {
    assert_eq!(
        setting_renames(&stated(undated::door), &[]),
        Err(
            "plugin 'stub-undated' declares a settings rename badly: the rename of \
             `signing-secret` states no release"
                .to_string()
        )
    );
}

#[test]
fn a_plugin_that_renames_nothing_has_no_row() {
    assert_eq!(setting_renames(&stated(plain::door), &[]), Ok(None));
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
    let facts = setting_renames(&stated(schematized::door), &[])
        .expect("the schema reads")
        .expect("the stub declares public settings");
    assert_eq!(
        facts.public.iter().map(String::as_str).collect::<Vec<_>>(),
        ["timeout_ms", "url"]
    );
    assert!(facts.renames.is_empty());
}

/// A stub whose schema declares a credential-looking setting public is refused at load, naming it,
/// by the same rule `plugin pack` holds a schema file to.
#[test]
fn a_stub_plugin_declaring_a_credential_public_is_refused() {
    let refused = setting_renames(&stated(leaky::door), &[]).expect_err("refused");
    assert!(
        refused.starts_with(
            "plugin 'stub-leaky': its settings schema: field 'api_token' looks \
         like a credential"
        ),
        "{refused}"
    );
}
