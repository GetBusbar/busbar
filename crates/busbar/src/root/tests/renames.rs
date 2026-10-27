// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! A STUB PLUGIN that renamed one of its settings keys, read the way the root reads every plugin:
//! its Statement's `REWRITE_RENAMED`/`REWRITE_RENAMED_SINCE` land in the table under every word it
//! answers to, and the kernel's load moves an operator's old key to the new one. A rename declared
//! badly is refused naming the plugin.

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

fn stated(door: DoorFn) -> Vec<u8> {
    crate::root::loader::dispatch::rendering_of(door).expect("the stub states itself")
}

#[test]
fn a_stub_plugins_rename_is_read_and_applied_on_load() {
    let r = row(&stated(renaming::door), &["stub-alias"])
        .expect("the declaration reads")
        .expect("the stub renames a key");
    assert_eq!(r.kind, Kind::Secret);
    let want = vec![SettingRename {
        from: "signing-secret".into(),
        to: "signing_secret".into(),
        since: "1.6.0".into(),
    }];
    let table = Table(vec![r]);
    assert_eq!(table.renames(Kind::Secret, "stub-renames"), want);
    assert_eq!(table.renames(Kind::Secret, "stub-alias"), want);
    assert!(table.renames(Kind::Auth, "stub-renames").is_empty());

    // The kernel's load over the root's table: the operator's old key reaches the plugin as the new.
    let mut deploy = busbar_kernel::config::deploy_from_yaml_str(
        "providers: {}\nmodels: {}\nsecrets:\n  stub-renames:\n    settings:\n      \
         signing-secret: {env: TOKEN}\n",
    )
    .expect("the document parses");
    let made = busbar_kernel::config::plugin_renames::apply_with(&mut deploy, &table)
        .expect("the rename applies");
    assert_eq!(made.len(), 1);
    let settings = &deploy.secrets["stub-renames"].settings;
    assert!(settings.contains_key("signing_secret"), "{settings:?}");
    assert!(!settings.contains_key("signing-secret"), "{settings:?}");
}

#[test]
fn a_stub_plugins_undated_rename_is_refused_naming_it() {
    let refused = row(&stated(undated::door), &[]).expect_err("no release stated");
    assert_eq!(
        refused,
        "plugin 'stub-undated' declares a settings rename badly: the rename of `signing-secret` \
         states no release"
    );
}
