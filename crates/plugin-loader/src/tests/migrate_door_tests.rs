// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The host calls a door's optional `migrate` and reads the plugin's own migration back; a door
//! that states none is not called.

use busbar_contract::abi::sdk::migrate::{Migrate, MigrateNeed, Migrated};

use super::migrate_door;
use crate::dispatch::load::raw;

/// The stub plugin's migration: renames `signing-secret` to `signing_secret` and asks core to allow
/// the host its `url` names. A section holding `refuse` is not migrated.
pub(crate) struct Stub;
impl Migrate for Stub {
    fn migrate(mut settings: serde_json::Value, from: &str) -> Migrated {
        if settings.get("refuse").is_some() {
            // An answer that is no migration: the host must refuse it, naming the plugin's words.
            return Migrated {
                settings: serde_json::Value::Null,
                report: vec!["refused".into()],
                needs: Vec::new(),
            };
        }
        let mut report = Vec::new();
        let mut needs = Vec::new();
        if let Some(m) = settings.as_object_mut() {
            if let Some(v) = m.remove("signing-secret") {
                m.insert("signing_secret".into(), v);
                report.push(format!(
                    "signing-secret -> signing_secret: renamed after {from}; the old name still \
                     reads at open"
                ));
            }
            if let Some(host) = m.get("url").and_then(|u| u.as_str()) {
                needs.push(MigrateNeed::AllowDestination(host.to_string()));
            }
        }
        Migrated {
            settings,
            report,
            needs,
        }
    }
}

mod witness {
    use busbar_contract::abi::mechanism::call::Outcome;
    use busbar_contract::abi::sdk::life::{Held, Life, Refreshed, Refusal};
    use busbar_contract::abi::sdk::{Instance, Lent, Out, SafeSlot};
    use busbar_contract::abi::secret::{ResolveIn, ResolveOut};

    pub struct L;
    impl Life for L {
        const CANCEL: u32 = 0;
        fn open(_: &[u8], _: &[&[u8]], _: u64) -> Result<Self, Refusal> {
            Ok(Self)
        }
        fn refresh(&self, _: &[u8], _: &[&[u8]], _: u64) -> Result<Refreshed, Refusal> {
            Ok(Refreshed::default())
        }
    }

    pub struct Resolve;
    impl SafeSlot for Resolve {
        type In = ResolveIn;
        type Out = ResolveOut;
        type State = Held<L>;
        fn call(
            _: Instance<'_, Held<L>>,
            _: Lent<'_, ResolveIn>,
            _: Out<'_, ResolveOut>,
        ) -> Outcome {
            Outcome::Refused
        }
    }

    pub mod with {
        busbar_contract::plugin_door! {
            ops: busbar_contract::abi::secret::Ops,
            statement: busbar_contract::abi::sdk::door::statement("migrate-stub", "1.6.0", 1),
            lifecycle: life(super::L),
            migrate: busbar_contract::abi::sdk::migrate::Migrator<super::super::Stub>,
            kind_ops: { resolve: busbar_contract::abi::sdk::Safe<super::Resolve> },
        }
    }

    pub mod without {
        busbar_contract::plugin_door! {
            ops: busbar_contract::abi::secret::Ops,
            statement: busbar_contract::abi::sdk::door::statement("migrate-stub", "1.5.5", 1),
            lifecycle: life(super::L),
            kind_ops: { resolve: busbar_contract::abi::sdk::Safe<super::Resolve> },
        }
    }
}

#[test]
fn the_host_calls_a_doors_migrate_and_reads_the_plugins_own_migration() {
    let m = migrate_door(
        raw(witness::with::door),
        &serde_json::json!({"signing-secret": {"env": "S"}, "url": "10.0.0.7"}),
        "1.5.5",
    )
    .expect("the door migrates")
    .expect("the door states migrate");
    assert_eq!(
        m.settings,
        serde_json::json!({"signing_secret": {"env": "S"}, "url": "10.0.0.7"})
    );
    assert_eq!(m.report.len(), 1);
    assert!(m.report[0].starts_with("signing-secret -> signing_secret: renamed after 1.5.5"));
    assert_eq!(
        m.needs,
        vec![MigrateNeed::AllowDestination("10.0.0.7".into())]
    );
}

#[test]
fn a_door_that_states_no_migrate_is_not_called() {
    let none = migrate_door(
        raw(witness::without::door),
        &serde_json::json!({"signing-secret": "x"}),
        "1.5.5",
    )
    .expect("the door loads");
    assert!(
        none.is_none(),
        "no migrate: the section passes through unchanged"
    );
}
