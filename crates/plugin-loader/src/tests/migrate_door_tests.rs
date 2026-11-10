// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use busbar_contract::abi::sdk::migrate::{Migrate, MigrateNeed, Migrated};

use super::migrate_door;
use crate::dispatch::load::raw;

pub(crate) struct Stub;
impl Migrate for Stub {
    type Kind = busbar_contract::plugin::markers::SecretKind;
    fn migrate(mut settings: serde_json::Value, from: &str) -> Migrated {
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
    use busbar_contract::abi::mechanism::call::{AbiStr, OutHead, Outcome};
    use busbar_contract::abi::mechanism::lifecycle::ValidateIn;
    use busbar_contract::abi::sdk::door::RawSlot;
    use busbar_contract::abi::sdk::life::{Held, Life, Refreshed, Refusal};
    use busbar_contract::abi::sdk::{Instance, Lent, Out, SafeSlot};
    use busbar_contract::abi::secret::{ResolveIn, ResolveOut};

    pub static OPENS: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
    pub struct L;
    impl Life for L {
        type Kind = busbar_contract::plugin::markers::SecretKind;
        const CANCEL: u32 = 0;
        fn validate(settings: &[u8]) -> Result<(), Refusal> {
            let settings: serde_json::Value = serde_json::from_slice(settings).unwrap();
            if settings.get("reject-current").is_some() {
                return Err(Refusal::refused("PRIVATE-REFUSAL-CANARY"));
            }
            Ok(())
        }
        fn open(_: &[u8], _: &[&[u8]], _: u64) -> Result<Self, Refusal> {
            OPENS.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Ok(Self)
        }
        fn refresh(&self, _: &[u8], _: &[&[u8]], _: u64) -> Result<Refreshed, Refusal> {
            Ok(Refreshed::default())
        }
    }

    pub struct Resolve;
    impl SafeSlot for Resolve {
        type Kind = busbar_contract::plugin::markers::SecretKind;
        type In = ResolveIn;
        type Out = ResolveOut;
        type State = Held<L>;
        fn call(
            _: Instance<'_, Held<L>, Self::Kind>,
            _: Lent<'_, ResolveIn>,
            _: Out<'_, ResolveOut>,
        ) -> Outcome {
            Outcome::Refused
        }
    }

    pub const REFUSAL: &str = "migrate-stub: the old endpoint needs an operator choice";

    pub struct Refuse;
    impl RawSlot for Refuse {
        type Kind = busbar_contract::plugin::markers::SecretKind;
        type In = ValidateIn;
        type Out = OutHead;

        unsafe fn call(_: *mut std::ffi::c_void, input: &ValidateIn, out: &mut OutHead) -> Outcome {
            assert!(!input.err_buf.is_null());
            assert!(input.err_cap >= REFUSAL.len());
            // SAFETY: migrate_door lends this writable buffer for the entire call; the checked
            // capacity covers the static refusal bytes, which do not overlap it.
            unsafe {
                std::ptr::copy_nonoverlapping(REFUSAL.as_ptr(), input.err_buf, REFUSAL.len());
            }
            out.error = AbiStr {
                ptr: input.err_buf,
                len: REFUSAL.len(),
            };
            Outcome::Refused
        }
    }

    pub mod refusing {
        busbar_contract::plugin_door! {
            ops: busbar_contract::abi::secret::Ops,
            statement: busbar_contract::abi::sdk::door::statement("migrate-stub", "1.6.0", 1),
            lifecycle: life(super::L),
            migrate: super::Refuse,
            kind_ops: { resolve: busbar_contract::abi::sdk::Safe<super::Resolve> },
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
        serde_json::from_slice::<serde_json::Value>(
            m.encode()
                .unwrap()
                .expose(&busbar_contract::plugin::TestKernelSeal)
        )
        .unwrap(),
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
fn a_null_migration_answer_stays_null_in_host_custody() {
    let answer = migrate_door(raw(witness::with::door), &serde_json::Value::Null, "1.5.5")
        .unwrap()
        .unwrap();
    let seal = busbar_contract::caps::KernelSeal::acquire_for_kernel();
    assert_eq!(
        serde_json::to_value(answer.authoring(&seal)).unwrap(),
        serde_json::Value::Null
    );
    assert_eq!(
        answer
            .encode()
            .unwrap()
            .expose(&busbar_contract::plugin::TestKernelSeal),
        b"null"
    );
    assert!(answer.report.is_empty());
    assert!(answer.needs.is_empty());
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

#[test]
fn a_refused_migration_preserves_the_plugins_reason() {
    let refused = migrate_door(
        raw(witness::refusing::door),
        &serde_json::json!({"url": "old-endpoint"}),
        "1.5.5",
    )
    .expect_err("a refused MIGRATE must not become an unchanged or migrated section");
    assert_eq!(refused, witness::REFUSAL);
}

#[test]
fn current_migration_validation_calls_real_slot_without_open_and_redacts_refusal() {
    super::validate_migrated_door(
        raw(witness::with::door),
        &serde_json::json!({"token":{"file":"/private/token"}}),
    )
    .unwrap();
    let error = super::validate_migrated_door(
        raw(witness::with::door),
        &serde_json::json!({"reject-current":true}),
    )
    .unwrap_err();
    assert!(!error.contains("PRIVATE-REFUSAL-CANARY"));
    assert_eq!(witness::OPENS.load(std::sync::atomic::Ordering::SeqCst), 0);
}

#[test]
fn credential_delivery_refuses_an_unrelated_kind_without_echoing_material() {
    let error = super::migrate_credential_door(
        raw(witness::with::door),
        &busbar_contract::Secret::new("SYNTHETIC_PRIVATE_CREDENTIAL".to_owned()),
        "1.5.5",
        &busbar_contract::plugin::TestKernelSeal,
    )
    .unwrap_err();
    assert_eq!(
        error,
        "credential owner could not migrate the original reference"
    );
}

#[test]
fn default_reference_discovery_does_not_run_ordinary_settings_migration() {
    let settings = serde_json::json!({"signing-secret":"SYNTHETIC","url":"10.0.0.7"});
    let answer = super::migrate_references_door(raw(witness::with::door), &settings, "1.5.5")
        .unwrap()
        .unwrap();
    assert!(answer.needs.is_empty() && answer.report.is_empty());
    let returned: serde_json::Value = serde_json::from_slice(
        answer
            .encode()
            .unwrap()
            .expose(&busbar_contract::plugin::TestKernelSeal),
    )
    .unwrap();
    assert_eq!(returned, settings);
}

#[test]
fn host_refuses_unsolicited_file_acceptance_and_bounds_file_continuations() {
    let seal = &busbar_contract::plugin::TestKernelSeal;
    let mut calls = 0;
    let result = super::complete_credential_migration(
        &busbar_contract::Secret::new("MUST_NOT_BE_READ".into()),
        seal,
        |loan| {
            calls += 1;
            assert!(loan.is_none());
            Ok(serde_json::from_str(r#"{"action":"use_file"}"#).unwrap())
        },
    );
    assert_eq!(calls, 1);
    assert_eq!(
        result.unwrap_err(),
        "credential owner could not migrate the original reference"
    );
    let file = std::env::temp_dir().join(format!("migration-bounded-read-{}", std::process::id()));
    std::fs::write(&file, b"SYNTHETIC_FILE").unwrap();
    calls = 0;
    let result = super::complete_credential_migration(
        &busbar_contract::Secret::new(file.to_str().unwrap().into()),
        seal,
        |loan| {
            calls += 1;
            if calls == 1 {
                assert!(loan.is_none());
            } else {
                assert_eq!(loan.unwrap().expose(seal), b"SYNTHETIC_FILE");
            }
            Ok(serde_json::from_str(r#"{"action":"read_file"}"#).unwrap())
        },
    );
    assert_eq!(calls, 2);
    assert_eq!(
        result.unwrap_err(),
        "credential owner could not migrate the original reference"
    );
    std::fs::remove_file(file).unwrap();
}
