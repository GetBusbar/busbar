// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use busbar_contract::abi::secret::{ERROR_KIND_INVALID, ERROR_KIND_NOT_FOUND, ERROR_KIND_UNSET};

use super::super::Step;
use super::contract;

fn step(label: &str, answer: String) -> Step {
    Step {
        label: label.into(),
        answer,
        crossed: 1,
        pinned: 1,
        resumes: 0,
    }
}

fn hit() -> String {
    format!(
        "Ready lease=false  kind={ERROR_KIND_UNSET} material=the-known-material secret_flag=true \
         in_host_buffer=true"
    )
}

fn miss(why: &str, kind: u32) -> String {
    format!(
        "Failed lease=false {why} kind={kind} material=none secret_flag=false in_host_buffer=false"
    )
}

fn conforming() -> Vec<Step> {
    vec![
        step("facts", "Secret secret-test max_inflight=1".into()),
        step("validate bad #0", "Failed lease=false no source".into()),
        step("validate bad #1", "Failed lease=false bad prefix".into()),
        step("open bad #0", "Failed lease=false no source".into()),
        step("open bad #1", "Failed lease=false bad prefix".into()),
        step(
            "resolve unopened",
            format!(
                "Refused lease=false  kind={ERROR_KIND_UNSET} material=none secret_flag=false \
                 in_host_buffer=false"
            ),
        ),
        step("validate", "Ready lease=false ".into()),
        step("open", "Ready lease=false ".into()),
        step("open again", "Refused lease=false ".into()),
        step("resolve known", hit()),
        step("resolve known again", hit()),
        step(
            "resolve short",
            format!(
                "Failed lease=false  kind={ERROR_KIND_UNSET} material=none secret_flag=false \
                 in_host_buffer=false needed=true"
            ),
        ),
        step("resolve unknown", miss("not held", ERROR_KIND_NOT_FOUND)),
        step(
            "resolve malformed",
            miss("not a reference", ERROR_KIND_INVALID),
        ),
        step(
            "resolve bad reference #0",
            miss("name is not a string", ERROR_KIND_INVALID),
        ),
        step(
            "resolve empty",
            miss("the value is EMPTY", ERROR_KIND_INVALID),
        ),
        step("release", "Refused lease=false ".into()),
        step("refresh bad", "Failed lease=false no source".into()),
        step("resolve after a refused refresh", hit()),
        step("refresh before bad #1", "Ready lease=false ".into()),
        step("refresh bad #1", "Failed lease=false bad prefix".into()),
        step("resolve after a refused refresh #1", hit()),
        step("tick", "Ready lease=false  next=0".into()),
        step("refresh", "Ready lease=false ".into()),
        step("resolve after refresh", hit()),
        step("close", "Ready lease=false ".into()),
        step("resolve after close", "Fault lease=false ".into()),
    ]
}

fn planted(mut fold: Vec<Step>, label: &str, answer: String) -> Vec<Step> {
    let s = fold
        .iter_mut()
        .find(|s| s.label == label)
        .unwrap_or_else(|| panic!("no step '{label}'"));
    s.answer = answer;
    fold
}

#[test]
fn a_conforming_secret_fold_passes_the_contract() {
    contract(&conforming());
}

#[test]
#[should_panic(expected = "a refused refresh keeps the instance as it was")]
fn red_a_refused_refresh_that_wiped_the_instance_fails_the_contract() {
    contract(&planted(
        conforming(),
        "resolve after a refused refresh",
        miss("not held", ERROR_KIND_NOT_FOUND),
    ));
}

#[test]
fn an_accepted_bad_refresh_is_recorded_not_judged() {
    let fold = planted(conforming(), "refresh bad", "Ready lease=false ".into());
    contract(&planted(
        fold,
        "resolve after a refused refresh",
        miss("not held", ERROR_KIND_NOT_FOUND),
    ));
}

#[test]
#[should_panic(expected = "resolve bad reference #0")]
fn red_a_bad_reference_answered_not_found_fails_the_contract() {
    contract(&planted(
        conforming(),
        "resolve bad reference #0",
        miss("no such secret", ERROR_KIND_NOT_FOUND),
    ));
}

#[test]
#[should_panic(expected = "validate bad #1")]
fn red_a_validate_that_accepts_the_second_bad_setting_fails_the_contract() {
    contract(&planted(
        conforming(),
        "validate bad #1",
        "Ready lease=false ".into(),
    ));
}

#[test]
#[should_panic(expected = "validate bad #1")]
fn a_validate_refusal_naming_nothing_fails_the_contract() {
    contract(&planted(
        conforming(),
        "validate bad #1",
        "Failed lease=false ".into(),
    ));
}

#[test]
#[should_panic(expected = "resolve unopened")]
fn red_a_resolve_before_open_answered_ready_fails_the_contract() {
    contract(&planted(conforming(), "resolve unopened", hit()));
}

#[test]
#[should_panic(expected = "resolve unopened")]
fn red_a_refused_resolve_before_open_that_carries_material_fails_the_contract() {
    contract(&planted(
        conforming(),
        "resolve unopened",
        format!(
            "Refused lease=false  kind={ERROR_KIND_UNSET} material=OTHER-material \
             secret_flag=true in_host_buffer=true"
        ),
    ));
}

#[test]
#[should_panic(expected = "resolve empty")]
fn red_an_empty_secret_answered_ready_fails_the_contract() {
    contract(&planted(
        conforming(),
        "resolve empty",
        format!(
            "Ready lease=false  kind={ERROR_KIND_UNSET} material=none secret_flag=true \
             in_host_buffer=true"
        ),
    ));
}

#[test]
#[should_panic(expected = "resolve empty")]
fn red_an_empty_secret_answered_not_found_fails_the_contract() {
    contract(&planted(
        conforming(),
        "resolve empty",
        miss("no such secret", ERROR_KIND_NOT_FOUND),
    ));
}

#[test]
fn a_fold_with_no_empty_input_passes_the_contract() {
    let fold: Vec<Step> = conforming()
        .into_iter()
        .filter(|s| s.label != "resolve empty")
        .collect();
    contract(&fold);
}

mod lifecycle_inputs {
    use std::sync::atomic::{AtomicBool, AtomicU8, Ordering};
    use std::sync::Mutex;

    use busbar_contract::abi::mechanism::call::Outcome;
    use busbar_contract::abi::sdk::door::statement;
    use busbar_contract::abi::sdk::life::{Held, HeldSlot, Life, Opened, Refreshed, Refusal};
    use busbar_contract::abi::sdk::{Instance, Lent, Out, Safe};
    use busbar_contract::abi::secret::{Ops, ResolveIn, ResolveOut};
    use busbar_contract::secret::SecretModuleError;

    use crate::conformance::{Leg, Subject};

    static SERIAL: Mutex<()> = Mutex::new(());
    static BAD_OPENS: AtomicU8 = AtomicU8::new(0);
    static BAD_REFRESHES: AtomicU8 = AtomicU8::new(0);
    const MATERIAL: &[u8] = b"material-preserved";

    fn bad(settings: &[u8]) -> Option<u8> {
        serde_json::from_slice::<serde_json::Value>(settings)
            .ok()?
            .get("bad")?
            .as_u64()
            .and_then(|n| u8::try_from(n).ok())
    }

    struct Probe<const WIPE_SECOND: bool>(AtomicBool);

    impl<const WIPE_SECOND: bool> Life for Probe<WIPE_SECOND> {
        const CANCEL: u32 = 0;

        fn validate(settings: &[u8]) -> Result<(), Refusal> {
            if bad(settings).is_some() {
                Err(Refusal::failed("probe: invalid setting"))
            } else {
                Ok(())
            }
        }

        fn open(settings: &[u8], _: &[&[u8]], _: u64) -> Result<Self, Refusal> {
            if let Some(n) = bad(settings) {
                BAD_OPENS.fetch_or(1 << n, Ordering::SeqCst);
            }
            Self::validate(settings)?;
            Ok(Self(AtomicBool::new(true)))
        }

        fn refresh(&self, settings: &[u8], _: &[&[u8]], _: u64) -> Result<Refreshed, Refusal> {
            if let Some(n) = bad(settings) {
                BAD_REFRESHES.fetch_or(1 << n, Ordering::SeqCst);
                if WIPE_SECOND && n == 1 {
                    self.0.store(false, Ordering::SeqCst);
                }
                return Err(Refusal::failed("probe: invalid setting"));
            }
            self.0.store(true, Ordering::SeqCst);
            Ok(Refreshed::default())
        }
    }

    struct Resolve<const WIPE_SECOND: bool>;

    impl<const WIPE_SECOND: bool> HeldSlot for Resolve<WIPE_SECOND> {
        type In = ResolveIn;
        type Out = ResolveOut;
        type Life = Probe<WIPE_SECOND>;

        fn call(
            held: &Held<Self::Life>,
            _: &Instance<'_, Held<Self::Life>>,
            input: Lent<'_, ResolveIn>,
            mut out: Out<'_, ResolveOut>,
        ) -> Outcome {
            let read = busbar_contract::abi::sdk::secret::settings_of(
                input.field(|i| &i.settings).bytes(),
            );
            let read = read.and_then(|s| {
                let name = s
                    .get("name")
                    .and_then(serde_json::Value::as_str)
                    .ok_or_else(|| SecretModuleError::invalid("probe: invalid name"))?;
                if name == "known" && held.life().0.load(Ordering::SeqCst) {
                    Ok(MATERIAL.to_vec())
                } else {
                    Err(SecretModuleError::not_found("probe: not held"))
                }
            });
            match read {
                Ok(bytes) => busbar_contract::abi::sdk::cred::resolved(
                    input,
                    &mut out,
                    busbar_contract::abi::sdk::cred::Held::new(bytes),
                ),
                Err(error) => busbar_contract::abi::sdk::secret::failed(&mut out, error),
            }
        }
    }

    mod honest {
        busbar_contract::plugin_door! {
            ops: super::Ops,
            statement: super::statement("secret-input-probe", "1.6.0", 4),
            lifecycle: life(super::Probe<false>),
            kind_ops: { resolve: super::Safe<super::Opened<super::Resolve<false>>> },
        }
    }

    mod wipes_second {
        busbar_contract::plugin_door! {
            ops: super::Ops,
            statement: super::statement("secret-input-probe", "1.6.0", 4),
            lifecycle: life(super::Probe<true>),
            kind_ops: { resolve: super::Safe<super::Opened<super::Resolve<true>>> },
        }
    }

    fn inputs() -> String {
        serde_json::json!({
            "settings": {},
            "credentials": [String::from_utf8_lossy(MATERIAL)],
            "secret": {
                "bad_settings": [{"bad": 0}, {"bad": 1}],
                "known": {"resolve": {"name": "known"}, "material": String::from_utf8_lossy(MATERIAL)},
                "unknown": {"name": "unknown"},
                "malformed": {"name": 5}
            }
        })
        .to_string()
    }

    #[test]
    fn every_bad_setting_reaches_open_and_refresh_through_the_secret_door() {
        let _serial = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
        BAD_OPENS.store(0, Ordering::SeqCst);
        BAD_REFRESHES.store(0, Ordering::SeqCst);
        let s = Subject::new(honest::door, "unused", &inputs());
        let _fold = super::super::fold(&s, Leg::Linked);
        assert_eq!(BAD_OPENS.load(Ordering::SeqCst), 0b11);
        assert_eq!(BAD_REFRESHES.load(Ordering::SeqCst), 0b11);
    }

    #[test]
    fn a_second_refused_refresh_that_loses_material_is_detected() {
        let _serial = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
        let s = Subject::new(wipes_second::door, "unused", &inputs());
        let failed = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            super::super::fold(&s, Leg::Linked)
        }));
        let error = failed.expect_err("the second refused refresh lost the material");
        let why = error
            .downcast_ref::<String>()
            .map(String::as_str)
            .or_else(|| error.downcast_ref::<&str>().copied())
            .unwrap_or("non-text panic");
        assert!(why.contains("resolve after a refused refresh #1"), "{why}");
    }
}
