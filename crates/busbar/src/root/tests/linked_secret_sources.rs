// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Generic linked source routing. Backend behavior is tested by each source owner.
use busbar_contract::abi::mechanism::call::{OutHead, Outcome};
use busbar_contract::abi::sdk::life::{Held, Life, Refreshed, Refusal};
use busbar_contract::abi::sdk::{Instance, Lent, Out, Safe, SafeSlot};
use busbar_contract::abi::secret::{CheckIn, ResolveIn, ResolveOut};
use busbar_contract::plugin::markers::SecretKind;
use busbar_contract::secret::SecretAxis;

pub(super) const NAME: &str = "test-fixed-secret";
pub(super) const MATERIAL: &[u8] = b"fixed-linked-material";
pub(super) const FAILURE: &str = "fixed source refused the reference";

struct Fixed;
impl Life for Fixed {
    type Kind = SecretKind;
    const CANCEL: u32 = busbar_contract::abi::secret::cancel::ABORTED;
    fn open(_: &[u8], _: &[&[u8]], _: u64) -> Result<Self, Refusal> {
        Ok(Self)
    }
    fn refresh(&self, _: &[u8], _: &[&[u8]], _: u64) -> Result<Refreshed, Refusal> {
        Ok(Refreshed::default())
    }
}
struct Resolve;
impl SafeSlot for Resolve {
    type Kind = SecretKind;
    type In = ResolveIn;
    type Out = ResolveOut;
    type State = Held<Fixed>;
    fn call(
        instance: Instance<'_, Held<Fixed>, SecretKind>,
        input: Lent<'_, ResolveIn>,
        mut out: Out<'_, ResolveOut>,
    ) -> Outcome {
        if instance.get().is_none() {
            return Outcome::Refused;
        }
        if input.field(|i| &i.settings).bytes() == b"{}" {
            busbar_contract::abi::sdk::cred::resolved(
                input,
                &mut out,
                busbar_contract::abi::sdk::cred::Held::new(MATERIAL.to_vec()),
            )
        } else {
            busbar_contract::abi::sdk::secret::failed(
                &mut out,
                busbar_contract::secret::SecretModuleError::not_found(FAILURE),
            )
        }
    }
}
struct Check;
impl SafeSlot for Check {
    type Kind = SecretKind;
    type In = CheckIn;
    type Out = OutHead;
    type State = Held<Fixed>;
    fn call(
        _: Instance<'_, Held<Fixed>, SecretKind>,
        _: Lent<'_, CheckIn>,
        _: Out<'_, OutHead>,
    ) -> Outcome {
        Outcome::Ready
    }
}
mod fixture {
    busbar_contract::plugin_door! {
        ops: busbar_contract::abi::secret::Ops,
        statement: busbar_contract::abi::sdk::door::statement(super::NAME, "1.0.0", 16),
        lifecycle: life(super::Fixed),
        kind_ops: {
            resolve: super::Safe<super::Resolve>,
            check: super::Safe<super::Check>,
        },
    }
}

pub(super) fn linked_axis() -> &'static crate::root::loader::secret_calls::SecretRows {
    static AXIS: std::sync::OnceLock<crate::root::loader::secret_calls::SecretRows> =
        std::sync::OnceLock::new();
    AXIS.get_or_init(|| {
        let mut rows = crate::root::loader::secret_calls::SecretRows::new(
            crate::root::dispatch::dispatcher,
            super::conns,
        )
        .with_logs(|| crate::root::boot::plugin_logs().clone());
        rows.link(fixture::door)
            .expect("the neutral fixture door states");
        rows
    })
}

#[test]
fn the_linked_source_fixture_is_independent_of_the_boot_registry_rows() {
    let boot = super::secret_rows();
    let before = boot.linked(NAME);
    let axis = linked_axis();
    assert!(axis.linked(NAME));
    assert!(!std::ptr::eq(boot, axis));
    assert_eq!(boot.linked(NAME), before);
}
