// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Primitive Store binding used by normal Store admission.

use busbar_contract::abi::mechanism::call::{DeadlineClass, Outcome};
use busbar_contract::abi::mechanism::check::{fault, Fault, Rule};
use busbar_contract::abi::mechanism::lifecycle::LIFECYCLE_SLOTS;
use busbar_contract::abi::mechanism::KindCode;
use busbar_contract::abi::store::v4::{self, slot};

use crate::dispatch::{lifecycle_name, Answer, InFrame, Kind, OutFrame};

/// Mandatory primitive Store ABI with no domain-specific capability negotiation.
#[derive(Debug, Clone, Copy)]
pub struct StoreV4;

// SAFETY: the v4 wire structs are repr(C), lead with the respective call head,
// and borrow inputs or host-owned buffers retained by the call's lent owner.
unsafe impl InFrame for v4::ReadIn {}
unsafe impl InFrame for v4::ScanIn {}
unsafe impl InFrame for v4::CommitIn {}
unsafe impl InFrame for v4::ClockIn {}
unsafe impl InFrame for v4::BootstrapIn {}
unsafe impl OutFrame for v4::ReadOut {}
unsafe impl OutFrame for v4::ScanOut {}
unsafe impl OutFrame for v4::CommitOut {}
unsafe impl OutFrame for v4::ClockOut {}
unsafe impl OutFrame for v4::BootstrapOut {}

impl crate::dispatch::kind_seal::Validated for StoreV4 {}

impl Kind for StoreV4 {
    const CODE: KindCode = KindCode::Store;
    const ABI_VERSION: u32 = v4::ABI_VERSION;
    const LAYOUT_FINGERPRINT: u64 = v4::LAYOUT_FINGERPRINT;
    type Ops = v4::Ops;
    const TIMEOUT: Outcome = Outcome::Failed;

    fn op_name(slot: u32) -> &'static str {
        slot.checked_sub(LIFECYCLE_SLOTS)
            .and_then(|index| v4::NAMES.get(index as usize).copied())
            .unwrap_or_else(|| lifecycle_name(slot))
    }

    fn ticketed_class(slot: u32) -> DeadlineClass {
        slot.checked_sub(LIFECYCLE_SLOTS)
            .and_then(|index| v4::OPS.get(index as usize))
            .map_or(DeadlineClass::Connection, |op| op.deadline)
    }

    fn check(answer: &Answer) -> Result<(), Fault> {
        match answer.slot {
            slot::READ => v4::check::read(
                answer.outcome,
                answer.input::<v4::ReadIn>()?,
                answer.out::<v4::ReadOut>()?,
            ),
            slot::SCAN => v4::check::scan(
                answer.outcome,
                answer.input::<v4::ScanIn>()?,
                answer.out::<v4::ScanOut>()?,
            ),
            slot::COMMIT => v4::check::commit(
                answer.outcome,
                answer.input::<v4::CommitIn>()?,
                answer.out::<v4::CommitOut>()?,
            ),
            slot::BOOTSTRAP => v4::check::bootstrap(
                answer.outcome,
                answer.input::<v4::BootstrapIn>()?,
                answer.out::<v4::BootstrapOut>()?,
            ),
            slot::CLOCK => {
                let out = answer.out::<v4::ClockOut>()?;
                if answer.outcome == Outcome::Ready && out.authority == [0; 16] {
                    Err(fault(Rule::Missing, "store.v4.clock.authority"))
                } else {
                    Ok(())
                }
            }
            _ => Ok(()),
        }
    }

    fn short(answer: &Answer) -> bool {
        if answer.outcome != Outcome::Failed {
            return false;
        }
        match answer.slot {
            slot::READ => answer
                .out::<v4::ReadOut>()
                .is_ok_and(|out| out.needed_items != 0 || out.needed_bytes != 0),
            slot::SCAN => answer
                .out::<v4::ScanOut>()
                .is_ok_and(|out| out.needed_items != 0 || out.needed_bytes != 0),
            slot::COMMIT => answer
                .out::<v4::CommitOut>()
                .is_ok_and(|out| out.needed != 0),
            slot::BOOTSTRAP => answer
                .out::<v4::BootstrapOut>()
                .is_ok_and(|out| out.needed != 0),
            _ => false,
        }
    }
}
