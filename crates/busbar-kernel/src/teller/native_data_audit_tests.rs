// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;
use busbar_contract::caps::{Abort, ReasonCode};

#[test]
fn delivered_error_body_does_not_become_completed_work() {
    let failure = Outcome::Aborted(Abort::Kernel {
        reason: ReasonCode::ClientGone,
    });
    assert_eq!(terminal_facts(failure, true).finish, FinishClass::Partial);
    assert_eq!(terminal_facts(failure, false).finish, FinishClass::Error);
    assert_eq!(
        terminal_facts(Outcome::Completed, false).finish,
        FinishClass::Complete
    );
    assert_eq!(
        terminal_facts(Outcome::Completed, true).op_class,
        busbar_contract::caps::OpClassId::new("data")
    );
}

#[test]
fn a_foreign_call_or_generation_cannot_bind_the_original_unit_context() {
    let kernel = Kernel::new();
    let original = UnitCtx {
        call: kernel.next_call(),
        key: UnitKey::new(1),
        origin: OriginKind::Client,
        session: None,
        generation: crate::registry::Generation::FIRST,
        admin_listener: false,
        kernel_verb_only: false,
    };
    assert!(same_context(&original, &original));
    let mut foreign = original.clone();
    foreign.call = kernel.next_call();
    assert!(!same_context(&original, &foreign));
    foreign = original.clone();
    foreign.key = UnitKey::new(2);
    assert!(!same_context(&original, &foreign));
    foreign = original.clone();
    foreign.generation = crate::registry::Generation::allocate().unwrap();
    assert!(!same_context(&original, &foreign));
    foreign = original.clone();
    foreign.kernel_verb_only = true;
    assert!(!same_context(&original, &foreign));
}
