// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE SEVEN KINDS, as the dispatcher binds them: one [`super::Kind`] per `abi/<kind>/`, naming
//! its code, its table, its timeout outcome, each op's name, and the op's own `check_<op>` run on
//! every READY or FAILED answer. A kind's `check_<op>` is pure and lives beside its shapes in
//! `busbar-contract`; these adapters only read the op's `in`/`out` through [`super::Answer`], build
//! each slice a plugin-reported count names through `abi::mechanism::check::reported` (the count
//! checked against the host's cap first), call the check, and map the kind's own fault to the
//! shared `Fault` the dispatcher logs.

pub mod export;
pub mod secret;

use busbar_contract::abi::mechanism::check::{fault, Fault, Rule};

/// A kind whose `check_<op>` answers a message-only fault: the rule is not named, so it is
/// reported as [`Rule::Contradiction`] with the kind's own message as the field.
pub(crate) fn message_fault(message: &'static str) -> Fault {
    fault(Rule::Contradiction, message)
}
