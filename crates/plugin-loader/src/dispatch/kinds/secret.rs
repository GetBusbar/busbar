// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE SECRET KIND: `abi/secret/`. `resolve` is checked by `check_resolve`.

use busbar_contract::abi::mechanism::call::Outcome;
use busbar_contract::abi::mechanism::check::Fault;
use busbar_contract::abi::mechanism::KindCode;
use busbar_contract::abi::secret::{self, slot, validate, ResolveIn, ResolveOut};

use crate::dispatch::{lifecycle_name, Answer, InFrame, Kind, OutFrame};

/// The secret kind.
#[derive(Debug, Clone, Copy)]
pub struct Secret;

// SAFETY: `#[repr(C)]` in `abi/secret/`, each leading with its head; host buffers only.
unsafe impl InFrame for ResolveIn {}
unsafe impl OutFrame for ResolveOut {}

impl Kind for Secret {
    const CODE: KindCode = KindCode::Secret;
    type Ops = secret::Ops;
    const TIMEOUT: Outcome = Outcome::Failed;

    fn op_name(s: u32) -> &'static str {
        match s {
            slot::RESOLVE => "resolve",
            _ => lifecycle_name(s),
        }
    }

    fn check(a: &Answer) -> Result<(), Fault> {
        match a.slot {
            slot::RESOLVE => validate::check_resolve(a.out::<ResolveOut>()?),
            _ => Ok(()),
        }
    }
}
