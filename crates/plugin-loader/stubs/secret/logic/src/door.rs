// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use busbar_contract::abi::mechanism::call::Outcome;
use busbar_contract::abi::mechanism::door::{
    Rewrite, Statement, REWRITE_ALIAS, REWRITE_SUGAR, REWRITE_SUGAR_NAMES, REWRITE_SUGAR_ROLE,
    REWRITE_SUGAR_SHOWN,
};
use busbar_contract::abi::sdk::cred::resolved;
use busbar_contract::abi::sdk::door::{abi_str, statement};
use busbar_contract::abi::sdk::life::{Held, Life, Refreshed, Refusal};
use busbar_contract::abi::sdk::{Instance, Lent, Out, Safe, SafeSlot};
use busbar_contract::abi::secret::{cancel, ResolveIn, ResolveOut};

use crate::{error_kind, settings_of};

const fn rewrite(class: u32, to: &'static str) -> Rewrite {
    Rewrite {
        class,
        _reserved: 0,
        from: abi_str(crate::WORD),
        to: abi_str(to),
    }
}

const REWRITES: &[Rewrite] = &[
    rewrite(REWRITE_ALIAS, ""),
    rewrite(REWRITE_SUGAR, crate::KEY),
    rewrite(REWRITE_SUGAR_SHOWN, "VAR"),
    rewrite(REWRITE_SUGAR_NAMES, "the environment variable name"),
    rewrite(REWRITE_SUGAR_ROLE, "fill"),
];

pub const STATEMENT: Statement = Statement {
    rewrites: REWRITES.as_ptr(),
    rewrites_len: REWRITES.len(),
    ..statement(crate::NAME, env!("CARGO_PKG_VERSION"), 16)
};

/// One instance: the environment is the process's, so there is nothing to hold.
#[derive(Debug)]
pub struct Env;

impl Life for Env {
    const CANCEL: u32 = cancel::ABORTED;

    fn open(_: &[u8], _: &[&[u8]], _: u64) -> Result<Self, Refusal> {
        Ok(Env)
    }

    fn refresh(&self, _: &[u8], _: &[&[u8]], _: u64) -> Result<Refreshed, Refusal> {
        Ok(Refreshed::default())
    }
}

pub struct Resolve;

impl SafeSlot for Resolve {
    type In = ResolveIn;
    type Out = ResolveOut;
    type State = Held<Env>;
    fn call(
        instance: Instance<'_, Held<Env>>,
        input: Lent<'_, ResolveIn>,
        mut out: Out<'_, ResolveOut>,
    ) -> Outcome {
        if instance.get().is_none() {
            return Outcome::Refused;
        }
        let settings = input.field(|i| &i.settings).bytes();
        match settings_of(settings).and_then(|s| crate::resolve(&s)) {
            Ok(material) => resolved(input, &mut out, material),
            Err(e) => {
                out.set(|o| &o.error_kind, error_kind(e.kind));
                out.fail(Refusal::failed(e.message))
            }
        }
    }
}

mod table {
    busbar_contract::plugin_door! {
        ops: busbar_contract::abi::secret::Ops,
        statement: super::STATEMENT,
        lifecycle: life(super::Env),
        kind_ops: { resolve: super::Safe<super::Resolve> },
    }
}

pub use table::door;
