// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE DOOR: the `env` source on the secret kind's table (`busbar_contract::abi::secret`), the nine
//! lifecycle slots the SDK's generic lifecycle (`lifecycle: life(Env)`, [`Life`]) and `resolve` a
//! [`SafeSlot`] — no `unsafe` in this crate.
//!
//! * `validate`, `open`, `refresh` — the source holds no settings and no state: any settings object
//!   opens it.
//! * `resolve` — a reference's `{ key: VAR }` to the variable's value, written by the SDK
//!   ([`resolved`]) into the host's zeroed buffer and wiped here (the credential chip, row 6:
//!   host-owned secret bytes; no lease, no copy left behind), or FAILED with its `ERROR_KIND_*` and
//!   1.5.5's text. A value over the host's buffer is the short-buffer answer. It never pends.
//! * `release`, `close`, `cancel`, `tick`, `retire`, `drive` — the SDK's.

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

/// A rewrite naming this source by its word ([`crate::WORD`]), in `class`, carrying `to`.
const fn rewrite(class: u32, to: &'static str) -> Rewrite {
    Rewrite {
        class,
        _reserved: 0,
        from: abi_str(crate::WORD),
        to: abi_str(to),
    }
}

/// The names config gives this source (THE DESIGN §2, the Statement's `rewrites`; busbar step 2c,
/// the sugar each secret plugin spells itself): the module alias (`module: env`), the
/// reference sugar (`{ env: X }` becomes `{module: env, settings: {key: X}}`), what a
/// refusal names its value, and its core role.
const REWRITES: &[Rewrite] = &[
    rewrite(REWRITE_ALIAS, ""),
    rewrite(REWRITE_SUGAR, crate::KEY),
    rewrite(REWRITE_SUGAR_SHOWN, "VAR"),
    rewrite(REWRITE_SUGAR_NAMES, "the environment variable name"),
    rewrite(REWRITE_SUGAR_ROLE, "fill"),
];

/// This plugin's Statement: its name, version, the most resolves one instance holds in flight, and
/// the names config gives it.
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

/// `resolve`: READY with the variable's value in the host's buffer, FAILED with its code and text.
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

/// This plugin's door: the one a compiled-in build links and the dropped-in image exports.
pub use table::door;
