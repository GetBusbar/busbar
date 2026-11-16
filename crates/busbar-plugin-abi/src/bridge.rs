// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The plugin-side bridge (IF §6.2-§6.4): one chain's inbox and step counter, the `CURRENT` the Need futures
//! bind to, the one poll every async adapter makes, and the answer writers every shim shares. W1-A3: the
//! signatures, bodies held (red first).

use crate::fail::Fail;
use crate::need::ChainBytes;
use crate::records::{Full, Reply};
use crate::types::{Status, Token};

/// What one poll came to (busbar-ffi's, re-exported for the adapters `plugin!` emits).
#[doc(hidden)]
pub use busbar_ffi::shim::Step;

/// The most NEEDs one step may hold (IF §6.1 rules); more is FAULT.
pub const MAX_NEEDS: u32 = 64;

/// One chain's state between polls (`ChainBox`'s `X`; IF §6.4 steps 1 and 4).
#[doc(hidden)]
pub struct Inbox {
    _held: (),
}

impl Inbox {
    pub fn new() -> Inbox {
        todo!("W1-A3")
    }
}

impl Default for Inbox {
    fn default() -> Self {
        Self::new()
    }
}

/// A chain's successful output: what Ready(Ok) writes into Out.
pub trait Answer {
    fn answer(self, out: &mut busbar_ffi::Out<'_>) -> Result<(), Full>;
}

impl Answer for Reply {
    fn answer(self, out: &mut busbar_ffi::Out<'_>) -> Result<(), Full> {
        let _ = out;
        todo!("W1-A3")
    }
}

/// One poll of a chain (IF §6.4 steps 1-4).
pub fn poll<A: Answer>(
    chain: busbar_ffi::ChainRef<'_, Result<A, Fail>, Inbox>,
    results: Option<ChainBytes>,
    out: &mut busbar_ffi::Out<'_>,
) -> Step {
    let _ = (chain, results, out);
    todo!("W1-A3")
}

/// After `Step::Need`: the chain's TOKEN record, then NEED (§6.4 step 3).
pub fn parked(token: Token, out: &mut busbar_ffi::Out<'_>) -> Status {
    let _ = (token, out);
    todo!("W1-A3")
}

/// The bytes a session opener's leading TOKEN record takes (§6.4 step 7).
pub const TOKEN_ROOM: usize = 16;

/// Before a session opener's call: the room for its leading TOKEN.
pub fn reserve_token(out: &mut busbar_ffi::Out<'_>) -> Result<(), Full> {
    let _ = out;
    todo!("W1-A3")
}

/// After a session opener's `Ok`: the session TOKEN as the answer's first record.
pub fn opened(token: Token, out: &mut busbar_ffi::Out<'_>) -> Status {
    let _ = (token, out);
    todo!("W1-A3")
}

/// A sync method's answer (§6.4 step 2).
pub fn answer_sync(out: &mut busbar_ffi::Out<'_>, result: Result<(), Fail>) -> Status {
    let _ = (out, result);
    todo!("W1-A3")
}
