// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The kind's ONE entry: `impl Unit for BreakerUnit`, in the exemplar's file position.

use busbar_caps::{Unit, UnitToken, Verify};
use busbar_contract::DestinationId;

use crate::classify::Diagnostics;
use crate::journal::JournalSink;
use crate::{Admit, BreakerUnit, LaneState};

/// Everything the loop hands this unit at the verify step.
pub struct BreakerInput<'a> {
    /// The pool the request named.
    pub pool: &'a str,
    /// The lane being asked about.
    pub destination: DestinationId,
    /// The unit's pinned arrival epoch. Never a fresh clock read: a peek taken at a different
    /// moment from the walk's own is a second opinion about a lane nothing happened to.
    pub now: u64,
}

/// The breaker unit SERVES the verify step: it answers whether ONE lane is open.
///
/// `OWNS_ITS_STEP` is `false` because the composition root's own table says so —
/// `crates/busbar/src/root/kernel.rs`: "the breaker unit is consulted at Verify and recorded at
/// Route without ever being a step of its own." The verify step's `Facts` are a set of SEALED
/// destinations and sealing one takes the trust token, which is lent to the trust unit and to no
/// one else; a breaker that answered `Decision<Verify>` would have to be lent it too, to say
/// nothing more than "this lane is open".
impl<J: JournalSink + 'static, D: Diagnostics + 'static> Unit for BreakerUnit<J, D> {
    type Step = Verify;
    type Input<'a> = BreakerInput<'a>;
    type Answer<'a>
        = Result<Admit, LaneState>
    where
        Self: 'a;
    const OWNS_ITS_STEP: bool = false;

    fn decide<'a>(
        &'a mut self,
        _token: &'a UnitToken<Verify>,
        input: BreakerInput<'a>,
    ) -> Result<Admit, LaneState> {
        self.try_admit(input.pool, input.destination, input.now)
    }
}
