// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The kind's ONE entry: `impl Unit for Verbs`, in the exemplar's file position.

use busbar_caps::{AdminToken, Route, Unit, UnitToken};

use crate::governance::Governance;
use crate::idempotency::ReplayEncoder;
use crate::refusal::Refusal;
use crate::store::Store;
use crate::verb::{KernelVerb, VerbScope};
use crate::verbs::{MintedKeyOutcome, NonceSource, Verbs};

/// Everything the loop hands this unit when it executes an administrative verb.
pub struct VerbInput<'a> {
    /// Which verb.
    pub verb: KernelVerb,
    /// The proof that a scope check has already run. Only this unit holds it.
    pub admin: &'a AdminToken,
    /// Who is asking, for the record.
    pub actor: &'a str,
    /// What they were granted.
    pub granted: VerbScope,
    /// The moment the request was pinned at — never a fresh clock read here.
    pub now: u64,
    /// The request body.
    pub request: &'a [u8],
}

/// The verbs unit SERVES the route step: it is a DESTINATION at Route, not the step's answer.
///
/// `OWNS_ITS_STEP` is `false` because the root's own table says so — `crates/busbar/src/root/
/// kernel.rs`: "the verbs unit is a destination at Route, holding the admin token". The admin
/// plane's route step calls it and then lifts the packed answer into `Decision<Route>`; the lift
/// needs `AdminAnswer::unpack` and the binding's answer slot, both of which are the root's, so it
/// stays there and this impl hands back the crate's own `Result<Vec<u8>, Refusal>` unchanged.
impl<
        G: Governance + 'static,
        S: Store + 'static,
        N: NonceSource + 'static,
        E: ReplayEncoder<MintedKeyOutcome> + 'static,
    > Unit for Verbs<G, S, N, E>
{
    type Step = Route;
    type Input<'a> = VerbInput<'a>;
    type Answer<'a>
        = Result<Vec<u8>, Refusal>
    where
        Self: 'a;
    const OWNS_ITS_STEP: bool = false;

    fn decide<'a>(
        &'a mut self,
        _token: &'a UnitToken<Route>,
        input: VerbInput<'a>,
    ) -> Result<Vec<u8>, Refusal> {
        self.execute(
            input.verb,
            input.admin,
            input.actor,
            input.granted,
            input.now,
            input.request,
        )
    }
}
