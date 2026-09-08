// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The kind's ONE entry: `impl Unit for EgressAuthUnit`, in the exemplar's file position.

use busbar_caps::{AuthDecoration, EgressAuthToken, Route, Unit, UnitToken};

use crate::{decorate, EgressBody, Scheme};

/// Everything the loop hands this unit inside the route step.
pub struct DecorateInput<'a> {
    /// The token that seals a decoration. Lent for this call only.
    pub egress_auth: &'a EgressAuthToken,
    /// The scheme the destination declared.
    pub scheme: &'a Scheme,
    /// The resolved secret.
    pub secret: &'a str,
    /// The envelope being decorated.
    pub body: &'a EgressBody<'a>,
}

/// The egress-auth unit, as the thing the loop is handed.
///
/// A zero-sized type because decoration is a pure function of its inputs; the crate had no unit
/// struct before, and the kind's shape is one type per crate implementing one trait.
pub struct EgressAuthUnit;

/// The egress-auth unit SERVES the route step: it hands back the decoration, not the step's answer.
///
/// The route step's answer belongs to the egress unit, which calls this one from inside its own
/// walk (`crates/busbar/src/root/kernel.rs`: "the egress-auth unit is called from inside Route by
/// the egress unit"). The `UnitToken<Route>` is still taken, and that is the point of taking it: it
/// is what makes this unit reachable only WHILE the route step is running.
impl Unit for EgressAuthUnit {
    type Step = Route;
    type Input<'a> = DecorateInput<'a>;
    type Answer<'a> = AuthDecoration;
    const OWNS_ITS_STEP: bool = false;

    fn decide<'a>(
        &'a mut self,
        _token: &'a UnitToken<Route>,
        input: DecorateInput<'a>,
    ) -> AuthDecoration {
        decorate(input.egress_auth, input.scheme, input.secret, input.body)
    }
}
