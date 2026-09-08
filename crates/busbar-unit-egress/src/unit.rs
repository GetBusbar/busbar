// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The kind's ONE entry: `impl Unit for EgressUnit`, in the exemplar's file position.

use busbar_caps::{Route, Unit, UnitToken};

use crate::ports::BoxFut;
use crate::select::RequestCtx;
use crate::walk::RouteRequest;
use crate::wire::RouteOutcome;
use crate::{Egress, EgressUnit};

/// Everything the loop hands this unit at the route step.
pub struct RouteInput<'a> {
    /// The request as [`Egress::route`] reads it.
    pub request: &'a RouteRequest<'a>,
    /// The walk's own mutable context.
    pub ctx: &'a mut RequestCtx,
}

/// The egress unit SERVES the route step: its answer is the FUTURE the loop awaits.
///
/// `OWNS_ITS_STEP` is `false` for one reason, and it is a real one: route is the single step of the
/// ten that the loop AWAITS, so what this unit hands back is a future and the `Decision<Route>` is
/// built by the loop once that future resolves. Making `Answer` a `Decision` would mean blocking on
/// the future inside `decide`, which is precisely what a unit may not do.
impl Unit for EgressUnit {
    type Step = Route;
    type Input<'a> = RouteInput<'a>;
    type Answer<'a> = BoxFut<'a, RouteOutcome>;
    const OWNS_ITS_STEP: bool = false;

    fn decide<'a>(
        &'a mut self,
        token: &'a UnitToken<Route>,
        input: RouteInput<'a>,
    ) -> BoxFut<'a, RouteOutcome> {
        Egress::route(&*self, input.request, input.ctx, token)
    }
}
