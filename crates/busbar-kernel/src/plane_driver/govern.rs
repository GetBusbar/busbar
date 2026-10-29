// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE DOOR OF A PLANE'S UNIT, AS ONE AWAITED STEP ([`Units::govern`]): arrival, the plane's
//! `arrive`, who is calling, where the unit may go, whether it may, the plane's screen, and the door,
//! in the loop's order, each refusal stamped at its seat.
//!
//! Its own file because it is the loop's door for every plane, and it keeps the loop's shape: no
//! `?` and no early return, so a refusal simply stops the chain. Whatever the door waits on, it
//! waits on here, BEFORE the admit: nothing is awaited between the door's yes and the loop's guard (see
//! [`Units::govern`]).

use busbar_contract::caps::{
    Admission, Admit, Admittance, Approve, Arrival, Authenticate, Authenticated, CallId, Decode,
    Dial, Grant, KernelSeal, Pass, PrincipalId, Refusal, SeatVerdict, Step, Verify,
};

use super::{CallerEnd, DriverSteps, FarEnd, PlaneUnits};
use crate::slice::GroupLeaseSlip;
use crate::teller::{Door, Governed, UnitCtx, Units};

impl<S: DriverSteps + Sync, F: FarEnd, C: CallerEnd> Units for PlaneUnits<'_, S, F, C> {
    fn govern<'a>(
        &'a self,
        ctx: &'a UnitCtx,
        door: Door<'a>,
    ) -> impl std::future::Future<Output = Result<Governed, Refusal>> + Send + 'a {
        self.door(ctx, door)
    }
}

impl<S: DriverSteps + Sync, F: FarEnd, C: CallerEnd> PlaneUnits<'_, S, F, C> {
    /// [`Units::govern`]'s body: the loop's seats up to the door, as one chain.
    async fn door<'a>(&'a self, ctx: &'a UnitCtx, door: Door<'a>) -> Result<Governed, Refusal> {
        let (seal, call) = (door.seal, ctx.call);
        let authenticated = self
            .steps
            .arrival(ctx)
            .map_err(stamped::<Arrival>(seal, call))
            .and_then(|_| self.decoded_op(ctx).map_err(stamped::<Decode>(seal, call)))
            .and_then(|_| {
                self.steps
                    .authenticate(ctx)
                    .map_err(stamped::<Authenticate>(seal, call))
            });
        let admit = Grant::<Admittance>::mint_bound(seal, call);
        match authenticated {
            Err(refusal) => Err(refusal),
            // A challenge round: no destination, the anonymous principal at approve and the door,
            // the zero hold whatever the door sized, and no lease; the slip, and whatever the door
            // counted on it, goes back at the end of this arm (see `teller::by_seats`).
            Ok(Authenticated::Challenge(_)) => {
                let anonymous = PrincipalId::anonymous();
                let groups = GroupLeaseSlip::new();
                self.approved(ctx, &anonymous, &[])
                    .map_err(stamped::<Approve>(seal, call))
                    .and_then(|_| {
                        self.admitted(&admit, ctx, &anonymous, &[], &groups)
                            .map_err(stamped::<Admit>(seal, call))
                    })
                    .map(|_admitted| Governed {
                        admission: Admission::ZeroHold,
                        destinations: Vec::new(),
                        lease: None,
                    })
            }
            Ok(Authenticated::Principal(principal)) => {
                let approved = self
                    .verified(&Grant::<Dial>::mint_bound(seal, call), ctx, &principal)
                    .map_err(stamped::<Verify>(seal, call))
                    .and_then(|destinations| {
                        self.approved(ctx, &principal, &destinations)
                            .map_err(stamped::<Approve>(seal, call))
                            .map(|_| destinations)
                    });
                // THE SCREEN BEFORE THE DOOR ([`crate::teller::RouteAwait::screen`]), built only
                // for an approved unit: a unit it stops is refused at Approve's seat, before
                // anything is admitted.
                let screened = match approved {
                    Ok(destinations) => match door.screen(ctx) {
                        Some(screen) => screen.await.map(|()| destinations).map_err(stamped::<
                            Approve,
                        >(
                            seal, call
                        )),
                        None => Ok(destinations),
                    },
                    Err(refusal) => Err(refusal),
                };
                screened.and_then(|destinations| {
                    let groups = GroupLeaseSlip::new();
                    self.admitted(&admit, ctx, &principal, &destinations, &groups)
                        .map_err(stamped::<Admit>(seal, call))
                        .map(|admission| Governed {
                            admission,
                            destinations,
                            lease: Some(groups),
                        })
                })
            }
        }
    }
}

/// A refusal of the door's chain, stamped at seat `T` exactly as that seat's own answer would be.
fn stamped<T: Step>(seal: &KernelSeal, call: CallId) -> impl Fn(Refusal) -> Refusal + '_ {
    move |refusal| match SeatVerdict::<T>::refuse(
        &Pass::<T>::mint_bound(seal, call),
        refusal.clone(),
    )
    .into_result(seal)
    {
        Err(stamped) => stamped,
        Ok(_) => refusal,
    }
}
