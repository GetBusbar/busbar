// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

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
