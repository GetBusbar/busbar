// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The door answered seat by seat: the test doubles' way through [`Units::govern`]. Production's one
//! door is the plane driver's (`plane_driver::govern`); this path is test support only.

use std::future::Future;

use busbar_contract::caps::{
    Admission, Admit, Admittance, Approve, Arrival, Authenticate, Authenticated, CallId, Decode,
    Dial, Grant, KernelSeal, Pass, PrincipalId, Refusal, SeatVerdict, VerifiedDestination, Verify,
};

use super::{Door, Governed, UnitCtx, UnitEnds, Units};
use crate::slice::GroupLeaseSlip;

impl<T: DoorSeats + UnitEnds + ?Sized> Units for T {
    fn govern<'a>(
        &'a self,
        ctx: &'a UnitCtx,
        door: Door<'a>,
    ) -> impl Future<Output = Result<Governed, Refusal>> + Send + 'a {
        by_seats(self, ctx, door)
    }
}

pub trait SeatedUnits: DoorSeats + UnitEnds {}

impl<T: DoorSeats + UnitEnds + ?Sized> SeatedUnits for T {}

pub trait DoorSeats: Sync {
    fn arrival(&self, token: &Pass<Arrival>, ctx: &UnitCtx) -> SeatVerdict<Arrival>;

    fn decode(&self, token: &Pass<Decode>, ctx: &UnitCtx) -> SeatVerdict<Decode>;

    fn authenticate(&self, token: &Pass<Authenticate>, ctx: &UnitCtx) -> SeatVerdict<Authenticate>;

    fn verify(
        &self,
        token: &Pass<Verify>,
        trust: &Grant<Dial>,
        ctx: &UnitCtx,
        principal: &PrincipalId,
    ) -> SeatVerdict<Verify>;

    fn approve(
        &self,
        token: &Pass<Approve>,
        ctx: &UnitCtx,
        principal: &PrincipalId,
        destinations: &[VerifiedDestination],
    ) -> SeatVerdict<Approve>;

    fn admit(
        &self,
        token: &Pass<Admit>,
        admit: &Grant<Admittance>,
        ctx: &UnitCtx,
        principal: &PrincipalId,
        destinations: &[VerifiedDestination],
        leases: &GroupLeaseSlip,
    ) -> SeatVerdict<Admit>;
}

async fn by_seats<'a, U: DoorSeats + ?Sized>(
    units: &'a U,
    ctx: &'a UnitCtx,
    door: Door<'a>,
) -> Result<Governed, Refusal> {
    let seal = door.seal;
    let authenticated = units
        .arrival(&Pass::<Arrival>::mint_bound(seal, ctx.call), ctx)
        .into_result(seal)
        .and_then(|_| {
            units
                .decode(&Pass::<Decode>::mint_bound(seal, ctx.call), ctx)
                .into_result(seal)
        })
        .and_then(|_| {
            units
                .authenticate(&Pass::<Authenticate>::mint_bound(seal, ctx.call), ctx)
                .into_result(seal)
        });

    let to_door = authenticated.map(|authenticated| async move {
        match authenticated {
            Authenticated::Challenge(_) => {
                let anonymous = PrincipalId::anonymous();

                let nowhere: [VerifiedDestination; 0] = [];
                let groups = GroupLeaseSlip::new();
                units
                    .approve(
                        &Pass::<Approve>::mint_bound(seal, ctx.call),
                        ctx,
                        &anonymous,
                        &nowhere,
                    )
                    .into_result(seal)
                    .and_then(|_| {
                        units
                            .admit(
                                &Pass::<Admit>::mint_bound(seal, ctx.call),
                                &Grant::<Admittance>::mint_bound(seal, ctx.call),
                                ctx,
                                &anonymous,
                                &nowhere,
                                &groups,
                            )
                            .into_result(seal)
                    })
                    .map(|_admitted| Governed {
                        admission: Admission::ZeroHold,
                        destinations: Vec::new(),
                        lease: None,
                    })
            }
            Authenticated::Principal(principal) => {
                let approved = units
                    .verify(
                        &Pass::<Verify>::mint_bound(seal, ctx.call),
                        &Grant::<Dial>::mint_bound(seal, ctx.call),
                        ctx,
                        &principal,
                    )
                    .into_result(seal)
                    .and_then(|destinations| {
                        units
                            .approve(
                                &Pass::<Approve>::mint_bound(seal, ctx.call),
                                ctx,
                                &principal,
                                &destinations,
                            )
                            .into_result(seal)
                            .map(|_| destinations)
                    });

                screened_by(approved, &door, ctx, seal)
                    .await
                    .and_then(|destinations| {
                        let groups = GroupLeaseSlip::new();
                        let admitted = units
                            .admit(
                                &Pass::<Admit>::mint_bound(seal, ctx.call),
                                &Grant::<Admittance>::mint_bound(seal, ctx.call),
                                ctx,
                                &principal,
                                &destinations,
                                &groups,
                            )
                            .into_result(seal);

                        admitted.map(|admission| Governed {
                            admission,
                            destinations,
                            lease: Some(groups),
                        })
                    })
            }
        }
    });
    door_answer(to_door).await
}

async fn screened_by<'d>(
    approved: Result<Vec<VerifiedDestination>, Refusal>,
    door: &Door<'d>,
    ctx: &'d UnitCtx,
    seal: &KernelSeal,
) -> Result<Vec<VerifiedDestination>, Refusal> {
    match approved {
        Ok(destinations) => match door.screen(ctx) {
            Some(screen) => screen
                .await
                .map(|()| destinations)
                .map_err(|refusal| screened(seal, ctx.call, refusal)),
            None => Ok(destinations),
        },
        Err(refusal) => Err(refusal),
    }
}

async fn door_answer<T>(
    to_door: Result<impl Future<Output = Result<T, Refusal>>, Refusal>,
) -> Result<T, Refusal> {
    match to_door {
        Ok(chain) => chain.await,
        Err(refusal) => Err(refusal),
    }
}

fn screened(seal: &KernelSeal, call: CallId, refusal: Refusal) -> Refusal {
    match SeatVerdict::<Approve>::refuse(&Pass::<Approve>::mint_bound(seal, call), refusal.clone())
        .into_result(seal)
    {
        Err(stamped) => stamped,
        Ok(_) => refusal,
    }
}
