// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use busbar_contract::caps::{
    Admission, Admit, Admittance, Approve, Arrival, Authenticate, Authenticated, CallId, Decode,
    Dial, Grant, KernelSeal, Pass, PrincipalId, ReasonCode, Refusal, SeatVerdict, Step, Verify,
};

use busbar_contract::plane::codes::PRINCIPAL_REQUIRED;

use super::{CallerEnd, DriverSteps, FarEnd, PlaneUnits};
use crate::slice::GroupLeaseSlip;
use crate::teller::{Door, Governed, UnitCtx, Units};

impl<S: DriverSteps + Sync, F: FarEnd, C: CallerEnd> Units for PlaneUnits<'_, S, F, C> {
    fn take_reserved_request_lineage(
        &self,
        ctx: &UnitCtx,
    ) -> Option<super::ReservedRequestLineage> {
        self.steps.take_reserved_request_lineage(ctx)
    }

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
                    .and_then(|authenticated| {
                        self.principal_needed(authenticated)
                            .map_err(stamped::<Authenticate>(seal, call))
                    })
            });
        let admit = Grant::<Admittance>::mint_bound(seal, call);
        match authenticated {
            Err(refusal) => Err(refusal),

            Ok(Authenticated::Challenge(_)) => {
                let anonymous = PrincipalId::anonymous();
                let groups = GroupLeaseSlip::new();
                self.approved(ctx, &anonymous, &[])
                    .map_err(stamped::<Approve>(seal, call))?;
                self.steps
                    .prepare_admission(ctx, &anonymous, &[])
                    .await
                    .map_err(stamped::<Admit>(seal, call))?;
                self.admitted(&admit, ctx, &anonymous, &[], &groups)
                    .map_err(stamped::<Admit>(seal, call))
                    .map(|_admitted| Governed {
                        admission: Admission::ZeroHold,
                        destinations: Vec::new(),
                        lease: None,
                    })
            }
            Ok(Authenticated::Principal(principal)) => {
                self.bind_authenticated_caller(&principal)
                    .await
                    .map_err(stamped::<Verify>(seal, call))?;
                if self.driver.authenticated_route {
                    self.resolve_authenticated_route(ctx, &principal)
                        .await
                        .map_err(stamped::<Verify>(seal, call))?;
                }
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
                let destinations = screened?;
                self.steps
                    .prepare_admission(ctx, &principal, &destinations)
                    .await
                    .map_err(stamped::<Admit>(seal, call))?;
                let groups = GroupLeaseSlip::new();
                self.admitted(&admit, ctx, &principal, &destinations, &groups)
                    .map_err(stamped::<Admit>(seal, call))
                    .map(|admission| Governed {
                        admission,
                        destinations,
                        lease: Some(groups),
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

impl<S: DriverSteps + Sync, F: FarEnd, C: CallerEnd> PlaneUnits<'_, S, F, C> {
    /// `arrive`'s `principal_need`, enforced once Authenticate has settled (#116).
    /// `PRINCIPAL_REQUIRED` means the kernel must verify a principal before the first piece, so the
    /// kernel's anonymous principal (an open claim's caller with no key) is refused `Unauthenticated`
    /// and audited, never admitted. A challenge round is how a principal gets verified, so it
    /// proceeds. `PRINCIPAL_NONE` and `PRINCIPAL_OPTIONAL` take Authenticate's answer as it stands
    /// (a key the caller presents is already verified there).
    fn principal_needed(&self, authenticated: Authenticated) -> Result<Authenticated, Refusal> {
        let required = self
            .lock()
            .decoded
            .as_ref()
            .is_some_and(|d| d.principal_need == PRINCIPAL_REQUIRED);
        match &authenticated {
            Authenticated::Principal(p) if required && *p == PrincipalId::anonymous() => {
                Err(Refusal::new(ReasonCode::Unauthenticated))
            }
            _ => Ok(authenticated),
        }
    }
}
