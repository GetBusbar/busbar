// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors
//! Real command admission for channel regression fixtures; no authority bypass constructor.
use super::*;
use crate::host_services::{
    KernelServices, NativeInvocationAdmission, Nest, NestDone, NestRoute, ServingGeneration,
};
use crate::upstreams::{ConfiguredUpstreams, UpstreamDef};
use busbar_contract::services::Caller;

struct NoChildren;
impl NestRoute for NoChildren {
    fn nest(&self, _: InvocationContext, _: Nest, _: NestDone) {
        panic!("fixture does not nest");
    }
}
struct Posted;
impl super::super::EndPost for Posted {
    fn post(&self, _: &crate::teller::UnitCtx, _: crate::teller::Ended) {}
}

pub(crate) struct CommandAdmissionFixture {
    pub request: AdmittedRequest,
    pub definition: Arc<UpstreamDef>,
    pub caller: Caller,
    money: super::super::PlaneMoney,
    _owner: NativeInvocationAdmission,
}

impl CommandAdmissionFixture {
    pub async fn new(definition: Arc<UpstreamDef>) -> Self {
        let core = Arc::new(KernelServices::new());
        let caller = Caller::for_test(
            Arc::from("command-fixture"),
            busbar_contract::kinds::codes::KindCode::Plane,
        );
        let owner = core.admit_native_invocation(&caller).unwrap();
        assert!(core.units().pre_admitted_for(
            1,
            &caller,
            crate::host_units::UnitRecord {
                principal: Some(Arc::new(VirtualKey {
                    id: "command-fixture".into(),
                    enabled: true,
                    ..Default::default()
                })),
                depth: 0,
            }
        ));
        let context = InvocationContext::new(
            Arc::new(ServingGeneration::new(core, Arc::new(NoChildren))),
            caller.clone(),
            1,
        )
        .unwrap();
        let table = Arc::new(ConfiguredUpstreams::from_definitions(
            [(definition.name.clone(), definition.clone())].into(),
        ));
        let routes = RequestRoutes::new("command-fixture", None, None, None)
            .unwrap()
            .with_registrations(table)
            .unwrap();
        let receipt = RequestAllocation::new(
            context,
            Arc::new(CostModel::resolve_parts(None, 0, &Default::default())),
            100,
        )
        .unwrap()
        .registration(&routes, None, &definition.name)
        .unwrap();
        let gov = Arc::new(
            GovState::new_with_core(crate::real_store::core().await, None, None)
                .await
                .unwrap(),
        );
        let money = super::super::PlaneMoney::new(gov, Arc::new(Posted));
        let request = money
            .admit_existing(
                receipt.begin().unwrap(),
                Arc::from([]),
                super::super::money::FeeRefund::CallerStatus,
                crate::config::groups::ExhaustionMode::FinishUnit,
            )
            .unwrap();
        Self {
            request,
            definition,
            caller,
            money,
            _owner: owner,
        }
    }
}

impl Drop for CommandAdmissionFixture {
    fn drop(&mut self) {
        self.money.settle_end_as(
            self.request.unit(),
            super::super::UnitEnd {
                caller_status: 502,
                cut: true,
                refused_unspent: false,
            },
        );
        self.request.context().retire();
    }
}
