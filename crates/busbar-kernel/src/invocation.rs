// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Complete serving ownership, lent to operations rather than plugin instances.
use super::{Caller, KernelServices, Nest, NestAsk, NestDone, NestRoute, NEST_NO_UNIT};
use std::sync::Arc;

/// Root constructs this only after its immutable dispatch snapshot is complete.
/// The route owns that snapshot; instances in it retain only core services.
pub struct ServingGeneration {
    core: Arc<KernelServices>,
    route: Arc<dyn NestRoute>,
}

impl ServingGeneration {
    pub fn new(core: Arc<KernelServices>, route: Arc<dyn NestRoute>) -> Self {
        Self { core, route }
    }

    pub fn core(&self) -> &Arc<KernelServices> {
        &self.core
    }
}

/// Execution authority for one admitted unit and instance in one generation.
/// Retaining a numeric request ID alone never constructs this authority.
#[derive(Clone)]
pub struct InvocationContext {
    generation: Arc<ServingGeneration>,
    caller: Caller,
    unit: u64,
    record: Arc<crate::host_units::UnitRecord>,
}

impl InvocationContext {
    pub fn new(
        generation: Arc<ServingGeneration>,
        caller: Caller,
        unit: u64,
    ) -> Result<Self, &'static str> {
        if generation.core.facts(&caller).is_none() {
            return Err(super::NOT_ADMITTED);
        }
        let record = generation
            .core
            .units()
            .invocation_record(unit, &caller)
            .ok_or(NEST_NO_UNIT)?;
        Ok(Self {
            generation,
            caller,
            unit,
            record,
        })
    }

    pub fn generation(&self) -> &Arc<ServingGeneration> {
        &self.generation
    }

    pub fn accepts(&self, caller: &Caller) -> bool {
        self.caller.incarnation() == caller.incarnation()
            && self.generation.core.facts(caller).is_some()
            && self
                .generation
                .core
                .units()
                .invocation_record(self.unit, caller)
                .is_some_and(|record| Arc::ptr_eq(&record, &self.record))
    }

    pub fn nest(&self, caller: &Caller, ask: NestAsk, done: NestDone) -> Result<(), &'static str> {
        if !self.accepts(caller) {
            return Err(NEST_NO_UNIT);
        }
        let retained = self.clone();
        self.generation.core.dispatch_child(
            &self.generation.route,
            Nest {
                parent: self.unit,
                depth: self.record.depth.saturating_add(1),
                principal: self.record.principal.clone(),
                ask,
                ancestry: self.generation.core.units().child_ancestry(self.unit),
                constraints: None,
            },
            Box::new(move |reply| {
                let _context = retained;
                done(reply);
            }),
        );
        Ok(())
    }
}
