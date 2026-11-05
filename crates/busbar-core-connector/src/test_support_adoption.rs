// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Observe the connector's actual adoption loan while retaining its loaded transport owner.

use std::sync::Arc;

use busbar_contract::abi::transport::listener_bindings::ListenerBinding;
use busbar_contract::framing_scope::FramingScope;

use crate::carrier::{Carry, Side};
use crate::framer::{Call, Crossed, DoorFacts, FramerDoor, Refused};

type Scope = Arc<dyn FramingScope>;

/// Record the exact claim lent to a real transport's adoption operation.
///
/// The observer borrows the claim only for the crossing. All operations, host scopes and image
/// ownership remain those of `actual`; the wrapper creates no framing or admission authority.
#[must_use]
pub fn observe_adoption(
    actual: Arc<dyn FramerDoor>,
    observer: impl Fn(&str) + Send + Sync + 'static,
) -> Arc<dyn FramerDoor> {
    Arc::new(Observed { actual, observer })
}

struct Observed<F> {
    actual: Arc<dyn FramerDoor>,
    observer: F,
}

impl<F: Fn(&str)> Observed<F> {
    // This test-support boundary reads the connector's scoped ABI loan before forwarding it.
    #[allow(unsafe_code)]
    fn observe(&self, call: &Call<'_>) {
        let Call::Adopt(input, _) = call else {
            return;
        };
        assert!(
            !input.facts.is_null(),
            "an actual adoption lends connection facts"
        );
        // SAFETY: as for the delegated FramerDoor crossing, the connector lends AdoptIn and
        // its ConnFacts for this operation. The claim is copied/observed before delegation,
        // and neither the pointer nor the borrowed string escapes this crossing.
        let facts = unsafe { &*input.facts };
        assert!(
            facts.size as usize
                >= std::mem::offset_of!(busbar_contract::abi::transport::ConnFacts, claim)
                    + std::mem::size_of_val(&facts.claim)
        );
        let claim = facts.claim;
        assert!(claim.len <= 64 * 1024, "the adoption claim is bounded");
        assert!(claim.len == 0 || !claim.ptr.is_null());
        let bytes = if claim.len == 0 {
            &[][..]
        } else {
            // SAFETY: the connector's bounded claim loan is live for this crossing above.
            unsafe { std::slice::from_raw_parts(claim.ptr, claim.len) }
        };
        (self.observer)(std::str::from_utf8(bytes).expect("the selected claim is UTF-8"));
    }
}

impl<F: Fn(&str) + Send + Sync> FramerDoor for Observed<F> {
    fn listener_bindings(&self) -> &[ListenerBinding] {
        self.actual.listener_bindings()
    }
    fn facts(&self) -> &DoorFacts {
        self.actual.facts()
    }
    fn seals_values(&self) -> bool {
        self.actual.seals_values()
    }
    fn accepts(&self) -> bool {
        self.actual.accepts()
    }
    fn detaches(&self) -> bool {
        self.actual.detaches()
    }
    fn adopts(&self) -> bool {
        self.actual.adopts()
    }
    fn instance(&self) -> Option<u64> {
        self.actual.instance()
    }
    fn io_owner(&self) -> Option<u64> {
        self.actual.io_owner()
    }
    fn side(&self) -> Option<Box<dyn Side>> {
        self.actual.side()
    }
    fn framing_side(&self) -> Option<Box<dyn Side>> {
        self.actual.framing_side()
    }
    fn incomplete_retirement(&self, error: &Refused) {
        self.actual.incomplete_retirement(error);
    }
    fn cross(&self, call: Call<'_>) -> Crossed {
        self.observe(&call);
        self.actual.cross(call)
    }
    fn cross_on(&self, side: &dyn Side, resume: bool, call: Call<'_>) -> Crossed {
        self.observe(&call);
        self.actual.cross_on(side, resume, call)
    }
    fn carry(&self, side: &dyn Side, resume: bool, call: Carry<'_>) -> Crossed {
        self.actual.carry(side, resume, call)
    }
    fn framing_context(&self, listener: u64, connection: u64) -> Result<Option<Scope>, Refused> {
        self.actual.framing_context(listener, connection)
    }
    fn adopting_context(&self, source: Scope) -> Result<Option<Scope>, Refused> {
        self.actual.adopting_context(source)
    }
    fn cross_scoped(
        &self,
        scope: Option<&Scope>,
        side: Option<&dyn Side>,
        resume: bool,
        call: Call<'_>,
    ) -> Crossed {
        self.observe(&call);
        self.actual.cross_scoped(scope, side, resume, call)
    }
    fn cancel_scoped(&self, scope: Option<&Scope>, side: &dyn Side, call: Carry<'_>) -> Crossed {
        self.actual.cancel_scoped(scope, side, call)
    }
}
