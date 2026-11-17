// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! A command channel retains the actual admitted request, never authority reconstructed from its name.

use std::hash::{Hash, Hasher};
use std::sync::Arc;

use crate::plane_driver::request_admission::AdmittedRequest;
use crate::plugin_records::RecordsDenied;
use crate::upstreams::UpstreamDef;

/// Unit-local sharing until the host has a credential-occurrence equivalence producer. Clones retain
/// the exact record, generation, selected table/definition and installed monetary Open.
#[derive(Clone)]
pub struct ChannelAuthority {
    admitted: AdmittedRequest,
    definition: Arc<UpstreamDef>,
}

impl ChannelAuthority {
    pub fn new(admitted: AdmittedRequest) -> Result<Self, RecordsDenied> {
        if !admitted.is_live() {
            return Err(RecordsDenied::Invalid);
        }
        let definition = admitted
            .registered_command()
            .cloned()
            .ok_or(RecordsDenied::Invalid)?;
        Ok(Self {
            admitted,
            definition,
        })
    }

    pub(crate) fn is_live(&self) -> bool {
        self.admitted.is_live()
    }

    pub(crate) fn accepts(&self, owner: &busbar_contract::services::Caller) -> bool {
        self.is_live() && self.admitted.context().accepts(owner)
    }

    pub(crate) fn check(&self, upstream: &UpstreamDef) -> Result<(), RecordsDenied> {
        if self.is_live() && std::ptr::eq(self.definition.as_ref(), upstream) {
            Ok(())
        } else {
            Err(RecordsDenied::Invalid)
        }
    }
}

impl PartialEq for ChannelAuthority {
    fn eq(&self, other: &Self) -> bool {
        self.admitted.same_admission(&other.admitted)
    }
}
impl Eq for ChannelAuthority {}
impl Hash for ChannelAuthority {
    fn hash<H: Hasher>(&self, state: &mut H) {
        // These select a bucket only. Equality checks the complete opaque record/Open identity.
        self.admitted.context().unit().hash(state);
        Arc::as_ptr(self.admitted.context().generation()).hash(state);
        Arc::as_ptr(&self.definition).hash(state);
    }
}
impl std::fmt::Debug for ChannelAuthority {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ChannelAuthority")
    }
}
