// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! [`RequestGrants`]: ENTITLE as a lookup in the grant set resolved once per request (IF §12.11).

use std::collections::{BTreeSet, HashMap};
use std::sync::{Arc, Mutex, PoisonError};

use busbar_plugin_abi::host_side::caller::Caller;

use super::Entitlements;

/// The core principal grant resolver: every grant the verified principal (or
/// ticket) whose identity records are `identity` holds, handed to `sink` one at a time.
pub trait GrantResolver: Send + Sync + 'static {
    fn grants(&self, identity: &[u8], sink: &mut dyn FnMut(&str));
}

/// One identity's resolved grant set, shared by every `check` of the request that names it.
type GrantSet = Arc<BTreeSet<Box<str>>>;

/// One request's entitlements. K8 builds one per request; the first `check` for an identity resolves its whole
/// grant set through the [`GrantResolver`] and every later `check` on the request is a lookup in it, so a
/// principal changed mid-request is judged the same way for the whole request.
pub struct RequestGrants<G> {
    resolver: G,
    sets: Mutex<HashMap<Box<[u8]>, GrantSet>>,
}

impl<G: GrantResolver> RequestGrants<G> {
    pub fn new(resolver: G) -> Self {
        Self {
            resolver,
            sets: Mutex::new(HashMap::new()),
        }
    }

    fn set(&self, identity: &[u8]) -> GrantSet {
        if let Some(set) = self
            .sets
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .get(identity)
        {
            return Arc::clone(set);
        }
        let mut set = BTreeSet::new();
        self.resolver.grants(identity, &mut |grant| {
            set.insert(Box::<str>::from(grant));
        });
        let set = Arc::new(set);
        Arc::clone(
            self.sets
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .entry(identity.into())
                .or_insert(set),
        )
    }
}

impl<G: GrantResolver> Entitlements for RequestGrants<G> {
    fn check(&self, who: &Caller<'_>, identity: &[u8], grant: &str) -> bool {
        let _ = who;
        self.set(identity).contains(grant)
    }
}
