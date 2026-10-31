// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Host-selected policy loans for streams sharing one framing connection.

use std::collections::HashMap;
use std::sync::Arc;

use crate::abi::mechanism::ticket::Ticket;
use crate::abi::mechanism::{call::BLOB_OCTETS, extensions};
use crate::abi::sdk::{life::Leases, out::Out};
use crate::abi::transport::guest_policy::{
    self, Identity, Open, Policy, EXT_GUEST_CURRENT, EXT_GUEST_OPEN, EXT_GUEST_POLICY,
};
use crate::abi::transport::{FramerOut, YIELD_MORE};

/// One connection's most recently decoded policy. Each stream retains its own immutable loan.
#[derive(Debug)]
pub struct Loans {
    current: Arc<Policy>,
    opening: HashMap<Ticket, (u64, Arc<Policy>)>,
}

#[cfg(test)]
#[path = "../tests/transport_policy_tests.rs"]
mod tests;

impl Loans {
    /// Decode the initial full policy once. `None` means the host did not advertise this
    /// protocol; the caller may keep its legacy guest-list behavior in that case alone.
    ///
    /// # Errors
    /// An invalid policy or a current-generation acknowledgement without an initial full loan.
    pub fn from_initial(extensions: &[u8]) -> Result<Option<Self>, &'static str> {
        if extensions::get(extensions, EXT_GUEST_CURRENT).is_some() {
            return Err("the initial policy must be a full loan");
        }
        extensions::get(extensions, EXT_GUEST_POLICY)
            .map(|bytes| {
                guest_policy::decode(bytes).map(|policy| Self {
                    current: Arc::new(policy),
                    opening: HashMap::new(),
                })
            })
            .transpose()
    }

    /// Open a stream against the host's selected generation. Pin `Some(policy)` in the stream
    /// before route matching, auth, or body handling, and retain it across PENDING and retries.
    /// Call this for a new stream, not again at each auth step of an already pinned stream.
    ///
    /// Without a reply, lease an Open request into `out`, set `YIELD_MORE`, and return `None`.
    /// The caller returns READY so the host can recall the operation with its policy reply;
    /// the operation ticket correlates that reply with this stream opening.
    ///
    /// # Errors
    /// A malformed or conflicting reply, a full policy for another listener, or an
    /// acknowledgement of a listener/generation absent from this connection's cache.
    pub fn open(
        &mut self,
        ticket: Ticket,
        stream: u64,
        extensions: &[u8],
        out: &mut Out<'_, FramerOut>,
        leases: &Leases,
    ) -> Result<Option<Arc<Policy>>, &'static str> {
        if self
            .opening
            .get(&ticket)
            .is_some_and(|(requested, _)| *requested != stream)
        {
            return Err("the operation is already opening another stream");
        }
        match (
            extensions::get(extensions, EXT_GUEST_POLICY),
            extensions::get(extensions, EXT_GUEST_CURRENT),
        ) {
            (Some(_), Some(_)) => {
                Err("the policy reply names both a full loan and an acknowledgement")
            }
            (Some(bytes), None) => {
                if !self.opening.contains_key(&ticket) {
                    return Err("the policy reply has no outstanding stream opening");
                }
                let policy = guest_policy::decode(bytes)?;
                if policy.listener != self.current.listener {
                    return Err("the policy reply belongs to another listener");
                }
                self.opening.remove(&ticket);
                self.current = Arc::new(policy);
                Ok(Some(Arc::clone(&self.current)))
            }
            (None, Some(bytes)) => {
                let identity = Identity::decode(bytes)?;
                let (_, cached) = self
                    .opening
                    .get(&ticket)
                    .ok_or("the policy reply has no outstanding stream opening")?;
                if identity.listener != cached.listener || identity.generation != cached.generation
                {
                    return Err("the acknowledged policy is not cached on this connection");
                }
                let policy = Arc::clone(cached);
                self.opening.remove(&ticket);
                Ok(Some(policy))
            }
            (None, None) => {
                let cached = self
                    .opening
                    .entry(ticket)
                    .or_insert_with(|| (stream, Arc::clone(&self.current)));
                let open = Open {
                    stream,
                    known_generation: cached.1.generation,
                }
                .encode();
                let bytes = extensions::encode(&[(EXT_GUEST_OPEN, &open)]);
                out.lease(|o| &o.head.extensions, leases, bytes, BLOB_OCTETS);
                let flags = out.get().yielded.flags | YIELD_MORE;
                out.set(|o| &o.yielded.flags, flags);
                Ok(None)
            }
        }
    }
}
