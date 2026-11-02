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
    /// The stream waiting for this operation's policy reply.
    #[must_use]
    pub fn pending_stream(&self, ticket: Ticket) -> Option<u64> {
        self.opening.get(&ticket).map(|(stream, _)| *stream)
    }

    /// Forget a cancelled opening. The host separately retires its unadmitted stream grant.
    pub fn cancel(&mut self, ticket: Ticket) -> Option<u64> {
        self.opening.remove(&ticket).map(|(stream, _)| stream)
    }

    /// Decode the initial full policy once. `None` means the host did not advertise this

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

        let reply = if self.opening.contains_key(&ticket) {
            (
                extensions::get(extensions, EXT_GUEST_POLICY),
                extensions::get(extensions, EXT_GUEST_CURRENT),
            )
        } else {
            (None, None)
        };
        match reply {
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
