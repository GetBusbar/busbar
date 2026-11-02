// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Host-only connection ownership shared by the connector and loader. This is Rust metadata;

/// The source of a host-authorized adoption. Never accepted from plugin input.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AdoptionSource {
    /// The original loaded owner.
    pub owner: u64,
    /// The original accepting listener.
    pub listener: u64,
    /// The original host framing incarnation.
    pub leg: u64,
    /// The confirmed original plugin-local token.
    pub conn: u64,
}

/// Host metadata for a staged transfer, before its new local token is confirmed.
#[derive(Debug, Clone, Copy)]
pub struct SessionTransfer {
    /// The pointer-free input loan to the new owner.
    pub session: crate::abi::transport::adopted_session::AdoptedSession,
    /// The admitted unit's original policy generation.
    pub generation: u64,
}

/// One host-owned framing leg, independent of the tickets its operations use.
pub trait FramingScope: std::fmt::Debug + Send + Sync {
    /// The latest copied count of this leg's framer-owned unread input, independent of tickets.
    fn retained_input(&self) -> u64 {
        0
    }
    /// Record a validated reply count while its lease is live. Missing reports do not clear it.
    fn set_retained_input(&self, _bytes: u64) {}
    /// The actual loaded plugin owner.
    fn owner(&self) -> u64;
    /// The accepting listener registration, or zero for an outbound connection.
    fn listener(&self) -> u64;
    /// The physical connection incarnation, retained across authorized adoption.
    fn connection(&self) -> u64;
    /// The framing leg incarnation.
    fn leg(&self) -> u64;
    /// The exact policy loan selected by the host for Begin/Peer, independent of global reloads.
    fn opening_policy(&self)
        -> Option<std::sync::Arc<crate::abi::transport::guest_policy::Policy>>;
    /// The trusted generation selected for a stream, or the initial opening Peer loan.
    fn policy_generation(&self, stream: u64, peer: bool) -> Option<u64>;
    /// Open a stream through the trusted host and retain its reply on this operation ticket.

    fn open_stream(
        &self,
        ticket: crate::abi::mechanism::ticket::Ticket,
        open: crate::abi::transport::guest_policy::Open,
    ) -> Result<(), &'static str>;
    /// The host-owned extension lent on this operation's next crossing.
    fn operation_reply(
        &self,
        ticket: crate::abi::mechanism::ticket::Ticket,
    ) -> Option<std::sync::Arc<[u8]>>;
    /// Keep the full lent extension bytes alive through a pending operation.
    fn hold_operation_reply(
        &self,
        ticket: crate::abi::mechanism::ticket::Ticket,
        reply: std::sync::Arc<[u8]>,
    );
    /// Release a crossing's policy reply; the operation may still owe more crossings.
    fn operation_done(&self, ticket: crate::abi::mechanism::ticket::Ticket);
    /// Begin a new operation on a ticket that may have previously been idle or cancelled.
    fn operation_started(&self, _ticket: crate::abi::mechanism::ticket::Ticket) {}
    /// Consume progress made by a newly granted stream on this operation alone.
    fn take_control_progress(&self, _ticket: crate::abi::mechanism::ticket::Ticket) -> bool {
        false
    }
    /// Associate a validated service with its still-unadmitted stream policy.

    fn claim_stream_operation(
        &self,
        _ticket: crate::abi::mechanism::ticket::Ticket,
        _stream: u64,
        _generation: u64,
    ) -> Result<(), &'static str> {
        Ok(())
    }
    /// The serving host claimed and published this stream's admitted request.
    fn admit_stream(&self, _stream: u64) {}
    /// Complete the whole operation, retaining body-waiting streams on success. Failure or

    fn operation_finished(&self, _ticket: crate::abi::mechanism::ticket::Ticket, _failed: bool) {}
    /// A stream ended independently of the operation tickets that drove it.
    fn stream_ended(&self, stream: u64);
    /// Validate a service's caller and plugin-local connection token.

    fn check(&self, owner: u64, conn: u64, teardown: bool) -> Result<(), &'static str>;
    /// Confirm the token returned by a READY opening, including prior provisional claims.

    fn confirm(&self, conn: u64) -> Result<(), &'static str>;
    /// Seal the source after successful protocol detach, retaining its admission custody.

    fn detach(&self) -> Result<(), &'static str>;
    /// The confirmed source binding, available only after host detach.
    fn adoption_source(&self) -> Option<AdoptionSource>;
    /// Stop ordinary admission before teardown.
    fn closing(&self);
    /// End authority once, even if asynchronous operations still retain this object.
    fn end(&self);
}
