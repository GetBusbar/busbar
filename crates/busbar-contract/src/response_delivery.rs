// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Read-only observations from the actual downstream carrier.
//!
//! These facts do not identify a response or establish its terminal outcome. The host joins them
//! with ordered protocol attribution and checked flush or shutdown results. A byte-stream trait
//! alone does not establish that its writes reach the physical carrier.

/// A sticky failure of the carrier or its exact write-progress accounting.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CarrierFault {
    /// A checked counter or tracking-descriptor bound was exhausted.
    Limit,
    /// Consumption, byte mapping or a reported write length violated the accounting contract.
    Integrity,
    /// The raw carrier accepted zero bytes from a nonempty write.
    WriteZero,
    /// The encryption provider failed to produce the required record.
    Encryption,
    /// The carrier cannot supply the required exact byte translation.
    Unsupported,
    /// The carrier reported a fatal I/O error; WouldBlock and Interrupted are not fatal.
    Io,
}

/// One coherent observation of monotone progress through the ordered protocol byte stream.
///
/// Offsets include protocol headers, framing and control bytes, not just response payload. For
/// TLS they begin at zero after the handshake, before application acceptance; handshake and TLS
/// control ciphertext have no logical span. Counters never wrap, rebase or get reused, and satisfy
/// `complete_records_plaintext <= written_plaintext <= accepted_plaintext`. A sticky fault retains
/// valid earlier progress. These counters alone never establish response completion.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CarrierProgress {
    /// The ordered plaintext prefix accepted by the carrier's logical writer.
    pub accepted_plaintext: u64,
    /// The plaintext prefix whose mapped bytes were actually accepted by the raw carrier.
    pub written_plaintext: u64,
    /// The plaintext prefix whose complete records, including authentication tags, were written.
    pub complete_records_plaintext: u64,
    /// The first fatal accounting or carrier failure, retained across all later observations.
    pub fault: Option<CarrierFault>,
}

/// Read-only access to progress privately maintained by the actual carrier producer.
///
/// Cloning access to a reader grants no mutation authority. Production assembly must bind the
/// reader to its genuine carrier; public construction of an observation is not evidence of a
/// write. There is deliberately no default observation or blanket byte-stream implementation.
pub trait CarrierProgressReader: Send + Sync {
    /// Read a coherent snapshot synchronously in constant space, without I/O or allocation.
    ///
    /// Consumers sample after every outer poll, including Pending and errors, and before retiring
    /// the writer. A fault must be checked even when that outer poll reports success.
    fn snapshot(&self) -> CarrierProgress;
}

/// Classification supplied at actual protocol serialization, before transport buffering.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WireClass {
    /// Headers, trailers, framing, padding and connection control; never application payload.
    Control,
    /// Encoded application body or message payload, excluding its protocol envelope.
    Payload,
}

/// Actual carrier operation required after a response's complete ordered wire prefix.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CompletionRequirement {
    /// The finite prefix must be committed and its real carrier flush must succeed.
    Flush,
    /// In addition to flush, actual carrier shutdown must succeed (close-delimited output).
    Shutdown,
}

/// The root-admitted identity of one response; constructing these facts grants no authority.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ResponseKey {
    /// Original durability node identity.
    pub node: u64,
    /// Original journal incarnation, retained across the response lifetime.
    pub incarnation: u64,
    /// Original governed unit, or an explicitly admitted pre-unit/unmetered response.
    pub unit: Option<crate::ids::UnitKey>,
    /// Non-reused native connection generation.
    pub connection_generation: u64,
    /// Monotonically admitted host stream, distinct from a protocol wire stream ID.
    pub stream: u64,
}

/// The final neutral command after every response-producing effect has resolved.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResponseDisposition {
    /// End the selected response; absence of status is preserved.
    End {
        /// The status already selected by the response owner, if any.
        status: Option<u16>,
    },
    /// Refuse under the existing neutral refusal status contract.
    Refuse {
        /// A refusal status in 400..=599.
        status: u16,
        /// Whether the final response owner already submitted its head.
        head_sent: bool,
    },
}

/// Immutable response intent facts, not a signing, release or delivery capability.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FinalResponseIntent {
    /// The original root-admitted response identity.
    pub key: ResponseKey,
    /// Checked ordinal of the actual final response publication operation.
    pub final_publication_ordinal: u64,
    /// The terminal command fixed before waiting for terminal transport credit.
    pub disposition: ResponseDisposition,
}

/// A bounded, content-free reason that response delivery stopped.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResponseStop {
    /// The response's owner requested cancellation.
    Cancelled,
    /// The response's absolute deadline expired.
    Deadline,
    /// The protocol producer aborted the response.
    Protocol,
    /// The actual carrier or its accounting failed.
    Carrier(CarrierFault),
    /// Identity, lifecycle or offset validation failed.
    Integrity,
    /// The admitted descriptor or response capacity was exhausted.
    Capacity,
    /// The actual carrier has been retired and cannot produce further writes.
    CarrierRetired,
}

/// One frozen response-delivery outcome, separate from work outcome and billing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeliveryTerminal {
    /// Required carrier completion, producer end and reader EOF have all joined.
    Complete,
    /// Publication stopped and all possible later writes have been settled or retired.
    Failed(ResponseStop),
}

/// Immutable host-produced facts about one admitted response.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DeliverySnapshot {
    /// At least one attributed payload byte reached the actual raw carrier.
    pub first_payload_written: bool,
    /// Frozen only after the corresponding successful or failed terminal join.
    pub terminal: Option<DeliveryTerminal>,
}

/// Read-only response facts usable without depending on the connector implementation.
pub trait DeliveryReader: Send + Sync {
    /// The original admitted identity privately retained by this delivery owner.
    fn key(&self) -> ResponseKey;
    /// Read the response's coherent monotone snapshot.
    fn snapshot(&self) -> DeliverySnapshot;
}
