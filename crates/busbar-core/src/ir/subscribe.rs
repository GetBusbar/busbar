// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE SUBSCRIBE IR — the `Operation::SUBSCRIBE` subclass of the parent
//! [`crate::ir::variant::IrReq`] / [`crate::ir::variant::IrResp`] enums.
//!
//! ## WHAT A SUBSCRIPTION REQUEST IS, REDUCED TO ITS INVARIANTS
//!
//! A caller names a thing and asks to start — or to stop — being told when it changes. That is the
//! whole operation, and it is two directions of ONE shape rather than two shapes: the name is the
//! same name, the answer is the same acknowledgement, and the only difference is which way the
//! registration moves. MCP spells the pair `resources/subscribe` and `resources/unsubscribe`; A2A
//! spells it as the push-notification-configuration verbs. They are the same request.
//!
//! ## THE SUBJECT IS THE REGISTRATION, NEVER THE EVENTS
//!
//! Nothing here models a notification. A subscription request is a request: it is made, it is
//! judged, it is answered, and it is over. The events that follow travel on whatever channel the
//! transport provides, and a request IR that tried to describe them would be describing a channel.
//! The notification vocabulary therefore lives with the protocol cell that frames it, not here.
//!
//! ## WHY REGISTER AND DEREGISTER ARE ONE VARIANT AND NOT TWO
//!
//! Two IR variants would mean every exhaustive match in the tree decides the same question twice,
//! and the second decision is the one that drifts. They differ in a single field, every guard that
//! applies to one applies to the other, and the pair is meaningless if the two ever disagree about
//! what a target name is. One variant with an explicit intent keeps that impossible.
//!
//! ## THE ANSWER CARRIES NOTHING, AND THAT IS A FACT ABOUT THE PROTOCOL
//!
//! MCP answers both verbs with an empty result: the acknowledgement IS the content. Other protocols
//! answer the same shape with the registration record they just stored. [`SubscribeResp`] therefore
//! carries an OPTIONAL record rather than pretending every peer returns one, so a cell never has to
//! invent a body its own wire does not have.

// THE PURE DATA (`SubscribeIntent`/`SubscribeReq`/`SubscribeResp`) RELOCATED to `busbar-substrate`
// (the neutral cross-plane IR leaf a plane crate names directly), and at Batch C-2 the family-blind
// `IrFacts` projection over `SubscribeReq` travelled with it (the trait is now substrate-resident, so
// the impl sits beside the trait/type to satisfy the orphan rule). Core re-exports the data types from
// this historical path; the projection reaches every in-core caller through the same re-export.
pub use busbar_substrate::ir::subscribe::{SubscribeIntent, SubscribeReq, SubscribeResp};

#[cfg(test)]
#[path = "tests/subscribe_tests.rs"]
mod subscribe_tests;
