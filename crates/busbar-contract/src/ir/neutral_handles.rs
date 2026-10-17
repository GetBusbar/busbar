// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The neutral `IrHandle`s for the two protocol-surface operations, `Invoke` and `Subscribe` (G6 A4b
//! dissolve). Their `InvokeReq`/`SubscribeReq` types live beside them (`ir::invoke`/`ir::subscribe`);
//! the handles wrap them and use the trait DEFAULTS for everything except `verb`, `facts`
//! (request-side projection) and `billing` (`Billing::Flat` — a tool call / subscription is
//! flat-metered, one call one unit). No cross-protocol prep or write: these operations are
//! same-protocol only, so the default empty egress/ingress write is never exercised (a same-protocol
//! route forwards the caller's bytes verbatim). A protocol-surface codec yields these handles from
//! its `read_request`/`read_response`.
//!
//! A SHAPE (DECISIONS #83), relocated from `busbar-substrate-values::ir::neutral_handles` (#83a
//! SD-2b) beside the `IrHandle` they implement; the substrate re-exports the four handles under their
//! historical path.

use crate::billing::Billing;
use crate::ir::facts::IrFacts;
use crate::ir::handle::sealed::Sealed;
use crate::ir::handle::IrHandle;
use crate::ir::invoke::{InvokeReq, InvokeResp};
use crate::ir::subscribe::{SubscribeReq, SubscribeResp};
use crate::operation::OpVerb;
use std::sync::Arc;

/// The request payload is held behind an `Arc` because `facts()` must hand back an OWNED
/// `Box<dyn IrFacts + Send + Sync>`: holding the request directly forced a DEEP CLONE of the whole
/// request — arguments `Value` and all — on every call, to answer a read-only question. Sharing the
/// one allocation means the caller's payload is cloned zero times.
pub struct InvokeReqHandle(pub Arc<InvokeReq>);
pub struct InvokeRespHandle(pub InvokeResp);
/// Shared for the same reason as [`InvokeReqHandle`].
pub struct SubscribeReqHandle(pub Arc<SubscribeReq>);
pub struct SubscribeRespHandle(pub SubscribeResp);

impl Sealed for InvokeReqHandle {}
impl Sealed for InvokeRespHandle {}
impl Sealed for SubscribeReqHandle {}
impl Sealed for SubscribeRespHandle {}

impl IrHandle for InvokeReqHandle {
    fn verb(&self) -> OpVerb {
        OpVerb::INVOKE
    }
    fn facts(&self) -> Box<dyn IrFacts + Send + Sync> {
        Box::new(Arc::clone(&self.0))
    }
}

impl IrHandle for InvokeRespHandle {
    fn verb(&self) -> OpVerb {
        OpVerb::INVOKE
    }
    fn billing(&self) -> Option<Billing> {
        Some(Billing::Flat)
    }
}

impl IrHandle for SubscribeReqHandle {
    fn verb(&self) -> OpVerb {
        OpVerb::SUBSCRIBE
    }
    fn facts(&self) -> Box<dyn IrFacts + Send + Sync> {
        Box::new(Arc::clone(&self.0))
    }
}

impl IrHandle for SubscribeRespHandle {
    fn verb(&self) -> OpVerb {
        OpVerb::SUBSCRIBE
    }
    fn billing(&self) -> Option<Billing> {
        Some(Billing::Flat)
    }
}

#[cfg(test)]
#[path = "tests/neutral_handles.rs"]
mod tests;
