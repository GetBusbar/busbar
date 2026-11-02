// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The neutral `IrHandle`s for the two protocol-surface operations, `Invoke` and `Subscribe`. Their `InvokeReq`/`SubscribeReq` types live beside them (`ir::invoke`/`ir::subscribe`);

use crate::billing::Billing;
use crate::ir::facts::IrFacts;
use crate::ir::handle::sealed::Sealed;
use crate::ir::handle::IrHandle;
use crate::ir::invoke::{InvokeReq, InvokeResp};
use crate::ir::subscribe::{SubscribeReq, SubscribeResp};
use crate::operation::OpVerb;
use std::sync::Arc;

/// The request payload is held behind an `Arc` because `facts()` must hand back an OWNED
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
