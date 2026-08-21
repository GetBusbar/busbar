// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The CORE-owned neutral `IrHandle`s for the two protocol-surface operations, `Invoke` and
//! `Subscribe` (G6 A4b dissolve). Their `InvokeReq`/`SubscribeReq` types stay in core
//! (`ir::invoke`/`ir::subscribe`); the handles wrap them and use the trait DEFAULTS for everything
//! except `verb`, `facts` (request-side projection) and `billing` (`Billing::Flat` — a tool call /
//! subscription is flat-metered, one call one unit). No cross-protocol prep or write: these
//! operations are same-protocol only (mcp/a2a), so the default empty egress/ingress write is never
//! exercised (a same-protocol route forwards the caller's bytes verbatim). busbar-mcp's codec yields
//! these handles from its `read_request`/`read_response`.

use crate::billing::Billing;
use crate::ir::facts::IrFacts;
use crate::ir::handle::sealed::Sealed;
use crate::ir::handle::IrHandle;
use crate::ir::invoke::{InvokeReq, InvokeResp};
use crate::ir::subscribe::{SubscribeReq, SubscribeResp};
use crate::operation::Operation;

pub struct InvokeReqHandle(pub InvokeReq);
pub struct InvokeRespHandle(pub InvokeResp);
pub struct SubscribeReqHandle(pub SubscribeReq);
pub struct SubscribeRespHandle(pub SubscribeResp);

impl Sealed for InvokeReqHandle {}
impl Sealed for InvokeRespHandle {}
impl Sealed for SubscribeReqHandle {}
impl Sealed for SubscribeRespHandle {}

impl IrHandle for InvokeReqHandle {
    fn verb(&self) -> Operation {
        Operation::INVOKE
    }
    fn facts(&self) -> Box<dyn IrFacts + Send + Sync> {
        Box::new(self.0.clone())
    }
}

impl IrHandle for InvokeRespHandle {
    fn verb(&self) -> Operation {
        Operation::INVOKE
    }
    fn billing(&self) -> Option<Billing> {
        Some(Billing::Flat)
    }
}

impl IrHandle for SubscribeReqHandle {
    fn verb(&self) -> Operation {
        Operation::SUBSCRIBE
    }
    fn facts(&self) -> Box<dyn IrFacts + Send + Sync> {
        Box::new(self.0.clone())
    }
}

impl IrHandle for SubscribeRespHandle {
    fn verb(&self) -> Operation {
        Operation::SUBSCRIBE
    }
    fn billing(&self) -> Option<Billing> {
        Some(Billing::Flat)
    }
}
