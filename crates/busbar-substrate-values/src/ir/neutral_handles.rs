// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The neutral `IrHandle`s for the two protocol-surface operations, `Invoke` and `Subscribe` (G6 A4b
//! dissolve). Their `InvokeReq`/`SubscribeReq` types live here in `busbar-substrate`
//! (`ir::invoke`/`ir::subscribe`); the handles wrap them and use the trait DEFAULTS for everything
//! except `verb`, `facts` (request-side projection) and `billing` (`Billing::Flat` — a tool call /
//! subscription is flat-metered, one call one unit). No cross-protocol prep or write: these
//! operations are same-protocol only (mcp/a2a), so the default empty egress/ingress write is never
//! exercised (a same-protocol route forwards the caller's bytes verbatim). busbar-mcp's codec yields
//! these handles from its `read_request`/`read_response`.
//!
//! RELOCATED DOWN from `busbar-core` (`ir::neutral_handles`) at Batch C-4 — now that `IrHandle`,
//! `IrFacts`, `Billing` and the two data leaves are all substrate-resident, these four thin newtype
//! impls travel wholesale beside them. Core re-exports the four handles from
//! `busbar_core::ir::neutral_handles` so its own call sites are unchanged.

use crate::billing::Billing;
use crate::ir::facts::IrFacts;
use crate::ir::handle::sealed::Sealed;
use crate::ir::handle::IrHandle;
use crate::ir::invoke::{InvokeReq, InvokeResp};
use crate::ir::subscribe::{SubscribeReq, SubscribeResp};
use busbar_api::operation::Operation;
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
    fn verb(&self) -> Operation {
        Operation::INVOKE
    }
    fn facts(&self) -> Box<dyn IrFacts + Send + Sync> {
        Box::new(Arc::clone(&self.0))
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
        Box::new(Arc::clone(&self.0))
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ir::subscribe::SubscribeIntent;

    /// `facts()` used to deep-clone the whole request — the caller's arguments `Value` and all — on
    /// every call, to answer a read-only question. It must SHARE the one allocation instead: the
    /// refcount goes up, and the handle still points at the SAME arguments `Value` afterwards,
    /// which is only true if nothing was cloned.
    #[test]
    fn invoke_facts_share_the_request_rather_than_cloning_it() {
        let req = Arc::new(InvokeReq {
            tool: "search".to_string(),
            arguments: serde_json::json!({"q": "hello"}),
            extra: Default::default(),
        });
        let arguments_ptr = std::ptr::addr_of!(req.arguments);
        let handle = InvokeReqHandle(Arc::clone(&req));
        let before = Arc::strong_count(&req);

        let facts = handle.facts();
        assert_eq!(
            Arc::strong_count(&req),
            before + 1,
            "facts() must SHARE the request (one refcount bump), not clone it"
        );
        assert_eq!(
            std::ptr::addr_of!(handle.0.arguments),
            arguments_ptr,
            "the arguments Value must not have been cloned"
        );
        assert_eq!(facts.verb(), Operation::INVOKE);
        drop(facts);
        assert_eq!(Arc::strong_count(&req), before, "the share is released");
    }

    /// The same for `Subscribe`.
    #[test]
    fn subscribe_facts_share_the_request_rather_than_cloning_it() {
        let req = Arc::new(SubscribeReq {
            intent: SubscribeIntent::Register,
            target: "file:///doc".to_string(),
            extra: Default::default(),
        });
        let target_ptr = std::ptr::addr_of!(req.target);
        let handle = SubscribeReqHandle(Arc::clone(&req));
        let before = Arc::strong_count(&req);
        let facts = handle.facts();
        assert_eq!(Arc::strong_count(&req), before + 1);
        assert_eq!(std::ptr::addr_of!(handle.0.target), target_ptr);
        drop(facts);
        assert_eq!(Arc::strong_count(&req), before);
    }
}
