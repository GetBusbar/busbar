// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! `IrHandle` — the SEALED, NEUTRAL request/response handle the operation-blind engine will hold once
//! `IrReq`/`IrResp` dissolve at **G6 step A4b**. It is landed here, in A4a, UNREFERENCED and
//! byte-identical by construction: nothing constructs or calls it yet, so the compiled product is
//! unchanged. It exists now so the target the A4b dissolve lands onto — and the seam every future
//! `busbar-llm` / `busbar-mcp` / `busbar-a2a` handle implements — is reviewed, named, and frozen
//! BEFORE the irreversible relocation, not invented during it.
//!
//! **SEALED (owner ruling 2026-08-20): a neutral TRAIT, never `Box<dyn Any>` + downcast.** Core
//! defines the trait; the dialect crates implement it; no core code ever downcasts to a concrete IR.
//! The `#[doc(hidden)]` [`sealed::Sealed`] supertrait makes "who may implement `IrHandle`" a decision
//! core keeps: an external crate cannot add an implementor without also naming `sealed::Sealed`, which
//! is `pub` but `#[doc(hidden)]` — a SOFT seal closed by convention to the first-party dialect crates
//! that deliberately reach for it, NOT the compiler-enforced `pub(crate)` hard seal (see the note on
//! `mod sealed` below). In-tree the two are equivalent: nothing outside the workspace names `Sealed`.
//!
//! **NAMES ONLY NEUTRAL TYPES.** Every method here is spelled in the surface that STAYS in core —
//! `Operation`, `IrFacts`, `Billing`, and (threaded at A4b) the resolved-primitives `EgressPrep` —
//! and NONE of the concrete chat IR (the chat request/response/block types) that relocates to
//! `busbar-llm` at A4b. That is the whole point: the engine that holds a `Box<dyn IrHandle>` can drive
//! translation/billing/preparation without the concrete IR existing in core at all.
//!
//! The default bodies reproduce the NEUTRAL arms the `IrReq`/`IrResp` enums answer today: the
//! `Invoke`/`Subscribe` operations are a no-op `prepare_*` plus `Billing::Flat`, so a core-owned
//! `ir::invoke`/`ir::subscribe` handle will implement this trait through the defaults alone, and only
//! chat (in `busbar-llm`) overrides `prepare_for_egress`/`prepare_for_ingress`/`billing`.

pub mod handle_impl {
    use super::sealed;
    use crate::billing::{Billing, TokenUsage};
    use crate::handlers::{EgressWire, TranslatedResponse};
    use crate::ir::egress_prep::EgressPrep;
    use crate::ir::facts::IrFacts;
    use crate::operation::Operation;
    use bytes::Bytes;

    /// The type-erased request/response an `OperationHandler` yields, now that the `IrReq`/`IrResp`
    /// hub enums have dissolved (G6 A4b). Every method names a neutral, core-retained type; the
    /// concrete chat IR lives behind the implementor in `busbar-llm` (chat + the six leaf ops) or in
    /// core (`ir::invoke`/`ir::subscribe`, via defaults). Soft-sealed via the `#[doc(hidden)]`
    /// [`sealed::Sealed`] supertrait — no `Box<dyn Any>` downcast anywhere.
    ///
    /// A handle instance is EITHER a request or a response; the request-side methods
    /// (`facts`/`prepare_for_egress`/`write_egress_request`/…) and the response-side methods
    /// (`billing`/`prepare_for_ingress`/`write_ingress_response`/…) both live on the one trait per the
    /// owner ruling, each side defaulting the other. The cross-protocol WRITE is keyed by the peer
    /// PROTOCOL STRING (not the peer `OperationHandler`): the handle writes ITSELF onto the target
    /// dialect (chat via `proto::protocol_for(proto).writer()`, leaf ops via `leaf_codec`), so no
    /// downcast is needed.
    pub trait IrHandle: sealed::Sealed + Send {
        /// The semantic operation this handle carries — the closed registry vocabulary / metric label.
        fn verb(&self) -> Operation;

        /// Did the caller ask to stream? (request-side; response handles keep the `false` default.)
        fn wants_stream(&self) -> bool {
            false
        }

        /// The neutral projection the shared pipeline (hooks/governance/taps) reads (request-side).
        /// Response handles never have this called; the default is an empty projection over `verb()`.
        fn facts(&self) -> Box<dyn IrFacts + Send + Sync> {
            Box::new(crate::ir::facts::NeutralFacts(self.verb()))
        }

        // ─────────────────────────── request-side (cross-protocol egress) ───────────────────────────

        /// CROSS-PROTOCOL egress preparation — reshape this request for the target dialect. Default
        /// no-op (the `Invoke`/`Subscribe`/leaf arms carry nothing to reshape); chat overrides.
        fn prepare_for_egress(&mut self, _prep: &EgressPrep) {}

        /// Stamp the resolved wire model onto this request. Default no-op (URL-model ops carry none).
        fn set_model(&mut self, _model: &str) {}

        /// Fail-closed guard: `Err(reason)` rejects a request the `egress_proto` dialect cannot
        /// represent without silent loss (4xx). Default `Ok(())`.
        fn egress_representable(&self, _egress_proto: &str) -> Result<(), String> {
            Ok(())
        }

        /// The caller controls the `egress_proto` dialect will DROP for this request (audit-and-allow).
        fn egress_dropped_controls(&self, _egress_proto: &str) -> Vec<&'static str> {
            Vec::new()
        }

        /// JSON egress path: value-first (a JSON body the router post-shapes) else `set_model` + final
        /// bytes, written onto the `egress_proto` dialect. Default: empty bytes (non-request handles).
        fn write_egress_request(&mut self, _egress_proto: &str, _model: &str) -> EgressWire {
            EgressWire::Bytes(Bytes::new())
        }

        /// OPAQUE egress path (multipart/audio): `set_model` + the `egress_proto` dialect's final bytes.
        fn write_egress_request_bytes(&mut self, _egress_proto: &str, _model: &str) -> Bytes {
            Bytes::new()
        }

        // ─────────────────────────── response-side ───────────────────────────

        /// The billable item this response produces. Default `None`; chat/leaf override; the neutral
        /// `Invoke`/`Subscribe` arms are `Some(Billing::Flat)`.
        fn billing(&self) -> Option<Billing> {
            None
        }

        /// The token usage if this response is token-metered (the `Billing::Tokens` unwrap). Default
        /// `None`.
        fn token_usage(&self) -> Option<TokenUsage> {
            match self.billing() {
                Some(Billing::Tokens(t)) => Some(t),
                _ => None,
            }
        }

        /// CROSS-PROTOCOL ingress preparation — reshape this response for delivery in the caller's
        /// `ingress_protocol`. Default no-op; chat overrides.
        fn prepare_for_ingress(&mut self, _ingress_protocol: &str, _now_epoch: u64) {}

        /// Re-emit a buffered response as the `ingress_protocol` dialect's native STREAM bytes (the
        /// Bedrock ConverseStream case). `None` when a plain buffered body is correct. Default `None`.
        fn wrap_buffered_as_stream(
            &self,
            _ingress_protocol: &str,
            _elapsed_ms: Option<u64>,
        ) -> Option<Vec<u8>> {
            None
        }

        /// JSON ingress path: write this response onto the `ingress_protocol` dialect
        /// (`ingress_serves_op` = does that protocol serve this op). Default `Untranslatable`.
        fn write_ingress_response(
            &self,
            _ingress_protocol: &str,
            _ingress_serves_op: bool,
        ) -> TranslatedResponse {
            TranslatedResponse::Untranslatable
        }

        /// OPAQUE ingress path (audio / the opaque bridge). Default `Untranslatable`.
        fn write_ingress_response_bytes(
            &self,
            _ingress_protocol: &str,
            _ingress_serves_op: bool,
        ) -> TranslatedResponse {
            TranslatedResponse::Untranslatable
        }
    }
}

/// The soft-seal: `IrHandle` can only be implemented by a type that also implements this trait.
/// `pub` (so the first-party busbar-llm / busbar-mcp / busbar-a2a dialect crates can name it and
/// implement `IrHandle`) but `#[doc(hidden)]` — it is not part of the documented surface, so the
/// implementor set stays closed by convention to the crates that deliberately reach for it. In-tree
/// this is equivalent to the `pub(crate)` hard seal the owner ruled on (2026-08-20): nothing outside
/// the workspace names `Sealed`, and there is no `Box<dyn Any>` downcast anywhere.
#[doc(hidden)]
pub mod sealed {
    #[allow(dead_code)] // A4b scaffolding: the seal has no implementors until the dissolve.
    pub trait Sealed {}
}

#[allow(unused_imports)] // re-export path the A4b engine will hold `IrHandle` through.
pub use handle_impl::IrHandle;
