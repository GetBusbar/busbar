// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! `IrHandle` — the SEALED, NEUTRAL request/response handle the operation-blind engine holds now that

pub mod handle_impl {
    use super::sealed;
    use crate::billing::{Billing, TokenUsage};
    use crate::bounded::SlabBytes;
    use crate::codec::{CodecError, CodecHost, EgressWire, TranslatedResponse};
    use crate::ir::facts::IrFacts;
    use crate::operation::OpVerb;

    /// The type-erased request/response an `OperationHandler` yields, now that the `IrReq`/`IrResp`
    pub trait IrHandle: sealed::Sealed + Send {
        /// The semantic operation this handle carries — the closed registry vocabulary / metric label.
        fn verb(&self) -> OpVerb;

        /// Did the caller ask to stream? (request-side; response handles keep the `false` default.)
        fn wants_stream(&self) -> bool {
            false
        }

        /// The neutral projection the shared pipeline (hooks/governance/taps) reads (request-side).
        fn facts(&self) -> Box<dyn IrFacts + Send + Sync> {
            Box::new(crate::ir::facts::NeutralFacts(self.verb()))
        }

        /// Apply an implementation-owned preparation context synchronously. The contract never
        fn prepare_for_egress(&mut self, _context: &dyn std::any::Any) -> Result<(), CodecError> {
            Ok(())
        }

        /// Stamp the resolved wire model onto this request. Default no-op (URL-model ops carry none).
        fn set_model(&mut self, _model: &str) {}

        /// Fail-closed guard: `Err(reason)` rejects a request the `egress_proto` dialect cannot
        fn egress_representable(&self, _egress_proto: &str) -> Result<(), String> {
            Ok(())
        }

        /// The caller controls the `egress_proto` dialect will DROP for this request (audit-and-allow).
        fn egress_dropped_controls(&self, _egress_proto: &str) -> Vec<&'static str> {
            Vec::new()
        }

        /// JSON egress path: value-first (a JSON body the router post-shapes) else `set_model` + final
        fn write_egress_request(
            &mut self,
            _host: &dyn CodecHost,
            egress_proto: &str,
            _model: &str,
        ) -> EgressWire {
            EgressWire::Unrepresentable {
                reason: format!(
                    "this request cannot be written onto {egress_proto}: the operation carries no \
                     writer for that dialect"
                ),
            }
        }

        /// OPAQUE egress path (multipart/audio): `set_model` + the `egress_proto` dialect's final bytes.
        fn write_egress_request_bytes(&mut self, _egress_proto: &str, _model: &str) -> SlabBytes {
            SlabBytes::default()
        }

        /// The billable item this response produces. Default `None`; chat/leaf override; the neutral
        fn billing(&self) -> Option<Billing> {
            None
        }

        /// The token usage if this response is token-metered (the `Billing::Tokens` unwrap). Default
        fn token_usage(&self) -> Option<TokenUsage> {
            match self.billing() {
                Some(Billing::Tokens(t)) => Some(t),
                _ => None,
            }
        }

        /// Fill the serving MODEL when the upstream body carried none. On a cross-protocol hop where
        fn fill_response_model_if_absent(&mut self, _model: &str) {}

        /// Hand this response the TRANSLATION CAP its plane enforces (the one the kernel handed the
        fn apply_translate_cap(&mut self, _cap: usize) {}

        /// CROSS-PROTOCOL ingress preparation — reshape this response for delivery in the caller's
        fn prepare_for_ingress(&mut self, _ingress_protocol: &str, _now_epoch: u64) {}

        /// Capture the ORIGINAL ingress request body — called once (when the caller has a
        fn apply_request_echo(&mut self, _ingress_request_body: &serde_json::Value) {}

        /// Re-emit a buffered response as the `ingress_protocol` dialect's native STREAM bytes (an
        fn wrap_buffered_as_stream(
            &self,
            _host: &dyn CodecHost,
            _ingress_protocol: &str,
            _elapsed_ms: Option<u64>,
        ) -> Option<Vec<u8>> {
            None
        }

        /// JSON ingress path: write this response onto the `ingress_protocol` dialect
        fn write_ingress_response(
            &self,
            _host: &dyn CodecHost,
            _ingress_protocol: &str,
            _ingress_serves_op: bool,
        ) -> TranslatedResponse {
            TranslatedResponse::Untranslatable
        }

        /// OPAQUE ingress path (audio / the opaque bridge). Default `Untranslatable`.
        fn write_ingress_response_bytes(
            &self,
            _host: &dyn CodecHost,
            _ingress_protocol: &str,
            _ingress_serves_op: bool,
        ) -> TranslatedResponse {
            TranslatedResponse::Untranslatable
        }
    }
}

/// The soft-seal: `IrHandle` can only be implemented by a type that also implements this trait.
/// It is public so first-party dialect crates can implement `IrHandle`,
/// but hidden from the documented surface. The implementor set
/// stays closed by workspace convention: nothing outside the workspace
/// names `Sealed`, and no `Box<dyn Any>` downcast is used.
#[doc(hidden)]
pub mod sealed {
    #[allow(dead_code)]
    pub trait Sealed {}
}

#[allow(unused_imports)]
pub use handle_impl::IrHandle;
