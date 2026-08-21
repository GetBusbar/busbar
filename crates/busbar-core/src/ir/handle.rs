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
//! The private [`sealed::Sealed`] supertrait makes "who may implement `IrHandle`" a decision core
//! keeps: an external crate cannot add an implementor without also naming `sealed::Sealed`, which is
//! `pub(crate)`, so the implementor set is closed to the crates core links.
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

#[allow(dead_code)] // A4b scaffolding: unreferenced until the enum dissolves onto it.
pub mod handle_impl {
    use super::sealed;
    use crate::billing::Billing;
    use crate::ir::facts::IrFacts;
    use crate::operation::Operation;

    /// The type-erased request/response an `OperationHandler` yields, once the `IrReq`/`IrResp` hub
    /// enums dissolve (A4b). Every method names a neutral, core-retained type; the concrete chat IR
    /// lives behind the implementor in `busbar-llm`. Soft-sealed via the `#[doc(hidden)]`
    /// [`sealed::Sealed`] supertrait (owner ruling 2026-08-20 — pre-step 2): `pub` so the busbar-llm
    /// dialect handlers can implement it, but an implementor must also name `Sealed`, which is hidden
    /// from the docs and only referenced by the first-party dialect crates, so the implementor set
    /// stays closed by convention (in-workspace this is equivalent to the hard seal — nothing outside
    /// the workspace names `Sealed`). No `Box<dyn Any>` downcast anywhere.
    pub trait IrHandle: sealed::Sealed + Send {
        /// The semantic operation this handle carries — the same closed vocabulary the registry
        /// declares and the metric labels use. Replaces the enum discriminant `match` that answered
        /// the operation today.
        fn verb(&self) -> Operation;

        /// Did the caller ask to stream?
        fn wants_stream(&self) -> bool;

        /// The neutral projection the shared pipeline (hooks, governance, taps) is allowed to read —
        /// the ONLY window onto the request's content, never the concrete IR.
        fn facts(&self) -> Box<dyn IrFacts>;

        /// The billable item this handle produces, or `None` when billing is deferred to a later
        /// seam. Default `None`; chat/embeddings/… override. The neutral `Invoke`/`Subscribe` arms
        /// are `Some(Billing::Flat)` in their own impls.
        fn billing(&self) -> Option<Billing> {
            None
        }

        /// CROSS-PROTOCOL egress preparation — reshape this handle's request for the target dialect.
        /// DEFAULT no-op: reproduces the `Invoke`/`Subscribe` arms, which carry nothing to reshape;
        /// chat overrides in `busbar-llm`.
        ///
        /// The resolved-primitives param bag (`ir::variant::EgressPrep` today) is threaded in as the
        /// argument at **A4b**, when the dissolve wires this method into the driver — deliberately NOT
        /// named here in A4a, because `EgressPrep` is a `g6-freeze-witness` TYPES entry and naming it
        /// from this unreferenced skeleton would bump the freeze count above its A4a baseline (which
        /// must not move). The skeleton names only neutral types the witness does NOT count.
        fn prepare_for_egress(&mut self) {}

        /// CROSS-PROTOCOL ingress preparation — reshape this handle's response for delivery in the
        /// caller's dialect. DEFAULT no-op (the neutral arms carry no cross-protocol identity to
        /// reshape); chat overrides.
        fn prepare_for_ingress(&mut self, _ingress_protocol: &str, _now_epoch: u64) {}

        /// Re-emit a buffered response as this dialect's native STREAM bytes when the client asked to
        /// stream but the upstream answered buffered (the Bedrock ConverseStream case). `None` when a
        /// plain buffered body is correct (every SSE-framed dialect). Default `None`.
        fn wrap_buffered_as_stream(&self, _elapsed_ms: Option<u64>) -> Option<Vec<u8>> {
            None
        }

        /// Stamp the resolved wire model onto this handle's request. Default no-op (an operation whose
        /// wire carries the model in the URL, not the body, has nothing to stamp).
        fn set_model(&mut self, _model: &str) {}

        /// Fail-closed guard for a cross-protocol request whose neutral content cannot be written onto
        /// the egress dialect without silent data loss — `Err(reason)` rejects up front (4xx). Default
        /// `Ok(())`.
        fn egress_representable(&self) -> Result<(), String> {
            Ok(())
        }

        /// The caller controls this handle will DROP on cross-protocol egress because the target
        /// dialect has no native representation (audit-and-allow). Default: none.
        fn egress_dropped_controls(&self) -> Vec<&'static str> {
            Vec::new()
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
