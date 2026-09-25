// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The claim shapes this transport declares, as the kind's own file (`PLUGIN-TREE.md` §3).
//!
//! A transport's claim is a SELECTOR FORM: the shape of question a plane may ask of arriving bytes
//! on this wire. It is a declaration and nothing else — data read once at registration — which is
//! why it lives beside `meta.rs` rather than inside the framing code that never reads it.

use busbar_contract::SelectorForm;

/// The forms an INGRESS claim over this wire may take: none.
///
/// `sse` is composed OVER `http` and adds no selection surface of its own — the request that opens
/// the stream is `http`'s, and the layer that owns the claim is the one that reads that request.
pub(crate) const SELECTOR_FORMS: &[SelectorForm] = &[];

/// The forms an EGRESS claim over this wire may take: none, for the same reason.
pub(crate) const EGRESS_SELECTOR_FORMS: &[SelectorForm] = &[];
