// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The claim shapes this transport declares, as the kind's own file (`PLUGIN-TREE.md` §3).
//!
//! A transport's claim is a SELECTOR FORM: the shape of question a plane may ask of arriving bytes
//! on this wire. It is a declaration and nothing else — data read once at registration — which is
//! why it lives beside `meta.rs` rather than inside the connection code that never reads it.

use busbar_contract::grammar::SelectorForm;

/// The forms an INGRESS claim over this wire may take: none.
///
/// stdio carries no header, path or handshake surface to select on: a claim on this transport can
/// only ever be the whole channel. Empty rather than guessed — see the crate report.
pub(crate) const SELECTOR_FORMS: &[SelectorForm] = &[];

/// The forms an EGRESS claim over this wire may take: none, for the same reason.
pub(crate) const EGRESS_SELECTOR_FORMS: &[SelectorForm] = &[];
