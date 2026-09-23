// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The claim shapes this transport declares, as the kind's own file (`PLUGIN-TREE.md` §3).
//!
//! A transport's claim is a SELECTOR FORM: the shape of question a plane may ask of arriving bytes
//! on this wire. It is a declaration and nothing else — data read once at registration — which is
//! why it lives beside `meta.rs` rather than inside the connection code that never reads it.

use busbar_contract::SelectorForm;

/// The forms an INGRESS claim over this wire may take.
///
/// One: the port. `tcp` carries no path, no header and no handshake name, so the local port is the
/// only thing a claim on this wire can be about.
pub(crate) const SELECTOR_FORMS: &[SelectorForm] = &[SelectorForm::Port];

/// The forms an EGRESS claim over this wire may take: none.
pub(crate) const EGRESS_SELECTOR_FORMS: &[SelectorForm] = &[];
