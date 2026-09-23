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
/// `ClientCertSubject` is deliberately absent. The form reads a distinguished name off the
/// presented certificate, and this transport does not parse one: what it records is the
/// certificate's fingerprint, a real fact the handshake already established. Advertising the
/// form on a constant subject would mean every client certificate compares equal, so a
/// cert-subject distinction would collapse silently rather than fail — the form goes back on
/// this row the day the DN is parsed, and not before.
pub(crate) const SELECTOR_FORMS: &[SelectorForm] = &[SelectorForm::Sni, SelectorForm::Alpn];

/// The forms an EGRESS claim over this wire may take: none.
pub(crate) const EGRESS_SELECTOR_FORMS: &[SelectorForm] = &[];
