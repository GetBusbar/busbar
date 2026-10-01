// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE INBOUND AGENT-CARD JWS SEAM (DECISIONS #26).
//!
//! Verifying an inbound agent card against the operator's out-of-band issuer key, and pinning ONLY
//! what verified, is [`pin::pin_a_signed_card`](super::pin::pin_a_signed_card) over the kernel's
//! [`busbar_kernel::trust::signed`] verifier — and the ONE path to it is this seam.
//! [`verify::verify_document`](super::verify::verify_document) reaches the signature through
//! [`inbound_card_jws`] and nothing else calls `pin_a_signed_card` (TODO 607), so the JWS verification
//! is swappable behind a stable boundary without the call site changing.
//!
//! ## Crate-internal, and why
//!
//! The verify outcome is a `CardPin` and its refusal is `pin::JwsError` — both this
//! plane's own crypto vocabulary, deliberately NOT part of the crate's public surface. So the seam is
//! `pub(crate)`, and its one implementation is [`PassThroughInboundJws`], which
//! [`inbound_card_jws`] answers.
//!
//! ## One path, byte for byte
//!
//! [`PassThroughInboundJws`] delegates to the exact `pin_a_signed_card` — same pin, same
//! `JwsError`, byte for byte. [`inbound_card_jws`] never answers "none" and holds no state, so
//! there is no fallback path that verifies any other way.

use serde_json::Value;

use super::pin::{CardPin, JwsError};

/// THE INBOUND AGENT-CARD JWS HOST CAPABILITY, as a neutral trait a caller reaches through instead of
/// calling [`pin::pin_a_signed_card`](super::pin::pin_a_signed_card) directly. `Send + Sync` so the
/// capability is a shareable `&'static dyn`.
pub(crate) trait InboundCardJws: Send + Sync {
    /// Verify `card` against the operator's out-of-band `issuer_key_info` and, on success, produce the
    /// pin bound to the fingerprint of the card that verified. Verify FIRST, pin only what passed —
    /// the ordering is [`pin_a_signed_card`](super::pin::pin_a_signed_card)'s and is not re-implemented
    /// here. Pass-through to that function.
    fn verify_signed_card(&self, card: &Value, issuer_key_info: &str) -> Result<CardPin, JwsError>;
}

/// The production inbound-JWS capability: a BYTE-FOR-BYTE pass-through to
/// [`pin::pin_a_signed_card`](super::pin::pin_a_signed_card), so a call site on the seam gets exactly
/// the pin/`JwsError` the free function produces.
pub(crate) struct PassThroughInboundJws;

impl InboundCardJws for PassThroughInboundJws {
    fn verify_signed_card(&self, card: &Value, issuer_key_info: &str) -> Result<CardPin, JwsError> {
        super::pin::pin_a_signed_card(card, issuer_key_info)
    }
}

/// The inbound-JWS capability every verification goes through: the production pass-through. There
/// is one implementation and nothing to install, so the capability is a constant and holds no
/// process-wide state.
pub(crate) fn inbound_card_jws() -> &'static dyn InboundCardJws {
    &PassThroughInboundJws
}

// Test body externalised to `tests/inbound_jws_tests.rs` (the sibling `jws`/`pin` convention) so this
// implementation file's length measures one thing — structure-lint:inline-tests.
#[cfg(all(test, feature = "test-support"))]
#[path = "tests/inbound_jws_tests.rs"]
mod inbound_jws_tests;
