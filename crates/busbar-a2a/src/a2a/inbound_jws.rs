// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE COMPOSITION-ROOT-OWNED INBOUND AGENT-CARD JWS SEAM (HOST-CAPS S3, DECISIONS #26).
//!
//! Verifying an inbound agent card against the operator's out-of-band issuer key, and pinning ONLY
//! what verified, lives today in [`pin::pin_a_signed_card`](super::pin::pin_a_signed_card) over
//! [`jws::verify_card`](super::jws::verify_card). That is a plane function called directly by
//! [`verify::verify_document`](super::verify::verify_document); nothing NAMES it as a host capability
//! a boot flip could swap behind a stable boundary.
//!
//! This seam is that name. [`InboundCardJws`] wraps the verify-then-pin decision as ONE capability the
//! plane's composition installs once at boot ([`install_inbound_card_jws`]); a caller reads it back
//! through [`inbound_card_jws`] and calls the typed method instead of the free function, so the JWS
//! verification is swappable without the call site changing. It mirrors the egress fetch seam's
//! `install_hostless_egress` / `hostless` and this wave's SSE / egress-trust host-caps seams.
//!
//! ## Crate-internal, and why
//!
//! The verify outcome is `(CardPin, jws::Verified)` and its refusal is `jws::JwsError` — both this
//! plane's own crypto vocabulary, deliberately NOT part of the crate's public surface. So the seam is
//! `pub(crate)` and its composition root is this plane's own boot wiring, exactly as
//! `busbar-plane-streaming`'s `register.rs` stages its plane-side composition IN-crate with the
//! cross-crate kernel flip written down for the switchover pass rather than half-done now.
//!
//! ## Additive and DORMANT
//!
//! [`PassThroughInboundJws`] delegates to the exact `pin_a_signed_card` the shipped path calls today —
//! same pin, same `Verified`, same `JwsError`, byte for byte. And NOTHING on the shipped path consults
//! the seam yet: `verify_document` still calls `pin_a_signed_card` directly, so inbound verification is
//! unchanged until the call site opts in. Reading [`inbound_card_jws`] in a build that installed
//! no capability returns `None`.

// The seam's install/get are reached by tests until the `verify_document` call site flips onto it
// — the same not-yet-mounted posture the plane's other staged pieces record.
#![cfg_attr(not(test), allow(dead_code))]

use serde_json::Value;

use super::jws;
use super::pin::CardPin;

/// THE INBOUND AGENT-CARD JWS HOST CAPABILITY, as a neutral trait a caller reaches through instead of
/// calling [`pin::pin_a_signed_card`](super::pin::pin_a_signed_card) directly. `Send + Sync` so the
/// installed capability is a process-wide `&'static dyn`.
pub(crate) trait InboundCardJws: Send + Sync {
    /// Verify `card` against the operator's out-of-band `issuer_key_spki` and, on success, produce the
    /// pin bound to the fingerprint of the card that verified. Verify FIRST, pin only what passed —
    /// the ordering is [`pin_a_signed_card`](super::pin::pin_a_signed_card)'s and is not re-implemented
    /// here. Pass-through to that function.
    fn verify_signed_card(
        &self,
        card: &Value,
        issuer_key_spki: &str,
    ) -> Result<(CardPin, jws::Verified), jws::JwsError>;
}

/// The production inbound-JWS capability: a BYTE-FOR-BYTE pass-through to
/// [`pin::pin_a_signed_card`](super::pin::pin_a_signed_card). The plane's composition installs this, so
/// a call site that opts onto the seam gets exactly the pin/`Verified`/`JwsError` the free
/// function produces now.
pub(crate) struct PassThroughInboundJws;

impl InboundCardJws for PassThroughInboundJws {
    fn verify_signed_card(
        &self,
        card: &Value,
        issuer_key_spki: &str,
    ) -> Result<(CardPin, jws::Verified), jws::JwsError> {
        super::pin::pin_a_signed_card(card, issuer_key_spki)
    }
}

/// THE PROCESS-WIDE inbound-JWS capability, installed once by the plane's composition
/// ([`install_inbound_card_jws`]). A caller reads it back through [`inbound_card_jws`] and gets `None`
/// in a build that installed none — the dormant default, under which `verify_document` calls
/// `pin_a_signed_card` directly and inbound verification is unchanged.
static INBOUND_JWS: std::sync::OnceLock<&'static dyn InboundCardJws> = std::sync::OnceLock::new();

/// Install the process inbound-JWS capability — the plane composition's one write, at boot, before any
/// card is verified. Idempotent by `OnceLock`: a second install is a no-op (the first wins).
pub(crate) fn install_inbound_card_jws(host: &'static dyn InboundCardJws) {
    let _ = INBOUND_JWS.set(host);
}

/// The installed inbound-JWS capability, or `None` when none was installed (the dormant default).
pub(crate) fn inbound_card_jws() -> Option<&'static dyn InboundCardJws> {
    INBOUND_JWS.get().copied()
}

// Test body externalised to `tests/inbound_jws_tests.rs` (the sibling `jws`/`pin` convention) so this
// implementation file's length measures one thing — structure-lint:inline-tests.
#[cfg(all(test, feature = "test-support"))]
#[path = "tests/inbound_jws_tests.rs"]
mod inbound_jws_tests;
