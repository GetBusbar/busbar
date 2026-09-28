// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE COMPOSITION-ROOT-OWNED INBOUND AGENT-CARD JWS SEAM (HOST-CAPS S3, DECISIONS #26).
//!
//! Verifying an inbound agent card against the operator's out-of-band issuer key, and pinning ONLY
//! what verified, is [`pin::pin_a_signed_card`](super::pin::pin_a_signed_card) over
//! [`jws::verify_card`](super::jws::verify_card) — and the ONE path to it is this seam.
//! [`verify::verify_document`](super::verify::verify_document) reaches the signature through
//! [`inbound_card_jws`] and nothing else calls `pin_a_signed_card` (TODO 607), so the JWS verification
//! is swappable behind a stable boundary without the call site changing. It mirrors the egress fetch
//! seam's `install_hostless_egress` / `hostless` and the SSE / egress-trust host-caps seams.
//!
//! ## Crate-internal, and why
//!
//! The verify outcome is `(CardPin, jws::Verified)` and its refusal is `jws::JwsError` — both this
//! plane's own crypto vocabulary, deliberately NOT part of the crate's public surface. So the seam is
//! `pub(crate)` and its composition root is this crate's own registry build (`from_config_carrying`),
//! which installs [`PassThroughInboundJws`] ([`install_inbound_card_jws`]).
//!
//! ## One path, byte for byte
//!
//! [`PassThroughInboundJws`] delegates to the exact `pin_a_signed_card` — same pin, same `Verified`,
//! same `JwsError`, byte for byte. [`inbound_card_jws`] never answers "none": a read before the
//! composition's install yields the same pass-through, so there is no fallback path that verifies
//! any other way.

use serde_json::Value;

use super::jws;
use super::pin::CardPin;

/// THE INBOUND AGENT-CARD JWS HOST CAPABILITY, as a neutral trait a caller reaches through instead of
/// calling [`pin::pin_a_signed_card`](super::pin::pin_a_signed_card) directly. `Send + Sync` so the
/// installed capability is a process-wide `&'static dyn`.
pub(crate) trait InboundCardJws: Send + Sync {
    /// Verify `card` against the operator's out-of-band `issuer_key_info` and, on success, produce the
    /// pin bound to the fingerprint of the card that verified. Verify FIRST, pin only what passed —
    /// the ordering is [`pin_a_signed_card`](super::pin::pin_a_signed_card)'s and is not re-implemented
    /// here. Pass-through to that function.
    fn verify_signed_card(
        &self,
        card: &Value,
        issuer_key_info: &str,
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
        issuer_key_info: &str,
    ) -> Result<(CardPin, jws::Verified), jws::JwsError> {
        super::pin::pin_a_signed_card(card, issuer_key_info)
    }
}

/// THE PROCESS-WIDE inbound-JWS capability, installed once by the plane's composition
/// ([`install_inbound_card_jws`]) and read by [`verify::verify_document`](super::verify::verify_document)
/// through [`inbound_card_jws`].
static INBOUND_JWS: std::sync::OnceLock<&'static dyn InboundCardJws> = std::sync::OnceLock::new();

/// The production capability the composition installs and a pre-install read resolves to.
static PASS_THROUGH: PassThroughInboundJws = PassThroughInboundJws;

/// Install the process inbound-JWS capability — the plane composition's one write, at build, before any
/// card is verified. Idempotent by `OnceLock`: a second install is a no-op (the first wins).
pub(crate) fn install_inbound_card_jws(host: &'static dyn InboundCardJws) {
    let _ = INBOUND_JWS.set(host);
}

/// Install the production pass-through — what the composition root calls on every build.
pub(crate) fn install_pass_through() {
    install_inbound_card_jws(&PASS_THROUGH);
}

/// The installed inbound-JWS capability. A read before any install pins the production pass-through,
/// so every verification goes through the ONE capability the process holds.
pub(crate) fn inbound_card_jws() -> &'static dyn InboundCardJws {
    *INBOUND_JWS.get_or_init(|| &PASS_THROUGH)
}

// Test body externalised to `tests/inbound_jws_tests.rs` (the sibling `jws`/`pin` convention) so this
// implementation file's length measures one thing — structure-lint:inline-tests.
#[cfg(all(test, feature = "test-support"))]
#[path = "tests/inbound_jws_tests.rs"]
mod inbound_jws_tests;
