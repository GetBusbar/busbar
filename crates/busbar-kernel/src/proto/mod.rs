// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE KERNEL'S NEUTRAL PROTOCOL ATOMS: the status-class vocabulary, the codec host every plane is
//! handed (the CSPRNG and the wall clock), the header-map rebuild the outbound credential path uses,
//! and the neutral wire vocabulary re-exported at its historical `busbar_kernel::proto::…` paths.
//!
//! NO DIALECT LIVES HERE. This module once held an installed-protocol registry (`ProtocolDecl`
//! install and lookup, the detection and residual folds, the codec and verb aggregates) that the
//! kernel's ingress, auth and error shaping read dialect facts from. A dialect is a thing inside its
//! plane (THE DESIGN §1/§9), the declaration and codec facade moved into the plane that owns them
//! (Q128 contract p11 finding 1), and production never installed a declaration into that registry
//! (no linked row carries a `protocols` axis), so every read already took its empty answer. Each
//! site now states that answer directly, and the registry is gone.

// StatusClass and CanonicalSignal are defined in breaker.rs and re-exported here for compatibility.
// The `CanonicalSignal` re-export is gated to test builds to avoid an unused-import warning in the
// production binary; production code refers to `crate::breaker::CanonicalSignal` directly.
#[cfg(any(test, feature = "test-support"))]
pub use crate::breaker::CanonicalSignal;
pub use crate::breaker::StatusClass;

// RELOCATED DOWN to `busbar_kernel::config::limits`, beside the `limits.default_max_tokens` key
// that overrides it (and now literally the same const as that key's own default, so the two cannot
// drift). Re-exported here at its historical `busbar_kernel::proto::DEFAULT_MAX_TOKENS` path so this
// crate's call sites are unchanged.
pub use busbar_kernel::config::limits::DEFAULT_MAX_TOKENS;

/// Canonical protocol-id vocabulary — now TEST-ONLY FIXTURES. PRODUCTION core names no dialect:
/// the dialects live in their plane, and an omitted `protocol:` is the speaking plane's own default
/// (the kernel's `ProviderCfg` leaves it empty). What remains is core's OWN test binary's fixtures,
/// which name the shipped dialects by convention (golden-value checks) — so these consts are
/// confined to test / `test-support` scope, and the neutral PRODUCTION source spells none.
///
/// EACH VALUE IS A FROZEN WIRE STRING, and that is the only ground on which it is spelled here: it is
/// the value an operator writes in a provider's `protocol:` key, and all six have been accepted there
/// unchanged since 1.5.3 (`git show v1.5.3:crates/busbar/src/proto/mod.rs`, lines 1744-1749, holds
/// these six consts byte-for-byte). So each line carries the frozen-wire pragma naming that key.
#[cfg(any(test, feature = "test-support"))]
mod dialect_test_names {
    // plane-purity: frozen-wire a value of a provider's `protocol:` key in the frozen providers.yaml config grammar (frozen since 1.5.3)
    pub const PROTO_ANTHROPIC: &str = "anthropic";
    // plane-purity: frozen-wire a value of a provider's `protocol:` key in the frozen providers.yaml config grammar (frozen since 1.5.3)
    pub const PROTO_OPENAI: &str = "openai";
    // plane-purity: frozen-wire a value of a provider's `protocol:` key in the frozen providers.yaml config grammar (frozen since 1.5.3)
    pub const PROTO_GEMINI: &str = "gemini";
    // plane-purity: frozen-wire a value of a provider's `protocol:` key in the frozen providers.yaml config grammar (frozen since 1.5.3)
    pub const PROTO_BEDROCK: &str = "bedrock";
    // plane-purity: frozen-wire a value of a provider's `protocol:` key in the frozen providers.yaml config grammar (frozen since 1.5.3)
    pub const PROTO_COHERE: &str = "cohere";
    // plane-purity: frozen-wire a value of a provider's `protocol:` key in the frozen providers.yaml config grammar (frozen since 1.5.3)
    pub const PROTO_RESPONSES: &str = "responses";
}
#[cfg(any(test, feature = "test-support"))]
pub use dialect_test_names::{
    PROTO_ANTHROPIC, PROTO_BEDROCK, PROTO_COHERE, PROTO_GEMINI, PROTO_OPENAI, PROTO_RESPONSES,
};

// THE NEUTRAL WIRE VOCABULARY (the contract's), at its historical `busbar_kernel::proto::…` paths.
pub use busbar_contract::protocol::{
    find_frame_terminator, IrError, SigningContext, ERR_TYPE_API_ERROR, ERR_TYPE_AUTHENTICATION,
    ERR_TYPE_INSUFFICIENT_QUOTA, ERR_TYPE_INVALID_REQUEST, ERR_TYPE_NOT_FOUND, ERR_TYPE_OVERLOADED,
    ERR_TYPE_PERMISSION, ERR_TYPE_RATE_LIMIT, ERR_TYPE_REQUEST_TOO_LARGE, ERR_TYPE_SERVER_ERROR,
    SIGNAL_IR_PARSE, STREAM_ABORT_DETAIL,
};

/// THE HOST'S CODEC SERVICES: the OS CSPRNG and the wall clock, the one [`CodecHost`] the kernel
/// hands a plane's codec (and backs the plane ABI's `entropy_fill` / `wall_clock_now` with).
///
/// [`CodecHost`]: busbar_contract::codec::CodecHost
#[derive(Clone, Copy, Debug, Default)]
pub struct CodecHostServices;

/// The kernel's one codec host, as the trait object a codec call takes.
pub const CODEC_HOST: &dyn busbar_contract::codec::CodecHost = &CodecHostServices;

impl busbar_contract::codec::CodecHost for CodecHostServices {
    fn fill_entropy(&self, out: &mut [u8]) -> bool {
        getrandom::fill(out).is_ok()
    }
    fn wall_clock_now(&self) -> Option<u64> {
        Some(crate::store::now())
    }
}

/// Collect `(name, value)` header pairs into a [`http::HeaderMap`], a later pair under the same
/// name replacing an earlier one.
pub fn convert_headers(headers: Vec<(http::HeaderName, http::HeaderValue)>) -> http::HeaderMap {
    let mut map = http::HeaderMap::new();
    for (name, value) in headers {
        map.insert(name, value);
    }
    map
}
