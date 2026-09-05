// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE BODY-SHAPING HELPERS ON EITHER SIDE OF A TRANSLATE.
//!
//! These three lived in `busbar-llm`'s engine because the engine is what calls them on the money
//! path. They are pure over the protocol registry and the neutral billing carrier — they read no
//! socket, no clock and no configuration but the installed limits — and the suites that pin them are
//! codec suites (the translate-parity goldens, the IR usage projection). So they travel with the
//! codecs, and the engine reaches them here.

use serde_json::Value;

/// Remove the router-internal SHIM KEYS the route layer injects into the request body for PATH-MODEL
/// ingress protocols (`gemini`, `bedrock`), where the native wire carries the model in the URL and
/// stream intent in the path, not the body. Two keys, handled differently relative to `rewrite_model`
/// because their correct egress treatment differs:
///
///   - The gemini JSON-array key is NEVER a native egress body field for ANY backend (it only
///     influences RESPONSE framing), so it is stripped UNCONDITIONALLY on every branch and for every
///     egress.
///   - `stream` is a body field only for the BODY-MODEL protocols (openai/anthropic/cohere/responses),
///     where the egress writer authoritatively writes `"stream": <ir.stream>` and the backend reads it
///     to decide streaming. It is a PATH shim only for the PATH-MODEL egress protocols
///     (`gemini`/`bedrock`), whose native wire conveys stream intent via the URL/path, never the body.
///     So `stream` is stripped iff the EGRESS is gemini/bedrock — NOT based on the ingress. An
///     ingress-gated strip would delete the writer-authored `"stream": true` on a gemini/bedrock-
///     ingress → body-model-egress streaming hop, so the backend would see no stream flag, answer
///     non-streaming, and the client would get a wrong (buffered / mis-framed) response.
///   - `model` is stripped ONLY on the same-protocol branch (by the engine's
///     `strip_same_protocol_model_shim`, after `rewrite_model`), never cross-protocol: a body-model
///     egress REQUIRES `model` and `rewrite_model` installs the authoritative one.
///
/// The gemini array key is stripped for body-model ingress too (it is never native to any protocol).
///
/// Returns whether the body actually CHANGED (a key was present and removed). This is invalidation
/// set entries #1 (gemini JSON-array key) and #2 (`stream` for path-model egress) of the request
/// short-circuit safety contract: a `true` here makes a same-protocol request NON-pristine. A
/// same-proto request that carries NEITHER of these keys is left byte-for-byte untouched and can
/// short-circuit to its retained original bytes.
pub fn strip_router_shim_keys(v: &mut Value, egress_protocol: &str) -> bool {
    let mut changed = false;
    if let Some(obj) = v.as_object_mut() {
        // A protocol's array-stream shim key is never native to ANY backend wire → strip every
        // registered protocol's key unconditionally (also closes the leak where a body-model client
        // smuggles a key in its own controlled body). Iterating the cached registry set keeps this
        // strip from naming any shim-key literal (and from re-sweeping `protocol_for` per request).
        // `remove` returns the previous value iff the key was present → a real mutation (#1).
        for &key in busbar_substrate_values::proto::array_stream_shim_keys() {
            if obj.remove(key).is_some() {
                changed = true;
            }
        }
        // `stream` is a path-model shim for the EGRESS protocols gemini/bedrock (stream intent and
        // model both ride the URL there; `has_model_in_url()` covers both). For body-model egress
        // `stream` is the writer-authored field the backend needs to start streaming, so it must be
        // PRESERVED. Gate on egress, never ingress.
        if busbar_substrate_values::proto::decl_for(egress_protocol)
            .map(|d| d.has_model_in_url)
            .unwrap_or(false)
            && obj.remove("stream").is_some()
        {
            // #2: `stream` was present AND the egress is path-model → real mutation.
            changed = true;
        }
    }
    changed
}

/// The per-response translation cap, read from the installed limits at each use site.
///
/// The cap is COUPLED with the inbound request-body limit so any completion the gateway would accept
/// inbound can also be buffered for translation, while still bounding the per-response allocation.
/// ONE knob (`limits.request_body_max_bytes`) drives BOTH the inbound body limit and this egress cap,
/// so they can never diverge. A function (not a `const`) so the installed value is read at each use
/// site; the substrate falls back to the historical 32 MiB default when the limits aren't installed.
#[must_use]
pub fn max_translated_body_bytes() -> usize {
    busbar_substrate_values::proxy::max_translate_body_bytes()
}

/// Bytes-per-token divisor for the truncated-tail billing FLOOR. Deliberately conservative
/// (~4 bytes/token is typical for English prose; a JSON response envelope with field names and
/// escaping runs HIGHER), so the estimate UNDER-counts the true consumption: the retained tail is
/// already only the LAST `cap` bytes of a strictly larger body, making this a genuine floor that
/// cannot over-charge relative to the tokens actually generated. Its only job is to keep a
/// truncated-beyond-recovery response from billing ZERO.
pub const TRUNCATED_TAIL_BYTES_PER_TOKEN: u64 = 4;

/// Project the IR's normalized usage into the neutral name-keyed [`busbar_substrate_values::billing::Usage`]
/// carrier: the four reserved units (`input`/`output`/`cache_read`/`cache_write`) as canonical map
/// keys. Readers normalize `input_tokens` to UNCACHED and keep the cache fields ADDITIVE, so the
/// mapping is direct: cache-creation is the `cache_write` unit. Zero tiers are omitted so the map
/// stays sparse (no-zero-entry).
#[must_use]
pub fn tier_usage(
    u: &busbar_substrate_values::billing::TokenUsage,
) -> busbar_substrate_values::billing::Usage {
    let mut usage_units = std::collections::BTreeMap::new();
    for (k, v) in [
        (busbar_api::UNIT_INPUT, u.input),
        (busbar_api::UNIT_OUTPUT, u.output),
        (busbar_api::UNIT_CACHE_READ, u.cache_read.unwrap_or(0)),
        (busbar_api::UNIT_CACHE_WRITE, u.cache_creation.unwrap_or(0)),
    ] {
        if v != 0 {
            usage_units.insert(k.to_string(), v);
        }
    }
    busbar_substrate_values::billing::Usage { usage_units }
}
