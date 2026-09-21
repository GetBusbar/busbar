// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The protocol seam: a protocol-agnostic core, with each wire dialect's specifics confined to a
//! `Reader` (wire → signal/IR) and a `Writer` (IR/intent → wire). `Protocol` bundles a Reader and
//! Writer; a string-keyed registry maps a provider's protocol name to its `Protocol`.

// StatusClass and CanonicalSignal are defined in breaker.rs and re-exported here for compatibility.
// The `CanonicalSignal` re-export is consumed only by the per-protocol `classify` test helpers (which
// are themselves `#[cfg(test)]`), so it is gated to test builds to avoid an unused-import warning in
// the 1.0 binary; production code refers to the canonical `crate::breaker::CanonicalSignal` directly.
#[cfg(any(test, feature = "test-support"))]
pub use crate::breaker::CanonicalSignal;
pub use crate::breaker::StatusClass;

// Import types needed for response/stream IR
// Consumed via `use super::*` by the proto test modules only, since the dialect that used them in
// production moved out to its own plugin crate.

// Neutral protocol atoms RELOCATED DOWN to `busbar-substrate` (`busbar_kernel::proto`) so an
// extracted dialect crate names them without reaching into `busbar-core` (the reverse-edge rule).
// Re-exported here at their historical `busbar_kernel::proto::…` paths so every
// in-core / plugin / witness-build caller compiles unchanged; the values are byte-identical.
//
// - `SIGNAL_IR_PARSE`     — busbar-internal IR-parse `provider_signal` label.
// - `SSE_DONE_SENTINEL` / `SSE_DONE_FRAME` — the bare-token / framed-byte forms of the SSE stream
//   terminator a dialect's writer emits.
// - `HDR_AUTHORIZATION`   — the canonical lowercase `Authorization` header name.
// - `IrError`             — the IR-level error alias (`breaker::CanonicalSignal`).
// - `bearer_auth_headers` — the shared `Authorization: Bearer <key>` builder (warn+OMIT on bad bytes).

// Signal the RESPONSE-side dialect-specific metadata that an egress protocol carries and no ingress
// protocol can express, so it does not vanish from a translated response with nothing in the logs.
//
// The request side has had this since `IrReq::prepare_for_egress` started naming every cleared
// `extra` key; the response side had no equivalent, so a cross-protocol hop could silently drop a
// backend's response-only metadata (for example a compliance/guardrail assessment) with nothing
// recording that it had happened.
//
// These are true target-protocol limits, not unmodelled IR gaps: each such field is shaped by its own
// protocol's account model or category vocabulary — no other protocol in the matrix has a field of
// that shape to receive it. So the fix is the signal, not a carrier. (Metadata that IS expressible
// everywhere — citations, for instance — is read into the IR instead of named here.)
//
// Called ONLY from the cross-protocol response seam, so a same-protocol route — where every one of
// these fields survives byte-for-byte — never logs a word about them.
// RELOCATED DOWN to `busbar_kernel::proto` (the cross-protocol response seam lives in the extracted
// dialect plugin, which now names the substrate fn directly); re-exported here at its historical
// `busbar_kernel::proto::warn_untranslatable_response_metadata` path so core's call sites are unchanged.

// RELOCATED DOWN to `busbar_kernel::config::limits`, beside the `limits.default_max_tokens` key
// that overrides it (and now literally the same const as that key's own default, so the two cannot
// drift). Re-exported here at its historical `busbar_kernel::proto::DEFAULT_MAX_TOKENS` path so this
// crate's call sites are unchanged.
pub use busbar_kernel::config::limits::DEFAULT_MAX_TOKENS;

// Mixed-case base62 alphabet (digits + lowercase + uppercase, no `-`/`_`) and the rejection-sampling
// threshold used when synthesizing opaque ids for protocols whose native ids are flat random tokens.
// Hoisted here as the single source of truth so the id generators cannot drift on the character set
// or the bias-elimination cutoff
// — `REJECT_THRESHOLD` is the largest multiple of 62 that fits in a `u8` (62 × 4 = 248); a draw in
// `0..248` maps uniformly via `% 62`, a draw `>= 248` is rejected and redrawn.
// Relocated DOWN to `busbar_kernel::proto`; re-exported here (see the neutral-atoms block above).

// `STREAM_ABORT_DETAIL` RELOCATED DOWN to `busbar_kernel::proto` (a dialect's own stream
// reassembler emits it without reaching into core); re-exported here at its historical
// `busbar_kernel::proto::STREAM_ABORT_DETAIL` path so core's proxy-engine caller is unchanged.

/// THE RESIDUAL ARM of the ingress resolver: which wire dialect a path names, from its shape alone.
/// `None` when it names none.
///
/// ## This is not the whole answer, and it must not be called as if it were
///
/// The whole answer is [`crate::plane::PlaneDispatch::ingress_of`], and this function is the arm it
/// reaches only AFTER the mount table has declined the path. That ordering is the fix for a shipped
/// defect: while this was the canonical classifier, it was consulted for paths a plane had been
/// MOUNTED on, knew nothing of mounts, and answered a dialect for every one of them — so an oversized
/// request to one plane's mount path came back in a DIFFERENT plane's wire envelope, one its own
/// client could not decode. A path shape can only ever answer for the residual, because a mount is a
/// fact about the deployment and no amount of looking at a URL will reveal it. `ingress_of` is
/// therefore the only caller.
///
/// ## There is no `else { <default dialect> }` any more, and that is the point
///
/// The old tail arm claimed every unclassifiable path for one dialect, which read as a harmless
/// default and was in fact the resolver asserting a protocol identity for paths that carry none. What
/// to say to a caller whose dialect is unknown is a decision — a real one, taken in
/// `ingress::native_error`, where the alternatives are visible — not something a classifier should
/// smuggle in as a fallthrough.
///
/// ## The ladder is DATA now, and core names no dialect
///
/// This once held a hand-ordered `if`-ladder naming every dialect; it is now a fold over the
/// registered protocols' own [`ProtocolDecl::residual_claims`] predicates
/// ([`registry::residual_protocol_for_path`]), so each dialect owns its arm (its own path-shape
/// quirks and disambiguation rules) and core spells none of them. Byte-identical to the old ladder —
/// the claim strengths ARE the ladder positions.
pub fn residual_dialect_for_path(path: &str) -> Option<&'static str> {
    registry::residual_protocol_for_path(path)
}

/// THE ROUTER: `(path, headers)` → which wire dialect a request speaks, or `None` for a path that
/// names none. A public re-export of the generic detection fold ([`registry::detect_protocol`]) so
/// the protocol plugin can exercise the byte-identical detection contract from its own tests.
pub fn detect_protocol(path: &str, headers: &axum::http::HeaderMap) -> Option<&'static str> {
    registry::detect_protocol(path, headers)
}

/// THE REGISTRY-SUPPLIED RESIDUAL DEFAULT dialect — the name core falls back to when no dialect
/// claims a request yet one must be named. `None` when no residual-default protocol is installed.
/// Reads [`ProtocolDecl::residual_default`], so the literal default dialect name leaves core.
pub fn residual_default_dialect() -> Option<&'static str> {
    registry::residual_default_protocol()
}

// The vendor-plausible auth-failure wire MESSAGE for an ingress protocol. This string lands verbatim
// in the native error body (`error.message` for anthropic/openai/gemini/responses, the bare
// top-level `message` for cohere, the `message` beside `__type` for bedrock). It MUST read like the
// copy the REAL vendor returns for a bad/missing credential and carry NO busbar-internal vocabulary
// ("lane", "virtual key", "passthrough", …): any such word is a deterministic protocol tell that
// also discloses busbar's auth model. Canonical source of truth; `auth.rs::vendor_auth_failure_message`
// is a thin delegation wrapper to this, not a copy. Strings sampled from real 401/403 bodies:
//   anthropic → "invalid x-api-key"; openai/responses → "Incorrect API key provided.";
//   gemini → "API key not valid. Please pass a valid API key."; cohere → "invalid api token";
//   bedrock → "" (AWS conveys AccessDenied via __type / x-amzn-errortype, not message prose).
//
// Thin wrapper: dispatches through `ProtocolWriter::auth_failure_message` so the per-vendor copy
// lives in the writer vtable, not in this agnostic function. An unknown future proto falls back to
// the default generic copy.
// RELOCATED DOWN to `busbar_kernel::proto`; re-exported here at its historical path.

// Per-request signing context. RELOCATED DOWN to the neutral `busbar_kernel::proto` leaf so the
// substrate `ProtocolDecl`'s `egress_auth_headers` builder names it without depending on
// `busbar-core`; re-exported here at its historical `busbar_kernel::proto::SigningContext` path so
// every in-core / plugin caller (`egress_auth`, `proxy::egress`, `health`, the walk/engine forward
// paths, the netted dialect writers) is unchanged. Its only non-primitive field is
// `busbar_api::UpstreamCreds`, so the move carries no core-only machinery.

// ProtocolWriter rewrites intents for the upstream wire format.
// Extract `(role, text)` pairs from a hook's rewrite reply for a dialect that must RE-FRAME the
// turns rather than insert them verbatim. `None` means at least one reply message does not carry
// plain-string content — the re-framing dialects cannot render that faithfully, so their
// [`ProtocolWriter::apply_rewrite_to_ingress_body`] aborts and leaves the body untouched rather
// than shipping a half-applied rewrite.
// Relocated DOWN to `busbar_kernel::proto`; re-exported here (see the neutral-atoms block above).

// `ArrayStreamFramer` (the streaming JSON-array reframer the SSE seam drives) and `DialectCodec` (the
// 4th neutral per-PROTOCOL computed-codec seam the operation-blind driver reads) RELOCATED to
// `busbar-substrate` (`busbar_kernel::proto`) so an extracted dialect crate implements them
// without reaching into `busbar-core`; re-exported here at their historical `busbar_kernel::proto::…`
// paths so core's call sites and the netted dual-compile test build are unchanged. Both name only the
// neutral surface (bytes / `Value` / `bool` / `TokenUsage` / `RawUpstreamError` / `CanonicalSignal`),
// so the relocation carries no core-only machinery. `DialectCodec::make_array_stream_framer` returns a
// `Box<dyn ArrayStreamFramer>`, so the two travel together. Reached via `decl_for(name).dialect()`.

// The set of streaming `Content-Type` values across every declared protocol. A registry aggregate,
// folded once at boot from `ProtocolDecl::streaming_content_type` — where it used to be an
// `OnceLock` sweep that built a `Protocol` per known name to read one `&'static` off its writer.
// RELOCATED DOWN to `busbar_kernel::proto`; re-exported here at its historical path.

// The set of array-stream shim keys across every declared protocol (most declare none).
// The same aggregate, from `ProtocolDecl::array_stream_shim_key`, and the reason
// `proxy::strip_router_shim_keys` can remove every protocol's marker while naming none of them.
// RELOCATED DOWN to `busbar_kernel::proto`; re-exported here at its historical path.

// The array-stream shim key the NAMED protocol declares, or `None` if it declares none (most
// don't) or is not registered. The INJECTION site (`ingress::ingress_path_model`) reads it by name
// so it names no protocol submodule: delete a protocol and the marker is simply never injected.
// RELOCATED DOWN to `busbar_kernel::proto`; re-exported here at its historical path.

/// The NEUTRAL streaming-translator seam (`StreamTranslator` trait + the fn-ptr factory) — STAYS in
/// core (names zero concrete stream IR). See `stream_translator.rs`.
pub(crate) mod stream_translator;
pub use stream_translator::install_stream_translator_factory;
pub use stream_translator::new_stream_translator;
/// Core's OWN test binary routes the streaming-translator seam straight to the extracted dialect
/// plugin's concrete factory through this `tests/` fixture (the neutral-purity lint excludes it), so the streaming
/// suites that drive `new_stream_translator` standalone keep working after the `#[path]` witness of the
/// concrete translator was deleted — with no plugin symbol in neutral source and no `install_*` call.
#[cfg(test)]
#[path = "tests/stream_factory_fixture.rs"]
mod stream_factory_fixture;
// The neutral `StreamTranslator` trait RELOCATED DOWN to `busbar_kernel::proto`; re-exported here
// at its historical `busbar_kernel::proto::StreamTranslator` path so core's forward path is unchanged.

// THE EXTRACTED CONCRETE STREAM TRANSLATOR (`StreamTranslate`) and WIRE-CODEC SURFACE
// (`ProtocolReader`/`ProtocolWriter`/`Protocol`/`protocol_for`/…) live wholly in the extracted dialect
// plugin crate (`proto_stream.rs`/`proto_codec.rs`) — they name the concrete IR types. Their `#[path]`
// witness re-includes (and the `pub use stream::*` / `pub use proto_codec::*` glob re-exports that
// let the pre-extraction fixture surface reach them at `crate::proto::…`) were DELETED once Phase 1.6
// drained core's own suite of any dependence on the witnessed codec: the concrete-codec tests moved
// beside the types they exercise, in the plugin crate's own test tree, where they name
// `crate::proto_codec::…` in the plugin. Production core drives translation through the neutral
// `DialectCodec` seam + the installed `StreamTranslator` factory and names none of these.

// `find_frame_terminator` and `parse_sse_frame` RELOCATED DOWN to `busbar_kernel::proto` (a
// dialect's stream translator and reassembler drive them); re-exported here at their
// historical `busbar_kernel::proto::…` paths so every in-core caller is unchanged.

// The `event:` name of one SSE frame, BORROWED from the frame bytes — the cheap probe for a
// consumer that only needs the event TYPE to decide whether a frame is worth parsing at all.
// [`parse_sse_frame`] pays three heap allocations per call (the event-type `String`, the
// `data:`-line `Vec`, the joined-payload `String`), which is exactly what a skip decision must
// not. Returns `""` when the frame carries no `event:` line (some dialects omit it) or the name is not
// UTF-8 — the same value `parse_sse_frame` reports for those shapes — and, like it, the LAST
// `event:` line wins when a frame illegally carries several.
// Relocated DOWN to `busbar_kernel::proto`; re-exported here (see the neutral-atoms block above).

// `strip_top_level_usage_member` (and its two private JSON span scanners) RELOCATED DOWN to
// `busbar_kernel::proto`; re-exported here at its historical path.

// `write_sse_frame` RELOCATED DOWN to `busbar_kernel::proto` (a dialect's own stream translator
// emits through it); re-exported here at its historical `busbar_kernel::proto::write_sse_frame` path.

// THE EXTRACTED WIRE DIALECTS live wholly in their own plugin crates. Their `#[path]` witness
// re-includes into core (which existed only so the pre-extraction fixture surface could reach the
// real codecs from inside core's own test binary, back when a `ProtocolDecl` was a `busbar-core` type
// an external crate could not hand to the registry) were DELETED: `ProtocolDecl` now lives in
// `busbar-substrate`, so core's test binary reads the plugin crates' declaration tables directly
// (dev-dependency) and the dialect suites moved into those plugin crates. Production core drives
// every dialect through the registry's `ProtocolDecl` vtable and names none of them.
/// Wire-dialect detection: `protocol_id(path, headers)` sniffs which protocol a request speaks.
pub(crate) mod detect;
/// THE REGISTRY: `ProtocolDecl`, the built-in declaration table, and the by-name lookup that
/// replaced `protocol_for`'s match.
pub mod registry;

// THE EXTRACTED PER-DIALECT CODEC HELPERS — the per-dialect encode/decode and id-synthesis helpers,
// plus the per-operation handle cell — live wholly in the extracted dialect plugin crate. Their
// `#[path]` witness re-includes into core, and the bare-name `use <dialect>::{Reader,Writer}`
// scaffolding imports the netted fixtures needed, were DELETED with the dialects: Phase 1.6 drained
// core's own suite of any dependence on the witnessed codec, so the suites that named these moved into
// the plugin crate, where they resolve the helpers at their plugin paths. Production core drives every
// codec through the registry's `ProtocolDecl` vtable.

// The declaration vocabulary, re-exported at `crate::proto::…` so every protocol module (each of
// which does `use super::*`) can state its `DECL` without importing the registry by path.
pub use registry::{
    decl_for, ClaimStrength, ClaimsFn, IngressAuth, ProtocolDecl, ResidualClaimsFn,
    VendorResponseMetadataFn,
};

/// Canonical protocol-id vocabulary — now TEST-ONLY FIXTURES. PRODUCTION core no longer names a
/// dialect: every request-path site reads the name off the protocol registry instead — the URL-model
/// arrivals live with their own dialect plugins, the `/v1/messages` convenience surface resolves its
/// dialect through [`residual_dialect_for_path`], the error-shaping fallback through
/// [`residual_default_dialect`], and the frozen config lane-default is a frozen-wire literal in
/// `config`. What remains is core's OWN test binary's fixtures, which name the shipped dialects by
/// convention (golden-value checks) — so these consts are confined to test / `test-support` scope,
/// where a neutral crate naming a dialect is expected, and the neutral PRODUCTION source spells none.
#[cfg(any(test, feature = "test-support"))]
mod dialect_test_names {
    pub const PROTO_ANTHROPIC: &str = "anthropic";
    pub const PROTO_OPENAI: &str = "openai";
    pub const PROTO_GEMINI: &str = "gemini";
    pub const PROTO_BEDROCK: &str = "bedrock";
    pub const PROTO_COHERE: &str = "cohere";
    pub const PROTO_RESPONSES: &str = "responses";
}
#[cfg(any(test, feature = "test-support"))]
pub use dialect_test_names::{
    PROTO_ANTHROPIC, PROTO_BEDROCK, PROTO_COHERE, PROTO_GEMINI, PROTO_OPENAI, PROTO_RESPONSES,
};

// A shared head-key set some dialects declare in common RELOCATED to the plugin crate that groups
// those dialects — it is dialect-specific vocabulary, so it belongs with the dialects that declare it,
// not in this neutral crate. Core unions whatever `ProtocolDecl::head_keys` each registered protocol
// declares (see `registry::Registry::new`) and names none of the keys itself.

// Every protocol name busbar ships a wire CODEC for — the set a provider's `protocol:` may name,
// and what the config validator rejects against so an unknown protocol is COLLECTED with every
// other config error rather than escaping to a lone `die()` at lane construction.
//
// DERIVED from the declarations (`ProtocolDecl::codec`), not maintained beside them. It used to be
// a hand-written const that a `debug_assert` compared against the constructor match it had to agree
// with — two lists and an assertion to keep them equal, where there is now one list and nothing to
// drift from.
//
// DECLARATION ORDER IS PRESERVED, AND IT IS LOAD-BEARING: `telemetry` indexes its per-protocol
// metric families by POSITION in this slice — `AppSlots::build` banks one family per entry in
// order, and `request_family` finds it again with `.position()`. That stays sound for the reason it
// always did, now stated rather than assumed: the slice is folded ONCE, from a `&'static`
// declaration table, inside a `OnceLock`, and no path appends to it afterwards — so the list a
// family was banked against and the list an index is computed from are the same list. A name that
// is not in it MISSES and falls through to `metrics.rs`'s cached-handle path, which renders a
// byte-identical series, so even a miss is not an operator-visible change.
//
// THE EMPTY ANSWER IS A REAL ANSWER and `config_validate` has an arm for it: this was a
// compile-time const that could not be empty, and a derived list can be, so the site that refuses
// operator config on it names that cause once rather than refusing every provider with an empty
// "must be one of:" tail. `registry_tests::the_derived_protocol_list_is_not_empty` pins the other
// half.
// RELOCATED DOWN to `busbar_kernel::proto::known_protocols` with the registry runtime (a plane's
// own `PLANE_DECL.wire_format_names` now names the substrate fn directly, so the plane crate reaches
// the registry aggregate through the neutral ABI, not back into `busbar-core`). Re-exported here at its
// historical `busbar_kernel::proto::known_protocols` path — as the SAME fn pointer, which is what the
// plane-decl identity pin in the plane's own test suite asserts — so every in-core caller is
// unchanged. Still a pure read of the registry aggregate; no protocol vocabulary crosses here, only the
// neutral derived list.

// EACH PLANE'S VOCABULARY DECLARATION lives wholly in that plane's own plugin crate — it is the
// plane's statement about ITSELF, so it leaves core with the plane. The composition root installs it
// via `register_planes` (`crates/busbar/src/main.rs`); core's own test binary names it through the
// `#[cfg(test)]` row in `plane::registry::BUILTIN_PLANE_DECLS` (the honest crate boundary, the plane's
// PUBLIC decl), so both shapes boot the same plane list. A model-serving plane's `wire_format_names`
// field still points at [`known_protocols`] here (now `pub`) — its wire formats ARE the registered
// codec protocols, wherever the declaration itself lives.

// Resolve a provider's configured protocol NAME to the registry's interned `&'static str` for the
// lane-build path, or `None` for an unknown name or one that declares no wire codec (some registered
// protocols carry no lane codec at all). Post-G6-A4b a lane stores this name, not a constructed `Protocol` (the concrete
// codec lives in the plugin and core reaches it via `decl_for(name).dialect()`), so the old
// `ProtocolRegistry` `Arc<Protocol>` cache is gone — this is the whole of what lane-build needed from it.
// RELOCATED DOWN to `busbar_kernel::proto`; re-exported here at their historical paths.

// THE CODEC/IR TEST SUITES that used to live here (`tests/tests.rs`, `registry_tests`,
// `stream_fanout_tests`, `stream_translate_tests`, `same_proto_fidelity_tests`, per-dialect
// unit and integration tests, `context_length_tests`, `response_format_matrix_tests`,
// `stop_reason_matrix_tests`, `image_source_matrix_tests`, `translate_parity_golden_tests`,
// `translate_parity_cross_pairs_tests`, `roundtrip_fidelity_tests`, `adversarial_tests`) were
// RELOCATED to the extracted dialect plugin crate's own test tree: they name the dialects
// and the concrete wire codecs, which a neutral crate's tests must not, so they live beside the
// types they exercise. The dialect/IR SOURCE `#[path]` witnesses above remain until Phase 2's flip.

// ==== merged from busbar-substrate proto.rs (W4.b P2) ====
pub use busbar_substrate_values::proto::*;

use crate::ingress::arrival::{install_path_ingress, PathIngress};

/// THE COMPOSITION ROOT'S ONE WRITE INTO BOTH PROTOCOL SEAMS — the declarations AND their path-model
/// arrivals, registered together so the second seam [`install_protocols`] gained when `path_ingress`
/// split off [`ProtocolDecl`] cannot drift from the first. Folds the two installs into one call and,
/// before either lands, asserts the PARITY that keeps the split honest:
///
/// **Every declaration whose model is in the URL path (`has_model_in_url`) MUST register a
/// `path_ingress` arrival.** A path-model protocol installed WITHOUT its arrival would resolve no
/// arrival and SILENTLY fall through to the body-model branch — a wrong-behavior 404-shaped bug.
/// Asserting it here makes that drift a LOUD PANIC at boot, and it is asserted BEFORE either install
/// so a refused boot leaves both seams unwritten rather than one of the two.
///
/// # Panics
/// - if a `has_model_in_url` decl has no registered arrival (the parity failure above).
/// - if either underlying install was already called (two composition roots).
pub fn install_protocols_with_path_ingress(
    decls: Vec<&'static ProtocolDecl>,
    path_ingress: Vec<(&'static str, PathIngress)>,
) {
    if let Some(name) = first_path_model_without_arrival(
        &decls,
        &path_ingress.iter().map(|(n, _)| *n).collect::<Vec<_>>(),
    ) {
        panic!(
            "protocol '{name}' declares has_model_in_url == true but registered no path_ingress \
             arrival: a request naming its URL model would silently fall through to the body-model \
             branch. Register its arrival alongside its declaration."
        );
    }
    install_protocols(decls);
    install_path_ingress(path_ingress);
}

#[cfg(test)]
#[path = "../tests/proto.rs"]
mod tests;
