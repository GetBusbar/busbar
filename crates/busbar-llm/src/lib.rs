// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE LLM PROTOCOL — six dialects, ONE plugin.
//!
//! Anthropic Messages, OpenAI Chat Completions, Google Gemini, AWS Bedrock Converse, OpenAI
//! Responses and Cohere v2 are six ways of saying the same thing, and busbar translates between any
//! pair of them through one neutral IR. That is what makes them DIALECTS rather than protocols: the
//! unit an operator installs, versions and deletes is "can this busbar speak LLM", never "can it
//! speak anthropic but not gemini". So they ship as one crate with six modules, and a seventh
//! dialect is a seventh module here — not a seventh crate and not a seventh feature flag.
//!
//! WHAT EACH DIALECT MODULE OWNS: its `ProtocolDecl`, its wire codec (`reader.rs`/`writer.rs`), its
//! `RequestHandler` and operation cells (`handler.rs`), its own wire constant bank, and its tests.
//! Nothing here is reachable from `busbar-core`: core names no dialect, and this crate's production
//! build names only the neutral ABI (`busbar-substrate` / `busbar-api`) — `busbar-core` is a
//! dev-dependency for the money-path test fixture and nothing more. Registration belongs to the
//! composition root alone —
//! `crates/busbar/src/main.rs::register_protocols` installs [`DECLS`] behind the `proto-llm`
//! feature, which carries the dependency edge too, so dropping the feature drops the whole LLM
//! protocol and the deletion gate watches busbar refuse all six names at boot.
//!
//! WHAT IS DELIBERATELY *NOT* HERE. `busbar_substrate::proto::openai_family` — the `ERR_TYPE_*` bank,
//! `bearer_error_code`, `tool_arguments_to_string`, `MESSAGE_NAMES_SENTINEL` — reads like it should
//! have travelled with the OpenAI dialects, and it must not: `busbar-core` itself consumes it in
//! PRODUCTION (`proxy`'s whole `KIND_*` vocabulary, `admin`'s error envelopes, `auth`'s bearer error
//! code, `ir::variant`'s sentinel). Moving it here would make core depend on this plugin, inverting
//! the seam this crate exists to create. It stays in core and every dialect reaches it there.
//!
//! THE DUAL COMPILE. `busbar-core`'s test and `test-support` builds compile these same source files
//! back in under `crate::proto::{anthropic, …}` via `#[path]`, so core's pre-extraction fixture
//! surface keeps exercising the real codecs from inside core's own test binary. Two consequences
//! bind every file here: dialect sources address core by its crate name (core's
//! `extern crate self as busbar_core` alias resolves that to itself), and a dialect referring to a
//! SIBLING dialect must do it RELATIVELY — `super::gemini::…` from a `mod.rs`, `super::super::…`
//! from one file deeper — because the parent module is this crate's root in one shape and
//! `crate::proto` in the other, and only a relative path is correct in both.

// THE ALLOCATION-COUNT PERF-GATE INSTRUMENT, ported from busbar-core WITH the money-path engine tests
// (money-path Phase 3-4 C M4). The gate (`engine/tests/alloc_gate.rs`) drives one openai>openai
// passthrough through the real forward path and asserts the per-request heap-allocation count has not
// regressed. Its instrument must be THIS test binary's `#[global_allocator]` (an allocator is a binary
// property, set by the crate under test), so it is installed here under the same target gate core uses.
// jemalloc-delegating so the telemetry tests' mallctl counters stay byte-accurate; per-thread counter
// so concurrent `cargo test` threads never inflate the measured thread.
#[cfg(all(test, not(target_env = "msvc")))]
pub(crate) use alloc_gate_instrument::CountingJemalloc;

#[cfg(all(test, not(target_env = "msvc")))]
#[global_allocator]
static GLOBAL: CountingJemalloc = CountingJemalloc;

#[cfg(all(test, not(target_env = "msvc")))]
#[allow(unsafe_code)]
mod alloc_gate_instrument {
    use std::alloc::{GlobalAlloc, Layout};
    use tikv_jemallocator::Jemalloc;

    thread_local! {
        static ALLOC_COUNT: std::cell::Cell<u64> = const { std::cell::Cell::new(0) };
    }

    /// A jemalloc wrapper that counts allocations per-thread — the instrument behind the alloc gate.
    pub(crate) struct CountingJemalloc;

    impl CountingJemalloc {
        /// Allocations observed on THIS thread since process start (or last `reset`).
        pub(crate) fn count() -> u64 {
            ALLOC_COUNT.with(|c| c.get())
        }
        /// Reset this thread's counter to zero, returning the previous value.
        pub(crate) fn reset() -> u64 {
            ALLOC_COUNT.with(|c| c.replace(0))
        }
        #[inline]
        fn bump() {
            ALLOC_COUNT.with(|c| c.set(c.get() + 1));
        }
    }

    // SAFETY: every method delegates verbatim to `Jemalloc` (a sound `GlobalAlloc`); the only added
    // work is a per-thread `Cell` increment, which allocates nothing and cannot re-enter the allocator.
    // `dealloc` is NOT counted — the gate measures allocation COUNT.
    unsafe impl GlobalAlloc for CountingJemalloc {
        #[inline]
        unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
            Self::bump();
            Jemalloc.alloc(layout)
        }
        #[inline]
        unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
            Jemalloc.dealloc(ptr, layout)
        }
        #[inline]
        unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
            Self::bump();
            Jemalloc.alloc_zeroed(layout)
        }
        #[inline]
        unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
            Self::bump();
            Jemalloc.realloc(ptr, layout, new_size)
        }
    }
}

/// THE CODECS, RE-EXPORTED FROM `busbar-llm-codec`.
///
/// The six dialect modules, the concrete IR, the chat/leaf handles, the wire-codec surface, the
/// stream translator and the answer-normalization helpers all live in `busbar-llm-codec` now — the
/// pure half of this plugin, split out so `busbar-plane-llm` can name the codecs without linking
/// this crate's HTTP stack and async runtime. They are re-exported HERE, under their old names, so
/// every caller that spells `busbar_llm::proto_codec::…`, `busbar_llm::anthropic::…`,
/// `busbar_llm::ir::…` resolves exactly what it always did. The split is a MOVE: no item changed
/// shape crossing it.
pub use busbar_llm_codec::{
    anthropic, bedrock, chat_handle, cohere, gemini, ir, ir_encode, leaf_codec, leaf_handles,
    openai_annotations, openai_chat, openai_responses, proto_codec, proto_stream, synth_rng,
    usage_tail, wire_shim, DECLS,
};

/// THE RELOCATED LLM MONEY-PATH ENGINE (1.6.0 money-path Phase 3-4 C). Routing tables, egress
/// pipeline, health probe loop and native fallback plane — see [`engine`].
pub mod engine;

/// THE INBOUND OPENAI RESPONSES WEBHOOK RECEIVER (T3). It parses and HMAC-verifies a signed inbound
/// webhook and mounts a live HTTP route behind the OFF-by-default `webhook-receiver` feature, so it
/// is ingress, not codec — it stays on this side of the split.
pub mod openai_responses_webhook;

/// THE PATH-MODEL DIALECT ARRIVALS (gemini/bedrock URL-model ingress), RELOCATED here from
/// `busbar-core` — the last piece of core→plane entanglement. They parse their own model out of the
/// URL and reach the core request pipeline through the neutral
/// [`busbar_substrate::ingress::arrival::ArrivalHost`] seam, so this crate names no core
/// item. Registered via [`PATH_INGRESS`].
pub mod arrival;

/// THE NATIVE-PLANE UNIVERSAL INGRESS (pool/model resolution + governance admission + the-one-engine
/// forward), RELOCATED here from `busbar-core` — it reads the LLM routing tables so it lives in the
/// plane and calls DOWN into core's neutral accounting. The two dialect arrival families
/// ([`arrival`]) converge on its [`native_ingress::operation_ingress`] / [`native_ingress::
/// ingress_path_model`] entry points.
pub mod native_ingress;

/// THE MONEY-PATH TEST FIXTURE, re-exported from core's now-plane-agnostic `test_support` (money-path
/// Phase 3-4 C M4). The relocated engine tests name `crate::test_support::{LaneSpec, TestApp,
/// MockServer, …}`; the fixture builds the LLM runtime through the neutral `PlaneBuildInput` +
/// `build_runtime` seam (naming no `Lane`/`NativeRuntime`), so it lives ONCE in core and the plane's
/// tests reach it here.
///
/// `cfg(test)` ONLY, never `feature = "test-support"`: `busbar-core` is a DEV-dependency of this
/// plane (its production build names nothing from core — only the substrate/api ABI), so core is
/// present solely in this crate's own test binary. Nothing outside that binary reaches this module.
#[cfg(test)]
pub mod test_support {
    pub use busbar_core::test_support::*;

    /// THE CHAT DISPATCH CELL the money-path tests hold by value — `frame(Http, CHAT, ChatOperation)`
    /// over THIS crate's real openai chat codec. It USED to live in core's `handlers/tests/chat_fixture`
    /// (a `#[cfg(test)]` file that named `busbar_llm::chat_handle::ChatOperation` across the dev-dep
    /// back-edge); with the money-path tests relocated here it is built in-plane, naming its own cell —
    /// no cross-crate `#[cfg(test)]` reach, and no `busbar-core[test-support] → busbar-llm` cycle.
    pub const CHAT: busbar_substrate::handlers::Op = busbar_substrate::handlers::frame(
        busbar_substrate::transport::Transport::Http,
        busbar_api::operation::Operation::CHAT,
        &crate::chat_handle::ChatOperation("openai"),
    );
}

/// THE LLM PLUGIN'S TEST-KIT — the composition-root-shaped install seams a test uses to bring the LLM
/// protocol (and plane) into the process registries WITHOUT the deleted `#[path]` witness re-includes.
/// Named beside the plane crates' testkits (`busbar_mcp::testkit`, `busbar_a2a::testkit`).
#[cfg(any(test, feature = "test-support"))]
pub mod testkit;

/// PUBLISH THIS PLUGIN'S DIALECT DECLARATIONS into the SHARED substrate test registry, ONCE — the
/// lazy, self-installing counterpart of the composition root's `install_protocols`, for the test
/// surface where no `main` runs a composition root.
///
/// It exists because the deleted `#[path]` witness re-includes used to make `busbar-core`'s
/// `test`/`test-support` builds carry these dialects as built-ins AUTOMATICALLY. With the witnesses
/// gone, `busbar-core`'s built-in table is empty and the process registry is populated only by
/// registration — so a codec that resolves a protocol fact through `busbar_substrate::proto::decl_for`
/// (the `Protocol` reader/writer resolution, `protocol_for`, the tool-id remap's
/// `native_tool_id_prefix`) must first ensure this plugin's declarations are registered. Calling this
/// at those few entry points makes every codec-exercising test in THIS crate's binary
/// order-independent without a per-test install. `Once`-guarded, so it is a single atomic load after
/// the first call — off any allocation-gated path. In a build with a real composition root (or
/// `busbar-core`'s own `cfg(test)` publish) the set is already present and the fold dedupes by name.
#[cfg(any(test, feature = "test-support"))]
pub(crate) use busbar_llm_codec::ensure_test_protocols_registered;

/// EVERY DIALECT THIS PLUGIN DECLARES, in the order an operator sees.
///
/// THE ORDER IS LOAD-BEARING AND IT IS NOT ALPHABETICAL. The composition root hands this slice to
/// core's `proto::registry::install_protocols`, which folds it AHEAD of whatever built-in
/// declarations core still carries; the resulting sequence is what `known_protocols()` reports (the
/// "must be one of:" tail an operator reads on a bad `protocol:`) and what `telemetry` banks its
/// per-protocol metric families against — it finds a family again by POSITION in that list. So this
/// order reproduces, exactly, the operator-visible list from before the dialects were plugins:
/// `anthropic, gemini, openai, bedrock, responses, cohere`. A dialect appended here rather than
/// inserted keeps every existing family's index; inserting one silently renumbers all of them.
/// THE LLM PLANE'S VOCABULARY DECLARATION — the plane's statement about ITSELF, relocated here from
/// `busbar_substrate::proto::PLANE_DECL` so the LLM plane owns its declaration exactly as `busbar-mcp` and
/// `busbar-a2a` own theirs. The composition root installs it through
/// core's `plane::registry::install_planes` (`crates/busbar/src/main.rs::register_planes`, behind
/// `proto-llm`); core's own test binary names it through the `#[cfg(test)]` row in
/// `plane::registry::BUILTIN_PLANE_DECLS`, so both shapes boot the same `[llm, mcp, a2a]` plane list.
///
/// `wire_format_names` is [`busbar_substrate::proto::known_protocols`] itself — the model plane's dialects
/// ARE the registered protocols, so a seventh dialect moves that list with nothing edited here. Every
/// other field is `None`/trivial (the fallback plane claims no path, mounts nothing and reconciles
/// nothing). R3/R4 sub-phase B DID move the LLM data-plane runtime (lanes/pools/failover/egress) off its
/// flat `App` field into the opaque `plane_slots` runtime slot every plane's runtime rides — but its
/// type still lives in `busbar-core`, which a plane crate may not name, so `busbar-core`'s `appbuild`
/// composes that slot through a core-local constructor rather than through this decl's `build_runtime`
/// pointer (which stays `None`); Phase 3 relocates the type here and flips the pointer on, like MCP's.
pub const PLANE_DECL: busbar_substrate::plane::registry::PlaneDecl =
    busbar_substrate::plane::registry::PlaneDecl {
        key: "llm",
        // THE FALLBACK CATCH-ALL — every unclaimed path falls through to the LLM plane, so core reads
        // the fallback key off this flag rather than a hard-coded `"llm"` literal.
        fallback: true,
        config_section: "pools",
        scope_kinds: &["pool"],
        subject_noun: "pool",
        // The LLM plane has no 1.5.3 named-definition-map section (`pools:` is not a
        // `NamedMapSection`), so `singular` is never routed here; carried for completeness.
        admin_noun: "pool",
        audit_kind: "pool",
        wire_format_names: busbar_substrate::proto::known_protocols,
        // THE FALLBACK MOUNTS NOTHING — the catch-all every unclaimed path falls through to, so it
        // claims no path and binds no audience.
        claims: |_| Vec::new(),
        admission: |_| None,
        // NO DISPATCH SLOT / NO SURFACE / NO DURABLE STATE — the fallback plane claims no path, so it
        // contributes no config-conditional dispatch resource, and it restores/reconciles nothing.
        build: |_| None,
        // T3 — the fallback plane MOUNTS NOTHING by default (its documented stance): `routes` stays
        // `None` so its boot is byte-identical. The OFF-by-default `webhook-receiver` feature flips it
        // to the inbound OpenAI Responses webhook receiver's route builder (which itself mounts nothing
        // unless `BUSBAR_LLM_WEBHOOK_SECRET` is configured). Gated so the money-path default build is
        // untouched; see `openai_responses_webhook.rs` for the deferred secret-config seam.
        #[cfg(not(feature = "webhook-receiver"))]
        routes: None,
        #[cfg(feature = "webhook-receiver")]
        routes: Some(crate::openai_responses_webhook::webhook_routes),
        admin_routes: None,
        openapi: None,
        hydrate: None,
        start: None,
        config_validate: None,
        card_signing_domain: None,
        card_kid_prefix: None,
        named_def_list: None,
        named_def_get: None,
        registry_contains: None,
        reresolve_gates: None,
        #[cfg(feature = "openapi-schema")]
        openapi_schemas: None,
        on_swap: None,
        parse_section: None,
        parse_endpoint: None,
        lower_endpoint: None,
        // THE PER-GENERATION RUNTIME SEAM stays `None` for the fallback plane THIS phase (R3/R4 sub-phase
        // B). The pool/lane/failover/egress runtime IS now carried in the opaque `plane_slots` runtime
        // slot every plane's runtime rides, and the money-path read (`App::engine_tables`) downcasts that
        // slot once per call — but its type (core's `state::NativeRuntime`) still lives in core,
        // and a plane crate may not name a core item, so `busbar-core`'s `appbuild` composes
        // the slot through a core-local constructor rather than through this pointer. Phase 3 relocates
        // the type here, at which point this becomes `Some(<this crate's build_runtime>)` like MCP's.
        build_runtime: Some(crate::engine::build_runtime::build_runtime),
        viewer: Some(crate::engine::build_runtime::viewer),
        retain_verify_gates: None,
        default_section: None,
        // config-seam stage 1: the registry starts EMPTY — nothing has moved out of core yet.
        owned_config_sections: &[],
    };

/// SPAWN THE ACTIVE HEALTH PROBERS for a freshly-built/-swapped snapshot — the relocated
/// `busbar-core::health::spawn_probers` (the prober loop reads the plane's own `Lane`/`NativeRuntime`
/// tables, so it lives here). The composition root (the `busbar` binary) calls it at boot and the
/// admin swap path re-attaches probers to each new generation. No-op when every lane is `mode: none`.
pub use crate::engine::health::spawn_probers;


/// THE PATH-MODEL ARRIVALS THIS PLUGIN REGISTERS, protocol-name-keyed.
///
/// When `ProtocolDecl` relocated to `busbar-substrate` (Batch C-6) its `path_ingress` field could not
/// travel — it named the core-only `Arrival` — so a path-model dialect now registers its arrival
/// through this SIDE-TABLE instead of on its declaration. The composition root
/// (`crates/busbar/src/main.rs::register_protocols`) hands this slice to
/// core's `proto::registry::install_protocols_with_path_ingress` ALONGSIDE [`DECLS`], which
/// asserts at boot that every `has_model_in_url` declaration here (gemini, bedrock) has an arrival —
/// so a dialect that grows a URL model but forgets its arrival is a loud boot panic, not a silent
/// fall-through. Only the two URL-model dialects appear; the four body-model dialects resolve their
/// operation off the body and register nothing. The arrival fns live in THIS crate
/// ([`crate::arrival::{gemini_arrival, bedrock_arrival}`]) and reach the core pipeline through the
/// neutral `ArrivalHost` seam — no reference into core; this states the NAME→fn pairing.
pub static PATH_INGRESS: &[(&str, busbar_substrate::ingress::arrival::PathIngress)] = &[
    (
        crate::proto_codec::PROTO_GEMINI,
        crate::arrival::gemini_arrival,
    ),
    (
        crate::proto_codec::PROTO_BEDROCK,
        crate::arrival::bedrock_arrival,
    ),
];

/// THE BODY-MODEL DIALECT ARRIVALS — the body-axis twin of [`PATH_INGRESS`]. The convenience surfaces
/// (`named`/`adhoc` `/v1/messages`) and the generic body-model dispatch arm resolve a dialect's
/// universal ingress by NAME through `busbar_substrate::ingress::arrival::body_ingress_for`; this slice
/// states each dialect's NAME→arrival pairing. The composition root
/// (`crates/busbar/src/main.rs::register_protocols`) hands it to
/// `busbar_substrate::ingress::arrival::install_body_ingress`; the test-kit seeds it through
/// `set_test_body_ingress`. Every dialect appears (each routes its body-model traffic through the ONE
/// engine); the URL-model pair (gemini/bedrock) also carry a body entry for the dispatch arm's
/// symmetry, even though their primary surface is [`PATH_INGRESS`].
pub static BODY_INGRESS: &[(&str, busbar_substrate::ingress::arrival::BodyIngress)] = &[
    (
        crate::proto_codec::PROTO_ANTHROPIC,
        crate::arrival::anthropic_body_arrival,
    ),
    (
        crate::proto_codec::PROTO_OPENAI,
        crate::arrival::openai_body_arrival,
    ),
    (
        crate::proto_codec::PROTO_GEMINI,
        crate::arrival::gemini_body_arrival,
    ),
    (
        crate::proto_codec::PROTO_BEDROCK,
        crate::arrival::bedrock_body_arrival,
    ),
    (
        crate::proto_codec::PROTO_RESPONSES,
        crate::arrival::responses_body_arrival,
    ),
    (
        crate::proto_codec::PROTO_COHERE,
        crate::arrival::cohere_body_arrival,
    ),
];

/// THE READS-NOT-RESTATES GUARANTEE for the LLM `PLANE_DECL`, pinned HERE because this is the crate
/// that owns the declaration — and the only place its `wire_format_names` field and
/// `busbar_substrate::proto::known_protocols` resolve to the SAME `busbar-core` instance, so a by-pointer
/// identity is meaningful (core's own test binary links two core instances and cannot check it — see
/// `busbar_core`'s `the_llm_planes_dialects_are_the_registrys_...`). A mutation that replaced the
/// registry read with a literal spelling today's six dialects — the vacuous shape a `PlaneDecl` uses
/// to keep claiming dialects a build no longer compiles in — is a DIFFERENT fn pointer and fails here.
#[cfg(test)]
#[path = "tests/plane_decl_identity_tests.rs"]
mod plane_decl_identity_tests;

// THE CODEC AND IR SUITES MOVED WITH THE CODECS. The detection fold, the error-frame writers, the
// tool-id decode, the leaf-op write dispatch, the translate-parity/streaming/round-trip goldens and
// the bedrock eventstream synthesis all name the dialects, so they are declared by
// `busbar-llm-codec` now and run in its test binary. What is left here is what names the ENGINE.