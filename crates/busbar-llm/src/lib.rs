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
//! Nothing here is reachable from `busbar-core`: core names no dialect, and this crate names
//! `busbar-core` and no other busbar crate. Registration belongs to the composition root alone —
//! `crates/busbar/src/main.rs::register_protocols` installs [`DECLS`] behind the `proto-llm`
//! feature, which carries the dependency edge too, so dropping the feature drops the whole LLM
//! protocol and the deletion gate watches busbar refuse all six names at boot.
//!
//! WHAT IS DELIBERATELY *NOT* HERE. `busbar_core::proto::openai_family` — the `ERR_TYPE_*` bank,
//! `bearer_error_code`, `tool_arguments_to_string`, `MESSAGE_NAMES_SENTINEL` — reads like it should
//! have travelled with the OpenAI dialects, and it must not: `busbar-core` itself consumes it in
//! PRODUCTION (`proxy`'s whole `KIND_*` vocabulary, `admin`'s error envelopes, `auth`'s bearer error
//! code, `ir::variant`'s sentinel). Moving it here would make core depend on this plugin, inverting
//! the seam this crate exists to create. It stays in core and every dialect reaches it there.
//!
//! THE DUAL COMPILE. `busbar-core`'s test and `test-support` builds compile these same source files
//! back in under `crate::proto::{anthropic, …}` via `#[path]`, so core's pre-extraction fixture
//! surface keeps exercising the real codecs from inside core's own test binary. Two consequences
//! bind every file here: dialect sources address core as `busbar_core::…` (core's
//! `extern crate self as busbar_core` alias resolves that to itself), and a dialect referring to a
//! SIBLING dialect must do it RELATIVELY — `super::gemini::…` from a `mod.rs`, `super::super::…`
//! from one file deeper — because the parent module is this crate's root in one shape and
//! `crate::proto` in the other, and only a relative path is correct in both.

// THE ALLOCATION-COUNT PERF-GATE INSTRUMENT, ported from busbar-core WITH the money-path engine tests
// (money-path Phase 3-4 C M4). The gate (`engine/proxy_tests/alloc_gate.rs`) drives one openai>openai
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

/// **G6 A4b relocation.** The concrete chat IR + leaf-op IR, moved here from busbar-core. Core keeps
/// the neutral `ir::facts` trait / `ir::handle` / `ir::invoke` / `ir::subscribe` and re-includes this
/// module via `#[path]` for its test build so `crate::ir::IrRequest` still resolves there.
pub mod ir;

/// THE RELOCATED LLM MONEY-PATH ENGINE (1.6.0 money-path Phase 3-4 C). Routing tables, egress
/// pipeline, health probe loop and native fallback plane — see [`engine`].
pub mod engine;

/// **G6 A4b dissolve.** The chat `IrHandle` (`ChatReqHandle`/`ChatRespHandle`) + its
/// `prepare_for_egress`/`_ingress`/`usage` bodies, lifted from the dissolved `IrReq::Chat`/`IrResp::Chat`
/// arms; the handle writes itself onto the egress dialect by protocol string.
pub mod chat_handle;

/// **G6 A4b dissolve.** The six leaf-op `IrHandle`s (embeddings/image/rerank/moderation/
/// transcription/speech), writing themselves onto the peer dialect via the `leaf_codec` `(op,proto)`
/// dispatchers.
pub mod leaf_handles;

pub mod anthropic;
pub mod bedrock;
pub mod cohere;
pub mod gemini;
pub mod openai_chat;
pub mod openai_responses;

/// THE PATH-MODEL DIALECT ARRIVALS (gemini/bedrock URL-model ingress), RELOCATED here from
/// `busbar-core` — the last piece of core→plane entanglement. They parse their own model out of the
/// URL and reach the core request pipeline through the neutral
/// [`busbar_substrate::ingress::arrival::ArrivalHost`] seam, so this crate names no `busbar_core::`
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
/// MockServer, …}`; the fixture builds the LLM runtime through the neutral `LlmBuildInput` +
/// `build_runtime` seam (naming no `Lane`/`NativeRuntime`), so it lives ONCE in core and the plane's
/// tests reach it here. Gated exactly as core's is.
#[cfg(any(test, feature = "test-support"))]
pub mod test_support {
    pub use busbar_core::test_support::*;

    /// THE CHAT DISPATCH CELL the money-path tests hold by value — `frame(Http, CHAT, ChatOperation)`
    /// over THIS crate's real openai chat codec. It USED to live in core's `handlers/tests/chat_fixture`
    /// (a `#[cfg(test)]` file that named `busbar_llm::chat_handle::ChatOperation` across the dev-dep
    /// back-edge); with the money-path tests relocated here it is built in-plane, naming its own cell —
    /// no cross-crate `#[cfg(test)]` reach, and no `busbar-core[test-support] → busbar-llm` cycle.
    pub const CHAT: busbar_core::handlers::Op = busbar_core::handlers::frame(
        busbar_core::transport::Transport::Http,
        busbar_core::operation::Operation::CHAT,
        &crate::chat_handle::ChatOperation("openai"),
    );
}

/// Thread-local OS-entropy pool shared by every writer's synthesized-wire-id path — amortises the
/// per-id `getrandom` syscall (the whole `rb_finish` cost on the anthropic-ingress hot path).
pub(crate) mod synth_rng;

/// The dialect-neutral tail-usage isolation helper shared by every reader's
/// `recover_truncated_usage` override.
pub(crate) mod usage_tail;

/// The OpenAI-family citation `annotations` mapping shared by the Chat and Responses codecs.
pub(crate) mod openai_annotations;

/// IR → wire encode helpers (image source, tool-result detection, strict-drop warn) shared by the
/// dialect writers.
pub(crate) mod ir_encode;

/// **G6 A4b option-a prep.** The per-`(operation, egress-protocol)` leaf-op writer dispatch — the
/// non-chat twin of chat's `protocol_for(proto).writer()`, so a dissolved leaf-op handle can write
/// itself by egress-protocol string without a downcast.
pub(crate) mod leaf_codec;

/// **G6 A4b relocation.** The concrete wire-codec surface (`ProtocolReader`/`ProtocolWriter`/
/// `StreamFraming`/`Protocol`/`protocol_for`/`DialectRef`/`ToolIdRemap`), moved out of busbar-core so
/// core names zero concrete LLM IR; core re-includes it under `crate::proto::proto_codec` for its test
/// build.
pub mod proto_codec;

/// **G6 A4b relocation.** The concrete streaming byte-translator (`StreamTranslate`) behind the neutral
/// `busbar_core::proto::StreamTranslator`; core re-includes it under `crate::proto::stream` for tests
/// and reaches it in production via the installed factory.
pub mod proto_stream;

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
/// registration — so a codec that resolves a protocol fact through `busbar_core::proto::decl_for`
/// (the `Protocol` reader/writer resolution, `protocol_for`, the tool-id remap's
/// `native_tool_id_prefix`) must first ensure this plugin's declarations are registered. Calling this
/// at those few entry points makes every codec-exercising test in THIS crate's binary
/// order-independent without a per-test install. `Once`-guarded, so it is a single atomic load after
/// the first call — off any allocation-gated path. In a build with a real composition root (or
/// `busbar-core`'s own `cfg(test)` publish) the set is already present and the fold dedupes by name.
#[cfg(any(test, feature = "test-support"))]
pub(crate) fn ensure_test_protocols_registered() {
    static REGISTER: std::sync::Once = std::sync::Once::new();
    REGISTER.call_once(|| busbar_substrate::proto::register_test_protocols(DECLS));
}

/// EVERY DIALECT THIS PLUGIN DECLARES, in the order an operator sees.
///
/// THE ORDER IS LOAD-BEARING AND IT IS NOT ALPHABETICAL. The composition root hands this slice to
/// `busbar_core::proto::registry::install_protocols`, which folds it AHEAD of whatever built-in
/// declarations core still carries; the resulting sequence is what `known_protocols()` reports (the
/// "must be one of:" tail an operator reads on a bad `protocol:`) and what `telemetry` banks its
/// per-protocol metric families against — it finds a family again by POSITION in that list. So this
/// order reproduces, exactly, the operator-visible list from before the dialects were plugins:
/// `anthropic, gemini, openai, bedrock, responses, cohere`. A dialect appended here rather than
/// inserted keeps every existing family's index; inserting one silently renumbers all of them.
/// THE LLM PLANE'S VOCABULARY DECLARATION — the plane's statement about ITSELF, relocated here from
/// `busbar_core::proto::PLANE_DECL` so the LLM plane owns its declaration exactly as `busbar-mcp` and
/// `busbar-a2a` own theirs. The composition root installs it through
/// `busbar_core::plane::registry::install_planes` (`crates/busbar/src/main.rs::register_planes`, behind
/// `proto-llm`); core's own test binary names it through the `#[cfg(test)]` row in
/// `plane::registry::BUILTIN_PLANE_DECLS`, so both shapes boot the same `[llm, mcp, a2a]` plane list.
///
/// `wire_format_names` is [`busbar_core::proto::known_protocols`] itself — the model plane's dialects
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
        routes: None,
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
        // slot once per call — but its type (`busbar_core::state::NativeRuntime`) still lives in core,
        // and a plane crate may not name a `busbar_core::` item, so `busbar-core`'s `appbuild` composes
        // the slot through a core-local constructor rather than through this pointer. Phase 3 relocates
        // the type here, at which point this becomes `Some(<this crate's build_runtime>)` like MCP's.
        build_runtime: Some(crate::engine::build_runtime::build_runtime),
        viewer: Some(crate::engine::build_runtime::viewer),
        retain_verify_gates: None,
        default_section: None,
    };

/// SPAWN THE ACTIVE HEALTH PROBERS for a freshly-built/-swapped snapshot — the relocated
/// `busbar-core::health::spawn_probers` (the prober loop reads the plane's own `Lane`/`NativeRuntime`
/// tables, so it lives here). The composition root (the `busbar` binary) calls it at boot and the
/// admin swap path re-attaches probers to each new generation. No-op when every lane is `mode: none`.
pub use crate::engine::health::spawn_probers;

pub static DECLS: &[&busbar_substrate::proto::ProtocolDecl] = &[
    &anthropic::DECL,
    &gemini::DECL,
    &openai_chat::DECL,
    &bedrock::DECL,
    &openai_responses::DECL,
    &cohere::DECL,
];

/// THE PATH-MODEL ARRIVALS THIS PLUGIN REGISTERS, protocol-name-keyed.
///
/// When `ProtocolDecl` relocated to `busbar-substrate` (Batch C-6) its `path_ingress` field could not
/// travel — it named the core-only `Arrival` — so a path-model dialect now registers its arrival
/// through this SIDE-TABLE instead of on its declaration. The composition root
/// (`crates/busbar/src/main.rs::register_protocols`) hands this slice to
/// `busbar_core::proto::registry::install_protocols_with_path_ingress` ALONGSIDE [`DECLS`], which
/// asserts at boot that every `has_model_in_url` declaration here (gemini, bedrock) has an arrival —
/// so a dialect that grows a URL model but forgets its arrival is a loud boot panic, not a silent
/// fall-through. Only the two URL-model dialects appear; the four body-model dialects resolve their
/// operation off the body and register nothing. The arrival fns live in THIS crate
/// ([`crate::arrival::{gemini_arrival, bedrock_arrival}`]) and reach the core pipeline through the
/// neutral `ArrivalHost` seam — no `busbar_core::` reference; this states the NAME→fn pairing.
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

/// THE READS-NOT-RESTATES GUARANTEE for the LLM `PLANE_DECL`, pinned HERE because this is the crate
/// that owns the declaration — and the only place its `wire_format_names` field and
/// `busbar_core::proto::known_protocols` resolve to the SAME `busbar-core` instance, so a by-pointer
/// identity is meaningful (core's own test binary links two core instances and cannot check it — see
/// `busbar_core`'s `the_llm_planes_dialects_are_the_registrys_...`). A mutation that replaced the
/// registry read with a literal spelling today's six dialects — the vacuous shape a `PlaneDecl` uses
/// to keep claiming dialects a build no longer compiles in — is a DIFFERENT fn pointer and fails here.
#[cfg(test)]
#[path = "tests/plane_decl_identity_tests.rs"]
mod plane_decl_identity_tests;

/// THE DETECTION TESTS, relocated here from `busbar-core` because they name dialects: they exercise
/// the generic detection fold through THIS plugin's registered `claims` / `residual_claims`
/// predicates, proving the ladder→predicate move is byte-identical.
#[cfg(test)]
#[path = "tests/detect_tests.rs"]
mod detect_tests;

#[cfg(test)]
#[path = "tests/write_error_frame_tests.rs"]
mod write_error_frame_tests;

#[cfg(test)]
#[path = "tests/decode_native_tool_id_tests.rs"]
mod decode_native_tool_id_tests;

#[cfg(test)]
#[path = "tests/leaf_write_dispatch_tests.rs"]
mod leaf_write_dispatch_tests;

/// THE CODEC/IR TEST SUITES relocated from `busbar-core`'s `proto/tests/*`: the detection,
/// translate-parity, streaming, round-trip and IR goldens that name the
/// dialects and the concrete wire codecs, now living beside the types they exercise. See the module
/// header for the `super::*` prelude reconstruction.
#[cfg(test)]
#[path = "tests/proto/mod.rs"]
mod relocated_proto_tests;

/// The bedrock buffered-response → native ConverseStream eventstream synthesis suite, RELOCATED from
/// `busbar-core`'s `proxy/tests/`: it drives
/// `bedrock::bedrock_response_to_eventstream`, a witnessed codec fn, so it lives beside that codec.
#[cfg(test)]
#[path = "tests/bedrock_eventstream_tests.rs"]
mod bedrock_eventstream_tests;
