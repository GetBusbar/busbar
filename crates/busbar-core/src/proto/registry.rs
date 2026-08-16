// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE PROTOCOL REGISTRY — a protocol is a DECLARATION, and core looks it up rather than matching
//! on its name.
//!
//! WHAT THIS REPLACED, and why the shape matters more than the saving. Until this module existed,
//! resolving a protocol was `match name { "anthropic" => …, "openai" => …, _ => None }` in
//! `proto/mod.rs`, with a second copy of the same match in `handlers::request_handler` and a third
//! in `ProtocolRegistry::with_builtins`. Every other axis in busbar is already a plugin — store,
//! auth, hooks, export — and the protocol axis was the last place where adding a capability meant
//! editing core. A `match` on a string literal is exactly that edit.
//!
//! **A REGISTRY WHOSE POPULATION IS A `match` IN CORE HAS NOT REMOVED THE MATCH, IT HAS MOVED IT.**
//! That is the sharp correction `design/protocol-plugin-abi.md` §8.1 makes about `admin-tokens`,
//! which is a crate behind a `#[cfg(feature)]` match ARM in core. So [`BUILTIN_DECLS`] is DATA — a
//! slice of `&'static ProtocolDecl`, one entry per protocol, each declared in the protocol's OWN
//! module beside the code it describes — and [`Registry::new`] takes an ITERATOR of declarations,
//! so a protocol that is not in that slice joins by being handed to the same constructor. Nothing
//! in this file branches on a protocol name, and nothing above it does either.
//!
//! WHAT A DECLARATION ABSORBED. Three `OnceLock` registry sweeps used to answer, per fact, by
//! building a `Protocol` for every known name and reading one method off its writer vtable —
//! `proto::streaming_content_types()`, `proto::array_stream_shim_keys()` and
//! `proxy::lazy_body::captured_head_keys()`. Each paid `protocol_for`'s two `Box` allocations per
//! protocol to learn a `&'static` constant. They are now three FIELDS on the declaration, folded
//! into one boot-time aggregate on the registry ([`Registry::new`]) — one `OnceLock` where there
//! were three, and no allocation on any of them.
//!
//! THE HOT PATH. [`decl_for`] is called several times per request (each layer resolves the protocol
//! it needs from a name string). It is one `OnceLock` acquire-load plus a linear scan of a handful
//! of interned `&'static str`s, and it allocates NOTHING — where the `match` it replaced allocated
//! a `Box<dyn ProtocolReader>` and a `Box<dyn ProtocolWriter>` on every call, including the many
//! calls that wanted a pure by-name constant. `scripts/structure-lint.sh`'s `A8-protocol-decl-for`
//! row scans this function and fails on an allocation appearing in it.
//!
//! WHAT IS NOT HERE YET, stated so its absence is not read as a claim. `ProtocolDecl` carries the
//! facts core reads TODAY. `route`/`read`/`Decoded` (the ABI's per-request methods),
//! `Dispatch::{Linked,Dlopen}` and the signed manifest arrive with the crate extraction and Tier B;
//! [`ProtocolDecl::verbs`] carries operator-facing verb NAMES because `Verb { op, name }` lands
//! with `Operation` 13 → 6, and this field is its destination.

use super::Protocol;
use crate::handlers::RequestHandler;

/// A path-model protocol's own ingress: one arrival in, one response out. See
/// [`ProtocolDecl::path_ingress`].
pub(crate) type PathIngress = fn(
    crate::ingress::dispatch::Arrival,
) -> std::pin::Pin<
    Box<dyn std::future::Future<Output = axum::response::Response> + Send>,
>;

/// WHICH INBOUND AUTH SCHEME a protocol's clients present. DECLARED metadata, never a branch: the
/// verification itself stays in the auth layer, which has the governance key lookup and the shared
/// signing helpers. This replaces `ProtocolReader::uses_sigv4_ingress_auth()`, which was the same
/// fact answered through a vtable — and answering it through a vtable meant allocating a reader to
/// ask a `&'static` question.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum IngressAuth {
    /// A bearer token / API key in a header (every protocol but Bedrock).
    Bearer,
    /// An AWS SigV4 request signature (Bedrock's ingress shape).
    SigV4,
}

/// EVERYTHING CORE KNOWS ABOUT A PROTOCOL, declared once by the protocol itself.
///
/// Core routes, mounts, labels and bounds from this and from nothing else. Each field replaces
/// either a `match` on a protocol name or a vtable sweep that allocated to read a constant; the
/// doc on each says which.
pub(crate) struct ProtocolDecl {
    /// The registry key, and the metrics label. **OPERATOR-VISIBLE:** a protocol name appears in
    /// dashboards and in `providers.*.protocol` config, so renaming one re-bases a metric series
    /// and invalidates a config file. Replaces the `match name` arm.
    pub(crate) name: &'static str,

    /// How to build this protocol's wire CODEC (reader + writer), or `None` for a protocol that
    /// serves operations without a cross-dialect codec (MCP, whose IR is its own). A fresh instance
    /// is REQUIRED per resolution — `GeminiWriter`, `CohereWriter` and `ResponsesWriter` carry
    /// per-STREAM mutable state — which is why this is a constructor rather than a `&'static
    /// Protocol`, and why the fact fields below exist: a caller that wants a constant must not have
    /// to build a codec to read one.
    pub(crate) codec: Option<fn() -> Protocol>,

    /// The cell that serves one exchange on this protocol. Replaces `handlers::request_handler`'s
    /// match. `None` would be a protocol that declares itself and serves nothing; every declaration
    /// in the tree today has one.
    pub(crate) handler: Option<&'static dyn RequestHandler>,

    /// THE OPERATOR-FACING VERB NAMES this protocol serves — `Operation::name()` for each operation
    /// its handler answers. Bounded at load and enumerable at boot (never request-derived), which is
    /// what makes them safe as metric labels. `the_declared_verbs_are_the_verbs_the_handler_serves`
    /// pins both directions, so a decl cannot claim a verb it does not serve or hide one it does.
    ///
    /// **THIS FIELD IS `Verb { op, name }`'s DESTINATION** (`design/protocol-plugin-abi.md` §4.4).
    /// It is name-only while `Operation` still carries the seven LLM verbs as variants; when that
    /// enum collapses 13 → 6 the pair lands here and core stops knowing the word `chat`.
    pub(crate) verbs: &'static [&'static str],

    /// TOP-LEVEL body keys the pre-materialized path may point-read, DOM-free. Replaces the
    /// hardcoded four in `proxy::lazy_body::captured_head_keys()` — the sweep that reached back into
    /// the protocol registry for the rest. The registry unions these with
    /// [`Self::array_stream_shim_key`] once, at boot.
    pub(crate) head_keys: &'static [&'static str],

    /// The `Content-Type` this protocol's writer emits on a STREAMING response, or `None` for a
    /// protocol that does not stream. Replaces `ProtocolWriter::streaming_content_type()` and the
    /// `OnceLock` sweep that read it off every protocol's freshly allocated writer.
    pub(crate) streaming_content_type: Option<&'static str>,

    /// The router's array-stream shim key for this protocol (only Gemini has one: a marker injected
    /// into a non-`alt=sse` request body and stripped before egress). Replaces
    /// `ProtocolWriter::array_stream_shim_key()` and its `OnceLock` sweep.
    pub(crate) array_stream_shim_key: Option<&'static str>,

    /// This protocol's NATIVE tool-call id prefix, or `None` when it carries no tool id on the wire
    /// (Gemini correlates by name) or uses free-form ids with no canonical prefix (Cohere). Replaces
    /// `proto::native_tool_id_prefix`'s match on the protocol name — the last one in `proto/mod.rs`.
    pub(crate) native_tool_id_prefix: Option<&'static str>,

    /// Which inbound auth scheme this protocol's clients present. Replaces
    /// `ProtocolReader::uses_sigv4_ingress_auth()`.
    pub(crate) ingress_auth: IngressAuth,

    /// THE ARRIVAL THIS PROTOCOL SERVES ITSELF, or `None` for a protocol whose operation the
    /// catch-all resolves from the body and serves through the universal ingress.
    ///
    /// Replaces the LAST TWO protocol-name comparisons in core: `ingress/dispatch.rs` matched
    /// `PROTO_GEMINI` and `PROTO_BEDROCK` by name to reach bespoke path-model futures. They
    /// survived the registry unit — which noted that removing them "needs an ingress fn-pointer on
    /// the declaration, i.e. designing the mount table" — and this is that pointer. Only a protocol
    /// that keeps its MODEL IN THE URL needs one; the four body-model dialects declare `None` and
    /// core reaches the same universal ingress for every one of them.
    ///
    /// It returns a BOXED future deliberately. The arms it replaced were `Box::pin`ed because in a
    /// `match` every arm's future is inlined into the dispatch coroutine's union, so a ~5.7 KB arm
    /// inflated the future every request carried regardless of dialect. A function pointer to a
    /// boxed future keeps that cost on the requests that take it.
    pub(crate) path_ingress: Option<PathIngress>,

    /// Whether a STREAMING response on this protocol reports token usage only when the request
    /// explicitly opted in (OpenAI Chat Completions' `stream_options.include_usage`). `false` — the
    /// default answer for every other dialect — means the stream reports usage unconditionally, so
    /// the engine has nothing to inject. Replaces `egress_name == "openai"` in the forward engine:
    /// the injection is a fact about what THIS dialect does with a streaming request, and the engine
    /// only needed to know whether to do it.
    pub(crate) stream_usage_requires_opt_in: bool,
}

impl ProtocolDecl {
    /// True when this protocol authenticates INBOUND requests with AWS SigV4 rather than a bearer
    /// token. The auth layer's one consumer of [`ProtocolDecl::ingress_auth`], kept as a predicate
    /// so the front door reads a QUESTION rather than comparing an enum it would then have to
    /// exhaust.
    pub(crate) fn uses_sigv4_ingress_auth(&self) -> bool {
        matches!(self.ingress_auth, IngressAuth::SigV4)
    }
}

/// THE BUILT-INS — one line per protocol, and every line is DATA.
///
/// This is the whole of core's knowledge of which protocols exist. It is deliberately not a match,
/// not a `#[cfg]`-gated arm, and not a constructor: it is a list of references to declarations that
/// live in the protocols' own modules. When a protocol becomes a crate (step 4), its line here
/// becomes the `busbar-proto-llm` crate's `&DECL` and nothing else in core moves; when a protocol is LOADED, it
/// never appears here at all and reaches [`Registry::new`] through the same iterator.
static BUILTIN_DECLS: &[&ProtocolDecl] = &[
    // Order is the operator-visible order: it is the order `known_protocols()` reports, and
    // `telemetry` indexes its per-protocol metric families by position in that list.
    &crate::proto::anthropic::DECL,
    &crate::proto::openai_chat::DECL,
    &crate::proto::gemini::DECL,
    &crate::proto::bedrock::DECL,
    &crate::proto::openai_responses::DECL,
    &crate::proto::cohere::DECL,
    // MCP declares a handler and NO codec: its IR is its own and there is no cross-dialect
    // translation into or out of it. That asymmetry is the point — the registry holds protocols,
    // not codecs, and a protocol that translates to nothing is still a protocol.
    &crate::handlers::mcp::DECL,
];

/// The built-in declarations. Read by [`registry`] to build the process registry, and by the
/// registry's own tests to build a registry with ONE MORE declaration in it — which is the whole of
/// what a loader will do differently.
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) fn builtin_decls() -> &'static [&'static ProtocolDecl] {
    BUILTIN_DECLS
}

/// THE REGISTRY: the declarations, plus the aggregates that used to be three separate `OnceLock`
/// sweeps. Built once; every field is derived from the declarations and from nothing else, so there
/// is no second place a protocol fact can be stated.
pub(crate) struct Registry {
    decls: Vec<&'static ProtocolDecl>,
    /// Absorbed `proxy::lazy_body::captured_head_keys()`: every declared head key, plus every
    /// declared shim key (the shim marker is point-read on the pre-materialized path exactly like a
    /// head key), sorted and deduped so the interning scan is stable.
    head_keys: &'static [&'static str],
    /// Absorbed `proto::streaming_content_types()`.
    streaming_content_types: &'static [&'static str],
    /// Absorbed `proto::array_stream_shim_keys()`.
    array_stream_shim_keys: &'static [&'static str],
    /// The names of the protocols that ship a wire CODEC — the set a provider lane's `protocol:`
    /// may name, and what `KNOWN_PROTOCOLS` used to state as a hand-maintained second list beside
    /// the constructors it had to agree with.
    codec_protocols: &'static [&'static str],
}

impl Registry {
    /// Build a registry from declarations. Production hands it the built-ins plus anything loaded;
    /// a test hands it the built-ins plus a protocol nobody wrote. THE CONSTRUCTOR IS THE SAME ONE,
    /// which is the property being claimed: joining costs a declaration and nothing else.
    pub(crate) fn new(decls: impl IntoIterator<Item = &'static ProtocolDecl>) -> Self {
        let decls: Vec<&'static ProtocolDecl> = decls.into_iter().collect();
        let mut head_keys: Vec<&'static str> = Vec::new();
        let mut streaming_content_types: Vec<&'static str> = Vec::new();
        let mut array_stream_shim_keys: Vec<&'static str> = Vec::new();
        let mut codec_protocols: Vec<&'static str> = Vec::new();
        for d in &decls {
            head_keys.extend_from_slice(d.head_keys);
            head_keys.extend(d.array_stream_shim_key);
            streaming_content_types.extend(d.streaming_content_type);
            array_stream_shim_keys.extend(d.array_stream_shim_key);
            if d.codec.is_some() {
                codec_protocols.push(d.name);
            }
        }
        for v in [
            &mut head_keys,
            &mut streaming_content_types,
            &mut array_stream_shim_keys,
        ] {
            v.sort_unstable();
            v.dedup();
        }
        assert!(
            {
                let mut names: Vec<&str> = decls.iter().map(|d| d.name).collect();
                names.sort_unstable();
                let before = names.len();
                names.dedup();
                names.len() == before
            },
            "two protocol declarations claim the same name: one of them would be unroutable"
        );
        // `Vec::leak` rather than a stored `Vec` + a lifetime cast: the registry is a process
        // singleton built once, so the "leak" is the same allocation a `static` would have held,
        // and it lets every accessor hand out the `&'static [&'static str]` its callers already
        // expect (the three sweeps this absorbed all returned that) with no `unsafe` anywhere.
        Self {
            decls,
            head_keys: head_keys.leak(),
            streaming_content_types: streaming_content_types.leak(),
            array_stream_shim_keys: array_stream_shim_keys.leak(),
            codec_protocols: codec_protocols.leak(),
        }
    }

    /// Resolve a declaration by name. A linear scan over a handful of interned `&'static str`s —
    /// the same comparison chain the `match` compiled to, with the arms as data.
    pub(crate) fn decl(&self, name: &str) -> Option<&'static ProtocolDecl> {
        self.decls.iter().copied().find(|d| d.name == name)
    }

    /// Every declaration, in declaration order.
    pub(crate) fn decls(&self) -> &[&'static ProtocolDecl] {
        &self.decls
    }

    /// The complete set of top-level body keys the head projection captures.
    pub(crate) fn head_keys(&self) -> &'static [&'static str] {
        self.head_keys
    }

    /// The streaming `Content-Type` set across every declared protocol.
    pub(crate) fn streaming_content_types(&self) -> &'static [&'static str] {
        self.streaming_content_types
    }

    /// The array-stream shim keys across every declared protocol.
    pub(crate) fn array_stream_shim_keys(&self) -> &'static [&'static str] {
        self.array_stream_shim_keys
    }

    /// The names of every protocol that ships a wire codec.
    pub(crate) fn codec_protocols(&self) -> &'static [&'static str] {
        self.codec_protocols
    }
}

/// The process registry, built on first read from the built-ins plus anything installed.
static REGISTRY: std::sync::OnceLock<Registry> = std::sync::OnceLock::new();

/// The process registry. One acquire-load once initialized.
pub(crate) fn registry() -> &'static Registry {
    REGISTRY.get_or_init(|| Registry::new(BUILTIN_DECLS.iter().copied()))
}

/// RESOLVE A PROTOCOL BY NAME — the one by-name protocol resolution in busbar, and the function the
/// `match` at `proto/mod.rs` became. Allocates nothing: everything a caller can read off the
/// declaration is a `&'static` constant that was declared, not built.
pub(crate) fn decl_for(name: &str) -> Option<&'static ProtocolDecl> {
    registry().decl(name)
}
