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
//! facts core reads TODAY. The plugin extraction (step 4; the `busbar-llm` protocol crate) happened
//! WITHOUT `route`/`read`/`Decoded` (the ABI design's per-request methods), deliberately: it moved
//! the dialect behind the existing `ProtocolReader`/`ProtocolWriter` pair, the compiler-measured
//! cheaper seam (`design/1.6.0-llm-extraction-plan.md` §2.1). `Dispatch::{Linked,Dlopen}` and the
//! signed manifest arrive with Tier B, whose first real consumer is still ahead — the registry
//! taking an ITERATOR of declarations (and [`install_protocols`] being the composition root's
//! write into it) is what keeps that possible without a core edit. Protocols are a plugin KIND
//! like store and auth: the extracted crates are its built-in members, registered by the binary
//! the way built-in stores are, and a loaded member would reach [`Registry::new`] through the same
//! constructor. [`ProtocolDecl::verbs`] now carries the `Verb { op, name }` PAIR — see its field
//! doc for what still anchors the seven LLM consts in `operation.rs`.

// WHICH INBOUND AUTH SCHEME a protocol's clients present. DECLARED metadata, never a branch: the
// verification itself stays in the auth layer. Relocated to the neutral `busbar_substrate::proto`
// leaf (Batch A) so `busbar-mcp` names it without depending on `busbar-core`; re-exported here so
// `registry::IngressAuth`, the `ProtocolDecl` field, and every plugin caller are unchanged.
pub use busbar_substrate::proto::IngressAuth;

// `ProtocolDecl` and its `EgressAuthHeaders` builder type RELOCATED DOWN to the neutral
// `busbar_substrate::proto` leaf (Batch C-6) so an extracted protocol crate (`busbar-mcp`, the
// `busbar-llm` dialects) names the declaration WITHOUT reaching into `busbar-core`. Every field type
// is now substrate/`busbar-api`/`axum`/`std`. Re-exported here at their historical
// `busbar_core::proto::registry::{ProtocolDecl, EgressAuthHeaders}` paths so the registry singleton
// below (which HOLDS `&'static ProtocolDecl`), the built-in table, and every core / plugin caller are
// unchanged. The one core-typed field the decl used to carry — `path_ingress` (which named the
// core-only `Arrival`) — is SPLIT OFF into a core-owned, protocol-name-keyed side-registration
// (`crate::ingress::path_ingress`); see there and [`install_protocols_with_path_ingress`].
pub use busbar_substrate::proto::{EgressAuthHeaders, ProtocolDecl};

/// THE BUILT-INS — one line per protocol, and every line is DATA.
///
/// This is the whole of core's knowledge of which protocols exist. It is deliberately not a match,
/// not a `#[cfg]`-gated arm, and not a constructor: it is a list of references to declarations that
/// live in the protocols' own modules. When a protocol becomes a plugin crate (step 4), its line
/// here becomes an entry in that crate's own declaration set (`busbar_llm::DECLS`) and nothing else
/// in core moves; when a protocol is LOADED, it never appears here at all and reaches
/// [`Registry::new`] through the same iterator.
static BUILTIN_DECLS: &[&ProtocolDecl] = &[
    // Order is the operator-visible order: it is the order `known_protocols()` reports, and
    // `telemetry` indexes its per-protocol metric families by position in that list.
    // ── THE LLM PROTOCOL'S DIALECTS THAT NOW LIVE IN THE `busbar-llm` PLUGIN ───────────────────
    // These rows exist ONLY in the builds that compile those dialects back in for the fixture
    // surface (see the `mod anthropic` decl in proto/mod.rs and the dual-compile note there). In
    // the production binary the composition root installs `busbar_llm::DECLS` through
    // [`install_protocols`], folded AHEAD of this table — so the operator-visible protocol order
    // is the same in both shapes, and `merged_boot_decls` skips whichever copy registers second.
    //
    // THEY ARE LISTED IN `busbar_llm::DECLS`' OWN ORDER, and that is a requirement, not tidiness:
    // this table and that slice are two statements of ONE sequence. Core cannot check that itself
    // (it must not name the plugin), so the check is black-box on the shipped binary —
    // `crates/busbar/tests/cli_validate.rs::the_operator_visible_protocol_order_is_exactly_the_
    // shipped_one` reads the `must be one of:` refusal an operator would read. Before the
    // consolidation the two orders DID disagree (this table said anthropic, openai, gemini; the
    // composition root installed anthropic, gemini, openai), which was harmless only because
    // nothing compared them.
    #[cfg(any(test, feature = "test-support"))]
    &crate::proto::anthropic::DECL,
    #[cfg(any(test, feature = "test-support"))]
    &crate::proto::gemini::DECL,
    #[cfg(any(test, feature = "test-support"))]
    &crate::proto::openai_chat::DECL,
    // ── The remaining LLM dialects also live in the `busbar-llm` plugin now — same rationale as
    //    the three rows above; these fixture-surface copies exist ONLY in the builds that compile
    //    the dialects back in, and their ORDER matches `busbar_llm::DECLS` exactly (this table and
    //    that slice are two statements of one operator-visible sequence).
    #[cfg(any(test, feature = "test-support"))]
    &crate::proto::bedrock::DECL,
    #[cfg(any(test, feature = "test-support"))]
    &crate::proto::openai_responses::DECL,
    #[cfg(any(test, feature = "test-support"))]
    &crate::proto::cohere::DECL,
    // MCP declares a handler and NO codec: its IR is its own and there is no cross-dialect
    // translation into or out of it. That asymmetry is the point — the registry holds protocols,
    // not codecs, and a protocol that translates to nothing is still a protocol.
    //
    // MCP IS AN EXTRACTED CRATE (`busbar-mcp`, the codec half) on the same terms as anthropic above,
    // and this row exists only in the builds that compile the dialect back in for the fixture surface
    // (see the `mod mcp` decl in handlers/mod.rs). In the production binary the composition root
    // installs the crate's own `PROTO_DECL` through [`install_protocols`], folded AHEAD of this table.
    // The `mcp/` PLANE is a different thing and is still core's — the crate carries the protocol.
    #[cfg(any(test, feature = "test-support"))]
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
    /// EVERY VERB ANY DECLARED PROTOCOL SERVES, in declaration order, deduped. The half of the
    /// operation vocabulary that is DECLARED rather than owned by the core: `Operation::ALL` holds
    /// the six shape verbs core itself defines, and this holds whatever the registered protocols
    /// brought with them (the seven LLM words today). Deleting a protocol deletes its verbs from
    /// this list with it — which is what makes the deletion test mean something at the vocabulary
    /// level rather than compiling against a core table that still names the deleted family.
    #[cfg_attr(not(test), allow(dead_code))]
    // read by the vocabulary pins until a prod consumer lands
    declared_verbs: &'static [crate::operation::Operation],
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
        // Declaration order, deduped BY VALUE (not sorted): the verb vocabulary is operator-visible
        // the same way the protocol list is, so it keeps the deterministic order the declarations
        // state rather than an alphabetical one nobody declared.
        let mut declared_verbs: Vec<crate::operation::Operation> = Vec::new();
        for d in &decls {
            head_keys.extend_from_slice(d.head_keys);
            head_keys.extend(d.array_stream_shim_key);
            streaming_content_types.extend(d.streaming_content_type);
            array_stream_shim_keys.extend(d.array_stream_shim_key);
            if d.codec.is_some() {
                codec_protocols.push(d.name);
            }
            for v in d.verbs {
                if !declared_verbs.contains(v) {
                    declared_verbs.push(*v);
                }
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
            declared_verbs: declared_verbs.leak(),
        }
    }

    /// Resolve a declaration by name. A linear scan over a handful of interned `&'static str`s —
    /// the same comparison chain the `match` compiled to, with the arms as data.
    pub(crate) fn decl(&self, name: &str) -> Option<&'static ProtocolDecl> {
        // Interned-name fast path: hot callers hold the registry's own `&'static` name
        // (`Lane.protocol`, the route table), so pointer identity settles the row without a byte
        // compare; a foreign string (config parse, a test literal) falls through to the equality
        // arm of the same pass. Same result either way.
        self.decls
            .iter()
            .copied()
            .find(|d| d.name.as_ptr() == name.as_ptr() || d.name == name)
    }

    /// Every declaration, in declaration order.
    #[allow(dead_code)] // used by the netted dialect test crates; unused in the core target
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

    /// Every verb any declared protocol serves, in declaration order, deduped. See the field doc.
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn declared_verbs(&self) -> &'static [crate::operation::Operation] {
        self.declared_verbs
    }
}

/// THE VERBS THE REGISTERED PROTOCOLS DECLARE — the declared half of the operation vocabulary
/// (`Operation::ALL`, the six shape verbs, is the core-owned half). Together they are the closed
/// metric-label surface `operation.rs`'s header promises; separately they say WHO owns each word.
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) fn declared_verbs() -> &'static [crate::operation::Operation] {
    registry().declared_verbs()
}

/// The process registry, built on first read from the built-ins plus anything installed.
static REGISTRY: std::sync::OnceLock<Registry> = std::sync::OnceLock::new();

/// Declarations the COMPOSITION ROOT installed before the registry was first read — the protocol
/// crates' entry point. Set once by [`install_protocols`]; folded ahead of the built-ins by
/// [`registry`]'s initializer.
/// A `Vec`, not a `&'static [_]`, because the composition root ASSEMBLES this list: one protocol
/// plugin contributes a whole slice of dialect declarations (the LLM protocol's six) and another
/// contributes a single one, and which of them are linked is a feature decision. Concatenating
/// those into one array literal is not something a `const` can express, and leaking a `Box` to
/// manufacture a `'static` slice would be a lie about the lifetime to satisfy a signature. The
/// ELEMENTS are still `&'static ProtocolDecl` — every declaration is a `const` in its own crate,
/// which is the property the registry actually relies on.
static INSTALLED: std::sync::OnceLock<Vec<&'static ProtocolDecl>> = std::sync::OnceLock::new();

/// INSTALL PROTOCOL DECLARATIONS — the composition root's one write into the protocol axis, and
/// the seam an extracted protocol crate registers through. The `busbar` binary calls this from
/// `main`, before any config read, with the `&DECL` of every protocol crate it links; core itself
/// never names a protocol crate (the split's exit criterion pins the protocol-crate-name grep
/// over this crate's sources at zero), so this parameter is the ONLY way an extracted protocol
/// reaches the registry.
///
/// ORDER: installed declarations are folded AHEAD of the built-ins, and the caller's own order is
/// preserved within them. The protocol list is operator-visible (`known_protocols()` order is
/// dashboards' metric-family order and the config-error `must be one of:` order), and `anthropic`
/// has led it since 1.0 — prepending keeps the shipped binary's list byte-identical to the
/// monolith's instead of demoting a protocol to the tail on the day it becomes a plugin.
///
/// A NAME THE BUILT-INS ALREADY DECLARE IS SKIPPED, deliberately and audibly (`tracing::info`),
/// not asserted on: under `cargo test`'s feature unification the `test-support` build of core
/// compiles the extracted dialect back in as a built-in (so the test fixtures that predate the
/// extraction still run) while the composition root still registers the crate's own copy — the
/// same protocol from two identical sources. Refusing the whole boot for that would fail builds
/// whose behavior is identical; letting both in would trip `Registry::new`'s duplicate-name
/// assert. Skipping the later copy keeps the assert meaningful for the case it exists for: two
/// DIFFERENT protocols claiming one name.
///
/// # Panics
/// - if called twice: two composition roots is a wiring bug, not a merge to attempt.
/// - if called after the registry was first read: a declaration installed after another layer
///   resolved against the smaller set would mean two layers of one process disagree about which
///   protocols exist — fail loudly at the boot line that got the order wrong.
#[allow(dead_code)] // pub-widened and called by the busbar binary once the first protocol crate registers through it
pub fn install_protocols(decls: Vec<&'static ProtocolDecl>) {
    assert!(
        INSTALLED.set(decls).is_ok(),
        "install_protocols called twice: there is one composition root, and it registers once"
    );
    assert!(
        REGISTRY.get().is_none(),
        "install_protocols called after the protocol registry was first read; register in main \
         before any config load or validation touches a protocol"
    );
}

/// THE COMPOSITION ROOT'S ONE WRITE INTO BOTH PROTOCOL SEAMS — the declarations AND their path-model
/// arrivals, registered together so the second seam [`install_protocols`] gained when `path_ingress`
/// split off `ProtocolDecl` (Batch C-6, relocation to `busbar-substrate`) cannot drift from the
/// first. Folds the two installs into one call and, before either lands, asserts the PARITY that
/// keeps the split honest:
///
/// **Every declaration whose model is in the URL path (`has_model_in_url`) MUST register a
/// `path_ingress` arrival.** A path-model protocol installed WITHOUT its arrival would resolve no
/// arrival in [`crate::ingress::dispatch::protocol_dispatch`] and SILENTLY fall through to the
/// body-model branch — a wrong-behavior 404-shaped bug, not a compile error, and exactly the class of
/// "two statements of one fact disagree" the registry design exists to prevent. Asserting it here
/// makes that drift a LOUD PANIC at boot.
///
/// # Panics
/// - if a `has_model_in_url` decl has no registered arrival (the parity failure above).
/// - if either underlying install was already called (two composition roots).
#[allow(dead_code)] // pub-widened and called by the busbar binary's `register_protocols`
pub fn install_protocols_with_path_ingress(
    decls: Vec<&'static ProtocolDecl>,
    path_ingress: Vec<(&'static str, crate::ingress::path_ingress::PathIngress)>,
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
    crate::ingress::path_ingress::install_path_ingress(path_ingress);
}

/// THE BOOT PARITY RULE, as a pure function so a test can drive it without touching the process
/// singletons: the NAME of the first declaration whose model is in the URL (`has_model_in_url`) that
/// has NO arrival among `path_ingress_names`, or `None` when every URL-model protocol has one. This is
/// the invariant [`install_protocols_with_path_ingress`] asserts at boot — the guard that a
/// path-model protocol installed without its arrival cannot silently 404 (see the module header and
/// `crate::ingress::path_ingress`).
pub(crate) fn first_path_model_without_arrival(
    decls: &[&'static ProtocolDecl],
    path_ingress_names: &[&str],
) -> Option<&'static str> {
    decls
        .iter()
        .find(|d| d.has_model_in_url && !path_ingress_names.contains(&d.name))
        .map(|d| d.name)
}

/// THE BOOT FOLD: installed declarations ahead of built-ins, one entry per NAME, later same-name
/// registrations skipped audibly (see [`install_protocols`]' doc for why skipped rather than
/// asserted). Split from [`registry`]'s `OnceLock` so its order and skip semantics are a function a
/// test can drive — the process singleton can only ever be initialized once per test binary, which
/// would leave these rules provable only by booting binaries.
pub(crate) fn merged_boot_decls(
    installed: &[&'static ProtocolDecl],
    builtins: &[&'static ProtocolDecl],
) -> Vec<&'static ProtocolDecl> {
    let mut decls: Vec<&'static ProtocolDecl> = Vec::new();
    for d in installed.iter().chain(builtins) {
        if decls.iter().any(|p| p.name == d.name) {
            tracing::info!(
                protocol = d.name,
                "skipping a later registration of an already-declared protocol \
                 (composition-root copy and built-in copy of one dialect)"
            );
            continue;
        }
        decls.push(d);
    }
    decls
}

/// The process registry. One acquire-load once initialized.
pub(crate) fn registry() -> &'static Registry {
    REGISTRY.get_or_init(|| {
        let installed: &[&'static ProtocolDecl] = INSTALLED.get().map(Vec::as_slice).unwrap_or(&[]);
        Registry::new(merged_boot_decls(installed, BUILTIN_DECLS))
    })
}

/// RESOLVE A PROTOCOL BY NAME — the one by-name protocol resolution in busbar, and the function the
/// `match` at `proto/mod.rs` became. Allocates nothing: everything a caller can read off the
/// declaration is a `&'static` constant that was declared, not built.
pub fn decl_for(name: &str) -> Option<&'static ProtocolDecl> {
    registry().decl(name)
}
