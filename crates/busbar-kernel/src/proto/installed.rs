// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE INSTALLED PROTOCOL SET — the process registry of `ProtocolDecl`s the composition root
//! installs, its boot-time aggregates, the lookups every by-name protocol read goes through, the
//! test-support registration seam, and the host services the install arms for the codecs behind the
//! contract seams (#83a O1: the registry is kernel semantics). The declaration SHAPES are the
//! contract's (`busbar_contract::protocol`). Moved verbatim from `busbar-substrate-values` when that
//! crate was deleted (SD-8); `proto/registry.rs` keeps only the population glue core owns.

use busbar_contract::protocol::{ProtocolDecl, StreamTranslator};

// ── TEST-SUPPORT PROTOCOL REGISTRATION (the neutral seam) ──────────────────────────────────────────
// A protocol crate's test-kit registers its `&'static ProtocolDecl` here — a SUBSTRATE type — exactly
// as production's composition root `install_protocols` does, so the extracted protocol crates
// (`busbar-llm`, `busbar-mcp`) reach the neutral ABI (`busbar_kernel::proto::register_test_protocol`)
// rather than back into `busbar_kernel::proto::registry`. `busbar-core`'s test-support `registry()` folds
// this list ahead of its built-ins on every read, so a protocol registered by any test before it reads
// the registry is visible regardless of test order. This is the exact analogue of the plane axis's
// `busbar_kernel::plane::registry::register_test_plane`, and it is what let the `#[path]` witness
// re-includes of the dialect sources into `busbar-core` be deleted: the externally-linked crate's
// `&DECL` is now the SAME `ProtocolDecl` type (this one), so core no longer needs a re-compiled copy.
#[cfg(any(test, feature = "test-support"))]
static TEST_REGISTERED_PROTOCOLS: std::sync::Mutex<Vec<&'static ProtocolDecl>> =
    std::sync::Mutex::new(Vec::new());

/// TEST-SUPPORT SEAM — register an extracted protocol's declaration into the process registry, the way
/// the composition root's `install_protocols` does in production. Idempotent by protocol name; a
/// protocol crate's test setup calls it (eagerly, and/or from its App-building finalizer) so the
/// fixture registry matches a shipped "busbar with this protocol" binary. The storage lives HERE, on
/// the neutral substrate, so a protocol crate names no `busbar_kernel::` implementation to register
/// itself.
#[cfg(any(test, feature = "test-support"))]
pub fn register_test_protocol(decl: &'static ProtocolDecl) {
    arm_host_services();
    // A name the composition root already installed is declared: this seam stands in for a root
    // in binaries that have none, and re-declaring behind a real root would make the boot fold
    // report a duplicate the operator never caused (a test-built binary would then carry boot
    // lines the shipped one does not).
    let installed_already = INSTALLED
        .get()
        .is_some_and(|installed| installed.iter().any(|d| d.name == decl.name));
    if installed_already {
        return;
    }
    let mut reg = TEST_REGISTERED_PROTOCOLS
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    if !reg.iter().any(|d| d.name == decl.name) {
        reg.push(decl);
    }
}

/// TEST-SUPPORT SEAM — register a whole SLICE of an extracted protocol crate's declarations at once
/// (the LLM protocol contributes six dialect declarations). Idempotent per name, order-preserving.
#[cfg(any(test, feature = "test-support"))]
pub fn register_test_protocols(decls: &[&'static ProtocolDecl]) {
    for d in decls {
        register_test_protocol(d);
    }
}

/// TEST-SUPPORT SEAM — the protocols registered through [`register_test_protocol`], snapshot in
/// registration order. `busbar-core`'s test-support `registry()` reads this to fold the extracted
/// protocols into the process registry.
#[cfg(any(test, feature = "test-support"))]
pub fn test_registered_protocols() -> Vec<&'static ProtocolDecl> {
    TEST_REGISTERED_PROTOCOLS
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .clone()
}

/// TEST-SUPPORT SEAM — the COUNT of registered protocols, without cloning the list. `busbar-core`'s
/// test-support `registry()` reads this on its memoized fast path (the one `decl_for` drives several
/// times per request) so resolving a registry that has NOT grown allocates nothing — the alloc-gated
/// hot-path invariant the production `OnceLock` had, preserved under the re-folding test surface.
#[cfg(any(test, feature = "test-support"))]
pub fn test_registered_protocols_len() -> usize {
    TEST_REGISTERED_PROTOCOLS
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .len()
}

// ── THE PROTOCOL REGISTRY SINGLETON — RELOCATED DOWN from `busbar_kernel::proto::registry` ───────────
// The declarations, the boot-time aggregates, and the process singleton, moved onto the neutral
// substrate so an extracted protocol crate (`busbar-llm`) resolves `decl_for` / `known_protocols`
// through the neutral ABI rather than reaching BACK into `busbar-core` implementation (the
// reverse-edge rule). `busbar-core` re-exports every item below at its historical
// `busbar_kernel::proto::registry::…` path, so every in-core / plugin caller compiles unchanged and the
// values are byte-identical. The one item that could NOT travel is the built-in table: production
// carries none (every protocol is a plugin the composition root installs through `install_protocols`),
// and core's OWN test binary names its shipped set in a `tests/` file the neutral-purity lint excludes,
// which reaches this singleton through the [`set_test_builtins`] hook below — so the neutral source here
// spells no protocol crate. `install_protocols_with_path_ingress` (which names the core-only `Arrival`)
// stays in `busbar-core`.

/// THE REGISTRY: the declarations, plus the aggregates that used to be three separate `OnceLock`
/// sweeps. Built once; every field is derived from the declarations and from nothing else, so there
/// is no second place a protocol fact can be stated.
pub struct Registry {
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
    /// this list with it.
    #[cfg_attr(not(any(test, feature = "test-support")), allow(dead_code))]
    declared_verbs: &'static [busbar_contract::operation::OpVerb],
}

impl Registry {
    /// Build a registry from declarations. Production hands it the built-ins plus anything loaded;
    /// a test hands it the built-ins plus a protocol nobody wrote. THE CONSTRUCTOR IS THE SAME ONE,
    /// which is the property being claimed: joining costs a declaration and nothing else.
    pub fn new(decls: impl IntoIterator<Item = &'static ProtocolDecl>) -> Self {
        let decls: Vec<&'static ProtocolDecl> = decls.into_iter().collect();
        let mut head_keys: Vec<&'static str> = Vec::new();
        let mut streaming_content_types: Vec<&'static str> = Vec::new();
        let mut array_stream_shim_keys: Vec<&'static str> = Vec::new();
        let mut codec_protocols: Vec<&'static str> = Vec::new();
        // Declaration order, deduped BY VALUE (not sorted): the verb vocabulary is operator-visible
        // the same way the protocol list is, so it keeps the deterministic order the declarations
        // state rather than an alphabetical one nobody declared.
        let mut declared_verbs: Vec<busbar_contract::operation::OpVerb> = Vec::new();
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
        // expect with no `unsafe` anywhere.
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
    pub fn decl(&self, name: &str) -> Option<&'static ProtocolDecl> {
        // Interned-name fast path: hot callers hold the registry's own `&'static` name, so pointer
        // identity settles the row without a byte compare; a foreign string falls through to the
        // equality arm of the same pass. Same result either way.
        //
        // A `&str` is a POINTER *and* a LENGTH — the fast path must compare both. A subslice of an
        // interned name (e.g. a caller stripping a suffix off an already-resolved name) starts at
        // the SAME address as the name it was sliced from, so a data-pointer match alone would
        // answer "root" with the declaration filed under "rooted": a protocol name nothing declared,
        // resolved to another protocol's codec, auth scheme and verbs.
        self.decls.iter().copied().find(|d| {
            (d.name.as_ptr() == name.as_ptr() && d.name.len() == name.len()) || d.name == name
        })
    }

    /// Every declaration, in declaration order.
    #[allow(dead_code)] // used by the netted dialect test crates; unused in the core target
    pub fn decls(&self) -> &[&'static ProtocolDecl] {
        &self.decls
    }

    /// The complete set of top-level body keys the head projection captures.
    pub fn head_keys(&self) -> &'static [&'static str] {
        self.head_keys
    }

    /// The streaming `Content-Type` set across every declared protocol.
    pub fn streaming_content_types(&self) -> &'static [&'static str] {
        self.streaming_content_types
    }

    /// The array-stream shim keys across every declared protocol.
    pub fn array_stream_shim_keys(&self) -> &'static [&'static str] {
        self.array_stream_shim_keys
    }

    /// The names of every protocol that ships a wire codec.
    pub fn codec_protocols(&self) -> &'static [&'static str] {
        self.codec_protocols
    }

    /// Every verb any declared protocol serves, in declaration order, deduped. See the field doc.
    #[cfg_attr(not(any(test, feature = "test-support")), allow(dead_code))]
    pub fn declared_verbs(&self) -> &'static [busbar_contract::operation::OpVerb] {
        self.declared_verbs
    }
}

/// THE VERBS THE REGISTERED PROTOCOLS DECLARE — the declared half of the operation vocabulary
/// (`Operation::ALL`, the six shape verbs, is the core-owned half).
#[cfg_attr(not(any(test, feature = "test-support")), allow(dead_code))]
pub fn declared_verbs() -> &'static [busbar_contract::operation::OpVerb] {
    registry().declared_verbs()
}

/// The process registry, built on first read from the built-ins plus anything installed. Production
/// only: under the test-support surface [`registry`] re-folds on every read, so there is no frozen
/// memo there — the FIRST-READ witness [`install_protocols`] asserts on is [`TEST_REGISTRY_MEMO`].
#[cfg(not(any(test, feature = "test-support")))]
static REGISTRY: std::sync::OnceLock<Registry> = std::sync::OnceLock::new();

/// Declarations the COMPOSITION ROOT installed before the registry was first read — the protocol
/// crates' entry point. Set once by [`install_protocols`]; folded ahead of the built-ins by
/// [`registry`]'s initializer.
static INSTALLED: std::sync::OnceLock<Vec<&'static ProtocolDecl>> = std::sync::OnceLock::new();

/// Arm the HOST SERVICES a protocol cell reaches through the contract: the usage-tap fault reporter
/// (`handlers::report_usage_tap_decode_failure`) a cell's default usage tap reports through, the
/// usage-tap fault latch (`handlers::usage_tap_decode_fail_should_warn`) a codec whose tap reads a
/// body more than one way counts each way through, the translate-body cap reader
/// (`proxy::max_translate_body_bytes`, the live operator knob), the host entropy source (the OS
/// CSPRNG) and the host wall clock (`store::now`). Called wherever protocols become reachable —
/// [`install_protocols`] and the test registration seams — so no cell can be dispatched before they
/// are armed. Idempotent.
fn arm_host_services() {
    busbar_contract::codec::install_usage_tap_fault_reporter(
        crate::handlers::report_usage_tap_decode_failure,
    );
    busbar_contract::codec::install_usage_tap_fault_latch(
        crate::handlers::usage_tap_decode_fail_should_warn,
    );
    busbar_contract::codec::install_translate_cap_reader(crate::proxy::max_translate_body_bytes);
    busbar_contract::codec::install_entropy_source(os_entropy);
    busbar_contract::codec::install_wall_clock(crate::store::now);
}

/// The host entropy source: the OS CSPRNG, one `getrandom` fill per call.
fn os_entropy(out: &mut [u8]) -> bool {
    getrandom::fill(out).is_ok()
}

/// INSTALL PROTOCOL DECLARATIONS — the composition root's one write into the protocol axis, and the
/// seam an extracted protocol crate registers through. The `busbar` binary calls this from `main`,
/// before any config read, with the `&DECL` of every protocol crate it links.
///
/// ORDER: installed declarations are folded AHEAD of the built-ins, and the caller's own order is
/// preserved within them.
///
/// # Panics
/// - if called twice: two composition roots is a wiring bug, not a merge to attempt.
/// - if called after the registry was first read.
#[allow(dead_code)] // pub-widened and called by the busbar binary once the first protocol crate registers through it
pub fn install_protocols(decls: Vec<&'static ProtocolDecl>) {
    arm_host_services();
    assert!(
        INSTALLED.set(decls).is_ok(),
        "install_protocols called twice: there is one composition root, and it registers once"
    );
    // The "install before first read" invariant is enforced by the production memo.
    #[cfg(not(any(test, feature = "test-support")))]
    assert!(
        REGISTRY.get().is_none(),
        "install_protocols called after the protocol registry was first read; register in main \
         before any config load or validation touches a protocol"
    );
    #[cfg(any(test, feature = "test-support"))]
    assert!(
        TEST_REGISTRY_MEMO
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .is_none(),
        "install_protocols called after the protocol registry was first read; register in main \
         before any config load or validation touches a protocol"
    );
}

/// THE BOOT PARITY RULE, as a pure function so a test can drive it without touching the process
/// singletons: the NAME of the first declaration whose model is in the URL (`has_model_in_url`) that
/// has NO arrival among `path_ingress_names`, or `None` when every URL-model protocol has one.
pub fn first_path_model_without_arrival(
    decls: &[&'static ProtocolDecl],
    path_ingress_names: &[&str],
) -> Option<&'static str> {
    decls
        .iter()
        .find(|d| d.has_model_in_url && !path_ingress_names.contains(&d.name))
        .map(|d| d.name)
}

/// THE BOOT FOLD: installed declarations ahead of built-ins, one entry per NAME, later same-name
/// registrations skipped audibly. Split from [`registry`]'s `OnceLock` so its order and skip
/// semantics are a function a test can drive.
pub fn merged_boot_decls(
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

/// The process registry. One acquire-load once initialized. Production carries no built-in rows.
#[cfg(not(any(test, feature = "test-support")))]
pub fn registry() -> &'static Registry {
    REGISTRY.get_or_init(|| {
        let installed: &[&'static ProtocolDecl] = INSTALLED.get().map(Vec::as_slice).unwrap_or(&[]);
        Registry::new(merged_boot_decls(installed, &[]))
    })
}

// ── TEST-SUPPORT PROCESS REGISTRY ─────────────────────────────────────────────────────────────────
// Under the test-support surface `registry` re-folds the registered set (and any `install_protocols`
// set) ahead of the built-ins on every read, recomputing (and leaking once) only when the set GROWS —
// so a protocol registered by any test before it reads the registry is visible regardless of test
// order, and the `&'static` contract holds. Bounded: at most one leak per distinct registered-set size.
#[cfg(any(test, feature = "test-support"))]
static TEST_REGISTRY_MEMO: std::sync::Mutex<Option<(usize, &'static Registry)>> =
    std::sync::Mutex::new(None);

/// CORE'S OWN-TEST-BINARY BUILT-IN HOOK. Core's `cfg(test)` build names its shipped protocol set
/// (`busbar_llm::DECLS` + the MCP protocol) in a `tests/` file the neutral-purity lint excludes, and
/// installs it here as the stable TAIL of the boot fold — exactly as the pre-relocation core registry
/// folded `builtin_decls()`. The neutral substrate spells no protocol crate; it only holds the fn
/// pointer core hands it. Unset in every other build (busbar-llm's own test binary registers its
/// dialects through [`register_test_protocol`] and needs no core tail).
#[cfg(any(test, feature = "test-support"))]
static TEST_BUILTINS_HOOK: std::sync::OnceLock<fn() -> &'static [&'static ProtocolDecl]> =
    std::sync::OnceLock::new();

/// Install the core-test built-in provider (idempotent). Called by `busbar-core`'s `cfg(test)`
/// registry accessors so the shipped protocol set (and its operator-visible ORDER) is folded as the
/// boot-fold tail. Setting it GROWS the memo's target size, so a registry already folded without the
/// tail re-folds WITH it on the next read — the read is self-healing regardless of call order.
#[cfg(any(test, feature = "test-support"))]
pub fn set_test_builtins(f: fn() -> &'static [&'static ProtocolDecl]) {
    arm_host_services();
    let _ = TEST_BUILTINS_HOOK.set(f);
}

#[cfg(any(test, feature = "test-support"))]
fn test_builtins() -> &'static [&'static ProtocolDecl] {
    TEST_BUILTINS_HOOK.get().map(|f| f()).unwrap_or(&[])
}

#[cfg(any(test, feature = "test-support"))]
pub fn registry() -> &'static Registry {
    // THE MEMOIZED FAST PATH IS ALLOCATION-FREE: the registered-set SIZE (plus the installed set and
    // the core-test built-in tail) is read without cloning any list, and a set that has not grown
    // returns the memoized `&'static Registry` with no fold and no allocation.
    let want = test_registered_protocols_len()
        + INSTALLED.get().map(Vec::len).unwrap_or(0)
        + test_builtins().len();
    let mut memo = TEST_REGISTRY_MEMO.lock().unwrap_or_else(|e| e.into_inner());
    if let Some((n, reg)) = *memo {
        if n == want {
            return reg;
        }
    }
    // SLOW PATH (the set GREW): fold explicit `install_protocols` registrations AND
    // `register_test_protocol` registrations ahead of the built-in tail, then leak ONCE for this
    // grown set — the same `Vec::leak`-shaped process-singleton allocation `Registry::new` relies on.
    let installed: &[&'static ProtocolDecl] = INSTALLED.get().map(Vec::as_slice).unwrap_or(&[]);
    let mut all: Vec<&'static ProtocolDecl> = installed.to_vec();
    all.extend(test_registered_protocols().iter().copied());
    let reg: &'static Registry = Box::leak(Box::new(Registry::new(merged_boot_decls(
        &all,
        test_builtins(),
    ))));
    *memo = Some((want, reg));
    reg
}

// RESOLVE A PROTOCOL BY NAME is [`Registry::decl`] (above). The single free-fn wrapper `decl_for` —
// the ONE by-name resolution the `structure-lint` census pins — stays in `busbar-core`
// (`proto::registry::decl_for`) so it can seed core's OWN-test built-in tail before it reads; every
// other crate (`busbar-llm`) resolves through `registry().decl(name)` directly on this neutral ABI.

/// THE GENERIC ROUTER DETECTION FOLD — `(path, headers)` → which registered protocol a request
/// speaks, or `None` for a path that names none. Folds every registered protocol's
/// [`ProtocolDecl::claims`] predicate in REGISTRATION ORDER and keeps the TIGHTEST claim (lowest
/// [`ClaimStrength`]); a tie breaks by registration order. Byte-identical to the old ladder.
pub fn detect_protocol(path: &str, headers: &http::HeaderMap) -> Option<&'static str> {
    registry()
        .decls()
        .iter()
        .filter_map(|d| d.claims.and_then(|c| c(headers, path)).map(|s| (s, d.name)))
        .min_by(|a, b| a.0.cmp(&b.0))
        .map(|(_, name)| name)
}

/// THE GENERIC RESIDUAL DETECTION FOLD — which registered protocol a path names FROM ITS SHAPE ALONE
/// (no headers), the arm the mount table falls through to. Byte-identical to the old ladder.
pub fn residual_protocol_for_path(path: &str) -> Option<&'static str> {
    registry()
        .decls()
        .iter()
        .filter_map(|d| d.residual_claims.and_then(|c| c(path)).map(|s| (s, d.name)))
        .min_by(|a, b| a.0.cmp(&b.0))
        .map(|(_, name)| name)
}

/// THE REGISTRY-SUPPLIED RESIDUAL DEFAULT — the ONE protocol name core falls back to when no dialect
/// claimed a request yet a dialect must still be named. Reads [`ProtocolDecl::residual_default`], so
/// the literal default dialect name leaves core entirely; `None` when no residual-default protocol is
/// installed (the all-planes-off deletion configuration).
pub fn residual_default_protocol() -> Option<&'static str> {
    registry()
        .decls()
        .iter()
        .find(|d| d.residual_default)
        .map(|d| d.name)
}

/// Every protocol name busbar ships a wire CODEC for — the set a provider's `protocol:` may name.
/// DERIVED from the declarations (`ProtocolDecl::codec`), not maintained beside them.
pub fn known_protocols() -> &'static [&'static str] {
    registry().codec_protocols()
}

// ── THE REGISTRY-RESOLVED PROTO ACCESSORS — RELOCATED DOWN from `busbar_kernel::proto` ───────────────
// Thin reads of the registry singleton above, moved onto the neutral substrate so an extracted
// protocol crate (`busbar-llm`) resolves a protocol fact through the neutral ABI rather than reaching
// BACK into `busbar-core` (the reverse-edge rule). `busbar-core` re-exports each at its historical
// `busbar_kernel::proto::…` path, so every in-core / plugin caller compiles unchanged and the values are
// byte-identical. They read the SAME singleton `registry()` returns, so — exactly as `known_protocols`
// already does — under core's own test binary they observe the core-test built-in tail once any core
// accessor has seeded the substrate hook (idempotent, self-healing).

// ── THE NEUTRAL STREAMING-TRANSLATOR FACTORY — RELOCATED DOWN from `busbar_kernel::proto` ────────────
// The plugin-provided fn-ptr factory that builds a concrete stream translator for an ingress→egress
// pair, and the single construction seam both forward paths call. Moved onto the neutral substrate so
// the `busbar-llm` plugin installs its factory and drives the seam through the neutral ABI rather than
// reaching BACK into `busbar-core`. The `OnceLock` moving DOWN to the single-compiled substrate is a
// strict improvement for the "one instance" invariant (core is dual-compilable). `busbar-core` keeps
// its `#[cfg(test)]` fixture-routing arm (its own test binary routes straight to the netted concrete
// factory) and re-exports the production arm + the installer at their historical paths.

/// The plugin-provided factory that builds a concrete stream translator for an ingress→egress pair.
type StreamTranslatorFactory = fn(&str, &str, bool) -> Option<Box<dyn StreamTranslator>>;

static STREAM_TRANSLATOR_FACTORY: std::sync::OnceLock<StreamTranslatorFactory> =
    std::sync::OnceLock::new();

/// Install the plugin's streaming-translator factory. Idempotent-by-first-write (the composition root
/// registers once); a second install is ignored so a test harness cannot clobber a live pointer.
pub fn install_stream_translator_factory(f: StreamTranslatorFactory) {
    let _ = STREAM_TRANSLATOR_FACTORY.set(f);
}

/// THE SINGLE streaming-translator construction seam the forward paths call. Neutral in and out. It
/// routes to the installed pointer (returns `None` — legacy raw passthrough — when no plugin installed
/// one, e.g. a core-only build with no dialects).
pub fn new_stream_translator(
    ingress: &str,
    egress: &str,
    is_sse: bool,
) -> Option<Box<dyn StreamTranslator>> {
    STREAM_TRANSLATOR_FACTORY
        .get()
        .and_then(|f| f(ingress, egress, is_sse))
}

/// RESOLVE A PROTOCOL BY NAME through the substrate registry singleton. A pure read of a
/// `&'static ProtocolDecl`; allocates nothing. `busbar-core` keeps its own `decl_for` wrapper (which
/// additionally seeds the core-test built-in hook under `#[cfg(test)]`); this is the plane-facing
/// entry, behaviorally identical for any consumer that compiles `busbar-core` as a non-test dependency.
pub fn decl_for(name: &str) -> Option<&'static ProtocolDecl> {
    registry().decl(name)
}

/// The set of streaming `Content-Type` values across every declared protocol — a registry aggregate
/// folded once at boot from `ProtocolDecl::streaming_content_type`.
pub fn streaming_content_types() -> &'static [&'static str] {
    registry().streaming_content_types()
}

/// The set of array-stream shim keys across every declared protocol (only Gemini declares one), the
/// aggregate `proxy::strip_router_shim_keys` reads to remove every protocol's marker while naming none.
pub fn array_stream_shim_keys() -> &'static [&'static str] {
    registry().array_stream_shim_keys()
}

/// The array-stream shim key the NAMED protocol declares, or `None` if it declares none or is not
/// registered. The injection site reads it by name so it names no protocol submodule.
pub fn array_stream_shim_key_for(protocol_name: &str) -> Option<&'static str> {
    decl_for(protocol_name).and_then(|d| d.array_stream_shim_key)
}

/// The vendor-plausible auth-failure wire MESSAGE for an ingress protocol, dispatched through
/// `ProtocolDecl::auth_failure_message` so the per-vendor copy lives in the declaration, not here. An
/// unknown protocol falls back to the default generic copy.
pub fn vendor_auth_failure_message(proto: &str) -> &'static str {
    decl_for(proto)
        .map(|d| d.auth_failure_message)
        .unwrap_or("authentication failed")
}

/// Resolve a provider's configured protocol NAME to the registry's interned `&'static str` for the
/// lane-build path, or `None` for an unknown name or one that declares no wire codec (MCP/A2A are not
/// lane protocols).
pub fn lane_protocol_name(name: &str) -> Option<&'static str> {
    decl_for(name).filter(|d| d.codec.is_some()).map(|d| d.name)
}

/// Collect `(HeaderName, HeaderValue)` pairs into an axum `HeaderMap`. A dependency-free neutral
/// helper (no protocol vocabulary), used by the dialect crates on the egress-header path.
pub fn convert_headers(headers: Vec<(http::HeaderName, http::HeaderValue)>) -> http::HeaderMap {
    let mut map = http::HeaderMap::new();
    for (name, value) in headers {
        map.insert(name, value);
    }
    map
}

/// Build the `Authorization: Bearer <key>` header pair for a protocol that presents its credential
/// itself — the builder body is the egress-auth unit's (`busbar_kernel_identity::egress_auth`), so
/// the omission rule has one definition; this adds the report. A key that is not a legal header value
/// (a stray CR/LF/NUL a config system injected) yields NO header — the upstream then 401s — and one
/// coded diagnostic naming the protocol; the key itself is never logged.
pub fn bearer_auth_headers(proto: &str, key: &str) -> Vec<(http::HeaderName, http::HeaderValue)> {
    let built = busbar_kernel_identity::egress_auth::bearer_auth_headers(key);
    if built.is_empty() {
        crate::diagnostics::diag_debug!(
            crate::diagnostics::PROTO_AUTH_INVALID_HEADER_BYTES,
            protocol = proto,
            "authorization credential contains invalid header bytes (ASCII control character); \
             omitting auth header — upstream will reject with 401"
        );
    }
    let typed = |(k, v): (String, String)| Some((k.parse().ok()?, v.parse().ok()?));
    built.into_iter().filter_map(typed).collect()
}

#[cfg(test)]
#[path = "tests/installed_tests.rs"]
mod installed_tests;
