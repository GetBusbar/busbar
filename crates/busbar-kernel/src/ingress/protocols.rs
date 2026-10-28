// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE INSTALLED PROTOCOL SET: the `ProtocolDecl`s the composition root installs once at boot
//! ([`install_protocols`]), the aggregates folded from them, and the lookups ingress reads to decide
//! which dialect a request speaks and how to answer it in that dialect. The declaration shapes are
//! the contract's (`busbar_contract::protocol`). Production carries no built-in protocol.

pub use busbar_contract::protocol::ProtocolDecl;

#[cfg(any(test, feature = "test-support"))]
static TEST_REGISTERED_PROTOCOLS: std::sync::Mutex<Vec<&'static ProtocolDecl>> =
    std::sync::Mutex::new(Vec::new());

/// Register a protocol for a test, as production's [`install_protocols`] does. Idempotent by name;
/// a protocol the root already installed is skipped.
#[cfg(any(test, feature = "test-support"))]
pub fn register_test_protocol(decl: &'static ProtocolDecl) {
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

/// [`register_test_protocol`] for each of `decls`, in order.
#[cfg(any(test, feature = "test-support"))]
pub fn register_test_protocols(decls: &[&'static ProtocolDecl]) {
    for d in decls {
        register_test_protocol(d);
    }
}

#[cfg(any(test, feature = "test-support"))]
fn test_registered_protocols() -> Vec<&'static ProtocolDecl> {
    TEST_REGISTERED_PROTOCOLS
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .clone()
}

/// The declarations plus the aggregates folded from them. Built once; every field is derived from
/// the declarations and from nothing else.
pub struct Registry {
    decls: Vec<&'static ProtocolDecl>,
    /// Every declared head key plus every declared shim key, sorted and deduped.
    head_keys: &'static [&'static str],
    streaming_content_types: &'static [&'static str],
    array_stream_shim_keys: &'static [&'static str],
    /// The protocols that ship a wire codec: the set a provider's `protocol:` may name.
    codec_protocols: &'static [&'static str],
    /// Every verb any declared protocol serves, in declaration order, deduped.
    #[cfg_attr(not(any(test, feature = "test-support")), allow(dead_code))]
    declared_verbs: &'static [busbar_contract::operation::OpVerb],
}

impl Registry {
    /// Build a registry from declarations.
    ///
    /// # Panics
    /// If two declarations claim the same name.
    pub fn new(decls: impl IntoIterator<Item = &'static ProtocolDecl>) -> Self {
        let decls: Vec<&'static ProtocolDecl> = decls.into_iter().collect();
        let mut head_keys: Vec<&'static str> = Vec::new();
        let mut streaming_content_types: Vec<&'static str> = Vec::new();
        let mut array_stream_shim_keys: Vec<&'static str> = Vec::new();
        let mut codec_protocols: Vec<&'static str> = Vec::new();
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
        Self {
            decls,
            head_keys: head_keys.leak(),
            streaming_content_types: streaming_content_types.leak(),
            array_stream_shim_keys: array_stream_shim_keys.leak(),
            codec_protocols: codec_protocols.leak(),
            declared_verbs: declared_verbs.leak(),
        }
    }

    /// The declaration named `name`. An interned name resolves by pointer AND length (a prefix
    /// slice of an interned name shares its pointer), anything else by value.
    pub fn decl(&self, name: &str) -> Option<&'static ProtocolDecl> {
        self.decls.iter().copied().find(|d| {
            (d.name.as_ptr() == name.as_ptr() && d.name.len() == name.len()) || d.name == name
        })
    }

    pub fn decls(&self) -> &[&'static ProtocolDecl] {
        &self.decls
    }

    pub fn head_keys(&self) -> &'static [&'static str] {
        self.head_keys
    }

    pub fn streaming_content_types(&self) -> &'static [&'static str] {
        self.streaming_content_types
    }

    pub fn array_stream_shim_keys(&self) -> &'static [&'static str] {
        self.array_stream_shim_keys
    }

    pub fn codec_protocols(&self) -> &'static [&'static str] {
        self.codec_protocols
    }

    #[cfg_attr(not(any(test, feature = "test-support")), allow(dead_code))]
    pub fn declared_verbs(&self) -> &'static [busbar_contract::operation::OpVerb] {
        self.declared_verbs
    }
}

/// Every verb any installed protocol serves.
#[cfg_attr(not(any(test, feature = "test-support")), allow(dead_code))]
pub fn declared_verbs() -> &'static [busbar_contract::operation::OpVerb] {
    registry().declared_verbs()
}

#[cfg(not(any(test, feature = "test-support")))]
static REGISTRY: std::sync::OnceLock<Registry> = std::sync::OnceLock::new();

/// Declarations the composition root installed before the registry was first read.
static INSTALLED: std::sync::OnceLock<Vec<&'static ProtocolDecl>> = std::sync::OnceLock::new();

/// THE KERNEL'S CODEC HOST: the host services every codec the kernel drives is handed (the OS
/// CSPRNG, the host wall clock and its monotonic clock).
#[derive(Clone, Copy, Debug, Default)]
pub struct CodecHostServices;

/// The kernel's codec host, as the borrowed handle a codec call takes.
pub const CODEC_HOST: &dyn busbar_contract::codec::CodecHost = &CodecHostServices;

impl busbar_contract::codec::CodecHost for CodecHostServices {
    fn fill_entropy(&self, out: &mut [u8]) -> bool {
        getrandom::fill(out).is_ok()
    }

    fn wall_clock_now(&self) -> Option<u64> {
        Some(crate::store::now())
    }

    fn monotonic_ns(&self) -> Option<u64> {
        static ORIGIN: std::sync::OnceLock<std::time::Instant> = std::sync::OnceLock::new();
        let origin = ORIGIN.get_or_init(std::time::Instant::now);
        Some(u64::try_from(origin.elapsed().as_nanos()).unwrap_or(u64::MAX))
    }
}

/// INSTALL PROTOCOL DECLARATIONS: the composition root's one write, from `main`, before any config
/// read, in the caller's order.
///
/// # Panics
/// - if called twice: two composition roots is a wiring bug, not a merge to attempt.
/// - if called after the registry was first read.
pub fn install_protocols(decls: Vec<&'static ProtocolDecl>) {
    assert!(
        INSTALLED.set(decls).is_ok(),
        "install_protocols called twice: there is one composition root, and it registers once"
    );
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

/// THE BOOT FOLD: installed declarations ahead of built-ins, one entry per name, a later same-name
/// registration skipped audibly.
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

/// The process registry. One acquire-load once initialized.
#[cfg(not(any(test, feature = "test-support")))]
pub fn registry() -> &'static Registry {
    REGISTRY.get_or_init(|| {
        let installed: &[&'static ProtocolDecl] = INSTALLED.get().map(Vec::as_slice).unwrap_or(&[]);
        Registry::new(merged_boot_decls(installed, &[]))
    })
}

#[cfg(any(test, feature = "test-support"))]
static TEST_REGISTRY_MEMO: std::sync::Mutex<Option<(usize, &'static Registry)>> =
    std::sync::Mutex::new(None);

/// The kernel's own test binary folds the neutral synthetic protocol set as the boot-fold tail;
/// every other build has none.
#[cfg(any(test, feature = "test-support"))]
fn test_builtins() -> &'static [&'static ProtocolDecl] {
    #[cfg(test)]
    {
        crate::testkit::neutral_protocols::NEUTRAL_PROTOCOLS
    }
    #[cfg(not(test))]
    {
        &[]
    }
}

/// The process registry under the test-support surface: re-folds the registered set (and any
/// installed set) ahead of the test built-ins whenever the set grows, leaking once per size.
#[cfg(any(test, feature = "test-support"))]
pub fn registry() -> &'static Registry {
    let registered = test_registered_protocols();
    let want =
        registered.len() + INSTALLED.get().map(Vec::len).unwrap_or(0) + test_builtins().len();
    let mut memo = TEST_REGISTRY_MEMO.lock().unwrap_or_else(|e| e.into_inner());
    if let Some((n, reg)) = *memo {
        if n == want {
            return reg;
        }
    }
    let installed: &[&'static ProtocolDecl] = INSTALLED.get().map(Vec::as_slice).unwrap_or(&[]);
    let mut all: Vec<&'static ProtocolDecl> = installed.to_vec();
    all.extend(registered);
    let reg: &'static Registry = Box::leak(Box::new(Registry::new(merged_boot_decls(
        &all,
        test_builtins(),
    ))));
    *memo = Some((want, reg));
    reg
}

/// The installed declaration named `name`.
pub fn decl_for(name: &str) -> Option<&'static ProtocolDecl> {
    registry().decl(name)
}

/// `(path, headers)` -> which installed protocol a request speaks, or `None` for a path that names
/// none: the tightest [`ProtocolDecl::claims`] claim, a tie broken by registration order.
pub fn detect_protocol(path: &str, headers: &http::HeaderMap) -> Option<&'static str> {
    let fields: Vec<(&[u8], &[u8])> = headers
        .iter()
        .map(|(n, v)| (n.as_str().as_bytes(), v.as_bytes()))
        .collect();
    registry()
        .decls()
        .iter()
        .filter_map(|d| d.claim_over(path, &fields).map(|s| (s, d.name)))
        .min_by(|a, b| a.0.cmp(&b.0))
        .map(|(_, name)| name)
}

/// THE RESIDUAL ARM of the ingress resolver: which dialect a path names from its shape alone, once
/// the mount table declined it (`PlaneDispatch::ingress_of` is the whole answer). `None` when it
/// names none.
pub fn residual_dialect_for_path(path: &str) -> Option<&'static str> {
    registry()
        .decls()
        .iter()
        .filter_map(|d| d.residual_claims.and_then(|c| c(path)).map(|s| (s, d.name)))
        .min_by(|a, b| a.0.cmp(&b.0))
        .map(|(_, name)| name)
}

/// The dialect named when no dialect claimed a request yet one must be named
/// ([`ProtocolDecl::residual_default`]); `None` when no such protocol is installed.
pub fn residual_default_dialect() -> Option<&'static str> {
    registry()
        .decls()
        .iter()
        .find(|d| d.residual_default)
        .map(|d| d.name)
}

/// Every protocol name busbar ships a wire codec for: the set a provider's `protocol:` may name.
pub fn known_protocols() -> &'static [&'static str] {
    registry().codec_protocols()
}

/// The streaming `Content-Type` values across every installed protocol.
pub fn streaming_content_types() -> &'static [&'static str] {
    registry().streaming_content_types()
}

/// The array-stream shim keys across every installed protocol.
pub fn array_stream_shim_keys() -> &'static [&'static str] {
    registry().array_stream_shim_keys()
}

/// The vendor-plausible auth-failure wire message for an ingress protocol; an unknown protocol
/// gets the generic copy.
pub fn vendor_auth_failure_message(proto: &str) -> &'static str {
    registry()
        .decl(proto)
        .map(|d| d.auth_failure_message)
        .unwrap_or("authentication failed")
}

/// Canonical dialect names, for tests only: production names no dialect.
#[cfg(any(test, feature = "test-support"))]
pub const PROTO_ANTHROPIC: &str = "anthropic";
#[cfg(any(test, feature = "test-support"))]
pub const PROTO_OPENAI: &str = "openai";
#[cfg(any(test, feature = "test-support"))]
pub const PROTO_GEMINI: &str = "gemini";
#[cfg(any(test, feature = "test-support"))]
pub const PROTO_BEDROCK: &str = "bedrock";
#[cfg(any(test, feature = "test-support"))]
pub const PROTO_COHERE: &str = "cohere";
#[cfg(any(test, feature = "test-support"))]
pub const PROTO_RESPONSES: &str = "responses";

#[cfg(test)]
#[path = "tests/protocols_installed_tests.rs"]
mod installed_tests;

#[cfg(test)]
#[path = "../tests/proto.rs"]
mod tests;
