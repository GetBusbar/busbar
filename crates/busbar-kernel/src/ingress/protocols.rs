// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE INSTALLED PROTOCOL SET: the `ProtocolDecl`s the composition root installs once at boot
//! ([`install_protocols`]), the aggregates folded from them, and the lookups ingress reads to decide
//! which dialect a request speaks and how to answer it in that dialect. The declaration shapes are
//! the contract's (`busbar_contract::protocol`). Production carries no built-in protocol.

pub use busbar_contract::protocol::ProtocolDecl;

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
        Self {
            decls,
            head_keys: head_keys.leak(),
            streaming_content_types: streaming_content_types.leak(),
            array_stream_shim_keys: array_stream_shim_keys.leak(),
            codec_protocols: codec_protocols.leak(),
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
}

/// The process registry: null until the first read folds the installed declarations, or a
/// registry [`publish_protocols`] set. Every pointer stored here comes from `Box::leak` and is never
/// freed or written through, so a reader holds it for `'static`.
static REGISTRY: std::sync::atomic::AtomicPtr<Registry> =
    std::sync::atomic::AtomicPtr::new(std::ptr::null_mut());

/// The registry behind a non-null [`REGISTRY`] pointer.
#[allow(unsafe_code)]
fn registry_at(ptr: *mut Registry) -> &'static Registry {
    // SAFETY: `ptr` is non-null and was stored in `REGISTRY` from `Box::leak`, which is never freed
    // or mutated; the Acquire load that read it pairs with the Release/AcqRel store that wrote it.
    unsafe { &*ptr }
}

/// The boot fold's tail after the installed declarations: none in any build but the kernel's own
/// unit-test binary, which folds its neutral synthetic set.
fn builtins() -> &'static [&'static ProtocolDecl] {
    #[cfg(test)]
    {
        crate::testkit::neutral_protocols::NEUTRAL_PROTOCOLS
    }
    #[cfg(not(test))]
    {
        &[]
    }
}

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
    assert!(
        REGISTRY
            .load(std::sync::atomic::Ordering::Acquire)
            .is_null(),
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

/// The process registry. One acquire-load once set.
pub fn registry() -> &'static Registry {
    use std::sync::atomic::Ordering;
    let ptr = REGISTRY.load(Ordering::Acquire);
    if !ptr.is_null() {
        return registry_at(ptr);
    }
    let installed: &[&'static ProtocolDecl] = INSTALLED.get().map(Vec::as_slice).unwrap_or(&[]);
    let fresh: *mut Registry = Box::leak(Box::new(Registry::new(merged_boot_decls(
        installed,
        builtins(),
    ))));
    match REGISTRY.compare_exchange(
        std::ptr::null_mut(),
        fresh,
        Ordering::AcqRel,
        Ordering::Acquire,
    ) {
        Ok(_) => registry_at(fresh),
        // Another reader (or a publish) set the registry first: that one stands.
        Err(set) => registry_at(set),
    }
}

/// Set the process registry to the fold of the installed declarations plus `registered`,
/// replacing any registry set before. The composition root never calls this: it installs once
/// through [`install_protocols`]. A test binary that registers protocols as it goes publishes each
/// registration set through it.
#[doc(hidden)]
pub fn publish_protocols(registered: &[&'static ProtocolDecl]) {
    let mut all: Vec<&'static ProtocolDecl> = INSTALLED.get().cloned().unwrap_or_default();
    all.extend_from_slice(registered);
    let fresh: *mut Registry =
        Box::leak(Box::new(Registry::new(merged_boot_decls(&all, builtins()))));
    REGISTRY.store(fresh, std::sync::atomic::Ordering::Release);
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

/// The test registration's former path, which the pinned plane repos' root tests still name; it
/// goes when they are re-pinned onto [`crate::test_support::protocols`].
#[cfg(any(test, feature = "test-support"))]
pub use crate::test_support::protocols::register_test_protocols;

#[cfg(test)]
#[path = "tests/protocols_installed_tests.rs"]
mod installed_tests;

#[cfg(test)]
#[path = "../tests/proto.rs"]
mod tests;
