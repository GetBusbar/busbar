// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

pub use busbar_contract::protocol::ProtocolDecl;

fn install_kernel_hooks() {
    busbar_kernel::ingress::protocols::install_test_hooks(
        busbar_kernel::ingress::protocols::ProtocolTestHooks {
            residual_dialect_for_path,
            residual_default_dialect,
            vendor_auth_failure_message,
            quota_exceeded_status,
            auth_failure_status_and_kind,
            signed_ingress: uses_signed_ingress_auth,
            error_parts,
        },
    );
}

pub struct Registry {
    decls: Vec<&'static ProtocolDecl>,

    head_keys: &'static [&'static str],
    streaming_content_types: &'static [&'static str],
    array_stream_shim_keys: &'static [&'static str],

    codec_protocols: &'static [&'static str],
}

impl Registry {
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

static REGISTRY: std::sync::atomic::AtomicPtr<Registry> =
    std::sync::atomic::AtomicPtr::new(std::ptr::null_mut());

#[allow(unsafe_code)]
fn registry_at(ptr: *mut Registry) -> &'static Registry {
    // SAFETY: `ptr` is non-null and was stored in `REGISTRY` from `Box::leak`, which is never freed
    // or mutated; the Acquire load that read it pairs with the Release/AcqRel store that wrote it.
    unsafe { &*ptr }
}

fn builtins() -> &'static [&'static ProtocolDecl] {
    crate::testkit::neutral_protocols::NEUTRAL_PROTOCOLS
}

static INSTALLED: std::sync::OnceLock<Vec<&'static ProtocolDecl>> = std::sync::OnceLock::new();

/// THE KERNEL'S CODEC HOST: the host services every codec the kernel drives is handed (the OS
/// CSPRNG, the host wall clock and its monotonic clock).
#[derive(Clone, Copy, Debug, Default)]
pub struct CodecHostServices;

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

pub fn install_protocols(decls: Vec<&'static ProtocolDecl>) {
    install_kernel_hooks();
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

pub fn registry() -> &'static Registry {
    install_kernel_hooks();
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

        Err(set) => registry_at(set),
    }
}

/// Set the process registry to the fold of the installed declarations plus `registered`,
/// replacing any registry set before. The composition root never calls this: it installs once
/// through [`install_protocols`]. A test binary that registers protocols as it goes publishes each
/// registration set through it.
#[doc(hidden)]
pub fn publish_protocols(registered: &[&'static ProtocolDecl]) {
    install_kernel_hooks();
    let mut all: Vec<&'static ProtocolDecl> = INSTALLED.get().cloned().unwrap_or_default();
    all.extend_from_slice(registered);
    let fresh: *mut Registry =
        Box::leak(Box::new(Registry::new(merged_boot_decls(&all, builtins()))));
    REGISTRY.store(fresh, std::sync::atomic::Ordering::Release);
}

pub fn decl_for(name: &str) -> Option<&'static ProtocolDecl> {
    registry().decl(name)
}

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

pub fn residual_dialect_for_path(path: &str) -> Option<&'static str> {
    registry()
        .decls()
        .iter()
        .filter_map(|d| d.residual_claims.and_then(|c| c(path)).map(|s| (s, d.name)))
        .min_by(|a, b| a.0.cmp(&b.0))
        .map(|(_, name)| name)
}

pub fn residual_default_dialect() -> Option<&'static str> {
    registry()
        .decls()
        .iter()
        .find(|d| d.residual_default)
        .map(|d| d.name)
}

pub fn known_protocols() -> &'static [&'static str] {
    registry().codec_protocols()
}

pub fn streaming_content_types() -> &'static [&'static str] {
    registry().streaming_content_types()
}

pub fn array_stream_shim_keys() -> &'static [&'static str] {
    registry().array_stream_shim_keys()
}

pub fn vendor_auth_failure_message(proto: &str) -> &'static str {
    registry()
        .decl(proto)
        .map(|d| d.auth_failure_message)
        .unwrap_or("authentication failed")
}

pub fn uses_signed_ingress_auth(proto: &str) -> bool {
    decl_for(proto).is_some_and(|decl| decl.uses_sigv4_ingress_auth())
}

pub fn quota_exceeded_status(proto: &str) -> u16 {
    decl_for(proto).map_or(429, |decl| decl.quota_exceeded_status)
}

pub fn auth_failure_status_and_kind(proto: &str) -> (u16, &'static str) {
    decl_for(proto).map_or(
        (401, busbar_contract::protocol::KIND_AUTHENTICATION),
        |decl| decl.auth_failure_status_and_kind,
    )
}

pub fn error_parts(
    proto: &str,
    status: u16,
    kind: &str,
    message: &str,
) -> (serde_json::Value, Vec<(String, Vec<u8>)>) {
    if let Some(dialect) = decl_for(proto).and_then(|decl| decl.dialect()) {
        let envelope = dialect.write_error(CODEC_HOST, status, kind, message);
        let fields = dialect.error_response_fields(CODEC_HOST, kind, &envelope);
        return (envelope, fields);
    }
    (
        serde_json::json!({ "error": { "message": message, "type": kind } }),
        Vec::new(),
    )
}

pub use crate::test_support::protocols::register_test_protocols;

#[cfg(test)]
#[path = "tests/protocols_installed_tests.rs"]
mod installed_tests;

#[cfg(test)]
#[path = "../tests/proto.rs"]
mod tests;
