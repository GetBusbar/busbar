// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE SAFE TEST HOST: tests admit MIN-3 images through the loader's own `admit_linked` and `admit` (the
//! dropped-in image staged and opened exactly as in production), signed by a fixed test key that only
//! [`test_trust`] trusts, with no `unsafe`.
#![forbid(unsafe_code)]

use std::path::PathBuf;
use std::sync::Arc;

/// The bytes of the cdylib example `lib_name` (a MIN-3 image for [`admit_bytes`]), found where
/// a test looks: the variable named for it, `BUSBAR_PLUGIN_CDYLIB`, or the build profile directory.
///
/// # Panics
/// When no such library exists (the panic names where it looked) or it cannot be read.
#[must_use]
pub fn cdylib_bytes(lib_name: &str) -> Vec<u8> {
    let path = locate(lib_name);
    std::fs::read(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()))
}

fn locate(lib_name: &str) -> PathBuf {
    let file = crate::plugin_library_filename(lib_name);
    let var = format!(
        "BUSBAR_PLUGIN_CDYLIB_{}",
        lib_name.to_ascii_uppercase().replace('-', "_")
    );
    if let Some(p) = std::env::var_os(&var) {
        return PathBuf::from(p);
    }
    if let Some(p) = std::env::var_os("BUSBAR_PLUGIN_CDYLIB")
        .map(PathBuf::from)
        .filter(|p| p.file_name().is_some_and(|n| *n == *file))
    {
        return p;
    }
    let profile = std::env::current_exe()
        .ok()
        .and_then(|exe| Some(exe.parent()?.parent()?.to_path_buf()))
        .unwrap_or_default();
    let tried = [profile.join(&file), profile.join("examples").join(&file)];
    tried.iter().find(|p| p.is_file()).cloned().unwrap_or_else(|| {
        panic!(
            "no cdylib for `{lib_name}`: set {var} or BUSBAR_PLUGIN_CDYLIB, or build it to {} or {}",
            tried[0].display(),
            tried[1].display()
        )
    })
}

/// The publisher every test-signed MIN-3 manifest names; only [`test_trust`] trusts it.
pub const TEST_PUBLISHER: &str = "busbar-test";

/// The test signing key (a fixed seed: never a release key, trusted by nothing but [`test_trust`]).
#[must_use]
pub fn test_key() -> crate::sign::SigningKey {
    crate::sign::SigningKey::from_bytes(&[0x5a; 32])
}

/// A `plugins.trust` that trusts [`TEST_PUBLISHER`]'s [`test_key`] only for `expected_scope`
/// (no opt-in flag). The scope must come from the fixture's expectation, not the manifest under test.
#[must_use]
pub fn test_trust(expected_scope: &str) -> crate::admit::TrustConfig {
    let mut trust = crate::sign::TrustPolicy::default();
    trust.publishers.insert(
        TEST_PUBLISHER.to_string(),
        crate::sign::PublisherTrust {
            plugins: [expected_scope.to_string()].into_iter().collect(),
            keys: vec![crate::sign::PublisherKey {
                key: test_key().verifying_key(),
                revoked: false,
            }],
        },
    );
    trust
}

/// The manifest a pack would sign for `bytes`: name, version, kind and ABI read from the image's own stamp,
/// `former_names` as the header states them, signed by [`test_key`] under [`TEST_PUBLISHER`].
///
/// # Errors
/// The image's stamp scan refusal (no stamp, more than one, or a malformed one).
pub fn test_manifest(
    bytes: &[u8],
    former_names: &[&str],
) -> Result<crate::admit::SignedManifest, crate::refusal::Refusal> {
    let stamp = crate::scan::stamp(bytes).map_err(crate::scan::StampScanErr::refusal)?;
    let kind = busbar_plugin_abi::types::KindCode::from_raw(stamp.kind)
        .map_or("", crate::admit::kind_word);
    let name = crate::scan::text(&stamp.name).to_string();
    let manifest = crate::sign::Manifest {
        alias: name.clone(),
        name,
        kind: kind.to_string(),
        version: crate::scan::text(&stamp.version).to_string(),
        publisher: TEST_PUBLISHER.to_string(),
        abi_version: stamp.kind_abi,
        former_names: former_names.iter().map(|n| (*n).to_string()).collect(),
        ..crate::sign::Manifest::default()
    };
    Ok(test_sign(manifest, bytes))
}

/// `manifest` re-signed by [`test_key`] over `bytes` (its `sha256` set to theirs).
#[must_use]
pub fn test_sign(
    manifest: crate::admit::SignedManifest,
    bytes: &[u8],
) -> crate::admit::SignedManifest {
    crate::sign::sign(&test_key(), manifest, bytes)
}

/// A compiled-in MIN-3 image, through the loader's `admit_linked` (steps 3 to 7 on the static).
///
/// # Errors
/// The loader's refusal.
pub fn admit_linked(
    plugin: &'static busbar_ffi::LinkedPlugin,
) -> Result<crate::admit::Admitted, crate::refusal::Refusal> {
    crate::admit::admit_linked(plugin)
}

/// A dropped-in MIN-3 image: `bytes` written to a private file, opened read-only, unlinked, and admitted from
/// that descriptor through the loader's `admit` under [`test_trust`] for the explicit expected plugin
/// scope (every step production runs).
///
/// # Errors
/// The loader's refusal.
///
/// # Panics
/// When the scratch file cannot be written or opened.
#[cfg(unix)]
pub fn admit_bytes(
    bytes: &[u8],
    manifest: &crate::admit::SignedManifest,
    expected_scope: &str,
) -> Result<crate::admit::Admitted, crate::refusal::Refusal> {
    use std::io::Write as _;
    let path = std::env::temp_dir().join(format!(
        "busbar-test-admit-{}-{}",
        std::process::id(),
        crate::stage::next_seq()
    ));
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&path)
        .unwrap_or_else(|e| panic!("create the scratch image {}: {e}", path.display()));
    file.write_all(bytes)
        .unwrap_or_else(|e| panic!("write the scratch image {}: {e}", path.display()));
    drop(file);
    let file = std::fs::File::open(&path)
        .unwrap_or_else(|e| panic!("open the scratch image {}: {e}", path.display()));
    let _ = std::fs::remove_file(&path);
    crate::admit::admit(
        std::os::fd::OwnedFd::from(file),
        manifest,
        &test_trust(expected_scope),
    )
}

/// The cdylib built from `lib_name` (found as [`cdylib_bytes`] finds it), admitted through `admit` under a
/// [`test_manifest`] stating `former_names`, trusted only for the explicit `expected_scope`.
///
/// # Errors
/// The loader's refusal.
///
/// # Panics
/// When no such file exists or it cannot be read.
#[cfg(unix)]
pub fn admit_cdylib(
    lib_name: &str,
    former_names: &[&str],
    expected_scope: &str,
) -> Result<crate::admit::Admitted, crate::refusal::Refusal> {
    let path = locate(lib_name);
    let bytes =
        std::fs::read(&path).unwrap_or_else(|e| panic!("read the cdylib {}: {e}", path.display()));
    let manifest = test_manifest(&bytes, former_names)?;
    admit_bytes(&bytes, &manifest, expected_scope)
}

/// Native stores for tests outside a booted root (the dist fixtures): one registry over one admitted store image,
/// opening each instance with no Needs and no reference sources. Enough for a store whose `open` makes no NEED and
/// binds no reference (a local file store such as store-sqlite: it calls only host services). The registry
/// outlives every handle it opened.
pub struct NativeStores {
    registry: crate::instance::Registry,
}

/// The test binary's one set of process plugin resources (a process installs its plugin sinks once).
///
/// # Errors
/// The resources could not start.
pub fn shared_process() -> Result<&'static crate::process::ProcessResources, &'static String> {
    static PROCESS: std::sync::OnceLock<Result<crate::process::ProcessResources, String>> =
        std::sync::OnceLock::new();
    PROCESS
        .get_or_init(crate::process::ProcessResources::new)
        .as_ref()
}

impl NativeStores {
    /// One registry over `admitted`, binding through `binder` (the kernel's `plugin_config::Binder`).
    ///
    /// # Errors
    /// The process resources or the image's admission refusal.
    pub fn new(
        admitted: crate::admit::Admitted,
        binder: Arc<dyn busbar_ports::binder::ConfigBinder>,
    ) -> Result<Self, crate::refusal::Refusal> {
        let process = shared_process().map_err(|error| {
            crate::refusal::Refusal::new(
                crate::refusal::RefusalCode::Integrity,
                "process",
                error.clone(),
                "process resources",
            )
        })?;
        let mut images = crate::instance::ImagesBuilder::new(
            &busbar_plugin_abi::host_side::host_vt::HOST,
            Arc::clone(process.slots()),
            crate::instance::Ceilings::DEFAULT,
        );
        images.admit(admitted)?;
        Ok(Self {
            registry: crate::instance::Registry::new(
                images.finish(),
                binder,
                Arc::clone(process.ids()),
            ),
        })
    }

    /// `Registry::open_store` for `spec` under `seal`, with every NEED denied and no reference source.
    ///
    /// # Errors
    /// The open's refusal.
    pub async fn open(
        &self,
        spec: &crate::instance::InstanceSpec<'_>,
        seal: crate::instance::StoreSeal,
    ) -> Result<busbar_ports::store::StoreHandle, crate::instance::OpenError> {
        let needs = Arc::new(crate::chains::DeniedNeeds);
        let refs: Arc<dyn busbar_ports::binder::RefSource> = Arc::new(crate::chains::DeniedRefs);
        self.registry.open_store(spec, &needs, &refs, seal).await
    }
}

/// A binder for a store that binds nothing: its config passes through unchanged and no secret, trust, dest or
/// reference position is bound (a local file store's `db_path`, the bench's in-memory store). A declared position
/// that holds a value is refused, so a store that needs custody is never opened over it.
struct PlainBinder;

impl busbar_ports::binder::ConfigBinder for PlainBinder {
    fn bind(
        &self,
        _instance: u64,
        config: &[u8],
        secret_paths: &[&str],
        trust_paths: &[&str],
        dest_paths: &[&str],
        _ref_paths: &[&str],
    ) -> Result<Vec<u8>, busbar_ports::binder::BindError> {
        if let Some(pointer) = secret_paths
            .iter()
            .chain(trust_paths)
            .chain(dest_paths)
            .next()
        {
            return Err(busbar_ports::binder::BindError::NotAReference {
                pointer: (*pointer).into(),
            });
        }
        Ok(config.to_vec())
    }
    fn resolve_refs<'a>(
        &'a self,
        _instance: u64,
        _slot: u32,
        bound: Vec<u8>,
        _source: &'a dyn busbar_ports::binder::RefSource,
    ) -> busbar_plugin_abi::host_side::caller::BoxFut<
        'a,
        Result<busbar_contract::secure::SecureVec, busbar_ports::binder::BindError>,
    > {
        Box::pin(async move { Ok(busbar_contract::secure::SecureVec::from(bound)) })
    }
    fn unbind(&self, _instance: u64) {}
    fn bind_any(
        &self,
        instance: u64,
        config: &[u8],
        secret_paths: &[&str],
        trust_paths: &[&str],
        dest_paths: &[&str],
        ref_paths: &[&str],
    ) -> Result<Vec<u8>, busbar_ports::binder::BindError> {
        self.bind(
            instance,
            config,
            secret_paths,
            trust_paths,
            dest_paths,
            ref_paths,
        )
    }
    fn unbind_refs(
        &self,
        _instance: u64,
        bound: &[u8],
    ) -> Result<Vec<u8>, busbar_ports::binder::BindError> {
        Ok(bound.to_vec())
    }
    fn secret(
        &self,
        _instance: u64,
        _handle: u32,
    ) -> Option<busbar_contract::secret_ref::SecretRef> {
        None
    }
    fn trust(
        &self,
        _instance: u64,
        _handle: u32,
    ) -> Option<Arc<busbar_ports::binder::TrustAnchor>> {
        None
    }
    fn dest(&self, _instance: u64, _handle: u32) -> Option<Arc<busbar_ports::binder::DestDef>> {
        None
    }
}

impl NativeStores {
    /// [`NativeStores::new`] with a binder that binds nothing ([`PlainBinder`]): for a store whose config holds no
    /// secret, trust or dest position (plugin-bench's native store workload).
    ///
    /// # Errors
    /// As [`NativeStores::new`].
    pub fn plain(admitted: crate::admit::Admitted) -> Result<Self, crate::refusal::Refusal> {
        Self::new(admitted, Arc::new(PlainBinder))
    }
}
