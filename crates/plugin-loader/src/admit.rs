// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Admission: read once, verify, load those bytes (IF §11.1). W0-ABI stub: frozen signatures, `todo!()` bodies;
//! L1 fills it.

use std::sync::Arc;

use busbar_plugin_abi::host_side::driver::Image;
use busbar_plugin_abi::plugin::Plugin;
use busbar_plugin_abi::stamp::Stamp;

use crate::refusal::Refusal;

// W0-ABI: the IF's `SignedManifest` ("existing L/sign.rs type, unchanged") and `TrustConfig` ("existing") have no
// item of those names in the loader; the stub aliases them to the existing sign.rs types they describe (the signed
// manifest and the `plugins.trust` policy). L1 settles the names with the lead designer.
pub type SignedManifest = crate::sign::Manifest;
pub type TrustConfig = crate::sign::TrustPolicy;

/// `plugin` points into `image` (H4-checked); it is only dereferenced through an Instance that holds `image`.
pub struct Admitted {
    pub stamp: Stamp,
    pub image: Arc<Image>,
    // W0-ABI: the IF's private `plugin: NonNull<Plugin>` and its `unsafe impl Send/Sync for Admitted` (round 26)
    // land with W1-L1 under an escapes.json admission; the stub keeps the type's auto traits without them.
    _stub: core::marker::PhantomData<&'static Plugin>,
}

// W0-ABI: `LoadedImage` (§11.1) is `busbar_plugin_abi::host_side::driver::LoadedImage` (§10.4), not redefined here.

/// Dropped-in plugin: read once, verify, load those bytes.
/// 1 fstat (regular, ≤ 256 MiB) + read all; 2 sha256 + signature (Integrity, Signature); 3 scan::stamp
/// (loader `scan.rs`); 4 exact: kind known, kind_abi, mechanism, layout, mechanism_layout, semantic,
/// mechanism_semantic, target; 5 engine_min <= ENGINE <= engine_max; 6 stamp.crypto, decided only from the
/// facade (no host-side table): "host" => accepted; "external" => accepted only if
/// `busbar_crypto::EXTERNAL_PLUGINS` (round 13: a required compile-time backend const, §5.2; a FIPS backend
/// states false, CRYPTO-SEAM §9 "no external"; round 12: the facade's answer is the whole gate, as ABI-1.6.0 step 4: there is **no**
/// operator switch, no config key and nothing for boot migration to set, so a 1.5.x secret-c config admits
/// unchanged on every non-FIPS backend); any other value => accepted only if STAMP_OUT_OF_PROCESS is set, busbar-plugin-host is
/// present, and the value == `busbar_crypto::BACKEND` (CRYPTO-SEAM §9: "stamp crypto == BACKEND"); else
/// refused `Crypto` with have = the stamp value, want = BACKEND; 7 manifest name,
/// version, kind and abi equal the stamp (round 28: nothing else is checked here; signature and publisher trust
/// stay in step 2, dev's `plugins.trust` unchanged); 8 stage.rs load_library_from_bytes
/// (memfd sealed) under NATIVE_LOAD_GUARD, whose `dlopen` runs on an ffi_thread permanent worker (as today);
/// 9 dlsym busbar_plugin (and the `busbar_plugin()` call, also on that worker); H4 bounds-check plugin, stamp and kind_vt
/// against the image's mapped segments; *plugin.stamp == verified stamp (DoorStampMismatch); plugin.former_names
/// bounds-checked the same way and equal to the manifest's signed `former_names` (DoorStampMismatch). An image
/// whose SHA-256 is already in the loader's image table is not loaded again: admit returns the resident Image.
/// **Round 30, the two exits of a dlopened library (normative, I13).** Every `libloading::Library` the loader gets
/// from `stage::dlopen_on_worker` leaves by exactly one of: (a) **admitted**: step 9 passed, the library moves into
/// the image table as `Image::Loaded` and is never unloaded (no `Drop` of `Image` unloads it); (b) **refused before
/// admission**: stage.rs `load_via_staged_file`'s post-dlopen `verify_pinned` failure (f6e2cf05d7 stage.rs:491), or a
/// step-9 refusal (no `busbar_plugin` symbol, H4 `ImageBounds`, `DoorStampMismatch` on the stamp or on
/// `former_names`): the library goes to `stage::dlclose_on_worker(lib)` (kept, f6e2cf05d7 stage.rs:28-41), which drops
/// it on the permanent ffi worker. Up to that point only `dlopen` (initializers) and `busbar_plugin()` have run, both
/// on that worker, and the worker never exits (ffi_thread.rs:1-40), so no thread that armed the image's TLS key can
/// exit after the unmap; stage.rs `retire_memfd` keeps the memfd of any image glibc leaves in the link map, so its fd
/// name is never recycled. **No other code drops a `Library`**: an X1 source check (§15 rule 13) finds `Library`
/// values only in stage.rs and the image table, and a `drop` of one only inside `dlclose_on_worker`; a refused
/// `Library` is never dropped on a tokio, blocking-pool or libtest thread. A refusal **after** admission
/// (`Registry::add`: NameConflict, DescribeInvalid; a failed `open`) never unloads: describe has run inline on a
/// caller thread, so the image stays resident in the image table and a later admit of the same bytes returns it.
/// C-ADMIT-UNLOAD (§14).
// W0-ABI: `std::os::fd::OwnedFd` exists only on unix, so the stub is `cfg(unix)` (the loader also builds on
// Windows); L1 decides the non-unix arm with the lead designer.
#[cfg(unix)]
pub fn admit(
    fd: std::os::fd::OwnedFd,
    manifest: &SignedManifest,
    trust: &TrustConfig,
) -> Result<Admitted, Refusal> {
    let _ = (fd, manifest, trust);
    todo!()
}

/// Compiled-in plugin: steps 3 to 7 on the static, no file, no signature. image = `Image::Linked`.
pub fn admit_linked(plugin: &'static Plugin) -> Result<Admitted, Refusal> {
    let _ = plugin;
    todo!()
}
