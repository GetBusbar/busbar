// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Admission: read once, verify, load those bytes (IF §11.1, r4 §3.6, MIN-3 §3.2).
//!
//! W1-L1, under UNSAFE-MIN r3.1 (owner-approved, after IF r34): every pointer step is busbar-ffi's. Step 8's
//! dlopen and step 9's `busbar_plugin()` call and H4 bounds check are `busbar_ffi::image::Opened::open`, run on
//! the loader's permanent ffi worker; exit a is `Opened::admit` (the library is leaked, never unloaded, I13) and
//! exit b is `stage::close_on_worker`. An `Admitted` holds busbar-ffi's `Admitted` (an address of the immutable
//! `'static` header) in place of the IF's `NonNull<Plugin>`, so it is `Send + Sync` with no `unsafe impl`.
//! `admit_linked` takes busbar-ffi's `LinkedPlugin` (UNSAFE-MIN A1: a bare `&'static Plugin` is forgeable).

#[cfg(unix)]
use std::collections::HashMap;
use std::sync::Arc;
#[cfg(unix)]
use std::sync::Mutex;
use std::sync::OnceLock;

use busbar_ffi::image::{Admitted as Header, ImageError};
use busbar_ffi::{LinkedPlugin, Plugin};

use busbar_plugin_abi::host_side::driver::Image;
#[cfg(unix)]
use busbar_plugin_abi::host_side::driver::LoadedImage;
use busbar_plugin_abi::stamp::{Stamp, STAMP_OUT_OF_PROCESS};
use busbar_plugin_abi::types::KindCode;
use busbar_plugin_abi::versions::{EngineVersion, ENGINE};

use crate::agree::{Agreed, Claim, Claims, Contract, Speaks, Version};
use crate::refusal::{Refusal, RefusalCode};
use crate::scan;

// W0-ABI: the IF's `SignedManifest` ("existing L/sign.rs type, unchanged") and `TrustConfig` ("existing") have no
// item of those names in the loader; they are the existing sign.rs types they describe (the signed manifest and
// the `plugins.trust` policy).
pub type SignedManifest = crate::sign::Manifest;
pub type TrustConfig = crate::sign::TrustPolicy;

/// The largest image admit reads (step 1).
pub const MAX_IMAGE_BYTES: u64 = 256 << 20;

/// Who vouches for an admitted image (DES-NATIVE-FIRST-PARTY r3 §2.2): compiled into this build, or exactly
/// what `sign::evaluate_with_verification` returned over a dropped image's bytes in this admission.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Signer {
    /// Compiled into this build (`admit_linked` / `admit_header`).
    Linked,
    /// Dropped in: this admission's verdict and the proof behind it.
    Dropped {
        verdict: crate::sign::Verdict,
        proof: busbar_artifact_metadata::rows::Verification,
    },
}

impl Signer {
    /// Linked, or verified against an embedded release key (AGREED:156 diagnostics and reserved `busbar_*`
    /// metrics). Never taken from the self-declared publisher text.
    #[must_use]
    pub fn first_party(&self) -> bool {
        match self {
            Signer::Linked => true,
            Signer::Dropped {
                verdict: crate::sign::Verdict::Trusted { first_party, .. },
                ..
            } => *first_party,
            Signer::Dropped { .. } => false,
        }
    }

    /// Linked, or any verified `Trusted` verdict (busbar or an operator-trusted publisher). Never `Allowed`.
    #[must_use]
    pub fn trusted(&self) -> bool {
        matches!(
            self,
            Signer::Linked
                | Signer::Dropped {
                    verdict: crate::sign::Verdict::Trusted { .. },
                    ..
                }
        )
    }
}

/// An admitted image: its verified stamp, the image that keeps it mapped, its header, and who vouched for it.
#[derive(Clone)]
pub struct Admitted {
    pub stamp: Stamp,
    pub image: Arc<Image>,
    /// This admission's signer (§2.1): never cached with the mapped image.
    signer: Signer,
    /// The header inside `image` (busbar-ffi's checked address of an immutable `'static` header: a
    /// `LinkedPlugin`, or the header of a dropped-in image whose library is never unloaded, I13).
    plugin: Header,
}

impl Admitted {
    /// The header, for the registry's describe/open and every instance built over this image.
    pub fn plugin(&self) -> Header {
        self.plugin
    }

    /// Who vouched for this image in this admission.
    #[must_use]
    pub fn signer(&self) -> &Signer {
        &self.signer
    }

    /// Linked, or verified against an embedded release key.
    #[must_use]
    pub fn first_party(&self) -> bool {
        self.signer.first_party()
    }

    /// Linked, or any verified `Trusted` verdict; never `Allowed`.
    #[must_use]
    pub fn trusted(&self) -> bool {
        self.signer.trusted()
    }

    /// The verified stamp name (the plugin identity).
    pub fn identity(&self) -> &str {
        scan::text(&self.stamp.name)
    }

    /// The kind the verified stamp names.
    pub fn kind(&self) -> KindCode {
        KindCode::from_raw(self.stamp.kind).expect("admit verified the stamp's kind")
    }

    /// The SHA-256 of a dropped-in image's bytes (None for a compiled-in image).
    pub fn sha256(&self) -> Option<&[u8; 32]> {
        match &*self.image {
            Image::Linked => None,
            Image::Loaded(loaded) => Some(loaded.sha256()),
        }
    }
}

impl core::fmt::Debug for Admitted {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Admitted")
            .field("identity", &self.identity())
            .field("kind", &self.kind())
            .field("linked", &matches!(&*self.image, Image::Linked))
            .finish()
    }
}

// W0-ABI: `LoadedImage` (§11.1) is `busbar_plugin_abi::host_side::driver::LoadedImage` (§10.4), not redefined here.

/// What step 6 decides from: the crypto facade's two answers, and whether this build has an out-of-process
/// plugin host (it has none: no busbar-plugin-host ships, so an out-of-process image is never loaded).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CryptoFacts {
    /// `busbar_crypto::EXTERNAL_PLUGINS`.
    pub external_plugins: bool,
    /// `busbar_crypto::BACKEND`.
    pub backend: &'static str,
    /// busbar-plugin-host is present.
    pub plugin_host: bool,
}

impl CryptoFacts {
    /// The linked facade's answers: the whole gate (round 12: no operator switch, no config key, nothing for
    /// boot migration to set).
    pub const FACADE: CryptoFacts = CryptoFacts {
        external_plugins: busbar_contract::crypto::EXTERNAL_PLUGINS,
        backend: busbar_contract::crypto::BACKEND,
        plugin_host: false,
    };
}

/// Step 6: `"host"` => accepted; `"external"` => accepted only if the facade's `EXTERNAL_PLUGINS`; any other value
/// => accepted only for an out-of-process image, with busbar-plugin-host present, naming exactly the facade's
/// `BACKEND`; else refused `Crypto` (have = the stamp value, want = BACKEND). Then an out-of-process image is
/// refused `OutOfProcessUnavailable` unless busbar-plugin-host is present: it never runs in this process.
pub fn crypto_gate(crypto: &str, out_of_process: bool, facts: &CryptoFacts) -> Result<(), Refusal> {
    let accepted = match crypto {
        "host" => true,
        "external" => facts.external_plugins,
        named => out_of_process && facts.plugin_host && named == facts.backend,
    };
    if !accepted {
        return Err(Refusal::new(
            RefusalCode::Crypto,
            "crypto",
            crypto,
            facts.backend,
        ));
    }
    if out_of_process && !facts.plugin_host {
        return Err(Refusal::new(
            RefusalCode::OutOfProcessUnavailable,
            "flags",
            "out_of_process",
            "an in-process image",
        ));
    }
    Ok(())
}

pub use busbar_artifact_verifier::kind_word;

/// What this engine speaks of the core and of each kind: the released lines of each contract's lock
/// file and, in a dev build only, the unreleased line at the label. Built from the contract crates'
/// own tables; the loader states no version and no fingerprint of its own.
pub fn speaks() -> &'static Speaks {
    static SPEAKS: OnceLock<Speaks> = OnceLock::new();
    SPEAKS.get_or_init(|| {
        let contract =
            |name: &'static str, pins: &'static busbar_plugin_abi::pins::Pins| Contract {
                name,
                first: pins.first,
                released: pins.released,
                dev: pins.dev,
            };
        let speaks = Speaks {
            core: contract("core", &busbar_plugin_abi::pins::CORE),
            kinds: KindCode::ALL
                .map(|kind| contract(kind_word(kind), busbar_plugin_abi::pins::of(kind))),
        };
        if let Err(fault) = speaks.well_formed() {
            // A build fault of the engine: no image can be judged against a broken table.
            panic!("the engine's contract tables are not well formed: {fault}");
        }
        speaks
    })
}

/// What a format-3 stamp states about the interface.
fn claims(stamp: &Stamp, kind: KindCode) -> Claims {
    Claims {
        core: Claim {
            version: Version {
                first: stamp.core_first,
                second: stamp.core_second,
            },
            wire: stamp.core_wire,
        },
        kind,
        of_kind: Claim {
            version: Version {
                first: stamp.kind_first,
                second: stamp.kind_second,
            },
            wire: stamp.kind_wire,
        },
    }
}

fn engine_text(v: EngineVersion) -> String {
    format!("{}.{}.{}", v.major, v.minor, v.patch)
}

/// Steps 4 to 6 on a stamp `scan::check` passed; shared by admission and the native packer's
/// pre-open inspection. The refusal names the structurally validated stamp's name.
pub(crate) fn compatible(stamp: &Stamp, facts: &CryptoFacts) -> Result<KindCode, Refusal> {
    agreed(stamp, facts).map(|agreed| agreed.kind)
}

/// `compatible`, keeping what was agreed: the second numbers the image was built for, which the
/// instance carries so nothing introduced later is ever sent to it.
pub(crate) fn agreed(stamp: &Stamp, facts: &CryptoFacts) -> Result<Agreed, Refusal> {
    let name = scan::text(&stamp.name);
    let refuse = |code: RefusalCode,
                  field: &'static str,
                  have: String,
                  want: String|
     -> Result<Agreed, Refusal> {
        Err(Refusal::new(code, field, have, want).named(name))
    };
    let Some(kind) = KindCode::from_raw(stamp.kind) else {
        return refuse(
            RefusalCode::KindUnknown,
            "kind",
            stamp.kind.to_string(),
            "1 to 7".into(),
        );
    };
    // Core first, then the kind: first number equal, second number not above this engine's newest
    // line, fingerprint equal to this engine's record of that line (`agree`).
    let agreed = speaks()
        .agree(&claims(stamp, kind))
        .map_err(|no| no.refusal().named(name))?;
    let target = busbar_plugin_abi::stamp::target_now();
    if stamp.target != target {
        return refuse(
            RefusalCode::Target,
            "target",
            scan::text(&stamp.target).to_string(),
            scan::text(&target).to_string(),
        );
    }
    // The engine range is a statement a plugin author makes about a known bad engine; a stamp that
    // states none carries the whole range (the default is "any"), so this refuses only a stated range.
    if !(stamp.engine_min <= ENGINE && ENGINE <= stamp.engine_max) {
        return refuse(
            RefusalCode::EngineRange,
            "engine",
            format!(
                "{} through {}",
                engine_text(stamp.engine_min),
                engine_text(stamp.engine_max)
            ),
            engine_text(ENGINE),
        );
    }
    crypto_gate(
        scan::text(&stamp.crypto),
        stamp.flags & STAMP_OUT_OF_PROCESS != 0,
        facts,
    )
    .map_err(|r| r.named(name))?;
    Ok(agreed)
}

/// Why busbar-ffi refused an image, as a refusal.
fn image_refusal(e: &ImageError) -> Refusal {
    match e {
        ImageError::Load(e) => Refusal::new(
            RefusalCode::Target,
            "dlopen",
            crate::stage::loader_error(e),
            scan::text(&busbar_plugin_abi::stamp::target_now()).to_string(),
        ),
        ImageError::NoSymbol => Refusal::new(
            RefusalCode::DoorStampMismatch,
            "busbar_plugin",
            "no busbar_plugin symbol",
            "the one exported symbol",
        ),
        ImageError::Parse => Refusal::new(
            RefusalCode::ImageBounds,
            "image",
            "not an image the loader can read",
            "an ELF, Mach-O or PE image",
        ),
        ImageError::Bounds(what) => Refusal::new(
            RefusalCode::ImageBounds,
            what,
            "outside the image's segments or misaligned",
            "inside one segment, aligned",
        ),
        ImageError::Kind => Refusal::new(
            RefusalCode::DoorStampMismatch,
            "stamp",
            "a stamp that names no kind",
            "the verified stamp",
        ),
        ImageError::Null(what) => {
            Refusal::new(RefusalCode::DoorStampMismatch, what, "null", "an entry")
        }
    }
}

/// The process-wide resident image table (I13): one entry per distinct image admitted, keyed by SHA-256, never
/// shrunk. Touched only by `admit`, on its cold path; the lock is held across a load so identical bytes are
/// loaded once.
#[cfg(unix)]
struct Resident {
    image: Arc<Image>,
    plugin: Header,
    former_names: String,
}

#[cfg(unix)]
fn resident() -> &'static Mutex<HashMap<[u8; 32], Resident>> {
    static TABLE: OnceLock<Mutex<HashMap<[u8; 32], Resident>>> = OnceLock::new();
    TABLE.get_or_init(|| Mutex::new(HashMap::new()))
}

/// The resident image with this SHA-256, if any: its admitted header and the `former_names` it was admitted under.
/// The table lock is released before this returns (DES-443 r2 §3.1: inspect never holds it across a call).
#[cfg(unix)]
pub(crate) fn resident_header(sha256: &[u8; 32]) -> Option<(Header, String)> {
    resident()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .get(sha256)
        .map(|r| (r.plugin, r.former_names.clone()))
}

/// Whether the image with this SHA-256 is resident: admitted, and never unloaded (I13).
#[cfg(unix)]
#[must_use]
pub fn is_resident(sha256: &[u8; 32]) -> bool {
    resident()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .contains_key(sha256)
}

/// The manifest's signed `former_names`, joined as the header states them.
#[cfg(unix)]
fn joined(manifest: &SignedManifest) -> String {
    manifest.former_names.join(",")
}

/// Step 7: the signed manifest's name, version, kind and abi equal the verified stamp's (round 28: nothing else).
#[cfg(unix)]
fn manifest_matches(
    stamp: &Stamp,
    kind: KindCode,
    manifest: &SignedManifest,
) -> Result<(), Refusal> {
    let name = scan::text(&stamp.name);
    let version = scan::text(&stamp.version);
    let printable_version = |v: &str| {
        crate::sign::valid_semver(v)
            && v.bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'+' | b'-'))
    };
    let mismatch = |field: &'static str, have: String, want: String| -> Result<(), Refusal> {
        Err(Refusal::new(RefusalCode::ManifestMismatch, field, have, want).named(name))
    };
    if manifest.name != name {
        let have = if crate::sign::valid_name(&manifest.name) {
            manifest.name.clone()
        } else {
            String::new()
        };
        return mismatch("manifest.name", have, name.to_string());
    }
    if manifest.version != version {
        let have = if printable_version(&manifest.version) {
            manifest.version.clone()
        } else {
            String::new()
        };
        return mismatch("manifest.version", have, version.to_string());
    }
    if manifest.kind != kind_word(kind) {
        let have = if crate::sign::KNOWN_KINDS.contains(&manifest.kind.as_str()) {
            manifest.kind.clone()
        } else {
            String::new()
        };
        return mismatch("manifest.kind", have, kind_word(kind).to_string());
    }
    if manifest.abi_version != stamp.kind_abi {
        return mismatch(
            "manifest.abi_version",
            manifest.abi_version.to_string(),
            stamp.kind_abi.to_string(),
        );
    }
    Ok(())
}

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
// W1-L1: steps 8-9 run through busbar-ffi (`stage::open_image`, `Opened::admit`, `stage::close_on_worker`); the
// library lives inside busbar-ffi's `Opened` until exit a or b.
#[cfg(unix)]
pub fn admit(
    fd: std::os::fd::OwnedFd,
    manifest: &SignedManifest,
    trust: &TrustConfig,
) -> Result<Admitted, Refusal> {
    admit_with(fd, manifest, trust, &CryptoFacts::FACADE)
}

/// `admit` over library bytes the caller already holds (the plugins directory's scan read them once): a sealed
/// memfd of exactly those bytes, then every `admit` step, so the bytes verified and the bytes loaded are the same.
#[cfg(target_os = "linux")]
pub fn admit_bytes(
    bytes: &[u8],
    manifest: &SignedManifest,
    trust: &TrustConfig,
) -> Result<Admitted, Refusal> {
    let fd = crate::stage::sealed_memfd(bytes).map_err(|e| {
        Refusal::new(RefusalCode::Integrity, "file", e, "a readable image")
            .named(manifest.name.as_str())
    })?;
    admit(fd, manifest, trust)
}

/// Steps 1-7, shared by install and inspection (DES-443 r3 §3.1, B-M2): the read, sha256 against the manifest,
/// the trust evaluation, the stamp scan, `compatible` and `manifest_matches`. Nothing is opened before all of them
/// pass, in either mode.
#[cfg(unix)]
pub(crate) struct Verified {
    pub(crate) bytes: Vec<u8>,
    pub(crate) sha256: [u8; 32],
    pub(crate) stamp: Stamp,
    pub(crate) kind: KindCode,
    pub(crate) name: String,
    pub(crate) former_names: String,
    /// This call's verdict and proof (DES-NATIVE-FIRST-PARTY r3 §2.1).
    pub(crate) signer: Signer,
}

#[cfg(unix)]
fn admit_with(
    fd: std::os::fd::OwnedFd,
    manifest: &SignedManifest,
    trust: &TrustConfig,
    facts: &CryptoFacts,
) -> Result<Admitted, Refusal> {
    let v = verify(fd, manifest, trust, facts)?;
    let mut table = resident().lock().unwrap_or_else(|p| p.into_inner());
    if let Some(r) = table.get(&v.sha256) {
        if r.former_names != v.former_names {
            return Err(Refusal::new(
                RefusalCode::DoorStampMismatch,
                "former_names",
                r.former_names.clone(),
                v.former_names,
            )
            .named(&v.name));
        }
        return Ok(Admitted {
            stamp: v.stamp,
            image: Arc::clone(&r.image),
            plugin: r.plugin,
            signer: v.signer,
        });
    }
    let (opened, staged) = open_checked(&v)?;
    let plugin = match opened.admit() {
        Ok(plugin) => plugin,
        Err((opened, e)) => {
            crate::stage::close_on_worker(opened);
            drop(staged);
            return Err(image_refusal(&e).named(&v.name));
        }
    };
    let image = Arc::new(Image::Loaded(LoadedImage::new(v.sha256, Box::new(staged))));
    table.insert(
        v.sha256,
        Resident {
            image: Arc::clone(&image),
            plugin,
            former_names: v.former_names,
        },
    );
    Ok(Admitted {
        stamp: v.stamp,
        image,
        plugin,
        signer: v.signer,
    })
}

/// Steps 1-7 over `fd` (see [`Verified`]).
#[cfg(unix)]
pub(crate) fn verify(
    fd: std::os::fd::OwnedFd,
    manifest: &SignedManifest,
    trust: &TrustConfig,
    facts: &CryptoFacts,
) -> Result<Verified, Refusal> {
    use std::io::Read as _;
    let manifest_name = manifest.name.as_str();
    // 1: one regular file of at most 256 MiB, read once.
    let file = std::fs::File::from(fd);
    let meta = file.metadata().map_err(|e| {
        Refusal::new(
            RefusalCode::Integrity,
            "file",
            e.to_string(),
            "a readable file",
        )
        .named(manifest_name)
    })?;
    if !meta.is_file() || meta.len() > MAX_IMAGE_BYTES {
        let have = if meta.is_file() {
            format!("{} bytes", meta.len())
        } else {
            "not a regular file".to_string()
        };
        return Err(Refusal::new(
            RefusalCode::Integrity,
            "file",
            have,
            "a regular file of at most 256 MiB",
        )
        .named(manifest_name));
    }
    let mut bytes = Vec::with_capacity(meta.len() as usize);
    file.take(MAX_IMAGE_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| {
            Refusal::new(
                RefusalCode::Integrity,
                "file",
                e.to_string(),
                "a readable file",
            )
            .named(manifest_name)
        })?;
    if bytes.len() as u64 > MAX_IMAGE_BYTES {
        return Err(Refusal::new(
            RefusalCode::Integrity,
            "file",
            format!("over {MAX_IMAGE_BYTES} bytes"),
            "a regular file of at most 256 MiB",
        )
        .named(manifest_name));
    }
    // 2: the bytes are the ones the manifest names, and the manifest's signature is trusted.
    let sha256 = busbar_contract::crypto::sha256(&bytes);
    let hex = hex::encode(sha256);
    if !manifest.sha256.eq_ignore_ascii_case(&hex) {
        return Err(Refusal::new(
            RefusalCode::Integrity,
            "sha256",
            hex,
            "the manifest's sha256",
        )
        .named(manifest_name));
    }
    // The one evaluation over these bytes; its verdict and proof are this admission's signer (§2.1).
    let (verdict, proof) = match crate::sign::evaluate_with_verification(&bytes, manifest, trust) {
        Ok(judged) => judged,
        Err(rejected) => {
            return Err(Refusal::new(
                RefusalCode::Signature,
                "signature",
                rejected.reason,
                "a signature plugins.trust accepts",
            )
            .named(manifest_name));
        }
    };
    // 3: exactly one stamp, every field checked.
    let stamp = scan::stamp(&bytes).map_err(|e| e.refusal().named(manifest_name))?;
    let name = scan::text(&stamp.name).to_string();
    // 4-6 on the stamp; 7 against the signed manifest.
    let kind = compatible(&stamp, facts)?;
    manifest_matches(&stamp, kind, manifest)?;
    let former_names = joined(manifest);
    Ok(Verified {
        bytes,
        sha256,
        stamp,
        kind,
        name,
        former_names,
        signer: Signer::Dropped { verdict, proof },
    })
}

/// Steps 8-9, shared by install and inspection: stage and open the verified bytes on a permanent worker, then
/// check the header's stamp, `former_names` and null entries on the borrowed `Opened` (no admission). A refusal
/// closes the image on a worker before it returns.
#[cfg(unix)]
pub(crate) fn open_checked(
    v: &Verified,
) -> Result<(busbar_ffi::image::Opened, crate::stage::Staged), Refusal> {
    // 8: stage and open on the permanent worker (busbar-ffi runs dlopen, `busbar_plugin()` and the H4 checks).
    let (opened, staged) = crate::stage::open_image(&v.bytes, &v.name).map_err(|e| {
        match e {
            crate::stage::Unopened::Stage(why) => Refusal::new(
                RefusalCode::Integrity,
                "stage",
                why,
                "the verified bytes, staged unchanged",
            ),
            crate::stage::Unopened::Image(e) => image_refusal(&e),
            crate::stage::Unopened::Panicked => Refusal::new(
                RefusalCode::DoorStampMismatch,
                "busbar_plugin",
                "the image's initializer panicked",
                "an image that loads",
            ),
        }
        .named(&v.name)
    })?;
    // 9: the header presents the verified stamp and the signed former names, and no entry is null.
    let refused = if opened.stamp().0 != stamp_bytes(&v.stamp) {
        Some(Refusal::new(
            RefusalCode::DoorStampMismatch,
            "stamp",
            "another stamp",
            "the verified stamp",
        ))
    } else {
        match opened.former_names() {
            Ok(names) if names == v.former_names => opened
                .null_field()
                .map(|field| image_refusal(&ImageError::Null(field))),
            Ok(names) => Some(Refusal::new(
                RefusalCode::DoorStampMismatch,
                "former_names",
                printable_names(names),
                v.former_names.clone(),
            )),
            Err(_) => Some(Refusal::new(
                RefusalCode::DoorStampMismatch,
                "former_names",
                "not UTF-8",
                v.former_names.clone(),
            )),
        }
    };
    if let Some(refusal) = refused {
        crate::stage::close_on_worker(opened);
        drop(staged);
        return Err(refusal.named(&v.name));
    }
    Ok((opened, staged))
}

/// A header's `former_names` as a refusal may print it: only when every word passes `valid_name`.
#[cfg(unix)]
fn printable_names(names: &str) -> String {
    if names.is_empty() || names.split(',').all(crate::sign::valid_name) {
        names.to_string()
    } else {
        "names that are not [a-z0-9-]".to_string()
    }
}

/// The 272 little-endian bytes of a stamp (IF §7.4 offsets), to compare with the header's own.
#[cfg(unix)]
fn stamp_bytes(s: &Stamp) -> [u8; scan::STAMP_SIZE] {
    let mut b = [0u8; scan::STAMP_SIZE];
    let mut put = |at: usize, src: &[u8]| b[at..at + src.len()].copy_from_slice(src);
    put(0, &s.magic);
    put(16, &s.format.to_le_bytes());
    put(20, &s.size.to_le_bytes());
    put(24, &s.kind.to_le_bytes());
    put(28, &s.kind_abi.to_le_bytes());
    put(32, &s.mechanism.to_le_bytes());
    put(36, &s.flags.to_le_bytes());
    put(40, &s.layout.to_le_bytes());
    put(48, &s.mechanism_layout.to_le_bytes());
    put(56, &s.semantic.to_le_bytes());
    put(64, &s.mechanism_semantic.to_le_bytes());
    for (at, v) in [(72, s.engine_min), (80, s.engine_max)] {
        put(at, &v.major.to_le_bytes());
        put(at + 2, &v.minor.to_le_bytes());
        put(at + 4, &v.patch.to_le_bytes());
        put(at + 6, &v._reserved.to_le_bytes());
    }
    put(88, &s.name);
    put(152, &s.version);
    put(184, &s.target);
    put(216, &s.build_id);
    put(248, &s.crypto);
    put(256, &s._reserved);
    b
}

/// Compiled-in plugin: steps 3 to 7 on the static, no file, no signature. image = `Image::Linked`.
pub fn admit_linked(plugin: &'static LinkedPlugin) -> Result<Admitted, Refusal> {
    admit_linked_with(plugin, &CryptoFacts::FACADE)
}

fn admit_linked_with(
    plugin: &'static LinkedPlugin,
    facts: &CryptoFacts,
) -> Result<Admitted, Refusal> {
    admit_header_with(Header::linked(plugin), facts)
}

/// [`admit_linked`] for a caller that holds the `&'static Plugin` a plugin crate's `PLUGIN.plugin()` returns
/// (the SDK suites' frozen signatures): the same null, stamp and compatibility checks.
pub fn admit_header(plugin: &'static Plugin) -> Result<Admitted, Refusal> {
    admit_header_with(Header::from_header(plugin), &CryptoFacts::FACADE)
}

fn admit_header_with(
    header: Result<Header, ImageError>,
    facts: &CryptoFacts,
) -> Result<Admitted, Refusal> {
    let header = header.map_err(|e| image_refusal(&e))?;
    let stamp = scan::check(&header.stamp().0).map_err(scan::StampScanErr::refusal)?;
    compatible(&stamp, facts)?;
    Ok(Admitted {
        stamp,
        image: Arc::new(Image::Linked),
        plugin: header,
        signer: Signer::Linked,
    })
}

#[cfg(test)]
#[path = "tests/admit_tests.rs"]
mod tests;
