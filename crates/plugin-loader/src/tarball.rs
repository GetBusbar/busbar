// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The one-file-per-plugin **signed tarball** format: a `.tar.gz` containing EXACTLY
//!
//! - `manifest.json` - the signed [`busbar_plugin_sign::Manifest`];
//! - one library file - the cdylib the manifest's `sha256` pins.
//!
//! [`unpack`] extracts FULLY IN MEMORY on every platform (the manifest never touches disk; the
//! library bytes only ever reach disk as loader staging output, never as trusted input), with hard
//! bounds on member count and decompressed sizes so a hostile archive (zip-bomb, entry flood,
//! path-traversal names) is refused before it can cost anything. [`package`] is the inverse, used
//! by the release pipeline, the packaging CLI, and tests.

use busbar_plugin_sign::Manifest;
use std::io::Read as _;

/// The manifest member name inside every plugin tarball.
pub const MANIFEST_FILE: &str = "manifest.json";

/// Hard cap on the DECOMPRESSED library member - matches the loader's own response cap scale; far
/// beyond any real cdylib (the shipped store plugins are single-digit MiB).
const MAX_LIB_BYTES: u64 = 256 * 1024 * 1024;
/// Hard cap on the DECOMPRESSED manifest member - a manifest is well under 4 KiB.
const MAX_MANIFEST_BYTES: u64 = 1024 * 1024;

/// Hard cap on the COMPRESSED tarball FILE, checked via `fs::metadata` before it is ever read into
/// memory (see `registry::examine`). [`unpack`] already bounds the two DECOMPRESSED members it will
/// extract (`MAX_LIB_BYTES` + `MAX_MANIFEST_BYTES`); this is that same ceiling applied to the file on
/// disk, one layer earlier. Gzip cannot meaningfully inflate a file's size (worst case is a few bytes
/// of overhead per block, nowhere near doubling it), so a genuine tarball containing only a
/// manifest + a library under the existing per-member caps is always comfortably under this sum -
/// anything larger is rejected before the read, not after.
// `pub`, not `pub(crate)`: `POST /plugins/inspect` needs this SAME ceiling to size its own
// request-body cap on the base64-encoded upload,
// checked BEFORE the decoder ever runs — one source of truth for "how big can a plugin tarball
// legitimately be", not a second guessed constant that could silently drift from this one.
pub const MAX_TARBALL_FILE_BYTES: u64 = MAX_LIB_BYTES + MAX_MANIFEST_BYTES;

/// A plugin tarball unpacked in memory: the parsed signed manifest plus the exact library bytes.
#[derive(Debug)]
pub struct UnpackedPlugin {
    pub manifest: Manifest,
    /// The library member's archived filename (display only - identity comes from the manifest).
    pub lib_name: String,
    pub lib_bytes: Vec<u8>,
}

/// Is this filename a plugin tarball (`.tar.gz` / `.tgz`)?
pub fn is_plugin_tarball(file: &str) -> bool {
    file.ends_with(".tar.gz") || file.ends_with(".tgz")
}

/// Build a plugin tarball: gzip'd tar with `manifest.json` (serialized from `manifest`) and the
/// library under `lib_name`. Deterministic enough for tests; the release pipeline signs the
/// manifest BEFORE packaging (the tarball itself carries no outer signature - the manifest inside
/// is the signed unit and it pins the library by sha256).
pub fn package(manifest: &Manifest, lib_name: &str, lib_bytes: &[u8]) -> Result<Vec<u8>, String> {
    let manifest_json = serde_json::to_vec_pretty(manifest)
        .map_err(|e| format!("manifest serialize failed: {e}"))?;
    let gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    let mut tar = tar::Builder::new(gz);
    let mut add = |name: &str, bytes: &[u8]| -> Result<(), String> {
        let mut header = tar::Header::new_gnu();
        header.set_size(bytes.len() as u64);
        header.set_mode(0o644);
        header.set_mtime(0);
        header.set_cksum();
        tar.append_data(&mut header, name, bytes)
            .map_err(|e| format!("tar append '{name}' failed: {e}"))
    };
    add(MANIFEST_FILE, &manifest_json)?;
    add(lib_name, lib_bytes)?;
    let gz = tar
        .into_inner()
        .map_err(|e| format!("tar finalize failed: {e}"))?;
    gz.finish()
        .map_err(|e| format!("gzip finalize failed: {e}"))
}

/// Ceiling on the up-front allocation reserved for a member read, independent of the member's
/// declared size. Mirrors `proxy::wire::read_capped`'s `READ_CAPPED_RESERVE_CEILING`: the DECLARED
/// size in a tar header is unverified input at this point (this runs before any signature/trust
/// check), so trusting it for an eager `Vec::with_capacity` reservation lets a malformed/truncated
/// header force a large allocation before a single real byte is validated. The `size > cap`
/// rejection below is a DIFFERENT, unrelated check that stays exactly as-is: refusing a
/// declared-oversize member before reading is a cheap, fail-closed refusal and is fine to keep
/// keying off the declared size — the bug this constant fixes is trusting declared size for
/// ALLOCATION, not for rejection. The two checks stay separate.
const MEMBER_RESERVE_CEILING: u64 = 64 * 1024;

/// Read one tar entry fully, bounded at `cap` decompressed bytes. An entry whose DECLARED size
/// exceeds the cap is refused before any read.
fn read_entry_bounded<R: std::io::Read>(
    entry: &mut tar::Entry<'_, R>,
    cap: u64,
    what: &str,
) -> Result<Vec<u8>, String> {
    let size = entry.size();
    if size > cap {
        return Err(format!(
            "{what} member is {size} bytes, exceeding the {cap}-byte cap"
        ));
    }
    // Reserve only up to `MEMBER_RESERVE_CEILING` up front, regardless of `size` — `size` is the
    // header's self-declared, as-yet-unverified value. Real reads beyond the ceiling grow the
    // buffer amortized (alloc+copy+dealloc) via `read_to_end`, same as any other trusted-input
    // buffer; a lying/truncated header now costs at most one bounded reservation, not up to `cap`.
    let mut buf = Vec::with_capacity(size.min(MEMBER_RESERVE_CEILING) as usize);
    // `take(cap + 1)`: even a lying header cannot stream more than the cap into memory.
    entry
        .take(cap + 1)
        .read_to_end(&mut buf)
        .map_err(|e| format!("cannot read {what} member: {e}"))?;
    if buf.len() as u64 > cap {
        return Err(format!("{what} member exceeds the {cap}-byte cap"));
    }
    Ok(buf)
}

/// Unpack a plugin tarball FULLY IN MEMORY, fail-closed: the archive must contain EXACTLY one
/// `manifest.json` and EXACTLY one other regular file (the library), nothing else - no
/// directories, links, absolute paths, or parent references. Returns the parsed manifest + the
/// exact library bytes; every failure names the specific violation.
///
/// NOTE: this performs NO signature/trust/structure checks - it is pure decoding. The caller runs
/// phase 1 (structural) and phase 2 (trust) over the returned parts.
pub fn unpack(bytes: &[u8]) -> Result<UnpackedPlugin, String> {
    let gz = flate2::read::GzDecoder::new(bytes);
    let mut archive = tar::Archive::new(gz);
    let mut manifest: Option<Manifest> = None;
    let mut lib: Option<(String, Vec<u8>)> = None;

    let entries = archive
        .entries()
        .map_err(|e| format!("not a readable tar.gz archive: {e}"))?;
    for entry in entries {
        let mut entry = entry.map_err(|e| format!("corrupt tar.gz archive: {e}"))?;
        if entry.header().entry_type() != tar::EntryType::Regular {
            return Err(format!(
                "archive contains a non-regular-file entry ({:?}); a plugin tarball holds exactly \
                 manifest.json and the library",
                entry.header().entry_type()
            ));
        }
        let path = entry
            .path()
            .map_err(|e| format!("archive entry has an unreadable path: {e}"))?;
        // Reject traversal/absolute names outright; then key on the flattened basename.
        if path.components().any(|c| {
            !matches!(
                c,
                std::path::Component::Normal(_) | std::path::Component::CurDir
            )
        }) {
            return Err(format!(
                "archive entry '{}' has an unsafe path (absolute or parent reference)",
                path.display()
            ));
        }
        let name = path
            .file_name()
            .and_then(|f| f.to_str())
            .ok_or_else(|| "archive entry has no usable filename".to_string())?
            .to_string();
        if name == MANIFEST_FILE {
            if manifest.is_some() {
                return Err("archive contains more than one manifest.json".to_string());
            }
            let raw = read_entry_bounded(&mut entry, MAX_MANIFEST_BYTES, "manifest")?;
            let m: Manifest = serde_json::from_slice(&raw)
                .map_err(|e| format!("manifest.json does not parse: {e}"))?;
            manifest = Some(m);
        } else {
            if lib.is_some() {
                return Err(format!(
                    "archive contains more than one library member ('{}' and '{name}'); a plugin \
                     tarball holds exactly one",
                    lib.as_ref().map(|(n, _)| n.as_str()).unwrap_or("?")
                ));
            }
            let raw = read_entry_bounded(&mut entry, MAX_LIB_BYTES, "library")?;
            lib = Some((name, raw));
        }
    }

    let manifest = manifest.ok_or_else(|| "archive has no manifest.json".to_string())?;
    let (lib_name, lib_bytes) = lib.ok_or_else(|| "archive has no library member".to_string())?;
    Ok(UnpackedPlugin {
        manifest,
        lib_name,
        lib_bytes,
    })
}

#[cfg(test)]
#[path = "tests/tarball_tests.rs"]
mod tests;
