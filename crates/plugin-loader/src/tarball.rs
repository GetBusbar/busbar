// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use crate::sign::Manifest;
use std::io::Read as _;

pub const MANIFEST_FILE: &str = "manifest.json";

const MAX_LIB_BYTES: u64 = 256 * 1024 * 1024;

const MAX_MANIFEST_BYTES: u64 = 1024 * 1024;

pub const MAX_TARBALL_FILE_BYTES: u64 = MAX_LIB_BYTES + MAX_MANIFEST_BYTES;

/// A plugin tarball unpacked in memory: the parsed signed manifest plus the exact library bytes.
#[derive(Debug)]
pub struct UnpackedPlugin {
    pub manifest: Manifest,
    /// The library member's archived filename (display only - identity comes from the manifest).
    pub lib_name: String,
    pub lib_bytes: Vec<u8>,
}

pub fn is_plugin_tarball(file: &str) -> bool {
    file.ends_with(".tar.gz") || file.ends_with(".tgz")
}

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

const MEMBER_RESERVE_CEILING: u64 = 64 * 1024;

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

    let mut buf = Vec::with_capacity(size.min(MEMBER_RESERVE_CEILING) as usize);

    entry
        .take(cap + 1)
        .read_to_end(&mut buf)
        .map_err(|e| format!("cannot read {what} member: {e}"))?;
    if buf.len() as u64 > cap {
        return Err(format!("{what} member exceeds the {cap}-byte cap"));
    }
    Ok(buf)
}

struct EofAsKind<R>(R);

impl<R: std::io::Read> std::io::Read for EofAsKind<R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.0.read(buf).map_err(|e| match e.kind() {
            std::io::ErrorKind::UnexpectedEof => std::io::ErrorKind::UnexpectedEof.into(),
            _ => e,
        })
    }
}

pub fn unpack(bytes: &[u8]) -> Result<UnpackedPlugin, String> {
    let gz = EofAsKind(flate2::read::GzDecoder::new(bytes));
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
