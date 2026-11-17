// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Native packaging inspects the same bounded image bytes it signs. This explicitly executes
//! the local build's initializers; archive structural validation never calls this module.

use crate::sign::Manifest;

/// Read one regular build artifact once, using admission's image-size bound.
pub fn read_image(path: &std::path::Path) -> Result<Vec<u8>, String> {
    use std::io::Read as _;
    let file = std::fs::File::open(path).map_err(|e| format!("{}: {e}", path.display()))?;
    let meta = file.metadata().map_err(|e| e.to_string())?;
    if !meta.is_file() || meta.len() > crate::admit::MAX_IMAGE_BYTES {
        return Err("pack requires a regular image of at most 256 MiB".into());
    }
    let mut bytes = Vec::new();
    file.take(crate::admit::MAX_IMAGE_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| e.to_string())?;
    if bytes.len() as u64 > crate::admit::MAX_IMAGE_BYTES {
        return Err("pack image exceeds 256 MiB".into());
    }
    Ok(bytes)
}

/// The stamp selects the native producer; malformed native artifacts cannot fall back.
pub fn is_native(bytes: &[u8]) -> Result<bool, String> {
    crate::sign::native_stamp(bytes).map(|stamp| stamp.is_some())
}

/// Complete the native manifest from the stamp/header. CLI identity values are assertions;
/// `abi_assertion` distinguishes an explicit ABI from the legacy caller's default.
pub fn complete(
    bytes: &[u8],
    mut manifest: Manifest,
    abi_assertion: Option<u32>,
) -> Result<Manifest, String> {
    if bytes.len() as u64 > crate::admit::MAX_IMAGE_BYTES {
        return Err("pack image exceeds 256 MiB".into());
    }
    let stamp = crate::sign::native_stamp(bytes)?.ok_or("native image has no stamp")?;
    let kind = crate::admit::compatible(&stamp, &crate::admit::CryptoFacts::FACADE)
        .map_err(|e| e.to_string())?;
    let name = crate::scan::text(&stamp.name);
    let version = crate::scan::text(&stamp.version);
    if !manifest.version.is_empty() && manifest.version != version {
        return Err(format!(
            "--version {} is not the version plugin '{name}' states in its native stamp ({version})",
            manifest.version
        ));
    }
    if manifest.name != name
        || manifest.kind != crate::admit::kind_word(kind)
        || abi_assertion.is_some_and(|abi| abi != stamp.kind_abi)
    {
        return Err("pack identity assertion disagrees with the native image stamp".into());
    }
    let names = inspect_names(bytes, name)?;
    if names.iter().filter(|word| **word == manifest.alias).count() != 1 {
        return Err("--alias must occur exactly once in the native header's former_names".into());
    }
    if !manifest.former_names.is_empty()
        && !names
            .iter()
            .filter(|word| **word != manifest.alias)
            .eq(manifest.former_names.iter())
    {
        return Err("--former-name assertions must equal the native header's ordered historical names excluding --alias".into());
    }
    manifest.name = name.into();
    manifest.version = version.into();
    manifest.kind = crate::admit::kind_word(kind).into();
    manifest.abi_version = stamp.kind_abi;
    manifest.former_names = names;
    // Validate operational-field authority here too, before signing or publishing any bytes.
    manifest.sha256 = crate::sign::sha256_hex(bytes);
    crate::sign::validate_structure(
        &manifest,
        bytes,
        &crate::supported_abi,
        crate::sign::HOST_IDENTITY,
    )?;
    Ok(manifest)
}

#[cfg(unix)]
struct Inspection {
    opened: Option<busbar_ffi::image::Opened>,
    _staged: crate::stage::Staged,
}

#[cfg(unix)]
impl Inspection {
    fn finish(mut self) -> Result<(), &'static str> {
        let Some(custody) = self.custody.take() else {
            return Ok(());
        };
        if crate::stage::close_on_worker(custody) {
            Ok(())
        } else {
            Err("native pack teardown is uncertain; image backing retained")
        }
    }
}

#[cfg(unix)]
impl Drop for Inspection {
    fn drop(&mut self) {
        if let Some(opened) = self.opened.take() {
            crate::stage::close_on_worker(opened);
        }
        // Field teardown releases staging only after the worker closed the image.
    }
}

#[cfg(unix)]
fn inspect_names(bytes: &[u8], name: &str) -> Result<Vec<String>, String> {
    let (opened, staged) = crate::stage::open_image(bytes, name).map_err(|error| match error {
        crate::stage::Unopened::Stage(why) => format!("native pack staging: {why}"),
        crate::stage::Unopened::Image(why) => format!("native pack header: {why:?}"),
        crate::stage::Unopened::Panicked => "native pack initializer panicked".into(),
    })?;
    let inspection = Inspection {
        opened: Some(opened),
        _staged: staged,
    };
    let opened = inspection
        .opened
        .as_ref()
        .ok_or("native pack inspection is closed")?;
    // The header's stamp must match the scanned bytes, not merely their identity fields.
    // complete already established exactly one well-formed stamp; retain its original encoding.
    let stamped = bytes
        .windows(crate::scan::STAMP_SIZE)
        .find(|window| window.starts_with(&busbar_plugin_abi::stamp::STAMP_MAGIC))
        .ok_or("native stamp disappeared from immutable image bytes")?;
    if opened.stamp().0.as_slice() != stamped {
        return Err("native header stamp differs from the image stamp".into());
    }
    let words = opened
        .former_names()
        .map_err(|_| "native former_names is not UTF-8")?;
    let mut names = Vec::new();
    if !words.is_empty() {
        for word in words.split(',') {
            if names.len() == 8
                || word.len() > 64
                || !crate::sign::valid_name(word)
                || word == name
                || names.iter().any(|prior| prior == word)
            {
                return Err(
                    "native header former_names contains an invalid, duplicate or canonical name"
                        .into(),
                );
            }
            names.push(word.to_owned());
        }
    }
    inspection.finish()?;
    Ok(names)
}

#[cfg(not(unix))]
fn inspect_names(_bytes: &[u8], _name: &str) -> Result<Vec<String>, String> {
    Err("native pack inspection requires a platform with the native staged-image loader".into())
}

#[cfg(all(test, unix))]
#[path = "tests/pack_native_tests.rs"]
mod tests;
