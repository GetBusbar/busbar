// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The release half of `busbar-plugin-pack`: the three commands of the hardware-key signing flow.
//! The signing key never reaches this tool or any CI runner.
//!
//! 1. `canonical`. CI packs a plugin UNSIGNED (`pack --allow-unsigned`) and runs this command. It
//!    prints, and with `--out` writes, the exact bytes the loader verifies a signature over
//!    ([`canonical_manifest_bytes`]), with their sha256. The owner re-derives the same bytes from the
//!    same tarball and signs them on the hardware key.
//! 2. `attach`. Inserts that 64-byte Ed25519 signature into the manifest and repackages. It refuses
//!    unless the result verifies against the given key list, so a wrong or corrupted signature
//!    never produces a tarball.
//! 3. `verify`. The publish gate's per-plugin check. It runs the loader's own structural validation,
//!    then strict Ed25519 verification against a first-party key list. It prints `VERIFIED …` and
//!    exits 0, or prints `REFUSED …` with the reason and exits 1.
//!
//! The key list uses the format of `BUSBAR_RELEASE_PUBKEY`: comma-separated entries, each
//! `<id>:<64 hex>` or a bare `<64 hex>`.

use busbar_plugin_loader::sign::{
    canonical_manifest_bytes, public_key_from_hex, sha256_hex, valid_name, validate_structure,
    Manifest, VerifyingKey, FIRST_PARTY_PUBLISHER, HOST_IDENTITY,
};
use busbar_plugin_loader::tarball::{package, unpack, UnpackedPlugin};
use ed25519_dalek::Signature;
use std::process::ExitCode;

/// One first-party key: its id (named in every verdict) and the public key.
pub(crate) struct ListedKey {
    pub(crate) id: String,
    pub(crate) key: VerifyingKey,
}

/// Parse a first-party key list. Every entry must be a usable key; [`public_key_from_hex`] refuses
/// a weak (small-order) key. Ids are `[a-z0-9-]+`, and neither an id nor a key may repeat. An empty
/// list is refused: a gate given no key must not be able to pass anything.
pub(crate) fn parse_key_list(spec: &str) -> Result<Vec<ListedKey>, String> {
    let mut keys: Vec<ListedKey> = Vec::new();
    for (i, entry) in spec.split(',').map(str::trim).enumerate() {
        let n = i + 1;
        if entry.is_empty() {
            return Err(format!("key list entry {n} is empty"));
        }
        let (id, hex_key) = match entry.split_once(':') {
            Some((id, hex_key)) => (Some(id.trim()), hex_key.trim()),
            None => (None, entry),
        };
        let key = public_key_from_hex(hex_key).map_err(|e| format!("key list entry {n}: {e}"))?;
        let id = match id {
            Some(id) if !valid_name(id) => {
                return Err(format!(
                    "key list entry {n}: id '{id}' is not lowercase [a-z0-9-]+"
                ))
            }
            Some(id) => id.to_string(),
            None => format!("ed25519:{}", &hex::encode(key.as_bytes())[..16]),
        };
        if let Some(dup) = keys.iter().find(|k| k.id == id || k.key == key) {
            return Err(format!(
                "key list entry {n} ('{id}') repeats the id or key of '{}'",
                dup.id
            ));
        }
        keys.push(ListedKey { id, key });
    }
    Ok(keys)
}

/// Read the `--flag value` pairs a release command takes; each flag at most once, and every
/// argument is either a known flag or the one positional tarball path.
fn parse(args: &[String], known: &[&str]) -> Result<(String, Vec<(String, String)>), String> {
    let mut tarball: Option<String> = None;
    let mut flags: Vec<(String, String)> = Vec::new();
    let mut it = args.iter();
    while let Some(a) = it.next() {
        if let Some(name) = a.strip_prefix("--") {
            if !known.contains(&name) {
                return Err(format!("unknown flag --{name}"));
            }
            if flags.iter().any(|(k, _)| k == name) {
                return Err(format!("--{name} given twice"));
            }
            let v = it.next().ok_or_else(|| format!("--{name} needs a value"))?;
            flags.push((name.to_string(), v.clone()));
        } else if tarball.is_none() {
            tarball = Some(a.clone());
        } else {
            return Err(format!("unexpected argument '{a}' (one tarball per call)"));
        }
    }
    let tarball = tarball.ok_or_else(|| "missing <tarball>".to_string())?;
    Ok((tarball, flags))
}

fn flag<'a>(flags: &'a [(String, String)], name: &str) -> Option<&'a str> {
    flags
        .iter()
        .find(|(k, _)| k == name)
        .map(|(_, v)| v.as_str())
}

fn read_plugin(path: &str) -> Result<UnpackedPlugin, String> {
    let bytes = std::fs::read(path).map_err(|e| format!("cannot read '{path}': {e}"))?;
    unpack(&bytes).map_err(|e| format!("'{path}' is not a plugin tarball: {e}"))
}

/// The digest the owner signs: sha256 of the canonical manifest bytes.
fn canonical_sha256(m: &Manifest) -> String {
    sha256_hex(&canonical_manifest_bytes(m))
}

/// The first-party verdict on one unpacked plugin: the loader's structural validation, then strict
/// Ed25519 verification against a key on the list. Returns the id of the key that verified.
pub(crate) fn verify_first_party(p: &UnpackedPlugin, keys: &[ListedKey]) -> Result<String, String> {
    let m = &p.manifest;
    validate_structure(
        m,
        &p.lib_bytes,
        &busbar_plugin_loader::supported_abi,
        HOST_IDENTITY,
    )
    .map_err(|e| format!("structural validation: {e}"))?;
    if m.publisher != FIRST_PARTY_PUBLISHER {
        return Err(format!(
            "publisher is '{}', not '{FIRST_PARTY_PUBLISHER}': not a first-party plugin",
            m.publisher
        ));
    }
    if m.signature.trim().is_empty() {
        return Err("the manifest carries no signature".to_string());
    }
    if sha256_hex(&p.lib_bytes) != m.sha256.to_ascii_lowercase() {
        return Err(format!(
            "library sha256 {} does not match the manifest's {}",
            sha256_hex(&p.lib_bytes),
            m.sha256
        ));
    }
    let sig = hex::decode(m.signature.trim()).map_err(|e| format!("signature is not hex: {e}"))?;
    let sig: [u8; 64] = sig
        .as_slice()
        .try_into()
        .map_err(|_| format!("signature is {} bytes, not 64", sig.len()))?;
    let sig = Signature::from_bytes(&sig);
    let msg = canonical_manifest_bytes(m);
    // STRICT verification, exactly as the loader's `signature_ok`: refuses weak keys and
    // non-canonical `R`.
    keys.iter()
        .find(|k| k.key.verify_strict(&msg, &sig).is_ok())
        .map(|k| k.id.clone())
        .ok_or_else(|| {
            let ids: Vec<&str> = keys.iter().map(|k| k.id.as_str()).collect();
            format!(
                "the signature verifies against none of the {} listed key(s) [{}]",
                ids.len(),
                ids.join(", ")
            )
        })
}

/// Decode a signature given as 128 hex digits, or as a file holding either the hex or the raw 64
/// bytes a hardware key writes.
fn read_signature(spec: &str) -> Result<[u8; 64], String> {
    let raw: Vec<u8> = if let Some(path) = spec.strip_prefix('@') {
        let bytes =
            std::fs::read(path).map_err(|e| format!("cannot read signature file '{path}': {e}"))?;
        if bytes.len() == 64 {
            bytes
        } else {
            let text = String::from_utf8(bytes)
                .map_err(|_| format!("signature file '{path}' is neither 64 raw bytes nor hex"))?;
            hex::decode(text.trim())
                .map_err(|e| format!("signature file '{path}' is not hex: {e}"))?
        }
    } else {
        hex::decode(spec.trim()).map_err(|e| format!("--signature is not hex: {e}"))?
    };
    raw.as_slice()
        .try_into()
        .map_err(|_| format!("the signature is {} bytes, not 64", raw.len()))
}

/// `canonical <tarball> [--out <file>]`
pub(crate) fn canonical(args: &[String]) -> ExitCode {
    let run = || -> Result<String, String> {
        let (path, flags) = parse(args, &["out"])?;
        let p = read_plugin(&path)?;
        let bytes = canonical_manifest_bytes(&p.manifest);
        if let Some(out) = flag(&flags, "out") {
            std::fs::write(out, &bytes).map_err(|e| format!("cannot write '{out}': {e}"))?;
        }
        let m = &p.manifest;
        Ok(format!(
            "canonical-sha256={} name={} version={} kind={} publisher={} lib-sha256={} signed={}",
            sha256_hex(&bytes),
            m.name,
            m.version,
            m.kind,
            m.publisher,
            m.sha256,
            !m.signature.trim().is_empty()
        ))
    };
    report(run())
}

/// `attach <tarball> --signature <hex|@file> --keys <list> --out <file>`
pub(crate) fn attach(args: &[String]) -> ExitCode {
    let run = || -> Result<String, String> {
        let (path, flags) = parse(args, &["signature", "keys", "out"])?;
        let sig = read_signature(
            flag(&flags, "signature").ok_or("missing --signature <128 hex | @file>")?,
        )?;
        let keys = parse_key_list(flag(&flags, "keys").ok_or("missing --keys <list>")?)?;
        let out = flag(&flags, "out").ok_or("missing --out <file>")?;
        let mut p = read_plugin(&path)?;
        if !p.manifest.signature.trim().is_empty() {
            return Err(format!(
                "'{path}' is already signed; attach takes the UNSIGNED tarball CI emitted"
            ));
        }
        let before = canonical_sha256(&p.manifest);
        p.manifest.signature = hex::encode(sig);
        // The signature field is outside the canonical bytes, so attaching cannot change what was
        // signed. Checked anyway: a change here would mean the owner signed other bytes.
        if canonical_sha256(&p.manifest) != before {
            return Err("attaching the signature changed the canonical bytes".to_string());
        }
        let key_id = verify_first_party(&p, &keys)?;
        let tarball = package(&p.manifest, &p.lib_name, &p.lib_bytes)?;
        // Verify what was actually written, not the in-memory copy.
        let back = unpack(&tarball).map_err(|e| format!("the repackaged tarball: {e}"))?;
        verify_first_party(&back, &keys)?;
        std::fs::write(out, &tarball).map_err(|e| format!("cannot write '{out}': {e}"))?;
        Ok(format!(
            "attached {} v{} key={key_id} canonical-sha256={before} tarball-sha256={} -> {out}",
            p.manifest.name,
            p.manifest.version,
            sha256_hex(&tarball)
        ))
    };
    report(run())
}

/// `verify <tarball> --keys <list> [--name <name>] [--version <semver>]`
pub(crate) fn verify(args: &[String]) -> ExitCode {
    let mut path_for_refusal = String::new();
    let run = |path_out: &mut String| -> Result<String, String> {
        let (path, flags) = parse(args, &["keys", "name", "version"])?;
        *path_out = path.clone();
        let keys = parse_key_list(flag(&flags, "keys").ok_or("missing --keys <list>")?)?;
        let p = read_plugin(&path)?;
        let key_id = verify_first_party(&p, &keys)?;
        let m = &p.manifest;
        if let Some(want) = flag(&flags, "name") {
            if m.name != want {
                return Err(format!("manifest name is '{}', expected '{want}'", m.name));
            }
        }
        if let Some(want) = flag(&flags, "version") {
            if m.version != want {
                return Err(format!(
                    "manifest version is '{}', expected '{want}'",
                    m.version
                ));
            }
        }
        Ok(format!(
            "VERIFIED {path} name={} version={} kind={} key={key_id} lib-sha256={} canonical-sha256={}",
            m.name,
            m.version,
            m.kind,
            m.sha256.to_ascii_lowercase(),
            canonical_sha256(m)
        ))
    };
    match run(&mut path_for_refusal) {
        Ok(msg) => {
            println!("{msg}");
            ExitCode::SUCCESS
        }
        Err(e) => {
            println!("REFUSED {path_for_refusal}: {e}");
            ExitCode::FAILURE
        }
    }
}

fn report(r: Result<String, String>) -> ExitCode {
    match r {
        Ok(msg) => {
            println!("{msg}");
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::FAILURE
        }
    }
}
