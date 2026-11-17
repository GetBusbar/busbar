// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! `busbar-plugin-pack` - the packaging + signing tool for busbar plugins.
//!
//! A busbar plugin ships as ONE signed `.tar.gz` containing exactly the cdylib and its signed
//! `manifest.json`. This tool builds that artifact:
//!
//! ```text
//! busbar-plugin-pack pack \
//!     --lib target/release/libbusbar_store_example_plugin.so \
//!     --name busbar-store-example-plugin --alias example --kind store \
//!     --version 1.5.0 --publisher busbar \
//!     --out busbar-store-example-1.5.0-x86_64-linux.tar.gz
//! ```
//!
//! The ed25519 SIGNING key is read from the `BUSBAR_SIGN_KEY` environment variable (64 hex chars:
//! the 32-byte seed) - in CI this is the release secret; a third-party publisher uses their own.
//! With no key set, `--allow-unsigned` produces an UNSIGNED tarball (dev only: busbar loads it
//! solely under `plugins.trust.allow_untrusted: true`).
//!
//! `busbar-plugin-pack keygen` generates a fresh keypair and prints both halves (hex). The PUBLIC
//! half goes in `plugins.trust.publishers` (third-party) or is embedded into the busbar binary at
//! build time via `BUSBAR_RELEASE_PUBKEY` (first-party); the PRIVATE half is the signing secret.

//!
//! FIRST-PARTY RELEASES ARE SEALED, ONE SIGNATURE PER RELEASE (`docs/design/release-trust.md`). A
//! release packs every plugin UNSIGNED; `release-manifest` writes the bytes of the one release
//! manifest listing every tarball for its target; the release signer signs those bytes once;
//! `envelope` wraps them with that signature (refusing one that does not verify); `seal` puts the
//! keys document and the release manifest into each tarball, refusing unless the result verifies
//! through the chain against the ROOT key list (`--keys`, or the `BUSBAR_RELEASE_PUBKEY` list this
//! tool was built with, the same list the engine embeds); `verify` re-checks a sealed tarball.
//! `keys-doc` writes the bytes of a keys document a root signs. The byte encoding of every
//! document is `busbar_plugin_loader::release_trust::wire`'s alone; the release gate
//! (`busbar-publish-gate`, owner release tooling) drives these commands and never spells a byte.

use busbar_plugin_loader::release_trust::{self, wire, ReleaseKey};
#[cfg(test)]
use busbar_plugin_loader::settings_schema::validate_secret_fields;
use busbar_plugin_loader::sign::{
    canonical_manifest_bytes, embedded_release_keys, first_party_signer_for, parse_release_keys,
    sha256_hex, sign, FirstPartyKey, Manifest, NeedLevel, SigningKey, FIRST_PARTY_PUBLISHER,
};
use std::collections::HashMap;
use std::process::ExitCode;

const SIGN_KEY_ENV: &str = "BUSBAR_SIGN_KEY";

#[cfg(test)]
const SCHEMA_2020_12: &str = "https://json-schema.org/draft/2020-12/schema";

#[cfg(test)]
const BUSBAR_REF_VALUES: &[&str] = &["pool", "group", "model", "provider"];

fn parse_need_level(s: &str) -> Result<NeedLevel, String> {
    match s.trim().to_ascii_lowercase().as_str() {
        "no" | "none" | "" => Ok(NeedLevel::No),
        "ro" | "read" => Ok(NeedLevel::Ro),
        "rw" | "readwrite" | "read-write" => Ok(NeedLevel::Rw),
        other => Err(format!("need level '{other}' is not one of no|ro|rw")),
    }
}

fn usage() -> &'static str {
    "busbar-plugin-pack - package + sign a busbar plugin tarball

USAGE:
    busbar-plugin-pack pack --lib <cdylib> --name <name> --alias <alias> --kind <store|auth|hook|secret|export|plane|transport>
                            [--version <semver>] [--abi-version <number>] --publisher <publisher> --out <file.tar.gz>
                            [--description <text>] [--homepage <url>] [--license <spdx>]
                            [--former-name <name>]...
                            [--native] [--allow-unsigned]
    busbar-plugin-pack keygen
    busbar-plugin-pack canonical <tarball> [--out <file>]
    busbar-plugin-pack release-manifest --version <n> --expires <time> --out <file> <tarball>=<target>...
    busbar-plugin-pack keys-doc --spec <spec.json> --out <file>
    busbar-plugin-pack envelope --signed <file> --key <alg>:<hex> --signature <file> --out <file>
    busbar-plugin-pack keyid <alg>:<hex>
    busbar-plugin-pack seal <tarball> --keys-doc <file> --release <file> --target <triple> [--keys <list>] --out <file>
    busbar-plugin-pack verify <tarball> [--keys <list>] [--target <triple>] [--name <name>] [--version <semver>]

    pack     builds manifest.json over the cdylib (sha256 binding), signs it with the ed25519 seed
             in $BUSBAR_SIGN_KEY (64 hex chars), and writes the {cdylib + manifest.json} .tar.gz.
             Native images supply identity/version/ABI from their stamp and the complete ordered
             former_names from their header. CLI identity values are equality assertions; an explicit
             --former-name list asserts the historical names excluding --alias. Native describe data
             is authenticated by the image digest; legacy declares/schema/needs flags are refused.
             Every artifact must carry a native stamp; --native is an optional explicit assertion.
             Legacy and unstamped images are refused before loading. Inspection runs on a compatible native host.
             --allow-unsigned permits packaging WITHOUT a signature (dev only; busbar loads such a
             tarball only under plugins.trust.allow_untrusted: true).
             --former-name (repeatable) names a manifest name an EARLIER release of the plugin
             carried (plugins.yaml `former_names:`): busbar resolves a config naming it to this
             plugin, as it resolves the alias. SIGNED; lowercase [a-z0-9-]+, never the plugin's own
             name or alias.
    keygen   generates a fresh ed25519 keypair and prints both halves as hex. Keep the private half
             secret (it becomes $BUSBAR_SIGN_KEY); publish/allowlist the public half.
    canonical
             writes the tarball manifest's canonical signed bytes (every field but `signature`) to
             --out, and prints one k=v line: canonical-sha256, name, version, kind, publisher,
             lib-sha256, signed. The canonical bytes are what a first-party signature is made over.
    release-manifest
             writes the SIGNED BYTES of one release manifest listing each <tarball> (first-party,
             unsigned) for its <target>: name, version, target, canonical-manifest sha256 and
             length. <time> is YYYY-MM-DDTHH:MM:SSZ. The release signer signs exactly these bytes.
    keys-doc writes the SIGNED BYTES of a keys document from a JSON spec: version, expires,
             signers ([\"<alg>:<hex>\"...]), threshold, revoked_keyids, revoked_digests
             ({\"<sha256>\": \"<why>\"}). A root key signs exactly these bytes.
    envelope wraps signed bytes with one signature (raw: DER for p256, 64 bytes for ed25519) by the
             key <alg>:<hex>, refusing a signature that does not verify over them.
    keyid    prints the key id of <alg>:<hex> (alg: p256 | ed25519).
    seal     puts the keys document and the release manifest into an UNSIGNED first-party tarball
             and writes the sealed one, refusing unless it verifies through the chain for
             --target against the root keys: --keys <list> (the BUSBAR_RELEASE_PUBKEY format), or
             the list this tool was built with.
    verify   checks a sealed (or per-plugin signed) first-party tarball against those keys, for
             --target (default: this tool's own) and --name/--version when given: prints VERIFIED
             ... and exits 0, or REFUSED <path>: <reason> and exits 1."
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        Some("keygen") => keygen(),
        Some("pack") => pack(&args[1..]),
        Some("canonical") => report(canonical_cli(&args[1..])),
        Some("release-manifest") => report(release_manifest_cli(&args[1..])),
        Some("keys-doc") => report(keys_doc_cli(&args[1..])),
        Some("envelope") => report(envelope_cli(&args[1..])),
        Some("keyid") => report(keyid_cli(&args[1..])),
        Some("seal") => report(seal_cli(&args[1..])),
        Some("verify") => verify_cli(&args[1..]),
        Some("--help" | "-h") | None => {
            println!("{}", usage());
            ExitCode::SUCCESS
        }
        Some(other) => {
            eprintln!("unknown command '{other}'\n\n{}", usage());
            ExitCode::from(2)
        }
    }
}

fn report(outcome: Result<String, String>) -> ExitCode {
    match outcome {
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

fn release_args(
    args: &[String],
    known: &[&str],
) -> Result<(String, Vec<(String, String)>), String> {
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

fn read_file(path: &str) -> Result<Vec<u8>, String> {
    std::fs::read(path).map_err(|e| format!("cannot read '{path}': {e}"))
}

fn release_keys(flags: &[(String, String)]) -> Result<Vec<FirstPartyKey>, String> {
    match flag(flags, "keys") {
        Some(spec) => parse_release_keys(spec).map_err(|e| format!("--keys: {e}")),
        None => Ok(embedded_release_keys()),
    }
}

fn canonical_sha256(m: &Manifest) -> String {
    sha256_hex(&canonical_manifest_bytes(m))
}

fn canonical_cli(args: &[String]) -> Result<String, String> {
    let (path, flags) = release_args(args, &["out"])?;
    let p = busbar_plugin_loader::tarball::unpack(&read_file(&path)?)
        .map_err(|e| format!("'{path}' is not a plugin tarball: {e}"))?;
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
}

fn release_checks() -> release_trust::Checks {
    release_trust::Checks {
        now: release_trust::now(),
        keys_floor: 0,
        enforce_expiry: true,
    }
}

fn public_key(spec: &str) -> Result<ReleaseKey, String> {
    parse_release_keys(&format!("key:{}", spec.trim()))
        .map(|mut k| k.remove(0).key)
        .map_err(|e| format!("key '{spec}': {e}"))
}

type FlagPairs = Vec<(String, String)>;

fn flag_args(args: &[String], known: &[&str]) -> Result<(Vec<String>, FlagPairs), String> {
    let mut pos = Vec::new();
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
        } else {
            pos.push(a.clone());
        }
    }
    Ok((pos, flags))
}

fn need<'a>(flags: &'a [(String, String)], name: &str) -> Result<&'a str, String> {
    flag(flags, name).ok_or_else(|| format!("missing --{name}"))
}

fn write_file(path: &str, bytes: &[u8]) -> Result<(), String> {
    std::fs::write(path, bytes).map_err(|e| format!("cannot write '{path}': {e}"))
}

pub(crate) fn release_entry(tarball: &[u8], target: &str) -> Result<release_trust::Target, String> {
    let up = busbar_plugin_loader::tarball::unpack(tarball)?;
    let m = &up.manifest;
    busbar_plugin_loader::sign::validate_structure(
        m,
        &up.lib_bytes,
        &busbar_plugin_loader::supported_abi,
        busbar_plugin_loader::sign::HOST_IDENTITY,
    )
    .map_err(|e| format!("structural validation: {e}"))?;
    if m.publisher != FIRST_PARTY_PUBLISHER {
        return Err(format!(
            "publisher is '{}', not '{FIRST_PARTY_PUBLISHER}': a release lists first-party plugins only",
            m.publisher
        ));
    }
    if !m.signature.trim().is_empty() {
        return Err("already signed or sealed; a release lists the UNSIGNED tarballs".to_string());
    }
    let bytes = canonical_manifest_bytes(m);
    Ok(release_trust::Target {
        name: m.name.clone(),
        version: m.version.clone(),
        target: target.to_string(),
        sha256: sha256_hex(&bytes),
        length: bytes.len() as u64,
    })
}

pub(crate) fn release_manifest_bytes(
    version: u64,
    expires: u64,
    targets: Vec<release_trust::Target>,
) -> Result<Vec<u8>, String> {
    let mut seen = std::collections::BTreeSet::new();
    for t in &targets {
        if !seen.insert((t.name.clone(), t.version.clone(), t.target.clone())) {
            return Err(format!(
                "{}/{}/{} is listed twice",
                t.name, t.version, t.target
            ));
        }
    }
    wire::canonical(&wire::targets_signed(&release_trust::TargetsDoc {
        role: release_trust::PLUGINS_ROLE.to_string(),
        version,
        expires,
        targets,
    }))
}

fn release_manifest_cli(args: &[String]) -> Result<String, String> {
    let (pos, flags) = flag_args(args, &["version", "expires", "out"])?;
    let version: u64 = need(&flags, "version")?
        .parse()
        .map_err(|e| format!("--version: {e}"))?;
    let expires = wire::parse_time(need(&flags, "expires")?)?;
    if pos.is_empty() {
        return Err("no <tarball>=<target> given".to_string());
    }
    let mut targets = Vec::new();
    for p in &pos {
        let (path, target) = p
            .rsplit_once('=')
            .ok_or_else(|| format!("'{p}' is not <tarball>=<target>"))?;
        targets
            .push(release_entry(&read_file(path)?, target).map_err(|e| format!("'{path}': {e}"))?);
    }
    let n = targets.len();
    let bytes = release_manifest_bytes(version, expires, targets)?;
    let out = need(&flags, "out")?;
    write_file(out, &bytes)?;
    Ok(format!(
        "release-manifest version={version} entries={n} signed-sha256={} -> {out}",
        sha256_hex(&bytes)
    ))
}

/// The keys-document spec `keys-doc --spec` reads.
#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct KeysSpec {
    version: u64,
    expires: String,
    signers: Vec<String>,
    #[serde(default = "one")]
    threshold: u64,
    #[serde(default)]
    revoked_keyids: Vec<String>,
    #[serde(default)]
    revoked_digests: std::collections::BTreeMap<String, String>,
}

fn one() -> u64 {
    1
}

pub(crate) fn keys_doc_bytes(spec: &[u8]) -> Result<Vec<u8>, String> {
    let spec: KeysSpec = serde_json::from_slice(spec).map_err(|e| format!("the spec: {e}"))?;
    if spec.signers.is_empty() || spec.threshold == 0 || spec.threshold > spec.signers.len() as u64
    {
        return Err(format!(
            "the spec names {} signer(s) with threshold {}; it must name at least one and a \
             threshold between 1 and their number",
            spec.signers.len(),
            spec.threshold
        ));
    }
    let mut keys = std::collections::BTreeMap::new();
    for s in &spec.signers {
        let k = public_key(s)?;
        if keys.insert(wire::key_id(&k), k).is_some() {
            return Err("the spec names a signer more than once".to_string());
        }
    }
    let keyids: Vec<String> = keys.keys().cloned().collect();
    wire::canonical(&wire::keys_signed(&release_trust::KeysDoc {
        version: spec.version,
        expires: wire::parse_time(&spec.expires)?,
        keys,
        roles: [(
            release_trust::PLUGINS_ROLE.to_string(),
            release_trust::Role {
                keyids,
                threshold: spec.threshold,
            },
        )]
        .into(),
        revoked_keyids: spec.revoked_keyids.into_iter().collect(),
        revoked_digests: spec.revoked_digests,
    }))
}

fn keys_doc_cli(args: &[String]) -> Result<String, String> {
    let (pos, flags) = flag_args(args, &["spec", "out"])?;
    if !pos.is_empty() {
        return Err(format!("unexpected argument '{}'", pos[0]));
    }
    let bytes = keys_doc_bytes(&read_file(need(&flags, "spec")?)?)?;
    let out = need(&flags, "out")?;
    write_file(out, &bytes)?;
    Ok(format!(
        "keys-doc signed-sha256={} -> {out}",
        sha256_hex(&bytes)
    ))
}

pub(crate) fn envelope(signed: &[u8], key: &ReleaseKey, sig: &[u8]) -> Result<Vec<u8>, String> {
    let value = busbar_contract::json::parse_value(signed)
        .map_err(|e| format!("the signed bytes are not JSON: {e}"))?;
    if wire::canonical(&value)? != signed {
        return Err(
            "the signed bytes are not canonical; sign what release-manifest or keys-doc wrote"
                .into(),
        );
    }
    if !wire::verify(key, signed, sig) {
        return Err(format!(
            "the signature does not verify over the signed bytes with {} key {}",
            key.algorithm(),
            wire::key_id(key)
        ));
    }
    wire::write_envelope(&value, &[(wire::key_id(key), sig.to_vec())])
}

fn envelope_cli(args: &[String]) -> Result<String, String> {
    let (pos, flags) = flag_args(args, &["signed", "key", "signature", "out"])?;
    if !pos.is_empty() {
        return Err(format!("unexpected argument '{}'", pos[0]));
    }
    let key = public_key(need(&flags, "key")?)?;
    let env = envelope(
        &read_file(need(&flags, "signed")?)?,
        &key,
        &read_file(need(&flags, "signature")?)?,
    )?;
    let out = need(&flags, "out")?;
    write_file(out, &env)?;
    Ok(format!("envelope keyid={} -> {out}", wire::key_id(&key)))
}

fn keyid_cli(args: &[String]) -> Result<String, String> {
    match args {
        [spec] => Ok(wire::key_id(&public_key(spec)?)),
        _ => Err("keyid takes one <alg>:<hex>".to_string()),
    }
}

pub(crate) fn seal(
    unsigned: &[u8],
    keys: &[u8],
    release: &[u8],
    target: &str,
    roots: &[FirstPartyKey],
) -> Result<(Vec<u8>, String), String> {
    release_entry(unsigned, target)?;
    let up = busbar_plugin_loader::tarball::unpack(unsigned)?;
    let manifest = Manifest {
        signature: wire::write_seal(keys, release)?,
        ..up.manifest
    };
    let sealed = busbar_plugin_loader::tarball::package(&manifest, &up.lib_name, &up.lib_bytes)?;

    let id = verify_first_party(&sealed, roots, target)?;
    Ok((sealed, id))
}

fn seal_cli(args: &[String]) -> Result<String, String> {
    let (path, flags) = release_args(args, &["keys-doc", "release", "target", "keys", "out"])?;
    let roots = release_keys(&flags)?;
    let target = need(&flags, "target")?;
    let (sealed, root) = seal(
        &read_file(&path)?,
        &read_file(need(&flags, "keys-doc")?)?,
        &read_file(need(&flags, "release")?)?,
        target,
        &roots,
    )
    .map_err(|e| format!("'{path}': {e}"))?;
    let m = busbar_plugin_loader::tarball::unpack(&sealed)?.manifest;
    let out = need(&flags, "out")?;
    write_file(out, &sealed)?;
    Ok(format!(
        "sealed {} v{} target={target} root={root} canonical-sha256={} tarball-sha256={} -> {out}",
        m.name,
        m.version,
        canonical_sha256(&m),
        sha256_hex(&sealed)
    ))
}

pub(crate) fn verify_first_party(
    tarball: &[u8],
    roots: &[FirstPartyKey],
    target: &str,
) -> Result<String, String> {
    if roots.is_empty() {
        return Err(
            "no first-party root key to verify against (pass --keys, or build this tool with \
             BUSBAR_RELEASE_PUBKEY set to the key list)"
                .to_string(),
        );
    }
    let up = busbar_plugin_loader::tarball::unpack(tarball)?;
    let m = &up.manifest;
    busbar_plugin_loader::sign::validate_structure(
        m,
        &up.lib_bytes,
        &busbar_plugin_loader::supported_abi,
        busbar_plugin_loader::sign::HOST_IDENTITY,
    )
    .map_err(|e| format!("structural validation: {e}"))?;
    if m.publisher != FIRST_PARTY_PUBLISHER {
        return Err(format!(
            "publisher is '{}', not '{FIRST_PARTY_PUBLISHER}': not a first-party plugin",
            m.publisher
        ));
    }
    if m.signature.trim().is_empty() {
        return Err("the manifest carries no seal or signature".to_string());
    }

    first_party_signer_for(m, &up.lib_bytes, roots, release_checks(), target)
        .map(|k| k.id.clone())
        .map_err(|unverified| unverified.naming_trusted_keys())
}

fn verify_cli(args: &[String]) -> ExitCode {
    let mut path = String::new();
    let mut run = || -> Result<String, String> {
        let (p, flags) = release_args(args, &["keys", "target", "name", "version"])?;
        path.clone_from(&p);
        let keys = release_keys(&flags)?;
        let target = flag(&flags, "target").unwrap_or(release_trust::PLUGIN_TARGET);
        let bytes = read_file(&p)?;
        let key_id = verify_first_party(&bytes, &keys, target)?;
        let m = busbar_plugin_loader::tarball::unpack(&bytes)?.manifest;
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
            "VERIFIED {p} name={} version={} kind={} target={target} root={key_id} lib-sha256={} canonical-sha256={}",
            m.name,
            m.version,
            m.kind,
            m.sha256.to_ascii_lowercase(),
            canonical_sha256(&m)
        ))
    };
    match run() {
        Ok(msg) => {
            println!("{msg}");
            ExitCode::SUCCESS
        }
        Err(e) => {
            println!("REFUSED {path}: {e}");
            ExitCode::FAILURE
        }
    }
}

fn keygen() -> ExitCode {
    let mut seed = [0u8; 32];
    if let Err(e) = busbar_contract::crypto::fill(&mut seed) {
        eprintln!("error: OS RNG unavailable: {e}");
        return ExitCode::FAILURE;
    }
    let key = SigningKey::from_bytes(&seed);
    println!(
        "private (BUSBAR_SIGN_KEY, keep secret): {}",
        hex::encode(seed)
    );
    println!(
        "public  (publishers allowlist / BUSBAR_RELEASE_PUBKEY): {}",
        hex::encode(key.verifying_key().to_bytes())
    );
    ExitCode::SUCCESS
}

struct Flags {
    map: HashMap<String, String>,
    allow_unsigned: bool,
    schema_derived: bool,
    former_names: Vec<String>,
    native: bool,
}

const FORMER_NAME: &str = "former-name";

fn parse_flags(args: &[String]) -> Result<Flags, String> {
    let mut map = HashMap::new();
    let mut allow_unsigned = false;
    let mut schema_derived = false;
    let mut former_names = Vec::new();
    let mut native = false;
    let mut it = args.iter();
    while let Some(a) = it.next() {
        if a == "--native" {
            if native {
                return Err("--native was supplied more than once".into());
            }
            native = true;
            continue;
        }
        if a == "--allow-unsigned" {
            if allow_unsigned {
                return Err("--allow-unsigned was supplied more than once".into());
            }
            allow_unsigned = true;
            continue;
        }
        if a == "--schema-derived" {
            if schema_derived {
                return Err("--schema-derived was supplied more than once".into());
            }
            schema_derived = true;
            continue;
        }
        let Some(name) = a.strip_prefix("--") else {
            return Err(format!("unexpected argument '{a}'"));
        };
        if !matches!(
            name,
            "lib"
                | "name"
                | "alias"
                | "kind"
                | "version"
                | "publisher"
                | "out"
                | "abi-version"
                | "description"
                | "homepage"
                | "license"
                | "needs-prompt"
                | "needs-user"
                | "settings-schema-file"
                | "declares-file"
                | FORMER_NAME
        ) {
            return Err(format!("unknown flag --{name}"));
        }
        let Some(v) = it.next() else {
            return Err(format!("--{name} requires a value"));
        };
        if name == FORMER_NAME {
            former_names.push(v.clone());
            continue;
        }
        if name == "needs-user" && parse_need_level(v)? == NeedLevel::Rw {
            return Err("--needs-user is no|ro; caller identity cannot be rewritten".into());
        }
        if map.insert(name.to_string(), v.clone()).is_some() {
            return Err(format!("--{name} was supplied more than once"));
        }
    }
    Ok(Flags {
        map,
        allow_unsigned,
        schema_derived,
        former_names,
        native,
    })
}

fn pack(args: &[String]) -> ExitCode {
    let Flags {
        map: flags,
        allow_unsigned,
        schema_derived,
        former_names,
        native: require_native,
    } = match parse_flags(args) {
        Ok(f) => f,
        Err(e) => {
            eprintln!("error: {e}\n\n{}", usage());
            return ExitCode::from(2);
        }
    };
    let required = |k: &str| -> Result<String, String> {
        flags
            .get(k)
            .cloned()
            .ok_or_else(|| format!("missing required --{k}"))
    };
    let run = || -> Result<String, String> {
        let lib_path = required("lib")?;
        let out = required("out")?;
        let kind = required("kind")?;
        let lib_bytes =
            busbar_plugin_loader::pack_native::read_image(std::path::Path::new(&lib_path))?;
        let native = busbar_plugin_loader::pack_native::is_native(&lib_bytes)?;
        if !native {
            let operation = if require_native { "--native" } else { "pack" };
            return Err(format!(
                "{operation} requires a native stamp; this artifact is legacy or unstamped"
            ));
        }
        if schema_derived
            || [
                "declares-file",
                "settings-schema-file",
                "needs-prompt",
                "needs-user",
            ]
            .iter()
            .any(|flag| flags.contains_key(*flag))
        {
            return Err("native metadata comes from the signed image; legacy declares/schema/needs flags are not accepted".into());
        }
        let abi_assertion = flags
            .get("abi-version")
            .map(|v| v.parse::<u32>().map_err(|e| format!("--abi-version: {e}")))
            .transpose()?;

        let manifest = Manifest {
            name: required("name")?,
            alias: required("alias")?,
            kind,

            version: flags.get("version").cloned().unwrap_or_default(),
            publisher: required("publisher")?,
            // complete derives the ABI from the verified stamp and checks any explicit assertion.
            abi_version: abi_assertion.unwrap_or_default(),
            sha256: String::new(),
            signature: String::new(),
            description: flags.get("description").cloned().unwrap_or_default(),
            homepage: flags.get("homepage").cloned().unwrap_or_default(),
            license: flags.get("license").cloned().unwrap_or_default(),

            needs: Default::default(),
            settings_schema: None,
            schema_derived: false,
            host: None,

            declares: Default::default(),
            statement: None,

            former_names,
        };
        let manifest =
            busbar_plugin_loader::pack_native::complete(&lib_bytes, manifest, abi_assertion)?;

        let manifest = match std::env::var(SIGN_KEY_ENV) {
            Ok(hex_seed) => {
                let seed = hex::decode(hex_seed.trim()).map_err(|e| {
                    let why = match e {
                        hex::FromHexError::InvalidHexCharacter { .. } => {
                            "it contains a character outside 0-9, a-f and A-F"
                        }
                        hex::FromHexError::OddLength => "it has an odd number of hex digits",
                        hex::FromHexError::InvalidStringLength => "its length is not a key's",
                    };
                    format!("{SIGN_KEY_ENV} is not valid hex: {why} (the seed itself is withheld)")
                })?;
                let seed: [u8; 32] = seed
                    .as_slice()
                    .try_into()
                    .map_err(|_| format!("{SIGN_KEY_ENV} must be 32 bytes (64 hex chars)"))?;
                sign(&SigningKey::from_bytes(&seed), manifest, &lib_bytes)
            }
            Err(std::env::VarError::NotUnicode(_)) => {
                return Err(format!(
                    "{SIGN_KEY_ENV} is set but is not valid UTF-8 hex (the seed itself is withheld)"
                ));
            }
            Err(_) if allow_unsigned => {
                let mut m = manifest;
                m.sha256 = busbar_plugin_loader::sign::sha256_hex(&lib_bytes);
                m
            }
            Err(_) => {
                return Err(format!(
                    "{SIGN_KEY_ENV} is not set. Set it to the 64-hex ed25519 seed to sign, or pass \
                     --allow-unsigned to package an UNSIGNED tarball (dev only; busbar loads it \
                     only under plugins.trust.allow_untrusted: true)."
                ));
            }
        };

        busbar_plugin_loader::sign::validate_structure(
            &manifest,
            &lib_bytes,
            &busbar_plugin_loader::supported_abi,
            busbar_plugin_loader::sign::HOST_IDENTITY,
        )
        .map_err(|e| format!("manifest would fail busbar's structural validation: {e}"))?;

        let lib_file = std::path::Path::new(&lib_path)
            .file_name()
            .and_then(|f| f.to_str())
            .unwrap_or("plugin-lib")
            .to_string();
        let tarball = busbar_plugin_loader::tarball::package(&manifest, &lib_file, &lib_bytes)?;
        std::fs::write(&out, &tarball).map_err(|e| format!("cannot write '{out}': {e}"))?;
        Ok(format!(
            "packaged {} ({} v{}, kind {}, publisher {}, {}) -> {out}",
            manifest.name,
            manifest.alias,
            manifest.version,
            manifest.kind,
            manifest.publisher,
            if manifest.signature.is_empty() {
                "UNSIGNED"
            } else {
                "signed"
            },
        ))
    };
    match run() {
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

#[cfg(test)]
#[path = "tests/pack_tests.rs"]
mod tests;
