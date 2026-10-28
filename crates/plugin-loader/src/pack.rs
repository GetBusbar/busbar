// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! `busbar-plugin-pack` - the packaging + signing tool for busbar plugins.
//!
//! A busbar plugin ships as ONE signed `.tar.gz` containing exactly the cdylib and its signed
//! `manifest.json`. This tool builds that artifact:
//!
//! ```text
//! busbar-plugin-pack pack \
//!     --lib target/release/libbusbar_store_valkey_plugin.so \
//!     --name busbar-store-valkey-plugin --alias valkey --kind store \
//!     --version 1.5.0 --publisher busbar \
//!     --out busbar-store-valkey-1.5.0-x86_64-linux.tar.gz
//! ```
//!
//! The ed25519 SIGNING key is read from the `BUSBAR_SIGN_KEY` environment variable (64 hex chars:
//! the 32-byte seed) - in CI this is the release secret; a third-party publisher uses their own.
//! With no key set, `--allow-unsigned` produces an UNSIGNED tarball (dev only: busbar loads it
//! solely under `plugins.trust.allow_unsigned: true`).
//!
//! `busbar-plugin-pack keygen` generates a fresh keypair and prints both halves (hex). The PUBLIC
//! half goes in `plugins.trust.publishers` (third-party); the PRIVATE half is the signing secret.
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
//! (`scripts/release/publish_gate.py`) drives these commands and never spells a byte itself.

use busbar_plugin_loader::release_trust::{self, wire, ReleaseKey};
use busbar_plugin_loader::settings_schema::validate_secret_fields;
use busbar_plugin_loader::sign::{
    canonical_manifest_bytes, embedded_release_keys, first_party_signer_for, parse_release_keys,
    sha256_hex, sign, Declares, FirstPartyKey, HookNeeds, Manifest, NeedLevel, SigningKey,
    FIRST_PARTY_PUBLISHER,
};
use std::collections::HashMap;
use std::process::ExitCode;

const SIGN_KEY_ENV: &str = "BUSBAR_SIGN_KEY";

/// The ONLY `$schema` value `--settings-schema-file` accepts.
/// `jsonschema::validator_for` auto-detects draft from `$schema` and silently falls back to
/// whatever draft it currently defaults to when the field is absent — it does not itself refuse
/// an older draft. busbar-ui ships exactly one 2020-12 form renderer, so a draft-07 document
/// (boolean `exclusiveMinimum`, `definitions` instead of `$defs`, ...) must never ship even
/// though it would compile fine as "a well-formed JSON Schema" of some draft.
const SCHEMA_2020_12: &str = "https://json-schema.org/draft/2020-12/schema";

/// The `x-busbar-ref` schema vocabulary entry: `x-busbar-ref: "pool" | "group" | "model" |
/// "provider"` on a field tells busbar-ui to render a picker populated from the relevant admin API
/// listing endpoint, not a free-text box. This is a UI-ONLY rendering hint — there is deliberately
/// NO server-side enforcement of it (the values it names are per-fleet-member runtime data, not
/// something a manifest schema or this pack-time tool could ever validate against). The only
/// pack-time requirement is that it not be silently swallowed as an unrecognized `x-*` extension:
/// `jsonschema::validator_for` already tolerates unknown keywords by design (JSON Schema itself is
/// forward-compatible with unrecognized keys), so `x-busbar-ref` passes through pack-time validation
/// with no code change required — this constant exists purely so the accepted value set is named
/// ONE place instead of only in prose, for the (optional, non-blocking) sanity check below.
#[cfg(test)]
const BUSBAR_REF_VALUES: &[&str] = &["pool", "group", "model", "provider"];

/// Parse a `--needs-*` flag value into a [`NeedLevel`] (`no` | `ro` | `rw`). This is the ADVISORY
/// declared-intent a `kind: hook` plugin's manifest carries — it is SIGNED (so it cannot be spoofed)
/// and surfaced to the admin at register/load, but the operator's config grant remains the
/// enforcement. An unknown value is a hard error (a fat-fingered intent must not silently default).
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
    busbar-plugin-pack pack --lib <cdylib> --name <name> --alias <alias> --kind <store|auth|hook|secret|export>
                            [--version <semver>] --publisher <publisher> --out <file.tar.gz>
                            [--description <text>] [--homepage <url>] [--license <spdx>]
                            [--needs-prompt <no|ro|rw>] [--needs-user <no|ro>]
                            [--settings-schema-file <path.json>] [--schema-derived]
                            [--declares-file <path.json>] [--former-name <name>]...
                            [--allow-unsigned]
    busbar-plugin-pack keygen
    busbar-plugin-pack canonical <unsigned.tar.gz> [--out <file>]
    busbar-plugin-pack release-manifest --version <n> --expires <time> --out <file> <tarball>=<target>...
    busbar-plugin-pack keys-doc --spec <spec.json> --out <file>
    busbar-plugin-pack envelope --signed <file> --key <alg>:<hex> --signature <file> --out <file>
    busbar-plugin-pack keyid <alg>:<hex>
    busbar-plugin-pack seal <unsigned.tar.gz> --keys-doc <file> --release <file> --target <triple>
                            [--keys <list>] --out <sealed.tar.gz>
    busbar-plugin-pack verify <sealed.tar.gz> [--keys <list>] [--target <triple>] [--name <name>] [--version <semver>]

    pack     builds manifest.json over the cdylib (sha256 binding), signs it with the ed25519 seed
             in $BUSBAR_SIGN_KEY (64 hex chars), and writes the {cdylib + manifest.json} .tar.gz.
             --allow-unsigned permits packaging WITHOUT a signature (dev only; busbar loads such a
             tarball only under plugins.trust.allow_unsigned: true).
             --needs-prompt / --needs-user declare a kind:hook plugin's ADVISORY intent (what caller
             content it asks to receive); SIGNED into the manifest. The operator's config grant still
             enforces — a plugin gets prompt/user content only when BOTH the manifest declares the
             need AND the operator grants it. A prompt:rw rewrite gate packs with --needs-prompt rw.
             --settings-schema-file embeds the plugin's `settings` shape as a JSON Schema document
             (generate it from the plugin's own config struct via the busbar-plugin-sdk schema_for!
             build-time macro — this tool only validates and embeds, it never generates and cannot,
             since it has no access to the plugin's Rust source). Rejected at pack time unless:
             `$schema` is exactly \"https://json-schema.org/draft/2020-12/schema\"; every
             `x-busbar-secret: true` field is a direct root-level property (never nested — $ref/
             allOf are resolved first) and is `type: string` (optionally `contentEncoding:
             \"base64\"` for a binary secret); and no UNMARKED field name matches
             password|secret|token|credential|passphrase|private_key|apikey|api_key
             (case-insensitive). Powers GET /plugins/{name}/schema without ever loading the plugin.
             --schema-derived asserts (SELF-ATTESTED, not verified by this tool) that the schema
             file was generated by the busbar-plugin-sdk macro from the same struct `open()`
             parses, not hand-written — copied verbatim into the manifest's schema_derived field.
             --declares-file embeds the plugin's `declares` section (a JSON object: `metrics`,
             `diagnostics`, `destinations`) — the metric series it emits, the BUSBAR-NNNN codes it
             raises and the settings keys naming its destinations. SIGNED like every field; the host
             grants the series and registers the codes only for a first-party plugin. Rejected at
             pack time unless it parses as exactly that section (an unknown key is an error).
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

/// Print a subcommand's outcome: its message on stdout and success, or its error on stderr.
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

/// A release command's arguments: the one positional tarball path, and `--flag value` pairs from
/// `known`, each at most once.
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

/// The first-party key list a release command checks against: `--keys <list>` (the
/// `BUSBAR_RELEASE_PUBKEY` format, [`parse_release_keys`]), or the list this tool was built with.
fn release_keys(flags: &[(String, String)]) -> Result<Vec<FirstPartyKey>, String> {
    match flag(flags, "keys") {
        Some(spec) => parse_release_keys(spec).map_err(|e| format!("--keys: {e}")),
        None => Ok(embedded_release_keys()),
    }
}

/// The digest the owner signs: sha256 of the canonical manifest bytes.
fn canonical_sha256(m: &Manifest) -> String {
    sha256_hex(&canonical_manifest_bytes(m))
}

/// `canonical <tarball> [--out <file>]`: the manifest's canonical signed bytes (every field but
/// `signature`) written to `--out`, and one `k=v` line naming them.
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

/// The checks a release command judges a seal at: now, and no accepted floor (a fresh install).
fn release_checks() -> release_trust::Checks {
    release_trust::Checks {
        now: release_trust::now(),
        keys_floor: 0,
    }
}

/// A public key spelled `<alg>:<hex>` (the key list's per-key spelling, without the id).
fn public_key(spec: &str) -> Result<ReleaseKey, String> {
    parse_release_keys(&format!("key:{}", spec.trim()))
        .map(|mut k| k.remove(0).key)
        .map_err(|e| format!("key '{spec}': {e}"))
}

/// A command's arguments: `--flag value` pairs from `known` (each at most once), and the
/// positionals.
fn flag_args(
    args: &[String],
    known: &[&str],
) -> Result<(Vec<String>, Vec<(String, String)>), String> {
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

/// One release-manifest entry for an UNSIGNED first-party tarball built for `target`.
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

/// The SIGNED BYTES of the release manifest listing `entries`.
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

/// `release-manifest --version <n> --expires <time> --out <file> <tarball>=<target>...`
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

/// The SIGNED BYTES of the keys document a spec describes.
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
        keys.insert(wire::key_id(&k), k);
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

/// `keys-doc --spec <spec.json> --out <file>`
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

/// The envelope over `signed` (the exact bytes `release-manifest`/`keys-doc` wrote) with `sig`, made
/// by `key`; refused unless the signature verifies over those bytes.
pub(crate) fn envelope(signed: &[u8], key: &ReleaseKey, sig: &[u8]) -> Result<Vec<u8>, String> {
    let value: serde_json::Value = serde_json::from_slice(signed)
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

/// `envelope --signed <file> --key <alg>:<hex> --signature <file> --out <file>`
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

/// `keyid <alg>:<hex>`
fn keyid_cli(args: &[String]) -> Result<String, String> {
    match args {
        [spec] => Ok(wire::key_id(&public_key(spec)?)),
        _ => Err("keyid takes one <alg>:<hex>".to_string()),
    }
}

/// SEAL: put `keys` and `release` (envelopes) into the unsigned first-party tarball `unsigned`
/// and return the sealed tarball with the id of the root that vouches for it. Refused for a
/// tarball that is not an unsigned first-party one, and unless the REPACKAGED bytes pass
/// [`verify_first_party`] for `target`: nothing that would not load as first-party leaves here.
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
    // Verify what is written, not the in-memory copy.
    let id = verify_first_party(&sealed, roots, target)?;
    Ok((sealed, id))
}

/// `seal <tarball> --keys-doc <file> --release <file> --target <triple> [--keys <list>] --out <file>`
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

/// VERIFY: the tarball is structurally valid, `publisher: busbar`, sealed (or per-plugin signed),
/// and verifies for `target` through the loader's own [`first_party_signer_for`] against `roots`;
/// the id of the vouching root.
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
    // The loader's own reason for a per-plugin signature is 1.5.5's bare "signature does not
    // verify"; this tool names the key ids it tried, from the refusal's structured field.
    first_party_signer_for(m, &up.lib_bytes, roots, release_checks(), target)
        .map(|k| k.id.clone())
        .map_err(|unverified| unverified.naming_trusted_keys())
}

/// `verify <tarball> [--keys <list>] [--target <triple>] [--name <name>] [--version <semver>]`:
/// `VERIFIED …` and exit 0, or `REFUSED <path>: <reason>` on stdout and exit 1.
fn verify_cli(args: &[String]) -> ExitCode {
    let mut path = String::new();
    let mut run = || -> Result<String, String> {
        let (p, flags) = release_args(args, &["keys", "target", "name", "version"])?;
        path = p.clone();
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

/// Generate a fresh ed25519 keypair from the OS RNG and print both halves (hex).
fn keygen() -> ExitCode {
    let mut seed = [0u8; 32];
    if let Err(e) = getrandom::fill(&mut seed) {
        eprintln!("error: OS RNG unavailable: {e}");
        return ExitCode::FAILURE;
    }
    let key = SigningKey::from_bytes(&seed);
    println!(
        "private (BUSBAR_SIGN_KEY, keep secret): {}",
        hex::encode(seed)
    );
    println!(
        "public  (publishers allowlist): {}",
        hex::encode(key.verifying_key().to_bytes())
    );
    ExitCode::SUCCESS
}

/// The flags `pack` takes: the `--flag value` pairs, the bare `--allow-unsigned` /
/// `--schema-derived`, and every value of the repeatable `--former-name`, in order.
struct Flags {
    map: HashMap<String, String>,
    allow_unsigned: bool,
    schema_derived: bool,
    former_names: Vec<String>,
}

/// The repeatable flag naming a manifest name an earlier release of the plugin carried.
const FORMER_NAME: &str = "former-name";

/// Parse `--flag value` pairs plus the bare `--allow-unsigned` / `--schema-derived` flags. The
/// repeatable `--former-name` keeps every value, in order.
fn parse_flags(args: &[String]) -> Result<Flags, String> {
    let mut map = HashMap::new();
    let mut allow_unsigned = false;
    let mut schema_derived = false;
    let mut former_names = Vec::new();
    let mut it = args.iter();
    while let Some(a) = it.next() {
        if a == "--allow-unsigned" {
            allow_unsigned = true;
            continue;
        }
        if a == "--schema-derived" {
            schema_derived = true;
            continue;
        }
        let Some(name) = a.strip_prefix("--") else {
            return Err(format!("unexpected argument '{a}'"));
        };
        let Some(v) = it.next() else {
            return Err(format!("--{name} requires a value"));
        };
        if name == FORMER_NAME {
            former_names.push(v.clone());
            continue;
        }
        map.insert(name.to_string(), v.clone());
    }
    Ok(Flags {
        map,
        allow_unsigned,
        schema_derived,
        former_names,
    })
}

/// Read `--settings-schema-file`'s contents and reject them at PACK time if they're not a
/// syntactically valid, DRAFT-2020-12 JSON Schema document, or if they misuse `x-busbar-secret` —
/// a broken/unsafe schema must never ship and only be discovered later when busbar-ui tries to
/// render a form from it. The file's exact
/// bytes (not a re-serialized/reformatted copy) are what get embedded and signed — so an operator
/// or busbar-ui reading the manifest back sees byte-for-byte what the plugin author wrote.
fn read_and_validate_settings_schema(path: &str) -> Result<String, String> {
    let text = std::fs::read_to_string(path)
        .map_err(|e| format!("cannot read --settings-schema-file '{path}': {e}"))?;
    let value: serde_json::Value = serde_json::from_str(&text)
        .map_err(|e| format!("--settings-schema-file '{path}' is not valid JSON: {e}"))?;
    // `jsonschema::validator_for` auto-detects draft from `$schema` and silently falls back to
    // whatever draft it currently defaults to when the field is absent — it does NOT itself
    // refuse an older draft, so the exact-match check is required, not redundant with the line
    // below.
    let schema_uri = value.get("$schema").and_then(|s| s.as_str());
    if schema_uri != Some(SCHEMA_2020_12) {
        return Err(format!(
            "--settings-schema-file '{path}': \"$schema\" must be exactly \"{SCHEMA_2020_12}\" \
             (found {schema_uri:?}) — busbar-ui's form renderer only understands JSON Schema \
             2020-12, an older/missing draft can silently misrender"
        ));
    }
    jsonschema::validator_for(&value).map_err(|e| {
        format!("--settings-schema-file '{path}' is not a valid JSON Schema document: {e}")
    })?;
    validate_secret_fields(&value).map_err(|e| format!("--settings-schema-file '{path}': {e}"))?;
    Ok(text)
}

/// Read `--declares-file`: the manifest's `declares` section, read by the one reader of a declares
/// document ([`Declares::from_declares_json`]) — so a file busbar would refuse to read (an unknown
/// key, a malformed declaration or `needs`) is refused here, at PACK time, rather than shipped, and
/// the file's `needs` (the conformance suite's and the fleet render's) never reaches the signed
/// manifest.
fn read_declares(path: &str) -> Result<Declares, String> {
    let bytes =
        std::fs::read(path).map_err(|e| format!("cannot read --declares-file '{path}': {e}"))?;
    Declares::from_declares_json(&bytes).map_err(|e| format!("--declares-file '{path}': {e}"))
}

fn read_rendering(
    rendering: &[u8],
) -> Result<busbar_contract::abi::mechanism::rendering::Read, String> {
    busbar_contract::abi::mechanism::rendering::read(rendering).map_err(|e| {
        format!(
            "the Statement rendering does not read back: byte {} is not {}",
            e.at, e.what
        )
    })
}

/// The version the plugin's Statement states: what `--version` defaults to.
///
/// # Errors
/// The rendering does not read back.
pub(crate) fn stated_version(rendering: &[u8]) -> Result<String, String> {
    read_rendering(rendering).map(|r| r.version)
}

/// ONE VERSION PER PLUGIN (ARCHITECT ruling C', question 3): the manifest's `--version` is the
/// version the plugin's own Statement states. The loader's one-version rule compares Statement
/// versions, so a release whose manifest says another version would publish a plugin that is not
/// the version it claims; packing refuses it, naming both.
///
/// # Errors
/// The rendering does not read back, or states another version.
pub(crate) fn statement_version_is(rendering: &[u8], version: &str) -> Result<(), String> {
    let r = read_rendering(rendering)?;
    if r.version == version {
        return Ok(());
    }
    Err(format!(
        "--version {version} is not the version plugin '{}' states in its Statement ({}): a \
         release's manifest version is the plugin's own; release the tag the crate states, or bump \
         the crate",
        r.name, r.version
    ))
}

fn pack(args: &[String]) -> ExitCode {
    let Flags {
        map: flags,
        allow_unsigned,
        schema_derived,
        former_names,
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
        // Default the ABI to the NEWEST version this binary's loader supports for the kind, so a
        // plain `pack` of a store plugin stamps the current store ABI instead of a stale literal.
        // `--abi-version` still overrides for cross-version packaging.
        let default_abi = busbar_plugin_loader::supported_abi(&kind)
            .iter()
            .copied()
            .max()
            .unwrap_or(1);
        let manifest = Manifest {
            name: required("name")?,
            alias: required("alias")?,
            kind,
            // Absent: the version the plugin's own Statement states (filled below).
            version: flags.get("version").cloned().unwrap_or_default(),
            publisher: required("publisher")?,
            abi_version: flags
                .get("abi-version")
                .map(|v| v.parse::<u32>().map_err(|e| format!("--abi-version: {e}")))
                .transpose()?
                .unwrap_or(default_abi),
            sha256: String::new(),
            signature: String::new(),
            description: flags.get("description").cloned().unwrap_or_default(),
            homepage: flags.get("homepage").cloned().unwrap_or_default(),
            license: flags.get("license").cloned().unwrap_or_default(),
            // Declared-intent (`needs:`) for a `kind: hook` plugin: authored at pack time via the
            // OPTIONAL `--needs-prompt`/`--needs-user` flags. Absent → "asks for nothing" (the correct
            // default for every non-hook kind and for a hook that needs no caller content). The value
            // is SIGNED (covered by the manifest signature) so it cannot be spoofed after packing.
            needs: HookNeeds {
                prompt: flags
                    .get("needs-prompt")
                    .map(|v| parse_need_level(v).map_err(|e| format!("--needs-prompt: {e}")))
                    .transpose()?
                    .unwrap_or_default(),
                user: flags
                    .get("needs-user")
                    .map(|v| parse_need_level(v).map_err(|e| format!("--needs-user: {e}")))
                    .transpose()?
                    .unwrap_or_default(),
            },
            // OPTIONAL: the plugin's `settings` shape as a JSON Schema 2020-12 document, read
            // verbatim from a file (the plugin author generates this from their own config
            // struct — e.g. a `schemars::schema_for!` derive — so schema/parser drift becomes a
            // compile error in the plugin's own crate, not a runtime mismatch discovered by an
            // operator; this tool only embeds and validates, it does not generate). Rejected at
            // PACK time if the file isn't syntactically valid JSON Schema, never left to fail at
            // UI-render time on some operator's machine. SIGNED (covered by the manifest
            // signature) alongside everything else.
            settings_schema: flags
                .get("settings-schema-file")
                .map(|path| read_and_validate_settings_schema(path))
                .transpose()?,
            // SELF-ATTESTED by the caller (the plugin's own build/CI, via the `busbar-plugin-sdk`
            // `schema_for!` macro) — this tool has no way to verify derivation itself, it only
            // embeds a schema file it's handed and never sees the plugin's Rust source.
            // `false` unless `--schema-derived` is passed.
            schema_derived,
            host: None,
            // OPTIONAL: what the plugin DECLARES to the host (K9a's host seams) — the same section
            // a linked build states from the same file, so a dropped-in first-party sink ships
            // exactly the declarations its compiled-in twin makes. SIGNED with everything else.
            declares: flags
                .get("declares-file")
                .map(|path| read_declares(path))
                .transpose()?
                .unwrap_or_default(),
            statement: None,
            // The manifest names the plugin's EARLIER RELEASES carried (`--former-name`, repeatable;
            // plugins.yaml's `former_names:`): config written for those releases resolves to this
            // one. Each is held to the alias's rules by the structural self-check below.
            former_names,
        };
        let lib_bytes =
            std::fs::read(&lib_path).map_err(|e| format!("cannot read --lib '{lib_path}': {e}"))?;
        // THE STATEMENT: rendered from the library's own door and signed with the rest, so a
        // reader that must not open the plugin reads its facts from the manifest, and the loader
        // compares the door with it at admit. A library with no door states none. A library this
        // host cannot open (another target's build) states none either, loudly: the engine refuses
        // a door-carrying plugin whose manifest states no Statement, so nothing unchecked loads.
        let statement = match busbar_plugin_loader::dispatch::rendering_of_library(
            std::path::Path::new(&lib_path),
        ) {
            Ok(r) => r.map(hex::encode),
            Err(busbar_plugin_loader::dispatch::LoadError::Open(e)) => {
                eprintln!(
                    "warning: --lib '{lib_path}' does not load on this host ({e}); the manifest \
                     states no Statement, and busbar refuses such a 1.6.0 plugin at admit: pack \
                     it on a host of its target"
                );
                None
            }
            Err(e) => return Err(format!("--lib '{lib_path}': {e}")),
        };
        let version = match statement.as_deref() {
            Some(stated) => {
                let bytes = hex::decode(stated).map_err(|e| format!("--lib '{lib_path}': {e}"))?;
                let own = stated_version(&bytes).map_err(|e| format!("--lib '{lib_path}': {e}"))?;
                if manifest.version.is_empty() {
                    own
                } else {
                    statement_version_is(&bytes, &manifest.version)
                        .map_err(|e| format!("--lib '{lib_path}': {e}"))?;
                    manifest.version.clone()
                }
            }
            None if manifest.version.is_empty() => {
                return Err(format!(
                    "missing required --version: --lib '{lib_path}' states no Statement to read \
                     the plugin's version from"
                ))
            }
            None => manifest.version.clone(),
        };
        let manifest = Manifest {
            statement,
            version,
            ..manifest
        };

        // Sign with $BUSBAR_SIGN_KEY, or package unsigned only under the explicit dev flag.
        let manifest = match std::env::var(SIGN_KEY_ENV) {
            Ok(hex_seed) => {
                // The CLASS of the failure, never `FromHexError`'s own `Display`: that names the
                // offending character of the SIGNING SEED and its position. Matched exhaustively
                // with no `_` arm, so a new variant in a `hex` upgrade fails the build and is
                // classified by hand rather than falling through to a printing catch-all.
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
            Err(_) if allow_unsigned => {
                let mut m = manifest;
                m.sha256 = busbar_plugin_loader::sign::sha256_hex(&lib_bytes);
                m
            }
            Err(_) => {
                return Err(format!(
                    "{SIGN_KEY_ENV} is not set. Set it to the 64-hex ed25519 seed to sign, or pass \
                     --allow-unsigned to package an UNSIGNED tarball (dev only; busbar loads it \
                     only under plugins.trust.allow_unsigned: true)."
                ));
            }
        };

        // Structural self-check: refuse to package a manifest busbar would refuse to load.
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
