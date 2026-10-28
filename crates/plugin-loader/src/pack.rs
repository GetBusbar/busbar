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
//! FIRST-PARTY SIGNING IS OFFLINE (SECURITY-FIRST-PLAN C1): no first-party seed is in CI. A release
//! packs UNSIGNED, `canonical` writes the bytes the owner signs on the hardware key, and `attach`
//! inserts that signature, refusing unless it verifies against a first-party key list (`--keys`, or
//! the `BUSBAR_RELEASE_PUBKEY` list this tool was built with, the same list the engine embeds).
//! `verify` re-checks a signed tarball against that list. The release gate
//! (`scripts/release/publish_gate.py`) drives all three.

use busbar_plugin_loader::settings_schema::validate_secret_fields;
use busbar_plugin_loader::sign::{
    canonical_manifest_bytes, embedded_release_keys, first_party_signer, parse_release_keys,
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
    busbar-plugin-pack attach <unsigned.tar.gz> --signature <128 hex | @file> [--keys <list>] --out <signed.tar.gz>
    busbar-plugin-pack verify <signed.tar.gz> [--keys <list>] [--name <name>] [--version <semver>]

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
    attach   inserts a first-party signature (hex, or @file holding the raw 64 bytes or their hex)
             into an UNSIGNED tarball and writes the signed one, refusing unless the repackaged
             tarball is `publisher: busbar`, structurally valid and verifies against a first-party
             key: --keys <list> (the BUSBAR_RELEASE_PUBKEY format), or the list this tool was built
             with.
    verify   checks a signed first-party tarball against those keys (and --name/--version when
             given): prints VERIFIED ... and exits 0, or REFUSED <path>: <reason> and exits 1."
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        Some("keygen") => keygen(),
        Some("pack") => pack(&args[1..]),
        Some("canonical") => report(canonical_cli(&args[1..])),
        Some("attach") => report(attach_cli(&args[1..])),
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

/// A signature given as 128 hex digits, or as `@file` holding either the raw 64 bytes a hardware
/// key writes or their hex.
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

/// `attach <tarball> --signature <hex|@file> [--keys <list>] --out <file>`
fn attach_cli(args: &[String]) -> Result<String, String> {
    let (path, flags) = release_args(args, &["signature", "keys", "out"])?;
    let sig =
        read_signature(flag(&flags, "signature").ok_or("missing --signature <128 hex | @file>")?)?;
    let keys = release_keys(&flags)?;
    let out = flag(&flags, "out").ok_or("missing --out <file>")?;
    let (tarball, key_id) =
        attach(&read_file(&path)?, &sig, &keys).map_err(|e| format!("'{path}': {e}"))?;
    let m = busbar_plugin_loader::tarball::unpack(&tarball)?.manifest;
    std::fs::write(out, &tarball).map_err(|e| format!("cannot write '{out}': {e}"))?;
    Ok(format!(
        "attached {} v{} key={key_id} canonical-sha256={} tarball-sha256={} -> {out}",
        m.name,
        m.version,
        canonical_sha256(&m),
        sha256_hex(&tarball)
    ))
}

/// ATTACH: insert `sig` into the unsigned first-party tarball `unsigned` and return the signed
/// tarball with the id of the key in `keys` that made it. Refused for an already-signed tarball,
/// and unless the REPACKAGED bytes pass [`verify_first_party`]: nothing that would not load as
/// first-party leaves here.
pub(crate) fn attach(
    unsigned: &[u8],
    sig: &[u8; 64],
    keys: &[FirstPartyKey],
) -> Result<(Vec<u8>, String), String> {
    let up = busbar_plugin_loader::tarball::unpack(unsigned)?;
    if !up.manifest.signature.trim().is_empty() {
        return Err(
            "already signed; attach takes the UNSIGNED tarball the release build emitted"
                .to_string(),
        );
    }
    let before = canonical_sha256(&up.manifest);
    let manifest = Manifest {
        signature: hex::encode(sig),
        ..up.manifest
    };
    // The signature is outside the canonical bytes, so attaching cannot change what was signed.
    // Checked anyway: a change here would mean the owner signed other bytes.
    if canonical_sha256(&manifest) != before {
        return Err("attaching the signature changed the canonical bytes".to_string());
    }
    let signed = busbar_plugin_loader::tarball::package(&manifest, &up.lib_name, &up.lib_bytes)?;
    // Verify what is written, not the in-memory copy.
    let id = verify_first_party(&signed, keys)?;
    Ok((signed, id))
}

/// VERIFY: the tarball is structurally valid, `publisher: busbar`, signed, and its signature
/// verifies against one of `keys` (the loader's own [`first_party_signer`]); the id of that key.
pub(crate) fn verify_first_party(tarball: &[u8], keys: &[FirstPartyKey]) -> Result<String, String> {
    if keys.is_empty() {
        return Err(
            "no first-party key to verify against (pass --keys, or build this tool with \
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
        return Err("the manifest carries no signature".to_string());
    }
    // The loader's own reason is 1.5.5's bare "signature does not verify"; this tool names the key
    // ids it tried, from the refusal's structured field.
    first_party_signer(m, &up.lib_bytes, keys)
        .map(|k| k.id.clone())
        .map_err(|unverified| unverified.naming_trusted_keys())
}

/// `verify <tarball> [--keys <list>] [--name <name>] [--version <semver>]`: `VERIFIED …` and exit
/// 0, or `REFUSED <path>: <reason>` on stdout and exit 1.
fn verify_cli(args: &[String]) -> ExitCode {
    let mut path = String::new();
    let mut run = || -> Result<String, String> {
        let (p, flags) = release_args(args, &["keys", "name", "version"])?;
        path = p.clone();
        let keys = release_keys(&flags)?;
        let bytes = read_file(&p)?;
        let key_id = verify_first_party(&bytes, &keys)?;
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
            "VERIFIED {p} name={} version={} kind={} key={key_id} lib-sha256={} canonical-sha256={}",
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
