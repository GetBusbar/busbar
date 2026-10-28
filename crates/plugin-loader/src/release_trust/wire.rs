// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE BYTE ENCODING of the release-trust documents, and nothing else: how a keys document and a
//! release manifest are written, which bytes a signature covers, how a key is named and how a
//! signature is spelled. Every other part of [`super`] works on the decoded shapes ([`KeysDoc`],
//! [`TargetsDoc`], [`ReleaseKey`]) and never sees a byte of JSON.
//!
//! PROVISIONAL (`spec_version` [`SPEC_VERSION`]). ModernCI's release-signing design will publish a
//! "v1 formats" section (canonicalization, algorithm tags, the offline encoding of PIV and WebAuthn
//! signatures); this module is the one place that changes to match it. The encoding below is
//! modelled on TUF (`docs/design/release-trust.md`):
//!
//! * an ENVELOPE `{"signatures":[{"keyid":<hex>,"sig":<hex>}],"signed":{...}}`;
//! * the signed bytes are the CANONICAL JSON of `signed`: object keys sorted bytewise, no
//!   whitespace, non-negative integers only (no floats), strings of printable ASCII only, escaping
//!   only `"` and `\`. For that subset this is byte-identical to OLPC canonical JSON (TUF's) and
//!   to Python's `json.dumps(v, sort_keys=True, separators=(",", ":"))`;
//! * a KEY OBJECT is TUF's `{"keytype","scheme","keyval":{"public"}}`: `ed25519`/`ed25519` with the
//!   32-byte key in hex, or `ecdsa`/`ecdsa-sha2-nistp256` with the 65-byte uncompressed SEC1 point
//!   in hex (TUF writes PEM there; hex keeps the verifier free of a PEM parser);
//! * a KEY ID is the lowercase hex SHA-256 of the key object's canonical JSON (TUF's rule);
//! * a SIGNATURE is hex: ed25519's 64 raw bytes, or ECDSA P-256's ASN.1 DER `SEQUENCE { r, s }`
//!   over SHA-256 of the signed bytes (what a YubiKey PIV slot and Cloud KMS both emit; TUF's
//!   `ecdsa-sha2-nistp256` signature is DER too). DER, not fixed `r || s`, so neither signer's
//!   output is re-encoded on its way into the envelope.

use super::{KeysDoc, ReleaseKey, Role, Signed, Target, TargetsDoc};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};

/// The encoding's version, written in every document and required on read.
pub const SPEC_VERSION: &str = "0.1-provisional";
/// The keys document's `_type`.
pub const KEYS_TYPE: &str = "busbar-keys";
/// The release manifest's `_type` (TUF's targets role).
pub const TARGETS_TYPE: &str = "targets";

// ── canonical JSON ──────────────────────────────────────────────────────────────────────────────

/// The canonical bytes of `v` ([module docs](self)).
///
/// # Errors
///
/// A float or negative number, or a string outside printable ASCII: the subset has one spelling
/// per value, and anything outside it is refused rather than guessed at.
pub fn canonical(v: &Value) -> Result<Vec<u8>, String> {
    let mut out = Vec::new();
    write_canonical(v, &mut out)?;
    Ok(out)
}

fn write_canonical(v: &Value, out: &mut Vec<u8>) -> Result<(), String> {
    match v {
        Value::Null => out.extend_from_slice(b"null"),
        Value::Bool(b) => out.extend_from_slice(if *b { b"true" } else { b"false" }),
        Value::Number(n) => match n.as_u64() {
            Some(u) => out.extend_from_slice(u.to_string().as_bytes()),
            None => return Err(format!("number {n} is not a non-negative integer")),
        },
        Value::String(s) => write_string(s, out)?,
        Value::Array(items) => {
            out.push(b'[');
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push(b',');
                }
                write_canonical(item, out)?;
            }
            out.push(b']');
        }
        Value::Object(map) => {
            let sorted: BTreeMap<&str, &Value> = map.iter().map(|(k, v)| (k.as_str(), v)).collect();
            out.push(b'{');
            for (i, (k, v)) in sorted.into_iter().enumerate() {
                if i > 0 {
                    out.push(b',');
                }
                write_string(k, out)?;
                out.push(b':');
                write_canonical(v, out)?;
            }
            out.push(b'}');
        }
    }
    Ok(())
}

fn write_string(s: &str, out: &mut Vec<u8>) -> Result<(), String> {
    if let Some(c) = s.chars().find(|c| !(' '..='~').contains(c)) {
        return Err(format!(
            "string {s:?} holds {c:?}, outside printable ASCII (the canonical subset)"
        ));
    }
    out.push(b'"');
    for b in s.bytes() {
        if b == b'"' || b == b'\\' {
            out.push(b'\\');
        }
        out.push(b);
    }
    out.push(b'"');
    Ok(())
}

// ── keys ────────────────────────────────────────────────────────────────────────────────────────

/// A key's TUF key object.
pub fn key_object(key: &ReleaseKey) -> Value {
    let (keytype, scheme, public) = match key {
        ReleaseKey::Ed25519(k) => ("ed25519", "ed25519", hex::encode(k.as_bytes())),
        ReleaseKey::P256(point) => ("ecdsa", "ecdsa-sha2-nistp256", hex::encode(point)),
    };
    serde_json::json!({"keytype": keytype, "scheme": scheme, "keyval": {"public": public}})
}

/// A key's id: hex SHA-256 of its key object's canonical bytes.
pub fn key_id(key: &ReleaseKey) -> String {
    let bytes = canonical(&key_object(key)).expect("a key object is in the canonical subset");
    crate::sign::sha256_hex(&bytes)
}

/// Read a TUF key object.
///
/// # Errors
///
/// An unknown keytype/scheme pair or a public key of the wrong shape.
pub fn read_key_object(v: &Value) -> Result<ReleaseKey, String> {
    let obj = v.as_object().ok_or("a key is not an object")?;
    let keytype = str_field(obj, "keytype")?;
    let scheme = str_field(obj, "scheme")?;
    let public = obj
        .get("keyval")
        .and_then(|kv| kv.get("public"))
        .and_then(Value::as_str)
        .ok_or("a key has no keyval.public")?;
    match (keytype, scheme) {
        ("ed25519", "ed25519") => crate::sign::public_key_from_hex(public).map(ReleaseKey::Ed25519),
        ("ecdsa", "ecdsa-sha2-nistp256") => ReleaseKey::p256_from_hex(public),
        _ => Err(format!(
            "key type '{keytype}' with scheme '{scheme}' is not one this build verifies \
             (ed25519/ed25519, ecdsa/ecdsa-sha2-nistp256)"
        )),
    }
}

/// Whether `sig` (this encoding's spelling, decoded from hex) is `key`'s signature over `msg`.
pub fn verify(key: &ReleaseKey, msg: &[u8], sig: &[u8]) -> bool {
    match key {
        ReleaseKey::Ed25519(k) => {
            let Ok(arr) = <[u8; 64]>::try_from(sig) else {
                return false;
            };
            k.verify_strict(msg, &ed25519_dalek::Signature::from_bytes(&arr))
                .is_ok()
        }
        ReleaseKey::P256(point) => ring::signature::UnparsedPublicKey::new(
            &ring::signature::ECDSA_P256_SHA256_ASN1,
            &point[..],
        )
        .verify(msg, sig)
        .is_ok(),
    }
}

// ── the envelope ────────────────────────────────────────────────────────────────────────────────

/// An envelope over `signed`: the signed bytes and each `(keyid, signature)`.
fn read_envelope(
    bytes: &[u8],
    what: &str,
) -> Result<(Value, Vec<u8>, Vec<(String, Vec<u8>)>), String> {
    let v: Value =
        serde_json::from_slice(bytes).map_err(|e| format!("the {what} is not JSON: {e}"))?;
    let obj = v
        .as_object()
        .ok_or_else(|| format!("the {what} is not an object"))?;
    if let Some(k) = obj.keys().find(|k| *k != "signed" && *k != "signatures") {
        return Err(format!("the {what} envelope has an unknown field '{k}'"));
    }
    let signed = obj
        .get("signed")
        .ok_or_else(|| format!("the {what} has no `signed`"))?
        .clone();
    let signed_bytes = canonical(&signed).map_err(|e| format!("the {what}: {e}"))?;
    let mut sigs = Vec::new();
    for s in obj
        .get("signatures")
        .and_then(Value::as_array)
        .ok_or_else(|| format!("the {what} has no `signatures` list"))?
    {
        let keyid = s
            .get("keyid")
            .and_then(Value::as_str)
            .ok_or_else(|| format!("a {what} signature has no keyid"))?;
        let sig = s
            .get("sig")
            .and_then(Value::as_str)
            .ok_or_else(|| format!("a {what} signature has no sig"))?;
        let sig = hex::decode(sig).map_err(|e| format!("a {what} signature is not hex: {e}"))?;
        sigs.push((keyid.to_string(), sig));
    }
    Ok((signed, signed_bytes, sigs))
}

/// Write an envelope: `signed` and its signatures. For the release tooling and tests.
///
/// # Errors
///
/// `signed` is outside the canonical subset.
pub fn write_envelope(signed: &Value, sigs: &[(String, Vec<u8>)]) -> Result<Vec<u8>, String> {
    canonical(signed)?;
    let signatures: Vec<Value> = sigs
        .iter()
        .map(|(id, s)| serde_json::json!({"keyid": id, "sig": hex::encode(s)}))
        .collect();
    canonical(&serde_json::json!({"signed": signed, "signatures": signatures}))
}

// ── the two documents ───────────────────────────────────────────────────────────────────────────

fn str_field<'v>(obj: &'v serde_json::Map<String, Value>, k: &str) -> Result<&'v str, String> {
    obj.get(k)
        .and_then(Value::as_str)
        .ok_or_else(|| format!("`{k}` is missing or not a string"))
}

fn u64_field(obj: &serde_json::Map<String, Value>, k: &str) -> Result<u64, String> {
    obj.get(k)
        .and_then(Value::as_u64)
        .ok_or_else(|| format!("`{k}` is missing or not a non-negative integer"))
}

fn only_fields(
    obj: &serde_json::Map<String, Value>,
    known: &[&str],
    what: &str,
) -> Result<(), String> {
    match obj.keys().find(|k| !known.contains(&k.as_str())) {
        Some(k) => Err(format!("the {what} has an unknown field '{k}'")),
        None => Ok(()),
    }
}

fn header(obj: &serde_json::Map<String, Value>, ty: &str) -> Result<(u64, u64), String> {
    if str_field(obj, "_type")? != ty {
        return Err(format!("`_type` is not '{ty}'"));
    }
    let spec = str_field(obj, "spec_version")?;
    if spec != SPEC_VERSION {
        return Err(format!(
            "`spec_version` is '{spec}'; this build reads '{SPEC_VERSION}'"
        ));
    }
    Ok((
        u64_field(obj, "version")?,
        parse_time(str_field(obj, "expires")?)?,
    ))
}

/// Read a keys document envelope.
///
/// # Errors
///
/// Anything that is not one whole, well-formed keys document.
pub fn read_keys(bytes: &[u8]) -> Result<Signed<KeysDoc>, String> {
    let (signed, signed_bytes, signatures) = read_envelope(bytes, "keys document")?;
    let obj = signed.as_object().ok_or("`signed` is not an object")?;
    only_fields(
        obj,
        &[
            "_type",
            "spec_version",
            "version",
            "expires",
            "keys",
            "roles",
            "revocations",
        ],
        "keys document",
    )?;
    let (version, expires) = header(obj, KEYS_TYPE)?;
    let mut keys = BTreeMap::new();
    for (id, k) in obj
        .get("keys")
        .and_then(Value::as_object)
        .ok_or("`keys` is not an object")?
    {
        let key = read_key_object(k).map_err(|e| format!("key {id}: {e}"))?;
        if key_id(&key) != *id {
            return Err(format!(
                "key {id} is listed under an id that is not its own"
            ));
        }
        keys.insert(id.clone(), key);
    }
    let mut roles = BTreeMap::new();
    for (name, r) in obj
        .get("roles")
        .and_then(Value::as_object)
        .ok_or("`roles` is not an object")?
    {
        let r = r
            .as_object()
            .ok_or_else(|| format!("role {name} is not an object"))?;
        only_fields(r, &["keyids", "threshold"], "role")?;
        let keyids: Vec<String> = r
            .get("keyids")
            .and_then(Value::as_array)
            .ok_or_else(|| format!("role {name} has no keyids list"))?
            .iter()
            .map(|v| v.as_str().map(str::to_string))
            .collect::<Option<_>>()
            .ok_or_else(|| format!("role {name} has a keyid that is not a string"))?;
        let threshold = u64_field(r, "threshold")?;
        roles.insert(name.clone(), Role { keyids, threshold });
    }
    let (mut revoked_keyids, mut revoked_digests) = (BTreeSet::new(), BTreeMap::new());
    if let Some(rev) = obj.get("revocations") {
        let rev = rev.as_object().ok_or("`revocations` is not an object")?;
        only_fields(rev, &["keyids", "digests"], "revocations")?;
        for id in rev
            .get("keyids")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            revoked_keyids.insert(
                id.as_str()
                    .ok_or("a revoked keyid is not a string")?
                    .to_string(),
            );
        }
        for (d, why) in rev
            .get("digests")
            .and_then(Value::as_object)
            .into_iter()
            .flatten()
        {
            let why = why.as_str().ok_or("a revocation reason is not a string")?;
            revoked_digests.insert(d.to_ascii_lowercase(), why.to_string());
        }
    }
    Ok(Signed {
        doc: KeysDoc {
            version,
            expires,
            keys,
            roles,
            revoked_keyids,
            revoked_digests,
        },
        signed_bytes,
        signatures,
    })
}

/// Read a release manifest (targets) envelope.
///
/// # Errors
///
/// Anything that is not one whole, well-formed release manifest.
pub fn read_targets(bytes: &[u8]) -> Result<Signed<TargetsDoc>, String> {
    let (signed, signed_bytes, signatures) = read_envelope(bytes, "release manifest")?;
    let obj = signed.as_object().ok_or("`signed` is not an object")?;
    only_fields(
        obj,
        &[
            "_type",
            "spec_version",
            "version",
            "expires",
            "role",
            "targets",
        ],
        "release manifest",
    )?;
    let (version, expires) = header(obj, TARGETS_TYPE)?;
    let role = str_field(obj, "role")?.to_string();
    let mut targets = Vec::new();
    for (path, t) in obj
        .get("targets")
        .and_then(Value::as_object)
        .ok_or("`targets` is not an object")?
    {
        let t = t
            .as_object()
            .ok_or_else(|| format!("target {path} is not an object"))?;
        only_fields(t, &["length", "hashes", "custom"], "target")?;
        let custom = t
            .get("custom")
            .and_then(Value::as_object)
            .ok_or_else(|| format!("target {path} has no custom"))?;
        let (name, version, target) = (
            str_field(custom, "name")?,
            str_field(custom, "version")?,
            str_field(custom, "target")?,
        );
        if *path != format!("{name}/{version}/{target}") {
            return Err(format!(
                "target {path} is not named <name>/<version>/<target> of its custom"
            ));
        }
        let sha256 = t
            .get("hashes")
            .and_then(|h| h.get("sha256"))
            .and_then(Value::as_str)
            .ok_or_else(|| format!("target {path} has no hashes.sha256"))?;
        if sha256.len() != 64
            || !sha256
                .bytes()
                .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
        {
            return Err(format!(
                "target {path}'s sha256 is not 64 lowercase hex digits"
            ));
        }
        targets.push(Target {
            name: name.to_string(),
            version: version.to_string(),
            target: target.to_string(),
            sha256: sha256.to_string(),
            length: u64_field(t, "length")?,
        });
    }
    Ok(Signed {
        doc: TargetsDoc {
            role,
            version,
            expires,
            targets,
        },
        signed_bytes,
        signatures,
    })
}

/// The `signed` value of a keys document. For the release tooling and tests.
pub fn keys_signed(doc: &KeysDoc) -> Value {
    let keys: serde_json::Map<String, Value> = doc
        .keys
        .iter()
        .map(|(id, k)| (id.clone(), key_object(k)))
        .collect();
    let roles: serde_json::Map<String, Value> = doc
        .roles
        .iter()
        .map(|(n, r)| {
            (
                n.clone(),
                serde_json::json!({"keyids": r.keyids, "threshold": r.threshold}),
            )
        })
        .collect();
    serde_json::json!({
        "_type": KEYS_TYPE,
        "spec_version": SPEC_VERSION,
        "version": doc.version,
        "expires": format_time(doc.expires),
        "keys": keys,
        "roles": roles,
        "revocations": {"keyids": doc.revoked_keyids, "digests": doc.revoked_digests},
    })
}

/// The `signed` value of a release manifest. For the release tooling and tests.
pub fn targets_signed(doc: &TargetsDoc) -> Value {
    let targets: serde_json::Map<String, Value> = doc
        .targets
        .iter()
        .map(|t| {
            (
                format!("{}/{}/{}", t.name, t.version, t.target),
                serde_json::json!({
                    "length": t.length,
                    "hashes": {"sha256": t.sha256},
                    "custom": {"name": t.name, "version": t.version, "target": t.target},
                }),
            )
        })
        .collect();
    serde_json::json!({
        "_type": TARGETS_TYPE,
        "spec_version": SPEC_VERSION,
        "version": doc.version,
        "expires": format_time(doc.expires),
        "role": doc.role,
        "targets": targets,
    })
}

// ── time ────────────────────────────────────────────────────────────────────────────────────────

/// `YYYY-MM-DDTHH:MM:SSZ` (UTC, TUF's spelling) as Unix seconds.
///
/// # Errors
///
/// Any other spelling, or an impossible date.
pub fn parse_time(s: &str) -> Result<u64, String> {
    let bad = || format!("time '{s}' is not YYYY-MM-DDTHH:MM:SSZ");
    let b = s.as_bytes();
    if b.len() != 20
        || b[4] != b'-'
        || b[7] != b'-'
        || b[10] != b'T'
        || b[13] != b':'
        || b[16] != b':'
        || b[19] != b'Z'
    {
        return Err(bad());
    }
    let num = |r: std::ops::Range<usize>| -> Result<u64, String> {
        let part = &s[r];
        if !part.bytes().all(|c| c.is_ascii_digit()) {
            return Err(bad());
        }
        part.parse::<u64>().map_err(|_| bad())
    };
    let (y, mo, d, h, mi, se) = (
        num(0..4)?,
        num(5..7)?,
        num(8..10)?,
        num(11..13)?,
        num(14..16)?,
        num(17..19)?,
    );
    if y < 1970
        || !(1..=12).contains(&mo)
        || d < 1
        || d > days_in_month(y, mo)
        || h > 23
        || mi > 59
        || se > 59
    {
        return Err(bad());
    }
    Ok(days_from_civil(y, mo, d) * 86_400 + h * 3600 + mi * 60 + se)
}

/// Unix seconds as `YYYY-MM-DDTHH:MM:SSZ`.
pub fn format_time(t: u64) -> String {
    let (days, rem) = (t / 86_400, t % 86_400);
    let (y, m, d) = civil_from_days(days);
    format!(
        "{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}Z",
        rem / 3600,
        rem % 3600 / 60,
        rem % 60
    )
}

fn leap(y: u64) -> bool {
    (y % 4 == 0 && y % 100 != 0) || y % 400 == 0
}

fn days_in_month(y: u64, m: u64) -> u64 {
    match m {
        2 if leap(y) => 29,
        2 => 28,
        4 | 6 | 9 | 11 => 30,
        _ => 31,
    }
}

fn days_from_civil(y: u64, m: u64, d: u64) -> u64 {
    let mut days = 0;
    for yy in 1970..y {
        days += if leap(yy) { 366 } else { 365 };
    }
    for mm in 1..m {
        days += days_in_month(y, mm);
    }
    days + d - 1
}

fn civil_from_days(mut days: u64) -> (u64, u64, u64) {
    let mut y = 1970;
    loop {
        let n = if leap(y) { 366 } else { 365 };
        if days < n {
            break;
        }
        days -= n;
        y += 1;
    }
    let mut m = 1;
    while days >= days_in_month(y, m) {
        days -= days_in_month(y, m);
        m += 1;
    }
    (y, m, days + 1)
}

// ── the seal a plugin manifest carries ──────────────────────────────────────────────────────────

/// The prefix that marks a manifest `signature` as a RELEASE SEAL rather than a per-plugin ed25519
/// signature (128 hex digits, which never start with it).
pub const SEAL_PREFIX: &str = "seal:";

/// The manifest `signature` spelling of a seal: [`SEAL_PREFIX`] then the canonical JSON
/// `{"keys":<keys envelope>,"targets":<release manifest envelope>}`. The `signature` field is outside
/// the plugin's canonical manifest bytes, so sealing never changes what the release lists.
///
/// # Errors
///
/// Either document is not a canonical-subset envelope.
pub fn write_seal(keys: &[u8], targets: &[u8]) -> Result<String, String> {
    let keys: Value = serde_json::from_slice(keys).map_err(|e| format!("keys document: {e}"))?;
    let targets: Value =
        serde_json::from_slice(targets).map_err(|e| format!("release manifest: {e}"))?;
    let body = canonical(&serde_json::json!({"keys": keys, "targets": targets}))?;
    Ok(format!(
        "{SEAL_PREFIX}{}",
        String::from_utf8(body).expect("canonical bytes are ASCII")
    ))
}

/// The seal in a manifest `signature`: `None` when it is not a seal, else its two documents'
/// bytes.
pub fn read_seal(signature: &str) -> Option<Result<(Vec<u8>, Vec<u8>), String>> {
    let body = signature.trim().strip_prefix(SEAL_PREFIX)?;
    Some((|| {
        let v: Value =
            serde_json::from_str(body).map_err(|e| format!("the seal is not JSON: {e}"))?;
        let obj = v.as_object().ok_or("the seal is not an object")?;
        only_fields(obj, &["keys", "targets"], "seal")?;
        let doc = |k: &str| -> Result<Vec<u8>, String> {
            let d = obj.get(k).ok_or_else(|| format!("the seal has no `{k}`"))?;
            serde_json::to_vec(d).map_err(|e| e.to_string())
        };
        Ok((doc("keys")?, doc("targets")?))
    })())
}

/// The version of the keys document a seal carries, unverified (for raising the accepted floor
/// after the chain was verified).
pub fn sealed_keys_version(signature: &str) -> Option<u64> {
    let (keys, _) = read_seal(signature)?.ok()?;
    let v: Value = serde_json::from_slice(&keys).ok()?;
    v.get("signed")?.get("version")?.as_u64()
}
