// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::{KeysDoc, ReleaseKey, Role, Signed, Target, TargetsDoc};
use crate::verification::Verifier;
use busbar_json::{self as json, JsonContainerTrait, JsonValueTrait, Map, Value};
use std::collections::{BTreeMap, BTreeSet};

pub const SPEC_VERSION: &str = "0.1-provisional";

pub const KEYS_TYPE: &str = "busbar-keys";

pub const TARGETS_TYPE: &str = "targets";

/// The canonical (OLPC) bytes of a release document, written by olpc-cjson's sonic-rs formatter
/// (DEPENDENCY-LADDER C16, SERDE-JSON-EXIT r2 §2) over the subset both sides sign: non-negative
/// integers and printable ASCII.
pub fn canonical(v: &Value) -> Result<Vec<u8>, String> {
    in_canonical_subset(v)?;
    let mut ser =
        sonic_rs::Serializer::with_formatter(Vec::new(), olpc_cjson::CanonicalFormatter::new());
    serde::Serialize::serialize(v, &mut ser).map_err(|e| e.to_string())?;
    Ok(ser.into_inner())
}

fn in_canonical_subset(v: &Value) -> Result<(), String> {
    if let Some(items) = v.as_array() {
        return items.iter().try_for_each(in_canonical_subset);
    }
    if let Some(map) = v.as_object() {
        return map.iter().try_for_each(|(k, v)| {
            printable_ascii(k)?;
            // olpc-cjson orders keys by their escaped bytes; these are the only keys for which
            // that differs from the Python (securesystemslib) order.
            if k.contains([' ', '!', '"']) {
                return Err(format!(
                    "key {k:?} holds a space, '!' or '\"', outside the canonical key set"
                ));
            }
            in_canonical_subset(v)
        });
    }
    if let Some(s) = v.as_str() {
        return printable_ascii(s);
    }
    if v.is_number() && whole(v).is_none() {
        return Err(format!("number {v} is not a non-negative integer"));
    }
    Ok(())
}

/// A non-negative integer. A number read from a document keeps its lexeme, and it counts only
/// when that lexeme is a `u64` (as exact numbers always read here: `1.0`, `1e2` and `-0` are
/// not); a number built in code is read as its value.
fn whole(v: &Value) -> Option<u64> {
    match v.as_raw_number() {
        Some(raw) => raw.as_str().parse().ok(),
        None => v.as_u64(),
    }
}

fn printable_ascii(s: &str) -> Result<(), String> {
    match s.chars().find(|c| !(' '..='~').contains(c)) {
        Some(c) => Err(format!(
            "string {s:?} holds {c:?}, outside printable ASCII (the canonical subset)"
        )),
        None => Ok(()),
    }
}

pub fn key_object(key: &ReleaseKey) -> Value {
    let (keytype, scheme, public) = match key {
        ReleaseKey::Ed25519(k) => ("ed25519", "ed25519", hex::encode(k.as_bytes())),
        ReleaseKey::P256(point) => ("ecdsa", "ecdsa-sha2-nistp256", hex::encode(point)),
    };
    json::json!({"keytype": keytype, "scheme": scheme, "keyval": {"public": public}})
}

pub fn key_id(key: &ReleaseKey) -> String {
    let bytes = canonical(&key_object(key)).expect("a key object is in the canonical subset");
    crate::sign::sha256_hex(&bytes)
}

#[doc(hidden)]
pub fn read_key_object(
    verifier: &Verifier<'_>,
    v: &Value,
) -> crate::verification::Result<ReleaseKey> {
    let obj = v.as_object().ok_or("a key is not an object")?;
    only_fields(obj, &["keytype", "scheme", "keyval"], "key")?;
    let keytype = str_field(obj, "keytype")?;
    let scheme = str_field(obj, "scheme")?;
    let keyval = obj
        .get(&"keyval")
        .and_then(Value::as_object)
        .ok_or("a key has no keyval object")?;
    only_fields(keyval, &["public"], "keyval")?;
    let public = str_field(keyval, "public")?;
    match (keytype, scheme) {
        ("ed25519", "ed25519") => verifier.public_key_from_hex(public).map(ReleaseKey::Ed25519),
        ("ecdsa", "ecdsa-sha2-nistp256") => p256_from_hex_guarded(verifier, public),
        _ => Err(format!("key type '{keytype}' with scheme '{scheme}' is not one this build verifies (ed25519/ed25519, ecdsa/ecdsa-sha2-nistp256)").into()),
    }
}

pub(crate) fn p256_from_hex_guarded(
    verifier: &Verifier<'_>,
    s: &str,
) -> crate::verification::Result<ReleaseKey> {
    let bytes = hex::decode(s.trim()).map_err(|e| format!("p256 public key not valid hex: {e}"))?;
    let point: [u8; 65] = bytes.as_slice().try_into().map_err(|_| {
        format!(
            "p256 public key must be the 65-byte uncompressed SEC1 point, got {} bytes",
            bytes.len()
        )
    })?;
    if point[0] != 4 {
        return Err("p256 public key is not an uncompressed SEC1 point (04 || x || y)".into());
    }
    Verifier::primitive(verifier.crypto.validate_p256(&point))?;
    Ok(ReleaseKey::P256(point))
}

/// Strict verification; provider failures remain distinct from invalid signatures.
pub fn verify(
    key: &ReleaseKey,
    msg: &[u8],
    sig: &[u8],
) -> Result<bool, busbar_crypto::verification::Failure> {
    Verifier::unrestricted().verify(key, msg, sig)
}

type KeyedSigs = Vec<(String, Vec<u8>)>;

pub type SealBytes = (Vec<u8>, Vec<u8>);

fn read_envelope(bytes: &[u8], what: &str) -> Result<(Value, Vec<u8>, KeyedSigs), String> {
    let v = json::parse_value(bytes).map_err(|e| format!("the {what} is not JSON: {e}"))?;
    let obj = v
        .as_object()
        .ok_or_else(|| format!("the {what} is not an object"))?;
    if let Some(k) = obj
        .iter()
        .map(|(k, _)| k)
        .find(|k| *k != "signed" && *k != "signatures")
    {
        return Err(format!("the {what} envelope has an unknown field '{k}'"));
    }
    let signed = obj
        .get(&"signed")
        .ok_or_else(|| format!("the {what} has no `signed`"))?
        .clone();
    let signed_bytes = canonical(&signed).map_err(|e| format!("the {what}: {e}"))?;
    let mut sigs = Vec::new();
    for s in obj
        .get(&"signatures")
        .and_then(Value::as_array)
        .ok_or_else(|| format!("the {what} has no `signatures` list"))?
    {
        let signature = s
            .as_object()
            .ok_or_else(|| format!("a {what} signature is not an object"))?;
        only_fields(signature, &["keyid", "sig"], "signature")?;
        let keyid = str_field(signature, "keyid")?;
        let sig = str_field(signature, "sig")?;
        let sig = hex::decode(sig).map_err(|e| format!("a {what} signature is not hex: {e}"))?;
        sigs.push((keyid.to_string(), sig));
    }
    Ok((signed, signed_bytes, sigs))
}

pub fn write_envelope(signed: &Value, sigs: &[(String, Vec<u8>)]) -> Result<Vec<u8>, String> {
    canonical(signed)?;
    let signatures: Vec<Value> = sigs
        .iter()
        .map(|(id, s)| json::json!({"keyid": id, "sig": hex::encode(s)}))
        .collect();
    let mut envelope = Map::new();
    envelope.insert("signed", signed.clone());
    envelope.insert("signatures", signatures);
    canonical(&envelope.into_value())
}

fn str_field<'v>(obj: &'v Map, k: &str) -> Result<&'v str, String> {
    obj.get(&k)
        .and_then(Value::as_str)
        .ok_or_else(|| format!("`{k}` is missing or not a string"))
}

fn u64_field(obj: &Map, k: &str) -> Result<u64, String> {
    obj.get(&k)
        .and_then(whole)
        .ok_or_else(|| format!("`{k}` is missing or not a non-negative integer"))
}

fn only_fields(obj: &Map, known: &[&str], what: &str) -> Result<(), String> {
    match obj.iter().map(|(k, _)| k).find(|k| !known.contains(k)) {
        Some(k) => Err(format!("the {what} has an unknown field '{k}'")),
        None => Ok(()),
    }
}

fn header(obj: &Map, ty: &str) -> Result<(u64, u64), String> {
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

pub fn read_keys(bytes: &[u8]) -> Result<Signed<KeysDoc>, String> {
    Verifier::unrestricted()
        .read_keys(bytes)
        .map_err(|error| error.to_string())
}

pub(crate) fn read_keys_guarded(
    verifier: &Verifier<'_>,
    bytes: &[u8],
) -> crate::verification::Result<Signed<KeysDoc>> {
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
        .get(&"keys")
        .and_then(Value::as_object)
        .ok_or("`keys` is not an object")?
    {
        let key = read_key_object(verifier, k)
            .map_err(|e| e.map_refused(|e| format!("key {id}: {e}")))?;
        if verifier.key_id(&key)? != *id {
            return Err(format!("key {id} is listed under an id that is not its own").into());
        }
        keys.insert(id.to_string(), key);
    }
    let mut roles = BTreeMap::new();
    for (name, r) in obj
        .get(&"roles")
        .and_then(Value::as_object)
        .ok_or("`roles` is not an object")?
    {
        let r = r
            .as_object()
            .ok_or_else(|| format!("role {name} is not an object"))?;
        only_fields(r, &["keyids", "threshold"], "role")?;
        let keyids: Vec<String> = r
            .get(&"keyids")
            .and_then(Value::as_array)
            .ok_or_else(|| format!("role {name} has no keyids list"))?
            .iter()
            .map(|v| v.as_str().map(str::to_string))
            .collect::<Option<_>>()
            .ok_or_else(|| format!("role {name} has a keyid that is not a string"))?;
        let threshold = u64_field(r, "threshold")?;
        roles.insert(name.to_string(), Role { keyids, threshold });
    }
    let (mut revoked_keyids, mut revoked_digests) = (BTreeSet::new(), BTreeMap::new());
    if let Some(rev) = obj.get(&"revocations") {
        let rev = rev.as_object().ok_or("`revocations` is not an object")?;
        only_fields(rev, &["keyids", "digests"], "revocations")?;
        if let Some(ids) = rev.get(&"keyids") {
            for id in ids.as_array().ok_or("revocations.keyids is not a list")? {
                revoked_keyids.insert(
                    id.as_str()
                        .ok_or("a revoked keyid is not a string")?
                        .to_string(),
                );
            }
        }
        if let Some(digests) = rev.get(&"digests") {
            for (d, why) in digests
                .as_object()
                .ok_or("revocations.digests is not an object")?
            {
                let why = why.as_str().ok_or("a revocation reason is not a string")?;
                revoked_digests.insert(d.to_ascii_lowercase(), why.to_string());
            }
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
    // In path order, as the document's own order is not signed (the canonical form sorts it).
    let by_path: BTreeMap<&str, &Value> = obj
        .get(&"targets")
        .and_then(Value::as_object)
        .ok_or("`targets` is not an object")?
        .iter()
        .collect();
    for (path, t) in by_path {
        let t = t
            .as_object()
            .ok_or_else(|| format!("target {path} is not an object"))?;
        only_fields(t, &["length", "hashes", "custom"], "target")?;
        let custom = t
            .get(&"custom")
            .and_then(Value::as_object)
            .ok_or_else(|| format!("target {path} has no custom"))?;
        only_fields(custom, &["name", "version", "target"], "target custom")?;
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
        let hashes = t
            .get(&"hashes")
            .and_then(Value::as_object)
            .ok_or_else(|| format!("target {path} has no hashes object"))?;
        only_fields(hashes, &["sha256"], "target hashes")?;
        let sha256 = str_field(hashes, "sha256")?;
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

pub fn keys_signed(doc: &KeysDoc) -> Value {
    let mut keys = Map::new();
    for (id, k) in &doc.keys {
        keys.insert(id, key_object(k));
    }
    let mut roles = Map::new();
    for (n, r) in &doc.roles {
        roles.insert(
            n,
            json::json!({"keyids": r.keyids, "threshold": r.threshold}),
        );
    }
    json::json!({
        "_type": KEYS_TYPE,
        "spec_version": SPEC_VERSION,
        "version": doc.version,
        "expires": format_time(doc.expires),
        "keys": keys,
        "roles": roles,
        "revocations": {"keyids": doc.revoked_keyids, "digests": doc.revoked_digests},
    })
}

pub fn targets_signed(doc: &TargetsDoc) -> Value {
    let mut targets = Map::new();
    for t in &doc.targets {
        targets.insert(
            &format!("{}/{}/{}", t.name, t.version, t.target),
            json::json!({
                "length": t.length,
                "hashes": {"sha256": t.sha256},
                "custom": {"name": t.name, "version": t.version, "target": t.target},
            }),
        );
    }
    json::json!({
        "_type": TARGETS_TYPE,
        "spec_version": SPEC_VERSION,
        "version": doc.version,
        "expires": format_time(doc.expires),
        "role": doc.role,
        "targets": targets,
    })
}

/// The release-document time grammar, `YYYY-MM-DDTHH:MM:SSZ` (DEPENDENCY-LADDER C10, on `time`).
const RELEASE_TIME: time::format_description::StaticFormatDescription =
    time::macros::format_description!("[year]-[month]-[day]T[hour]:[minute]:[second]Z");

pub fn parse_time(s: &str) -> Result<u64, String> {
    let bad = || format!("time '{s}' is not YYYY-MM-DDTHH:MM:SSZ");
    // `[year]` also takes a leading sign; the grammar is exactly twenty bytes, which refuses it.
    if s.len() != 20 {
        return Err(bad());
    }
    let at = time::PrimitiveDateTime::parse(s, RELEASE_TIME).map_err(|_| bad())?;
    u64::try_from(at.assume_utc().unix_timestamp()).map_err(|_| bad())
}

pub fn format_time(t: u64) -> String {
    busbar_artifact_metadata::civil::rfc3339_from_secs(t)
}

pub const SEAL_PREFIX: &str = "seal:";

pub fn write_seal(keys: &[u8], targets: &[u8]) -> Result<String, String> {
    let keys = json::parse_value(keys).map_err(|e| format!("keys document: {e}"))?;
    let targets = json::parse_value(targets).map_err(|e| format!("release manifest: {e}"))?;
    let mut seal = Map::new();
    seal.insert("keys", keys);
    seal.insert("targets", targets);
    let body = canonical(&seal.into_value())?;
    Ok(format!(
        "{SEAL_PREFIX}{}",
        String::from_utf8(body).expect("canonical bytes are ASCII")
    ))
}

pub fn read_seal(signature: &str) -> Option<Result<SealBytes, String>> {
    let body = signature.trim().strip_prefix(SEAL_PREFIX)?;
    Some((|| {
        let v =
            json::parse_value(body.as_bytes()).map_err(|e| format!("the seal is not JSON: {e}"))?;
        let obj = v.as_object().ok_or("the seal is not an object")?;
        only_fields(obj, &["keys", "targets"], "seal")?;
        let doc = |k: &str| -> Result<Vec<u8>, String> {
            let d = obj
                .get(&k)
                .ok_or_else(|| format!("the seal has no `{k}`"))?;
            json::to_vec(d).map_err(|e| e.to_string())
        };
        Ok((doc("keys")?, doc("targets")?))
    })())
}

#[cfg(any(test, feature = "test-support"))]
pub fn sealed_keys_version(signature: &str) -> Option<u64> {
    let (keys, _) = read_seal(signature)?.ok()?;
    let v = json::parse_value(&keys).ok()?;
    whole(v.get("signed")?.get("version")?)
}
