// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::{KeysDoc, ReleaseKey, Role, Signed, Target, TargetsDoc};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};

pub const SPEC_VERSION: &str = "0.1-provisional";

pub const KEYS_TYPE: &str = "busbar-keys";

pub const TARGETS_TYPE: &str = "targets";

/// The canonical (OLPC) bytes of a release document, written by olpc-cjson (DEPENDENCY-LADDER C16)
/// over the subset both sides sign: non-negative integers and printable ASCII.
pub fn canonical(v: &Value) -> Result<Vec<u8>, String> {
    in_canonical_subset(v)?;
    let mut out = Vec::new();
    let mut ser =
        serde_json::Serializer::with_formatter(&mut out, olpc_cjson::CanonicalFormatter::new());
    serde::Serialize::serialize(v, &mut ser).map_err(|e| e.to_string())?;
    Ok(out)
}

fn in_canonical_subset(v: &Value) -> Result<(), String> {
    match v {
        Value::Null | Value::Bool(_) => Ok(()),
        Value::Number(n) if n.as_u64().is_some() => Ok(()),
        Value::Number(n) => Err(format!("number {n} is not a non-negative integer")),
        Value::String(s) => printable_ascii(s),
        Value::Array(items) => items.iter().try_for_each(in_canonical_subset),
        Value::Object(map) => map.iter().try_for_each(|(k, v)| {
            printable_ascii(k)?;
            // olpc-cjson orders keys by their escaped bytes; these are the only keys for which
            // that differs from the Python (securesystemslib) order.
            if k.contains([' ', '!', '"']) {
                return Err(format!(
                    "key {k:?} holds a space, '!' or '\"', outside the canonical key set"
                ));
            }
            in_canonical_subset(v)
        }),
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
    serde_json::json!({"keytype": keytype, "scheme": scheme, "keyval": {"public": public}})
}

pub fn key_id(key: &ReleaseKey) -> String {
    let bytes = canonical(&key_object(key)).expect("a key object is in the canonical subset");
    crate::sign::sha256_hex(&bytes)
}

pub(crate) fn read_key_object(v: &Value) -> Result<ReleaseKey, String> {
    let obj = v.as_object().ok_or("a key is not an object")?;
    only_fields(obj, &["keytype", "scheme", "keyval"], "key")?;
    let keytype = str_field(obj, "keytype")?;
    let scheme = str_field(obj, "scheme")?;
    let keyval = obj
        .get("keyval")
        .and_then(Value::as_object)
        .ok_or("a key has no keyval object")?;
    only_fields(keyval, &["public"], "keyval")?;
    let public = str_field(keyval, "public")?;
    match (keytype, scheme) {
        ("ed25519", "ed25519") => crate::sign::public_key_from_hex(public).map(ReleaseKey::Ed25519),
        ("ecdsa", "ecdsa-sha2-nistp256") => p256_from_hex(public),
        _ => Err(format!(
            "key type '{keytype}' with scheme '{scheme}' is not one this build verifies \
             (ed25519/ed25519, ecdsa/ecdsa-sha2-nistp256)"
        )),
    }
}

pub(crate) fn p256_from_hex(s: &str) -> Result<ReleaseKey, String> {
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
    Ok(ReleaseKey::P256(point))
}

/// Strict Ed25519 (a weak key never verifies) or P-256 SHA-256 with an ASN.1 DER signature.
pub fn verify(key: &ReleaseKey, msg: &[u8], sig: &[u8]) -> bool {
    match key {
        ReleaseKey::Ed25519(k) => {
            let Ok(sig) = <&[u8; 64]>::try_from(sig) else {
                return false;
            };
            !k.is_weak()
                && k.verify_strict(msg, &crate::sign::Signature::from_bytes(sig))
                    .is_ok()
        }
        ReleaseKey::P256(k) => {
            k[0] == 4 && busbar_contract::crypto::ecdsa_p256::verify_asn1(k, msg, sig).is_ok()
        }
    }
}

type KeyedSigs = Vec<(String, Vec<u8>)>;

pub type SealBytes = (Vec<u8>, Vec<u8>);

fn read_envelope(bytes: &[u8], what: &str) -> Result<(Value, Vec<u8>, KeyedSigs), String> {
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
        .map(|(id, s)| serde_json::json!({"keyid": id, "sig": hex::encode(s)}))
        .collect();
    canonical(&serde_json::json!({"signed": signed, "signatures": signatures}))
}

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
        if let Some(ids) = rev.get("keyids") {
            for id in ids.as_array().ok_or("revocations.keyids is not a list")? {
                revoked_keyids.insert(
                    id.as_str()
                        .ok_or("a revoked keyid is not a string")?
                        .to_string(),
                );
            }
        }
        if let Some(digests) = rev.get("digests") {
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
            .get("hashes")
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
    busbar_contract::civil::rfc3339_from_secs(t)
}

pub const SEAL_PREFIX: &str = "seal:";

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

pub fn read_seal(signature: &str) -> Option<Result<SealBytes, String>> {
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

#[cfg(test)]
pub fn sealed_keys_version(signature: &str) -> Option<u64> {
    let (keys, _) = read_seal(signature)?.ok()?;
    let v: Value = serde_json::from_slice(&keys).ok()?;
    v.get("signed")?.get("version")?.as_u64()
}
