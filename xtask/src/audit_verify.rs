//! `cargo xtask audit-verify` — an audit-chain verifier that never runs busbar's code.
//!
//! BUSBAR-1.6.0.md #82(c): "if only busbar can verify busbar's chain it is a claim, not evidence".
//! This module reads the three published bodies (`GET /api/v1/admin/audit/range`, `/keys`, and
//! optionally `/head`, saved to files by any HTTP client) and checks them by the published pages
//! ALONE: `docs/audit-chain-digest-v4.md` and the `v3`/`v2` pages it keeps beside it.
//!
//! It links nothing from the product. The field order below is transcribed from the pages, the
//! framing is the pages' (big-endian eight-byte length, then the bytes; a number is its big-endian
//! eight-byte form), the hash is this crate's own SHA-256, and the signature is checked with `ring`
//! (the workspace's one crypto backend). A verifier that called the code that seals the chain would
//! agree with any build whose field order had drifted from the page, which is the one failure worth
//! catching.
//!
//! What it checks, in the page's own order (section 5): every record's position and link, its digest
//! recomputed from its published fields, its signature against the published key its `key_id`
//! names, the key set's own `key_id` derivations, and — with a head — the tail a dropped last record
//! would leave. An empty run verifies, as the page says it must.

use std::fmt;

use serde_json::Value;

use crate::sha256::Sha256;

/// The signature domain every record's preimage starts with (page section 4).
pub const SIGNATURE_DOMAIN: &str = "busbar.audit.record.v1";

/// The only signature algorithm the pages publish.
pub const ALGORITHM: &str = "ed25519";

/// How one recipe field is framed: a text is length-prefixed bytes, a number its big-endian `u64`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    Text,
    Num,
}

use Kind::{Num, Text};

/// THE FIELD ORDER of `busbar.audit.digest.v4`, transcribed from the page's section 3.6. A name
/// `group[].member` is one member of each element of the record's `group` array, `group[]` an element
/// that is itself the value; each group follows its own `group_count` field.
pub const V4_FIELDS: &[(&str, Kind)] = &[
    ("prev_hash", Text),
    ("seq", Num),
    ("subject_tag", Text),
    ("subject_value", Text),
    ("unit_key", Num),
    ("incarnation", Num),
    ("op_class", Text),
    ("destination", Text),
    ("parent", Num),
    ("pre_hook_head", Text),
    ("post_hook_head", Text),
    ("wall", Num),
    ("mono", Num),
    ("origin_kind", Text),
    ("outcome", Text),
    ("step", Text),
    ("finish", Text),
    ("hook_failed", Num),
    ("emission_delta", Text),
    ("stale_policy", Num),
    ("lines_count", Num),
    ("lines[].class", Text),
    ("lines[].quantity", Num),
    ("lines[].source", Text),
    ("lines[].estimated", Num),
    ("tier_bp", Num),
    ("fee_count", Num),
    ("rate_card_version", Num),
    ("bucket_chain_ref", Text),
    ("hold_ref", Text),
    ("settle_ref", Text),
    ("slice_ref", Text),
    ("lease_ref", Text),
    ("lease_epoch", Num),
    ("policy_epoch", Num),
    ("hooks_count", Num),
    ("hooks[].hook", Text),
    ("replayed", Num),
    ("children_count", Num),
    ("children[]", Num),
    ("correlation_hash", Text),
];

/// One published recipe, as its difference from `v4` (each page states exactly that difference):
/// the fields it does not frame, and the one it frames after a named field.
pub struct Recipe {
    pub name: &'static str,
    pub without: &'static [&'static str],
    pub plus_after: Option<(&'static str, &'static str, Kind)>,
}

/// Every recipe a node may still hold a record under. `v1` is not here: the `v4` page says no node
/// retains a `v1` record, and a recipe this verifier does not know is refused, never guessed.
pub const RECIPES: &[Recipe] = &[
    Recipe {
        name: "busbar.audit.digest.v4",
        without: &[],
        plus_after: None,
    },
    // `v3` is `v4` less `incarnation`.
    Recipe {
        name: "busbar.audit.digest.v3",
        without: &["incarnation"],
        plus_after: None,
    },
    // `v2` is `v3` plus `currency`, a text between `fee_count` and `rate_card_version`.
    Recipe {
        name: "busbar.audit.digest.v2",
        without: &["incarnation"],
        plus_after: Some(("fee_count", "currency", Text)),
    },
];

/// The field order of the recipe named `name`, or `None` for a recipe this verifier does not know.
#[must_use]
pub fn fields_of(name: &str) -> Option<Vec<(&'static str, Kind)>> {
    let recipe = RECIPES.iter().find(|r| r.name == name)?;
    let mut out = Vec::with_capacity(V4_FIELDS.len() + 1);
    for &(field, kind) in V4_FIELDS {
        if recipe.without.contains(&field) {
            continue;
        }
        out.push((field, kind));
        if let Some((after, added, added_kind)) = recipe.plus_after {
            if after == field {
                out.push((added, added_kind));
            }
        }
    }
    Some(out)
}

/// The small-order points of edwards25519, each with its sign bit cleared (libsodium's list): a key
/// on one of them would verify signatures nobody minted, so the page refuses it. The sign bit is
/// ignored on compare, which also covers the non-canonical spellings `p - 1`, `p` and `p + 1`.
pub const SMALL_ORDER: &[&str] = &[
    "0000000000000000000000000000000000000000000000000000000000000000",
    "0100000000000000000000000000000000000000000000000000000000000000",
    "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05",
    "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a",
    "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
    "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
    "eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
];

/// Whether a 32-byte public key is a small-order point (sign bit ignored).
#[must_use]
pub fn is_small_order(key: &[u8; 32]) -> bool {
    SMALL_ORDER.iter().any(|h| {
        let p = unhex(h).expect("the small-order table is hex");
        p[..31] == key[..31] && (p[31] & 0x7f) == (key[31] & 0x7f)
    })
}

/// `key_id = first 8 bytes of SHA-256(public_key_bytes)`, as 16 lowercase hex (page section 4.1).
#[must_use]
pub fn key_id_of(public_key: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(public_key);
    h.hexdigest()[..16].to_string()
}

/// One thing the bodies got wrong. Each names the record position it is about (0 for the body).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Finding {
    pub seq: u64,
    pub what: String,
}

impl fmt::Display for Finding {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.seq == 0 {
            write!(f, "body: {}", self.what)
        } else {
            write!(f, "seq {}: {}", self.seq, self.what)
        }
    }
}

/// The verdict over one range: how many records were checked, and every finding.
#[derive(Debug, Default)]
pub struct Verdict {
    pub records: usize,
    pub signatures: usize,
    pub findings: Vec<Finding>,
}

impl Verdict {
    #[must_use]
    pub fn green(&self) -> bool {
        self.findings.is_empty()
    }

    fn find(&mut self, seq: u64, what: impl Into<String>) {
        self.findings.push(Finding {
            seq,
            what: what.into(),
        });
    }
}

fn unhex(s: &str) -> Option<Vec<u8>> {
    if !s.len().is_multiple_of(2) || !s.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).ok())
        .collect()
}

fn frame(out: &mut Vec<u8>, kind: Kind, value: &Value) -> Result<(), String> {
    match (kind, value) {
        (Text, Value::String(s)) => {
            out.extend_from_slice(&(s.len() as u64).to_be_bytes());
            out.extend_from_slice(s.as_bytes());
            Ok(())
        }
        (Num, Value::Number(n)) => {
            let v = n
                .as_u64()
                .ok_or_else(|| format!("{n} is not an unsigned 64-bit number"))?;
            out.extend_from_slice(&8u64.to_be_bytes());
            out.extend_from_slice(&v.to_be_bytes());
            Ok(())
        }
        (Text, other) => Err(format!("a text field carries {other}")),
        (Num, other) => Err(format!("a number field carries {other}")),
    }
}

/// THE DIGEST of one published record under the recipe it names: its fields framed in the page's
/// order, concatenated with nothing between, SHA-256, 64 lowercase hex.
///
/// # Errors
///
/// A missing field, a field of the wrong kind, a group whose length is not its count, or a recipe
/// this verifier does not know.
pub fn digest(record: &Value, recipe: &str) -> Result<String, String> {
    let fields = fields_of(recipe).ok_or_else(|| format!("unknown recipe {recipe:?}"))?;
    let mut pre = Vec::new();
    let mut i = 0;
    while i < fields.len() {
        let (name, kind) = fields[i];
        let Some((group, _)) = name.split_once("[]") else {
            let v = record
                .get(name)
                .ok_or_else(|| format!("no `{name}` field"))?;
            frame(&mut pre, kind, v).map_err(|e| format!("`{name}`: {e}"))?;
            i += 1;
            continue;
        };
        // A repeated group: the run of table rows naming it, framed once per element in order.
        let end = fields[i..]
            .iter()
            .position(|(n, _)| !n.starts_with(&format!("{group}[]")))
            .map_or(fields.len(), |p| i + p);
        let members = &fields[i..end];
        let elements = record
            .get(group)
            .and_then(Value::as_array)
            .ok_or_else(|| format!("no `{group}` array"))?;
        let count = record
            .get(format!("{group}_count").as_str())
            .and_then(Value::as_u64);
        if count != Some(elements.len() as u64) {
            return Err(format!(
                "`{group}` holds {} element(s) but `{group}_count` says {count:?}",
                elements.len()
            ));
        }
        for element in elements {
            for &(member, kind) in members {
                let v = match member.strip_prefix(&format!("{group}[].")) {
                    Some(m) => element
                        .get(m)
                        .ok_or_else(|| format!("a `{group}` element has no `{m}`"))?,
                    None => element,
                };
                frame(&mut pre, kind, v).map_err(|e| format!("`{member}`: {e}"))?;
            }
        }
        i = end;
    }
    let mut h = Sha256::new();
    h.update(&pre);
    Ok(h.hexdigest())
}

/// The published key set, by `key_id`, each id re-derived from its key and each key checked.
fn key_set(keys: &Value, v: &mut Verdict) -> Vec<(String, Vec<u8>)> {
    let mut out = Vec::new();
    let Some(list) = keys.get("keys").and_then(Value::as_array) else {
        v.find(0, "the key set has no `keys` array");
        return out;
    };
    for k in list {
        let id = k.get("key_id").and_then(Value::as_str).unwrap_or("");
        let algorithm = k.get("algorithm").and_then(Value::as_str).unwrap_or("");
        let Some(bytes) = k
            .get("public_key")
            .and_then(Value::as_str)
            .and_then(unhex)
            .filter(|b| b.len() == 32)
        else {
            v.find(0, format!("key {id:?}: its public_key is not 32 hex bytes"));
            continue;
        };
        if algorithm != ALGORITHM {
            v.find(
                0,
                format!("key {id:?}: algorithm {algorithm:?}, not {ALGORITHM}"),
            );
            continue;
        }
        let derived = key_id_of(&bytes);
        if derived != id {
            v.find(
                0,
                format!("key {id:?}: its key_id is not the derivation of its key ({derived})"),
            );
            continue;
        }
        let arr: [u8; 32] = bytes.as_slice().try_into().expect("32 bytes");
        if is_small_order(&arr) {
            v.find(
                0,
                format!("key {id:?} is a small-order point and would verify anything"),
            );
            continue;
        }
        out.push((derived, bytes));
    }
    out
}

/// VERIFY one range body against the published key set and, when given, the head.
///
/// Every finding is collected; nothing stops at the first. A green verdict means: every record is
/// in position and linked, every digest recomputes from the published fields, every signature
/// checks against a published key, and (with a head) no record is missing from the window's end.
#[must_use]
pub fn verify(range: &Value, keys: &Value, head: Option<&Value>) -> Verdict {
    let mut v = Verdict::default();
    for (member, want) in [
        ("signature_domain", SIGNATURE_DOMAIN),
        ("algorithm", ALGORITHM),
    ] {
        for (body, which) in [(range, "range"), (keys, "key set")] {
            let got = body.get(member).and_then(Value::as_str);
            if got != Some(want) {
                v.find(
                    0,
                    format!("the {which} names {member} {got:?}, not {want:?}"),
                );
            }
        }
    }
    let keys = key_set(keys, &mut v);
    let body_recipe = range.get("recipe").and_then(Value::as_str).unwrap_or("");
    let Some(records) = range.get("records").and_then(Value::as_array) else {
        v.find(0, "the range has no `records` array");
        return v;
    };
    let mut prev: Option<(u64, String)> = None;
    for record in records {
        v.records += 1;
        let seq = record.get("seq").and_then(Value::as_u64).unwrap_or(0);
        let hash = record.get("hash").and_then(Value::as_str).unwrap_or("");
        let prev_hash = record
            .get("prev_hash")
            .and_then(Value::as_str)
            .unwrap_or("");
        // 1. Link and position.
        match &prev {
            Some((p_seq, p_hash)) => {
                if seq != p_seq + 1 {
                    v.find(
                        seq,
                        format!("follows seq {p_seq}: the run is not contiguous"),
                    );
                }
                if prev_hash != p_hash {
                    v.find(seq, "its prev_hash is not the previous record's hash");
                }
            }
            None if seq == 1 && !prev_hash.is_empty() => {
                v.find(seq, "the genesis record carries a prev_hash");
            }
            None => {}
        }
        if seq == 0 {
            v.find(seq, "a record without a position");
        }
        // 2. Digest, under the recipe the record names (the body's, on a page that predates it).
        let recipe = record
            .get("recipe")
            .and_then(Value::as_str)
            .unwrap_or(body_recipe);
        match digest(record, recipe) {
            Ok(d) if d == hash => {}
            Ok(d) => v.find(seq, format!("its digest recomputes to {d}, not {hash}")),
            Err(e) => v.find(seq, format!("its digest cannot be taken: {e}")),
        }
        // 3. Signature, against the published key its key_id names.
        let key_id = record.get("key_id").and_then(Value::as_str).unwrap_or("");
        let signature = record.get("signature").and_then(Value::as_str);
        match (
            keys.iter().find(|(id, _)| id == key_id),
            signature.and_then(unhex),
        ) {
            (None, _) => v.find(seq, format!("its key_id {key_id:?} names no published key")),
            (_, None) => v.find(seq, "it carries no readable signature"),
            (Some((_, key)), Some(sig)) => {
                let mut preimage = SIGNATURE_DOMAIN.as_bytes().to_vec();
                preimage.push(0);
                preimage.extend_from_slice(hash.as_bytes());
                let pk = ring::signature::UnparsedPublicKey::new(&ring::signature::ED25519, key);
                if pk.verify(&preimage, &sig).is_ok() {
                    v.signatures += 1;
                } else {
                    v.find(
                        seq,
                        "its signature does not check against its published key",
                    );
                }
            }
        }
        prev = Some((seq, hash.to_string()));
    }
    // 5. The window's anchor names a head; where it falls inside the run, it must be that record.
    if let Some(anchor) = range.get("anchor").filter(|a| !a.is_null()) {
        check_head(&mut v, records, anchor, "anchor");
    }
    // 4. The tail: a window that stops short of min(to, head.seq) has lost records from its end.
    if let Some(head_body) = head {
        let head = head_body.get("head").unwrap_or(head_body);
        check_head(&mut v, records, head, "head");
        let head_seq = head.get("seq").and_then(Value::as_u64).unwrap_or(0);
        let to = range.get("to").and_then(Value::as_u64).unwrap_or(u64::MAX);
        let want = to.min(head_seq);
        let last = records
            .last()
            .and_then(|r| r.get("seq"))
            .and_then(Value::as_u64)
            .unwrap_or(0);
        let from = range.get("from").and_then(Value::as_u64).unwrap_or(1);
        if want >= from && last < want {
            v.find(
                0,
                format!("the run ends at seq {last} but the head says {want}: records are missing from its end"),
            );
        }
    }
    v
}

fn check_head(v: &mut Verdict, records: &[Value], head: &Value, which: &str) {
    let seq = head.get("seq").and_then(Value::as_u64).unwrap_or(0);
    let hash = head.get("hash").and_then(Value::as_str).unwrap_or("");
    let at = records
        .iter()
        .find(|r| r.get("seq").and_then(Value::as_u64) == Some(seq));
    if let Some(r) = at {
        if r.get("hash").and_then(Value::as_str) != Some(hash) {
            v.find(
                seq,
                format!("the {which} names a different hash for this position"),
            );
        }
    }
}

const USAGE: &str =
    "usage: cargo xtask audit-verify --range <range.json> --keys <keys.json> [--head <head.json>]";

fn read_json(path: &str) -> Result<Value, String> {
    let text = std::fs::read_to_string(path).map_err(|e| format!("{path}: {e}"))?;
    serde_json::from_str(&text).map_err(|e| format!("{path}: {e}"))
}

/// `cargo xtask audit-verify`. Exit 0 green, 1 a finding, 2 bad arguments, 3 an unreadable body.
#[must_use]
pub fn main(args: &[String]) -> i32 {
    let (mut range, mut keys, mut head) = (None, None, None);
    let mut it = args.iter();
    while let Some(flag) = it.next() {
        let slot = match flag.as_str() {
            "--range" => &mut range,
            "--keys" => &mut keys,
            "--head" => &mut head,
            _ => {
                eprintln!("audit-verify: unknown argument {flag:?}\n{USAGE}");
                return 2;
            }
        };
        let Some(path) = it.next() else {
            eprintln!("audit-verify: {flag} needs a file\n{USAGE}");
            return 2;
        };
        *slot = Some(path.clone());
    }
    let (Some(range), Some(keys)) = (range, keys) else {
        eprintln!("{USAGE}");
        return 2;
    };
    let read = |p: &str| {
        read_json(p).map_err(|e| {
            eprintln!("audit-verify: {e}");
            3
        })
    };
    let (range, keys) = match (read(&range), read(&keys)) {
        (Ok(r), Ok(k)) => (r, k),
        (Err(code), _) | (_, Err(code)) => return code,
    };
    let head = match head.as_deref().map(read).transpose() {
        Ok(h) => h,
        Err(code) => return code,
    };
    let verdict = verify(&range, &keys, head.as_ref());
    for f in &verdict.findings {
        println!("RED   {f}");
    }
    if verdict.green() {
        println!(
            "GREEN {} record(s), {} signature(s) checked by the published recipe pages",
            verdict.records, verdict.signatures
        );
        0
    } else {
        println!(
            "RED   {} finding(s) over {} record(s)",
            verdict.findings.len(),
            verdict.records
        );
        1
    }
}
