//! `cargo xtask audit-verify` (#82(c), TODO 597): the verifier reproduces the chains the published
//! recipe pages carry, from the pages alone, and every kind of tamper the page names turns it red.

use serde_json::{json, Value};
use xtask::audit_verify::{
    digest, fields_of, is_small_order, key_id_of, verify, SIGNATURE_DOMAIN, SMALL_ORDER, V4_FIELDS,
};

/// The RFC 8032 test seed the v4 page's worked example is sealed with.
const RFC8032_SEED: &str = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60";

fn page(version: u8) -> String {
    let path = format!(
        "{}/../docs/audit-chain-digest-v{version}.md",
        env!("CARGO_MANIFEST_DIR")
    );
    std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{path}: {e}"))
}

/// The ```json block under the worked example's own heading line for `read` (a line that is only
/// "`GET /api/v1/admin/audit/<read>...`:"), never the reads table above it.
fn example(version: u8, read: &str) -> Value {
    let text = page(version);
    let lead = format!("`GET /api/v1/admin/audit/{read}");
    let at = text
        .match_indices('\n')
        .map(|(i, _)| i + 1)
        .find(|&i| {
            let line = text[i..].lines().next().unwrap_or("");
            line.starts_with(&lead) && line.ends_with("`:")
        })
        .unwrap_or_else(|| panic!("the v{version} page shows no {read} body"));
    let rest = &text[at..];
    let open = rest.find("```json\n").expect("a json block") + "```json\n".len();
    let close = rest[open..].find("```").expect("a closed block") + open;
    serde_json::from_str(&rest[open..close]).expect("the page's body is JSON")
}

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

fn hexs(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn red_with(range: &Value, keys: &Value, head: Option<&Value>, needle: &str) {
    let v = verify(range, keys, head);
    assert!(!v.green(), "expected RED containing {needle:?}, got GREEN");
    assert!(
        v.findings.iter().any(|f| f.to_string().contains(needle)),
        "no finding names {needle:?}: {:?}",
        v.findings
    );
}

#[test]
fn the_v4_pages_worked_example_verifies_with_its_signature_and_head() {
    let (range, keys, head) = (example(4, "range"), example(4, "keys"), example(4, "head"));
    let v = verify(&range, &keys, Some(&head));
    assert!(v.green(), "{:?}", v.findings);
    assert_eq!((v.records, v.signatures), (1, 1));
}

#[test]
fn the_kept_v3_and_v2_pages_examples_verify_by_their_own_recipes() {
    for version in [3, 2] {
        let v = verify(&example(version, "range"), &example(version, "keys"), None);
        assert!(v.green(), "v{version}: {:?}", v.findings);
        assert_eq!(v.signatures, 1, "v{version}");
    }
}

#[test]
fn the_recipes_differ_from_v4_exactly_as_their_pages_say() {
    let v4: Vec<_> = fields_of("busbar.audit.digest.v4").unwrap();
    let v3: Vec<_> = fields_of("busbar.audit.digest.v3").unwrap();
    let v2: Vec<_> = fields_of("busbar.audit.digest.v2").unwrap();
    assert_eq!(v4.len(), V4_FIELDS.len());
    assert_eq!(v3.len() + 2, v4.len());
    assert!(!v3.iter().any(|(n, _)| *n == "incarnation" || *n == "node"));
    let mono = v4.iter().position(|(n, _)| *n == "mono").unwrap();
    assert_eq!(v4[mono + 1], ("node", xtask::audit_verify::Kind::Num));
    let fee = v2.iter().position(|(n, _)| *n == "fee_count").unwrap();
    assert_eq!(v2[fee + 1].0, "currency");
    assert_eq!(v2.len(), v3.len() + 1);
    assert!(fields_of("busbar.audit.digest.v1").is_none());
}

#[test]
fn an_edited_field_is_a_digest_mismatch() {
    let (mut range, keys) = (example(4, "range"), example(4, "keys"));
    range["records"][0]["op_class"] = json!("chat.completions");
    red_with(&range, &keys, None, "its digest recomputes to");
}

#[test]
fn a_number_published_as_text_is_refused_not_coerced() {
    let (mut range, keys) = (example(4, "range"), example(4, "keys"));
    range["records"][0]["tier_bp"] = json!("9000");
    red_with(&range, &keys, None, "`tier_bp`: a number field carries");
}

#[test]
fn a_record_relabelled_to_another_recipe_no_longer_digests() {
    let (mut range, keys) = (example(4, "range"), example(4, "keys"));
    range["records"][0]["recipe"] = json!("busbar.audit.digest.v3");
    red_with(&range, &keys, None, "its digest recomputes to");
    range["records"][0]["recipe"] = json!("busbar.audit.digest.v9");
    red_with(&range, &keys, None, "unknown recipe");
}

#[test]
fn a_flipped_signature_byte_is_refused() {
    let (mut range, keys) = (example(4, "range"), example(4, "keys"));
    let sig = range["records"][0]["signature"]
        .as_str()
        .unwrap()
        .to_string();
    let flipped = format!("{}{}", if &sig[..1] == "0" { "1" } else { "0" }, &sig[1..]);
    range["records"][0]["signature"] = json!(flipped);
    red_with(&range, &keys, None, "its signature does not check");
}

#[test]
fn a_key_set_whose_key_id_is_not_its_derivation_is_refused() {
    let (range, mut keys) = (example(4, "range"), example(4, "keys"));
    keys["keys"][0]["key_id"] = json!("0000000000000000");
    red_with(&range, &keys, None, "is not the derivation of its key");
    red_with(&range, &keys, None, "names no published key");
}

#[test]
fn a_small_order_key_is_refused_even_with_a_matching_id() {
    let (range, mut keys) = (example(4, "range"), example(4, "keys"));
    let identity = unhex(SMALL_ORDER[1]);
    keys["keys"][0]["public_key"] = json!(hexs(&identity));
    keys["keys"][0]["key_id"] = json!(key_id_of(&identity));
    red_with(&range, &keys, None, "small-order point");
}

#[test]
fn a_window_short_of_the_head_has_lost_its_tail() {
    let (mut range, keys, mut head) = (example(4, "range"), example(4, "keys"), example(4, "head"));
    range["to"] = json!(2);
    head["head"]["seq"] = json!(2);
    red_with(
        &range,
        &keys,
        Some(&head),
        "records are missing from its end",
    );
}

#[test]
fn an_empty_run_verifies() {
    let (mut range, keys) = (example(4, "range"), example(4, "keys"));
    range["records"] = json!([]);
    range["anchor"] = Value::Null;
    let v = verify(&range, &keys, None);
    assert!(v.green(), "{:?}", v.findings);
    assert_eq!(v.records, 0);
}

/// A second record sealed onto the page's example with the page's own RFC 8032 key: the run links,
/// and breaking the link or the numbering turns it red.
#[test]
fn a_two_record_run_links_and_a_broken_link_or_gap_is_red() {
    let (mut range, keys) = (example(4, "range"), example(4, "keys"));
    let pair = ring::signature::Ed25519KeyPair::from_seed_unchecked(&unhex(RFC8032_SEED)).unwrap();
    let first = range["records"][0].clone();
    let mut second = first.clone();
    second["seq"] = json!(2);
    second["prev_hash"] = first["hash"].clone();
    second["op_class"] = json!("embeddings");
    let reseal = |r: &mut Value| {
        let d = digest(r, "busbar.audit.digest.v4").unwrap();
        let mut pre = SIGNATURE_DOMAIN.as_bytes().to_vec();
        pre.push(0);
        pre.extend_from_slice(d.as_bytes());
        r["hash"] = json!(d);
        r["signature"] = json!(hexs(pair.sign(&pre).as_ref()));
    };
    reseal(&mut second);
    range["records"] = json!([first.clone(), second.clone()]);
    range["to"] = json!(2);
    let v = verify(&range, &keys, None);
    assert!(v.green(), "{:?}", v.findings);
    assert_eq!(v.signatures, 2);

    let mut unlinked = second.clone();
    unlinked["prev_hash"] = json!("00".repeat(32));
    reseal(&mut unlinked);
    range["records"] = json!([first.clone(), unlinked]);
    red_with(
        &range,
        &keys,
        None,
        "prev_hash is not the previous record's hash",
    );

    let mut gapped = second;
    gapped["seq"] = json!(3);
    reseal(&mut gapped);
    range["records"] = json!([first, gapped]);
    red_with(&range, &keys, None, "not contiguous");
}

/// The small-order table, checked against an independent curve implementation: every entry, with
/// either sign bit, either does not decompress or is a weak key; the page's key is not.
#[test]
fn the_small_order_table_is_what_an_independent_curve_calls_weak() {
    for h in SMALL_ORDER {
        for sign in [0u8, 0x80] {
            let mut b: [u8; 32] = unhex(h).try_into().unwrap();
            b[31] = (b[31] & 0x7f) | sign;
            assert!(is_small_order(&b), "{h} sign {sign}");
            if let Ok(k) = ed25519_dalek::VerifyingKey::from_bytes(&b) {
                assert!(
                    k.is_weak(),
                    "{} decompresses to a key that is not weak",
                    hexs(&b)
                );
            }
        }
    }
    let keys = example(4, "keys");
    let page_key: [u8; 32] = unhex(keys["keys"][0]["public_key"].as_str().unwrap())
        .try_into()
        .unwrap();
    assert!(!is_small_order(&page_key));
    assert!(!ed25519_dalek::VerifyingKey::from_bytes(&page_key)
        .unwrap()
        .is_weak());
}
