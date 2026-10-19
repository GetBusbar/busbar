// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE RENDERING'S PINS: a golden of one Statement carrying every field, and a RED arm per field —
//! a rendering that dropped, reordered or ignored a field would leave two different Statements
//! with the same bytes, and a manifest check built on it would pass a lying manifest.

use super::*;
use crate::abi::host::conn::connector::{DIRECTION_OUTBOUND, KEEP_NAMED};
use crate::abi::mechanism::call::{BLOB_JSON, BLOB_OCTETS};
use crate::abi::mechanism::door::{
    KindTailHead, FAMILY_COUNTER, MARK_ONE_INSTANCE, MARK_WORD_HOOK, REWRITE_ALIAS, REWRITE_KEY,
    SECTION_DECLARING,
};
use crate::abi::sdk::door::{abi_str, statement};

const NONE: AbiStr = AbiStr {
    ptr: core::ptr::null(),
    len: 0,
};

const fn blob(b: &'static [u8], fmt: u32) -> Blob {
    Blob {
        ptr: b.as_ptr(),
        len: b.len(),
        fmt,
        flags: 0,
    }
}

const LABELS: &[AbiStr] = &[abi_str("reason")];
const FAMILIES: &[MetricFamily] = &[MetricFamily {
    name: abi_str("golden_total"),
    help: abi_str("golden help"),
    unit: NONE,
    label_keys: LABELS.as_ptr(),
    label_keys_len: 1,
    kind: FAMILY_COUNTER,
    _reserved: [0; 7],
}];
const DIAGS: &[AbiStr] = &[abi_str("golden.note")];
const REFS: &[AbiStr] = &[abi_str("password")];
const WORDS: &[MarkWord] = &[MarkWord {
    class: MARK_WORD_HOOK,
    _reserved: 0,
    word: abi_str("usage"),
}];
const REWRITES: &[Rewrite] = &[
    Rewrite {
        class: REWRITE_ALIAS,
        _reserved: 0,
        from: abi_str("old-name"),
        to: NONE,
    },
    Rewrite {
        class: REWRITE_KEY,
        _reserved: 0,
        from: abi_str("key_ref"),
        to: abi_str("key.ref"),
    },
];
const SECTIONS: &[Section] = &[Section {
    name: abi_str("golden"),
    flags: SECTION_DECLARING,
    _reserved: 0,
}];
const NEEDS: &[Need] = &[Need {
    direction: DIRECTION_OUTBOUND,
    egress_class: 1,
    transport: abi_str("https"),
    auth: abi_str("bearer"),
    target_from: abi_str("settings.url"),
    trust_from: NONE,
    details: blob(b"{}", BLOB_JSON),
    keep_response_headers: std::ptr::null(),
    keep_response_headers_len: 0,
    timeout_ms: 30_000,
    keep_mode: KEEP_NAMED,
    _reserved: 0,
    deny_response_headers: core::ptr::null(),
    deny_response_headers_len: 0,
}];
const ANSWERS: &[AbiStr] = &[abi_str("status")];
const CLAIMS: &[AbiStr] = &[abi_str("https"), abi_str("sse")];
const TAIL: &KindTailHead = &KindTailHead {
    size: 8,
    _reserved: 0,
};

/// One Statement carrying every field the rendering reads.
fn full() -> Statement {
    Statement {
        size: core::mem::size_of::<Statement>() as u32,
        kind: 2,
        kind_abi: 2,
        families: FAMILIES.as_ptr(),
        families_len: FAMILIES.len(),
        diag_ids: DIAGS.as_ptr(),
        diag_ids_len: DIAGS.len(),
        kind_tail: TAIL,
        extensions: blob(b"ext", BLOB_OCTETS),
        secret_refs: REFS.as_ptr(),
        secret_refs_len: REFS.len(),
        settings_schema: blob(b"{\"type\":\"object\"}", BLOB_JSON),
        marks: MARK_ONE_INSTANCE,
        mark_words: WORDS.as_ptr(),
        mark_words_len: WORDS.len(),
        rewrites: REWRITES.as_ptr(),
        rewrites_len: REWRITES.len(),
        sections: SECTIONS.as_ptr(),
        sections_len: SECTIONS.len(),
        needs: NEEDS.as_ptr(),
        needs_len: NEEDS.len(),
        target_from: abi_str("settings.url"),
        trust_from: abi_str("settings.ca"),
        answers: ANSWERS.as_ptr(),
        answers_len: ANSWERS.len(),
        claims: CLAIMS.as_ptr(),
        claims_len: CLAIMS.len(),
        ..statement("golden-plugin", "1.2.3", 7)
    }
}

fn bytes(st: &Statement) -> Vec<u8> {
    // SAFETY: every list above is a `'static` array of its stated count.
    unsafe { render(st) }.expect("renders")
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

const GOLDEN: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/golden/statement-rendering.golden"
);

#[test]
fn the_rendering_matches_its_golden() {
    let got = format!("{}\n", hex(&bytes(&full())));
    if std::env::var_os("BUSBAR_UPDATE_GOLDEN").is_some() {
        std::fs::write(GOLDEN, &got).expect("write the golden");
    }
    let want = std::fs::read_to_string(GOLDEN)
        .expect("the rendering golden exists; re-seed intentionally with BUSBAR_UPDATE_GOLDEN=1");
    assert_eq!(got, want, "the Statement rendering drifted from its golden");
}

#[test]
fn the_rendering_leads_with_its_magic_and_the_mechanism_version() {
    let b = bytes(&statement("p", "1", 1));
    assert_eq!(&b[..8], RENDERING_MAGIC);
    assert_eq!(b[8..12], MECHANISM_VERSION.to_le_bytes());
}

#[test]
fn every_field_changes_the_bytes() {
    let base = bytes(&full());
    let one_word: &[MarkWord] = &[MarkWord {
        word: abi_str("cheapest"),
        ..WORDS[0]
    }];
    let swapped: &[Rewrite] = &[REWRITES[1], REWRITES[0]];
    let other_timeout: &[Need] = &[Need {
        timeout_ms: 5_000,
        ..NEEDS[0]
    }];
    let mut edits: Vec<(&str, Statement)> = Vec::new();
    let mut push = |name: &'static str, f: &dyn Fn(&mut Statement)| {
        let mut st = full();
        f(&mut st);
        edits.push((name, st));
    };
    push("kind", &|s| s.kind = 3);
    push("kind_abi", &|s| s.kind_abi = 3);
    push("max_inflight", &|s| s.max_inflight = 8);
    push("name", &|s| s.name = abi_str("golden-plugim"));
    push("version", &|s| s.version = abi_str("1.2.4"));
    push("families dropped", &|s| s.families_len = 0);
    push("diag_ids dropped", &|s| s.diag_ids_len = 0);
    push("kind_tail dropped", &|s| s.kind_tail = core::ptr::null());
    push("extensions", &|s| s.extensions = blob(b"exu", BLOB_OCTETS));
    push("secret_refs dropped", &|s| s.secret_refs_len = 0);
    push("settings_schema fmt", &|s| {
        s.settings_schema.fmt = BLOB_OCTETS
    });
    push("marks", &|s| s.marks = 0);
    push("mark_words", &|s| s.mark_words = one_word.as_ptr());
    push("rewrites dropped", &|s| s.rewrites_len = 1);
    push("rewrites reordered", &|s| s.rewrites = swapped.as_ptr());
    push("sections dropped", &|s| s.sections_len = 0);
    push("needs dropped", &|s| s.needs_len = 0);
    push("need.timeout_ms", &|s| s.needs = other_timeout.as_ptr());
    push("target_from", &|s| s.target_from = NONE);
    push("trust_from", &|s| s.trust_from = NONE);
    push("answers dropped", &|s| s.answers_len = 0);
    push("a claim dropped", &|s| s.claims_len = 1);
    // Moving a string between two adjacent fields keeps every byte but the boundary: the length
    // prefixes are what tell them apart.
    push("name/version boundary", &|s| {
        s.name = abi_str("golden-plugin1");
        s.version = abi_str(".2.3");
    });
    for (name, st) in &edits {
        assert_ne!(bytes(st), base, "{name} did not change the rendering");
    }
}

#[test]
fn a_rendering_reads_back_to_every_fact_it_carries() {
    let r = read(&bytes(&full())).expect("reads back");
    assert_eq!(r.mechanism_version, MECHANISM_VERSION);
    assert_eq!((r.kind, r.kind_abi, r.max_inflight), (2, 2, 7));
    assert_eq!(
        (r.name.as_str(), r.version.as_str()),
        ("golden-plugin", "1.2.3")
    );
    assert_eq!(r.families.len(), 1);
    assert_eq!(r.families[0].label_keys, vec!["reason".to_string()]);
    assert_eq!(r.diag_ids, vec!["golden.note".to_string()]);
    assert_eq!(r.kind_tail_size, 8);
    assert_eq!(r.extensions.bytes, b"ext");
    assert_eq!(r.secret_refs, vec!["password".to_string()]);
    assert_eq!(r.settings_schema.fmt, BLOB_JSON);
    assert_eq!(r.marks, MARK_ONE_INSTANCE);
    assert_eq!(r.mark_words, vec![(MARK_WORD_HOOK, "usage".to_string())]);
    assert_eq!(
        r.rewrites,
        vec![
            (REWRITE_ALIAS, "old-name".to_string(), String::new()),
            (REWRITE_KEY, "key_ref".to_string(), "key.ref".to_string()),
        ]
    );
    assert_eq!(r.sections, vec![("golden".to_string(), SECTION_DECLARING)]);
    assert_eq!(r.needs.len(), 1);
    assert_eq!(r.needs[0].target_from, "settings.url");
    assert_eq!(r.needs[0].details.bytes, b"{}");
    assert_eq!(r.needs[0].timeout_ms, 30_000);
    assert_eq!(r.target_from, "settings.url");
    assert_eq!(r.trust_from, "settings.ca");
    assert_eq!(r.answers, vec!["status".to_string()]);
    assert_eq!(r.claims, vec!["https".to_string(), "sse".to_string()]);
}

#[test]
fn a_truncated_padded_or_foreign_rendering_is_unreadable() {
    let b = bytes(&full());
    for cut in [0, 7, 8, 20, b.len() / 2, b.len() - 1] {
        assert!(read(&b[..cut]).is_err(), "cut at {cut}");
    }
    let mut padded = b.clone();
    padded.push(0);
    assert_eq!(read(&padded).unwrap_err().what, "the end");
    let mut foreign = b.clone();
    foreign[0] = b'X';
    assert_eq!(read(&foreign).unwrap_err().what, "the magic");
    // A count no rest could hold is refused, never used to size an allocation.
    let mut huge = b[..RENDERING_MAGIC.len() + 16].to_vec();
    huge.extend_from_slice(&u32::MAX.to_le_bytes());
    assert!(read(&huge).is_err());
}

// ── a transport's claim-row flags (BUSBAR-1.6.0.md #50; Part 2 #2: linked and dropped judge alike) ──

use crate::abi::transport::{Claim, TransportTail, CLAIM_SECURE};

use super::TAIL_CLAIM_FLAGS;

const fn row(flags: u32) -> Claim {
    Claim {
        selector_forms: NONE,
        egress_selector_forms: NONE,
        facts: core::ptr::null(),
        facts_len: 0,
        status_namespace: NONE,
        session: 0,
        session_bound: 0,
        unit0_trigger: 0,
        status_at: 0,
        flags,
    }
}

/// One row per [`CLAIMS`] entry: the first secure, the second plaintext.
const SECURE_ROWS: &[Claim] = &[row(CLAIM_SECURE), row(0)];
/// The same rows stating nothing: every rendering signed before the field existed.
const PLAIN_ROWS: &[Claim] = &[row(0), row(0)];

/// [`full`] as a TRANSPORT's Statement whose tail states `rows`.
fn transport(rows: &'static [Claim]) -> Statement {
    // SAFETY: a transport tail is plain C data (integers, raw pointers); all-zero is valid.
    let mut tail: TransportTail = unsafe { core::mem::zeroed() };
    tail.head = KindTailHead {
        size: core::mem::size_of::<TransportTail>() as u32,
        _reserved: 0,
    };
    tail.claim_rows = rows.as_ptr();
    tail.claim_rows_len = rows.len();
    let tail: &'static TransportTail = Box::leak(Box::new(tail));
    Statement {
        kind: crate::abi::mechanism::KindCode::Transport as u32,
        kind_tail: core::ptr::from_ref(tail).cast::<KindTailHead>(),
        ..full()
    }
}

const SECURE_GOLDEN: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/golden/statement-rendering-secure.golden"
);

/// THE SECOND GOLDEN: a transport whose first claim row states `CLAIM_SECURE` renders the optional
/// `claim_flags` after `claims`, one `u32` per claim.
#[test]
fn a_secure_claim_renders_its_flags_after_the_claims() {
    let got = format!("{}\n", hex(&bytes(&transport(SECURE_ROWS))));
    if std::env::var_os("BUSBAR_UPDATE_GOLDEN").is_some() {
        std::fs::write(SECURE_GOLDEN, &got).expect("write the golden");
    }
    let want = std::fs::read_to_string(SECURE_GOLDEN).expect(
        "the secure rendering golden exists; re-seed intentionally with BUSBAR_UPDATE_GOLDEN=1",
    );
    assert_eq!(
        got, want,
        "the secure claim rendering drifted from its golden"
    );
}

/// A RENDERING SIGNED TODAY IS UNCHANGED: a transport whose rows state no flag renders no
/// `claim_flags` at all (absent is the one spelling of "every flag zero"), so its bytes are exactly
/// the secure one's less the field, and every signed manifest still matches its door.
#[test]
fn a_rendering_with_no_flag_is_byte_identical_to_the_one_signed_before_the_field() {
    let plain = bytes(&transport(PLAIN_ROWS));
    let secure = bytes(&transport(SECURE_ROWS));
    let field: Vec<u8> = [TAIL_CLAIM_FLAGS, 2, CLAIM_SECURE, 0]
        .iter()
        .flat_map(|v| v.to_le_bytes())
        .collect();
    assert_eq!([plain.as_slice(), field.as_slice()].concat(), secure);
    assert_eq!(read(&plain).expect("reads").claim_flags, vec![0, 0]);
}

/// THE ROUND TRIP: what renders reads back to the flags its rows state, and the read flags render
/// the same bytes again (the reader accepts exactly the renderer's one spelling).
#[test]
fn claim_flags_round_trip() {
    for rows in [SECURE_ROWS, PLAIN_ROWS] {
        let b = bytes(&transport(rows));
        let r = read(&b).expect("reads");
        assert_eq!(
            r.claim_flags,
            rows.iter().map(|c| c.flags).collect::<Vec<_>>()
        );
        let again: &'static [Claim] = Box::leak(
            r.claim_flags
                .iter()
                .map(|f| row(*f))
                .collect::<Vec<_>>()
                .into_boxed_slice(),
        );
        assert_eq!(bytes(&transport(again)), b);
    }
}

/// THE ENCODING IS CANONICAL (REDs): the optional tail is tagged fields in strictly ascending tag
/// order (one routine reads every optional field, the order fixed in one place). A present
/// `claim_flags` spelling "every flag zero", on another kind, of another count, or stating a bit but
/// `CLAIM_SECURE` is refused as `claim_flags`; an unknown tag, a tag not above the one before it,
/// and a byte that is no tag are refused at "the end". So no Statement has two signed byte forms.
#[test]
fn a_non_canonical_claim_flags_is_unreadable() {
    let field = |vals: &[u32]| -> Vec<u8> { vals.iter().flat_map(|v| v.to_le_bytes()).collect() };
    let plain = bytes(&transport(PLAIN_ROWS));
    let with = |vals: &[u32]| [plain.as_slice(), field(vals).as_slice()].concat();
    let t = TAIL_CLAIM_FLAGS;
    for vals in [
        vec![t, 2, 0, 0],
        vec![t, 1, CLAIM_SECURE],
        vec![t, 3, CLAIM_SECURE, 0, 0],
        vec![t, 2, 2, 0],
        vec![t, 2, CLAIM_SECURE | 4, 0],
    ] {
        assert_eq!(
            read(&with(&vals)).unwrap_err().what,
            "claim_flags",
            "{vals:?}"
        );
    }
    let secure = bytes(&transport(SECURE_ROWS));
    let mut trailing = secure.clone();
    trailing.push(0);
    assert_eq!(read(&trailing).unwrap_err().what, "the end");
    let again = [
        secure.as_slice(),
        field(&[t, 2, CLAIM_SECURE, 0]).as_slice(),
    ]
    .concat();
    assert_eq!(read(&again).unwrap_err().what, "the end", "a tag twice");
    assert_eq!(
        read(&with(&[99, 0])).unwrap_err().what,
        "the end",
        "an unknown tag"
    );
    // Another kind states no claim flags.
    let other = [
        bytes(&full()).as_slice(),
        field(&[t, 2, CLAIM_SECURE, 0]).as_slice(),
    ]
    .concat();
    assert_eq!(read(&other).unwrap_err().what, "claim_flags");
}

// ── the declares document (Part 2 #2: a compiled-in and a dropped-in copy state it alike) ──────────

use super::TAIL_DECLARES;

const DECLARES: &[u8] = br#"{"destinations":["path"]}"#;

/// `full()` with its declares document present.
fn declaring() -> Statement {
    Statement {
        declares: blob(DECLARES, BLOB_JSON),
        ..full()
    }
}

/// `words` as the little-endian bytes the rendering writes them in.
fn le(words: &[u32]) -> Vec<u8> {
    words.iter().flat_map(|v| v.to_le_bytes()).collect()
}

/// THE FIELD'S BYTES: a present declares document is its tag, then the blob (format, flags, length,
/// bytes), after everything else; an absent one writes nothing, so every rendering signed before the
/// field existed is byte-identical to its door's today (`full()`'s golden is unchanged).
#[test]
fn a_declares_document_renders_tagged_after_the_claims_and_absent_writes_nothing() {
    assert_eq!(
        full().declares.fmt,
        crate::abi::mechanism::call::BLOB_ABSENT
    );
    let want = [
        bytes(&full()).as_slice(),
        le(&[TAIL_DECLARES, BLOB_JSON, 0, DECLARES.len() as u32]).as_slice(),
        DECLARES,
    ]
    .concat();
    assert_eq!(bytes(&declaring()), want);
    assert_eq!(read(&bytes(&full())).expect("reads").declares, None);
}

/// THE ROUND TRIP: what renders reads back to the document, and the document read back renders the
/// same bytes again.
#[test]
fn declares_round_trip() {
    let b = bytes(&declaring());
    let r = read(&b).expect("reads");
    let d = r.declares.expect("present");
    assert_eq!(
        (d.fmt, d.flags, d.bytes.as_slice()),
        (BLOB_JSON, 0, DECLARES)
    );
    let again: &'static [u8] = Box::leak(d.bytes.into_boxed_slice());
    let st = Statement {
        declares: blob(again, BLOB_JSON),
        ..full()
    };
    assert_eq!(bytes(&st), b);
}

/// After the claim flags (tag 1): both present read back, in the one order.
#[test]
fn declares_follows_the_claim_flags() {
    let st = Statement {
        declares: blob(DECLARES, BLOB_JSON),
        ..transport(SECURE_ROWS)
    };
    let b = bytes(&st);
    let r = read(&b).expect("reads");
    assert_eq!(r.claim_flags, vec![CLAIM_SECURE, 0]);
    assert_eq!(r.declares.expect("present").bytes, DECLARES);
    let tail = [
        le(&[TAIL_CLAIM_FLAGS, 2, CLAIM_SECURE, 0]),
        le(&[TAIL_DECLARES, BLOB_JSON, 0, DECLARES.len() as u32]),
        DECLARES.to_vec(),
    ]
    .concat();
    assert!(b.ends_with(&tail));
}

/// THE ENCODING IS CANONICAL (REDs): a present declares document that is empty, of a format other
/// than JSON, or flagged is refused as `declares`; a second one, one written before the claim flags,
/// and a byte after it are refused at "the end".
#[test]
fn a_non_canonical_declares_is_unreadable() {
    let base = bytes(&full());
    let with = |words: &[u32], doc: &[u8]| [base.as_slice(), le(words).as_slice(), doc].concat();
    let n = DECLARES.len() as u32;
    for (words, doc) in [
        (vec![TAIL_DECLARES, BLOB_JSON, 0, 0], &b""[..]),
        (vec![TAIL_DECLARES, BLOB_OCTETS, 0, n], DECLARES),
        (vec![TAIL_DECLARES, 0, 0, n], DECLARES),
        (vec![TAIL_DECLARES, BLOB_JSON, 1, n], DECLARES),
    ] {
        assert_eq!(
            read(&with(&words, doc)).unwrap_err().what,
            "declares",
            "{words:?}"
        );
    }
    let present = bytes(&declaring());
    let mut trailing = present.clone();
    trailing.push(0);
    assert_eq!(read(&trailing).unwrap_err().what, "the end");
    let twice = [
        present.as_slice(),
        le(&[TAIL_DECLARES, BLOB_JSON, 0, n]).as_slice(),
        DECLARES,
    ]
    .concat();
    assert_eq!(read(&twice).unwrap_err().what, "the end", "a tag twice");
    let st = Statement {
        declares: blob(DECLARES, BLOB_JSON),
        ..transport(SECURE_ROWS)
    };
    let in_order = bytes(&st);
    let flags = le(&[TAIL_CLAIM_FLAGS, 2, CLAIM_SECURE, 0]);
    let at = in_order.len() - flags.len() - 16 - DECLARES.len();
    let declares_first = [
        &in_order[..at],
        &in_order[at + flags.len()..],
        flags.as_slice(),
    ]
    .concat();
    assert_eq!(
        read(&declares_first).unwrap_err().what,
        "the end",
        "declares before the claim flags"
    );
}
