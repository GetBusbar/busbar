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

// ── an auth plugin's tail facts (Law 7: a dropped auth plugin is selected and listed unopened) ──

use crate::abi::auth::{
    ranked, AuthTail, StyleDecl, CAP_OUTBOUND, POINT_HEAD, STYLE_ENDPOINT_TOKEN_URL,
};

use super::{ReadAuth, ReadStyle, TAIL_AUTH};

const STYLES: &[StyleDecl] = &[
    StyleDecl {
        name: abi_str("first"),
        flags: ranked(1),
        points: POINT_HEAD,
    },
    StyleDecl {
        name: abi_str("second"),
        flags: STYLE_ENDPOINT_TOKEN_URL,
        points: POINT_HEAD,
    },
];

/// [`full`] as an AUTH plugin's Statement whose tail serves `styles` outbound (none: a tail that
/// states nothing).
fn auth(styles: &'static [StyleDecl]) -> Statement {
    // SAFETY: an auth tail is plain C data (integers, raw pointers, strings); all-zero is valid.
    let mut tail: AuthTail = unsafe { core::mem::zeroed() };
    tail.head = KindTailHead {
        size: core::mem::size_of::<AuthTail>() as u32,
        _reserved: 0,
    };
    if !styles.is_empty() {
        tail.caps = CAP_OUTBOUND;
        tail.styles = styles.as_ptr();
        tail.styles_len = styles.len();
    }
    let tail: &'static AuthTail = Box::leak(Box::new(tail));
    Statement {
        kind: crate::abi::mechanism::KindCode::Auth as u32,
        kind_tail: core::ptr::from_ref(tail).cast::<KindTailHead>(),
        ..full()
    }
}

/// The `auth` field's bytes, tag first.
fn auth_field(caps: u32, facts: u32, login: u32, styles: &[(&str, u32, u32)]) -> Vec<u8> {
    let mut b = Vec::new();
    for v in [TAIL_AUTH, caps, facts, login, 0, 0, 0] {
        b.extend_from_slice(&v.to_le_bytes());
    }
    b.extend_from_slice(&(styles.len() as u32).to_le_bytes());
    for (name, flags, points) in styles {
        b.extend_from_slice(&(name.len() as u32).to_le_bytes());
        b.extend_from_slice(name.as_bytes());
        b.extend_from_slice(&flags.to_le_bytes());
        b.extend_from_slice(&points.to_le_bytes());
    }
    b
}

const AUTH_GOLDEN: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/golden/statement-rendering-auth.golden"
);

/// THE THIRD GOLDEN: an auth plugin's tail facts render as the `auth` field after `claims`.
#[test]
fn an_auth_tail_renders_its_facts_after_the_claims() {
    let got = format!("{}\n", hex(&bytes(&auth(STYLES))));
    if std::env::var_os("BUSBAR_UPDATE_GOLDEN").is_some() {
        std::fs::write(AUTH_GOLDEN, &got).expect("write the golden");
    }
    let want = std::fs::read_to_string(AUTH_GOLDEN).expect(
        "the auth rendering golden exists; re-seed intentionally with BUSBAR_UPDATE_GOLDEN=1",
    );
    assert_eq!(got, want, "the auth tail rendering drifted from its golden");
}

/// THE ROUND TRIP, AND ABSENCE IS CANONICAL: the field reads back to exactly the facts the tail
/// states, and a tail stating nothing renders no field (its bytes are the stating one's less the
/// field), so every auth rendering signed before the field existed is unchanged.
#[test]
fn auth_facts_round_trip_and_a_silent_tail_renders_none() {
    let stating = bytes(&auth(STYLES));
    let silent = bytes(&auth(&[]));
    let field = auth_field(
        CAP_OUTBOUND,
        0,
        0,
        &[
            ("first", ranked(1), POINT_HEAD),
            ("second", STYLE_ENDPOINT_TOKEN_URL, POINT_HEAD),
        ],
    );
    assert_eq!([silent.as_slice(), field.as_slice()].concat(), stating);
    assert_eq!(read(&silent).expect("reads").auth, None);
    assert_eq!(
        read(&stating).expect("reads").auth,
        Some(ReadAuth {
            caps: CAP_OUTBOUND,
            styles: vec![
                ReadStyle {
                    name: "first".into(),
                    flags: ranked(1),
                    points: POINT_HEAD,
                },
                ReadStyle {
                    name: "second".into(),
                    flags: STYLE_ENDPOINT_TOKEN_URL,
                    points: POINT_HEAD,
                },
            ],
            ..ReadAuth::default()
        })
    );
}

/// THE `auth` FIELD IS CANONICAL (REDs): refused on another kind, all empty, with an unknown
/// capability, fact or login kind, or a style the contract refuses; a byte after it, or a tag out
/// of order, is refused at "the end".
#[test]
fn a_non_canonical_auth_field_is_unreadable() {
    let silent = bytes(&auth(&[]));
    let with = |f: Vec<u8>| [silent.as_slice(), f.as_slice()].concat();
    let ok = [("s", 0, POINT_HEAD)];
    for (why, field) in [
        ("all empty", auth_field(0, 0, 0, &[])),
        (
            "unknown capability",
            auth_field(CAP_OUTBOUND | 8, 0, 0, &ok),
        ),
        ("unknown fact", auth_field(CAP_OUTBOUND, 1 << 20, 0, &ok)),
        ("unknown login kind", auth_field(CAP_OUTBOUND, 0, 3, &ok)),
        (
            "a refused style",
            auth_field(CAP_OUTBOUND, 0, 0, &[("s", 1 << 24, POINT_HEAD)]),
        ),
    ] {
        assert_eq!(read(&with(field)).unwrap_err().what, "auth", "{why}");
    }
    let other = [
        bytes(&full()).as_slice(),
        auth_field(CAP_OUTBOUND, 0, 0, &ok).as_slice(),
    ]
    .concat();
    assert_eq!(read(&other).unwrap_err().what, "auth", "another kind");
    let mut trailing = bytes(&auth(STYLES));
    trailing.push(0);
    assert_eq!(read(&trailing).unwrap_err().what, "the end");
    let out_of_order = [
        bytes(&auth(STYLES)).as_slice(),
        &TAIL_CLAIM_FLAGS.to_le_bytes(),
    ]
    .concat();
    assert_eq!(read(&out_of_order).unwrap_err().what, "the end");
}
