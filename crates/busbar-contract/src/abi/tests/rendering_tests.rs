// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE RENDERING'S PINS: a golden of one Statement carrying every field, and a RED arm per field —
//! a rendering that dropped, reordered or ignored a field would leave two different Statements
//! with the same bytes, and a manifest check built on it would pass a lying manifest.

use super::*;
use crate::abi::host::conn::connector::DIRECTION_OUTBOUND;
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
        from: abi_str("key_env"),
        to: abi_str("key.env"),
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
}];
const ANSWERS: &[AbiStr] = &[abi_str("status")];
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
    push("target_from", &|s| s.target_from = NONE);
    push("trust_from", &|s| s.trust_from = NONE);
    push("answers dropped", &|s| s.answers_len = 0);
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
            (REWRITE_KEY, "key_env".to_string(), "key.env".to_string()),
        ]
    );
    assert_eq!(r.sections, vec![("golden".to_string(), SECTION_DECLARING)]);
    assert_eq!(r.needs.len(), 1);
    assert_eq!(r.needs[0].target_from, "settings.url");
    assert_eq!(r.needs[0].details.bytes, b"{}");
    assert_eq!(r.target_from, "settings.url");
    assert_eq!(r.trust_from, "settings.ca");
    assert_eq!(r.answers, vec!["status".to_string()]);
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
