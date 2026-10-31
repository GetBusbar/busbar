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
use crate::abi::mechanism::KindCode;
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
    assert!(
        r.kind_tail.is_empty(),
        "a secret Statement states no tail facts"
    );
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

// ── THE KIND TAIL, RENDERED WHOLE (ARCHITECT ruling 2026-10-20, audit root#7 and loader#9) ───────

const STYLES: &[crate::abi::auth::StyleDecl] = &[
    crate::abi::auth::StyleDecl {
        name: abi_str("golden-style"),
        flags: 0,
        points: 1,
    },
    crate::abi::auth::StyleDecl {
        name: abi_str("second-style"),
        flags: crate::abi::auth::STYLE_NEEDS_HEADERS,
        points: 2,
    },
];
const CREDENTIAL_KINDS: &[AbiStr] = &[abi_str("golden-kind")];

/// An auth tail stating every field.
fn auth_tail() -> crate::abi::auth::AuthTail {
    use crate::abi::auth::{
        AuthTail, CAP_INBOUND, CAP_OUTBOUND, FACT_OPERATOR, FACT_READS_CREDENTIALS,
    };
    AuthTail {
        head: KindTailHead {
            size: core::mem::size_of::<AuthTail>() as u32,
            _reserved: 0,
        },
        caps: CAP_INBOUND | CAP_OUTBOUND,
        facts: FACT_OPERATOR | FACT_READS_CREDENTIALS,
        login_kind: 0,
        inbound_points: 1,
        styles: STYLES.as_ptr(),
        styles_len: STYLES.len(),
        operator_principal: abi_str("golden-operator"),
        credential_kinds: CREDENTIAL_KINDS.as_ptr(),
        credential_kinds_len: CREDENTIAL_KINDS.len(),
    }
}

/// The rendering of a Statement of `kind` whose tail is `t`.
fn with_tail<T>(kind: KindCode, t: &T) -> Result<Vec<u8>, RenderError> {
    let st = Statement {
        kind: kind as u32,
        kind_abi: kind.abi_version(),
        kind_tail: core::ptr::from_ref(t).cast::<KindTailHead>(),
        ..statement("tail-plugin", "1.0.0", 1)
    };
    // SAFETY: every list the Statement and `t` state is a `'static` array of its stated count, or
    // NULL with none (a NULL list with a count is bounded before it is read).
    unsafe { render(&st) }
}

/// A tail of `T`, all zero but its head, which states the whole of `T`.
fn zeroed_tail<T: Copy>() -> T {
    // SAFETY: every kind tail is `#[repr(C)]` plain data: all-zero bytes are a valid `T`.
    let mut t: T = unsafe { core::mem::zeroed() };
    // SAFETY: every kind tail leads with its `KindTailHead`.
    unsafe {
        core::ptr::from_mut(&mut t)
            .cast::<KindTailHead>()
            .write(KindTailHead {
                size: core::mem::size_of::<T>() as u32,
                _reserved: 0,
            });
    }
    t
}

#[test]
fn an_auth_tail_renders_whole_and_reads_back_with_no_library() {
    let b = with_tail(KindCode::Auth, &auth_tail()).expect("renders");
    let r = read(&b).expect("reads back");
    assert_eq!(
        r.kind_tail_size as usize,
        core::mem::size_of::<crate::abi::auth::AuthTail>()
    );
    let t = read_auth_tail(&r.kind_tail).expect("the auth tail reads back");
    assert_eq!(
        t,
        ReadAuthTail {
            caps: crate::abi::auth::CAP_INBOUND | crate::abi::auth::CAP_OUTBOUND,
            facts: crate::abi::auth::FACT_OPERATOR | crate::abi::auth::FACT_READS_CREDENTIALS,
            login_kind: 0,
            inbound_points: 1,
            styles: vec![
                ReadStyle {
                    name: "golden-style".into(),
                    flags: 0,
                    points: 1,
                },
                ReadStyle {
                    name: "second-style".into(),
                    flags: crate::abi::auth::STYLE_NEEDS_HEADERS,
                    points: 2,
                },
            ],
            operator_principal: "golden-operator".into(),
            credential_kinds: vec!["golden-kind".into()],
        }
    );
    // A truncated or padded tail is refused, never read short.
    assert!(read_auth_tail(&r.kind_tail[..r.kind_tail.len() - 1]).is_err());
    let mut padded = r.kind_tail.clone();
    padded.push(0);
    assert_eq!(read_auth_tail(&padded).unwrap_err().what, "the end");
}

#[test]
fn every_auth_tail_field_changes_the_bytes() {
    let base = with_tail(KindCode::Auth, &auth_tail()).expect("renders");
    let renamed: &[crate::abi::auth::StyleDecl] = &[
        crate::abi::auth::StyleDecl {
            name: abi_str("golden-stylf"),
            ..STYLES[0]
        },
        STYLES[1],
    ];
    let reflagged: &[crate::abi::auth::StyleDecl] = &[
        crate::abi::auth::StyleDecl {
            flags: crate::abi::auth::STYLE_CALLER_CREDENTIAL,
            ..STYLES[0]
        },
        STYLES[1],
    ];
    let repointed: &[crate::abi::auth::StyleDecl] = &[
        crate::abi::auth::StyleDecl {
            points: 3,
            ..STYLES[0]
        },
        STYLES[1],
    ];
    let other_kinds: &[AbiStr] = &[abi_str("golden-kinc")];
    let mut edits: Vec<(&str, crate::abi::auth::AuthTail)> = Vec::new();
    let mut push = |name: &'static str, f: &dyn Fn(&mut crate::abi::auth::AuthTail)| {
        let mut t = auth_tail();
        f(&mut t);
        edits.push((name, t));
    };
    push("caps", &|t| t.caps = crate::abi::auth::CAP_INBOUND);
    push("facts", &|t| {
        t.facts = crate::abi::auth::FACT_READS_CREDENTIALS
    });
    push("login_kind", &|t| t.login_kind = 1);
    push("inbound_points", &|t| t.inbound_points = 2);
    push("a style dropped", &|t| t.styles_len = 1);
    push("a style's name", &|t| t.styles = renamed.as_ptr());
    push("a style's flags", &|t| t.styles = reflagged.as_ptr());
    push("a style's points", &|t| t.styles = repointed.as_ptr());
    push("operator_principal", &|t| {
        t.operator_principal = abi_str("golden-operatos")
    });
    push("credential_kinds", &|t| {
        t.credential_kinds = other_kinds.as_ptr()
    });
    push("credential_kinds dropped", &|t| t.credential_kinds_len = 0);
    for (name, t) in &edits {
        let b = with_tail(KindCode::Auth, t).expect("renders");
        assert_ne!(b, base, "{name} did not change the rendering");
    }
}

#[test]
fn a_tail_renders_by_the_growth_rule() {
    // A plugin built when the auth tail froze states its frozen size: the fields appended after it
    // render absent, whatever bytes follow in its memory.
    let mut old = auth_tail();
    old.head.size = crate::abi::auth::TAIL_FROZEN as u32;
    let b = with_tail(KindCode::Auth, &old).expect("renders");
    let t = read_auth_tail(&read(&b).expect("reads back").kind_tail).expect("reads back");
    assert_eq!(t.operator_principal, "");
    assert!(t.credential_kinds.is_empty());
    assert_eq!(t.styles.len(), 2, "the frozen fields render whole");
}

#[test]
fn a_tail_list_or_string_out_of_bounds_is_refused_before_it_is_read() {
    use crate::abi::mechanism::check::{fault, Rule, STATEMENT_LIST_MAX};
    let mut t = auth_tail();
    t.styles = core::ptr::null();
    assert_eq!(
        with_tail(KindCode::Auth, &t),
        Err(RenderError::Tail(fault(Rule::NullWithCount, "auth.styles")))
    );
    let mut t = auth_tail();
    t.credential_kinds_len = STATEMENT_LIST_MAX + 1;
    assert_eq!(
        with_tail(KindCode::Auth, &t),
        Err(RenderError::Tail(fault(
            Rule::OverMax,
            "auth.credential_kinds"
        )))
    );
    let mut t = auth_tail();
    t.operator_principal = AbiStr {
        ptr: core::ptr::null(),
        len: 4,
    };
    assert_eq!(
        with_tail(KindCode::Auth, &t),
        Err(RenderError::Tail(fault(
            Rule::NullWithCount,
            "auth.operator_principal"
        )))
    );
}

#[test]
fn every_kind_renders_its_tail_facts_not_only_its_size() {
    use crate::abi::{export, hook, plane, store, transport};
    let differs = |kind: KindCode,
                   a: &dyn Fn() -> Result<Vec<u8>, RenderError>,
                   b: &dyn Fn() -> Result<Vec<u8>, RenderError>| {
        let (a, b) = (a().expect("renders"), b().expect("renders"));
        assert_ne!(a, b, "{kind:?}: a tail fact did not change the rendering");
    };
    let s0: store::StoreTail = zeroed_tail();
    let s1 = store::StoreTail {
        fork_refusal: 1,
        ..s0
    };
    differs(
        KindCode::Store,
        &|| with_tail(KindCode::Store, &s0),
        &|| with_tail(KindCode::Store, &s1),
    );
    let h0: hook::Tail = zeroed_tail();
    let h1 = hook::Tail {
        infallible: 1,
        ..h0
    };
    differs(KindCode::Hook, &|| with_tail(KindCode::Hook, &h0), &|| {
        with_tail(KindCode::Hook, &h1)
    });
    let streams: &[u8] = &[1, 2];
    let e0: export::Tail = zeroed_tail();
    let e1 = export::Tail {
        streams: streams.as_ptr(),
        streams_len: streams.len(),
        ..e0
    };
    differs(
        KindCode::Export,
        &|| with_tail(KindCode::Export, &e0),
        &|| with_tail(KindCode::Export, &e1),
    );
    let p0: plane::PlaneTail = zeroed_tail();
    let p1 = plane::PlaneTail {
        label: abi_str("golden label"),
        ..p0
    };
    differs(
        KindCode::Plane,
        &|| with_tail(KindCode::Plane, &p0),
        &|| with_tail(KindCode::Plane, &p1),
    );
    let t0: transport::TransportTail = zeroed_tail();
    let t1 = transport::TransportTail {
        frame_piece_size: 1,
        ..t0
    };
    differs(
        KindCode::Transport,
        &|| with_tail(KindCode::Transport, &t0),
        &|| with_tail(KindCode::Transport, &t1),
    );
}

/// A PLANE'S COMMAND-LINE HELP READS BACK FROM ITS RENDERING, with no library (audit busbar-src r4
/// S-2; BUSBAR-1.6.0.md l.2179, Part 2 #2: compiled in or dropped in, one loading path). The host
/// reads a dropped-in plane's `busbar --help` rows, its line-serve flag among them, off the signed
/// manifest before any configuration is served, as it reads a linked door's off its tail. Every
/// tail field rendered before the help is stated, so a reader that skipped one reads another field
/// as the help.
#[test]
fn a_plane_tails_cli_help_reads_back_with_no_library() {
    use crate::abi::plane::PlaneTail;
    const HELP: &str = "    --golden-serve      serve the golden plane on stdin/stdout";
    let p0: PlaneTail = zeroed_tail();
    let p = PlaneTail {
        flags: 1,
        ingress: 2,
        dispatch_shape: 3,
        answer_layout: 4,
        scope: abi_str("golden-scope"),
        label: abi_str("golden label"),
        subject_noun: abi_str("golden route"),
        admin_noun: abi_str("golden"),
        audit_kind: abi_str("golden_kind"),
        signing_domain: abi_str("golden-domain/v1"),
        signing_kid_prefix: abi_str("golden-kid-"),
        cli_help: abi_str(HELP),
        dialects: DIALECTS.as_ptr(),
        dialects_len: DIALECTS.len(),
        ..p0
    };
    let r = read(&with_tail(KindCode::Plane, &p).expect("renders")).expect("reads back");
    assert_eq!(
        read_plane_cli_help(&r.kind_tail).expect("the help reads back"),
        HELP
    );
    let r0 = read(&with_tail(KindCode::Plane, &p0).expect("renders")).expect("reads back");
    assert_eq!(
        read_plane_cli_help(&r0.kind_tail).expect("an absent help reads back"),
        "",
        "a plane that states no help reads back as none"
    );
    let end = r
        .kind_tail
        .windows(HELP.len())
        .position(|w| w == HELP.as_bytes())
        .expect("the help is in the tail's facts")
        + HELP.len();
    assert!(
        read_plane_cli_help(&r.kind_tail[..end - 1]).is_err(),
        "a tail cut inside its help is unreadable"
    );
    assert!(read_plane_cli_help(&[]).is_err(), "no tail states no help");
}

const DIALECTS: &[AbiStr] = &[abi_str("golden-dialect")];
