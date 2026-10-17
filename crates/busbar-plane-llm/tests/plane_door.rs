// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The llm plane's door, its static half: a Statement and tail the contract accepts, the needs
//! the dialects' schemes call for, the settings it reads, and the counts it reports.

use busbar_contract::abi::mechanism::check::check_needs;
use busbar_contract::abi::plane::check::{check_refusal_statuses, check_sections, check_tail};
use busbar_contract::abi::plane::{TAIL_FALLBACK, TAIL_PROBES, UNITS_REPORTED};
use busbar_plane_llm::dialect::DIALECTS;
use busbar_plane_llm::exchange::reply::Units;
use busbar_plane_llm::plane_door::{
    claims, counts, read_settings, route_of, DENY_RESPONSE_HEADERS, EGRESS_STYLES, NEEDS,
    OPEN_CLASSES, STATEMENT, TAIL, VERSION,
};

#[test]
fn the_statement_names_the_crate_version() {
    assert_eq!(VERSION, env!("CARGO_PKG_VERSION"));
}

#[test]
fn the_tail_is_one_the_contract_accepts() {
    assert_eq!(check_tail(TAIL), Ok(()));
    // SAFETY: the Statement's sections are a `'static` list of `sections_len` entries.
    let sections =
        unsafe { std::slice::from_raw_parts(STATEMENT.sections, STATEMENT.sections_len) };
    assert_eq!(check_sections(sections), Ok(()));
    assert_eq!(
        check_refusal_statuses(
            &busbar_plane_llm::refusal::REFUSAL_STATUSES,
            TAIL.dialects_len as u64
        ),
        Ok(())
    );
    assert_eq!(TAIL.flags, TAIL_FALLBACK | TAIL_PROBES);
    assert_eq!(TAIL.dialects_len, DIALECTS.len());
    assert_eq!(TAIL.op_classes_len, 7);
    assert_eq!(
        TAIL.billable_classes_len, 20,
        "tokens in, out, cache read, cache write, the open classes, then the per-request fee unit"
    );
    // Every reported count's class (owner LEDGER-100), `search_units` first and in its own family.
    assert_eq!(
        OPEN_CLASSES,
        &[
            ("search_units", "units"),
            ("classifications", "count"),
            ("web_fetch_requests", "count"),
            ("unitemized_tokens", "count"),
            ("images", "count"),
            ("audio_ms", "duration"),
            ("guardrail_automated_reasoning_policies", "count"),
            ("guardrail_automated_reasoning_policy_units", "count"),
            ("guardrail_content_policy_image_units", "count"),
            ("guardrail_content_policy_units", "count"),
            ("guardrail_contextual_grounding_policy_units", "count"),
            ("guardrail_sensitive_information_policy_free_units", "count"),
            ("guardrail_sensitive_information_policy_units", "count"),
            ("guardrail_topic_policy_units", "count"),
            ("guardrail_word_policy_units", "count"),
        ]
    );
    // SAFETY: the tail's billable classes are a `'static` list of `billable_classes_len` entries.
    let stated =
        unsafe { std::slice::from_raw_parts(TAIL.billable_classes, TAIL.billable_classes_len) };
    for (k, (class, family)) in OPEN_CLASSES.iter().enumerate() {
        let b = &stated[4 + k];
        // SAFETY: each `AbiStr` names a `'static` string of `len` bytes.
        let (c, f) = unsafe {
            (
                std::slice::from_raw_parts(b.class.ptr, b.class.len),
                std::slice::from_raw_parts(b.family.ptr, b.family.len),
            )
        };
        assert_eq!(
            (c, f),
            (class.as_bytes(), family.as_bytes()),
            "tail class {}",
            4 + k
        );
    }
    // THE FEE UNIT (owner #77, money-B1): one per billable request, the last billable class.
    assert_eq!(TAIL.fee_units_len, 1);
    // SAFETY: the tail's `'static` fee-unit list of `fee_units_len` entries.
    let fee = unsafe { *TAIL.fee_units };
    // SAFETY: a `'static` str the door states (abi_str).
    let fee = unsafe { std::slice::from_raw_parts(fee.ptr, fee.len) };
    assert_eq!(fee, busbar_contract::plane::PER_REQUEST.as_bytes());
    assert_eq!(
        busbar_plane_llm::plane_door::FEE_CLASS_INDEX as usize,
        TAIL.billable_classes_len - 1
    );
}

/// ARCHITECT Q-L1-AUTH (A): every dialect states its default outbound style in the tail, and every
/// style a member may be bound under (each dialect's default, the provider `auth:` overrides) has
/// exactly one outbound need naming it.
#[test]
fn every_dialects_default_style_is_stated_and_every_style_has_its_one_outbound_need() {
    assert_eq!(check_needs(NEEDS), Ok(()));
    assert_eq!(STATEMENT.needs_len, NEEDS.len());
    assert_eq!(TAIL.dialect_auth_len, DIALECTS.len());
    for (i, d) in DIALECTS.iter().enumerate() {
        // SAFETY: the tail's `'static` dialect_auth list of `dialect_auth_len` entries.
        let stated = unsafe { *TAIL.dialect_auth.add(i) };
        assert_eq!(stated.dialect as usize, i);
        // SAFETY: a `'static` str the door states (abi_str).
        let style = unsafe { std::slice::from_raw_parts(stated.style.ptr, stated.style.len) };
        assert_eq!(style, d.egress_style.as_bytes(), "{}", d.name);
        assert_eq!(
            EGRESS_STYLES
                .iter()
                .filter(|s| **s == d.egress_style)
                .count(),
            1,
            "{}",
            d.name
        );
    }
    for style in [
        "api-key",
        "bearer",
        "jwt-bearer",
        "oauth-client-credentials",
    ] {
        assert!(EGRESS_STYLES.contains(&style), "{style}");
    }
    assert_eq!(NEEDS.len(), EGRESS_STYLES.len());
}

#[test]
fn the_settings_read_as_the_tables_and_a_broken_section_is_refused() {
    assert!(read_settings(b"").is_ok(), "an empty blob is no section");
    let one =
        br#"{"providers":{"ant":{"protocol":"anthropic","base_url":"https://anthropic.example"}},
        "models":{"claude":{"provider":"ant"}},"pools":{"p":{"members":["claude"]}}}"#;
    let shaping = read_settings(one).expect("a well-formed generation reads");
    assert!(shaping.lane("claude").is_some());
    assert!(read_settings(b"not json").is_err());
    assert!(read_settings(br#"{"providers":7}"#).is_err());
}

#[test]
fn counts_are_the_far_ends_tokens_in_the_tails_class_order_and_nothing_before_one_is_reported() {
    assert!(counts(&Units::default()).is_empty());
    let units = Units {
        tokens_in: 7,
        tokens_out: 3,
        cache_read: 2,
        cache_write: 1,
        ..Units::default()
    };
    let got: Vec<(u32, u64)> = counts(&units).iter().map(|u| (u.class, u.amount)).collect();
    assert_eq!(got, vec![(0, 7), (1, 3), (2, 2), (3, 1)]);
    assert!(counts(&units).iter().all(|u| u.source == UNITS_REPORTED));
}

/// The claim a POST on `path` meets: the exact claim on it, else the prefix claim with the longest
/// target whose subtree holds it (a claim's target and every path under it, at any depth).
fn claim_for(path: &str) -> busbar_contract::abi::sdk::publish::ClaimSpec {
    use busbar_contract::abi::plane::CLAIM_EXACT;
    let all = claims();
    let post = all.iter().filter(|c| c.verb == "POST");
    let exact = post
        .clone()
        .find(|c| c.flags & CLAIM_EXACT != 0 && c.target == path);
    let under = |c: &&busbar_contract::abi::sdk::publish::ClaimSpec| {
        let t = c.target.trim_end_matches('/');
        c.flags & CLAIM_EXACT == 0 && (path == c.target || path.starts_with(&format!("{t}/")))
    };
    exact
        .or_else(|| post.filter(under).max_by_key(|c| c.target.len()))
        .cloned()
        .unwrap_or_else(|| panic!("no claim takes POST {path}"))
}

fn dialect_of(claim: &busbar_contract::abi::sdk::publish::ClaimSpec) -> &'static str {
    DIALECTS[usize::from(claim.refusal_dialect)].name
}

/// THE PLANE STATES ITS PATHS AS CLAIMS (ARCHITECT Q-FL1, 2026-10-02): each dialect's own path is a
/// claim wearing the dialect its path shape names, the same rule a refusal renders by.
#[test]
fn every_dialects_path_is_a_claim_wearing_its_dialect() {
    use busbar_plane_llm::exchange::arrive::envelope_for;
    for path in [
        "/v1/messages",
        "/v1/chat/completions",
        "/v1/responses",
        "/v2/chat",
        "/v1beta/models/gemini-pro:generateContent",
        "/model/m/converse",
        "/model/m/converse-stream",
    ] {
        let claim = claim_for(path);
        assert_eq!(dialect_of(&claim), envelope_for(path), "POST {path}");
    }
}

/// THE PREVIOUS RELEASE'S FALLBACK IS A PREFIX CLAIM ON `/`, per verb, so a path no dialect names, at
/// any depth, still reaches the plane (`http.crosscut|unknown-path|bare` and `|openai-suffix`), and
/// a dialect path hit with another verb reaches `arrive`, which answers the dialect's 405.
#[test]
fn the_fallback_is_a_prefix_claim_on_the_root_for_every_verb() {
    use busbar_contract::abi::plane::{CLAIM_EXACT, CLAIM_OPEN};
    let all = claims();
    for verb in ["GET", "POST", "PUT", "PATCH", "DELETE"] {
        let root = all
            .iter()
            .find(|c| c.verb == verb && c.target == "/")
            .unwrap_or_else(|| panic!("no fallback claim for {verb}"));
        assert_eq!(root.flags & (CLAIM_EXACT | CLAIM_OPEN), 0, "{verb} /");
        assert_eq!(
            dialect_of(root),
            busbar_plane_llm::exchange::arrive::envelope_for("/"),
            "{verb} /"
        );
    }
    for path in ["/definitely/unknown", "/x/v1/chat/completions", "/whatever"] {
        assert_eq!(claim_for(path).target, "/", "POST {path}");
    }
    // No claim is open: every llm path takes a credential, as it did.
    assert!(all.iter().all(|c| c.flags & CLAIM_OPEN == 0));
    // Every claim arrives over the one transport the far ends are reached over, and is named.
    assert!(all
        .iter()
        .all(|c| !c.verb.is_empty() && c.target.starts_with('/') && c.carrier == "http"));
}

/// RED for the `$` G3 commit: an open count the far end reported reaches the kernel in its
/// declared class, beside or without token counts; before it, `counts()` dropped it.
#[test]
fn an_open_count_is_reported_in_its_declared_class_and_never_dropped() {
    let open = Units {
        open: std::collections::BTreeMap::from([("search_units".to_string(), 12)]),
        ..Units::default()
    };
    let got: Vec<(u32, u64, bool)> = counts(&open)
        .iter()
        .map(|u| (u.class, u.amount, u.source == UNITS_REPORTED))
        .collect();
    assert_eq!(got, vec![(4, 12, true)], "no token counts, one open count");
    let both = Units {
        tokens_in: 5,
        ..open.clone()
    };
    let classes: Vec<u32> = counts(&both).iter().map(|u| u.class).collect();
    assert_eq!(classes, vec![0, 1, 2, 3, 4]);
    let unknown = Units {
        open: std::collections::BTreeMap::from([("nothing_stated".to_string(), 3)]),
        ..Units::default()
    };
    assert!(
        counts(&unknown).is_empty(),
        "a class the plane does not state is warned, never counted under another class"
    );
}

/// RED for the keep mode: every need relays the far end's whole head but the governed fields, and
/// the deny list is exactly every dialect's governed response fields, each once.
#[test]
fn every_need_keeps_all_but_every_dialects_governed_response_fields() {
    use busbar_contract::abi::host::conn::connector::KEEP_ALL_EXCEPT_DENIED;
    let mut governed: Vec<&str> = DIALECTS
        .iter()
        .flat_map(|d| d.governed_response_headers.iter().copied())
        .collect();
    governed.sort_unstable();
    governed.dedup();
    let mut denied = DENY_RESPONSE_HEADERS.to_vec();
    denied.sort_unstable();
    assert_eq!(denied, governed);
    for n in NEEDS {
        assert_eq!(n.keep_mode, KEEP_ALL_EXCEPT_DENIED);
        assert_eq!(n.keep_response_headers_len, 0);
        assert_eq!(n.deny_response_headers_len, DENY_RESPONSE_HEADERS.len());
    }
}

/// RED (F2, ARCHITECT 2026-10-02 option B): no dialect's tenant- or credential-derived response
/// field crosses to the plane through any need, read from the need itself through the contract's one
/// crossing rule; every other upstream field does (the S-16 register entry's premise).
#[test]
fn red_no_dialects_governed_response_field_leaks_through_a_need() {
    use busbar_contract::abi::host::conn::connector::keeps_response_field;
    let none: [&[u8]; 0] = [];
    for n in NEEDS {
        let denied: Vec<&str> = if n.deny_response_headers_len == 0 {
            Vec::new()
        } else {
            // SAFETY: the door's `'static` deny list of `deny_response_headers_len` strings.
            let list = unsafe {
                std::slice::from_raw_parts(n.deny_response_headers, n.deny_response_headers_len)
            };
            list.iter()
                .map(|s| {
                    // SAFETY: each entry is a `'static` str the door states (abi_str).
                    let bytes = unsafe { std::slice::from_raw_parts(s.ptr, s.len) };
                    std::str::from_utf8(bytes).expect("a field name is UTF-8")
                })
                .collect()
        };
        for d in DIALECTS {
            for governed in d.governed_response_headers {
                assert!(
                    !keeps_response_field(n.keep_mode, &[], &denied, governed, none),
                    "{} leaks `{governed}`",
                    d.name
                );
            }
        }
        for relayed in [
            "request-id",
            "x-amzn-requestid",
            "x-ratelimit-remaining-requests",
            "set-cookie",
        ] {
            assert!(
                keeps_response_field(n.keep_mode, &[], &denied, relayed, none),
                "`{relayed}` is the upstream's and crosses (F2)"
            );
        }
    }
}

/// THE ROUTE AN ARRIVAL NAMES (ARCHITECT Q-SW6 / Q-FL3, 2026-10-02): its model, verbatim, as a pool
/// when the plane's `pools` names it, else as a direct entry, the previous release's order (a pool
/// first, then a configured model). A model that is neither is still named, as a direct entry the
/// kernel does not hold, so the kernel refuses it (`no_destination`, 1.5.5's 404).
#[test]
fn an_arrival_routes_over_its_model_a_pool_first_then_a_direct_entry() {
    use busbar_contract::abi::plane::{ROUTE_DIRECT, ROUTE_POOL};
    let shaping = read_settings(
        br#"{"providers":{"ant":{"protocol":"anthropic","base_url":"https://anthropic.example"}},
        "models":{"claude":{"provider":"ant"},"both":{"provider":"ant"}},
        "pools":{"p":{"members":["claude"]},"both":{"members":["claude"]}}}"#,
    )
    .expect("a well-formed generation reads");
    assert_eq!(route_of(&shaping, "p"), (ROUTE_POOL, "p"));
    assert_eq!(route_of(&shaping, "claude"), (ROUTE_DIRECT, "claude"));
    assert_eq!(route_of(&shaping, "both"), (ROUTE_POOL, "both"));
    assert_eq!(route_of(&shaping, "nope"), (ROUTE_DIRECT, "nope"));
}

/// THE STICKY-ROUTING KEY (ARCHITECT Q1 ArriveOut, 2026-10-05), as 1.5.5 derived it: the pool's
/// `affinity.header_name` (else `x-session-id`), matched case-blind, wins over chat's non-empty body
/// `system`; a header value that is not text is no key; neither is no affinity.
#[test]
fn the_sticky_key_is_the_pools_header_else_the_chat_bodys_system() {
    use busbar_plane_llm::plane_door::affinity_key;
    let shaping = read_settings(
        br#"{"providers":{"ant":{"protocol":"anthropic","base_url":"https://anthropic.example"}},
        "models":{"claude":{"provider":"ant"}},
        "pools":{"p":{"members":["claude"]},
                 "u":{"members":["claude"],"affinity":{"mode":"session","header_name":"x-user-id"}}}}"#,
    )
    .expect("a well-formed generation reads");
    assert_eq!(shaping.affinity_header("p"), "x-session-id");
    assert_eq!(shaping.affinity_header("u"), "x-user-id");
    let chat = busbar_plane_llm::codec::DECLS
        .iter()
        .find(|d| d.name == "anthropic")
        .and_then(|d| d.handler)
        .and_then(|h| h.operation_handler(busbar_contract::operation::OpVerb::CHAT));
    let body = serde_json::json!({"model": "p", "system": "be brief", "messages": []});
    let session: &[(&[u8], &[u8])] = &[(b"X-Session-Id", b"s-1")];
    assert_eq!(
        affinity_key("x-session-id", session, chat, Some(&body)),
        Some("s-1".to_string())
    );
    assert_eq!(
        affinity_key("x-user-id", session, chat, Some(&body)),
        Some("be brief".to_string()),
        "another pool's header is not this pool's"
    );
    let unreadable: &[(&[u8], &[u8])] = &[(b"x-session-id", b"s\x01")];
    assert_eq!(
        affinity_key("x-session-id", unreadable, chat, Some(&body)),
        Some("be brief".to_string())
    );
    let plain = serde_json::json!({"model": "p", "system": "", "messages": []});
    assert_eq!(affinity_key("x-session-id", &[], chat, Some(&plain)), None);
    assert_eq!(affinity_key("x-session-id", &[], None, Some(&body)), None);
}

/// EVERY DECLARED OPEN CLASS REACHES THE DURABLE BOOK (owner LEDGER-100): one count of each open
/// class becomes exactly one reported `UnitCount` at that class's index in the tail, so no reported
/// count is dropped with the "class the plane does not state" WARN.
#[test]
fn every_open_class_becomes_one_reported_count_at_its_tail_index() {
    use busbar_contract::abi::plane::UNITS_REPORTED;
    for (k, (class, _)) in OPEN_CLASSES.iter().enumerate() {
        let units = busbar_plane_llm::exchange::reply::Units {
            open: std::collections::BTreeMap::from([(class.to_string(), 7)]),
            ..Default::default()
        };
        let out = counts(&units);
        assert_eq!(out.len(), 1, "{class}: {out:?}");
        assert_eq!(
            (out[0].class, out[0].source, out[0].amount),
            (u32::try_from(4 + k).expect("small"), UNITS_REPORTED, 7),
            "{class}"
        );
    }
}

// ── F25 REHOME: the registry facts and the plane's published identity (coverage map v2) ──────────

/// The declaration of the dialect named `name`, from the one table the plane serves through.
fn decl_named(name: &str) -> Option<&'static busbar_contract::protocol::ProtocolDecl> {
    busbar_plane_llm::codec::DECLS
        .iter()
        .copied()
        .find(|d| d.name == name)
}

/// The six dialects 1.5.5 shipped, by the names its registry keyed them under.
const SHIPPED_DIALECTS: [&str; 6] = [
    "openai",
    "anthropic",
    "gemini",
    "bedrock",
    "cohere",
    "responses",
];

/// LEGACY `crates/busbar-llm/src/engine/tests/dialect_registry_facts_tests.rs::registry_resolves_openai_and_its_moderation_handler`
/// (coverage map v2 row 98). 1.5.5: the openai registration resolves a handler whose protocol name
/// is its own and which serves the moderation operation; a protocol nobody registered resolves to
/// nothing.
///
/// RED: the openai declaration loses its handler or its moderation cell, its handler answers to
/// another protocol's name, or an unknown name resolves to some declaration.
#[test]
fn registry_resolves_openai_and_its_moderation_handler() {
    use busbar_contract::operation::OpVerb;
    let handler = decl_named("openai")
        .and_then(|d| d.handler)
        .expect("the shipped protocol's handler is registered");
    assert_eq!(handler.protocol_name(), "openai");
    assert!(handler.operation_handler(OpVerb::MODERATION).is_some());
    assert!(
        decl_named("zzz-unknown").is_none(),
        "unknown protocol -> None"
    );
}

/// LEGACY `crates/busbar-llm/src/engine/tests/dialect_registry_facts_tests.rs::every_protocol_serves_chat_via_its_request_handler`
/// (coverage map v2 row 99). 1.5.5: chat is reached through the same registry as every other
/// operation, and all six shipped protocols resolve a handler with a chat operation handler.
///
/// RED: any of the six dialects stops resolving a handler, or its handler stops serving chat.
#[test]
fn every_protocol_serves_chat_via_its_request_handler() {
    use busbar_contract::operation::OpVerb;
    for proto in SHIPPED_DIALECTS {
        let handler = decl_named(proto)
            .and_then(|d| d.handler)
            .unwrap_or_else(|| panic!("{proto}: protocol registered"));
        assert_eq!(handler.protocol_name(), proto);
        assert!(
            handler.operation_handler(OpVerb::CHAT).is_some(),
            "{proto} must serve chat via operation_handler(Chat)"
        );
    }
    let mut stated: Vec<&str> = DIALECTS.iter().map(|d| d.name).collect();
    stated.sort_unstable();
    let mut shipped = SHIPPED_DIALECTS.to_vec();
    shipped.sort_unstable();
    assert_eq!(
        stated, shipped,
        "the plane states exactly the six shipped dialects"
    );
}

/// LEGACY `crates/busbar-llm/src/engine/tests/dialect_registry_facts_tests.rs::chat_declares_its_capabilities`
/// (coverage map v2 row 100). 1.5.5: the chat cell as production resolves it (openai, chat) streams,
/// taps usage from a non-stream body, reads the body's `stream` boolean as the caller's intent, and
/// takes a non-empty top-level `system` as its body affinity key (an empty one is no key).
///
/// RED: chat stops streaming, stops tapping non-stream usage, misreads the stream flag, or derives
/// an affinity key from an empty `system` (or none from a non-empty one).
#[test]
fn chat_declares_its_capabilities() {
    use busbar_contract::operation::OpVerb;
    let chat = decl_named("openai")
        .and_then(|d| d.handler)
        .and_then(|h| h.operation_handler(OpVerb::CHAT))
        .expect("the shipped protocol serves chat");
    assert!(chat.streaming(), "chat streams");
    assert!(chat.taps_usage(), "chat bills tokens from the body");
    assert!(
        chat.wants_stream(&serde_json::json!({"stream": true})),
        "chat reads the stream boolean"
    );
    assert!(!chat.wants_stream(&serde_json::json!({})));
    assert!(!chat.wants_stream(&serde_json::json!({"stream": false})));
    assert_eq!(
        chat.body_affinity_key(&serde_json::json!({"system": "you are helpful"})),
        Some("you are helpful")
    );
    assert_eq!(
        chat.body_affinity_key(&serde_json::json!({"system": ""})),
        None
    );
}

/// LEGACY `crates/busbar-llm/src/engine/tests/ingress_integration_tests.rs::test_affinity_header_session_mode_without_name_uses_default`
/// (coverage map v2 row 375). 1.5.5: a pool whose `affinity` is `mode: session` with no
/// `header_name` keys its sticky routing on `x-session-id`.
///
/// RED: a session-mode pool with no header name reads another header (or none), so a client's
/// `x-session-id` stops pinning its session.
#[test]
fn test_affinity_header_session_mode_without_name_uses_default() {
    use busbar_plane_llm::plane_door::affinity_key;
    let shaping = read_settings(
        br#"{"providers":{"ant":{"protocol":"anthropic","base_url":"https://anthropic.example"}},
        "models":{"claude":{"provider":"ant"}},
        "pools":{"p":{"members":["claude"],"affinity":{"mode":"session"}}}}"#,
    )
    .expect("a session-mode pool with no header name reads");
    assert_eq!(shaping.affinity_header("p"), "x-session-id");
    let session: &[(&[u8], &[u8])] = &[(b"x-session-id", b"s-7")];
    assert_eq!(
        affinity_key(shaping.affinity_header("p"), session, None, None),
        Some("s-7".to_string()),
        "the default header is the one the pool keys on"
    );
}

/// A `'static` string the door states, as its bytes.
fn abi_text(s: busbar_contract::abi::mechanism::call::AbiStr) -> &'static [u8] {
    // SAFETY: every `AbiStr` the door states names a `'static` string of `len` bytes.
    unsafe { std::slice::from_raw_parts(s.ptr, s.len) }
}

/// LEGACY `crates/busbar-llm/src/tests/plane_decl_identity_tests.rs::the_plane_declares_its_published_key_and_is_the_fallback`
/// (coverage map v2 row 643). 1.5.5: the plane's operator-visible identity, as literals: the key
/// every metric, log and record carries is `llm`, it is the one fallback catch-all, its config
/// section is `pools`, and a grant on it names a `pool`.
///
/// RED: the published key, the fallback flag, the declaring section or the scope kind moves.
#[test]
fn the_plane_declares_its_published_key_and_is_the_fallback() {
    use busbar_contract::abi::mechanism::door::SECTION_DECLARING;
    assert_eq!(abi_text(STATEMENT.name), b"llm");
    assert_ne!(
        TAIL.flags & TAIL_FALLBACK,
        0,
        "the fallback catch-all every unclaimed path falls through to"
    );
    assert_eq!(abi_text(TAIL.scope), b"pools");
    // SAFETY: the Statement's sections are a `'static` list of `sections_len` entries.
    let sections =
        unsafe { std::slice::from_raw_parts(STATEMENT.sections, STATEMENT.sections_len) };
    let declaring: Vec<&[u8]> = sections
        .iter()
        .filter(|s| s.flags & SECTION_DECLARING != 0)
        .map(|s| abi_text(s.name))
        .collect();
    assert_eq!(declaring, vec![b"pools".as_slice()]);
    // SAFETY: the tail's `'static` scope-kind list of `scope_kinds_len` entries.
    let kinds = unsafe { std::slice::from_raw_parts(TAIL.scope_kinds, TAIL.scope_kinds_len) };
    let kinds: Vec<&[u8]> = kinds.iter().map(|k| abi_text(*k)).collect();
    assert_eq!(kinds, vec![b"pool".as_slice()]);
}
