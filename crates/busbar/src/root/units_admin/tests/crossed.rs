// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE RENDERERS, PROVED AGAINST THE SERIALIZER THEY REPLACED.
//!
//! The composition-level tests beside this file ask the whole composition a question and compare the
//! answer byte for byte, which is the right shape for "who answers, and does it answer the same
//! thing". It is the wrong shape for two claims this cut has to make, because neither of them is
//! about one node's answer:
//!
//! 1. A `f64` has many decimal spellings and only one of them is the byte a client pinned. A fixture
//!    can pin the spelling of the latency its own lanes happen to report; it cannot pin the spelling
//!    of every latency a lane could report, and "shortest round-trip" is not a byte.
//! 2. Nine of the plugin row's fifteen fields are OMITTED when absent rather than written as `null`.
//!    A fixture whose rows have no artifact behind them exercises only the omitting, and the whole
//!    risk is on the other side: a row that grew a `"version":null` where a client had been reading
//!    no key at all.
//!
//! So both are proved here, against the thing they have to agree with: the field-for-field
//! declaration the retired view carried, serialized by the serializer that carried it.

use super::super::crossed::{json_optional_float, render_plugins, render_pools_detail};
use busbar_substrate_values::facts::{LaneHealth, PluginFacts};

/// One `f64`, rendered by this file's renderer and by the serializer it replaced, must be the same
/// bytes.
///
/// THE SERIALIZER IS THE ORACLE, and it is asked the same question in the same shape: an
/// `Option<f64>` field, which is exactly how the reading this renders is declared. That makes the
/// comparison total — the `None` arm, the non-finite arms and every finite value are one question
/// with one right answer — rather than a spot check of the finite path with the rest reasoned about.
fn agrees_with_the_serializer(value: Option<f64>) {
    let mut ours = String::new();
    json_optional_float(value, &mut ours);
    let theirs = serde_json::to_string(&value).expect("an Option<f64> serializes");
    assert_eq!(
        ours, theirs,
        "the crossed read's float renderer must write what the retired serializer wrote for {value:?}"
    );
}

/// The float renderer writes what the retired serializer wrote, over a corpus that includes every
/// shape this field can actually carry and the ones that break a naive renderer.
///
/// A CORPUS, NOT A SAMPLE. Each group below is a spelling a different renderer would get wrong:
///
/// * LATENCY-SHAPED readings, which is what this field carries in production — an EWMA of
///   milliseconds, so a small number with a long fractional tail. `0.1 + 0.2` is in there because it
///   is the canonical value whose shortest round-trip has seventeen significant digits.
/// * WHOLE NUMBERS HELD AS FLOATS. The standard library's `Display` writes `1` and the serializer
///   writes `1.0`; a renderer that reached for `to_string` would move this byte on the most ordinary
///   value the field can hold.
/// * THE EXPONENT BOUNDARIES. The serializer switches to scientific notation outside a range and the
///   standard library never does, so these are the values where the two spellings diverge most
///   loudly — `1e100` is one character under one renderer and a hundred and one under another.
/// * SUBNORMALS, including the smallest positive one, where the shortest round-trip is not the
///   obvious decimal at all.
/// * ZERO, BOTH OF THEM. `-0.0` is a distinct bit pattern that reads back distinctly, and a renderer
///   that normalized it would lose a fact the value carried.
/// * THE VALUES THAT ARE NOT NUMBERS. JSON has no NaN and no infinity; the policy is the
///   serializer's, and asserting it here is what makes it the serializer's rather than this file's.
/// * ABSENCE, which is the same `null` byte by a different route, and the one place the two can
///   collapse without anything noticing.
#[test]
fn the_float_renderer_writes_what_the_retired_serializer_wrote() {
    let corpus: &[f64] = &[
        // Latency-shaped.
        0.0,
        0.5,
        1.5,
        12.25,
        42.125,
        0.1 + 0.2,
        1.0 / 3.0,
        123.456_789_012_345_67,
        9_999.999_999,
        // Whole numbers held as floats.
        1.0,
        2.0,
        10.0,
        100.0,
        1_000_000.0,
        9_007_199_254_740_992.0,
        // Exponent boundaries, both directions.
        1e15,
        1e16,
        1e17,
        1e-4,
        1e-5,
        1e-6,
        1e100,
        1e-100,
        1e308,
        1e-308,
        // Subnormals.
        f64::MIN_POSITIVE,
        f64::MIN_POSITIVE / 2.0,
        5e-324,
        // Zeroes and extremes.
        -0.0,
        f64::MAX,
        f64::MIN,
        -1.5,
        -0.000_123_45,
        // Not numbers.
        f64::NAN,
        f64::INFINITY,
        f64::NEG_INFINITY,
    ];

    for value in corpus {
        agrees_with_the_serializer(Some(*value));
    }
    // Absence, which is the same byte by another route.
    agrees_with_the_serializer(None);

    // AND A SWEEP, so the corpus above is a list of the cases somebody thought of rather than the
    // whole claim. The bit patterns are walked by a stride that is not a power of two, so the
    // exponent and the mantissa both move on every step and the walk does not sit in one binade.
    let mut bits: u64 = 1;
    for _ in 0..20_000 {
        agrees_with_the_serializer(Some(f64::from_bits(bits)));
        bits = bits.wrapping_mul(6_364_136_223_846_793_005).wrapping_add(1);
    }
}

/// ONE PLUGIN ROW, declared exactly as the retired view declared it — field for field, in its order,
/// with the same nine `skip_serializing_if` attributes.
///
/// A MIRROR, and it is honest about being one: the view it mirrors is `pub(crate)` in another crate
/// and cannot be named here, and the whole point of the crossing is that this crate does not name it.
/// What makes the mirror worth anything is that it is serialized by the SAME serializer the view was,
/// so the two agree about every question that is the serializer's — the escaping, the `null`s, the
/// omissions and the order — and the only thing left for a reader to check is that the declaration
/// below matches the one it is copied from. That check is a diff of two field lists; the alternative
/// was no check at all.
#[derive(serde::Serialize)]
struct RetiredPluginView<'a> {
    name: &'a str,
    r#type: &'a str,
    loader: &'a str,
    active: Option<bool>,
    target: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    file: Option<&'a str>,
    has_schema: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    version: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    publisher: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    interface_version: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    trust: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    valid: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    schema_url: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    schema_error: Option<&'a str>,
}

/// The page envelope every list read answers in, around the rows above.
#[derive(serde::Serialize)]
struct RetiredPage<'a> {
    items: Vec<RetiredPluginView<'a>>,
    next_cursor: Option<String>,
}

/// Project one neutral row into the mirror of the view the surface underneath used to serialize.
fn as_retired_view(row: &PluginFacts) -> RetiredPluginView<'_> {
    RetiredPluginView {
        name: &row.name,
        r#type: row.kind,
        loader: row.loader,
        active: row.active,
        target: row.target.as_deref(),
        file: row.file.as_deref(),
        has_schema: row.has_schema,
        version: row.version.as_deref(),
        publisher: row.publisher.as_deref(),
        interface_version: row.interface_version,
        trust: row.trust,
        valid: row.valid,
        error: row.error.as_deref(),
        schema_url: row.schema_url.as_deref(),
        schema_error: row.schema_error.as_deref(),
    }
}

/// A row with NOTHING behind it — the compiled-in shape, where every optional field is absent.
fn a_compiled_in_row() -> PluginFacts {
    PluginFacts {
        name: "memory".to_string(),
        kind: "store",
        loader: "compiled-in",
        active: None,
        target: None,
        file: None,
        has_schema: false,
        version: None,
        publisher: None,
        interface_version: None,
        trust: None,
        valid: None,
        error: None,
        schema_url: None,
        schema_error: None,
    }
}

/// A row with EVERYTHING behind it — the artifact shape, where every optional field is present, and
/// the strings carry the characters a hand-written renderer gets wrong.
fn a_fully_populated_row() -> PluginFacts {
    PluginFacts {
        // A quote, a backslash, a newline, a tab and a character outside the BMP: the escape set is
        // JSON's, not this file's, and the only way to be sure of it is to ask the serializer.
        name: "acme\"store\\\n\tstore\u{1F512}".to_string(),
        kind: "store",
        loader: "dynamic-library",
        active: Some(true),
        target: Some("acme-store-1.0.0.tar.gz".to_string()),
        file: Some("acme-store-1.0.0.tar.gz".to_string()),
        has_schema: true,
        version: Some("1.0.0".to_string()),
        publisher: Some("acme".to_string()),
        interface_version: Some(3),
        trust: Some("trusted"),
        valid: Some(false),
        error: Some("INVALID: cannot read plugins dir".to_string()),
        schema_url: Some("/api/v1/admin/plugins/acme-store-1.0.0.tar.gz/schema".to_string()),
        schema_error: Some("settings_schema does not parse".to_string()),
    }
}

/// The plugin-row renderer writes what the retired view serialized — the omissions, the `null`s, the
/// order and the escaping.
///
/// THE ROWS ARE RENDERED TOGETHER AS WELL AS APART, because a page is not just its rows: the
/// separator between two of them, and the envelope around all of them, are bytes a client pinned too,
/// and a renderer that wrote a correct row could still write a wrong page. The empty page is in there
/// for the same reason — a node with no plugins of a kind still answers, and it answers `[]`.
#[test]
fn the_plugin_row_renderer_writes_what_the_retired_view_serialized() {
    let cases: Vec<Vec<PluginFacts>> = vec![
        Vec::new(),
        vec![a_compiled_in_row()],
        vec![a_fully_populated_row()],
        vec![a_compiled_in_row(), a_fully_populated_row()],
        vec![
            a_fully_populated_row(),
            a_compiled_in_row(),
            PluginFacts {
                // ACTIVE AND TARGET ARE THE TWO THAT ARE WRITTEN WHEN ABSENT, and a row that is
                // absent in one and present in the other is what tells the two rules apart.
                active: Some(false),
                target: None,
                ..a_compiled_in_row()
            },
        ],
    ];

    for rows in &cases {
        let ours = render_plugins(rows);
        let theirs = serde_json::to_string(&RetiredPage {
            items: rows.iter().map(as_retired_view).collect(),
            next_cursor: None,
        })
        .expect("the retired page serializes");
        assert_eq!(
            ours, theirs,
            "the crossed catalog's renderer must write what the retired view serialized"
        );
    }
}

/// ONE POOL MEMBER'S LIVE STATUS, declared exactly as the retired view declared it — field for
/// field, in its order, with the same two nullable readings and nothing skipped.
///
/// A mirror, for the reason [`RetiredPluginView`] is one, and here it closes a different gap: the
/// composition-level cell beside this file serves a fixture whose lanes have taken no dispatch, so
/// every reading in it is a zero and the latency is `null`. That pins the shape and says nothing
/// about the one field on this surface that can carry a fraction. This does.
#[derive(serde::Serialize)]
struct RetiredPoolMemberStatusView<'a> {
    model: &'a str,
    weight: u32,
    usable: bool,
    cooldown_remaining_seconds: u64,
    available_concurrency: usize,
    inflight: i64,
    latency_ms: Option<f64>,
    ok: u64,
    err: u64,
    dead: bool,
    trip_count: u64,
    last_trip_at: Option<u64>,
}

/// One pool's detail row, as the retired view declared it.
#[derive(serde::Serialize)]
struct RetiredPoolDetailView<'a> {
    name: &'a str,
    members: Vec<RetiredPoolMemberStatusView<'a>>,
}

/// The page envelope every list read answers in, around the pool rows above.
#[derive(serde::Serialize)]
struct RetiredPoolPage<'a> {
    items: Vec<RetiredPoolDetailView<'a>>,
    next_cursor: Option<String>,
}

/// The pool-detail renderer writes what the retired view serialized, LATENCY INCLUDED.
///
/// The corpus is small on purpose: the float's own spelling is proved exhaustively above, and what
/// is left for this to prove is that the renderer puts it in the right PLACE — that the field order,
/// the two `null`s and the page around them are the retired view's. A pool with no members and a
/// page with no pools are in it because a node really can answer either, and a renderer that got a
/// separator wrong would be correct on every row and wrong on the page.
#[test]
fn the_pool_detail_renderer_writes_what_the_retired_view_serialized() {
    let member = |model: &str, latency: Option<f64>, last_trip: Option<u64>| LaneHealth {
        model: model.to_string(),
        weight: 7,
        usable: false,
        cooldown_remaining_seconds: 42,
        available_concurrency: 3,
        inflight: -1,
        latency_ms: latency,
        ok: 1_234,
        err: 5,
        dead: true,
        trip_count: 9,
        last_trip_at: last_trip,
    };
    let cases: Vec<Vec<(String, Vec<LaneHealth>)>> = vec![
        Vec::new(),
        vec![("empty-pool".to_string(), Vec::new())],
        vec![(
            // A quote, a backslash and a character outside the BMP: a pool name is the operator's
            // string, and the escape set is JSON's rather than this file's.
            "a\"pool\\\u{1F512}".to_string(),
            vec![
                member("never-dispatched", None, None),
                member("whole", Some(12.0), Some(1)),
                member("fractional", Some(0.1 + 0.2), Some(u64::MAX)),
                member("tiny", Some(f64::MIN_POSITIVE), Some(0)),
                member("huge", Some(1e100), None),
                member("not-a-number", Some(f64::NAN), None),
            ],
        )],
        vec![
            ("first".to_string(), vec![member("m", Some(1.5), None)]),
            ("second".to_string(), vec![member("m", Some(2.5), Some(7))]),
        ],
    ];

    for pools in &cases {
        let ours = render_pools_detail(pools);
        let theirs = serde_json::to_string(&RetiredPoolPage {
            items: pools
                .iter()
                .map(|(name, members)| RetiredPoolDetailView {
                    name,
                    members: members
                        .iter()
                        .map(|m| RetiredPoolMemberStatusView {
                            model: &m.model,
                            weight: m.weight,
                            usable: m.usable,
                            cooldown_remaining_seconds: m.cooldown_remaining_seconds,
                            available_concurrency: m.available_concurrency,
                            inflight: m.inflight,
                            latency_ms: m.latency_ms,
                            ok: m.ok,
                            err: m.err,
                            dead: m.dead,
                            trip_count: m.trip_count,
                            last_trip_at: m.last_trip_at,
                        })
                        .collect(),
                })
                .collect(),
            next_cursor: None,
        })
        .expect("the retired page serializes");
        assert_eq!(
            ours, theirs,
            "the crossed topology-with-health renderer must write what the retired view serialized"
        );
    }
}
