//! Crate-level test suite.
//!
//! Inline (`#[cfg(test)] mod tests` from `lib.rs`) rather than an external `tests/` integration
//! crate, because the table-driven test below needs the crate's own `pub(crate)` verb table and
//! `find_verb` to state its expectations without hand-duplicating either.

use std::cell::Cell;
use std::sync::Arc;

use busbar_contract::bounded::{Arena, ArenaBudget, ArenaBytes, Labels};
use busbar_contract::bounded::{SlabBytes, Span};
use busbar_contract::plane::{Ingress, Plane, PlaneMeta};
use busbar_contract::unit::{Clock, ConfigView, Ctx, SessionView, TransportView};
use busbar_contract::wire::{Direction, Frame, FrameCursor, FrameMeta};

use crate::verbs::{self, VERB_COUNT};
use crate::AdminPlane;

// ── a minimal, leak-based test arena ─────────────────────────────────────────────────────────────
//
// The `Arena` trait's only two allocators hand back byte/str slices, never a typed slice — see
// `verbs.rs`'s and the crate report's note on why `Ir.spans` stays empty in this plane. A test
// double for `Arena` has the same shape problem the plane itself does, minus the "never leak"
// requirement production code is held to: this is TEST-ONLY code, run a bounded number of times
// per process, and a short-lived leak here trades a small amount of test-process memory for a
// simple, honest double instead of unsafe code (which this crate forbids even in its own tests).
struct TestArena;

/// One arena that outlives every unit a test builds, because a span table handed to a `Unit<'u>`
/// has to live at least as long as the unit does and a test's own local arena does not.
static LEAK_ARENA: TestArena = TestArena;

impl Arena for TestArena {
    fn alloc_bytes<'a>(&'a self, src: &[u8]) -> Result<ArenaBytes<'a>, ArenaBudget> {
        let leaked: &'static [u8] = Box::leak(src.to_vec().into_boxed_slice());
        Ok(ArenaBytes::new(leaked))
    }

    fn alloc_str<'a>(&'a self, src: &str) -> Result<&'a str, ArenaBudget> {
        let leaked: &'static str = Box::leak(src.to_string().into_boxed_str());
        Ok(leaked)
    }

    fn alloc_spans<'a>(
        &'a self,
        src: &[(&'a str, Span)],
    ) -> Result<&'a [(&'a str, Span)], ArenaBudget> {
        Ok(Box::leak(src.to_vec().into_boxed_slice()))
    }

    fn remaining(&self) -> usize {
        usize::MAX
    }
}

struct TestConfig;

impl ConfigView for TestConfig {
    fn get_str(&self, _key: &str) -> Option<&str> {
        None
    }
    fn get_int(&self, _key: &str) -> Option<i64> {
        None
    }
    fn get_bool(&self, _key: &str) -> Option<bool> {
        None
    }
}

struct TestTransport;

impl TransportView for TestTransport {
    fn key(&self) -> &'static str {
        "http"
    }
    fn chain(&self) -> &[&'static str] {
        &["http"]
    }
    fn fact(&self, _key: &str) -> Option<&str> {
        None
    }
}

/// Build a one-frame cursor over a synthetic admin envelope: `{"method":..,"path":..,"body":{..}}`.
fn frame_cursor_for(envelope: &str) -> (Vec<Frame>, ()) {
    let bytes: Arc<[u8]> = Arc::from(envelope.as_bytes());
    let frame = Frame {
        direction: Direction::Inbound,
        stream: busbar_contract::ids::StreamId(0),
        bytes: SlabBytes::new(bytes),
        meta: FrameMeta::default(),
    };
    (vec![frame], ())
}

fn test_ctx<'u>(
    config: &'u TestConfig,
    transport: &'u TestTransport,
    labels: &'u Labels<'u>,
    arena: &'u TestArena,
) -> Ctx<'u> {
    let clock = Clock {
        unix_secs: 0,
        monotonic_nanos: 0,
    };
    let session: Option<&'u dyn SessionView> = None;
    Ctx::new(clock, config, session, transport, labels, arena)
}

/// A synthetic HTTP envelope naming one method/path/body, in the wire shape this plane's
/// `scan` module reads. See `codec.rs`'s module doc comment and `lib.rs`'s scope-boundary note for
/// why this plane assumes an already-framed envelope rather than parsing raw HTTP/1.1 text: that
/// framing is a transport's job, out of this crate's ownership.
fn envelope(method: &str, path: &str, body: &str) -> String {
    format!(r#"{{"method":"{method}","path":"{path}","body":{body}}}"#)
}

/// Fill every `{param}` segment of a path template with a short, distinct placeholder value, so a
/// templated fixture path becomes something `decode_ingress` can actually match against.
fn concretize_path(template: &str) -> String {
    template
        .split('/')
        .map(|seg| {
            if seg.starts_with('{') && seg.ends_with('}') {
                "x1"
            } else {
                seg
            }
        })
        .collect::<Vec<_>>()
        .join("/")
}

// ── requirement 1: the closed-loop table test against the pinned fixture ───────────────────────

/// For every one of the 66 operations the pinned `openapi-1.5.5.json` fixture declares,
/// `decode_ingress` resolves the SAME `(verb, read_only)` pair this crate's own generated table
/// says it should, and `approve`'s resource locator names that same verb — so the fixture, the
/// generated table and the running codec cannot silently drift apart from one another.
#[test]
fn decode_ingress_matches_the_pinned_1_5_5_fixture_for_every_operation() {
    let fixture_path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../testing/shadow-oracle/fixtures/openapi-1.5.5.json");
    let text = std::fs::read_to_string(&fixture_path)
        .unwrap_or_else(|e| panic!("reading {}: {e}", fixture_path.display()));
    let doc: serde_json::Value = serde_json::from_str(&text).expect("fixture is valid json");
    let paths = doc["paths"]
        .as_object()
        .expect("fixture has a paths object");

    let plane = AdminPlane::new();
    let config = TestConfig;
    let transport = TestTransport;
    let labels = Labels::new();
    let arena = TestArena;

    let mut seen = 0usize;
    let mut read_only_count = 0usize;
    let mut full_count = 0usize;

    for (path_template, item) in paths {
        let item = item.as_object().expect("path item is an object");
        for (method_lower, _op) in item {
            let method = match method_lower.as_str() {
                "get" => "GET",
                "post" => "POST",
                "put" => "PUT",
                "patch" => "PATCH",
                "delete" => "DELETE",
                _ => continue, // not an HTTP verb key (e.g. an `x-*` extension)
            };
            seen += 1;

            let concrete_path = concretize_path(path_template);
            // Every method's fixture body is empty here: this test asserts the (method, path) ->
            // verb/scope mapping, not per-operation body-field extraction (covered separately by
            // `codec::tests::identify_resolves_every_documented_body_field_verb`).
            let body = "{}";
            let text = envelope(method, &concrete_path, body);
            let (frames, ()) = frame_cursor_for(&text);
            let mut cursor = FrameCursor::new(&frames);
            let ctx = test_ctx(&config, &transport, &labels, &arena);

            let ingress = plane
                .decode_ingress(&mut cursor, None, &ctx)
                .unwrap_or_else(|e| {
                    panic!(
                        "decode_ingress refused {method} {path_template} (as {concrete_path}): {e}"
                    )
                });
            let draft = match ingress {
                Ingress::OneShot(draft) => draft,
                other => panic!("expected OneShot for {method} {path_template}, got {other:?}"),
            };

            // Cross-check against this crate's own closed table: the fixture-driven expectation
            // and the generated-table expectation must be the SAME row.
            let (expected_entry, _) = verbs::find_verb(method, &concrete_path)
                .unwrap_or_else(|| panic!("no table row for {method} {concrete_path}"));

            if expected_entry.read_only {
                read_only_count += 1;
                assert_eq!(
                    draft.op,
                    verbs::OP_READ,
                    "{method} {path_template} should price as read-only"
                );
            } else {
                full_count += 1;
                assert_eq!(
                    draft.op,
                    verbs::OP_WRITE,
                    "{method} {path_template} should price as full"
                );
            }

            // `approve`'s resource locator names the same verb `decode_ingress` resolved.
            let unit = build_unit(&text, draft.op, draft.facts);
            let scope = plane.approve(&unit, &ctx);
            let resource = scope.resources.as_slice().first().unwrap_or_else(|| {
                panic!("approve named no resource for {method} {path_template}")
            });
            assert_eq!(resource.name, expected_entry.verb);
            assert_eq!(resource.kind, "admin_verb");

            // `verify` names the same `KernelVerb`.
            let dest = plane.verify(&unit, &ctx);
            match dest {
                busbar_contract::dest::DestinationFacts::KernelVerb { verb } => {
                    assert_eq!(verb, expected_entry.verb);
                }
                other => panic!("expected KernelVerb for {method} {path_template}, got {other:?}"),
            }
        }
    }

    assert_eq!(
        seen, 66,
        "the pinned fixture no longer declares 66 operations"
    );
    assert_eq!(
        read_only_count, 34,
        "the fixture's read-only count drifted from the pinned 34"
    );
    assert_eq!(
        full_count, 32,
        "the fixture's full count drifted from the pinned 32"
    );
}

/// The generated table itself declares exactly the pinned 34/32 split, independent of the fixture
/// walk above (this is the same invariant, checked a second, cheaper way).
#[test]
fn generated_table_has_the_pinned_read_only_full_split() {
    let rows = &crate::generated::verb_table_1_5_5::VERB_TABLE_1_5_5;
    assert_eq!(rows.len(), 66);
    let read_only = rows.iter().filter(|(_, _, _, ro)| *ro).count();
    assert_eq!(read_only, 34);
    assert_eq!(rows.len() - read_only, 32);
}

/// The combined table (66 generated + 17 additive) has exactly 83 rows and no duplicate verb name.
#[test]
fn combined_table_has_83_unique_verb_names() {
    let all = verbs::all_verbs();
    assert_eq!(all.len(), VERB_COUNT);
    let mut names: Vec<&str> = all.iter().map(|e| e.verb).collect();
    names.sort_unstable();
    let before = names.len();
    names.dedup();
    assert_eq!(
        names.len(),
        before,
        "a verb name repeats in the combined table"
    );
}

fn build_unit<'u>(
    bytes: &'u str,
    op: busbar_contract::ids::OpClassId,
    facts: busbar_contract::bounded::Facts<'u>,
) -> busbar_contract::unit::Unit<'u> {
    struct TestSeal;
    impl busbar_contract::plugin::KernelSeal for TestSeal {
        fn seal_origin(&self) -> &'static str {
            "busbar-plane-admin::tests"
        }
    }
    // Through the one scanner, exactly as the codec builds it, so a unit a test hands the plane
    // carries the same span table a unit the plane decoded would.
    let spans =
        busbar_contract::spans::resolve(bytes.as_bytes(), &["/method", "/path"], &LEAK_ARENA)
            .expect("the leaking arena always has room");
    let ir = busbar_contract::bounded::Ir::new(bytes.as_bytes(), spans);
    busbar_contract::unit::Unit::new(
        &TestSeal,
        busbar_contract::UnitKey::new(0),
        busbar_contract::unit::Origin::Client,
        None,
        None,
        Direction::Inbound,
        None,
        op,
        ir,
        facts,
        None,
    )
}

// ── requirement 2: the refusal envelope's error codes ──────────────────────────────────────────

#[test]
fn encode_refusal_renders_the_1_5_5_error_envelope_for_common_codes() {
    let plane = AdminPlane::new();
    let config = TestConfig;
    let transport = TestTransport;
    let labels = Labels::new();
    let arena = TestArena;
    let ctx = test_ctx(&config, &transport, &labels, &arena);

    let cases = [
        (
            busbar_contract::unit::RefusalReason::NoDestination,
            "not_found",
        ),
        (
            busbar_contract::unit::RefusalReason::CredentialRejected,
            "unauthorized",
        ),
        (
            busbar_contract::unit::RefusalReason::ScopeMissing,
            "forbidden",
        ),
        (
            busbar_contract::unit::RefusalReason::BodyTooLarge,
            "invalid_request",
        ),
        (
            busbar_contract::unit::RefusalReason::OpenSlotBusy,
            "conflict",
        ),
        (
            busbar_contract::unit::RefusalReason::InFlightCap,
            "rate_limited",
        ),
        (
            busbar_contract::unit::RefusalReason::TierMismatch,
            "internal",
        ),
        (
            busbar_contract::unit::RefusalReason::DurabilityUnavailable,
            "unavailable",
        ),
    ];
    for (reason, code) in cases {
        let refusal = busbar_contract::unit::Refusal {
            step: busbar_contract::unit::Step::Approve,
            reason,
            retry_after_secs: None,
            stream: None,
            correlates: None,
        };
        let rendered = plane
            .encode_refusal(&refusal, None, None, &ctx)
            .expect("refusal renders");
        let text = core::str::from_utf8(rendered.as_slice()).expect("utf8");
        let parsed: serde_json::Value = serde_json::from_str(text).expect("valid json");
        assert_eq!(parsed["error"]["code"], code, "reason {reason:?}");
        assert!(parsed["error"]["message"].is_string());
        assert_eq!(parsed.as_object().unwrap().len(), 1);
        assert_eq!(parsed["error"].as_object().unwrap().len(), 2);
    }
}

// ── requirement 3: purity / determinism ─────────────────────────────────────────────────────────

/// Calling `decode_ingress` twice on the same bytes yields the same verb, the same op class and the
/// same path-parameter facts: the plane keeps no interior state that could make the second call
/// disagree with the first.
#[test]
fn decode_ingress_is_deterministic_over_repeated_calls() {
    let plane = AdminPlane::new();
    let config = TestConfig;
    let transport = TestTransport;
    let labels = Labels::new();
    let arena = TestArena;
    let ctx = test_ctx(&config, &transport, &labels, &arena);

    let text = envelope("GET", "/api/v1/admin/keys/abc", "{}");
    let mut results = Vec::new();
    for _ in 0..3 {
        let (frames, ()) = frame_cursor_for(&text);
        let mut cursor = FrameCursor::new(&frames);
        let ingress = plane
            .decode_ingress(&mut cursor, None, &ctx)
            .expect("decodes");
        let draft = match ingress {
            Ingress::OneShot(d) => d,
            other => panic!("expected OneShot, got {other:?}"),
        };
        let verb = draft.facts.get("verb");
        results.push(format!("{verb:?}|{:?}", draft.op));
    }
    assert!(
        results.windows(2).all(|w| w[0] == w[1]),
        "decode_ingress disagreed across identical calls: {results:?}"
    );
}

/// `AdminPlane` has no fields — asserted structurally, not just by comment, matching the plugin
/// contract's rule that a plane's only cross-frame state lives in the kernel-held
/// `PlaneSessionState`, never in the plane value itself.
#[test]
fn admin_plane_carries_no_fields() {
    assert_eq!(std::mem::size_of::<AdminPlane>(), 0);
}

/// The registry only requires `SessionPlane` when a claimed transport declares itself session
/// shaped; this plane's one claim is over `"http"`, and it implements `PlaneMeta` with a `CLAIMS`
/// slice of length one, matching `claims::CLAIMS`.
#[test]
fn declares_exactly_one_claim_over_http() {
    let claims = <AdminPlane as PlaneMeta>::CLAIMS;
    assert_eq!(claims.len(), 1);
    assert_eq!(claims[0].transport, "http");
}

// A cell used only to keep clippy quiet about an otherwise-unused import in some feature
// combinations; referenced so the import is never flagged as dead in a `--tests` build.
#[allow(dead_code)]
fn _touch(_: &Cell<u8>, _: Span) {}

// ── requirement 4: no section-sign or parity-binding literals anywhere in this crate ────────────

#[test]
fn source_cites_the_design_in_words_not_in_symbols() {
    let src_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut offenders = Vec::new();
    walk(&src_dir, &mut |path, text| {
        for (n, line) in text.lines().enumerate() {
            if line.contains('\u{00a7}') {
                offenders.push(format!("{}:{}: section sign", path.display(), n + 1));
            }
            let bytes = line.as_bytes();
            for i in 0..bytes.len().saturating_sub(4) {
                if bytes[i] == b'P'
                    && bytes[i + 1] == b'B'
                    && bytes[i + 2] == b'-'
                    && bytes[i + 3].is_ascii_digit()
                {
                    offenders.push(format!("{}:{}: binding identifier", path.display(), n + 1));
                }
            }
        }
    });
    assert!(
        offenders.is_empty(),
        "section-sign or parity-binding literal found: {offenders:?}"
    );
}

fn walk(dir: &std::path::Path, f: &mut impl FnMut(&std::path::Path, &str)) {
    let entries = std::fs::read_dir(dir).expect("src dir is readable");
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            walk(&path, f);
        } else if path.extension().is_some_and(|e| e == "rs") {
            let text = std::fs::read_to_string(&path).expect("source file is readable");
            f(&path, &text);
        }
    }
}
