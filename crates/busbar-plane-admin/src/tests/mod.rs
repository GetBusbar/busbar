//! Crate-level test suite.
//!
//! Inline (`#[cfg(test)] mod tests` from `lib.rs`) rather than an external `tests/` integration
//! crate, because the table-driven test below needs the crate's own `pub(crate)` verb table and
//! `find_verb` to state its expectations without hand-duplicating either.

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

/// The combined table (66 generated + 17 money-governance + 5 ledger views) has exactly the rows
/// its count declares, and no duplicate verb name.
#[test]
fn combined_table_has_unique_verb_names() {
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

/// A request still arriving asks for the next frame; it is not ended as a caller's mistake.
///
/// Two shapes reach this: a cursor with nothing left in it (every byte that has arrived is already
/// handed over) and a frame whose envelope object has not closed. Both used to end the unit — the
/// first as `Malformed`, the second as `UnsupportedOperation` — so a caller whose body was merely
/// still on the wire was answered as though they had sent a bad one.
#[test]
fn a_request_still_arriving_asks_for_the_next_frame() {
    let plane = AdminPlane::new();
    let config = TestConfig;
    let transport = TestTransport;
    let labels = Labels::new();
    let arena = TestArena;
    let ctx = test_ctx(&config, &transport, &labels, &arena);

    let empty: Vec<Frame> = Vec::new();
    let mut cursor = FrameCursor::new(&empty);
    assert_eq!(
        plane.decode_ingress(&mut cursor, None, &ctx),
        Ok(Ingress::NeedMore),
        "a cursor with no frame left has nothing yet to decode"
    );

    let whole = envelope("POST", "/api/v1/admin/keys", r#"{"name":"k1"}"#);
    let half = &whole[..whole.len() - 4];
    let (frames, ()) = frame_cursor_for(half);
    let mut cursor = FrameCursor::new(&frames);
    assert_eq!(
        plane.decode_ingress(&mut cursor, None, &ctx),
        Ok(Ingress::NeedMore),
        "an envelope that has not closed is not yet an envelope"
    );

    // and the whole thing still decodes, so the check above is a filter and not a wall
    let (frames, ()) = frame_cursor_for(&whole);
    let mut cursor = FrameCursor::new(&frames);
    assert!(matches!(
        plane.decode_ingress(&mut cursor, None, &ctx),
        Ok(Ingress::OneShot(_))
    ));
}

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
        // EVERY fact the draft carries, not just the verb: the path parameters this target names
        // are facts too, and a call that agreed about the verb while disagreeing about which key it
        // was for would have passed a test that only read the verb.
        let mut facts: Vec<String> = draft
            .facts
            .iter()
            .map(|(key, value)| format!("{key}={value:?}"))
            .collect();
        facts.sort();
        results.push(format!("{facts:?}|{:?}", draft.op));
    }
    // The path parameter is one of the facts being compared, so the target above has to name one or
    // this test is back to comparing the verb alone.
    assert!(
        results[0].contains("abc"),
        "the target names a path parameter and the draft did not carry it: {}",
        results[0]
    );
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
            if cites_a_binding(line) {
                offenders.push(format!("{}:{}: binding identifier", path.display(), n + 1));
            }
        }
    });
    assert!(
        offenders.is_empty(),
        "section-sign or parity-binding literal found: {offenders:?}"
    );
}

/// Whether a line cites a parity binding by its identifier rather than in words.
///
/// The window is four bytes wide, so the last position it can start at is four from the end. An
/// exclusive bound of `len - 4` stops one position short of that, which makes the gate blind to a
/// citation that ENDS a line — the one place a comment naturally puts one.
fn cites_a_binding(line: &str) -> bool {
    let bytes = line.as_bytes();
    (0..bytes.len().saturating_sub(3)).any(|i| {
        bytes[i] == b'P'
            && bytes[i + 1] == b'B'
            && bytes[i + 2] == b'-'
            && bytes[i + 3].is_ascii_digit()
    })
}

/// The citations here are spelled in two pieces on purpose: a whole one would be the very literal
/// the gate above forbids, and this file is inside the tree it walks.
#[test]
fn the_binding_scan_sees_a_citation_that_ends_a_line() {
    assert!(
        cites_a_binding(concat!("// the admin-listener exemption, P", "B-7")),
        "a citation four bytes from the end is the shape a comment ends on"
    );
    assert!(cites_a_binding(concat!(
        "P",
        "B-60 is checked after Authenticate"
    )));
    assert!(!cites_a_binding("nothing here cites anything"));
    assert!(!cites_a_binding(concat!("P", "B- with no number")));
}

// ── the response pass-through does not go through the arena ────────────────────────────────────

/// An arena the size the design pins production's at, and a bump cursor that refuses past it.
/// `TestArena` above leaks and so has room for anything, which is what a test that needs a span
/// table wants and exactly what a test about the arena's BUDGET must not have.
struct TinyArena {
    used: std::sync::atomic::AtomicUsize,
}

impl TinyArena {
    fn used(&self) -> usize {
        self.used.load(std::sync::atomic::Ordering::Relaxed)
    }
}

impl Arena for TinyArena {
    fn alloc_bytes<'a>(&'a self, src: &[u8]) -> Result<ArenaBytes<'a>, ArenaBudget> {
        let used = self.used() + src.len();
        if used > busbar_contract::ARENA_BYTES {
            return Err(ArenaBudget {
                wanted: src.len(),
                remaining: self.remaining(),
            });
        }
        self.used.store(used, std::sync::atomic::Ordering::Relaxed);
        Ok(ArenaBytes::new(Box::leak(src.to_vec().into_boxed_slice())))
    }

    fn alloc_str<'a>(&'a self, src: &str) -> Result<&'a str, ArenaBudget> {
        let used = self.used() + src.len();
        if used > busbar_contract::ARENA_BYTES {
            return Err(ArenaBudget {
                wanted: src.len(),
                remaining: self.remaining(),
            });
        }
        self.used.store(used, std::sync::atomic::Ordering::Relaxed);
        Ok(Box::leak(src.to_string().into_boxed_str()))
    }

    fn alloc_spans<'a>(
        &'a self,
        src: &[(&'a str, Span)],
    ) -> Result<&'a [(&'a str, Span)], ArenaBudget> {
        Ok(Box::leak(src.to_vec().into_boxed_slice()))
    }

    fn remaining(&self) -> usize {
        busbar_contract::ARENA_BYTES - self.used()
    }
}

/// A response bigger than the whole arena still encodes, byte for byte.
///
/// The admin surface's own `openapi.json` is over 350 KB and the arena is 4 KiB, so a codec that
/// COPIED the response into the arena refused the single largest document the surface serves — and
/// every other answer over 4 KiB with it (a key listing, a config dump, an audit page). The body
/// already lives for the unit, so the encode borrows it and there is no budget left to exhaust.
#[test]
fn a_response_larger_than_the_arena_encodes_verbatim() {
    let plane = AdminPlane::new();
    let config = TestConfig;
    let transport = TestTransport;
    let labels = Labels::new();
    let arena = TinyArena {
        used: std::sync::atomic::AtomicUsize::new(0),
    };
    let clock = Clock {
        unix_secs: 0,
        monotonic_nanos: 0,
    };
    let session: Option<&dyn SessionView> = None;
    let ctx = Ctx::new(clock, &config, session, &transport, &labels, &arena);

    let big = vec![b'x'; busbar_contract::ARENA_BYTES * 4];
    let response = busbar_contract::plane::Response {
        ir: busbar_contract::bounded::Ir::new(&big, &[]),
        finish: busbar_contract::unit::FinishClass::Complete,
        facts: busbar_contract::bounded::Facts::new(),
    };
    let encoded = plane
        .encode_response(&response, None, &ctx)
        .expect("a body the unit already owns needs no room in the arena");
    assert_eq!(encoded.as_slice(), big.as_slice());
    assert_eq!(
        arena.remaining(),
        busbar_contract::ARENA_BYTES,
        "the pass-through must not spend a byte of the arena"
    );
}

// ── the plane's own registration identity ───────────────────────────────────────────────────────

/// The key the plugin answers to IS the key the plane declares, and it is the registry's `admin`.
///
/// Two reads of one name: the registry binds this plane's claim by the plugin's `key`, and a
/// composition root names the plane by `PlaneMeta::KEY`. A drift between them registers the admin
/// surface's claim under a name nothing looks up — the whole surface simply stops being reachable,
/// with every one of this crate's other tests still green. The literal is pinned too: two spellings
/// checked only against each other agree perfectly while both being wrong.
#[test]
fn the_plugin_key_is_the_plane_key_and_is_admin() {
    let plane = AdminPlane::new();
    assert_eq!(
        busbar_contract::plugin::Plugin::key(&plane),
        <AdminPlane as PlaneMeta>::KEY
    );
    assert_eq!(busbar_contract::plugin::Plugin::key(&plane), "admin");
}

/// This plugin registers as a PLANE, on the one ABI the loader accepts.
#[test]
fn the_plugin_registers_as_a_plane_on_abi_one() {
    let plane = AdminPlane::new();
    assert_eq!(
        busbar_contract::plugin::Plugin::kind(&plane),
        busbar_contract::plugin::Kind::Plane
    );
    assert_eq!(
        busbar_contract::plugin::Plugin::abi(&plane),
        busbar_contract::plugin::AbiVersion(1)
    );
}

// ── the refusal envelope: this plane's own shape, with 1.5.5's bytes ────────────────────────────

/// Every one of the closed reason set renders the frozen envelope, with prose of its own.
///
/// The envelope's SHAPE was already pinned; what nothing pinned was the message inside it. A
/// message table that answered the empty string for every reason, or one string for every reason,
/// left an envelope that still parsed, still carried the right code and told an operator nothing —
/// and the shape assertions could not see the difference. So this reads all forty-two: each message
/// is non-empty, none of them is a Rust identifier leaking through, and the set is not one string
/// wearing forty-two hats. The exact bytes of a representative envelope are pinned as bytes,
/// because the wire shape is bytes and not a parsed document.
#[test]
fn every_refusal_reason_renders_its_own_prose_inside_the_frozen_envelope() {
    use busbar_contract::unit::RefusalReason as R;
    let all = [
        R::InFlightCap,
        R::CursorBudget,
        R::CredentialBudget,
        R::SessionBudget,
        R::BodyTooLarge,
        R::OpenSlotBusy,
        R::SchemeNotDeclared,
        R::CredentialRejected,
        R::SessionUnbound,
        R::Revoked,
        R::ScopeMissing,
        R::Vetoed,
        R::NoDestination,
        R::OverBudget,
        R::GroupFrozen,
        R::Unpriced,
        R::OverdraftCeiling,
        R::StaleSlice,
        R::DurabilityUnavailable,
        R::TierMismatch,
        R::SpillBudget,
        R::ArenaBudget,
        R::RateLimited,
        R::DecodeFailed,
        R::ChallengeExhausted,
        R::PoolNotPermitted,
        R::NoRate,
        R::Replayed,
        R::InFlight,
        R::DestinationBudgetExhausted,
        R::BreakerOpen,
        R::DestinationUnreachable,
        R::MeterDisputed,
        R::HandoffMismatch,
        R::PlanePanic,
        R::TaskLost,
        R::SecretPlaceholder,
        R::Stalled,
        R::Drain,
        R::Superseded,
        R::ClientGone,
        R::DeadlineExceeded,
    ];
    assert_eq!(
        all.len(),
        42,
        "the contract's reason set changed and this walk did not"
    );
    let mut distinct = std::collections::BTreeSet::new();
    for reason in all {
        let message = crate::refusal::message_for(reason);
        assert!(!message.is_empty(), "{reason:?} renders an empty message");
        assert_ne!(
            message,
            format!("{reason:?}"),
            "{reason:?} puts a Rust identifier on the wire"
        );
        assert!(
            !message.contains('"') && !message.contains('\\'),
            "{reason:?}: the envelope is hand-formatted, so its message must be quote-free"
        );
        distinct.insert(message);
        // Whatever the prose, it is the prose the rendered envelope carries.
        assert_eq!(
            crate::refusal::envelope(reason),
            format!(
                r#"{{"error":{{"code":"{}","message":"{message}"}}}}"#,
                crate::refusal::code_for(reason)
            )
        );
    }
    assert!(
        distinct.len() >= 40,
        "forty-two reasons share {} messages: an operator cannot tell them apart",
        distinct.len()
    );
}

/// The refusal a caller receives is those exact bytes, in that exact order, with nothing round it.
///
/// Pinned as a byte string rather than as a parsed document: key order, spacing and the absence of
/// a trailing newline are all part of the surface 1.5.5 froze, and a parsed comparison sees none of
/// them.
#[test]
fn the_refusal_a_caller_receives_is_the_frozen_bytes() {
    let plane = AdminPlane::new();
    let config = TestConfig;
    let transport = TestTransport;
    let labels = Labels::new();
    let arena = TestArena;
    let ctx = test_ctx(&config, &transport, &labels, &arena);
    let refusal = busbar_contract::unit::Refusal {
        step: busbar_contract::unit::Step::Approve,
        reason: busbar_contract::unit::RefusalReason::ScopeMissing,
        retry_after_secs: None,
        stream: None,
        correlates: None,
    };
    let rendered = plane
        .encode_refusal(&refusal, None, None, &ctx)
        .expect("refusal renders");
    assert_eq!(
        rendered.as_slice(),
        br#"{"error":{"code":"forbidden","message":"principal lacks the required scope"}}"#
    );
}

// ── the envelope scan: a brace inside a string is text, across a frame boundary too ─────────────

/// A split that lands inside a string carrying a brace still reads the whole envelope.
///
/// The single-frame case cannot tell a string-aware scan from a brace-counting one: both answer
/// "complete" over bytes that ARE complete, and the decode reads the same head either way. The
/// difference only shows at a boundary — a scan that treated a quote as nothing would see the brace
/// inside a string value close the envelope early, hand `identify` a truncated object and refuse a
/// request that had merely not finished arriving.
///
/// The plane answers one frame at a time and never joins two itself — `envelope_is_complete`'s
/// whole job is to say "not yet" so the loop hands over the next frame — so the two halves of the
/// property are read where each is observable. Over the HEAD ALONE the answer must be `NeedMore`
/// and not a refusal: that is the string-aware scan refusing to read the quoted brace as the
/// close. Over the JOINED bytes the answer must be the whole request, verb and all: that is the
/// envelope reading through the same quoted brace to its real end.
#[test]
fn a_split_inside_a_string_carrying_a_brace_is_read_whole() {
    let head = br#"{"method":"GET","path":"/api/v1/admin/audit","body":{},"note":"}"#;
    let tail = br#"x"}"#;
    let plane = AdminPlane::new();
    let config = TestConfig;
    let transport = TestTransport;
    let labels = Labels::new();
    let arena = TestArena;
    let ctx = test_ctx(&config, &transport, &labels, &arena);

    let frame_of = |bytes: &[u8]| Frame {
        direction: Direction::Inbound,
        stream: busbar_contract::ids::StreamId(0),
        bytes: SlabBytes::new(std::sync::Arc::from(bytes.to_vec().into_boxed_slice())),
        meta: FrameMeta::default(),
    };

    // The head alone: the brace inside the string value is text, so the envelope has not closed.
    // A brace-counting scan would answer here, and it would answer with a refusal.
    let head_only = vec![frame_of(head)];
    let mut cursor = FrameCursor::new(&head_only);
    let ingress = plane
        .decode_ingress(&mut cursor, None, &ctx)
        .expect("an unfinished envelope is not a bad one");
    assert!(
        matches!(ingress, Ingress::NeedMore),
        "the brace inside the string value must not close the envelope"
    );

    // The two halves as they arrive joined: the same quoted brace is read through to the real end.
    let mut whole = head.to_vec();
    whole.extend_from_slice(tail);
    let joined = vec![frame_of(&whole)];
    let mut cursor = FrameCursor::new(&joined);
    let ingress = plane
        .decode_ingress(&mut cursor, None, &ctx)
        .expect("the joined bytes close one envelope");
    let Ingress::OneShot(draft) = ingress else {
        panic!("an admin request is one shot");
    };
    assert!(matches!(
        draft.facts.get(crate::meta::FACT_VERB),
        Some(busbar_contract::bounded::FactValue::Str("get_audit"))
    ));
}

// ── what the decode step hands on: the span table, and every pointer it resolved ────────────────

/// The pointer the verb's documented body field names reaches the draft's span table.
///
/// The decode resolves the request line's two structural values and, where the row documents one,
/// the body member as well — and the count of pointers it declares is what the span table is built
/// from. A count that stopped short dropped the path, the body field or both: the fact map still
/// carried them, so every fact assertion stayed green while the IR a later step reads went blind.
#[test]
fn every_pointer_the_decode_resolved_reaches_the_drafts_span_table() {
    let plane = AdminPlane::new();
    let config = TestConfig;
    let transport = TestTransport;
    let labels = Labels::new();
    let arena = TestArena;
    let ctx = test_ctx(&config, &transport, &labels, &arena);

    let text = envelope("POST", "/api/v1/admin/keys", r#"{"name":"k1"}"#);
    let (frames, ()) = frame_cursor_for(&text);
    let mut cursor = FrameCursor::new(&frames);
    let Ingress::OneShot(draft) = plane
        .decode_ingress(&mut cursor, None, &ctx)
        .expect("post_keys decodes")
    else {
        panic!("an admin request is one shot");
    };

    assert_eq!(draft.body_ir.pointer("/method"), Some(&b"\"POST\""[..]));
    assert_eq!(
        draft.body_ir.pointer("/path"),
        Some(&b"\"/api/v1/admin/keys\""[..])
    );
    assert_eq!(draft.body_ir.pointer("/body/name"), Some(&b"\"k1\""[..]));
    assert_eq!(
        draft.body_ir.pointers().count(),
        3,
        "three pointers were resolved, so three belong in the table"
    );

    // A verb whose row documents no body field declares the two structural pointers and no third.
    let text = envelope("GET", "/api/v1/admin/audit", "{}");
    let (frames, ()) = frame_cursor_for(&text);
    let mut cursor = FrameCursor::new(&frames);
    let Ingress::OneShot(draft) = plane
        .decode_ingress(&mut cursor, None, &ctx)
        .expect("get_audit decodes")
    else {
        panic!("an admin request is one shot");
    };
    assert_eq!(draft.body_ir.pointers().count(), 2);
}

/// A body member that is not a string is read as its own bytes, quotes and all being absent.
///
/// The quote-stripping is conditional on the value BEING quoted; a member spelled as a number or an
/// object is located, not unwrapped, so nothing invents a value by shaving a byte off each end of
/// something that was never a string.
#[test]
fn a_body_member_that_is_not_a_string_is_located_rather_than_unwrapped() {
    let plane = AdminPlane::new();
    let config = TestConfig;
    let transport = TestTransport;
    let labels = Labels::new();
    let arena = TestArena;
    let ctx = test_ctx(&config, &transport, &labels, &arena);

    // `post_config_rollback` documents `version`; a caller who sends it as a number rather than a
    // string still decodes, and the span the draft carries is the number's own bytes.
    let text = envelope("POST", "/api/v1/admin/config/rollback", r#"{"version":12}"#);
    let (frames, ()) = frame_cursor_for(&text);
    let mut cursor = FrameCursor::new(&frames);
    let Ingress::OneShot(draft) = plane
        .decode_ingress(&mut cursor, None, &ctx)
        .expect("post_config_rollback decodes")
    else {
        panic!("an admin request is one shot");
    };
    assert_eq!(draft.body_ir.pointer("/body/version"), Some(&b"12"[..]));
}

// ── codec only: this plane executes nothing and dials nobody ────────────────────────────────────

/// Nothing on this plane reaches an upstream, in either direction, at any step.
///
/// The admin surface's operations are KERNEL VERBS: `busbar-unit-verbs` executes them, and this
/// crate is the codec that reads the request and renders the answer. The three egress-shaped steps
/// therefore have no honest answer at all and say so, rather than quietly succeeding with nothing —
/// a `route` that planned a leg, or an `encode_egress` that answered empty bytes, would put the
/// admin credential's own surface on a wire.
#[test]
fn the_plane_plans_no_leg_and_encodes_no_egress() {
    let plane = AdminPlane::new();
    let config = TestConfig;
    let transport = TestTransport;
    let labels = Labels::new();
    let arena = TestArena;
    let ctx = test_ctx(&config, &transport, &labels, &arena);

    let bytes = envelope("GET", "/api/v1/admin/audit", "{}");
    let unit = build_unit(
        &bytes,
        verbs::OP_READ,
        busbar_contract::bounded::Facts::new(),
    );
    let dest = busbar_contract::dest::VerifiedDestination::seal(
        &TestUnitSeal,
        busbar_contract::dest::DestinationFacts::KernelVerb { verb: "get_audit" },
        "http",
        None,
    );

    assert_eq!(
        plane.route(&unit, &ctx).legs.as_slice().len(),
        0,
        "this plane opens no leg of its own"
    );
    assert!(matches!(
        plane.encode_egress(&unit, &dest, None, &ctx),
        Err(busbar_contract::wire::Encode::Unrepresentable)
    ));
    let frame = Frame {
        direction: Direction::Outbound,
        stream: busbar_contract::ids::StreamId(0),
        bytes: SlabBytes::new(std::sync::Arc::from(b"{}".to_vec().into_boxed_slice())),
        meta: FrameMeta::default(),
    };
    assert!(matches!(
        plane.encode_ingress_frame(&unit, &frame, &dest, None, &ctx),
        Err(busbar_contract::wire::Encode::Unrepresentable)
    ));
    let empty: Vec<Frame> = Vec::new();
    let mut cursor = FrameCursor::new(&empty);
    assert!(matches!(
        plane.decode_response(&mut cursor, &dest, None, &ctx),
        Err(busbar_contract::wire::Decode::UnsupportedOperation)
    ));
    assert_eq!(
        plane.encode_end(
            &unit,
            &busbar_contract::unit::UnitEnd::Completed,
            None,
            &ctx
        ),
        Ok(None)
    );
}

/// This plane prices nothing of its own: no lane, no ceiling, no priced span, no usage line.
///
/// The design's admin row prices every verb under the kernel-reserved `count` class, which a plane
/// may not declare — so an admit that named a lane locator, or a meter that located a quantity,
/// would be this plane pricing a surface the kernel already prices.
#[test]
fn the_admin_plane_locates_no_priced_quantity() {
    let plane = AdminPlane::new();
    let config = TestConfig;
    let transport = TestTransport;
    let labels = Labels::new();
    let arena = TestArena;
    let ctx = test_ctx(&config, &transport, &labels, &arena);

    let bytes = envelope("GET", "/api/v1/admin/audit", "{}");
    let unit = build_unit(
        &bytes,
        verbs::OP_READ,
        busbar_contract::bounded::Facts::new(),
    );
    let admit = plane.admit(&unit, &ctx);
    assert!(admit.lane_locator.is_none());
    assert!(admit.max_response_ptrs.as_slice().is_empty());
    assert!(admit.input_span.is_none());

    let response = busbar_contract::plane::Response {
        ir: busbar_contract::bounded::Ir::empty(),
        finish: busbar_contract::unit::FinishClass::Complete,
        facts: busbar_contract::bounded::Facts::new(),
    };
    assert!(plane
        .meter(&unit, &response, &ctx)
        .lines
        .as_slice()
        .is_empty());
    assert!(<AdminPlane as PlaneMeta>::METER_CLASSES.is_empty());
}

/// The admin credential travels on every request, under the claim's one alternative, never cached.
///
/// The claim is over plain HTTP request/response, so there is no session for a credential to be
/// cached on — a locator that said otherwise would ask the auth unit for a principal off a session
/// that has none. And the claim declares exactly one alternative, so there is nothing to narrow to.
#[test]
fn the_admin_credential_is_on_the_request_and_narrows_to_nothing() {
    let plane = AdminPlane::new();
    let config = TestConfig;
    let transport = TestTransport;
    let labels = Labels::new();
    let arena = TestArena;
    let ctx = test_ctx(&config, &transport, &labels, &arena);
    let bytes = envelope("GET", "/api/v1/admin/audit", "{}");
    let unit = build_unit(
        &bytes,
        verbs::OP_READ,
        busbar_contract::bounded::Facts::new(),
    );

    let locator = plane.authenticate(&unit, &ctx);
    assert!(locator.narrowing.is_none());
    assert!(!locator.from_session);
    assert_eq!(crate::claims::CLAIMS[0].scheme_alternatives.len(), 1);
}

/// A plane that declares no introspection verb answers none — it does not answer an empty one.
///
/// An empty `PlaneFacts` is a plane saying "that verb of mine had nothing to report", which is a
/// different sentence from "that is not a verb of mine": the first is a successful read of a verb
/// this plane never declared.
#[test]
fn this_plane_declares_no_introspection_verb_so_it_answers_none() {
    let plane = AdminPlane::new();
    let config = TestConfig;
    let transport = TestTransport;
    let labels = Labels::new();
    let arena = TestArena;
    let ctx = test_ctx(&config, &transport, &labels, &arena);
    assert!(<AdminPlane as PlaneMeta>::INTROSPECTION_VERBS.is_empty());
    for verb in ["dialects", "ladder", "verb_table"] {
        assert!(matches!(
            plane.plane_facts(busbar_contract::ids::AdminVerbId::new(verb), None, &ctx),
            Err(busbar_contract::wire::Decode::UnsupportedOperation)
        ));
    }
}

/// The content fact names the verb, and the EXECUTING unit's own answer wins over the draft's.
///
/// The response's `verb` fact is what the unit that actually ran stamped back; the draft's is what
/// the decode step resolved before anything ran. They agree on every ordinary request, which is why
/// a test that only ever set one of them could not see the precedence at all — and why dropping the
/// response arm looked harmless. Where they differ, the record has to say what ran.
#[test]
fn the_content_fact_names_the_verb_the_executing_unit_reported() {
    let plane = AdminPlane::new();
    let config = TestConfig;
    let transport = TestTransport;
    let labels = Labels::new();
    let arena = TestArena;
    let ctx = test_ctx(&config, &transport, &labels, &arena);

    let bytes = envelope("GET", "/api/v1/admin/audit", "{}");
    let mut draft_facts = busbar_contract::bounded::Facts::new();
    draft_facts
        .set(
            crate::meta::FACT_VERB,
            busbar_contract::bounded::FactValue::Str("get_audit"),
        )
        .expect("one fact fits");
    let unit = build_unit(&bytes, verbs::OP_READ, draft_facts);

    // With nothing on the response, the draft's verb is what the record carries.
    let bare = busbar_contract::plane::Response {
        ir: busbar_contract::bounded::Ir::empty(),
        finish: busbar_contract::unit::FinishClass::Complete,
        facts: busbar_contract::bounded::Facts::new(),
    };
    assert!(matches!(
        plane
            .content_facts(&unit, &bare, &ctx)
            .facts
            .get(crate::meta::FACT_VERB),
        Some(busbar_contract::bounded::FactValue::Str("get_audit"))
    ));

    // With a verb on the response, THAT is what ran, and that is what the record carries.
    let mut response_facts = busbar_contract::bounded::Facts::new();
    response_facts
        .set(
            crate::meta::FACT_VERB,
            busbar_contract::bounded::FactValue::Str("get_usage"),
        )
        .expect("one fact fits");
    let executed = busbar_contract::plane::Response {
        ir: busbar_contract::bounded::Ir::empty(),
        finish: busbar_contract::unit::FinishClass::Complete,
        facts: response_facts,
    };
    assert!(matches!(
        plane
            .content_facts(&unit, &executed, &ctx)
            .facts
            .get(crate::meta::FACT_VERB),
        Some(busbar_contract::bounded::FactValue::Str("get_usage"))
    ));
}

// ── replay: decoding the same mutating request twice is the same draft, every time ──────────────

/// Every mutating verb in the closed table decodes identically the second time it arrives.
///
/// An admin mutation that a client retries — because a connection dropped, because a proxy
/// retried, because an operator pressed the button twice — has to reach the verbs unit as the same
/// operation carrying the same parameters both times, or the idempotency the executing unit
/// enforces is being enforced over two different requests. The plane is the step that has to be
/// boring here: same bytes in, same verb, same class, same parameter facts, same span table.
#[test]
fn every_mutating_verb_decodes_identically_on_replay() {
    let plane = AdminPlane::new();
    let config = TestConfig;
    let transport = TestTransport;
    let labels = Labels::new();
    let arena = TestArena;
    let ctx = test_ctx(&config, &transport, &labels, &arena);

    let mut mutating = 0usize;
    for row in verbs::table() {
        if row.read_only {
            continue;
        }
        mutating += 1;
        let concrete = concretize_path(row.template);
        let body = match verbs::documented_body_field(row.verb) {
            Some(field) => format!(r#"{{"{field}":"v1"}}"#),
            None => "{}".to_string(),
        };
        let text = envelope(row.method, &concrete, &body);

        let mut seen: Option<(String, busbar_contract::ids::OpClassId, Vec<String>)> = None;
        for attempt in 0..2 {
            let (frames, ()) = frame_cursor_for(&text);
            let mut cursor = FrameCursor::new(&frames);
            let Ingress::OneShot(draft) = plane
                .decode_ingress(&mut cursor, None, &ctx)
                .unwrap_or_else(|e| panic!("{} {concrete}: {e:?}", row.method))
            else {
                panic!("an admin request is one shot");
            };
            let verb = match draft.facts.get(crate::meta::FACT_VERB) {
                Some(busbar_contract::bounded::FactValue::Str(v)) => v,
                other => panic!("{}: the verb fact is {other:?}", row.verb),
            };
            let mut pointers: Vec<String> = draft
                .body_ir
                .pointers()
                .map(|(p, s)| {
                    format!(
                        "{p}={}",
                        String::from_utf8_lossy(&text.as_bytes()[s.start..s.end])
                    )
                })
                .collect();
            pointers.sort();
            match &seen {
                None => seen = Some(((*verb).to_string(), draft.op, pointers)),
                Some((first_verb, first_op, first_pointers)) => {
                    assert_eq!(verb, first_verb, "{}: replay {attempt}", row.verb);
                    assert_eq!(draft.op, *first_op, "{}: replay {attempt}", row.verb);
                    assert_eq!(&pointers, first_pointers, "{}: replay {attempt}", row.verb);
                }
            }
            assert_eq!(verb, row.verb);
            assert_eq!(draft.op, verbs::OP_WRITE);
        }
    }
    assert_eq!(
        mutating,
        VERB_COUNT - verbs::table().iter().filter(|r| r.read_only).count(),
        "every mutating row was walked"
    );
    assert!(mutating >= 32, "the pinned split has at least 32 mutations");
}

// ── the pinned document ─────────────────────────────────────────────────────────────────────────

/// The `openapi.json` this surface serves is 1.5.5's own bytes, but for `info.version`.
///
/// The document is the operator-facing contract, and every byte of it — key order, whitespace,
/// every field this crate has no opinion about — is passed through rather than re-serialised. The
/// one documented exception is `info.version`, which names the version actually running. Checked
/// against the pinned fixture as BYTES: a parsed comparison would agree with a document whose keys
/// had been reordered, which is exactly the change a client pinned to the bytes would notice.
#[test]
fn the_openapi_document_is_the_pinned_bytes_but_for_the_version() {
    let plane = AdminPlane::new();
    let config = TestConfig;
    let transport = TestTransport;
    let labels = Labels::new();
    let arena = TestArena;
    let ctx = test_ctx(&config, &transport, &labels, &arena);

    let fixture = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../testing/shadow-oracle/fixtures/openapi-1.5.5.json");
    let pinned = std::fs::read(&fixture).expect("the pinned document is readable");

    let mut facts = busbar_contract::bounded::Facts::new();
    facts
        .set(
            crate::meta::FACT_VERB,
            busbar_contract::bounded::FactValue::Str(verbs::VERB_OPENAPI_JSON),
        )
        .expect("one fact fits");
    let response = busbar_contract::plane::Response {
        ir: busbar_contract::bounded::Ir::new(&pinned, &[]),
        finish: busbar_contract::unit::FinishClass::Complete,
        facts,
    };
    let served = plane
        .encode_response(&response, None, &ctx)
        .expect("the document encodes");

    // The one substitution, and nothing else. The expected bytes are the pinned ones with the
    // CONTENT of `/info/version` replaced — located through the contract's own span grammar rather
    // than by a string search, so what is compared is the whole document and not a window of it.
    let version_span = match busbar_contract::spans::resolve_pointer(&pinned, "/info/version") {
        busbar_contract::spans::Resolved::Found(span) => span,
        other => panic!("the pinned document names no info.version: {other:?}"),
    };
    let mut expected = Vec::with_capacity(pinned.len());
    expected.extend_from_slice(&pinned[..version_span.start]);
    expected.extend_from_slice(format!(r#""{}""#, env!("CARGO_PKG_VERSION")).as_bytes());
    expected.extend_from_slice(&pinned[version_span.end..]);
    assert_eq!(
        served.as_slice(),
        expected.as_slice(),
        "the served document differs from the pinned one somewhere other than info.version"
    );
    // And the version really did change, so the comparison above is not vacuous.
    assert_ne!(served.as_slice(), pinned.as_slice());

    // A response the executing unit did not label as the document is passed through untouched.
    let unlabelled = busbar_contract::plane::Response {
        ir: busbar_contract::bounded::Ir::new(&pinned, &[]),
        finish: busbar_contract::unit::FinishClass::Complete,
        facts: busbar_contract::bounded::Facts::new(),
    };
    assert_eq!(
        plane
            .encode_response(&unlabelled, None, &ctx)
            .expect("passthrough")
            .as_slice(),
        pinned.as_slice()
    );
}

/// The seal a test uses to build a verified destination, which only the kernel builds for real.
struct TestUnitSeal;

impl busbar_contract::plugin::KernelSeal for TestUnitSeal {
    fn seal_origin(&self) -> &'static str {
        "busbar-plane-admin::tests"
    }
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
