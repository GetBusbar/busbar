//! Crate-level test suite.
//!
//! Inline (`#[cfg(test)] mod tests` from `lib.rs`) rather than an external `tests/` integration
//! crate, because the table-driven test below needs the crate's own `pub(crate)` verb table and
//! `find_verb` to state its expectations without hand-duplicating either.

use busbar_contract::bounded::Span;
use busbar_contract::bounded::{Arena, ArenaBudget, ArenaBytes, Labels};
use busbar_contract::control::{Control, ControlMeta, Rendering};
use busbar_contract::unit::{Clock, ConfigView, Ctx, SessionView, TransportView};
use busbar_contract::wire::Direction;

use crate::meta::FACT_VERB;
use crate::verbs::{self, VERB_COUNT};
use crate::AdminControl;

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

/// For every one of the 66 operations the pinned `openapi-1.5.5.json` fixture declares, the ONE
/// DECLARED CLAIM — `ControlMeta::ROUTES` — carries a row for it with the same `(operation,
/// read_only)` pair, the loop's resolve finds that row, and `verify` names that same operation. So
/// the fixture, the declaration and the running face cannot silently drift apart.
///
/// It reads the DECLARATION and not a crate-private table on purpose: the declaration is what a
/// composition root binds against and what every other reader of the matrix reads, so a proof that
/// walked the private side would be proving something nobody uses.
#[test]
fn the_declared_claim_matches_the_pinned_1_5_5_fixture_for_every_operation() {
    let fixture_path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../testing/shadow-oracle/fixtures/openapi-1.5.5.json");
    let text = std::fs::read_to_string(&fixture_path)
        .unwrap_or_else(|e| panic!("reading {}: {e}", fixture_path.display()));
    let doc: serde_json::Value = serde_json::from_str(&text).expect("fixture is valid json");
    let paths = doc["paths"]
        .as_object()
        .expect("fixture has a paths object");

    let surface = AdminControl::new();
    let config = TestConfig;
    let transport = TestTransport;
    let labels = Labels::new();
    let arena = TestArena;
    let declared = <AdminControl as ControlMeta>::ROUTES;

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
            let resolved = verbs::resolve(method, &concrete_path).unwrap_or_else(|| {
                panic!("the declaration carries no row for {method} {path_template} (as {concrete_path})")
            });
            // The row the loop resolved is a row of the DECLARATION, by identity.
            let row = declared
                .iter()
                .find(|r| r.method == method && r.path == path_template)
                .unwrap_or_else(|| panic!("{method} {path_template} is not a declared row"));
            assert_eq!(resolved.verb, row.operation);
            assert_eq!(resolved.read_only, row.read_only);

            if row.read_only {
                read_only_count += 1;
                assert_eq!(
                    resolved.op_class(),
                    verbs::OP_READ,
                    "{method} {path_template} should price as read-only"
                );
            } else {
                full_count += 1;
                assert_eq!(
                    resolved.op_class(),
                    verbs::OP_WRITE,
                    "{method} {path_template} should price as full"
                );
            }

            // The loop stamps the operation it resolved onto the unit, and `verify` names it back.
            let text = envelope(method, &concrete_path, "{}");
            let mut facts = busbar_contract::bounded::Facts::new();
            facts
                .set(
                    FACT_VERB,
                    busbar_contract::bounded::FactValue::Str(row.operation),
                )
                .expect("one fact fits");
            let unit = build_unit(&text, resolved.op_class(), facts);
            let ctx = test_ctx(&config, &transport, &labels, &arena);
            match surface.verify(&unit, &ctx) {
                busbar_contract::dest::DestinationFacts::KernelVerb { verb } => {
                    assert_eq!(verb, row.operation);
                }
                other => panic!("expected KernelVerb for {method} {path_template}, got {other:?}"),
            }
            // A control unit draws no priced dimension, for every one of the 66.
            assert_eq!(
                surface.admit(&unit, &ctx),
                busbar_contract::unit::AdmitFacts::default()
            );
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
    let mut names: Vec<&str> = all.iter().map(|e| e.operation).collect();
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
fn answering_a_refusal_renders_the_1_5_5_error_envelope_for_common_codes() {
    let surface = AdminControl::new();
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
        let text = envelope("GET", "/api/v1/admin/audit", "{}");
        let unit = build_unit(
            &text,
            verbs::OP_READ,
            busbar_contract::bounded::Facts::new(),
        );
        let rendered = surface
            .answer(&unit, Rendering::Refused(&refusal), &ctx)
            .expect("refusal renders");
        let text = core::str::from_utf8(rendered.as_slice()).expect("utf8");
        let parsed: serde_json::Value = serde_json::from_str(text).expect("valid json");
        assert_eq!(parsed["error"]["code"], code, "reason {reason:?}");
        assert!(parsed["error"]["message"].is_string());
        assert_eq!(parsed.as_object().unwrap().len(), 1);
        assert_eq!(parsed["error"].as_object().unwrap().len(), 2);
    }
}

/// `AdminControl` has no fields — asserted structurally, not just by comment. Every answer this
/// surface gives is a pure function of the declaration and the unit; a field here would be state
/// that survives between two units the loop believes are unrelated.
#[test]
fn the_admin_control_surface_carries_no_fields() {
    assert_eq!(std::mem::size_of::<AdminControl>(), 0);
}

/// One claim, over plain HTTP request/response. A control surface declares what it answers for as
/// data, and this is the transport half of that declaration; `ROUTES` is the other half.
#[test]
fn declares_exactly_one_claim_over_http() {
    let claims = <AdminControl as ControlMeta>::CLAIMS;
    assert_eq!(claims.len(), 1);
    assert_eq!(claims[0].transport, "http");
}

/// The declaration is the whole table: 66 pinned rows, 17 money-governance verbs, 5 ledger views,
/// and nothing built at first use. `ROUTES` is what the kind's open vocabulary IS, so a surface
/// whose declaration and whose lookup were two values would be a surface that answers one table and
/// declares another.
#[test]
fn the_declaration_is_the_table_the_lookup_reads() {
    let declared = <AdminControl as ControlMeta>::ROUTES;
    assert_eq!(declared.len(), VERB_COUNT);
    assert!(std::ptr::eq(declared, verbs::all_verbs()));
    for row in declared {
        let resolved = verbs::resolve(row.method, &concretize_path(row.path))
            .unwrap_or_else(|| panic!("{} {} declared and not resolvable", row.method, row.path));
        assert_eq!(resolved.verb, row.operation);
    }
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

/// An answer bigger than the whole arena still renders, byte for byte.
///
/// The admin surface's own `openapi.json` is over 350 KB and the arena is 4 KiB, so a rendering that
/// COPIED the body into the arena refused the single largest document the surface serves — and
/// every other answer over 4 KiB with it (a key listing, a config dump, an audit page). The body
/// already lives for the unit, so the answer borrows it and there is no budget left to exhaust.
#[test]
fn an_answer_larger_than_the_arena_renders_verbatim() {
    let surface = AdminControl::new();
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
    let text = envelope("GET", "/api/v1/admin/audit", "{}");
    let unit = build_unit(
        &text,
        verbs::OP_READ,
        busbar_contract::bounded::Facts::new(),
    );
    let facts = busbar_contract::bounded::Facts::new();
    let encoded = surface
        .answer(
            &unit,
            Rendering::Served {
                body: ArenaBytes::new(&big),
                facts: &facts,
            },
            &ctx,
        )
        .expect("a body the unit already owns needs no room in the arena");
    assert_eq!(encoded.as_slice(), big.as_slice());
    assert_eq!(
        arena.remaining(),
        busbar_contract::ARENA_BYTES,
        "the pass-through must not spend a byte of the arena"
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
