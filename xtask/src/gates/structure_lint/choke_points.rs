//! INVARIANT 4: THE CHOKE-POINT REGISTRY.
//!
//! A "choke point" is the single place a whole class of hazard is handled correctly ONCE, so a
//! future sibling cannot re-introduce the class by hand-rolling its own copy. The remediation
//! contract (`docs/testing.md`) says a finding with a sibling is not a bug, it is a MISSING CHOKE
//! POINT — and the fix is the choke point plus ONE class-level test.
//!
//! This is the machine-readable ledger of that contract: ONE declarative table, not N bespoke
//! scanners. Every row is a complete choke point, and adding the next one is a one-row addition —
//! no new scanner, no new loop, no new exit path.
//!
//! ## Four rules per row, four ledger rows
//!
//! The shell folded all four into one exit status, so "structure-lint failed" never said which:
//!
//! * [`ROW_ROW_INTEGRITY`] — a row is complete and its cells hold no separator. Under the shell a
//!   `|` leaking into a rule's ERE shifted every field right: the pattern got truncated, the
//!   allowed-exception list emptied, and the OWNER file started reporting itself as a bypass. Rust
//!   gives the fields their own types, so THAT parse cannot happen — the rule survives because the
//!   claim it makes ("every cell is filled, and none of them carries the separator the legacy row
//!   format and this gate's own parity translator both read") is still one a row can break.
//! * [`ROW_CLASS_TEST`] — the class-level test exists. A choke point whose one class test was
//!   deleted or renamed is a choke point nothing proves; the contract requires the pair.
//! * [`ROW_ALLOWED_PATH`] — every allowed-exception path exists. A path names the file that OWNS
//!   the correct implementation; if it moved, the ban silently widens to cover the owner's new home
//!   and the first thing that breaks is the owner reporting ITSELF as a bypass. Say it here, where
//!   the fix is one path, rather than there, where it reads as a real violation.
//! * [`ROW_SCAN_SET`] — the rule had a file left to scan. If the allow-list subtracts EVERY
//!   candidate, the rule is skipped in silence while the registry still prints "ok".
//! * [`ROW_BYPASS`] — the finding.
//!
//! ## Differently-enforced choke points
//!
//! A row with NO rules has no greppable bypass: it is enforced in the type system or at runtime
//! instead (D's router layer PANICS on an under-claim, and its class test fails on an over-claim).
//! Those rows are still listed here so the registry is a COMPLETE map of every choke point in the
//! tree — you should never have to ask "is there a choke point for X?" anywhere but this table.

use crate::ctx::Ctx;
use crate::ere::Ere;
use crate::gates::structure_lint::corpus::{Candidate, Corpus};
use crate::gates::structure_lint::roots::Addresses;
use crate::gates::structure_lint::{row, Findings, Tables};
use crate::ledger::Row;

pub const ROW_ROW_INTEGRITY: &str = "structure-lint:choke-point:row-integrity";
pub const ROW_CLASS_TEST: &str = "structure-lint:choke-point:class-test";
pub const ROW_ALLOWED_PATH: &str = "structure-lint:choke-point:allowed-path";
pub const ROW_SCAN_SET: &str = "structure-lint:choke-point:scan-set";
pub const ROW_BYPASS: &str = "structure-lint:choke-point:bypass";

/// One banned pattern that BYPASSES a choke point.
#[derive(Debug, Clone)]
pub struct BanRule {
    pub pattern: String,
    pub what: String,
    /// The files that OWN the correct implementation, exempt by name.
    pub allow: Vec<String>,
    /// The rule OPT-OUT for a shape that shares the pattern but not the hazard.
    pub unless: Option<String>,
}

impl BanRule {
    fn new(pattern: &str, what: &str, allow: &[String]) -> BanRule {
        BanRule {
            pattern: pattern.to_string(),
            what: what.to_string(),
            allow: allow.to_vec(),
            unless: None,
        }
    }

    fn unless(mut self, unless: &str) -> BanRule {
        self.unless = Some(unless.to_string());
        self
    }
}

#[derive(Debug, Clone)]
pub struct ChokeRow {
    /// The choke point's stable name, and the `docs/testing.md` anchor.
    pub id: String,
    /// The violation label printed on a bypass.
    pub tag: String,
    /// The module or API that OWNS the choke point.
    pub owner: String,
    /// `<path>::<fn>` — the ONE class-level test.
    pub class_test: String,
    /// The one-line "route through X" instruction printed with every violation.
    pub remedy: String,
    /// Empty for a differently-enforced choke point.
    pub rules: Vec<BanRule>,
    /// One line: why this class needs a single point of truth.
    pub why: String,
}

/// THE REGISTRY. Every ledgered exemption below is argued in the commit that added it; the argument
/// is kept in `docs/testing.md` rather than repeated per cell, and the exemption itself is data
/// here so a reader can see the whole map at once.
pub fn table(a: &Addresses) -> Vec<ChokeRow> {
    let core = &a.core;
    let substrate = &a.substrate;
    let mcp = &a.mcp;
    let a2a = &a.a2a;

    vec![
        // ── A ── persistence: one durable-write primitive. A fifth call site re-hand-rolling the
        //         atomic-write dance would silently drop whichever facet (parent fsync / temp
        //         cleanup / 0600 mode) its author forgot.
        //
        //         LEDGERED EXEMPTION, `fs::rename`, for the request-log sink's rotate-by-rename:
        //         rotation renames a file whose bytes are already fully on disk, and `fs::rename`
        //         moves a directory entry without touching them, so there is no torn state to
        //         protect. LEDGERED EXEMPTION, `sync_[ad]` and `create_dir_all`, for the WAL: it is
        //         a SIBLING durability primitive, not a consumer — a log appends into a segment
        //         that stays put and fsyncs it IN PLACE, and it performs the parent fsync itself.
        ChokeRow {
            id: "A-persistence".into(),
            tag: "DURABLE-BYPASS".into(),
            owner: "crates/api/src/durable.rs (durable::write / write_with; AppHandle::commit_and_swap)".into(),
            class_test: "crates/api/src/tests/durable_tests.rs::fault_matrix_returns_err_untouched_target_no_temp_leak".into(),
            remedy: "route through crate::durable::write".into(),
            rules: vec![
                BanRule::new(
                    r"fs::rename\(",
                    "hand-rolled rename-to-publish",
                    &["crates/api/src/durable.rs".into(), format!("{core}/export/file.rs")],
                ),
                BanRule::new(
                    "sync_[ad]",
                    "hand-rolled fsync durability (sync_all/sync_data)",
                    &[
                        "crates/api/src/durable.rs".into(),
                        "crates/busbar-unit-wal/src/backend.rs".into(),
                    ],
                ),
                BanRule::new(
                    r"fs::create_dir_all\(",
                    "directory creation that leaves the new entry non-durable",
                    &[
                        "crates/api/src/durable.rs".into(),
                        format!("{core}/test_support/mod.rs"),
                        "crates/busbar-unit-wal/src/backend.rs".into(),
                        // The plugin TARBALL FIXTURE's scratch directory (`tmp_plugin_dir`) carried
                        // a ledgered exemption here while it lived in `busbar-plugin-testkit`'s
                        // library (production-CLASSIFIED, because a helper another crate calls
                        // cannot sit behind `cfg(test)`). The dlopen battery came home beside the
                        // seat adapter (C1, 737c09412) and the fixture went back to
                        // `busbar_core::tests`, test-classified and exempt by that; the row went
                        // with it, because an allowed path that names no file widens the ban.
                    ],
                ),
            ],
            why: "persist-then-swap is only atomic if EVERY writer does the identical fsync/rename/cleanup dance".into(),
        },
        // ── B ── plugin FFI/ABI: one export boundary. A hand-written export skips the
        //         null-out-guard-before-alloc, the mandatory catch_unwind and the total status map.
        //
        //         The ABI spike plugin's ledgered exemption is RETIRED: that crate was deleted per
        //         docs/design/PLUGIN-TREE.md §7, so the SDK is once again the only file in the tree
        //         allowed to spell the export by hand.
        ChokeRow {
            id: "B-plugin-export".into(),
            tag: "EXPORT-BYPASS".into(),
            owner: "crates/plugin-sdk/src/boundary.rs (via the export_*_plugin! macro)".into(),
            class_test: "crates/plugin-sdk/tests/boundary_class.rs::null_out_pointer_never_leaks".into(),
            remedy: "define exports via export_*_plugin!, never by hand".into(),
            rules: vec![
                BanRule::new(
                    r"#\[(unsafe\()?no_mangle",
                    "hand-rolled #[no_mangle] export",
                    &["crates/plugin-sdk/src/lib.rs".into()],
                ),
                BanRule::new(
                    r"#\[(unsafe\()?export_name",
                    "hand-rolled #[export_name] export",
                    &["crates/plugin-sdk/src/lib.rs".into()],
                ),
            ],
            why: "an unwind or a written-then-failed out-param crossing the C ABI is UB, so no export may skip the wrapper".into(),
        },
        // ── C ── admin config mutation: one transaction. A raw lock re-opens
        //         lock-then-arbitrary-code; a swap outside the section IS the lost update the lock
        //         exists to prevent. `state.rs` DEFINES swap/commit_and_swap, so it is allowed
        //         alongside `txn.rs`.
        //
        //         LEDGERED EXEMPTION, `AppHandle::swap`, for the plane test kit: the hit is not a
        //         mutation SITE, it is the one line of the trait impl that FORWARDS to the inherent
        //         `swap` `state.rs` defines. A delegate adding no logic cannot lose an update the
        //         definition it calls does not already lose.
        ChokeRow {
            id: "C-config-mutation".into(),
            tag: "MUTATION-BYPASS".into(),
            owner: format!("{core}/admin/v1/json/txn.rs (config_transaction)"),
            class_test: format!("{core}/admin/v1/json/tests/txn_tests.rs::concurrent_transactions_never_lose_a_swap"),
            remedy: "route through json::txn::config_transaction".into(),
            rules: vec![
                BanRule::new(
                    "CONFIG_MUTATION_LOCK",
                    "names the config mutation lock",
                    &[format!("{core}/admin/v1/json/txn.rs")],
                ),
                BanRule::new(
                    r"commit_and_swap\(",
                    "direct commit_and_swap outside a transaction",
                    &[
                        format!("{core}/admin/v1/json/txn.rs"),
                        format!("{core}/state.rs"),
                    ],
                ),
                BanRule::new(
                    r"\.swap\(",
                    "direct swap on an AppHandle outside a transaction",
                    &[
                        format!("{core}/admin/v1/json/txn.rs"),
                        format!("{core}/state.rs"),
                    ],
                )
                .unless("Ordering::"),
                BanRule::new(
                    r"AppHandle::swap\(",
                    "direct AppHandle::swap outside a transaction",
                    &[
                        format!("{core}/admin/v1/json/txn.rs"),
                        format!("{core}/state.rs"),
                        format!("{core}/test_support/engine_kit.rs"),
                    ],
                ),
            ],
            why: "a fresh post-lock snapshot + one persist-then-swap is the only way concurrent mutations cannot lose an update".into(),
        },
        // ── D ── OpenAPI error taxonomy: one declaration the generator PROJECTS. Enforced
        //         differently — there is no pattern to ban, because the hazard is an endpoint
        //         emitting an ErrKind the declaration omits. The v1 router's recording layer PANICS
        //         on that under-claim at the moment of emission, and the class test fails on the
        //         mirror-image over-claim.
        ChokeRow {
            id: "D-openapi-taxonomy".into(),
            tag: "TAXONOMY-BYPASS".into(),
            owner: format!("{core}/admin/v1/contract/taxonomy.rs (declared_errors)"),
            class_test: format!("{core}/admin/tests/tests.rs::declared_error_set_is_exactly_what_the_handlers_emit"),
            remedy: "declare the ErrKind in contract::taxonomy::declared_errors".into(),
            rules: Vec::new(),
            why: "openapi.json must be a PROJECTION of one declaration, never a hand-maintained parallel list".into(),
        },
        // ── F ── the trusted-upstream trust LIFECYCLE: one plane-neutral machine, the pinned
        //         artifact a type parameter. Enforced differently — the hazard is not a call
        //         somebody hand-rolls, it is a plane's VOCABULARY leaking into the machine, after
        //         which the sibling plane can no longer parameterise it and writes a parallel copy.
        ChokeRow {
            id: "F-trust-lifecycle".into(),
            tag: "TRUST-PLANE-LEAK".into(),
            owner: format!("{substrate}/trust/mod.rs (Approval / TrustState / Drift, generic over PinnedArtifact)"),
            class_test: format!("{substrate}/trust/tests/genericity_tests.rs::the_lifecycle_names_no_plane_in_its_code"),
            remedy: "keep the plane noun in the artifact, the capability name or the caller, never in the lifecycle".into(),
            rules: Vec::new(),
            why: "the registry is being written generic on its FIRST build because there is no first use to extract a trait from later, so genericity has to be a test rather than a review habit".into(),
        },
        // ── G ── the same choke point from the OTHER side: a plane PARAMETERISES the lifecycle, it
        //         never re-declares one. F stops a plane's vocabulary leaking INTO the machine; this
        //         stops a copy of the machine leaking OUT into a plane.
        ChokeRow {
            id: "G-trust-parameterised".into(),
            tag: "TRUST-MACHINE-FORK".into(),
            owner: format!("{a2a}/pin.rs (CardPin, the artifact, plus the one plane-specific refusal)"),
            class_test: format!("{a2a}/tests/reuse_tests.rs::the_a2a_plane_declares_no_trust_state_of_its_own"),
            remedy: "supply an artifact implementing trust::PinnedArtifact; never re-declare TrustState, Drift, Approval or their verbs".into(),
            rules: Vec::new(),
            why: "two planes carrying two copies of one lifecycle disagree the first time either copy is fixed, and the disagreement surfaces as a registration dispatch serves while the operator view calls it quarantined".into(),
        },
        // ── H ── THE OPERATOR-AUTHORED ASK: one origin for the bytes busbar puts its own name to.
        //         Half one is the TYPE SYSTEM — `CallerAsk` lives in a private module with one
        //         constructor — which leaves `AskEntryCfg` itself as the way in. An `AskEntryCfg` is
        //         DESERIALISED from the operator's YAML; a hand-built one is how upstream text would
        //         reach `params` after half one closed every other door.
        ChokeRow {
            id: "H-operator-authored-ask".into(),
            tag: "ASK-NOT-OPERATOR-AUTHORED".into(),
            owner: format!("{mcp}/config.rs (AskEntryCfg, deserialised from operator YAML) + {mcp}/callerask.rs (the private `authored` module, sole constructor)"),
            class_test: format!("{mcp}/tests/callerask_tests.rs::the_asks_params_are_the_operators_bytes_and_nothing_else"),
            remedy: "let the operator write the ask: an AskEntryCfg is deserialised, never assembled".into(),
            rules: vec![BanRule::new(
                r"AskEntryCfg[[:space:]]*\{",
                "an AskEntryCfg built in code rather than deserialised from operator configuration",
                &[format!("{mcp}/config.rs")],
            )],
            why: "the text and schema a caller is shown when busbar asks it to confirm something must be bytes the operator wrote; the moment a value can flow from an upstream response into that ask, busbar is laundering an upstream demand for authority under its own name".into(),
        },
        // ── I ── THE ONE TRUST COMPARISON, negative half. `Approval::serves` is the single answer
        //         to "may this upstream serve this capability at this digest?" and the census keeps
        //         it single. This row stops the other shape of the same defect: a call site
        //         re-deriving the answer INLINE from the raw registration fields.
        ChokeRow {
            id: "I-trust-serve-derivation".into(),
            tag: "TRUST-COMPARISON-BYPASS".into(),
            owner: format!("{substrate}/trust/mod.rs (Approval::serves)"),
            class_test: format!("{mcp}/tests/trust_gate_tests.rs::the_routed_gate_answers_exactly_what_the_deleted_inline_decision_answered"),
            remedy: "ask crate::trust::Approval::serves; never re-derive the answer from the raw registration fields".into(),
            rules: vec![
                BanRule::new(
                    r"schema_hash[[:space:]]*\.is_some",
                    "an inline \"is there an approved digest?\" test",
                    &[],
                ),
                BanRule::new(
                    r"schema_hash[[:space:]]*\.is_none",
                    "an inline \"is there no approved digest?\" test",
                    &[],
                ),
                BanRule::new(
                    r"\.pin[[:space:]]*\.is_some",
                    "an inline \"is this upstream pinned?\" test",
                    &[format!("{substrate}/trust/mod.rs")],
                ),
                BanRule::new(
                    r"\.pin[[:space:]]*\.is_none",
                    "an inline \"is this upstream unpinned?\" test",
                    &[format!("{substrate}/trust/mod.rs")],
                ),
            ],
            why: "a second answer to \"may this serve?\" diverges from the first the moment either is fixed, and the divergence is discovered as an in-flight call that served after the operator revoked it".into(),
        },
        // ── J ── A DECISION MADE AT OPEN AND TRUSTED WHILE OPEN. Enforced differently for the
        //         reason F and G are: the hazard is a FIELD, not a call. MEASURED, which is why the
        //         row exists: a subscription re-read the CATALOGUE on every poll and carried the KEY
        //         from open, so a revoked approval bit within one poll and a key deleted for
        //         compromise did not bite at all.
        ChokeRow {
            id: "J-standing-permission".into(),
            tag: "OPEN-AND-TRUSTED".into(),
            owner: format!("{core}/trust/validate.rs (Standing::opened / still_permitted)"),
            class_test: format!("{mcp}/tests/subscribe_tests.rs::the_long_lived_response_holds_no_principal_it_resolved_at_open"),
            remedy: "hold a trust::validate::Standing and re-resolve the principal per frame; if you must freeze it, disclose the freeze beside the bound it trades on".into(),
            rules: Vec::new(),
            why: "a principal resolved at open and carried into a long-lived response is an identity a revocation cannot reach, and the failure is silent because everything else about the response is re-derived correctly".into(),
        },
        // ── E ── core route admission: one table, declared AT the mount. Enforced differently —
        //         `CoreRouter::route` is the only way core routes reach a router and it cannot be
        //         called without a declared bar, and the class test walks the resulting table.
        ChokeRow {
            id: "E-core-route-auth".into(),
            tag: "ROUTE-AUTH-BYPASS".into(),
            owner: format!("{core}/core_routes.rs (CoreRouter::route / CoreRouteTable::declared_auth)"),
            class_test: "crates/busbar-core/tests/plane_integration.rs::test_mcp_token_is_confined_to_the_mcp_plane".into(),
            remedy: "mount core routes through core_routes::CoreRouter::route, which takes the RouteAuth with the handler".into(),
            rules: Vec::new(),
            why: "a route whose admission bar lives in the middleware rather than at the mount is a bar that drifts, and a per-process bypass leaks onto planes that never mount the route".into(),
        },
    ]
}

pub fn finding_malformed(id: &str, why: &str) -> String {
    format!("MALFORMED-ROW: {id} — {why}")
}

pub fn finding_class_test(id: &str, detail: &str) -> String {
    format!("MISSING-CLASS-TEST: {id} — {detail}")
}

pub fn finding_allowed_path(id: &str, path: &str) -> String {
    format!("ALLOWED-PATH-MISSING: {id} — `{path}` does not exist; point the row at the owner's new home")
}

pub fn finding_zero_scan(id: &str) -> String {
    format!(
        "ZERO-SCAN: choke point {id} had NO file left to scan after its allow-list — the rule did \
         not run, and a rule that did not run is not a rule that passed"
    )
}

pub fn finding_bypass(tag: &str, rel: &str, line: usize, what: &str) -> String {
    format!("{tag}: {rel}:{line}: {what}")
}

/// The row-shape rule and the class-test rule, both of which are answerable without a corpus.
pub fn scan_class_tests(cx: &Ctx, t: &Tables, f: &mut Findings) {
    if t.choke_points.is_empty() {
        f.choke_row_integrity.push(finding_malformed(
            "the registry",
            "the choke-point table is EMPTY, so this invariant scanned nothing and would have \
             reported a pass",
        ));
    }
    for r in &t.choke_points {
        check_row_shape(r, f);
        check_class_test(cx, r, f);
    }
}

fn check_row_shape(r: &ChokeRow, f: &mut Findings) {
    let cells: [(&str, &str); 5] = [
        ("id", &r.id),
        ("tag", &r.tag),
        ("owner", &r.owner),
        ("classtest", &r.class_test),
        ("why", &r.why),
    ];
    for (name, value) in cells {
        if value.trim().is_empty() {
            f.choke_row_integrity.push(finding_malformed(
                &r.id,
                &format!("the `{name}` cell is empty"),
            ));
        } else if value.contains('|') {
            f.choke_row_integrity.push(finding_malformed(
                &r.id,
                &format!(
                    "the `{name}` cell carries a literal `|`, the row separator this gate's own \
                     ledger rows and its legacy translator both read"
                ),
            ));
        }
    }
    for rule in &r.rules {
        if rule.pattern.trim().is_empty() || rule.what.trim().is_empty() {
            f.choke_row_integrity.push(finding_malformed(
                &r.id,
                "a ban rule has no pattern or no description",
            ));
        }
        if let Err(e) = Ere::new(&rule.pattern) {
            f.choke_row_integrity.push(finding_malformed(
                &r.id,
                &format!("its ban pattern does not compile: {e}"),
            ));
        }
    }
}

fn check_class_test(cx: &Ctx, r: &ChokeRow, f: &mut Findings) {
    let Some((file, func)) = r.class_test.rsplit_once("::") else {
        f.choke_row_integrity.push(finding_malformed(
            &r.id,
            "the classtest cell is not `<path>::<fn>`",
        ));
        return;
    };
    let Ok(text) = cx.read(file) else {
        f.choke_class_test.push(finding_class_test(
            &r.id,
            &format!("{file} does not exist ({})", r.why),
        ));
        return;
    };
    let decl = Ere::new(&format!(r"fn[[:space:]]+{func}[[:space:]]*\("))
        .expect("a class-test name is an identifier");
    if !text.lines().any(|l| decl.is_match(l)) {
        f.choke_class_test.push(finding_class_test(
            &r.id,
            &format!("{file} has no `fn {func}` ({})", r.why),
        ));
    }
}

pub fn scan(cx: &Ctx, corpus: &Corpus, t: &Tables, f: &mut Findings) {
    scan_class_tests(cx, t, f);

    for r in &t.choke_points {
        for rule in &r.rules {
            // An allowed-exception path names the file that OWNS the correct implementation.
            for p in &rule.allow {
                if !cx.exists(p) {
                    f.choke_allowed_path.push(finding_allowed_path(&r.id, p));
                }
            }
            let files: Vec<&Candidate> = corpus
                .files
                .iter()
                .filter(|c| !rule.allow.iter().any(|p| p == &c.rel))
                .collect();
            if files.is_empty() {
                f.choke_scan_set.push(finding_zero_scan(&r.id));
                continue;
            }
            // A pattern that does not compile is already a row-integrity finding above; scanning
            // with it would turn that loud failure into the silence this gate exists to refuse.
            let Ok(pat) = Ere::new(&rule.pattern) else {
                continue;
            };
            let unless = rule.unless.as_deref().and_then(|u| Ere::new(u).ok());
            for c in files {
                for line in c.code_lines() {
                    if unless.as_ref().is_some_and(|u| u.is_match(&line.raw)) {
                        continue;
                    }
                    if pat.is_match(&line.raw) {
                        f.choke_bypass
                            .push(finding_bypass(&r.tag, &c.rel, line.no, &rule.what));
                    }
                }
            }
        }
    }
}

pub fn rows(f: &Findings) -> Vec<Row> {
    vec![
        row(
            ROW_ROW_INTEGRITY,
            "every registry row is complete and its patterns compile",
            "a registry row is incomplete, or carries a separator, or will not compile",
            &f.choke_row_integrity,
        ),
        row(
            ROW_CLASS_TEST,
            "every choke point's one class-level test is present",
            "a choke point's class test was deleted or renamed, so nothing proves it",
            &f.choke_class_test,
        ),
        row(
            ROW_ALLOWED_PATH,
            "every allowed-exception path names a file that exists",
            "an allowed-exception path moved, so the ban silently widened onto the owner",
            &f.choke_allowed_path,
        ),
        row(
            ROW_SCAN_SET,
            "every ban had a file left to scan after its allow-list",
            "a ban's allow-list subtracted every candidate, so the rule did not run",
            &f.choke_scan_set,
        ),
        row(
            ROW_BYPASS,
            "no production file hand-rolls a bypass of a registered choke point",
            "a hazard class was re-implemented outside its one owner",
            &f.choke_bypass,
        ),
    ]
}
