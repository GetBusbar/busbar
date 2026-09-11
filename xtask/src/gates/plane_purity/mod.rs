//! `cargo xtask gate plane-purity` — THE ENFORCEMENT GATE FOR THE PLANE ABI, converted from
//! `scripts/plane-purity-lint.sh` plus `scripts/g6-freeze-witness.sh`.
//!
//! WHY IT EXISTS. A protocol plane must be a self-contained plugin merely compiled in for
//! convenience: turn its feature off, or delete its crate, and the NEUTRAL crates must still
//! compile and serve no protocol. That was the requirement on day one and it eroded, for one
//! reason above all — THERE WAS NO GATE. A boundary with no instrument watching it drifts.
//!
//! THE INVARIANT. The plane ABI is the ONE surface across which core and a plane communicate.
//! Every side channel is a violation to REMOVE, not to gate, and each is its own ledger row:
//!
//! | row | the side channel |
//! | --- | --- |
//! | [`ROW_PATH_INCLUDE`] | a `#[path]` or `include!` dual-compile of plane source into a neutral crate |
//! | [`ROW_SYMBOL`] | a `busbar_<plane>::` path, `extern crate`, or `use … as` alias |
//! | [`ROW_TYPE`] | a plane record type, or any plane-/dialect-prefixed type name |
//! | [`ROW_KEY`] | a concrete plane key as a bare token |
//! | [`ROW_DIALECT`] | one of the six dialect names as a bare token |
//! | [`ROW_BACKWARDS`] | a plane crate reaching BACK into `busbar_core::` implementation |
//! | [`ROW_FREEZE`] | core still naming a concrete LLM-family IR type (the G6 freeze witness) |
//!
//! and two rows in front of all of them, because **the gate cannot pass by scanning nothing**:
//! [`ROW_ROOTS`] (a listed root that is not on disk is scanned as zero files, and zero is the
//! passing answer to every ban) and [`ROW_DENOMINATOR`] (a scan that opened zero `.rs` files
//! reports zero violations, which is indistinguishable from a clean tree).
//!
//! THE FROZEN-WIRE CARVE-OUT is the one documented exception and it is per-line, not per-rule: a
//! neutral source line may carry `// plane-purity: frozen-wire <reason>` and be exempt from the
//! VOCABULARY rows (TYPE/KEY/DIALECT) only. It never launders PATH-INCLUDE or SYMBOL, a trailing
//! pragma never bleeds onto the next line, and **a marker with no reason is not a pragma** — the
//! reason is the entire reviewability of the carve-out. All four properties have their own selftest
//! case below.

pub mod freeze;
pub mod scanner;
pub mod strict;

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use crate::ctx::{Ctx, Edit, Overlay, SourceFile, WalkSpec};
use crate::gates::{prove_green, prove_red, Case, Expect, Gate, LegacyRun, Report};
use crate::ledger::{Row, Verdict};
use crate::planes;

use scanner::{Hit, Mode, Scope};

pub const ROW_ROOTS: &str = "plane-purity:roots";
pub const ROW_DENOMINATOR: &str = "plane-purity:scan-denominator";
pub const ROW_PATH_INCLUDE: &str = "plane-purity:path-include";
pub const ROW_SYMBOL: &str = "plane-purity:symbol";
pub const ROW_TYPE: &str = "plane-purity:type";
pub const ROW_KEY: &str = "plane-purity:key";
pub const ROW_DIALECT: &str = "plane-purity:dialect";
pub const ROW_BACKWARDS: &str = "plane-purity:backwards";
pub const ROW_FREEZE: &str = "plane-purity:core-llm-family-freeze";

/// The row id for one strict category, e.g. `plane-purity-strict:category:SYMBOL`.
pub fn strict_category_row(category: &str) -> String {
    format!("plane-purity-strict:category:{category}")
}

/// The row id for one plane crate's test-reach, e.g. `plane-purity-strict:test-reach:llm`.
pub fn strict_reach_row(key: &str) -> String {
    format!("plane-purity-strict:test-reach:{key}")
}

/// Where a caller OUTSIDE this process asks for the hit artefact to be written.
///
/// The construction gate used to be that caller, through `scripts/construction-gate.sh`; it is now
/// linked into the same binary and reads [`check_hits_artefact`] directly, so nothing in the tree
/// sets this today. The env var stays because it is the seam for a consumer that CANNOT be a
/// function call — a script, another process — and because the two paths render the same bytes
/// from the same derivation, which is what keeps them from drifting if one appears.
pub const HITS_OUT_ENV: &str = "PLANE_PURITY_HITS_OUT";

/// The core walk's own denominator floor. The two big walks carry theirs in [`ROW_DENOMINATOR`]
/// instead of in the [`WalkSpec`], so the floor is a ROW a selftest can plant against rather than
/// an error the run reports once and the ledger never names.
const CORE_FLOOR: usize = 1;

/// The measurement both the `--check` gate and the `--strict` ratchet are built from: one walk,
/// one scanner, four passes, and the accounting the zero-file guard reports.
pub struct Measurement {
    pub neutral_roots: Vec<String>,
    pub plane_roots: Vec<String>,
    pub neutral_files: usize,
    pub plane_files: usize,
    /// Forward hits in PRODUCTION scope — the scan `--check` judges.
    pub prod_forward: Vec<Hit>,
    /// Forward hits in TEST scope — what `--strict` adds, never double-counted against the above.
    pub test_forward: Vec<Hit>,
    pub prod_reverse: Vec<Hit>,
    pub test_reverse: Vec<Hit>,
}

impl Measurement {
    /// The `--check` hit list, in the order the shell wrote it: the forward scan, then the reverse.
    pub fn check_hits(&self) -> Vec<&Hit> {
        self.prod_forward.iter().chain(&self.prod_reverse).collect()
    }

    /// The `#SCAN` provenance line the artefact is prefixed with, so the downstream consumer of the
    /// hit COUNT can tell "clean" from "scanned nothing" without re-deriving the file list.
    pub fn scan_line(&self) -> String {
        format!(
            "#SCAN\tneutral_files={}\tneutral_roots={}\tplane_files={}\tplane_roots={}",
            self.neutral_files,
            self.neutral_roots.len(),
            self.plane_files,
            self.plane_roots.len()
        )
    }
}

/// THE DELEGATED SCAN'S ARTEFACT: the `#SCAN` denominator line, then one TSV row per hit.
///
/// One derivation with two readers. `run` writes it to [`HITS_OUT_ENV`] for a caller outside this
/// process, and the construction gate's `neutral-no-dialect` rule — which does not re-implement
/// dialect policy, it reads this gate's answer — asks [`check_hits_artefact`] for the same bytes
/// without a subprocess. A count read out of a file and a count read out of a return value must be
/// the same count, so they come from the same place.
pub fn hits_artefact(m: &Measurement, hits: &[&Hit]) -> String {
    let mut text = m.scan_line();
    text.push('\n');
    for h in hits {
        text.push_str(&h.tsv());
        text.push('\n');
    }
    text
}

/// The `--check` hit artefact for `cx`, derived in this process.
///
/// This is what replaced `scripts/plane-purity-lint.sh`. The construction gate used to shell out to
/// that script and read the file it left behind; the script is gone, this gate is what it became,
/// and a gate that is already linked into the same binary does not need to be spawned to be asked.
/// The failure mode it removes is the one this rule actually hit: a delegated scan whose SCRIPT had
/// been deleted reported "no hits file" — which is indistinguishable, to a reader of the row, from
/// a scan that ran and found nothing.
pub fn check_hits_artefact(cx: &Ctx) -> Result<String, String> {
    let m = measure(cx)?;
    let hits = m.check_hits();
    Ok(hits_artefact(&m, &hits))
}

/// Every listed root that is not present. A listed root that does not exist is scanned as zero
/// files, and zero is the passing answer to every ban — so a crate that is legitimately gone leaves
/// the set by being DELETED from [`crate::planes`] in a reviewed diff, never by its directory
/// quietly ceasing to exist under a stale entry.
fn missing_roots(cx: &Ctx, roots: &[String]) -> Vec<String> {
    roots.iter().filter(|r| !cx.exists(r)).cloned().collect()
}

fn measure(cx: &Ctx) -> Result<Measurement, String> {
    let neutral_roots = planes::neutral_src_roots();
    // THE PLANE POPULATION COMES FROM THE KIND TABLE, not from a list in `planes`: see
    // `kind_isolation::plane_kind_src_roots`. `busbar-plane-*` was plane-kind and in no scan, and
    // after the dialect split every `busbar-plane-<p>-<d>` crate would have had to be added by hand
    // — a plane crate nobody added is a plane crate the backwards rule scans zero files of.
    let plane_roots = crate::gates::kind_isolation::plane_kind_src_roots(cx)?;
    let present: Vec<String> = neutral_roots
        .iter()
        .filter(|r| cx.exists(r))
        .cloned()
        .collect();
    let neutral: Vec<SourceFile> = cx
        .walk(&WalkSpec::new(present).ext("rs"))
        .map_err(|e| e.to_string())?;
    let present: Vec<String> = plane_roots
        .iter()
        .filter(|r| cx.exists(r))
        .cloned()
        .collect();
    let plane: Vec<SourceFile> = cx
        .walk(&WalkSpec::new(present).ext("rs"))
        .map_err(|e| e.to_string())?;
    Ok(Measurement {
        neutral_files: neutral.len(),
        plane_files: plane.len(),
        prod_forward: scanner::scan(&neutral, Mode::Forward, Scope::Production),
        test_forward: scanner::scan(&neutral, Mode::Forward, Scope::Test),
        prod_reverse: scanner::scan(&plane, Mode::Reverse, Scope::Production),
        test_reverse: scanner::scan(&plane, Mode::Reverse, Scope::Test),
        neutral_roots,
        plane_roots,
    })
}

/// The category rows, built from a hit list. Shared by [`PlanePurityGate::run`] and by the parity
/// adapter, which builds the SAME rows out of the legacy script's own hit artefact — so identical
/// rows means identical HIT SETS, not two prose parsers agreeing with each other.
fn category_rows(hits: &[&Hit]) -> Vec<Row> {
    let mut out = Vec::new();
    for (category, id) in [
        ("PATH-INCLUDE", ROW_PATH_INCLUDE),
        ("SYMBOL", ROW_SYMBOL),
        ("TYPE", ROW_TYPE),
        ("KEY", ROW_KEY),
        ("DIALECT", ROW_DIALECT),
        ("BACKWARDS", ROW_BACKWARDS),
    ] {
        let sites: Vec<String> = hits
            .iter()
            .filter(|h| h.category == category)
            .map(|h| h.site())
            .collect();
        let detail = if sites.is_empty() {
            "0 hit(s)".to_string()
        } else {
            format!("{} hit(s): {}", sites.len(), sites.join(" "))
        };
        out.push(if sites.is_empty() {
            Row::pass(id, category_title(category), detail)
        } else {
            Row::fail(id, category_title(category), detail)
        });
    }
    out
}

fn category_title(category: &str) -> &'static str {
    match category {
        "PATH-INCLUDE" => "no plane source is dual-compiled into a neutral crate",
        "SYMBOL" => "no neutral crate binds a plane crate under any spelling",
        "TYPE" => "no neutral crate names a plane or dialect type",
        "KEY" => "no neutral crate names a concrete plane key",
        "DIALECT" => "no neutral crate names a dialect",
        "KEY-SEGMENT" => "no neutral crate names a plane key inside a longer identifier",
        _ => "no plane crate reaches back into busbar_core:: implementation",
    }
}

fn roots_row(neutral_roots: usize, plane_roots: usize, missing: &[String]) -> Row {
    let detail = format!("neutral_roots={neutral_roots} plane_roots={plane_roots}");
    if missing.is_empty() {
        Row::pass(
            ROW_ROOTS,
            "every listed source root is present on disk",
            detail,
        )
    } else {
        Row::fail(
            ROW_ROOTS,
            "a listed source root is not present on disk",
            format!(
                "{detail} — missing: {}. A listed root that does not exist is scanned as ZERO \
                 files, and zero passes every ban; delete the entry in a reviewed diff instead.",
                missing.join(" ")
            ),
        )
    }
}

fn denominator_row(neutral_files: usize, plane_files: usize) -> Row {
    let detail = format!("neutral_files={neutral_files} plane_files={plane_files}");
    if neutral_files == 0 || plane_files == 0 {
        Row::fail(
            ROW_DENOMINATOR,
            "the scan opened files to answer with",
            format!(
                "{detail} — a scan of zero files reports zero violations, which is \
                 indistinguishable from a clean tree"
            ),
        )
    } else {
        Row::pass(
            ROW_DENOMINATOR,
            "the scan opened files to answer with",
            detail,
        )
    }
}

fn freeze_row(f: &freeze::Freeze) -> Row {
    let detail = format!("count={} defs={} uprefs={}", f.count, f.defs, f.uprefs);
    if f.count == 0 {
        Row::pass(
            ROW_FREEZE,
            "core names zero concrete LLM-family IR type",
            detail,
        )
    } else {
        Row::fail(
            ROW_FREEZE,
            "core still names a concrete LLM-family IR type",
            format!("{detail} — the freeze is not met while core reads the request as a family"),
        )
    }
}

// ── the `--check` gate ────────────────────────────────────────────────────────────────────────

pub struct PlanePurityGate;

impl Gate for PlanePurityGate {
    fn name(&self) -> &'static str {
        "plane-purity"
    }

    fn owed(&self) -> Vec<String> {
        [
            ROW_ROOTS,
            ROW_DENOMINATOR,
            ROW_PATH_INCLUDE,
            ROW_SYMBOL,
            ROW_TYPE,
            ROW_KEY,
            ROW_DIALECT,
            ROW_BACKWARDS,
            ROW_FREEZE,
        ]
        .iter()
        .map(|s| (*s).to_string())
        .collect()
    }

    fn run(&self, cx: &Ctx) -> Verdict {
        let m = match measure(cx) {
            Ok(m) => m,
            Err(e) => return Verdict::of(unscannable(&self.owed(), &e)),
        };
        let missing: Vec<String> = missing_roots(cx, &m.neutral_roots)
            .into_iter()
            .chain(missing_roots(cx, &m.plane_roots))
            .collect();
        let denominator = denominator_row(m.neutral_files, m.plane_files);
        let scanned_nothing = denominator.status != crate::ledger::Status::Pass;
        let mut rows = vec![
            roots_row(m.neutral_roots.len(), m.plane_roots.len(), &missing),
            denominator,
        ];
        let hits = m.check_hits();
        // A CATEGORY ROW OVER A ZERO-FILE SCAN IS NOT A PASS. Every rule here answers a question
        // about a file list, and every one of those answers is "clean" when the list is empty.
        if scanned_nothing {
            for id in [
                ROW_PATH_INCLUDE,
                ROW_SYMBOL,
                ROW_TYPE,
                ROW_KEY,
                ROW_DIALECT,
                ROW_BACKWARDS,
            ] {
                rows.push(Row::fail(
                    id,
                    "the rule was not applied to anything",
                    format!(
                        "neutral_files={} plane_files={} — zero hits over zero files is not a \
                         clean tree",
                        m.neutral_files, m.plane_files
                    ),
                ));
            }
        } else {
            rows.extend(category_rows(&hits));
        }

        // The hit artefact, for the one delegated consumer that reads hit COUNTS out of it. Written
        // only when asked for by name, and prefixed with its own denominator.
        if let Some(path) = std::env::var_os(HITS_OUT_ENV) {
            let _ = std::fs::write(PathBuf::from(path), hits_artefact(&m, &hits));
        }

        match cx.walk(
            &WalkSpec::new([freeze::CORE_ROOT])
                .ext("rs")
                .min_files(CORE_FLOOR),
        ) {
            Ok(core) => rows.push(freeze_row(&freeze::measure(&core))),
            Err(e) => rows.push(Row::fail(
                ROW_FREEZE,
                "core could not be scanned for concrete LLM-family types",
                e.to_string(),
            )),
        }
        Verdict::of(rows)
    }

    fn selftest(&self, cx: &Ctx) -> Report {
        let mut report = Report::new();
        let owed: Vec<String> = self.owed();
        let all: Vec<&str> = owed.iter().map(String::as_str).collect();
        report.push(prove_green(
            cx,
            self,
            "the neutral crates are clean and core names no LLM family",
            &all,
        ));

        // Every RED case plants into the FIRST neutral root, so the plant is inside the walk the
        // gate actually performs rather than beside it.
        let neutral = planes::neutral_src_roots();
        let plant_at = format!("{}/planted_plane_purity.rs", neutral[0]);
        let plane_at = format!("{}/planted_plane_purity.rs", planes::plane_src_roots()[0]);

        report.push(create(
            cx,
            self,
            "a #[path] dual-compile of plane source into a neutral crate",
            &[ROW_PATH_INCLUDE],
            &plant_at,
            "#[path = \"../../../busbar-mcp/src/witness.rs\"]\nmod mcp_witness;\n",
            &[ROW_PATH_INCLUDE, "planted_plane_purity.rs:1"],
        ));

        // The OTHER dual-compile spelling. It used to fall through to the vocabulary rules, which
        // sit BELOW the pragma gate — so one trailing comment spliced a plane's source into a
        // neutral crate under a clean report. The pragma is on the fixture on purpose.
        report.push(create(
            cx,
            self,
            "an include! dual-compile, carrying a pragma that must not launder it",
            &[ROW_PATH_INCLUDE],
            &plant_at,
            "include!(\"../../../busbar-voice/src/witness.rs\"); // plane-purity: frozen-wire abuse\n",
            &[ROW_PATH_INCLUDE, "planted_plane_purity.rs:1"],
        ));

        report.push(create(
            cx,
            self,
            "a busbar_<plane>:: symbol path in a neutral crate",
            &[ROW_SYMBOL],
            &plant_at,
            "use busbar_a2a::TaskThing;\n",
            &[ROW_SYMBOL, "planted_plane_purity.rs:1"],
        ));

        report.push(create(
            cx,
            self,
            "the two symbol spellings that carry no :: on the line",
            &[ROW_SYMBOL],
            &plant_at,
            "extern crate busbar_mcp;\nuse busbar_a2a as plane_alias;\n",
            &[ROW_SYMBOL, "planted_plane_purity.rs:2"],
        ));

        report.push(create(
            cx,
            self,
            "a plane record type in a neutral crate",
            &[ROW_TYPE],
            &plant_at,
            "pub struct McpFoo;\n",
            &[ROW_TYPE, "planted_plane_purity.rs:1"],
        ));

        report.push(create(
            cx,
            self,
            "the screaming-acronym type spellings",
            &[ROW_TYPE],
            &plant_at,
            "pub struct MCPCallRecord;\npub struct OpenAIClient;\npub struct LLMRouter;\n",
            &[ROW_TYPE, "planted_plane_purity.rs:3"],
        ));

        report.push(create(
            cx,
            self,
            "a bare plane key as a token in a neutral crate",
            &[ROW_KEY],
            &plant_at,
            "fn route() { let plane_key = \"mcp\"; }\n",
            &[ROW_KEY, "planted_plane_purity.rs:1"],
        ));

        report.push(create(
            cx,
            self,
            "a dialect name as a token in a neutral crate",
            &[ROW_DIALECT],
            &plant_at,
            "fn d() { let dialect = \"anthropic\"; }\n",
            &[ROW_DIALECT, "planted_plane_purity.rs:1"],
        ));

        // A MARKER WITH NO REASON IS NOT A PRAGMA. "One pragma per excused line, each justifying
        // itself in the diff" is the entire reviewability of the carve-out; a bare marker excusing
        // a line names no contract and cannot be reviewed. The reasoned form of the SAME line is
        // the green control immediately after, so this case proves the reason, not the tokens.
        report.push(create(
            cx,
            self,
            "a frozen-wire marker with no reason excuses nothing",
            &[ROW_KEY, ROW_TYPE],
            &plant_at,
            "pub(crate) mcp: McpEndpointSection, // plane-purity: frozen-wire\n",
            &[ROW_KEY, ROW_TYPE],
        ));

        report.push(green_with(
            cx,
            self,
            "a reasoned frozen-wire pragma exempts the vocabulary rows on its line only",
            &[ROW_KEY, ROW_TYPE, ROW_DIALECT],
            &plant_at,
            "pub(crate) mcp: McpEndpointSection, // plane-purity: frozen-wire DeployCfg mcp: key \
             + snapshot type\n",
        ));

        report.push(create(
            cx,
            self,
            "a plane crate reaching back into busbar_core:: implementation",
            &[ROW_BACKWARDS],
            &plane_at,
            "use busbar_core::internal::foo;\nextern crate busbar_core;\nuse busbar_core as c;\n",
            &[ROW_BACKWARDS, "planted_plane_purity.rs:3"],
        ));

        // THE POPULATION IS THE KIND TABLE'S, AND THIS IS THE CRATE THAT PROVES IT. `busbar-plane-*`
        // is plane-kind by every rule the tree has and was in NO scan: the literal root list held
        // the four `busbar-<key>` crates and the four codec halves, so a backwards reach planted
        // here was scanned by nobody and the gate said "no plane crate reaches back". Delete the
        // kind-derived population and this case goes green while every case above stays red — which
        // is the whole of the difference, and the shape the dialect split multiplies by one crate
        // per dialect.
        report.push(create(
            cx,
            self,
            "a backwards reach in a busbar-plane-* crate, which no literal root list scanned",
            &[ROW_BACKWARDS],
            "crates/busbar-plane-mcp/src/planted_plane_kind.rs",
            "use busbar_core::internal::foo;\n",
            &[ROW_BACKWARDS, "planted_plane_kind.rs:1"],
        ));

        // The two guards in front of every rule above, because each of them answers "clean" about
        // a tree it never read. They get separate fixtures on purpose: a root that VANISHED and a
        // root that is present but EMPTY are different failures, and a single case that happened to
        // trip both would let either one be deleted with the selftest still green.
        let mut ov = Overlay::new();
        ov.remove(&neutral[0]);
        report.push(prove_red(
            cx,
            self,
            "a listed neutral root that is not on disk",
            &[ROW_ROOTS],
            ov,
            &[ROW_ROOTS, &neutral[0]],
        ));

        let mut ov = Overlay::new();
        for root in neutral.iter().chain(planes::plane_src_roots().iter()) {
            for f in cx
                .walk(&WalkSpec::new([root.clone()]).ext("rs"))
                .unwrap_or_default()
            {
                ov.remove(&f.rel);
            }
        }
        report.push(prove_red(
            cx,
            self,
            "roots that are present but opened no files",
            &[ROW_DENOMINATOR],
            ov,
            &[ROW_DENOMINATOR, "neutral_files=0"],
        ));

        // Core still naming a concrete LLM-family IR type.
        report.push(create(
            cx,
            self,
            "core names a concrete LLM-family IR type",
            &[ROW_FREEZE],
            &format!("{}/planted_freeze_witness.rs", freeze::CORE_ROOT),
            "pub fn f(_: IrStreamEvent) {}\n",
            // The row's detail is the COUNTED table and nothing else, because that is all the
            // legacy witness prints and `--parity` compares this row against it. A named site here
            // would be a row the legacy half cannot produce, i.e. a parity diff by construction.
            &[ROW_FREEZE, "count=1"],
        ));

        report
    }

    fn has_legacy_adapter(&self) -> bool {
        true
    }

    fn legacy_companions(&self) -> Vec<Vec<String>> {
        vec![vec!["scripts/g6-freeze-witness.sh".to_string()]]
    }

    fn legacy_env(&self, scratch: &Path) -> Vec<(String, String)> {
        vec![(
            HITS_OUT_ENV.to_string(),
            scratch.join("legacy-hits.tsv").display().to_string(),
        )]
    }

    fn legacy_rows(&self, _cx: &Ctx, runs: &[LegacyRun]) -> Option<Result<Vec<Row>, String>> {
        Some(legacy_check_rows(runs))
    }
}

/// Build the legacy half's rows out of what the two scripts MEASURED: the hit artefact (with its
/// `#SCAN` denominator line) and the freeze witness's counted table. Never out of their prose.
fn legacy_check_rows(runs: &[LegacyRun]) -> Result<Vec<Row>, String> {
    let [lint, witness] = runs else {
        return Err(format!(
            "parity: expected the lint and the freeze witness, got {} run(s)",
            runs.len()
        ));
    };
    let path = lint.scratch.join("legacy-hits.tsv");
    let text = std::fs::read_to_string(&path).map_err(|e| {
        format!(
            "parity: {} wrote no hit artefact to {} ({e}). stderr: {}",
            lint.argv.join(" "),
            path.display(),
            lint.stderr.trim()
        )
    })?;

    let mut neutral_files = None;
    let mut neutral_roots = None;
    let mut plane_files = None;
    let mut plane_roots = None;
    let mut hits: Vec<Hit> = Vec::new();
    for line in text.lines() {
        let cols: Vec<&str> = line.split('\t').collect();
        if cols.first() == Some(&"#SCAN") {
            for field in &cols[1..] {
                let Some((k, v)) = field.split_once('=') else {
                    continue;
                };
                let n = v.parse::<usize>().ok();
                match k {
                    "neutral_files" => neutral_files = n,
                    "neutral_roots" => neutral_roots = n,
                    "plane_files" => plane_files = n,
                    "plane_roots" => plane_roots = n,
                    _ => {}
                }
            }
            continue;
        }
        if cols.len() < 3 {
            continue;
        }
        let category = scanner::CATEGORIES
            .iter()
            .find(|c| **c == cols[0])
            .ok_or_else(|| format!("parity: the legacy hit list carried category `{}`", cols[0]))?;
        let (file, line_no) = cols[1]
            .rsplit_once(':')
            .ok_or_else(|| format!("parity: the legacy hit list carried site `{}`", cols[1]))?;
        hits.push(Hit {
            category,
            file: file.to_string(),
            line: line_no.parse().unwrap_or(0),
            code: cols[2].to_string(),
        });
    }

    let (Some(nf), Some(nr), Some(pf), Some(pr)) =
        (neutral_files, neutral_roots, plane_files, plane_roots)
    else {
        return Err(format!(
            "parity: the legacy hit artefact carried no complete #SCAN provenance line, so the \
             legacy side has no denominator to compare. stderr: {}",
            lint.stderr.trim()
        ));
    };

    // The legacy script ABORTS before writing the artefact when a root is missing, so an artefact
    // that exists at all is a run whose roots were all present. The rows say so explicitly rather
    // than leaving the reader to infer it.
    let mut rows = vec![roots_row(nr, pr, &[]), denominator_row(nf, pf)];
    rows.extend(category_rows(&hits.iter().collect::<Vec<_>>()));
    rows.push(freeze_row(&parse_freeze_witness(witness)?));
    Ok(rows)
}

/// The freeze witness's three counted lines. It has no artefact, so its own table is the
/// measurement; the numbers are read positionally off the labels it prints.
fn parse_freeze_witness(run: &LegacyRun) -> Result<freeze::Freeze, String> {
    let mut count = None;
    let mut defs = None;
    let mut uprefs = None;
    for line in run.stdout.lines() {
        let Some((label, value)) = line.rsplit_once(':') else {
            continue;
        };
        let Ok(n) = value.trim().parse::<usize>() else {
            continue;
        };
        if label.contains("references to concrete LLM-family IR types") {
            count = Some(n);
        } else if label.contains("in ir/") {
            defs = Some(n);
        } else if label.contains("OUTSIDE ir/") {
            uprefs = Some(n);
        }
    }
    let (Some(count), Some(defs), Some(uprefs)) = (count, defs, uprefs) else {
        return Err(format!(
            "parity: {} printed no counted freeze table (exit {:?}). stderr: {}",
            run.argv.join(" "),
            run.code,
            run.stderr.trim()
        ));
    };
    Ok(freeze::Freeze {
        sites: Vec::new(),
        count,
        defs,
        uprefs,
    })
}

// ── the `--strict` ratchet ────────────────────────────────────────────────────────────────────

/// The strict ratchet is its own registered gate rather than a flag on the one above, because the
/// two are different questions with different owed sets: `plane-purity` asks whether PRODUCTION
/// code carries a side channel (a yes/no the every-push job blocks on), and `plane-purity-strict`
/// asks whether TEST-scope debt has risen above a hand-lowered ceiling. Collapsing them onto a
/// boolean is exactly what `docs/design/xtask-gates.md` risk 5.2 warns about — and a boolean read
/// from the environment is how a floor becomes overridable downward.
/// The two counted tables `--strict` decides against: the six categories, and the per-plane-crate
/// test-reach. Named as a pair because they are always measured, compared and refused together —
/// one of them missing is the short-ledger failure the shell had to be taught out of.
pub type StrictTables = (BTreeMap<String, u64>, BTreeMap<String, u64>);

pub struct PlanePurityStrictGate;

impl PlanePurityStrictGate {
    fn ceilings(cx: &Ctx) -> Result<BTreeMap<String, strict::Ceiling>, String> {
        cx.read(strict::STRICT_TOML)
            .map(|t| strict::parse_ceilings(&t))
    }

    /// The two measured tables: the six categories over production+test scope combined, and the
    /// BACKWARDS class broken out per plane crate over test scope only.
    fn counts(m: &Measurement) -> StrictTables {
        let mut cats: BTreeMap<String, u64> = BTreeMap::new();
        for c in scanner::CATEGORIES {
            let n = if c == "BACKWARDS" {
                (m.prod_reverse.len() + m.test_reverse.len()) as u64
            } else {
                m.prod_forward.iter().filter(|h| h.category == c).count() as u64
                    + m.test_forward.iter().filter(|h| h.category == c).count() as u64
            };
            cats.insert(c.to_string(), n);
        }
        let mut reach: BTreeMap<String, u64> = BTreeMap::new();
        for k in planes::PLANE_KEYS {
            let prefix = format!("crates/busbar-{k}/");
            reach.insert(
                k.to_string(),
                m.test_reverse
                    .iter()
                    .filter(|h| h.file.starts_with(&prefix))
                    .count() as u64,
            );
        }
        (cats, reach)
    }
}

fn strict_rows(
    ceilings: &BTreeMap<String, strict::Ceiling>,
    cats: &BTreeMap<String, u64>,
    reach: &BTreeMap<String, u64>,
) -> Vec<Row> {
    let mut rows = Vec::new();
    for c in scanner::CATEGORIES {
        let id = strict_category_row(c);
        // AN UNMEASURED ROW IS NOT A MET CEILING. The shell's two `while read` loops ran zero
        // times over a ledger written with `cp … || true` and printed every ceiling met.
        let Some(measured) = cats.get(c) else {
            rows.push(Row::fail(
                id,
                format!("the {c} category was measured"),
                "no measurement for this category — an uncompared row reads as a ceiling met"
                    .to_string(),
            ));
            continue;
        };
        let d = strict::decide(ceilings, c, *measured);
        rows.push(Row::new(
            if d.red() {
                crate::ledger::Status::Fail
            } else {
                crate::ledger::Status::Pass
            },
            id,
            format!("{c} is within its ceiling"),
            d.detail(),
        ));
    }
    for k in planes::PLANE_KEYS {
        let id = strict_reach_row(k);
        let Some(measured) = reach.get(k) else {
            rows.push(Row::fail(
                id,
                format!("busbar-{k}'s test-reach was measured"),
                "no measurement for this plane crate — an uncompared row reads as a ceiling met"
                    .to_string(),
            ));
            continue;
        };
        let d = strict::decide(ceilings, k, *measured);
        rows.push(Row::new(
            if d.red() {
                crate::ledger::Status::Fail
            } else {
                crate::ledger::Status::Pass
            },
            id,
            format!("busbar-{k}'s own test code reaches busbar_core:: within its ceiling"),
            d.detail(),
        ));
    }
    rows
}

impl Gate for PlanePurityStrictGate {
    fn name(&self) -> &'static str {
        "plane-purity-strict"
    }

    fn owed(&self) -> Vec<String> {
        scanner::CATEGORIES
            .iter()
            .map(|c| strict_category_row(c))
            .chain(planes::PLANE_KEYS.iter().map(|k| strict_reach_row(k)))
            .collect()
    }

    fn run(&self, cx: &Ctx) -> Verdict {
        let ceilings = match Self::ceilings(cx) {
            Ok(c) => c,
            Err(e) => {
                return Verdict::of(unscannable(
                    &self.owed(),
                    &format!("{}: {e}", strict::STRICT_TOML),
                ))
            }
        };
        let m = match measure(cx) {
            Ok(m) => m,
            Err(e) => return Verdict::of(unscannable(&self.owed(), &e)),
        };
        let (cats, reach) = Self::counts(&m);
        Verdict::of(strict_rows(&ceilings, &cats, &reach))
    }

    fn selftest(&self, cx: &Ctx) -> Report {
        let mut report = Report::new();
        let owed = self.owed();
        let base = cx.read(strict::STRICT_TOML).unwrap_or_default();

        // THE GREEN ARM IS A CEILING FIXTURE, NOT THE COMMITTED FILE. A ratchet is green when the
        // measurement is AT its ceiling, and proving that against whatever the committed ceilings
        // happen to be today would make this case report on the tree's debt rather than on the
        // ratchet — so it would go red for a reason that says nothing about the gate. The ceilings
        // are set to the measured counts and the SAME counts are then pushed under them below.
        let measured = measure(cx).map(|m| Self::counts(&m));
        match &measured {
            Ok((cats, reach)) => {
                let mut at = Overlay::new();
                at.set(strict::STRICT_TOML, ceilings_at(&base, cats, reach));
                report.push(prove_green(
                    &cx.with_overlay(at),
                    self,
                    "a measurement AT its ceiling is green — the ratchet is not a fixed gate",
                    &owed.iter().map(String::as_str).collect::<Vec<_>>(),
                ));
            }
            Err(e) => report.note_infra_failure(format!(
                "plane-purity-strict: the tree could not be measured: {e}"
            )),
        }

        // A QUOTED CEILING. TOML accepts `SYMBOL = "5"`; the shell's `[ n -gt '"5"' ]` was an
        // ERROR that `if` read as "not over the ceiling", so the row stopped enforcing in silence.
        let mut ov = Overlay::new();
        ov.set(
            strict::STRICT_TOML,
            base.replace("SYMBOL = ", "SYMBOL = \"") + "\n",
        );
        report.push(prove_red(
            cx,
            self,
            "a quoted ceiling is refused, not compared",
            &[&strict_category_row("SYMBOL")],
            ov,
            &["not a bare integer"],
        ));

        // ONE MORE HIT THAN THE CEILING ALLOWS is the ratchet doing its job, and it is planted as
        // a real violation in test scope rather than as a lowered number — a case that only edits
        // the ceilings file proves the comparison, never the scan that feeds it. Each row gets its
        // OWN fixture: floors exercised only together can have all but one deleted with the
        // selftest still green, which is exactly how three of the shell self-tests went blind.
        if let Ok((cats, reach)) = &measured {
            for (name, plant_in, content) in strict_plants() {
                let id = if scanner::CATEGORIES.contains(&name) {
                    strict_category_row(name)
                } else {
                    strict_reach_row(name)
                };
                let mut ov = Overlay::new();
                ov.set(strict::STRICT_TOML, ceilings_at(&base, cats, reach));
                if Edit::Create(content.to_string())
                    .apply(cx, plant_in, &mut ov)
                    .is_err()
                {
                    report.push(Case {
                        name: format!("{name}: one hit more than its ceiling allows"),
                        covers: vec![id],
                        expected: Expect::Red {
                            naming: vec![name.to_string()],
                        },
                        got: Expect::Skipped,
                    });
                    continue;
                }
                report.push(prove_red(
                    cx,
                    self,
                    format!("{name}: one hit more than its ceiling allows"),
                    &[&id],
                    ov,
                    &[&id, "> ceiling"],
                ));
            }
        }
        report
    }

    fn has_legacy_adapter(&self) -> bool {
        true
    }

    fn legacy_rows(&self, cx: &Ctx, runs: &[LegacyRun]) -> Option<Result<Vec<Row>, String>> {
        Some(legacy_strict_rows(cx, runs))
    }
}

/// Rewrite every ceiling to the count measured beside it. A key the file does not carry is
/// APPENDED rather than skipped: a fixture that silently omits a row would prove the row's absence
/// green, which is the very failure the shell's short-ledger floor exists for.
fn ceilings_at(base: &str, cats: &BTreeMap<String, u64>, reach: &BTreeMap<String, u64>) -> String {
    let mut out = String::new();
    let mut written: Vec<&str> = Vec::new();
    for line in base.lines() {
        let key = line.split('=').next().map(str::trim).unwrap_or("");
        if let Some(n) = cats.get(key).or_else(|| reach.get(key)) {
            out.push_str(&format!("{key} = {n}\n"));
            written.push(key);
        } else {
            out.push_str(line);
            out.push('\n');
        }
    }
    for (k, n) in cats.iter().chain(reach.iter()) {
        if !written.contains(&k.as_str()) {
            out.push_str(&format!("{k} = {n}\n"));
        }
    }
    out
}

/// One plant per strict row: the row's name, the TEST-SCOPE file to create, and the single line
/// that adds exactly one hit to that row's class. The paths all sit under a `/tests/` segment,
/// which is what puts them in the scope `--strict` adds and `--check` deliberately does not see.
fn strict_plants() -> Vec<(&'static str, String, &'static str)> {
    let neutral_test = |leaf: &str| format!("crates/busbar-core/src/tests/{leaf}");
    let plane_test = |key: &str| format!("crates/busbar-{key}/src/tests/planted_strict_reach.rs");
    let mut out: Vec<(&'static str, String, &'static str)> = vec![
        (
            "PATH-INCLUDE",
            neutral_test("planted_strict_path.rs"),
            "#[path = \"../../../busbar-mcp/src/witness.rs\"]\nmod w;\n",
        ),
        (
            "SYMBOL",
            neutral_test("planted_strict_symbol.rs"),
            "use busbar_a2a::TaskThing;\n",
        ),
        (
            "TYPE",
            neutral_test("planted_strict_type.rs"),
            "pub struct McpFoo;\n",
        ),
        (
            "KEY",
            neutral_test("planted_strict_key.rs"),
            "fn k() { let _ = \"mcp\"; }\n",
        ),
        (
            "DIALECT",
            neutral_test("planted_strict_dialect.rs"),
            "fn d() { let _ = \"anthropic\"; }\n",
        ),
        (
            "BACKWARDS",
            plane_test("llm"),
            "fn b() { let _ = busbar_core::internal::foo(); }\n",
        ),
    ];
    for key in planes::PLANE_KEYS {
        out.push((
            key,
            plane_test(key),
            "fn r() { let _ = busbar_core::internal::foo(); }\n",
        ));
    }
    out
}

/// The strict half's legacy rows. `--strict --baseline` prints both counted tables and always
/// exits 0; the ceilings are then applied HERE by the same `decide`, so what parity compares is the
/// MEASUREMENT the two scanners made, which is the only half a rewrite can get wrong.
fn legacy_strict_rows(cx: &Ctx, runs: &[LegacyRun]) -> Result<Vec<Row>, String> {
    let [run] = runs else {
        return Err(format!(
            "parity: expected one legacy run, got {}",
            runs.len()
        ));
    };
    let ceilings = PlanePurityStrictGate::ceilings(cx)?;
    let (cats, reach) = parse_strict_tables(run)?;
    Ok(strict_rows(&ceilings, &cats, &reach))
}

/// Scrape the two fixed-format `  <NAME>   <n>` tables the strict report prints. The category
/// names and the plane keys are disjoint, so one pass over the lines fills both without needing to
/// know which header it is under — and a name that appears twice is a refusal, because the second
/// table's `TOTAL` row is the only repeat the format allows.
fn parse_strict_tables(run: &LegacyRun) -> Result<StrictTables, String> {
    let mut cats: BTreeMap<String, u64> = BTreeMap::new();
    let mut reach: BTreeMap<String, u64> = BTreeMap::new();
    for line in run.stdout.lines() {
        let mut it = line.split_whitespace();
        let (Some(name), Some(value), None) = (it.next(), it.next(), it.next()) else {
            continue;
        };
        let Ok(n) = value.parse::<u64>() else {
            continue;
        };
        if scanner::CATEGORIES.contains(&name) {
            if cats.insert(name.to_string(), n).is_some() {
                return Err(format!(
                    "parity: the strict report named category {name} twice"
                ));
            }
        } else if planes::PLANE_KEYS.contains(&name) && reach.insert(name.to_string(), n).is_some()
        {
            return Err(format!(
                "parity: the strict report named plane {name} twice"
            ));
        }
    }
    if cats.len() != scanner::CATEGORIES.len() || reach.len() != planes::PLANE_KEYS.len() {
        return Err(format!(
            "parity: the strict report carried {} of {} categories and {} of {} plane keys \
             (exit {:?}). A short table compared against ceilings reads as every ceiling met. \
             stderr: {}",
            cats.len(),
            scanner::CATEGORIES.len(),
            reach.len(),
            planes::PLANE_KEYS.len(),
            run.code,
            run.stderr.trim()
        ));
    }
    Ok((cats, reach))
}

// ── selftest helpers ──────────────────────────────────────────────────────────────────────────

/// Every owed row FAILs with the same reason when the tree could not be read. A gate that cannot
/// see its subject reports UNPROVEN, never the passing answer to a ban it never applied.
fn unscannable(owed: &[String], why: &str) -> Vec<Row> {
    owed.iter()
        .map(|id| Row::fail(id, "the tree could not be scanned", why.to_string()))
        .collect()
}

/// Plant a NEW file inside a scanned root and require RED naming the plant.
fn create(
    cx: &Ctx,
    gate: &dyn Gate,
    name: &str,
    covers: &[&str],
    path: &str,
    content: &str,
    naming: &[&str],
) -> Case {
    let mut ov = Overlay::new();
    if Edit::Create(content.to_string())
        .apply(cx, path, &mut ov)
        .is_err()
    {
        return Case {
            name: name.to_string(),
            covers: covers.iter().map(|s| (*s).to_string()).collect(),
            expected: Expect::Red {
                naming: naming.iter().map(|s| (*s).to_string()).collect(),
            },
            got: Expect::Skipped,
        };
    }
    prove_red(cx, gate, name, covers, ov, naming)
}

/// The control arm: the SAME shape planted with its excuse in place must be GREEN, or the RED case
/// beside it proves only that the rule fires on everything.
fn green_with(
    cx: &Ctx,
    gate: &dyn Gate,
    name: &str,
    covers: &[&str],
    path: &str,
    content: &str,
) -> Case {
    let mut ov = Overlay::new();
    if Edit::Create(content.to_string())
        .apply(cx, path, &mut ov)
        .is_err()
    {
        return Case {
            name: name.to_string(),
            covers: covers.iter().map(|s| (*s).to_string()).collect(),
            expected: Expect::Green,
            got: Expect::Skipped,
        };
    }
    let planted = cx.with_overlay(ov);
    prove_green(&planted, gate, name, covers)
}
