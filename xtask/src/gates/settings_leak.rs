//! `cargo xtask gate settings-leak` — AN ADMIN READ NEVER SERVES AN OPERATOR SETTINGS BAG'S VALUES.
//! The successor to `scripts/settings-leak-lint.sh`, rule for rule.
//!
//! An admin-facing PROJECTION may carry the KEY NAMES of an opaque `settings:` bag (`settings_keys`,
//! from `admin::v1::service::settings_keys`, or structurally from `service::redact_settings_bags`)
//! but never the bag itself. This defect class has been found FOUR times, in four independently
//! written projections, each accompanied by a doc comment asserting the bag was safe:
//! `NamedDefView` (an OIDC `client_secret`), `HookView` ("never a secret by contract"; a hook's bag
//! is a `SecretRef` carrier by design), `GET /hooks/{name}/status` (the hook's echo of the
//! secret-RESOLVED bag — plaintext, at READ-ONLY scope) and `GET /config/settings` (the whole
//! `RootSettings`, carrying a `store.settings.url` busbar's own docs spell with a password). A fifth
//! projection will be written the same way; this fails the build instead.
//!
//! Four rows, because the shell had four distinct ways to stop:
//!
//! * `settings-leak:plane-roots` — the mcp and a2a planes RESOLVE. 1.6.0's R-E makes them plugin
//!   crates; they are 71 of the 238 files scanned, so if they leave `busbar-core` the count falls to
//!   167, CLEARS the floor of 100, and the lint goes on printing `ok` over a tree it no longer
//!   reads. The floor catches a root that MOVED; only this catches a root that SPLIT.
//! * `settings-leak:scan-roots` — EACH root is on disk and holds a non-test `.rs`, checked ON ITS
//!   OWN before the total means anything. `find A B C` complains about a missing A to stderr, goes
//!   on listing B and C, and its status is lost to the `< <(…)` the loop read from. `$CORE` is 150
//!   of 277 files, and renaming it leaves 127 — which clears a floor of 100 and prints `passed`.
//! * `settings-leak:scan-floor` — the aggregate floor, which catches a root that moved.
//! * `settings-leak:no-raw-bag` — the finding: R1, a struct field named `settings`/`*_settings`
//!   declared as a raw bag type; R2, a hand-built `json!` member named `"settings"`.
//!
//! THE ALLOWLIST is explicit, per-line and self-documenting — `// settings-leak-lint: allow —
//! <reason>` on the line or the comment block immediately above — and covers exactly the one
//! declaration it sits above. Use it only for an INBOUND request body, a response ENVELOPE whose
//! nested bags are already redacted, or a NON-PROJECTION engine type. Adding a marker with any
//! other reason is the bug this gate exists to catch, in a costume.

use crate::ctx::{Ctx, Overlay, WalkSpec};
use crate::gates::{
    prove_green, prove_red, prove_rows_red_at, Gate, Report, PLANE_ROOT_MISSING_FIXTURE,
};
use crate::ledger::{Row, Verdict};
use crate::parity::LegacyRun;
use crate::planes::PlaneRoots;

pub const ROW_PLANE_ROOTS: &str = "settings-leak:plane-roots";
pub const ROW_SCAN_ROOTS: &str = "settings-leak:scan-roots";
pub const ROW_SCAN_FLOOR: &str = "settings-leak:scan-floor";
pub const ROW_NO_RAW_BAG: &str = "settings-leak:no-raw-bag";

/// The core/bin split roots plus the LLM plane. The plane roots are FOUND, not spelled.
const FIXED_ROOTS: &[&str] = &[
    "crates/busbar-core/src",
    "crates/busbar/src",
    "crates/busbar-llm/src",
];

/// The planes whose source must be in the scan whatever crate they end up in.
const PLANE_KEYS: &[&str] = &["mcp", "a2a"];

const EXCLUDE_TESTS_DIR: &str = "/tests/";

/// The aggregate floor. Not `> 0` — one file is as vacuous as none; it tracks the real tree (123
/// files when written) with slack for genuine consolidation.
const SCAN_FLOOR: usize = 100;

const CLEAN: &str = "the scan cleared its floors and named nothing";

const ALLOW_MARKER: &str = "settings-leak-lint:";

fn finding_field(rel: &str, line: usize) -> String {
    format!(
        "{rel}:{line}: admin view field carries a RAW settings bag — project settings_keys \
         (admin::v1::service::settings_keys) or redact via service::redact_settings_bags"
    )
}

fn finding_member(rel: &str, line: usize) -> String {
    format!(
        "{rel}:{line}: admin JSON body serializes a `settings` member — serve `settings_keys` \
         instead (or redact the tree with service::redact_settings_bags and allowlist the envelope)"
    )
}

fn row_no_raw_bag(offenders: &[String]) -> Row {
    if offenders.is_empty() {
        return Row::pass(
            ROW_NO_RAW_BAG,
            "no engine type reaching an admin read carries a raw operator settings bag",
            CLEAN,
        );
    }
    Row::fail(
        ROW_NO_RAW_BAG,
        "an engine type reaching an admin read carries a raw operator settings bag",
        format!("{} finding(s): {}", offenders.len(), offenders.join(" | ")),
    )
}

/// Is this line a comment, by the shell's rule: `^[[:space:]]*(//|\*|/\*)`. A doc comment quoting
/// `"settings":` is prose, not a projection.
fn is_comment(line: &str) -> bool {
    let t = line.trim_start();
    t.starts_with("//") || t.starts_with('*') || t.starts_with("/*")
}

/// `settings-leak-lint:` followed by optional whitespace and `allow`.
fn carries_allow_marker(line: &str) -> bool {
    let mut rest = line;
    while let Some(i) = rest.find(ALLOW_MARKER) {
        if rest[i + ALLOW_MARKER.len()..]
            .trim_start()
            .starts_with("allow")
        {
            return true;
        }
        rest = &rest[i + ALLOW_MARKER.len()..];
    }
    false
}

/// R1 — a raw settings BAG as a struct field type. The shell's anchored alternation, read left to
/// right: an optional `pub`/`pub(vis)`, an identifier of `[a-z_]` ending in `settings`, a colon,
/// an optional `Option<`, an optional `serde_json::`, and then a `Map<`, a `Value` followed by `,`
/// or `>`, or a `Value` at end of line.
fn is_raw_bag_field(line: &str) -> bool {
    let s: Vec<char> = line.chars().collect();
    let mut i = 0;
    let skip_ws = |s: &[char], i: &mut usize| {
        while *i < s.len() && (s[*i] == ' ' || s[*i] == '\t') {
            *i += 1;
        }
    };
    let eat = |s: &[char], i: &mut usize, lit: &str| -> bool {
        let l: Vec<char> = lit.chars().collect();
        if *i + l.len() <= s.len() && s[*i..*i + l.len()] == l[..] {
            *i += l.len();
            true
        } else {
            false
        }
    };
    skip_ws(&s, &mut i);

    // optional `pub` or `pub(vis)`, then REQUIRED whitespace
    let save = i;
    if eat(&s, &mut i, "pub") {
        if i < s.len() && s[i] == '(' {
            i += 1;
            let start = i;
            while i < s.len() && s[i].is_ascii_lowercase() {
                i += 1;
            }
            if i == start || i >= s.len() || s[i] != ')' {
                i = save;
            } else {
                i += 1;
            }
        }
        if i != save {
            let before = i;
            skip_ws(&s, &mut i);
            if i == before {
                i = save;
            }
        }
    }

    // `[a-z_]*settings`
    let name_start = i;
    while i < s.len() && (s[i].is_ascii_lowercase() || s[i] == '_') {
        i += 1;
    }
    let name: String = s[name_start..i].iter().collect();
    if !name.ends_with("settings") {
        return false;
    }

    skip_ws(&s, &mut i);
    if i >= s.len() || s[i] != ':' {
        return false;
    }
    i += 1;
    skip_ws(&s, &mut i);

    if eat(&s, &mut i, "Option") {
        skip_ws(&s, &mut i);
        if i >= s.len() || s[i] != '<' {
            return false;
        }
        i += 1;
        skip_ws(&s, &mut i);
    }
    let _ = eat(&s, &mut i, "serde_json::");

    if eat(&s, &mut i, "Map") {
        skip_ws(&s, &mut i);
        return i < s.len() && s[i] == '<';
    }
    if eat(&s, &mut i, "Value") {
        skip_ws(&s, &mut i);
        return i >= s.len() || s[i] == ',' || s[i] == '>';
    }
    false
}

/// R2 — a hand-built JSON response member named `settings`: `"settings"` then optional whitespace
/// then `:`.
fn is_raw_bag_member(line: &str) -> bool {
    let needle = "\"settings\"";
    let mut rest = line;
    while let Some(i) = rest.find(needle) {
        if rest[i + needle.len()..].trim_start().starts_with(':') {
            return true;
        }
        rest = &rest[i + needle.len()..];
    }
    false
}

/// One file's findings. `prev_allow` carries a marker forward across the COMMENT BLOCK it starts
/// (a reason rarely fits on one line) and NO FURTHER: the first non-comment line consumes it and
/// the line after that is armed again, so a marker covers exactly one declaration.
fn scan_file(rel: &str, text: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut prev_allow = false;
    for (idx, line) in text.lines().enumerate() {
        let comment = is_comment(line);
        let marker = carries_allow_marker(line);
        let allow = marker || prev_allow;
        prev_allow = marker || (comment && prev_allow);
        if comment || allow {
            continue;
        }
        if is_raw_bag_field(line) {
            out.push(finding_field(rel, idx + 1));
            continue;
        }
        if is_raw_bag_member(line) {
            out.push(finding_member(rel, idx + 1));
        }
    }
    out
}

pub struct SettingsLeakGate;

/// The scan roots for this tree: the three fixed ones plus the resolved plane homes, relative to
/// the workspace root.
fn scan_roots(cx: &Ctx) -> Result<Vec<String>, String> {
    let roots = PlaneRoots::at(cx.abs("crates"));
    let mut out: Vec<String> = FIXED_ROOTS.iter().map(|r| (*r).to_string()).collect();
    let (ok, errs) = roots.resolve_all(PLANE_KEYS);
    if !errs.is_empty() {
        return Err(errs
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join(" | "));
    }
    for (_, dir) in ok {
        let rel = dir
            .strip_prefix(cx.root())
            .map_err(|_| format!("{} is not under the workspace root", dir.display()))?;
        out.push(rel.to_string_lossy().replace('\\', "/"));
    }
    Ok(out)
}

impl Gate for SettingsLeakGate {
    fn name(&self) -> &'static str {
        "settings-leak"
    }

    fn owed(&self) -> Vec<String> {
        vec![
            ROW_PLANE_ROOTS.to_string(),
            ROW_SCAN_ROOTS.to_string(),
            ROW_SCAN_FLOOR.to_string(),
            ROW_NO_RAW_BAG.to_string(),
        ]
    }

    fn run(&self, cx: &Ctx) -> Verdict {
        let roots = match scan_roots(cx) {
            Ok(r) => r,
            Err(why) => {
                return Verdict::of(vec![
                    Row::fail(ROW_PLANE_ROOTS, "a plane root did not resolve", why),
                    Row::fail(
                        ROW_SCAN_ROOTS,
                        "the root set is unknown",
                        DID_NOT_RUN.to_string(),
                    ),
                    Row::fail(
                        ROW_SCAN_FLOOR,
                        "the root set is unknown",
                        DID_NOT_RUN.to_string(),
                    ),
                    Row::fail(
                        ROW_NO_RAW_BAG,
                        "the scan did not run",
                        DID_NOT_RUN.to_string(),
                    ),
                ]);
            }
        };

        // EACH ROOT ON ITS OWN, before the total means anything.
        let mut unusable = Vec::new();
        let mut files = Vec::new();
        for root in &roots {
            let spec = WalkSpec::new([root.clone()])
                .ext("rs")
                .exclude([EXCLUDE_TESTS_DIR])
                .min_files(1);
            match cx.walk(&spec) {
                Ok(f) => files.extend(f),
                Err(e) => unusable.push(format!("{root}: {e}")),
            }
        }
        if !unusable.is_empty() {
            return Verdict::of(vec![
                Row::pass(ROW_PLANE_ROOTS, "every plane root resolved", CLEAN),
                Row::fail(
                    ROW_SCAN_ROOTS,
                    "a scan root is missing or drained",
                    format!(
                        "{} — a root that is missing or drained is scanned as ZERO files, and zero \
                         files carry no leak. If the layout moved, point the root at its new home \
                         in a reviewed diff that says so.",
                        unusable.join(" | ")
                    ),
                ),
                Row::fail(
                    ROW_SCAN_FLOOR,
                    "the scan set is incomplete",
                    DID_NOT_RUN.to_string(),
                ),
                Row::fail(
                    ROW_NO_RAW_BAG,
                    "the scan did not run",
                    DID_NOT_RUN.to_string(),
                ),
            ]);
        }

        files.sort_by_key(crate::ctx::SourceFile::rel_str);
        files.dedup_by_key(|f| f.rel_str());

        if files.len() < SCAN_FLOOR {
            return Verdict::of(vec![
                Row::pass(ROW_PLANE_ROOTS, "every plane root resolved", CLEAN),
                Row::pass(
                    ROW_SCAN_ROOTS,
                    "every scan root holds production source",
                    CLEAN,
                ),
                Row::fail(
                    ROW_SCAN_FLOOR,
                    "the scan set is below its floor",
                    format!(
                        "found {} non-test .rs file(s) across the scan roots, expected >= \
                         {SCAN_FLOOR}. This gate scanned (almost) nothing, so its verdict is \
                         meaningless — it is NOT a pass.",
                        files.len()
                    ),
                ),
                Row::fail(
                    ROW_NO_RAW_BAG,
                    "the scan did not run",
                    DID_NOT_RUN.to_string(),
                ),
            ]);
        }

        let mut offenders = Vec::new();
        for f in &files {
            offenders.extend(scan_file(&f.rel_str(), &f.text));
        }
        offenders.sort();

        Verdict::of(vec![
            Row::pass(ROW_PLANE_ROOTS, "every plane root resolved", CLEAN),
            Row::pass(
                ROW_SCAN_ROOTS,
                "every scan root holds production source",
                CLEAN,
            ),
            Row::pass(ROW_SCAN_FLOOR, "the scan set cleared its floor", CLEAN),
            row_no_raw_bag(&offenders),
        ])
    }

    fn has_legacy_adapter(&self) -> bool {
        true
    }

    fn legacy_rows(&self, _cx: &Ctx, runs: &[LegacyRun]) -> Option<Result<Vec<Row>, String>> {
        let run = &runs[0];
        Some(translate(run))
    }

    fn selftest(&self, cx: &Ctx) -> Report {
        let mut report = Report::new();
        report.push(prove_green(
            cx,
            self,
            "no admin projection in the tree carries a raw settings bag",
            &[
                ROW_PLANE_ROOTS,
                ROW_SCAN_ROOTS,
                ROW_SCAN_FLOOR,
                ROW_NO_RAW_BAG,
            ],
        ));

        // The four historical leaks, transcribed: a Map field, an Option<Map> field, a Value field
        // and a hand-built json! member.
        let mut ov = Overlay::new();
        ov.set(
            "crates/busbar-core/src/planted_views.rs",
            "#[derive(Serialize)]\npub(crate) struct HookView {\n\
             \x20   pub(crate) name: String,\n\
             \x20   pub(crate) settings: serde_json::Map<String, serde_json::Value>,\n}\n\n\
             #[derive(Serialize)]\npub(crate) struct HookReportedStatus {\n\
             \x20   pub(crate) settings: Option<serde_json::Map<String, serde_json::Value>>,\n}\n\n\
             #[derive(Serialize)]\npub(crate) struct ConfigSettingsView {\n\
             \x20   pub(crate) settings: serde_json::Value,\n}\n\n\
             fn hook_status() -> Response {\n    ok_json(StatusCode::OK, &json!({\n\
             \x20       \"name\": name,\n\
             \x20       \"reported\": {\"settings\": r.settings, \"settings_version\": r.v},\n\
             \x20   }))\n}\n",
        );
        report.push(prove_red(
            cx,
            self,
            "all four leak shapes are flagged (Map / Option<Map> / Value field, json! member)",
            &[ROW_NO_RAW_BAG],
            ov,
            // Named by LINE, one per shape: the Map field, the Option<Map> field, the Value field
            // and the json! member. Naming only the count would let three of the four rules be
            // deleted with this case still green.
            &[
                "4 finding(s)",
                "planted_views.rs:4",
                "planted_views.rs:9",
                "planted_views.rs:14",
                "planted_views.rs:20",
            ],
        ));

        // THE SANCTIONED FORMS stay silent: the keys projection, the redaction helper, both
        // allowlist categories, and a doc comment naming either shape.
        let mut ov = Overlay::new();
        ov.set(
            "crates/busbar-core/src/planted_sanctioned.rs",
            "#[derive(Serialize)]\npub(crate) struct HookView {\n\
             \x20   pub(crate) settings_keys: Vec<String>,\n}\n\n\
             #[derive(Deserialize)]\npub(crate) struct PatchSettingsReq {\n\
             \x20   // settings-leak-lint: allow — inbound request body; never serialized back.\n\
             \x20   settings: serde_json::Map<String, serde_json::Value>,\n}\n\n\
             fn hook_status() -> Response {\n\
             \x20   crate::admin::v1::service::redact_settings_bags(&mut settings);\n\
             \x20   ok_json(StatusCode::OK, &json!({\n\
             \x20       \"desired\": {\"settings_keys\": settings_keys(&h.settings)},\n\
             \x20       // settings-leak-lint: allow — envelope; nested bags redacted above.\n\
             \x20       \"settings\": settings,\n\
             \x20   }))\n}\n\n\
             // A doc comment naming a \"settings\": member, or a settings: Map<…> field, is prose.\n",
        );
        report.push(prove_green(
            &cx.with_overlay(ov),
            self,
            "keys projections, the redaction helper, both allowlist categories and prose stay silent",
            &[ROW_NO_RAW_BAG],
        ));

        // A MARKER IS NOT A BLANKET MUTE. It covers the next declaration and its own comment
        // continuation, and an unmarked leak two lines below is still caught.
        let mut ov = Overlay::new();
        ov.set(
            "crates/busbar-core/src/planted_scope.rs",
            "// settings-leak-lint: allow — this marker (and its continuation line, since a reason\n\
             // rarely fits on one line) covers the NEXT declaration only.\n\
             pub(crate) settings: serde_json::Value,\n\
             pub(crate) other: u8,\n\
             pub(crate) settings: serde_json::Map<String, serde_json::Value>,\n",
        );
        report.push(prove_red(
            cx,
            self,
            "an allow marker covers exactly one declaration, so a later unmarked leak is flagged",
            &[ROW_NO_RAW_BAG],
            ov,
            &["1 finding(s)", "planted_scope.rs:5"],
        ));

        // THE INSTRUMENT: A ROOT THAT LEFT THE SCAN. `$CORE` is 150 of 277 files; renaming it left
        // 127, which cleared a floor of 100 and printed `passed`. Drain ONE root and the per-root
        // check must bite even though the aggregate would still clear.
        match scan_roots(cx) {
            Ok(roots) => {
                let engine = &roots[0];
                match cx.walk(
                    &WalkSpec::new([engine.clone()])
                        .ext("rs")
                        .exclude([EXCLUDE_TESTS_DIR]),
                ) {
                    Ok(files) => {
                        let mut ov = Overlay::new();
                        for f in &files {
                            ov.remove(&f.rel);
                        }
                        report.push(prove_red(
                            cx,
                            self,
                            "one drained root is refused on its own, before the total means anything",
                            &[ROW_SCAN_ROOTS],
                            ov,
                            &["missing or drained"],
                        ));
                    }
                    Err(e) => report.note_infra_failure(format!(
                        "settings-leak selftest: the engine root is unreadable ({e})"
                    )),
                }
            }
            Err(e) => report.note_infra_failure(format!(
                "settings-leak selftest: the plane roots do not resolve on this tree ({e}), so \
                 neither root plant has anything to drain"
            )),
        }

        // THE AGGREGATE FLOOR, on the run path: every root keeps a file, so the per-root check
        // passes, and the total still falls under the floor.
        match scan_roots(cx) {
            Ok(roots) => {
                let mut ov = Overlay::new();
                let mut planted_any = false;
                for root in &roots {
                    if let Ok(files) = cx.walk(
                        &WalkSpec::new([root.clone()])
                            .ext("rs")
                            .exclude([EXCLUDE_TESTS_DIR]),
                    ) {
                        for f in files.iter().skip(1) {
                            ov.remove(&f.rel);
                            planted_any = true;
                        }
                    }
                }
                if planted_any {
                    report.push(prove_red(
                        cx,
                        self,
                        "a scan set below its floor is refused even when every root still holds a file",
                        &[ROW_SCAN_FLOOR],
                        ov,
                        &["below its floor"],
                    ));
                } else {
                    report.note_infra_failure(
                        "settings-leak selftest: no root holds a second file, so the aggregate \
                         floor cannot be driven without also emptying a root"
                            .to_string(),
                    );
                }
            }
            Err(_) => { /* already reported by the case above */ }
        }

        // THE PLANE ROOTS: the row this gate's header calls the only thing that can catch a plane
        // that split, and which had no red proof at all — a plane that left takes its projections
        // with it, and every remaining root still clears its floor. Driven THROUGH `Gate::run`
        // over a fixture tree in which no plane declares its grammar; the plane resolver reads
        // `std::fs`, so no overlay can plant this.
        report.push(prove_rows_red_at(
            cx,
            self,
            "a plane that cannot be located is refused, not scanned as a smaller tree",
            &[ROW_PLANE_ROOTS],
            PLANE_ROOT_MISSING_FIXTURE,
            &["PLANE-ROOT-MISSING"],
        ));

        report
    }
}

const DID_NOT_RUN: &str = "nothing was read, and nothing read is not a clean tree";

/// Read the shell gate's own output into the same four rows. Nothing here re-scans the tree.
fn translate(run: &LegacyRun) -> Result<Vec<Row>, String> {
    let mut offenders = Vec::new();
    let mut plane_unresolved = None;
    let mut roots_unusable = None;
    let mut floor_broken = None;
    let mut ran = false;

    for raw in run.lines() {
        let t = raw.trim();
        if t.contains("PLANE ROOT UNRESOLVED") {
            plane_unresolved = Some(t.to_string());
            continue;
        }
        if t.contains("SCAN ROOT UNUSABLE") {
            roots_unusable = Some(t.to_string());
            continue;
        }
        if t.contains("SCAN ROOT EMPTY OR MOVED") {
            floor_broken = Some(t.to_string());
            continue;
        }
        if t.starts_with("scan set:") || t == "settings-leak-lint passed" {
            ran = true;
            continue;
        }
        if let Some(hit) = t.strip_prefix("SETTINGS-LEAK: ") {
            ran = true;
            offenders.push(hit.to_string());
        }
    }

    if plane_unresolved.is_none() && roots_unusable.is_none() && floor_broken.is_none() && !ran {
        return Err(format!(
            "the legacy translator recognised nothing in `{}`'s output: no scan-set line, no \
             verdict, no findings. Silence read as a clean tree is the exact defect this gate \
             exists for.",
            run.argv.join(" ")
        ));
    }

    if let Some(why) = plane_unresolved {
        return Ok(vec![
            Row::fail(ROW_PLANE_ROOTS, "a plane root did not resolve", why),
            Row::fail(
                ROW_SCAN_ROOTS,
                "the root set is unknown",
                DID_NOT_RUN.to_string(),
            ),
            Row::fail(
                ROW_SCAN_FLOOR,
                "the root set is unknown",
                DID_NOT_RUN.to_string(),
            ),
            Row::fail(
                ROW_NO_RAW_BAG,
                "the scan did not run",
                DID_NOT_RUN.to_string(),
            ),
        ]);
    }
    if let Some(why) = roots_unusable {
        return Ok(vec![
            Row::pass(ROW_PLANE_ROOTS, "every plane root resolved", CLEAN),
            Row::fail(ROW_SCAN_ROOTS, "a scan root is missing or drained", why),
            Row::fail(
                ROW_SCAN_FLOOR,
                "the scan set is incomplete",
                DID_NOT_RUN.to_string(),
            ),
            Row::fail(
                ROW_NO_RAW_BAG,
                "the scan did not run",
                DID_NOT_RUN.to_string(),
            ),
        ]);
    }
    if let Some(why) = floor_broken {
        return Ok(vec![
            Row::pass(ROW_PLANE_ROOTS, "every plane root resolved", CLEAN),
            Row::pass(
                ROW_SCAN_ROOTS,
                "every scan root holds production source",
                CLEAN,
            ),
            Row::fail(ROW_SCAN_FLOOR, "the scan set is below its floor", why),
            Row::fail(
                ROW_NO_RAW_BAG,
                "the scan did not run",
                DID_NOT_RUN.to_string(),
            ),
        ]);
    }

    offenders.sort();
    Ok(vec![
        Row::pass(ROW_PLANE_ROOTS, "every plane root resolved", CLEAN),
        Row::pass(
            ROW_SCAN_ROOTS,
            "every scan root holds production source",
            CLEAN,
        ),
        Row::pass(ROW_SCAN_FLOOR, "the scan set cleared its floor", CLEAN),
        row_no_raw_bag(&offenders),
    ])
}
