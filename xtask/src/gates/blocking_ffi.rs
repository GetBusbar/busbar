//! `cargo xtask gate blocking-ffi` — A SYNCHRONOUS CALL INTO A DLOPENED PLUGIN NEVER RUNS ON A
//! TOKIO WORKER. The successor to `scripts/blocking-ffi-lint.sh`, rule for rule.
//!
//! Every call that reaches a plugin's `transport_call` (or the `dlopen` + constructor before it)
//! must be made from a BLOCKING context — inside `spawn_blocking`, `Txn::read_store` /
//! `Txn::store_write`, `hooks::offload_bounded`, `auth::token::offload_login_call`, or a plain `fn`
//! that only such a context calls. Never inline in an `async fn`.
//!
//! WHY. A plugin call is a C-ABI hop into out-of-tree code with real network I/O behind it: an
//! LDAP bind, a Vault fetch, a JWKS round trip, a store round trip. Called inline from an
//! `async fn`, ONE such call parks a Tokio worker for the plugin's full timeout; N concurrent
//! callers park N workers; once every worker is parked the runtime polls NOTHING — not other
//! requests, not the admin plane, not `/healthz`, which is exempt from auth but still needs a worker
//! to run at all. The node then fails its liveness probe and is killed, on account of a plugin most
//! of the stalled traffic never used. Found in FIVE independent places already.
//!
//! HOW IT DECIDES "inside an async fn" — the statement window, two counters:
//!
//! * BRACE depth: an `async fn` arms at the depth its signature starts and disarms when depth
//!   returns to it. A sync `fn` never arms. `entered` guards a MULTI-LINE SIGNATURE: `async fn f(\n
//!   a: A,\n) -> R {` leaves brace depth unchanged for several lines, and disarming on "depth is
//!   back where it started" would end the fn before its body began, silently exempting every call
//!   in it.
//! * PAREN depth: an OFFLOAD OPENER disarms the async context for its whole ARGUMENT LIST, whether
//!   the closure body is a braced block on the next line or an expression on the fifth line of a
//!   multi-line call. Both spellings are in-tree, and only the paren counter carries the second.
//!
//! Four rows:
//!
//! * `blocking-ffi:plane-roots` — mcp and a2a resolve. They are 71 of the 238 files scanned against
//!   a floor of 100, and both cross the hook/store seams from async code, so a plane that SPLIT into
//!   its own crate would leave the floor cleared and 71 of the most relevant files unscanned.
//! * `blocking-ffi:scan-floor` — the aggregate floor.
//! * `blocking-ffi:scan-status` — THE SCAN THE GATE REPORTS ON IS THE SCAN IT ACTUALLY TOOK. The
//!   shell read `h=$(scan_rule "$f") || true`, which discarded awk's exit status; awk exits
//!   non-zero for every reason that is NOT "this file is clean", and every one of those produced an
//!   EMPTY `h` — this gate's no-findings answer — for EVERY file. Planted, a one-character break in
//!   the awk program printed `blocking-ffi-lint passed` while awk had refused to run over all 238
//!   files. The floor cannot see it: the scan SET was full; it was the scan that never happened.
//!   In Rust the scanner cannot abort, so the guard is re-asserted as the fact it was protecting:
//!   an OFFLOAD WINDOW THAT NEVER SHUT exempted every remaining line of its file, which is a silent
//!   pass over real code and is reported rather than banked as "no findings".
//! * `blocking-ffi:no-inline-ffi` — the finding.
//!
//! ONE CARVE-OUT, and it is a shape no plugin call can wear: a method call whose first argument is
//! a freshly minted capability token is the KERNEL's sealed step seam, not a plugin handle. See
//! [`opens_with_capability_token`] for why `busbar_kernel::teller::Units::authenticate` and
//! `busbar_api::AuthModule::authenticate` share a spelling and nothing else.
//!
//! Imprecise about strings and comments in the same way the shell was: a brace inside a string
//! literal can shift the depth. That is a false-POSITIVE risk — a spurious flag someone must look
//! at — never a false negative, and the allowlist is how a real one gets recorded.

use crate::ctx::{Ctx, Overlay, WalkSpec};
use crate::gates::population::{self, Population};
use crate::gates::{
    prove_green, prove_red, prove_rows_red_at, Gate, Report, PLANE_ROOT_MISSING_FIXTURE,
};
use crate::ledger::{Row, Verdict};
use crate::parity::LegacyRun;
use crate::planes::PlaneRoots;
use crate::scan;

pub const ROW_PLANE_ROOTS: &str = "blocking-ffi:plane-roots";
pub const ROW_SCAN_FLOOR: &str = "blocking-ffi:scan-floor";
pub const ROW_SCAN_STATUS: &str = "blocking-ffi:scan-status";
pub const ROW_NO_INLINE: &str = "blocking-ffi:no-inline-ffi";

const CORE: &str = "crates/busbar-core/src";
const FIXED_ROOTS: &[&str] = &[CORE, "crates/busbar/src", "crates/busbar-llm/src"];
const PLANE_KEYS: &[&str] = &["mcp", "a2a"];
const EXCLUDE_TESTS_DIR: &str = "/tests/";
// THE FLOOR MOVED TO `gates::population`, along with the scan set it is a floor on.

const CLEAN: &str = "the scan cleared its floors and named nothing";
const DID_NOT_RUN: &str = "nothing was read, and nothing read is not a clean tree";
const ALLOW_MARKER: &str = "blocking-ffi-lint:";

/// The offload seams. A call inside one of these argument lists is already on a blocking thread.
const OFFLOAD_OPENERS: &[&str] = &[
    "spawn_blocking",
    "read_store",
    "store_write",
    "offload_bounded",
    "offload_bounded_with_deadline",
    "offload_login_call",
    "Outcome::blocking",
    "block_in_place",
];

/// One seam class: how it is spelled, and what the finding says. Order is load-bearing — the shell
/// was an `else if` chain and the FIRST match wins, so a line calling two seams reports the first.
struct Seam {
    /// Method-call spellings: `.name(`.
    methods: &'static [&'static str],
    /// Bare-call spellings: `name(` at an identifier boundary.
    bare: &'static [&'static str],
    msg: &'static str,
}

fn seams() -> Vec<Seam> {
    vec![
        // A `kind: auth` LOGIN plugin (the hosted browser flow) — a credential bind or a token hop.
        Seam {
            methods: &["begin_login", "complete_login", "login_kind"],
            bare: &[],
            msg: "login-plugin FFI (begin_login/complete_login/login_kind) called inline from an \
                  async fn — route it through auth::token::offload_login_call",
        },
        // A `kind: auth` VERIFY plugin, direct or via the chain runner.
        Seam {
            methods: &["authenticate"],
            bare: &["run_chain_cached"],
            msg:
                "auth-plugin FFI (authenticate/run_chain_cached) called inline from an async fn — \
                  use run_chain_on_request_path / run_admin_chain_maybe_offloaded",
        },
        // A `kind: secret` plugin: SecretResolver's non-built-in arm is a transport_call.
        Seam {
            methods: &[],
            bare: &[
                "resolve_hook_settings",
                "resolve_settings",
                "resolve_string",
                "preresolve_hook_secrets",
                "build_server_config",
            ],
            msg: "secret-plugin FFI (SecretResolver::resolve*) called inline from an async fn — \
                  resolve on a blocking thread (see hooks::gate_transport_named)",
        },
        // dlopen + the plugin CONSTRUCTOR: a staging copy, dynamic-linker work, then the open.
        Seam {
            methods: &[
                "open_hook",
                "open_login",
                "open_auth",
                "open_store",
                "open_secret",
                "open_export",
            ],
            bare: &["gate_transport_named", "preopen_gate_hooks"],
            msg: "plugin OPEN (dlopen + constructor) called inline from an async fn — use \
                  hooks::gate_transport_offloaded / offload_bounded",
        },
        // Whole-snapshot builders: each re-resolves the hook chain, i.e. secrets + opens, per hook.
        Seam {
            methods: &[],
            bare: &[
                "build_app_from_config",
                "build_with_hook",
                "build_without_hook",
                "build_with_registry",
                "resolve_gate_hooks",
                "resolve_rewrite_hooks",
                "resolve_tap_hooks",
                "resolve_pool_gates",
                "resolve_pool_rewrites",
            ],
            msg:
                "an App/hook-chain build (secret resolve + dlopen per hook) called inline from an \
                  async fn — defer it through Txn::read_store",
        },
        // A `kind: export` / `kind: hook` plugin serving an inbound HTTP route.
        Seam {
            methods: &["handle_http", "handle_http_with_app"],
            bare: &[],
            msg: "export/hook-plugin HTTP dispatch called inline from an async fn — serve it on \
                  spawn_blocking (see plugin_routes::plugin_route_dispatch)",
        },
    ]
}

fn finding(rel: &str, line: usize, msg: &str) -> String {
    format!("{rel}:{line}: {msg}")
}

fn row_no_inline(offenders: &[String]) -> Row {
    if offenders.is_empty() {
        return Row::pass(
            ROW_NO_INLINE,
            "no synchronous plugin FFI is called inline from an async fn",
            CLEAN,
        );
    }
    Row::fail(
        ROW_NO_INLINE,
        "a synchronous plugin FFI call runs on a reactor worker",
        format!("{} finding(s): {}", offenders.len(), offenders.join(" | ")),
    )
}

fn is_ident_char(c: char) -> bool {
    c.is_alphanumeric() || c == '_'
}

/// `name` followed by optional whitespace and `(`, anywhere in the line, at an identifier boundary
/// on the left. The shell's `(a|b)[[:space:]]*\(`.
fn bare_call(line: &str, name: &str) -> bool {
    let chars: Vec<char> = line.chars().collect();
    let n: Vec<char> = name.chars().collect();
    if n.len() > chars.len() {
        return false;
    }
    for i in 0..=(chars.len() - n.len()) {
        if chars[i..i + n.len()] != n[..] {
            continue;
        }
        if i > 0 && is_ident_char(chars[i - 1]) {
            continue;
        }
        let mut j = i + n.len();
        while j < chars.len() && chars[j].is_whitespace() {
            j += 1;
        }
        if j < chars.len() && chars[j] == '(' {
            return true;
        }
    }
    false
}

/// The kernel's sealed step-trait receipt: a call whose FIRST argument is a freshly minted
/// capability token.
///
/// WHY THIS IS NOT A HOLE. Every seam in [`seams`] is a call into a DLOPENED PLUGIN, and every one
/// of those is reached through a plugin handle whose method takes plugin arguments —
/// `busbar_api::AuthModule::authenticate` takes `Option<&str>`, the presented credential, and
/// nothing else. `busbar_kernel::teller::Units` is a DIFFERENT trait that happens to spell one of
/// its steps `authenticate`, and the kernel calls it as `units.authenticate(&UnitToken::<
/// Authenticate>::mint(seal), ctx)`. A `UnitToken` is a capability the kernel mints against its own
/// `seal` for the length of one call; it is not a type a plugin's ABI can name, and `busbar-kernel`
/// depends on `busbar-caps`, `busbar-contract` and `busbar-grammar` — it links no plugin loader and
/// no async runtime at all, so there is no Tokio worker there to park. So the mint spelling is not
/// "a call we have decided to trust": it is the one textual form a plugin call CANNOT take.
///
/// It is recognised on the CALL LINE only, and requires the mint to open the argument list. Split
/// the call across lines and the exemption stops applying — a false positive somebody must look at,
/// which is the direction this gate is allowed to be wrong in.
///
/// ONE spelling, not a family. `TrustToken` is minted the same way and is never a step's FIRST
/// argument, so it is deliberately absent: an arm no red proof drives is coverage this gate would
/// be asserting about itself.
fn opens_with_capability_token(rest: &str) -> bool {
    let arg = rest.trim_start();
    let arg = arg.strip_prefix('&').unwrap_or(arg).trim_start();
    arg.starts_with("UnitToken::<")
}

/// `.name` followed by optional whitespace and `(`. The shell's `\.(a|b)[[:space:]]*\(`, plus the
/// kernel step-seam carve-out in [`opens_with_capability_token`].
fn method_call(line: &str, name: &str) -> bool {
    let dotted = format!(".{name}");
    let chars: Vec<char> = line.chars().collect();
    let n: Vec<char> = dotted.chars().collect();
    if n.len() > chars.len() {
        return false;
    }
    for i in 0..=(chars.len() - n.len()) {
        if chars[i..i + n.len()] != n[..] {
            continue;
        }
        let mut j = i + n.len();
        // The name must END here, or `.open_hookish(` would read as `.open_hook(`.
        if j < chars.len() && is_ident_char(chars[j]) {
            continue;
        }
        while j < chars.len() && chars[j].is_whitespace() {
            j += 1;
        }
        if j < chars.len() && chars[j] == '(' {
            let inside: String = chars[j + 1..].iter().collect();
            if opens_with_capability_token(&inside) {
                continue;
            }
            return true;
        }
    }
    false
}

/// `resolver` `.` `resolve` `(`, each separated by optional whitespace — a spelling the bare and
/// method forms both miss.
fn resolver_resolve(line: &str) -> bool {
    let mut rest = line;
    while let Some(i) = rest.find("resolver") {
        let after = rest[i + "resolver".len()..].trim_start();
        if let Some(a) = after.strip_prefix('.') {
            let a = a.trim_start();
            if let Some(b) = a.strip_prefix("resolve") {
                if b.trim_start().starts_with('(') {
                    return true;
                }
            }
        }
        rest = &rest[i + "resolver".len()..];
    }
    false
}

/// `async` at a word boundary, then whitespace, then `fn`, then whitespace. An `async move {` or
/// `async {` block does NOT arm: those are values, and what matters is the thread that polls them,
/// decided by the enclosing fn (already tracked) or by a spawn site (already an offload opener).
fn opens_async_fn(line: &str) -> bool {
    let chars: Vec<char> = line.chars().collect();
    let n: Vec<char> = "async".chars().collect();
    if n.len() > chars.len() {
        return false;
    }
    for i in 0..=(chars.len() - n.len()) {
        if chars[i..i + n.len()] != n[..] {
            continue;
        }
        if i > 0 && is_ident_char(chars[i - 1]) {
            continue;
        }
        let mut j = i + n.len();
        let ws = j;
        while j < chars.len() && chars[j].is_whitespace() {
            j += 1;
        }
        if j == ws {
            continue;
        }
        if chars[j..].starts_with(&['f', 'n'])
            && chars.get(j + 2).is_some_and(|c| c.is_whitespace())
        {
            return true;
        }
    }
    false
}

fn is_comment(line: &str) -> bool {
    let t = line.trim_start();
    t.starts_with("//") || t.starts_with('*') || t.starts_with("/*")
}

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

/// What one file's scan produced, and whether it finished in a state the reader can trust.
struct FileScan {
    hits: Vec<String>,
    /// The scan ended with a counter still open. The Rust analogue of the shell's aborted awk: the
    /// window never closed, so everything after the opener was judged in a state the scanner had
    /// already lost track of, and the answer it gives is not "clean".
    lost_track: Option<String>,
}

fn scan_file(rel: &str, text: &str) -> FileScan {
    let table = seams();
    let mut hits = Vec::new();
    let mut depth: i64 = 0;
    let mut pdepth: i64 = 0;
    let mut async_at: i64 = -1;
    let mut entered = false;
    let mut off_b: i64 = -1;
    let mut off_p: i64 = 0;
    let mut test_at: i64 = -1;
    let mut t_entered = false;
    let mut prev_allow = false;
    let mut lex = scan::LexState::default();

    for (idx, line) in text.lines().enumerate() {
        let comment = is_comment(line);
        let marker = carries_allow_marker(line);
        let allow = marker || prev_allow;
        prev_allow = marker || (comment && prev_allow);

        // The seam patterns below read the RAW line; the two depth counters read the blanked copy.
        // A `}` inside a string literal used to drive `depth` below `async_at` and close the async
        // window early, disarming every seam check for the rest of the function.
        let counted = scan::blank_code(line, &mut lex);
        let db = i64::from(scan::delta(&counted, '{', '}'));
        let dp = i64::from(scan::delta(&counted, '(', ')'));

        if !comment {
            if off_b < 0 && OFFLOAD_OPENERS.iter().any(|o| bare_call(line, o)) {
                off_b = depth;
                off_p = pdepth;
            }
            if async_at < 0 && opens_async_fn(line) {
                async_at = depth;
                entered = false;
            }
            if test_at < 0 && line.contains("#[cfg(test)]") {
                test_at = depth;
                t_entered = false;
            }
        }

        let armed = async_at >= 0 && off_b < 0 && test_at < 0 && !comment && !allow;
        if armed {
            for seam in &table {
                let hit = seam.methods.iter().any(|m| method_call(line, m))
                    || seam.bare.iter().any(|b| bare_call(line, b))
                    || (seam.msg.starts_with("secret-plugin") && resolver_resolve(line));
                if hit {
                    hits.push(finding(rel, idx + 1, seam.msg));
                    break;
                }
            }
        }

        // Advance LAST, so a rule sees the depth the line STARTED at.
        depth += db;
        pdepth += dp;
        if off_b >= 0 && depth <= off_b && pdepth <= off_p {
            off_b = -1;
            off_p = 0;
        }
        if async_at >= 0 && depth > async_at {
            entered = true;
        }
        if async_at >= 0 && entered && depth <= async_at && off_b < 0 {
            async_at = -1;
        }
        if test_at >= 0 && depth > test_at {
            t_entered = true;
        }
        if test_at >= 0 && t_entered && depth <= test_at {
            test_at = -1;
        }
        if test_at >= 0 && !t_entered && line.trim_end().ends_with(';') {
            test_at = -1;
        }
    }

    // THE SCANNER LOST TRACK is an OFFLOAD WINDOW THAT NEVER SHUT, and deliberately nothing else.
    //
    // The obvious wider test — "the brace depth returned to zero" — is still not adopted here. The
    // reason it was ruled out is GONE: the counter used to read a `{` inside a string literal as
    // structure, which is why thirteen files in this tree ended at a non-zero depth without one of
    // them being malformed, and the depths now come off `scan::blank_code`, which cannot see a
    // literal. Adopting the wider test is a separate change with its own measurement — this row is
    // NOT quietly widened on the strength of the counter having got better.
    //
    // An unclosed OFFLOAD window is different in kind: it does not merely mean the counters drifted,
    // it means every remaining line of the file was EXEMPTED by a window that should have shut. That
    // is a silent pass over real code, which is the failure this row exists for — the same fact the
    // shell was recording when it caught an awk that never ran.
    let lost_track = (off_b >= 0).then(|| {
        format!(
            "{rel}: an offload opener's argument list never closed, so every line after it was \
             exempted by a window that should have shut"
        )
    });

    FileScan { hits, lost_track }
}

pub struct BlockingFfiGate;

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

/// THE POPULATION IS DERIVED FROM THE TREE (see [`crate::gates::population`]), not from `roots`:
/// the three fixed roots plus the two resolved plane homes opened 280 of the tree's 725 non-test
/// `.rs` files, and `tokio::spawn(async move { … })` inside `busbar-substrate` was never read at
/// all. `roots` is still resolved and still checked for existence, because a plane that cannot be
/// located is its own refusal — it just no longer decides what gets opened.
fn candidates(cx: &Ctx, roots: &[String]) -> Result<Population, String> {
    let population = population::source_population(cx)?;
    let mut unusable: Vec<String> = population
        .drained
        .iter()
        .map(|c| format!("crates/{c}: has a src/ and contributed no file to the scan"))
        .collect();
    for root in roots {
        if !cx.exists(root) {
            unusable.push(format!("{root}: not on disk"));
        }
    }
    if !unusable.is_empty() {
        return Err(unusable.join(" | "));
    }
    Ok(population)
}

impl Gate for BlockingFfiGate {
    fn name(&self) -> &'static str {
        "blocking-ffi"
    }

    fn owed(&self) -> Vec<String> {
        vec![
            ROW_PLANE_ROOTS.to_string(),
            ROW_SCAN_FLOOR.to_string(),
            ROW_SCAN_STATUS.to_string(),
            ROW_NO_INLINE.to_string(),
        ]
    }

    fn run(&self, cx: &Ctx) -> Verdict {
        let roots = match scan_roots(cx) {
            Ok(r) => r,
            Err(why) => {
                return Verdict::of(vec![
                    Row::fail(ROW_PLANE_ROOTS, "a plane root did not resolve", why),
                    Row::fail(
                        ROW_SCAN_FLOOR,
                        "the root set is unknown",
                        DID_NOT_RUN.to_string(),
                    ),
                    Row::fail(
                        ROW_SCAN_STATUS,
                        "the root set is unknown",
                        DID_NOT_RUN.to_string(),
                    ),
                    Row::fail(
                        ROW_NO_INLINE,
                        "the scan did not run",
                        DID_NOT_RUN.to_string(),
                    ),
                ]);
            }
        };
        let population = match candidates(cx, &roots) {
            Ok(f) => f,
            Err(why) => {
                return Verdict::of(vec![
                    Row::pass(ROW_PLANE_ROOTS, "every plane root resolved", CLEAN),
                    Row::fail(ROW_SCAN_FLOOR, "a scan root could not be read", why),
                    Row::fail(
                        ROW_SCAN_STATUS,
                        "the scan set is incomplete",
                        DID_NOT_RUN.to_string(),
                    ),
                    Row::fail(
                        ROW_NO_INLINE,
                        "the scan did not run",
                        DID_NOT_RUN.to_string(),
                    ),
                ]);
            }
        };

        let files = population.files.clone();
        if population.below_floor() {
            return Verdict::of(vec![
                Row::pass(ROW_PLANE_ROOTS, "every plane root resolved", CLEAN),
                Row::fail(
                    ROW_SCAN_FLOOR,
                    "the scan set is below its floor",
                    format!(
                        "{}. This gate scanned (almost) nothing, so its verdict is meaningless — \
                         it is NOT a pass.",
                        population.census()
                    ),
                ),
                Row::fail(
                    ROW_SCAN_STATUS,
                    "the scan did not run",
                    DID_NOT_RUN.to_string(),
                ),
                Row::fail(
                    ROW_NO_INLINE,
                    "the scan did not run",
                    DID_NOT_RUN.to_string(),
                ),
            ]);
        }

        let mut hits = Vec::new();
        let mut broke = Vec::new();
        for f in &files {
            let scan = scan_file(&f.rel_str(), &f.text);
            match scan.lost_track {
                // A FILE THE SCANNER DID NOT GET THROUGH CONTRIBUTES NO FINDINGS AND IS NOT CLEAN.
                // Banking its empty output as "no findings" is the defect this row exists for.
                Some(why) => broke.push(why),
                None => hits.extend(scan.hits),
            }
        }
        hits.sort();
        broke.sort();

        let status = if broke.is_empty() {
            Row::pass(
                ROW_SCAN_STATUS,
                "every candidate file was scanned end to end",
                CLEAN,
            )
        } else {
            Row::fail(
                ROW_SCAN_STATUS,
                "the scanner did not get through every candidate file",
                format!(
                    "{} file(s): {} — an aborted scan finds no inline plugin call, and finding none \
                     is this gate's PASS. It is RED instead.",
                    broke.len(),
                    broke.join(" | ")
                ),
            )
        };

        Verdict::of(vec![
            Row::pass(ROW_PLANE_ROOTS, "every plane root resolved", CLEAN),
            Row::pass(
                ROW_SCAN_FLOOR,
                "the scan set cleared its floor",
                population.census(),
            ),
            status,
            row_no_inline(&hits),
        ])
    }

    fn has_legacy_adapter(&self) -> bool {
        true
    }

    fn legacy_rows(&self, _cx: &Ctx, runs: &[LegacyRun]) -> Option<Result<Vec<Row>, String>> {
        let run = &runs[0];
        Some(translate(run))
    }

    fn selftest<'a>(&'a self, cx: &'a Ctx) -> Report<'a> {
        let mut report = Report::new();
        report.push(prove_green(
            cx,
            self,
            "no plugin FFI is called inline from an async fn",
            &self.owed().iter().map(String::as_str).collect::<Vec<_>>(),
        ));

        // THE FIVE HISTORICAL INSTANCES, transcribed, plus the snapshot builder: six shapes.
        let mut ov = Overlay::new();
        ov.set(
            format!("{CORE}/planted_inline_ffi.rs"),
            "async fn begin(app: &App, method: &str) -> Response {\n\
             \x20   match m.module.begin_login(&begin) {\n        _ => todo!(),\n    }\n}\n\n\
             async fn credential_submit(app: &App) -> Response {\n\
             \x20   let principal = match m.module.complete_login(&cl) {\n        _ => todo!(),\n    };\n}\n\n\
             async fn auth_middleware(app: &App) -> Response {\n\
             \x20   let outcome = module.authenticate(bearer);\n}\n\n\
             pub(crate) async fn push_configure(env: &HookEnv) -> Result<(), String> {\n\
             \x20   let resolved = env.resolve_hook_settings(&hook.settings)?;\n    Ok(())\n}\n\n\
             async fn status(env: &HookEnv) -> Option<HookStatus> {\n\
             \x20   let transport = gate_transport_named(name, hook, env, 0)?;\n    None\n}\n\n\
             pub(crate) async fn register_hook(handle: &Arc<AppHandle>) -> Response {\n\
             \x20   let installed = Arc::new(build_with_hook(current, &txn_name, cfg)?);\n}\n",
        );
        report.push(prove_red(
            cx,
            self,
            "all six inline shapes are flagged",
            &[ROW_NO_INLINE],
            ov,
            &[
                "6 finding(s)",
                "login-plugin FFI",
                "auth-plugin FFI",
                "secret-plugin FFI",
                "plugin OPEN",
                "an App/hook-chain build",
            ],
        ));

        // THE KERNEL'S STEP SEAM IS NOT A PLUGIN HANDLE, AND THE CARVE-OUT IS NOT A MUTE FOR THE
        // LINE BELOW IT. `Units::authenticate` and `AuthModule::authenticate` are two different
        // traits with one spelling; only the second is a dlopen hop. The pair is planted TOGETHER
        // in one async fn, because a carve-out proved on a file that holds nothing else proves
        // nothing: the plugin call one line down must still be named.
        let mut ov = Overlay::new();
        ov.set(
            format!("{CORE}/planted_kernel_step.rs"),
            "pub async fn run_unit_async<U: Units>(units: &U, ctx: &UnitCtx) -> Ended {\n\
             \x20   let opened = units.authenticate(&UnitToken::<Authenticate>::mint(seal), ctx);\n\
             \x20   let outcome = module.authenticate(bearer);\n\
             \x20   opened\n}\n",
        );
        report.push(prove_red(
            cx,
            self,
            "a kernel step reached through a minted capability token is not a plugin call, and the \
             plugin call beside it still is",
            &[ROW_NO_INLINE],
            ov,
            &[
                "1 finding(s)",
                "planted_kernel_step.rs:3",
                "auth-plugin FFI",
            ],
        ));

        // THE SANCTIONED FORMS, in BOTH spellings: a braced closure on the opener line, and the
        // same call across a multi-line argument list where no brace ever opens — only the paren
        // counter can carry that one. Plus a sync fn and an allowlisted boot call.
        let mut ov = Overlay::new();
        ov.set(
            format!("{CORE}/planted_offloaded.rs"),
            "async fn begin(app: &App) -> Response {\n\
             \x20   match offload_login_call(&app.login_methods, method, \"begin_login\", move |m| {\n\
             \x20       m.module.begin_login(&begin)\n    })\n    .await\n    {\n        _ => todo!(),\n    }\n}\n\n\
             async fn credential_submit(app: &App) -> Response {\n\
             \x20   let principal = match offload_login_call(\n        &app.login_methods,\n\
             \x20       &cookie.method,\n        \"complete_login\",\n\
             \x20       move |m| m.module.complete_login(&cl),\n    )\n    .await\n    {\n        _ => todo!(),\n    };\n}\n\n\
             pub(crate) async fn run_chain(auth: &Arc<AuthMiddleware>) -> ChainVerdict {\n\
             \x20   let joined = tokio::task::spawn_blocking(move || {\n\
             \x20       let verdict = auth.run_chain_cached(candidate.as_deref());\n        verdict\n\
             \x20   })\n    .await;\n}\n\n\
             async fn gate_transport_offloaded(env: &HookEnv) -> Option<Arc<dyn RoutingPolicy>> {\n\
             \x20   offload_bounded(name, move || gate_transport_named(&n, &hook, &env, 0)).await\n}\n\n\
             fn gate_transport_named(env: &HookEnv) -> Option<Arc<dyn RoutingPolicy>> {\n\
             \x20   let resolved = env.resolve_hook_settings(&hook.settings).ok()?;\n\
             \x20   env.registry.open_hook(&hook.plugin, &cfg_json).ok()\n}\n\n\
             async fn serve_listener(secret_resolver: Arc<SecretResolver>) {\n\
             \x20   // blocking-ffi-lint: allow — BOOT ONLY, before this listener serves anything.\n\
             \x20   let server_config = tls::build_server_config(&tls, &secret_resolver);\n}\n\n\
             // A doc comment naming m.module.begin_login(&begin) inside an async fn is prose.\n",
        );
        report.push(prove_green(
            &cx.with_overlay(ov),
            self,
            "both offload spellings, a sync fn, an allowlisted boot call and prose stay silent",
            &[ROW_NO_INLINE],
        ));

        // AN OFFLOAD CLOSURE MUST NOT MUTE THE REST OF THE FN, and a marker is not a blanket mute.
        let mut ov = Overlay::new();
        ov.set(
            format!("{CORE}/planted_scope.rs"),
            "async fn handler(app: &App, env: &HookEnv) -> Response {\n\
             \x20   let a = tokio::task::spawn_blocking(move || {\n\
             \x20       env2.resolve_hook_settings(&hook.settings)\n    })\n    .await;\n\
             \x20   // Back on the reactor — this one IS the defect.\n\
             \x20   let b = env.resolve_hook_settings(&hook.settings);\n\
             \x20   // blocking-ffi-lint: allow — covers the NEXT call only (and this reason may run\n\
             \x20   // onto a second comment line without widening the marker).\n\
             \x20   let c = env.resolve_hook_settings(&hook.settings);\n\
             \x20   let d = env.resolve_hook_settings(&hook.settings);\n}\n",
        );
        report.push(prove_red(
            cx,
            self,
            "an offload closure exempts only its own body, and a marker covers exactly one call",
            &[ROW_NO_INLINE],
            ov,
            &["2 finding(s)", "planted_scope.rs:7", "planted_scope.rs:11"],
        ));

        // AN IN-FILE `#[cfg(test)]` MODULE is exempt — the kind a `tests/`-directory exclusion
        // cannot see — and production code AFTER it is scanned again.
        let mut ov = Overlay::new();
        ov.set(
            format!("{CORE}/planted_test_mod.rs"),
            "#[cfg(test)]\nmod tests {\n    async fn t(env: &HookEnv) {\n\
             \x20       let _ = env.resolve_hook_settings(&hook.settings);\n    }\n}\n\n\
             async fn after(env: &HookEnv) {\n\
             \x20   let _ = env.resolve_hook_settings(&hook.settings);\n}\n",
        );
        report.push(prove_red(
            cx,
            self,
            "a cfg(test) module is exempt and the production fn after it is scanned again",
            &[ROW_NO_INLINE],
            ov,
            &["1 finding(s)", "planted_test_mod.rs:9"],
        ));

        // THE SCANNER THAT DID NOT GET THROUGH. The shell banked an aborted awk's empty output as
        // "no findings", for every file at once. Here the window that never closes is the same
        // fact, and it must not be reported as a clean file.
        let mut ov = Overlay::new();
        ov.set(
            format!("{CORE}/planted_unclosed.rs"),
            "async fn never_closes(env: &HookEnv) {\n\
             \x20   let a = tokio::task::spawn_blocking(move || {\n\
             \x20       env.resolve_hook_settings(&hook.settings)\n",
        );
        report.push(prove_red(
            cx,
            self,
            "a file the scanner lost track of is a refusal, not a file with no findings",
            &[ROW_SCAN_STATUS],
            ov,
            &["never closed", "planted_unclosed.rs"],
        ));

        // THE FLOOR, on the run path.
        match scan_roots(cx) {
            Ok(roots) => match candidates(cx, &roots) {
                Ok(_) => {
                    let mut ov = Overlay::new();
                    for root in &roots {
                        if let Ok(files) = cx.walk(
                            &WalkSpec::new([root.clone()])
                                .ext("rs")
                                .exclude([EXCLUDE_TESTS_DIR]),
                        ) {
                            for f in files.iter().skip(1) {
                                ov.remove(&f.rel);
                            }
                        }
                    }
                    report.push(prove_red(
                        cx,
                        self,
                        "a scan set below its floor is refused though every root still holds a file",
                        &[ROW_SCAN_FLOOR],
                        ov,
                        &["below its floor"],
                    ));
                }
                Err(e) => report.note_infra_failure(format!("blocking-ffi selftest: {e}")),
            },
            Err(e) => report.note_infra_failure(format!("blocking-ffi selftest: {e}")),
        }

        // THE PLANE ROOTS: a plane that SPLIT away is invisible to every floor. Driven THROUGH
        // `Gate::run` over a fixture tree in which no plane declares its grammar, because the
        // plane resolver reads `std::fs` and no overlay can reach it.
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

/// Read the shell gate's own output into the same four rows. Nothing here re-scans the tree.
fn translate(run: &LegacyRun) -> Result<Vec<Row>, String> {
    let mut hits = Vec::new();
    let mut plane_unresolved = None;
    let mut floor_broken = None;
    let mut scanner_broke = false;
    let mut broke_lines = Vec::new();
    let mut ran = false;

    for raw in run.lines() {
        let t = raw.trim();
        if t.contains("PLANE ROOT UNRESOLVED") {
            plane_unresolved = Some(t.to_string());
            continue;
        }
        if t.contains("SCAN ROOT EMPTY OR MOVED") {
            floor_broken = Some(t.to_string());
            continue;
        }
        if t.contains("THE SCANNER DID NOT RUN") {
            scanner_broke = true;
            continue;
        }
        if scanner_broke && t.contains("awk exited") {
            broke_lines.push(t.to_string());
            continue;
        }
        if t.starts_with("scan set:") || t == "blocking-ffi-lint passed" {
            ran = true;
            continue;
        }
        if let Some(hit) = t.strip_prefix("BLOCKING-FFI: ") {
            ran = true;
            hits.push(hit.to_string());
        }
    }

    if plane_unresolved.is_none() && floor_broken.is_none() && !scanner_broke && !ran {
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
                ROW_SCAN_FLOOR,
                "the root set is unknown",
                DID_NOT_RUN.to_string(),
            ),
            Row::fail(
                ROW_SCAN_STATUS,
                "the root set is unknown",
                DID_NOT_RUN.to_string(),
            ),
            Row::fail(
                ROW_NO_INLINE,
                "the scan did not run",
                DID_NOT_RUN.to_string(),
            ),
        ]);
    }
    if let Some(why) = floor_broken {
        return Ok(vec![
            Row::pass(ROW_PLANE_ROOTS, "every plane root resolved", CLEAN),
            Row::fail(ROW_SCAN_FLOOR, "the scan set is below its floor", why),
            Row::fail(
                ROW_SCAN_STATUS,
                "the scan did not run",
                DID_NOT_RUN.to_string(),
            ),
            Row::fail(
                ROW_NO_INLINE,
                "the scan did not run",
                DID_NOT_RUN.to_string(),
            ),
        ]);
    }
    if scanner_broke {
        return Ok(vec![
            Row::pass(ROW_PLANE_ROOTS, "every plane root resolved", CLEAN),
            Row::pass(ROW_SCAN_FLOOR, "the scan set cleared its floor", CLEAN),
            Row::fail(
                ROW_SCAN_STATUS,
                "the scanner did not get through every candidate file",
                broke_lines.join(" | "),
            ),
            Row::fail(
                ROW_NO_INLINE,
                "the scan did not run",
                DID_NOT_RUN.to_string(),
            ),
        ]);
    }

    hits.sort();
    Ok(vec![
        Row::pass(ROW_PLANE_ROOTS, "every plane root resolved", CLEAN),
        Row::pass(ROW_SCAN_FLOOR, "the scan set cleared its floor", CLEAN),
        Row::pass(
            ROW_SCAN_STATUS,
            "every candidate file was scanned end to end",
            CLEAN,
        ),
        row_no_inline(&hits),
    ])
}
