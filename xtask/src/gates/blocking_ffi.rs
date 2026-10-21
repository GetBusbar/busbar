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
//! * `blocking-ffi:plane-roots` — mcp resolves (and a2a did, until FLIP-A2A deleted its engine).
//!   They were 71 of the 238 files scanned against a floor of 100, and both cross the hook/store seams from async code, so a plane that SPLIT into
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
//! `busbar_contract::auth::AuthModule::authenticate` share a spelling and nothing else.
//!
//! THE SEAMS are two tables. The hand rows ([`seams`]) are the historical shapes, each one a
//! composite that reaches a plugin through the kernel (a secret resolve, a hook-chain build). The
//! DOOR seams are DERIVED from `crates/plugin-loader/src` on every run ([`door_seams`]): every method
//! of an `impl Trait for Type` there that parks its caller's thread on a door crossing is a seam,
//! so the store bridge (`impl RecordStore for LoadedStore`) is one without anyone listing it, and a
//! door the loader grows is one the day it lands.
//!
//! EVERY REAL LINE IS READ, AND ONLY CODE. The rules read the line as [`scan::blank_code`] leaves
//! it — literal and comment bodies blanked, carried across lines — so a seam named in a string or a
//! trailing comment is not a call, and a line is a comment only when no code survives the blanking
//! (`*slot = …` is code). Test scope is [`scan::test_scope`]'s answer, shared with every scanner in
//! this crate. A brace counted wrong is a false-POSITIVE risk — a spurious flag someone must look
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
use std::collections::{BTreeMap, BTreeSet};

pub const ROW_PLANE_ROOTS: &str = "blocking-ffi:plane-roots";
pub const ROW_SCAN_FLOOR: &str = "blocking-ffi:scan-floor";
pub const ROW_SCAN_STATUS: &str = "blocking-ffi:scan-status";
pub const ROW_NO_INLINE: &str = "blocking-ffi:no-inline-ffi";

// `busbar-core` was absorbed into `busbar-kernel` (W4.a, 673ecdaaa) — the hook/store offload seams
// (`Txn::read_store`, `Txn::store_write`, `hooks::offload_bounded`) this gate polices now live
// under `crates/busbar-kernel/src`.
const CORE: &str = "crates/busbar-kernel/src";
// `crates/busbar-llm/src` is struck (DEV-GREEN row 83, coordinator ruling 2026-10-18): the retired
// engine crate is deleted and the llm plane is its door crate, `crates/busbar-plane-llm`, read with
// every other crate by the population scan below.
const FIXED_ROOTS: &[&str] = &[CORE, "crates/busbar/src"];
// `a2a` is struck: FLIP-A2A deleted crates/busbar-a2a, and the A2A plane is crates/busbar-plane-a2a,
// a memory-ABI door that declares no `PLANE_DECL` (so no root resolves for it). Its source is still
// read: the scan population is every crate under `crates/` (`population::source_population`).
const PLANE_KEYS: &[&str] = &["mcp"];
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
#[derive(Clone)]
struct Seam {
    /// Method-call spellings: `.name(`.
    methods: Vec<String>,
    /// Bare-call spellings: `name(` at an identifier boundary.
    bare: Vec<String>,
    msg: String,
    /// A seam DERIVED from the loader's door-backed impls ([`door_seams`]). Its method names are
    /// shared with the door's ASYNC methods (`RecordStore::upsert_plane_record` beside
    /// `StoreCalls::upsert_plane_record`), and only the second can be awaited: every derived seam
    /// is a synchronous method answering a value, so an `.await` on its result does not compile and
    /// an awaited call of the name is the async door method.
    derived: bool,
    /// A derived seam's parameter count per method, `self` not counted. Rust has no overloading
    /// and no default arguments, so a call naming the method with another argument count is
    /// another type's method (`table.open(raw_key)` is not `HookAxis::open`, which takes four). An
    /// arity the reader could not settle, on either side, matches.
    arity: BTreeMap<String, Option<usize>>,
    /// A derived seam's trait and the types whose impls back it: what a receiver must be bound to
    /// for a call of one of its method names to be this seam's.
    types: Vec<String>,
    /// THE RECEIVERS a derived seam's call may be made on: every name the tree binds to one of
    /// [`Seam::types`] (a field, parameter or binding typed with it, or a fn returning it). A
    /// method name is not a type (`conns.open(..)` is the connector's, `post.open(..)` the node's
    /// posting site): a call whose receiver is bound to none of them is another type's method.
    /// `None` for a hand row, and a receiver the reader cannot name is held to be the seam's.
    bound: Option<BTreeSet<String>>,
}

fn strs(names: &[&str]) -> Vec<String> {
    names.iter().map(|n| (*n).to_string()).collect()
}

fn seams() -> Vec<Seam> {
    vec![
        // A `kind: auth` LOGIN plugin (the hosted browser flow) — a credential bind or a token hop.
        Seam {
            methods: strs(&["begin_login", "complete_login", "login_kind"]),
            bare: Vec::new(),
            msg: "login-plugin FFI (begin_login/complete_login/login_kind) called inline from an \
                  async fn — route it through auth::token::offload_login_call"
                .to_string(),
            derived: false,
            arity: BTreeMap::new(),
            types: Vec::new(),
            bound: None,
        },
        // A `kind: auth` VERIFY plugin, direct or via the chain runner.
        Seam {
            methods: strs(&["authenticate"]),
            bare: strs(&["run_chain_cached"]),
            msg:
                "auth-plugin FFI (authenticate/run_chain_cached) called inline from an async fn — \
                  use run_chain_on_request_path / run_admin_chain_maybe_offloaded"
                    .to_string(),
            derived: false,
            arity: BTreeMap::new(),
            types: Vec::new(),
            bound: None,
        },
        // A `kind: secret` plugin: SecretResolver's non-built-in arm is a transport_call.
        Seam {
            methods: Vec::new(),
            bare: strs(&[
                "resolve_hook_settings",
                "resolve_settings",
                "resolve_string",
                "preresolve_hook_secrets",
                "build_server_config",
            ]),
            msg: "secret-plugin FFI (SecretResolver::resolve*) called inline from an async fn — \
                  resolve on a blocking thread (see hooks::gate_transport_named)"
                .to_string(),
            derived: false,
            arity: BTreeMap::new(),
            types: Vec::new(),
            bound: None,
        },
        // dlopen + the plugin CONSTRUCTOR: a staging copy, dynamic-linker work, then the open.
        Seam {
            methods: strs(&["open_hook"]),
            bare: strs(&["gate_transport_named", "preopen_gate_hooks"]),
            msg: "plugin OPEN (dlopen + constructor) called inline from an async fn — use \
                  hooks::gate_transport_offloaded / offload_bounded"
                .to_string(),
            derived: false,
            arity: BTreeMap::new(),
            types: Vec::new(),
            bound: None,
        },
        // Whole-snapshot builders: each re-resolves the hook chain, i.e. secrets + opens, per hook.
        Seam {
            methods: Vec::new(),
            bare: strs(&[
                "build_app_from_config",
                "build_with_hook",
                "build_without_hook",
                "build_with_registry",
                "resolve_gate_hooks",
                "resolve_rewrite_hooks",
                "resolve_tap_hooks",
                "resolve_pool_gates",
                "resolve_pool_rewrites",
            ]),
            msg:
                "an App/hook-chain build (secret resolve + dlopen per hook) called inline from an \
                  async fn — route it through Txn::read_store"
                    .to_string(),
            derived: false,
            arity: BTreeMap::new(),
            types: Vec::new(),
            bound: None,
        },
        // A `kind: export` / `kind: hook` plugin serving an inbound HTTP route.
        Seam {
            methods: strs(&["handle_http", "handle_http_with_app"]),
            bare: Vec::new(),
            msg: "export/hook-plugin HTTP dispatch called inline from an async fn — serve it on \
                  spawn_blocking (see plugin_routes::plugin_route_dispatch)"
                .to_string(),
            derived: false,
            arity: BTreeMap::new(),
            types: Vec::new(),
            bound: None,
        },
    ]
}

fn finding(rel: &str, line: usize, msg: &str) -> String {
    format!("{rel}:{line}: {msg}")
}

/// `census` names the door seams the run derived, so a pass says WHICH crossings it looked for.
fn row_no_inline(offenders: &[String], census: &str) -> Row {
    if offenders.is_empty() {
        let detail = if census.is_empty() {
            CLEAN.to_string()
        } else {
            format!("{CLEAN}; {census}")
        };
        return Row::pass(
            ROW_NO_INLINE,
            "no synchronous plugin FFI is called inline from an async fn",
            detail,
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
/// `busbar_contract::auth::AuthModule::authenticate` takes `Option<&str>`, the presented credential, and
/// nothing else. `busbar_kernel::teller::Units` is a DIFFERENT trait that happens to spell one of
/// its steps `authenticate`, and the kernel calls it as `units.authenticate(&Pass::<
/// Authenticate>::mint(seal), ctx)`. A `Pass` (`busbar_contract::caps::Pass`, the stage-pass of
/// #72, once spelled `UnitToken`) is a capability the kernel mints against its own `seal` for the
/// length of one call; it is not a type a plugin's ABI can name, and no plugin can mint one. The
/// step it opens states an identity: the async loop's implementors read one their door already
/// resolved, and the one implementor whose step crosses a plugin (the admin chain's) is walked by
/// the synchronous `run_unit` on the blocking pool. So the mint spelling is not "a call we have
/// decided to trust": it is the one textual form a plugin call CANNOT take.
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
    arg.starts_with("Pass::<")
}

/// `.name` followed by optional whitespace and `(`. The shell's `\.(a|b)[[:space:]]*\(`, plus the
/// kernel step-seam carve-out in [`opens_with_capability_token`].
fn method_call(line: &str, name: &str) -> bool {
    !method_calls(line, name).is_empty()
}

/// Every `.name(` call on the line, as the CHAR index of its `(` — the place [`awaited`] starts
/// matching the argument list from.
fn method_calls(line: &str, name: &str) -> Vec<usize> {
    let mut at = Vec::new();
    let dotted = format!(".{name}");
    let chars: Vec<char> = line.chars().collect();
    let n: Vec<char> = dotted.chars().collect();
    if n.len() > chars.len() {
        return at;
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
            at.push(j);
        }
    }
    at
}

/// The argument list opening at char `open` of line `idx`, across lines, without its parens; `None`
/// when it does not close within the window.
fn arg_list(lines: &[&str], idx: usize, open: usize) -> Option<String> {
    const WINDOW: usize = 40;
    let mut depth = 0i64;
    let mut out = String::new();
    for (k, line) in lines.iter().enumerate().skip(idx).take(WINDOW) {
        let from = if k == idx { open } else { 0 };
        for c in line.chars().skip(from) {
            match c {
                '(' | '[' | '{' => depth += 1,
                ')' | ']' | '}' => depth -= 1,
                _ => {}
            }
            if depth == 0 {
                return Some(out.chars().skip(1).collect());
            }
            out.push(c);
        }
        out.push(' ');
    }
    None
}

/// How many arguments a parenthesised list holds: its top-level `,`-separated non-empty parts.
/// `None` when the list holds a closure's `|` or an angle bracket at top level, whose commas this
/// reader cannot place.
fn arity_of(list: &str) -> Option<usize> {
    let mut depth = 0i32;
    let mut parts = 0usize;
    let mut seen = false;
    let mut prev = ' ';
    for c in list.chars() {
        match c {
            '(' | '[' | '{' => depth += 1,
            ')' | ']' | '}' => depth -= 1,
            '|' | '<' if depth == 0 => return None,
            '>' if depth == 0 && prev != '-' && prev != '=' => return None,
            ',' if depth == 0 => {
                if seen {
                    parts += 1;
                }
                seen = false;
                prev = c;
                continue;
            }
            _ => {}
        }
        if !c.is_whitespace() {
            seen = true;
        }
        prev = c;
    }
    Some(parts + usize::from(seen))
}

fn call_arity(lines: &[&str], idx: usize, open: usize) -> Option<usize> {
    arity_of(&arg_list(lines, idx, open)?)
}

/// A declaration's parameter count, `self` not counted, read off its signature (`fn name(…)`).
/// Angle brackets ARE read here: a parameter's type is where they occur (`HashMap<K, V>`), and a
/// `->` or `=>` is not one.
fn param_arity(sig: &str, name: &str) -> Option<usize> {
    let at = sig.find(&format!("fn {name}"))? + "fn ".len() + name.len();
    let chars: Vec<char> = sig[at..].chars().collect();
    let arrow = |i: usize| i > 0 && matches!(chars[i - 1], '-' | '=');
    let mut i = 0;
    while chars.get(i).is_some_and(|c| c.is_whitespace()) {
        i += 1;
    }
    // The fn's own generics, `fn name<T: Fn(A) -> B>(`.
    if chars.get(i) == Some(&'<') {
        let mut depth = 0i32;
        while i < chars.len() {
            match chars[i] {
                '<' => depth += 1,
                '>' if !arrow(i) => depth -= 1,
                _ => {}
            }
            i += 1;
            if depth == 0 {
                break;
            }
        }
    }
    while chars.get(i).is_some_and(|c| c.is_whitespace()) {
        i += 1;
    }
    if chars.get(i) != Some(&'(') {
        return None;
    }
    i += 1;
    let mut depth = 1i32;
    let mut parts: Vec<String> = vec![String::new()];
    while i < chars.len() {
        let c = chars[i];
        match c {
            '(' | '[' | '{' | '<' => depth += 1,
            '>' if arrow(i) => {}
            ')' | ']' | '}' | '>' => depth -= 1,
            ',' if depth == 1 => {
                parts.push(String::new());
                i += 1;
                continue;
            }
            _ => {}
        }
        if depth == 0 {
            break;
        }
        if let Some(last) = parts.last_mut() {
            last.push(c);
        }
        i += 1;
    }
    let parts: Vec<&str> = parts
        .iter()
        .map(|p| p.trim())
        .filter(|p| !p.is_empty())
        .collect();
    let takes_self = parts.first().is_some_and(|p| {
        let p = p.trim_start_matches('&').trim_start();
        let p = match p.strip_prefix('\'') {
            Some(lt) => lt.split_once(char::is_whitespace).map_or("", |(_, r)| r),
            None => p,
        };
        let p = p.strip_prefix("mut ").unwrap_or(p).trim_start();
        p.strip_prefix("self")
            .is_some_and(|r| !r.starts_with(is_ident_char))
    });
    Some(parts.len() - usize::from(takes_self))
}

/// Is the call whose `(` sits at char `open` of line `idx` AWAITED — its argument list closed and
/// `.await` the next thing after it, on the same line or the next? Read over BLANKED lines, so a
/// paren inside a literal cannot close the list early. An argument list that never closes within
/// the window is answered `false`: the call is then judged as the synchronous seam, the direction
/// this gate may err in.
fn awaited(lines: &[&str], idx: usize, open: usize) -> bool {
    const WINDOW: usize = 40;
    let mut depth = 0i64;
    let mut tail: Option<String> = None;
    'lines: for (k, line) in lines.iter().enumerate().skip(idx).take(WINDOW) {
        let chars: Vec<char> = line.chars().collect();
        let from = if k == idx { open } else { 0 };
        for (i, c) in chars.iter().enumerate().skip(from) {
            match c {
                '(' => depth += 1,
                ')' => {
                    depth -= 1;
                    if depth == 0 {
                        let mut rest: String = chars[i + 1..].iter().collect();
                        if let Some(next) = lines.get(k + 1) {
                            rest.push(' ');
                            rest.push_str(next);
                        }
                        tail = Some(rest);
                        break 'lines;
                    }
                }
                _ => {}
            }
        }
    }
    tail.is_some_and(|t| {
        t.trim_start()
            .strip_prefix(".await")
            .is_some_and(|r| !r.starts_with(is_ident_char))
    })
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

/// The calls that hand an `async` block to a Tokio WORKER. `spawn_blocking` is deliberately not
/// here (it is an offload opener); these are the ones whose body runs on the async pool.
const ASYNC_SPAWNERS: &[&str] = &[
    "tokio::spawn",
    "tokio::task::spawn",
    "task::spawn",
    "spawn_local",
];

/// `async {` / `async move {` — an async BLOCK opener at a word boundary.
fn opens_async_block(line: &str) -> bool {
    async_block_at(line).is_some()
}

/// The byte offset of the first `async {` / `async move {` opener on the line.
fn async_block_at(line: &str) -> Option<usize> {
    let mut base = 0;
    let mut rest = line;
    while let Some(i) = rest.find("async") {
        let before_ok = rest[..i]
            .chars()
            .next_back()
            .is_none_or(|c| !is_ident_char(c));
        let after = &rest[i + "async".len()..];
        if before_ok {
            let a = after.trim_start();
            let a = a
                .strip_prefix("move")
                .filter(|m| !m.starts_with(is_ident_char))
                .map_or(a, str::trim_start);
            if a.starts_with('{') {
                return Some(base + i);
            }
        }
        base += i + "async".len();
        rest = after;
    }
    None
}

/// Does this line SPAWN onto the async pool — `tokio::spawn(` and friends, or a `.spawn(` method
/// (a `JoinSet`/`Handle`)?
fn calls_async_spawner(line: &str) -> bool {
    ASYNC_SPAWNERS.iter().any(|s| bare_call(line, s)) || method_call(line, "spawn")
}

/// The word starting at `s` (after leading whitespace) and what follows it.
fn next_word(s: &str) -> (&str, &str) {
    let s = s.trim_start();
    let end = s.find(|c: char| !is_ident_char(c)).unwrap_or(s.len());
    (&s[..end], &s[end..])
}

/// `async` at a word boundary, then whitespace, then the qualifiers Rust allows between it and
/// `fn` (`unsafe`, `extern` with or without its ABI string), then `fn` and whitespace. Visibility
/// (`pub(crate) async fn`) and `const` sit BEFORE `async` and need no reading. A bare `async move
/// {` or `async {` block does NOT arm here: those are values, and what matters is the thread that
/// polls them. A block handed to a SPAWNER does arm — see [`calls_async_spawner`] and item 186: a
/// `tokio::spawn(async move { … })` inside a SYNC fn runs its body on a Tokio worker, and a plugin
/// call there parks that worker exactly as one in an `async fn` does. `tokio::spawn` is not an
/// offload opener, so before item 186 that body was scanned by nothing.
///
/// Read over the BLANKED line, so `extern "C"` arrives as `extern " "`: the ABI string is skipped
/// by its quotes, whatever it held.
fn opens_async_fn(line: &str) -> bool {
    let mut base = 0;
    while let Some(i) = line[base..].find("async") {
        let at = base + i;
        base = at + "async".len();
        if line[..at].chars().next_back().is_some_and(is_ident_char) {
            continue;
        }
        let mut rest = &line[base..];
        if !rest.starts_with(char::is_whitespace) {
            continue;
        }
        let (mut word, mut after) = next_word(rest);
        if word == "unsafe" {
            rest = after;
            (word, after) = next_word(rest);
        }
        if word == "extern" {
            rest = after.trim_start();
            if let Some(abi) = rest.strip_prefix('"') {
                rest = abi.find('"').map_or("", |q| &abi[q + 1..]);
            }
            (word, after) = next_word(rest);
        }
        if word == "fn" && after.starts_with(char::is_whitespace) {
            return true;
        }
    }
    false
}

/// A line holding no CODE: [`scan::blank_code`] blanked every char of it, which is what a `//`
/// comment, a doc comment, the inside of a `/* … */` block and the inside of a multi-line string
/// literal all come to. Read off the blanked line rather than the raw one's first char: a raw line
/// opening with `*` is a block comment's margin OR a deref-assignment (`*slot = env.resolve(…)?;`),
/// and only the lexer knows which.
fn is_comment(raw: &str, counted: &str) -> bool {
    !raw.trim().is_empty() && counted.trim().is_empty()
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

/// [`scan_file`]'s answer for one file, MEMOISED on its path, its bytes and the seam table.
///
/// The gate re-scanned every candidate file of the tree on every run, and a self-test case is a run
/// over a tree one planted file away from the last: the battery paid for the whole tree's scan once
/// per case, and went over its work-unit budget (9 189 of 9 000, 2026-10-02) doing it. The scan is
/// a pure function of `(path, bytes, seams)` — and the seams are DERIVED from the loader, so a plant
/// in the loader changes them and is a different key — so every case after the first re-reads only
/// what it planted; the verdict over the hits is still taken fresh on every run.
static SCAN_MEMO: std::sync::OnceLock<
    std::sync::Mutex<std::collections::BTreeMap<u64, std::sync::Arc<FileScan>>>,
> = std::sync::OnceLock::new();

fn table_key(table: &[Seam]) -> u64 {
    use std::hash::{Hash, Hasher};
    let mut h = std::collections::hash_map::DefaultHasher::new();
    for seam in table {
        seam.methods.hash(&mut h);
        seam.bare.hash(&mut h);
        seam.msg.hash(&mut h);
        seam.derived.hash(&mut h);
        seam.arity.hash(&mut h);
    }
    h.finish()
}

fn scan_file_memo(rel: &str, text: &str, table: &[Seam], tkey: u64) -> std::sync::Arc<FileScan> {
    use std::hash::{Hash, Hasher};
    let key = {
        let mut h = std::collections::hash_map::DefaultHasher::new();
        rel.hash(&mut h);
        text.hash(&mut h);
        tkey.hash(&mut h);
        h.finish()
    };
    let memo = SCAN_MEMO.get_or_init(Default::default);
    if let Some(found) = memo
        .lock()
        .expect("the scan memo mutex is never poisoned")
        .get(&key)
    {
        return std::sync::Arc::clone(found);
    }
    let scan = std::sync::Arc::new(scan_file(rel, text, table));
    memo.lock()
        .expect("the scan memo mutex is never poisoned")
        .insert(key, std::sync::Arc::clone(&scan));
    scan
}

/// Does `seam` name a call on line `idx` of the BLANKED file?
fn seam_hit(seam: &Seam, lines: &[&str], idx: usize) -> bool {
    let line = lines[idx];
    let method = seam.methods.iter().any(|m| {
        method_calls(line, m).into_iter().any(|open| {
            if !seam.derived {
                return true;
            }
            let want = seam.arity.get(m).copied().flatten();
            let got = call_arity(lines, idx, open);
            !awaited(lines, idx, open)
                && (want.is_none() || got.is_none() || want == got)
                && receiver_bound(seam, lines, idx, open, m)
        })
    });
    method
        || seam.bare.iter().any(|b| bare_call(line, b))
        || (seam.msg.starts_with("secret-plugin") && resolver_resolve(line))
}

/// Whether the receiver of the `.name(` call whose `(` is at char `open` is one [`Seam::bound`]
/// names. A hand row binds every receiver; a receiver the reader cannot name (a call result, an
/// index) is held to be the seam's, the direction this gate is
/// allowed to be wrong in.
fn receiver_bound(seam: &Seam, lines: &[&str], idx: usize, open: usize, name: &str) -> bool {
    let Some(bound) = &seam.bound else {
        return true;
    };
    // The call's text up to its `(`. A chain split across lines (`table\n    .conns\n    .open(`)
    // keeps its receiver on the lines above, so those are joined on until the text opens with
    // something other than a `.` (at most eight lines up).
    let mut text: String = lines[idx].chars().take(open).collect();
    let mut back = idx;
    while text.trim_start().starts_with('.') && back > 0 && idx - back < 8 {
        back -= 1;
        text = format!("{}{}", lines[back].trim_end(), text.trim_start());
    }
    let chars: Vec<char> = text.chars().collect();
    // Back from the `(` over any space and the method's name to its `.`.
    let mut dot = chars.len();
    while dot > 0 && chars[dot - 1].is_whitespace() {
        dot -= 1;
    }
    dot = dot.saturating_sub(name.chars().count());
    if dot == 0 || chars[dot - 1] != '.' {
        return true;
    }
    let mut end = dot - 1;
    // `recv().name(` or `recv(..).name(`: the receiver is the fn the call result comes from.
    if end > 0 && chars[end - 1] == ')' {
        let mut depth = 0_i32;
        let mut i = end;
        while i > 0 {
            i -= 1;
            match chars[i] {
                ')' => depth += 1,
                '(' => {
                    depth -= 1;
                    if depth == 0 {
                        break;
                    }
                }
                _ => {}
            }
        }
        if depth != 0 {
            return true;
        }
        end = i;
    }
    let mut start = end;
    while start > 0 && (chars[start - 1].is_alphanumeric() || chars[start - 1] == '_') {
        start -= 1;
    }
    if start == end {
        return true;
    }
    let ident: String = chars[start..end].iter().collect();
    bound.contains(&ident)
}

/// Fill each derived seam's [`Seam::bound`] from the tree: every identifier written `ident: <type>`
/// where the type names one of the seam's [`Seam::types`] (a field, a parameter, a typed binding),
/// and every `fn name(..) -> <type>` returning one.
fn bind_receivers<'a>(door: &mut [Seam], texts: impl Iterator<Item = &'a str>) {
    let texts: Vec<&str> = texts.collect();
    for seam in door.iter_mut().filter(|s| s.derived) {
        let mut bound = BTreeSet::new();
        for text in &texts {
            for line in text.lines() {
                if !seam.types.iter().any(|t| has_word(line, t)) {
                    continue;
                }
                bind_line(line, &seam.types, &mut bound);
            }
        }
        seam.bound = Some(bound);
    }
}

/// Whether `word` appears in `line` at identifier boundaries.
fn has_word(line: &str, word: &str) -> bool {
    line.match_indices(word).any(|(i, _)| {
        let before = line[..i].chars().next_back();
        let after = line[i + word.len()..].chars().next();
        !before.is_some_and(|c| c.is_alphanumeric() || c == '_')
            && !after.is_some_and(|c| c.is_alphanumeric() || c == '_')
    })
}

/// The names one line binds to one of `types`: `ident: ..Type..` (the type running to the next
/// `,`, `;`, `=`, `)` or `{`), and `fn name(..) -> ..Type..`.
fn bind_line(line: &str, types: &[String], bound: &mut BTreeSet<String>) {
    let chars: Vec<char> = line.chars().collect();
    let mut i = 0;
    while i < chars.len() {
        // `ident :` that is not `::`.
        if chars[i] == ':' && chars.get(i + 1) != Some(&':') && (i == 0 || chars[i - 1] != ':') {
            let mut e = i;
            while e > 0 && chars[e - 1] == ' ' {
                e -= 1;
            }
            let mut b = e;
            while b > 0 && (chars[b - 1].is_alphanumeric() || chars[b - 1] == '_') {
                b -= 1;
            }
            let mut j = i + 1;
            let mut depth = 0_i32;
            while j < chars.len() {
                match chars[j] {
                    '<' | '(' | '[' => depth += 1,
                    '>' | ')' | ']' if depth > 0 => depth -= 1,
                    ',' | ';' | '=' | ')' | '{' if depth == 0 => break,
                    _ => {}
                }
                j += 1;
            }
            let ty: String = chars[i + 1..j].iter().collect();
            if b < e && types.iter().any(|t| has_word(&ty, t)) {
                bound.insert(chars[b..e].iter().collect());
            }
        }
        i += 1;
    }
    if let (Some(f), Some(arrow)) = (line.find("fn "), line.find("->")) {
        let after = &line[f + 3..];
        let name: String = after
            .chars()
            .take_while(|c| c.is_alphanumeric() || *c == '_')
            .collect();
        if !name.is_empty() && types.iter().any(|t| has_word(&line[arrow..], t)) {
            bound.insert(name);
        }
    }
}

/// THE ONE READING OF A LINE. Every rule below reads the BLANKED copy (`ScopeLine::counted`:
/// literal and comment bodies blanked by [`scan::blank_code`], carried across lines), so a seam
/// named inside a string or a trailing comment is not a call, and a `}` in a literal cannot move a
/// depth. Only the allow marker reads the raw line, because it lives IN a comment. Test scope is
/// [`scan::test_scope`]'s answer, the one every scanner in this crate shares: a `#[cfg(test)]` is
/// resolved against the item it applies to — a field ends at its `,` — and no window of this
/// gate's own can outlive it.
fn scan_file(rel: &str, text: &str, table: &[Seam]) -> FileScan {
    let scope = scan::test_scope(text);
    let lines: Vec<&str> = scope.iter().map(|l| l.counted.as_str()).collect();
    let mut hits = Vec::new();
    let mut depth: i64 = 0;
    let mut pdepth: i64 = 0;
    let mut async_at: i64 = -1;
    let mut entered = false;
    let mut off_b: i64 = -1;
    let mut off_p: i64 = 0;
    let mut prev_allow = false;
    // A spawner whose `async` block opens on a LATER line (`tokio::spawn(\n    async move {`).
    let mut spawn_pending = false;

    for (idx, sl) in scope.iter().enumerate() {
        let code = lines[idx];
        let comment = is_comment(&sl.raw, code);
        let marker = carries_allow_marker(&sl.raw);
        let allow = marker || prev_allow;
        prev_allow = marker || (comment && prev_allow);

        let db = i64::from(scan::delta(code, '{', '}'));
        let dp = i64::from(scan::delta(code, '(', ')'));

        if !comment {
            if off_b < 0 && OFFLOAD_OPENERS.iter().any(|o| bare_call(code, o)) {
                off_b = depth;
                off_p = pdepth;
            }
            let spawner = calls_async_spawner(code);
            let block = opens_async_block(code);
            if async_at < 0 && (opens_async_fn(code) || (block && (spawner || spawn_pending))) {
                async_at = depth;
                entered = false;
            }
            spawn_pending = spawner && !block && dp > 0;
        }

        let armed = async_at >= 0 && off_b < 0 && !sl.gated && !comment && !allow;
        if armed {
            if let Some(seam) = table.iter().find(|s| seam_hit(s, &lines, idx)) {
                hits.push(finding(rel, idx + 1, &seam.msg));
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

// ── THE DOOR SEAMS, DERIVED FROM THE LOADER ──────────────────────────────────────────────────────
//
// "A roster maintained by hand is a defect with a date on it" (BUSBAR-1.6.0.md, Law 8). The hand
// roster above held no store crossing: `impl RecordStore for LoadedStore` waits on the store door
// on the caller's thread, and `s.put_key(&k)?` inline in an async fn was green. So the door seams
// are READ from `crates/plugin-loader/src`, the one crate that crosses a plugin door:
//
// 1. A fn CROSSES SYNCHRONOUSLY when, outside every `async` block of its body, it parks its own
//    thread on a door crossing: `.wait_done()` (the bridge's wait for a submitted op), or a `.call`
//    / `.recall` of a LIFECYCLE slot — the slots `dispatch::plugin::is_lifecycle` routes to a
//    permanent plugin thread through a synchronous handoff (`ffi_thread`), read off that fn's own
//    body rather than typed here. A request op crossed ticket-less is NOT one: THE DESIGN §11.9
//    holds a crossing under 1 µs and slow I/O pends, so `plugin.call(slot::VERIFY, …)` alone does
//    not park a worker. An `async fn` never crosses synchronously in this sense: what it waits on
//    it awaits.
// 2. It reaches one TRANSITIVELY through `self.f(`, `Self::f(`, `run!(self, f, …)`, `Type::f(`, a
//    free fn of its own file (`f(`) or a free fn of a named module (`module::f(`).
// 3. Every such fn that is a method of an `impl Trait for Type` is a seam, by its method name,
//    grouped by trait. `Drop` is not: a destructor has no call spelling to find.
//
// The derivation fails CLOSED: a loader that holds no source, or no `is_lifecycle`, is refused, not
// read as a loader with no blocking door.

const LOADER: &str = "crates/plugin-loader/src/";

/// One fn of the loader, as the derivation reads it.
struct DoorFn {
    file: String,
    /// The module a `module::f(` path reaches it by: the file stem, or its directory for a
    /// `mod.rs`/`lib.rs`.
    module: String,
    /// `Some((type, trait))` for a method; the trait is `None` in an inherent impl.
    owner: Option<(String, Option<String>)>,
    name: String,
    /// The signature, blanked, from `fn` to its body's `{`.
    sig: String,
    is_async: bool,
    direct: bool,
    edges: Vec<Edge>,
}

enum Edge {
    /// `self.f(`, `Self::f(`, `run!(self, f, …)`.
    SameType(String),
    /// `Type::f(`.
    OfType(String, String),
    /// `f(` — a free fn of the same file.
    Local(String),
    /// `module::f(` — a free fn of that module.
    InModule(String, String),
}

/// The last path segment of a type or trait in an impl header, generics and references stripped.
fn last_segment(s: &str) -> String {
    let s = s.trim();
    let s = s.trim_start_matches('&').trim_start();
    let s = match s.strip_prefix('\'') {
        Some(lt) => lt.split_once(char::is_whitespace).map_or("", |(_, r)| r),
        None => s,
    };
    let s = s.strip_prefix("mut ").unwrap_or(s).trim_start();
    let s = s.strip_prefix("dyn ").unwrap_or(s).trim_start();
    let s = s.split('<').next().unwrap_or("");
    s.rsplit("::").next().unwrap_or("").trim().to_string()
}

/// `impl<…> Trait for Type<…> where …` → `(Type, Some(Trait))`; `impl Type` → `(Type, None)`.
fn parse_impl(header: &str) -> Option<(String, Option<String>)> {
    let at = header.find("impl")?;
    let mut h = header[at + "impl".len()..].trim_start();
    if h.starts_with('<') {
        let mut depth = 0i32;
        let mut end = h.len();
        for (i, c) in h.char_indices() {
            match c {
                '<' => depth += 1,
                '>' => {
                    depth -= 1;
                    if depth == 0 {
                        end = i + 1;
                        break;
                    }
                }
                _ => {}
            }
        }
        h = &h[end..];
    }
    let h = h.split(" where").next().unwrap_or(h);
    let padded = format!(" {h} ");
    let (tr, ty) = match padded.find(" for ") {
        Some(i) => (
            Some(last_segment(&padded[..i])),
            &padded[i + " for ".len()..],
        ),
        None => (None, padded.as_str()),
    };
    let ty = last_segment(ty);
    (!ty.is_empty()).then_some((ty, tr.filter(|t| !t.is_empty())))
}

/// The impl header opening on this blanked line, if one does: `impl` as the line's first word after
/// any visibility, `unsafe` or `default`.
fn opens_impl(code: &str) -> bool {
    let mut t = code.trim_start();
    loop {
        if let Some(r) = t.strip_prefix("pub") {
            let r = r.trim_start();
            t = match r.strip_prefix('(') {
                Some(v) => v.split_once(')').map_or("", |(_, rest)| rest).trim_start(),
                None => r,
            };
            continue;
        }
        let (word, rest) = next_word(t);
        if word == "unsafe" || word == "default" {
            t = rest.trim_start();
            continue;
        }
        return word == "impl" && (rest.starts_with('<') || rest.starts_with(char::is_whitespace));
    }
}

/// The fn this blanked line declares: `fn name` at a word boundary, with whether `async` precedes it.
fn declares_fn(code: &str) -> Option<(String, bool)> {
    let mut base = 0;
    while let Some(i) = code[base..].find("fn") {
        let at = base + i;
        base = at + 2;
        if code[..at].chars().next_back().is_some_and(is_ident_char) {
            continue;
        }
        let rest = &code[base..];
        if !rest.starts_with(char::is_whitespace) {
            continue;
        }
        let (name, _) = next_word(rest);
        if name.is_empty() {
            continue;
        }
        let is_async = code[..at]
            .split(|c: char| !is_ident_char(c))
            .any(|w| w == "async");
        return Some((name.to_string(), is_async));
    }
    None
}

/// Every `ident(` on the line with what precedes the ident: `.` (a method), `::` and the segment
/// before it (a path), or neither (a bare call). `fn ident(` is a declaration and `ident!(` a macro;
/// neither is a call.
fn calls_on(code: &str) -> Vec<(Option<char>, String, String)> {
    let chars: Vec<char> = code.chars().collect();
    let mut out = Vec::new();
    let mut i = 0;
    while i < chars.len() {
        if !is_ident_char(chars[i]) || (i > 0 && is_ident_char(chars[i - 1])) {
            i += 1;
            continue;
        }
        let start = i;
        while i < chars.len() && is_ident_char(chars[i]) {
            i += 1;
        }
        let name: String = chars[start..i].iter().collect();
        let mut j = i;
        while j < chars.len() && chars[j].is_whitespace() {
            j += 1;
        }
        if chars.get(j) != Some(&'(') || name.starts_with(|c: char| c.is_ascii_digit()) {
            continue;
        }
        let before: String = chars[..start].iter().collect();
        let before = before.trim_end();
        if before.ends_with("fn")
            && !before[..before.len() - 2]
                .chars()
                .next_back()
                .is_some_and(is_ident_char)
        {
            continue;
        }
        if let Some(path) = before.strip_suffix("::") {
            let seg: String = path
                .chars()
                .rev()
                .take_while(|c| is_ident_char(*c))
                .collect::<Vec<_>>()
                .into_iter()
                .rev()
                .collect();
            out.push((Some(':'), seg, name));
        } else if let Some(path) = before.strip_suffix('.') {
            let recv: String = path
                .chars()
                .rev()
                .take_while(|c| is_ident_char(*c))
                .collect::<Vec<_>>()
                .into_iter()
                .rev()
                .collect();
            out.push((Some('.'), recv, name));
        } else {
            out.push((None, String::new(), name));
        }
    }
    out
}

/// `name!(self, f` — a runner macro handed a method of the impl's own type (`run!(self, now, r)`).
fn macro_self_method(code: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut rest = code;
    while let Some(i) = rest.find("!(") {
        let args = rest[i + 2..].trim_start();
        if let Some(after) = args.strip_prefix("self") {
            if let Some(after) = after.trim_start().strip_prefix(',') {
                let (word, _) = next_word(after);
                if !word.is_empty() {
                    out.push(word.to_string());
                }
            }
        }
        rest = &rest[i + 2..];
    }
    out
}

/// Does this sync code park its own thread on a door crossing? See the section note.
fn crosses_synchronously(code: &str, lifecycle: &[String]) -> bool {
    if method_call(code, "wait_done") {
        return true;
    }
    ["call", "recall"].iter().any(|m| {
        method_calls(code, m).into_iter().any(|open| {
            let args: String = code.chars().skip(open + 1).collect();
            lifecycle.iter().any(|slot| {
                let needle = format!("::{slot}");
                args.match_indices(&needle)
                    .any(|(at, _)| !args[at + needle.len()..].starts_with(is_ident_char))
            })
        })
    })
}

fn module_of(rel: &str) -> String {
    let parts: Vec<&str> = rel.trim_end_matches(".rs").split('/').collect();
    match parts.as_slice() {
        [.., dir, "mod" | "lib"] => (*dir).to_string(),
        [.., stem] => (*stem).to_string(),
        [] => String::new(),
    }
}

/// The slots `fn is_lifecycle` names (`slot::OPEN | slot::REFRESH | …`), read off its body.
fn lifecycle_slots(files: &[(String, Vec<scan::ScopeLine>)]) -> Vec<String> {
    let mut out = Vec::new();
    for (_, scope) in files {
        let mut inside = false;
        let mut depth = 0i32;
        for l in scope.iter().filter(|l| !l.gated) {
            if !inside {
                if declares_fn(&l.counted).is_some_and(|(n, _)| n == "is_lifecycle") {
                    inside = true;
                    depth = 0;
                } else {
                    continue;
                }
            }
            let mut rest = l.counted.as_str();
            while let Some(i) = rest.find("slot::") {
                let (word, after) = next_word(&rest[i + "slot::".len()..]);
                if !word.is_empty() && !out.iter().any(|s| s == word) {
                    out.push(word.to_string());
                }
                rest = after;
            }
            depth += scan::delta(&l.counted, '{', '}');
            if depth <= 0 && l.counted.contains('}') {
                inside = false;
            }
        }
    }
    out
}

/// Read every fn of one loader file.
fn door_fns(rel: &str, scope: &[scan::ScopeLine], lifecycle: &[String], out: &mut Vec<DoorFn>) {
    let module = module_of(rel);
    let mut depth: i32 = 0;
    // (depth the impl opened at, type, trait)
    let mut impls: Vec<(i32, String, Option<String>)> = Vec::new();
    let mut header: Option<String> = None;
    let mut cur: Option<(DoorFn, i32, bool)> = None;
    // The depths the open `async` blocks of the current fn opened at.
    let mut asyncs: Vec<i32> = Vec::new();

    for l in scope {
        let code = if l.gated { "" } else { l.counted.as_str() };
        let at = depth;

        if cur.is_none() {
            if header.is_none() && opens_impl(code) {
                header = Some(String::new());
            }
            if let Some(h) = header.as_mut() {
                h.push(' ');
                h.push_str(code.split('{').next().unwrap_or(""));
                if code.contains('{') {
                    if let Some((ty, tr)) = parse_impl(h) {
                        impls.push((at, ty, tr));
                    }
                    header = None;
                } else if code.trim_end().ends_with(';') {
                    header = None;
                }
            }
        }
        if cur.is_none() && header.is_none() {
            if let Some((name, is_async)) = declares_fn(code) {
                let owner = impls
                    .last()
                    .filter(|(d, _, _)| at == d + 1)
                    .map(|(_, ty, tr)| (ty.clone(), tr.clone()));
                cur = Some((
                    DoorFn {
                        file: rel.to_string(),
                        module: module.clone(),
                        owner,
                        name,
                        sig: String::new(),
                        is_async,
                        direct: false,
                        edges: Vec::new(),
                    },
                    at,
                    false,
                ));
                asyncs.clear();
            }
        }

        if let Some((f, _, entered)) = cur.as_mut() {
            if !*entered && !f.sig.contains('{') {
                f.sig.push(' ');
                f.sig.push_str(code);
            }
            // The SYNC part of the line: all of it outside an async block, the part before the
            // opener on the line that opens one, none of it inside one.
            let sync = if !asyncs.is_empty() {
                ""
            } else if let Some(open) = async_block_at(code) {
                asyncs.push(at + scan::delta(&code[..open], '{', '}'));
                &code[..open]
            } else {
                code
            };
            if !f.is_async && !sync.is_empty() {
                f.direct |= crosses_synchronously(sync, lifecycle);
                for m in macro_self_method(sync) {
                    f.edges.push(Edge::SameType(m));
                }
                for (how, seg, name) in calls_on(sync) {
                    f.edges.push(match how {
                        Some('.') if seg == "self" => Edge::SameType(name),
                        Some('.') => continue,
                        Some(_) if seg == "Self" => Edge::SameType(name),
                        Some(_) if seg == "self" || seg.is_empty() => Edge::Local(name),
                        Some(_) if seg.starts_with(|c: char| c.is_ascii_uppercase()) => {
                            Edge::OfType(seg, name)
                        }
                        Some(_) => Edge::InModule(seg, name),
                        None => Edge::Local(name),
                    });
                }
            }
        }

        depth += scan::delta(code, '{', '}');

        while asyncs.last().is_some_and(|d| depth <= *d) {
            asyncs.pop();
        }
        let mut done = false;
        if let Some((_, start, entered)) = cur.as_mut() {
            if depth > *start {
                *entered = true;
            }
            done = (*entered && depth <= *start) || (!*entered && code.trim_end().ends_with(';'));
        }
        if done {
            if let Some((f, _, _)) = cur.take() {
                out.push(f);
            }
        }
        while impls.last().is_some_and(|(d, _, _)| depth <= *d) {
            impls.pop();
        }
    }
}

type Derived = Result<(Vec<Seam>, String), String>;

/// [`door_seams`], MEMOISED on the loader's paths and bytes for the reason [`SCAN_MEMO`] is: a
/// self-test case is one plant away from the last, and the plant is rarely in the loader.
static DOOR_MEMO: std::sync::OnceLock<std::sync::Mutex<BTreeMap<u64, Derived>>> =
    std::sync::OnceLock::new();

fn door_seams_memo<'a>(files: impl Iterator<Item = (String, &'a str)> + Clone) -> Derived {
    use std::hash::{Hash, Hasher};
    let key = {
        let mut h = std::collections::hash_map::DefaultHasher::new();
        for (rel, text) in files.clone().filter(|(rel, _)| rel.starts_with(LOADER)) {
            rel.hash(&mut h);
            text.hash(&mut h);
        }
        h.finish()
    };
    let memo = DOOR_MEMO.get_or_init(Default::default);
    if let Some(found) = memo
        .lock()
        .expect("the door memo mutex is never poisoned")
        .get(&key)
    {
        return found.clone();
    }
    let derived = door_seams(files);
    memo.lock()
        .expect("the door memo mutex is never poisoned")
        .insert(key, derived.clone());
    derived
}

/// THE DOOR SEAMS of the tree the run reads, and a census naming them. `Err` when the loader cannot
/// support the derivation.
fn door_seams<'a>(
    files: impl Iterator<Item = (String, &'a str)>,
) -> Result<(Vec<Seam>, String), String> {
    let loader: Vec<(String, Vec<scan::ScopeLine>)> = files
        .filter(|(rel, _)| rel.starts_with(LOADER))
        .map(|(rel, text)| (rel, scan::test_scope(text)))
        .collect();
    if loader.is_empty() {
        return Err(format!(
            "{LOADER} contributed no file, so no door seam could be derived — a loader that was \
             not read is not a loader with no blocking door"
        ));
    }
    let lifecycle = lifecycle_slots(&loader);
    if lifecycle.is_empty() {
        return Err(format!(
            "no `fn is_lifecycle` naming a `slot::` in {LOADER}, so which door crossings park a \
             thread is unknown — refused rather than guessed"
        ));
    }
    let mut fns = Vec::new();
    for (rel, scope) in &loader {
        door_fns(rel, scope, &lifecycle, &mut fns);
    }

    // Who answers to which spelling: a method by its type, a free fn by its file and its module.
    type Key = (String, String);
    let mut of_type: BTreeMap<Key, Vec<usize>> = BTreeMap::new();
    let mut in_file: BTreeMap<Key, Vec<usize>> = BTreeMap::new();
    let mut in_module: BTreeMap<Key, Vec<usize>> = BTreeMap::new();
    for (i, f) in fns.iter().enumerate() {
        match &f.owner {
            Some((ty, _)) => of_type
                .entry((ty.clone(), f.name.clone()))
                .or_default()
                .push(i),
            None => {
                in_file
                    .entry((f.file.clone(), f.name.clone()))
                    .or_default()
                    .push(i);
                in_module
                    .entry((f.module.clone(), f.name.clone()))
                    .or_default()
                    .push(i);
            }
        }
    }
    let targets = |f: &DoorFn, e: &Edge| -> Vec<usize> {
        let key = match e {
            Edge::SameType(n) => match &f.owner {
                Some((ty, _)) => of_type.get(&(ty.clone(), n.clone())),
                None => None,
            },
            Edge::OfType(t, n) => of_type.get(&(t.clone(), n.clone())),
            Edge::Local(n) => in_file.get(&(f.file.clone(), n.clone())),
            Edge::InModule(m, n) => in_module.get(&(m.clone(), n.clone())),
        };
        key.cloned().unwrap_or_default()
    };

    let mut blocking: Vec<bool> = fns.iter().map(|f| f.direct && !f.is_async).collect();
    loop {
        let next: Vec<bool> = fns
            .iter()
            .enumerate()
            .map(|(i, f)| {
                blocking[i]
                    || (!f.is_async
                        && f.edges
                            .iter()
                            .any(|e| targets(f, e).into_iter().any(|j| blocking[j])))
            })
            .collect();
        if next == blocking {
            break;
        }
        blocking = next;
    }

    // trait -> (method names with their arity, the impls that back them)
    type Backed = (BTreeMap<String, Option<usize>>, BTreeSet<String>);
    let mut by_trait: BTreeMap<String, Backed> = BTreeMap::new();
    for (f, _) in fns.iter().zip(&blocking).filter(|(_, b)| **b) {
        let Some((ty, Some(tr))) = &f.owner else {
            continue;
        };
        if tr == "Drop" {
            continue;
        }
        let entry = by_trait.entry(tr.clone()).or_default();
        entry.0.insert(f.name.clone(), param_arity(&f.sig, &f.name));
        entry.1.insert(format!("{ty} ({})", f.file));
    }

    let mut census = Vec::new();
    let seams = by_trait
        .into_iter()
        .map(|(tr, (methods, impls))| {
            let impls: Vec<String> = impls.into_iter().collect();
            census.push(format!(
                "{tr} [{}]",
                methods.keys().cloned().collect::<Vec<_>>().join(", ")
            ));
            Seam {
                msg: format!(
                    "door-backed {tr} call (`impl {tr} for {}` crosses the plugin door \
                     synchronously) called inline from an async fn — run it on a blocking thread \
                     (spawn_blocking, Txn::read_store, Txn::store_write) or call the door's async \
                     method",
                    impls.join(", ")
                ),
                methods: methods.keys().cloned().collect(),
                bare: Vec::new(),
                derived: true,
                arity: methods,
                types: std::iter::once(tr.clone())
                    .chain(
                        impls
                            .iter()
                            .filter_map(|i| i.split(' ').next().map(str::to_string)),
                    )
                    .collect(),
                bound: None,
            }
        })
        .collect();
    Ok((
        seams,
        format!(
            "door seams derived from {LOADER} (lifecycle slots {}): {}",
            lifecycle.join("/"),
            if census.is_empty() {
                "none".to_string()
            } else {
                census.join("; ")
            }
        ),
    ))
}

pub struct BlockingFfiGate;

fn scan_roots(cx: &Ctx) -> Result<Vec<String>, String> {
    let roots = PlaneRoots::at(cx.abs("crates")).over(cx);
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
        if population.unreconciled() {
            return Verdict::of(vec![
                Row::pass(ROW_PLANE_ROOTS, "every plane root resolved", CLEAN),
                Row::fail(
                    ROW_SCAN_FLOOR,
                    "the scan set is not the tracked set",
                    format!(
                        "{}. This gate did not read the tree it would report on, so its verdict \
                         is meaningless — it is NOT a pass.",
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

        // THE SEAM TABLE: the hand rows, then the door seams the loader's own source backs.
        let (door, census) =
            match door_seams_memo(files.iter().map(|f| (f.rel_str(), f.text.as_str()))) {
                Ok(d) => d,
                Err(why) => {
                    return Verdict::of(vec![
                        Row::pass(ROW_PLANE_ROOTS, "every plane root resolved", CLEAN),
                        Row::pass(
                            ROW_SCAN_FLOOR,
                            "the scan set is the tracked set",
                            population.census(),
                        ),
                        Row::fail(
                            ROW_SCAN_STATUS,
                            "the door seams could not be derived",
                            DID_NOT_RUN.to_string(),
                        ),
                        Row::fail(ROW_NO_INLINE, "the door seams could not be derived", why),
                    ]);
                }
            };
        let mut door = door;
        bind_receivers(&mut door, files.iter().map(|f| f.text.as_str()));
        let mut table = seams();
        table.extend(door);
        let tkey = table_key(&table);

        let mut hits = Vec::new();
        let mut broke = Vec::new();
        for f in &files {
            let scan = scan_file_memo(&f.rel_str(), &f.text, &table, tkey);
            match &scan.lost_track {
                // A FILE THE SCANNER DID NOT GET THROUGH CONTRIBUTES NO FINDINGS AND IS NOT CLEAN.
                // Banking its empty output as "no findings" is the defect this row exists for.
                Some(why) => broke.push(why.clone()),
                None => hits.extend(scan.hits.iter().cloned()),
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
                "the scan set is the tracked set",
                population.census(),
            ),
            status,
            row_no_inline(&hits, &census),
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

        // ITEM 186: A SPAWNED ASYNC BLOCK IN A SYNC FN RUNS ON A TOKIO WORKER. `tokio::spawn` is
        // not an offload opener and a sync fn never arms, so this body was scanned by nothing. The
        // two-line spelling (spawner, then the block on the next line) is planted too, and a
        // `spawn_blocking` body beside them stays exempt.
        let mut ov = Overlay::new();
        ov.set(
            format!("{CORE}/planted_spawned_block.rs"),
            "pub(crate) fn spawn_sweeper(env: Arc<HookEnv>) {\n\
             \x20   tokio::spawn(async move {\n\
             \x20       let r = env.resolve_hook_settings(&hook.settings);\n\
             \x20   });\n\
             \x20   tokio::spawn(\n\
             \x20       async move {\n\
             \x20           let outcome = module.authenticate(bearer);\n\
             \x20       },\n\
             \x20   );\n\
             \x20   tokio::task::spawn_blocking(move || {\n\
             \x20       let ok = env.resolve_hook_settings(&hook.settings);\n\
             \x20   });\n\
             }\n",
        );
        report.push(prove_red(
            cx,
            self,
            "a plugin call in an async block spawned from a sync fn is flagged",
            &[ROW_NO_INLINE],
            ov,
            &[
                "2 finding(s)",
                "planted_spawned_block.rs:3",
                "planted_spawned_block.rs:7",
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
             \x20   let opened = units.authenticate(&Pass::<Authenticate>::mint(seal), ctx);\n\
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

        // THE CARVE-OUT IS THE STAGE-PASS'S CURRENT SPELLING, ON THE CALL LINE, AND NOTHING WIDER.
        // The retired `UnitToken` name is no capability any more (a type nobody mints proves no
        // kernel step), a `Pass` mint split onto the next line is out of the call line's reach, and
        // a plugin's own `authenticate` re-inlined into the async chain is the finding itself: all
        // three are named, in the open-to-door shape the loop has.
        let mut ov = Overlay::new();
        ov.set(
            format!("{CORE}/planted_step_spellings.rs"),
            "async fn open_to_door<U: Units>(units: &U, ctx: &UnitCtx) -> Opened {\n\
             \x20   let a = units.authenticate(&UnitToken::<Authenticate>::mint(seal), ctx);\n\
             \x20   let b = units.authenticate(\n\
             \x20       &Pass::<Authenticate>::mint(seal),\n\
             \x20       ctx,\n\
             \x20   );\n\
             \x20   let c = module.authenticate(candidate.as_deref());\n\
             \x20   a.or(b).or(c)\n}\n",
        );
        report.push(prove_red(
            cx,
            self,
            "a retired token spelling, a mint split off the call line and a plugin verify re-inlined \
             into the async chain are each flagged",
            &[ROW_NO_INLINE],
            ov,
            &[
                "3 finding(s)",
                "planted_step_spellings.rs:2",
                "planted_step_spellings.rs:3",
                "planted_step_spellings.rs:7",
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

        // A STORE CROSSING IS A SEAM, AND THE ROSTER OF SEAMS IS THE LOADER'S, NOT A HAND LIST.
        // `impl RecordStore for LoadedStore` waits on the store door on the caller's thread (the
        // bridge's `wait_done`), so `s.put_key(&k)?` inline in an async fn parks a Tokio worker
        // for the store's full round trip. The `StoreCalls` method of the same name is submitted
        // and AWAITED, and stays silent in both spellings.
        let mut ov = Overlay::new();
        ov.set(
            format!("{CORE}/planted_store_call.rs"),
            "async fn rotate(s: &dyn RecordStore, calls: &dyn StoreCalls, k: VirtualKey) -> Result<(), E> {\n\
             \x20   s.put_key(&k)?;\n\
             \x20   calls.upsert_plane_record(rec).await?;\n\
             \x20   calls\n\
             \x20       .upsert_plane_record(\n\
             \x20           rec,\n\
             \x20       )\n\
             \x20       .await?;\n\
             \x20   Ok(())\n}\n",
        );
        report.push(prove_red(
            cx,
            self,
            "a synchronous store call inline in an async fn is flagged, and the awaited door call \
             of the same name is not",
            &[ROW_NO_INLINE],
            ov,
            &[
                "1 finding(s)",
                "planted_store_call.rs:2",
                "door-backed RecordStore call",
            ],
        ));

        // THE DERIVATION READS THE LOADER, so a door-backed trait the loader grows tomorrow is a
        // seam tomorrow: a planted impl whose method reaches a synchronous wait through a helper
        // of its own type is named at its call site, and its sibling that only builds a future is
        // not.
        let mut ov = Overlay::new();
        ov.set(
            "crates/plugin-loader/src/planted_door.rs",
            "impl ZapCalls for ZapInstance {\n\
             \x20   fn zap_now(&self, x: u32) -> Result<(), String> {\n\
             \x20       self.bridge(x)\n\
             \x20   }\n\
             \x20   fn zap_later(&self, x: u32) -> ZapCall<'_> {\n\
             \x20       Box::pin(async move { self.dispatcher.submit(x).await })\n\
             \x20   }\n\
             }\n\n\
             impl ZapInstance {\n\
             \x20   fn bridge(&self, x: u32) -> Result<(), String> {\n\
             \x20       self.dispatcher.submit(x).wait_done().ok()\n\
             \x20   }\n\
             }\n",
        );
        ov.set(
            format!("{CORE}/planted_zap_site.rs"),
            "async fn zap_site(z: &dyn ZapCalls, post: &NodePost) {\n\
             \x20   let a = z.zap_later(1).await;\n\
             \x20   let b = z.zap_now(2);\n\
             \x20   let c = post.zap_now(3);\n\
             \x20   let d = post\n\
             \x20       .zap_now(4);\n\
             }\n",
        );
        report.push(prove_red(
            cx,
            self,
            "a door-backed method the loader grows is a seam without anyone listing it, and the same \
             name on a receiver bound to another type is not, its chain split across lines or not",
            &[ROW_NO_INLINE],
            ov,
            &[
                "1 finding(s)",
                "planted_zap_site.rs:3",
                "door-backed ZapCalls call",
            ],
        ));

        // EVERY REAL LINE IS ARMED. A statement that opens with `*` is a deref-assignment, not the
        // inside of a block comment; `async unsafe fn` and `async extern "C" fn` are async fns; and
        // a `#[cfg(test)]` on a struct FIELD gates that field, not the fn after the struct.
        let mut ov = Overlay::new();
        ov.set(
            format!("{CORE}/planted_deref.rs"),
            "async fn refill(env: &HookEnv, slot: &mut Settings) -> Result<(), String> {\n\
             \x20   *slot = env.resolve_hook_settings(&s)?;\n\
             \x20   Ok(())\n}\n",
        );
        report.push(prove_red(
            cx,
            self,
            "a deref-assignment opening with `*` is code, not a comment",
            &[ROW_NO_INLINE],
            ov,
            &["1 finding(s)", "planted_deref.rs:2", "secret-plugin FFI"],
        ));

        let mut ov = Overlay::new();
        ov.set(
            format!("{CORE}/planted_async_spellings.rs"),
            "pub(crate) async unsafe fn raw_resolve(env: &HookEnv) {\n\
             \x20   let _ = env.resolve_hook_settings(&hook.settings);\n}\n\n\
             pub(crate) async extern \"C\" fn c_resolve(env: &HookEnv) {\n\
             \x20   let _ = env.resolve_hook_settings(&hook.settings);\n}\n",
        );
        report.push(prove_red(
            cx,
            self,
            "an async fn spelled with `unsafe` or an ABI between `async` and `fn` is armed",
            &[ROW_NO_INLINE],
            ov,
            &[
                "2 finding(s)",
                "planted_async_spellings.rs:2",
                "planted_async_spellings.rs:6",
            ],
        ));

        let mut ov = Overlay::new();
        ov.set(
            format!("{CORE}/planted_field_cfg.rs"),
            "struct Probe {\n\
             \x20   #[cfg(test)]\n\
             \x20   seen: u32,\n\
             \x20   #[cfg(test)] calls: u32,\n\
             }\n\n\
             async fn after_field(env: &HookEnv) {\n\
             \x20   let _ = env.resolve_hook_settings(&hook.settings);\n\
             }\n",
        );
        report.push(prove_red(
            cx,
            self,
            "a field-level cfg(test) gates its field and not the async fn after the struct",
            &[ROW_NO_INLINE],
            ov,
            &["1 finding(s)", "planted_field_cfg.rs:8"],
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

        // THE SCAN IS RECONCILED AGAINST THE TRACKED SET: one tracked file hidden from the walk
        // is refused, and the refusal NAMES it. There is no count to re-pin, so neither a tree that
        // grew nor one that shrank turns this plant green.
        match population::one_file_hidden(cx) {
            Ok((ov, rel)) => report.push(prove_red(
                cx,
                self,
                "a tracked file the scan did not read is refused by name",
                &[ROW_SCAN_FLOOR],
                ov,
                &["NOT scanned", rel.as_str()],
            )),
            Err(e) => report.note_infra_failure(format!("blocking-ffi selftest: {e}")),
        }

        // THE RECONCILIATION, on the run path: every root keeps a file, so the per-root check
        // passes, and the files hidden from the walk are still owed.
        match scan_roots(cx) {
            Ok(roots) => match candidates(cx, &roots) {
                Ok(_) => {
                    let mut hidden = Vec::new();
                    for root in &roots {
                        if let Ok(files) = cx.walk(
                            &WalkSpec::new([root.clone()])
                                .ext("rs")
                                .exclude([EXCLUDE_TESTS_DIR]),
                        ) {
                            hidden.extend(files.iter().skip(1).map(|f| f.rel.clone()));
                        }
                    }
                    match cx.hide_from_scan(&hidden) {
                        Ok(ov) => report.push(prove_red(
                            cx,
                            self,
                            "files hidden from the walk are refused though every root still holds one",
                            &[ROW_SCAN_FLOOR],
                            ov,
                            &["NOT scanned"],
                        )),
                        Err(e) => report.note_infra_failure(format!("blocking-ffi selftest: {e}")),
                    }
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
        row_no_inline(&hits, ""),
    ])
}
