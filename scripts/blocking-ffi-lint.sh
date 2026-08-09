#!/usr/bin/env bash
# Blocking-FFI enforcement lint — the can't-forget guarantee behind the "a synchronous call into a
# dlopened PLUGIN never runs on a Tokio worker" rule.
#
# THE RULE: every call that reaches a plugin's `transport_call` (or the `dlopen` + constructor that
# precedes it) must be made from a BLOCKING context — inside `spawn_blocking`, `Txn::read_store` /
# `Txn::store_write`, `hooks::offload_bounded`, `auth::token::offload_login_call`, or a plain `fn`
# that only such a context calls. Never inline in an `async fn`.
#
# WHY. A plugin call is a C-ABI hop into out-of-tree code, and behind it is real network I/O: an
# LDAP/AD bind (`kind: auth` credential login), a Vault / AWS-SM fetch (`kind: secret`), a JWKS or
# token-introspection round trip, a store round trip. Called inline from an `async fn`, ONE such call
# parks a Tokio worker for the plugin's full timeout. N concurrent callers park N workers, and once
# every worker is parked the runtime polls NOTHING — not other requests, not the admin plane, not
# `/healthz` (which is exempt from auth but still needs a worker to run at all). The node then fails
# its liveness probe and is killed, on account of a plugin most of the stalled traffic never used.
#
# WHY A LINT AND NOT N PATCHES. This defect class has now been found in FIVE independent places, each
# written separately, each by someone who had read neither the previous fix nor the doc comment it
# left behind:
#   * the data-plane auth chain (`AuthMiddleware::run_chain_on_request_path`) — the first fix, and the
#     one whose doc comment describes this exact hazard in full;
#   * the ADMIN auth chain (`run_admin_chain_maybe_offloaded`) — same shape, written later, its own
#     separate offload budget;
#   * `hooks::gate_transport_offloaded` — a `GET /metrics/hooks` a monitoring system polls forever,
#     doing `dlopen` + a plugin constructor inline;
#   * `hooks::settings_drift_keys` — a polled admin GET resolving `SecretRef`s over `kind: secret`
#     FFI, fixed by REMOVING the `HookEnv` parameter so resolution became structurally impossible;
#   * `GET|POST /auth/token` (`begin_login` / `complete_login`) — the worst of them: mounted on the
#     DATA router and EXPLICITLY BYPASSED by the auth middleware, so the concurrency is chosen by an
#     unauthenticated caller.
# A sixth will be written the same way; this makes it fail the build instead.
#
# WHAT IT SCANS: `crates/busbar/src/**/*.rs` — the whole engine crate, minus test trees (named-
# navigated and exempt exactly the way structure-lint.sh / settings-leak-lint.sh treat them). The
# engine crate is the boundary that holds: `plugin-loader` DEFINES the synchronous seams (they are
# synchronous by contract — the C ABI has no futures) and `busbar` is the only crate that decides
# what thread they run on.
#
# HOW IT DECIDES "inside an async fn". One awk pass per file tracking two counters:
#   * BRACE depth — an `async fn` arms at the depth its signature starts, and disarms when depth
#     returns to it. A sync `fn` never arms.
#   * PAREN depth — so that an OFFLOAD OPENER (`spawn_blocking(`, `read_store(`, `store_write(`,
#     `offload_bounded(`, `offload_login_call(`, `Outcome::blocking(`, `block_in_place(`) disarms the
#     async context for its whole argument list, whether the closure body is a braced block on the
#     next line or an expression on the fifth line of a multi-line call. Both forms appear in-tree.
# Imprecise about strings and comments in the same way its sibling lints are — a brace inside a
# string literal can shift the depth. That is a false-POSITIVE risk (a spurious flag someone must
# look at), never a false negative, and the allowlist is how a real one gets recorded.
#
# THE ALLOWLIST is explicit, per-line and self-documenting: put
#     // blocking-ffi-lint: allow — <reason>
# on the line itself or the line immediately above. There is NO silent skip and no blanket mute: a
# marker covers exactly the one call below it. Use it ONLY for a call that genuinely cannot park a
# serving worker:
#   (a) BOOT — it runs once during startup, before the listener it belongs to serves anything;
#   (b) ALREADY-BLOCKING — the enclosing `async fn` is itself only ever driven on a blocking thread
#       or a dedicated `std::thread`, and the marker says which one and where.
# "It's only the admin plane" is NOT a reason: the admin plane shares the process's workers with the
# data plane, which is how `run_admin_chain_maybe_offloaded` came to exist.
#
# Runs in CI (see .github/workflows/ci.yml, structure-lint job) alongside its sibling lints: no
# external deps, bash 3.2 + POSIX awk (macOS/Linux), and `--selftest` proves the scanner still
# catches a real inline call before its verdict on the tree is trusted.
set -euo pipefail
cd "$(dirname "$0")/.."

note() { printf '  %s\n' "$1"; }
hdr()  { printf '\n== %s ==\n' "$1"; }

# ── THE SCANNER ────────────────────────────────────────────────────────────────────────────────────
BLOCKING_FFI_SCAN_AWK='
  function braces(s,   n, c, i) {
    n = 0
    for (i = 1; i <= length(s); i++) { c = substr(s, i, 1); if (c == "{") n++; else if (c == "}") n-- }
    return n
  }
  function parens(s,   n, c, i) {
    n = 0
    for (i = 1; i <= length(s); i++) { c = substr(s, i, 1); if (c == "(") n++; else if (c == ")") n-- }
    return n
  }
  FNR==1 { depth=0; pdepth=0; async_at=-1; entered=0; off_b=-1; off_p=-1; test_at=-1; t_entered=0; prev_allow=0 }
  {
    line = $0
    is_comment = (line ~ /^[[:space:]]*(\/\/|\*|\/\*)/)
    allow = (line ~ /blocking-ffi-lint:[[:space:]]*allow/) || prev_allow
    # Carry an allow marker forward across the COMMENT BLOCK it starts (a reason rarely fits on one
    # line) and no further: the first non-comment line consumes it, and the line after is armed again.
    if (line ~ /blocking-ffi-lint:[[:space:]]*allow/)  prev_allow = 1
    else if (is_comment && prev_allow)                 prev_allow = 1
    else                                               prev_allow = 0

    db = braces(line); dp = parens(line)

    if (!is_comment) {
      # An OFFLOAD OPENER disarms the async context from this line until both counters return to
      # where they were when it opened. Recorded only when not already inside one (the outermost
      # offload wins; a nested one changes nothing).
      if (off_b < 0 && line ~ /(spawn_blocking|read_store|store_write|offload_bounded|offload_bounded_with_deadline|offload_login_call|Outcome::blocking|block_in_place)[[:space:]]*\(/) {
        off_b = depth; off_p = pdepth
      }
      # An `async fn` arms at the depth its signature starts. `async move`/`async {` blocks do NOT
      # arm: they are values, and the thing that matters is what thread polls them, which is decided
      # by the enclosing fn (already tracked) or by a spawn site (already an offload opener or not).
      if (async_at < 0 && line ~ /(^|[^[:alnum:]_])async[[:space:]]+fn[[:space:]]/) { async_at = depth; entered = 0 }
      # `#[cfg(test)]` opens an EXEMPT region: an in-file test module (the kind `tests/`-directory
      # exclusion cannot see) never serves traffic, so a blocking call in one parks nothing. The
      # region ends with the item it annotates, so production code AFTER the module is still scanned.
      if (test_at < 0 && line ~ /#\[cfg\(test\)\]/) { test_at = depth; t_entered = 0 }
    }

    in_offload = (off_b >= 0)
    armed = (async_at >= 0) && !in_offload && (test_at < 0) && !is_comment && !allow

    msg = ""
    if (armed) {
      # ── the SEAMS: everything that reaches a dlopened plugin, or dlopens one ──
      # A `kind: auth` LOGIN plugin (the hosted browser flow) — a credential bind or a token hop.
      if (line ~ /\.(begin_login|complete_login|login_kind)[[:space:]]*\(/)
        msg = "login-plugin FFI (begin_login/complete_login/login_kind) called inline from an async fn — route it through auth::token::offload_login_call"
      # A `kind: auth` VERIFY plugin, direct or via the chain runner.
      else if (line ~ /\.authenticate[[:space:]]*\(/ || line ~ /run_chain_cached[[:space:]]*\(/)
        msg = "auth-plugin FFI (authenticate/run_chain_cached) called inline from an async fn — use run_chain_on_request_path / run_admin_chain_maybe_offloaded"
      # A `kind: secret` plugin: SecretResolver'"'"'s non-built-in arm is a transport_call.
      else if (line ~ /(resolve_hook_settings|resolve_settings|resolve_string|preresolve_hook_secrets|build_server_config)[[:space:]]*\(/ || line ~ /resolver[[:space:]]*\.[[:space:]]*resolve[[:space:]]*\(/)
        msg = "secret-plugin FFI (SecretResolver::resolve*) called inline from an async fn — resolve on a blocking thread (see hooks::gate_transport_named)"
      # dlopen + the plugin CONSTRUCTOR: a staging copy, dynamic-linker work, then the plugin'"'"'s open.
      else if (line ~ /\.(open_hook|open_login|open_auth|open_store|open_secret|open_export)[[:space:]]*\(/ || line ~ /(gate_transport_named|preopen_gate_hooks)[[:space:]]*\(/)
        msg = "plugin OPEN (dlopen + constructor) called inline from an async fn — use hooks::gate_transport_offloaded / offload_bounded"
      # Whole-snapshot builders: each re-resolves the hook chain, i.e. secrets + opens, per hook.
      else if (line ~ /(build_app_from_config|build_with_hook|build_without_hook|build_with_registry|resolve_gate_hooks|resolve_rewrite_hooks|resolve_tap_hooks|resolve_pool_gates|resolve_pool_rewrites)[[:space:]]*\(/)
        msg = "an App/hook-chain build (secret resolve + dlopen per hook) called inline from an async fn — defer it through Txn::read_store"
      # A `kind: export` / `kind: hook` plugin serving an inbound HTTP route.
      else if (line ~ /\.(handle_http|handle_http_with_app)[[:space:]]*\(/)
        msg = "export/hook-plugin HTTP dispatch called inline from an async fn — serve it on spawn_blocking (see plugin_routes::plugin_route_dispatch)"
      if (msg != "") printf "%s:%d: %s\n", FILENAME, FNR, msg
    }

    # Advance the counters LAST, so a rule sees the depth the line STARTED at.
    depth += db; pdepth += dp
    if (off_b >= 0 && depth <= off_b && pdepth <= off_p) { off_b = -1; off_p = -1 }
    # `entered` guards a MULTI-LINE SIGNATURE: `async fn f(\n  a: A,\n) -> R {` leaves the brace
    # depth unchanged for several lines, and disarming on "depth is back where it started" would end
    # the fn before its body began — silently exempting every call in it. So the arm only lifts once
    # the body has actually been entered. Same guard on the `#[cfg(test)]` region.
    if (async_at >= 0 && depth > async_at) entered = 1
    if (async_at >= 0 && entered && depth <= async_at && off_b < 0) async_at = -1
    if (test_at >= 0 && depth > test_at) t_entered = 1
    if (test_at >= 0 && t_entered && depth <= test_at) test_at = -1
    if (test_at >= 0 && !t_entered && line ~ /;[[:space:]]*$/) test_at = -1
  }
'
scan_rule() { awk "$BLOCKING_FFI_SCAN_AWK" "$@"; }

# ── SELF-TEST — prove the scanner still catches a real inline call before trusting its verdict ─────
run_selftest() {
  hdr "blocking-ffi-lint SELF-TEST (the inline-FFI scanner cannot be lied to)"
  local tmp; tmp="$(mktemp -d)"; trap 'rm -rf "$tmp"' RETURN
  local fail=0 pass=0

  # RED: every shape this lint exists to catch — the five historical instances, transcribed.
  cat >"${tmp}/red.rs" <<'RED'
async fn begin(app: &App, method: &str) -> Response {
    let m = app.login_methods.methods.get(method).unwrap();
    match m.module.begin_login(&begin) {
        _ => todo!(),
    }
}

async fn credential_submit(app: &App) -> Response {
    let principal = match m.module.complete_login(&cl) {
        _ => todo!(),
    };
}

async fn auth_middleware(app: &App) -> Response {
    let outcome = module.authenticate(bearer);
}

pub(crate) async fn push_configure(hook: &HookCfg, env: &HookEnv) -> Result<(), String> {
    let resolved = env.resolve_hook_settings(&hook.settings)?;
    Ok(())
}

async fn status(name: &str, hook: &HookCfg, env: &HookEnv) -> Option<HookStatus> {
    let transport = gate_transport_named(name, hook, env, 0)?;
    None
}

pub(crate) async fn register_hook(handle: &Arc<AppHandle>) -> Response {
    let installed = Arc::new(build_with_hook(current, &txn_name, cfg)?);
}
RED
  local hits n
  hits=$(scan_rule "${tmp}/red.rs")
  n=$(printf '%s\n' "$hits" | grep -c ':' || true)
  if [ "$n" -eq 6 ]; then
    pass=$((pass+1)); note "RED: all 6 inline shapes (begin_login / complete_login / authenticate / secret resolve / plugin open / snapshot build) flagged"
  else
    fail=1; note "RED FAILED: expected 6 hits, got ${n}:"; note "$hits"
  fi

  # GREEN: the SANCTIONED forms — every offload wrapper in the tree, in BOTH the braced-block and the
  # multi-line-argument spelling, plus a plain sync fn and an allowlisted boot call. All must be silent.
  cat >"${tmp}/green.rs" <<'GREEN'
async fn begin(app: &App, method: &str) -> Response {
    // A braced closure on the opener line.
    match offload_login_call(&app.login_methods, method, "begin_login", move |m| {
        m.module.begin_login(&begin)
    })
    .await
    {
        _ => todo!(),
    }
}

async fn credential_submit(app: &App) -> Response {
    // The SAME call spelled across a multi-line argument list — no brace ever opens, so only the
    // paren counter can carry the exemption.
    let principal = match offload_login_call(
        &app.login_methods,
        &cookie.method,
        "complete_login",
        move |m| m.module.complete_login(&cl),
    )
    .await
    {
        _ => todo!(),
    };
}

pub(crate) async fn run_chain_on_request_path(auth: &Arc<AuthMiddleware>) -> ChainVerdict {
    let joined = tokio::task::spawn_blocking(move || {
        let verdict = auth.run_chain_cached(candidate.as_deref(), Some(&cache), gov.as_deref());
        drop(permit);
        verdict
    })
    .await;
}

pub(crate) async fn register_hook(handle: &Arc<AppHandle>) -> Response {
    let out = config_transaction(&handle, move |txn| {
        let snapshot = txn.app().clone();
        Ok(txn.read_store(move || {
            let installed = Arc::new(build_with_hook(&snapshot, &txn_name, cfg)?);
            Ok(Outcome::commit(installed.clone(), || Ok(()), installed))
        }))
    })
    .await;
}

async fn gate_transport_offloaded(name: &str, env: &HookEnv) -> Option<Arc<dyn RoutingPolicy>> {
    offload_bounded(name, move || gate_transport_named(&name_owned, &hook, &env, 0)).await
}

/// A plain sync fn is never armed — the whole point is that a blocking context may call these.
fn gate_transport_named(name: &str, hook: &HookCfg, env: &HookEnv) -> Option<Arc<dyn RoutingPolicy>> {
    let resolved = env.resolve_hook_settings(&hook.settings).ok()?;
    env.registry.open_hook(&hook.plugin, &cfg_json, name, env.projectors.clone()).ok()
}

async fn serve_listener(tls_cfg: Option<TlsCfg>, secret_resolver: Arc<SecretResolver>) {
    // blocking-ffi-lint: allow — BOOT ONLY, and before this listener serves anything.
    let server_config = tls::build_server_config(&tls, &secret_resolver);
}

// A doc comment merely NAMING `m.module.begin_login(&begin)` inside an async fn is prose, not a call.
GREEN
  hits=$(scan_rule "${tmp}/green.rs")
  if [ -z "$hits" ]; then
    pass=$((pass+1)); note "GREEN: offload_login_call (both spellings), spawn_blocking, Txn::read_store, offload_bounded, a sync fn and an allowlisted boot call all stay silent"
  else
    fail=1; note "GREEN FAILED: expected silence, got: $hits"
  fi

  # An offload closure must not mute the REST of the async fn, and a marker must not be a blanket
  # mute: the inline call AFTER each is still caught.
  cat >"${tmp}/scope.rs" <<'SCOPE'
async fn handler(app: &App, env: &HookEnv) -> Response {
    let a = tokio::task::spawn_blocking(move || {
        env2.resolve_hook_settings(&hook.settings)
    })
    .await;
    // Back on the reactor — this one IS the defect.
    let b = env.resolve_hook_settings(&hook.settings);
    // blocking-ffi-lint: allow — covers the NEXT call only (and this reason may run onto a
    // second comment line without widening the marker).
    let c = env.resolve_hook_settings(&hook.settings);
    let d = env.resolve_hook_settings(&hook.settings);
}
SCOPE
  hits=$(scan_rule "${tmp}/scope.rs")
  n=$(printf '%s\n' "$hits" | grep -c ':' || true)
  if [ "$n" -eq 2 ]; then
    pass=$((pass+1)); note "SCOPE: an offload closure exempts only its own body, and an allow marker covers exactly one call — the two unmarked inline calls are still flagged"
  else
    fail=1; note "SCOPE FAILED: expected 2 hits, got ${n}: $hits"
  fi

  note "self-test: ${pass}/3 fixture groups passed"
  if [ "$fail" -ne 0 ]; then
    note "blocking-ffi-lint SELF-TEST FAILED — the scanner would let an inline plugin call through"
    return 1
  fi
  note "ok"
  return 0
}

if [ "${1:-}" = "--selftest" ]; then run_selftest; exit $?; fi

hdr "no synchronous plugin FFI is called inline from an async fn"
CANDIDATES=()
while IFS= read -r f; do CANDIDATES+=("$f"); done < <(find crates/busbar/src -name '*.rs' -not -path '*/tests/*' | sort)

# ── SCAN FLOOR — the loop below is "for each file, assert no inline FFI", which is VACUOUSLY TRUE
# over zero files. Rename `crates/busbar` (a normal refactor), move the engine, or mistype the root,
# and every rule above reports `ok` FOREVER while the tree is unscanned — a green verdict about a
# property nothing looked at. The floor is not `> 0`: one surviving file is just as vacuous as none.
# It tracks the real tree (123 files at the time of writing) with room to shrink, so a genuine
# consolidation still passes and a root that has moved out from under the lint cannot.
SCAN_FLOOR=100
if [ "${#CANDIDATES[@]}" -lt "$SCAN_FLOOR" ]; then
  hdr "result"
  note "blocking-ffi-lint FAILED — SCAN ROOT EMPTY OR MOVED"
  note "found ${#CANDIDATES[@]} non-test .rs files under crates/busbar/src, expected >= ${SCAN_FLOOR}."
  note "This lint scanned (almost) nothing, so its verdict is meaningless — it is NOT a pass."
  note "If the engine crate legitimately moved, update the find root above AND this floor together."
  exit 1
fi
note "scan set: ${#CANDIDATES[@]} files under crates/busbar/src (floor ${SCAN_FLOOR})"

hits=""
for f in "${CANDIDATES[@]}"; do
  h=$(scan_rule "$f") || true
  [ -n "$h" ] && hits="${hits}${h}"$'\n'
done
hits="${hits%$'\n'}"

fail=0
if [ -n "$hits" ]; then
  while IFS= read -r h; do note "BLOCKING-FFI: $h"; done <<<"$hits"
  fail=1
else
  note "ok"
fi

hdr "result"
if [ "$fail" -ne 0 ]; then
  note "blocking-ffi-lint FAILED"
  note "a synchronous call into a dlopened plugin must run on a blocking thread, never on a reactor"
  note "worker. Route it through the offload seam that already exists for its kind:"
  note "  * auth chain      -> AuthMiddleware::run_chain_on_request_path / run_admin_chain_maybe_offloaded"
  note "  * login plugin    -> auth::token::offload_login_call"
  note "  * hook transport  -> hooks::gate_transport_offloaded (which resolves the secrets too)"
  note "  * config mutation -> Txn::read_store / Txn::store_write (the body runs on the ASYNC side)"
  note "  * anything else   -> tokio::task::spawn_blocking, BOUNDED by a semaphore, FAILING CLOSED"
  note "    when a permit cannot be acquired (spawn_blocking alone exhausts the shared pool)."
  note "If (and ONLY if) the call is BOOT-time, or the enclosing async fn is only ever driven on a"
  note "blocking thread, mark it: \`// blocking-ffi-lint: allow — <reason, naming which>\`."
  exit 1
fi
note "blocking-ffi-lint passed"
