use super::*;
use std::collections::HashSet;

#[test]
fn from_ranked_drops_unknown_and_dedups() {
    let valid: HashSet<usize> = [0usize, 1, 2].into_iter().collect();
    // 9 is unknown (dropped); 1 is duplicated (deduped); order preserved.
    let d = RoutingDecision::from_ranked([2usize, 9, 1, 1, 0], &valid);
    assert_eq!(d, RoutingDecision::Prefer(vec![2, 1, 0]));
}

use crate::config::{HookCfg, HookKind, PolicyOnError, PoolPolicy, PromptAccess, UserAccess};
use std::collections::HashMap;
use std::path::PathBuf;

// ── Hook plugin test env ──────────────────────────────────────────────────────────────────────────
// The 1.5.0 hooks-as-plugins world: a hook resolves its `plugin:` ref against a validated plugin
// registry into a `DlopenPolicy`. These resolution tests build a real registry from the hermetic
// `busbar-hook-test-plugin` cdylib (aliased `test-hook`), so `resolve_*` exercises the true
// registry-resolution path — the same seam the request path uses. A gate whose `plugin:` names a
// missing plugin resolves to `None` (gate-absent), exactly as before.

/// Locate the hermetic hook-test plugin cdylib in the build's target dir (like the store/auth tests).
/// Under CI (`cargo test --workspace` always builds it) a missing cdylib is a HARD failure; locally a
/// missing cdylib returns `None` and the caller skips cleanly.
///
/// Checks BOTH the "uplifted" `<profile_dir>/<name>` copy (only refreshed when `[lib]` is a ROOT
/// build target, e.g. `cargo build --all-targets`) and the raw `<profile_dir>/deps/<name>` compiler
/// output (refreshed on every build that recompiles the lib). A bare `cargo test` (or any other
/// scoped build) does NOT uplift the cdylib to the top-level profile dir, only to
/// `target/deps` — checking only `profile_dir` silently found nothing even though the cdylib really
/// was built, so every test gated on this returned `None` and silently skipped (confirmed by hand:
/// `cargo test -p busbar hooks::tests::` printed "skip: hook cdylib not built" for every hook
/// resolution test after clearing target/debug/deps). Same fix already applied to
/// auth-oidc-plugin's/store-postgres-plugin's/webrequest-hook's equivalent `plugin_path()` helpers.
fn hook_cdylib() -> Option<PathBuf> {
    let candidate = (|| {
        let exe = std::env::current_exe().ok()?;
        let profile_dir = exe.parent()?.parent()?;
        let name = busbar_plugin_loader::plugin_library_filename("busbar_hook_test_plugin");
        let uplifted = profile_dir.join(&name);
        let raw = profile_dir.join("deps").join(&name);
        [uplifted, raw]
            .into_iter()
            .filter_map(|p| {
                std::fs::metadata(&p)
                    .and_then(|m| m.modified())
                    .ok()
                    .map(|mtime| (p, mtime))
            })
            .max_by_key(|(_, mtime)| *mtime)
            .map(|(p, _)| p)
    })();
    if candidate.is_none() && std::env::var_os("CI").is_some() {
        panic!(
            "the hook-test plugin cdylib is not built under CI (checked both the uplifted target \
             dir and target/deps); refusing to silently skip the hook-plugin resolution coverage"
        );
    }
    candidate
}

/// Build a validated [`HookEnv`] whose registry loads the hook-test cdylib under the given alias and
/// declared manifest `needs`. `None` when the cdylib is not built (the caller skips). Uses the
/// unsigned + `allow_unsigned` path (the test can't sign with the embedded first-party key), which
/// still exercises the full scan/trust/load pipeline.
/// Serialises the dlopen-backed hook tests.
///
/// Resolving a hook transport stages a copy of the cdylib to disk, `dlopen`s it and runs its
/// constructor, all under `TRANSPORT_RESOLVE_TIMEOUT_MS` (5s). That deadline is a deliberate
/// PRODUCTION value and correct: the work is milliseconds on any sane machine. But fifteen of these
/// tests run concurrently inside a full `cargo test --workspace`, each doing that same staging and
/// dlopen, and on an oversubscribed machine the 5s can genuinely elapse — the caller then reports
/// "hook plugin unresolvable" and the test fails for a reason that says nothing about the code.
///
/// Observed as an intermittent failure of `dlopen_configure_acks_exact_version` and
/// `dlopen_status_and_schema_reads`: green in isolation and single-threaded, red roughly one run in
/// three under `--workspace`. Serialising the tests fixes the oversubscription, which is a
/// TEST-HARNESS problem, rather than loosening a deadline that protects a real control-plane path.
///
/// Held only for the STAGING step inside `test_env_needs`, never across an await: that is the part
/// that competes for disk and CPU, and it is what the callers (sync and async alike) all share. A
/// plain `std` mutex is therefore correct and works for both, where a guard spanning an await would
/// not be.
pub(super) static DLOPEN_TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// Held for the WHOLE body of every `dlopen_*` test, which the staging lock above cannot do.
///
/// The expensive, deadline-bound part is not staging: it is `gate_transport_named` doing the real
/// `dlopen` and running the plugin constructor, inside `offload_bounded`'s 5s budget, during the
/// test body. Fifteen of those racing each other is what actually elapses the deadline. Async
/// because the guard spans awaits.
pub(super) static DLOPEN_BODY_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

fn test_env_needs(alias: &str, needs: busbar_plugin_sign::HookNeeds) -> Option<HookEnv> {
    // Poison-tolerant: a panicking test elsewhere must not cascade into every other dlopen test
    // reporting a lock error instead of its own result.
    let _staging_guard = DLOPEN_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let lib = std::fs::read(hook_cdylib()?).expect("read hook cdylib");
    let dir = crate::tests::tmp_plugin_dir(&format!("hook-env-{alias}"));
    let mut m = crate::tests::plugin_manifest("busbar-hook-test-plugin", alias, "acme");
    m.kind = "hook".into();
    m.abi_version = *busbar_plugin_loader::supported_abi("hook")
        .iter()
        .max()
        .expect("hook abi");
    m.needs = needs;
    let tarball = crate::tests::unsigned_tarball(m, &lib);
    std::fs::write(dir.join("hook.tar.gz"), tarball).unwrap();
    let mut policy = busbar_plugin_sign::TrustPolicy {
        binary_version: "1.5.0".into(),
        ..Default::default()
    };
    policy.allow_unsigned = true;
    let registry = busbar_plugin_loader::scan_and_validate(&dir, &policy).expect("scan");
    let _ = std::fs::remove_dir_all(&dir);
    Some(HookEnv::new(
        std::sync::Arc::new(registry),
        std::sync::Arc::new(crate::config::secret::SecretResolver::builtins_only()),
    ))
}

/// A [`HookEnv`] that resolves `test-hook` (declaring rw prompt + ro user intent, so the projection
/// matrix's operator grants are not clamped by the manifest in the general resolution tests).
fn test_env() -> Option<HookEnv> {
    test_env_needs(
        "test-hook",
        busbar_plugin_sign::HookNeeds {
            prompt: busbar_plugin_sign::NeedLevel::Rw,
            user: busbar_plugin_sign::NeedLevel::Ro,
        },
    )
}

/// An empty env (no plugins loaded) — a hook ref resolves to `None` (gate-absent).
fn empty_env() -> HookEnv {
    HookEnv::new(
        std::sync::Arc::new(busbar_plugin_loader::PluginRegistry::empty()),
        std::sync::Arc::new(crate::config::secret::SecretResolver::builtins_only()),
    )
}

/// Fail-closed: a hook whose SecretRef setting cannot resolve must make `preresolve_hook_secrets`
/// return `Err` (aborting boot/reload CLOSED), matching the store/auth paths — NOT be silently dropped
/// from the routing chain. A hook whose settings all resolve returns `Ok`.
#[test]
fn preresolve_hook_secrets_fails_closed_on_unresolvable_secret() {
    let env = empty_env();
    // A hook carrying a SecretRef (`{ env: <unset var> }`) — the resolver (`builtins_only`) cannot
    // resolve an unset env var, so this MUST fail the pre-resolve pass.
    let mut settings = serde_json::Map::new();
    settings.insert(
        "licenseKey".to_string(),
        serde_json::json!({ "env": "BUSBAR_TEST_DEFINITELY_UNSET_SECRET_B1" }),
    );
    let mut hook = base_gate();
    hook.settings = settings;
    let mut hooks = HashMap::new();
    hooks.insert("compliance-gate".to_string(), hook);
    let err = env
        .preresolve_hook_secrets(&hooks)
        .expect_err("an unresolvable hook secret must fail the pre-resolve pass CLOSED");
    assert!(
        err.contains("compliance-gate"),
        "the error names the offending hook: {err}"
    );

    // A hook with NO secret refs (plain settings) resolves cleanly — the pass is Ok.
    let mut plain = base_gate();
    plain
        .settings
        .insert("mode".to_string(), serde_json::json!("strict"));
    let mut ok_hooks = HashMap::new();
    ok_hooks.insert("plain-gate".to_string(), plain);
    assert!(env.preresolve_hook_secrets(&ok_hooks).is_ok());
}

/// `preopen_gate_hooks` pre-opens ONLY `kind: gate` hooks (decision + rewrite), never taps — taps
/// observe and legitimately fail-open, so a broken tap must never abort boot/reload. A GATE whose
/// plugin resolves but whose settings/open() fails MUST abort (fail-closed): the gate would
/// otherwise be silently dropped and its admission/rewrite decision lost.
#[test]
fn preopen_gate_hooks_aborts_on_a_broken_gate_but_never_a_broken_tap() {
    let Some(env) = test_env() else {
        eprintln!("skip: hook cdylib not built (run under --workspace)");
        return;
    };
    // An unresolvable SecretRef in settings — the plugin itself resolves fine (it's registered in
    // `env`), but `resolve_hook_settings` must fail BEFORE open() is ever attempted.
    let mut settings = serde_json::Map::new();
    settings.insert(
        "licenseKey".to_string(),
        serde_json::json!({ "env": "BUSBAR_TEST_DEFINITELY_UNSET_SECRET_PREOPEN" }),
    );

    // A broken TAP must not abort — taps fail-open by design.
    let mut broken_tap = base_gate();
    broken_tap.kind = HookKind::Tap;
    broken_tap.settings = settings.clone();
    let tap_hooks = registry("broken-tap", broken_tap);
    assert!(
        env.preopen_gate_hooks(&tap_hooks).is_ok(),
        "a broken TAP must never abort boot/reload (taps fail-open)"
    );

    // The SAME broken settings on a GATE must abort — a decision/rewrite gate can never silently
    // vanish while boot/reload reports success.
    let mut broken_gate = base_gate();
    broken_gate.settings = settings;
    let gate_hooks = registry("broken-gate", broken_gate);
    let err = env
        .preopen_gate_hooks(&gate_hooks)
        .expect_err("a gate whose settings/open() fails must abort boot/reload CLOSED");
    assert!(
        err.contains("broken-gate"),
        "the error names the offending gate: {err}"
    );

    // A healthy gate (resolvable plugin, valid settings) pre-opens cleanly.
    let ok_hooks = registry("ok-gate", base_gate());
    assert!(
        env.preopen_gate_hooks(&ok_hooks).is_ok(),
        "a gate with valid settings must pre-open without error"
    );
}

/// A pool with a native ranking strategy and no gate.
fn pool_policy(policy: PoolPolicy) -> crate::config::PoolCfg {
    crate::config::PoolCfg {
        upstream_credentials: None,
        members: vec![],
        breaker: None,
        failover: None,
        on_exhausted: None,
        affinity: None,
        policy,
        gates: Vec::new(),
        base_named: true,
    }
}

/// A pool referencing a gate hook by name (native strategy defaults to weighted).
fn pool_with_hook(name: &str) -> crate::config::PoolCfg {
    crate::config::PoolCfg {
        upstream_credentials: None,
        members: vec![],
        breaker: None,
        failover: None,
        on_exhausted: None,
        affinity: None,
        policy: PoolPolicy::Weighted,
        gates: vec![name.to_string()],
        base_named: false,
    }
}

/// A minimal gate hook backed by the `test-hook` plugin; grants filled by the caller.
fn base_gate() -> HookCfg {
    HookCfg {
        kind: HookKind::Gate,
        plugin: "test-hook".to_string(),
        timeout_ms: crate::config::DEFAULT_POLICY_TIMEOUT_MS,
        on_error: "weighted".to_string(),
        prompt: PromptAccess::No,
        user: UserAccess::No,
        priority: 0,
        at: None,
        settings: serde_json::Map::new(),
        on_empty: None,
        global: false,
        default: false,
        signals: Vec::new(),
        groups: Vec::new(),
        phase: Vec::new(),
    }
}

/// A one-entry hooks registry.
fn registry(name: &str, hook: HookCfg) -> HashMap<String, HookCfg> {
    let mut m = HashMap::new();
    m.insert(name.to_string(), hook);
    m
}

/// Each native `policy:` strategy resolves to a constructed `Policy` whose name round-trips the
/// native registry name. (No gate; empty hook registry.) Requires the removable `hooks-ranking`
/// plugin — under `--no-default-features` a non-weighted native policy is a boot error, not a
/// resolvable policy, so this behavior test only applies when the plugin is compiled in.
#[cfg(feature = "hooks-ranking")]
#[test]
fn native_policy_resolves_constructed_policy() {
    for (policy, name) in [
        (PoolPolicy::Cheapest, "cheapest"),
        (PoolPolicy::Fastest, "fastest"),
        (PoolPolicy::LeastBusy, "least_busy"),
        (PoolPolicy::Usage, "usage"),
    ] {
        let cfg = pool_policy(policy);
        match resolve_policy(&cfg) {
            Some(ResolvedPolicy::Policy { policy, .. }) => {
                assert_eq!(
                    policy.name(),
                    name,
                    "resolved native policy name must round-trip"
                );
            }
            other => panic!(
                "policy: {name} must resolve to a Policy, got none={}",
                other.is_none()
            ),
        }
    }
}

/// The `default:` hook becomes the base ordering for a pool that named NO base (base_named=false)
/// and has no gate of its own — but NOT for a pool that named a base or brought its own gate.
#[test]
fn default_hook_resolves_as_base_for_unnamed_pools() {
    let Some(env) = test_env() else {
        eprintln!("skip: hook cdylib not built (run under --workspace)");
        return;
    };
    let mut def = base_gate();
    def.default = true;
    let mut hooks = registry("def", def);
    // also register the own-gate hook "h"
    hooks.insert("h".to_string(), base_gate());

    assert_eq!(default_hook_name(&hooks), Some("def"));

    // base_named=false + no gate ⇒ inherits the default gate as its base ordering.
    let mut unnamed = pool_with_hook("x");
    unnamed.gates.clear(); // base_named is already false from pool_with_hook
    assert!(
        resolve_pool_ordering(&unnamed, &hooks, &env, Some("def"), 0).is_some(),
        "an unnamed-base pool inherits the default hook as its ordering"
    );

    // base_named=true (explicit weighted) ⇒ default does NOT override; weighted ⇒ None.
    assert!(
        resolve_pool_ordering(
            &pool_policy(PoolPolicy::Weighted),
            &hooks,
            &env,
            Some("def"),
            0
        )
        .is_none(),
        "a pool that named its base keeps it; the default does not override"
    );

    // base_named=false with its OWN gate ⇒ STILL inherits the default as its base — gates are
    // orthogonal to the base ordering (they fire in the phase-2 reconcile on top of it), and
    // its own gate resolves separately via resolve_pool_gates.
    let gated = pool_with_hook("h");
    assert!(
        resolve_pool_ordering(&gated, &hooks, &env, Some("def"), 0).is_some(),
        "an unnamed-base pool with its own gate still inherits the default as base"
    );
    assert_eq!(
        resolve_pool_gates(&gated, &hooks, &env, 0).len(),
        1,
        "the pool's own gate resolves separately, on top of the inherited base"
    );

    // No default registered ⇒ identical to resolve_policy (backstop): unnamed pool ⇒ None.
    assert!(
        resolve_pool_ordering(&unnamed, &HashMap::new(), &env, None, 0).is_none(),
        "no default hook ⇒ the compiled-in weighted backstop (None)"
    );
}

/// A `default: true` hook that is NOT a non-rewriting decision gate (a `prompt: rw` gate, or a
/// `tap`) must NOT become a pool's base ordering — it structurally cannot return an `order`
/// (a rw hook's decision arm normalizes to Abstain; a tap has no decision arm at all). Before the
/// fix, `resolve_pool_ordering` applied NO filter at all (unlike its siblings
/// `resolve_pool_gates`/`resolve_gate_hooks`), so every unnamed-base pool paid a per-request
/// plugin round-trip + DOM materialization for a guaranteed no-op.
///
/// HARNESS CAVEAT: like every test in this file, `test_env()` prints a skip and returns green if
/// the hook cdylib is not built. Run under `cargo test --workspace` and confirm the output does
/// NOT contain "skip: hook cdylib not built" before trusting this RED proof.
#[test]
fn default_rw_hook_is_not_the_base_ordering() {
    let Some(env) = test_env() else {
        eprintln!("skip: hook cdylib not built (run under --workspace)");
        return;
    };

    // `kind: gate, prompt: rw, default: true` — a rewrite gate, not a decision gate.
    let mut rw = base_gate();
    rw.prompt = PromptAccess::Rw;
    rw.default = true;
    let hooks = registry("def", rw);
    let mut unnamed = pool_with_hook("x");
    unnamed.gates.clear();
    assert!(
        resolve_pool_ordering(&unnamed, &hooks, &env, Some("def"), 0).is_none(),
        "a prompt:rw default hook must not become the base ordering — it can never return an order"
    );

    // `kind: tap, default: true` — no decision arm at all.
    let mut tap = base_gate();
    tap.kind = HookKind::Tap;
    tap.default = true;
    let hooks = registry("deftap", tap);
    let mut unnamed2 = pool_with_hook("x");
    unnamed2.gates.clear();
    assert!(
        resolve_pool_ordering(&unnamed2, &hooks, &env, Some("deftap"), 0).is_none(),
        "a tap default hook must not become the base ordering — it has no decision arm"
    );
}

/// `policy: weighted` (default / absent) collapses to the zero-cost default (`None`).
#[test]
fn weighted_policy_resolves_none_zero_cost() {
    assert!(
        resolve_policy(&pool_policy(PoolPolicy::Weighted)).is_none(),
        "the weighted native must collapse to the zero-cost default path"
    );
}

/// A pool gate referencing an UNKNOWN registry entry is skipped at resolution (gate absent) —
/// routing never strands a request; config_validate/pre-flight is the loud gate at boot.
#[test]
fn unknown_hook_ref_falls_back_to_none() {
    let hooks = HashMap::new();
    assert!(resolve_pool_gates(&pool_with_hook("nonexistent"), &hooks, &empty_env(), 0).is_empty());
}

/// A pool `hook:` naming a plugin-backed gate resolves to a constructed `DlopenPolicy` whose name is
/// the hook's registry name; a gate whose plugin is missing (empty registry) degrades to gate-absent.
#[test]
fn plugin_gate_resolves_constructed_policy() {
    let Some(env) = test_env() else {
        eprintln!("skip: hook cdylib not built (run under --workspace)");
        return;
    };
    let hooks = registry("h", base_gate());
    match resolve_pool_gates(&pool_with_hook("h"), &hooks, &env, 0)
        .into_iter()
        .next()
    {
        Some((
            _,
            ResolvedPolicy::Policy {
                policy, timeout, ..
            },
        )) => {
            assert_eq!(
                policy.name(),
                "h",
                "the DlopenPolicy carries the hook's registry name"
            );
            assert_eq!(
                timeout,
                std::time::Duration::from_millis(crate::config::DEFAULT_POLICY_TIMEOUT_MS),
                "a gate with the default timeout resolves to the documented deadline, not 0ms",
            );
        }
        None => panic!("plugin gate must resolve to a Policy"),
    }
    // A missing plugin (empty registry) → gate absent (the pre-flight is the loud gate at boot).
    assert!(resolve_pool_gates(&pool_with_hook("h"), &hooks, &empty_env(), 0).is_empty());
}

/// The plain default (`policy: weighted`, no hook) stays the zero-cost `None` path.
#[test]
fn weighted_default_resolves_none() {
    assert!(resolve_policy(&pool_policy(PoolPolicy::Weighted)).is_none());
}

/// `on_error` resolution: a reserved terminal yields an EMPTY chain + that terminal; a gate
/// name appends its transport and follows ITS on_error; a ranking strategy appends one
/// infallible link and terminates.
#[test]
fn on_error_chain_resolves_gates_and_terminals() {
    let Some(env) = test_env() else {
        eprintln!("skip: hook cdylib not built (run under --workspace)");
        return;
    };
    // a (plugin, on_error: b) -> b (plugin, on_error: reject)
    let mut a = base_gate();
    a.on_error = "b".to_string();
    let mut b = base_gate();
    b.on_error = "reject".to_string();
    let mut hooks = registry("a", a);
    hooks.insert("b".to_string(), b);

    let resolved = resolve_pool_gates(&pool_with_hook("a"), &hooks, &env, 0);
    let Some((
        _,
        ResolvedPolicy::Policy {
            on_error,
            on_error_chain,
            ..
        },
    )) = resolved.into_iter().next()
    else {
        panic!("gate a must resolve");
    };
    assert_eq!(on_error_chain.len(), 1, "one fallback link (gate b)");
    assert_eq!(on_error_chain[0].policy.name(), "b");
    assert_eq!(
        on_error,
        PolicyOnError::Reject,
        "the chain bottoms out on b's reject terminal"
    );

    // `on_error: nothing` — the explicit do-not-participate terminal — resolves to the same
    // no-op machinery as weighted (an empty chain + the Weighted terminal, which every
    // reconcile pass skips): a failing gate with `nothing` can never displace another gate.
    let mut n = base_gate();
    n.on_error = "nothing".to_string();
    let hooks_n = registry("n", n);
    let Some((
        _,
        ResolvedPolicy::Policy {
            on_error,
            on_error_chain,
            ..
        },
    )) = resolve_pool_gates(&pool_with_hook("n"), &hooks_n, &env, 0)
        .into_iter()
        .next()
    else {
        panic!("gate n must resolve");
    };
    assert!(on_error_chain.is_empty());
    assert_eq!(
        on_error,
        PolicyOnError::Weighted,
        "nothing = the non-participating terminal"
    );

    // A direct terminal ⇒ empty chain.
    let mut c = base_gate();
    c.on_error = "first".to_string();
    let hooks = registry("c", c);
    let Some((
        _,
        ResolvedPolicy::Policy {
            on_error,
            on_error_chain,
            ..
        },
    )) = resolve_pool_gates(&pool_with_hook("c"), &hooks, &env, 0)
        .into_iter()
        .next()
    else {
        panic!("gate c must resolve");
    };
    assert!(on_error_chain.is_empty(), "a terminal name has no chain");
    assert_eq!(on_error, PolicyOnError::First);
}

/// `on_error: <ranking strategy>` appends one infallible link and terminates at weighted.
#[cfg(feature = "hooks-ranking")]
#[test]
fn on_error_chain_strategy_terminates() {
    let Some(env) = test_env() else {
        eprintln!("skip: hook cdylib not built (run under --workspace)");
        return;
    };
    let mut g = base_gate();
    g.on_error = "cheapest".to_string();
    let hooks = registry("g", g);
    let Some((
        _,
        ResolvedPolicy::Policy {
            on_error,
            on_error_chain,
            ..
        },
    )) = resolve_pool_gates(&pool_with_hook("g"), &hooks, &env, 0)
        .into_iter()
        .next()
    else {
        panic!("gate g must resolve");
    };
    assert_eq!(on_error_chain.len(), 1);
    assert_eq!(on_error_chain[0].policy.name(), "cheapest");
    assert_eq!(on_error, PolicyOnError::Weighted);
}

/// A pool's `prompt: rw` gate is a PHASE-1 rewrite, not a phase-2 decision gate: it is
/// EXCLUDED from `resolve_pool_gates` and resolved by `resolve_pool_rewrites` instead — so it
/// never pays a decision deadline for a reply arm it cannot return.
#[test]
fn pool_rw_gate_resolves_as_rewrite_not_decision() {
    let Some(env) = test_env() else {
        eprintln!("skip: hook cdylib not built (run under --workspace)");
        return;
    };
    let mut rw = base_gate();
    rw.prompt = PromptAccess::Rw;
    let hooks = registry("rw", rw);
    let pool = pool_with_hook("rw");
    assert!(
        resolve_pool_gates(&pool, &hooks, &env, 0).is_empty(),
        "an rw gate must not resolve as a decision gate"
    );
    assert_eq!(
        resolve_pool_rewrites(&pool, &hooks, &env, 0).len(),
        1,
        "an rw gate must resolve into the pool rewrite chain"
    );
    // And the inverse: a plain (non-rw) gate stays a decision gate, no rewrite entry.
    let hooks = registry("plain", base_gate());
    let pool = pool_with_hook("plain");
    assert_eq!(resolve_pool_gates(&pool, &hooks, &env, 0).len(), 1);
    assert!(resolve_pool_rewrites(&pool, &hooks, &env, 0).is_empty());
}

/// A gate hook with `on_error: nothing`/loop but a MISSING plugin resolves cleanly to gate-absent
/// (never a stranded request), independent of the plugin registry contents.
#[test]
fn missing_plugin_gate_is_absent_not_stranded() {
    let hooks = registry("h", base_gate());
    // With an empty registry the plugin doesn't resolve → gate absent.
    assert!(resolve_pool_gates(&pool_with_hook("h"), &hooks, &empty_env(), 0).is_empty());
}

/// SECURITY INVARIANT: `resolve_rewrite_hooks` admits ONLY `prompt: rw` GATES as rewrite hooks.
/// A `ro`/`no` gate and a tap (even one that claims `prompt: rw`) are excluded — the rw grant is
/// enforced at RESOLUTION, so a hook without the grant can NEVER reach the rewrite/transform path,
/// independent of what it tries to return (the bidirectional grant holds by construction).
#[test]
fn resolve_rewrite_hooks_admits_only_prompt_rw_gates() {
    let Some(env) = test_env() else {
        eprintln!("skip: hook cdylib not built (run under --workspace)");
        return;
    };
    let mk = |kind: HookKind, prompt: PromptAccess| HookCfg {
        kind,
        prompt,
        global: true,
        ..base_gate()
    };
    let mut hooks = HashMap::new();
    hooks.insert("rw-gate".to_string(), mk(HookKind::Gate, PromptAccess::Rw));
    hooks.insert("ro-gate".to_string(), mk(HookKind::Gate, PromptAccess::Ro));
    hooks.insert("no-gate".to_string(), mk(HookKind::Gate, PromptAccess::No));
    // A tap that (nonsensically) claims prompt: rw — still NEVER a rewrite hook (a tap can't reply).
    hooks.insert("rw-tap".to_string(), mk(HookKind::Tap, PromptAccess::Rw));
    let global = vec![
        "rw-gate".to_string(),
        "ro-gate".to_string(),
        "no-gate".to_string(),
        "rw-tap".to_string(),
    ];
    let resolved = resolve_rewrite_hooks(&hooks, &global, &env, 0);
    assert_eq!(
        resolved.len(),
        1,
        "only the prompt:rw GATE is a rewrite hook; ro/no gates + the tap are excluded"
    );
}

/// CLASS INVARIANT: REWRITE admission goes through the SAME belt-and-suspenders meet
/// as the read projections — `hooks::effective_access`. A `prompt: rw` OPERATOR grant is not
/// sufficient on its own; the plugin's SIGNED manifest must also declare `needs: { prompt: rw }`.
///
/// One assertion covers BOTH halves of the bypass, because admission is what carries them:
///  * CONFIDENTIALITY — a hook admitted to a rewrite chain is handed the FULL flattened prompt
///    projection (`proxy::hooks::apply_global_rewrites` passes `with_prompt = true`
///    unconditionally, which is sound ONLY because of this gate);
///  * INTEGRITY — an admitted hook may return a `RewriteReply` that is spliced into the upstream
///    request body (messages replaced, `tools` appended).
///
/// The matrix is {manifest need} × {both rewrite resolvers}, with the operator grant pinned at `rw`
/// throughout, so the signed intent is the only variable. Pre-fix, both resolvers keyed admission
/// on `hook.prompt.can_rewrite()` alone and every row admitted.
#[test]
fn rewrite_admission_requires_the_signed_manifest_rewrite_need() {
    use busbar_plugin_sign::{HookNeeds, NeedLevel};

    for (need, admitted) in [
        (NeedLevel::No, false),
        (NeedLevel::Ro, false),
        (NeedLevel::Rw, true),
    ] {
        let needs = HookNeeds {
            prompt: need,
            user: NeedLevel::No,
        };
        let Some(env) = test_env_needs("test-hook", needs) else {
            eprintln!("skip: hook cdylib not built (run under --workspace)");
            return;
        };
        // The operator's grant is the MAXIMUM rung on every row — only the manifest varies.
        let mut rw = base_gate();
        rw.prompt = PromptAccess::Rw;
        rw.global = true;
        let hooks = registry("rw", rw);

        let global = resolve_rewrite_hooks(&hooks, &["rw".to_string()], &env, 0);
        assert_eq!(
            !global.is_empty(),
            admitted,
            "global rewrite chain: `prompt: rw` + manifest `needs.prompt: {need:?}` must \
             {} admit — the operator grant alone is not the ticket",
            if admitted { "" } else { "NOT " }
        );
        let pool = resolve_pool_rewrites(&pool_with_hook("rw"), &hooks, &env, 0);
        assert_eq!(
            !pool.is_empty(),
            admitted,
            "pool rewrite chain: `prompt: rw` + manifest `needs.prompt: {need:?}` must {} admit \
             — the per-pool resolver is a SIBLING of the global one and must not diverge",
            if admitted { "" } else { "NOT " }
        );

        // The read half is derived from the SAME meet, so admission and projection can never
        // disagree: anything admitted to a rewrite chain is, by the ladder, allowed to read.
        let (send_prompt, _) = projection_grants("rw", hooks.get("rw").unwrap(), &env);
        assert!(
            !admitted || send_prompt,
            "an admitted rewrite hook must also be cleared to READ the prompt it rewrites"
        );
        assert_eq!(
            send_prompt,
            need.wants_read(),
            "the read half stays the meet of grant and manifest, unchanged by this fix"
        );
    }
}

/// A `kind: gate` hook whose OPERATOR grant is `prompt: rw` but whose
/// SIGNED MANIFEST declares less (`ro`/absent `needs.prompt`) is excluded from BOTH admission chains
/// by construction — `resolve_pool_gates`/`resolve_gate_hooks` exclude it from the decision chain on
/// the raw grant (deliberate, see `resolve_pool_gates`'s doc comment); `resolve_pool_rewrites`/
/// `resolve_rewrite_hooks` exclude it from the rewrite chain on the effective grant (also deliberate,
/// see `rewrite_admission_requires_the_signed_manifest_rewrite_need` above). Each exclusion is
/// individually correct, but together they leave the hook completely inert — configured, opening fine
/// at boot, reported registered by the admin API, yet never firing on any request — with no
/// operator-visible signal beyond a `tracing::warn!` that RUST_LOG=error silences.
///
/// `hook_inert_gate_banner` is the fix: the SAME mismatch, surfaced with the SAME loudness discipline
/// as `open_relay_banner`/`inert_durable_keys_banner` (ERROR level + unconditional stderr at the call
/// site in `effective_access`). This test pins the banner's firing condition directly, exactly as the
/// `open_relay_banner`/`inert_durable_keys_banner` unit tests pin theirs.
#[test]
fn hook_inert_gate_banner_fires_only_for_a_gate_with_the_chain_killing_mismatch() {
    use busbar_plugin_sign::NeedLevel;

    // The exact bug scenario: `kind: gate`, operator `prompt: rw`, manifest only `ro`. Must banner,
    // loudly, naming the hook, the plugin, and both exclusion mechanisms.
    let banner = hook_inert_gate_banner(
        "compliance-gate",
        "acme.compliance",
        HookKind::Gate,
        NeedLevel::Ro,
    )
    .expect("a gate with a manifest-denied rw grant must produce a banner");
    assert!(
        banner.contains("compliance-gate") && banner.contains("acme.compliance"),
        "banner must name the offending hook and plugin: {banner}"
    );
    assert!(
        banner.contains("INERT")
            && banner.contains("decision-gate chain")
            && banner.contains("rewrite chain"),
        "banner must explain BOTH exclusions, not just one: {banner}"
    );

    // Manifest declaring `no` need is the same story (absent `needs.prompt` deserializes to `No`).
    assert!(hook_inert_gate_banner("g", "p", HookKind::Gate, NeedLevel::No).is_some());

    // A `kind: tap` hook was never in either admission chain to begin with — the same grant/manifest
    // mismatch on a tap is a fat-fingered grant (still warn-worthy), not a silent gate outage.
    assert!(
        hook_inert_gate_banner("t", "p", HookKind::Tap, NeedLevel::Ro).is_none(),
        "a tap never joins an admission chain, so it must not get the gate-outage banner"
    );
}

/// A minimal capturing `tracing::Subscriber` (no test-only crate needed) — records every event's
/// source line, so a test can assert exactly which `tracing::warn!`/`tracing::error!` call site
/// fired, and how many times. Mirrors the pattern already used for
/// `to_policy_with_floor_warns_only_on_a_non_empty_malformed_floor` in config's own test suite.
struct LineCapturingSubscriber(std::sync::Arc<std::sync::Mutex<Vec<u32>>>);
impl tracing::Subscriber for LineCapturingSubscriber {
    fn enabled(&self, _metadata: &tracing::Metadata<'_>) -> bool {
        true
    }
    fn new_span(&self, _span: &tracing::span::Attributes<'_>) -> tracing::span::Id {
        tracing::span::Id::from_u64(1)
    }
    fn record(&self, _span: &tracing::span::Id, _values: &tracing::span::Record<'_>) {}
    fn record_follows_from(&self, _span: &tracing::span::Id, _follows: &tracing::span::Id) {}
    fn event(&self, event: &tracing::Event<'_>) {
        // WARN/ERROR only — `effective_access` also emits a legitimate `tracing::info!` (declared
        // intent) whenever the manifest declares ANY need, which would otherwise pollute a test
        // that's specifically checking for the fat-fingered-grant WARN/inert-gate ERROR.
        let level = *event.metadata().level();
        if level == tracing::Level::WARN || level == tracing::Level::ERROR {
            if let Some(line) = event.metadata().line() {
                self.0.lock().unwrap().push(line);
            }
        }
    }
    fn enter(&self, _span: &tracing::span::Id) {}
    fn exit(&self, _span: &tracing::span::Id) {}
}

/// `effective_access`'s two "fat-fingered grant" warns (prompt-read, user-read) are PURE logging
/// side effects — they never change the returned `(PromptAccess, UserAccess)` — so they're only
/// observable by capturing the actual `tracing` event. Each must fire EXACTLY when the operator
/// grants MORE than the plugin's manifest wants to READ, and never otherwise.
#[test]
fn effective_access_warns_on_inert_read_grants_only() {
    use busbar_plugin_sign::NeedLevel;

    let events: std::sync::Arc<std::sync::Mutex<Vec<u32>>> =
        std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    let sub = LineCapturingSubscriber(events.clone());

    // Fat-fingered PROMPT grant: operator grants `ro`, manifest declares no prompt need at all.
    // Must warn at effective_access's prompt-inert-grant call site.
    let Some(env) = test_env_needs(
        "inert-prompt",
        busbar_plugin_sign::HookNeeds {
            prompt: NeedLevel::No,
            user: NeedLevel::No,
        },
    ) else {
        eprintln!("skip: hook cdylib not built (run under --workspace)");
        return;
    };
    let mut h = base_gate();
    h.plugin = "inert-prompt".to_string();
    h.prompt = PromptAccess::Ro;
    tracing::subscriber::with_default(sub, || {
        let _ = effective_access("h", &h, &env);
    });
    let seen = events.lock().unwrap().clone();
    assert_eq!(
        seen.len(),
        1,
        "a prompt grant the manifest never declared must warn exactly once: {seen:?}"
    );

    // The matching case (manifest declares what's granted) must NOT warn.
    let events2: std::sync::Arc<std::sync::Mutex<Vec<u32>>> =
        std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    let sub2 = LineCapturingSubscriber(events2.clone());
    let Some(env2) = test_env_needs(
        "matched-prompt",
        busbar_plugin_sign::HookNeeds {
            prompt: NeedLevel::Ro,
            user: NeedLevel::No,
        },
    ) else {
        return;
    };
    let mut h2 = base_gate();
    h2.plugin = "matched-prompt".to_string();
    h2.prompt = PromptAccess::Ro;
    tracing::subscriber::with_default(sub2, || {
        let _ = effective_access("h2", &h2, &env2);
    });
    assert!(
        events2.lock().unwrap().is_empty(),
        "a grant the manifest DOES declare must not warn: {:?}",
        events2.lock().unwrap()
    );

    // Fat-fingered USER grant: operator grants `ro`, manifest declares no user need.
    let events3: std::sync::Arc<std::sync::Mutex<Vec<u32>>> =
        std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    let sub3 = LineCapturingSubscriber(events3.clone());
    let Some(env3) = test_env_needs(
        "inert-user",
        busbar_plugin_sign::HookNeeds {
            prompt: NeedLevel::No,
            user: NeedLevel::No,
        },
    ) else {
        return;
    };
    let mut h3 = base_gate();
    h3.plugin = "inert-user".to_string();
    h3.user = UserAccess::Ro;
    tracing::subscriber::with_default(sub3, || {
        let _ = effective_access("h3", &h3, &env3);
    });
    let seen3 = events3.lock().unwrap().clone();
    assert_eq!(
        seen3.len(),
        1,
        "a user grant the manifest never declared must warn exactly once: {seen3:?}"
    );

    // The matching user case must NOT warn.
    let events4: std::sync::Arc<std::sync::Mutex<Vec<u32>>> =
        std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    let sub4 = LineCapturingSubscriber(events4.clone());
    let Some(env4) = test_env_needs(
        "matched-user",
        busbar_plugin_sign::HookNeeds {
            prompt: NeedLevel::No,
            user: NeedLevel::Ro,
        },
    ) else {
        return;
    };
    let mut h4 = base_gate();
    h4.plugin = "matched-user".to_string();
    h4.user = UserAccess::Ro;
    tracing::subscriber::with_default(sub4, || {
        let _ = effective_access("h4", &h4, &env4);
    });
    assert!(
        events4.lock().unwrap().is_empty(),
        "a user grant the manifest DOES declare must not warn: {:?}",
        events4.lock().unwrap()
    );
}

/// The inert-GATE-rewrite banner (`effective_access`'s WRITE-half branch) must fire EXACTLY ONCE
/// per hook NAME per `HookEnv` lifetime — a hook resolved twice (e.g. named in two pools'
/// `hooks:` lists) must not re-banner. Pins `banner_seen`'s de-dup guard directly (the guard IS
/// the `.insert()` call — a hand-applied `with false`/`with true` mutation of the guard removes
/// the call entirely, so `banner_seen` is never populated either way, distinguishing both from
/// real code via the set's post-call membership).
#[test]
fn effective_access_inert_gate_rewrite_banner_fires_once_per_hook_name() {
    use busbar_plugin_sign::NeedLevel;

    let events: std::sync::Arc<std::sync::Mutex<Vec<u32>>> =
        std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    let sub = LineCapturingSubscriber(events.clone());

    // The exact inert-gate scenario: kind: gate, operator grants `rw`, manifest only declares `ro`
    // (can_rewrite() true, wants_rewrite() false) — the WRITE-half mismatch.
    let Some(env) = test_env_needs(
        "inert-rewrite",
        busbar_plugin_sign::HookNeeds {
            prompt: NeedLevel::Ro,
            user: NeedLevel::No,
        },
    ) else {
        eprintln!("skip: hook cdylib not built (run under --workspace)");
        return;
    };
    let mut h = base_gate();
    h.plugin = "inert-rewrite".to_string();
    h.prompt = PromptAccess::Rw;

    assert!(
        !env.banner_seen.lock().unwrap().contains("h"),
        "banner_seen must start empty for this name"
    );
    tracing::subscriber::with_default(sub, || {
        let _ = effective_access("h", &h, &env);
    });
    assert!(
        env.banner_seen.lock().unwrap().contains("h"),
        "the FIRST call for an inert-rewrite gate must record the hook name in banner_seen \
         (proves the dedup guard's `.insert()` actually ran)"
    );
    let banner_events = events.lock().unwrap().clone();
    assert_eq!(
        banner_events.len(),
        1,
        "the first call for an inert-rewrite gate must emit exactly one banner-adjacent event: \
         {banner_events:?}"
    );

    // A SECOND call for the SAME name must NOT re-banner (dedup).
    let events2: std::sync::Arc<std::sync::Mutex<Vec<u32>>> =
        std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    let sub2 = LineCapturingSubscriber(events2.clone());
    tracing::subscriber::with_default(sub2, || {
        let _ = effective_access("h", &h, &env);
    });
    assert!(
        events2.lock().unwrap().is_empty(),
        "a hook already in banner_seen must not re-banner on a second resolution: {:?}",
        events2.lock().unwrap()
    );

    // A DIFFERENT non-inert (matching) gate must never enter banner_seen or emit any event.
    let events3: std::sync::Arc<std::sync::Mutex<Vec<u32>>> =
        std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    let sub3 = LineCapturingSubscriber(events3.clone());
    let Some(env3) = test_env_needs(
        "matched-rewrite",
        busbar_plugin_sign::HookNeeds {
            prompt: NeedLevel::Rw,
            user: NeedLevel::No,
        },
    ) else {
        return;
    };
    let mut h3 = base_gate();
    h3.plugin = "matched-rewrite".to_string();
    h3.prompt = PromptAccess::Rw;
    tracing::subscriber::with_default(sub3, || {
        let _ = effective_access("clean", &h3, &env3);
    });
    assert!(
        !env3.banner_seen.lock().unwrap().contains("clean"),
        "a gate whose manifest matches its grant must never enter banner_seen"
    );
    assert!(
        events3.lock().unwrap().is_empty(),
        "a matched-rewrite gate must emit no banner-adjacent event: {:?}",
        events3.lock().unwrap()
    );
}

/// `resolve_gate_hooks` admits the GLOBAL DECISION gates: `kind: gate` that is NOT a rewrite
/// (`prompt: rw`) gate. A rewrite gate fires in the phase-1 transform pass (excluded here); a tap
/// never decides (excluded). So from {rw-gate, ro-gate, no-gate, rw-tap} exactly the ro + no gates
/// resolve as decision gates.
#[test]
fn resolve_gate_hooks_admits_only_decision_gates() {
    let Some(env) = test_env() else {
        eprintln!("skip: hook cdylib not built (run under --workspace)");
        return;
    };
    let mk = |kind: HookKind, prompt: PromptAccess| HookCfg {
        kind,
        prompt,
        global: true,
        ..base_gate()
    };
    let mut hooks = HashMap::new();
    hooks.insert("rw-gate".to_string(), mk(HookKind::Gate, PromptAccess::Rw));
    hooks.insert("ro-gate".to_string(), mk(HookKind::Gate, PromptAccess::Ro));
    hooks.insert("no-gate".to_string(), mk(HookKind::Gate, PromptAccess::No));
    hooks.insert("a-tap".to_string(), mk(HookKind::Tap, PromptAccess::Ro));
    let global = vec![
        "rw-gate".to_string(),
        "ro-gate".to_string(),
        "no-gate".to_string(),
        "a-tap".to_string(),
    ];
    let resolved = resolve_gate_hooks(&hooks, &global, &env, 0);
    assert_eq!(
        resolved.len(),
        2,
        "decision gates = the ro + no gates; the rw (rewrite) gate and the tap are excluded"
    );
}

/// `resolve_tap_hooks` admits ONLY `kind: tap` hooks observing at the REQUESTED stage (unset
/// `at:` defaults to request). A gate is excluded (it fires on the gate seam, not the tap
/// fan-out).
#[test]
fn resolve_tap_hooks_admits_only_request_stage_taps() {
    let Some(env) = test_env() else {
        eprintln!("skip: hook cdylib not built (run under --workspace)");
        return;
    };
    let mk = |kind: HookKind, at: Option<crate::config::HookStage>| HookCfg {
        kind,
        at,
        global: true,
        ..base_gate()
    };
    let mut hooks = HashMap::new();
    hooks.insert(
        "tap-req".to_string(),
        mk(HookKind::Tap, Some(crate::config::HookStage::Request)),
    );
    // FREEZE BLOCKER: a tap with NEITHER `phase:` nor `at:` fires at THE FOUR CORE STAGES (not
    // just `request`, and not "every stage that will ever exist") — so it is admitted at request AND
    // response below. See `CORE_HOOK_PHASES`.
    hooks.insert("tap-unset".to_string(), mk(HookKind::Tap, None));
    hooks.insert(
        "tap-completion".to_string(),
        mk(HookKind::Tap, Some(crate::config::HookStage::Response)),
    );
    hooks.insert("a-gate".to_string(), mk(HookKind::Gate, None));
    let global = vec![
        "tap-req".to_string(),
        "tap-unset".to_string(),
        "tap-completion".to_string(),
        "a-gate".to_string(),
    ];
    let resolved = resolve_tap_hooks(&hooks, &global, &env, 0, crate::config::HookStage::Request);
    assert_eq!(
        resolved.len(),
        2,
        "only the two REQUEST-stage taps resolve; the gate and the completion-stage tap are excluded"
    );
    // The same registry resolved for the RESPONSE stage admits exactly the response tap.
    let completion =
        resolve_tap_hooks(&hooks, &global, &env, 0, crate::config::HookStage::Response);
    assert_eq!(
        completion.len(),
        2,
        "the explicit response-stage tap AND the unset tap (omitted = the four core stages)"
    );
    // The ROUTING stage admits only the unset tap, never the two stage-pinned ones.
    assert_eq!(
        resolve_tap_hooks(&hooks, &global, &env, 0, crate::config::HookStage::Routing).len(),
        1,
        "only the phase-unset tap observes the routing stage (omitted = the four core stages)"
    );
    // Every resolved tap here is `prompt: no`, so `send_prompt` (the middle tuple element) is false.
    assert!(
        resolved.iter().all(|(_, send_prompt, _, _)| !*send_prompt),
        "a prompt:no tap must not carry the prompt-content grant"
    );
}

/// 1.5.3 PHASE LIST: a tap with `phase: [response]` resolves ONLY into the response stage bucket —
/// not request/candidate/routing — generalizing the single `at:`. A tap with a MULTI-stage phase
/// (`[request, response]`) resolves into BOTH named buckets.
#[test]
fn resolve_tap_hooks_honors_phase_list() {
    use crate::config::HookStage;
    let Some(env) = test_env() else {
        eprintln!("skip: hook cdylib not built (run under --workspace)");
        return;
    };
    let mk = |phase: Vec<HookStage>| HookCfg {
        kind: HookKind::Tap,
        global: true,
        phase,
        ..base_gate()
    };
    let mut hooks = HashMap::new();
    hooks.insert("resp-only".to_string(), mk(vec![HookStage::Response]));
    hooks.insert(
        "req-and-resp".to_string(),
        mk(vec![HookStage::Request, HookStage::Response]),
    );
    let global = vec!["resp-only".to_string(), "req-and-resp".to_string()];

    // Response stage: both fire.
    assert_eq!(
        resolve_tap_hooks(&hooks, &global, &env, 0, HookStage::Response).len(),
        2,
        "both taps declare the response phase"
    );
    // Request stage: only the multi-stage tap fires; `phase: [response]` is excluded here.
    assert_eq!(
        resolve_tap_hooks(&hooks, &global, &env, 0, HookStage::Request).len(),
        1,
        "phase: [response] does not fire at the request stage"
    );
    // Candidate/routing: neither declares them.
    assert!(resolve_tap_hooks(&hooks, &global, &env, 0, HookStage::Candidate).is_empty());
    assert!(resolve_tap_hooks(&hooks, &global, &env, 0, HookStage::Routing).is_empty());
}

/// A tap's `prompt: ro` grant flows through `resolve_tap_hooks` as `send_prompt = true` (the plugin
/// also declares the prompt need), so the firing site can hand it the prompt-content projection; a
/// `prompt: no` tap stays `false` (shape-only). This is the per-grant projection contract for taps.
#[test]
fn resolve_tap_hooks_carries_prompt_grant() {
    let Some(env) = test_env() else {
        eprintln!("skip: hook cdylib not built (run under --workspace)");
        return;
    };
    let mk = |prompt: PromptAccess| HookCfg {
        kind: HookKind::Tap,
        prompt,
        global: true,
        ..base_gate()
    };
    let mut hooks = HashMap::new();
    hooks.insert("ro-tap".to_string(), mk(PromptAccess::Ro));
    hooks.insert("no-tap".to_string(), mk(PromptAccess::No));
    let resolved = resolve_tap_hooks(
        &hooks,
        &["ro-tap".to_string(), "no-tap".to_string()],
        &env,
        0,
        crate::config::HookStage::Request,
    );
    assert_eq!(resolved.len(), 2);
    // Both taps share priority 0; identify each by re-resolving individually to assert the flag.
    let ro = resolve_tap_hooks(
        &hooks,
        &["ro-tap".to_string()],
        &env,
        0,
        crate::config::HookStage::Request,
    );
    let no = resolve_tap_hooks(
        &hooks,
        &["no-tap".to_string()],
        &env,
        0,
        crate::config::HookStage::Request,
    );
    assert!(ro[0].1, "prompt:ro tap carries send_prompt = true");
    assert!(!no[0].1, "prompt:no tap carries send_prompt = false");
}

/// The `timeout_ms == 0` → default guard in `policy_timeout` (belt-and-suspenders for any
/// code-built `PolicyCfg` that slips a 0 through).
#[test]
fn policy_timeout_treats_zero_as_default() {
    assert_eq!(
        policy_timeout(0),
        std::time::Duration::from_millis(crate::config::DEFAULT_POLICY_TIMEOUT_MS),
        "0ms must be coerced to the documented default policy timeout, never 0"
    );
    assert_eq!(
        policy_timeout(42),
        std::time::Duration::from_millis(42),
        "a non-zero timeout must be honored verbatim"
    );
}

#[test]
fn from_ranked_empty_is_abstain() {
    let valid: HashSet<usize> = [0usize].into_iter().collect();
    assert_eq!(
        RoutingDecision::from_ranked([7usize, 8], &valid),
        RoutingDecision::Abstain,
        "all-unknown ranked list collapses to Abstain"
    );
    assert_eq!(
        RoutingDecision::from_ranked(std::iter::empty(), &valid),
        RoutingDecision::Abstain,
    );
}

/// A native `policy:` FORCES the payload projections off at resolve (no native policy reads them).
/// Requires the `hooks-ranking` plugin (a native non-weighted policy exists only when compiled in).
#[cfg(feature = "hooks-ranking")]
#[test]
fn native_resolve_forces_opt_in_flags_off() {
    match resolve_policy(&pool_policy(PoolPolicy::Cheapest)) {
        Some(ResolvedPolicy::Policy {
            send_prompt,
            send_user,
            ..
        }) => {
            assert!(!send_prompt, "native must force send_prompt off");
            assert!(!send_user, "native must force send_user off");
        }
        None => panic!("native pool must resolve to a policy"),
    }
}

/// A gate hook's `prompt: ro` / `user: ro` grants PASS THROUGH to the resolved policy as
/// send_prompt / send_user — the mirror image of the native force-off: an accidental hardcoded
/// `false` would silently strip content from every opted-in hook. (The plugin manifest here declares
/// the matching intent, so BOTH agree and the projection is on.)
#[test]
fn gate_grants_pass_through_as_projection_flags() {
    let Some(env) = test_env() else {
        eprintln!("skip: hook cdylib not built (run under --workspace)");
        return;
    };
    let hooks = registry(
        "h",
        HookCfg {
            prompt: PromptAccess::Ro,
            user: UserAccess::Ro,
            ..base_gate()
        },
    );
    match resolve_pool_gates(&pool_with_hook("h"), &hooks, &env, 0)
        .into_iter()
        .next()
    {
        Some((
            _,
            ResolvedPolicy::Policy {
                send_prompt,
                send_user,
                ..
            },
        )) => {
            assert!(
                send_prompt,
                "prompt:ro grant + manifest need must pass send_prompt through"
            );
            assert!(
                send_user,
                "user:ro grant + manifest need must pass send_user through"
            );
        }
        None => panic!("gate must resolve to a policy"),
    }
}

/// THE MANIFEST-INTENT × OPERATOR-GRANT PROJECTION MATRIX (the belt-and-suspenders rule): the core
/// projects prompt/user content ONLY when BOTH the operator grants it AND the signed manifest
/// declares the need. A grant above the declared need is a no-op; a manifest need above the grant is
/// a no-op. Prompt content flows only when both are ≥ read; rewrite-power (rw) requires both rw.
#[test]
fn manifest_intent_and_grant_projection_matrix() {
    use busbar_plugin_sign::NeedLevel;
    // (manifest prompt need, operator prompt grant) -> expected send_prompt
    let prompt_cases = [
        (NeedLevel::No, PromptAccess::No, false),
        (NeedLevel::No, PromptAccess::Ro, false), // grant above declared need = no-op
        (NeedLevel::No, PromptAccess::Rw, false),
        (NeedLevel::Ro, PromptAccess::No, false), // declared above grant = no-op
        (NeedLevel::Ro, PromptAccess::Ro, true),
        (NeedLevel::Ro, PromptAccess::Rw, true), // both ≥ read → content flows
        (NeedLevel::Rw, PromptAccess::No, false),
        (NeedLevel::Rw, PromptAccess::Ro, true),
        (NeedLevel::Rw, PromptAccess::Rw, true),
    ];
    for (idx, (need, grant, want_prompt)) in prompt_cases.into_iter().enumerate() {
        let alias = format!("mtx-{idx}");
        let Some(env) = test_env_needs(
            &alias,
            busbar_plugin_sign::HookNeeds {
                prompt: need,
                user: NeedLevel::No,
            },
        ) else {
            eprintln!("skip: hook cdylib not built (run under --workspace)");
            return;
        };
        let hooks = registry(
            "h",
            HookCfg {
                plugin: alias.clone(),
                prompt: grant,
                ..base_gate()
            },
        );
        let Some(ResolvedPolicy::Policy { send_prompt, .. }) =
            resolve_gate_transport("h", &hooks["h"], &hooks, &env, 0)
        else {
            panic!("gate must resolve for case {idx}");
        };
        assert_eq!(
            send_prompt, want_prompt,
            "case {idx}: manifest {need:?} × grant {grant:?} → send_prompt {want_prompt}"
        );
    }

    // The user axis: send_user only when BOTH manifest declares (ro) AND operator grants (ro).
    let user_cases = [
        (NeedLevel::No, UserAccess::No, false),
        (NeedLevel::No, UserAccess::Ro, false),
        (NeedLevel::Ro, UserAccess::No, false),
        (NeedLevel::Ro, UserAccess::Ro, true),
    ];
    for (idx, (need, grant, want_user)) in user_cases.into_iter().enumerate() {
        let alias = format!("mtx-user-{idx}");
        let Some(env) = test_env_needs(
            &alias,
            busbar_plugin_sign::HookNeeds {
                prompt: NeedLevel::No,
                user: need,
            },
        ) else {
            return;
        };
        let hooks = registry(
            "h",
            HookCfg {
                plugin: alias.clone(),
                user: grant,
                ..base_gate()
            },
        );
        let Some(ResolvedPolicy::Policy { send_user, .. }) =
            resolve_gate_transport("h", &hooks["h"], &hooks, &env, 0)
        else {
            panic!("gate must resolve for user case {idx}");
        };
        assert_eq!(
            send_user, want_user,
            "user case {idx}: manifest {need:?} × grant {grant:?} → send_user {want_user}"
        );
    }
}

/// LOCKS the invariant behind `forward`'s `unreachable!("from_ranked never rejects")` arm:
/// `from_ranked` is a pure order-normalizer and must only ever produce Prefer/Abstain. If a
/// future change makes it emit Reject, that unreachable arm panics on a live request — this
/// test is the tripwire that fails FIRST.
#[test]
fn from_ranked_never_produces_reject() {
    let valid: HashSet<usize> = [0usize, 1, 2].into_iter().collect();
    for ranked in [
        vec![0usize, 1, 2],
        vec![2, 2, 2],
        vec![9, 8, 7],
        vec![],
        vec![1],
        vec![0, 9, 1, 0, 2, 2],
    ] {
        let d = RoutingDecision::from_ranked(ranked.clone(), &valid);
        assert!(
            !matches!(d, RoutingDecision::Reject { .. }),
            "from_ranked({ranked:?}) must never yield Reject"
        );
    }
}

/// The opt-in projections REDACT their content in Debug: a stray `{{:?}}` debug log on the
/// routing path must never fan operator-opted-in prompt text or end-user PII into the log
/// stream (the VirtualKey key-hash precedent).
#[test]
fn opt_in_projections_redact_debug() {
    let p = PromptProjection {
        system: Some("SECRET-SYSTEM-PROMPT".into()),
        messages: vec![("user".into(), "SECRET-MESSAGE-TEXT".into())],
    };
    let dbg = format!("{p:?}");
    assert!(
        !dbg.contains("SECRET-SYSTEM-PROMPT"),
        "leaked system: {dbg}"
    );
    assert!(
        !dbg.contains("SECRET-MESSAGE-TEXT"),
        "leaked message: {dbg}"
    );

    let i = CallerIdentity {
        key_id: Some("k-1".into()),
        key_name: Some("sales-team".into()),
        user: Some("alice@example.com".into()),
    };
    let dbg = format!("{i:?}");
    assert!(
        !dbg.contains("alice@example.com"),
        "leaked end-user id: {dbg}"
    );
    // The operator-facing key labels stay visible — they are the operator's own config values,
    // and losing them would make the struct undiagnosable.
    assert!(dbg.contains("sales-team"));
}

// ── DlopenPolicy behavior over the REAL projectors (ported socket/webhook transport coverage) ──────
// These drive a LOADED test-hook plugin through the resolved `DlopenPolicy` using the engine's REAL
// `hooks::plugin::projectors()` (the wire.rs fail-closed parsers), porting the retired socket/webhook
// transport tests (reject-precedence, order, abstain, rewrite, notify delivery) onto the dlopen seam.

/// Resolve the single gate `h` from a one-hook registry backed by the test-hook plugin (settings
/// carry the plugin's behavior config), returning the constructed `Arc<dyn RoutingPolicy>`.
fn resolve_one(env: &HookEnv, settings: serde_json::Value) -> Option<Arc<dyn RoutingPolicy>> {
    let mut hook = base_gate();
    hook.prompt = PromptAccess::Ro; // so the opt-in prompt projection is sent (matches manifest rw need)
    hook.settings = settings.as_object().cloned().unwrap_or_default();
    let hooks = registry("h", hook);
    match resolve_gate_transport("h", &hooks["h"], &hooks, env, 0)? {
        ResolvedPolicy::Policy { policy, .. } => Some(policy),
    }
}

fn dreq(text: &str) -> RoutingRequest<'static> {
    RoutingRequest {
        request_id: 1,
        pool: "p",
        ingress_protocol: "anthropic",
        requested_model: None,
        message_count: 1,
        tool_count: 0,
        has_tools: false,
        total_chars: text.len(),
        system_chars: 0,
        max_tokens: None,
        stream: false,
        prompt: Some(PromptProjection {
            system: None,
            messages: vec![("user".into(), text.to_string().into())],
        }),
        identity: None,
        signals: Default::default(),
    }
}

fn dcand(idx: usize) -> Candidate<'static> {
    Candidate {
        idx,
        model: "m",
        provider: "prov",
        weight: 1,
        context_max: None,
        tier: None,
        cost_per_mtok: None,
        tags: &[],
        latency_ms: None,
        available_concurrency: 1,
        budget_remaining: None,
        rate_headroom: None,
        signals: Default::default(),
    }
}

fn dctx() -> RoutingContext<'static> {
    RoutingContext {
        pool: "p",
        budget_remaining: None,
        budget: &[],
    }
}

/// `decide` over the dlopen seam: the plugin's configured order is echoed and normalized by the REAL
/// `wire::normalize` (unknown idxs dropped); an empty order abstains.
#[tokio::test]
async fn dlopen_decide_order_and_abstain() {
    let _dlopen_body = DLOPEN_BODY_LOCK.lock().await;
    let Some(env) = test_env() else {
        eprintln!("skip: hook cdylib not built (run under --workspace)");
        return;
    };
    let budget = std::time::Duration::from_secs(5);
    let cands = [dcand(0), dcand(1)];

    let policy = resolve_one(&env, serde_json::json!({"order": [9, 1, 0]})).expect("resolve");
    let d = policy
        .decide(&dreq("hi"), &cands, &dctx(), budget)
        .await
        .expect("decide");
    assert_eq!(
        d,
        RoutingDecision::Prefer(vec![1, 0]),
        "unknown idx 9 dropped by the real normalizer"
    );

    let policy = resolve_one(&env, serde_json::json!({})).expect("resolve");
    let d = policy
        .decide(&dreq("hi"), &cands, &dctx(), budget)
        .await
        .expect("decide");
    assert_eq!(d, RoutingDecision::Abstain);
}

/// `decide` REJECT over the dlopen seam: the opt-in prompt projection reaches the in-process gate
/// (proving content delivery under the grant + manifest need), and the plugin's `{"reject":{...}}`
/// surfaces as a `RoutingDecision::Reject` through the REAL fail-closed normalizer (status/message).
#[tokio::test]
async fn dlopen_decide_reject_from_opt_in_prompt() {
    let _dlopen_body = DLOPEN_BODY_LOCK.lock().await;
    let Some(env) = test_env() else {
        eprintln!("skip: hook cdylib not built (run under --workspace)");
        return;
    };
    let budget = std::time::Duration::from_secs(5);
    let cands = [dcand(0)];
    let policy = resolve_one(
        &env,
        serde_json::json!({"order": [0], "reject_if_contains": "BLOCKME"}),
    )
    .expect("resolve");

    // Prompt WITHOUT the token → the gate ranks (no reject).
    let d = policy
        .decide(&dreq("clean prompt"), &cands, &dctx(), budget)
        .await
        .expect("decide");
    assert_eq!(d, RoutingDecision::Prefer(vec![0]));

    // Prompt WITH the token → the gate rejects (content reached it over the ABI).
    let d = policy
        .decide(&dreq("please BLOCKME"), &cands, &dctx(), budget)
        .await
        .expect("decide");
    assert_eq!(
        d,
        RoutingDecision::Reject {
            status: 403,
            message: "blocked by test gate".to_string()
        }
    );
}

/// `transform` over the dlopen seam: the plugin rewrites the body (a rw gate), and rejects on the
/// screen token — reject > rewrite precedence, through the REAL `wire::transform_outcome`.
#[tokio::test]
async fn dlopen_transform_rewrite_and_reject() {
    let _dlopen_body = DLOPEN_BODY_LOCK.lock().await;
    use busbar_api::TransformOutcome;
    let Some(env) = test_env() else {
        eprintln!("skip: hook cdylib not built (run under --workspace)");
        return;
    };
    let budget = std::time::Duration::from_secs(5);
    let policy =
        resolve_one(&env, serde_json::json!({"reject_if_contains": "BLOCKME"})).expect("resolve");

    match policy.transform(&dreq("hello"), budget).await {
        TransformOutcome::Rewrite(rw) => assert_eq!(rw.messages.len(), 1),
        other => panic!("expected Rewrite, got {other:?}"),
    }
    match policy.transform(&dreq("BLOCKME"), budget).await {
        TransformOutcome::Reject { status, .. } => assert_eq!(status, 451),
        other => panic!("expected Reject, got {other:?}"),
    }
}

/// A `notify` tap over the dlopen seam is fire-and-forget AND actually DISPATCHED: a well-formed
/// projection reaches the plugin's `notify`, a malformed one is swallowed BEFORE the ABI call, and
/// neither errors or tears down the seam.
///
/// The dispatch is observed through the plugin's own `test_notifies_total` counter, read back over
/// `status`. Without that observation this test asserted nothing at all — `notify` returns `()`, so
/// a seam stubbed to a no-op would have passed it just as happily as the real one.
#[tokio::test]
async fn dlopen_notify_is_fire_and_forget() {
    let _dlopen_body = DLOPEN_BODY_LOCK.lock().await;
    let Some(env) = test_env() else {
        eprintln!("skip: hook cdylib not built (run under --workspace)");
        return;
    };
    let budget = std::time::Duration::from_secs(5);
    let policy = resolve_one(&env, serde_json::json!({})).expect("resolve");
    /// The plugin's tap counter, read over the SAME handle the notifies went to.
    async fn taps(policy: &Arc<dyn RoutingPolicy>) -> f64 {
        let status = policy
            .status(std::time::Duration::from_secs(5))
            .await
            .expect("status");
        let metrics = status.metrics.expect("metrics");
        let tap = metrics
            .iter()
            .find(|m| m["name"] == "test_notifies_total")
            .expect("test_notifies_total metric");
        tap["value"].as_f64().expect("counter value")
    }

    assert_eq!(taps(&policy).await, 0.0, "no tap dispatched yet");
    let projection = serde_json::to_vec(&serde_json::json!({"request": {"pool": "p"}})).unwrap();
    policy.notify(&projection, budget).await;
    assert_eq!(
        taps(&policy).await,
        1.0,
        "a well-formed tap projection must actually reach the plugin's `notify` over the ABI"
    );

    // A MALFORMED projection is swallowed at the engine boundary: no panic, no error (the call
    // returns `()` either way) and — the part that is observable — no ABI dispatch at all.
    policy.notify(b"not json", budget).await;
    assert_eq!(
        taps(&policy).await,
        1.0,
        "a malformed tap projection must be swallowed BEFORE the ABI call, not forwarded"
    );

    // The seam is still live and correct after both taps — a fire-and-forget call must never
    // poison or close the handle it rode.
    match policy.transform(&dreq("hello"), budget).await {
        busbar_api::TransformOutcome::Rewrite(rw) => assert_eq!(rw.messages.len(), 1),
        other => panic!("seam unusable after notify: expected Rewrite, got {other:?}"),
    }
}

/// `status` + `describe` over the dlopen seam: the plugin reports a metric (via `fetch_status`) and a
/// schema envelope (via `fetch_schema`, single-nest extracted), using the REAL projectors.
#[tokio::test]
async fn dlopen_status_and_schema_reads() {
    let _dlopen_body = DLOPEN_BODY_LOCK.lock().await;
    let Some(env) = test_env() else {
        eprintln!("skip: hook cdylib not built (run under --workspace)");
        return;
    };
    let hook = {
        let mut h = base_gate();
        h.settings = serde_json::json!({"order": [0]})
            .as_object()
            .cloned()
            .unwrap();
        h
    };
    // Drive a decide first so the plugin's decide counter is non-zero, then read status.
    let hooks = registry("h", hook.clone());
    let ResolvedPolicy::Policy { policy, .. } =
        resolve_gate_transport("h", &hooks["h"], &hooks, &env, 0).expect("resolve");
    let _ = policy
        .decide(
            &dreq("x"),
            &[dcand(0)],
            &dctx(),
            std::time::Duration::from_secs(5),
        )
        .await;

    let status = fetch_status("h", &hook, 0, &env).await.expect("status");
    let metrics = status.metrics.expect("metrics");
    assert_eq!(metrics[0]["name"], "test_decides_total");

    let schema = fetch_schema("h", &hook, 0, &env).await.expect("schema");
    // fetch_schema returns the schema member ALREADY EXTRACTED (single nest).
    assert_eq!(schema["type"], "object");
}

/// `configure` push over the dlopen seam: the test-hook plugin acks the EXACT pushed version → Ok.
/// (A wrong-version ack rejecting the commit is covered at the DlopenPolicy configure unit level.)
#[tokio::test]
async fn dlopen_configure_acks_exact_version() {
    let _dlopen_body = DLOPEN_BODY_LOCK.lock().await;
    let Some(env) = test_env() else {
        eprintln!("skip: hook cdylib not built (run under --workspace)");
        return;
    };
    let hook = base_gate();
    push_configure(&hook, "h", 7, &env)
        .await
        .expect("the plugin acks the pushed version");
}

/// The on_error CHAIN fires through LOADED plugins: gate `a` (on_error → gate `b`) resolves a
/// one-link fallback chain whose link is a live `DlopenPolicy` (name `b`), bottoming out on `b`'s
/// `reject` terminal. Ported from the socket on_error-chain test onto the dlopen seam.
#[tokio::test]
async fn dlopen_on_error_chain_link_is_live_plugin() {
    let _dlopen_body = DLOPEN_BODY_LOCK.lock().await;
    let Some(env) = test_env() else {
        eprintln!("skip: hook cdylib not built (run under --workspace)");
        return;
    };
    let mut a = base_gate();
    a.on_error = "b".to_string();
    let mut b = base_gate();
    b.on_error = "reject".to_string();
    let mut hooks = registry("a", a);
    hooks.insert("b".to_string(), b);
    let ResolvedPolicy::Policy {
        on_error,
        on_error_chain,
        ..
    } = resolve_gate_transport("a", &hooks["a"], &hooks, &env, 0).expect("gate a resolves");
    assert_eq!(on_error_chain.len(), 1);
    assert_eq!(
        on_error_chain[0].policy.name(),
        "b",
        "the fallback link is a live DlopenPolicy"
    );
    assert_eq!(on_error, PolicyOnError::Reject);
    // And the live fallback link actually decides over the ABI.
    let cands = [dcand(0)];
    let d = on_error_chain[0]
        .policy
        .decide(
            &dreq("x"),
            &cands,
            &dctx(),
            std::time::Duration::from_secs(5),
        )
        .await
        .expect("the fallback link decides");
    assert!(matches!(
        d,
        RoutingDecision::Abstain | RoutingDecision::Prefer(_)
    ));
}

/// A `prompt: no` gate (default) sends NO prompt content even though the plugin declares an rw need:
/// the belt-and-suspenders rule requires BOTH — the operator grant of `no` wins. So the gate cannot
/// reject on prompt content it never received.
#[tokio::test]
async fn dlopen_prompt_no_grant_withholds_content() {
    let _dlopen_body = DLOPEN_BODY_LOCK.lock().await;
    let Some(env) = test_env() else {
        eprintln!("skip: hook cdylib not built (run under --workspace)");
        return;
    };
    // A gate with the DEFAULT prompt: no grant, but a plugin that WOULD reject on the token.
    let mut hook = base_gate(); // prompt defaults to No
    hook.settings = serde_json::json!({"order": [0], "reject_if_contains": "BLOCKME"})
        .as_object()
        .cloned()
        .unwrap();
    let hooks = registry("h", hook);
    let ResolvedPolicy::Policy {
        policy,
        send_prompt,
        ..
    } = resolve_gate_transport("h", &hooks["h"], &hooks, &env, 0).expect("resolve");
    assert!(
        !send_prompt,
        "prompt:no grant → no content projected, regardless of manifest intent"
    );
    // The prompt carries the token, but with send_prompt=false the CORE would not project it. Here we
    // simulate the firing site: a `prompt: no` gate gets a request with NO prompt projection.
    let mut req = dreq("please BLOCKME");
    req.prompt = None; // the core withholds content for a no-grant hook
    let d = policy
        .decide(
            &req,
            &[dcand(0)],
            &dctx(),
            std::time::Duration::from_secs(5),
        )
        .await
        .expect("decide");
    assert_eq!(
        d,
        RoutingDecision::Prefer(vec![0]),
        "no content reached the gate → it ranks, never rejects"
    );
}

/// REJECT-STATUS CLAMP over the dlopen seam (ported from the socket reject-status test): a hook may
/// only speak client errors. Whatever status the plugin returns, the REAL `wire::normalize` clamps
/// anything outside 400..=499 to 403 — a hook cannot mint a success/redirect/5xx through the ABI.
#[tokio::test]
async fn dlopen_decide_reject_status_is_clamped() {
    let _dlopen_body = DLOPEN_BODY_LOCK.lock().await;
    let Some(env) = test_env() else {
        eprintln!("skip: hook cdylib not built (run under --workspace)");
        return;
    };
    let budget = std::time::Duration::from_secs(5);
    let cands = [dcand(0)];
    for (sent, want) in [
        (400, 400),
        (451, 451),
        (499, 499),
        (200, 403),
        (302, 403),
        (500, 403),
        (0, 403),
        (70000, 403),
    ] {
        let policy = resolve_one(
            &env,
            serde_json::json!({"reject_if_contains": "X", "reject_status": sent}),
        )
        .expect("resolve");
        match policy
            .decide(&dreq("X please"), &cands, &dctx(), budget)
            .await
            .expect("decide")
        {
            RoutingDecision::Reject { status, .. } => {
                assert_eq!(status, want, "sent {sent} must clamp to {want}")
            }
            other => panic!("expected Reject for sent {sent}, got {other:?}"),
        }
    }
}

/// RESTRICT over the dlopen seam (ported from the socket restrict coverage): a compliance gate's
/// `{"restrict":{"tags_any":[...]}}` reply surfaces as a `RoutingDecision::Restrict` through the REAL
/// `wire::normalize` — restrict wins over `order`, and a malformed/empty restrict is fail-closed to an
/// EMPTY tag set (resolved downstream by `on_empty`, never allow-all).
#[tokio::test]
async fn dlopen_decide_restrict_and_fail_closed() {
    let _dlopen_body = DLOPEN_BODY_LOCK.lock().await;
    let Some(env) = test_env() else {
        eprintln!("skip: hook cdylib not built (run under --workspace)");
        return;
    };
    let budget = std::time::Duration::from_secs(5);
    let cands = [dcand(0), dcand(1)];

    // Well-formed restrict → Restrict{tags_any}; restrict wins even though `order` is also set.
    let policy = resolve_one(
        &env,
        serde_json::json!({"order": [1, 0], "restrict_tags": ["baa"]}),
    )
    .expect("resolve");
    match policy
        .decide(&dreq("x"), &cands, &dctx(), budget)
        .await
        .expect("decide")
    {
        RoutingDecision::Restrict { tags_any } => assert_eq!(tags_any, vec!["baa".to_string()]),
        other => panic!("expected Restrict, got {other:?}"),
    }

    // A malformed restrict (empty tags) is fail-closed to an EMPTY tag set — never allow-all/order.
    let policy = resolve_one(
        &env,
        serde_json::json!({"raw_decide_reply": {"restrict": {"tags_any": []}}}),
    )
    .expect("resolve");
    match policy
        .decide(&dreq("x"), &cands, &dctx(), budget)
        .await
        .expect("decide")
    {
        RoutingDecision::Restrict { tags_any } => assert!(
            tags_any.is_empty(),
            "malformed restrict stays Restrict (fail-closed → on_empty), got {tags_any:?}"
        ),
        other => panic!("malformed restrict must stay Restrict, got {other:?}"),
    }
}

/// FAIL-CLOSED reply parsing over the dlopen seam (ported from the socket malformed-reply coverage):
/// the REAL `wire::normalize` degrades a mis-typed `reject` detail to a full-strength 403 rejection
/// (never a silent route), while a non-verb reply object abstains — a hook that tried to stop a
/// request can never have it routed because a detail was malformed.
#[tokio::test]
async fn dlopen_decide_raw_reply_is_fail_closed() {
    let _dlopen_body = DLOPEN_BODY_LOCK.lock().await;
    let Some(env) = test_env() else {
        eprintln!("skip: hook cdylib not built (run under --workspace)");
        return;
    };
    let budget = std::time::Duration::from_secs(5);
    let cands = [dcand(0)];

    // A `reject` with a bogus (string) status degrades to the default 403 — still a rejection.
    let policy = resolve_one(
        &env,
        serde_json::json!({"raw_decide_reply": {"reject": {"status": "451"}}}),
    )
    .expect("resolve");
    match policy
        .decide(&dreq("x"), &cands, &dctx(), budget)
        .await
        .expect("decide")
    {
        RoutingDecision::Reject { status, .. } => assert_eq!(status, 403),
        other => panic!("malformed reject must stay a 403 Reject, got {other:?}"),
    }

    // A non-verb reply object → Abstain (no opinion), never an error.
    let policy = resolve_one(
        &env,
        serde_json::json!({"raw_decide_reply": {"unknown_field": true}}),
    )
    .expect("resolve");
    assert_eq!(
        policy
            .decide(&dreq("x"), &cands, &dctx(), budget)
            .await
            .expect("decide"),
        RoutingDecision::Abstain
    );

    // `reject: false` is the explicit opt-out — defers to `order`.
    let policy = resolve_one(
        &env,
        serde_json::json!({"raw_decide_reply": {"reject": false, "order": [0]}}),
    )
    .expect("resolve");
    assert_eq!(
        policy
            .decide(&dreq("x"), &cands, &dctx(), budget)
            .await
            .expect("decide"),
        RoutingDecision::Prefer(vec![0])
    );
}

/// The USER-identity opt-in projection rides the dlopen seam when BOTH the grant and manifest agree:
/// a `user: ro` gate (manifest declares the user need) gets the caller identity in the projection.
/// This is the identity analogue of the prompt opt-in delivery test.
#[tokio::test]
async fn dlopen_user_identity_projection_rides_the_wire() {
    let _dlopen_body = DLOPEN_BODY_LOCK.lock().await;
    use busbar_plugin_sign::{HookNeeds, NeedLevel};
    let Some(env) = test_env_needs(
        "user-hook",
        HookNeeds {
            prompt: NeedLevel::No,
            user: NeedLevel::Ro,
        },
    ) else {
        eprintln!("skip: hook cdylib not built (run under --workspace)");
        return;
    };
    let hooks = registry(
        "h",
        HookCfg {
            plugin: "user-hook".to_string(),
            user: UserAccess::Ro,
            ..base_gate()
        },
    );
    let Some(ResolvedPolicy::Policy {
        send_user,
        send_prompt,
        ..
    }) = resolve_gate_transport("h", &hooks["h"], &hooks, &env, 0)
    else {
        panic!("gate must resolve");
    };
    assert!(send_user, "user:ro grant + manifest user need → send_user");
    assert!(
        !send_prompt,
        "no prompt grant/need → prompt content stays withheld"
    );
}

/// A SLOW gate is cut off by the wall-clock `budget` over the dlopen seam (ported from the socket
/// silent-hook timeout test): a decide that overruns the deadline surfaces as `Err` (→ the caller's
/// `on_error`), promptly — never a hang. The blocking call runs on `spawn_blocking`, so a sleeping
/// plugin never stalls the runtime.
#[tokio::test]
async fn dlopen_decide_deadline_cuts_off_a_slow_gate() {
    let _dlopen_body = DLOPEN_BODY_LOCK.lock().await;
    let Some(env) = test_env() else {
        eprintln!("skip: hook cdylib not built (run under --workspace)");
        return;
    };
    let policy =
        resolve_one(&env, serde_json::json!({"order": [0], "sleep_ms": 2000})).expect("resolve");
    let started = std::time::Instant::now();
    let r = policy
        .decide(
            &dreq("x"),
            &[dcand(0)],
            &dctx(),
            std::time::Duration::from_millis(100),
        )
        .await;
    assert!(r.is_err(), "a slow gate must exceed the deadline → Err");
    assert!(
        started.elapsed() < std::time::Duration::from_secs(1),
        "the deadline must cut the exchange off promptly, not wait out the sleep"
    );
}

/// FAIL-OPEN management reads over the dlopen seam (ported from the socket status/describe
/// "unsupported" coverage): a hook that replies `{}` to `status`/`describe` is treated as
/// "doesn't speak it" — `fetch_status`/`fetch_schema` return `None`, never affecting a request.
#[tokio::test]
async fn dlopen_empty_management_reads_are_fail_open_none() {
    let _dlopen_body = DLOPEN_BODY_LOCK.lock().await;
    let Some(env) = test_env() else {
        eprintln!("skip: hook cdylib not built (run under --workspace)");
        return;
    };
    let mut hook = base_gate();
    hook.settings = serde_json::json!({"empty_management": true})
        .as_object()
        .cloned()
        .unwrap();
    assert!(
        fetch_status("h", &hook, 0, &env).await.is_none(),
        "an empty status reply is fail-open None"
    );
    assert!(
        fetch_schema("h", &hook, 0, &env).await.is_none(),
        "an empty describe reply is fail-open None"
    );
}

/// A NACK'd `configure` push over the dlopen seam does NOT commit (ported from the socket
/// wrong-version-ack coverage): the plugin refuses to ack, so `push_configure` returns `Err` and the
/// settings PATCH would not commit — the exact-version ack rule holds over the ABI.
#[tokio::test]
async fn dlopen_configure_nack_does_not_commit() {
    let _dlopen_body = DLOPEN_BODY_LOCK.lock().await;
    let Some(env) = test_env() else {
        eprintln!("skip: hook cdylib not built (run under --workspace)");
        return;
    };
    let mut hook = base_gate();
    hook.settings = serde_json::json!({"nack_configure": true})
        .as_object()
        .cloned()
        .unwrap();
    assert!(
        push_configure(&hook, "h", 7, &env).await.is_err(),
        "a hook that refuses to ack must fail the configure push (no commit)"
    );
}

// ── offload_bounded (bound the transport resolve, name a swallowed JoinError) ────────────────────

/// UNIT TEST of the new bound (NOT a red proof of the old unbounded `.await` — there is no fixture
/// that makes a real `dlopen`/constructor hang, so the "no timeout today" claim is established by
/// reading `gate_transport_offloaded`, not by a test). `spawn_blocking` runs the closure on a real OS
/// thread, which a paused tokio clock cannot accelerate (a live blocking thread never reports the
/// runtime "idle", so time auto-advance never fires) — so this drives the deadline-parameterized
/// core directly with a short REAL deadline instead, making the timeout arm deterministic and fast.
#[test]
fn offload_bounded_returns_none_when_the_work_outlives_the_deadline() {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    rt.block_on(async {
        let out: Option<()> = offload_bounded_with_deadline(
            "slow-hook",
            std::time::Duration::from_millis(20),
            || {
                std::thread::sleep(std::time::Duration::from_millis(500));
                Some(())
            },
        )
        .await;
        assert!(
            out.is_none(),
            "work that outlives the deadline must resolve to None, not block the caller forever"
        );
    });
}

/// UNIT TEST of the new bound's panic arm — but WRITABLE NOW, unlike the timeout arm: the closure
/// itself can panic without needing a real plugin. Pins the fix for the swallowed `JoinError`
/// a panicking blocking task must not unwind the caller, and must be named in a captured
/// warn distinctly from an ordinary "no resolvable transport" `None`.
#[test]
fn offload_bounded_logs_when_the_blocking_task_panics() {
    use crate::test_support::warn_capture::WarnCapture;
    use tracing_subscriber::layer::SubscriberExt as _;

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let cap = WarnCapture::default();
    let subscriber = tracing_subscriber::registry().with(cap.clone());

    let out: Option<()> = tracing::subscriber::with_default(subscriber, || {
        rt.block_on(offload_bounded("panicky-hook", || {
            panic!("plugin constructor blew up");
        }))
    });

    assert!(
        out.is_none(),
        "a panicking resolve must still resolve to None, not propagate the panic to the caller"
    );
    assert!(
        cap.contains("panicky-hook") && cap.contains("panicked"),
        "the panic must be logged, naming the hook and distinct from the ordinary unresolvable \
         case: {:?}",
        cap.messages()
    );
}

/// The settings-drift signal yields KEY NAMES ONLY, and is computed WITHOUT resolving a single
/// secret.
///
/// Three defects in one line of `GET /api/v1/admin/hooks/{name}/status`. It serialized
/// `reported.settings` verbatim — the hook's ECHO of the bag busbar pushed it, which
/// `configure_hook` resolves first, so that field carried the PLAINTEXT of every `SecretRef` at
/// READ-ONLY admin scope. It compared that resolved echo against the UNRESOLVED `hook.settings`, so
/// a `SecretRef` field could NEVER match and reported drift on every single poll, forever — a
/// permanent false positive on the one signal the endpoint exists to raise. And the fix for THAT
/// (resolving the desired bag per request) put blocking secret FFI on a polled async GET; a
/// `SecretRef` field is now skipped by SHAPE instead, with no resolution anywhere on the path.
#[test]
fn settings_drift_reports_only_key_names_and_never_resolves_a_secret() {
    let var = "BUSBAR_TEST_HOOK_DRIFT_SECRET";
    // The var name is unique to this test, so no sibling reads or clobbers it.
    std::env::set_var(var, "hunter2-resolved");
    let mut hook: HookCfg = serde_json::from_value(serde_json::json!({
        "kind": "gate",
        "plugin": "test-hook",
        "timeout_ms": 5,
        "on_error": "weighted"
    }))
    .unwrap();
    hook.settings = serde_json::json!({
        "api_token": { "env": var },
        "ratio": 0.4,
        // The `{ literal: … }` escape hatch is NOT a reference: the plugin receives the inner value,
        // so the read path must compare against the inner value too.
        "db": { "literal": { "file": "/var/lib/db" } }
    })
    .as_object()
    .unwrap()
    .clone();

    // The hook echoes back exactly what it was configured with — i.e. the RESOLVED secret.
    let in_sync = serde_json::json!({
        "api_token": "hunter2-resolved",
        "ratio": 0.4,
        "db": { "file": "/var/lib/db" }
    })
    .as_object()
    .unwrap()
    .clone();
    assert!(
        crate::hooks::settings_drift_keys(&hook, Some(&in_sync)).is_empty(),
        "a hook running EXACTLY the pushed settings is not drifting — comparing the resolved echo \
         against the unresolved `SecretRef` made every secret-bearing hook report drift forever"
    );

    // A hook running a stale ORDINARY value drifts — and the signal is the KEY NAME, never a value.
    let drifted = serde_json::json!({
        "api_token": "hunter2-resolved",
        "ratio": 0.9,
        "db": { "file": "/var/lib/db" },
        "self_managed": "not drift"
    })
    .as_object()
    .unwrap()
    .clone();
    let keys = crate::hooks::settings_drift_keys(&hook, Some(&drifted));
    assert_eq!(
        keys,
        vec!["ratio".to_string()],
        "drift is reported as DESIRED key names only (an extra self-managed key is not drift)"
    );
    assert!(
        !format!("{keys:?}").contains("hunter"),
        "no value from either bag may ride out on the drift signal: {keys:?}"
    );

    // A stale LITERAL-wrapped value drifts too: unwrapping is shape-only, no resolution involved.
    let literal_drift = serde_json::json!({
        "api_token": "hunter2-resolved",
        "ratio": 0.4,
        "db": { "file": "/somewhere/else" }
    })
    .as_object()
    .unwrap()
    .clone();
    assert_eq!(
        crate::hooks::settings_drift_keys(&hook, Some(&literal_drift)),
        vec!["db".to_string()],
        "`{{ literal: … }}` is ordinary data, compared against its INNER value"
    );

    // A hook that reports no settings at all is fail-open, not drift.
    assert!(crate::hooks::settings_drift_keys(&hook, None).is_empty());
}

/// `hook_status` is a POLLED async GET, so nothing it calls may resolve a secret.
/// The earlier drift check compared against the RESOLVED desired bag, which reaches
/// `SecretResolver::resolve` — a SYNCHRONOUS FFI call into a `kind: secret` plugin for any
/// non-built-in module — inline on a Tokio worker with no `spawn_blocking` and no cache, plus a
/// `tracing::info!` naming the setting and its reference on EVERY call. A dashboard polling every 5s
/// became a Vault round-trip every 5s, parking a worker for the plugin's full timeout when Vault is
/// slow.
///
/// The observable consequence of removing the resolution: a `SecretRef` field's desired value is no
/// longer knowable on the read path, so it is NOT COMPARED and never reports drift — whatever the
/// hook echoes back for it. Ordinary fields keep drifting normally (asserted above and here).
#[test]
fn settings_drift_never_compares_a_secret_ref_field() {
    let var = "BUSBAR_TEST_HOOK_DRIFT_NO_RESOLVE";
    std::env::set_var(var, "the-real-secret");
    let mut hook: HookCfg = serde_json::from_value(serde_json::json!({
        "kind": "gate",
        "plugin": "test-hook",
        "timeout_ms": 5,
        "on_error": "weighted"
    }))
    .unwrap();
    hook.settings = serde_json::json!({
        // A built-in `env` reference (resolvable), and a `kind: secret` PLUGIN reference — the arm
        // that is a blocking FFI call, and the one no read path may ever touch.
        "api_token": { "env": var },
        "licenseKey": { "module": "vault", "settings": { "path": "secret/busbar" } },
        "ratio": 0.4
    })
    .as_object()
    .unwrap()
    .clone();

    // Whatever the hook echoes for the two reference fields — the resolved plaintext, a STALE
    // plaintext, or nothing comparable at all — none of it is drift, because deciding would require
    // the resolution this path refuses to perform.
    for echoed in [
        serde_json::json!({ "api_token": "the-real-secret", "licenseKey": "lic-1", "ratio": 0.4 }),
        serde_json::json!({ "api_token": "a-stale-secret", "licenseKey": "lic-2", "ratio": 0.4 }),
    ] {
        let observed = echoed.as_object().unwrap().clone();
        assert!(
            crate::hooks::settings_drift_keys(&hook, Some(&observed)).is_empty(),
            "a SecretRef-valued field is never compared on the read path (and resolving it to \
             compare would be blocking FFI on a polled async GET): {observed:?}"
        );
    }

    // Drift detection still works for ordinary fields alongside them.
    let observed = serde_json::json!({
        "api_token": "the-real-secret",
        "licenseKey": "lic-1",
        "ratio": 0.9
    })
    .as_object()
    .unwrap()
    .clone();
    assert_eq!(
        crate::hooks::settings_drift_keys(&hook, Some(&observed)),
        vec!["ratio".to_string()],
        "an ordinary field still drifts — the fix must not blind the endpoint"
    );
}

// ── the BLOCKING-FFI class: a hook's SECRET resolution must not run on a reactor worker ──────────

/// A `HookEnv` whose secret resolver's PLUGIN arm blocks the calling thread for `park`. That arm is a
/// synchronous `transport_call` into a `kind: secret` plugin in production (`DynSecret::resolve` →
/// `RawPlugin::transport_call`), and behind it a Vault/AWS-SM round trip. Nothing here is async —
/// the ENGINE is responsible for keeping it off the reactor.
fn parking_secret_env(park: std::time::Duration) -> HookEnv {
    HookEnv::new(
        std::sync::Arc::new(busbar_plugin_loader::PluginRegistry::empty()),
        std::sync::Arc::new(crate::config::secret::SecretResolver::with_plugin(
            Box::new(move |_module: &str, _settings: &str| {
                std::thread::sleep(park);
                Ok(b"resolved".to_vec())
            }),
        )),
    )
}

/// A hook whose `settings:` carry a SecretRef pointing at a NON-built-in module, i.e. one that must
/// be resolved by a `kind: secret` PLUGIN — the shape `classify_setting` reports as
/// `SettingShape::Reference` and `resolve_settings` therefore resolves over FFI.
fn hook_with_plugin_secret() -> HookCfg {
    let mut hook = base_gate();
    hook.settings.insert(
        "licenseKey".to_string(),
        serde_json::json!({ "module": "vault", "settings": { "path": "kv/busbar" } }),
    );
    hook
}

/// See `auth::token::token_tests::assert_runtime_still_polls` for why this waits on WALL CLOCK and
/// never on a Tokio timer: when every worker is parked in FFI the time driver is parked too, so a
/// `tokio::time::timeout` does not fire — it returns late and its assertion passes against a runtime
/// that was dead for the whole window.
fn assert_runtime_still_polls(
    rt: &tokio::runtime::Runtime,
    budget: std::time::Duration,
    msg: &str,
) {
    let canary = rt.spawn(async {});
    let deadline = std::time::Instant::now() + budget;
    while std::time::Instant::now() < deadline {
        if canary.is_finished() {
            return;
        }
        std::thread::sleep(std::time::Duration::from_millis(5));
    }
    panic!("{msg}");
}

/// `PATCH /api/v1/admin/hooks/{name}/settings` → `push_configure`, an `async fn`. It resolved the
/// hook's SecretRef settings INLINE — one line above the `gate_transport_offloaded` call that exists
/// to keep exactly this work off the reactor — and did so UNTIMED: `CONFIGURE_TIMEOUT_MS` bounds only
/// the `configure` call that follows. Concurrent admin pushes must not stop the runtime polling.
#[test]
fn concurrent_push_configure_does_not_starve_the_runtime() {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .expect("test runtime");
    let env = parking_secret_env(std::time::Duration::from_secs(3));
    let hook = hook_with_plugin_secret();
    let tasks: Vec<_> = (0..4)
        .map(|_| {
            let (h, e) = (hook.clone(), env.clone());
            rt.spawn(
                async move { crate::hooks::push_configure(&h, "compliance-gate", 1, &e).await },
            )
        })
        .collect();
    std::thread::sleep(std::time::Duration::from_millis(200));
    assert_runtime_still_polls(
        &rt,
        std::time::Duration::from_millis(750),
        "the runtime stopped polling while four hook settings pushes sat inside the `kind: secret` \
         plugin's synchronous resolve: every Tokio worker is parked in FFI",
    );
    for t in tasks {
        // Every push still FAILS (the registry is empty, so there is no transport) — the point is
        // that the failure arrives without the reactor having stopped.
        assert!(rt.block_on(async { t.await.expect("task") }).is_err());
    }
}
