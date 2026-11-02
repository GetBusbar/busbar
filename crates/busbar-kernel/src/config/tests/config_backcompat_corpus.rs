// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! CONFIG BACK-COMPAT CORPUS GATE — the resolved BILLING/LIMITS surface is byte-stable.
//!
//! WHAT THIS GUARDS. An operator's `config.yaml` says what their deployment charges and caps:
//! the per-token `rate_card`, the per-model and global token defaults, the `reasoning_effort_budgets`
//! ladder, the flat `per_request_fee`, and the `groups:` limit tree (every `tokens_*`/`budget`/
//! `requests`/`concurrent` cap, its window, its pool scope, its downgrade rule). `config::resolve`
//! lowers that YAML into the effective settings the cost model and governance actually enforce. This
//! gate SNAPSHOTS that resolved surface for a corpus of representative 1.5.x-style configs and pins
//! each snapshot to a blessed golden.
//!
//! WHY IT EXISTS NOW. 1.6.0's M3 config-noun eviction moves the PARSING of `rate_card` / `models` /
//! `limits` out of busbar-core and into the plane crate that owns them. The whole promise of that move is that it changes
//! WHERE the config is parsed, not WHAT an operator's YAML resolves to. This baseline — blessed from
//! the CURRENT behavior — is that promise written down: after the eviction, every golden here
//! must still be byte-identical. A refactor that quietly drops a cache tier, reorders a group's
//! limits, flips a default, or rounds a rate turns this RED before it can ship.
//!
//! WHAT THE SNAPSHOT CAPTURES, and what it deliberately does NOT. It renders ONLY the billing/limits
//! projection of the resolved `RootCfg`, in a stable, sorted, timestamp-free text form:
//!   * `per_request_fee`,
//!   * `limits.default_max_tokens` and the four `reasoning_effort_budgets` rungs,
//!   * `rate_card` — every model's four per-token tiers (a `BTreeMap`, already ordered),
//!   * `models.*` — the resolved per-model caps (`default_max_tokens`, `max_requests`, `max_concurrent`),
//!   * `groups.*` — each group's `enabled`/`parent` and its ordered limits (metric, amount, window,
//!     pool scope, on-exhaust behavior, downgrade target) plus any `child_default` template.
//!
//! It does NOT capture listen addresses, auth, providers, TLS, or anything else — narrowing the
//! snapshot to the money surface is what makes a RED here MEAN "billing/limits resolution changed"
//! rather than "some unrelated field moved".
//!
//! ADDING A CORPUS MEMBER. Drop a `*.yaml` in `tests/backcompat-corpus/`; the test discovers it.
//! Bless its golden with `BLESS_BACKCOMPAT_CORPUS=1 cargo test -p busbar-core config_backcompat`.
//! Bless ONLY when the change to the resolved output is intended and reviewed — an unexplained
//! re-bless is the exact regression this gate is here to stop.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use super::{resolve, DeployCfg, ProviderDef};

fn corpus_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("src/config/tests/backcompat-corpus")
}

fn corpus_configs() -> Vec<PathBuf> {
    let mut v: Vec<PathBuf> = std::fs::read_dir(corpus_dir())
        .expect("read the back-compat corpus directory")
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| p.extension().is_some_and(|x| x == "yaml" || x == "yml"))
        .collect();
    v.sort();
    v
}

fn defs_for(deploy: &DeployCfg) -> HashMap<String, ProviderDef> {
    deploy
        .providers
        .keys()
        .map(|name| {
            let def: ProviderDef = serde_yaml::from_str(
                "{ protocol: proto-a, base_url: \"https://provider.invalid\" }",
            )
            .expect("the fixed ProviderDef literal parses");
            (name.clone(), def)
        })
        .collect()
}

fn rate(v: f64) -> String {
    format!("{v}")
}

fn snapshot(cfg: &super::RootCfg) -> String {
    use std::fmt::Write as _;
    let mut s = String::new();

    let _ = writeln!(s, "per_request_fee = {}", cfg.per_request_fee);
    let _ = writeln!(
        s,
        "limits.default_max_tokens = {}",
        cfg.limits.default_max_tokens
    );
    let b = cfg.limits.reasoning_effort_budgets;
    let _ = writeln!(
        s,
        "limits.reasoning_effort_budgets = minimal={} low={} medium={} high={}",
        b.minimal, b.low, b.medium, b.high
    );

    s.push_str("rate_card:\n");
    match &cfg.rate_card {
        None => s.push_str("  <absent>\n"),
        Some(rc) => {
            for (model, r) in rc {
                let _ = writeln!(
                    s,
                    "  {model}: input={} output={} cache_read={} cache_write={}",
                    rate(r.input_utok),
                    rate(r.output_utok),
                    rate(r.cache_read_utok),
                    rate(r.cache_write_utok),
                );
            }
        }
    }

    s.push_str("models:\n");
    let mut model_names: Vec<&String> = cfg.models.keys().collect();
    model_names.sort();
    for name in model_names {
        let m = &cfg.models[name];
        let dmt = m
            .default_max_tokens
            .map_or_else(|| "-".to_string(), |v| v.to_string());
        let mc = m
            .max_concurrent
            .map_or_else(|| "-".to_string(), |v| v.to_string());
        let _ = writeln!(
            s,
            "  {name}: default_max_tokens={dmt} max_requests={} max_concurrent={mc}",
            m.max_requests,
        );
    }

    s.push_str("groups:\n");
    for (name, g) in &cfg.groups {
        let parent = g.parent.as_deref().unwrap_or("-");
        let _ = writeln!(s, "  {name}: enabled={} parent={parent}", g.enabled);
        for l in &g.limits {
            s.push_str("    limit: ");
            s.push_str(&render_limit(l));
            s.push('\n');
        }
        if let Some(cd) = &g.child_default {
            for l in &cd.limits {
                s.push_str("    child_default.limit: ");
                s.push_str(&render_limit(l));
                s.push('\n');
            }
        }
    }

    s
}

fn render_limit(l: &super::LimitCfg) -> String {
    let per = l.per.map_or("-", |w| w.as_str());
    let scope = l
        .scope
        .as_ref()
        .map_or_else(|| "-".to_string(), |s| format!("{}:{}", s.kind, s.value));
    let on_exhaust = match l.on_exhaust {
        None => "-",
        Some(super::groups::OnExhaust::Block) => "block",
        Some(super::groups::OnExhaust::Downgrade) => "downgrade",
    };
    let downgrade_to = l
        .downgrade_to
        .as_ref()
        .map_or_else(|| "-".to_string(), |s| format!("{}:{}", s.kind, s.value));
    format!(
        "metric={} amount={} per={per} scope={scope} on_exhaust={on_exhaust} downgrade_to={downgrade_to}",
        l.metric.as_str(),
        l.amount,
    )
}

fn snapshot_for(config_path: &Path) -> String {
    let yaml = std::fs::read_to_string(config_path)
        .unwrap_or_else(|e| panic!("read corpus config {}: {e}", config_path.display()));
    let deploy: DeployCfg = serde_yaml::from_str(&yaml)
        .unwrap_or_else(|e| panic!("parse corpus config {}: {e}", config_path.display()));
    let defs = defs_for(&deploy);
    let cfg = resolve(&deploy, &defs).unwrap_or_else(|errs| {
        panic!(
            "resolve refused corpus config {}:\n  - {}",
            config_path.display(),
            errs.join("\n  - ")
        )
    });
    snapshot(&cfg)
}

fn golden_path(config_path: &Path) -> PathBuf {
    config_path.with_extension("snap")
}

#[test]
fn resolved_billing_and_limits_config_is_byte_stable() {
    let configs = corpus_configs();
    assert!(
        configs.len() >= 5,
        "the back-compat corpus looks empty or truncated ({} configs). It should hold the \
         representative billing/limits configs in tests/backcompat-corpus/.",
        configs.len()
    );

    let bless = std::env::var_os("BLESS_BACKCOMPAT_CORPUS").is_some();
    let mut failures: Vec<String> = Vec::new();

    for config in &configs {
        let name = config
            .file_name()
            .unwrap_or_default()
            .to_string_lossy()
            .to_string();
        let got = snapshot_for(config);
        let golden = golden_path(config);

        if bless {
            std::fs::write(&golden, &got)
                .unwrap_or_else(|e| panic!("bless {}: {e}", golden.display()));
            continue;
        }

        let want = match std::fs::read_to_string(&golden) {
            Ok(w) => w,
            Err(_) => {
                failures.push(format!(
                    "[{name}] NO GOLDEN at {}. Bless it with \
                     BLESS_BACKCOMPAT_CORPUS=1 after confirming the resolved output is correct.\n\
                     --- resolved billing/limits snapshot ---\n{got}",
                    golden.display()
                ));
                continue;
            }
        };

        if got != want {
            failures.push(format!(
                "[{name}] RESOLVED BILLING/LIMITS CONFIG CHANGED.\n\
                 An operator's YAML now resolves to DIFFERENT effective settings than the blessed \
                 baseline. If this change is INTENDED and reviewed, re-bless with \
                 BLESS_BACKCOMPAT_CORPUS=1; otherwise it is a back-compat regression (M3's config \
                 eviction must preserve this surface byte-for-byte).\n\
                 --- expected (golden) ---\n{want}\n--- got (current resolve) ---\n{got}"
            ));
        }
    }

    assert!(
        !bless,
        "goldens re-blessed from current behavior; unset BLESS_BACKCOMPAT_CORPUS and re-run to verify."
    );
    assert!(
        failures.is_empty(),
        "{} corpus config(s) resolved to a DIFFERENT billing/limits surface than their blessed \
         baseline:\n\n{}",
        failures.len(),
        failures.join("\n\n========================================\n\n")
    );
}
