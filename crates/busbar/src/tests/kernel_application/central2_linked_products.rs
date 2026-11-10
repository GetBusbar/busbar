// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors
use crate::root::test_plugins as plugins;
use std::sync::Arc;
use std::time::{Duration, Instant};
fn plugins_cfg(dir: &std::path::Path, enabled: bool) -> busbar_kernel::config::PluginsCfg {
    busbar_kernel::config::PluginsCfg {
        enabled,
        dir: dir.to_string_lossy().into_owned(),
        ..Default::default()
    }
}
fn linked_hook_name() -> &'static str {
    "cheapest"
}
fn real_ranking(word: &str) -> Option<(Arc<dyn busbar_kernel::hooks::RoutingPolicy>, Duration)> {
    let cfg = busbar_kernel::config::PoolCfg {
        policy: serde_yaml::from_str(word).expect("an ordinary pool policy word"),
        ..Default::default()
    };
    match busbar_kernel::hooks::resolve_policy(&cfg) {
        Some(busbar_kernel::hooks::ResolvedPolicy::Policy {
            policy, timeout, ..
        }) => Some((policy, timeout)),
        None => None,
    }
}
#[test]
fn a_linked_hook_named_in_config_passes_preflight_and_an_unknown_one_is_refused() {
    const CHILD: &str = "BUSBAR_CENTRAL2_LINKED_CHILD";
    const WITNESS: &str = "actual linked product assertions completed";
    if std::env::var_os(CHILD).is_none() {
        struct Child(std::process::Child);
        impl Drop for Child {
            fn drop(&mut self) {
                let _ = self.0.kill();
                let _ = self.0.wait();
            }
        }
        let name = std::thread::current()
            .name()
            .expect("the test runner names its test thread")
            .to_string();
        let mut child = Child(
            std::process::Command::new(std::env::current_exe().unwrap())
                .args(["--exact", &name, "--nocapture"])
                .env(CHILD, "1")
                .stdout(std::process::Stdio::piped())
                .spawn()
                .expect("start the isolated actual-root test"),
        );
        let until = Instant::now() + Duration::from_secs(60);
        loop {
            if let Some(status) = child.0.try_wait().unwrap() {
                use std::io::Read;
                let mut output = String::new();
                child
                    .0
                    .stdout
                    .take()
                    .unwrap()
                    .read_to_string(&mut output)
                    .unwrap();
                assert!(
                    status.success(),
                    "the actual-root usage witness failed: {status}: {output}"
                );
                assert!(
                    output.contains(WITNESS),
                    "the exact child did not complete its assertions: {output}"
                );
                return;
            }
            assert!(
                Instant::now() < until,
                "the actual-root usage witness timed out"
            );
            std::thread::park_timeout(Duration::from_millis(5));
        }
    }
    crate::dist_root_install::install();
    let hook = |module: &str| {
        let cfg: busbar_kernel::config::HookCfg =
            serde_yaml::from_str(&format!("kind: gate\nmodule: {module}\n")).expect("a hook");
        std::collections::HashMap::from([("h".to_string(), cfg)])
    };
    let dir = plugins::scratch("linked-hook");
    let run = |module: &str, enabled: bool| {
        busbar_kernel::preflight::plugins_preflight(
            None,
            None,
            &Default::default(),
            &hook(module),
            &plugins_cfg(&dir, enabled),
            &Default::default(),
        )
    };
    let linked = linked_hook_name();
    for enabled in [false, true] {
        run(linked, enabled).unwrap_or_else(|e| {
            panic!("the linked hook '{linked}' passes (plugins.enabled: {enabled}): {e}")
        });
    }
    let err = run("oracle-hook", true).expect_err("an unknown hook is refused");
    assert!(
        err.starts_with(&format!(
            "no plugin matching the hook reference 'oracle-hook' is installed in '{}' (plugins ARE \
             enabled; loadable: []). Two things to check: is the plugin subsystem enabled? (it is) \
             — and is the signed `kind: hook` tarball actually IN the folder?",
            dir.display()
        )),
        "{err}"
    );
    let _ = std::fs::remove_dir_all(&dir);
    println!("{WITNESS}");
}
#[test]
fn the_built_in_ranking_strategies_are_hook_words_of_one_linked_door_on_the_hook_axis() {
    const CHILD: &str = "BUSBAR_CENTRAL2_LINKED_CHILD";
    const WITNESS: &str = "actual linked product assertions completed";
    if std::env::var_os(CHILD).is_none() {
        struct Child(std::process::Child);
        impl Drop for Child {
            fn drop(&mut self) {
                let _ = self.0.kill();
                let _ = self.0.wait();
            }
        }
        let name = std::thread::current()
            .name()
            .expect("the test runner names its test thread")
            .to_string();
        let mut child = Child(
            std::process::Command::new(std::env::current_exe().unwrap())
                .args(["--exact", &name, "--nocapture"])
                .env(CHILD, "1")
                .stdout(std::process::Stdio::piped())
                .spawn()
                .expect("start the isolated actual-root test"),
        );
        let until = Instant::now() + Duration::from_secs(60);
        loop {
            if let Some(status) = child.0.try_wait().unwrap() {
                use std::io::Read;
                let mut output = String::new();
                child
                    .0
                    .stdout
                    .take()
                    .unwrap()
                    .read_to_string(&mut output)
                    .unwrap();
                assert!(
                    status.success(),
                    "the actual-root usage witness failed: {status}: {output}"
                );
                assert!(
                    output.contains(WITNESS),
                    "the exact child did not complete its assertions: {output}"
                );
                return;
            }
            assert!(
                Instant::now() < until,
                "the actual-root usage witness timed out"
            );
            std::thread::park_timeout(Duration::from_millis(5));
        }
    }
    crate::dist_root_install::install();
    for name in busbar_kernel::config::RESERVED_HOOK_NAMES
        .iter()
        .filter(|n| {
            busbar_kernel::config::is_strategy_name(n)
                && **n != busbar_kernel::config::ON_ERROR_WEIGHTED
        })
    {
        assert!(
            real_ranking(name).is_some(),
            "a built-in ranking strategy is a hook word of the linked ranking door: {name}"
        );
        let (policy, _) = real_ranking(name).expect("the strategy opens");
        assert_eq!(policy.name(), *name);
    }
    assert!(!real_ranking(busbar_kernel::config::ON_ERROR_WEIGHTED).is_some());
    let reg = busbar_kernel::preflight::linked().expect("the linked rows register");
    assert!(
        reg.resolve("cheapest").is_none(),
        "a strategy word is the door's mark, not a registry alias"
    );
    println!("{WITNESS}");
}
#[tokio::test]
async fn each_strategy_word_ranks_as_1_5_5_did_through_the_door_and_never_reaches_on_error() {
    const CHILD: &str = "BUSBAR_CENTRAL2_LINKED_CHILD";
    const WITNESS: &str = "actual linked product assertions completed";
    if std::env::var_os(CHILD).is_none() {
        struct Child(std::process::Child);
        impl Drop for Child {
            fn drop(&mut self) {
                let _ = self.0.kill();
                let _ = self.0.wait();
            }
        }
        let name = std::thread::current()
            .name()
            .expect("the test runner names its test thread")
            .to_string();
        let mut child = Child(
            std::process::Command::new(std::env::current_exe().unwrap())
                .args(["--exact", &name, "--nocapture"])
                .env(CHILD, "1")
                .stdout(std::process::Stdio::piped())
                .spawn()
                .expect("start the isolated actual-root test"),
        );
        let until = Instant::now() + Duration::from_secs(60);
        loop {
            if let Some(status) = child.0.try_wait().unwrap() {
                use std::io::Read;
                let mut output = String::new();
                child
                    .0
                    .stdout
                    .take()
                    .unwrap()
                    .read_to_string(&mut output)
                    .unwrap();
                assert!(
                    status.success(),
                    "the actual-root usage witness failed: {status}: {output}"
                );
                assert!(
                    output.contains(WITNESS),
                    "the exact child did not complete its assertions: {output}"
                );
                return;
            }
            assert!(
                Instant::now() < until,
                "the actual-root usage witness timed out"
            );
            std::thread::park_timeout(Duration::from_millis(5));
        }
    }
    crate::dist_root_install::install();
    use busbar_kernel::hooks::{Candidate, RoutingContext, RoutingDecision, RoutingRequest};

    type Row = (usize, Option<f64>, Option<f64>, usize, Option<f64>);
    let cand = |&(idx, cost, lat, conc, rate): &Row| Candidate {
        idx,
        model: "m",
        provider: "p",
        weight: 1,
        context_max: None,
        tier: None,
        cost_per_mtok: cost,
        tags: &[],
        latency_ms: lat,
        available_concurrency: conc,
        budget_remaining: None,
        rate_headroom: rate,
        signals: {
            // One expected unit at the candidate's declared routing price. The current
            // ranking door consumes this recipe, never the legacy scalar above.
            let mut signals = busbar_contract::SignalBag::new();
            busbar_contract::signal::route_cost::append(
                &mut signals,
                [busbar_contract::signal::route_cost::Term {
                    class: "work",
                    price_per_unit: cost,
                    expected_units: 1.0,
                }],
            );
            signals
        },
    };
    let req = RoutingRequest {
        request_id: 1,
        pool: "p",
        ingress_protocol: "wire-a",
        requested_model: None,
        message_count: 1,
        tool_count: 0,
        has_tools: false,
        total_chars: 10,
        system_chars: 0,
        max_tokens: None,
        stream: false,
        prompt: None,
        identity: None,
        signals: Default::default(),
        session: None,
    };
    let ctx = RoutingContext {
        pool: "p",
        budget_remaining: None,
        budget: &[],
    };
    let prefer = |o: &[usize]| RoutingDecision::Prefer(o.to_vec());

    let cases: Vec<(&str, Vec<Row>, RoutingDecision)> = vec![
        (
            "cheapest",
            vec![
                (0, Some(15.0), None, 1, None),
                (1, Some(3.0), None, 1, None),
                (2, None, None, 1, None),
            ],
            prefer(&[1, 0, 2]),
        ),
        (
            "cheapest",
            vec![(0, None, None, 1, None), (1, None, None, 1, None)],
            RoutingDecision::Abstain,
        ),
        (
            "cheapest",
            vec![(0, Some(5.0), None, 1, None)],
            prefer(&[0]),
        ),
        (
            "fastest",
            vec![
                (0, None, Some(120.0), 1, None),
                (1, None, Some(40.0), 1, None),
                (2, None, Some(80.0), 1, None),
            ],
            prefer(&[1, 2, 0]),
        ),
        (
            "fastest",
            vec![(0, None, None, 1, None), (1, None, None, 1, None)],
            RoutingDecision::Abstain,
        ),
        (
            "fastest",
            vec![(0, None, Some(30.0), 1, None)],
            prefer(&[0]),
        ),
        (
            "least_busy",
            vec![
                (0, None, None, 2, None),
                (1, None, None, 9, None),
                (2, None, None, 5, None),
            ],
            prefer(&[1, 2, 0]),
        ),
        (
            "least_busy",
            vec![
                (0, None, None, 0, None),
                (1, None, None, 0, None),
                (2, None, None, 0, None),
            ],
            prefer(&[0, 1, 2]),
        ),
        ("least_busy", vec![(0, None, None, 3, None)], prefer(&[0])),
        (
            "usage",
            vec![
                (0, None, None, 1, Some(0.10)),
                (1, None, None, 1, Some(0.90)),
                (2, None, None, 1, None),
                (3, None, None, 1, Some(0.50)),
            ],
            prefer(&[1, 3, 0, 2]),
        ),
        (
            "usage",
            vec![
                (0, None, None, 1, None),
                (1, None, None, 1, None),
                (2, None, None, 1, None),
            ],
            RoutingDecision::Abstain,
        ),
        (
            "usage",
            vec![(0, None, None, 1, Some(0.0)), (1, None, None, 1, Some(0.0))],
            prefer(&[0, 1]),
        ),
        ("cheapest", Vec::new(), RoutingDecision::Abstain),
        ("fastest", Vec::new(), RoutingDecision::Abstain),
        ("least_busy", Vec::new(), RoutingDecision::Abstain),
        ("usage", Vec::new(), RoutingDecision::Abstain),
        // Valid recipe prices preserve the old cheapest ordering, including ties and zero.
        // Non-finite latency/headroom signals still retain their numeric ordering.
        (
            "cheapest",
            vec![
                (0, Some(f64::MAX), None, 1, None),
                (1, Some(f64::MAX), None, 1, None),
            ],
            prefer(&[0, 1]),
        ),
        (
            "cheapest",
            vec![
                (0, Some(3.0), None, 1, None),
                (1, Some(0.0), None, 1, None),
                (2, None, None, 1, None),
            ],
            prefer(&[1, 0, 2]),
        ),
        (
            "fastest",
            vec![
                (0, None, Some(f64::INFINITY), 1, None),
                (1, None, Some(10.0), 1, None),
            ],
            prefer(&[1, 0]),
        ),
        (
            "usage",
            vec![
                (0, None, None, 1, Some(0.5)),
                (1, None, None, 1, None),
                (2, None, None, 1, Some(f64::INFINITY)),
            ],
            prefer(&[2, 0, 1]),
        ),
    ];
    let gate_default =
        std::time::Duration::from_millis(busbar_kernel::config::DEFAULT_POLICY_TIMEOUT_MS);
    for (word, rows, want) in cases {
        let (policy, budget) = real_ranking(word).expect("the strategy opens through the door");
        assert!(
            budget > gate_default,
            "`{word}`'s deadline is the dispatcher's Call class budget, not the gate default"
        );
        let cands: Vec<Candidate<'_>> = rows.iter().map(cand).collect();
        let got = policy.decide(&req, &cands, &ctx, budget).await;
        match got {
            Ok(decision) => assert_eq!(decision, want, "`{word}` over {rows:?}"),
            Err(e) => panic!("`{word}` reached on_error ({e}); 1.5.5's ranking never did"),
        }
    }
    for invalid in [f64::INFINITY, f64::NEG_INFINITY, f64::NAN, -1.0] {
        let rows = [
            (0, Some(invalid), None, 1, None),
            (1, Some(3.0), None, 1, None),
            (2, None, None, 1, None),
        ];
        let cands: Vec<Candidate<'_>> = rows.iter().map(cand).collect();
        assert!(busbar_contract::signal::route_cost::decode(&cands[0].signals).is_err());
        let (policy, budget) =
            real_ranking("cheapest").expect("the strategy opens through the door");
        assert_eq!(
            policy.decide(&req, &cands, &ctx, budget).await.unwrap(),
            RoutingDecision::Prefer(vec![1, 0, 2]),
            "malformed price {invalid} is unknown, never cheaper than a valid recipe or dropped"
        );
    }
    println!("{WITNESS}");
}
