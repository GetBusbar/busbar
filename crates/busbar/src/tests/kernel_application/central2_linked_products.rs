// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors
use crate::root::test_plugins as plugins;
use std::sync::Arc;
use std::time::{Duration, Instant};
fn gov_with_store(store: &str) -> busbar_kernel::config::StoreCfg {
    busbar_kernel::config::StoreCfg {
        module: store.into(),
        settings: Default::default(),
    }
}
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
fn a_store_row_reads_alike_by_door_function_or_by_macro_door() {
    use busbar_kernel::preflight::{LinkedStore, LinkedStoreDoor, StoreRow};
    const BY_FN: LinkedStore = StoreRow::<LinkedStore>((
        busbar_store_memory::linked::STORE.0,
        busbar_store_memory::linked::STORE.1,
        busbar_store_memory::door,
        busbar_store_memory::linked::STORE.3,
    ))
    .linked();
    const BY_MACRO: LinkedStore =
        StoreRow::<LinkedStoreDoor>(busbar_store_memory::linked::STORE).linked();
    assert_eq!(
        (BY_FN.0, BY_FN.1, BY_FN.3),
        (BY_MACRO.0, BY_MACRO.1, BY_MACRO.3)
    );
    assert_eq!(BY_FN.2 as usize, BY_MACRO.2 as usize, "one door function");
    assert_eq!(
        BY_FN.2 as usize,
        busbar_store_memory::door as *const () as usize
    );
}
#[test]
fn the_built_in_store_is_a_linked_row_of_the_store_axis() {
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
    let store = gov_with_store(busbar_store_memory::linked::STORE.0);
    let name = store.module.as_str();
    let reg = busbar_kernel::preflight::plugins_preflight(
        Some(&store),
        None,
        &Default::default(),
        &Default::default(),
        &busbar_kernel::config::PluginsCfg::default(),
        &Default::default(),
    )
    .expect("the configured store resolves on the axis");
    let row = reg.resolve(name).expect("the configured store is a row");
    assert_eq!(
        (row.kind.as_str(), row.ephemeral),
        (busbar_contract::abi::mechanism::kind::STORE, true)
    );
    let stores = reg
        .linked()
        .into_iter()
        .filter(|p| p.kind == busbar_contract::abi::mechanism::kind::STORE);
    assert_eq!((stores.count(), reg.loadable().len()), (1, 0));
    reg.store_door(name)
        .expect("the row states its door to boot");
    let canonical = row.name.clone();
    assert_ne!(canonical, name, "the row's canonical name is not its key");
    assert_eq!(row.key, name, "the row prints its key");
    reg.store_door(&canonical)
        .expect("the canonical name opens the same store");
    let by_canonical = busbar_kernel::preflight::plugins_preflight(
        Some(&gov_with_store(&canonical)),
        None,
        &Default::default(),
        &Default::default(),
        &busbar_kernel::config::PluginsCfg::default(),
        &Default::default(),
    )
    .expect("`store.module: <canonical>` resolves as the key does");
    assert!(by_canonical.resolve(&canonical).expect("resolves").linked);
    println!("{WITNESS}");
}
#[test]
fn a_linked_rows_refusals_print_its_key() {
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
    let store = gov_with_store(busbar_store_memory::linked::STORE.0);
    let key = store.module.clone();
    let dir = plugins::scratch("printed-key");
    let plugins = plugins_cfg(&dir, true);
    let reg = busbar_kernel::preflight::plugins_preflight(
        Some(&store),
        None,
        &Default::default(),
        &Default::default(),
        &plugins,
        &Default::default(),
    )
    .expect("the store resolves");
    let canonical = reg.resolve(&key).expect("the row").name;
    for word in [key.as_str(), canonical.as_str()] {
        let hooks: std::collections::HashMap<String, busbar_kernel::config::HookCfg> =
            serde_json::from_value(serde_json::json!({ "h": { "module": word, "kind": "tap" } }))
                .expect("hooks");
        let refused = busbar_kernel::preflight::plugins_preflight(
            Some(&store),
            None,
            &Default::default(),
            &hooks,
            &plugins,
            &Default::default(),
        )
        .expect_err("a store is not a hook");
        assert!(
            refused.contains(&format!(
                "resolves to plugin '{key}' of kind 'store', not a `hook` plugin"
            )),
            "{word}: {refused}"
        );
        let providers: busbar_kernel::config::IdentityProviders =
            serde_json::from_value(serde_json::json!({ "x": { "module": word } })).expect("idps");
        let refused = busbar_kernel::preflight::plugins_preflight(
            Some(&store),
            None,
            &providers,
            &Default::default(),
            &plugins,
            &Default::default(),
        )
        .expect_err("a store is not an auth plugin");
        assert!(
            refused.contains(&format!(
                "identity-providers.x.module: '{word}' resolves to plugin '{key}' of kind 'store'"
            )),
            "{word}: {refused}"
        );
        let dialect = busbar_kernel::plane_driver::dispatch::provider_dialects()
            .into_iter()
            .next()
            .expect("actual provider dialect");
        let provider_defs = serde_json::from_value(serde_json::json!({
            "acme": {"protocol": dialect, "base_url": "https://api.example.com"}
        }))
        .expect("the actual provider catalog entry parses");
        let deploy = busbar_kernel::config::deploy_from_deserializer(serde_json::json!({
            "providers": {"acme": {"protocol": dialect,
                "base_url": "https://api.example.com", "api_key": "none"}},
            "models": {}, "auth": {"chain": [], "admin_auth": []},
            "store": {"module": busbar_store_memory::linked::STORE.0},
        }))
        .expect("actual root input parses");
        let mut cfg = busbar_kernel::config::resolve(&deploy, &provider_defs)
            .expect("actual root input resolves");
        let refusal =
            |cfg: &busbar_kernel::config::RootCfg| match busbar_kernel::config_validate::check(
                cfg,
                busbar_kernel::config_validate::Check {
                    plugins: &plugins,
                    unset_env_vars: &[],
                    root: &busbar_kernel::config_validate::no_root_rules,
                    fetch: None,
                    resolve_builtins: false,
                },
            ) {
                Err(busbar_kernel::config_validate::Refusal::Plugins(message)) => message,
                other => panic!("the genuine registry policy must refuse the kind: {other:?}"),
            };
        cfg.secrets.insert(word.to_string(), Default::default());
        assert_eq!(refusal(&cfg), format!(
            "secrets.{word}: plugin '{key}' has kind 'store', not 'secret'; only a kind: secret plugin can back a `secrets:` block entry"
        ));
        cfg.secrets.clear();
        cfg.providers.get_mut("acme").unwrap().api_key = busbar_kernel::config::SecretRef {
            module: word.to_string(),
            ..busbar_kernel::config::SecretRef::env("K")
        };
        let refused = refusal(&cfg);
        assert!(
            refused.contains(&format!(
                "references secret module '{word}', but plugin '{key}' has kind 'store'"
            )),
            "{word}: {refused}"
        );
    }
    let _ = std::fs::remove_dir_all(&dir);
    println!("{WITNESS}");
}
#[test]
fn the_linked_secret_sources_are_plugins_on_the_secret_table() {
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
    use busbar_kernel::config::secret::{SecretRef, SecretResolver};
    let reg = busbar_kernel::preflight::plugins_preflight(
        None,
        None,
        &Default::default(),
        &Default::default(),
        &busbar_kernel::config::PluginsCfg::default(),
        &Default::default(),
    )
    .expect("the default boot registers its linked rows");
    for name in ["env", "file"] {
        assert!(reg.resolve(name).is_none(), "{name} is no cold-kind row");
        assert!(
            busbar_kernel::preflight::root_rows()
                .secret_axis
                .expect("actual secret axis")
                .linked(name),
            "{name} is a linked secret plugin"
        );
    }
    let var = "BUSBAR_K5B_LINKED_SECRET_ROW";
    std::env::set_var(var, "hunter2");
    let resolver = SecretResolver::builtins_only();
    assert_eq!(
        busbar_contract::secret::SecretResolve::resolve(&resolver, &SecretRef::env(var)).unwrap(),
        busbar_contract::redacted::Secret::new(b"hunter2".to_vec())
    );
    let missing = busbar_contract::secret::SecretResolve::resolve(
        &resolver,
        &SecretRef::env("BUSBAR_K5B_NO_SUCH_VARIABLE"),
    )
    .expect_err("an unset variable refuses");
    assert_eq!(
        missing,
        "secret env:BUSBAR_K5B_NO_SUCH_VARIABLE cannot resolve: environment variable \
         'BUSBAR_K5B_NO_SUCH_VARIABLE' is unset"
    );

    let cold = SecretResolver::with_plugin(Box::new(|_, _| {
        panic!("a linked actual secret source must never delegate to the cold fallback")
    }));
    assert_eq!(
        busbar_contract::secret::SecretResolve::resolve(&cold, &SecretRef::env(var)).unwrap(),
        busbar_contract::redacted::Secret::new(b"hunter2".to_vec())
    );
    std::env::remove_var(var);
    println!("{WITNESS}");
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
        signals: Default::default(),
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
        // An infinity is a key like any other, ordered as 1.5.5 ordered it (the v1.5.5 ranking
        // natives' `lib.rs:77-80`, `:99-102`): never dropped as absent.
        (
            "cheapest",
            vec![
                (0, Some(f64::INFINITY), None, 1, None),
                (1, Some(f64::INFINITY), None, 1, None),
            ],
            prefer(&[0, 1]),
        ),
        (
            "cheapest",
            vec![
                (0, Some(3.0), None, 1, None),
                (1, Some(f64::NEG_INFINITY), None, 1, None),
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
    println!("{WITNESS}");
}
