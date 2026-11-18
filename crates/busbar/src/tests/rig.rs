// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The shared distribution test rig (CORE-ARCHITECTURE-DIET W0.4).

/// Re-run the calling test alone in a child process and return its verdict.
///
/// The parent (no `$child` in the environment) re-executes this test binary with `--exact` on
/// the current test thread's name and `$child=1`, kills the child if the parent unwinds, fails
/// when the child fails, times out, or never prints `$witness`, and returns from the calling
/// test. The child (the variable set) falls through and runs the test body.
///
/// `isolated!(CHILD, WITNESS)` is an actual-root case (90 s); `isolated!(CHILD, WITNESS,
/// witness = "usage")` is an actual-root witness named "usage" (60 s).
macro_rules! isolated {
    ($child:expr, $witness:expr) => {
        if std::env::var_os($child).is_none() {
            crate::distribution::rig::run_isolated(
                $child,
                $witness,
                crate::distribution::rig::Isolation {
                    thread: "the test runner names its exact test thread",
                    spawn: "start the isolated actual-root case",
                    timeout: std::time::Duration::from_secs(90),
                    failed: "the actual-root child failed",
                    timed_out: "the actual-root child timed out",
                },
            );
            return;
        }
    };
    ($child:expr, $witness:expr, witness = $noun:literal) => {
        if std::env::var_os($child).is_none() {
            crate::distribution::rig::run_isolated(
                $child,
                $witness,
                crate::distribution::rig::Isolation {
                    thread: "the test runner names its test thread",
                    spawn: "start the isolated actual-root test",
                    timeout: std::time::Duration::from_secs(60),
                    failed: concat!("the actual-root ", $noun, " witness failed"),
                    timed_out: concat!("the actual-root ", $noun, " witness timed out"),
                },
            );
            return;
        }
    };
}

/// The messages and deadline of one isolated re-run.
pub(super) struct Isolation {
    pub(super) thread: &'static str,
    pub(super) spawn: &'static str,
    pub(super) timeout: std::time::Duration,
    pub(super) failed: &'static str,
    pub(super) timed_out: &'static str,
}

/// The parent side of `isolated!`: run this exact test in a child and judge it.
pub(super) fn run_isolated(child_var: &str, witness: &str, isolation: Isolation) {
    struct Child(std::process::Child);
    impl Drop for Child {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }
    let name = std::thread::current()
        .name()
        .expect(isolation.thread)
        .to_string();
    let mut child = Child(
        std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", &name, "--nocapture"])
            .env(child_var, "1")
            .stdout(std::process::Stdio::piped())
            .spawn()
            .expect(isolation.spawn),
    );
    let until = std::time::Instant::now() + isolation.timeout;
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
            assert!(status.success(), "{}: {status}: {output}", isolation.failed);
            assert!(
                output.contains(witness),
                "the exact child did not complete its assertions: {output}"
            );
            return;
        }
        assert!(std::time::Instant::now() < until, "{}", isolation.timed_out);
        std::thread::park_timeout(std::time::Duration::from_millis(5));
    }
}

/// Install the distribution root and stage the signed actual Store plugin in scratch `tag`.
///
/// Returns the Store module name, the plugin directory, and the Store settings.
pub(super) fn actual_store(
    tag: &str,
) -> (String, std::path::PathBuf, busbar_contract::json::Value) {
    crate::dist_root_install::install();
    let store_library = crate::root::test_plugins::application_store_library();
    let module = crate::root::test_plugins::native_image(&store_library).name;
    let manifest = crate::root::test_plugins::native_manifest(
        "store",
        &store_library,
        crate::root::test_plugins::FIXTURE_PUBLISHER,
    );
    let directory = crate::root::test_plugins::scratch(tag);
    let archive = crate::root::test_plugins::signed(
        &crate::dist_root_install::release_key(),
        manifest,
        &std::fs::read(store_library).expect("the actual Store artifact reads"),
    );
    std::fs::write(directory.join("store.tar.gz"), archive).expect("stage the actual Store");
    let settings = crate::root::test_plugins::application_store_settings(&directory);
    (module, directory, settings)
}

/// The served actual root: its address, its server task, and the node book it holds.
type Served = (
    std::net::SocketAddr,
    tokio::task::JoinHandle<()>,
    crate::root::durability::NodeBook,
);

/// Compose the real root over the actual Store from `document`, hydrate it, and serve it.
pub(super) async fn actual_root(
    document: busbar_contract::json::Value,
    directory: &std::path::Path,
    module: &str,
) -> Served {
    let (app, book) = compose(document, directory, module).await;
    let router = busbar_kernel::build_router(
        crate::root::real_store::hydrated(std::sync::Arc::new(app)).await,
    );
    serve(router, book).await
}

/// [`actual_root`] without hydrating the application before serving it.
pub(super) async fn actual_root_unhydrated(
    document: busbar_contract::json::Value,
    directory: &std::path::Path,
    module: &str,
) -> Served {
    let (app, book) = compose(document, directory, module).await;
    let router = busbar_kernel::build_router(std::sync::Arc::new(app));
    serve(router, book).await
}

async fn compose(
    document: busbar_contract::json::Value,
    directory: &std::path::Path,
    module: &str,
) -> (busbar_kernel::state::App, crate::root::durability::NodeBook) {
    let deploy = busbar_kernel::config::deploy_from_deserializer(
        &document,
        &crate::root::boot::axis_test_grammar(),
    )
    .expect("the actual admin deployment parses");
    let config = busbar_kernel::config::resolve(&deploy, &Default::default())
        .expect("the actual admin deployment resolves");
    let rules = std::sync::Arc::new(crate::root::door_steps::Rules::default())
        as std::sync::Arc<dyn busbar_kernel::appbuild::RootRules>;
    let plugin_config = crate::root::test_plugins::trusted_config(directory);
    let crate::root::min3_boot::fixture::Fixture {
        backend: anchor,
        rules,
    } = crate::root::min3_boot::fixture::open(&config, &plugin_config, rules.clone())
        .await
        .expect("the actual Store opens the configuration authority");
    let anchor = crate::root::real_store::core_over(anchor).await;
    let overlay = busbar_kernel::config::overlay::OverlayStore::from_core(anchor.clone())
        .expect("the actual Store supports conditional configuration records");
    let (app, rotate, limits) = busbar_kernel::appbuild::build_app_from_config_with_store(
        config,
        plugin_config,
        Some(overlay),
        std::collections::HashSet::new(),
        std::collections::HashSet::new(),
        (None, None),
        None,
        &rules,
        Some(anchor),
        true,
    )
    .await
    .expect("the real root composes the configured Store and admin application");
    limits.stage_boot();
    let book = crate::root::boot::book(&app, module)
        .await
        .expect("the actual Store binds rate-card history and usage recovery before activation");
    limits.keep().await.expect("the actual limits commit");
    if let Some(rotate) = rotate {
        rotate.await;
    }
    (app, book)
}

async fn serve(router: axum::Router, book: crate::root::durability::NodeBook) -> Served {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    (addr, handle, book)
}

/// [`actual_store`] with its settings as a JSON facade value, so a new test builds its deployment document
/// without serde_json (DEP-3). The conversion is this rig's boundary; the rig itself still speaks serde_json
/// (flagged for W-SERDE, #162).
pub(super) fn actual_store_facade(
    tag: &str,
) -> (String, std::path::PathBuf, busbar_contract::json::Value) {
    let (module, directory, settings) = actual_store(tag);
    let settings = busbar_contract::json::parse_value(settings.to_string().as_bytes())
        .expect("the actual Store settings read back through the JSON facade");
    (module, directory, settings)
}

/// [`actual_root`] for a deployment document built through the JSON facade (DEP-3); see
/// [`actual_store_facade`].
pub(super) async fn actual_root_facade(
    document: &busbar_contract::json::Value,
    directory: &std::path::Path,
    module: &str,
) -> Served {
    let document: serde_json::Value = serde_json::from_str(&document.to_string())
        .expect("a JSON facade document reads as the rig's deployment document");
    actual_root(document, directory, module).await
}
