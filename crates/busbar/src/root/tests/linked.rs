// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE ROOT'S LINKED TABLES: the export, diagnostic, egress, store, hook and secret axes, each a row a
//! dropped-in plugin of the same kind meets in one fold.
//!
//! The plane axis's HOT-lane both-ways proofs (the example plane fixture linked and dropped in, one
//! row and one serve) left with `busbar-plugin-example-plane` (P5, "delete plane-example"; Q128
//! audit). A plane is proven through its memory-ABI door, by its own repo's conformance run.

use super::*;
#[cfg(linked_egress)]
use crate::root::boot::HostEgressCarrier;
use crate::root::loader::sign::{DiagnosticDecl, SigningKey};
use crate::root::loader::PluginRegistry;
use crate::root::test_plugins;

/// THE KERNEL SERVES NO EXPORT MODULE OF ITS OWN (K9e-2: its last built-in became a linked sink),
/// so the refusal of a row "spelling a built-in module" has nothing left to guard and is gone. What
/// replaces it: every module is a row of the axis, and each LINKED export row answers its own
/// module ahead of any row a plugins directory drops in under the same alias — a dropped-in row
/// never takes a module from the sink this build links. RED: without the linked rows, the
/// dropped-in one answers.
#[test]
fn every_linked_export_row_answers_its_module_ahead_of_a_dropped_in_spelling() {
    let release = test_plugins::key(7);
    let linked = crate::LINKED
        .exports
        .iter()
        .map(|&(name, alias, ..)| (name, alias));
    let doors = crate::LINKED.export_doors.iter().map(|d| (d.name, d.alias));
    for (name, alias) in linked.chain(doors) {
        let scan = || export_row_registry(alias, "k9e-dropped", alias, "busbar", &release, vec![]);
        let rows = linked_exports(crate::LINKED.exports, crate::LINKED.export_doors)
            .expect("the linked export rows");
        let both = scan().link(rows).expect("the linked door admits them");
        let answering = |r: &PluginRegistry| r.resolve(alias).map(|p| p.manifest.name.clone());
        assert_eq!(answering(&both).as_deref(), Some(name), "{alias}");
        // RED ARM: the dropped-in row alone answers.
        assert_eq!(
            answering(&scan()).as_deref(),
            Some("k9e-dropped"),
            "{alias}"
        );
    }
}

/// THE HOST'S METRIC CATALOG CANNOT DRIFT (K9a S1). Every `busbar_*` series constant the host's
/// metric modules define is in [`HOST_SERIES`], so a first-party plugin's claim on one is refused;
/// and a derived histogram series is the host's too. RED: drop an entry from the list and the
/// scan names it.
#[test]
fn the_host_series_catalog_holds_every_series_the_host_defines() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
    let sources = [
        "busbar-kernel/src/metrics/mod.rs",
        "busbar-kernel/src/telemetry.rs",
        "busbar-kernel/src/proxy/proxy_vocab.rs",
    ];
    let mut defined = Vec::new();
    for file in sources {
        let text = std::fs::read_to_string(root.join(file)).expect("read a metric module");
        // A `const NAME: &str =` followed (on its line or the next) by a `"busbar_…"` literal.
        let mut pending = false;
        for line in text.lines() {
            let decl = line.contains("const ") && line.contains(": &str =");
            if decl || pending {
                if let Some(start) = line.find("\"busbar_") {
                    let rest = &line[start + 1..];
                    defined.push(rest[..rest.find('"').expect("closed")].to_string());
                    pending = false;
                    continue;
                }
                pending = decl && line.trim_end().ends_with('=');
            }
        }
    }
    assert!(
        defined.len() >= HOST_SERIES.len(),
        "the scan found {defined:?}"
    );
    let missing: Vec<&String> = defined.iter().filter(|n| !host_series(n)).collect();
    assert!(
        missing.is_empty(),
        "host series missing from HOST_SERIES: {missing:?}"
    );
    assert!(host_series("busbar_request_duration_seconds_count"));
    assert!(!host_series("busbar_example_deliveries_total"));
}

/// A fresh `plugins/` directory holding one `kind: export` row signed by `signer` under `publisher`,
/// declaring `decls`, scanned under a posture holding the release key `[7; 32]` and allowlisting
/// any other signer as its publisher. Manifest-only: nothing here is loaded.
fn declaring_registry(
    tag: &str,
    publisher: &str,
    signer: &SigningKey,
    decls: Vec<DiagnosticDecl>,
) -> PluginRegistry {
    let name = format!("s3-{tag}");
    export_row_registry(tag, &name, &name, publisher, signer, decls)
}

/// [`declaring_registry`]'s row under the `name` and `alias` given.
fn export_row_registry(
    tag: &str,
    name: &str,
    alias: &str,
    publisher: &str,
    signer: &SigningKey,
    decls: Vec<DiagnosticDecl>,
) -> PluginRegistry {
    let dir = test_plugins::scratch(&format!("root-s3-{tag}"));
    let mut manifest = test_plugins::manifest("export", name, publisher);
    manifest.alias = alias.into();
    manifest.declares.diagnostics = decls;
    let lib = b"a manifest-only row";
    std::fs::write(
        dir.join("s3.tar.gz"),
        test_plugins::signed(signer, manifest, lib),
    )
    .unwrap();
    let mut policy = test_plugins::release_policy(&test_plugins::key(7));
    policy.publishers = [(publisher.to_string(), signer.verifying_key())]
        .into_iter()
        .filter(|_| publisher != "busbar")
        .collect();
    let registry = test_plugins::boot_with(&dir, &policy);
    let _ = std::fs::remove_dir_all(&dir);
    registry
}

fn decl(code: u16, severity: &str) -> DiagnosticDecl {
    DiagnosticDecl {
        code,
        slug: format!("s3-code-{code}"),
        title: "A declared plugin code".into(),
        severity: severity.into(),
        summary: "The plugin raised it.".into(),
        action: "Read the plugin's docs.".into(),
        since: "1.6.0".into(),
    }
}

/// **K9a S3 — PLUGIN DIAGNOSTICS join the catalogue.** A first-party plugin's declared code becomes
/// a catalogue entry one for one (its class from its thousands digit, its severity from its token),
/// so the host's fold resolves a diagnostic the plugin raises under it exactly as a built-in one.
/// RED ARMS: the same declaration from a third party is refused; a code the catalogue already holds
/// is refused (never shadowed); a class or severity that is not the host's is refused. (The loader's
/// both-ways test proves either door states the same declaration as first-party.)
#[test]
fn a_first_party_plugins_declared_codes_join_the_catalogue_and_nothing_else_does() {
    use busbar_contract::diagnostic::{Class, Severity};
    use busbar_kernel::diagnostics::{by_code, REGISTRY};
    let release = test_plugins::key(7);
    assert!(by_code(6990).is_none(), "the witness code must be free");
    let registry = declaring_registry("ok", "busbar", &release, vec![decl(6990, "actionable")]);
    let declared = declared_diagnostics(&registry, &[]).expect("a first-party declaration joins");
    assert_eq!(declared.len(), 1);
    let d = declared[0];
    assert_eq!(
        (d.code, d.class, d.severity, d.slug, d.retired),
        (
            6990,
            Class::Plugins,
            Severity::Actionable,
            "s3-code-6990",
            false
        )
    );
    assert_eq!(d.banner().to_string(), "BUSBAR-6990");

    let acme = test_plugins::key(8);
    let third = declaring_registry("third", "acme", &acme, vec![decl(6990, "actionable")]);
    let refused = declared_diagnostics(&third, &[]).expect_err("a third party is refused");
    assert!(refused.contains("not first-party"), "{refused}");

    let taken = REGISTRY[0].code;
    for (tag, bad) in [
        ("taken", decl(taken, "actionable")),
        ("class", decl(990, "actionable")),
        ("severity", decl(6991, "loud")),
    ] {
        let registry = declaring_registry(tag, "busbar", &release, vec![bad]);
        let refused = declared_diagnostics(&registry, &[]).expect_err(tag);
        assert!(refused.starts_with("plugin 's3-"), "{tag}: {refused}");
    }
}

/// **K9a S5 — THE HOST'S EGRESS CARRIER applies the host's URL policy before any hop.** A target the
/// built-in webhook guard refuses — plaintext, loopback, cloud metadata — is refused with the
/// guard's own words and nothing is dialled, so a plugin sink can reach no further than the host's
/// own telemetry egress may. RED: carry the request without the policy check and the loopback
/// target is dialled (a `request` failure, not a `refused` one).
#[cfg(linked_egress)]
#[test]
fn the_egress_carrier_refuses_what_the_host_policy_refuses() {
    use crate::root::loader::EgressCarrier as _;
    use busbar_contract::abi::cold::export::{HostResult, HttpRequest};
    for url in [
        "http://collector.example/v1",
        "https://127.0.0.1:9/v1",
        "https://169.254.169.254/latest",
    ] {
        let request = HttpRequest {
            method: "POST".into(),
            url: url.into(),
            headers: Vec::new(),
            body: "{}".into(),
            timeout_ms: 500,
        };
        match HostEgressCarrier.carry(&request) {
            HostResult::Failed { step, error, .. } => {
                assert_eq!(step, "refused", "{url}: {error}");
                let guard = busbar_kernel::observability::validate_webhook_url(Some(url.into()));
                assert_eq!(Err(error), guard, "{url}");
            }
            other => panic!("{url} was carried: {other:?}"),
        }
        // K9c: the policy asked WITHOUT carrying — the same guard, the same words.
        let guard = busbar_kernel::observability::validate_webhook_url(Some(url.into()));
        assert_eq!(HostEgressCarrier.admit(url), guard.map(|_| ()), "{url}");
    }
    assert_eq!(
        HostEgressCarrier.admit("https://collector.example/v1"),
        Ok(())
    );
}

/// **K9e-2 — THE COLLECTOR POLICY, AND OCTETS ON THE WIRE.** Under the collector policy a sink may
/// declare, the host's carrier takes a BINARY body to a plaintext loopback collector — the listener
/// receives exactly the octets and headers the sink asked for — while refusing, with the OTLP
/// endpoint guard's own words and nothing dialled, a plaintext remote collector, a private address
/// and cloud metadata. RED ARM: the same loopback request under the open web (the webhook policy
/// every undeclared sink gets) is refused and never reaches the listener.
#[cfg(linked_egress)]
#[tokio::test(flavor = "multi_thread")]
async fn the_collector_policy_carries_octets_to_a_loopback_collector_and_nothing_else() {
    use crate::root::loader::{EgressCarrier as _, EgressPolicy};
    use busbar_contract::abi::cold::export::{HostResult, HttpRequest};
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let port = listener.local_addr().expect("addr").port();
    let (seen_tx, mut seen) = tokio::sync::mpsc::unbounded_channel::<Vec<u8>>();
    tokio::spawn(async move {
        while let Ok((mut conn, _)) = listener.accept().await {
            let seen_tx = seen_tx.clone();
            tokio::spawn(async move {
                let mut raw = Vec::new();
                let mut buf = [0u8; 4096];
                loop {
                    let n = conn.read(&mut buf).await.unwrap_or(0);
                    if n == 0 {
                        return;
                    }
                    raw.extend_from_slice(&buf[..n]);
                    let Some(end) = raw.windows(4).position(|w| w == b"\r\n\r\n") else {
                        continue;
                    };
                    let head = String::from_utf8_lossy(&raw[..end]).to_ascii_lowercase();
                    let length: usize = head
                        .lines()
                        .find_map(|l| l.strip_prefix("content-length:"))
                        .and_then(|v| v.trim().parse().ok())
                        .unwrap_or(0);
                    if raw.len() >= end + 4 + length {
                        let _ = seen_tx.send(raw.clone());
                        let _ = conn
                            .write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 0\r\n\r\n")
                            .await;
                        return;
                    }
                }
            });
        }
    });
    let collector = format!("http://127.0.0.1:{port}/v1/traces");
    let octets = vec![0x0a, 0x00, 0xff, 0x80, 0x0d, 0x0a];
    let request = |url: &str| HttpRequest {
        method: "POST".into(),
        url: url.into(),
        headers: vec![("content-type".into(), "application/x-protobuf".into())],
        body: String::new(),
        timeout_ms: 5000,
    };
    let carried = HostEgressCarrier
        .carry_under_async(EgressPolicy::Collector, request(&collector), octets.clone())
        .await;
    assert!(
        matches!(carried, HostResult::Http(ref r) if r.status == 200),
        "{carried:?}"
    );
    let raw = seen
        .recv()
        .await
        .expect("the collector received the request");
    let end = raw
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .expect("a head")
        + 4;
    let head = String::from_utf8_lossy(&raw[..end]).to_ascii_lowercase();
    assert!(head.starts_with("post /v1/traces http/1.1\r\n"), "{head}");
    assert!(
        head.contains("content-type: application/x-protobuf\r\n"),
        "{head}"
    );
    assert_eq!(&raw[end..], &octets[..], "the octets arrive exactly");
    assert_eq!(
        HostEgressCarrier.admit_under(EgressPolicy::Collector, "http://localhost:4318/v1/traces"),
        Ok(())
    );

    for url in [
        "http://collector.example/v1/traces",
        "https://10.0.0.1/v1/traces",
        "https://169.254.169.254/latest",
    ] {
        let guard = crate::root::otlp::collector_policy(url, false);
        assert!(guard.is_err(), "{url}");
        let answer = HostEgressCarrier
            .carry_under_async(EgressPolicy::Collector, request(url), octets.clone())
            .await;
        match answer {
            HostResult::Failed { step, error, .. } => {
                assert_eq!((step.as_str(), Err(error)), ("refused", guard), "{url}")
            }
            other => panic!("{url} was carried: {other:?}"),
        }
    }

    // RED ARM: the loopback collector under the open web is refused, and nothing arrives.
    let open_web = HostEgressCarrier
        .carry_under_async(EgressPolicy::OpenWeb, request(&collector), octets)
        .await;
    let guard = busbar_kernel::observability::validate_webhook_url(Some(collector.clone()));
    match open_web {
        HostResult::Failed { step, error, .. } => {
            assert_eq!((step.as_str(), Err(error)), ("refused", guard.map(|_| ())))
        }
        other => panic!("the open web carried a loopback request: {other:?}"),
    }
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    assert!(
        seen.try_recv().is_err(),
        "a refused request reached the collector"
    );
}

/// K5d (DECISIONS #2 rule (1), #40) — THE DEFAULT STORE AND THE RANKING HOOKS ARE ROWS OF THE ROOT'S
/// LINKED TABLES. The kernel names neither; `main` hands the `stores`/`hooks` tables to the kernel's
/// cold-kind axis (`root::linked::register_stores` -> `preflight::install_linked_rows`), which
/// registers them through `PluginRegistry::link` like any dropped-in row: the default
/// `governance.store` is the one row that declares itself the default, an ephemeral in-process store
/// that opens; the hook table is the linked ranking DOOR, whose Statement claims each built-in
/// strategy word (the root's hook axis binds it).
///
/// RED by deleting the `store-memory` / `hooks-ranking` rows of `[package.metadata.busbar.linked]`:
/// the tables carry no default store (and no ranking row) to hand the kernel.
#[test]
fn the_default_store_and_ranking_hooks_are_rows_of_the_linked_tables() {
    let default = super::default_store(crate::LINKED.stores)
        .expect("one claim")
        .expect("a linked store declares itself the default");
    let stores: Vec<_> = crate::LINKED
        .stores
        .iter()
        .map(|s| (s.0, s.1, s.2))
        .collect();
    assert_eq!(
        stores,
        [(default, true, true)],
        "one linked store: the ephemeral default"
    );
    (crate::LINKED.stores[0].3)("{}").expect("the default store opens");
    let strategies = [
        busbar_kernel::config::STRATEGY_CHEAPEST,
        busbar_kernel::config::STRATEGY_FASTEST,
        busbar_kernel::config::STRATEGY_LEAST_BUSY,
        busbar_kernel::config::STRATEGY_USAGE,
    ];
    // Each linked hook door's claimed hook words (its Statement's `MARK_WORD_HOOK` marks).
    let words: Vec<Vec<String>> = crate::LINKED
        .hook_doors
        .iter()
        .map(|door| {
            let stated =
                crate::root::loader::dispatch::rendering_of(*door).expect("the door states");
            busbar_contract::abi::mechanism::rendering::read(&stated)
                .expect("the rendering reads")
                .mark_words
                .into_iter()
                .filter(|(class, _)| {
                    *class == busbar_contract::abi::mechanism::door::MARK_WORD_HOOK
                })
                .map(|(_, word)| word)
                .collect()
        })
        .collect();
    let want: Vec<Vec<String>> = if cfg!(linked_axis_hooks) {
        vec![strategies.iter().map(|s| s.to_string()).collect()]
    } else {
        Vec::new()
    };
    assert_eq!(words, want, "the ranking door claims every strategy word");
}

/// STORE-DEFAULT — THE DEFAULT GOVERNANCE STORE IS THE LINKED ROW THAT DECLARES ITSELF THE DEFAULT.
/// The root holds no store name: `default_store` asks each row. The declaring row is the default
/// wherever it sits in the table, a table with no claim has none, and the one-claim table is what the
/// kernel resolves an omitted `store.module` to once the rows are installed.
///
/// RED when the resolver reads a row's position or its name instead of its claim (e.g. "the first
/// row"): the declaring second row stops being the default.
#[test]
fn the_default_store_is_the_row_that_declares_it() {
    use busbar_kernel::preflight::LinkedStore;
    fn open(_: &str) -> Result<Box<dyn busbar_contract::records::RecordStore>, String> {
        Err("never opened".into())
    }
    extern "C" fn door() -> *const busbar_contract::abi::mechanism::door::Door {
        std::ptr::null()
    }
    const PLAIN: LinkedStore = ("acme-plain", false, false, open, door);
    const CLAIMS: LinkedStore = ("acme-default", true, true, open, door);
    assert_eq!(
        super::default_store(&[PLAIN, CLAIMS]),
        Ok(Some("acme-default"))
    );
    assert_eq!(
        super::default_store(&[CLAIMS, PLAIN]),
        Ok(Some("acme-default"))
    );
    assert_eq!(super::default_store(&[PLAIN]), Ok(None));
    assert_eq!(super::default_store(&[]), Ok(None));

    // The shipped table: the kernel's default is the one declaring row, and an omitted
    // `store.module` reads as it.
    let shipped = super::default_store(crate::LINKED.stores).expect("one claim");
    let declaring = crate::LINKED.stores.iter().find(|s| s.2).map(|s| s.0);
    assert_eq!((shipped, shipped.is_some()), (declaring, true));
}

/// STORE-DEFAULT — TWO ROWS DECLARING THE DEFAULT REFUSE BOOT, naming both, like any duplicate claim:
/// ambiguity is never resolved by picking a winner.
///
/// RED ARM: a resolver that takes the first claim (first-wins) answers `Ok(Some("acme-a"))` and the
/// refusal assertion fails; the single-claim arm beside it stays green.
#[test]
fn two_rows_declaring_the_default_refuse_boot() {
    use busbar_kernel::preflight::LinkedStore;
    fn open(_: &str) -> Result<Box<dyn busbar_contract::records::RecordStore>, String> {
        Err("never opened".into())
    }
    extern "C" fn door() -> *const busbar_contract::abi::mechanism::door::Door {
        std::ptr::null()
    }
    const A: LinkedStore = ("acme-a", true, true, open, door);
    const B: LinkedStore = ("acme-b", false, true, open, door);
    const C: LinkedStore = ("acme-c", false, false, open, door);
    assert_eq!(
        super::default_store(&[A, C, B]),
        Err(
            "linked stores 'acme-a' and 'acme-b' both declare themselves the default governance \
             store; a build links at most one default store"
                .to_string()
        )
    );
    assert_eq!(super::default_store(&[A, C]), Ok(Some("acme-a")));
}

/// WIRE-SECRET (THE DESIGN, "Plugins"; TODO step 28) — THE SECRET AXIS IS THE ROOT'S, OVER THE ONE
/// DISPATCHER. `env` and `file` are the linked secret plugins the root's axis answers for, by the
/// module alias their Statements declare; a reference resolves through the secret kind table on
/// `root::dispatch`'s dispatcher, on one shared instance, and the refusal text is the plugin's own
/// (1.5.5's). A module no plugin answers is refused.
///
/// RED by dropping a door from the linked table: `file` stops being linked.
#[test]
fn the_secret_axis_resolves_the_linked_sources_over_the_one_dispatcher() {
    use busbar_contract::secret::SecretAxis;
    let axis = super::link_secrets(crate::LINKED.secrets).expect("the linked secret doors state");
    assert!(axis.linked("env") && axis.linked("file") && !axis.answers("vault"));
    let env = axis.shared("env").expect("env opens");
    assert!(
        std::sync::Arc::ptr_eq(&env, &axis.shared("env").expect("env opens")),
        "one shared instance per linked plugin"
    );
    let var = "BUSBAR_WIRE_SECRET_ROOT_AXIS";
    std::env::set_var(var, "hunter2");
    let got = env
        .resolve(format!(r#"{{"key":"{var}"}}"#).as_bytes())
        .expect("a set variable resolves");
    assert_eq!(got.expose_secret().as_slice(), b"hunter2");
    std::env::remove_var(var);
    let refused = env
        .resolve(br#"{"key":"BUSBAR_WIRE_SECRET_ROOT_UNSET"}"#)
        .unwrap_err();
    assert_eq!(
        refused.text,
        "secret env:BUSBAR_WIRE_SECRET_ROOT_UNSET cannot resolve: environment variable \
         'BUSBAR_WIRE_SECRET_ROOT_UNSET' is unset"
    );
    assert!(axis.shared("vault").is_err());
}
