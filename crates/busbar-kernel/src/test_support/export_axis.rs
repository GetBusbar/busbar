// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE EXPORT AXIS a test binary resolves `export:` against. The kernel names no export plugin, so
//! the axis here is a plugin registry scanned out of a temp `plugins/` directory holding NEUTRAL
//! `kind: export` rows whose library bytes are not a library, and THE SCRAPE DOUBLE
//! ([`ScrapeDouble`]): an in-process sink answering the frozen scrape module word (R-FIX3: the
//! kernel's own tests use in-crate doubles; the real scrape sink's proofs live with the composition
//! root, which links it).

use busbar_contract::abi::export::ExportStream;
use busbar_plugin_loader::{
    dispatch::{DispatchConfig, Dispatcher},
    export_axis::ExportRows,
    PluginRegistry,
};

/// A structurally valid, unsigned `kind: export` tarball named `name`/`alias` over `lib`.
fn write_row(dir: &std::path::Path, name: &str, alias: &str, lib: &[u8]) {
    let m = busbar_plugin_loader::sign::Manifest {
        name: name.into(),
        alias: alias.into(),
        kind: "export".into(),
        version: "1.6.0".into(),
        publisher: "acme".into(),
        abi_version: *busbar_plugin_loader::supported_abi("export")
            .iter()
            .max()
            .expect("an export payload schema"),
        sha256: busbar_plugin_loader::sign::sha256_hex(lib),
        signature: String::new(),
        description: String::new(),
        homepage: String::new(),
        license: String::new(),
        needs: Default::default(),
        settings_schema: None,
        schema_derived: false,
        host: None,
        ..Default::default()
    };
    let bytes = busbar_plugin_loader::tarball::package(&m, "lib.so", lib).expect("package");
    std::fs::write(dir.join(format!("{name}.tar.gz")), bytes).expect("write the tarball");
}

/// A registry scanned from a fresh directory holding one export row per `(name, alias)`.
pub fn registry_of(tag: &str, rows: &[(&str, &str)]) -> PluginRegistry {
    let dir = std::env::temp_dir().join(format!("busbar-export-axis-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("plugins dir");
    for (name, alias) in rows {
        write_row(&dir, name, alias, b"not a library");
    }
    let plugins: crate::config::PluginsCfg = serde_json::from_value(serde_json::json!({
        "enabled": true,
        "dir": dir.display().to_string(),
        "trust": { "allow_unsigned": true },
    }))
    .expect("a plugins block");
    let policy = crate::test_support::trust_policy(&plugins).expect("a trust policy");
    busbar_plugin_loader::scan_and_validate(&dir, &policy).expect("the scan")
}

/// The registry the stand-in axis reads, kept for the test binary's life. Unset = no export module
/// resolves (a test binary that installs none).
static REGISTRY: std::sync::OnceLock<&'static PluginRegistry> = std::sync::OnceLock::new();

/// The registry [`install_export_axis_with`] builds, owned for the test binary's life.
static BUILT: std::sync::OnceLock<PluginRegistry> = std::sync::OnceLock::new();

/// THE STAND-IN EXPORT AXIS: `preflight::RootInstall`'s `export_axis` in a test build (a test build
/// has no root). It answers over the registry installed here, on one test dispatcher, through the
/// export rows the root's axis answers with.
#[derive(Debug)]
pub struct StandIn;

/// The stand-in axis `preflight::RootInstall` holds in a test build.
pub static STAND_IN: StandIn = StandIn;

fn rows() -> Option<ExportRows<'static>> {
    static DISPATCHER: std::sync::OnceLock<std::sync::Arc<Dispatcher>> = std::sync::OnceLock::new();
    let registry = REGISTRY.get()?;
    // The kernel's own host services, so an opened sink's `serve` reads the host snapshot
    // service as it does in a booted process.
    let dispatcher = DISPATCHER.get_or_init(|| {
        std::sync::Arc::new(Dispatcher::with_services(
            DispatchConfig::default(),
            std::sync::Arc::new(crate::host_services::KernelServices::new()),
        ))
    });
    Some(ExportRows::new(registry, dispatcher.clone()))
}

impl busbar_contract::export_calls::ExportAxis for StandIn {
    fn probe(
        &self,
        module: &str,
        instance: &str,
        settings: &serde_json::Value,
    ) -> Option<busbar_contract::export_calls::Probed> {
        let rows = rows()?;
        match by_double(&rows, module) {
            Some(_) => Some(ScrapeDouble::probed()),
            None => rows.probe(module, instance, settings),
        }
    }

    fn check(
        &self,
        module: &str,
        phase: u32,
        instances: &[(String, serde_json::Value)],
    ) -> Option<Vec<String>> {
        let rows = rows()?;
        match by_double(&rows, module) {
            Some(_) => Some(ScrapeDouble::check(phase, instances)),
            None => rows.check(module, phase, instances),
        }
    }

    fn open(
        &self,
        module: &str,
        label: &str,
        settings: &serde_json::Value,
    ) -> Result<std::sync::Arc<dyn busbar_contract::export_calls::ExportCalls>, String> {
        let rows =
            rows().ok_or_else(|| format!("no `kind: export` plugin answers to '{module}'"))?;
        match by_double(&rows, module) {
            Some(double) => Ok(std::sync::Arc::new(double)),
            None => rows.open(module, label, settings),
        }
    }

    fn linked(&self, module: &str) -> bool {
        rows().is_some_and(|r| by_double(&r, module).is_some() || r.linked(module))
    }

    fn first_party(&self, module: &str) -> bool {
        rows().is_some_and(|r| by_double(&r, module).is_some() || r.first_party(module))
    }

    fn one_instance(&self, module: &str) -> bool {
        rows().is_some_and(|r| by_double(&r, module).is_some() || r.one_instance(module))
    }

    fn linked_modules(&self) -> Vec<String> {
        rows()
            .map(|r| {
                let mut linked = r.linked_modules();
                if by_double(&r, scrape_module()).is_some() {
                    // Linked ahead of the neutral rows, as the root links its scrape sink.
                    linked.insert(0, scrape_module().to_string());
                }
                linked
            })
            .unwrap_or_default()
    }

    fn routes(&self, module: &str) -> Vec<busbar_contract::abi::mechanism::route::Route> {
        rows()
            .map(|r| match by_double(&r, module) {
                Some(_) => lines_routes().to_vec(),
                None => r.routes(module),
            })
            .unwrap_or_default()
    }
}

/// THE FROZEN SCRAPE MODULE WORD: the `module:` backing the 1.5.x type key whose default instance is
/// named for the `metrics` stream (the root legacy table's `export_type_keys` row, read through the
/// migrator's own `config::migrate_export::export_type_keys`: 1.5.5's spelling of the scrape
/// sink, which `--migrate-config` writes). The double answers to it; the kernel spells no export
/// module.
#[must_use]
pub fn scrape_module() -> &'static str {
    crate::config::migrate_export::export_type_keys()
        .into_iter()
        .find(|(_, instance, _)| *instance == ExportStream::Metrics.as_token())
        .map_or("", |(_, _, module)| module)
}

/// The scrape double, when `module` is the word it answers to and no row of the installed registry
/// answers to it (a test binary that links a real sink under that word is answered by the sink).
fn by_double(rows: &ExportRows<'static>, module: &str) -> Option<ScrapeDouble> {
    let word = scrape_module();
    (!word.is_empty()
        && module == word
        && rows
            .probe(module, module, &serde_json::Value::Null)
            .is_none())
    .then_some(ScrapeDouble)
}

/// THE SCRAPE DOUBLE (R-FIX3): the stand-in axis's answer for [`scrape_module`] when no row of the
/// installed registry answers to it — a FIRST-PARTY, `one_instance` sink carrying exactly the
/// `metrics` stream and declaring the two well-known scrape routes. It is not a plugin and not a
/// door: it answers in process, its words are its own, and it validates nothing (the recorder's
/// settings are the kernel's to read off the scrape instance). Opened, it renders a snapshot as the
/// test view ([`lines`]) and serves `/metrics` and `/metrics/hooks` from the host snapshot service
/// under content types of its own ([`SCRAPE_DOUBLE_CONTENT_TYPE`],
/// [`SCRAPE_DOUBLE_HOOKS_CONTENT_TYPE`]), so a test can see the kernel passes an answer through
/// verbatim. What the REAL scrape sink renders and words is proven where it is linked
/// (`crates/busbar/src/root/tests/linked.rs`).
#[derive(Debug, Clone, Copy)]
pub struct ScrapeDouble;

/// The content type the double answers `/metrics` with.
pub const SCRAPE_DOUBLE_CONTENT_TYPE: &str = "text/plain; scrape-double=metrics";

/// The content type the double answers `/metrics/hooks` with.
pub const SCRAPE_DOUBLE_HOOKS_CONTENT_TYPE: &str = "text/plain; scrape-double=hooks";

/// The stream set the double carries: `metrics`, alone.
const SCRAPE_DOUBLE_STREAM_SET: &[u8] = &[ExportStream::Metrics as u8];

impl ScrapeDouble {
    /// What the axis's `probe` states for the double: the `metrics` stream, and no refusal.
    fn probed() -> busbar_contract::export_calls::Probed {
        (Some(SCRAPE_DOUBLE_STREAM_SET.to_vec()), Vec::new())
    }

    /// The double's own LIMITS check across `instances` (configuration order): one line per
    /// instance after the first, naming the first, in the double's words. Any other phase finds
    /// nothing.
    #[must_use]
    pub fn check(phase: u32, instances: &[(String, serde_json::Value)]) -> Vec<String> {
        if phase != busbar_contract::abi::export::CHECK_PHASE_LIMITS {
            return Vec::new();
        }
        let Some(((first, _), rest)) = instances.split_first() else {
            return Vec::new();
        };
        rest.iter()
            .map(|(name, _)| {
                format!("export.{name}: the scrape double takes one instance, and '{first}' is it")
            })
            .collect()
    }
}

impl busbar_contract::export_calls::ExportCalls for ScrapeDouble {
    fn streams(&self) -> &[u8] {
        SCRAPE_DOUBLE_STREAM_SET
    }
    fn routes(&self) -> &[busbar_contract::abi::mechanism::route::Route] {
        lines_routes()
    }
    fn deliver(
        &self,
        _: u8,
        _: Vec<u8>,
        _: Box<dyn Send>,
    ) -> busbar_contract::export_calls::Delivered {
        busbar_contract::export_calls::Delivered::Shed
    }
    fn scrape(
        &self,
        families: &[busbar_contract::export_calls::Family],
    ) -> Result<Vec<u8>, String> {
        Ok(lines(families).into_bytes())
    }
    fn status(&self) -> Option<Vec<u8>> {
        None
    }
    fn serve(
        &self,
        req: &busbar_contract::export_calls::ServeRequest<'_>,
    ) -> Result<busbar_contract::export_calls::Served, String> {
        let content_type = match req.path {
            "/metrics" => SCRAPE_DOUBLE_CONTENT_TYPE,
            "/metrics/hooks" => SCRAPE_DOUBLE_HOOKS_CONTENT_TYPE,
            other => return Err(format!("the scrape double serves no {other}")),
        };
        serve_snapshot(req.path, content_type)
    }
}

/// The axis every test in this binary resolves `export:` against — installed once, as the
/// composition root does. Besides a neutral row (`k9-axis-sink`, alias `k9-tail`) it holds a row
/// spelling each FIRST-PARTY sink's frozen module name (`request-log-file`, K9b;
/// `request-log-webhook`, K9c; `otlp`, K9e-2): a linked build resolves that module on its axis, so a
/// test configuration naming it resolves here too. The rows' bytes are not a library, so each sink
/// validates nothing and opens nothing — enough for the configuration layer, which is all a kernel
/// test drives. The scrape module word ([`scrape_module`]) is answered by the [`ScrapeDouble`],
/// linked ahead of the rows.
pub fn install_export_axis() {
    install_export_axis_with(Vec::new());
}

/// [`install_export_axis`], with `linked` registered ahead of the neutral rows through the linked
/// door — for a test binary that links a sink of its own. The first install holds.
pub fn install_export_axis_with(linked: Vec<busbar_plugin_loader::LinkedPlugin>) {
    let built = BUILT.get_or_init(|| {
        let rows = [
            ("k9-axis-sink", "k9-tail"),
            ("k9b-log-file", "request-log-file"),
            ("k9c-webhook", "request-log-webhook"),
            (
                "k9e-otlp",
                crate::config::legacy::text("export_trace_module"),
            ),
        ];
        let scanned = registry_of("installed", &rows);
        scanned
            .link(linked)
            .expect("the linked door admits the rows")
    });
    let _ = REGISTRY.set(built);
}

/// A FIRST-PARTY memory-ABI sink linked as the composition root links it, by its `door` (its logic
/// crate's `plugin_door!`), under `name`/`alias` — for a test binary whose axis must know that sink.
pub fn install_first_party_door(
    name: &str,
    alias: &str,
    door: busbar_contract::abi::mechanism::door::DoorFn,
) {
    install_export_axis_with(vec![busbar_plugin_loader::LinkedPlugin::first_party_door(
        "export", name, alias, door,
    )]);
}

/// THE TEST VIEW of a scrape snapshot: each family's `# HELP` (when it has one) and `# TYPE` lines,
/// its samples as `name{labels} value`, and a blank line — the layout every test that asserts on an
/// observation by line reads. A test's own view, never served: what an operator scrapes is the
/// export plugin's rendering.
#[must_use]
pub fn lines(families: &[busbar_contract::export_calls::Family]) -> String {
    let mut out = String::new();
    for f in families {
        if let Some(help) = &f.help {
            out.push_str(&format!("# HELP {} {help}\n", f.name));
        }
        let kind = busbar_contract::export_calls::type_word(f.kind).unwrap_or("untyped");
        out.push_str(&format!("# TYPE {} {kind}\n", f.name));
        for s in &f.samples {
            let labels: Vec<String> = s
                .labels
                .iter()
                .map(|(k, v)| format!("{k}=\"{v}\""))
                .collect();
            let set = if labels.is_empty() {
                String::new()
            } else {
                format!("{{{}}}", labels.join(","))
            };
            out.push_str(&format!("{}{set} {}\n", s.name, s.value));
        }
        out.push('\n');
    }
    out
}

/// A NEUTRAL scrape sink for a test app's `/metrics` and `/metrics/hooks` (a test app has no
/// `export:` block): it declares both routes, as the scrape sink does, and answers them from the
/// host snapshot service, rendered as [`lines`]; it carries nothing.
#[derive(Debug)]
pub struct LinesSink;

/// The routes [`LinesSink`] declares: the scrape sink's two well-known paths, behind the key.
fn lines_routes() -> &'static [busbar_contract::abi::mechanism::route::Route] {
    use busbar_contract::abi::mechanism::route::{Route, RouteAuth, RouteMethod};
    static ROUTES: std::sync::OnceLock<Vec<Route>> = std::sync::OnceLock::new();
    ROUTES.get_or_init(|| {
        ["/metrics", "/metrics/hooks"]
            .map(|path| Route {
                path: path.to_string(),
                method: RouteMethod::Get,
                auth: RouteAuth::Key,
            })
            .to_vec()
    })
}

impl busbar_contract::export_calls::ExportCalls for LinesSink {
    fn streams(&self) -> &[u8] {
        &[]
    }
    fn routes(&self) -> &[busbar_contract::abi::mechanism::route::Route] {
        lines_routes()
    }
    fn deliver(
        &self,
        _: u8,
        _: Vec<u8>,
        _: Box<dyn Send>,
    ) -> busbar_contract::export_calls::Delivered {
        busbar_contract::export_calls::Delivered::Shed
    }
    fn scrape(
        &self,
        families: &[busbar_contract::export_calls::Family],
    ) -> Result<Vec<u8>, String> {
        Ok(lines(families).into_bytes())
    }
    fn status(&self) -> Option<Vec<u8>> {
        None
    }
    fn serve(
        &self,
        req: &busbar_contract::export_calls::ServeRequest<'_>,
    ) -> Result<busbar_contract::export_calls::Served, String> {
        serve_snapshot(req.path, "text/plain; version=0.0.4")
    }
}

/// `/metrics` or `/metrics/hooks` answered from the host snapshot service, rendered as [`lines`]
/// under `content_type`: `503` with `retry-after` while the recorder is not installed; a read the
/// host refuses (no grant, an unknown scope) is the sink's failure.
fn serve_snapshot(
    path: &str,
    content_type: &str,
) -> Result<busbar_contract::export_calls::Served, String> {
    use busbar_contract::abi::host::service::{SNAPSHOT_SCOPE_HOOKS, SNAPSHOT_SCOPE_WHOLE};
    use busbar_contract::services::Snapshot;
    let scope = match path {
        "/metrics" => SNAPSHOT_SCOPE_WHOLE,
        "/metrics/hooks" => SNAPSHOT_SCOPE_HOOKS,
        other => return Err(format!("the test scrape sink serves no {other}")),
    };
    let served = |status, headers: Vec<(&str, &str)>, body| {
        Ok(busbar_contract::export_calls::Served {
            status,
            headers: headers
                .into_iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect(),
            body,
        })
    };
    match crate::export::scrape::read(scope) {
        Snapshot::Families(f) => served(
            200,
            vec![("content-type", content_type)],
            lines(&f).into_bytes(),
        ),
        Snapshot::NotReady => served(503, vec![("retry-after", "1")], Vec::new()),
        Snapshot::Refused(why) => Err(why.to_string()),
    }
}

/// The scrape routes of a test app, declared and answered by [`LinesSink`] through the snapshot
/// grant, as a scrape sink's are.
pub(crate) fn lines_scrape_routes() -> Vec<crate::plugin_routes::RouteDecl> {
    let sink: std::sync::Arc<dyn busbar_contract::export_calls::ExportCalls> =
        std::sync::Arc::new(LinesSink);
    let dispatch: std::sync::Arc<dyn crate::plugin_routes::PluginHttpDispatch> =
        std::sync::Arc::new(crate::export::scrape::Granted(
            crate::export::plugin::served(sink.clone()),
        ));
    sink.routes()
        .iter()
        .map(|route| crate::plugin_routes::RouteDecl {
            owner: "metrics".into(),
            kind: crate::plugin_routes::RouteKind::Export,
            route: route.clone(),
            scrape: true,
            dispatch: dispatch.clone(),
        })
        .collect()
}
