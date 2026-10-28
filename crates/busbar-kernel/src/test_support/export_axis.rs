// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE EXPORT AXIS a test binary resolves `export:` against. The kernel names no export plugin and
//! no loader (BUSBAR-1.6.0.md THE DESIGN l.322), so the axis here answers IN PROCESS: a set of
//! NEUTRAL dropped-in `kind: export` rows that state no door, and THE SCRAPE DOUBLE
//! ([`ScrapeDouble`]), an in-process sink answering the frozen scrape module word (R-FIX3: the
//! kernel's own tests use in-crate doubles; the real scrape sink's proofs live with the composition
//! root, which links it).
//!
//! WHAT THE NEUTRAL ROWS ANSWER mirrors what the loader's export rows (`ExportRows`,
//! `crates/plugin-loader/src/export_axis.rs`) answered for the unsigned rows this kit once packed
//! over bytes that are not a library and scanned: such a row RESOLVES (by its canonical name or its
//! alias), so `probe` states no streams and no problem and `check` finds nothing (the row "will not
//! load here: its open refuses the boot naming the instance"); `open` refuses, naming the row and
//! the rebuild ([`NO_DOOR`], the loader's words); and the row is neither linked nor first-party,
//! states no `one_instance` mark and declares no route. How the loader admits, binds and opens a
//! real export row is the loader's and the root's to prove (`crates/plugin-loader`,
//! `crates/busbar/tests`).

use busbar_contract::abi::export::ExportStream;

/// Why a neutral row does not open: it states no export door (the loader's `NO_DOOR`, verbatim).
pub const NO_DOOR: &str = "it states no export door (the 1.5.5 JSON export contract, which this host does not load) — rebuild the plugin against the 1.6.0 SDK";

/// One neutral dropped-in `kind: export` row: its canonical name and its alias.
#[derive(Debug, Clone)]
struct NeutralRow {
    name: String,
    alias: String,
}

/// The neutral rows the stand-in axis answers, kept for the test binary's life. Unset = no export
/// module resolves (a test binary that installs none), the scrape double's word included.
static ROWS: std::sync::OnceLock<Vec<NeutralRow>> = std::sync::OnceLock::new();

/// THE STAND-IN EXPORT AXIS: `preflight::RootInstall`'s `export_axis` in a test build (a test build
/// has no root). It answers over the rows [`install_export_axis`] installs, in process.
#[derive(Debug)]
pub struct StandIn;

/// The stand-in axis `preflight::RootInstall` holds in a test build.
pub static STAND_IN: StandIn = StandIn;

/// The installed rows, `None` before [`install_export_axis`].
fn rows() -> Option<&'static [NeutralRow]> {
    ROWS.get().map(Vec::as_slice)
}

/// The neutral row `module` resolves to: canonical name first, then alias (the registry's order).
fn row<'r>(rows: &'r [NeutralRow], module: &str) -> Option<&'r NeutralRow> {
    rows.iter()
        .find(|r| r.name == module)
        .or_else(|| rows.iter().find(|r| r.alias == module))
}

impl busbar_contract::export_calls::ExportAxis for StandIn {
    fn probe(
        &self,
        module: &str,
        _instance: &str,
        _settings: &serde_json::Value,
    ) -> Option<busbar_contract::export_calls::Probed> {
        let rows = rows()?;
        match by_double(rows, module) {
            Some(_) => Some(ScrapeDouble::probed()),
            // It will not load here: its open refuses the boot naming the instance.
            None => row(rows, module).map(|_| (None, Vec::new())),
        }
    }

    fn check(
        &self,
        module: &str,
        phase: u32,
        instances: &[(String, serde_json::Value)],
    ) -> Option<Vec<String>> {
        let rows = rows()?;
        match by_double(rows, module) {
            Some(_) => Some(ScrapeDouble::check(phase, instances)),
            None => row(rows, module).map(|_| Vec::new()),
        }
    }

    fn open(
        &self,
        module: &str,
        _label: &str,
        _settings: &serde_json::Value,
    ) -> Result<std::sync::Arc<dyn busbar_contract::export_calls::ExportCalls>, String> {
        let unanswered = || format!("no `kind: export` plugin answers to '{module}'");
        let rows = rows().ok_or_else(unanswered)?;
        match by_double(rows, module) {
            Some(double) => Ok(std::sync::Arc::new(double)),
            None => {
                let r = row(rows, module).ok_or_else(unanswered)?;
                Err(format!("export plugin '{}': {NO_DOOR}", r.name))
            }
        }
    }

    fn linked(&self, module: &str) -> bool {
        rows().is_some_and(|r| by_double(r, module).is_some())
    }

    fn first_party(&self, module: &str) -> bool {
        rows().is_some_and(|r| by_double(r, module).is_some())
    }

    fn one_instance(&self, module: &str) -> bool {
        rows().is_some_and(|r| by_double(r, module).is_some())
    }

    fn linked_modules(&self) -> Vec<String> {
        rows()
            .filter(|r| by_double(r, scrape_module()).is_some())
            // Linked as the root links its scrape sink; the neutral rows are dropped in.
            .map(|_| vec![scrape_module().to_string()])
            .unwrap_or_default()
    }

    fn routes(&self, module: &str) -> Vec<busbar_contract::abi::mechanism::route::Route> {
        rows()
            .and_then(|r| by_double(r, module))
            .map(|_| lines_routes().to_vec())
            .unwrap_or_default()
    }
}

/// THE FROZEN SCRAPE MODULE WORD: the `module:` backing the 1.5.x type key whose default instance is
/// named for the `metrics` stream (the root migration table's `export_type_keys` row, read through the
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

/// The scrape double, when `module` is the word it answers to and no neutral row answers to it (the
/// installed rows leave that word to the double).
fn by_double(rows: &[NeutralRow], module: &str) -> Option<ScrapeDouble> {
    let word = scrape_module();
    (!word.is_empty() && module == word && row(rows, module).is_none()).then_some(ScrapeDouble)
}

/// THE SCRAPE DOUBLE (R-FIX3): the stand-in axis's answer for [`scrape_module`] when no neutral
/// row answers to it — a FIRST-PARTY, `one_instance` sink carrying exactly the
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
/// for each FIRST-PARTY sink's frozen 1.5.5 module word but the scrape one, read off the root
/// migration table's `export_modules` row (K9b, K9c, K9e-2): a linked build resolves that module on
/// its axis, so a test configuration naming it resolves here too. The host spells none of them.
/// The rows state no door, so each sink validates nothing and opens nothing (see the module doc) —
/// enough for the configuration layer, which is all a kernel test drives. The scrape module word
/// ([`scrape_module`]) is answered by the [`ScrapeDouble`], linked ahead of the rows. The first
/// install holds.
pub fn install_export_axis() {
    let _ = ROWS.get_or_init(|| {
        let modules = crate::config::migration_table::text("export_modules")
            .split(" | ")
            .filter(|module| !module.is_empty() && *module != scrape_module());
        let mut rows = vec![NeutralRow {
            name: "k9-axis-sink".to_string(),
            alias: "k9-tail".to_string(),
        }];
        rows.extend(modules.enumerate().map(|(n, module)| NeutralRow {
            name: format!("k9-first-party-sink-{n}"),
            alias: module.to_string(),
        }));
        rows
    });
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
