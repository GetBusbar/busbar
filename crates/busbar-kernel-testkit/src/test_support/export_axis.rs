// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use busbar_contract::abi::export::ExportStream;

pub const NO_DOOR: &str = "it states no export door (the 1.5.5 JSON export contract, which this host does not load) — rebuild the plugin against the 1.6.0 SDK";

/// One neutral dropped-in `kind: export` row: its canonical name and its alias.
#[derive(Debug, Clone)]
struct NeutralRow {
    name: String,
    alias: String,
}

static ROWS: std::sync::OnceLock<Vec<NeutralRow>> = std::sync::OnceLock::new();

/// THE STAND-IN EXPORT AXIS: `preflight::RootInstall`'s `export_axis` in a test build (a test build
/// has no root). It answers over the rows [`install_export_axis`] installs, in process.
#[derive(Debug)]
pub struct StandIn;

pub static STAND_IN: StandIn = StandIn;

fn rows() -> Option<&'static [NeutralRow]> {
    ROWS.get().map(Vec::as_slice)
}

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

            None => row(rows, module).map(|_| (None, Vec::new())),
        }
    }

    fn check(
        &self,
        module: &str,
        phase: u32,
        instances: &[(String, &serde_json::Value)],
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
            .map(|_| vec![scrape_module().to_string()])
            .unwrap_or_default()
    }

    fn routes(&self, module: &str) -> Vec<busbar_contract::abi::mechanism::route::Route> {
        rows()
            .and_then(|r| by_double(r, module))
            .map(|_| lines_routes().to_vec())
            .unwrap_or_default()
    }

    fn public_routes(&self, module: &str) -> Vec<String> {
        self.routes(module).into_iter().map(|r| r.path).collect()
    }

    fn persistent_routes(&self, module: &str) -> Vec<String> {
        self.public_routes(module)
            .into_iter()
            .filter(|p| p == "/metrics/hooks")
            .collect()
    }
}

#[must_use]
pub fn scrape_module() -> &'static str {
    crate::config::migration_table::pairs("export_type_keys")
        .into_iter()
        .filter_map(|(_, fields)| {
            let mut field = fields.split(':');
            Some((field.next()?, field.next()?))
        })
        .find(|(instance, _)| *instance == ExportStream::Metrics.as_token())
        .map_or("", |(_, module)| module)
}

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

pub const SCRAPE_DOUBLE_CONTENT_TYPE: &str = "text/plain; scrape-double=metrics";

pub const SCRAPE_DOUBLE_HOOKS_CONTENT_TYPE: &str = "text/plain; scrape-double=hooks";

const SCRAPE_DOUBLE_STREAM_SET: &[u8] = &[ExportStream::Metrics as u8];

impl ScrapeDouble {
    fn probed() -> busbar_contract::export_calls::Probed {
        (Some(SCRAPE_DOUBLE_STREAM_SET.to_vec()), Vec::new())
    }

    #[must_use]
    pub fn check(phase: u32, instances: &[(String, &serde_json::Value)]) -> Vec<String> {
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
    fn public_routes(&self) -> &[String] {
        public_paths()
    }
    fn persistent_routes(&self) -> &[String] {
        persistent_paths()
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

fn public_paths() -> &'static [String] {
    static PATHS: std::sync::OnceLock<Vec<String>> = std::sync::OnceLock::new();
    PATHS.get_or_init(|| lines_routes().iter().map(|r| r.path.clone()).collect())
}

fn persistent_paths() -> &'static [String] {
    static PATHS: std::sync::OnceLock<Vec<String>> = std::sync::OnceLock::new();
    PATHS.get_or_init(|| vec!["/metrics/hooks".into()])
}

impl busbar_contract::export_calls::ExportCalls for LinesSink {
    fn streams(&self) -> &[u8] {
        &[]
    }
    fn routes(&self) -> &[busbar_contract::abi::mechanism::route::Route] {
        lines_routes()
    }
    fn public_routes(&self) -> &[String] {
        public_paths()
    }
    fn persistent_routes(&self) -> &[String] {
        persistent_paths()
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
    match crate::export::read_test_snapshot(scope) {
        Snapshot::Families(f) => served(
            200,
            vec![("content-type", content_type)],
            lines(&f).into_bytes(),
        ),
        Snapshot::NotReady => served(503, vec![("retry-after", "1")], Vec::new()),
        Snapshot::Refused(why) => Err(why.to_string()),
    }
}

pub(crate) fn lines_scrape_routes() -> Vec<crate::plugin_routes::RouteDecl> {
    let sink: std::sync::Arc<dyn busbar_contract::export_calls::ExportCalls> =
        std::sync::Arc::new(LinesSink);
    let dispatch = crate::export::serve_test_sink(sink.clone());
    sink.routes()
        .iter()
        .map(|route| crate::plugin_routes::RouteDecl {
            owner: "metrics".into(),
            source_instance: "metrics".into(),
            dispatch_available: true,
            kind: crate::plugin_routes::RouteKind::Export,
            route: route.clone(),
            scrape: true,
            persistent: route.path == "/metrics/hooks",
            dispatch: dispatch.clone(),
        })
        .collect()
}

pub fn render() -> String {
    lines(&busbar_kernel::snapshot::snapshot().unwrap_or_default())
}
