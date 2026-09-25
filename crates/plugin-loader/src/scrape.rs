// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE RECORDER SNAPSHOT (K9a S6) — the host side of [`ExportRequest::Scrape`].
//!
//! The host's recorder is the host's: ~57 emit sites write it, and a dropped-in sink links its own
//! `metrics` facade, so a sink can never read it directly (the #11 trap BUSBAR-1.6.0 names). What
//! crosses instead is a SNAPSHOT of what the recorder renders, in the stable [`MetricFamily`]
//! shape, which the sink renders its exposition from.
//!
//! [`snapshot`] reads the recorder's text exposition — the families it writes, each `# HELP`
//! (optional), `# TYPE`, its samples, and a blank line — into that shape LOSSLESSLY: every label
//! value and every number is carried as the recorder spelled it, so rendering the snapshot back in
//! the same format reproduces the recorder's bytes exactly. Anything the reader cannot place is
//! refused rather than approximated — a snapshot that could not render back byte-identically would
//! be a scrape that silently differs.

use crate::DynExport;
use busbar_plugin::cold::export::{ExportRequest, ExportResponse, MetricFamily, MetricSample};

/// Read a text exposition into the recorder snapshot's families, in order.
pub fn snapshot(exposition: &str) -> Result<Vec<MetricFamily>, String> {
    if !exposition.is_empty() && !exposition.ends_with('\n') {
        return Err("the exposition does not end with a newline".into());
    }
    let mut families = Vec::new();
    let mut open: Option<MetricFamily> = None;
    for (n, line) in exposition.split_terminator('\n').enumerate() {
        let at = |why: &str| format!("exposition line {}: {why}", n + 1);
        if line.is_empty() {
            families.push(
                open.take()
                    .ok_or_else(|| at("a blank line closes no family"))?,
            );
        } else if let Some(rest) = line.strip_prefix("# HELP ") {
            if open.is_some() {
                return Err(at("a HELP line inside an unclosed family"));
            }
            let (name, help) = rest
                .split_once(' ')
                .ok_or_else(|| at("a HELP line with no text"))?;
            open = Some(family(name, String::new(), Some(help.to_string())));
        } else if let Some(rest) = line.strip_prefix("# TYPE ") {
            let (name, kind) = rest
                .split_once(' ')
                .ok_or_else(|| at("a TYPE line with no type"))?;
            match &mut open {
                None => open = Some(family(name, kind.to_string(), None)),
                Some(f) if f.name == name && f.kind.is_empty() => f.kind = kind.to_string(),
                Some(_) => return Err(at("a TYPE line that does not open or type its family")),
            }
        } else {
            let f = open
                .as_mut()
                .filter(|f| !f.kind.is_empty())
                .ok_or_else(|| at("a sample outside a typed family"))?;
            f.samples.push(sample(line).map_err(|why| at(&why))?);
        }
    }
    match open {
        Some(f) => Err(format!("the family '{}' is not closed", f.name)),
        None => Ok(families),
    }
}

fn family(name: &str, kind: String, help: Option<String>) -> MetricFamily {
    let (name, samples) = (name.to_string(), Vec::new());
    MetricFamily {
        name,
        kind,
        help,
        samples,
    }
}

/// One sample line: `name[{k="v",…}] value`, the label values and the value kept as written.
fn sample(line: &str) -> Result<MetricSample, String> {
    let name_end = line.find(['{', ' ']).ok_or("a sample with no value")?;
    let name = line[..name_end].to_string();
    let mut rest = &line[name_end..];
    let mut labels = Vec::new();
    if let Some(mut body) = rest.strip_prefix('{') {
        loop {
            let (key, tail) = body.split_once("=\"").ok_or("a label with no value")?;
            let end = value_end(tail).ok_or("an unterminated label value")?;
            labels.push((key.to_string(), tail[..end].to_string()));
            match tail[end + 1..].split_at_checked(1) {
                Some((",", next)) => body = next,
                Some(("}", after)) => {
                    rest = after;
                    break;
                }
                _ => return Err("a label set that does not close".into()),
            }
        }
    }
    let value = rest.strip_prefix(' ').ok_or("a sample with no value")?;
    if name.is_empty() || key_is_bad(&labels) || value.is_empty() || value.contains(' ') {
        return Err("a sample that is not `name[{labels}] value`".into());
    }
    let value = value.to_string();
    Ok(MetricSample {
        name,
        labels,
        value,
    })
}

/// A label key that could not render back as written.
fn key_is_bad(labels: &[(String, String)]) -> bool {
    labels
        .iter()
        .any(|(k, _)| k.is_empty() || k.contains([',', '{', '}', '"', ' ']))
}

/// Where an escaped label value ends: the first `"` no backslash escapes.
fn value_end(escaped: &str) -> Option<usize> {
    let mut quoted = false;
    for (i, c) in escaped.char_indices() {
        match (quoted, c) {
            (true, _) => quoted = false,
            (false, '\\') => quoted = true,
            (false, '"') => return Some(i),
            _ => {}
        }
    }
    None
}

impl DynExport {
    /// Hand the sink the recorder snapshot and take back the exposition it rendered:
    /// `(content_type, body)`. A sink that cannot decode the op says so out of band — it renders
    /// nothing, and the host keeps rendering its own.
    pub fn scrape(&self, families: Vec<MetricFamily>) -> Result<(String, String), String> {
        let req = ExportRequest::Scrape { families };
        match self
            .raw
            .transport_call::<ExportRequest, ExportResponse>(&req)?
        {
            ExportResponse::Exposition { content_type, body } => Ok((content_type, body)),
            other => Err(format!(
                "export plugin '{}' returned an unexpected response to scrape: {other:?}",
                self.raw.path
            )),
        }
    }
}

impl crate::PluginRegistry {
    /// THE SCRAPE SINK QUESTION, asked while the host validates its configuration (K9d): does the
    /// sink `module` names carry the `metrics` stream and claim a route at `path` — the well-known
    /// exposition path the host serves by snapshotting its recorder and having that sink render?
    /// The claimed route, as the sink declared it; `None` for a module that is not a `kind: export`
    /// row, a sink that will not open here (its open refuses the boot naming the instance), or one
    /// that claims no such route.
    pub fn scrape_route(
        &self,
        module: &str,
        path: &str,
        settings: &serde_json::Value,
    ) -> Option<busbar_plugin::cold::endpoint::Route> {
        let p = self
            .resolve(module)
            .filter(|p| p.manifest.kind == busbar_plugin::cold::kind::EXPORT)?;
        let cfg = settings.to_string();
        let sink =
            crate::load_export_image(p.image(), &cfg, &p.manifest.name, &p.manifest.kind).ok()?;
        let metrics = sink
            .streams()
            .contains(&busbar_plugin::cold::export::ExportStream::Metrics);
        let claimed = sink.routes().iter().find(|r| r.path == path).cloned();
        claimed.filter(|_| metrics)
    }
}

#[cfg(test)]
#[path = "tests/scrape_tests.rs"]
pub(crate) mod tests;
