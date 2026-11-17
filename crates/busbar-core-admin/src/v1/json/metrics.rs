// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! `GET /metrics` and `GET /metrics/hooks` on the admin listener (ADMIN-API-1.6 section 12): one
//! registry, three representations chosen by `Accept`. The text forms come from core's own encoder
//! (`crate::metrics_text`); the JSON form is the same families, generalised from `/telemetry`.

use std::sync::Arc;

use axum::extract::State;
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Extension;
use busbar_contract::abi::export as kinds;
use busbar_contract::export_calls::Family;
use busbar_kernel::export::BudgetedScrapeRefusal;
use busbar_kernel::export::ScrapeRefusal;
use busbar_kernel::limits::output::{Captured, OutputBuffer, OutputError};
use busbar_kernel::limits::process_admission::RequestLease;
use serde::{Serialize, Serializer};

use super::{err_json, err_json_cond};
use crate::metrics_text::{encode, Format};
use crate::v1::contract::taxonomy::Cond;
use crate::v1::contract::AdminError;
use busbar_kernel::state::AppHandle;

/// The representation `Accept` selects.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum Representation {
    Text(Format),
    Json,
}

/// The first recognised media type in `Accept` order wins; an absent header, `*/*` or nothing
/// recognised is Prometheus text. A media type with `q=0` is skipped.
pub(crate) fn negotiate(headers: &HeaderMap) -> Representation {
    let Some(accept) = headers.get(header::ACCEPT).and_then(|v| v.to_str().ok()) else {
        return Representation::Text(Format::Prometheus);
    };
    for item in accept.split(',') {
        let mut parts = item.split(';');
        let media = parts.next().unwrap_or("").trim();
        if parts.any(|p| {
            p.trim()
                .strip_prefix("q=")
                .is_some_and(|q| q.trim().parse::<f64>() == Ok(0.0))
        }) {
            continue;
        }
        if media.eq_ignore_ascii_case("application/json") {
            return Representation::Json;
        }
        if media.eq_ignore_ascii_case("application/openmetrics-text") {
            return Representation::Text(Format::OpenMetrics);
        }
        if media.eq_ignore_ascii_case("text/plain") {
            return Representation::Text(Format::Prometheus);
        }
    }
    Representation::Text(Format::Prometheus)
}

pub(crate) async fn get(
    State(handle): State<Arc<AppHandle>>,
    headers: busbar_kernel::inbound::http_projection::AdminHeaders,
    request: Option<Extension<RequestLease>>,
) -> Response {
    let Some(Extension(request)) = request else {
        return missing_lease();
    };
    let app = handle.load();
    match busbar_kernel::export::app_families_budgeted(&app, &request).await {
        Ok(families) => render(families, negotiate(&headers)),
        Err(BudgetedScrapeRefusal::Source(refusal)) => refused(refusal),
        Err(BudgetedScrapeRefusal::Output(error)) => output_refused(error),
    }
}

pub(crate) async fn get_hooks(
    State(handle): State<Arc<AppHandle>>,
    headers: busbar_kernel::inbound::http_projection::AdminHeaders,
    request: Option<Extension<RequestLease>>,
) -> Response {
    let Some(Extension(request)) = request else {
        return missing_lease();
    };
    let app = handle.load();
    match busbar_kernel::export::hook_families_budgeted(&app, &request) {
        Ok(families) => render(families, negotiate(&headers)),
        Err(error) => output_refused(error),
    }
}

fn missing_lease() -> Response {
    // Preserve the established six-field envelope and request-id correlation. Its emergency
    // allocation policy is a separate explicit adoption hold, not a static-body guarantee.
    err_json(&AdminError::Unavailable(
        "metric output is unavailable".into(),
    ))
}

fn output_refused(error: OutputError) -> Response {
    // Projection guards and partial output owners have already retired at this boundary.
    error.report();
    match error {
        OutputError::Capacity => missing_lease(),
        OutputError::Allocation | OutputError::Encoding => err_json(&AdminError::Internal),
    }
}

/// The refusal an unreadable registry answers. An operator's `telemetry.enabled: false` is
/// 503 with reason `telemetry_disabled`.
pub(crate) fn refused(refusal: ScrapeRefusal) -> Response {
    match refusal {
        ScrapeRefusal::TelemetryDisabled => err_json_cond(
            &AdminError::Unavailable("telemetry is disabled (telemetry.enabled: false)".into()),
            Cond::TelemetryDisabled,
        ),
        ScrapeRefusal::NotReady => err_json(&AdminError::Unavailable(
            "the metric registry is not ready".into(),
        )),
        ScrapeRefusal::Failed(why) => err_json(&AdminError::Unavailable(why.into())),
    }
}

pub(crate) fn render(
    mut families: Captured<Vec<Family>>,
    representation: Representation,
) -> Response {
    let result = (|| {
        if representation == Representation::Json {
            families.reserve_encoding(json_scratch(families.value())?)?;
        }
        encode_response(families.value(), families.request(), representation)
    })();
    drop(families);
    match result {
        Ok(response) => response,
        Err(error) => output_refused(error),
    }
}

fn encode_response(
    families: &[Family],
    request: &RequestLease,
    representation: Representation,
) -> Result<Response, OutputError> {
    let mut out = OutputBuffer::with_capacity(request, 0)?;
    let content_type = match representation {
        Representation::Text(format) => {
            if encode(&mut out, families, format).is_err() {
                return Err(out.failure().unwrap_or(OutputError::Encoding));
            }
            format.content_type()
        }
        Representation::Json => {
            if busbar_contract::json::to_writer(&mut out, &Document { families }).is_err() {
                return Err(out.failure().unwrap_or(OutputError::Encoding));
            }
            busbar_contract::protocol::APPLICATION_JSON
        }
    };
    Ok((
        StatusCode::OK,
        [
            (header::CONTENT_TYPE, content_type),
            (header::CACHE_CONTROL, "no-store"),
            (header::VARY, "Accept"),
        ],
        out.into_bytes()?,
    )
        .into_response())
}

fn json_scratch(families: &[Family]) -> Result<usize, OutputError> {
    let mut scratch = 4096usize;
    let mut longest = 64usize; // Closed Document field names and numeric/error control storage.
    let mut add = |count: usize, width: usize| -> Result<(), OutputError> {
        scratch = count
            .max(4)
            .checked_mul(width)
            .and_then(|n| n.checked_mul(4))
            .and_then(|n| scratch.checked_add(n))
            .ok_or(OutputError::Capacity)?;
        Ok(())
    };
    for family in families {
        longest = longest
            .max(family.name.len())
            .max(family.help.as_ref().map_or(0, String::len));
        let mut pairs = 0usize;
        for sample in &family.samples {
            longest = longest.max(sample.name.len()).max(sample.value.len());
            pairs = pairs
                .checked_add(sample.labels.len())
                .ok_or(OutputError::Capacity)?;
            for (key, value) in &sample.labels {
                longest = longest.max(key.len()).max(value.len());
            }
            add(sample.labels.len(), std::mem::size_of::<(&str, &str)>())?;
        }
        add(pairs, std::mem::size_of::<&str>())?; // LabelNames seen set
        add(family.samples.len(), std::mem::size_of::<(&str, &str)>())?; // Group buckets
        add(family.samples.len(), std::mem::size_of::<Bucket<'_>>())?; // Serialized bucket view
    }
    let sonic = longest
        .checked_mul(6)
        .and_then(|n| n.checked_add(35))
        .and_then(|n| n.checked_mul(6))
        .ok_or(OutputError::Capacity)?;
    scratch.checked_add(sonic).ok_or(OutputError::Capacity)
}

/// `{families: [...], cursor: null}`. The cursor is `null` until the series cursor of MR7 lands;
/// every series is in the one response.
struct Document<'a> {
    families: &'a [Family],
}

impl Serialize for Document<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeMap;
        let mut map = serializer.serialize_map(Some(2))?;
        map.serialize_entry("families", &Families(self.families))?;
        map.serialize_entry("cursor", &None::<&str>)?;
        map.end()
    }
}

struct Families<'a>(&'a [Family]);

impl Serialize for Families<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_seq(self.0.iter().map(FamilyView))
    }
}

/// Core's own families are `busbar_*`; anything else reached the registry from a plugin.
fn owner(name: &str) -> &'static str {
    if name.starts_with("busbar_") {
        "core"
    } else {
        "plugin"
    }
}

struct FamilyView<'a>(&'a Family);

impl Serialize for FamilyView<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeMap;
        let family = self.0;
        let mut map = serializer.serialize_map(Some(6))?;
        map.serialize_entry("name", &family.name)?;
        map.serialize_entry(
            "type",
            busbar_contract::export_calls::type_word(family.kind).unwrap_or("untyped"),
        )?;
        map.serialize_entry("labels", &LabelNames(family))?;
        map.serialize_entry("help", family.help.as_deref().unwrap_or(""))?;
        map.serialize_entry("owner", owner(&family.name))?;
        map.serialize_entry("series", &Series(family))?;
        map.end()
    }
}

/// The label names the family's series use, in first-seen order. `le` is a bucket coordinate, not
/// a series label.
struct LabelNames<'a>(&'a Family);

impl Serialize for LabelNames<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let histogram = self.0.kind == kinds::SCRAPE_KIND_HISTOGRAM;
        let mut seen: Vec<&str> = Vec::new();
        for sample in &self.0.samples {
            for (key, _) in &sample.labels {
                if (histogram && key == "le") || seen.contains(&key.as_str()) {
                    continue;
                }
                seen.push(key);
            }
        }
        serializer.collect_seq(seen)
    }
}

struct Labels<'a>(Vec<(&'a str, &'a str)>);

impl Serialize for Labels<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_map(self.0.iter().copied())
    }
}

/// A recorder value as a JSON number; a value that is not a finite number is `null`.
struct Number<'a>(&'a str);

impl Serialize for Number<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match self.0.parse::<f64>() {
            Ok(v) if v.is_finite() => serializer.serialize_f64(v),
            _ => serializer.serialize_none(),
        }
    }
}

struct Series<'a>(&'a Family);

impl Serialize for Series<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeSeq;
        let family = self.0;
        if family.kind != kinds::SCRAPE_KIND_HISTOGRAM {
            let mut seq = serializer.serialize_seq(Some(family.samples.len()))?;
            for sample in &family.samples {
                seq.serialize_element(&ValueSeries {
                    family: &family.name,
                    sample,
                })?;
            }
            return seq.end();
        }
        let mut seq = serializer.serialize_seq(None)?;
        let mut group: Option<Group<'_>> = None;
        for sample in &family.samples {
            let labels: Vec<(&str, &str)> = sample
                .labels
                .iter()
                .filter(|(k, _)| k != "le")
                .map(|(k, v)| (k.as_str(), v.as_str()))
                .collect();
            if group.as_ref().is_some_and(|g| g.labels.0 != labels) {
                if let Some(done) = group.take() {
                    seq.serialize_element(&done)?;
                }
            }
            let g = group.get_or_insert_with(|| Group {
                labels: Labels(labels),
                buckets: Vec::new(),
                sum: "0",
                count: "0",
            });
            if sample.name.ends_with("_bucket") {
                let le = sample
                    .labels
                    .iter()
                    .find(|(k, _)| k == "le")
                    .map_or("", |(_, v)| v.as_str());
                g.buckets.push((le, sample.value.as_str()));
            } else if sample.name.ends_with("_sum") {
                g.sum = sample.value.as_str();
            } else if sample.name.ends_with("_count") {
                g.count = sample.value.as_str();
            }
        }
        if let Some(done) = group {
            seq.serialize_element(&done)?;
        }
        seq.end()
    }
}

/// `{labels, value}`; a sample whose series name differs from its family's (a summary's `_sum`
/// and `_count`) also carries that `name`.
struct ValueSeries<'a> {
    family: &'a str,
    sample: &'a busbar_contract::export_calls::Sample,
}

impl Serialize for ValueSeries<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeMap;
        let named = self.sample.name != self.family;
        let mut map = serializer.serialize_map(Some(2 + usize::from(named)))?;
        if named {
            map.serialize_entry("name", &self.sample.name)?;
        }
        let labels = Labels(
            self.sample
                .labels
                .iter()
                .map(|(k, v)| (k.as_str(), v.as_str()))
                .collect(),
        );
        map.serialize_entry("labels", &labels)?;
        map.serialize_entry("value", &Number(&self.sample.value))?;
        map.end()
    }
}

/// One histogram series: cumulative buckets as the text form carries them, then sum and count.
struct Group<'a> {
    labels: Labels<'a>,
    buckets: Vec<(&'a str, &'a str)>,
    sum: &'a str,
    count: &'a str,
}

struct Bucket<'a>(&'a str, &'a str);

impl Serialize for Bucket<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeMap;
        let mut map = serializer.serialize_map(Some(2))?;
        map.serialize_entry("le", self.0)?;
        map.serialize_entry("count", &Number(self.1))?;
        map.end()
    }
}

impl Serialize for Group<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeMap;
        let mut map = serializer.serialize_map(Some(4))?;
        map.serialize_entry("labels", &self.labels)?;
        map.serialize_entry(
            "buckets",
            &self
                .buckets
                .iter()
                .map(|b| Bucket(b.0, b.1))
                .collect::<Vec<_>>(),
        )?;
        map.serialize_entry("sum", &Number(self.sum))?;
        map.serialize_entry("count", &Number(self.count))?;
        map.end()
    }
}

#[cfg(test)]
#[path = "tests/metrics_tests.rs"]
mod tests;
