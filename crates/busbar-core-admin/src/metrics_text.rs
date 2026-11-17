// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The admin `/metrics` text encoder: Prometheus text 0.0.4 and OpenMetrics, written by core with
//! no dependency (ADMIN-API-1.6 section 12).
//!
//! It walks the snapshot families once, in the order the recorder produced them, and appends to one
//! caller-owned `String`. It sorts nothing and allocates nothing per sample or per label: names and
//! label values are written through, sanitised or escaped a character at a time.

use busbar_contract::abi::export as kinds;
use busbar_contract::export_calls::{Family, Sample};
use std::fmt::{self, Write};

/// The two text representations `Accept` can select.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum Format {
    /// Prometheus text exposition 0.0.4 (`text/plain; version=0.0.4`).
    Prometheus,
    /// OpenMetrics text (`application/openmetrics-text`).
    OpenMetrics,
}

impl Format {
    pub(crate) const fn content_type(self) -> &'static str {
        match self {
            Self::Prometheus => "text/plain; version=0.0.4; charset=utf-8",
            Self::OpenMetrics => "application/openmetrics-text; version=1.0.0; charset=utf-8",
        }
    }
}

const TOTAL: &str = "_total";

/// Append every family to `out` in `format`. `out` is never cleared or shrunk.
pub(crate) fn encode(out: &mut impl Write, families: &[Family], format: Format) -> fmt::Result {
    for family in families {
        family_into(out, family, format)?;
    }
    if format == Format::OpenMetrics {
        out.write_str("# EOF\n")?;
    }
    Ok(())
}

fn family_into(out: &mut impl Write, family: &Family, format: Format) -> fmt::Result {
    let Some(word) = type_word(family.kind, format) else {
        return Ok(());
    };
    let counter = family.kind == kinds::SCRAPE_KIND_COUNTER;
    // OpenMetrics names the counter family without `_total`; its samples carry the suffix.
    let family_name = match (format, counter) {
        (Format::OpenMetrics, true) => family.name.strip_suffix(TOTAL).unwrap_or(&family.name),
        _ => &family.name,
    };
    out.write_str("# HELP ")?;
    name_into(out, family_name, true)?;
    out.write_char(' ')?;
    help_into(out, family.help.as_deref().unwrap_or(""))?;
    out.write_str("\n# TYPE ")?;
    name_into(out, family_name, true)?;
    out.write_char(' ')?;
    out.write_str(word)?;
    out.write_char('\n')?;
    for sample in &family.samples {
        sample_into(out, sample, counter && format == Format::OpenMetrics)?;
    }
    Ok(())
}

fn type_word(kind: u8, format: Format) -> Option<&'static str> {
    match (kind, format) {
        (kinds::SCRAPE_KIND_UNTYPED, Format::OpenMetrics) => Some("unknown"),
        _ => busbar_contract::export_calls::type_word(kind),
    }
}

fn sample_into(out: &mut impl Write, sample: &Sample, owe_total: bool) -> fmt::Result {
    name_into(out, &sample.name, true)?;
    if owe_total && !sample.name.ends_with(TOTAL) {
        out.write_str(TOTAL)?;
    }
    if !sample.labels.is_empty() {
        out.write_char('{')?;
        for (i, (key, value)) in sample.labels.iter().enumerate() {
            if i != 0 {
                out.write_char(',')?;
            }
            name_into(out, key, false)?;
            out.write_str("=\"")?;
            escaped_into(out, value, true)?;
            out.write_char('"')?;
        }
        out.write_char('}')?;
    }
    out.write_char(' ')?;
    value_into(out, &sample.value)?;
    out.write_char('\n')
}

/// A sample value: finite numbers pass through in the recorder's spelling; anything else becomes
/// `NaN`, `+Inf` or `-Inf`, so no hostile text reaches the line.
fn value_into(out: &mut impl Write, raw: &str) -> fmt::Result {
    match raw.parse::<f64>() {
        Ok(v) if v.is_finite() => out.write_str(raw),
        Ok(v) if v.is_infinite() => out.write_str(if v > 0.0 { "+Inf" } else { "-Inf" }),
        _ => out.write_str("NaN"),
    }
}

/// `[a-zA-Z_:][a-zA-Z0-9_:]*` for a metric name; label names (`colon == false`) exclude `:`, which
/// the exposition formats do not allow there. An invalid byte becomes `_`; an empty name is `_`.
fn name_into(out: &mut impl Write, name: &str, colon: bool) -> fmt::Result {
    if name.is_empty() {
        return out.write_char('_');
    }
    for (i, c) in name.chars().enumerate() {
        let valid = c.is_ascii_alphabetic()
            || c == '_'
            || (colon && c == ':')
            || (i != 0 && c.is_ascii_digit());
        out.write_char(if valid { c } else { '_' })?;
    }
    Ok(())
}

/// HELP text escapes `\` and newline.
fn help_into(out: &mut impl Write, help: &str) -> fmt::Result {
    escaped_into(out, help, false)
}

/// Escape `\` and newline, and the double quote when `quote` (a label value).
fn escaped_into(out: &mut impl Write, text: &str, quote: bool) -> fmt::Result {
    for c in text.chars() {
        match c {
            '\\' => out.write_str("\\\\"),
            '\n' => out.write_str("\\n"),
            '"' if quote => out.write_str("\\\""),
            _ => out.write_char(c),
        }?;
    }
    Ok(())
}

#[cfg(test)]
#[path = "tests/metrics_text_tests.rs"]
mod tests;
