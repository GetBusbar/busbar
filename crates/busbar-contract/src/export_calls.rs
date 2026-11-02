// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE EXPORT KIND'S CALLS, AS THE HOST'S TWO HALVES SHARE THEM (`BUSBAR-1.6.0.md` THE DESIGN, the

use zeroize::Zeroize;

/// JSON list of declared route paths requesting a first-party snapshot consumer's
pub const EXT_PUBLIC_ROUTES: &str = "listener.public_routes";

/// JSON list of public route paths retained by the boot instance after config removal.
pub const EXT_PERSISTENT_ROUTES: &str = "listener.persistent_routes";

/// The settings key that states an export instance's in-flight bound: how many deliveries the host
pub const INFLIGHT_KEY: &str = "max_inflight_deliveries";

/// The in-flight bound of an export instance whose settings state none: 1.5.5's default for its
pub const DEFAULT_INFLIGHT: u32 = 64;

/// One metric family of a host recorder's snapshot, in the recorder's render order. The loader
/// lowers it to [`crate::abi::export::ScrapeFamily`] for the `scrape` op.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Family {
    /// The family name, as its `# TYPE` line spells it.
    pub name: String,
    /// The `# HELP` text as the recorder wrote it (escaped, one line); `None` = no `# HELP` line.
    pub help: Option<String>,
    /// The unit; `None` = none.
    pub unit: Option<String>,
    /// [`crate::abi::export::SCRAPE_KIND_COUNTER`] | `_GAUGE` | `_HISTOGRAM` | `_SUMMARY` |
    /// `_UNTYPED`.
    pub kind: u8,
    /// The samples, in order.
    pub samples: Vec<Sample>,
}

/// One sample line of a [`Family`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Sample {
    /// The series name: the family name, or it with `_bucket` / `_sum` / `_count`.
    pub name: String,
    /// The labels in order, each value as the exposition writes it (escaped), `le` / `quantile`
    /// included where the recorder wrote them.
    pub labels: Vec<(String, String)>,
    /// The value, in the recorder's own spelling.
    pub value: String,
}

impl Drop for Family {
    fn drop(&mut self) {
        self.name.zeroize();
        self.help.zeroize();
        self.unit.zeroize();
    }
}

impl Drop for Sample {
    fn drop(&mut self) {
        self.name.zeroize();
        self.labels.zeroize();
        self.value.zeroize();
    }
}

/// The `# TYPE` word of a [`Family::kind`]; `None` for a kind outside the vocabulary.
///
/// # Examples
/// ```
/// use busbar_contract::abi::export::SCRAPE_KIND_SUMMARY;
/// assert_eq!(busbar_contract::export_calls::type_word(SCRAPE_KIND_SUMMARY), Some("summary"));
/// assert_eq!(busbar_contract::export_calls::type_word(9), None);
/// ```
#[must_use]
pub const fn type_word(kind: u8) -> Option<&'static str> {
    use crate::abi::export as x;
    match kind {
        x::SCRAPE_KIND_COUNTER => Some("counter"),
        x::SCRAPE_KIND_GAUGE => Some("gauge"),
        x::SCRAPE_KIND_HISTOGRAM => Some("histogram"),
        x::SCRAPE_KIND_SUMMARY => Some("summary"),
        x::SCRAPE_KIND_UNTYPED => Some("untyped"),
        _ => None,
    }
}

/// The [`Family::kind`] a `# TYPE` word names; `None` for a word outside the vocabulary.
///
/// # Examples
/// ```
/// use busbar_contract::export_calls::{kind_of, type_word};
/// assert_eq!(kind_of("histogram").and_then(type_word), Some("histogram"));
/// assert_eq!(kind_of("info"), None);
/// ```
#[must_use]
pub fn kind_of(word: &str) -> Option<u8> {
    use crate::abi::export as x;
    Some(match word {
        "counter" => x::SCRAPE_KIND_COUNTER,
        "gauge" => x::SCRAPE_KIND_GAUGE,
        "histogram" => x::SCRAPE_KIND_HISTOGRAM,
        "summary" => x::SCRAPE_KIND_SUMMARY,
        "untyped" => x::SCRAPE_KIND_UNTYPED,
        _ => return None,
    })
}

/// THE RECORDER SNAPSHOT (K9a S6): a host recorder's text exposition — each family's `# HELP`
pub fn parse_families(exposition: &str) -> Result<Vec<Family>, String> {
    if !exposition.is_empty() && !exposition.ends_with('\n') {
        return Err("the exposition does not end with a newline".into());
    }
    let mut families = Vec::new();
    let mut open: Option<(Family, bool)> = None;
    for (n, line) in exposition.split_terminator('\n').enumerate() {
        let at = |why: &str| format!("exposition line {}: {why}", n + 1);
        if line.is_empty() {
            let (f, _) = open
                .take()
                .ok_or_else(|| at("a blank line closes no family"))?;
            families.push(f);
        } else if let Some(rest) = line.strip_prefix("# HELP ") {
            if open.is_some() {
                return Err(at("a HELP line inside an unclosed family"));
            }
            let (name, help) = rest
                .split_once(' ')
                .ok_or_else(|| at("a HELP line with no text"))?;
            open = Some((family(name, Some(help.to_string())), false));
        } else if let Some(rest) = line.strip_prefix("# TYPE ") {
            let (name, word) = rest
                .split_once(' ')
                .ok_or_else(|| at("a TYPE line with no type"))?;
            let kind = kind_of(word).ok_or_else(|| at(&format!("the unknown type '{word}'")))?;
            match &mut open {
                None => {
                    let mut f = family(name, None);
                    f.kind = kind;
                    open = Some((f, true));
                }
                Some((f, typed)) if f.name == name && !*typed => {
                    f.kind = kind;
                    *typed = true;
                }
                Some(_) => return Err(at("a TYPE line that does not open or type its family")),
            }
        } else {
            let (f, _) = open
                .as_mut()
                .filter(|(_, typed)| *typed)
                .ok_or_else(|| at("a sample outside a typed family"))?;
            f.samples.push(sample(line).map_err(|why| at(&why))?);
        }
    }
    match open {
        Some((f, _)) => Err(format!("the family '{}' is not closed", f.name)),
        None => Ok(families),
    }
}

fn family(name: &str, help: Option<String>) -> Family {
    Family {
        name: name.to_string(),
        help,
        unit: None,
        kind: crate::abi::export::SCRAPE_KIND_UNTYPED,
        samples: Vec::new(),
    }
}

/// One sample line: `name[{k="v",…}] value`, the label values and the value kept as written.
fn sample(line: &str) -> Result<Sample, String> {
    let name_end = line.find(['{', ' ']).ok_or("a sample with no value")?;
    let mut sample = Sample {
        name: line[..name_end].to_string(),
        labels: Vec::new(),
        value: String::new(),
    };
    let mut rest = &line[name_end..];
    if let Some(mut body) = rest.strip_prefix('{') {
        loop {
            let (key, tail) = body.split_once("=\"").ok_or("a label with no value")?;
            let end = value_end(tail).ok_or("an unterminated label value")?;
            sample
                .labels
                .push((key.to_string(), tail[..end].to_string()));
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
    let bad_key = sample
        .labels
        .iter()
        .any(|(k, _)| k.is_empty() || k.contains([',', '{', '}', '"', ' ']));
    if sample.name.is_empty() || bad_key || value.is_empty() || value.contains(' ') {
        return Err("a sample that is not `name[{labels}] value`".into());
    }
    sample.value = value.to_string();
    Ok(sample)
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

/// One request, dispatched to an instance's own route.
#[derive(Debug, Clone, Copy)]
pub struct ServeRequest<'a> {
    /// The method.
    pub method: &'a str,
    /// The path.
    pub path: &'a str,
    /// The raw query string; `None` = none.
    pub query: Option<&'a str>,
    /// Header name/value pairs, at most 64.
    pub headers: &'a [(String, String)],
    /// The body.
    pub body: &'a [u8],
}

/// The instance's answer to a [`ServeRequest`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Served {
    /// The status code.
    pub status: u16,
    /// Response header name/value pairs.
    pub headers: Vec<(String, String)>,
    /// The body.
    pub body: Vec<u8>,
}

/// What [`ExportCalls::deliver`] did with a line.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Delivered {
    /// Queued for the instance's next coalesced batch.
    Queued,
    /// Shed: the instance's bounded queue is full, or the instance is faulted or closed. Never
    /// queued; the caller counts it.
    Shed,
}

/// ONE EXPORT INSTANCE'S CALLS, as the kernel makes them.
pub trait ExportCalls: Send + Sync {
    /// Apply settings to this instance. A refusal retains its current settings and bindings.
    fn refresh(&self, settings: &serde_json::Value, generation: u64) -> Result<(), String> {
        let _ = (settings, generation);
        Err("this export instance does not support refresh".into())
    }

    /// The streams this instance carries (its Statement tail's `streams[]`), as
    fn streams(&self) -> &[u8];

    /// The routes this instance serves (its Statement tail's `routes[]`), in the route vocabulary
    fn routes(&self) -> &[crate::abi::mechanism::route::Route];

    /// Declared routes outside the instance namespace, granted only to the first-party
    fn public_routes(&self) -> &[String] {
        &[]
    }

    /// Public routes retained by the boot instance across configuration removal.
    fn persistent_routes(&self) -> &[String] {
        &[]
    }

    /// Hand one already-projected JSON line for `stream` to the instance, OFF the request path:
    fn deliver(&self, stream: u8, line: Vec<u8>, hold: Box<dyn Send>) -> Delivered;

    /// Whether this instance takes each `traces` line's full span record as its reserved `span`
    fn takes_span_records(&self) -> bool {
        false
    }

    /// Render `families` as this instance's exposition text, through `scrape`, on the calling
    fn scrape(&self, families: &[Family]) -> Result<Vec<u8>, String>;

    /// Render the HOOK `families` (`/metrics/hooks`) as this instance's exposition text, through
    fn scrape_hooks(&self, families: &[Family]) -> Result<Vec<u8>, String> {
        let _ = families;
        Err("this instance renders no hook families".to_string())
    }

    /// Ask the instance for its `status` (what it reports when the host renders its status
    fn status(&self) -> Option<Vec<u8>>;

    /// Dispatch one request to the instance's own routes, through `serve`. The host enforced
    fn serve(&self, req: &ServeRequest<'_>) -> Result<Served, String>;

    /// The admission this instance stated for its deliveries: whether it takes deliveries this run,
    fn admission(&self) -> Option<(bool, u64, String)> {
        None
    }

    /// START the instance: its door's `ready` (discovery at boot) is awaited HERE, when the host
    fn start(&self) -> Result<(), String> {
        Ok(())
    }

    /// The host shed a line for this instance before handing it over: an instance that declared a
    fn shed(&self) {}
}

/// What [`ExportAxis::probe`] answers of a module: the streams its sink declares (`None` when it
pub type Probed = (Option<Vec<u8>>, Vec<String>);

/// THE EXPORT AXIS, as the kernel asks it: every `kind: export` row the composition root admitted
pub trait ExportAxis: Send + Sync {
    /// `None` when no `kind: export` row names `module`; else what [`Probed`] states, asked while
    fn probe(&self, module: &str, instance: &str, settings: &serde_json::Value) -> Option<Probed>;

    /// The sink's own checks across every configured `instances` of `module`, at `phase`
    fn check(
        &self,
        module: &str,
        phase: u32,
        instances: &[(String, &serde_json::Value)],
    ) -> Option<Vec<String>>;

    /// OPEN one instance of `module` with `settings`, under the host's instance `label` (unique per
    fn open(
        &self,
        module: &str,
        label: &str,
        settings: &serde_json::Value,
    ) -> Result<std::sync::Arc<dyn ExportCalls>, String>;

    /// Whether `module` names a row this build LINKS (as opposed to one dropped in).
    fn linked(&self, module: &str) -> bool;

    /// Whether `module` names a FIRST-PARTY row: linked, or dropped in signed by the release key.
    fn first_party(&self, module: &str) -> bool;

    /// Whether `module`'s row states the `one_instance` mark
    fn one_instance(&self, module: &str) -> bool {
        let _ = module;
        false
    }

    /// The routes `module`'s row declares (its Statement's `routes`), read without opening an
    fn routes(&self, module: &str) -> Vec<crate::abi::mechanism::route::Route> {
        let _ = module;
        Vec::new()
    }

    /// Public route declarations, including rows that have not opened an instance.
    fn public_routes(&self, module: &str) -> Vec<String> {
        let _ = module;
        Vec::new()
    }

    /// Boot-lifetime route declarations, including unopened rows.
    fn persistent_routes(&self, module: &str) -> Vec<String> {
        let _ = module;
        Vec::new()
    }

    /// The `module:` words of the export rows this build LINKS, in the order the composition root
    fn linked_modules(&self) -> Vec<String> {
        Vec::new()
    }

    /// The settings paths `module`'s Statement declares secret (its `secret_refs`, `.`-separated,
    fn secret_refs(&self, module: &str) -> Vec<String> {
        let _ = module;
        Vec::new()
    }

    /// The REFERENCE-CAPABLE, NOT-SECRET settings paths `module`'s Statement states (its
    fn reference_fields(&self, module: &str) -> Vec<String> {
        let _ = module;
        Vec::new()
    }
}

#[cfg(test)]
#[path = "tests/export_calls_tests.rs"]
mod tests;
