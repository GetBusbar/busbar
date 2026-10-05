// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE EXPORT KIND'S CALLS, AS THE HOST'S TWO HALVES SHARE THEM (`BUSBAR-1.6.0.md` THE DESIGN, the
//! export kind ABI): the [`ExportCalls`] trait the plugin loader implements over one opened
//! export instance and the kernel feeds and scrapes through, and the scrape snapshot
//! ([`Family`]/[`Sample`]) the kernel builds from its recorders. The kernel names this, the loader
//! names this, and neither names the other. Nothing here crosses the plugin boundary: the export
//! kind's ABI is `abi::export`, and the loader lowers these types to it.

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
/// (optional), `# TYPE`, its samples and a blank line — read into [`Family`]s, in order, LOSSLESSLY:
/// every label value and every number as the recorder spelled it, so rendering them back in the same
/// format reproduces the recorder's bytes. Anything that cannot be placed — a sample outside a typed
/// family, a `# TYPE` word outside the vocabulary, an unclosed family — is refused rather than
/// approximated. The kernel reads its recorders through it.
///
/// # Errors
/// The first line that cannot be placed, numbered.
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
    let bad_key = labels
        .iter()
        .any(|(k, _)| k.is_empty() || k.contains([',', '{', '}', '"', ' ']));
    if name.is_empty() || bad_key || value.is_empty() || value.contains(' ') {
        return Err("a sample that is not `name[{labels}] value`".into());
    }
    Ok(Sample {
        name,
        labels,
        value: value.to_string(),
    })
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
    /// The streams this instance carries (its Statement tail's `streams[]`), as
    /// [`crate::abi::export::ExportStream`] bytes.
    fn streams(&self) -> &[u8];

    /// The routes this instance serves (its Statement tail's `routes[]`), in the route vocabulary
    /// every kind declares in.
    fn routes(&self) -> &[crate::abi::mechanism::route::Route];

    /// Hand one already-projected JSON line for `stream` to the instance, OFF the request path:
    /// the line joins the instance's bounded queue, and the host coalesces queued lines into
    /// `deliver` batches (JSON LINES, one host-minted `op_id` each) in the write-behind deadline
    /// class. `hold` is dropped when the line's batch has answered (or the line was shed).
    fn deliver(&self, stream: u8, line: Vec<u8>, hold: Box<dyn Send>) -> Delivered;

    /// Render `families` as this instance's exposition text, through `scrape`, on the calling
    /// thread (request path). `Err` names why the instance did not render.
    ///
    /// # Errors
    /// The instance failed, was refused, faulted, or answered short twice.
    fn scrape(&self, families: &[Family]) -> Result<Vec<u8>, String>;

    /// Render the HOOK `families` (`/metrics/hooks`) as this instance's exposition text, through
    /// `scrape` with [`crate::abi::export::SCRAPE_FLAG_HOOK_FAMILIES`] set, on the calling thread.
    /// An instance with no hook rendering answers `Err`.
    ///
    /// # Errors
    /// The instance renders no hook families, failed, was refused, faulted, or answered short twice.
    fn scrape_hooks(&self, families: &[Family]) -> Result<Vec<u8>, String> {
        let _ = families;
        Err("this instance renders no hook families".to_string())
    }

    /// Ask the instance for its `status` (what it reports when the host renders its status
    /// exposition): the 1.5.5 status JSON, or `None` when it has none. Its envelope's metrics and
    /// diagnostics are folded by the host as every reply's are.
    fn status(&self) -> Option<Vec<u8>>;

    /// Dispatch one request to the instance's own routes, through `serve`. The host enforced
    /// the route's auth before this call.
    ///
    /// # Errors
    /// The instance failed, was refused or faulted.
    fn serve(&self, req: &ServeRequest<'_>) -> Result<Served, String>;

    /// The admission this instance stated for its deliveries: whether it takes deliveries this run,
    /// its in-flight bound (`0`: the host's) and its gate's name (empty: the module's). `None` =
    /// the host's defaults. (A memory-ABI instance states none; its `max_inflight` is the
    /// dispatcher's.)
    fn admission(&self) -> Option<(bool, u64, String)> {
        None
    }

    /// The host shed a line for this instance before handing it over: an instance that declared a
    /// shed counter has it counted. Nothing by default.
    fn shed(&self) {}
}

/// What [`ExportAxis::probe`] answers of a module: the streams its sink declares (`None` when it
/// will not load here) and its own validation of the instance's settings, verbatim.
pub type Probed = (Option<Vec<u8>>, Vec<String>);

/// THE EXPORT AXIS, as the kernel asks it: every `kind: export` row the composition root admitted
/// (compiled in or dropped in, one registration), resolved by `module:` name or alias. The root
/// implements it over its plugin registry and the process's one dispatcher and installs it once;
/// the kernel opens, probes and checks export instances through it and names nothing behind it.
pub trait ExportAxis: Send + Sync {
    /// `None` when no `kind: export` row names `module`; else what [`Probed`] states, asked while
    /// the configuration is resolved (`instance` names the configured instance in any refusal).
    fn probe(&self, module: &str, instance: &str, settings: &serde_json::Value) -> Option<Probed>;

    /// The sink's own checks across every configured `instances` of `module`, at `phase`
    /// ([`crate::abi::export::CHECK_PHASE_LIMITS`] | `_INSTANCES`), each line verbatim; `None`
    /// when `module` is not an export row.
    fn check(
        &self,
        module: &str,
        phase: u32,
        instances: &[(String, serde_json::Value)],
    ) -> Option<Vec<String>>;

    /// OPEN one instance of `module` with `settings`, under the host's instance `label` (unique per
    /// opened instance: the name every host service keys its caller by).
    ///
    /// # Errors
    /// Why it will not open, naming the module.
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
}

#[cfg(test)]
#[path = "tests/export_calls_tests.rs"]
mod tests;
