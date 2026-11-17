// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE EXPORT KIND'S CALLS, AS THE HOST'S TWO HALVES SHARE THEM (`BUSBAR-1.6.0.md` THE DESIGN, the

use zeroize::Zeroize;

/// JSON list of declared route paths requesting the admitted recorder consumer's
pub const EXT_PUBLIC_ROUTES: &str = "listener.public_routes";

/// JSON list of public route paths retained by the boot instance after config removal.
pub const EXT_PERSISTENT_ROUTES: &str = "listener.persistent_routes";

/// The settings key that states an export instance's in-flight bound: how many deliveries the host
pub const INFLIGHT_KEY: &str = "max_inflight_deliveries";

/// The in-flight bound of an export instance whose settings state none: 1.5.5's default for its
pub const DEFAULT_INFLIGHT: u32 = 64;

/// One metric family of a host recorder's snapshot, in the recorder's render order. The loader
/// lowers it to [`crate::abi::export::ScrapeFamily`] for the `scrape` op.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Family {
    /// The raw metric family name; exporters own wire identifier normalization.
    pub name: String,
    /// Raw help text; `None` means no description.
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
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Sample {
    /// The series name: the family name, or it with `_bucket` / `_sum` / `_count`.
    pub name: String,
    /// Raw label keys and values, including distribution coordinates, in recorder order.
    /// Exporters own any wire identifier normalization and escaping.
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

/// The distribution name of a [`Family::kind`]; `None` outside the kind vocabulary.
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

/// The [`Family::kind`] a distribution name denotes; `None` outside the kind vocabulary.
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
    /// queued; the adapter reports the exact refusal or drop once. The caller must not recount it.
    Shed,
}

/// ONE EXPORT INSTANCE'S CALLS, as the kernel makes them.
pub trait ExportCalls: Send + Sync {
    /// Validated immutable startup requirements, absent for exporters needing no recorder.
    fn recorder_requirements(&self) -> Option<RecorderRequirements> {
        None
    }

    /// Apply settings to this instance. A refusal retains its current settings and bindings.
    fn refresh(
        &self,
        settings: &crate::plugin_settings::ResolvedSettings,
        generation: u64,
    ) -> Result<(), String> {
        let _ = (settings, generation);
        Err("this export instance does not support refresh".into())
    }

    /// The streams this instance carries (its Statement tail's `streams[]`), as
    fn streams(&self) -> &[u8];

    /// The routes this instance serves (its Statement tail's `routes[]`), in the route vocabulary
    fn routes(&self) -> &[crate::abi::mechanism::route::Route];

    /// Declared routes outside the instance namespace, granted only to the admitted recorder consumer
    fn public_routes(&self) -> &[String] {
        &[]
    }

    /// Public routes retained by the boot instance across configuration removal.
    fn persistent_routes(&self) -> &[String] {
        &[]
    }

    /// The immutable MIN-3 snapshot scope served at this exact declared path, if any.
    fn scope(&self, _path: &str) -> Option<u32> {
        None
    }

    /// Render a declared MIN-3 scope from a snapshot collected by the owning kernel.
    fn render_scope(&self, _scope: u32, _families: &[Family]) -> Result<Served, String> {
        Err("this export instance declares no snapshot scopes".into())
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

    /// Report one host-side capture refusal or integrity failure with its exact classification.
    /// Delivery adapters own their own terminal drops; callers never recount `Delivered::Shed`.
    fn shed(&self, _kind: ExportLossKind) {}
}

/// Config probe result: declared streams, validation problems, and the explicit
/// recorder requirements obtained from the validated probe instance, if advertised.
pub type Probed = (Option<Vec<u8>>, Vec<String>, Option<RecorderRequirements>);

/// Opt-in Statement extension. Its JSON value must be version `1`; advertised exporters
/// must answer `CHECK_PHASE_RECORDER` after validated OPEN, including during config probes.
pub const EXT_RECORDER_REQUIREMENTS: &str = "recorder.requirements";

/// Immutable startup requirements for the host-owned metrics recorder. These are a
/// kind declaration, never the exporter's opaque operator settings. The host retains
/// its fixed series/bucket bounds and applies the declared per-key projection limit.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecorderRequirements {
    /// Positive rolling observation retention window, in seconds.
    pub retention_seconds: u64,
    /// Maximum per-key gauges included in a scrape; zero includes none.
    pub key_gauge_limit: usize,
}

impl RecorderRequirements {
    /// Validate the declaration without interpreting implementation settings.
    pub fn validate(&self) -> Result<(), String> {
        if self.retention_seconds == 0 {
            return Err("recorder retention_seconds must be positive".into());
        }
        Ok(())
    }
}

/// Validate the admitted declaration protocol version. Absence opts out.
pub fn recorder_protocol(extensions: &[u8]) -> Result<bool, String> {
    use crate::abi::mechanism::extensions;
    let mut declarations = extensions::entries(extensions)
        .filter(|(key, _)| *key == EXT_RECORDER_REQUIREMENTS.as_bytes());
    let Some((_, value)) = declarations.next() else {
        return Ok(false);
    };
    if declarations.next().is_some() {
        return Err("repeated recorder.requirements declaration".into());
    }
    if value != b"1" {
        return Err("unsupported recorder.requirements declaration version".into());
    }
    Ok(true)
}

/// THE EXPORT AXIS, as the kernel asks it: every `kind: export` row the composition root admitted
pub trait ExportAxis: Send + Sync {
    /// `None` when no `kind: export` row names `module`; else what [`Probed`] states, asked while
    fn probe(
        &self,
        module: &str,
        instance: &str,
        settings: &crate::plugin_settings::ResolvedSettings,
    ) -> Option<Probed>;

    /// The sink's own checks across every configured `instances` of `module`, at `phase`
    fn check(
        &self,
        module: &str,
        phase: u32,
        instances: &[(String, &crate::plugin_settings::ResolvedSettings)],
    ) -> Option<Vec<String>>;

    /// Whether `module` names a row this build LINKS (as opposed to one dropped in), judged under `read`: the
    /// prepared-read context of the generation the question is about (DES-NATIVE-FIRST-PARTY r3 §3.1). `None`
    /// when the caller judges no generation's images.
    fn linked(&self, module: &str, read: Option<&(dyn core::any::Any + Send + Sync)>) -> bool;

    /// Whether `module` names a FIRST-PARTY row: linked, or dropped in signed by the release key, judged under
    /// `read` (as [`Self::linked`]). The answer for a word that generation's images resolve comes from those
    /// images' signer alone.
    fn first_party(&self, module: &str, read: Option<&(dyn core::any::Any + Send + Sync)>) -> bool;

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

mod opening;
pub use opening::{ExportOpening, PreparedExport};

/// Why bytes already in export custody were terminally discarded.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ExportDropReason {
    /// The bounded export queue discarded the bytes when its capacity was exhausted.
    QueueFull,
    /// The exporter discarded the bytes while stopping.
    Stopped,
    /// Delivery exhausted its permitted attempts.
    AttemptsExhausted,
    /// The destination refused delivery terminally.
    Refused,
    /// The retained bytes named a destination outside this exporter.
    ForeignDestination,
    /// The retained bytes exceeded their delivery lifetime.
    Expired,
    /// Only discarded bytes: retained ciphertext with an unavailable key is not a loss.
    KeyUnavailable,
}

impl ExportDropReason {
    #[must_use]
    /// Stable host-owned reason used in loss records.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::QueueFull => "queue_full",
            Self::Stopped => "stopped",
            Self::AttemptsExhausted => "attempts_exhausted",
            Self::Refused => "refused",
            Self::ForeignDestination => "foreign_destination",
            Self::Expired => "expired",
            Self::KeyUnavailable => "key_unavailable",
        }
    }
}

/// Delivery loss, pre-custody refusal and audit integrity are distinct facts.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ExportLossKind {
    /// Bytes already accepted into export custody were discarded.
    Dropped(ExportDropReason),
    /// Capture was refused before export custody accepted the bytes.
    CaptureRefused,
    /// An integrity check failed, independently of a delivery-loss count.
    IntegrityFailed,
}

/// First-loss facts retained by the host observer before transfer into native audit custody.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExportLossFacts {
    /// Configured exporter instance that observed the event.
    pub instance: String,
    /// Wall-clock seconds when loss was first observed, not the eventual retry time.
    pub observed_at: u64,
    /// Dropped line count, or occurrence count for capture/integrity failures.
    pub count: u64,
    /// Whether the event records delivery loss, capture refusal or integrity failure.
    pub kind: ExportLossKind,
}

/// A checked positive custody acknowledgement; NONE and unknown wire values are not levels.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ExportCustodyLevel {
    /// The destination accepted the prefix into its custody.
    Accepted,
    /// The destination durably retained the prefix.
    Durable,
    /// The destination indexed the prefix.
    Indexed,
}

impl ExportCustodyLevel {
    /// Stable metric label for this checked positive custody level.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Accepted => "accepted",
            Self::Durable => "durable",
            Self::Indexed => "indexed",
        }
    }
}

/// Host-owned observation vocabulary. Instance identity is bound by the constructor.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ExportObservation {
    /// Bytes already in custody were terminally discarded.
    Dropped {
        /// Closed host-owned terminal-loss reason.
        reason: ExportDropReason,
        /// Number of discarded lines; zero is ignored.
        lines: u64,
    },
    /// The destination acknowledged an accepted prefix.
    Custody {
        /// Existing stream vocabulary.
        stream: crate::export_stream::ExportStream,
        /// Checked positive acknowledgement level.
        level: ExportCustodyLevel,
        /// Accepted prefix length; zero is ignored.
        lines: u64,
    },
    /// The sole capture-refusal reason is admission_rejected, counted per occurrence.
    CaptureRefused,
    /// One audit-integrity failure, independent of whether queued bytes deliver.
    IntegrityFailed,
    /// Absolute retained ciphertext line count while its key is unavailable; never a loss.
    Held {
        /// Absolute current retained lines, including zero to clear the gauge.
        lines: u64,
    },
}

/// One logical instance's observer, shared with every generation and capture producer.
pub trait ExportObserver: Send + Sync + 'static {
    /// Record bounded typed facts against this constructor-bound logical instance.
    fn observe(&self, observation: ExportObservation);
}
