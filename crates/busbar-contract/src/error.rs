//! The one structured error every plugin kind answers with, its closed class taxonomy, and the
//! catalog a plugin ships beside its claims so the host can render a code it has never seen.
//!
//! A plugin says five things when it fails: which CLASS of failure it is (closed, this crate's),
//! which CODE it is (open, the plugin's own, stable and namespaced), the structured PARAMS the code
//! is about, its own DEVELOPER MESSAGE for a log, and any ADVISORY hint. The host records all five
//! verbatim and decides everything else — status, retry, severity, what a client is shown — from
//! the class alone. It reads the code through the plugin's CATALOG, a table of templates by
//! locale that is data rather than a call, so a host never asks a plugin what its own error means.

use crate::bounded::BoundedVec;
use core::fmt;

/// The most parameters one error may carry.
pub const MAX_ERROR_PARAMS: usize = 8;

/// The most codes one catalog may declare.
pub const MAX_CATALOG_CODES: usize = 256;

/// The most locales one code may be templated in.
pub const MAX_CATALOG_LOCALES: usize = 16;

/// The closed class taxonomy.
///
/// Closed on purpose: the host keys its status, its retry policy, the record's severity and what
/// a client is shown off this and nothing else, so a plugin cannot invent a class any more than it
/// can invent a kind. Everything a plugin wants to say beyond the class goes in the code.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ErrorClass {
    /// The request is outside the plugin's grammar. The caller's, and told so.
    Malformed,
    /// The named thing does not exist. The caller's, and told so.
    NotFound,
    /// Policy refuses the caller this thing. A configuration matter, never an outage.
    Denied,
    /// The backend refused the value itself. The caller's, and told so.
    Rejected,
    /// A concurrent writer won: this side's view is stale and must re-read before it retries.
    Conflict,
    /// What came back did not authenticate, or has a gap. Never retried; always recorded.
    Integrity,
    /// The backend could not be reached. An outage to wait out.
    Unavailable,
    /// The call did not return within its deadline.
    Timeout,
    /// A bound the plugin holds was reached — a quota, a rate, a capacity. Retry later.
    Exhausted,
    /// The plugin's own fault, and every failure that predates a taxonomy.
    Internal,
}

impl ErrorClass {
    /// Every class, in declaration order.
    pub const ALL: [ErrorClass; 10] = [
        Self::Malformed,
        Self::NotFound,
        Self::Denied,
        Self::Rejected,
        Self::Conflict,
        Self::Integrity,
        Self::Unavailable,
        Self::Timeout,
        Self::Exhausted,
        Self::Internal,
    ];

    /// The one word this class is written as.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Malformed => "malformed",
            Self::NotFound => "not_found",
            Self::Denied => "denied",
            Self::Rejected => "rejected",
            Self::Conflict => "conflict",
            Self::Integrity => "integrity",
            Self::Unavailable => "unavailable",
            Self::Timeout => "timeout",
            Self::Exhausted => "exhausted",
            Self::Internal => "internal",
        }
    }
}

impl fmt::Display for ErrorClass {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// One structured value a code is about.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(untagged)]
pub enum ParamValue {
    /// A string.
    Str(String),
    /// A whole number.
    Int(i64),
    /// A flag.
    Bool(bool),
}

/// One named parameter.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Param {
    /// The name a template refers to it by.
    pub key: String,
    /// The value.
    pub value: ParamValue,
}

/// The bounded parameter list.
pub type Params = BoundedVec<Param, MAX_ERROR_PARAMS>;

/// Hints a plugin attaches to a failure. Every field is optional and means nothing when absent.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Advisory {
    /// How long the caller should wait before trying again, in milliseconds.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub retry_after_ms: Option<u64>,
    /// When the thing the failure is about stops being good, in seconds since the epoch.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<u64>,
}

/// What a plugin of any kind answers with when it fails.
///
/// The host records every field as it was given. `class` is the only field it acts on; `code`
/// and `params` are rendered through the plugin's [`Catalog`]; `developer_message` goes to the
/// log and nowhere else; `advisory` is a hint the host may take or leave.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct PluginError {
    /// Which class of failure this is.
    pub class: ErrorClass,
    /// The plugin's own stable identifier for it, namespaced by the plugin: `vault.token_expired`.
    pub code: String,
    /// The values the code is about, by the names its template uses.
    #[serde(default)]
    pub params: Params,
    /// The plugin's own rendering, for a log. Never shown to a client.
    #[serde(default)]
    pub developer_message: String,
    /// Hints.
    #[serde(default)]
    pub advisory: Advisory,
}

impl PluginError {
    /// A failure of one class under one code, with nothing else said yet.
    #[must_use]
    pub fn new(class: ErrorClass, code: impl Into<String>) -> Self {
        Self {
            class,
            code: code.into(),
            params: Params::new(),
            developer_message: String::new(),
            advisory: Advisory::default(),
        }
    }

    /// The same failure, with the plugin's own words for the log.
    #[must_use]
    pub fn with_message(mut self, developer_message: impl Into<String>) -> Self {
        self.developer_message = developer_message.into();
        self
    }

    /// The same failure with one more parameter. A parameter past the ceiling is dropped rather
    /// than growing the list: the code and the class are what the failure IS, and a lost
    /// parameter renders as its own name in the template rather than losing the failure.
    #[must_use]
    pub fn with_param(mut self, key: impl Into<String>, value: ParamValue) -> Self {
        let _ = self.params.push(Param {
            key: key.into(),
            value,
        });
        self
    }

    /// The parameter under a name, if it is set.
    #[must_use]
    pub fn param(&self, key: &str) -> Option<&ParamValue> {
        self.params
            .as_slice()
            .iter()
            .find(|p| p.key == key)
            .map(|p| &p.value)
    }
}

impl fmt::Display for PluginError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} {}", self.class, self.code)?;
        if !self.developer_message.is_empty() {
            write!(f, ": {}", self.developer_message)?;
        }
        Ok(())
    }
}

impl std::error::Error for PluginError {}

/// One code's template in one locale.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Template {
    /// The locale tag, as the host's callers spell theirs: `en`, `de-CH`.
    pub locale: String,
    /// The text, with `{param}` holes the host fills from the error's parameters.
    pub text: String,
}

/// One code and its templates.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct CatalogEntry {
    /// The code, exactly as the plugin emits it.
    pub code: String,
    /// Its templates, at most one per locale.
    pub templates: BoundedVec<Template, MAX_CATALOG_LOCALES>,
}

/// A plugin's catalog: every code it can emit, templated per locale, as data.
///
/// It ships beside the plugin's claims and is read once when the plugin is registered or loaded.
/// A code the plugin emits that is not here is the plugin contradicting its own declaration, and a
/// host refuses it. A locale the caller asks for that is not here falls back to the plugin's
/// default locale — never to the developer message, which is not a rendering.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Catalog {
    /// The locale every code is guaranteed a template in.
    pub default_locale: String,
    /// The codes.
    pub entries: BoundedVec<CatalogEntry, MAX_CATALOG_CODES>,
}

impl Catalog {
    /// A catalog that declares no code, in one default locale.
    #[must_use]
    pub fn empty(default_locale: impl Into<String>) -> Self {
        Self {
            default_locale: default_locale.into(),
            entries: BoundedVec::new(),
        }
    }

    /// The entry for a code, if the catalog declares it.
    #[must_use]
    pub fn entry(&self, code: &str) -> Option<&CatalogEntry> {
        self.entries.as_slice().iter().find(|e| e.code == code)
    }

    /// The template for a code in a locale, falling back to the default locale. `None` only when
    /// the code is not declared at all.
    #[must_use]
    pub fn template(&self, code: &str, locale: &str) -> Option<&str> {
        let entry = self.entry(code)?;
        let find = |l: &str| {
            entry
                .templates
                .as_slice()
                .iter()
                .find(|t| t.locale == l)
                .map(|t| t.text.as_str())
        };
        find(locale).or_else(|| find(&self.default_locale))
    }

    /// Whether this catalog is well-formed: a non-empty default locale, no duplicate or empty
    /// code, and every code templated in the default locale. The one check a host runs before
    /// it accepts the plugin.
    ///
    /// # Errors
    /// Names the first thing wrong.
    pub fn check(&self) -> Result<(), CatalogFault> {
        if self.default_locale.is_empty() {
            return Err(CatalogFault::NoDefaultLocale);
        }
        let entries = self.entries.as_slice();
        for (i, e) in entries.iter().enumerate() {
            if e.code.is_empty() {
                return Err(CatalogFault::EmptyCode);
            }
            if entries[..i].iter().any(|p| p.code == e.code) {
                return Err(CatalogFault::DuplicateCode(e.code.clone()));
            }
            if !e
                .templates
                .as_slice()
                .iter()
                .any(|t| t.locale == self.default_locale)
            {
                return Err(CatalogFault::MissingDefault(e.code.clone()));
            }
        }
        Ok(())
    }
}

/// What is wrong with a catalog.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CatalogFault {
    /// No default locale was declared.
    NoDefaultLocale,
    /// An entry has no code.
    EmptyCode,
    /// The same code is declared twice.
    DuplicateCode(String),
    /// A code has no template in the default locale.
    MissingDefault(String),
}

impl fmt::Display for CatalogFault {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoDefaultLocale => f.write_str("catalog declares no default locale"),
            Self::EmptyCode => f.write_str("catalog entry has an empty code"),
            Self::DuplicateCode(c) => write!(f, "catalog declares `{c}` twice"),
            Self::MissingDefault(c) => {
                write!(
                    f,
                    "catalog code `{c}` has no template in the default locale"
                )
            }
        }
    }
}

impl std::error::Error for CatalogFault {}

/// The frozen v1 refusal envelope around one code and one message.
///
/// THE SHAPE LIVES HERE AND NOWHERE ELSE. A refusal reaches a client as a two-key document a
/// client pinned — a machine-stable `code` tooling branches on and a caller-safe `message` a human
/// reads — and WHICH code a condition renders under is a different question for the side of the
/// tree that maps a plane's refusal reason than for the composition root that maps a kernel reason
/// code. Those two tables legitimately differ, because they answer different questions. The two
/// keys, their order, the quoting and the absence of a trailing byte do not: they are ONE frozen
/// wire shape, and a second `format!` of it somewhere else is a second chance for the surface a
/// client pinned to change in one place and not the other. So the callers bring the code and the
/// message, and this brings the envelope.
///
/// It sits beside [`PluginError`] rather than on it because the two answer different halves. The
/// class taxonomy above is what a PLUGIN says when it fails; the envelope is how ANY refusal is
/// written down for a client, including the node's own management surface, which has no plugin
/// behind it at all. A face every kind is written against is the one place both can be reached
/// from without either reaching the other.
///
/// SERIALIZED, not hand-formatted. The two are the same bytes for a caller that brings closed,
/// quote-free prose, and they stop being the same bytes the moment a message carries text a CALLER
/// wrote — a resource name in a not-found, the human half of a validation complaint — because a `"`
/// in one of those closes the string early and hands the reader a different document, with a `code`
/// its parser never reaches. The escape set is JSON's, not this crate's, so the honest way to apply
/// it is to ask the serializer.
///
/// The key order is `code` then `message` whichever way the map is built — the serializer orders a
/// map's keys and `code` sorts before `message` — so the frozen shape does not depend on the order
/// this function happens to insert them in.
#[must_use]
pub fn envelope_of(code: &str, message: &str) -> String {
    serde_json::json!({ "error": { "code": code, "message": message } }).to_string()
}
