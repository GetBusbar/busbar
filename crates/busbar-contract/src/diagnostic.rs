// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE DIAGNOSTIC SHAPES (DECISIONS #83: contract = shapes; #83a O3) — the catalog-entry struct a

use std::fmt;

/// The class of a diagnostic — the thousands digit of its code.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Class {
    /// 1000 — durable audit floor, single-writer detach, store-outage backfill.
    Durability,
    /// 2000 — audit chain verification, tamper evidence, snapshot restore.
    Audit,
    /// 3000 — config.yaml parse/validate/schema, providers file, overrides.
    Config,
    /// 4000 — tokens, the authorization server, egress auth, trust, request-signing credentials.
    Auth,
    /// 5000 — upstream, egress gate, SSRF guard, breaker, availability, handlers.
    Proxy,
    /// 6000 — loader, ABI floor, signature/trust, plugin_routes, hooks.
    Plugins,
    /// 7000 — the planes, export, ir, proto, plane store.
    Plane,
    /// 8000 — holds, quotas, metering, appbuild, governance state.
    Governance,
    /// 9000 — startup, tls, telemetry, eventstream, preflight, the allocator.
    Boot,
}

impl Class {
    /// The thousands multiplier: `Durability` → 1, `Boot` → 9. The code's `code / 1000`.
    pub const fn ordinal(self) -> u16 {
        match self {
            Class::Durability => 1,
            Class::Audit => 2,
            Class::Config => 3,
            Class::Auth => 4,
            Class::Proxy => 5,
            Class::Plugins => 6,
            Class::Plane => 7,
            Class::Governance => 8,
            Class::Boot => 9,
        }
    }

    /// Human title for the class, used as the section heading in the generated docs page.
    pub const fn title(self) -> &'static str {
        match self {
            Class::Durability => "Durability & write-through",
            Class::Audit => "Audit chain",
            Class::Config => "Config",
            Class::Auth => "Auth & identity",
            Class::Proxy => "Proxy & routing",
            Class::Plugins => "Plugins",
            Class::Plane => "Plane protocols",
            Class::Governance => "Governance & cost",
            Class::Boot => "Boot & lifecycle",
        }
    }

    /// Every class, in code order — the iteration order for the generated docs.
    pub const ALL: [Class; 9] = [
        Class::Durability,
        Class::Audit,
        Class::Config,
        Class::Auth,
        Class::Proxy,
        Class::Plugins,
        Class::Plane,
        Class::Governance,
        Class::Boot,
    ];
}

/// How severe a diagnostic is — this decides the log level the emitting site uses.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Severity {
    /// Expected, self-healing, may fire per request/tick. `debug!` or a `warn!`-once latch.
    BenignRecurring,
    /// An operator can and should act (misconfig, outage, refusal). `warn!` or `error!`.
    Actionable,
    /// Boot refuses / the process exits. `error!` then exit.
    Fatal,
}

impl Severity {
    /// Stable lowercase token for the machine (`diagnostics.json`) form.
    pub const fn as_str(self) -> &'static str {
        match self {
            Severity::BenignRecurring => "benign_recurring",
            Severity::Actionable => "actionable",
            Severity::Fatal => "fatal",
        }
    }
}

/// One catalog entry. Constructed as a `const` per code; all are gathered into the catalog
/// registry.
#[derive(Debug, Clone, Copy)]
pub struct Diagnostic {
    /// The numeric code, e.g. `1001`. Rendered as `BUSBAR-1001`.
    pub code: u16,
    /// The class this code belongs to; `class.ordinal()` must equal `code / 1000`.
    pub class: Class,
    /// Stable kebab-case anchor: the docs URL fragment and a rename-proof identity. Never changes.
    pub slug: &'static str,
    /// Short human title.
    pub title: &'static str,
    /// Intended severity → the log level the emitting site uses.
    pub severity: Severity,
    /// One to three sentences: what the condition means.
    pub summary: &'static str,
    /// What an operator should do, or `"None — self-heals."` for benign-recurring.
    pub action: &'static str,
    /// The version the code was introduced in.
    pub since: &'static str,
    /// A retired code: kept for historical log resolution, no longer emitted.
    pub retired: bool,
}

impl Diagnostic {
    /// The `BUSBAR-NNNN` banner, zero-allocation (a [`fmt::Display`] wrapper over the code).
    pub const fn banner(&self) -> Banner {
        Banner(self.code)
    }
}

/// `Display`s as `BUSBAR-0001`. Used as the `diag` field on every emitted line.
#[derive(Debug, Clone, Copy)]
pub struct Banner(pub u16);

impl fmt::Display for Banner {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "BUSBAR-{:04}", self.0)
    }
}

/// `warn!` carrying the `diag = "BUSBAR-NNNN"` field. First arg is the [`Diagnostic`] const. The
/// one spelling every crate emits through.
#[macro_export]
macro_rules! diag_warn {
    ($diag:expr, $($rest:tt)*) => {
        ::tracing::warn!(diag = %$diag.banner(), $($rest)*)
    };
}
/// `error!` carrying the `diag = "BUSBAR-NNNN"` field. The one spelling every crate emits through.
#[macro_export]
macro_rules! diag_error {
    ($diag:expr, $($rest:tt)*) => {
        ::tracing::error!(diag = %$diag.banner(), $($rest)*)
    };
}
/// `debug!` carrying the `diag = "BUSBAR-NNNN"` field (the benign-recurring / latched-quiet arm). The
/// one spelling every crate emits through.
#[macro_export]
macro_rules! diag_debug {
    ($diag:expr, $($rest:tt)*) => {
        ::tracing::debug!(diag = %$diag.banner(), $($rest)*)
    };
}

/// A plugin instance's scheduled tick failed; the driver retries it with backoff instead of
/// stopping. Emitted by the plugin loader's tick driver, which names no kernel catalog.
pub const PLUGIN_TICK_FAILED: Diagnostic = Diagnostic {
    code: 8029,
    class: Class::Governance,
    slug: "plugin-tick-failed",
    title: "A plugin instance's scheduled tick failed",
    severity: Severity::Actionable,
    summary: "busbar drives the tick of each secret and auth plugin instance that asks for one \
              (its own token refresh or version watch). A tick answered neither ready nor \
              pending (it failed, faulted or timed out). The schedule does not stop: the tick is \
              retried with a jittered backoff (1 second doubling to 60 seconds) until it succeeds \
              or the instance closes. Reported on the first failure and then at most once a \
              minute per instance.",
    action: "Check the plugin's own log lines for the instance named. A tick that keeps failing \
             usually means the plugin cannot reach the service it refreshes against.",
    since: "1.6.0",
    retired: false,
};

/// Usage tap: read_response could not decode a same-protocol 2xx body. Warn-once (latched).
pub const USAGE_TAP_DECODE_FAILED: Diagnostic = Diagnostic {
    code: 5029,
    class: Class::Proxy,
    slug: "usage-tap-decode-failed",
    title: "Usage tap: read_response failed to decode a same-protocol 2xx body",
    severity: Severity::BenignRecurring,
    summary: "The usage tap's `read_response` could not decode a same-protocol 2xx body into the \
              IR, so it bills 0 tokens for the request. Warned once per (protocol, reason); \
              BILLING_TAP_DECODE_FAIL_TOTAL carries the volume.",
    action: "None — self-heals per request. If a metered dialect bills 0 tokens repeatedly, the \
             upstream's response shape may have changed; check for a busbar update covering it.",
    since: "1.6.0",
    retired: false,
};

/// THE ONE DOCS URL BASE for operator error pages (owner decision 2026-11-12). It carries the
/// release's major.minor, so a message printed by 1.6 links the 1.6 page even after 1.7 ships.
/// Every docs link a code renders is this base followed by the code's [`Banner`]; nothing else
/// spells the host, the path or the version.
pub const ERROR_DOCS_BASE: &str = "https://getbusbar.com/docs/1.6/errors/";

/// The major.minor the docs base links (`"1.6"`), read out of [`ERROR_DOCS_BASE`] so the two can
/// never disagree. The page generator files pages under this version.
#[must_use]
pub fn error_docs_version() -> &'static str {
    ERROR_DOCS_BASE
        .trim_end_matches('/')
        .trim_end_matches("/errors")
        .rsplit('/')
        .next()
        .unwrap_or_default()
}

/// `Display`s as the code's docs page, e.g. `https://getbusbar.com/docs/1.6/errors/BUSBAR-3101`.
/// Zero-allocation; built only from [`ERROR_DOCS_BASE`] and the code.
#[derive(Debug, Clone, Copy)]
pub struct DocsUrl(pub u16);

impl fmt::Display for DocsUrl {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{ERROR_DOCS_BASE}{}", Banner(self.0))
    }
}

impl Diagnostic {
    /// An operator-facing message under this code: `BUSBAR-NNNN: <detail>. See <docs url>`.
    /// Error paths only — this is the one allocation a refusal makes, and no success path builds
    /// one. Prefer the typed constructor the catalog generates for a code that has a `text`
    /// template; this is the primitive those constructors call.
    #[cold]
    #[must_use]
    pub fn coded(&self, detail: impl fmt::Display) -> Coded {
        let mut detail = detail.to_string();
        // A one-line detail that already carries a coded message (a serde error wrapping a coded
        // refusal, a family wrapper around a coded cause) reports THAT code: the most specific one
        // wins, stays first, and keeps one link, last. A multi-line detail is a list whose items
        // keep their own codes; it is left as written.
        let inner = if detail.contains('\n') {
            None
        } else {
            take_inner_code(&mut detail)
        };
        let code = inner.unwrap_or(self.code);
        // The message ends `. See <link>`: a detail's own final period would double it.
        if detail.ends_with('.') {
            detail.pop();
        }
        Coded { code, detail }
    }
}

/// If `detail` holds a coded message (`BUSBAR-NNNN: ... . See <base>BUSBAR-NNNN`), strip its
/// code prefix and its link in place and return its code. Only [`Coded`]'s own rendering matches:
/// a prose mention of a code without its link is left alone.
fn take_inner_code(detail: &mut String) -> Option<u16> {
    let mut from = 0;
    while let Some(at) = detail[from..].find("BUSBAR-").map(|i| i + from) {
        let digits = detail.get(at + 7..at + 11)?;
        let code: Option<u16> = digits
            .bytes()
            .all(|b| b.is_ascii_digit())
            .then(|| digits.parse().ok())
            .flatten();
        if let Some(code) = code.filter(|_| detail[at + 11..].starts_with(": ")) {
            let link = format!(". See {}", DocsUrl(code));
            if let Some(l) = detail[at..].find(&link).map(|i| i + at) {
                detail.replace_range(l..l + link.len(), "");
                detail.replace_range(at..at + 13, "");
                return Some(code);
            }
        }
        from = at + 7;
    }
    None
}

/// One operator-facing message: a catalog code, the specific text, and the code's docs link.
/// `Display`s as `BUSBAR-NNNN: <detail>. See https://getbusbar.com/docs/<major.minor>/errors/BUSBAR-NNNN`:
/// the code first, the link last. Built only through [`Diagnostic::coded`] (and the typed
/// constructors over it), so the shape is written once.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Coded {
    code: u16,
    detail: String,
}

impl Coded {
    /// The numeric catalog code this message reports.
    #[must_use]
    pub const fn code(&self) -> u16 {
        self.code
    }

    /// The specific text, without the code or the link.
    #[must_use]
    pub fn detail(&self) -> &str {
        &self.detail
    }
}

impl fmt::Display for Coded {
    /// One line: `BUSBAR-NNNN: <detail>. See <link>`. A multi-line detail is a head and a list
    /// (`config errors:` then `  - <item>` lines, each item carrying its own code): the head line
    /// takes the code and the link, its trailing `:` or `.` dropped, and the rest follows unchanged.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let (head, rest) = match self.detail.split_once('\n') {
            Some((head, rest)) => (head.trim_end_matches([':', '.']), Some(rest)),
            None => (self.detail.as_str(), None),
        };
        write!(
            f,
            "{}: {head}. See {}",
            Banner(self.code),
            DocsUrl(self.code)
        )?;
        match rest {
            Some(rest) => write!(f, "\n{rest}"),
            None => Ok(()),
        }
    }
}

impl From<Coded> for String {
    fn from(c: Coded) -> String {
        c.to_string()
    }
}

/// The message template and worked example a code's docs page shows, beside its catalog row. The
/// row (title, summary = cause, action = fix, since, retired) is the [`Diagnostic`]; this is the
/// rest of the page. `text` is the template the code's typed constructor formats (`{name}`
/// placeholders, no trailing period); `example` is what triggers it (a config fragment or a
/// command line) and `example_detail` the template filled in for that example. The page renders
/// the example message through [`Diagnostic::coded`], so no page text spells a code or a link.
#[derive(Debug, Clone, Copy)]
pub struct ErrorText {
    /// The code this text belongs to.
    pub code: u16,
    /// The message template, `{placeholder}` per argument.
    pub text: &'static str,
    /// What triggers the code: a config fragment, a command line, a request. May be empty.
    pub example: &'static str,
    /// `text` filled in for `example` (what the operator reads, minus the code and the link).
    pub example_detail: &'static str,
}

impl ErrorText {
    /// Whether `detail` is an instance of `text`: every `{placeholder}` matches any non-empty run
    /// and every other byte matches itself. The drift check between a page's example and the
    /// template the code's constructor formats.
    #[must_use]
    pub fn matches(&self, detail: &str) -> bool {
        fn go(t: &str, d: &str) -> bool {
            match t.find('{') {
                None => t == d,
                Some(open) => {
                    let Some(close) = t[open..].find('}') else {
                        return t == d;
                    };
                    let (lit, rest) = (&t[..open], &t[open + close + 1..]);
                    let Some(after) = d.strip_prefix(lit) else {
                        return false;
                    };
                    (1..=after.len())
                        .filter(|&i| after.is_char_boundary(i))
                        .any(|i| go(rest, &after[i..]))
                }
            }
        }
        go(self.text, detail)
    }
}

/// Declares a contract-owned coded message: the template as a `pub const` and a typed constructor
/// that formats exactly that template (the compiler checks every `{placeholder}` against the
/// arguments). For codes the contract itself must emit; host codes get the same pair generated
/// from `catalog.toml`.
#[macro_export]
macro_rules! coded_text {
    ($(#[$meta:meta])* $vis:vis fn $fn:ident($($arg:ident),* $(,)?) => $diag:path, $text_const:ident = $text:literal) => {
        #[doc = concat!("The message template of [`", stringify!($fn), "`].")]
        pub const $text_const: &str = $text;
        $(#[$meta])*
        #[cold]
        $vis fn $fn($($arg: impl ::core::fmt::Display),*) -> $crate::diagnostic::Coded {
            $diag.coded(format!($text, $($arg = $arg),*))
        }
    };
}

/// A registration is named with a word the section reserves. Contract-owned: the section splitter
/// in [`crate::section`] refuses it, and the host catalog re-exports this row.
pub const CONFIG_RESERVED_NAME: Diagnostic = Diagnostic {
    code: 3101,
    class: Class::Config,
    slug: "config-reserved-name",
    title: "A registration is named with a reserved word",
    severity: Severity::Fatal,
    summary: "Inside a section that registers named entries (`pools:`, `tools:`, `agents:`, \
              `streams:`, `decisions:` and the rest), a few keys belong to Busbar: the \
              section-level `hooks`, `upstream_credentials` and `usage_observations`, and the \
              core-owned settings `pools`, `breaker`, `on_exhausted`, `affinity`, `gates`, `tier`, \
              `repeatable`, `work`, `timeout`, `rate_card` and `fees`. A registration that takes one \
              of those names cannot be told apart from the setting, so the configuration is refused \
              at `--validate` and at startup.",
    action: "Rename the registration; any name not on the list works. Then run `busbar --validate`. \
             The reserved names and what each is for are tabled in docs/configuration.md \
             (Reserved names).",
    since: "1.6.0",
    retired: false,
};

/// The page text of the contract-owned codes, by code (the host catalog adds its own).
pub static CONTRACT_TEXTS: &[ErrorText] = &[ErrorText {
    code: CONFIG_RESERVED_NAME.code,
    text: crate::section::RESERVED_NAME_TEXT,
    example: "pools:\n  hooks:            # a pool named `hooks`\n    members: [gpt-4o]",
    example_detail: "a pool may not be named `hooks` (reserved in `pools:`)",
}];
