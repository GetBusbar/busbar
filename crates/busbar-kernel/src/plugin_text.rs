// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Plugin text and the code beside it, the one kernel type every plugin-derived string travels as (IF §12.16
//! round 34, §50; PLUGIN-ERROR-CODES r4 §2.6).
//!
//! The text is the plugin's, exactly the scrubbed text §12.16 produces (whole scrub, then the 512-byte cut), with
//! no scanning, stripping or rewriting of a `BUSBAR-...` the plugin wrote. The code is core's own, written into its
//! own field `plugin_diag` and never into the text. The joined `"{code}: {text}"` exists only for text lines and
//! one-string displays, where the prefix is added after the cut, so a plugin keeps its full 512 bytes.

use busbar_plugin_abi::host_side::scrub::{fail_text, Scrub};
use busbar_plugin_loader::ports::PortError;

/// The resolved code (IF §11.2): `Copy` over `&'static`, `Display` = `BUSBAR-{plugin}-{number:04}`, which can never
/// start like a core `BUSBAR-[0-9]{4}` code. The loader's type, so the kernel renders exactly what it resolved.
pub use busbar_plugin_loader::instance::PluginCode;

/// The JSON member that holds the plugin's raw text.
pub(crate) const TEXT_MEMBER: &str = "text";
/// The JSON member that holds the core-written code (string or `null`), always beside `TEXT_MEMBER`.
pub(crate) const DIAG_MEMBER: &str = "plugin_diag";

/// Plugin text as core holds it: the plugin's scrubbed text and the code core resolved for it, if any. Its JSON
/// serializer writes the raw text member and `plugin_diag` (string or `null`), always together, into the object
/// that holds it (`#[serde(flatten)]`, or [`PluginText::write_members`] for a `serde_json` map); its `Display` is
/// the joined `"{code}: {text}"` (or `"{text}"`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PluginText {
    pub code: Option<PluginCode>,
    pub text: Box<str>,
}

impl PluginText {
    /// Text that is already the §12.16 shown text (a `PortError`'s, which the shared builder scrubbed and cut).
    #[must_use]
    pub fn new(code: Option<PluginCode>, text: impl Into<Box<str>>) -> Self {
        Self {
            code,
            text: text.into(),
        }
    }

    /// Raw plugin text: `scrub::fail_text` first (whole needles, URL userinfo, credential parameters, a wire-cut
    /// tail), then the 512-byte cut. The code is never part of what is scrubbed or cut.
    #[must_use]
    pub fn scrubbed(scrub: &Scrub, code: Option<PluginCode>, raw: &str) -> Self {
        Self {
            code,
            text: fail_text(scrub, raw).into(),
        }
    }

    /// The plugin text of a port error, with its code; None for a `CallError`, which carries no plugin text.
    #[must_use]
    pub fn of_port_error(e: &PortError) -> Option<Self> {
        match e {
            PortError::Refused { text, error, .. } | PortError::Failed { text, error, .. } => {
                Some(Self {
                    code: *error,
                    text: text.clone(),
                })
            }
            PortError::Call(_) => None,
        }
    }

    /// The raw text, byte-exact, with no prefix.
    #[must_use]
    pub fn text(&self) -> &str {
        &self.text
    }

    /// Writes both members into a JSON object: `text` raw and `plugin_diag` (string or `null`). An existing
    /// member of either name is replaced, so the pair can never disagree.
    pub fn write_members(&self, object: &mut serde_json::Map<String, serde_json::Value>) {
        object.insert(
            TEXT_MEMBER.into(),
            serde_json::Value::String(String::from(&*self.text)),
        );
        let diag = match self.code {
            Some(code) => serde_json::Value::String(code.to_string()),
            None => serde_json::Value::Null,
        };
        object.insert(DIAG_MEMBER.into(), diag);
    }
}

impl core::fmt::Display for PluginText {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self.code {
            Some(code) => write!(f, "{code}: {}", self.text),
            None => f.write_str(&self.text),
        }
    }
}

/// `plugin_diag` as a JSON value: the code through its `Display`, never a `String` held beside it.
struct Diag(PluginCode);

impl serde::Serialize for Diag {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(&self.0)
    }
}

impl serde::Serialize for PluginText {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeMap as _;
        let mut map = serializer.serialize_map(Some(2))?;
        map.serialize_entry(TEXT_MEMBER, &*self.text)?;
        map.serialize_entry(DIAG_MEMBER, &self.code.map(Diag))?;
        map.end()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SENT: &str = "  BUSBAR-6013 bad\tthing\nx\x1b[2K";

    fn acme(number: u16) -> PluginCode {
        PluginCode {
            plugin: "acme-store",
            number,
        }
    }

    #[derive(serde::Serialize)]
    struct Row<'a> {
        message: &'a str,
        #[serde(flatten)]
        plugin: &'a PluginText,
    }

    /// PLUGIN-ERROR-CODES T1a (the kernel half): the structured form carries the sent bytes raw, no prefix, and
    /// the code in its own member, beside core's own `message`.
    #[test]
    fn plugin_text_structured_byte_exact() {
        let t = PluginText::new(Some(acme(3)), SENT);
        let row = serde_json::to_value(Row {
            message: "open refused",
            plugin: &t,
        })
        .expect("serialize");
        assert_eq!(row["text"], SENT);
        assert_eq!(row["plugin_diag"], "BUSBAR-acme-store-0003");
        assert_eq!(row["message"], "open refused");
        let mut map = serde_json::Map::new();
        map.insert("text".into(), serde_json::Value::Bool(true));
        t.write_members(&mut map);
        assert_eq!(map["text"], SENT);
        assert_eq!(map["plugin_diag"], "BUSBAR-acme-store-0003");
    }

    /// T2: a no-code text that looks like a core code stays the plugin's text; `plugin_diag` is `null`.
    #[test]
    fn plugin_never_renders_a_core_code() {
        let t = PluginText::new(None, "BUSBAR-4013: egress key invalid");
        let v = serde_json::to_value(&t).expect("serialize");
        assert_eq!(v["plugin_diag"], serde_json::Value::Null);
        assert_eq!(v["text"], "BUSBAR-4013: egress key invalid");
        assert_eq!(t.to_string(), "BUSBAR-4013: egress key invalid");
        let declared = PluginText::new(Some(acme(6013)), "x");
        let diag = serde_json::to_value(&declared).expect("serialize")["plugin_diag"].clone();
        let diag = diag.as_str().expect("a string");
        assert_eq!(diag, "BUSBAR-acme-store-6013");
        assert!(!diag.as_bytes()[7].is_ascii_digit(), "{diag}");
    }

    /// The joined display: the code first, then the text unchanged; no code, the text alone.
    #[test]
    fn display_joins_code_and_text() {
        assert_eq!(
            PluginText::new(Some(acme(71)), "m").to_string(),
            "BUSBAR-acme-store-0071: m"
        );
        assert_eq!(PluginText::new(None, "m").to_string(), "m");
    }

    /// T8: a registered secret inside the text is masked; the code is intact and outside the scrubbed part.
    #[test]
    fn scrub_applies_before_prefix() {
        let scrub = Scrub::new();
        scrub.register(1, &[b"hunter2-secret"]);
        let t = PluginText::scrubbed(&scrub, Some(acme(3)), "login failed for hunter2-secret");
        assert!(!t.text().contains("hunter2-secret"), "{}", t.text());
        assert!(t.to_string().starts_with("BUSBAR-acme-store-0003: "));
    }

    /// The prefix is added after the cut: a 600-byte text keeps exactly 512 bytes, and the joined form adds the
    /// code in front of all of them.
    #[test]
    fn the_prefix_never_costs_the_plugin_bytes() {
        let raw = "a".repeat(600);
        let t = PluginText::scrubbed(&Scrub::new(), Some(acme(3)), &raw);
        assert_eq!(
            t.text().len(),
            busbar_plugin_abi::host_side::scrub::FAIL_TEXT_SHOWN
        );
        assert_eq!(
            t.to_string().len(),
            "BUSBAR-acme-store-0003: ".len() + t.text().len()
        );
    }

    /// A port error's text and code come across together; a CallError carries no plugin text.
    #[test]
    fn port_errors_carry_their_text_and_code() {
        let e = PortError::Refused {
            code: 5,
            text: "bad".into(),
            error: Some(acme(3)),
        };
        assert_eq!(
            PluginText::of_port_error(&e),
            Some(PluginText::new(Some(acme(3)), "bad"))
        );
        let call = PortError::Call(busbar_plugin_abi::fail::CallError::Deadline);
        assert_eq!(PluginText::of_port_error(&call), None);
    }
}
