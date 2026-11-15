// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Plugin text and the code beside it, the one kernel type every plugin-derived string travels as (IF §12.16 round 34, §50; PLUGIN-ERROR-CODES r4 §2.6). W0-ABI stub: frozen signatures, `todo!()` bodies; W1-K8D fills it.

// W0-ABI: stand-in for busbar-plugin-loader's `PluginCode` (IF §11.2), field for field. The kernel does not depend
// on plugin-loader in wave 0; W1-K8D replaces this definition with the loader's type (a `pub use`) when that
// dependency lands. It carries no `Display` here: the loader's type owns it.
/// The resolved code, `Copy` over `&'static`, so carrying it does no refcount RMW (B-SYNC REFUSED arm unchanged).
/// `Display` = `BUSBAR-{plugin}-{number:04}`; it always matches `^BUSBAR-[a-z][a-z0-9-]{0,63}-[0-9]{4}$` and can
/// never start like a core `BUSBAR-[0-9]{4}` code.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PluginCode {
    pub plugin: &'static str,
    pub number: u16,
}

/// Plugin text as core holds it: the plugin's scrubbed text (whole scrub, then the 512-byte cut) and the code
/// core resolved for it, if any. Its JSON serializer writes the raw text member and `plugin_diag` (string or
/// `null`), always together; its `Display` is the joined `"{code}: {text}"` (or `"{text}"`).
// W0-ABI: the IF fixes `code: Option<PluginCode>` and leaves the type of `text` open; the stub uses `Box<str>`
// (the type `PortError` carries plugin text in, IF §11.3). The JSON serializer is W1-K8D's.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PluginText {
    pub code: Option<PluginCode>,
    pub text: Box<str>,
}

impl core::fmt::Display for PluginText {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let _ = (&self.code, &self.text, f);
        todo!()
    }
}
