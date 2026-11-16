// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The config binder's interface (IF §12.7, round 35 R7b): declared here, in the crate whose `Registry::new`
//! names it; `busbar_kernel::plugin_config` re-exports it and W1-K7 implements `ConfigBinder` there. `Bindings`
//! stays in the kernel. Every path and signature is the §12.7 text; only the home moved.

use busbar_plugin_abi::host_side::caller::BoxFut;

/// Round 7. A file-sink destination bound at a D_DEST_PATH node (operator grammar, unchanged from 1.5.x
/// export-file: `{path: string, rotate_mb?: u64 (default 64), keep?: u32 (default 9; 0 = truncate in place)}`).
/// `path` must pass today's DESTINATION admission, unchanged (the rule origin/dev applies before a `disk_append`
/// grant: plugin-loader host_services.rs:3209 and its test `disk_append_writes_only_to_a_granted_bound_destination`),
/// and `keep` ≤ host_disk.rs `MAX_KEEP` (64), else BindError::BadDest. The plugin sees only `{"$dest": n}`.
pub struct DestDef {
    pub path: Box<str>,
    pub rotate_mb: u64,
    pub keep: u32,
}
/// Parsed PEM certificates (one or more), plus their SHA-256 for pool keys and audit.
pub struct TrustAnchor {
    pub der: Vec<Vec<u8>>,
    pub sha256: [u8; 32],
}
#[derive(Debug)]
pub enum BindError {
    NotAReference {
        pointer: Box<str>,
    },
    StraySecret {
        pointer: Box<str>,
    },
    BadPem {
        pointer: Box<str>,
    },
    BadDest {
        pointer: Box<str>,
    },
    /// Round 8: a secret reference whose `settings` fail the target secret instance's D_REF_SCHEMA (§8.2). `text`
    /// is core-written (the failing keyword and pointer, plus the shorthand's `names` text); never plugin text.
    BadReference {
        pointer: Box<str>,
        text: Box<str>,
    },
    TooMany,
}
pub trait ConfigBinder: Send + Sync + 'static {
    /// Round 6: install the declared shorthands (from `Registry::sugars()` through `Sugars::declare`), once, after
    /// every plugin is admitted and before the first `bind`/`bind_any`. A bind before it is a core bug (panics in
    /// debug, refuses in release). Core itself declares no word.
    fn set_sugars(&self, sugars: std::sync::Arc<busbar_contract::secret_ref::Sugars>);
    /// Round 8: install, once and at the same point as `set_sugars`, each configured secret instance's reference
    /// schema (its plugin's D_REF_SCHEMA, compiled once by the binder). Key = the secret instance's configured
    /// name (operator vocabulary; an implicit shorthand instance is keyed by its `<word>`). From then on every
    /// `bind`, `bind_any` and core section parser validates each SecretRef's `settings` against the schema of the
    /// instance it routes to, before the reference is stored (`BadReference`). `--validate` runs this too.
    fn set_ref_schemas(&self, schemas: Vec<(std::sync::Arc<str>, Box<str>)>);
    /// Walk `config` (the operator's JSON for this instance). At every node matched by a D_SECRET_PATH
    /// pointer: parse it with busbar-contract's SecretRef parser in the admitted-source context with the
    /// installed `Sugars` (secret_ref.rs `context`: SourceReference, a declared shorthand `{<word>: X}` expanded to
    /// its SourceReference, TemplateReference with its FillSource from the FILL-role source, or "none"), append it
    /// to `secrets` and replace the node with `{"$secret": n}`. At every D_TRUST_PATH node: parse the PEM,
    /// append to `trust`, replace with `{"$trust": n}`. Any `$secret`-shaped object or SourceReference outside
    /// a declared path => StraySecret (the operator config is refused; nothing reaches the plugin). The
    /// result contains no `module` and no other plugin identity anywhere (I2, C-BLIND). Stores the Bindings
    /// under `instance` and returns the bound config bytes.
    /// Round 7: `dest_paths` (D_DEST_PATH, export only): each node is parsed as a DestDef, appended to `dests`
    /// and replaced by `{"$dest": n}`.
    /// Round 13: `ref_paths` (D_REF_PATH, any kind): a node holding a plain JSON string is left as is; a node that
    /// parses as a SecretRef (same parser and `Sugars` as D_SECRET_PATH, D_REF_SCHEMA checked) is appended to
    /// `refs` with its concrete pointer and left in place until `resolve_refs`; anything else is NotAReference.
    /// A reference at a D_REF_PATH node is not StraySecret.
    fn bind(
        &self,
        instance: u64,
        config: &[u8],
        secret_paths: &[&str],
        trust_paths: &[&str],
        dest_paths: &[&str],
        ref_paths: &[&str],
    ) -> Result<Vec<u8>, BindError>;
    /// Round 13, cold: resolve every `refs` entry of `instance` through custody (`SecretCustody::resolve`, §12.2,
    /// registering the value in the instance's scrub set) and write each value, as a JSON string, at its node of
    /// `bound`. A value that is not UTF-8, or a failed resolve, is `BadReference` naming the pointer (core text).
    /// The registry calls it after `bind` and before validating against D_SCHEMA, so `check` and `open` see plain
    /// strings; the returned buffer is zeroized when `open` returns. No refs: returns `bound` unchanged, no I/O.
    // The IF writes `zeroize::Zeroizing<Vec<u8>>`, which core bans (LR-094); its replacement is `SecureVec`.
    fn resolve_refs<'a>(
        &'a self,
        instance: u64,
        bound: Vec<u8>,
    ) -> BoxFut<'a, Result<busbar_contract::secure::SecureVec, BindError>>;
    fn unbind(&self, instance: u64);
    /// Round 31: `open` on an **unstamped boot only** (§7.2, §11.2), where the plugin may receive a 1.x bag
    /// whose older positions no current describe declares; every other load path uses `bind`. Every declared
    /// path is bound exactly as `bind` binds it (D_TRUST_PATH, D_DEST_PATH, and D_REF_PATH recorded in `refs` and
    /// resolved by `resolve_refs` before `open`). In addition, every other JSON object that parses as a SecretRef
    /// under the installed `Sugars` (SourceReference, a declared shorthand object, or TemplateReference) **at any
    /// position** is appended to `secrets` and replaced by `{"$secret": n}` (not StraySecret), and a plain JSON
    /// string at a D_SECRET_PATH node is left as is (a 1.x literal, for CORE_CFG(LIFT); not NotAReference); PEM
    /// text outside D_TRUST_PATH is left in place. Generic: no plugin name, no per-plugin path, no shorthand word
    /// of core's own. The result carries no `module` and no shorthand word anywhere (I2), so a 1.5.5 `{env: X}`
    /// at an undeclared position reaches the plugin's `open` only as a handle. `unbind_refs` restores the
    /// operator's original text (the shorthand stays a shorthand).
    fn bind_any(
        &self,
        instance: u64,
        config: &[u8],
        secret_paths: &[&str],
        trust_paths: &[&str],
        dest_paths: &[&str],
        ref_paths: &[&str],
    ) -> Result<Vec<u8>, BindError>;
    /// The inverse, core's reference map applied to `open`'s CONFIG and CORE_CFG values (§11.2 `take_settled`),
    /// for a bag bound by `bind` or `bind_any`: every `{"$secret": n}`, `{"$trust": n}` and `{"$dest": n}` back
    /// to the operator's original text for `instance`; and at every `refs` entry (D_REF_PATH), a JSON string
    /// equal to that entry's resolved value, at its recorded pointer or at any D_REF_PATH pointer of the current
    /// describe (a field the conversion moved), back to the operator's original reference text. A resolved plain
    /// value is never written back: one found anywhere else => NotAReference naming the pointer (core text; the
    /// write-back is skipped, logged and audited, the instance keeps serving). An n that was not bound =>
    /// NotAReference (the plugin invented one).
    fn unbind_refs(&self, instance: u64, bound: &[u8]) -> Result<Vec<u8>, BindError>;
    /// Custody's lookup. None for an unknown instance or an out-of-range handle.
    fn secret(&self, instance: u64, handle: u32) -> Option<busbar_contract::secret_ref::SecretRef>;
    /// The connector's lookup for OPEN/STARTTLS/FETCH `trust`.
    fn trust(&self, instance: u64, handle: u32) -> Option<std::sync::Arc<TrustAnchor>>;
    /// Round 24, the connector's check for a `unix:` OPEN on a pool miss (§12.1 rule (5)): whether `path` equals
    /// one of the ≤ 16 `unix_paths` `bind` computed from the instance's operator config (more: `TooMany`).
    /// False for an unknown instance. No allocation; a linear byte compare.
    fn unix_path(&self, instance: u64, path: &str) -> bool;
    /// Round 7: the export pump's lookup for APPEND `dest` (§12.21).
    fn dest(&self, instance: u64, handle: u32) -> Option<std::sync::Arc<DestDef>>;
}
