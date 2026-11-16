// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The plugin header, `Open`, `Endpoints`, `Describe`, and the `plugin!`/`export!` macros (IF §7.1, §7.2, §7.7). W0-ABI stub: frozen signatures, `todo!()` bodies; A4 fills it.

use core::marker::PhantomData;

use crate::fail::Fail;
use crate::host::Host;
use crate::need::ChainBytes;
use crate::records::{Full, Nested, Out};

/// The plugin header, `OPEN_DRY_RUN` and the exported symbol name are busbar-ffi's (UNSAFE-MIN r3.1): the header
/// holds `unsafe extern "C"` entries and raw table pointers, and only `plugin()` builds one. Re-exported here
/// under their frozen paths; their `mechanism!` block is busbar-ffi's, folded into `CORE_FP` after this crate's.
pub use busbar_ffi::header::{OPEN_DRY_RUN, Plugin, SYMBOL};
// W0-ABI: `pub type EntryFn = unsafe extern "C" fn() -> *const Plugin;` lands with W1-A4 (an unsafe fn pointer
// type).

/// Every plugin type implements its kind trait and this.
pub trait Open: Sized + Send + Sync + 'static {
    /// Build the instance. May await Need steps (connect, fetch JWKS, SECRET by handle). `config` is the bound
    /// JSON (§12.7); keep SecretHandle/TrustHandle values, never resolved secret bytes, in long-lived state
    /// unless the protocol needs the value on every call (then wrap it in `zeroize::Zeroizing`).
    ///
    /// Round 31 (owner ruling, §47): **`open` is the plugin's migration.** Before it answers INSTANCE it brings
    /// its own data and its own settings to its current format, keyed on its own markers (current data: one
    /// marker read, nothing written), on every load path (boot, reload, admin install), so a plugin upgraded
    /// without an engine upgrade converts itself. `config` may be any older settings shape the plugin supports.
    /// Older and supported: convert, then serve. Data or settings newer than the plugin knows: Fail REFUSED
    /// R_VERSION, text starting NEWER; unknown or unsupported: REFUSED R_VERSION; the plugin writes nothing then.
    /// `config` is bound with `bind_any` on an unstamped boot (a 1.x bag whose older positions no describe
    /// declares) and with `bind` on every other load path (a 1.6+ older shape is declared by D_*_PATH; §12.7).
    /// A store calls `h.migrate_admit(n)` (§5) before handing core recoverable rows.
    /// **Live instances.** On reload or admin install the old instance is still serving while the new one opens;
    /// a plugin whose conversion cannot run beside its own running older instance refuses R_CONFLICT
    /// (LIVE_WRITER) and writes nothing, and the old instance keeps serving. That check is the plugin's own (its
    /// lock and live-writer rules, MIGRATE-ON-BOOT §A5), not core's.
    /// **Refusal.** A refused open fails that instance. At boot the existing rule for a failed open applies
    /// unchanged (origin/dev): a store or a gate hook that fails to open refuses the boot (kernel hooks/mod.rs
    /// `preopen_definitions`, fail-closed); a non-gate hook that fails to open is treated as absent and logged
    /// (hooks/mod.rs `open_resolved`, fail-open); every other kind keeps its existing rule. The owner's "fails
    /// that instance only" applies to reload and admin install: there the old instance keeps serving.
    fn open(
        h: &'static Host,
        config: ChainBytes,
    ) -> impl Future<Output = Result<Self, Fail>> + Send;
    /// Round 31, provided: the canonical settings and core config `open` returns beside INSTANCE (CONFIG +
    /// CORE_CFG*, §3), written by the shim after `open` succeeded; the default writes nothing (the bag was
    /// canonical). A plugin that converted an older bag writes it with `abi::settled::config(w, bag')` and
    /// `abi::settled::core_cfg(w, section, name, value_json)`. Core first maps CONFIG and every CORE_CFG value
    /// back through its own reference map (`binder.unbind_refs`, §12.7: every handle back to the operator's text,
    /// every resolved D_REF_PATH value back to the operator's reference; a resolved plain value is never written
    /// back), writes nothing when the bytes equal what it holds, and keeps no per-plugin version. Then core (never
    /// a helper session) writes them back uninterpreted, by load path (MIGRATE-ON-BOOT §3 step 5W, §4):
    /// unstamped boot: K9's step 5; stamped boot: step 5W, the seam (`root/migrate.rs`, in-process) after step 4
    /// and before step 6; reload: the kernel's reload path, after the new instance is swapped in. Those two take
    /// the config directory lock (`<f>.busbar-lock`, MIGRATE-ON-BOOT §A3 5L), re-read config.yaml (changed since
    /// the load read it: no write) and write through the patch writer; admin install: the admin config store's
    /// own write, after the install. A failed or skipped write-back is logged and audited and the instance keeps
    /// serving; the next load converts again.
    /// Round 33: an export instance may also write here, last, one `export::tag::CUSTODY` record
    /// (CustodyRec{level, 0}): its custody ceiling (§8.5). No other kind record is admitted after INSTANCE.
    fn settled(&self, w: &mut Out<'_>) -> Result<(), Full> {
        let _ = w;
        Ok(())
    }
    /// DRY_RUN: parse and validate config only. No I/O. Refuse with R_CONFIG and a text naming the field.
    /// Round 31: accepts every settings shape `open` accepts (current and older).
    /// Round 32 (TRANSPORT-SECURITY-POLICY §2): states every endpoint this config will OPEN or FETCH, exactly as
    /// the Need will state it; the shim writes them as ENDPOINT records. A fact, not a permission (core judges).
    fn check(h: &Host, config: &[u8], ends: &mut Endpoints<'_>) -> Result<(), Fail>;
    /// Optional. The default declares the kind's REQUIRED methods and nothing else.
    fn describe(d: &mut Describe<'_>) {
        let _ = d;
    }
}

/// Round 32: the ENDPOINT writer `check` receives (TRANSPORT-SECURITY-POLICY §2). A 17th call, a dest over
/// 2,048 bytes or a `Full` out buffer makes the shim answer INVALID (CONFIG refused, naming the instance).
pub struct Endpoints<'a> {
    // W0-ABI: the private field (an `Out<'a>`) lands with W1-A4.
    _stub: PhantomData<&'a ()>,
}
impl Endpoints<'_> {
    /// One endpoint this config will OPEN: dest and TLS mode exactly as the OPEN states them.
    pub fn open(&mut self, dest: &str, tls: u32, egress: u32) -> &mut Self {
        let _ = (dest, tls, egress);
        todo!()
    }
    /// One URL this config will FETCH (`https://` = TLS, `http://` = none).
    pub fn fetch(&mut self, url: &str, egress: u32) -> &mut Self {
        let _ = (url, egress);
        todo!()
    }
}

pub struct Describe<'a> {
    // W0-ABI: the private fields (an `Out<'a>`, the kind's REQUIRED mask) land with W1-A4.
    _stub: PhantomData<&'a ()>,
}
impl Describe<'_> {
    /// Method bits from the kind's M_* consts. Replaces the default. Core refuses (CapUnknown) any bit not in the kind.
    pub fn methods(&mut self, mask: u64) -> &mut Self {
        let _ = mask;
        todo!()
    }
    /// Kind fact bits (F_* in the kind's consts).
    pub fn facts(&mut self, mask: u64) -> &mut Self {
        let _ = mask;
        todo!()
    }
    /// JSON Schema of the config. Core validates config against it before `open`. Round 31: it covers every
    /// shape `check` accepts, and core validates a returned CONFIG against it too (a mismatch fails the
    /// instance). D_SECRET_PATH / D_TRUST_PATH / D_REF_PATH likewise declare the positions of every accepted shape.
    pub fn schema(&mut self, json_schema: &'static str) -> &mut Self {
        let _ = json_schema;
        todo!()
    }
    /// Output cap per call. Core clamps it to its own ceiling (default 1 MiB, store 16 MiB).
    pub fn max_out(&mut self, bytes: u64) -> &mut Self {
        let _ = bytes;
        todo!()
    }
    /// Wall-clock ceiling for one sync call of `method` (one M_ bit), or the first poll of its async chain; or,
    /// with `abi::CEIL_OPEN`, the first poll of `open` (round 31: migration included). Clamped by core into
    /// the §10.6 range (round 11). Watchdog input.
    pub fn ceiling_us(&mut self, method: u64, micros: u64) -> &mut Self {
        let _ = (method, micros);
        todo!()
    }
    /// A config position that holds a secret reference (D_SECRET_PATH, JSON Pointer, `*` = any array index).
    pub fn secret_path(&mut self, pointer: &'static str) -> &mut Self {
        let _ = pointer;
        todo!()
    }
    /// A config position that holds an operator PEM CA (D_TRUST_PATH).
    pub fn trust_path(&mut self, pointer: &'static str) -> &mut Self {
        let _ = pointer;
        todo!()
    }
    /// Round 7, export only: a config position that holds a file-sink destination (D_DEST_PATH; `""` = the
    /// whole bag). Core binds it to `{"$dest": n}` (§12.7); embed `DEST_SCHEMA` there in D_SCHEMA.
    pub fn dest_path(&mut self, pointer: &'static str) -> &mut Self {
        let _ = pointer;
        todo!()
    }
    /// Round 13: a config position whose plain value the operator may write as a secret reference (D_REF_PATH);
    /// core hands the plugin the resolved plain string (§12.7). D_SCHEMA states the plain type there.
    pub fn ref_path(&mut self, pointer: &'static str) -> &mut Self {
        let _ = pointer;
        todo!()
    }
    /// Round 14, plane only: the config position where core writes its top-level `public_url` (D_PUBLIC_URL_PATH,
    /// a JSON string or `null`). D_SCHEMA states `{"type": ["string", "null"]}` there.
    pub fn public_url_path(&mut self, pointer: &'static str) -> &mut Self {
        let _ = pointer;
        todo!()
    }
    /// Round 22, plane only: the config position where core writes the caller-connection upstream names
    /// (D_CALLER_UPSTREAMS_PATH). D_SCHEMA states `{"type": "array", "items": {"type": "string"}}` there.
    pub fn caller_upstreams_path(&mut self, pointer: &'static str) -> &mut Self {
        let _ = pointer;
        todo!()
    }
    /// A metric this plugin reports through METRIC records (D_METRIC, §12.17). kind = metric::MX_*.
    pub fn metric(
        &mut self,
        id: u32,
        kind: u32,
        name: &'static str,
        help: &'static str,
        label_keys: &[&'static str],
    ) -> &mut Self {
        let _ = (id, kind, name, help, label_keys);
        todo!()
    }
    /// Round 34 (PLUGIN-ERROR-CODES): the error numbers this plugin's Fails (`Fail::with_error`) and
    /// `Host::log_error` lines may carry (D_ERRORS): strictly ascending, 1..=256 of them, each 1..=9999. A plugin
    /// writes `pub const ERRORS: &[u16] = &[7070, 7071];` and `d.errors(ERRORS)`. Docs text lives in the repo's
    /// `docs/diagnostics.json`, never in the binary.
    pub fn errors(&mut self, numbers: &'static [u16]) -> &mut Self {
        let _ = numbers;
        todo!()
    }
    /// A kind describe item (tag 0x0180..=0x01FF, declared in that kind's `tags {}`).
    pub fn item(&mut self, tag: u16, body: &[u8]) -> &mut Self {
        let _ = (tag, body);
        todo!()
    }
    pub fn item_text(&mut self, tag: u16, text: &str) -> &mut Self {
        let _ = (tag, text);
        todo!()
    }
    /// A kind describe item whose body is nested records (D_SUGAR, D_SCOPE-style items). Round 6.
    pub fn item_nested(
        &mut self,
        tag: u16,
        f: impl FnOnce(&mut Nested<'_>) -> Result<(), Full>,
    ) -> &mut Self {
        let _ = (tag, f);
        todo!()
    }
}

/// Emits a plugin's stamp, kind vtable, header and shims (IF §7.7). W0-ABI stub: every invocation is a
/// compile error until W1-A4 lands the macro.
///
/// ```text
/// // In the plugin's logic crate (lib.rs). Requires T: <Kind> + Open.
/// busbar_plugin_abi::plugin!(Auth, MyAuth);
/// busbar_plugin_abi::plugin!(Auth, MyAuth, engine_min: "1.6.2", engine_max: "1.6.4");
/// busbar_plugin_abi::plugin!(Transport, Rtc, out_of_process);                   // sets STAMP_OUT_OF_PROCESS
/// busbar_plugin_abi::plugin!(Secret, Fixture, name: "fixture-secret-a");        // fixtures only (r10 D66)
/// busbar_plugin_abi::plugin!(Store, Sqlite, former_names: "sqlite,busbar-store-sqlite-plugin"); // round 11: alias + former name (§7.1, §12.10 item 2)
/// busbar_plugin_abi::plugin!(Export, Prometheus, former_names: "prometheus");   // round 9: an alias is a former_names word
/// // Arms may combine, in this order: engine_min, engine_max, out_of_process, former_names, name.
/// // Round 28: there is no publisher-tier arm. A plugin that binds to this install reads the stable 16-byte install
/// // identity with Host::deployment_id inside its own `check`, which `open` also calls. It is None during boot steps
/// // 2a/2b; core re-runs `check` for 2a/2b instances once it is known (§11.2). Helper crates: §15 rule 1a.
/// ```
///
/// ```text
/// - `plugin!` emits: `static STAMP: Stamp` (crate-local, mangled, no `#[used]` and no link_section, as in r10
///   §2.3.2); `static VT: <kind>::Vt = <kind>::vt::<T>()`; `pub static PLUGIN: Plugin` (with `former_names` =
///   the arm's text, const-validated, or `Str::EMPTY`); and the describe/open/resume/cancel/close shims (round 31:
///   no `migrate` shim; the `open` shim writes `Open::settled` after INSTANCE),
///   each wrapped in `entry(..)` (§6.4 step 0); the `open` shim puts its chains on the image's one
///   `static GLOBAL: Slots<ChainBox>`. `resume` and `cancel` dispatch first on `inst`: **null → `GLOBAL`** (bit 63
///   clear: that chain; bit 63 set: no-op OK), non-null → token bit 63 to the chain slots or the session slots of
///   `Inst<T, S>` (§6.5). No shim dereferences a null `inst`; `close` is never called with null (the host has no
///   instance to close before INSTANCE, §10.4).
/// - **Linked plugins** (dist/default) register `&logic_crate::PLUGIN` with the loader (§11.2). There is no symbol.
/// - **Stamp values:** kind and kind_abi from the kind module; mechanism = 2; layout = semantic = `<kind>::FP`;
///   mechanism_layout = mechanism_semantic = CORE_FP; crypto = `"host"`, except with `out_of_process`, where it is
///   the build-time `env!("BUSBAR_PLUGIN_CRYPTO")` (the backend name the plugin's own out-of-process host links;
///   plugins never name a crypto crate, §15.4); admit compares it with `busbar_crypto::BACKEND` (§11.1); the
///   remaining fields as r10.
///   No first-party plugin uses `out_of_process` after round 2 (webrtc is an in-process datagram framer, §8.7).
///
/// Complete glue for a plugin is the `plugin!` line, the `export!` line, `impl Open` and the kind impl.
/// ```
#[macro_export]
macro_rules! plugin {
    ($($tt:tt)*) => {
        ::core::compile_error!("plugin! lands with W1-A4 (IF §7.7)");
    };
}
