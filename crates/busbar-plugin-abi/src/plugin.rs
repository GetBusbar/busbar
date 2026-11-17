// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The plugin header, `Open`, `Endpoints`, `Describe`, the `plugin!` macro and the glue its images call
//! (IF §6.4, §7.1, §7.2, §7.7).
//!
//! UNSAFE-MIN r3.1 splits the bridge in two. busbar-ffi owns every raw entry (`describe`, `open`, `resume`,
//! `cancel`, `close` and one shim per kind slot): the `inst` deref, the slot tables, the chain boxes, the
//! `catch_unwind` around each entry. The safe half is W1-A3's `bridge.rs` (the inbox, CURRENT, the one poll,
//! FAIL/ERROR/FACT, NEED + TOKEN, the session TOKEN). This module adds only what is the macros' own: the
//! `open` answer (INSTANCE, then `Open::settled`), `check`'s ENDPOINT records, `describe`'s items, and the
//! sync and opener wrappers that hand plugin methods a `records::Out`. `kind!` emits, per kind, one
//! `Shim<T>` image type whose `busbar_ffi::shim` impls are one-line calls into these and into `bridge`;
//! `plugin!` adds the stamp, the table, the header and the image's open slab.

use crate::bridge::{self, Inbox};
use crate::fail::{Fail, failed, refused};
use crate::host::Host;
use crate::need::Destination;
use crate::need::{ChainBytes, need_flag, op};
use crate::records::put_parts_iter;
use crate::records::{
    EndpointRec, Full, InstanceRec, MaskRec, MetricDecl, Nested, Out, Reply, U64Rec, Writer, tag,
};
use crate::slots::{ChainBox, Slots};
use crate::types::{Bytes, Status};
use zerocopy::IntoBytes;

/// The plugin header, `OPEN_DRY_RUN` and the exported symbol name are busbar-ffi's (UNSAFE-MIN r3.1): the header
/// holds `unsafe extern "C"` entries and raw table pointers, and only `plugin()` builds one. Re-exported here
/// under their frozen paths; their `mechanism!` block is busbar-ffi's, folded into `CORE_FP` after this crate's.
pub use busbar_ffi::header::{
    OPEN_DRY_RUN, PLUGIN_CANCEL_AT, PLUGIN_CLOSE_AT, PLUGIN_DESCRIBE_AT, PLUGIN_FORMER_NAMES_AT,
    PLUGIN_KIND_VT_AT, PLUGIN_OPEN_AT, PLUGIN_RESUME_AT, PLUGIN_STAMP_AT, Plugin, SYMBOL,
};

/// The type of the one exported symbol, `busbar_plugin` (IF §7.1). UNSAFE-MIN r3.1: `export!` emits it as a
/// safe `extern "C" fn` (it only returns the address of a `'static` header), so the pointer type is safe too.
pub type EntryFn = extern "C" fn() -> *const Plugin;

/// What the macros name, under one hidden path, so a plugin crate needs no busbar-ffi dependency of its own.
#[doc(hidden)]
pub mod __rt {
    pub use busbar_ffi::raw::ViewRef;
    pub use busbar_ffi::shim::{self, ChainFut};
    pub use busbar_ffi::vt::{self, views};
    pub use busbar_ffi::{
        Arg, Built, ChainRef, Kind, LinkedPlugin, Out, Slots, StampBytes, kind, plugin,
    };
    #[cfg(feature = "host")]
    pub use busbar_ffi::{host, image};
    pub use zerocopy;
}

/// Every plugin type implements its kind trait and this.
pub trait Open: Sized + Send + Sync + 'static {
    /// Build the instance. May await Need steps (connect, fetch JWKS, SECRET by handle). `config` is the bound
    /// JSON (§12.7); keep SecretHandle/TrustHandle values, never resolved secret bytes, in long-lived state
    /// unless the protocol needs the value on every call (then hold it in a [`crate::secure::SecureVec`]).
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

/// Round 32: at most this many ENDPOINT records per `check` (TRANSPORT-SECURITY-POLICY §2).
pub const ENDPOINTS_MAX: usize = 16;
/// Round 32: an ENDPOINT's dest (`host:port`, `unix:/abs` or the FETCH URL) is at most this many bytes.
pub const ENDPOINT_DEST_MAX: usize = 2_048;

/// Round 32: the ENDPOINT writer `check` receives (TRANSPORT-SECURITY-POLICY §2). A 17th call, a dest over
/// 2,048 bytes or a `Full` out buffer makes the shim answer INVALID (CONFIG refused, naming the instance).
pub struct Endpoints<'a> {
    out: Out<'a>,
    count: usize,
    /// The first breach; once set nothing more is written and the shim answers REFUSED R_INVALID with it.
    bad: Option<&'static str>,
}
impl Endpoints<'_> {
    /// One endpoint this config will OPEN: dest and TLS mode exactly as the OPEN states them.
    pub fn open(&mut self, dest: &str, tls: u32, egress: u32) -> &mut Self {
        match flags_of(tls, egress) {
            Some(flags) => self.put_destination(op::OPEN, flags, Destination::One(dest)),
            None => self.refuse("an endpoint states a TLS mode or an egress class out of range"),
        }
    }
    /// One OPEN endpoint from borrowed destination segments, under the same check-time limits.
    pub fn open_parts(&mut self, dest: &[&str], tls: u32, egress: u32) -> &mut Self {
        match flags_of(tls, egress) {
            Some(flags) => self.put_destination(op::OPEN, flags, Destination::Parts(dest)),
            None => self.refuse("an endpoint states a TLS mode or an egress class out of range"),
        }
    }
    /// One URL this config will FETCH (`https://` = TLS, `http://` = none).
    pub fn fetch(&mut self, url: &str, egress: u32) -> &mut Self {
        let tls = if scheme_is(url, "https://") {
            need_flag::TLS_REQUIRED
        } else if scheme_is(url, "http://") {
            need_flag::TLS_NONE
        } else {
            return self.refuse("a FETCH endpoint is not an http:// or https:// URL");
        };
        match flags_of(tls, egress) {
            Some(flags) => self.put(op::FETCH, flags, url),
            None => self.refuse("an endpoint states an egress class out of range"),
        }
    }
    fn put(&mut self, op: u32, flags: u32, dest: &str) -> &mut Self {
        self.put_destination(op, flags, Destination::One(dest))
    }
    fn put_destination(&mut self, op: u32, flags: u32, dest: Destination<'_>) -> &mut Self {
        if self.bad.is_some() {
            return self;
        }
        if self.count == ENDPOINTS_MAX {
            return self.refuse("check stated more than 16 endpoints");
        }
        if !dest
            .checked_len()
            .is_some_and(|len| len <= ENDPOINT_DEST_MAX)
        {
            return self.refuse("an endpoint is over 2,048 bytes");
        }
        let rec = EndpointRec { op, flags };
        if put_parts_iter(
            &mut self.out,
            tag::ENDPOINT,
            std::iter::once(rec.as_bytes()).chain(dest.parts()),
        )
        .is_err()
        {
            return self.refuse("the endpoints do not fit the answer");
        }
        self.count += 1;
        self
    }
    fn refuse(&mut self, why: &'static str) -> &mut Self {
        if self.bad.is_none() {
            self.bad = Some(why);
        }
        self
    }
}

/// NeedRec.flags as OPEN/FETCH state them: the TLS mode in bits 0..=3, the egress class in bits 16..=19.
fn flags_of(tls: u32, egress: u32) -> Option<u32> {
    let class = egress.checked_shl(need_flag::EGRESS_SHIFT)?;
    (tls & !need_flag::TLS_MASK == 0
        && class & !need_flag::EGRESS_MASK == 0
        && class >> need_flag::EGRESS_SHIFT == egress)
        .then_some(tls | class)
}

fn scheme_is(url: &str, scheme: &str) -> bool {
    url.get(..scheme.len())
        .is_some_and(|head| head.eq_ignore_ascii_case(scheme))
}

pub struct Describe<'a> {
    out: Out<'a>,
    /// The kind's REQUIRED mask: the D_METHODS a plugin that never calls `methods` declares.
    required: u64,
    methods: bool,
    /// A write did not fit: nothing more is written and the shim answers FAILED F_LIMIT.
    full: bool,
}
impl Describe<'_> {
    /// Method bits from the kind's M_* consts. Replaces the default. Core refuses (CapUnknown) any bit not in the kind.
    pub fn methods(&mut self, mask: u64) -> &mut Self {
        self.methods = true;
        self.write(|w| w.put_pod(tag::D_METHODS, &MaskRec { mask }))
    }
    /// Kind fact bits (F_* in the kind's consts).
    pub fn facts(&mut self, mask: u64) -> &mut Self {
        self.write(|w| w.put_pod(tag::D_FACTS, &MaskRec { mask }))
    }
    /// JSON Schema of the config. Core validates config against it before `open`. Round 31: it covers every
    /// shape `check` accepts, and core validates a returned CONFIG against it too (a mismatch fails the
    /// instance). D_SECRET_PATH / D_TRUST_PATH / D_REF_PATH likewise declare the positions of every accepted shape.
    pub fn schema(&mut self, json_schema: &'static str) -> &mut Self {
        self.write(|w| w.put_text(tag::D_SCHEMA, json_schema))
    }
    /// Output cap per call. Core clamps it to its own ceiling (default 1 MiB, store 16 MiB).
    pub fn max_out(&mut self, bytes: u64) -> &mut Self {
        self.write(|w| w.put_pod(tag::D_MAX_OUT, &U64Rec { value: bytes }))
    }
    /// Wall-clock ceiling for one sync call of `method` (one M_ bit), or the first poll of its async chain; or,
    /// with `abi::CEIL_OPEN`, the first poll of `open` (round 31: migration included). Clamped by core into
    /// the §10.6 range (round 11). Watchdog input.
    pub fn ceiling_us(&mut self, method: u64, micros: u64) -> &mut Self {
        let rec = crate::records::CeilingRec { method, micros };
        self.write(|w| w.put_pod(tag::D_CEILING, &rec))
    }
    /// Plane registration map (D_UPSTREAM_PATH): RFC 6901 pointer ending in an object-member `*`.
    /// Core strips its upstream fields from each registration before schema/check/open.
    pub fn upstream_path(&mut self, pointer: &'static str) -> &mut Self {
        self.write(|w| w.put_text(tag::D_UPSTREAM_PATH, pointer))
    }
    /// A config position that holds a secret reference.
    pub fn secret_path(&mut self, pointer: &'static str) -> &mut Self {
        self.write(|w| w.put_text(tag::D_SECRET_PATH, pointer))
    }
    /// A config position that holds an operator PEM CA (D_TRUST_PATH).
    pub fn trust_path(&mut self, pointer: &'static str) -> &mut Self {
        self.write(|w| w.put_text(tag::D_TRUST_PATH, pointer))
    }
    /// Round 7, export only: a config position that holds a file-sink destination (D_DEST_PATH; `""` = the
    /// whole bag). Core binds it to `{"$dest": n}` (§12.7); embed `DEST_SCHEMA` there in D_SCHEMA.
    pub fn dest_path(&mut self, pointer: &'static str) -> &mut Self {
        self.write(|w| w.put_text(tag::D_DEST_PATH, pointer))
    }
    /// Round 13: a config position whose plain value the operator may write as a secret reference (D_REF_PATH);
    /// core hands the plugin the resolved plain string (§12.7). D_SCHEMA states the plain type there.
    pub fn ref_path(&mut self, pointer: &'static str) -> &mut Self {
        self.write(|w| w.put_text(tag::D_REF_PATH, pointer))
    }
    /// Round 14, plane only: the config position where core writes its top-level `public_url` (D_PUBLIC_URL_PATH,
    /// a JSON string or `null`). D_SCHEMA states `{"type": ["string", "null"]}` there.
    pub fn public_url_path(&mut self, pointer: &'static str) -> &mut Self {
        self.write(|w| w.put_text(tag::D_PUBLIC_URL_PATH, pointer))
    }
    /// Round 22, plane only: the config position where core writes the caller-connection upstream names
    /// (D_CALLER_UPSTREAMS_PATH). D_SCHEMA states `{"type": "array", "items": {"type": "string"}}` there.
    pub fn caller_upstreams_path(&mut self, pointer: &'static str) -> &mut Self {
        self.write(|w| w.put_text(tag::D_CALLER_UPSTREAMS_PATH, pointer))
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
        // Body: MetricDecl, then nested TEXT name, TEXT help, TEXT label key* (records.rs D_METRIC).
        let mut tail = Reply::new();
        let built = tail
            .put_text(tag::TEXT, name)
            .and_then(|()| tail.put_text(tag::TEXT, help))
            .and_then(|()| {
                label_keys
                    .iter()
                    .try_for_each(|key| tail.put_text(tag::TEXT, key))
            });
        let decl = MetricDecl { id, kind };
        self.write(|w| built.and_then(|()| w.put_pod_tail(tag::D_METRIC, &decl, tail.as_bytes())))
    }
    /// Round 34 (PLUGIN-ERROR-CODES): the error numbers this plugin's Fails (`Fail::with_error`) and
    /// `Host::log_error` lines may carry (D_ERRORS): strictly ascending, 1..=256 of them, each 1..=9999. A plugin
    /// writes `pub const ERRORS: &[u16] = &[7070, 7071];` and `d.errors(ERRORS)`. Docs text lives in the repo's
    /// `docs/diagnostics.json`, never in the binary.
    pub fn errors(&mut self, numbers: &'static [u16]) -> &mut Self {
        // u16 little-endian, as given: core judges the list (a bad one drops this image's codes, never the image).
        let body: Vec<u8> = numbers.iter().flat_map(|n| n.to_le_bytes()).collect();
        self.write(|w| w.put(tag::D_ERRORS, &body))
    }
    /// A kind describe item (tag 0x0180..=0x01FF, declared in that kind's `tags {}`).
    pub fn item(&mut self, tag: u16, body: &[u8]) -> &mut Self {
        self.write(|w| w.put(tag, body))
    }
    /// A kind item written directly from borrowed body pieces; host tag validation is unchanged.
    pub fn item_parts(&mut self, tag: u16, parts: &[&[u8]]) -> &mut Self {
        self.write(|w| w.put_parts(tag, parts))
    }
    /// A fixed POD prefix followed by terminal nested records, with whole-record rollback on Full.
    pub fn item_pod_nested<T: crate::records::Pod>(
        &mut self,
        tag: u16,
        prefix: &T,
        fill: impl FnOnce(&mut Nested<'_>) -> Result<(), Full>,
    ) -> &mut Self {
        self.write(|w| w.put_pod_nested(tag, prefix, fill))
    }
    pub fn item_text(&mut self, tag: u16, text: &str) -> &mut Self {
        self.write(|w| w.put_text(tag, text))
    }
    /// A kind describe item whose body is nested records (D_SUGAR, D_SCOPE-style items). Round 6.
    pub fn item_nested(
        &mut self,
        tag: u16,
        f: impl FnOnce(&mut Nested<'_>) -> Result<(), Full>,
    ) -> &mut Self {
        self.write(|w| w.put_nested(tag, f))
    }
    /// One describe item, unless an earlier one did not fit (a describe answer is whole or FAILED F_LIMIT).
    fn write(&mut self, f: impl FnOnce(&mut Out<'_>) -> Result<(), Full>) -> &mut Self {
        if !self.full && f(&mut self.out).is_err() {
            self.full = true;
        }
        self
    }
}

// ---- the macro glue (IF §6.4, §7.7): what the `Shim<T>` impls `kind!` emits call, over A3's bridge ----

/// What a chain of plugin type `P` ends with: an async method's records, or the plugin value its `open` built.
#[doc(hidden)]
pub enum Done<P> {
    Reply(Reply),
    Opened(P),
}

/// A chain's answer: the `Reply` type of every `Shim<T>` image (`bridge::poll` writes it).
#[doc(hidden)]
pub type Outcome<P> = Result<Done<P>, Fail>;

/// The one `open` slab of plugin type `P` (IF §6.4 step 6: `static GLOBAL`, emitted by `plugin!`).
#[doc(hidden)]
pub type Slab<P> = Slots<ChainBox<Outcome<P>, Inbox>>;

/// What `plugin!` adds to a plugin type: its image's open slab, and the `open` answer built over its image.
#[doc(hidden)]
pub trait Glue: Open {
    fn global() -> &'static Slab<Self>;
    /// `open`'s last answer (§6.4 step 6, round 31): [`instance`] over this type's `Shim<Self>`.
    fn instance(self, out: &mut busbar_ffi::Out<'_>) -> Result<(), Full>;
}

/// Ready(Ok) of a chain: a method's records are copied; an `open`'s plugin value becomes INSTANCE, then
/// whatever `Open::settled` writes. `Full` makes the bridge answer FAILED F_LIMIT (§6.4 step 2).
impl<P: Glue> bridge::Answer for Done<P> {
    fn answer(self, out: &mut busbar_ffi::Out<'_>) -> Result<(), Full> {
        match self {
            Done::Reply(reply) => <Reply as bridge::Answer>::answer(reply, out),
            Done::Opened(plugin) => plugin.instance(out),
        }
    }
}

/// A sync method or a method on a live session: Ok = OK with the records written, Err = §6.4 step 2.
#[doc(hidden)]
pub fn sync(
    out: &mut busbar_ffi::Out<'_>,
    call: impl FnOnce(&mut Out<'_>) -> Result<(), Fail>,
) -> Status {
    let done = call(&mut Out::from(out.reborrow()));
    bridge::answer_sync(out, done)
}

/// A session opener (§6.4 step 7): the room for the leading TOKEN is reserved at offset 0 before the call, so
/// the plugin's records start at 16; the image's `opened` (`bridge::opened`) writes the token there once the
/// session is in the slots. Err carries the FAIL answer already written.
#[doc(hidden)]
pub fn opener<S>(
    out: &mut busbar_ffi::Out<'_>,
    call: impl FnOnce(&mut Out<'_>) -> Result<S, Fail>,
) -> Result<S, Status> {
    let opened = match bridge::reserve_token(out) {
        Ok(()) => call(&mut Out::from(out.reborrow())),
        Err(full) => Err(Fail::from(full)),
    };
    opened.map_err(|fail| bridge::answer_sync(out, Err(fail)))
}

/// Start an async method's chain over the future its trait method returned, with a fresh inbox minted on
/// the starting thread.
#[doc(hidden)]
pub fn chain<'i, P: 'static>(
    method: impl Future<Output = Result<Reply, Fail>> + Send + 'i,
) -> (busbar_ffi::shim::ChainFut<'i, Outcome<P>>, Inbox) {
    (
        Box::pin(async move { method.await.map(Done::Reply) }),
        Inbox::new(),
    )
}

/// The `describe` entry: the plugin's items, then D_METHODS = `required` if it declared none.
#[doc(hidden)]
pub fn describe<T: Open>(required: u64, out: &mut busbar_ffi::Out<'_>) -> Status {
    let full = {
        let mut d = Describe {
            out: Out::from(out.reborrow()),
            required,
            methods: false,
            full: false,
        };
        T::describe(&mut d);
        if !d.methods {
            let required = d.required;
            d.methods(required);
        }
        d.full
    };
    if full {
        bridge::answer_sync(out, Err(Fail::failed(failed::F_LIMIT)))
    } else {
        Status::OK
    }
}

/// The `open` entry. DRY_RUN: `check`, whose ENDPOINT records are the answer (round 32). Otherwise the `open`
/// future on the image's slab; its Ready(Ok) writes INSTANCE and `Open::settled` (`Glue::instance`).
#[doc(hidden)]
pub fn open<T: Open>(
    h: &'static Host,
    config: Bytes<'_>,
    chained: ChainBytes,
    flags: u32,
    out: &mut busbar_ffi::Out<'_>,
) -> busbar_ffi::shim::Opening<Outcome<T>, Inbox> {
    use busbar_ffi::shim::Opening;
    if flags & OPEN_DRY_RUN != 0 {
        drop(chained);
        return Opening::Done(check::<T>(h, config.get(), out));
    }
    Opening::Chain(
        Box::pin(async move { T::open(h, chained).await.map(Done::Opened) }),
        Inbox::new(),
    )
}

fn check<T: Open>(h: &Host, config: &[u8], out: &mut busbar_ffi::Out<'_>) -> Status {
    let (checked, bad) = {
        let mut ends = Endpoints {
            out: Out::from(out.reborrow()),
            count: 0,
            bad: None,
        };
        let checked = crate::fail::in_check(|| T::check(h, config, &mut ends));
        (checked, ends.bad)
    };
    let answer = match (checked, bad) {
        (Err(fail), _) => Err(fail),
        (Ok(()), Some(why)) => Err(Fail::refused_because(refused::R_INVALID, why)),
        (Ok(()), None) => Ok(()),
    };
    bridge::answer_sync(out, answer)
}

/// The byte offset of a record's body: after its 8-byte head.
const BODY_AT: usize = size_of::<crate::records::RecHead>();

/// The last answer of `open` for image `I` (§6.4 step 6, round 31): INSTANCE, then whatever `Open::settled`
/// writes. The INSTANCE body is patched once the instance is boxed into the image's own `InstOf`, so `settled`
/// runs on the value before it is handed over; a `settled` that does not fit drops the value and builds nothing.
#[doc(hidden)]
pub fn instance<I>(plugin: I::Plugin, out: &mut busbar_ffi::Out<'_>) -> Result<(), Full>
where
    I: busbar_ffi::shim::Image,
    I::Plugin: Open,
{
    let inst = Box::new(busbar_ffi::shim::InstOf::<I>::new(plugin));
    let at = out.written() + BODY_AT;
    {
        let mut w = Out::from(out.reborrow());
        w.put_pod(tag::INSTANCE, &InstanceRec { inst: 0 })?;
        inst.plugin().settled(&mut w)?;
    }
    let address = inst.into_instance();
    // The 8 bytes at `at` were written just above, so the patch lands inside what was written.
    let patched = out.patch(at, &address.to_le_bytes());
    debug_assert!(patched, "INSTANCE's body was written above");
    Ok(())
}

/// Emits a plugin's stamp, kind table and header (IF §7.7): `pub static PLUGIN`, the one value a linked build
/// registers and `export!` returns.
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
/// - `plugin!` emits: `static STAMP` (crate-local, mangled, no `#[used]` and no link_section, as in r10
///   §2.3.2), `static VT` (the kind's busbar-ffi table built for `<kind>::Shim<T>`), `pub static PLUGIN`
///   (with `former_names` = the arm's text, const-validated, or `Str::EMPTY`) and `impl Glue for T` (the
///   image's one `static GLOBAL` open slab and its `open` answer). The describe/open/resume/cancel/close entries and every kind
///   slot are busbar-ffi's shims over `Shim<T>` (UNSAFE-MIN r3.1); there is no `migrate` slot (round 31), and
///   the `open` answer is INSTANCE then `Open::settled`.
/// - **Linked plugins** (dist/default) register `&logic_crate::PLUGIN` with the loader (§11.2). There is no symbol.
/// - **Stamp values:** kind and kind_abi from the kind module; mechanism = 2; layout = semantic = `<kind>::FP`;
///   mechanism_layout = mechanism_semantic = CORE_FP; crypto = `"host"`, except with `out_of_process`, where it is
///   the build-time `env!("BUSBAR_PLUGIN_CRYPTO")`; name = the `name:` arm, else `BUSBAR_PLUGIN_NAME`, else the
///   logic crate's `CARGO_PKG_NAME`; version = its `CARGO_PKG_VERSION`; build id from `BUSBAR_BUILD_ID`. Every
///   field is checked while the static is evaluated: a bad one is a compile error.
/// - `plugin!(@kind [path::to::kind_module] T, ..)` names the kind module directly (a kind declared with
///   `kind!` outside the seven, as the conformance fixtures do).
///
/// Complete glue for a plugin is the `plugin!` line, the `export!` line, `impl Open` and the kind impl.
/// ```
#[macro_export]
macro_rules! plugin {
    (Store, $T:ty $(, $($arm:tt)*)?) => { $crate::plugin! { @kind [$crate::store] $T $(, $($arm)*)? } };
    (Secret, $T:ty $(, $($arm:tt)*)?) => { $crate::plugin! { @kind [$crate::secret] $T $(, $($arm)*)? } };
    (Auth, $T:ty $(, $($arm:tt)*)?) => { $crate::plugin! { @kind [$crate::auth] $T $(, $($arm)*)? } };
    (Hook, $T:ty $(, $($arm:tt)*)?) => { $crate::plugin! { @kind [$crate::hook] $T $(, $($arm)*)? } };
    (Export, $T:ty $(, $($arm:tt)*)?) => { $crate::plugin! { @kind [$crate::export] $T $(, $($arm)*)? } };
    (Plane, $T:ty $(, $($arm:tt)*)?) => { $crate::plugin! { @kind [$crate::plane] $T $(, $($arm)*)? } };
    (Transport, $T:ty $(, $($arm:tt)*)?) => { $crate::plugin! { @kind [$crate::transport] $T $(, $($arm)*)? } };
    (@kind [$($k:tt)*] $T:ty $(, $($arm:tt)*)?) => {
        $crate::plugin! { @arms [$($k)*] [$T] [] [] [] [] [] $(, $($arm)*)? }
    };
    // The optional arms, in the frozen order; each fills its slot once.
    (@arms $k:tt $T:tt [] $emax:tt $oop:tt $former:tt $name:tt , engine_min: $v:literal $($rest:tt)*) => {
        $crate::plugin! { @arms $k $T [$v] $emax $oop $former $name $($rest)* }
    };
    (@arms $k:tt $T:tt $emin:tt [] $oop:tt $former:tt $name:tt , engine_max: $v:literal $($rest:tt)*) => {
        $crate::plugin! { @arms $k $T $emin [$v] $oop $former $name $($rest)* }
    };
    (@arms $k:tt $T:tt $emin:tt $emax:tt [] $former:tt $name:tt , out_of_process $($rest:tt)*) => {
        $crate::plugin! { @arms $k $T $emin $emax [out_of_process] $former $name $($rest)* }
    };
    (@arms $k:tt $T:tt $emin:tt $emax:tt $oop:tt [] $name:tt , former_names: $v:literal $($rest:tt)*) => {
        $crate::plugin! { @arms $k $T $emin $emax $oop [$v] $name $($rest)* }
    };
    (@arms $k:tt $T:tt $emin:tt $emax:tt $oop:tt $former:tt [] , name: $v:literal $($rest:tt)*) => {
        $crate::plugin! { @arms $k $T $emin $emax $oop $former [$v] $($rest)* }
    };
    (@arms [$($k:tt)*] [$T:ty] [$($emin:literal)?] [$($emax:literal)?] [$($oop:ident)?] [$($former:literal)?] [$($name:literal)?] $(,)?) => {
        impl $crate::plugin::Glue for $T {
            fn global() -> &'static $crate::plugin::Slab<Self> {
                static GLOBAL: $crate::plugin::Slab<$T> = $crate::plugin::__rt::Slots::new();
                &GLOBAL
            }
            fn instance(
                self,
                out: &mut $crate::plugin::__rt::Out<'_>,
            ) -> ::core::result::Result<(), $crate::records::Full> {
                $crate::plugin::instance::<$($k)*::Shim<$T>>(self, out)
            }
        }

        /// This plugin's header (IF §7.7): the address a linked build registers and `export!` returns.
        pub static PLUGIN: $crate::plugin::__rt::LinkedPlugin = {
            static STAMP: $crate::plugin::__rt::StampBytes = $crate::stamp::emit(&$crate::stamp::Spec {
                kind: $($k)*::KIND,
                kind_abi: $($k)*::ABI,
                layout: $($k)*::FP,
                out_of_process: $crate::plugin!(@if [$($oop)?] true false),
                engine_min: $crate::plugin!(@option [$($emin)?]),
                engine_max: $crate::plugin!(@option [$($emax)?]),
                name: $crate::stamp::pick_name(
                    $crate::plugin!(@option [$($name)?]),
                    ::core::option_env!("BUSBAR_PLUGIN_NAME"),
                    ::core::env!("CARGO_PKG_NAME"),
                ),
                version: ::core::env!("CARGO_PKG_VERSION"),
                build_id: ::core::option_env!("BUSBAR_BUILD_ID"),
                crypto: $crate::plugin!(@if [$($oop)?] { ::core::env!("BUSBAR_PLUGIN_CRYPTO") } { "host" }),
            });
            static VT: $crate::plugin::__rt::Built<$($k)*::Shim<$T>, $($k)*::Vt> = $($k)*::vt::<$T>();
            $crate::plugin::__rt::plugin::<$($k)*::Shim<$T>, $($k)*::Marker>(
                &VT,
                &STAMP,
                $crate::stamp::former_names($crate::plugin!(@option [$($former)?])),
            )
        };
    };
    (@option []) => { ::core::option::Option::None };
    (@option [$v:literal]) => { ::core::option::Option::Some($v) };
    (@if [] $yes:tt $no:tt) => { $no };
    (@if [$flag:ident] $yes:tt $no:tt) => { $yes };
}

#[cfg(all(test, feature = "host"))]
#[path = "plugin_parts_tests.rs"]
mod parts_tests;
