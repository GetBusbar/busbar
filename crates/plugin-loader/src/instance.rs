// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The MIN-3 registry: admitted plugins, the instance and slot tables, error books, boot plan (IF §11.2, round 31
//! §47, round 34 §50, round 35 §51). W1-L2. The 1.5 `PluginRegistry` stays in `registry.rs`.
//!
//! Landed here: `Registry::new` over the moved `ConfigBinder` (R7b), the admitted-image table and its add-time
//! checks (NameConflict over identities and `former_names`, D_ERRORS into an `ErrorBook`, the §10.6 clamp row),
//! `take_settled`, `ephemeral_stores`, `described`, the `SlotTable`/`SlotLease` slot records (safe Rust: an
//! `ArcSwapOption` holds the record and the lease holds its table, so no `UnsafeCell` and no `unsafe impl`), the
//! ENDPOINT decode and the check-time transport verdict (BUSBAR-3160/3163, R7a `check_endpoints`). The entries
//! themselves run through `entry::guard` (describe) and the driver (every open step takes the same guard); the
//! chains are in `chains.rs`, the kind ports built over them are the `open_<kind>` methods here.

use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::collections::HashMap;
use std::sync::{Arc, Mutex, OnceLock, PoisonError};

use arc_swap::ArcSwapOption;
use busbar_contract::json::{self, JsonContainerTrait as _, JsonValueTrait as _};
use busbar_plugin_abi::fail::{refused, CallError};
use busbar_plugin_abi::host::Host;
use busbar_plugin_abi::host_side::answer::Answer;
use busbar_plugin_abi::host_side::caller::{
    transport_verdict, Accept, BoxFut, InstanceLimits, Verdict,
};
use busbar_plugin_abi::host_side::driver::Image;
use busbar_plugin_abi::host_side::entry;
use busbar_plugin_abi::host_side::needs::Needs;
use busbar_plugin_abi::host_side::pool::Pool;
use busbar_plugin_abi::host_side::scrub::Scrub;
use busbar_plugin_abi::host_side::watch::ENTRY_DESCRIBE;
use busbar_plugin_abi::need::{egress, need_flag, op};
use busbar_plugin_abi::records::{tag, CeilingRec, EndpointRec, Records};
use busbar_plugin_abi::types::KindCode;

use crate::admit::Admitted;
use crate::chains::{self, OwnedSpec};
use crate::refusal::{Refusal, RefusalCode};
use crate::reopen::{BoundNeeds, Reopener};
use busbar_ffi::kind as k;
use busbar_ports::auth::{AuthPort, IssuedShape};
use busbar_ports::binder::{ConfigBinder, RefSource};
use busbar_ports::codec::plane;
use busbar_ports::export::ExportPort;
use busbar_ports::hook::HookPort;
use busbar_ports::plane::PlanePort;
use busbar_ports::secret::{SecretPort, SugarDecl};
use busbar_ports::store::StoreHandle;
use busbar_ports::transport::TransportPort;
use busbar_ports::PluginCode;

/// Admission and description, before any binder, Needs or instance exists (HOST M3a).
pub struct ImagesBuilder {
    host: &'static Host,
    slots: Arc<SlotTable>,
    ceilings: Ceilings,
    entries: Vec<ImageEntry>,
    sugars: Vec<SugarDecl>,
    issued: Vec<(Box<str>, IssuedShape)>,
}

/// Immutable admitted image leases and describe facts for one configuration read.
#[derive(Clone)]
pub struct Images {
    host: &'static Host,
    slots: Arc<SlotTable>,
    ceilings: Ceilings,
    entries: Vec<ImageEntry>,
    sugars: Vec<SugarDecl>,
    issued: Vec<(Box<str>, IssuedShape)>,
}

impl ImagesBuilder {
    pub fn new(host: &'static Host, slots: Arc<SlotTable>, ceilings: Ceilings) -> Self {
        Self {
            host,
            slots,
            ceilings,
            entries: Vec::new(),
            sugars: Vec::new(),
            issued: Vec::new(),
        }
    }
    pub fn finish(self) -> Images {
        Images {
            host: self.host,
            slots: self.slots,
            ceilings: self.ceilings,
            entries: self.entries,
            sugars: self.sugars,
            issued: self.issued,
        }
    }
    /// `add` after its describe ran: every check that reads only the decoded describe. NameConflict first (the
    /// identity and each `former_names` word against every admitted identity and word), then D_ERRORS into the
    /// image's `ErrorBook` (a bad list admits the image with `ErrorBook::Refused`, never a refusal), then the
    /// §10.6 ceiling row (a clamp is logged once here; a CeilingRec naming no entry is DescribeInvalid).
    pub(crate) fn admit_described(
        &mut self,
        identity: &str,
        stamp_name: &[u8; 64],
        former_names: &[&str],
        linked: bool,
        mut described: Described,
    ) -> Result<(), Refusal> {
        if let Some(refusal) = name_conflict(
            self.entries
                .iter()
                .map(|e| (&*e.identity, e.former_names.iter().map(|w| &**w))),
            identity,
            former_names,
        ) {
            return Err(refusal);
        }
        let bodies: Vec<&[u8]> = described
            .items
            .iter()
            .filter(|(t, _)| *t == tag::D_ERRORS)
            .map(|(_, b)| b.as_slice())
            .collect();
        let errors: &'static ErrorBook =
            match decode_errors(&bodies, || crate::scan::error_identity(stamp_name)) {
                Ok(book) => Box::leak(Box::new(book)),
                Err(refused) => {
                    described.error_codes_refused = Some(refused);
                    &ErrorBook::Refused
                }
            };
        let declared: Vec<(u64, u64)> = described
            .items
            .iter()
            .filter(|(t, _)| *t == tag::D_CEILING)
            .filter_map(|(t, b)| {
                let rec = busbar_plugin_abi::records::Rec { tag: *t, body: b };
                rec.pod::<CeilingRec>().ok().map(|c| (c.method, c.micros))
            })
            .collect();
        let blocking = described.kind == KindCode::Store
            && described.facts & busbar_plugin_abi::store::F_BLOCKING_FILE != 0;
        let row = crate::watchdog::ceiling_row(&declared, blocking).map_err(|have| Refusal {
            code: RefusalCode::DescribeInvalid,
            field: "describe.ceiling",
            plugin: Some(identity.to_owned()),
            have,
            want: "one CeilingRec per kind method bit 0..=55 or CEIL_OPEN".to_owned(),
            link: None,
        })?;
        for clamp in &row.clamped {
            tracing::warn!(
                plugin = identity,
                entry = clamp.entry,
                declared_us = clamp.declared,
                clamped_us = clamp.clamped,
                "plugin ceiling clamped into its range"
            );
        }
        self.entries.push(ImageEntry {
            identity: Arc::from(identity),
            former_names: former_names.iter().map(|w| Box::from(*w)).collect(),
            linked,
            described,
            errors,
            ceilings: row.row,
            header: None,
            image: None,
            dialect_auth: Vec::new(),
        });
        Ok(())
    }

    /// Round 6: also runs the plugin's describe once (cold, `EntryOwner::Image`, round 14: its own leased watchdog
    /// slot with the fixed describe row, refused `DescribeInvalid` "describe.ceiling" if the watchdog marked it; round 10:
    /// inline under `entry::guard` on the calling thread) and keeps the `Described`; a secret plugin's D_SUGAR items are decoded here
    /// (`secret::decode_sugars`) so `sugars()` is complete before any config is bound. Round 9: refuses
    /// `NameConflict` (§4.3) when the plugin's identity or a `former_names` word (§7.1) equals an already-admitted
    /// plugin's identity or word; the generic `module:` match resolves identity, then words.
    /// **Round 34 (PLUGIN-ERROR-CODES §2.2-§2.4):** in the same describe pass it decodes D_ERRORS and builds the
    /// image's `ErrorBook` (below), on both load paths. A bad declaration is exactly one of: more than one D_ERRORS
    /// item (`have` "2 D_ERRORS items"); body empty, odd or over 512 bytes ("body 3 bytes"); a number 0 or above 9999
    /// ("10000 at index 4"); not strictly ascending ("7071 after 7071 at index 2"); an identity that cannot form a
    /// code (`scan::error_identity`, L1: "bad character at byte 4", "length 70 > 64"). The check runs before any
    /// allocation. Every fault ends the same way: **the image is admitted with `ErrorBook::Refused`** (never a
    /// `Refusal`, never DescribeInvalid; a store or gate hook still serves, boot continues) and the fault is kept
    /// as `Described::error_codes_refused`; the kernel's admission path reads it once and writes one WARN (core
    /// diagnostic BUSBAR-6xxx "plugin error numbers refused", `field: "errors"`, `have`, `want`) and one audit row
    /// `plugin.error_codes_refused` (outcome `degraded`, severity `warning`, `data` = `ErrorCodesRefused {field,
    /// have, want}`, principal `node:<id>`, resource `plugin:<file>`, `kind`, `instance: null`, a core-written
    /// `message` naming the file and the library SHA-256) (K8D), and the admin API shows
    /// `image.admission.error_codes_refused` = that `data`, or `null` (K8C, ADMIN-API-1.6 §B.9). `have` is built only from
    /// the templates above (decimal counts, declared numbers, byte offsets and lengths), never a stamp or name byte;
    /// `want` is the constant "1..=256 numbers, each 1..=9999, strictly ascending; name ^[a-z][a-z0-9-]{0,63}$ not
    /// ending '-'". A malformed describe frame stays DescribeInvalid. An image without D_ERRORS gets
    /// `ErrorBook::None` and no identity check.
    pub fn admit(&mut self, admitted: Admitted) -> Result<(), Refusal> {
        let identity = admitted.identity().to_owned();
        let (header, kind) = (admitted.plugin(), admitted.kind());
        let named = |r: Refusal| r.named(&identity);
        let lease = self.slots.alloc(
            SlotRecord {
                kind,
                name: Arc::from(identity.as_str()),
                scrub: Arc::new(Scrub::new()),
                errors: &ErrorBook::None,
                undeclared_warned: AtomicBool::new(false),
            },
            &crate::watchdog::describe_row(),
        );
        let mut buf = Pool::global().acquire(self.ceilings.max_out);
        let host = self.host;
        let status = entry::guard(lease.slot(), ENTRY_DESCRIBE, &mut buf, |out| {
            header.describe(host, out)
        })
        .ok_or_else(|| {
            named(Refusal::new(
                RefusalCode::DescribeInvalid,
                "describe",
                "the entry stack is full",
                "a describe entry",
            ))
        })?;
        if !lease.is_live() {
            return Err(named(Refusal::new(
                RefusalCode::DescribeInvalid,
                "describe.ceiling",
                "the describe entry passed its ceiling",
                "an answer within 5 s",
            )));
        }
        let answer = Answer::parse(status, buf.bytes()).map_err(|reason| {
            named(Refusal::new(
                RefusalCode::DescribeInvalid,
                "describe",
                format!("{reason:?}"),
                "a well-formed describe answer",
            ))
        })?;
        if !answer.is_ok() {
            return Err(named(Refusal::new(
                RefusalCode::DescribeInvalid,
                "describe",
                format!("status {}", status.0),
                "OK",
            )));
        }
        let described = chains::decode_described(kind, answer.records()).map_err(named)?;
        let kind_items =
            decode_kind_items(&described, answer.records(), &identity).map_err(named)?;
        let former: Vec<&str> = header
            .former_names()
            .split(',')
            .filter(|w| !w.is_empty())
            .collect();
        let linked = matches!(*admitted.image, Image::Linked);
        self.admit_described(&identity, &admitted.stamp.name, &former, linked, described)?;
        if let Some(entry) = self.entries.last_mut() {
            entry.header = Some(header);
            entry.image = Some(Arc::clone(&admitted.image));
            entry.dialect_auth = kind_items.dialect_auth;
        }
        self.sugars.extend(kind_items.sugars);
        self.issued.extend(kind_items.issued);
        Ok(())
    }
}
impl Images {
    pub fn identities(&self) -> impl Iterator<Item = &str> {
        self.entries.iter().map(|entry| entry.identity.as_ref())
    }
    pub fn names(&self, identity: &str) -> Vec<&str> {
        self.entries
            .iter()
            .find(|entry| entry.identity.as_ref() == identity)
            .map(|entry| {
                std::iter::once(entry.identity.as_ref())
                    .chain(entry.former_names.iter().map(|name| name.as_ref()))
                    .collect()
            })
            .unwrap_or_default()
    }
    /// Create an independent candidate sharing the admitted image leases, never mutating this snapshot.
    pub fn extend(&self) -> ImagesBuilder {
        ImagesBuilder {
            host: self.host,
            slots: Arc::clone(&self.slots),
            ceilings: self.ceilings.clone(),
            entries: self.entries.clone(),
            sugars: self.sugars.clone(),
            issued: self.issued.clone(),
        }
    }
    /// Round 6: every admitted secret plugin's declared shorthands, in admission order. The kernel feeds them to
    /// `busbar_contract::secret_ref::Sugars::declare` (which refuses core words, duplicate words and duplicate
    /// roles) and hands the resulting `Sugars` to the binder (§12.7) and to its own config-section parsing.
    pub fn sugars(&self) -> &[SugarDecl] {
        &self.sugars
    }

    /// Round 11: per admitted auth image, its identity and its D_OUTBOUND_STYLE words (decoded at `add`), in
    /// admission order. Read only to build the STYLES frame the helper's `config::resolve_styles` consumes
    /// (round 13, §12.10 item 3, §12.18).
    pub fn outbound_styles(&self) -> Vec<(&str, Vec<&str>)> {
        self.texts(
            KindCode::Auth,
            busbar_plugin_abi::auth::tag::D_OUTBOUND_STYLE,
        )
    }

    /// Round 22: the D_STYLE_FLAGS mask (`auth::STYLE_*`) an admitted auth image declared for one of its styles
    /// (decoded at `add`; 0 when it declared none or the pair is unknown). Read only by K6 when it resolves a
    /// binding's credential mode and O_SCOPE (§12.18 "credential mode").
    pub fn style_flags(&self, identity: &str, style: &str) -> u64 {
        let Some(entry) = self
            .entries
            .iter()
            .find(|e| e.described.kind == KindCode::Auth && &*e.identity == identity)
        else {
            return 0;
        };
        entry
            .described
            .items
            .iter()
            .filter(|(t, _)| *t == busbar_plugin_abi::auth::tag::D_STYLE_FLAGS)
            .find_map(|(t, b)| {
                let rec = busbar_plugin_abi::records::Rec { tag: *t, body: b };
                let (mask, word) = rec.pod_tail::<busbar_plugin_abi::records::MaskRec>().ok()?;
                (word == style.as_bytes()).then_some(mask.mask)
            })
            .unwrap_or(0)
    }

    /// Round 12: the identities of admitted **compiled-in** (`Image::Linked`) store images whose describe facts
    /// carry `store::FB_EPHEMERAL`, in admission order. Read only by K9's absent-store rule (§12.10 item 1;
    /// MIGRATE-ON-BOOT r15 §3 1d); drop-ins are never listed.
    pub fn ephemeral_stores(&self) -> Vec<&str> {
        self.entries
            .iter()
            .filter(|e| {
                e.linked
                    && e.described.kind == KindCode::Store
                    && e.described.facts & busbar_plugin_abi::store::FB_EPHEMERAL != 0
            })
            .map(|e| &*e.identity)
            .collect()
    }

    /// Round 12: per admitted hook image, its identity and its D_WORD words (§8.4), in admission order. Read
    /// only by the kernel's pool strategy resolution (§12.25).
    pub fn hook_words(&self) -> Vec<(&str, Vec<&str>)> {
        self.texts(KindCode::Hook, busbar_plugin_abi::hook::tag::D_WORD)
    }

    /// Round 12: per issued-credential kind any admitted auth image declares (D_ISSUED_KIND), the shape its
    /// D_ISSUED_SHAPE item states (§8.3), decoded at `add`. Read only by issued credentials (§12.8).
    pub fn issued_shapes(&self) -> Vec<(&str /* issued kind */, IssuedShape)> {
        self.issued
            .iter()
            .map(|(kind, shape)| (&**kind, shape.clone()))
            .collect()
    }

    /// Round 13: per admitted plane image, its identity and its D_PROVIDER_SCHEMA text (§8.6 provider keys),
    /// decoded at `add`. Read only by the kernel's provider-entry validation at config load.
    pub fn provider_schemas(&self) -> Vec<(&str, &str)> {
        self.texts(
            KindCode::Plane,
            busbar_plugin_abi::plane::tag::D_PROVIDER_SCHEMA,
        )
        .into_iter()
        .filter_map(|(identity, texts)| texts.first().map(|schema| (identity, *schema)))
        .collect()
    }

    /// Round 14 (round 15: typed): per admitted plane image, its identity and its D_DIALECT_AUTH rows, decoded at
    /// `add` (`plane::decode_dialect_auth`, owned copies). Read only by K6's binding materialisation (§12.18).
    pub fn dialect_auth(&self) -> Vec<(&str, Vec<plane::DialectAuthOwned>)> {
        self.entries
            .iter()
            .filter(|e| e.described.kind == KindCode::Plane)
            .map(|e| (&*e.identity, e.dialect_auth.clone()))
            .collect()
    }

    /// The image entry the generic `module:` match resolves: identity first, then `former_names` words.
    pub(crate) fn resolve_module(
        &self,
        module: &str,
    ) -> Option<(&str, &'static ErrorBook, &[u32; 64])> {
        let hit = self
            .entries
            .iter()
            .find(|e| &*e.identity == module)
            .or_else(|| {
                self.entries
                    .iter()
                    .find(|e| e.former_names.iter().any(|w| &**w == module))
            })?;
        Some((&hit.identity, hit.errors, &hit.ceilings))
    }

    /// The canonical identity of the admitted image the operator's `module` word names (identity, then a
    /// `former_names` word), or None when no admitted image answers to it.
    pub fn identity_of(&self, module: &str) -> Option<String> {
        self.resolve_module(module)
            .map(|(identity, _, _)| identity.to_owned())
    }

    /// Plugin describe facts for admin/health (never shown to another plugin).
    pub fn described(&self, identity: &str) -> Option<Described> {
        self.entries
            .iter()
            .find(|e| &*e.identity == identity)
            .map(|e| e.described.clone())
    }

    fn texts(&self, kind: KindCode, tag: u16) -> Vec<(&str, Vec<&str>)> {
        self.entries
            .iter()
            .filter(|e| e.described.kind == kind)
            .map(|e| {
                let words = e
                    .described
                    .items
                    .iter()
                    .filter(|(t, _)| *t == tag)
                    .filter_map(|(_, b)| core::str::from_utf8(b).ok())
                    .collect();
                (&*e.identity, words)
            })
            .collect()
    }
}

pub struct Registry {
    pub(crate) reservation_owner: Arc<()>,
    pub(crate) host: &'static Host,
    pub(crate) binder: Arc<dyn ConfigBinder>,
    pub(crate) ceilings: Ceilings,
    pub(crate) slots: Arc<SlotTable>,
    /// Admitted images in admission order (identity unique, `former_names` words unique across all of them).
    pub(crate) images: Images,
    /// Runtime instance ids (never 0, never reused).
    pub(crate) ids: Arc<crate::process::InstanceIds>,
    /// The config each open instance was last opened with, by (kind, configured name), for `reconfigure`.
    applied: Mutex<HashMap<(KindCode, Box<str>), Applied>>,
    /// Round 31: each instance's settled answer from its last `open`, by configured name, until taken once.
    settled: Mutex<HashMap<Box<str>, Settled>>,
}

/// One admitted image as `add` left it: the verified identity, its `former_names` words, whether it is
/// compiled in, the describe facts, its leaked error book and the §10.6 ceiling row every slot of it gets.
#[derive(Clone)]
pub(crate) struct ImageEntry {
    pub(crate) identity: Arc<str>,
    former_names: Vec<Box<str>>,
    linked: bool,
    pub(crate) described: Described,
    pub(crate) errors: &'static ErrorBook,
    pub(crate) ceilings: [u32; 64],
    /// The header and image `add` admitted (None only for an entry a unit test built by hand).
    pub(crate) header: Option<busbar_ffi::image::Admitted>,
    pub(crate) image: Option<Arc<Image>>,
    /// D_DIALECT_AUTH rows of a plane image, decoded and copied at `add`.
    dialect_auth: Vec<plane::DialectAuthOwned>,
}

/// The factory of the kernel seal the store adapter installs (one seal per `StoreAdapter::new`).
pub type StoreSeal =
    Arc<dyn Fn() -> Box<dyn busbar_contract::plugin::KernelSeal + Send + Sync> + Send + Sync>;

/// What `reconfigure` merges a push into: the config an instance was opened with and the last applied version.
#[derive(Clone)]
struct Applied {
    refs: Arc<dyn RefSource>,
    opener: Arc<dyn Reopener>,
    identity: Box<str>,
    config: Vec<u8>,
    limits: InstanceLimits,
    public_url: Option<String>,
    caller_upstreams: Vec<Box<str>>,
    version: u64,
}

/// One non-reusable runtime identity and slot, reserved before building the directory.
/// Its private fields prevent callers manufacturing instance authority.
pub struct PreparedInstance {
    pub(crate) owner: Arc<()>,
    pub(crate) spec: OwnedSpec,
    pub(crate) id: u64,
    pub(crate) kind: KindCode,
    pub(crate) lease: SlotLease,
}
impl PreparedInstance {
    pub fn id(&self) -> u64 {
        self.id
    }
    pub fn slot(&self) -> u32 {
        self.lease.slot()
    }
    pub fn kind(&self) -> KindCode {
        self.kind
    }
    pub fn name(&self) -> &str {
        self.spec.name()
    }
    pub fn identity(&self) -> &str {
        self.spec.identity()
    }
    pub fn spec(&self) -> InstanceSpec<'_> {
        self.spec.spec()
    }
}

/// `config_json` is the operator's config for this instance as core holds it (secret references with their
/// `module`, PEM CAs inline). The registry never passes it to the plugin: the binder rewrites it first.
/// identity = which admitted plugin (verified stamp name); name = the operator's instance name (the config
/// key, e.g. `planes.mcp-main`, `auth.openai-outbound`), stable across restart, reconfigure and replicas, unique
/// per kind; every durable core state for the instance is keyed by (identity, name) (§10.3).
/// Trusted host intent, never inferred from plugin data or represented as an ABI flag.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OpenPurpose {
    Canonical,
    ConvertUnstamped,
}

pub struct InstanceSpec<'a> {
    pub purpose: OpenPurpose,
    pub identity: &'a str,
    pub name: &'a str,
    pub config_json: &'a [u8],
    /// Round 8: parsed by the kernel from `limits` beside `module` (§12.22); `config_json` never contains it.
    pub limits: InstanceLimits,
    /// Round 14: core's top-level `public_url` (None = unset), the same value for every instance. The registry
    /// writes it only at a D_PUBLIC_URL_PATH a plane image declared (§12.7 core values); every other kind ignores it.
    pub public_url: Option<&'a str>,
    /// Round 22: the configured upstream names whose resolved binding is caller-mode (`UpstreamAuth.caller`,
    /// §12.1), sorted; the same slice for every instance. Written only at a D_CALLER_UPSTREAMS_PATH a plane image
    /// declared; every other kind ignores it.
    pub caller_upstreams: &'a [Box<str>],
}

#[derive(Clone)]
pub struct Ceilings {
    pub max_out: usize,
    pub max_out_store: usize,
    pub sync_ceiling_us: u32,
    pub poll_ceiling_us: u32,
    pub cold_ceiling_us: u32,
    pub max_steps: u32,
}

impl Ceilings {
    /// The IF's defaults (§10.5, §10.6, §11.2): `max_out` 1 MiB (a store's 16 MiB), a sync method 50 ms, one poll
    /// 2 s, the cold entries 5 s, 10,000 driver steps.
    pub const DEFAULT: Ceilings = Ceilings {
        max_out: 1 << 20,
        max_out_store: 16 << 20,
        sync_ceiling_us: 50_000,
        poll_ceiling_us: 2_000_000,
        cold_ceiling_us: 5_000_000,
        max_steps: 10_000,
    };
}

impl Registry {
    /// Round 35 (R7b): `ConfigBinder` is the loader's own trait (`crate::binder`), so `new` names it here.
    /// Images are already described; construction cannot admit or mutate an image.
    pub fn new(
        images: Images,
        binder: Arc<dyn ConfigBinder>,
        ids: Arc<crate::process::InstanceIds>,
    ) -> Self {
        Registry {
            reservation_owner: Arc::new(()),
            host: images.host,
            binder,
            ceilings: images.ceilings.clone(),
            slots: Arc::clone(&images.slots),
            images,
            ids,
            applied: Mutex::new(HashMap::new()),
            settled: Mutex::new(HashMap::new()),
        }
    }

    /// Reserve before S7; dropping a failed candidate never returns its process ID.
    pub fn reserve(&self, spec: &InstanceSpec<'_>) -> Result<PreparedInstance, OpenError> {
        let entry = self.entry_of(spec.identity).ok_or_else(|| {
            OpenError::Unknown(format!(
                "{}: no admitted plugin answers to module {}",
                spec.name, spec.identity
            ))
        })?;
        let id = self.ids.next()?;
        let kind = entry.described.kind;
        let lease = self.slots.alloc(
            SlotRecord {
                kind,
                name: Arc::from(spec.name),
                scrub: Arc::new(Scrub::new()),
                errors: entry.errors,
                undeclared_warned: AtomicBool::new(false),
            },
            &entry.ceilings,
        );
        Ok(PreparedInstance {
            owner: Arc::clone(&self.reservation_owner),
            spec: OwnedSpec::new(spec),
            id,
            kind,
            lease,
        })
    }

    /// The registry's slot table (the watchdog thread and the adapters' leases).
    pub(crate) fn slots(&self) -> &Arc<SlotTable> {
        &self.slots
    }

    /// The scrub set of the instance that owns watchdog slot `slot` (its slot record, §10.6): what custody
    /// registers every value it hands that instance in (§12.2 step 5). None: the slot is not live.
    pub fn scrub_of(&self, slot: u32) -> Option<Arc<Scrub>> {
        self.slots.scrub_of(slot)
    }

    /// The image entry the generic `module:` match resolves: identity first, then `former_names` words.
    pub(crate) fn resolve_module(
        &self,
        module: &str,
    ) -> Option<(&str, &'static ErrorBook, &[u32; 64])> {
        let hit = self
            .images
            .entries
            .iter()
            .find(|e| &*e.identity == module)
            .or_else(|| {
                self.images
                    .entries
                    .iter()
                    .find(|e| e.former_names.iter().any(|w| &**w == module))
            })?;
        Some((&hit.identity, hit.errors, &hit.ceilings))
    }

    /// Round 31: an `open_<kind>` keeps its decoded settled answer for the caller's write-back.
    pub(crate) fn keep_settled(&self, name: &str, settled: Settled) {
        self.settled
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(Box::from(name), settled);
    }

    /// The check-time half of `check_endpoints`, after the DRY_RUN chain answered: decode the ENDPOINT records
    /// and judge them against the instance's `accept` (BUSBAR-3160/3163; §48, TRANSPORT-SECURITY-POLICY §3-§4).
    pub(crate) fn judge_check_answer(
        &self,
        s: &InstanceSpec<'_>,
        answer: &[u8],
    ) -> Result<Vec<DeclaredEndpoint>, OpenError> {
        let declared = decode_endpoints(answer, s.name)?;
        let module = self
            .resolve_module(s.identity)
            .map_or(s.identity, |(identity, _, _)| identity);
        judge_endpoints(s.name, module, s.limits.accept, &declared)?;
        Ok(declared)
    }

    /// Round 6: every admitted secret plugin's declared shorthands, in admission order. The kernel feeds them to
    /// `busbar_contract::secret_ref::Sugars::declare` (which refuses core words, duplicate words and duplicate
    /// roles) and hands the resulting `Sugars` to the binder (§12.7) and to its own config-section parsing.
    pub fn sugars(&self) -> &[SugarDecl] {
        &self.images.sugars
    }

    /// Round 11: per admitted auth image, its identity and its D_OUTBOUND_STYLE words (decoded at `add`), in
    /// admission order. Read only to build the STYLES frame the helper's `config::resolve_styles` consumes
    /// (round 13, §12.10 item 3, §12.18).
    pub fn outbound_styles(&self) -> Vec<(&str, Vec<&str>)> {
        self.texts(
            KindCode::Auth,
            busbar_plugin_abi::auth::tag::D_OUTBOUND_STYLE,
        )
    }

    /// Round 22: the D_STYLE_FLAGS mask (`auth::STYLE_*`) an admitted auth image declared for one of its styles
    /// (decoded at `add`; 0 when it declared none or the pair is unknown). Read only by K6 when it resolves a
    /// binding's credential mode and O_SCOPE (§12.18 "credential mode").
    pub fn style_flags(&self, identity: &str, style: &str) -> u64 {
        let Some(entry) = self
            .images
            .entries
            .iter()
            .find(|e| e.described.kind == KindCode::Auth && &*e.identity == identity)
        else {
            return 0;
        };
        entry
            .described
            .items
            .iter()
            .filter(|(t, _)| *t == busbar_plugin_abi::auth::tag::D_STYLE_FLAGS)
            .find_map(|(t, b)| {
                let rec = busbar_plugin_abi::records::Rec { tag: *t, body: b };
                let (mask, word) = rec.pod_tail::<busbar_plugin_abi::records::MaskRec>().ok()?;
                (word == style.as_bytes()).then_some(mask.mask)
            })
            .unwrap_or(0)
    }

    /// Round 12: the identities of admitted **compiled-in** (`Image::Linked`) store images whose describe facts
    /// carry `store::FB_EPHEMERAL`, in admission order. Read only by K9's absent-store rule (§12.10 item 1;
    /// MIGRATE-ON-BOOT r15 §3 1d); drop-ins are never listed.
    pub fn ephemeral_stores(&self) -> Vec<&str> {
        self.images
            .entries
            .iter()
            .filter(|e| {
                e.linked
                    && e.described.kind == KindCode::Store
                    && e.described.facts & busbar_plugin_abi::store::FB_EPHEMERAL != 0
            })
            .map(|e| &*e.identity)
            .collect()
    }

    /// Round 12: per admitted hook image, its identity and its D_WORD words (§8.4), in admission order. Read
    /// only by the kernel's pool strategy resolution (§12.25).
    pub fn hook_words(&self) -> Vec<(&str, Vec<&str>)> {
        self.texts(KindCode::Hook, busbar_plugin_abi::hook::tag::D_WORD)
    }

    /// Round 12: per issued-credential kind any admitted auth image declares (D_ISSUED_KIND), the shape its
    /// D_ISSUED_SHAPE item states (§8.3), decoded at `add`. Read only by issued credentials (§12.8).
    pub fn issued_shapes(&self) -> Vec<(&str /* issued kind */, IssuedShape)> {
        self.images
            .issued
            .iter()
            .map(|(kind, shape)| (&**kind, shape.clone()))
            .collect()
    }

    /// Round 13: per admitted plane image, its identity and its D_PROVIDER_SCHEMA text (§8.6 provider keys),
    /// decoded at `add`. Read only by the kernel's provider-entry validation at config load.
    pub fn provider_schemas(&self) -> Vec<(&str, &str)> {
        self.texts(
            KindCode::Plane,
            busbar_plugin_abi::plane::tag::D_PROVIDER_SCHEMA,
        )
        .into_iter()
        .filter_map(|(identity, texts)| texts.first().map(|schema| (identity, *schema)))
        .collect()
    }

    /// Round 14 (round 15: typed): per admitted plane image, its identity and its D_DIALECT_AUTH rows, decoded at
    /// `add` (`plane::decode_dialect_auth`, owned copies). Read only by K6's binding materialisation (§12.18).
    pub fn dialect_auth(&self) -> Vec<(&str, Vec<plane::DialectAuthOwned>)> {
        self.images
            .entries
            .iter()
            .filter(|e| e.described.kind == KindCode::Plane)
            .map(|e| (&*e.identity, e.dialect_auth.clone()))
            .collect()
    }

    /// Allocate the instance id and watchdog slot (the slot record carries (kind, configured name, a fresh
    /// `Arc<Scrub>`) from this moment, so log attribution and custody's scrub registration work in open chains.
    /// Round 8: the record stays in the registry's slot table for its whole life and is owned through a
    /// `SlotLease`; the lease moves Image chain → Instance and is released only after the last entry that can log
    /// under that slot has returned (round 10: after the inline close in `Drop for Instance`, or after the inline
    /// cancel in a dropped Image chain's guard, §10.4, §10.5), so a slot is never reused while a close or cancel
    /// of its previous owner is still running); describe; check against the kind (CapUnknown/DescribeInvalid);
    /// `binder.bind(id, config, D_SECRET_PATH*, D_TRUST_PATH*, D_DEST_PATH*, D_REF_PATH*)` then (round 13)
    /// `binder.resolve_refs(id, bound)` (§12.7); then (round 14) write `s.public_url` at each D_PUBLIC_URL_PATH
    /// and (round 22) `s.caller_upstreams` at each D_CALLER_UPSTREAMS_PATH (§12.7 core values; refuse CONFIG if the operator's bag already held that position); validate the *bound* config against
    /// D_SCHEMA; open (driving NEEDs); wrap the result in the kind's port. Any failure after bind calls
    /// `binder.unbind(id)`. Reconfigure = open new, swap, drop old (R6); dropping the old instance unbinds it.
    /// Round 10: describe, migrate and open (every step of their chains), check and close run inline under
    /// `entry::guard` on the thread that drives them, exactly like request ops (I10, §10.7). No dropped-in image
    /// is ever dlclosed (I13), so no entry needs TLS sampling or a permanent worker: origin/dev ffi_thread.rs's
    /// stated hazard (a thread that armed a plugin TLS key exiting after the unmap) is closed by residency, not
    /// by routing, for every entry alike. `ffi_thread` keeps only `dlopen` and `name_still_loaded` (§11.1).
    /// The store adapter is the kernel's existing `PersistenceBackend` (busbar-contract persistence.rs:534),
    /// implemented directly over the proxy. There is no other store port.
    pub fn open_store<N: Needs>(
        &self,
        s: &InstanceSpec<'_>,
        needs: &Arc<N>,
        refs: &Arc<dyn RefSource>,
        seal: StoreSeal,
    ) -> BoxFut<'_, Result<StoreHandle, OpenError>> {
        match self.reserve(s) {
            Ok(prepared) => self.open_store_reserved(prepared, needs, refs, seal),
            Err(error) => Box::pin(async move { Err(error) }),
        }
    }

    pub fn open_store_reserved<N: Needs>(
        &self,
        prepared: PreparedInstance,
        needs: &Arc<N>,
        refs: &Arc<dyn RefSource>,
        seal: StoreSeal,
    ) -> BoxFut<'_, Result<StoreHandle, OpenError>> {
        let owned = OwnedSpec::new(&prepared.spec());
        let needs = Arc::clone(needs);
        let refs = Arc::clone(refs);
        Box::pin(async move {
            let spec = owned.spec();
            let opened = self
                .open_reserved_instance::<k::Store, N>(prepared, &needs, &*refs)
                .await?;
            let proxy =
                busbar_plugin_abi::store::Proxy::bind(opened.instance).ok_or_else(not_this_kind)?;
            let adapter = crate::adapters::store::StoreAdapter::new(
                proxy,
                Arc::clone(&needs),
                &tokio::runtime::Handle::current(),
                seal(),
            )?;
            self.remember(
                &spec,
                KindCode::Store,
                &needs,
                &refs,
                Some(Arc::clone(&seal)),
            );
            Ok(StoreHandle {
                backend: Arc::new(adapter),
            })
        })
    }

    pub fn open_secret<N: Needs>(
        &self,
        s: &InstanceSpec<'_>,
        needs: &Arc<N>,
        refs: &Arc<dyn RefSource>,
    ) -> BoxFut<'_, Result<Arc<dyn SecretPort>, OpenError>> {
        match self.reserve(s) {
            Ok(prepared) => self.open_secret_reserved(prepared, needs, refs),
            Err(error) => Box::pin(async move { Err(error) }),
        }
    }

    pub fn open_secret_reserved<N: Needs>(
        &self,
        prepared: PreparedInstance,
        needs: &Arc<N>,
        refs: &Arc<dyn RefSource>,
    ) -> BoxFut<'_, Result<Arc<dyn SecretPort>, OpenError>> {
        let owned = OwnedSpec::new(&prepared.spec());
        let needs = Arc::clone(needs);
        let refs = Arc::clone(refs);
        Box::pin(async move {
            let spec = owned.spec();
            let opened = self
                .open_reserved_instance::<k::Secret, N>(prepared, &needs, &*refs)
                .await?;
            let proxy = busbar_plugin_abi::secret::Proxy::bind(opened.instance)
                .ok_or_else(not_this_kind)?;
            self.remember(&spec, KindCode::Secret, &needs, &refs, None);
            let port: Arc<dyn SecretPort> = Arc::new(crate::adapters::secret::SecretAdapter::new(
                proxy,
                Arc::clone(&needs),
            ));
            Ok(port)
        })
    }

    pub fn open_auth<N: Needs>(
        &self,
        s: &InstanceSpec<'_>,
        needs: &Arc<N>,
        refs: &Arc<dyn RefSource>,
    ) -> BoxFut<'_, Result<Arc<dyn AuthPort>, OpenError>> {
        match self.reserve(s) {
            Ok(prepared) => self.open_auth_reserved(prepared, needs, refs),
            Err(error) => Box::pin(async move { Err(error) }),
        }
    }

    pub fn open_auth_reserved<N: Needs>(
        &self,
        prepared: PreparedInstance,
        needs: &Arc<N>,
        refs: &Arc<dyn RefSource>,
    ) -> BoxFut<'_, Result<Arc<dyn AuthPort>, OpenError>> {
        let owned = OwnedSpec::new(&prepared.spec());
        let needs = Arc::clone(needs);
        let refs = Arc::clone(refs);
        Box::pin(async move {
            let spec = owned.spec();
            let opened = self
                .open_reserved_instance::<k::Auth, N>(prepared, &needs, &*refs)
                .await?;
            let proxy =
                busbar_plugin_abi::auth::Proxy::bind(opened.instance).ok_or_else(not_this_kind)?;
            let frame = chains::frame(&opened.described.items);
            let adapter = crate::adapters::auth::AuthAdapter::new(
                proxy,
                Arc::clone(&needs),
                Records::new(&frame),
                opened.errors,
            )
            .map_err(|e| {
                OpenError::Call(CallError::Fault(
                    busbar_plugin_abi::fail::FaultReason::BadRecords(e),
                ))
            })?;
            self.remember(&spec, KindCode::Auth, &needs, &refs, None);
            let port: Arc<dyn AuthPort> = Arc::new(adapter);
            Ok(port)
        })
    }

    pub fn open_hook<N: Needs>(
        &self,
        s: &InstanceSpec<'_>,
        needs: &Arc<N>,
        refs: &Arc<dyn RefSource>,
    ) -> BoxFut<'_, Result<Arc<dyn HookPort>, OpenError>> {
        match self.reserve(s) {
            Ok(prepared) => self.open_hook_reserved(prepared, needs, refs),
            Err(error) => Box::pin(async move { Err(error) }),
        }
    }

    pub fn open_hook_reserved<N: Needs>(
        &self,
        prepared: PreparedInstance,
        needs: &Arc<N>,
        refs: &Arc<dyn RefSource>,
    ) -> BoxFut<'_, Result<Arc<dyn HookPort>, OpenError>> {
        let owned = OwnedSpec::new(&prepared.spec());
        let needs = Arc::clone(needs);
        let refs = Arc::clone(refs);
        Box::pin(async move {
            let spec = owned.spec();
            let opened = self
                .open_reserved_instance::<k::Hook, N>(prepared, &needs, &*refs)
                .await?;
            let proxy =
                busbar_plugin_abi::hook::Proxy::bind(opened.instance).ok_or_else(not_this_kind)?;
            let points = opened
                .described
                .items
                .iter()
                .find(|(t, _)| *t == busbar_plugin_abi::hook::tag::D_POINTS)
                .and_then(|(t, b)| {
                    busbar_plugin_abi::records::Rec { tag: *t, body: b }
                        .pod::<busbar_plugin_abi::hook::Points>()
                        .ok()
                })
                .map_or(0, |p| p.mask);
            self.remember(&spec, KindCode::Hook, &needs, &refs, None);
            let port: Arc<dyn HookPort> = Arc::new(crate::adapters::hook::HookAdapter::new(
                proxy,
                Arc::clone(&needs),
                points,
                opened.errors,
            ));
            Ok(port)
        })
    }

    pub fn open_export<N: Needs>(
        &self,
        s: &InstanceSpec<'_>,
        needs: &Arc<N>,
        refs: &Arc<dyn RefSource>,
    ) -> BoxFut<'_, Result<Arc<dyn ExportPort>, OpenError>> {
        match self.reserve(s) {
            Ok(prepared) => self.open_export_reserved(prepared, needs, refs),
            Err(error) => Box::pin(async move { Err(error) }),
        }
    }

    pub fn open_export_reserved<N: Needs>(
        &self,
        prepared: PreparedInstance,
        needs: &Arc<N>,
        refs: &Arc<dyn RefSource>,
    ) -> BoxFut<'_, Result<Arc<dyn ExportPort>, OpenError>> {
        let owned = OwnedSpec::new(&prepared.spec());
        let needs = Arc::clone(needs);
        let refs = Arc::clone(refs);
        Box::pin(async move {
            let spec = owned.spec();
            let opened = self
                .open_reserved_instance::<k::Export, N>(prepared, &needs, &*refs)
                .await?;
            let proxy = busbar_plugin_abi::export::Proxy::bind(Arc::clone(&opened.instance))
                .ok_or_else(not_this_kind)?;
            let frame = chains::frame(&opened.described.items);
            let describe = crate::adapters::export::decode_describe(
                Records::new(&frame),
                opened.described.methods,
                opened.described.facts,
            )
            .map_err(|e| {
                OpenError::Unknown(format!("{}: the export's describe: {:?}", spec.name, e))
            })?;
            let adapter = crate::adapters::export::ExportAdapter::open(
                proxy,
                Arc::clone(&needs),
                opened.errors,
                describe,
                opened.dests,
                &opened.answer.answer(),
            )
            .map_err(OpenError::Call)?;
            self.remember(&spec, KindCode::Export, &needs, &refs, None);
            let port: Arc<dyn ExportPort> = Arc::new(adapter);
            Ok(port)
        })
    }

    pub fn open_plane<N: Needs>(
        &self,
        s: &InstanceSpec<'_>,
        needs: &Arc<N>,
        refs: &Arc<dyn RefSource>,
    ) -> BoxFut<'_, Result<Arc<dyn PlanePort>, OpenError>> {
        match self.reserve(s) {
            Ok(prepared) => self.open_plane_reserved(prepared, needs, refs),
            Err(error) => Box::pin(async move { Err(error) }),
        }
    }

    pub fn open_plane_reserved<N: Needs>(
        &self,
        prepared: PreparedInstance,
        needs: &Arc<N>,
        refs: &Arc<dyn RefSource>,
    ) -> BoxFut<'_, Result<Arc<dyn PlanePort>, OpenError>> {
        let owned = OwnedSpec::new(&prepared.spec());
        let needs = Arc::clone(needs);
        let refs = Arc::clone(refs);
        Box::pin(async move {
            let spec = owned.spec();
            let opened = self
                .open_reserved_instance::<k::Plane, N>(prepared, &needs, &*refs)
                .await?;
            let proxy =
                busbar_plugin_abi::plane::Proxy::bind(opened.instance).ok_or_else(not_this_kind)?;
            let frame = chains::frame(&opened.described.items);
            let describe = crate::adapters::plane::decode_describe(
                Records::new(&frame),
                opened.described.methods,
                opened.described.facts,
            )
            .map_err(|e| {
                OpenError::Unknown(format!("{}: the plane's describe: {}", spec.name, e.0))
            })?;
            self.remember(&spec, KindCode::Plane, &needs, &refs, None);
            let port: Arc<dyn PlanePort> = Arc::new(crate::adapters::plane::PlaneAdapter::new(
                proxy,
                Arc::clone(&needs),
                describe,
                opened.errors,
            ));
            Ok(port)
        })
    }

    pub fn open_transport<N: Needs>(
        &self,
        s: &InstanceSpec<'_>,
        needs: &Arc<N>,
        refs: &Arc<dyn RefSource>,
    ) -> BoxFut<'_, Result<Arc<dyn TransportPort>, OpenError>> {
        match self.reserve(s) {
            Ok(prepared) => self.open_transport_reserved(prepared, needs, refs),
            Err(error) => Box::pin(async move { Err(error) }),
        }
    }

    pub fn open_transport_reserved<N: Needs>(
        &self,
        prepared: PreparedInstance,
        needs: &Arc<N>,
        refs: &Arc<dyn RefSource>,
    ) -> BoxFut<'_, Result<Arc<dyn TransportPort>, OpenError>> {
        let owned = OwnedSpec::new(&prepared.spec());
        let needs = Arc::clone(needs);
        let refs = Arc::clone(refs);
        Box::pin(async move {
            let spec = owned.spec();
            let opened = self
                .open_reserved_instance::<k::Transport, N>(prepared, &needs, &*refs)
                .await?;
            let proxy = busbar_plugin_abi::transport::Proxy::bind(opened.instance)
                .ok_or_else(not_this_kind)?;
            let protocols: Box<[Box<str>]> = opened
                .described
                .items
                .iter()
                .filter(|(t, _)| *t == busbar_plugin_abi::transport::tag::D_PROTOCOL)
                .filter_map(|(_, b)| core::str::from_utf8(b).ok())
                .map(Box::from)
                .collect();
            let adapter =
                crate::adapters::transport::TransportAdapter::open(proxy, opened.errors, protocols)
                    .map_err(crate::answer::open_error)?;
            self.remember(&spec, KindCode::Transport, &needs, &refs, None);
            let port: Arc<dyn TransportPort> = Arc::new(adapter);
            Ok(port)
        })
    }

    /// DRY_RUN open (`--validate`, admin config check). Async because it drives an open chain whose NEEDs await
    /// (round 10: its steps run inline, §10.5); `--validate` awaits it on its own runtime.
    pub fn check(&self, s: &InstanceSpec<'_>) -> BoxFut<'_, Result<(), OpenError>> {
        let endpoints = self.check_endpoints(s);
        Box::pin(async move { endpoints.await.map(drop) })
    }

    /// Round 35 (R7a): the same DRY_RUN chain as `check`, returning the decoded ENDPOINT records (≤ 16, in answer
    /// order) after the same validation and `transport_verdict` refusals. `check` is this call mapped to `()`.
    pub fn check_endpoints(
        &self,
        s: &InstanceSpec<'_>,
    ) -> BoxFut<'_, Result<Vec<DeclaredEndpoint>, OpenError>> {
        self.check_endpoints_with_refs(s, &(Arc::new(chains::DeniedRefs) as Arc<dyn RefSource>))
    }

    pub fn check_endpoints_with_refs(
        &self,
        s: &InstanceSpec<'_>,
        refs: &Arc<dyn RefSource>,
    ) -> BoxFut<'_, Result<Vec<DeclaredEndpoint>, OpenError>> {
        let refs = Arc::clone(refs);
        let owned = OwnedSpec::new(s);
        Box::pin(async move {
            let spec = owned.spec();
            match self.entry_of(spec.identity).map(|e| e.described.kind) {
                Some(KindCode::Store) => self.dry_run::<k::Store>(&spec, &*refs).await,
                Some(KindCode::Secret) => self.dry_run::<k::Secret>(&spec, &*refs).await,
                Some(KindCode::Auth) => self.dry_run::<k::Auth>(&spec, &*refs).await,
                Some(KindCode::Hook) => self.dry_run::<k::Hook>(&spec, &*refs).await,
                Some(KindCode::Export) => self.dry_run::<k::Export>(&spec, &*refs).await,
                Some(KindCode::Plane) => self.dry_run::<k::Plane>(&spec, &*refs).await,
                Some(KindCode::Transport) => self.dry_run::<k::Transport>(&spec, &*refs).await,
                None => Err(OpenError::Unknown(format!(
                    "{}: no admitted plugin answers to module {}",
                    spec.name, spec.identity
                ))),
            }
        })
    }

    /// Round 31 (owner ruling, §47): there is no `Registry::migrate`. The boot caller walks `BootPlan` (below) —
    /// 2a, 2b, 2c — calling `open_<kind>` for each step before the next step starts, identically for every plugin
    /// (257b: no plugin name, branch or table anywhere on this path), so every secret instance a store's open asks
    /// for through SECRET is already open. Every `open_<kind>` (boot, reload, admin install) binds the bag with
    /// `binder.bind_any` on an unstamped boot and `binder.bind` otherwise (§7.2, §12.7), decodes the optional
    /// CONFIG + CORE_CFG* after INSTANCE with `settled::decode_settled`, validates CONFIG against D_SCHEMA, maps it
    /// and every CORE_CFG value back through core's reference map with `binder.unbind_refs`, and keeps the owned
    /// `Settled` for its caller's write-back (§7.2: step 5, step 5W, the reload path or the admin config store).
    /// REFUSED => `OpenError::Refused` naming the instance index and its configured module, with the plugin's
    /// scrubbed text (or core's own `migrate_admit` text, §5); what that means at boot, reload and admin install
    /// is §7.2's "Refusal" rule, and a reload or admin install refused R_CONFLICT LIVE_WRITER is §7.2's "Live
    /// instances" rule.
    pub fn take_settled(&self, name: &str) -> Option<Settled> {
        self.settled
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .remove(name)
    }

    /// Round 6, boot only: the r6 §3 step 2 order, computed generically. `instances[i]` is configured instance i
    /// with its kind; `deps` = the kernel's existing edges, `appbuild::bootstrap_dependency_names` (appbuild.rs:770),
    /// fed with every SecretRef the binder finds in the store's bag at **any** position (`bind_any` semantics,
    /// because a 1.x bag's older positions are undeclared on an unstamped boot) and in core's own sections that the store
    /// boot needs (admin token, signing key), each resolved to a configured secret instance through
    /// `Sugars`. 2a = those secret instances, then transitively the secret instances their own bags reference
    /// (depth ≤ 4; a cycle refuses CONFIG naming the instance indices), dependencies first; 2b = the store;
    /// 2c = every remaining instance kind by kind (secret, auth, hook, export, plane, transport), config order
    /// within a kind. Reads only kinds, configured names and SecretRefs: no plugin name (§15.8).
    pub fn boot_plan(
        &self,
        instances: &[(KindCode, InstanceSpec<'_>)],
        sugars: &busbar_contract::secret_ref::Sugars,
    ) -> Result<BootPlan, OpenError> {
        self.boot_plan_with_core(instances, sugars, &[])
    }

    /// `boot_plan` fed, as §11.2 says, with core's own sections the store boot needs (admin token, signing key,
    /// at-rest keys): `core_modules` is the `module` each of those references names (a configured secret
    /// instance's exact name, already bound under the read grammar). Each opens
    /// in 2a after the store's own, dependencies first; a missing instance refuses before the walk.
    /// Core is not an instance, so the frozen
    /// `boot_plan` signature has no place for them: this is its fed form and `boot_plan` is the `&[]` case.
    pub fn boot_plan_with_core(
        &self,
        instances: &[(KindCode, InstanceSpec<'_>)],
        sugars: &busbar_contract::secret_ref::Sugars,
        core_modules: &[&str],
    ) -> Result<BootPlan, OpenError> {
        let kinds: Vec<KindCode> = instances.iter().map(|(kind, _)| *kind).collect();
        let roots: Vec<usize> = core_modules
            .iter()
            .map(|module| {
                self.secret_index(module, instances, sugars).ok_or_else(|| {
                    OpenError::Unknown(format!(
                        "core secret reference names no configured instance '{module}'"
                    ))
                })
            })
            .collect::<Result<_, _>>()?;
        let mut deps = |at: usize| self.secret_deps(at, instances, sugars);
        let steps = chains::plan_order(&kinds, &roots, &mut deps)?;
        Ok(BootPlan { steps })
    }

    /// References have already been bound under this read's grammar; only the exact configured name routes.
    fn secret_index(
        &self,
        module: &str,
        instances: &[(KindCode, InstanceSpec<'_>)],
        _sugars: &busbar_contract::secret_ref::Sugars,
    ) -> Option<usize> {
        instances
            .iter()
            .position(|(kind, spec)| *kind == KindCode::Secret && spec.name == module)
    }

    /// A pushed desired state (today's hook/plane `configure`): merge `patch` (a JSON object) into the stored
    /// config of instance `name` (absent fields keep their values), `check` it (a refusal is the NACK and
    /// nothing changes), then open the new instance and return it for the caller to swap in (R6). `version`
    /// ordering: a push older than the last applied one is acknowledged and not applied. Core-owned; no plugin
    /// has a configure method.
    pub fn reconfigure(
        &self,
        kind: KindCode,
        name: &str,
        patch: &[u8],
        version: u64,
    ) -> BoxFut<'_, Result<Reconfigured, OpenError>> {
        let (name, patch) = (name.to_owned(), patch.to_vec());
        Box::pin(async move {
            let stored = self
                .applied
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .get(&(kind, Box::from(name.as_str())))
                .cloned();
            let Some(stored) = stored else {
                return Err(OpenError::Unknown(format!(
                    "{name}: no open {kind:?} instance by that name"
                )));
            };
            if version < stored.version {
                return Ok(Reconfigured::Stale);
            }
            let merged =
                chains::merge_patch(&stored.config, &patch).map_err(|text| OpenError::Config {
                    code: refused::R_CONFIG,
                    text: format!("{name}: {text}"),
                    error: None,
                })?;
            let spec = InstanceSpec {
                purpose: OpenPurpose::Canonical,
                identity: &stored.identity,
                name: &name,
                config_json: &merged,
                limits: stored.limits,
                public_url: stored.public_url.as_deref(),
                caller_upstreams: &stored.caller_upstreams,
            };
            self.check_endpoints_with_refs(&spec, &stored.refs).await?;
            let port = stored
                .opener
                .open(self, OwnedSpec::new(&spec), kind)
                .await?;
            if let Some(held) = self
                .applied
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .get_mut(&(kind, Box::from(name.as_str())))
            {
                held.version = version;
            }
            Ok(Reconfigured::Opened(port))
        })
    }

    /// Reopen the saved config under exactly the Needs retained by its last successful open.
    /// Rotation does not consume a pushed configuration version (HOST §3.3 a).
    /// Stores require a restart because replacing them requires rebuilding core state.
    pub fn reopen(&self, kind: KindCode, name: &str) -> BoxFut<'_, Result<OpenedPort, OpenError>> {
        let stored = self
            .applied
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .get(&(kind, Box::from(name)))
            .cloned();
        let name = name.to_owned();
        Box::pin(async move {
            if kind == KindCode::Store {
                return Err(OpenError::Unknown(
                    "store credential rotation requires a restart".into(),
                ));
            }
            let stored = stored.ok_or_else(|| {
                OpenError::Unknown(format!("{name}: no open {kind:?} instance by that name"))
            })?;
            let spec = InstanceSpec {
                purpose: OpenPurpose::Canonical,
                identity: &stored.identity,
                name: &name,
                config_json: &stored.config,
                limits: stored.limits,
                public_url: stored.public_url.as_deref(),
                caller_upstreams: &stored.caller_upstreams,
            };
            stored.opener.open(self, OwnedSpec::new(&spec), kind).await
        })
    }

    /// The image entry the generic `module:` match resolves (identity first, then `former_names` words).
    pub(crate) fn entry_of(&self, module: &str) -> Option<&ImageEntry> {
        self.images
            .entries
            .iter()
            .find(|e| &*e.identity == module)
            .or_else(|| {
                self.images
                    .entries
                    .iter()
                    .find(|e| e.former_names.iter().any(|w| &**w == module))
            })
    }

    /// The canonical identity of the admitted image the operator's `module` word names (identity, then a
    /// `former_names` word), or None when no admitted image answers to it.
    pub fn identity_of(&self, module: &str) -> Option<String> {
        self.resolve_module(module)
            .map(|(identity, _, _)| identity.to_owned())
    }

    /// Records the config an instance opened with, for `reconfigure` (the last applied version is kept).
    pub(crate) fn remember<N: Needs>(
        &self,
        s: &InstanceSpec<'_>,
        kind: KindCode,
        needs: &Arc<N>,
        refs: &Arc<dyn RefSource>,
        seal: Option<StoreSeal>,
    ) {
        let mut applied = self.applied.lock().unwrap_or_else(PoisonError::into_inner);
        let key = (kind, Box::from(s.name));
        let version = applied.get(&key).map_or(0, |a| a.version);
        applied.insert(
            key,
            Applied {
                refs: Arc::clone(refs),
                opener: Arc::new(BoundNeeds {
                    needs: Arc::clone(needs),
                    refs: Arc::clone(refs),
                    seal,
                }),
                identity: Box::from(s.identity),
                config: s.config_json.to_vec(),
                limits: s.limits,
                public_url: s.public_url.map(str::to_owned),
                caller_upstreams: s.caller_upstreams.to_vec(),
                version,
            },
        );
    }

    /// The configured secret instances `instances[at]`'s bag references at any position (`bind_any`: a 1.x bag's
    /// older positions are undeclared on an unstamped boot), by index. Reads only kinds, configured names and
    /// SecretRefs (no plugin name, §15.8). A module the registry does not know has no dependencies here: its
    /// own open refuses it.
    fn secret_deps(
        &self,
        at: usize,
        instances: &[(KindCode, InstanceSpec<'_>)],
        sugars: &busbar_contract::secret_ref::Sugars,
    ) -> Result<Vec<usize>, OpenError> {
        let s = &instances[at].1;
        let Some(entry) = self.entry_of(s.identity) else {
            return Ok(Vec::new());
        };
        let paths = |wanted: u16| -> Vec<&str> {
            entry
                .described
                .items
                .iter()
                .filter(|(t, _)| *t == wanted)
                .filter_map(|(_, b)| core::str::from_utf8(b).ok())
                .collect()
        };
        let id = self.ids.next()?;
        let bound = self
            .binder
            .bind_any(
                id,
                s.config_json,
                &paths(tag::D_SECRET_PATH),
                &paths(tag::D_TRUST_PATH),
                &paths(tag::D_DEST_PATH),
                &paths(tag::D_REF_PATH),
            )
            .map_err(|e| OpenError::Config {
                code: refused::R_CONFIG,
                text: format!("{}: {e:?}", s.name),
                error: None,
            })?;
        let _unbound = chains::Unbind::new(Arc::clone(&self.binder), id);
        let config: json::Value = json::parse_value(&bound).unwrap_or_default();
        let mut handles = Vec::new();
        secret_handles(&config, &mut handles);
        let mut out = Vec::new();
        for handle in handles {
            let Some(module) = self
                .binder
                .secret(id, handle)
                .and_then(|r| r.source_module().map(str::to_owned))
            else {
                continue;
            };
            let index = self
                .secret_index(&module, instances, sugars)
                .ok_or_else(|| {
                    OpenError::Unknown(format!(
                        "{}: secret reference names no configured instance '{module}'",
                        s.name
                    ))
                })?;
            if !out.contains(&index) {
                out.push(index);
            }
        }
        Ok(out)
    }

    /// Plugin describe facts for admin/health (never shown to another plugin).
    pub fn described(&self, identity: &str) -> Option<Described> {
        self.images
            .entries
            .iter()
            .find(|e| &*e.identity == identity)
            .map(|e| e.described.clone())
    }

    /// Every admitted image of `kind` with the UTF-8 bodies of its `tag` describe items, in admission order. A
    /// body that is not UTF-8 is skipped.
    fn texts(&self, kind: KindCode, tag: u16) -> Vec<(&str, Vec<&str>)> {
        self.images
            .entries
            .iter()
            .filter(|e| e.described.kind == kind)
            .map(|e| {
                let words = e
                    .described
                    .items
                    .iter()
                    .filter(|(t, _)| *t == tag)
                    .filter_map(|(_, b)| core::str::from_utf8(b).ok())
                    .collect();
                (&*e.identity, words)
            })
            .collect()
    }
}

#[derive(Clone)]
pub struct Described {
    pub kind: KindCode,
    pub methods: u64,
    pub facts: u64,
    pub items: Vec<(u16, Vec<u8>)>,
    pub schema: Option<Box<str>>,
    pub metrics: Vec<MetricInfo>,
    /// Round 34: Some when D_ERRORS was present and refused (`Registry::add`); the image runs without codes.
    pub error_codes_refused: Option<ErrorCodesRefused>,
}

impl Described {
    /// Exact describe texts, in image order. Admission validates D_UPSTREAM_PATH before exposing it.
    pub fn paths(&self, wanted: u16) -> impl Iterator<Item = &str> {
        self.items.iter().filter_map(move |(tag, body)| {
            (*tag == wanted)
                .then(|| core::str::from_utf8(body).ok())
                .flatten()
        })
    }
}

/// Round 34: the one schema for the WARN, the audit `data` and `image.admission.error_codes_refused`.
/// `field` is always "errors"; `have` is template-built (never a plugin byte); `want` is the constant of `add`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ErrorCodesRefused {
    pub field: &'static str,
    pub have: Box<str>,
    pub want: &'static str,
}

/// Indices into the `instances` slice given to `boot_plan`, in execution order, with the r6 phase of each.
pub struct BootPlan {
    pub steps: Vec<(u32 /* instance index */, BootPhase)>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BootPhase {
    StoreSecrets, /* 2a */
    Store,        /* 2b */
    Rest,         /* 2c */
}

// Round 29, the deployment point between 2b and 2c (L2, `registry.rs` +2; §5 `deployment`, §16.187). After the
// last `Store` step and before the first `Rest` step, the boot walk calls `host_vt::set_deployment(id)` with the
// id the kernel read or wrote (K-side, boot_identity.rs keep-once), then `Registry::check` once for every
// `StoreSecrets` and `Store` instance, in plan order, with the same `InstanceSpec`. Any `Err` refuses the boot
// exactly as a step-2c `open` refusal does (`OpenError::Refused` naming the instance index and module, the plugin's
// scrubbed text). Those instances keep running; nothing is re-opened. A plugin that binds to the install identity
// therefore sees `deployment_id()` None in its 2a/2b `check`/`open` and Some in this re-check, always before 2c.

/// Round 31: one instance's settled settings from its `open`, in operator form (secret references restored).
/// `core_cfg` fragments are filed by `config::file_core_cfg` into core's own sections (§12.10); `config_json`
/// replaces the bag. Taken once by the write-back (`take_settled`); core stores no version with it.
pub struct Settled {
    pub config_json: busbar_contract::secure::SecureVec,
    pub core_cfg: Vec<CoreCfg>,
}

/// section = abi::core_cfg::*; value_json in that section's grammar.
pub struct CoreCfg {
    pub section: u32,
    pub name: Box<str>,
    pub value_json: busbar_contract::secure::SecureVec,
}

#[derive(Clone)]
pub struct MetricInfo {
    pub id: u32,
    pub kind: u32,
    pub name: Box<str>,
    pub help: Box<str>,
    pub label_keys: Vec<Box<str>>,
}

/// Round 8: one watchdog slot's record. The log sink and the watchdog map a slot to its `SlotCell`, never to an
/// Instance. Written only by `SlotTable::alloc`, under the table's cold mutex, while the slot is free (no lease,
/// so no entry runs under it and no log line can map to it); read without a lock by the log sink only for the slot
/// of a running entry (whose lease is held, so the record cannot change), and by `hung` under the mutex.
/// Round 34: `errors` = the owning image's book (set at `alloc`, so migrate/open render codes as an instance does);
/// `undeclared_warned` = the per-slot latch of the undeclared WARN, touched only on that path (a Relaxed load and,
/// only when false, a Relaxed store; no RMW, I5; two racing threads may print the WARN twice, which is harmless).
pub struct SlotRecord {
    pub kind: KindCode,
    pub name: Arc<str>,
    pub scrub: Arc<Scrub>,
    pub errors: &'static ErrorBook,
    pub undeclared_warned: AtomicBool,
}

/// Round 34 (PLUGIN-ERROR-CODES §2.5). One per admitted image, built in `Registry::add`, leaked once (images are
/// never unloaded, I13, so `'static` is exact and the leak is bounded: ≤ 512 bytes of numbers + one ≤ 64-byte
/// identity copy per declaring image).
pub enum ErrorBook {
    /// D_ERRORS accepted. `identity` passed `scan::error_identity` (re-checked here with a `debug_assert` and the
    /// same function, so no unchecked identity reaches a rendered code); `numbers` strictly ascending.
    Declared {
        identity: &'static str,
        numbers: &'static [u16],
    },
    /// D_ERRORS present and bad (§11.2 `add`): text renders with no code and no undeclared WARN.
    Refused,
    /// No D_ERRORS.
    None,
}

impl ErrorBook {
    /// The one rule for ERROR records and `log` numbers: 0 → None; n > 9999 (as `u32`) → not declared; `Declared`
    /// and `numbers.binary_search(&(n as u16))` hits → Some(code); `Declared` miss or `None` → not declared (None,
    /// and the first time per slot one WARN BUSBAR-6xxx "plugin error number not declared" `{number}`, attributed;
    /// no audit row, never FAULT); `Refused` → None, no WARN.
    pub fn resolve(&self, n: u32, latch: &AtomicBool) -> Option<PluginCode> {
        match self {
            ErrorBook::Refused => None,
            _ if n == 0 => None,
            ErrorBook::Declared {
                identity, numbers, ..
            } if n <= 9999 && numbers.binary_search(&(n as u16)).is_ok() => Some(PluginCode {
                plugin: identity,
                number: n as u16,
            }),
            _ => {
                if !latch.load(Ordering::Relaxed) {
                    latch.store(true, Ordering::Relaxed);
                    tracing::warn!(number = n, "plugin error number not declared");
                }
                None
            }
        }
    }
}

/// The D_ERRORS faults' fixed `want` (PLUGIN-ERROR-CODES §2.4).
const ERRORS_WANT: &str = "1..=256 numbers, each 1..=9999, strictly ascending; name ^[a-z][a-z0-9-]{0,63}$ not ending '-'";

/// PLUGIN-ERROR-CODES §2.4: decode the image's D_ERRORS bodies into its book. Every check runs before any
/// allocation; `have` is built only from counts, declared numbers, offsets and lengths, never a plugin byte.
/// `identity` is `scan::error_identity` over the stamp name, called only when the list itself was good.
fn decode_errors<'a>(
    bodies: &[&[u8]],
    identity: impl FnOnce() -> Result<&'a str, crate::scan::IdentityFault>,
) -> Result<ErrorBook, ErrorCodesRefused> {
    use crate::scan::IdentityFault;
    let refuse = |have: String| ErrorCodesRefused {
        field: "errors",
        have: have.into(),
        want: ERRORS_WANT,
    };
    let body = match bodies {
        [] => return Ok(ErrorBook::None),
        [one] => *one,
        many => return Err(refuse(format!("{} D_ERRORS items", many.len()))),
    };
    if body.is_empty() || body.len() % 2 != 0 || body.len() > 512 {
        return Err(refuse(format!("body {} bytes", body.len())));
    }
    let mut numbers: Vec<u16> = Vec::with_capacity(body.len() / 2);
    for (index, pair) in body.chunks_exact(2).enumerate() {
        let n = u16::from_le_bytes([pair[0], pair[1]]);
        if n == 0 || n > 9999 {
            return Err(refuse(format!("{n} at index {index}")));
        }
        if let Some(&prev) = numbers.last() {
            if n <= prev {
                return Err(refuse(format!("{n} after {prev} at index {index}")));
            }
        }
        numbers.push(n);
    }
    let name = identity().map_err(|fault| {
        refuse(match fault {
            IdentityFault::Empty => "empty name".to_owned(),
            IdentityFault::BadChar { byte } => format!("bad character at byte {byte}"),
            IdentityFault::Length { len } => format!("length {len} > 64"),
            IdentityFault::TrailingDash => "name ends in '-'".to_owned(),
        })
    })?;
    Ok(ErrorBook::Declared {
        identity: Box::leak(name.to_owned().into_boxed_str()),
        numbers: Box::leak(numbers.into_boxed_slice()),
    })
}

/// Round 9: `add`'s NameConflict. The identity and each `former_names` word of the newcomer against every
/// admitted identity and word (and the newcomer's own identity against its words).
fn name_conflict<'a, W: Iterator<Item = &'a str>>(
    admitted: impl Iterator<Item = (&'a str, W)>,
    identity: &str,
    former_names: &[&str],
) -> Option<Refusal> {
    let conflict = |field: &'static str, word: &str| Refusal {
        code: RefusalCode::NameConflict,
        field,
        plugin: Some(identity.to_owned()),
        have: word.to_owned(),
        want: "a word no other admitted plugin answers to".to_owned(),
        link: None,
    };
    if former_names.contains(&identity) {
        return Some(conflict("former_names", identity));
    }
    for (other, words) in admitted {
        let words: Vec<&str> = words.collect();
        if other == identity {
            return Some(conflict("identity", identity));
        }
        if let Some(word) = former_names
            .iter()
            .find(|w| **w == other || words.contains(w))
        {
            return Some(conflict("former_names", word));
        }
        if words.contains(&identity) {
            return Some(conflict("identity", identity));
        }
    }
    None
}

/// One ENDPOINT record a plugin's CHECK answer declared (§3, round 32), decoded and bounds-checked.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DeclaredEndpoint {
    /// The need op the plugin will use: `op::OPEN` or `op::FETCH`.
    pub op: u32,
    /// The `NeedRec.flags` encoding: TLS bits 0..=3 and the egress class in bits 16..=19.
    pub flags: u32,
    /// The destination the plugin declared, at most `MAX_DEST` bytes of UTF-8.
    pub dest: Box<str>,
}

/// The most ENDPOINT records an answer may carry and the longest dest (§3, round 32).
const MAX_ENDPOINTS: usize = 16;
const MAX_DEST: usize = 2_048;

/// §3: the ENDPOINT records of a CHECK answer, in answer order. More than 16, a dest over 2,048 bytes or not
/// UTF-8, an op other than OPEN/FETCH, an egress above `LOOPBACK_ALLOWED`, the retired 0x200 or any other
/// stray flag bit is INVALID, which refuses CONFIG naming the instance.
fn decode_endpoints(answer: &[u8], name: &str) -> Result<Vec<DeclaredEndpoint>, OpenError> {
    let invalid = |why: &str| OpenError::Config {
        code: refused::R_CONFIG,
        text: format!("{name}: the plugin declared an invalid ENDPOINT ({why})"),
        error: None,
    };
    let mut out = Vec::new();
    for rec in Records::new(answer) {
        let rec = rec.map_err(|_| invalid("malformed record"))?;
        if rec.tag != tag::ENDPOINT {
            continue;
        }
        if out.len() == MAX_ENDPOINTS {
            return Err(invalid("more than 16"));
        }
        let (head, dest) = rec
            .pod_tail::<EndpointRec>()
            .map_err(|_| invalid("bad size"))?;
        if head.op != op::OPEN && head.op != op::FETCH {
            return Err(invalid("op"));
        }
        let known = need_flag::TLS_MASK | (0xF << 16);
        if head.flags & !known != 0 || (head.flags >> 16) & 0xF > egress::LOOPBACK_ALLOWED {
            return Err(invalid("flags"));
        }
        if dest.len() > MAX_DEST {
            return Err(invalid("dest over 2,048 bytes"));
        }
        let dest = core::str::from_utf8(dest).map_err(|_| invalid("dest not UTF-8"))?;
        out.push(DeclaredEndpoint {
            op: head.op,
            flags: head.flags,
            dest: dest.into(),
        });
    }
    Ok(out)
}

/// The host a declared dest names, for the printed `verify: pin` match: a FETCH URL's authority, `host:port` without
/// its port, `[v6]:port` as `[v6]`; a `unix:` path is returned whole.
fn dest_host(dest: &str) -> &str {
    let rest = ["https://", "http://"]
        .iter()
        .find_map(|scheme| {
            dest.get(..scheme.len())
                .filter(|head| head.eq_ignore_ascii_case(scheme))
                .map(|_| &dest[scheme.len()..])
        })
        .unwrap_or(dest);
    if rest
        .get(..5)
        .is_some_and(|head| head.eq_ignore_ascii_case("unix:"))
    {
        return rest;
    }
    let authority = rest.split('/').next().unwrap_or(rest);
    match authority.strip_prefix('[') {
        Some(inner) => inner
            .find(']')
            .map_or(authority, |end| &authority[..end + 2]),
        None => authority
            .rsplit_once(':')
            .map_or(authority, |(host, _)| host),
    }
}

/// BUSBAR-3160 (TRANSPORT-SECURITY-POLICY §6, "the exact boot refusal"): the frame core prints for a declared
/// endpoint that would be dialled without TLS, with the one line that accepts it. `<config path>` is not known
/// here, so the line is placed "in the `<instance>` block of your configuration".
fn plaintext_refusal(name: &str, module: &str, dest: &str) -> String {
    let class = if dest
        .get(..5)
        .is_some_and(|head| head.eq_ignore_ascii_case("unix:"))
    {
        "unix socket"
    } else if dest
        .get(..7)
        .is_some_and(|head| head.eq_ignore_ascii_case("http://"))
    {
        "http"
    } else {
        "tcp"
    };
    let host = dest_host(dest);
    format!(
        "BUSBAR-3160: {name} (module {module}) would connect to {dest} without TLS ({class}, plaintext).\n\
         busbar 1.6.0 connects only over verified TLS, and nothing is exempt: not loopback, not unix sockets.\n\
         Fix it one of two ways:\n\
         \x20 1. Turn on TLS for this connection (the plugin's docs name its TLS setting) and make the server's\n\
         \x20    certificate verifiable: put its CA under advanced.tls.trust_anchors, or pin its key under\n\
         \x20    advanced.tls.destinations (match: {host}, verify: pin).\n\
         \x20 2. If verified TLS is not possible here, accept the risk explicitly. Add this line to the {name}\n\
         \x20    block of your configuration, and replace the reason:\n\
         \x20      insecure_transport: {{ accept: plaintext, reason: \"<why this is acceptable>\" }}\n\
         See https://getbusbar.com/docs/1.6/errors/BUSBAR-3160 and docs/migration-1.6.md#transport-security"
    )
}

/// BUSBAR-3160/3161/3163: judge every declared endpoint with `transport_verdict`, then refuse an acceptance none
/// of the declared endpoints needs (only when at least one was declared; with none the acceptance is kept).
fn judge_endpoints(
    name: &str,
    module: &str,
    accept: Accept,
    declared: &[DeclaredEndpoint],
) -> Result<(), OpenError> {
    let config = |text: String| OpenError::Config {
        code: refused::R_CONFIG,
        text,
        error: None,
    };
    let (mut plain, mut waived) = (false, false);
    for ep in declared {
        match transport_verdict(accept, ep.flags & need_flag::TLS_MASK, &ep.dest) {
            Verdict::Refuse => return Err(config(plaintext_refusal(name, module, &ep.dest))),
            Verdict::Plain => plain = true,
            Verdict::WaiveVerify => waived = true,
            Verdict::Verify => {}
        }
    }
    if declared.is_empty() {
        return Ok(());
    }
    let unused = (accept.0 & Accept::PLAINTEXT != 0 && !plain)
        || (accept.0 & Accept::UNVERIFIED_TLS != 0 && !waived);
    if unused {
        return Err(config(format!(
            "BUSBAR-3163: {name} (module {module}) sets insecure_transport, but none of its declared endpoints needs it"
        )));
    }
    Ok(())
}

/// Round 14: one slot's state word and §10.6 ceiling row are `busbar_plugin_abi`'s `SlotCell` (the abi crate
/// owns the type because the host-side `Instance` reaches it). The registry's table keeps one `Arc<SlotCell>` per
/// leased slot and hands the same `Arc` to the lease and then to the `Instance`, so the watchdog's quarantine and
/// the instance's `is_live` read one word.
pub use busbar_plugin_abi::host_side::driver::SlotCell;

const PAGE: usize = 64;
const FAN: usize = 512;
/// Slot indices stay below the watch word's 24-bit field.
const SLOTS_MAX: u32 = 1 << 24;

/// One slot of the table: the cell and the record of its current lease (both `None` while the slot is free), and
/// the last epoch used, so the next lease of the slot always has a later one. Written only by `alloc` and
/// `release`, under the table's cold mutex.
struct SlotEntry {
    cell: ArcSwapOption<SlotCell>,
    record: ArcSwapOption<SlotRecord>,
    epoch: AtomicU32,
}

impl SlotEntry {
    fn new() -> Self {
        SlotEntry {
            cell: ArcSwapOption::empty(),
            record: ArcSwapOption::empty(),
            epoch: AtomicU32::new(0),
        }
    }
}

type Page = Box<[SlotEntry; PAGE]>;
type Mid = Box<[OnceLock<Page>; FAN]>;

/// Round 14: the registry's slot table. Entries live in pages of 64, allocated under the cold mutex when the free
/// list is empty, never moved or freed; slot indices stay < 2^24 (the watch word's field).
pub struct SlotTable {
    dir: Box<[OnceLock<Mid>; FAN]>,
    /// Free slot indices and the next never-used index.
    cold: Mutex<(Vec<u32>, u32)>,
}

impl Default for SlotTable {
    fn default() -> Self {
        Self::new()
    }
}

impl SlotTable {
    /// The scrub set of the instance leasing this process slot.
    pub fn scrub_of(&self, slot: u32) -> Option<Arc<Scrub>> {
        self.record(slot).map(|record| Arc::clone(&record.scrub))
    }

    pub fn new() -> Self {
        SlotTable {
            dir: Box::new(core::array::from_fn(|_| OnceLock::new())),
            cold: Mutex::new((Vec::new(), 0)),
        }
    }

    fn entry(&self, slot: u32) -> Option<&SlotEntry> {
        let slot = slot as usize;
        let mid = self.dir.get(slot / (FAN * PAGE))?.get()?;
        let page = mid.get((slot / PAGE) % FAN)?.get()?;
        page.get(slot % PAGE)
    }

    /// The record of a slot that is leased now (the log sink's attribution for a running entry).
    pub(crate) fn record(&self, slot: u32) -> Option<Arc<SlotRecord>> {
        self.entry(slot)?.record.load_full()
    }

    /// Cold: under the mutex, pops a free slot, writes its record and its ceiling row (`ceilings` = the §10.6 row
    /// for this image, kind and store fact; describe's slot gets the fixed describe row, every index 5 s), gives
    /// it a later epoch and a LIVE cell, and returns the lease. Every entry (describe included: round 14 withdraws
    /// the inert slot 0) runs under a leased slot.
    pub fn alloc(self: &Arc<Self>, rec: SlotRecord, ceilings: &[u32; 64]) -> SlotLease {
        let mut cold = self.cold.lock().unwrap_or_else(PoisonError::into_inner);
        let slot = match cold.0.pop() {
            Some(slot) => slot,
            None => {
                let next = cold.1;
                assert!(next < SLOTS_MAX, "plugin slot table exhausted");
                cold.1 += 1;
                next
            }
        };
        let at = slot as usize;
        let mid = self.dir[at / (FAN * PAGE)]
            .get_or_init(|| Box::new(core::array::from_fn(|_| OnceLock::new())));
        let page = mid[(at / PAGE) % FAN]
            .get_or_init(|| Box::new(core::array::from_fn(|_| SlotEntry::new())));
        let entry = &page[at % PAGE];
        let epoch = entry.epoch.load(Ordering::Relaxed).wrapping_add(1).max(1);
        entry.epoch.store(epoch, Ordering::Relaxed);
        let cell = Arc::new(SlotCell::new(epoch, ceilings));
        let rec = Arc::new(rec);
        entry.record.store(Some(Arc::clone(&rec)));
        entry.cell.store(Some(Arc::clone(&cell)));
        drop(cold);
        SlotLease {
            slot,
            epoch,
            table: Arc::clone(self),
            cell,
            record: rec,
            armed: true,
        }
    }

    /// `watch::scan`'s `ceiling` (§10.6): `ceilings_us[entry]` (Relaxed) and `epoch` (Acquire). No lock.
    pub fn watch_view(&self, slot: u32, entry: u8) -> (u32, u32) {
        match self.entry(slot).and_then(|e| e.cell.load_full()) {
            Some(cell) => {
                let us = cell
                    .ceilings_us()
                    .get(usize::from(entry))
                    .map_or(u32::MAX, |c| c.load(Ordering::Relaxed));
                (us, cell.epoch())
            }
            None => (u32::MAX, 0),
        }
    }

    /// `watch::scan`'s `report`, cold: takes the mutex (so the slot cannot be released or re-allocated meanwhile);
    /// if the cell's epoch is still `epoch` and its state is LIVE, CASes it to QUARANTINED and audits `plugin_hung`
    /// with the record's (kind, configured name), entry and busy_ms, plus the alert; otherwise (the owner already
    /// released the slot, or was already quarantined) does nothing. Never reaches an Instance: the owner observes
    /// the state word itself. Instance owner: `is_live()` turns false, so the ports answer
    /// `CallError::Quarantined` and the kernel's quarantine-and-reopen path runs (§10.7). Image owner: the registry
    /// checks `lease.is_live()` when the describe, migrate or open entry returns: describe → `Registry::add` refuses
    /// `Refusal { code: DescribeInvalid, field: "describe.ceiling" }`; migrate → `OpenError::Call(Quarantined)`
    /// (MIGRATION_REFUSED, nothing written); open → if INSTANCE was answered the Instance is built in that poll as
    /// always (so its Drop closes it) and dropped at once, and `open_<kind>` returns `OpenError::Call(Quarantined)`.
    pub fn hung(&self, slot: u32, epoch: u32, entry: u8, busy_ms: u64) {
        let _cold = self.cold.lock().unwrap_or_else(PoisonError::into_inner);
        let Some(e) = self.entry(slot) else { return };
        let Some(cell) = e.cell.load_full() else {
            return;
        };
        if !cell.quarantine(epoch) {
            return;
        }
        if let Some(rec) = e.record.load_full() {
            tracing::error!(
                kind = ?rec.kind,
                instance = &*rec.name,
                entry,
                busy_ms,
                "plugin_hung: a plugin entry passed its watchdog ceiling; the instance is quarantined"
            );
        }
    }

    /// The FAULT path (`driver::set_fault_sink`): quarantine whatever instance holds `slot` now. Cold.
    pub(crate) fn fault(
        &self,
        slot: u32,
        image_owned: bool,
        reason: busbar_plugin_abi::fail::FaultReason,
    ) {
        let _cold = self.cold.lock().unwrap_or_else(PoisonError::into_inner);
        let Some(e) = self.entry(slot) else { return };
        let (Some(cell), Some(rec)) = (e.cell.load_full(), e.record.load_full()) else {
            return;
        };
        if !image_owned {
            cell.quarantine(cell.epoch());
        }
        tracing::error!(
            kind = ?rec.kind,
            instance = &*rec.name,
            image_owned,
            reason = ?reason,
            "plugin_fault: a plugin entry broke the interface contract"
        );
    }

    fn release(&self, slot: u32, epoch: u32) {
        let mut cold = self.cold.lock().unwrap_or_else(PoisonError::into_inner);
        let Some(e) = self.entry(slot) else { return };
        if e.epoch.load(Ordering::Relaxed) != epoch {
            return;
        }
        e.cell.store(None);
        e.record.store(None);
        cold.0.push(slot);
    }
}

/// One leased slot: its cell (shared with the `Instance` built over it) and record. The slot returns to the
/// table when the last entry that can log under it has returned (round 8).
pub struct SlotLease {
    slot: u32,
    epoch: u32,
    table: Arc<SlotTable>,
    cell: Arc<SlotCell>,
    record: Arc<SlotRecord>,
    armed: bool,
}

impl Drop for SlotLease {
    fn drop(&mut self) {
        if self.armed {
            self.table.release(self.slot, self.epoch);
        }
    }
}

impl SlotLease {
    pub(crate) fn table(&self) -> &Arc<SlotTable> {
        &self.table
    }
    pub fn slot(&self) -> u32 {
        self.slot
    }

    pub fn epoch(&self) -> u32 {
        self.epoch
    }

    pub fn record(&self) -> &SlotRecord {
        &self.record
    }

    /// The slot's cell; `InstanceParts::cell` takes a clone of this `Arc`.
    pub fn cell(&self) -> &Arc<SlotCell> {
        &self.cell
    }

    pub fn is_live(&self) -> bool {
        self.armed && self.cell.is_live(self.epoch)
    }

    /// Hands the lease to its next owner (Image chain → Instance); this one no longer releases the slot.
    pub fn take(&mut self) -> SlotLease {
        let lease = SlotLease {
            slot: self.slot,
            epoch: self.epoch,
            table: Arc::clone(&self.table),
            cell: Arc::clone(&self.cell),
            record: Arc::clone(&self.record),
            armed: self.armed,
        };
        self.armed = false;
        lease
    }
}

pub enum Reconfigured {
    Opened(OpenedPort),
    Stale,
}

pub enum OpenedPort {
    Store(StoreHandle),
    Secret(Arc<dyn SecretPort>),
    Auth(Arc<dyn AuthPort>),
    Hook(Arc<dyn HookPort>),
    Export(Arc<dyn ExportPort>),
    Plane(Arc<dyn PlanePort>),
    Transport(Arc<dyn TransportPort>),
}

/// Round 34: the three plugin-answer variants carry the resolved ERROR number (`ErrorBook::resolve`; None for a
/// core-made refusal). Its `Display` writes core's own words and the code only; the plugin text is a separate
/// field, never interpolated into a message (§12.16).
#[derive(Debug)]
pub enum OpenError {
    Refused {
        refusal: Refusal,
        error: Option<PluginCode>,
    },
    Config {
        code: u32,
        text: String,
        error: Option<PluginCode>,
    },
    Failed {
        code: u32,
        text: String,
        error: Option<PluginCode>,
    },
    Call(CallError),
    Unknown(String),
}

#[cfg(test)]
mod l2_tests {
    use super::*;

    /// The 2a walk from secret `from` of a store, through the shared `chains::plan_order` (secret `i` of
    /// `deps` is instance `i + 1`; instance 0 is the store; core's own sections name no root).
    fn walk(deps: &[Vec<usize>], from: usize) -> Result<Vec<u32>, OpenError> {
        let mut kinds = vec![KindCode::Store];
        kinds.extend(deps.iter().map(|_| KindCode::Secret));
        let mut of = |at: usize| {
            Ok(if at == 0 {
                vec![from + 1]
            } else {
                deps[at - 1].iter().map(|d| d + 1).collect()
            })
        };
        let plan = chains::plan_order(&kinds, &[], &mut of)?;
        Ok(plan
            .into_iter()
            .filter(|(_, phase)| matches!(phase, BootPhase::StoreSecrets))
            .map(|(i, _)| i - 1)
            .collect())
    }

    #[test]
    fn secret_dependencies_come_first_and_once() {
        let deps = vec![vec![1, 2], vec![2], vec![]];
        assert_eq!(walk(&deps, 0).unwrap(), vec![2, 1, 0]);
    }

    #[test]
    fn a_secret_cycle_refuses_config_naming_the_indices() {
        let deps = vec![vec![1], vec![0]];
        let err = walk(&deps, 0).unwrap_err();
        assert!(
            matches!(&err, OpenError::Config { text, .. } if text.contains("reference each other"))
        );
    }

    #[test]
    fn a_secret_chain_deeper_than_four_is_refused() {
        let deps = vec![vec![1], vec![2], vec![3], vec![4], vec![5], vec![]];
        assert!(matches!(walk(&deps, 0), Err(OpenError::Config { .. })));
        let four = vec![vec![1], vec![2], vec![3], vec![]];
        assert_eq!(walk(&four, 0).unwrap(), vec![3, 2, 1, 0]);
    }

    fn body(numbers: &[u16]) -> Vec<u8> {
        numbers.iter().flat_map(|n| n.to_le_bytes()).collect()
    }

    #[test]
    fn a_bad_d_errors_list_is_refused_with_template_text() {
        let ok = || Ok("acme");
        let b = body(&[7071, 7071]);
        let e = decode_errors(&[&b], ok).err().unwrap();
        assert_eq!(&*e.have, "7071 after 7071 at index 1");
        let b = body(&[10000]);
        assert_eq!(
            &*decode_errors(&[&b], ok).err().unwrap().have,
            "10000 at index 0"
        );
        let b = body(&[1]);
        assert_eq!(
            &*decode_errors(&[&b, &b], ok).err().unwrap().have,
            "2 D_ERRORS items"
        );
        assert_eq!(
            &*decode_errors(&[&b[..1]], ok).err().unwrap().have,
            "body 1 bytes"
        );
        assert!(matches!(decode_errors(&[], ok), Ok(ErrorBook::None)));
    }

    #[test]
    fn a_declared_number_resolves_and_an_undeclared_one_does_not() {
        let b = body(&[3, 7]);
        let book = decode_errors(&[&b], || Ok("acme-store")).ok().unwrap();
        let latch = AtomicBool::new(false);
        assert_eq!(
            book.resolve(7, &latch).unwrap().to_string(),
            "BUSBAR-acme-store-0007"
        );
        assert!(book.resolve(4, &latch).is_none());
        assert!(latch.load(Ordering::Relaxed));
        assert!(book.resolve(0, &latch).is_none());
    }

    #[test]
    fn a_former_name_may_not_shadow_an_admitted_plugin() {
        let admitted = [("a", vec!["old-a"])];
        let it = || admitted.iter().map(|(i, w)| (*i, w.iter().copied()));
        assert!(name_conflict(it(), "b", &["old-a"]).is_some());
        assert!(name_conflict(it(), "old-a", &[]).is_some());
        assert!(name_conflict(it(), "a", &[]).is_some());
        assert!(name_conflict(it(), "b", &["old-b"]).is_none());
    }

    #[test]
    fn slots_are_leased_quarantined_and_reused() {
        let table = Arc::new(SlotTable::new());
        let rec = || SlotRecord {
            kind: KindCode::Store,
            name: Arc::from("s"),
            scrub: Arc::new(Scrub::new()),
            errors: &ErrorBook::None,
            undeclared_warned: AtomicBool::new(false),
        };
        let row = [7u32; 64];
        let mut lease = table.alloc(rec(), &row);
        assert!(lease.is_live());
        let (slot, (us, epoch)) = (lease.slot(), table.watch_view(lease.slot(), 3));
        assert_eq!(us, 7);
        table.hung(slot, epoch, 3, 9);
        assert!(!lease.is_live());
        let inert = lease.take();
        drop(lease);
        assert_eq!(table.alloc(rec(), &row).slot(), slot + 1);
        drop(inert);
        assert_eq!(table.alloc(rec(), &row).slot(), slot);
    }
}

/// What `add` decodes from the kind's own describe items (validated: a bad item is `DescribeInvalid`), kept only
/// once the image is admitted.
struct KindItems {
    sugars: Vec<SugarDecl>,
    issued: Vec<(Box<str>, IssuedShape)>,
    dialect_auth: Vec<plane::DialectAuthOwned>,
}

fn decode_kind_items(
    described: &Described,
    describe: busbar_plugin_abi::records::Records<'_>,
    identity: &str,
) -> Result<KindItems, Refusal> {
    let bad = |field: &'static str, e: busbar_plugin_abi::records::RecErr| {
        Refusal::new(
            RefusalCode::DescribeInvalid,
            field,
            format!("{e:?}"),
            "the item grammar of the kind's describe",
        )
    };
    let mut out = KindItems {
        sugars: Vec::new(),
        issued: Vec::new(),
        dialect_auth: Vec::new(),
    };
    match described.kind {
        KindCode::Secret => {
            let who: Arc<str> = Arc::from(identity);
            out.sugars = busbar_ports::codec::secret::decode_sugars(describe)
                .map_err(|e| bad("describe.sugar", e))?
                .into_iter()
                .map(|mut sugar| {
                    sugar.identity = Arc::clone(&who);
                    sugar
                })
                .collect();
        }
        KindCode::Auth => {
            out.issued = busbar_ports::codec::auth::decode_issued_shape(describe)
                .map_err(|e| bad("describe.issued_shape", e))?
                .into_iter()
                .collect();
        }
        KindCode::Plane => {
            crate::adapters::plane::decode_describe(describe, described.methods, described.facts)
                .map_err(|e| {
                Refusal::new(
                    RefusalCode::DescribeInvalid,
                    e.0,
                    "a describe the plane rules refuse",
                    "the plane describe grammar",
                )
            })?;
            out.dialect_auth = plane::decode_dialect_auth(describe)
                .map_err(|e| bad("describe.dialect_auth", e))?
                .iter()
                .map(plane::DialectAuth::to_owned)
                .collect();
        }
        KindCode::Hook => {
            busbar_ports::codec::hook::decode_words(describe)
                .map_err(|e| bad("describe.word", e))?;
        }
        KindCode::Export => {
            busbar_ports::codec::export::decode_delivery(describe, described.methods)
                .map_err(|e| bad("describe.delivery", e))?;
        }
        KindCode::Store | KindCode::Transport => {}
    }
    Ok(out)
}

/// The slot table the process-wide sinks read: the first registry's (a process has one; a second registry, which
/// only tests build, shares the sinks and is not attributed).
static ACTIVE: OnceLock<Arc<SlotTable>> = OnceLock::new();

/// Once per process: the watch table, the entry fault sink (`driver::set_fault_sink`: quarantine the slot's
/// instance when the entry was an instance's, audit either way) and the log sink (`host_vt::set_log_sink`: every
/// plugin line attributed by the entry's slot and scrubbed with that slot's set, I14).
pub(crate) fn install_sinks(slots: &Arc<SlotTable>) -> Result<(), String> {
    if let Err(candidate) = ACTIVE.set(Arc::clone(slots)) {
        return if ACTIVE
            .get()
            .is_some_and(|active| Arc::ptr_eq(active, &candidate))
        {
            Ok(())
        } else {
            Err("process plugin sinks already belong to another slot table".into())
        };
    }
    busbar_plugin_abi::host_side::watch::init();
    busbar_plugin_abi::host_side::driver::set_fault_sink(|slot, image_owned, reason| {
        if let Some(table) = ACTIVE.get() {
            table.fault(slot, image_owned, reason);
        }
    });
    busbar_plugin_abi::host_side::host_vt::set_log_sink(log_sink);
    busbar_plugin_abi::host_side::host_vt::set_log_level(
        match tracing::level_filters::LevelFilter::current() {
            tracing::level_filters::LevelFilter::OFF => 0,
            tracing::level_filters::LevelFilter::ERROR => 1,
            tracing::level_filters::LevelFilter::WARN => 2,
            tracing::level_filters::LevelFilter::INFO => 3,
            tracing::level_filters::LevelFilter::DEBUG => 4,
            _ => 5,
        },
    );
    Ok(())
}

fn log_sink(slot: Option<u32>, level: u32, error: u32, msg: &str) {
    let Some(rec) = slot
        .zip(ACTIVE.get())
        .and_then(|(slot, table)| table.record(slot))
    else {
        return;
    };
    let shown = busbar_plugin_abi::host_side::scrub::fail_text(&rec.scrub, msg);
    let code = rec
        .errors
        .resolve(error, &rec.undeclared_warned)
        .map(|c| c.to_string());
    let (kind, instance, code) = (rec.kind as u32, &*rec.name, code.as_deref().unwrap_or(""));
    match level {
        1 => tracing::error!(kind, instance, code, "{shown}"),
        2 => tracing::warn!(kind, instance, code, "{shown}"),
        3 => tracing::info!(kind, instance, code, "{shown}"),
        4 => tracing::debug!(kind, instance, code, "{shown}"),
        _ => tracing::trace!(kind, instance, code, "{shown}"),
    }
}

/// The proxy of a kind refused an instance of another kind: a registry bug, never a plugin's.
fn not_this_kind() -> OpenError {
    OpenError::Call(CallError::Fault(
        busbar_plugin_abi::fail::FaultReason::BadInstance,
    ))
}

/// Every `{"$secret": n}` handle in a bound config.
fn secret_handles(v: &json::Value, out: &mut Vec<u32>) {
    match v.get_type() {
        json::JsonType::Object => {
            let Some(map) = v.as_object() else { return };
            if let Some(n) = map.get(&"$secret").and_then(json::Value::as_u64) {
                out.extend(u32::try_from(n));
            } else {
                map.iter().for_each(|(_, v)| secret_handles(v, out));
            }
        }
        json::JsonType::Array => {
            if let Some(items) = v.as_array() {
                items.iter().for_each(|v| secret_handles(v, out));
            }
        }
        _ => {}
    }
}

/// C-NEED-DECODE `bad_endpoint_records_are_invalid` (TRANSPORT-SECURITY-POLICY §8 test 10, IF §3 round 32; moved
/// here from busbar-plugin-test `c_need_decode`, whose case index points at this module): a CHECK answer's
/// ENDPOINT records decode in answer order; more than 16, a dest over 2,048 bytes or not UTF-8, an op other than
/// OPEN/FETCH, an egress class above LOOPBACK_ALLOWED, the retired bit 0x200 or any other stray bit is INVALID,
/// which refuses CONFIG naming the instance.
#[cfg(test)]
mod endpoint_decode_tests {
    use super::*;
    use busbar_plugin_abi::records::{Reply, Writer};

    const NAME: &str = "store-x";

    fn flags(tls: u32, class: u32) -> u32 {
        tls | (class << 16)
    }

    fn answer(endpoints: &[(u32, u32, &[u8])]) -> Reply {
        let mut out = Reply::new();
        out.put_text(tag::TEXT, "a record of another tag is not an endpoint")
            .expect("the test answer fits");
        for &(op, flags, dest) in endpoints {
            out.put_pod_tail(tag::ENDPOINT, &EndpointRec { op, flags }, dest)
                .expect("the test answer fits");
        }
        out
    }

    /// The CONFIG refusal's text for `endpoints`; anything else fails the test.
    fn invalid(endpoints: &[(u32, u32, &[u8])]) -> String {
        match decode_endpoints(answer(endpoints).as_bytes(), NAME) {
            Err(OpenError::Config { code, text, .. }) => {
                assert_eq!(code, refused::R_CONFIG, "{text}");
                assert!(
                    text.starts_with("store-x: the plugin declared an invalid ENDPOINT ("),
                    "the refusal names the instance: {text}"
                );
                text
            }
            other => panic!("an invalid ENDPOINT refuses CONFIG, got {other:?}"),
        }
    }

    #[test]
    fn bad_endpoint_records_are_invalid() {
        let db = flags(need_flag::TLS_REQUIRED, egress::OPERATOR_INFRASTRUCTURE);
        let collector = flags(need_flag::TLS_NONE, egress::LOOPBACK_ALLOWED);
        let decoded = decode_endpoints(
            answer(&[
                (op::OPEN, db, &b"db.internal:5432"[..]),
                (
                    op::FETCH,
                    collector,
                    &b"http://127.0.0.1:4318/v1/traces"[..],
                ),
            ])
            .as_bytes(),
            NAME,
        )
        .expect("two well-formed endpoints decode");
        assert_eq!(
            decoded,
            vec![
                DeclaredEndpoint {
                    op: op::OPEN,
                    flags: db,
                    dest: "db.internal:5432".into(),
                },
                DeclaredEndpoint {
                    op: op::FETCH,
                    flags: collector,
                    dest: "http://127.0.0.1:4318/v1/traces".into(),
                },
            ],
            "in answer order, as declared"
        );

        // Sixteen is the bound; the seventeenth is INVALID.
        let sixteen = [(op::OPEN, db, &b"h:1"[..]); 16];
        assert_eq!(
            decode_endpoints(answer(&sixteen).as_bytes(), NAME)
                .expect("sixteen endpoints decode")
                .len(),
            16
        );
        let seventeen = [(op::OPEN, db, &b"h:1"[..]); 17];
        assert!(invalid(&seventeen).contains("more than 16"));

        // 2,048 dest bytes is the bound; one more is INVALID, and so is a dest that is not UTF-8.
        let longest = [b'a'; 2_048];
        assert_eq!(
            decode_endpoints(answer(&[(op::OPEN, db, &longest[..])]).as_bytes(), NAME)
                .expect("a 2,048-byte dest decodes")
                .len(),
            1
        );
        let over = [b'a'; 2_049];
        assert!(invalid(&[(op::OPEN, db, &over[..])]).contains("dest over 2,048 bytes"));
        assert!(invalid(&[(op::OPEN, db, &b"\xff\xfe:1"[..])]).contains("dest not UTF-8"));

        // An op other than OPEN or FETCH.
        for unknown in [0, 2, 0xFF, u32::MAX] {
            assert!(
                invalid(&[(unknown, db, &b"h:1"[..])]).contains("(op)"),
                "op {unknown}"
            );
        }

        // An egress class above LOOPBACK_ALLOWED, the retired 0x200 and any other stray bit.
        for class in egress::LOOPBACK_ALLOWED + 1..=15 {
            let bad = flags(need_flag::TLS_REQUIRED, class);
            assert!(
                invalid(&[(op::OPEN, bad, &b"h:1"[..])]).contains("(flags)"),
                "class {class}"
            );
        }
        for stray in [0x200, 0x10, 1 << 20, 1 << 31] {
            assert!(
                invalid(&[(op::FETCH, db | stray, &b"https://h/"[..])]).contains("(flags)"),
                "bit {stray:#x}"
            );
        }
    }
}

#[cfg(test)]
#[path = "tests/transport_endpoint_tests.rs"]
mod transport_endpoint_tests;

#[cfg(test)]
mod needs_tests;
