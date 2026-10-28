// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE DOOR CELLS' RIG: the ONE surface a door plane's own root cells (each plane crate's
//! `tests/root/mod.rs`, compiled here through `$OUT_DIR/door_cells.rs`; ARCHITECT ruling on #464)
//! reach the composition root through. A plane's cells are pinned in another repository, so a root
//! refactor that changes a struct's fields, a builder's arguments or an installer's path would
//! break them at the pin; every such shape is held here instead, behind a signature that does not
//! move when the root's internals do:
//!
//! * no struct literal of a root type: the door's egress is an [`EgressRig`] (its reach and journal,
//!   the rest defaulted), its composition a [`DoorCompose`], the store it records to
//!   a [`DoorStore`], its process connector a [`ProcessRig`];
//! * no installer by its path: [`install_root_auth`] hands the kernel the root's auth rows and its
//!   auth-axis opener by whichever install path the kernel has;
//! * no positional argument list of a root builder: each builder's defaults are the root's.
//!
//! A cell names the root through this module alone (`super::door_rig`), and the kernel's and the
//! contract's own public surfaces directly. What a cell needs and this rig does not offer is added
//! HERE, never reached for past it.
//!
//! The rig compiles iff an enabled door's cells name it (`build.rs` sets `door_rig`), and it
//! carries no allow: an item no compiled cell calls is dead code and refused, so the surface is
//! exactly what the cells use.

use std::collections::BTreeMap;
use std::sync::Arc;

use busbar_contract::abi::mechanism::door::DoorFn;
use busbar_contract::conn::{ConnWake, DeclaredConns, PollConns};
use busbar_contract::secret::SecretResolve;
use busbar_contract::services::HostServices;
use busbar_contract::transport::TransportSettings;
use busbar_kernel::governance::GovState;
use busbar_kernel::host_services::{DestJudge, SignKey};
use busbar_kernel::plane_driver::{GenerationHost, PlaneMoney};
use busbar_kernel_egress::ports::Journal;

use super::{DoorEgress, HookStage, LateServices, Served, StreamFramers};
use crate::root::boot::DoorPlane;
use crate::root::door_steps::{DoorReach, OutboundAuths, ProviderRoute};
use crate::root::durability::NodeBook;
use crate::root::kernel::PinnedHistory;
use crate::root::loader::dispatch::kinds::plane::Plane;
use crate::root::loader::dispatch::{
    load_linked, Bind, ConnTable, DispatchConfig, Dispatcher, NoSink,
};
use crate::root::loader::sign::BreakerDecl;

pub(crate) use super::planes_tests::{Published, PUBLISHING};
pub(crate) use super::with_pools;
pub(crate) use crate::root::door_steps::Rules;
pub(crate) use crate::root::durability::{Durability, UnitCounts};
pub(crate) use crate::root::kernel::RootHistory;
pub(crate) use crate::root::loader::dispatch::LinkedRow;
pub(crate) use crate::root::loader::sign::NeedLevel;
pub(crate) use crate::root::plane_node::{Node, NodeEndPost};
pub(crate) use busbar_core_connector::tls::install_crypto_provider;
pub(crate) use busbar_core_connector::Connector;

/// The root's secret-source scan helpers, for the cells that drive a door's secret source.
#[cfg(linked_axis_plane_door)]
pub(super) use super::secret_source_tests::{
    assert_clean, missing, refused_naming_its_source, unset,
};

// ── THE LINKED TABLE ─────────────────────────────────────────────────────────────────────────────

/// Every linked protocol declaration registered on the kernel's test protocol set, as the root's
/// config-fixture cells install it.
pub(crate) fn register_linked_protocols() {
    for decls in crate::LINKED.protocols {
        busbar_kernel::test_support::protocols::register_test_protocols(decls);
    }
}

/// The breaker fact a linked plane door's `declares` section states, read by its Statement name
/// as the root reads it.
///
/// # Errors
///
/// Its declares section does not read.
pub(crate) fn door_breaker(statement_name: &str) -> Result<Option<BreakerDecl>, String> {
    crate::root::linked::door_breaker(&crate::LINKED, None, statement_name)
}

// ── THE DOOR, BOUND ──────────────────────────────────────────────────────────────────────────────

/// The section `door` declares, read by binding it once as a probe (nothing opened to the network)
/// under `instance`; `None` when it will not bind.
fn declared_section(door: DoorFn, instance: &str) -> Option<&'static str> {
    let dispatcher = Dispatcher::new(DispatchConfig::default());
    let row = LinkedRow::of(door).ok()?;
    let plane = load_linked::<Plane>(
        &row,
        Bind {
            instance: Arc::from(instance),
            max_inflight_cap: 64,
            sink: Arc::new(NoSink),
            dispatcher: dispatcher.adopter(),
            conns: ConnTable::Probe,
        },
    )
    .ok()?;
    Some(plane.served().section)
}

/// Of the linked plane doors, the one that declares `section` ([`declared_section`]).
pub(crate) fn door_declaring(section: &str) -> Option<DoorFn> {
    crate::LINKED
        .plane_doors
        .iter()
        .copied()
        .find(|&door| declared_section(door, "door-rig-probe") == Some(section))
}

/// `door`, bound through the loader's one load to SERVE under `instance` on `dispatcher`, its
/// needs declared on `conns` (the process's connection table).
///
/// # Errors
///
/// The door does not state its Statement, or will not bind.
pub(crate) fn bind_door(
    door: DoorFn,
    instance: &str,
    dispatcher: &Dispatcher,
    conns: Arc<dyn DeclaredConns>,
) -> Result<DoorPlane, String> {
    let row = LinkedRow::of(door).map_err(|e| e.to_string())?;
    load_linked::<Plane>(
        &row,
        Bind {
            instance: Arc::from(instance),
            max_inflight_cap: 64,
            sink: Arc::new(NoSink),
            dispatcher: dispatcher.adopter(),
            conns: ConnTable::Host(conns),
        },
    )
    .map(Arc::new)
    .map_err(|e| e.to_string())
}

/// `door`'s registry row, folded from its Statement as the composition root folds it
/// (DECL-FOLD), its probe bound under `instance`.
///
/// # Errors
///
/// The door does not bind, or its registration does not fold.
pub(crate) fn folded_door(
    door: DoorFn,
    instance: &str,
) -> Result<&'static busbar_kernel::plane_driver::registry::PlaneDecl, String> {
    use crate::root::loader::dispatch::kinds::plane::{linked_probe, registration};
    busbar_kernel::plane_driver::door::fold(registration(linked_probe(door, instance))?)
}

/// [`folded_door`], registered on the kernel's test registry as the composition root installs it.
///
/// # Errors
///
/// As [`folded_door`].
pub(crate) fn register_door(door: DoorFn, instance: &str) -> Result<(), String> {
    busbar_kernel::test_support::planes::register_test_plane(folded_door(door, instance)?);
    Ok(())
}

// ── THE PROCESS ──────────────────────────────────────────────────────────────────────────────────

/// The deployment's one destination guard over `destinations`, as boot builds it.
///
/// # Errors
///
/// An `allow_destinations` entry the guard refuses.
pub(crate) fn destination_guard(
    destinations: &busbar_kernel::config::Destinations,
) -> Result<Arc<dyn DestJudge>, String> {
    crate::root::connector::guard_for(destinations).map(|g| g as Arc<dyn DestJudge>)
}

/// The process's I/O reactor, installed as boot installs it.
pub(crate) fn install_io_reactor() {
    crate::root::connector::install_io_reactor();
}

/// THE ROOT'S AUTH, HANDED TO THE KERNEL: the linked auth rows with the operator credential's
/// words, and the root's auth-axis opener, each by the install path the kernel has.
pub(crate) fn install_root_auth() {
    busbar_kernel::preflight::install_linked_auth(
        crate::LINKED.auths,
        crate::root::auth_bindings::operator_words(),
    );
    busbar_kernel::test_support::install_root_auth_axis(crate::root::dispatch::auth_axis);
}

/// The kernel's host services judging every destination by `dest`, installed into a fresh
/// [`LateServices`] as boot composes them.
pub(crate) fn late_services(dest: Arc<dyn DestJudge>) -> Arc<LateServices> {
    let late = LateServices::new();
    let kernel = Arc::new(super::kernel_services(dest));
    late.install_kernel(Arc::clone(&kernel), kernel as Arc<dyn HostServices>)
        .expect("a fresh LateServices takes its first install");
    late
}

/// THE LATE ATTACH, as the first app build runs it: the runtime's blocking pool, and `gov` as the
/// record store and the signer. Runs on the runtime.
pub(crate) fn attach_late(late: &LateServices, gov: &Arc<GovState>) {
    super::attach(
        late,
        Some(gov),
        Some(Arc::clone(gov) as Arc<dyn SignKey>),
        &Arc::new(busbar_kernel::trust::DemotionRecord::default()),
        &[],
    );
}

/// The process's dispatcher over `late`, `workers` wide, as boot builds it.
pub(crate) fn dispatcher(workers: usize, late: &Arc<LateServices>) -> Arc<Dispatcher> {
    Arc::new(crate::root::dispatch::build(
        workers,
        Arc::clone(late) as Arc<dyn HostServices>,
    ))
}

/// THE PROCESS'S CONNECTOR, as boot builds it: every linked transport door a framer entry, every
/// dial judged by the destination guard, a plugin's ticket woken through the dispatcher. With an
/// anchor added ([`ProcessRig::trusting`]), its connections trust that root beside the public
/// roots. Whatever else boot hands the connector it builds, the rig hands it too.
pub(crate) struct ProcessRig {
    dest: Arc<dyn DestJudge>,
    wake: ConnWake,
    settings: TransportSettings,
    anchors: Vec<Vec<u8>>,
}

impl ProcessRig {
    /// The connector judging every dial by `dest` and waking through `wake`, the default
    /// transport settings, the public roots alone.
    pub(crate) fn new(dest: Arc<dyn DestJudge>, wake: ConnWake) -> Self {
        Self {
            dest,
            wake,
            settings: TransportSettings::default(),
            anchors: Vec::new(),
        }
    }

    /// One more trust anchor (a root certificate's DER) its connections trust.
    #[must_use]
    pub(crate) fn trusting(mut self, der: Vec<u8>) -> Self {
        self.anchors.push(der);
        self
    }

    /// The connector.
    ///
    /// # Errors
    ///
    /// Its connection security will not build, or its transport entries refuse.
    pub(crate) fn build(self) -> Result<Arc<Connector>, String> {
        let Self {
            dest,
            wake,
            settings,
            anchors,
        } = self;
        let entries = || crate::root::connector::entries(crate::LINKED_TRANSPORT_DOORS, &settings);
        if anchors.is_empty() {
            return busbar_core_connector::process::build_with_secrets(
                entries,
                dest,
                &[],
                wake,
                crate::root::connector::pool_posture(&settings),
                busbar_kernel::config::secret::resolve_linked_string_at_config,
            );
        }
        let tls = busbar_core_connector::tls::client::build_client_config(
            &busbar_contract::transport::trust::EgressTrust {
                extra_anchors: anchors,
                ..Default::default()
            },
        )
        .map_err(|e| format!("its connection security: {e}"))?;
        let view = busbar_core_connector::registry::Transports::new(entries()?)
            .map_err(|e| e.to_string())?;
        Ok(Arc::new(Connector::serving(
            view,
            busbar_core_connector::process::judge(dest, &[]),
            Some(Arc::new(tls)),
            wake,
        )))
    }
}

// ── THE BOOK AND THE STORE ───────────────────────────────────────────────────────────────────────

/// A dated card history with no price: one entry, billing off, applied at `now_ms`.
pub(crate) fn unpriced_card(now_ms: u64) -> RootHistory {
    let holder = RootHistory::default();
    holder.apply(
        crate::root::kernel::card_from_config(
            std::iter::empty::<(&str, busbar_contract::billing::RawTierRates)>(),
            0,
            true,
        ),
        now_ms,
    );
    holder
}

/// The node's book, its units priced against the history `pin` answers.
pub(crate) fn node_book(pin: fn() -> Option<PinnedHistory>) -> NodeBook {
    crate::root::durability::node_book_over(Box::new(pin))
}

/// A store opened through a linked store door, as the governance book's store is opened: its
/// records and its record slots are the kernel's record store (ARCHITECT Q-L3B-RECORDS).
pub(crate) struct DoorStore {
    opened: busbar_contract::store_calls::OpenedStore,
    /// The axis it was opened on, held while the store is.
    _axis: crate::root::loader::store_v3::DoorStoreAxis,
}

impl DoorStore {
    /// Its typed records.
    pub(crate) fn records(&self) -> Arc<dyn busbar_contract::records::RecordStore> {
        Arc::clone(&self.opened.records)
    }

    /// Its record slots (`None` for a store reached by no door).
    pub(crate) fn calls(&self) -> Option<Arc<dyn busbar_contract::store_calls::StoreCalls>> {
        self.opened.calls.clone()
    }
}

/// The build's ephemeral linked store, opened through its door under `instance` with no settings.
///
/// # Errors
///
/// The build links no ephemeral store, or it will not open.
pub(crate) fn open_ephemeral_store(instance: &str) -> Result<DoorStore, String> {
    let axis = crate::root::loader::store_v3::DoorStoreAxis {
        dispatcher: Arc::new(Dispatcher::new(DispatchConfig::default())),
        logs: crate::root::boot::plugin_logs().clone(),
        conns: ConnTable::NoNeeds,
        mint: busbar_kernel::door::op_id,
    };
    let door = crate::LINKED
        .stores
        .iter()
        .find(|s| s.1)
        .ok_or_else(|| "the build links no ephemeral store".to_string())?
        .2;
    let opened = busbar_contract::store_calls::StoreAxis::open(
        &axis,
        busbar_contract::store_calls::StoreDoor::Linked(door),
        instance,
        b"{}",
    )?;
    Ok(DoorStore {
        opened,
        _axis: axis,
    })
}

// ── THE DOOR'S EGRESS AND ITS COMPOSITION ────────────────────────────────────────────────────────

/// WHAT A DOOR PLANE'S EGRESS IS SEALED OVER, as production seals it: no provider (a member is
/// reached at its own address), the builtin secret sources, the linked outbound auths over the
/// process's connection table, the walk's connections and the node's journal. Every part not
/// handed to [`EgressRig::new`] is defaulted.
pub(crate) struct EgressRig {
    providers: BTreeMap<String, ProviderRoute>,
    secrets: Arc<dyn SecretResolve>,
    auths: Arc<OutboundAuths>,
    conns: Arc<dyn PollConns>,
    stream_ceiling_secs: u64,
    journal: Arc<dyn Journal>,
}

impl EgressRig {
    /// The egress whose outbound auths run on `dispatcher` over `table` (the process's connection
    /// table), whose walk reaches its far ends through `conns` and journals to `journal`.
    pub(crate) fn new(
        dispatcher: &Arc<Dispatcher>,
        table: Arc<dyn DeclaredConns>,
        conns: Arc<dyn PollConns>,
        journal: Arc<dyn Journal>,
    ) -> Self {
        Self {
            providers: BTreeMap::new(),
            secrets: Arc::new(busbar_kernel::config::secret::SecretResolver::builtins_only()),
            auths: Arc::new(OutboundAuths::new(
                Arc::clone(dispatcher),
                crate::LINKED.auths,
                None,
                ConnTable::Host(table),
            )),
            conns,
            stream_ceiling_secs: 600,
            journal,
        }
    }

    /// `f` over the root's [`DoorEgress`] sealed over this rig.
    fn sealed<R>(&self, f: impl FnOnce(&DoorEgress<'_>) -> R) -> R {
        let reach = DoorReach {
            providers: &self.providers,
            secrets: Arc::clone(&self.secrets),
            auths: Arc::clone(&self.auths),
            conns: Arc::clone(&self.conns),
            stream_ceiling_secs: self.stream_ceiling_secs,
            catalog: None,
            models: None,
            upgrades: Vec::new(),
        };
        f(&DoorEgress {
            reach: &reach,
            journal: Arc::clone(&self.journal),
        })
    }
}

/// THE DOOR PLANES' COMPOSITION, as boot composes them ([`super::compose_planes`]): `doors` on
/// `dispatcher` over `late`, opened with `sections`, their money steps from `money`; with no
/// egress (every walk exhausted at once), no hook stage, no public URL, the root's own posting site
/// and the process connector's framers unless each is given.
pub(crate) struct DoorCompose<'a> {
    doors: Vec<(String, DoorPlane)>,
    dispatcher: &'a Arc<Dispatcher>,
    late: &'a LateServices,
    sections: &'a BTreeMap<&'static str, serde_yaml::Value>,
    money: &'a dyn Fn() -> Arc<PlaneMoney>,
    public_url: Option<&'a str>,
    egress: Option<&'a EgressRig>,
    hooks: Option<HookStage>,
    post: Option<Arc<NodeEndPost>>,
    framers: Option<Arc<Connector>>,
}

impl<'a> DoorCompose<'a> {
    /// The composition of `doors` (each under its instance label).
    pub(crate) fn new(
        doors: Vec<(String, DoorPlane)>,
        dispatcher: &'a Arc<Dispatcher>,
        late: &'a LateServices,
        sections: &'a BTreeMap<&'static str, serde_yaml::Value>,
        money: &'a dyn Fn() -> Arc<PlaneMoney>,
    ) -> Self {
        Self {
            doors,
            dispatcher,
            late,
            sections,
            money,
            public_url: None,
            egress: None,
            hooks: None,
            post: None,
            framers: None,
        }
    }

    /// The deployment's public base URL.
    #[must_use]
    pub(crate) fn public_url(mut self, url: &'a str) -> Self {
        self.public_url = Some(url);
        self
    }

    /// Each plane's egress, sealed over `egress`.
    #[must_use]
    pub(crate) fn egress(mut self, egress: &'a EgressRig) -> Self {
        self.egress = Some(egress);
        self
    }

    /// THE KERNEL'S HOOK STAGE: each unit binds its hooks over the generation `host` answers, a
    /// verified principal's key read from `gov`.
    #[must_use]
    pub(crate) fn hooks(mut self, host: GenerationHost, gov: Arc<GovState>) -> Self {
        self.hooks = Some(HookStage {
            host,
            gov,
            journal: None,
        });
        self
    }

    /// The posting site the planes' money steps post an abandoned end to.
    #[must_use]
    pub(crate) fn post(mut self, post: Arc<NodeEndPost>) -> Self {
        self.post = Some(post);
        self
    }

    /// The framers that frame a claim's stream another framer answers: `connector`'s.
    #[must_use]
    pub(crate) fn framers(mut self, connector: Arc<Connector>) -> Self {
        self.framers = Some(connector);
        self
    }

    /// The composed planes.
    ///
    /// # Errors
    ///
    /// A plane that will not open, publish, be admitted or seal its members' routes, named.
    pub(crate) fn compose(self) -> Result<Served, String> {
        let mut served = match self.egress {
            Some(rig) => rig.sealed(|egress| self.composed(Some(egress))),
            None => self.composed(None),
        }?;
        if let Some(post) = self.post {
            served.post = Some(post);
        }
        if let Some(connector) = self.framers {
            served.framers = Some(StreamFramers(Arc::new(move |claim: &str| {
                connector.framer_for(claim)
            })));
        }
        Ok(served)
    }

    fn composed(&self, egress: Option<&DoorEgress<'_>>) -> Result<Served, String> {
        super::compose_planes(
            &self.doors,
            self.dispatcher,
            self.late,
            self.sections,
            self.public_url,
            self.money,
            egress,
            self.hooks.as_ref(),
        )
    }
}

/// THE DOORS' DATA ROUTES, as the data router's construction mounts them: every claim of every
/// served plane, pinned to the card `pin` answers, with no data chain and no kernel routes beside.
///
/// # Errors
///
/// A claim the data listener cannot mount, or two claims at an equal precedence.
pub(crate) fn door_routes(
    served: Served,
    pin: fn() -> Option<PinnedHistory>,
) -> Result<Vec<busbar_kernel::plane_routes::PlaneRouteSpec>, String> {
    super::door_routes(served, pin, &[], &[])
}

/// THE DOORS' FACING, as boot's dispatch build reads it off each served plane: its claims' literal
/// prefixes, and the audience and metadata document its snapshot states (a plane stating neither
/// faces nothing).
pub(crate) fn admissions(
    served: &Served,
) -> Vec<(
    Vec<String>,
    busbar_kernel::plane_driver::dispatch::PlaneAdmission,
)> {
    served
        .planes
        .iter()
        .filter_map(|p| {
            let admission = busbar_kernel::plane_driver::dispatch::PlaneAdmission {
                audience: p.snapshot.audience.clone()?,
                resource_metadata: p.snapshot.resource_metadata.clone()?,
            };
            let paths = p
                .snapshot
                .claims
                .iter()
                .map(|c| {
                    let literal = c.target.split("/{").next().unwrap_or(&c.target);
                    literal.trim_end_matches('/').to_string()
                })
                .filter(|path| !path.is_empty())
                .collect();
            Some((paths, admission))
        })
        .collect()
}

/// THE NODE'S ADMIN SURFACE over `admin`, as boot mounts it: the generic verbs over `book` and the
/// kernel's services in `late`, the default breaker policy.
pub(crate) fn mount_node_admin(
    admin: axum::Router,
    request_body_max_bytes: usize,
    handle: &Arc<busbar_kernel::state::AppHandle>,
    book: &NodeBook,
    late: &Arc<LateServices>,
) -> axum::Router {
    crate::root::units_admin::mount_node(
        admin,
        request_body_max_bytes,
        handle,
        book,
        None,
        late,
        crate::root::adapters::BreakerPolicy::new(),
    )
}

// ── HOOKS AND CREDENTIALS ────────────────────────────────────────────────────────────────────────

/// The kernel's hook double behind `aliases`, its row stating the manifest needs `prompt` and
/// `user`.
pub(crate) fn hook_env(
    aliases: &[&str],
    prompt: NeedLevel,
    user: NeedLevel,
) -> busbar_kernel::hooks::HookEnv {
    busbar_kernel::test_support::test_hook_env(
        aliases,
        crate::root::loader::sign::HookNeeds { prompt, user },
    )
}

/// Every served credential refreshed now. Blocking: run it off the runtime's workers.
pub(crate) fn refresh_credentials() {
    crate::root::door_steps::refresh_credentials();
}
