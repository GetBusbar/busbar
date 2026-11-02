// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

#![cfg_attr(not(door_rig), allow(dead_code, unused_imports))]

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

pub(crate) use super::planes_tests::PUBLISHING;
pub(crate) use super::with_pools;
pub(crate) use crate::root::door_steps::Rules;
pub(crate) use crate::root::durability::Durability;
pub(crate) use crate::root::kernel::RootHistory;
pub(crate) use crate::root::loader::dispatch::LinkedRow;
pub(crate) use crate::root::loader::sign::NeedLevel;
pub(crate) use crate::root::plane_node::{Node, NodeEndPost};
pub(crate) use busbar_core_connector::tls::install_crypto_provider;
pub(crate) use busbar_core_connector::Connector;

#[cfg(linked_axis_plane_door)]
pub(super) use super::secret_source_tests::{
    assert_clean, missing, refused_naming_its_source, unset,
};

pub(crate) fn register_linked_protocols() {
    for decls in crate::LINKED.protocols {
        busbar_kernel_testkit::test_support::protocols::register_test_protocols(decls);
    }
}

pub(crate) fn door_breaker(statement_name: &str) -> Result<Option<BreakerDecl>, String> {
    crate::root::linked::door_breaker(&crate::LINKED, None, statement_name)
}

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

pub(crate) fn door_declaring(section: &str) -> Option<DoorFn> {
    crate::LINKED
        .plane_doors
        .iter()
        .copied()
        .find(|&door| declared_section(door, "door-rig-probe") == Some(section))
}

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

pub(crate) fn folded_door(
    door: DoorFn,
    instance: &str,
) -> Result<&'static busbar_kernel::plane_driver::registry::PlaneDecl, String> {
    use crate::root::loader::dispatch::kinds::plane::{linked_probe, registration};
    busbar_kernel::plane_driver::door::fold(registration(linked_probe(door, instance))?)
}

pub(crate) fn register_door(door: DoorFn, instance: &str) -> Result<(), String> {
    busbar_kernel_testkit::test_support::planes::register_test_plane(folded_door(door, instance)?);
    Ok(())
}

pub(crate) fn destination_guard(
    destinations: &busbar_kernel::config::Destinations,
) -> Result<Arc<dyn DestJudge>, String> {
    crate::root::connector::guard_for(destinations).map(|g| g as Arc<dyn DestJudge>)
}

pub(crate) fn install_io_reactor() {
    crate::root::connector::install_io_reactor();
}

pub(crate) fn install_root_auth() {
    busbar_kernel::preflight::install_linked_auth(
        crate::LINKED.auths,
        crate::root::auth_bindings::operator_words(),
    );
    busbar_kernel_testkit::test_support::install_root_auth_axis(crate::root::dispatch::auth_axis);
}

pub(crate) fn late_services(dest: Arc<dyn DestJudge>) -> Arc<LateServices> {
    let late = LateServices::new();
    let kernel = Arc::new(super::kernel_services(dest));
    late.install_kernel(Arc::clone(&kernel), kernel as Arc<dyn HostServices>)
        .expect("a fresh LateServices takes its first install");
    late
}

pub(crate) fn attach_late(late: &LateServices, gov: &Arc<GovState>) {
    super::attach(
        late,
        Some(gov),
        Some(Arc::clone(gov) as Arc<dyn SignKey>),
        &Arc::new(busbar_kernel::trust::DemotionRecord::default()),
        &[],
    );
}

pub(crate) fn dispatcher(workers: usize, late: &Arc<LateServices>) -> Arc<Dispatcher> {
    Arc::new(crate::root::dispatch::build(workers, late))
}

pub(crate) struct ProcessRig {
    dest: Arc<dyn DestJudge>,
    wake: ConnWake,
    settings: TransportSettings,
    anchors: Vec<Vec<u8>>,
}

impl ProcessRig {
    pub(crate) fn new(dest: Arc<dyn DestJudge>, wake: ConnWake) -> Self {
        Self {
            dest,
            wake,
            settings: TransportSettings::default(),
            anchors: Vec::new(),
        }
    }

    #[must_use]
    pub(crate) fn trusting(mut self, der: Vec<u8>) -> Self {
        self.anchors.push(der);
        self
    }

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

pub(crate) struct DoorStore {
    opened: busbar_contract::store_calls::OpenedStore,

    _axis: crate::root::loader::store_v3::DoorStoreAxis,
}

impl DoorStore {
    pub(crate) fn records(&self) -> Arc<dyn busbar_contract::records::RecordStore> {
        Arc::clone(&self.opened.records)
    }

    pub(crate) fn calls(&self) -> Option<Arc<dyn busbar_contract::store_calls::StoreCalls>> {
        self.opened.calls.clone()
    }
}

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

pub(crate) struct EgressRig {
    providers: BTreeMap<String, ProviderRoute>,
    secrets: Arc<dyn SecretResolve>,
    auths: Arc<OutboundAuths>,
    conns: Arc<dyn PollConns>,
    stream_ceiling_secs: u64,
    journal: Arc<dyn Journal>,
}

impl EgressRig {
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
                busbar_kernel::diagnostics::Catalogue::NEUTRAL,
            )),
            conns,
            stream_ceiling_secs: 600,
            journal,
        }
    }

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
    tables: Option<&'a busbar_kernel::plane_driver::serve::ServeTables>,
}

impl<'a> DoorCompose<'a> {
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
            tables: None,
        }
    }

    #[must_use]
    pub(crate) fn tables(
        mut self,
        tables: &'a busbar_kernel::plane_driver::serve::ServeTables,
    ) -> Self {
        self.tables = Some(tables);
        self
    }

    #[must_use]
    pub(crate) fn public_url(mut self, url: &'a str) -> Self {
        self.public_url = Some(url);
        self
    }

    #[must_use]
    pub(crate) fn egress(mut self, egress: &'a EgressRig) -> Self {
        self.egress = Some(egress);
        self
    }

    #[must_use]
    pub(crate) fn hooks(mut self, host: GenerationHost, gov: Arc<GovState>) -> Self {
        self.hooks = Some(HookStage {
            host,
            gov,
            journal: None,
        });
        self
    }

    #[must_use]
    pub(crate) fn post(mut self, post: Arc<NodeEndPost>) -> Self {
        self.post = Some(post);
        self
    }

    #[must_use]
    pub(crate) fn framers(mut self, connector: Arc<Connector>) -> Self {
        self.framers = Some(connector);
        self
    }

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
        let own = busbar_kernel::plane_driver::serve::ServeTables::default();
        super::compose_planes(
            &self.doors,
            self.dispatcher,
            self.late,
            self.sections,
            self.public_url,
            self.money,
            egress,
            self.hooks.as_ref(),
            self.tables.unwrap_or(&own),
        )
    }
}

pub(crate) fn door_routes(
    served: Served,
    pin: fn() -> Option<PinnedHistory>,
) -> Result<Vec<busbar_kernel::plane_routes::PlaneRouteSpec>, String> {
    super::door_routes(served, pin, &[], &[])
}

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

pub(crate) fn node_book() -> NodeBook {
    crate::root::durability::node_book()
}

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

pub(crate) fn hook_env(
    aliases: &[&str],
    prompt: NeedLevel,
    user: NeedLevel,
) -> busbar_kernel::hooks::HookEnv {
    busbar_kernel_testkit::test_support::test_hook_env(
        aliases,
        busbar_kernel_testkit::test_support::HookNeeds { prompt, user },
    )
}

pub(crate) fn refresh_credentials() {
    crate::root::door_steps::refresh_credentials();
}
