// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use std::sync::{Arc, Mutex};

use busbar_contract::abi::mechanism::route::RouteMethod;
use busbar_contract::services::Caller;
use busbar_kernel::host_records::QUEUE_CAP;
use busbar_kernel::host_services::{BlockingPool, DestJudge, KernelServices, SignKey};
use busbar_kernel::limits::process_admission::RequestLease;
use busbar_kernel::plane_routes::PlaneReqCtx;

// The composition this module's request path serves: built off the request path.
pub(crate) use crate::root::off_path::serve::*;

#[path = "native_nests.rs"]
pub(crate) mod native_nests;

/// The serving generation's kernel services: the core store, the blocking pool, the signer and
/// ticket press over governance, the destination judge, the credentials and the disk lane.
pub(crate) fn compose(
    dest: Arc<dyn DestJudge>,
    app: &busbar_kernel::state::App,
    core: Arc<busbar_kernel::persistence::facade::CoreStore>,
) -> Arc<Services> {
    let signer = app.governance.clone().map(|gov| gov as Arc<dyn SignKey>);
    let tickets = app.governance.as_ref().map(|governance| {
        Arc::new(GenerationTickets {
            governance: Arc::clone(governance),
            block_max_ttl_secs: app.mint_policy.block_max_ttl_secs,
        }) as Arc<dyn busbar_kernel::host_services::TicketPress>
    });
    let kernel = KernelServices::from_inputs(busbar_kernel::host_services::CoreServicesInputs {
        persistence: core,
        pool: Arc::new(BlockingPool::new(
            tokio::runtime::Handle::current(),
            QUEUE_CAP,
        )),
        signer,
        demotions: Arc::clone(&app.demotion_record),
        demotion_owner: None,
        tickets,
        standing: busbar_kernel::plane_driver::policy_standing(
            app.governance.clone(),
            app.role_bindings.clone(),
        ),
        judge: dest,
        credentials: Arc::new(crate::root::credentials::AppCredentials::new(
            app.governance.clone(),
        )),
        disk: crate::root::linked::disk_lane(),
    })
    .with_mono_clock(Arc::new(busbar_kernel::store::monotonic_ns));
    Services::serving(Arc::new(kernel))
}

/// Mint authority retained by the serving generation that admitted the unit.
pub(crate) struct GenerationTickets {
    pub(crate) governance: Arc<busbar_kernel::governance::GovState>,
    pub(crate) block_max_ttl_secs: Option<u64>,
}

#[async_trait::async_trait]
impl busbar_kernel::host_services::TicketPress for GenerationTickets {
    /// A unit-bound ticket was held in the door planes' ticket custody, which only a door unit
    /// registered a source in. No unit registers one on the new interface, so none is kept.
    async fn mint_for_unit(
        &self,
        _unit: u64,
        _caller: &Caller,
        _principal: &Arc<busbar_contract::records::VirtualKey>,
        _prefix: &str,
        _ttl_secs: u64,
        _record: &[u8],
        _now: u64,
    ) -> Result<(String, u64), busbar_kernel::governance::TicketRefusal> {
        Err(busbar_kernel::governance::TicketRefusal::NotKept)
    }

    async fn mint(
        &self,
        key_id: &str,
        prefix: &str,
        ttl_secs: u64,
        record: &[u8],
        now: u64,
    ) -> Result<(String, u64), busbar_kernel::governance::TicketRefusal> {
        let gov = &self.governance;
        gov.mint_ticket(
            key_id,
            prefix,
            ttl_secs,
            self.block_max_ttl_secs,
            record,
            now,
        )
        .await
    }
}

pub(crate) const RECORD_DRAIN: std::time::Duration =
    std::time::Duration::from_secs(5 * busbar_kernel::host_records::FLUSH_INTERVAL.as_secs());

pub(crate) async fn drain_records(late: &Services, deadline: std::time::Duration) -> bool {
    let Some(kernel) = late.kernel() else {
        return true;
    };
    tokio::task::spawn_blocking(move || kernel.drain(deadline))
        .await
        .unwrap_or(false)
}

/// The serving generation's fully constructed kernel services.
pub(crate) struct Services {
    kernel: Option<Arc<KernelServices>>,
}

impl Services {
    pub(crate) fn serving(kernel: Arc<KernelServices>) -> Arc<Self> {
        Arc::new(Self {
            kernel: Some(kernel),
        })
    }

    /// No serving kernel: a test drain with no records to flush.
    #[cfg(test)]
    pub(crate) fn idle() -> Arc<Self> {
        Arc::new(Self { kernel: None })
    }

    pub(crate) fn kernel(&self) -> Option<Arc<KernelServices>> {
        self.kernel.clone()
    }

    /// Prepare the flush loop under the same lifecycle owner as the generation's other workers.
    pub(crate) fn prepare_workers(&self, workers: &mut super::boot::workers::PreparedWorkers) {
        if let Some(kernel) = self.kernel() {
            workers.push(async move { kernel.flushes().await });
        }
    }
}

/// THE ONE TRUST BINDING (TRUST-ADMIN-PRODUCER-DESIGN r3 §2.2): the serving kernel twice, as the
/// admin governance's decide-capable handle and as the read-only handle the `AppHandle` carries.
/// Bootstrap services have neither.
pub(crate) fn admin_trust(
    services: &Services,
) -> (
    Option<Arc<KernelServices>>,
    Option<busbar_kernel::trust::TrustReadout>,
) {
    let kernel = services.kernel();
    let readout = kernel.clone().map(busbar_kernel::trust::TrustReadout::over);
    (kernel, readout)
}

/// EVERY PLANE INSTANCE THIS PROCESS SERVES, composed once after the first app is built.
#[derive(Debug, Default, Clone)]
pub(crate) struct Served {
    /// The MIN-3 plane instances served through their ports (`PortDriver`), in the order they were opened.
    pub(crate) ports: Vec<busbar_kernel::plane_driver::port::PortSeat>,
    /// Complete native instance ownership of this serving generation.
    pub(crate) native: Option<Arc<crate::root::min3_boot::Booted>>,
    /// Retain the actual opened fixture and its invocation admission for the serving lifetime.
    #[cfg(test)]
    pub(crate) native_fixture: Option<Arc<crate::root::min3_boot::fixture::PlaneFixture>>,
    /// What bills the requests those ports serve (their unit admission and settlement); `None` = no governance
    /// book, so a port request is not a billed unit (audit rows only).
    pub(crate) billing: Option<busbar_kernel::plane_driver::port_billing::PortBilling>,
    /// The posting site the ports' money steps post an abandoned end to, and the units' facts are
    /// opened on while they run: the process's one node's.
    pub(crate) post: Option<Arc<crate::root::plane_node::NodeEndPost>>,
}

pub(crate) struct DataRoutes {
    pub(crate) snapshot: Arc<DispatchSnapshot>,
    pub(crate) generation: Option<Arc<busbar_kernel::host_services::ServingGeneration>>,
}

impl std::ops::Deref for DataRoutes {
    type Target = DispatchSnapshot;
    fn deref(&self) -> &Self::Target {
        &self.snapshot
    }
}

impl DataRoutes {
    /// Register the allocated native unit against this selected immutable dispatch snapshot.
    /// Monetary/effect authority remains pending until the retained task resolves its actual pool.
    pub(crate) fn native_unit(
        self: &Arc<Self>,
        seat: &busbar_kernel::plane_driver::port::PortSeat,
        unit: &mut busbar_kernel::plane_driver::port::Unit,
        ctx: &PlaneReqCtx,
    ) -> Result<NativeUnit, &'static str> {
        let generation = self
            .generation
            .as_ref()
            .ok_or("native route has no complete generation")?;
        unit.ctx.generation = generation
            .routing_generation()
            .ok_or("native route has no allocated routing generation")?;
        if Arc::clone(&ctx.engine)
            .downcast::<busbar_kernel::state::App>()
            .is_err()
        {
            return Err("native invocation needs its selected App snapshot");
        }
        let key = ctx
            .gov
            .as_ref()
            .and_then(|gov| gov.key.clone())
            .ok_or("native billed invocation has no verified key")?;
        if !Arc::ptr_eq(generation.core(), seat.driver.core()) {
            return Err("native invocation belongs to another core services owner");
        }
        let id = unit.ctx.key.get();
        if self.frames_lock().contains_key(&id) || generation.core().units().get(id).is_some() {
            return Err("native unit is already registered");
        }
        let registered = match &ctx.signed_authority {
            Some(authority) => {
                if !Arc::ptr_eq(&key, authority.original_key()) {
                    return Err("native signed allocation has a different original key");
                }
                generation.core().units().pre_admitted_signed_for(
                    id,
                    seat.driver.caller(),
                    authority.clone(),
                    0,
                )
            }
            None => generation.core().units().pre_admitted_for(
                id,
                seat.driver.caller(),
                busbar_kernel::host_units::UnitRecord {
                    principal: Some(key),
                    depth: 0,
                },
            ),
        };
        if !registered {
            return Err("native allocation could not be registered");
        }
        let context = match seat.driver.invocation(Arc::clone(generation), id) {
            Ok(context) => context,
            Err(why) => {
                generation.core().units().ended(id);
                return Err(why);
            }
        };
        if let Some(credential) = &ctx.caller_credential {
            generation.core().units().lend(id, credential.clone());
        }
        generation.core().units().ticketed(id, ctx.ticket.clone());
        self.frames_lock().insert(
            id,
            DispatchFrame {
                request: ctx.request.clone(),
            },
        );
        Ok(NativeUnit {
            context,
            routes: Arc::clone(self),
        })
    }

    fn frames_lock(&self) -> std::sync::MutexGuard<'_, foldhash::HashMap<u64, DispatchFrame>> {
        self.frames
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

pub(crate) struct DispatchSnapshot {
    pub(crate) served: Served,
    pub(crate) post: Arc<crate::root::plane_node::NodeEndPost>,

    pub(crate) guests: busbar_kernel::guest::GuestList,

    pub(crate) frames: Mutex<foldhash::HashMap<u64, DispatchFrame>>,
}

/// A nested operation inherits its parent's logical request admission. Cloning the frame shares
/// that admission; no child acquires another request-count permit.
#[derive(Clone)]
pub(crate) struct DispatchFrame {
    pub(crate) request: RequestLease,
}

pub(crate) struct NativeUnit {
    pub(crate) context: busbar_kernel::host_services::InvocationContext,
    routes: Arc<DataRoutes>,
}

impl Drop for NativeUnit {
    fn drop(&mut self) {
        let id = self.context.unit();
        self.context.retire();
        self.routes.frames_lock().remove(&id);
    }
}

pub(crate) const NEST_REPLY_MAX: usize = 16 << 20;

pub(crate) const NEST_UNSERVED: &str = "no plane serves the nested unit's claim";

pub(crate) const NEST_PARENT_GONE: &str = "the nested unit's parent is not in flight";

pub(crate) const NEST_UNREAD: &str = "the nested unit's reply could not be read";

pub(crate) const NEST_INPUT_FULL: &str = "the nested unit's input budget is exhausted";

/// The serving generation's nested-unit route: a nested unit is served by the native instance its
/// claim selects ([`native_nests::NativeNests`]), or answered unserved.
pub(crate) struct GenerationNests {
    pub(crate) routes: Arc<DispatchSnapshot>,
    pub(crate) native: Arc<native_nests::NativeNests>,
    pub(crate) runtime: tokio::runtime::Handle,
    pub(crate) detached: Option<Arc<busbar_kernel::detached::DetachedTasks>>,
}

impl busbar_kernel::host_services::NestRoute for GenerationNests {
    fn nest(
        &self,
        context: busbar_kernel::host_services::InvocationContext,
        nest: busbar_kernel::host_services::Nest,
        done: busbar_kernel::host_services::NestDone,
    ) {
        let routes = Arc::clone(&self.routes);
        let native = Arc::clone(&self.native);
        let child = async move {
            let answer = native
                .dispatch(routes, &context, &nest)
                .await
                .unwrap_or(busbar_kernel::host_services::NestReply::Unserved(NEST_UNSERVED));
            done(answer);
        };
        drop(match &self.detached {
            Some(detached) => detached.spawn_on(&self.runtime, child),
            None => self.runtime.spawn(child),
        });
    }
}

impl std::fmt::Debug for DataRoutes {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DataRoutes")
            .field("served", &self.served)
            .finish_non_exhaustive()
    }
}

pub(crate) type ChainAuth = (String, busbar_contract::abi::auth::AuthPoints);

pub(crate) fn listener_method_bits(method: RouteMethod) -> u32 {
    busbar_contract::abi::transport::route::method_bit(method.as_str())
        | if method == RouteMethod::Get {
            busbar_contract::abi::transport::route::METHOD_HEAD
        } else {
            0
        }
}

#[path = "serve_lines.rs"]
pub(crate) mod lines;

#[cfg(test)]
#[path = "tests/serve.rs"]
mod tests;

#[cfg(test)]
#[path = "tests/serve_planes.rs"]
pub(crate) mod planes_tests;

#[cfg(test)]
include!(concat!(env!("OUT_DIR"), "/root_test_sources.rs"));

#[cfg(test)]
#[path = "tests/journal_live_retry.rs"]
mod journal_live_retry_tests;
