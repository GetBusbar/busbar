// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! K9: what a MIN-3 plane seat forwards and attaches through, composed at boot from the instance's configured
//! upstreams (ABI-MIN3-INTERFACE §12.1, §12.3, §12.19; PLANE-DRIVER.md "BOOT (K9)").
//!
//! One upstream table per boot ([`ConfiguredUpstreams`]) is shared by every seat's egress walk and its carrier.
//! For each seat:
//!
//! * **Egress** ([`PortEgress`]): the seat's [`SeatPool`] (one member per `url` upstream) over the connector's
//!   connection table, under a seat owner of its own ([`seat_owner`]); each member's need is declared on the table
//!   with no pinned target, so the guard judges every dial, and its anchors (operator CA, SPKI pin) are sealed
//!   there before the first dial. Every dial is also judged by `transport_verdict` under the instance's core-held
//!   `accept` (`UnitRoute::accept`). Probes: when the plane states FB_PROBES, [`EgressProbes`] drives
//!   `PortProbes` in recovery mode (a member is probed only while the breaker holds it off), and a probe whose
//!   plane breaks a once rule charges its image.
//! * **Carrier** ([`PortCarrier`]): a [`ChannelDriver`] over [`ProcessWires`] (stdio children started by
//!   [`ContainedSpawn`], so dropping a generation stops the child's whole process tree; `env` references resolved
//!   through custody at every spawn, [`SpawnCustody`]; held HTTP requests through [`UpstreamHttp`], judged like
//!   every dial), the plane's `demux`, the process's signal registry and [`SeatEvents`].
//!
//! `insecure_transport` (TRANSPORT-SECURITY-POLICY §4): a seat whose `accept` is not empty is logged (BUSBAR-3162)
//! and audited (`config.insecure_transport_accepted`) at every boot; every refused dial is audited
//! (`egress.insecure_transport_refused`). A dial `accept: unverified_tls` admits is still verified on this path:
//! the connection table's open has no unverified mode, which is stricter than the acceptance, never looser.

use std::collections::BTreeMap;
use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use busbar_contract::abi::host::conn::connector::{
    DIRECTION_OUTBOUND, EGRESS_DEFAULT, KEEP_ALL_EXCEPT_DENIED,
};
use busbar_contract::abi::mechanism::rendering::{ReadBlob, ReadNeed};
use busbar_contract::conn::{
    ConnId, DeclaredConns, InstanceId, NeedId, OpenDesc, PieceKind, PollConns,
};
use busbar_contract::secret_ref::SecretRef;
use busbar_contract::services::Caller;
use busbar_contract::transport::wire::WireStatusClass;
use busbar_core_connector::child_job::ContainedChild;
use busbar_kernel::channels::budget::InstanceBudget;
use busbar_kernel::channels::carrier::{ChannelDriver, Events};
use busbar_kernel::channels::signals::SignalRegistry;
use busbar_kernel::channels::stdio::{
    ChildSpawn, HeldHttp, HeldRequest, ProcessWires, SpawnSecrets, Spawned,
};
use busbar_kernel::channels::SessionSignals;
use busbar_kernel::plane_driver::port_carrier::PortCarrier;
use busbar_kernel::plane_driver::port_channels::PortDemuxer;
use busbar_kernel::plane_driver::port_egress::{
    upstream_targets, EgressProbes, PortEgress, PortUpstream, ProbeTarget, SeatPool, Targets,
};
use busbar_kernel::plane_driver::port_intents::Namespace;
use busbar_kernel::plane_driver::port_probes::PortProbes;
use busbar_kernel::plane_driver::port_session::Effects;
use busbar_kernel::plane_driver::provider_catalog::{CatalogPlan, CatalogPool, RouteKind};
use busbar_kernel::plane_driver::request_admission::{RequestRoutes, SectionPool};
use busbar_kernel::plane_driver::route_input::HealthModeInput;
use busbar_kernel::plugin_records::RecordsDenied;
use busbar_kernel::probe::{run_probers, ProbeCfg, ProbeMember, ProbeSchedule};
use busbar_kernel::teller::Kernel;
use busbar_kernel::upstreams::{ConfiguredUpstreams, UpstreamDef, Upstreams};
use busbar_kernel_egress::ports::{Dispatched, DurabilityUnavailable, Journal};
use busbar_plugin_abi::host_side::caller::{transport_verdict, Accept, BoxFut, Verdict};
use busbar_plugin_abi::need::need_flag::{TLS_NONE, TLS_REQUIRED};
use busbar_ports::plane::PlanePort;
use tokio::io::{AsyncRead, ReadBuf};
use tokio::process::Command;

use super::secret_custody::BootSecrets;

/// How long resolving one child `env` reference may take.
const SPAWN_SECRET_DEADLINE: Duration = Duration::from_secs(30);
/// How long a held HTTP request may take to open (dial, TLS and the request head written).
const HELD_OPEN_MS: u64 = 30_000;
/// The read buffer of one held HTTP response.
const HELD_BUF: usize = 16 * 1024;
/// The seat owners sit above every dispatch handle id (24 bits) and below the connector's test owners.
const SEAT_OWNER_BASE: u64 = 1 << 40;
/// The audit action of a seat that runs with an `insecure_transport` acceptance (TRANSPORT-SECURITY-POLICY §4).
pub(crate) const INSECURE_ACCEPTED: &str =
    busbar_kernel::config::listener_acceptance::INSECURE_ACCEPTED;
/// The audit action of a held HTTP dial the instance's acceptance does not cover (the connector's own action).
const INSECURE_REFUSED: &str = "egress.insecure_transport_refused";
/// The audit action of a stdio channel that tripped (IF §12.19: the fifth child end inside 60 s).
pub(crate) const CHILD_TRIPPED: &str = "upstream_child_tripped";

/// The connection table core's own upstream exchanges ride (the process's connector).
#[derive(Clone)]
pub(crate) struct ConnTable {
    pub(crate) declared: Arc<dyn DeclaredConns>,
    pub(crate) conns: Arc<dyn PollConns>,
}

impl ConnTable {
    /// The installed connector's table; `None` before the connector is built (a seat then walks nothing).
    pub(crate) fn installed() -> Option<Self> {
        let connector = super::connector::installed()?;
        Some(Self {
            declared: Arc::clone(connector) as Arc<dyn DeclaredConns>,
            conns: Arc::clone(connector) as Arc<dyn PollConns>,
        })
    }
}

/// Immutable model routing facts and sealed destinations from one candidate.
pub(crate) struct CatalogSeat {
    pub(crate) plan: Arc<CatalogPlan>,
    pub(crate) sealed: super::min3_provider_catalog::SealedCatalog,
    pub(crate) pools: BTreeMap<String, CatalogPool>,
}

/// What every seat of one boot composes over.
pub(crate) struct SeatShared {
    /// Per-instance registration tables; a seat never sees another plane's registrations.
    pub(crate) upstreams: BTreeMap<String, Arc<ConfiguredUpstreams>>,
    /// Auth-sealed model destinations and owned pool policy from this same candidate.
    pub(crate) catalogs: BTreeMap<String, Arc<CatalogSeat>>,
    /// Root-retained stable instance accounts, shared with every serving/draining generation.
    pub(crate) channel_budgets: BTreeMap<String, InstanceBudget>,
    pub(crate) signals: Arc<SignalRegistry>,
    pub(crate) secrets: Arc<dyn SpawnSecrets>,
    pub(crate) kernel: Arc<Kernel>,
    /// `None` = no connection table: no seat walks or holds an HTTP request (a CHANNEL to a stdio upstream still
    /// opens).
    pub(crate) table: Option<ConnTable>,
    /// Each instance's section `pools:` (members, fallback, `member_granted`), walked natively (#108).
    pub(crate) section_pools: SectionPoolsByInstance,
}

/// What one seat runs over.
pub(crate) struct SeatWiring {
    /// The exact registration and catalog inventory used for this generation's request admission.
    pub(crate) request_routes: Arc<RequestRoutes>,
    /// Shared with the channel driver; original unit admission derives its account exactly once.
    pub(crate) channel_budget: InstanceBudget,
    /// Actual registration table shared with CHANNEL and the physical inventory builder.
    pub(crate) inventory_upstreams: Arc<dyn Upstreams>,
    /// Actual exact-pair resolver shared with egress and the physical inventory builder.
    pub(crate) inventory_targets: Targets,
    /// `None` = no connection table: a FORWARD fails `NotDriven`.
    pub(crate) upstream: Option<Arc<dyn PortUpstream>>,
    pub(crate) carrier: Arc<PortCarrier>,
    /// Dormant probe work that retains its target until stopped by the generation owner.
    pub(crate) probes: Option<std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send>>>,
}

/// The connection-table owner of a seat's upstream exchanges: its own identity, never a dispatch handle's.
#[must_use]
pub(crate) fn seat_owner(instance: u64) -> InstanceId {
    InstanceId(SEAT_OWNER_BASE | (instance & (SEAT_OWNER_BASE - 1)))
}

/// The need an upstream member's connections open on: outbound, the URL's own scheme as its transport, egress class
/// DEFAULT (core config names the upstream: `judged_class` treats it as configured), no pinned target (the guard
/// judges every dial), the far end's head kept but for the kernel's own deny list.
#[must_use]
pub(crate) fn upstream_need(url: &str) -> ReadNeed {
    let transport = url
        .split_once("://")
        .map_or(String::new(), |(scheme, _)| scheme.to_ascii_lowercase());
    ReadNeed {
        direction: DIRECTION_OUTBOUND,
        egress_class: EGRESS_DEFAULT,
        transport,
        auth: String::new(),
        target_from: String::new(),
        trust_from: String::new(),
        details: ReadBlob {
            fmt: 0,
            flags: 0,
            bytes: Vec::new(),
        },
        timeout_ms: 0,
        keep_mode: KEEP_ALL_EXCEPT_DENIED,
        keep_response_headers: Vec::new(),
        deny_response_headers: Vec::new(),
    }
}

/// Whether `url` may be dialled under `accept` (`transport_verdict` with the URL's scheme as its TLS mode).
#[must_use]
pub(crate) fn admitted(accept: Accept, url: &str) -> bool {
    let tls = if names_tls(url) {
        TLS_REQUIRED
    } else {
        TLS_NONE
    };
    !matches!(transport_verdict(accept, tls, url), Verdict::Refuse)
}

/// Whether `url` names TLS from its first byte (`https://`, `wss://`). An [`admitted`] URL that does
/// not was admitted by the seat's PLAINTEXT acceptance, which its open carries to the connector
/// (`OpenDesc::plaintext_accepted`, #297 model A).
fn names_tls(url: &str) -> bool {
    let named = |prefix: &str| {
        url.get(..prefix.len())
            .is_some_and(|p| p.eq_ignore_ascii_case(prefix))
    };
    named("https://") || named("wss://")
}

/// The `accept` words as the audit row and the warning print them.
#[must_use]
pub(crate) fn accept_words(accept: Accept) -> Vec<&'static str> {
    let mut words = Vec::new();
    if accept.0 & Accept::PLAINTEXT != 0 {
        words.push("plaintext");
    }
    if accept.0 & Accept::UNVERIFIED_TLS != 0 {
        words.push("unverified_tls");
    }
    words
}

/// A seat that runs with an acceptance: the BUSBAR-3162 line and the `config.insecure_transport_accepted` row.
/// Answers whether it wrote them (an empty acceptance writes nothing).
pub(crate) fn audit_acceptance(instance: &str, accept: Accept, upstreams: &SeatPool) -> bool {
    let words = accept_words(accept);
    if words.is_empty() {
        return false;
    }
    let endpoints: Vec<String> = upstreams
        .members
        .iter()
        .map(|member| shown(&member.url).to_owned())
        .collect();
    busbar_kernel::audit_ring::AUDIT.record_by(
        INSECURE_ACCEPTED,
        &format!("plane:{instance}:accept={}", words.join(",")),
        busbar_kernel::audit_ring::OUTCOME_APPLIED,
        "system",
    );
    let dests = if endpoints.is_empty() {
        "no declared endpoint uses this yet".to_owned()
    } else {
        endpoints.join(", ")
    };
    tracing::warn!(
        "BUSBAR-3162: plane.{instance} runs with insecure_transport: accept [{}] for {dests}. Anything sent to \
         it, credentials included, can be read and altered by anyone who can intercept the network path. Remove \
         its insecure_transport once the server offers verifiable TLS.",
        words.join(", ")
    );
    true
}

/// The destination as a row or a line may name it: no scheme, userinfo, path or query.
fn shown(url: &str) -> &str {
    let rest = url.split_once("://").map_or(url, |(_, r)| r);
    let rest = rest.split(['/', '?', '#']).next().unwrap_or(rest);
    rest.rsplit_once('@').map_or(rest, |(_, host)| host)
}

/// The dispatch journal of a seat's walk. A port session's unit lives on its own `PlaneMoney`
/// (PLANE-BILLING), and no open-unit evidence collector reads port units yet, so a dispatch has no durable record
/// to wait for: it is admitted at once and nothing is written.
struct SeatJournal;

impl Journal for SeatJournal {
    fn dispatched(&self, _record: &Dispatched) -> Result<(), DurabilityUnavailable> {
        Ok(())
    }

    fn abandoned(&self, _record: &Dispatched) {}
}

/// What a probe exchange does with a line-carrier emit: nothing (a probe has no carrier).
struct ProbeEffects;

impl Effects for ProbeEffects {
    fn emit(&self, carrier: u64, _bytes: &[u8]) {
        tracing::debug!(carrier, "a plane probe emitted to a line carrier: dropped");
    }
}

/// The carrier's events for one seat: a tripped channel is an audit row; a resight is logged (the sighting probe
/// it asks for is the probe schedule's next round).
struct SeatEvents {
    instance: Arc<str>,
}

impl Events for SeatEvents {
    fn tripped(&self, upstream: &str) {
        busbar_kernel::audit_ring::AUDIT.record_by(
            CHILD_TRIPPED,
            &format!("upstream:{upstream}:{}", self.instance),
            busbar_kernel::audit_ring::OUTCOME_DEGRADED,
            "system",
        );
        tracing::warn!(
            instance = %self.instance,
            upstream,
            "upstream_child_tripped: the upstream's child ended five times inside 60 s; attaches fail until it is \
             declared again"
        );
    }

    fn resight(&self, upstream: &str) {
        tracing::debug!(instance = %self.instance, upstream, "a channel asked for a sighting");
    }
}

/// Child `env` references resolved through the process's custody at every spawn (§12.2: by reference, an empty
/// call stack, no source named in an error).
pub(crate) struct SpawnCustody(pub(crate) Arc<BootSecrets>);

impl SpawnSecrets for SpawnCustody {
    fn resolve<'a>(&'a self, secret: &'a SecretRef) -> BoxFut<'a, Option<String>> {
        Box::pin(async move {
            let value = self
                .0
                .resolve_ref(Instant::now() + SPAWN_SECRET_DEADLINE, secret)
                .await
                .ok()?;
            String::from_utf8(value[..].to_vec()).ok()
        })
    }
}

/// Children started in an owned process tree (the connector's [`ContainedChild`]: a Unix process group, a Windows
/// Job), so dropping a generation stops every process the child started, not the child alone.
pub(crate) struct ContainedSpawn;

impl ChildSpawn for ContainedSpawn {
    fn spawn<'a>(&'a self, command: &'a mut Command) -> BoxFut<'a, Option<Spawned>> {
        Box::pin(async move {
            let mut child = ContainedChild::spawn(command).await.ok()?;
            let stdin = child.take_stdin()?;
            let stdout = child.take_stdout()?;
            Some(Spawned {
                stdin,
                stdout,
                hold: Box::new(child),
            })
        })
    }
}

/// The held HTTP requests of one seat (CARRIER_HTTP channels) over the connection table, on the needs its members
/// declared: every dial judged by the guard and by `transport_verdict` under the instance's `accept`. A refused
/// dial, a failed open or a non-2xx head is `Unavailable`.
pub(crate) struct UpstreamHttp {
    owner: InstanceId,
    instance: Arc<str>,
    table: ConnTable,
    needs: BTreeMap<Box<str>, NeedId>,
    accept: Accept,
}

/// `path` joined onto `base` (one `/` between them).
fn joined(base: &str, path: &str) -> String {
    let base = base.trim_end_matches('/');
    if path.starts_with('/') {
        format!("{base}{path}")
    } else {
        format!("{base}/{path}")
    }
}

/// The path and query of `url` (`/` when it names none).
fn head_target(url: &str) -> &str {
    let rest = url.split_once("://").map_or(url, |(_, r)| r);
    match rest.find('/') {
        Some(at) => &rest[at..],
        None => "/",
    }
}

impl HeldHttp for UpstreamHttp {
    fn open<'a>(
        &'a self,
        upstream: &'a UpstreamDef,
        request: HeldRequest<'a>,
    ) -> BoxFut<'a, Result<Box<dyn AsyncRead + Send + Unpin>, RecordsDenied>> {
        Box::pin(async move {
            let need = *self
                .needs
                .get(&*upstream.name)
                .ok_or(RecordsDenied::Unavailable)?;
            let base = upstream.url.as_deref().ok_or(RecordsDenied::Invalid)?;
            let target = joined(base, request.path);
            if !admitted(self.accept, &target) {
                busbar_kernel::audit_ring::AUDIT.record_by(
                    INSECURE_REFUSED,
                    &format!("dest:{}:{}", shown(&target), self.instance),
                    busbar_kernel::audit_ring::OUTCOME_REJECTED,
                    "system",
                );
                tracing::warn!(
                    action = INSECURE_REFUSED,
                    destination = shown(&target),
                    "a held upstream request was refused: no insecure_transport acceptance covers it"
                );
                return Err(RecordsDenied::Unavailable);
            }
            let conn = self
                .table
                .conns
                .open(
                    self.owner,
                    need,
                    &OpenDesc {
                        target: &target,
                        fields: &request.headers,
                        timeout_ms: HELD_OPEN_MS,
                        method: request.method.as_bytes(),
                        head_target: head_target(&target).as_bytes(),
                        member: &upstream.name,
                        plaintext_accepted: !names_tls(&target),
                        ..OpenDesc::default()
                    },
                )
                .map_err(|_| RecordsDenied::Unavailable)?;
            let mut body = HeldBody {
                conns: Arc::clone(&self.table.conns),
                owner: self.owner,
                conn,
                buf: vec![0; HELD_BUF],
                pending: Vec::new(),
                at: 0,
                done: false,
            };
            body.head().await?;
            Ok(Box::new(body) as Box<dyn AsyncRead + Send + Unpin>)
        })
    }
}

/// The streamed body of one held response; dropping it closes the connection.
struct HeldBody {
    conns: Arc<dyn PollConns>,
    owner: InstanceId,
    conn: ConnId,
    buf: Vec<u8>,
    pending: Vec<u8>,
    at: usize,
    done: bool,
}

impl HeldBody {
    /// Reads the response head: a 2xx opens the body, anything else (or no head) is `Unavailable`.
    async fn head(&mut self) -> Result<(), RecordsDenied> {
        let piece = std::future::poll_fn(|cx| {
            self.conns
                .poll_read(self.owner, self.conn, cx, &mut self.buf)
        })
        .await
        .map_err(|_| RecordsDenied::Unavailable)?;
        match piece.kind {
            // The far end's head is the answer's first piece (`PieceKind::Fields`), status and all.
            PieceKind::Fields | PieceKind::HookReply => {
                let success = piece.status == Some(WireStatusClass::Success)
                    || piece
                        .status_code
                        .is_some_and(|code| (200..300).contains(&code));
                if success {
                    Ok(())
                } else {
                    Err(RecordsDenied::Unavailable)
                }
            }
            PieceKind::Body => Err(RecordsDenied::Invalid),
            PieceKind::Completion => Err(RecordsDenied::Unavailable),
        }
    }
}

impl AsyncRead for HeldBody {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        out: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = &mut *self;
        loop {
            if this.at < this.pending.len() {
                let n = (this.pending.len() - this.at).min(out.remaining());
                out.put_slice(&this.pending[this.at..this.at + n]);
                this.at += n;
                return Poll::Ready(Ok(()));
            }
            if this.done {
                return Poll::Ready(Ok(()));
            }
            let piece = match this
                .conns
                .poll_read(this.owner, this.conn, cx, &mut this.buf)
            {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Ok(piece)) => piece,
                Poll::Ready(Err(_)) => {
                    this.done = true;
                    return Poll::Ready(Err(io::Error::other("the held upstream request failed")));
                }
            };
            match piece.kind {
                PieceKind::Body => {
                    this.pending.clear();
                    this.pending.extend_from_slice(&this.buf[..piece.len]);
                    this.at = 0;
                }
                PieceKind::Completion => this.done = true,
                PieceKind::Fields | PieceKind::HookReply => {}
            }
        }
    }
}

impl Drop for HeldBody {
    fn drop(&mut self) {
        let _closed = self.conns.close(self.owner, self.conn);
    }
}

/// Join only the exact sealed associations to the candidate's configured pool policies.
/// Registration membership remains in its own default pool and CHANNEL table.
/// Each plane instance's section pools, by instance name.
pub(crate) type SectionPoolsByInstance = BTreeMap<String, Arc<BTreeMap<String, SectionPool>>>;

/// Read each plane section's `pools:` exactly as the 1.5.5 door did: members,
/// `on_exhausted.fallback_pool` and `member_granted`. These become native walks (#108).
///
/// # Errors
/// A section's pool is malformed (the 1.5.5 refusal).
pub(crate) fn section_pools(
    sections: &BTreeMap<&'static str, busbar_contract::yaml::Value>,
) -> Result<SectionPoolsByInstance, String> {
    sections
        .iter()
        .map(|(instance, section)| {
            let pools = pools_of(section).map_err(|why| format!("{instance}: {why}"))?;
            Ok(((*instance).to_owned(), Arc::new(pools)))
        })
        .collect()
}

/// One section's reserved `pools:` sub-key: each named pool's members, its
/// `on_exhausted.fallback_pool` and whether it is `member_granted`. A section that is no mapping
/// states no pool.
fn pools_of(
    section: &busbar_contract::yaml::Value,
) -> Result<BTreeMap<String, SectionPool>, String> {
    use busbar_contract::yaml::{MappingExt, Value, ValueExt as _};
    let Some(declared) = section
        .as_mapping()
        .and_then(|map| map.get_key(busbar_contract::section::RESERVED_POOLS_KEY))
        .and_then(Value::as_mapping)
    else {
        return Ok(BTreeMap::new());
    };
    let mut pools = BTreeMap::new();
    for (name, pool) in declared {
        let Some(name) = name.as_str() else {
            continue;
        };
        let members = pool_members(pool).map_err(|e| format!("pool '{name}': {e}"))?;
        let fallback = pool
            .get(super::door_steps::ON_EXHAUSTED_KEY)
            .and_then(|on| on.get(super::door_steps::FALLBACK_POOL_KEY))
            .and_then(Value::as_str)
            .map(str::to_owned);
        let member_granted = pool
            .get(busbar_contract::section::POOL_MEMBER_GRANTED_KEY)
            .and_then(Value::as_bool)
            .unwrap_or(false);
        pools.insert(
            name.to_owned(),
            SectionPool {
                members,
                fallback,
                member_granted,
            },
        );
    }
    Ok(pools)
}

/// A pool's member names, in order. A member is a name, `{name, tier}` or an llm pool's
/// `{model, ..}`; a member naming neither, or a tier that is no `u32`, refuses the load: skipping
/// it would load a pool whose walk reaches no member.
fn pool_members(pool: &busbar_contract::yaml::Value) -> Result<Vec<String>, String> {
    use busbar_contract::section::{POOL_MEMBERS_KEY, POOL_MEMBER_MODEL_KEY, POOL_MEMBER_NAME_KEY};
    use busbar_contract::yaml::{Value, ValueExt as _};
    let Some(list) = pool.get(POOL_MEMBERS_KEY).and_then(Value::as_sequence) else {
        return Ok(Vec::new());
    };
    let mut out = Vec::with_capacity(list.len());
    for (i, m) in list.iter().enumerate() {
        if let Some(name) = m.as_str() {
            out.push(name.to_owned());
            continue;
        }
        let Some(name) = m
            .get(POOL_MEMBER_NAME_KEY)
            .or_else(|| m.get(POOL_MEMBER_MODEL_KEY))
            .and_then(Value::as_str)
        else {
            return Err(format!(
                "member {i} names no entry (expected `{POOL_MEMBER_NAME_KEY}` or `{POOL_MEMBER_MODEL_KEY}`)"
            ));
        };
        if let Some(written) = m.get(busbar_contract::section::POOL_MEMBER_TIER_KEY) {
            if written
                .as_u64()
                .and_then(|t| u32::try_from(t).ok())
                .is_none()
            {
                return Err(format!(
                    "member '{name}' has tier {written:?}, which is no unsigned integer that fits u32"
                ));
            }
        }
        out.push(name.to_owned());
    }
    Ok(out)
}

/// The section pools this seat walks: each pool keeps only its members that are walked URL
/// registrations (a command is never walked; it is reached by registration selection). A pool
/// left with no walked member is no walk. Each kept pool joins egress beside the registration pool.
///
/// # Errors
/// A section pool name collides with a pool this seat already walks.
fn extend_sections(
    instance: &str,
    seat: &mut SeatPool,
    sections: &BTreeMap<String, SectionPool>,
) -> Result<BTreeMap<String, SectionPool>, String> {
    let walked: BTreeMap<String, SectionPool> = sections
        .iter()
        .filter_map(|(name, pool)| {
            let members: Vec<String> = pool
                .members
                .iter()
                .filter(|member| seat.members.iter().any(|m| &*m.upstream == member.as_str()))
                .cloned()
                .collect();
            (!members.is_empty()).then(|| {
                let pool = SectionPool {
                    members,
                    ..pool.clone()
                };
                (name.clone(), pool)
            })
        })
        .collect();
    for (name, configured) in &walked {
        if seat.pools.contains_key(name.as_str()) {
            return Err(format!(
                "section pool `{name}` collides with a pool this plane already walks"
            ));
        }
        let members = configured
            .members
            .iter()
            .filter_map(|member| {
                let walked = seat
                    .members
                    .iter()
                    .find(|m| &*m.upstream == member.as_str())?;
                let lane = format!(
                    "{instance}{}{member}",
                    busbar_kernel::governance::PLANE_LANE_SEP
                );
                Some(busbar_kernel_egress::Member::new(
                    walked.destination,
                    lane,
                    1,
                ))
            })
            .collect();
        let mut pool = busbar_kernel_egress::Pool::new(name, members);
        pool.on_exhausted = match configured
            .fallback
            .as_ref()
            .filter(|fallback| walked.contains_key(fallback.as_str()))
        {
            Some(fallback) => busbar_kernel_egress::OnExhausted::FallbackPool(fallback.clone()),
            None => busbar_kernel_egress::OnExhausted::Status503,
        };
        // Keyed by the pool's own name: one shared text for both.
        seat.pools.insert(pool.name.clone(), pool);
    }
    // A fallback that is not itself walked is dropped from the routing record as from egress.
    Ok(walked
        .iter()
        .map(|(name, pool)| {
            let pool = SectionPool {
                fallback: pool
                    .fallback
                    .clone()
                    .filter(|fallback| walked.contains_key(fallback)),
                ..pool.clone()
            };
            (name.clone(), pool)
        })
        .collect())
}

/// A section pool's listed member reads as the same registration target as on the seat's own
/// registration walk. An unlisted pair is left to `registrations` (which refuses it).
fn section_targets(
    instance: &str,
    registrations: Targets,
    sections: Arc<BTreeMap<String, SectionPool>>,
) -> Targets {
    let instance = instance.to_owned();
    let prefix = format!("{instance}{}", busbar_kernel::governance::PLANE_LANE_SEP);
    Arc::new(move |pool, member| {
        let listed = sections.get(pool).is_some_and(|section| {
            member
                .strip_prefix(prefix.as_str())
                .is_some_and(|name| section.members.iter().any(|listed| listed == name))
        });
        if listed {
            registrations(&instance, member)
        } else {
            registrations(pool, member)
        }
    })
}

fn extend_catalog(
    instance: &str,
    seat: &mut SeatPool,
    catalog: &CatalogSeat,
) -> Result<(), String> {
    if catalog.sealed.instance != instance || catalog.plan.instance != instance {
        return Err("catalog belongs to another plane instance".into());
    }
    for (name, configured) in &catalog.pools {
        if seat.pools.contains_key(name.as_str()) {
            return Err("catalog pool collides with the registration pool".into());
        }
        let cfg = &configured.config;
        let members = cfg
            .members
            .iter()
            .map(|member| {
                let qualified = format!(
                    "{instance}{}{name}",
                    busbar_kernel::governance::PLANE_LANE_SEP,
                    name = member.name()
                );
                let association = catalog
                    .sealed
                    .associations
                    .get(&(name.clone(), qualified.clone()))
                    .ok_or("catalog pool member has no sealed association")?;
                let mut walked = busbar_kernel_egress::Member::new(
                    association.destination,
                    qualified,
                    member.weight,
                );
                walked.attempt_timeout_ms = association.attempt_timeout_ms;
                walked.context_max = association.context_max.map(|limit| limit as u64);
                walked.passthrough = association.credential_mode
                    == busbar_contract::config::UpstreamCreds::Passthrough;
                Ok(walked)
            })
            .collect::<Result<Vec<_>, String>>()?;
        let mut pool = busbar_kernel_egress::Pool::new(name, members);
        if let Some(failover) = &cfg.failover {
            pool.set_failover(busbar_kernel_egress::Failover {
                timeout_secs: failover.timeout_secs,
                max_hops: failover.max_hops,
                exclusions: failover
                    .exclusions
                    .iter()
                    .flatten()
                    .map(|member| {
                        format!(
                            "{instance}{}{member}",
                            busbar_kernel::governance::PLANE_LANE_SEP
                        )
                    })
                    .collect(),
            });
        }
        pool.on_exhausted = match &cfg.on_exhausted {
            None | Some(busbar_kernel::config::OnExhaustedCfg::Reject) => {
                busbar_kernel_egress::OnExhausted::Status503
            }
            Some(busbar_kernel::config::OnExhaustedCfg::LeastBad) => {
                busbar_kernel_egress::OnExhausted::LeastBad
            }
            Some(busbar_kernel::config::OnExhaustedCfg::Queue { max_ms }) => {
                busbar_kernel_egress::OnExhausted::Queue { max_ms: *max_ms }
            }
            Some(busbar_kernel::config::OnExhaustedCfg::FallbackPool(fallback)) => {
                let (actual, _) = catalog.pools.iter().find(|(_, pool)| matches!(&pool.kind, RouteKind::NamedPool(logical) if logical == fallback))
                    .ok_or("catalog fallback has no pool in this plane")?;
                busbar_kernel_egress::OnExhausted::FallbackPool(actual.clone())
            }
        };
        // Keyed by the pool's own name: one shared text for both.
        seat.pools.insert(pool.name.clone(), pool);
    }
    for (destination, route) in &catalog.sealed.routes {
        if seat.routes.insert(*destination, route.clone()).is_some() {
            return Err("catalog destination collides with a registration".into());
        }
    }
    seat.members.extend(catalog.sealed.members.iter().cloned());
    Ok(())
}

/// Every probe retains the selected pool/member pair, including repeated models across pools.
fn probe_targets(pool: &SeatPool) -> Vec<ProbeTarget> {
    let mut targets: Vec<_> = pool
        .pools
        .values()
        .flat_map(|walked| {
            walked.members.iter().map(|member| ProbeTarget {
                destination: member.destination,
                pool: walked.name.as_str().to_owned(),
                qualified_member: member.name.as_str().to_owned(),
            })
        })
        .collect();
    targets.sort_by(|a, b| (&a.pool, &a.qualified_member).cmp(&(&b.pool, &b.qualified_member)));
    targets
}

/// The seat's egress walk over `table`: its members' needs declared and their anchors sealed, then the walk.
fn egress_of(
    instance: &str,
    owner: InstanceId,
    table: &ConnTable,
    pool: &SeatPool,
    catalog: Option<&CatalogSeat>,
) -> Result<busbar_kernel::plane_driver::Egress, String> {
    for member in &pool.members {
        table
            .declared
            .declare(owner, member.need, &upstream_need(&member.url), None, None)
            .map_err(|refused| {
                format!(
                    "upstream `{}` of plane `{instance}` cannot be reached: the connection table refused its \
                     URL's scheme or target ({refused:?})",
                    member.upstream
                )
            })?;
        if let Some(route) = pool.routes.get(&member.destination) {
            table
                    .conns
                    .anchor(owner, member.need, &route.provider, &route.base_url, &route.anchors)
                    .map_err(|refused| {
                        format!(
                            "upstream `{}` of plane `{instance}`: its trust anchors could not be sealed \
                             ({refused:?})",
                            member.upstream
                        )
                    })?;
        }
    }
    let names: Vec<(busbar_kernel_egress::ports::DestinationId, String)> = pool
        .pools
        .values()
        .flat_map(|walked| walked.members.iter())
        .map(|member| (member.destination, member.name.as_str().to_owned()))
        .collect();
    let cell = || busbar_kernel::store::pool_breaker_cfg(None);
    let policy = pool.pools.keys().fold(
        super::adapters::BreakerPolicy::new().with_default_cell(cell()),
        |policy, name| {
            let configured = catalog.and_then(|catalog| catalog.pools.get(name.as_str()));
            policy.with_pool(
                name.as_str(),
                busbar_kernel::store::pool_breaker_cfg(
                    configured.and_then(|pool| pool.config.breaker.as_ref()),
                ),
            )
        },
    );
    let limits = busbar_kernel::config::limits::installed();
    let (hard_down_cooldown_secs, max_honored_retry_after_secs) = limits.as_ref().map_or(
        (
            busbar_kernel::config::limits::DEFAULT_HARD_DOWN_COOLDOWN_SECS,
            busbar_kernel::config::limits::DEFAULT_MAX_HONORED_RETRY_AFTER_SECS,
        ),
        |l| (l.hard_down_cooldown_secs, l.max_honored_retry_after_secs),
    );
    let unit = busbar_kernel_breaker::BreakerUnit::new()
        .with_limits(hard_down_cooldown_secs, max_honored_retry_after_secs);
    Ok(busbar_kernel::plane_driver::Egress {
        caller: owner,
        conns: Arc::clone(&table.conns),
        breaker: busbar_kernel::plane_driver::fixed_breaker(Arc::new(
            super::adapters::BreakerAdapter::new(unit, policy),
        )),
        capacity: Arc::new(super::egress_ports::MemberPermits {
            limits: catalog
                .into_iter()
                .flat_map(|catalog| {
                    catalog
                        .sealed
                        .capacity
                        .iter()
                        .map(|(destination, slots)| (*destination, Arc::clone(slots)))
                })
                .collect(),
        }),
        clock: busbar_contract::clock::HostClock::system(super::egress_ports::tokio_sleep),
        journal: Arc::new(SeatJournal),
        telemetry: Arc::new(super::egress_ports::WalkTelemetry::new(names)),
        pools: pool.pools.clone(),
        routes: pool.routes.clone(),
        stream_ceiling_secs: limits.as_ref().map_or(
            busbar_kernel::config::limits::DEFAULT_UPSTREAM_REQUEST_TIMEOUT_SECS,
            |l| l.upstream_request_timeout_secs,
        ),
        stated_ceiling_secs: 0,
        error_body_max: limits
            .as_ref()
            .map_or(busbar_kernel::plane_driver::DEFAULT_ERROR_BODY_MAX, |l| {
                l.upstream_error_body_max_bytes
            }),
    })
}

/// Dormant probes for a seat whose plane states FB_PROBES: recovery probes only
/// (`HealthModeInput::Dead`: a member is probed while the breaker holds it off), the limits' default interval and
/// timeout. `None` = the plane states no probes or walks no member.
fn probes_of(
    port: &Arc<dyn PlanePort>,
    egress: &PortEgress,
    pool: &SeatPool,
) -> Option<std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send>>> {
    if port.facts() & busbar_plugin_abi::plane::FB_PROBES == 0 || pool.members.is_empty() {
        return None;
    }
    let members = probe_targets(pool);
    let schedule = Arc::new(ProbeSchedule::new(members.len()));
    let probers: Vec<ProbeMember> = members
        .iter()
        .enumerate()
        .map(|(index, member)| ProbeMember {
            index,
            name: member.name().to_owned(),
            cfg: ProbeCfg::resolve(
                HealthModeInput::Dead,
                None,
                None,
                busbar_kernel::config::limits::DEFAULT_PROBE_INTERVAL_SECS,
                busbar_kernel::config::limits::DEFAULT_PROBE_TIMEOUT_SECS,
            ),
        })
        .collect();
    let dialect = port
        .dialects()
        .first()
        .map(ToString::to_string)
        .unwrap_or_default();
    let far: EgressProbes = egress.probes(members);
    let target = Arc::new(
        PortProbes::new(
            Arc::clone(port),
            Arc::new(far),
            dialect,
            String::new(),
            Arc::new(ProbeEffects),
        )
        .charging(Arc::clone(port)),
    );
    Some(Box::pin(run_probers(target, schedule, probers)))
}

/// Build the real channel driver over the retained account, never a generation-local replacement.
fn channels_of(
    shared: &SeatShared,
    budget: InstanceBudget,
    who: &Namespace,
    caller: Caller,
    port: Arc<dyn PlanePort>,
    held: Option<Arc<dyn HeldHttp>>,
) -> ChannelDriver {
    let wires =
        ProcessWires::new(Arc::clone(&shared.secrets), held).spawning(Arc::new(ContainedSpawn));
    ChannelDriver::new(
        who.instance,
        caller,
        budget,
        Arc::new(wires),
        Arc::new(PortDemuxer::new(port)),
        Arc::clone(&shared.signals) as Arc<dyn SessionSignals>,
        Arc::new(SeatEvents {
            instance: Arc::clone(&who.name),
        }),
    )
}

/// Composes one seat's egress and carrier (see the module docs). `accept` is the instance's core-held
/// `insecure_transport.accept` (`InstanceSpec.limits.accept`).
///
/// # Errors
/// An upstream states a TLS check this path cannot enforce, or the connection table refused a member's need or
/// anchors: the plane does not open (a configured upstream is never silently unreachable or unchecked).
pub(crate) fn compose(
    shared: &SeatShared,
    instance: &str,
    accept: Accept,
    who: &Namespace,
    caller: Caller,
    port: Arc<dyn PlanePort>,
) -> Result<SeatWiring, String> {
    let channel_budget = shared
        .channel_budgets
        .get(instance)
        .cloned()
        .ok_or_else(|| format!("plane {instance}: no retained channel account was supplied"))?;
    let upstreams = shared.upstreams.get(instance).ok_or_else(|| {
        format!("plane {instance}: no declared registration table was built for this generation")
    })?;
    let registration = Arc::new(SeatPool::of(instance, upstreams)?);
    let catalog = shared.catalogs.get(instance);
    let mut pool = SeatPool {
        pool: registration.pool.clone(),
        pools: registration.pools.clone(),
        routes: registration.routes.clone(),
        members: registration.members.clone(),
    };
    // The section's own pools walk natively over these registrations (#108).
    let sections = Arc::new(extend_sections(
        instance,
        &mut pool,
        shared
            .section_pools
            .get(instance)
            .map_or(&BTreeMap::new(), |pools| pools.as_ref()),
    )?);
    // No kind is inferred from instance/image vocabulary. The seat that walks core's own model
    // catalog walks the operator's `pools:`, and a key's `allowed_pools` is judged against them as
    // 1.5.5 judged it (`key.scope_allowed("pool", pool)`): a restricted key reaches its pools only.
    let scope_kind = catalog.map(|_| Arc::<str>::from("pool"));
    let request_routes = Arc::new(
        RequestRoutes::new(
            instance,
            scope_kind,
            catalog.map(|catalog| Arc::clone(&catalog.plan)),
            Some(Arc::clone(&registration)),
        )
        .and_then(|routes| routes.with_registrations(Arc::clone(upstreams)))
        .and_then(|routes| routes.with_section_pools(sections.as_ref().clone()))
        .map_err(|_| format!("plane {instance}: inconsistent request routing inventory"))?,
    );
    // Held HTTP channels receive only the registration domain, before model destinations join egress.
    let registration_needs = pool
        .members
        .iter()
        .map(|member| (member.upstream.clone(), member.need))
        .collect();
    if let Some(catalog) = catalog {
        extend_catalog(instance, &mut pool, catalog)?;
    }
    audit_acceptance(instance, accept, &pool);
    let owner = seat_owner(who.instance);
    let table_upstreams: Arc<dyn Upstreams> = Arc::clone(upstreams) as Arc<dyn Upstreams>;
    let registrations = section_targets(
        instance,
        upstream_targets(instance, Arc::clone(&table_upstreams)),
        Arc::clone(&sections),
    );
    let targets: Targets = match catalog {
        Some(catalog) => {
            let catalog = Arc::clone(catalog);
            Arc::new(move |pool, member| {
                (catalog.sealed.targets)(pool, member).or_else(|| registrations(pool, member))
            })
        }
        None => registrations,
    };
    let inventory_upstreams = Arc::clone(&table_upstreams);
    let inventory_targets = Arc::clone(&targets);
    let (upstream, held, probes) = match &shared.table {
        Some(table) => {
            let egress = egress_of(instance, owner, table, &pool, catalog.map(Arc::as_ref))?;
            let walk = PortEgress::new(
                Arc::new(egress),
                Arc::clone(&shared.kernel),
                pool.pool.clone(),
                accept,
                targets,
            );
            let probes = probes_of(&port, &walk, &pool);
            let held: Arc<dyn HeldHttp> = Arc::new(UpstreamHttp {
                owner,
                instance: Arc::from(instance),
                table: table.clone(),
                needs: registration_needs,
                accept,
            });
            let walk: Arc<dyn PortUpstream> = Arc::new(walk);
            (Some(walk), Some(held), probes)
        }
        None => (None, None, None),
    };
    let channels = channels_of(shared, channel_budget.clone(), who, caller, port, held);
    let clock: Arc<dyn Fn() -> u64 + Send + Sync> =
        Arc::new(busbar_plugin_abi::host_side::host_vt::vt::mono);
    let carrier = PortCarrier::new(
        Arc::new(channels),
        table_upstreams,
        Arc::clone(&shared.signals),
        who.clone(),
        clock,
    );
    Ok(SeatWiring {
        request_routes,
        channel_budget,
        inventory_upstreams,
        inventory_targets,
        upstream,
        carrier: Arc::new(carrier),
        probes,
    })
}

#[cfg(test)]
#[path = "tests/plane_seats.rs"]
mod tests;
