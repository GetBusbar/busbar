// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use std::sync::Arc;

use busbar_kernel::plane_driver::registry::PlaneDecl;
use busbar_kernel::plane_driver::registry::PlaneDeclaration;
use busbar_kernel::plane_driver::EngineHost;
use busbar_kernel::preflight::{LinkedAuth, LinkedStore, RootInstall};

pub type Compose = Box<dyn FnOnce(&dyn busbar_contract::secret::SecretResolve) + Send>;

pub type CliHelpRow = (&'static str, &'static str);

pub struct Linked {
    pub plane_doors: &'static [busbar_contract::abi::mechanism::door::DoorFn],

    pub secrets: &'static [busbar_contract::abi::mechanism::door::DoorFn],

    pub secret_declares: &'static [(busbar_contract::abi::mechanism::door::DoorFn, &'static str)],

    pub plane_door_declares: &'static [(
        &'static str,
        busbar_contract::abi::mechanism::door::DoorFn,
        &'static str,
    )],

    pub protocol_seams: &'static [fn()],

    pub diagnostics: &'static [&'static [&'static busbar_contract::diagnostic::Diagnostic]],

    pub on_host: &'static [fn(&Arc<dyn EngineHost>)],

    pub compose: &'static [fn(&busbar_kernel::config::RootCfg) -> Option<Compose>],

    pub cli_help: &'static [&'static [CliHelpRow]],

    pub export_doors: &'static std::sync::LazyLock<Vec<LinkedDoorExport>>,

    pub stores: &'static std::sync::LazyLock<Vec<LinkedStore>>,

    pub hook_doors: &'static [busbar_contract::abi::mechanism::door::DoorFn],

    pub auths: &'static [LinkedAuth],

    pub transports: &'static [LinkedTransport],

    pub claims: &'static [LinkedClaims],

    /// The former names each linked store, auth, secret and plane door declares
    /// (`DoorDecl::FORMER_NAMES`), read by [`words_of`].
    pub former: &'static std::sync::LazyLock<Vec<LinkedFormer>>,
}

pub mod node {
    use std::sync::Arc;

    #[cfg(test)]
    use busbar_contract::caps::{OpClassId, PrincipalId};
    #[cfg(test)]
    use busbar_kernel::plane_driver::PlaneAnswer;
    #[cfg(test)]
    use busbar_kernel::teller::RouteAwait;

    pub type Resolve = Arc<dyn Fn(&str) -> Option<busbar_contract::LaneId> + Send + Sync>;

    #[cfg(test)]
    pub type Lent = (Resolve, u64);

    /// What a unit consumed: its usage, its fee count, its serving lane and its sealed
    /// attribution (`group`, `pool`, `provider`; ADMIN-API-1.6 §3.2).
    pub type Reported = (busbar_contract::billing::ExactUsage, u32, String, String);

    pub type Late = Box<dyn FnOnce() -> Option<Reported> + Send>;

    #[cfg(test)]
    pub type Finish = Box<dyn FnOnce() -> (Option<PlaneAnswer>, Option<Late>) + Send>;

    #[cfg(test)]
    pub type Built = (
        Arc<dyn busbar_kernel::teller::seats::SeatedUnits + Send + Sync>,
        Arc<dyn RouteAwait + Send + Sync>,
        Finish,
    );

    #[cfg(test)]
    pub type Build = Box<dyn FnOnce(Lent) -> Built + Send>;

    #[cfg(test)]
    pub(crate) type Handed = (PrincipalId, OpClassId, &'static str, Build);
}

/// One linked wire, as its door's Statement states it: the layers it declares, its claims (its
/// own, which is its registry key, first), its upgrade and first-line claims and the auth points it
/// offers. Every field is read
/// off the row's bare `door` (`linked_transport!`): no row reads a constant of its crate's, so a
/// door-root crate whose only public item is `door` (`BUSBAR-1.6.0.md` l.3560) links exactly as a
/// crate with a `linked` module does (l.3561: a linked row holds the same `door` pointer).
#[derive(Clone, Copy)]
pub struct LinkedTransport {
    /// The layers its door's tail declares, in the order it would take one.
    pub composes_over: LayersOf,
    /// Every scheme its entry claims, its own first: a door row's are read off the door's
    /// Statement (ONE ENTRY PER PLUGIN, the schemes are its claims), and the connector serves each.
    pub claims: ClaimsOf,
    /// The claims whose unit 0 opens at an UPGRADE, read off the door's Statement: the data door's
    /// upgrade lines (`crate::root::serve::upgrade_carriers`).
    pub upgrades: ClaimsOf,
    /// The claims whose unit 0 opens on the FIRST LINE, read off the door's Statement: the line
    /// carrier the process's own stdin/stdout serves (`crate::root::serve::lines::line_carrier`).
    pub lines: ClaimsOf,
    /// The auth points it offers, read off the door's Statement (`abi::transport::
    /// EXT_OFFERED_POINTS`): a guest-list line's auth may need no other (THE DESIGN §6 step 3).
    pub offered: OfferedOf,
}

pub type ClaimsOf = fn() -> Vec<&'static str>;

pub type LayersOf = fn() -> &'static [&'static str];

/// The linked transport row is built from its bare `door`: its layers are read once (the
/// Statement's name held equal to its own claim, the tail's `composes_over`), and its claims,
/// upgrade lines, first-line claims and offered points are read off the same door. The generated linked table expands one per `transport` row, so every
/// transport, whatever its crate exports beside `door`, is linked through this one path. Core alone
/// links no transport, so it expands nowhere there.
#[cfg(any(test, linked_transport_rows))]
macro_rules! linked_transport {
    ($door:path) => {{
        fn facts() -> &'static $crate::root::doors::RowFacts {
            static FACTS: ::std::sync::OnceLock<$crate::root::doors::RowFacts> =
                ::std::sync::OnceLock::new();
            FACTS.get_or_init(|| $crate::root::doors::row_facts($door))
        }
        fn composes_over() -> &'static [&'static str] {
            facts().composes_over.as_slice()
        }
        fn claims() -> ::std::vec::Vec<&'static str> {
            $crate::root::doors::claims_of($door)
        }
        fn upgrades() -> ::std::vec::Vec<&'static str> {
            $crate::root::doors::upgrades_of($door)
        }
        fn lines() -> ::std::vec::Vec<&'static str> {
            $crate::root::doors::lines_of($door)
        }
        fn offered() -> ::busbar_contract::abi::auth::AuthPoints {
            $crate::root::doors::offered_of($door)
        }
        $crate::root::linked::LinkedTransport {
            composes_over,
            claims,
            upgrades,
            lines,
            offered,
        }
    }};
}
#[cfg(any(test, linked_transport_rows))]
pub(crate) use linked_transport;

pub type OfferedOf = fn() -> busbar_contract::abi::auth::AuthPoints;

/// One linked plane's contribution to the boot seal: the pure plane registered under its own key,
/// and the claims that plane declares.
#[derive(Clone, Copy)]
pub struct LinkedClaims {
    /// The pure plane, as the seal's registry holds it.
    pub plane: fn() -> Arc<dyn busbar_contract::Plugin>,
    /// The bytes it claims.
    pub claims: &'static [busbar_contract::grammar::Claim],
}

/// A linked export sink on the export kind's MEMORY ABI: what its signed tarball states (its name,
/// its alias, the manifest `declares` section as JSON) and its door (`plugin_door!`), the same door
/// its `cdylib` exports.
#[derive(Clone, Copy)]
pub struct LinkedDoorExport {
    /// The plugin's name.
    pub name: &'static str,
    /// The module name an `export:` instance names it by.
    pub alias: &'static str,
    /// Its manifest `declares` section.
    pub declares: &'static str,
    /// Its door.
    pub door: busbar_contract::abi::mechanism::door::DoorFn,
    /// The names an earlier release answered to (its `FORMER_NAMES`); empty when it declares none.
    pub former_names: &'static [&'static str],
}

/// The words a linked door answers to besides its alias: its `FORMER_NAMES`, then the `from` of
/// each `REWRITE_ALIAS` rewrite its Statement states, as one list.
pub(crate) fn door_words(former: &[&str], rewrites: &[(u32, String, String)]) -> Vec<String> {
    let aliases = rewrites
        .iter()
        .filter(|(class, _, _)| *class == busbar_contract::abi::mechanism::door::REWRITE_ALIAS)
        .map(|(_, from, _)| from.clone());
    former
        .iter()
        .map(|word| (*word).to_string())
        .chain(aliases)
        .collect()
}

/// One linked door's declared former names, on a kind axis that registers by key or by name.
/// The generated table holds one per row that declares any (and one per store row).
#[derive(Clone, Copy)]
pub struct LinkedFormer {
    /// The axis: `store`, `auth`, `secret` or `plane`.
    pub axis: &'static str,
    /// The registry key the row answers on, or empty when the door's Statement name is the key.
    pub key: &'static str,
    /// The row's door: its Statement's `REWRITE_ALIAS` words join the former names.
    pub door: busbar_contract::abi::mechanism::door::DoorFn,
    /// The door's `FORMER_NAMES`.
    pub former_names: &'static [&'static str],
}

/// A door's Statement name and the rewrites it states; `None` when it does not read back.
fn door_statement(
    door: busbar_contract::abi::mechanism::door::DoorFn,
) -> Option<(String, Vec<(u32, String, String)>)> {
    let bytes = crate::root::loader::dispatch::rendering_of(door).ok()?;
    let statement = busbar_contract::abi::mechanism::rendering::read(&bytes).ok()?;
    Some((statement.name, statement.rewrites))
}

/// The words the linked row `key` on `axis` answers to besides its own: for each matching
/// [`LinkedFormer`], its door's `FORMER_NAMES` then its `REWRITE_ALIAS` words (`door_words`).
pub(crate) fn words_of(former: &[LinkedFormer], axis: &str, key: &str) -> Vec<String> {
    former
        .iter()
        .filter(|f| f.axis == axis)
        .filter_map(|f| {
            let (name, rewrites) = door_statement(f.door).unwrap_or_default();
            let row = if f.key.is_empty() {
                name.as_str()
            } else {
                f.key
            };
            (row == key).then(|| door_words(f.former_names, &rewrites))
        })
        .flatten()
        .collect()
}

fn export_abi() -> u32 {
    crate::root::loader::supported_abi("export").unwrap_or_default()
}

pub(crate) fn linked_exports(
    doors: &[LinkedDoorExport],
) -> Result<Vec<crate::root::loader::LinkedPlugin>, String> {
    let manifest = |name: &str, alias: &str, declares: &str| {
        let declares = crate::root::loader::sign::Declares::from_declares_json(declares.as_bytes())
            .map_err(|e| format!("linked export '{name}': its declares section: {e}"))?;
        Ok::<_, String>(crate::root::loader::sign::Manifest {
            name: name.into(),
            alias: alias.into(),
            kind: "export".into(),
            version: env!("CARGO_PKG_VERSION").into(),
            publisher: crate::root::loader::sign::FIRST_PARTY_PUBLISHER.into(),
            abi_version: export_abi(),
            sha256: String::new(),
            signature: String::new(),
            description: String::new(),
            homepage: String::new(),
            license: String::new(),
            needs: Default::default(),
            settings_schema: None,
            schema_derived: false,
            host: None,
            declares,
            statement: None,
            former_names: Vec::new(),
        })
    };
    let mut rows = doors
        .iter()
        .map(|d| {
            manifest(d.name, d.alias, d.declares).map(|m| {
                let rewrites = crate::root::loader::dispatch::rendering_of(d.door)
                    .ok()
                    .and_then(|bytes| busbar_contract::abi::mechanism::rendering::read(&bytes).ok())
                    .map(|statement| statement.rewrites)
                    .unwrap_or_default();
                crate::root::loader::LinkedPlugin::door(m, d.door)
                    .with_former_names(door_words(d.former_names, &rewrites))
            })
        })
        .collect::<Result<Vec<_>, String>>()?;

    let order = crate::root::migration_table::export_order();
    rows.sort_by_key(|p| {
        order
            .iter()
            .position(|m| *m == p.manifest.alias)
            .unwrap_or(usize::MAX)
    });
    Ok(rows)
}

pub struct RootUnit {
    pub seal: Option<fn() -> Result<(), String>>,

    pub on_config: Option<fn(&busbar_kernel::config::limits::LimitsResolved)>,

    #[cfg(test)]
    pub opens_book: bool,

    #[cfg(any(test, distribution_root))]
    pub on_book: Option<fn(&BookCtx<'_>)>,
}

#[cfg(any(test, distribution_root))]
pub struct BookCtx<'a> {
    pub book: &'a crate::root::durability::NodeBook,
    /// The app the book was opened for: what the mounted owner tests' steps read.
    #[cfg(test)]
    pub app: &'a busbar_kernel::state::App,
}

pub fn register_protocols(linked: &Linked) {
    for install in linked.protocol_seams {
        install();
    }
}

pub fn register_stores(linked: &Linked) {
    match link_secrets(linked.secrets, linked.secret_declares, linked.former) {
        Ok(secrets) => busbar_kernel::preflight::install_linked_rows(RootInstall {
            stores: linked.stores,
            registry_build: Some(crate::root::boot::registry_rows),
            endpoint_locate: Some(crate::root::boot::locate_provider_destination),
            plugins_fetch: Some(crate::root::boot::plugins_fetch),
            hook_axis: Some(crate::root::hooks::axis),
            hook_names: crate::LINKED_HOOK_NAMES,
            store_axis: Some(store_axis),
            secret_axis: Some(secrets),
            secret_admit: Some(crate::root::boot::admit_secrets),
            secret_snapshot: Some(secret_snapshot),

            rate_apply: Some(&crate::root::kernel::CardRepricer),
            rate_epoch: Some(&crate::root::kernel::CardRepricer),
            export_axis: Some(&crate::root::exports::EXPORTS),
            admission: Some(&crate::root::admission::ADMISSION),
            durable: Some(&crate::root::admission::DURABLE),
            plugin_logs: Some(crate::root::admission::plugin_logs),
            hook_answers: Some(crate::root::admission::hook_answers),
            auth_chain_module: Some(crate::root::admission::auth_chain_module),
            dispatch_latched: Some(crate::root::admission::dispatch_latched),
            auth_axis: Some(crate::root::dispatch::auth_axis),

            in_process_auth: None,
            config_projection: Some(crate::root::door_steps::door_config),
            grammar: Some(crate::root::boot::phase_one),
            admitted_grammar: Some(crate::root::boot::admitted_grammar),
        }),
        Err(refusal) => {
            eprintln!("busbar: {refusal}");
            crate::root::exit::exit(2);
        }
    }
}

fn store_axis() -> std::sync::Arc<dyn busbar_contract::persistence::axis::PersistenceAxis> {
    let conns: std::sync::Arc<dyn busbar_contract::conn::DeclaredConns> =
        crate::root::connector::the().clone();
    std::sync::Arc::new(crate::root::loader::store_v4::DoorPersistenceAxis {
        dispatcher: crate::root::dispatch::dispatcher(),
        logs: crate::root::boot::plugin_logs().clone(),
        conns: crate::root::loader::dispatch::ConnTable::Host(crate::root::connector::admit(conns)),
        // Resource admission for one crossing, not a persisted-record or transaction limit.
        // Includes descriptor overhead above the existing raw conditional carrier.
        limits: crate::root::loader::store_v4::Limits {
            descriptor_bytes: 512 * 1024 * 1024,
            output_items: (512 * 1024 * 1024)
                / std::mem::size_of::<busbar_contract::abi::store::v4::ReadValue>(),
            output_bytes: 512 * 1024 * 1024,
            decode_bytes: 512 * 1024 * 1024,
        },
    })
}

static SECRETS: std::sync::OnceLock<crate::root::loader::secret_calls::SecretRows> =
    std::sync::OnceLock::new();

pub(crate) fn link_secrets(
    doors: &[busbar_contract::abi::mechanism::door::DoorFn],
    declares: &[(busbar_contract::abi::mechanism::door::DoorFn, &str)],
    former: &[LinkedFormer],
) -> Result<&'static crate::root::loader::secret_calls::SecretRows, String> {
    if let Some(rows) = SECRETS.get() {
        return Ok(rows);
    }
    let rows = build_secrets(doors, declares, former)?;
    Ok(SECRETS.get_or_init(|| rows))
}

/// The secret rows over `doors`, each answering also to the words its [`LinkedFormer`] row gives.
pub(crate) fn build_secrets(
    doors: &[busbar_contract::abi::mechanism::door::DoorFn],
    declares: &[(busbar_contract::abi::mechanism::door::DoorFn, &str)],
    former: &[LinkedFormer],
) -> Result<crate::root::loader::secret_calls::SecretRows, String> {
    let mut rows = crate::root::loader::secret_calls::SecretRows::new(
        crate::root::dispatch::dispatcher,
        conns,
    )
    .with_logs(|| crate::root::boot::plugin_logs().clone())
    .with_disk_lane(disk_run);
    for door in doors {
        let name = door_statement(*door)
            .map(|(name, _)| name)
            .unwrap_or_default();
        rows.link_with_former(*door, &words_of(former, "secret", &name))
            .map_err(|e| format!("a linked secret plugin does not state itself: {e}"))?;
    }
    for (door, json) in declares {
        rows.declare_linked(*door, json)?;
    }
    Ok(rows)
}

static DISK: std::sync::OnceLock<std::sync::Arc<busbar_kernel::host_disk::DiskLane>> =
    std::sync::OnceLock::new();

pub(crate) fn disk_lane() -> std::sync::Arc<busbar_kernel::host_disk::DiskLane> {
    DISK.get_or_init(std::sync::Arc::default).clone()
}

fn disk_run(job: Box<dyn FnOnce() + Send>) -> Result<(), String> {
    disk_lane().run(job).map_err(str::to_string)
}

fn conns() -> Option<busbar_contract::conn::admissions::AdmissionAuthority> {
    crate::root::connector::installed().map(|one| {
        crate::root::connector::admit(
            std::sync::Arc::clone(one) as std::sync::Arc<dyn busbar_contract::conn::DeclaredConns>
        )
    })
}

/// Takes the dropped-in secret set a config transaction found; the returned restore puts it back if
/// the transaction publishes nothing ([`busbar_kernel::preflight::RootInstall::secret_snapshot`]).
fn secret_snapshot() -> busbar_kernel::preflight::SecretRestoreFn {
    let found = secret_rows().dropped();
    Box::new(move || {
        secret_rows().restore_if_changed(found);
    })
}

/// The process's one secret axis: this build's linked secret sources, whichever reader asks first.
/// It is never an unlinked set, so a reader that runs before boot publishes the axis reads the
/// same admitted source declarations boot does.
pub fn secret_rows() -> &'static crate::root::loader::secret_calls::SecretRows {
    link_secrets(
        crate::LINKED.secrets,
        crate::LINKED.secret_declares,
        crate::LINKED.former,
    )
    .unwrap_or_else(|refusal| {
        eprintln!("busbar: {refusal}");
        crate::root::exit::exit(2);
    })
}

pub fn register_planes() {
    match plane_rows() {
        Ok(rows) => busbar_kernel::plane_driver::registry::install_planes(rows.leak()),
        Err(refusal) => {
            eprintln!("busbar: {refusal}");
            crate::root::exit::exit(2);
        }
    }
}

fn plane_rows() -> Result<Vec<&'static PlaneDecl>, String> {
    let rows = door_rows()?;
    let declared: Vec<&PlaneDeclaration> = rows.iter().map(|d| &d.declaration).collect();
    busbar_contract::plane::check_metric_families(&declared, PLANE_CARRIED_SERIES)?;
    busbar_contract::plane::check_served_op_classes(&declared)?;
    Ok(rows)
}

pub(crate) fn refuse_a_key_two_doors_register(named: &[(String, &str)]) -> Result<(), String> {
    for (i, (name, key)) in named.iter().enumerate() {
        if let Some((first, _)) = named[..i].iter().find(|(_, k)| k == key) {
            return Err(format!(
                "the plane door rows `{first}` and `{name}` both register the plane `{key}` on \
                 the same axis; one row owns an axis's key"
            ));
        }
    }
    Ok(())
}

pub(crate) fn door_probe_dispatcher() -> Arc<crate::root::loader::dispatch::Dispatcher> {
    crate::root::dispatch::dispatcher()
}

fn door_rows() -> Result<Vec<&'static PlaneDecl>, String> {
    let doors = crate::root::boot::DOOR_CANDIDATES
        .get()
        .map_or(&[][..], Vec::as_slice);
    if doors.is_empty() {
        return Ok(Vec::new());
    }

    let probe = door_probe_dispatcher();
    let registrations = doors
        .iter()
        .map(|candidate| {
            let name = candidate.name.clone();
            let bound = candidate.clone();
            let probe = Arc::clone(&probe);
            let bind: crate::root::loader::dispatch::kinds::plane::ProbeBind =
                Arc::new(move || {
                    if matches!(
                        &bound.origin,
                        crate::root::loader::boot::Origin::Dropped { .. }
                    ) {
                        crate::root::boot::authorize_early_plugin(&bound.name)?;
                    }
                    crate::root::loader::boot::load_planes(
                        std::slice::from_ref(&bound),
                        crate::root::boot::plugin_logs(),
                        Arc::new(crate::root::loader::dispatch::NoSink),
                        probe.adopter(),
                        u32::MAX,
                        crate::root::loader::dispatch::ConnTable::Probe,
                    )?
                    .into_iter()
                    .next()
                    .map(|(_, plane)| plane)
                    .ok_or_else(|| format!("{}: the door bound nothing", bound.name))
                });
            Ok((
                name,
                crate::root::loader::dispatch::kinds::plane::stated_registration(candidate, bind)?,
            ))
        })
        .collect::<Result<Vec<_>, String>>()?;
    let named: Vec<(String, &str)> = (registrations.iter())
        .map(|(name, reg)| (name.clone(), reg.key))
        .collect();
    refuse_a_key_two_doors_register(&named)?;
    registrations
        .into_iter()
        .map(|(_, reg)| busbar_kernel::plane_driver::door::fold(reg))
        .collect()
}

pub(crate) const PLANE_CARRIED_SERIES: &[(&str, &[&str])] = &[
    (
        "busbar_requests_total",
        &["ingress_protocol", "pool", "outcome"],
    ),
    ("busbar_upstream_attempts_total", &["pool", "lane"]),
    (
        "busbar_upstream_failures_total",
        &["pool", "lane", "disposition"],
    ),
    ("busbar_breaker_trips_total", &["pool", "lane"]),
    ("busbar_failovers_total", &["pool", "reason"]),
    ("busbar_translations_total", &["from", "to"]),
    ("busbar_route_policy_selections_total", &["policy", "pool"]),
    (
        "busbar_route_policy_rejections_total",
        &["policy", "pool", "status"],
    ),
    ("busbar_billing_truncated_total", &[]),
    ("busbar_tap_notifications_dropped_total", &[]),
    ("busbar_webhook_logs_dropped_total", &[]),
    ("busbar_file_logs_dropped_total", &[]),
    (
        "busbar_billing_tap_decode_fail_total",
        &["protocol", "reason"],
    ),
];

pub(crate) fn register_exports(dropped: Option<&'static crate::root::loader::PluginRegistry>) {
    let _ = crate::root::dispatch::dispatcher()
        .observing()
        .install_host_series(host_series);
    if let Some(registry) = dropped {
        let _ = DROPPED.set(registry);
    }
}

pub(crate) fn dropped() -> Option<&'static crate::root::loader::PluginRegistry> {
    DROPPED.get().copied()
}

pub fn plane_door_declares(
    linked: &Linked,
) -> Vec<(
    &'static str,
    busbar_contract::abi::mechanism::door::DoorFn,
    &'static str,
)> {
    linked.plane_door_declares.to_vec()
}

pub(crate) fn door_breaker(
    linked: &Linked,
    dropped: Option<&crate::root::loader::PluginRegistry>,
    plane: &str,
) -> Result<Option<crate::root::loader::sign::BreakerDecl>, String> {
    for (row, door, json) in &plane_door_declares(linked) {
        let stated = crate::root::loader::dispatch::LinkedRow::of(*door)
            .map_err(|e| format!("plugin '{row}': {e}"))?;
        let name = busbar_contract::abi::mechanism::rendering::read(&stated.statement)
            .map_err(|e| {
                format!(
                    "plugin '{row}': its Statement rendering does not read back at byte {}",
                    e.at
                )
            })?
            .name;
        if name != plane {
            continue;
        }
        let declares = crate::root::loader::sign::Declares::from_declares_json(json.as_bytes())
            .map_err(|e| {
                format!("plugin '{row}' states a `declares` section that does not read: {e}")
            })?;
        return Ok(declares.breaker);
    }
    let Some(registry) = dropped else {
        return Ok(None);
    };
    let planes = registry.loadable().iter();
    for p in planes.filter(|p| p.manifest.kind == busbar_contract::abi::mechanism::kind::PLANE) {
        let Some(stated) = p
            .manifest
            .stated()
            .map_err(|e| format!("plugin '{}': {e}", p.manifest.name))?
        else {
            continue;
        };
        if stated.name == plane {
            return Ok(p.manifest.declares.breaker);
        }
    }
    Ok(None)
}

pub(crate) fn logs() -> &'static crate::root::loader::dispatch::PluginLogConfig {
    crate::root::boot::plugin_logs()
}

pub(crate) const HOST_SERIES: &[&str] = &[
    busbar_kernel::snapshot::ROUTE_POLICY_SELECTIONS_TOTAL,
    busbar_kernel::snapshot::ROUTE_POLICY_REJECTIONS_TOTAL,
    busbar_kernel::snapshot::HOOK_CONTENT_TRUNCATED_TOTAL,
    busbar_kernel::snapshot::HOOK_PROJECT_OVER_CAP_TOTAL,
    busbar_kernel::snapshot::BILLING_TRUNCATED_TOTAL,
    busbar_kernel::snapshot::PLUGIN_OBSERVATIONS_DROPPED_TOTAL,
    busbar_kernel::snapshot::PLUGIN_TEXT_CUT_TOTAL,
    busbar_kernel::snapshot::JOURNAL_QUARANTINED_TOTAL,
    busbar_kernel::snapshot::STORE_SLOTS,
    busbar_kernel::snapshot::REQUESTS_TOTAL,
    busbar_kernel::snapshot::BREAKER_TRIPS_TOTAL,
    busbar_kernel::snapshot::FAILOVERS_TOTAL,
    busbar_kernel::snapshot::REQUEST_DURATION_SECONDS,
    busbar_kernel::snapshot::TRANSLATIONS_TOTAL,
    busbar_kernel::snapshot::PLANE_REQUESTS_TOTAL,
    busbar_kernel::snapshot::PLANE_REQUEST_DURATION_SECONDS,
    busbar_kernel::snapshot::LANE_REQUEST_DURATION_SECONDS,
    busbar_kernel::snapshot::UNIT_REFUSALS_TOTAL,
    busbar_kernel::snapshot::BUILD_INFO,
    busbar_kernel::snapshot::ADMISSION_DENIED_TOTAL,
    busbar_kernel::snapshot::METERING_PENDING_COALESCED_TOTAL,
    busbar_kernel::snapshot::PLUGIN_REQUEST_HEADERS_TRUNCATED_TOTAL,
    busbar_kernel::snapshot::PLUGIN_RESPONSE_HEADERS_REJECTED_TOTAL,
    busbar_kernel::snapshot::PLUGIN_LABEL_REFUSED_TOTAL,
    busbar_kernel::snapshot::TELEMETRY_OVERFLOW_REPLAYS_TOTAL,
    busbar_kernel::snapshot::KEY_SPEND_CENTS,
    busbar_kernel::snapshot::KEY_TOKENS_TOTAL,
    busbar_kernel::snapshot::BUCKET_TOKENS,
    busbar_kernel::snapshot::BUCKET_SPEND_CENTS,
    busbar_kernel::snapshot::BUCKET_BUDGET_REMAINING_CENTS,
    busbar_kernel::snapshot::LANE_STATE,
    busbar_kernel::snapshot::LANE_AVAILABLE,
    busbar_kernel::snapshot::LANE_RECOVERY_HINT_MS,
    busbar_kernel::snapshot::LANE_INFLIGHT,
    busbar_kernel::snapshot::LANE_AVAILABLE_PERMITS,
    busbar_kernel::snapshot::POOL_QUEUED,
    busbar_kernel::telemetry::UPSTREAM_ATTEMPTS_TOTAL,
    busbar_kernel::telemetry::UPSTREAM_FAILURES_TOTAL,
    busbar_kernel::snapshot::BILLING_TAP_DECODE_FAIL_TOTAL,
    "busbar_tap_notifications_dropped_total",
];

pub(crate) fn host_series(name: &str) -> bool {
    let base = ["_sum", "_count", "_bucket"]
        .iter()
        .find_map(|suffix| name.strip_suffix(suffix));
    HOST_SERIES.iter().any(|s| *s == name || Some(*s) == base)
}

static DROPPED: std::sync::OnceLock<&'static crate::root::loader::PluginRegistry> =
    std::sync::OnceLock::new();

static CATALOGUE: std::sync::OnceLock<busbar_kernel::diagnostics::Catalogue> =
    std::sync::OnceLock::new();

pub(crate) fn catalogue() -> busbar_kernel::diagnostics::Catalogue {
    CATALOGUE
        .get()
        .copied()
        .unwrap_or(busbar_kernel::diagnostics::Catalogue::NEUTRAL)
}

pub fn register_diagnostics(linked: &Linked) -> busbar_kernel::diagnostics::Catalogue {
    let mut installed: Vec<&'static busbar_contract::diagnostic::Diagnostic> = linked
        .diagnostics
        .iter()
        .flat_map(|diags| diags.iter().copied())
        .collect();
    match door_declared_diagnostics(&plane_door_declares(linked), &installed) {
        Ok(declared) => installed.extend(declared),
        Err(refusal) => {
            eprintln!("busbar: {refusal}");
            crate::root::exit::exit(2);
        }
    }
    let declared = catalogue_registry(linked, DROPPED.get().copied())
        .and_then(|registry| declared_diagnostics(&registry, &installed));
    match declared {
        Ok(declared) => installed.extend(declared),
        Err(refusal) => {
            eprintln!("busbar: {refusal}");
            crate::root::exit::exit(2);
        }
    }
    let catalogue = busbar_kernel::diagnostics::Catalogue::lent(installed.leak());
    let _ = CATALOGUE.set(catalogue);
    catalogue
}

pub(crate) fn declared_diagnostics(
    registry: &crate::root::loader::PluginRegistry,
    taken: &[&'static busbar_contract::diagnostic::Diagnostic],
) -> Result<Vec<&'static busbar_contract::diagnostic::Diagnostic>, String> {
    let mut declared = Vec::new();
    for p in registry.linked().iter().chain(registry.loadable()) {
        let name = p.key();
        let declarations = p.declarations().map_err(|e| {
            format!("plugin '{name}' states a `declares` section that does not read: {e}")
        })?;
        let decls = &declarations.diagnostics;
        if !decls.is_empty() && !p.first_party() {
            return Err(format!(
                "plugin '{name}' declares diagnostics but is not first-party; only a first-party \
                 plugin's codes join the catalogue"
            ));
        }
        let held: Vec<_> = taken.iter().chain(&declared).copied().collect();
        declared.extend(catalogue_entries(name, decls, &held)?);
    }
    Ok(declared)
}

#[cfg(test)]
pub(crate) fn linked_declared_diagnostics(
    linked: &Linked,
    taken: &[&'static busbar_contract::diagnostic::Diagnostic],
) -> Result<Vec<&'static busbar_contract::diagnostic::Diagnostic>, String> {
    declared_diagnostics(&catalogue_registry(linked, None)?, taken)
}

fn catalogue_registry(
    linked: &Linked,
    scanned: Option<&crate::root::loader::PluginRegistry>,
) -> Result<crate::root::loader::PluginRegistry, String> {
    use crate::root::loader::{LinkedPlugin, PluginRegistry};

    let mut rows: Vec<_> = linked
        .auths
        .iter()
        .map(|(key, canonical, door)| {
            LinkedPlugin::auth_door_named(canonical, key, *door).with_former_names(words_of(
                linked.former,
                "auth",
                key,
            ))
        })
        .collect();
    for door in linked.hook_doors {
        let stated =
            crate::root::loader::dispatch::LinkedRow::of(*door).map_err(|e| e.to_string())?;
        let statement = busbar_contract::abi::mechanism::rendering::read(&stated.statement)
            .map_err(|e| format!("invalid linked hook Statement: {e:?}"))?;
        rows.push(LinkedPlugin::door_of_kind(
            busbar_contract::abi::mechanism::kind::HOOK,
            &statement.name,
            *door,
        ));
    }
    scanned
        .cloned()
        .unwrap_or_else(PluginRegistry::empty)
        .link(rows)
}

pub(crate) fn door_declared_diagnostics(
    doors: &[(
        &'static str,
        busbar_contract::abi::mechanism::door::DoorFn,
        &'static str,
    )],
    taken: &[&'static busbar_contract::diagnostic::Diagnostic],
) -> Result<Vec<&'static busbar_contract::diagnostic::Diagnostic>, String> {
    let mut declared = Vec::new();
    for (name, _, json) in doors {
        let declares = crate::root::loader::sign::Declares::from_declares_json(json.as_bytes())
            .map_err(|e| {
                format!("plugin '{name}' states a `declares` section that does not read: {e}")
            })?;
        let held: Vec<_> = taken.iter().chain(&declared).copied().collect();
        declared.extend(catalogue_entries(name, &declares.diagnostics, &held)?);
    }
    Ok(declared)
}

fn catalogue_entries(
    name: &str,
    decls: &[crate::root::loader::sign::DiagnosticDecl],
    held_already: &[&'static busbar_contract::diagnostic::Diagnostic],
) -> Result<Vec<&'static busbar_contract::diagnostic::Diagnostic>, String> {
    use busbar_contract::diagnostic::{Class, Diagnostic, Severity};
    use busbar_kernel::diagnostics::REGISTRY;
    let taken = held_already;
    let leak = |s: &str| -> &'static str { Box::leak(s.to_string().into_boxed_str()) };
    let mut declared: Vec<&'static Diagnostic> = Vec::new();
    {
        for d in decls {
            let refuse = |why: &str| {
                Err(format!(
                    "plugin '{name}' declares BUSBAR-{:04}: {why}",
                    d.code
                ))
            };
            let class = Class::ALL
                .into_iter()
                .find(|c| c.ordinal() == d.code / 1000);
            let severity = [
                Severity::BenignRecurring,
                Severity::Actionable,
                Severity::Fatal,
            ]
            .into_iter()
            .find(|s| s.as_str() == d.severity);
            let held = REGISTRY.iter().chain(taken).chain(&declared);
            let (Some(class), Some(severity)) = (class, severity) else {
                return refuse("its class or severity is not the host's");
            };
            if held.map(|h| h.code).any(|code| code == d.code) {
                return refuse("the catalogue already holds that code");
            }
            declared.push(Box::leak(Box::new(Diagnostic {
                code: d.code,
                class,
                slug: leak(&d.slug),
                title: leak(&d.title),
                severity,
                summary: leak(&d.summary),
                action: leak(&d.action),
                since: leak(&d.since),
                retired: false,
            })));
        }
    }
    Ok(declared)
}

pub fn seal(units: &[&RootUnit]) {
    for seal in units.iter().filter_map(|u| u.seal) {
        if let Err(refusal) = seal() {
            eprintln!("busbar: {refusal}");
            crate::root::exit::exit(2);
        }
    }
}

#[cfg(test)]
#[path = "tests/linked.rs"]
mod tests;

#[cfg(test)]
#[path = "tests/linked_secret_sources.rs"]
mod secret_source_tests;

#[cfg(all(test, linked_operator_auth, linked_section_pools))]
#[path = "tests/linked_auth.rs"]
mod auth_tests;

#[cfg(test)]
#[path = "tests/linked_canonical.rs"]
mod linked_canonical;

#[cfg(all(test, linked_every_plane_door))]
#[path = "tests/linked_protocols.rs"]
mod linked_protocols;

#[cfg(test)]
#[path = "tests/linked_store_double.rs"]
mod linked_store_double;

#[cfg(test)]
#[path = "tests/linked_declarations.rs"]
mod linked_declarations;
