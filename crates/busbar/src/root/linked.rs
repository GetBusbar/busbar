// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE ONE REGISTRATION PATH — every linked entry the composition root holds, folded into the
//! kernel's registration seams axis by axis, in the order the entries arrive.
//!
//! The root names no plugin. `build.rs` reads the manifest's `[package.metadata.busbar.linked]`
//! (cargo feature → plugin crate), `linked-axes` (crate → the registration axes it fills),
//! `linked-entry` and `root-units` tables and emits `$OUT_DIR/linked.rs`: `extern crate <crate> as _;`
//! for every ENABLED feature, [`Linked`] — one table per registration axis over each crate's
//! `linked` entry module — a `linked_*` cfg per root-bound seam an enabled entry drives, and the
//! `ROOT_UNITS` table of each enabled root module's [`RootUnit`]. `main.rs` includes it and hands the
//! tables to the functions below — and they are the SAME functions a plugin dropped into `plugins/`
//! feeds (#2 rule (1): compiled in or dropped in, same contract, same loading path). On the plane
//! axis that is literal: a plane door linked into the build and the same door dropped into
//! `plugins/` are both bound through the loader's one load and folded onto the axis by one fold.
//! Nothing here asks where a row came from.
//!
//! What a plugin STATES about itself (its plane declaration) is contract data; what the kernel RUNS
//! for it is typed by the kernel's own seams (its plane hooks, protocol declarations, arrivals,
//! diagnostics) — the split `PlaneDeclaration` / `PlaneHooks` already has, joined kernel-side by
//! `PlaneDecl::assemble` in the generated plane table. The kernel defines nothing for this path.
//!
//! Every function keeps the shape of the per-crate write it replaced: the same seam, called the same
//! number of times, with the same contributions in the same order — the table's order, which is the
//! manifest's, which is the order the root always registered in. A build with a feature off has no
//! row for it, so its axis gets nothing from it, exactly as the feature-gated line it replaces did.

use std::sync::Arc;

use busbar_kernel::ingress::arrival::BodyIngressEntry;
use busbar_kernel::plane::registry::PlaneDecl;
use busbar_kernel::plane::registry::PlaneDeclaration;
use busbar_kernel::plane_driver::EngineHost;
use busbar_kernel::preflight::{LinkedAuth, LinkedStore, RootInstall};

/// A provider composition step, captured off the resolved configuration before the app is built and
/// run once the deployment's secret resolver exists.
pub type Compose = Box<dyn FnOnce(&dyn busbar_contract::secret::SecretResolve)>;

/// One row a plane declares for `busbar --help`: `(slot, text)`. Slot `"tagline"` is the one-line
/// description the help opens with; slot `"flag"` is a row of the `Flags:` block, whose first word is
/// a flag the binary accepts; slot `"endpoint"` is a row of the `ENDPOINTS` block. A plane compiled
/// out contributes no row, so its lines leave the help with it, the same way its config section is
/// refused.
pub type CliHelpRow = (&'static str, &'static str);

/// EVERY LINKED ENTRY'S ITEMS, one table per registration axis, in manifest order.
pub struct Linked {
    /// The plane axis: each entry's contract declaration joined kernel-side to its hooks.
    pub planes: &'static [PlaneDecl],
    /// The plane axis, door lane: each linked plane's door (`busbar_plugin_door`), bound through the
    /// one load on the process's dispatcher exactly as the same plane dropped into `plugins/` is
    /// (see [`crate::root::boot::load_door_planes`]).
    pub plane_doors: &'static [busbar_contract::abi::mechanism::door::DoorFn],
    /// The secret axis: each linked secret plugin's door, loaded through the one loader when a
    /// reference first names it (see [`secret_rows`]).
    pub secrets: &'static [busbar_contract::abi::mechanism::door::DoorFn],
    /// Each plane door row's place among [`Linked::planes`] (how many plane rows precede it in
    /// manifest order), parallel to [`Linked::plane_doors`]: where its folded registry row goes.
    pub plane_door_slots: &'static [usize],
    /// Each linked secret door's DECLARED METADATA, `(door, declares)`: its `declares.json` (named by
    /// `[package.metadata.busbar.linked-declares]`), read as a dropped-in copy's signed `declares`
    /// is — its disk need (THE DESIGN §11.11 R4). A door with no row declares none.
    pub secret_declares: &'static [(busbar_contract::abi::mechanism::door::DoorFn, &'static str)],
    /// Each linked plane door's DECLARED METADATA, `(row, door, declares)`: its manifest `declares`
    /// section as JSON (the crate's `declares.json`, named by `[package.metadata.busbar.linked-declares]`),
    /// read as every default-linked plugin's is, beside the door it belongs to. A linked door is
    /// first-party.
    pub plane_door_declares: &'static [(
        &'static str,
        busbar_contract::abi::mechanism::door::DoorFn,
        &'static str,
    )],
    /// Protocol declarations, appended to the installed protocol set in this order.
    pub protocols:
        &'static [&'static [&'static busbar_kernel::ingress::protocols::ProtocolDecl]],
    /// Body-model arrivals, by protocol name.
    pub body_ingress: &'static [&'static [BodyIngressEntry]],
    /// Installers of the protocol-axis seams an entry provides beside its declarations (a completion
    /// synthesizer, a stream-translator factory), each set once.
    pub protocol_seams: &'static [fn()],
    /// Owned diagnostics, joining the rendered catalog.
    pub diagnostics: &'static [&'static [&'static busbar_contract::diagnostic::Diagnostic]],
    /// Background work re-anchored on every generation's engine host (boot, then each swap).
    pub on_host: &'static [fn(&Arc<dyn EngineHost>)],
    /// Providers composed off the resolved configuration (see [`Compose`]).
    pub compose: &'static [fn(&busbar_kernel::config::RootCfg) -> Option<Compose>],
    /// The CLI-help axis: each linked plane's rows of `busbar --help` (see [`CliHelpRow`]).
    pub cli_help: &'static [&'static [CliHelpRow]],
    /// The export axis on the memory ABI: each linked export sink's statement and door (see
    /// [`LinkedDoorExport`]), built on first read (a door-root row's facts are its Statement's,
    /// `crate::root::door_root::export_row`); a reference to it is the slice every reader takes.
    pub export_doors: &'static std::sync::LazyLock<Vec<LinkedDoorExport>>,
    /// The store axis: each linked store's `(key, ephemeral, door, canonical)`, built on first read
    /// (a door-root row's facts are its Statement's, `crate::root::door_root::store_row`).
    pub stores: &'static std::sync::LazyLock<Vec<LinkedStore>>,
    /// Every DOOR-ROOT row (`[package.metadata.busbar.door-root]`), checked against its door's
    /// Statement before anything registers (`crate::root::door_root::check`).
    pub door_roots: &'static [crate::root::door_root::DoorRoot],
    /// The hook axis: each linked `kind: hook` row's door, bound through the one loader path by the
    /// root's hook axis (`crate::root::hooks`).
    pub hook_doors: &'static [busbar_contract::abi::mechanism::door::DoorFn],
    /// The auth axis: each linked `kind: auth` plugin's `(registry key, SDK boundary)`.
    pub auths: &'static [LinkedAuth],
    /// The operator credential's provider word: the key the manifest's operator row states
    /// (`[package.metadata.busbar.operator-auth]`), linked in this build or not.
    pub operator_auth: &'static str,
    /// The transport axis (#3, #30): each linked wire's key, declared layers and build, each read off
    /// its door's Statement (`linked_transport!`), in manifest order — the boot seal folds them
    /// bottom-up (see `crate::root::registry`).
    pub transports: &'static [LinkedTransport],
    /// Each linked plane's pure plane, as the boot seal registers it, and the claims it declares.
    pub claims: &'static [LinkedClaims],
    /// The node axis: each entry whose arrivals hand their units to a node, handed the node a root
    /// unit drives them through (see [`node`]).
    pub node: &'static [fn(node::Drive)],
}

/// THE NODE AXIS — what crosses between a plane whose arrivals hand their units to a node and the
/// node that drives them through the kernel's loop. Plain values in the loop's own vocabulary, so
/// neither side names the other: an arrival hands the node whose unit it is, its operation class, the
/// dialect a node-side refusal is written in, and a build; the node lends the build its lane
/// resolver, the loop's meter and the unit's pinned arrival epoch, and gets back the unit's steps,
/// its awaited Route leg and its finish — the terminal's bytes and the reading of what they consumed,
/// taken once their body has drained. The reading is a report, never an amount.
pub mod node {
    use std::future::Future;
    use std::pin::Pin;
    use std::sync::Arc;

    use busbar_contract::caps::{OpClassId, PrincipalId};
    use busbar_kernel::plane_driver::PlaneAnswer;
    use busbar_kernel::teller::{RouteAwait, Units};

    /// A configured lane name to the interned lane the priced axis is written in, or `None` where
    /// the image's vocabulary cannot hold the name.
    pub type Resolve = Arc<dyn Fn(&str) -> Option<busbar_contract::LaneId> + Send + Sync>;
    /// What the node lends a build: its lane resolver and the pinned arrival epoch.
    pub type Lent = (Resolve, u64);
    /// What a unit consumed, read after its body drained: every class, the billable count, the
    /// serving lane's config name.
    pub type Reported = (busbar_contract::billing::Usage, u32, String);
    /// The late reading, taken once, when the body is done with.
    pub type Late = Box<dyn FnOnce() -> Option<Reported> + Send>;
    /// A unit's finish: the answer its terminal posted (#28), and the late reading of what it
    /// consumed. The node turns the answer into the served response on its audited exit.
    pub type Finish = Box<dyn FnOnce() -> (Option<PlaneAnswer>, Option<Late>) + Send>;
    /// A built unit: its steps, its awaited Route leg (the same unit), and its finish.
    pub type Built = (
        Arc<dyn Units + Send + Sync>,
        Arc<dyn RouteAwait + Send + Sync>,
        Finish,
    );
    /// The build the node runs once it holds the values it lends.
    pub type Build = Box<dyn FnOnce(Lent) -> Built + Send>;
    /// One arrival, handed to the node.
    pub type Handed = (PrincipalId, OpClassId, &'static str, Build);
    /// The node: takes a handed unit, drives it through the loop, answers with its terminal's answer.
    pub type Drive = fn(Handed) -> Pin<Box<dyn Future<Output = PlaneAnswer> + Send>>;
}

/// One linked wire, as its door's Statement states it: the registry key, the layers it declares it
/// can be built over, and its build, handed the deployment's transport settings. Every field is read
/// off the row's bare `door` (`linked_transport!`): no row reads a constant of its crate's, so a
/// door-root crate whose only public item is `door` (`BUSBAR-1.6.0.md` l.3560) links exactly as a
/// crate with a `linked` module does (l.3561: a linked row holds the same `door` pointer).
#[derive(Clone, Copy)]
pub struct LinkedTransport {
    /// The wire's registry key: its door's own claim, which is its Statement's name.
    pub key: KeyOf,
    /// The layers its door's tail declares, in the order it would take one.
    pub composes_over: LayersOf,
    /// Open the row's door and serve it over the host's sockets (it is handed no layer: no transport
    /// names another).
    pub build: BuildTransport,
    /// Every scheme its entry claims, its own first: a door row's are read off the door's
    /// Statement (ONE ENTRY PER PLUGIN, the schemes are its claims), and the seal registers each.
    pub claims: ClaimsOf,
    /// The claims whose unit 0 opens at an UPGRADE, read off the door's Statement: the data door's
    /// upgrade lines (`crate::root::serve::upgrade_carriers`; ARCHITECT ruling Q128 U7).
    pub upgrades: ClaimsOf,
    /// The claims whose unit 0 opens on the FIRST LINE, read off the door's Statement: the line
    /// carrier the process's own stdin/stdout serves (`crate::root::serve::lines::line_carrier`).
    pub lines: ClaimsOf,
    /// The auth points it offers, read off the door's Statement (`abi::transport::
    /// EXT_OFFERED_POINTS`): a guest-list line's auth may need no other (THE DESIGN §6 step 3).
    pub offered: OfferedOf,
}

/// A row's claims, read when the seal runs.
pub type ClaimsOf = fn() -> Vec<&'static str>;

/// A row's registry key, read off its door's Statement when the seal first asks for it.
pub type KeyOf = fn() -> &'static str;

/// A row's declared layers, read off its door's transport tail when the seal first asks for them.
pub type LayersOf = fn() -> &'static [&'static str];

/// THE ONE LINKED TRANSPORT ROW, built from its bare `door` and nothing else (`BUSBAR-1.6.0.md`
/// l.3560-3561; coordinator ruling (b) on row 159): the row's key, layers and session are read once
/// off the door's Statement by the loader's one reader (`crate::root::doors::row_facts`: the
/// Statement's name held equal to its own claim, the tail's `composes_over`, the claim rows'
/// `session`), and its build, claims, upgrade lines, first-line claims and offered points are read
/// off the same door. The generated linked table expands one per `transport` row, so every
/// transport, whatever its crate exports beside `door`, is linked through this one path. Core alone
/// links no transport, so it expands nowhere there.
#[allow(unused_macros)]
macro_rules! linked_transport {
    ($door:path) => {{
        fn facts() -> &'static $crate::root::doors::RowFacts {
            static FACTS: ::std::sync::OnceLock<$crate::root::doors::RowFacts> =
                ::std::sync::OnceLock::new();
            FACTS.get_or_init(|| $crate::root::doors::row_facts($door))
        }
        fn key() -> &'static str {
            facts().key
        }
        fn composes_over() -> &'static [&'static str] {
            facts().composes_over.as_slice()
        }
        fn build(
            settings: &::busbar_contract::transport::TransportSettings,
        ) -> ::std::sync::Arc<::busbar_core_connector::wire::HostWire> {
            $crate::root::doors::build(key(), $door, settings)
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
            key,
            composes_over,
            build,
            claims,
            upgrades,
            lines,
            offered,
        }
    }};
}
#[allow(unused_imports)]
pub(crate) use linked_transport;

/// A row's offered auth points, read when the guest lists seal.
pub type OfferedOf = fn() -> busbar_contract::abi::auth::AuthPoints;

/// A wire's build: handed the deployment's settings, it opens the row's door and answers the boot's
/// admission of it (`HostWire::new`: a claim, no layer).
pub type BuildTransport = fn(
    &busbar_contract::transport::TransportSettings,
) -> Arc<busbar_core_connector::wire::HostWire>;

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
}

/// The newest export payload schema this binary speaks — what a linked sink states.
fn export_abi() -> u32 {
    let supported = crate::root::loader::supported_abi("export");
    supported.iter().copied().max().unwrap_or_default()
}

/// The registry rows the linked export sinks state: first-party manifests of `kind: export` at this
/// binary's payload schema, exactly what a release-signed tarball of each carries but `sha256` and
/// `signature`, which describe a file a linked row does not have.
pub fn linked_exports(
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
            manifest(d.name, d.alias, d.declares)
                .map(|m| crate::root::loader::LinkedPlugin::door(m, d.door))
                .map(crate::root::boot::answering_former_names)
        })
        .collect::<Result<Vec<_>, String>>()?;
    // In 1.5.5's order (the root legacy table's `export_modules`, the order 1.5.5 listed its
    // built-in exporters in), so the kernel's unknown-exporter refusal, which lists the linked rows
    // in registration order, reads as 1.5.5's did. A row the table does not name follows, in place.
    let order = crate::root::legacy::export_order();
    rows.sort_by_key(|p| {
        order
            .iter()
            .position(|m| *m == p.manifest.alias)
            .unwrap_or(usize::MAX)
    });
    Ok(rows)
}

/// What the composition root wires for one of its own unit modules — the kernel-loop half of a plane
/// that still lives in the root. Addressed through the same generated tables as a plugin: the module
/// exports a `ROOT_UNIT` of this type, the manifest maps the cargo feature that compiles the module
/// to it, and the root's source names neither.
pub struct RootUnit {
    /// The boot-time self-check of what this unit composes. `Err` carries the refusal as the operator
    /// reads it after `busbar: `; the process exits 2 before any listener binds.
    pub seal: Option<fn() -> Result<(), String>>,
    /// The node this unit drives the node axis's units through, handed to every entry on that axis.
    pub drive: Option<node::Drive>,
    /// Runs once the deployment's limits are resolved, before the app is built.
    pub on_config: Option<fn(&busbar_kernel::config::limits::LimitsResolved)>,
    /// TRUE for a unit that settles onto the node's book: the book is opened for it.
    pub opens_book: bool,
    /// Runs once the node's book is open, before any listener binds.
    pub on_book: Option<fn(&BookCtx<'_>)>,
    /// The posting site a door plane's driven unit posts its abandoned end onto: the node's book
    /// this unit settles on (`root::serve::compose_planes`' money seam). `None`: this unit keeps no
    /// such book.
    pub end_post: Option<fn() -> std::sync::Arc<dyn busbar_kernel::plane_driver::EndPost>>,
}

/// What a unit's [`RootUnit::on_book`] step is handed: the node's one book and the boot generation.
/// No secret resolver and no listener TLS block: the listeners' material is resolved by the path
/// that serves them, once, and a book step has no second reading of it to make.
pub struct BookCtx<'a> {
    /// The process's one book, opening already sealed.
    pub book: &'a crate::root::durability::NodeBook,
    /// The boot generation.
    pub app: &'a busbar_kernel::state::App,
}

/// THE PROTOCOL AXIS: every entry's declarations and its body-model arrivals, then each entry's
/// protocol-axis seams. A dialect whose model rides the URL has no arrival here: its plane's door
/// claims and serves those paths (ARCHITECT 2026-10-16 ruling 3 item 1). Then the node axis, which
/// those arrivals hand their units to: every entry on it is handed the node a root unit drives it
/// through.
pub fn register_protocols(linked: &Linked, units: &[&RootUnit]) {
    let installed: Vec<&'static busbar_kernel::ingress::protocols::ProtocolDecl> = linked
        .protocols
        .iter()
        .flat_map(|decls| decls.iter().copied())
        .collect();
    busbar_kernel::ingress::protocols::install_protocols(installed);
    let body_ingress: Vec<BodyIngressEntry> = linked
        .body_ingress
        .iter()
        .flat_map(|arrivals| arrivals.iter().copied())
        .collect();
    busbar_kernel::ingress::arrival::install_body_ingress(body_ingress);
    for install in linked.protocol_seams {
        install();
    }
    for drive in units.iter().filter_map(|u| u.drive) {
        for install in linked.node {
            install(drive);
        }
    }
}

/// THE STORE, HOOK AND SECRET AXES: the linked store and hook rows onto the kernel's cold-kind axis,
/// and the secret axis ([`secret_rows`]), on the root's one install record with the auth-axis
/// opener (`crate::root::dispatch::auth_axis`) and the projection the door planes are sealed over,
/// taken of every configuration as it is built (`crate::root::door_steps::door_config`), so a
/// config apply refreshes them onto the new generation. No row is a default store: the store is
/// the one config names (Q-STORE = (B)). A linked secret door that does not state itself refuses
/// the boot (exit 2) before anything resolves a store or a secret.
pub fn register_stores(linked: &Linked) {
    let declared: Vec<(busbar_contract::abi::mechanism::door::DoorFn, &str)> = linked
        .secret_declares
        .iter()
        .copied()
        .chain(
            crate::root::door_root::declared(linked.door_roots, "secret-doors")
                .into_iter()
                .map(|(_, door, json)| (door, json)),
        )
        .collect();
    match link_secrets(linked.secrets, &declared) {
        Ok(secrets) => busbar_kernel::preflight::install_linked_rows(RootInstall {
            stores: linked.stores,
            registry_build: Some(crate::root::boot::registry_rows),
            plugins_fetch: Some(crate::root::boot::plugins_fetch),
            hook_axis: Some(crate::root::hooks::axis),
            hook_names: crate::LINKED_HOOK_NAMES,
            store_axis: Some(store_axis),
            secret_axis: Some(secrets),
            secret_admit: Some(crate::root::boot::admit_secrets),
            // The root's card repricer is the kernel's rate holder and dater (the node unit, in
            // every build's root-unit table, arms its journal before the boot resolution:
            // `crate::root::kernel::install_card_repricer`).
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
            config_projection: Some(crate::root::door_steps::door_config),
        }),
        Err(refusal) => {
            eprintln!("busbar: {refusal}");
            std::process::exit(2);
        }
    }
}

/// THE STORE AXIS the kernel opens its governance store through (WIRE-STORE Q8/Q9): the loader's
/// axis over the process's ONE dispatcher (`root::dispatch`, built at boot before the configuration
/// is applied), each store instance logging under the configured `plugins.logs`, its needs declared
/// on the process's one connection table, its bridge writes minted by the kernel's one `op_id`
/// allocator.
fn store_axis() -> std::sync::Arc<dyn busbar_contract::store_calls::StoreAxis> {
    let conns: std::sync::Arc<dyn busbar_contract::conn::DeclaredConns> =
        crate::root::connector::the().clone();
    std::sync::Arc::new(crate::root::loader::store_v3::DoorStoreAxis {
        dispatcher: crate::root::dispatch::dispatcher(),
        logs: crate::root::boot::plugin_logs().clone(),
        conns: crate::root::loader::dispatch::ConnTable::Host(conns),
        mint: busbar_kernel::door::op_id,
    })
}

/// The process's secret plugins (`root::loader::secret_calls::SecretRows`), over the process's one
/// dispatcher (`root::dispatch`): the linked rows [`register_stores`] adds once, and the dropped-in
/// ones each app build and boot's scan replace (`root::boot::admit_secrets`).
static SECRETS: std::sync::OnceLock<crate::root::loader::secret_calls::SecretRows> =
    std::sync::OnceLock::new();

/// THE SECRET AXIS: the secret plugins this build links, each door's Statement read once (nothing is
/// loaded until a reference names it). The first call stands.
///
/// # Errors
/// A linked secret door that does not state itself, naming why.
pub fn link_secrets(
    doors: &[busbar_contract::abi::mechanism::door::DoorFn],
    declares: &[(busbar_contract::abi::mechanism::door::DoorFn, &str)],
) -> Result<&'static crate::root::loader::secret_calls::SecretRows, String> {
    if let Some(rows) = SECRETS.get() {
        return Ok(rows);
    }
    let mut rows = crate::root::loader::secret_calls::SecretRows::new(
        crate::root::dispatch::dispatcher,
        conns,
    )
    .with_logs(|| crate::root::boot::plugin_logs().clone())
    .with_disk_lane(disk_run);
    for door in doors {
        rows.link(*door)
            .map_err(|e| format!("a linked secret plugin does not state itself: {e}"))?;
    }
    for (door, json) in declares {
        rows.declare_linked(*door, json)?;
    }
    rows.with_former_names(busbar_kernel::config::legacy::former_names)?;
    Ok(SECRETS.get_or_init(|| rows))
}

/// THE PROCESS'S ONE DISK LANE (THE DESIGN §11.11 R4): the kernel's host services append on it
/// ([`crate::root::serve::kernel_services`]) and a disk-declared secret source's config-time
/// `resolve` runs on it ([`disk_run`]).
static DISK: std::sync::OnceLock<std::sync::Arc<busbar_kernel::host_disk::DiskLane>> =
    std::sync::OnceLock::new();

/// The process's one disk lane.
pub fn disk_lane() -> std::sync::Arc<busbar_kernel::host_disk::DiskLane> {
    DISK.get_or_init(std::sync::Arc::default).clone()
}

/// The secret axis's hook onto [`disk_lane`]: a job submitted to the lane thread.
fn disk_run(job: Box<dyn FnOnce() + Send>) -> Result<(), String> {
    disk_lane().run(job).map_err(str::to_string)
}

/// The host's one connection table (`root::connector::the()`), on which a secret plugin that declares
/// a need is declared and through which it is lent its connector.
fn conns() -> Option<std::sync::Arc<dyn busbar_contract::conn::DeclaredConns>> {
    Some(crate::root::connector::the().clone())
}

/// The secret axis [`register_stores`] installed (an empty one where no root registered).
pub fn secret_rows() -> &'static crate::root::loader::secret_calls::SecretRows {
    SECRETS.get_or_init(|| {
        crate::root::loader::secret_calls::SecretRows::new(crate::root::dispatch::dispatcher, conns)
            .with_logs(|| crate::root::boot::plugin_logs().clone())
            .with_disk_lane(disk_run)
    })
}

/// THE PLANE AXIS: every entry's registry row and every plane door's — linked or dropped in —
/// installed once. A plane whose declaration the loader will not admit refuses the boot (exit 2)
/// whichever door it came in by, before any listener binds.
pub fn register_planes(linked: &Linked) {
    match plane_rows(linked) {
        Ok(rows) => busbar_kernel::plane::registry::install_planes(rows.leak()),
        Err(refusal) => {
            eprintln!("busbar: {refusal}");
            std::process::exit(2);
        }
    }
}

/// The rows [`register_planes`] installs, in install order: the linked Rust-hook planes with each
/// linked door's folded row at its manifest place, then the dropped-in doors' rows. The kernel's boot
/// fold (`merged_boot_plane_decls`) then orders, dedups and claim-checks them without knowing which
/// door any came in by.
pub fn plane_rows(linked: &Linked) -> Result<Vec<&'static PlaneDecl>, String> {
    let mut rows: Vec<&'static PlaneDecl> = linked.planes.iter().collect();
    // A linked door's folded row goes at its manifest row's place among the linked plane rows (the
    // layering order is the manifest's whichever axis a plane registers on); a dropped one follows.
    let doors = door_rows()?;
    let (linked_doors, dropped_doors) =
        doors.split_at(linked.plane_door_slots.len().min(doors.len()));
    for (row, slot) in linked_doors.iter().zip(linked.plane_door_slots).rev() {
        rows.insert((*slot).min(rows.len()), row);
    }
    rows.extend(dropped_doors.iter().copied());
    // PER-AXIS (SEAM-L(s)): a door row owns the plane axis for its key; a legacy row of the same
    // key yields that axis alone and keeps every other axis it registers (its tables are its own).
    let rows = doors_own_their_plane_keys(rows, &doors);
    let declared: Vec<&PlaneDeclaration> = rows.iter().map(|d| &d.declaration).collect();
    busbar_contract::plane::check_metric_families(&declared, PLANE_CARRIED_SERIES)?;
    busbar_contract::plane::check_served_op_classes(&declared)?;
    Ok(rows)
}

/// THE PLANE AXIS, PER AXIS (SEAM-L(s)): every row of `rows` that is one of `doors` stays, and a
/// row that is not (a linked legacy or HOT-lane row) stays unless a door registers its key, in
/// which case the door serves the plane and the legacy row keeps only the axes the door does not
/// register (its other tables: the CLI help, the one-shot runner, the protocols, the diagnostics),
/// which this fold never touches. Order is kept.
///
/// The ENGINE does not ride the door's row (status row 83, PR 4a; BUSBAR-1.6.0.md l.639, l.2577,
/// #7: the route tables, the view, the health loop and `on_swap` are the KERNEL's). The door's own
/// tail states whether it is the fallback plane (`TAIL_FALLBACK`), the core's readers (the
/// `/metrics` lane gauges, `/v1/models`, the keys and service-operations views) walk the kernel's
/// own [`busbar_kernel::plane_driver::route_tables::ConfigTables`], built from the same resolved lanes and pools,
/// the provider merge is the kernel's `merge_provider_fallback`, and the health probes are the
/// kernel's probe units on the door's sealed egress (`root::serve::arm_probes`). So a legacy row of
/// the door's key yields the plane axis whole, its `build_runtime`, `viewer`, `resolve_provider`,
/// `on_swap` and fallback flag included.
pub fn doors_own_their_plane_keys(
    rows: Vec<&'static PlaneDecl>,
    doors: &[&'static PlaneDecl],
) -> Vec<&'static PlaneDecl> {
    let is_door = |row: &PlaneDecl| doors.iter().any(|d| std::ptr::eq(*d, row));
    rows.into_iter()
        .filter(|row| is_door(row) || !doors.iter().any(|d| d.key == row.key))
        .collect()
}

/// TWO DOORS ON ONE AXIS: a plane key registered by two door rows (each `(row name, key)`) is a
/// boot refusal naming both; the per-axis fold cannot pick between two owners of the same axis.
///
/// # Errors
///
/// The first key two rows both register, with both rows' names.
pub fn refuse_a_key_two_doors_register(named: &[(String, &str)]) -> Result<(), String> {
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

/// The dispatcher a door row's probe binds on: the process's one ([`crate::root::dispatch`]).
pub(crate) fn door_probe_dispatcher() -> Arc<crate::root::loader::dispatch::Dispatcher> {
    crate::root::dispatch::dispatcher()
}

/// THE DOOR PLANES' REGISTRY ROWS (DECL-FOLD; ARCHITECT RULING 2026-10-03 on the door's declaration; spec #49
/// and R2-C): every plane [`crate::root::boot::discover_planes`] discovered through a door, linked
/// or dropped, bound once through the loader's one load on the process's one dispatcher (booted as main's first act,
/// before any plane registers and before the config prepass), and its Statement
/// folded into a registry row by the kernel (`busbar_kernel::plane_driver::door::fold`). The row's every
/// word is the door's; a door owns the plane axis for its key, a linked legacy row of the same key
/// keeping only its other axes ([`doors_own_their_plane_keys`]), and two doors registering one key
/// refuse the boot naming both. A door that will not bind refuses the boot, as its load would.
fn door_rows() -> Result<Vec<&'static PlaneDecl>, String> {
    let doors = crate::root::boot::DOOR_CANDIDATES
        .get()
        .map_or(&[][..], Vec::as_slice);
    if doors.is_empty() {
        return Ok(Vec::new());
    }
    // The probe binds on the PROCESS'S ONE DISPATCHER (booted first, in `main`), never one of
    // their own: a second dispatcher is a second set of `busbar-dispatch` threads. A probe plugin
    // it adopted is refreshed through it at every generation.
    let probe = door_probe_dispatcher();
    let registrations = doors
        .iter()
        .map(|candidate| {
            let name = candidate.name.clone();
            let bound = candidate.clone();
            let probe = Arc::clone(&probe);
            let bind: crate::root::loader::dispatch::kinds::plane::ProbeBind =
                Arc::new(move || {
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

/// THE FIRST-PARTY SERIES A PLANE MAY CARRY — the host-owned list a plane's `busbar_`-named metric
/// family must be on, with exactly these label keys in this order, to be admitted (ARCHITECT RULING
/// S2-c; #65: a plane cannot mint an arbitrary `busbar_` series, and a carried one renders byte for
/// byte as the host's). A plane adds to a family only through `counter_add`, so only COUNTERS are
/// listed.
///
/// SOURCE: every `counter` row of the 1.5.5 metrics inventory, `v1.5.5:docs/observability.md`
/// (the metric table, lines 95–119), with its label keys in the order the host emits them — which
/// is the order the 1.5.5 exposition renders them (`busbar_route_policy_*` emit `policy` before
/// `pool`). Plus ONE row the ruling names that 1.5.5 did not have:
/// `busbar_billing_tap_decode_fail_total{protocol,reason}` is absent at the v1.5.5 tag (introduced
/// at 4cab71389) and is listed because S2-c requires the seam to carry it byte-identically.
pub const PLANE_CARRIED_SERIES: &[(&str, &[&str])] = &[
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

/// THE EXPORT AXIS'S REGISTRY: the registry an `export:` instance's `module:` resolves against —
/// every `kind: export` row the plugin registry's one registration admitted, linked and dropped in
/// ([`crate::root::boot::dropped_from_config`]) — kept for the root's export axis
/// ([`crate::root::exports`], installed with the root rows by [`register_stores`]). The kernel serves
/// no export module of its own, so every module is a row here; a linked row and a different
/// dropped-in plugin spelling one module refuse the boot (ARCHITECT Q-P4-12).
pub fn register_exports(dropped: Option<&'static crate::root::loader::PluginRegistry>) {
    // The host's own series, named on the process's one dispatcher (built first, in `main`), whose
    // observability every first-party export open is granted against.
    let _ = crate::root::dispatch::dispatcher()
        .observing()
        .install_host_series(host_series);
    if let Some(registry) = dropped {
        let _ = DROPPED.set(registry);
    }
}

/// The registry [`register_exports`] kept; `None` before it ran, or with nothing to keep.
pub(crate) fn dropped() -> Option<&'static crate::root::loader::PluginRegistry> {
    DROPPED.get().copied()
}

/// EVERY LINKED PLANE DOOR'S `declares`, `(row, door, declares)`: a transitional row's off its
/// `linked-declares` row ([`Linked::plane_door_declares`]), a door-root row's off its door's
/// Statement (`EXT_DECLARES`; status row 195).
pub fn plane_door_declares(
    linked: &Linked,
) -> Vec<(
    &'static str,
    busbar_contract::abi::mechanism::door::DoorFn,
    &'static str,
)> {
    linked
        .plane_door_declares
        .iter()
        .copied()
        .chain(crate::root::door_root::declared(
            linked.door_roots,
            "plane-door",
        ))
        .collect()
}

/// THE BREAKER FACTS A DOOR PLANE DECLARES (`declares.breaker`, ARCHITECT Q4), found by the plane's
/// Statement name: a linked door's in its row's `declares.json` ([`Linked::plane_door_declares`]),
/// a dropped-in plane's in its signed manifest (`dropped`). `None`: it declares none, and its
/// members' cells keep the host's default posture. The root names no plane: whichever plane states
/// the fact, it reads it.
///
/// # Errors
///
/// A linked door whose Statement or `declares` section does not read, or a dropped-in manifest
/// whose Statement does not read.
pub fn door_breaker(
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

/// The configured `plugins.logs`, or its defaults: where every opened plugin instance logs.
pub(crate) fn logs() -> &'static crate::root::loader::dispatch::PluginLogConfig {
    crate::root::boot::plugin_logs()
}

/// THE HOST'S METRIC CATALOG — every series the host itself emits, which a first-party plugin's
/// declared series may not claim (K9a S1: a claim on one is refused at open rather than merged into
/// the host's writes). The composition root is the one place that names it; the root's tests hold
/// it to every `busbar_*` series constant the kernel's metric modules define, so it cannot drift.
pub const HOST_SERIES: &[&str] = &[
    busbar_kernel::snapshot::ROUTE_POLICY_SELECTIONS_TOTAL,
    busbar_kernel::snapshot::ROUTE_POLICY_REJECTIONS_TOTAL,
    busbar_kernel::snapshot::HOOK_CONTENT_TRUNCATED_TOTAL,
    busbar_kernel::snapshot::BILLING_TRUNCATED_TOTAL,
    busbar_kernel::snapshot::PLUGIN_OBSERVATIONS_DROPPED_TOTAL,
    busbar_kernel::snapshot::JOURNAL_QUARANTINED_TOTAL,
    busbar_kernel::snapshot::REQUESTS_TOTAL,
    busbar_kernel::snapshot::BREAKER_TRIPS_TOTAL,
    busbar_kernel::snapshot::FAILOVERS_TOTAL,
    busbar_kernel::snapshot::REQUEST_DURATION_SECONDS,
    busbar_kernel::snapshot::TRANSLATIONS_TOTAL,
    busbar_kernel::snapshot::PLANE_REQUESTS_TOTAL,
    busbar_kernel::snapshot::PLANE_REQUEST_DURATION_SECONDS,
    busbar_kernel::snapshot::ADMISSION_DENIED_TOTAL,
    busbar_kernel::snapshot::METERING_PENDING_COALESCED_TOTAL,
    busbar_kernel::snapshot::PLUGIN_REQUEST_HEADERS_TRUNCATED_TOTAL,
    busbar_kernel::snapshot::PLUGIN_RESPONSE_HEADERS_REJECTED_TOTAL,
    busbar_kernel::snapshot::PLUGIN_LABEL_REFUSED_TOTAL,
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
    // `hooks::taps`' crate-private constant, spelled here as it renders.
    "busbar_tap_notifications_dropped_total",
];

/// Is `name` a series the host emits — one of [`HOST_SERIES`], or a histogram/summary's derived
/// `_sum` / `_count` / `_bucket` series of one?
pub fn host_series(name: &str) -> bool {
    let base = ["_sum", "_count", "_bucket"]
        .iter()
        .find_map(|suffix| name.strip_suffix(suffix));
    HOST_SERIES.iter().any(|s| *s == name || Some(*s) == base)
}

/// The plugin registry [`register_exports`] installed — read again by [`register_diagnostics`], so
/// the configured `plugins.dir` is scanned once.
static DROPPED: std::sync::OnceLock<&'static crate::root::loader::PluginRegistry> =
    std::sync::OnceLock::new();

/// THE DIAGNOSTICS AXIS: every entry's owned diagnostics, and every first-party plugin's DECLARED
/// ones (K9a S3), installed once. A declaration the catalogue refuses refuses the boot.
pub fn register_diagnostics(linked: &Linked) {
    let mut installed: Vec<&'static busbar_contract::diagnostic::Diagnostic> = linked
        .diagnostics
        .iter()
        .flat_map(|diags| diags.iter().copied())
        .collect();
    match door_declared_diagnostics(&plane_door_declares(linked), &installed) {
        Ok(declared) => installed.extend(declared),
        Err(refusal) => {
            eprintln!("busbar: {refusal}");
            std::process::exit(2);
        }
    }
    if let Some(registry) = DROPPED.get() {
        match declared_diagnostics(registry, &installed) {
            Ok(declared) => installed.extend(declared),
            Err(refusal) => {
                eprintln!("busbar: {refusal}");
                std::process::exit(2);
            }
        }
    }
    busbar_kernel::diagnostics::install_diagnostics(installed.leak());
}

/// PLUGIN DIAGNOSTICS (K9a S3): the catalogue entries `registry`'s plugins DECLARE
/// (`declares.diagnostics`), one for one, beside the `taken` ones already installed. Only a
/// first-party plugin (linked door, or signed by the release key) may declare a code; a code the
/// catalogue already holds, a class that is not the host's, or a severity that is not a severity
/// token is refused naming the plugin — a code is REGISTERED, never shadowed or renumbered.
pub fn declared_diagnostics(
    registry: &crate::root::loader::PluginRegistry,
    taken: &[&'static busbar_contract::diagnostic::Diagnostic],
) -> Result<Vec<&'static busbar_contract::diagnostic::Diagnostic>, String> {
    let mut declared = Vec::new();
    for p in registry.linked().iter().chain(registry.loadable()) {
        let (name, decls) = (p.key(), &p.manifest.declares.diagnostics);
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

/// THE DIAGNOSTICS LINKED PLANE DOORS DECLARE (`declares.json`, first-party by being linked), each
/// judged as a dropped plugin's declaration is ([`declared_diagnostics`]).
///
/// # Errors
///
/// A declaration that is not a `declares` section, or one the catalogue refuses.
pub fn door_declared_diagnostics(
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

/// One plugin's declared diagnostics as catalogue entries, beside the `held` ones: a class that is
/// not the host's, a severity that is not a token, or a code the catalogue holds is refused.
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

/// THE ROOT UNITS' SEALS, in table order. A composition that disagrees with itself must not bind a
/// listener: the first refusal is written to standard error and the process exits 2.
pub fn seal(units: &[&RootUnit]) {
    for seal in units.iter().filter_map(|u| u.seal) {
        if let Err(refusal) = seal() {
            eprintln!("busbar: {refusal}");
            std::process::exit(2);
        }
    }
}

#[cfg(test)]
#[path = "tests/linked.rs"]
mod tests;

#[cfg(test)]
#[path = "tests/linked_secret_sources.rs"]
mod secret_source_tests;

#[cfg(all(test, linked_operator_auth, linked_axis_body_ingress))]
#[path = "tests/linked_auth.rs"]
mod auth_tests;

#[cfg(test)]
#[path = "tests/linked_canonical.rs"]
mod linked_canonical;

#[cfg(all(test, linked_every_plane))]
#[path = "tests/linked_protocols.rs"]
mod linked_protocols;

#[cfg(all(test, linked_axis_hooks))]
#[path = "tests/linked_hook_ranking.rs"]
mod linked_hook_ranking;

#[cfg(test)]
#[path = "tests/linked_store_double.rs"]
mod linked_store_double;
