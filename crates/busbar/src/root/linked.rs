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
//! axis that is literal: a HOT-lane plane dropped into `plugins/` ([`dropped_planes`]) and the same
//! plane linked into the build ([`Linked::hot_planes`]) are both admitted by the loader into a
//! `DynPlane` and adapted onto the axis by the one [`hot_plane_row`]. Nothing here asks where a row
//! came from.
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

use crate::root::loader::{DynPlane, ServedPlane};
use busbar_contract::abi::hot;
use busbar_contract::abi::hot::StatusClass;
use busbar_contract::abi::mechanism::route::{RouteAuth, RouteMethod};
use busbar_contract::ids::OpClassId;
use busbar_contract::plane::{MetricFamily, ServedOpClass};
use busbar_kernel::ingress::arrival::{BodyIngressEntry, PathIngressEntry};
use busbar_kernel::plane::registry::PlaneDecl;
use busbar_kernel::plane::registry::{BillableClass, BuildCtx, PlaneDeclaration, PlaneHooks};
use busbar_kernel::plane::PlaneAdmission;
use busbar_kernel::plane_host::{EngineHost, LiveHostFactory};
use busbar_kernel::plane_routes::{PlaneReqCtx, PlaneResponse, PlaneRouteSpec};
use busbar_kernel::preflight::{LinkedAuth, LinkedStore, RootInstall};

/// A provider composition step, captured off the resolved configuration before the app is built and
/// run once the deployment's secret resolver exists.
pub type Compose = Box<dyn FnOnce(&dyn busbar_contract::secret::SecretResolve)>;

/// The stdio serve mode: frames on stdin/stdout instead of a listener; resolves to the exit code.
pub type StdioServe =
    fn(LiveHostFactory) -> std::pin::Pin<Box<dyn std::future::Future<Output = i32>>>;

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
    /// The plane axis, HOT lane: each linked plane that exports a `#[repr(C)]` plane declaration
    /// (`busbar_contract::abi::hot::PlaneDecl`) instead of Rust hooks — admitted and adapted exactly as the
    /// same plane dropped into `plugins/` is (see [`register_planes`]).
    pub hot_planes: &'static [&'static hot::PlaneDecl],
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
    pub protocols: &'static [&'static [&'static busbar_kernel::proto::ProtocolDecl]],
    /// URL-model arrivals, by protocol name.
    pub path_ingress: &'static [&'static [PathIngressEntry]],
    /// Body-model arrivals, by protocol name.
    pub body_ingress: &'static [&'static [BodyIngressEntry]],
    /// Installers of the protocol-axis seams an entry provides beside its declarations (a completion
    /// synthesizer, a stream-translator factory), each set once.
    pub protocol_seams: &'static [fn()],
    /// Owned diagnostics, joining the rendered catalog.
    pub diagnostics: &'static [&'static [&'static busbar_contract::diagnostic::Diagnostic]],
    /// Installers of a duplex plane's inbound WS-accept arrivals (the seam is set once: the first
    /// duplex entry in table order is the one installed).
    pub ws_arrivals: &'static [fn()],
    /// Background work re-anchored on every generation's engine host (boot, then each swap).
    pub on_host: &'static [fn(&Arc<dyn EngineHost>)],
    /// Providers composed off the resolved configuration (see [`Compose`]).
    pub compose: &'static [fn(&busbar_kernel::config::RootCfg) -> Option<Compose>],
    /// The stdio serve mode (see [`StdioServe`]).
    pub stdio_serve: &'static [StdioServe],
    /// The CLI-help axis: each linked plane's rows of `busbar --help` (see [`CliHelpRow`]).
    pub cli_help: &'static [&'static [CliHelpRow]],
    /// The export axis on the memory ABI: each linked export sink's statement and door (see
    /// [`LinkedDoorExport`]).
    pub export_doors: &'static [LinkedDoorExport],
    /// The store axis: each linked in-process store's `(name, ephemeral, default, open)`.
    pub stores: &'static [LinkedStore],
    /// The hook axis: each linked `kind: hook` row's door, bound through the one loader path by the
    /// root's hook axis (`crate::root::hooks`).
    pub hook_doors: &'static [busbar_contract::abi::mechanism::door::DoorFn],
    /// The auth axis: each linked `kind: auth` plugin's `(registry key, SDK boundary)`.
    pub auths: &'static [LinkedAuth],
    /// The kernel-loop axes (#28): the declaration key of each plane `gauntlet_install::install()`
    /// flips onto the unified loop's ONE-SHOT runner, and of each it flips onto the SESSION runner.
    pub gauntlet_one_shot: &'static [&'static str],
    pub gauntlet_session: &'static [&'static str],
    /// The transport axis (#3, #30): each linked wire's key, declared layers and build, in manifest
    /// order — the boot seal folds them bottom-up (see `crate::root::registry`).
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
    use busbar_kernel::plane_host::PlaneAnswer;
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

/// One linked wire, as its crate's entry states it: the registry key, the layers it declares it can
/// be built over, and its build — handed the layer the root built beneath it, where one is, and the
/// deployment's transport settings.
#[derive(Clone, Copy)]
pub struct LinkedTransport {
    /// The wire's registry key.
    pub key: &'static str,
    /// The layers it declares, in the order it would take one.
    pub composes_over: &'static [&'static str],
    /// Build the wire over `lower`.
    pub build: BuildTransport,
}

/// A wire's build: handed the layer built beneath it, where one is, and the deployment's settings.
pub type BuildTransport = fn(
    Option<Arc<dyn busbar_contract::Transport>>,
    &busbar_contract::transport::TransportSettings,
) -> Arc<dyn busbar_contract::Transport>;

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
        let declares = serde_json::from_str(declares)
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
    doors
        .iter()
        .map(|d| {
            manifest(d.name, d.alias, d.declares)
                .map(|m| crate::root::loader::LinkedPlugin::door(m, d.door))
                .map(busbar_kernel::preflight::answering_former_names)
        })
        .collect()
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

/// THE PROTOCOL AXIS: every entry's declarations and its path- and body-model arrivals, then each
/// entry's protocol-axis seams — and the node axis, which those arrivals hand their units to: every
/// entry on it is handed the node a root unit drives it through.
pub fn register_protocols(linked: &Linked, units: &[&RootUnit]) {
    let installed: Vec<&'static busbar_kernel::proto::ProtocolDecl> = linked
        .protocols
        .iter()
        .flat_map(|decls| decls.iter().copied())
        .collect();
    let path_ingress: Vec<PathIngressEntry> = linked
        .path_ingress
        .iter()
        .flat_map(|arrivals| arrivals.iter().copied())
        .collect();
    busbar_kernel::proto::install_protocols_with_path_ingress(installed, path_ingress);
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
/// and the secret axis ([`secret_rows`]). No row is a default store: the store is the one config
/// names (Q-STORE = (B)). A linked secret door that does not state itself refuses the boot (exit 2)
/// before anything resolves a store or a secret.
pub fn register_stores(linked: &Linked) {
    match link_secrets(linked.secrets) {
        Ok(secrets) => busbar_kernel::preflight::install_linked_rows(RootInstall {
            stores: linked.stores,
            registry_build: Some(crate::root::boot::registry),
            plugins_fetch: Some(crate::root::boot::plugins_fetch),
            hook_axis: Some(crate::root::hooks::axis),
            store_axis: Some(store_axis),
            secret_axis: Some(secrets),
            export_axis: Some(&crate::root::exports::EXPORTS),
        }),
        Err(refusal) => {
            eprintln!("busbar: {refusal}");
            std::process::exit(2);
        }
    }
    // A member program's `env` secret references resolve through the same linked secret plugins
    // (ARCHITECT round 5 Q-L3B-STDIO-UPSTREAM (A): as the previous release resolved them).
    crate::root::loader::dispatch::install_member_secrets(
        busbar_kernel::config::secret::resolve_linked_string,
    );
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
/// ones each registry build replaces (`root::boot::registry`).
static SECRETS: std::sync::OnceLock<crate::root::loader::secret_calls::SecretRows> =
    std::sync::OnceLock::new();

/// THE SECRET AXIS: the secret plugins this build links, each door's Statement read once (nothing is
/// loaded until a reference names it). The first call stands.
///
/// # Errors
/// A linked secret door that does not state itself, naming why.
pub fn link_secrets(
    doors: &[busbar_contract::abi::mechanism::door::DoorFn],
) -> Result<&'static crate::root::loader::secret_calls::SecretRows, String> {
    if let Some(rows) = SECRETS.get() {
        return Ok(rows);
    }
    let mut rows = crate::root::loader::secret_calls::SecretRows::new(
        crate::root::dispatch::dispatcher,
        conns,
    );
    for door in doors {
        rows.link(*door)
            .map_err(|e| format!("a linked secret plugin does not state itself: {e}"))?;
    }
    rows.with_former_names(busbar_kernel::config::legacy::former_names)?;
    Ok(SECRETS.get_or_init(|| rows))
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
    })
}

/// THE PLANE AXIS: every entry's registry row and every HOT-lane plane's — linked or dropped in —
/// installed once. A plane whose declaration the loader will not admit refuses the boot (exit 2)
/// whichever door it came in by, before any listener binds.
pub fn register_planes(linked: &Linked, dropped: Vec<DynPlane>) {
    match plane_rows(linked, dropped) {
        Ok(rows) => busbar_kernel::plane::registry::install_planes(rows.leak()),
        Err(refusal) => {
            eprintln!("busbar: {refusal}");
            std::process::exit(2);
        }
    }
}

/// The rows [`register_planes`] installs, in install order: the linked Rust-hook planes, then the
/// linked HOT-lane planes, then the dropped-in ones — each HOT-lane plane admitted by the loader
/// (`link_plane` for a linked decl, the `plugins/` load for a dropped one) and adapted by the one
/// [`hot_plane_row`]. The kernel's boot fold (`merged_boot_plane_decls`) then orders, dedups and
/// claim-checks them without knowing which door any came in by.
pub fn plane_rows(
    linked: &Linked,
    dropped: Vec<DynPlane>,
) -> Result<Vec<&'static PlaneDecl>, String> {
    let mut hot = linked
        .hot_planes
        .iter()
        .map(|decl| crate::root::loader::link_plane(decl, "linked plane"))
        .collect::<Result<Vec<DynPlane>, String>>()?;
    hot.extend(dropped);
    // The HOT-lane planes live as long as the process, as a linked plane's image does, and so do the
    // rows read off them: the batch is kept once, the same way the installed row list is.
    let hot: &'static [DynPlane] = hot.leak();
    let hot_rows: &'static [PlaneDecl] = hot
        .iter()
        .map(hot_plane_row)
        .collect::<Result<Vec<PlaneDecl>, String>>()?
        .leak();
    let mut rows: Vec<&'static PlaneDecl> = linked.planes.iter().collect();
    // A linked door's folded row goes at its manifest row's place among the linked plane rows (the
    // layering order is the manifest's whichever axis a plane registers on); a dropped one follows.
    let doors = door_rows()?;
    let (linked_doors, dropped_doors) =
        doors.split_at(linked.plane_door_slots.len().min(doors.len()));
    for (row, slot) in linked_doors.iter().zip(linked.plane_door_slots).rev() {
        rows.insert((*slot).min(rows.len()), row);
    }
    rows.extend(hot_rows);
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
/// row that is not (a linked legacy or HOT-lane row) stays unless a door registers its key, in which
/// case the door serves the plane and the legacy row keeps only the axes the door does not register
/// (its other tables: the stdio serve, the CLI help, the one-shot runner, the protocols, the
/// diagnostics), which this fold never touches. Order is kept.
#[must_use]
pub fn doors_own_their_plane_keys(
    rows: Vec<&'static PlaneDecl>,
    doors: &[&'static PlaneDecl],
) -> Vec<&'static PlaneDecl> {
    rows.into_iter()
        .filter(|row| {
            doors.iter().any(|d| std::ptr::eq(*d, *row)) || !doors.iter().any(|d| d.key == row.key)
        })
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

/// THE DOOR PLANES' REGISTRY ROWS (DECL-FOLD; ARCHITECT RULING 2026-10-03, Q-DEL-A2A-DECL; spec #49
/// and R2-C): every plane [`dropped_planes_of`] discovered through a door, linked or dropped, bound
/// once through the loader's one load on a dispatcher of its own (the process's is built after the
/// configuration is read, and the rows must be in before the config prepass), and its Statement
/// folded into a registry row by the kernel (`busbar_kernel::plane::door::fold`). The row's every
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
            let candidate = candidate.clone();
            let probe = Arc::clone(&probe);
            let bind: crate::root::loader::dispatch::kinds::plane::ProbeBind =
                Arc::new(move || {
                    crate::root::loader::boot::load_planes(
                        std::slice::from_ref(&candidate),
                        crate::root::boot::plugin_logs(),
                        Arc::new(crate::root::loader::dispatch::NoSink),
                        probe.adopter(),
                        u32::MAX,
                        crate::root::loader::dispatch::ConnTable::Probe,
                    )?
                    .into_iter()
                    .next()
                    .map(|(_, plane)| plane)
                    .ok_or_else(|| format!("{}: the door bound nothing", candidate.name))
                });
            Ok((
                name,
                crate::root::loader::dispatch::kinds::plane::registration(bind)?,
            ))
        })
        .collect::<Result<Vec<_>, String>>()?;
    let named: Vec<(String, &str)> = (registrations.iter())
        .map(|(name, reg)| (name.clone(), reg.key))
        .collect();
    refuse_a_key_two_doors_register(&named)?;
    registrations
        .into_iter()
        .map(|(_, reg)| busbar_kernel::plane::door::fold(reg))
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

/// ADAPT ONE HOT-LANE PLANE onto the plane axis — the ONE function a linked and a dropped-in plane
/// both pass through. The row's contract declaration is the plane's own statement, field for field:
/// its `name` is the registry key, its `section_key` the declaring section, and every other fact is
/// read off the decl's declaration tail (the loader refuses a decl that states none). Nothing is
/// defaulted and nothing stands in for anything. The plane lives for the process, so every string
/// and list here is borrowed from it or kept once, as the installed row list is. Its hooks are
/// [`HOT_PLANE_HOOKS`], and the plane is recorded where their shared `build` finds it.
pub fn hot_plane_row(plane: &'static DynPlane) -> Result<PlaneDecl, String> {
    let key = plane.name();
    if key.is_empty() || plane.section_key().is_empty() {
        return Err(format!(
            "plane {plane:?} declares no name or no config section; a plane is installed by its \
             name and configured by its section"
        ));
    }
    let stated = plane.declaration();
    let list = |items: &'static [String]| -> &'static [&'static str] {
        items.iter().map(String::as_str).collect::<Vec<_>>().leak()
    };
    let declaration = PlaneDeclaration {
        key,
        fallback: stated.fallback,
        config_section: plane.section_key(),
        scope_kinds: list(&stated.scope_kinds),
        subject_noun: &stated.subject_noun,
        admin_noun: &stated.admin_noun,
        audit_kind: &stated.audit_kind,
        card_signing_domain: stated.signing_domain.as_deref(),
        card_kid_prefix: stated.signing_kid_prefix.as_deref(),
        owned_config_sections: list(&stated.owned_sections),
        billable_classes: stated
            .billable_classes
            .iter()
            .map(|(class, family)| BillableClass { class, family })
            .collect::<Vec<_>>()
            .leak(),
        fee_units: list(&stated.fee_units),
        record_kinds: list(&stated.record_kinds),
        required_config_sections: list(&stated.required_sections),
        trust_keys: &[],
        metric_families: stated
            .metric_families
            .iter()
            .map(|f| MetricFamily {
                name: &f.name,
                kind: &f.kind,
                label_keys: list(&f.label_keys),
            })
            .collect::<Vec<_>>()
            .leak(),
        served_op_classes: stated
            .served_op_classes
            .iter()
            .map(|(op, name)| ServedOpClass {
                op: OpClassId::new(op),
                name,
            })
            .collect::<Vec<_>>()
            .leak(),
        caller_credential_refusal: None,
    };
    HOT_PLANES
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .push(plane);
    Ok(PlaneDecl::assemble(declaration, HOT_PLANE_HOOKS))
}

/// Every HOT-lane plane [`hot_plane_row`] adapted, in adaptation (= install) order: where the one
/// shared [`hot_build`] finds the plane a row is for, by the section its resource names. The first
/// plane with a section is the one the boot fold kept (it keeps the first row of a key).
static HOT_PLANES: std::sync::Mutex<Vec<&'static DynPlane>> = std::sync::Mutex::new(Vec::new());

/// THE HOST EVERY HOT-LANE PLANE IS BUILT AGAINST: the kernel's own vtable, every slot, built once
/// and kept for the process — a built plane may hold the table it was handed at `build`, so the
/// table outlives it (the ABI's build contract), and a dropped-in plane's contract host-service
/// ports are armed over it when its door opens (minor 30). Each dispatch is handed a table and
/// `HostCtx` of its own, minted for it.
static HOT_HOST: std::sync::LazyLock<hot::PlaneHostVtable> =
    std::sync::LazyLock::new(busbar_kernel::plane_host::build_plane_host_vtable);

/// A HOT-lane plane's runtime slot for one config generation: the plane as built, and the door it
/// stated through its `claims` and `admission` slots when it was built.
struct HotSlot {
    /// The built plane.
    served: ServedPlane,
    /// Each path it answers on: the method, the path, and the wire format (one the host speaks).
    claims: Vec<(RouteMethod, String, &'static str)>,
    /// The audience it binds, if it binds one.
    admission: Option<PlaneAdmission>,
    /// The operator's destinations in its section — what its egress may reach (DEC-SERVE G3).
    destinations: busbar_kernel::plane_host::egress::OperatorDestinations,
}

/// BUILD a HOT-lane plane's slot for this generation, over the ABI. The kernel hands a plane whose
/// section it carries raw that section as its resource, `(section, value)`; the section names the
/// plane. The value crosses as JSON bytes, beside the deployment's public URL, into the plane's own
/// `build` slot (against [`HOT_HOST`]); what the built plane states through `claims` and `admission`
/// is read once, here. A plane that will not build, or states a door the host cannot mount, gets no
/// slot — it serves nothing this generation, and the refusal is logged, naming it.
fn hot_build(ctx: &BuildCtx) -> Option<std::sync::Arc<dyn std::any::Any + Send + Sync>> {
    let resource = ctx.endpoint_slot.as_deref()?;
    let (section, value) = resource.downcast_ref::<(&'static str, serde_yaml::Value)>()?;
    let plane = HOT_PLANES
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .iter()
        .copied()
        .find(|p| p.section_key() == *section)?;
    match hot_slot(plane, value, ctx.public_url) {
        Ok(slot) => Some(std::sync::Arc::new(slot)),
        Err(refusal) => {
            tracing::error!(plane = plane.name(), "{refusal}");
            None
        }
    }
}

/// [`hot_build`]'s body: serve `plane` over `section`, then read and check the door it states.
fn hot_slot(
    plane: &'static DynPlane,
    section: &serde_yaml::Value,
    public_url: Option<&str>,
) -> Result<HotSlot, String> {
    let name = plane.name();
    let bytes = serde_json::to_vec(section)
        .map_err(|e| format!("plane `{name}`'s section is not representable as JSON: {e}"))?;
    let served = plane.serve(&HOT_HOST, &bytes, public_url)?;
    let methods = [
        RouteMethod::Get,
        RouteMethod::Post,
        RouteMethod::Put,
        RouteMethod::Patch,
        RouteMethod::Delete,
    ];
    let wires = [
        busbar_kernel::plane::WIRE_HTTP_JSON,
        busbar_kernel::plane::WIRE_JSONRPC,
        busbar_kernel::plane::WIRE_GRPC,
    ];
    let claims = served
        .claims()?
        .into_iter()
        .map(|c| {
            let method = methods.into_iter().find(|m| m.as_str() == c.method);
            let wire = wires.into_iter().find(|w| *w == c.wire);
            match (method, wire) {
                (Some(method), Some(wire)) => Ok((method, c.path, wire)),
                _ => Err(format!(
                    "plane `{name}` claims `{} {} {}`, a method or wire format the host does not serve",
                    c.method, c.path, c.wire
                )),
            }
        })
        .collect::<Result<Vec<_>, String>>()?;
    let admission = served
        .admission()?
        .map(|(audience, resource_metadata)| PlaneAdmission {
            audience,
            resource_metadata,
        });
    Ok(HotSlot {
        served,
        claims,
        admission,
        destinations: busbar_kernel::plane_host::egress::OperatorDestinations::of_section(section),
    })
}

/// THE PATHS A HOT-LANE PLANE ANSWERS ON, as its `claims` slot stated them at build.
fn hot_claims(slot: &dyn std::any::Any) -> Vec<(String, &'static str)> {
    slot.downcast_ref::<HotSlot>().map_or_else(Vec::new, |s| {
        s.claims
            .iter()
            .map(|(_, path, wire)| (path.clone(), *wire))
            .collect()
    })
}

/// THE AUDIENCE A HOT-LANE PLANE BINDS, as its `admission` slot stated it at build.
fn hot_admission(slot: &dyn std::any::Any) -> Option<PlaneAdmission> {
    slot.downcast_ref::<HotSlot>()?.admission.clone()
}

/// THE DATA ROUTES A HOT-LANE PLANE SERVES: one per claimed path, at the data-plane bar
/// ([`RouteAuth::Key`]). Each is answered INLINE on the request's worker ([`hot_answer_inline`]) —
/// the #30 HOT lane takes no thread hop — unless the plane declares its dispatch blocks (minor 32,
/// `DISPATCH_BLOCKS`), when it is answered on a blocking thread ([`hot_answer_blocking`]).
fn hot_routes(slot: &dyn std::any::Any) -> Vec<PlaneRouteSpec> {
    let Some(slot) = slot.downcast_ref::<HotSlot>() else {
        return Vec::new();
    };
    let blocks = slot.served.plane().dispatch_blocks();
    slot.claims
        .iter()
        .map(|(method, path, _)| PlaneRouteSpec {
            path: path.clone(),
            method: *method,
            auth: RouteAuth::Key,
            handler: std::sync::Arc::new(move |ctx| {
                Box::pin(async move {
                    match blocks {
                        true => hot_answer_blocking(ctx).await,
                        false => hot_answer_inline(&ctx),
                    }
                })
            }),
        })
        .collect()
}

/// One event of a HOT-lane answer on its way to the caller: the streamed head, a body chunk, or the
/// plane's fault after the stream began.
enum Emitted {
    Head(Option<u16>, Vec<(Vec<u8>, Vec<u8>)>),
    Chunk(axum::body::Bytes),
    Fault,
}

/// How many streamed chunks may wait for the caller before the plane's next `emit_body` blocks.
const HOT_STREAM_DEPTH: usize = 8;

/// The dispatching thread's [`crate::root::loader::ReplyStream`]: each event goes to the caller's
/// response; `false` once the caller went away.
struct ToCaller(tokio::sync::mpsc::Sender<Emitted>);

impl crate::root::loader::ReplyStream for ToCaller {
    fn head(&mut self, status: Option<u16>, headers: &[(Vec<u8>, Vec<u8>)]) -> bool {
        self.0
            .blocking_send(Emitted::Head(status, headers.to_vec()))
            .is_ok()
    }
    fn chunk(&mut self, bytes: &[u8]) -> bool {
        let chunk = axum::body::Bytes::copy_from_slice(bytes);
        self.0.blocking_send(Emitted::Chunk(chunk)).is_ok()
    }
}

/// A streamed HOT-lane body: the chunks as the plane writes them; a plane fault after the stream
/// began ends the body with an error, so the caller sees a cut answer, never a clean short one.
struct HotStream(tokio::sync::mpsc::Receiver<Emitted>);

impl http_body::Body for HotStream {
    type Data = axum::body::Bytes;
    type Error = std::io::Error;

    fn poll_frame(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Result<http_body::Frame<Self::Data>, Self::Error>>> {
        self.0.poll_recv(cx).map(|event| match event? {
            Emitted::Chunk(chunk) => Some(Ok(http_body::Frame::data(chunk))),
            Emitted::Head(..) | Emitted::Fault => Some(Err(std::io::Error::other(
                "the plane faulted after its answer began",
            ))),
        })
    }
}

/// What an inline dispatch streamed, held until it returns: the stated head and the chunks, bounded
/// by the host's per-response buffering cap (the operator's translate-body cap) — past it the plane
/// is told the caller is gone.
/// A stated answer head: the status (`None` = unstated) and the headers.
type StatedHead = (Option<u16>, Vec<(Vec<u8>, Vec<u8>)>);

struct Held {
    head: Option<StatedHead>,
    chunks: Vec<axum::body::Bytes>,
    held: usize,
    cap: usize,
}

impl crate::root::loader::ReplyStream for Held {
    fn head(&mut self, status: Option<u16>, headers: &[(Vec<u8>, Vec<u8>)]) -> bool {
        self.head = Some((status, headers.to_vec()));
        true
    }
    fn chunk(&mut self, bytes: &[u8]) -> bool {
        self.held = self.held.saturating_add(bytes.len());
        if self.held > self.cap {
            return false;
        }
        self.chunks.push(axum::body::Bytes::copy_from_slice(bytes));
        true
    }
}

/// ANSWER ONE REQUEST INLINE ON THE REQUEST'S WORKER (#30 HOT lane; ARCHITECT HOTDOOR-B queue 2): a
/// plane whose dispatch does not block is called in place — no thread hop. A body it streamed is
/// held until the dispatch returns and then served as a stream (its length unstated), exactly as
/// the blocking door serves it; a plane that faults after streaming answers its class status.
fn hot_answer_inline(ctx: &PlaneReqCtx) -> PlaneResponse {
    let mut held = Held {
        head: None,
        chunks: Vec::new(),
        held: 0,
        cap: busbar_contract::codec::max_translate_body_bytes(),
    };
    let reply = hot_dispatch(ctx, &mut held);
    let (Some((status, headers)), StatusClass::Ok) = (held.head, reply.class) else {
        return buffered_response(reply);
    };
    let (tx, rx) = tokio::sync::mpsc::channel(held.chunks.len().max(1));
    for chunk in held.chunks {
        let _ = tx.try_send(Emitted::Chunk(chunk));
    }
    drop(tx);
    live_response(status, &headers, rx)
}

/// A streamed answer: its head, then the body the channel carries.
fn live_response(
    status: Option<u16>,
    headers: &[(Vec<u8>, Vec<u8>)],
    rx: tokio::sync::mpsc::Receiver<Emitted>,
) -> PlaneResponse {
    let body = axum::body::Body::new(HotStream(rx));
    match status {
        Some(status) => hot_response(status, Some(headers), body),
        None => hot_response(200, None, body),
    }
}

/// A buffered answer: the plane's stated head on `Ok`, else its class status (see [`hot_response`]).
fn buffered_response(reply: crate::root::loader::HotReply) -> PlaneResponse {
    let body = axum::body::Body::from(reply.body);
    match (reply.class, reply.status) {
        (StatusClass::Ok, Some(status)) => hot_response(status, Some(&reply.headers), body),
        (StatusClass::Ok, None) => hot_response(200, None, body),
        (StatusClass::Refused, _) => hot_response(403, None, body),
        (StatusClass::Gone, _) => hot_response(410, None, body),
        (StatusClass::Unsupported, _) => hot_response(501, None, body),
        (StatusClass::Fault, _) => hot_response(500, None, body),
    }
}

/// ANSWER ONE REQUEST THROUGH A PLANE WHOSE DISPATCH BLOCKS (DEC-SERVE G2; minor 32
/// `DISPATCH_BLOCKS`). The dispatch runs on a blocking thread ([`hot_dispatch`]): its host calls
/// may wait, and a streamed body is written while the caller already reads it. A streamed body is
/// served LIVE — its head first, then each chunk as the plane writes it; a buffered one is served
/// whole.
async fn hot_answer_blocking(ctx: PlaneReqCtx) -> PlaneResponse {
    let (tx, mut rx) = tokio::sync::mpsc::channel(HOT_STREAM_DEPTH);
    let run = tokio::task::spawn_blocking(move || {
        let mut to_caller = ToCaller(tx);
        let reply = hot_dispatch(&ctx, &mut to_caller);
        if reply.streamed && reply.class != StatusClass::Ok {
            let _ = to_caller.0.blocking_send(Emitted::Fault);
        }
        reply
    });
    if let Some(Emitted::Head(status, headers)) = rx.recv().await {
        return live_response(status, &headers, rx);
    }
    let reply = run.await.unwrap_or_else(|_| crate::root::loader::HotReply {
        class: StatusClass::Fault,
        status: None,
        headers: Vec::new(),
        body: Vec::new(),
        streamed: false,
    });
    buffered_response(reply)
}

/// The response a HOT-lane plane answered: on an `Ok` answer with a stated head, EXACTLY the status
/// and headers it stated — its provider's, passed through; otherwise (`headers` `None`) the status
/// of its class with the JSON content type every HOT-lane answer carried before a plane could state
/// a head (`Ok` 200, `Refused` 403, `Gone` 410, `Unsupported` 501, anything else 500). A status or
/// header the host cannot serve is a 500.
fn hot_response(
    status: u16,
    headers: Option<&[(Vec<u8>, Vec<u8>)]>,
    body: axum::body::Body,
) -> PlaneResponse {
    let mut response = axum::http::Response::builder().status(status);
    match headers {
        None => response = response.header(axum::http::header::CONTENT_TYPE, "application/json"),
        Some(headers) => {
            for (name, value) in headers {
                response = response.header(name.as_slice(), value.as_slice());
            }
        }
    }
    response.body(body).unwrap_or_else(|_| {
        let mut fault = axum::http::Response::default();
        *fault.status_mut() = axum::http::StatusCode::INTERNAL_SERVER_ERROR;
        fault
    })
}

/// DRIVE ONE REQUEST THROUGH A HOT-LANE PLANE: the request body is the work item's finite inbound
/// buffer and the request's method, path, query and headers its request head, dispatched through the
/// plane's `dispatch` slot inside the kernel's plane-door mint (`with_plane_door`, under the plane's
/// registry key, over this request's engine snapshot and a fresh arena) — so every host call the
/// plane makes back is recovered, governed, metered and journalled as this plane's, billed to the
/// caller the auth middleware resolved (`ctx.gov`, never a key id the plane writes; DEC-SERVE G1),
/// and its egress judged against the operator's destinations in its section (DEC-SERVE G3). A body
/// larger than the reply buffer goes to `stream` (DEC-SERVE G2).
fn hot_dispatch(
    ctx: &PlaneReqCtx,
    stream: &mut dyn crate::root::loader::ReplyStream,
) -> crate::root::loader::HotReply {
    let slot = ctx.slot.downcast_ref::<HotSlot>();
    let handle = ctx.engine.downcast_ref::<busbar_kernel::state::AppHandle>();
    let headers: Vec<(&[u8], &[u8])> = ctx
        .headers
        .iter()
        .map(|(name, value)| (name.as_str().as_bytes(), value.as_bytes()))
        .collect();
    let head = crate::root::loader::RequestHead {
        method: ctx.method.as_str().as_bytes(),
        path: ctx.uri.path().as_bytes(),
        query: ctx.uri.query().unwrap_or_default().as_bytes(),
        headers: &headers,
    };
    let (Some(slot), Some(handle)) = (slot, handle) else {
        return crate::root::loader::HotReply {
            class: StatusClass::Fault,
            status: None,
            headers: Vec::new(),
            body: Vec::new(),
            streamed: false,
        };
    };
    let app = handle.load();
    let scope = busbar_kernel::plane_host::DispatchScope::new();
    busbar_kernel::plane_host::with_plane_door(
        slot.served.plane().name(),
        ctx.gov.as_ref(),
        &slot.destinations,
        &app,
        &scope,
        |host, vt| {
            slot.served
                .answer(vt, host, Some(&head), &ctx.body, Some(stream))
        },
    )
}

/// THE KERNEL HOOKS OF A HOT-LANE PLANE — the same set for every HOT-lane plane, whichever door it
/// came in by: its claims, admission, build and data routes each run over the plane's C-ABI slots
/// (the loader's [`DynPlane`] / [`ServedPlane`] against the kernel's own host vtable), and the
/// request loop drives it through the same plane-route mount every linked plane's routes take.
pub const HOT_PLANE_HOOKS: PlaneHooks = PlaneHooks {
    wire_format_names: || &[],
    claims: hot_claims,
    admission: hot_admission,
    build: hot_build,
    routes: Some(hot_routes),
    admin_routes: None,
    openapi: None,
    hydrate: None,
    start: None,
    config_validate: None,
    named_def_list: None,
    named_def_get: None,
    registry_contains: None,
    reresolve_gates: None,
    openapi_schemas: None,
    on_swap: None,
    parse_section: None,
    parse_endpoint: None,
    lower_endpoint: None,
    build_runtime: None,
    viewer: None,
    retain_verify_gates: None,
    default_section: None,
    resolve_provider: None,
};

/// THE EXPORT AXIS'S REGISTRY: the registry an `export:` instance's `module:` resolves against —
/// every `kind: export` row the plugin registry's one registration admitted, linked and dropped in
/// ([`crate::root::boot::dropped_from_config`]) — kept for the root's export axis
/// ([`crate::root::exports`], installed with the root rows by [`register_stores`]). The kernel serves
/// no export module of its own, so every module is a row here; a linked row and a different
/// dropped-in plugin spelling one module refuse the boot (ARCHITECT Q-P4-12).
pub fn register_exports(dropped: Option<&'static crate::root::loader::PluginRegistry>) {
    crate::root::loader::observe::install_host_series(host_series);
    if let Some(registry) = dropped {
        let _ = DROPPED.set(registry);
    }
}

/// The registry [`register_exports`] kept; `None` before it ran, or with nothing to keep.
pub(crate) fn dropped() -> Option<&'static crate::root::loader::PluginRegistry> {
    DROPPED.get().copied()
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
    for (row, door, json) in linked.plane_door_declares {
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
        let declares: crate::root::loader::sign::Declares =
            serde_json::from_str(json).map_err(|e| {
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
    busbar_kernel::metrics::ROUTE_POLICY_SELECTIONS_TOTAL,
    busbar_kernel::metrics::ROUTE_POLICY_REJECTIONS_TOTAL,
    busbar_kernel::metrics::HOOK_CONTENT_TRUNCATED_TOTAL,
    busbar_kernel::metrics::BILLING_TRUNCATED_TOTAL,
    busbar_kernel::metrics::PLUGIN_OBSERVATIONS_DROPPED_TOTAL,
    busbar_kernel::metrics::JOURNAL_QUARANTINED_TOTAL,
    busbar_kernel::metrics::REQUESTS_TOTAL,
    busbar_kernel::metrics::BREAKER_TRIPS_TOTAL,
    busbar_kernel::metrics::FAILOVERS_TOTAL,
    busbar_kernel::metrics::REQUEST_DURATION_SECONDS,
    busbar_kernel::metrics::TRANSLATIONS_TOTAL,
    busbar_kernel::metrics::PLANE_REQUESTS_TOTAL,
    busbar_kernel::metrics::PLANE_REQUEST_DURATION_SECONDS,
    busbar_kernel::metrics::ADMISSION_DENIED_TOTAL,
    busbar_kernel::metrics::METERING_PENDING_COALESCED_TOTAL,
    busbar_kernel::metrics::PLUGIN_REQUEST_HEADERS_TRUNCATED_TOTAL,
    busbar_kernel::metrics::PLUGIN_RESPONSE_HEADERS_REJECTED_TOTAL,
    busbar_kernel::metrics::KEY_SPEND_CENTS,
    busbar_kernel::metrics::KEY_TOKENS_TOTAL,
    busbar_kernel::metrics::BUCKET_TOKENS,
    busbar_kernel::metrics::BUCKET_SPEND_CENTS,
    busbar_kernel::metrics::BUCKET_BUDGET_REMAINING_CENTS,
    busbar_kernel::metrics::LANE_STATE,
    busbar_kernel::metrics::LANE_AVAILABLE,
    busbar_kernel::metrics::LANE_RECOVERY_HINT_MS,
    busbar_kernel::metrics::LANE_INFLIGHT,
    busbar_kernel::metrics::LANE_AVAILABLE_PERMITS,
    busbar_kernel::metrics::POOL_QUEUED,
    busbar_kernel::telemetry::UPSTREAM_ATTEMPTS_TOTAL,
    busbar_kernel::telemetry::UPSTREAM_FAILURES_TOTAL,
    busbar_kernel::metrics::BILLING_TAP_DECODE_FAIL_TOTAL,
    // `proxy_vocab`'s crate-private constant, spelled here as it renders.
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
    use busbar_contract::diagnostic::{Class, Diagnostic, Severity};
    use busbar_kernel::diagnostics::REGISTRY;
    let leak = |s: &str| -> &'static str { Box::leak(s.to_string().into_boxed_str()) };
    let mut declared: Vec<&'static Diagnostic> = Vec::new();
    for p in registry.linked().iter().chain(registry.loadable()) {
        let (name, decls) = (p.key(), &p.manifest.declares.diagnostics);
        if !decls.is_empty() && !p.first_party() {
            return Err(format!(
                "plugin '{name}' declares diagnostics but is not first-party; only a first-party \
                 plugin's codes join the catalogue"
            ));
        }
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

/// THE WS-ACCEPT AXIS: each duplex entry installs its inbound arrivals — and none does when no entry
/// is duplex, so the router mounts no WS-accept route.
pub fn register_ws_arrivals(linked: &Linked) {
    for install in linked.ws_arrivals {
        install();
    }
}

/// THE ROOT-BOUND SEAMS an enabled entry drives, each bound once and only when some entry drives it
/// (the manifest's `egress` / `plane-sections` / `admin-envelope` axes, emitted by the build script as
/// `linked_*` cfgs): the hostless-egress driver and the egress-trust host, the parse-time section
/// list a cross-plane hook refusal reads, and the envelope a self-enveloping admin verb replies
/// through. Each backing is a ZST unit struct, so it promotes to `'static`. The egress-trust host
/// is installed by `run` once the configuration loads, over the destination guard.
pub fn register_seams() {
    #[cfg(linked_egress)]
    {
        busbar_kernel::egress::seam::install_hostless_egress(
            &busbar_kernel::egress::seam::CoreHostlessEgress,
        );
    }
    #[cfg(linked_plane_sections)]
    busbar_kernel::plane::config::install_plane_sections(
        busbar_kernel::plane::config::config_sections,
    );
    #[cfg(linked_admin_envelope)]
    busbar_kernel::admin_verbs::install_plane_admin_envelope(
        &busbar_kernel::admin::planeverbs::CorePlaneAdminEnvelope,
    );
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

#[cfg(all(test, feature = "auth-admin-tokens", linked_axis_body_ingress))]
#[path = "tests/linked_auth.rs"]
mod auth_tests;

#[cfg(test)]
#[path = "tests/metric_family_conformance.rs"]
mod metric_family_conformance;

#[cfg(test)]
#[path = "tests/linked_canonical.rs"]
mod linked_canonical;

#[cfg(all(test, linked_every_plane))]
#[path = "tests/linked_protocols.rs"]
mod linked_protocols;
