// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE BOOT (`BUSBAR-1.6.0.md` THE DESIGN, §3): the composition root's boot stages, reaching the
//! plugin loader through [`super::loader`] (the one module that names it). Stage 0 Plan reads what the configuration USES; stage 1 Discover reads
//! each plugin's facts off its Statement (a signed manifest's rendering; nothing is opened); stage 2
//! Select picks the plugins the configuration uses (BUSBAR-1.6.0.md §2, §4 Law 7). `--validate` runs these three
//! stages and nothing dials, no library is opened and no store is opened.
//!
//! Stage 4 Book ([`book`]) opens the store, replays the WAL, seals the opening and binds the
//! keyset, at boot only. The configured `plugins.dir` scan ([`dropped_from_config`]), the door
//! planes' and dropped transports' one load ([`load_door_planes`], [`dropped_transports`]) live here
//! too. The rest of boot — register and seal —
//! moves here as BOOT-LOOP 8.

use std::sync::Arc;

use super::linked::{linked_exports, Linked};
use super::loader::{
    boot::*, dispatch::LoadError, dispatch::ManifestFacts, LinkedPlugin, PluginRegistry,
};
use busbar_contract::abi::mechanism::KindCode;
use busbar_contract::plugin_rows::PluginRows;
use busbar_kernel::config::{FetchTarget, PluginsCfg};
use busbar_kernel::config_validate::deal::{Document, Seat};
use busbar_kernel::preflight::{BuildNote, CopyLine, Fetched, LinkedRow, RegistryIn};

/// THE ONE REGISTRY BUILD (BUSBAR-1.6.0.md §3 stage 1; ARCHITECT ruling Q8): the
/// plugin registry is built here, in the composition root, and nowhere else — the kernel's preflight
/// receives it through the root's rows (the kernel preflight's `RegistryBuild`), and the root's own
/// dropped-plugin scan runs the same build. The linked rows alone, or the `plugins:` block's trust
/// resolved ([`trust_policy`]) and its directory scanned with the first-party floor armed and
/// raised; each step is noted to `note`. Nothing is opened.
///
/// # Errors
///
/// `plugins.trust is invalid: …`, an invalid tarball, manifest or conflict, or a linked row the
/// admission refuses.
pub fn registry(
    linked: Vec<LinkedPlugin>,
    plugins: Option<&PluginsCfg>,
    data_dir: Option<&std::path::Path>,
    note: &mut dyn FnMut(Note<'_>),
) -> Result<PluginRegistry, String> {
    let scan = match plugins {
        None => None,
        Some(p) => Some(Scan {
            policy: trust_policy(p, env!("CARGO_PKG_VERSION"))
                .map_err(|e| format!("plugins.trust is invalid: {e}"))?,
            data_dir,
            dir: p.enabled.then_some(std::path::Path::new(&p.dir)),
        }),
    };
    let registry = super::loader::boot::registry(Build { linked, scan }, note)?;
    // The dropped-in secret plugins that state a door are JUDGED here, as every build judges them,
    // and join the secret axis only through [`admit_secrets`]: this build is stage 1, which
    // `--validate` and every dry run share, and a dry run keeps the running node's secret plugins
    // (BUSBAR-1.6.0.md l.456-457).
    super::linked::secret_rows().judge_dropped(discovered(&registry, |kind| kind == "secret")?)?;
    Ok(registry)
}

/// STAGE 3's SECRET ADMISSION (BUSBAR-1.6.0.md §3, 3a/3e; the kernel's `RootInstall::secret_admit`):
/// the dropped-in secret plugins that state a door join the secret axis (the root's, over the one
/// dispatcher), replacing the last set; a 1.5.x one with no door stays on the cold lane (M6). The
/// app build calls it through the install record with the rows the kernel holds, read back as the
/// registry this root built them as (a test build's rows double admits nothing); boot's scan calls
/// [`admit_dropped_secrets`] on its own registry. The registry build ([`registry`]) never does.
///
/// # Errors
///
/// A stated rendering that does not read back, or a dropped-in secret plugin that claims a word
/// another plugin answers to, naming both.
pub fn admit_secrets(rows: &Arc<dyn PluginRows>) -> Result<(), String> {
    match super::loader::rows::registry_arc(Arc::clone(rows)) {
        Some(registry) => admit_dropped_secrets(&registry),
        None => Ok(()),
    }
}

/// [`admit_secrets`] over a registry this root built.
///
/// # Errors
///
/// As [`admit_secrets`].
pub fn admit_dropped_secrets(registry: &PluginRegistry) -> Result<(), String> {
    super::linked::secret_rows().admit_dropped(discovered(registry, |kind| kind == "secret")?)
}

/// THE REGISTRY BUILD THE KERNEL RECEIVES (`RootInstall::registry_build`): [`registry`] over the
/// kernel's linked rows ([`linked_row`]), each loader note handed on in the kernel's words, and the
/// registry handed back as the contract's `PluginRows` view (the kernel names no loader type).
///
/// # Errors
///
/// As [`registry`].
pub fn registry_rows(
    i: RegistryIn<'_>,
    note: &mut dyn FnMut(BuildNote<'_>),
) -> Result<Arc<dyn PluginRows>, String> {
    let linked = i.linked.iter().map(linked_row).collect();
    let registry = registry(linked, i.plugins, i.data_dir, &mut |n| match n {
        Note::FloorUnreadable(detail) => note(BuildNote::FloorUnreadable(detail)),
        Note::Off => note(BuildNote::Off),
        Note::Scanned(scanned) => {
            let copies: Vec<CopyLine> = scanned
                .linked_copies()
                .iter()
                .map(|c| CopyLine {
                    name: c.name.clone(),
                    version: c.version.clone(),
                    file: c.file.clone(),
                    line: c.line(),
                })
                .collect();
            note(BuildNote::Scanned {
                rows: scanned,
                copies: &copies,
            });
        }
        Note::FloorUnwritable(e) => note(BuildNote::FloorUnwritable(e)),
    })?;
    Ok(Arc::new(registry))
}

/// The registry row one of the kernel's linked rows states: a STORE under its canonical name,
/// answering also to its key; an AUTH row likewise — each answering also to the former names the
/// root migration table gives that key ([`answering_former_names`]).
#[must_use]
pub fn linked_row(row: &LinkedRow) -> LinkedPlugin {
    match *row {
        LinkedRow::Store((key, ephemeral, door, canonical)) => {
            answering_former_names(LinkedPlugin::store_named(canonical, key, door, ephemeral))
        }
        LinkedRow::Auth((key, canonical, door)) => {
            answering_former_names(LinkedPlugin::auth_door_named(canonical, key, door))
        }
    }
}

/// THE REGISTRY OF THIS BUILD'S LINKED ROWS ALONE (the kernel's `preflight::linked_rows`): what an
/// axis answers over when the rows it is handed are not a registry this root built (a test build's
/// rows double), and what the one-version rule compares an upload against.
#[must_use]
pub fn linked_registry() -> PluginRegistry {
    let linked = busbar_kernel::preflight::linked_rows()
        .iter()
        .map(linked_row)
        .collect();
    PluginRegistry::empty()
        .link(linked)
        .unwrap_or_else(|_| PluginRegistry::empty())
}

/// `row`, answering also to the former names the root migration table declares for its alias
/// (`former.<alias>`, from plugins.yaml `former_names:`): a linked plugin answers the names its
/// earlier releases carried exactly as its dropped-in copy's signed manifest does.
#[must_use]
pub fn answering_former_names(row: LinkedPlugin) -> LinkedPlugin {
    let former = busbar_kernel::config::migration_table::former_names(&row.manifest.alias);
    row.with_former_names(former)
}

/// THE `plugins:` BLOCK'S TRUST, resolved: the embedded first-party key, the configured
/// publishers and opt-ins and the per-name floors (`min_versions`, the rollback pins), through the
/// loader's `TrustPolicy::from_config`. `binary_version` is carried for diagnostics only. The
/// automatic first-party floor is the registry build's to arm. THE ONE BUILDER: the root hands this
/// same function to the kernel's plugin admission (`root::admission::ADMISSION`, installed by
/// `root::linked::register_stores`), and
/// every snapshot carries it to the admin surface, which judges a plugin under nothing else.
///
/// # Errors
///
/// A reserved or malformed publisher; in a `test-harness` build, a malformed
/// `HARNESS_FIRST_PARTY_KEY_ENV`.
pub fn trust_policy(
    cfg: &PluginsCfg,
    binary_version: &str,
) -> Result<super::loader::sign::TrustPolicy, String> {
    #[allow(unused_mut)] // assigned only in a `test-harness` build
    let mut policy =
        super::loader::sign::TrustPolicy::from_config(super::loader::sign::TrustInput {
            publishers: &cfg.publisher_keys(),
            allow_unsigned: cfg.trust.allow_unsigned,
            allow_third_party: cfg.trust.allow_third_party,
            min_versions: &cfg.min_versions,
            first_party_floors: &cfg.first_party_floors,
            binary_version,
        })?;
    #[cfg(feature = "test-harness")]
    if let Some(key) =
        harness_first_party_key(std::env::var(HARNESS_FIRST_PARTY_KEY_ENV).ok().as_deref())?
    {
        policy.first_party_key = Some(key);
    }
    Ok(policy)
}

/// THE TEST HARNESS'S FIRST-PARTY KEY SEAM (ARCHITECT ruling, busbar #700, 2026-10-10): a
/// `test-harness` build of the binary takes its first-party key from this variable when it is set,
/// in place of the embedded release key, whose private half no test holds. That is how a child
/// `busbar` process under test admits a plugin a test signed first-party: a plugin whose needs sit
/// in a first-party egress class (`BUSBAR-1.6.0.md` §5), such as the dropped-in OIDC module this
/// crate's end-to-end battery drives. The seam exists only under `cfg(feature = "test-harness")`,
/// which no release build enables (`crates/busbar/Cargo.toml`, `test-harness`; asserted by
/// `root::tests::boot::the_release_feature_set_excludes_test_harness`). Without the feature, no code
/// path reads the variable, and the embedded key stays the only first-party key.
#[cfg(feature = "test-harness")]
pub const HARNESS_FIRST_PARTY_KEY_ENV: &str = "BUSBAR_TEST_HARNESS_FIRST_PARTY_KEY";

/// The harness first-party key that `raw` (the value of [`HARNESS_FIRST_PARTY_KEY_ENV`]) names:
/// `None` when the variable is unset or empty, so the embedded release key stands.
///
/// # Errors
///
/// A value that is not a 64-hex ed25519 public key. A harness that sets the variable meant it, so
/// a typo is refused rather than silently ignored.
#[cfg(feature = "test-harness")]
pub fn harness_first_party_key(
    raw: Option<&str>,
) -> Result<Option<super::loader::sign::VerifyingKey>, String> {
    match raw.map(str::trim).filter(|s| !s.is_empty()) {
        None => Ok(None),
        Some(hex_key) => super::loader::sign::public_key_from_hex(hex_key)
            .map(Some)
            .map_err(|e| format!("{HARNESS_FIRST_PARTY_KEY_ENV} is not a usable key: {e}")),
    }
}

/// THE ROOT'S PLUGINS FETCH (the kernel preflight's `PluginsFetch`): every `plugins.fetch` target
/// through the loader's fetch (cache-by-pin, verify-before-write, atomic write) into `dir`, and only
/// ever through the SSRF-guarded download over the one connector
/// ([`super::plugin_fetch::downloader`], the operator's metadata denylist `blocked` extending it).
///
/// # Errors
///
/// Every problem, at boot (`fatal_on_miss`).
pub fn plugins_fetch(
    dir: &std::path::Path,
    targets: &[FetchTarget],
    fatal_on_miss: bool,
    blocked: &[String],
) -> Result<Vec<Fetched>, Vec<String>> {
    let download = super::plugin_fetch::downloader(blocked);
    let specs: Vec<super::loader::FetchSpec> = targets
        .iter()
        .map(|t| super::loader::FetchSpec {
            url: t.url.clone(),
            sha256: t.sha256.clone(),
            filename: t.filename.clone(),
        })
        .collect();
    let outcomes = super::loader::fetch_plugins(dir, &specs, fatal_on_miss, &download)?;
    Ok(outcomes
        .into_iter()
        .map(|o| match o {
            super::loader::FetchOutcome::Cached { filename } => Fetched::Cached { filename },
            super::loader::FetchOutcome::Fetched { filename } => Fetched::Fetched { filename },
            super::loader::FetchOutcome::Warned { url, error } => Fetched::Warned { url, error },
        })
        .collect())
}

/// The configuration file this process boots from (`--config`, or its default).
fn config_path() -> std::path::PathBuf {
    std::path::PathBuf::from(crate::root::cli::resolve_config_path(
        crate::root::cli::config_path_flag().as_deref(),
    ))
}

/// STAGE 0, PLAN: what the configuration file at `path` uses, read off its raw document (secret
/// references stay raw; environment references are interpolated leniently, as the boot's early
/// reads do). An unreadable file uses nothing: the boot's own load reports why.
pub fn plan(path: &std::path::Path) -> Uses {
    document(path)
        .map(|doc| Uses::of(doc.value()))
        .unwrap_or_default()
}

/// The raw document at `path` (secret references raw, environment interpolated leniently), with the
/// text its position map is read off; `None` when it does not read.
pub fn document(path: &std::path::Path) -> Option<Document> {
    let raw = std::fs::read_to_string(path).ok()?;
    let text = busbar_kernel::config::interpolate_env_with(
        &raw,
        busbar_kernel::config::EnvSubst::Lenient,
        &mut Vec::new(),
    )
    .ok()?;
    Document::parse(text).ok()
}

/// STAGE 3g, THE DEAL AND ITS VALIDATION HALF (`BUSBAR-1.6.0.md` §3): each seat is dealt its own
/// section (an instance the document writes none for is dealt none) and `validate` asked of its
/// instance with the section's JSON; the first refusal, naming the operator's file position in
/// 1.5.5's form (`config.yaml: invalid YAML: <path>: <reason> at line L column C`).
///
/// # Errors
///
/// The first refusal.
pub fn validate_dealt<'s>(
    doc: &Document,
    seats: impl IntoIterator<Item = (&'s str, Seat<'s>)>,
    mut validate: impl FnMut(&'s str, &[u8]) -> Result<(), String>,
) -> Result<(), String> {
    for (instance, seat) in seats {
        let Some(section) = doc.deal(seat) else {
            continue;
        };
        // A plane's verb sections, keyed by their top-level names, carry a secret reference at every
        // credential position `${VAR}` filled: a plane never receives secret bytes (THE DESIGN §6).
        // An instance's own settings are a non-plane plugin's, which may hold the secrets they name.
        let settings = match seat {
            Seat::Verbs(_) => {
                busbar_kernel::config::filled::plane_bound(&[], section.settings.clone())
            }
            Seat::Instance(..) => section.settings.clone(),
        };
        let blob = serde_json::to_vec(&settings).map_err(|e| e.to_string())?;
        validate(instance, &blob).map_err(|reason| {
            format!(
                "config.yaml: invalid YAML: {}",
                doc.refuse(&section, &reason)
            )
        })?;
    }
    Ok(())
}

/// The lifecycle `validate` of one bound door, over `settings` (JSON): its reason when it does not
/// answer READY.
fn validate_door(door: &DoorPlane, settings: &[u8]) -> Result<(), String> {
    use busbar_contract::abi::mechanism::call::{Blob, OutHead, Outcome, BLOB_JSON};
    use busbar_contract::abi::mechanism::lifecycle::{slot as life, ValidateIn};
    use busbar_contract::abi::sdk::door::{blank_in, blank_out};
    let mut err = [0_u8; 1024];
    let mut i: ValidateIn = blank_in();
    i.settings = Blob {
        ptr: settings.as_ptr(),
        len: settings.len(),
        fmt: BLOB_JSON,
        flags: 0,
    };
    i.err_buf = err.as_mut_ptr();
    i.err_cap = err.len();
    let mut f = super::loader::dispatch::Frame::new(i, blank_out::<OutHead>());
    let called = door.call(life::VALIDATE, &mut f);
    if called.outcome == Outcome::Ready {
        return Ok(());
    }
    Err(called.error.map_or_else(
        || format!("{:?}", called.outcome),
        |e| String::from_utf8_lossy(&e).into_owned(),
    ))
}

/// STAGE 1, DISCOVER (the dropped-in half): every admitted plugin in `registry` whose signed
/// manifest states a Statement, read off that rendering. A 1.6.0 plugin states one; a manifest that
/// states none keeps today's handling.
///
/// # Errors
///
/// A stated rendering that does not read back, naming the plugin.
pub fn discover(registry: &PluginRegistry) -> Result<Vec<Candidate>, String> {
    discovered(registry, |_| true)
}

/// [`discover`] over the admitted plugins whose manifest kind `keep` accepts.
fn discovered(
    registry: &PluginRegistry,
    keep: impl Fn(&str) -> bool,
) -> Result<Vec<Candidate>, String> {
    let mut out = Vec::new();
    for row in registry
        .loadable()
        .iter()
        .filter(|r| keep(&r.manifest.kind))
    {
        let Some(stated) = row
            .manifest
            .stated_rendering()
            .map_err(|e| format!("plugin '{}': {e}", row.manifest.name))?
        else {
            continue;
        };
        let origin = Origin::Dropped {
            file: row.file.clone(),
            bytes: Arc::new(row.lib_bytes.clone()),
        };
        out.push(
            Candidate::from_manifest(stated, &row.manifest, origin)
                .map_err(|e| format!("plugin '{}': {e}", row.manifest.name))?,
        );
    }
    Ok(out)
}

/// What stages 0-2 found, for `--validate`'s report.
pub struct Stages {
    /// The discovered plugins.
    pub candidates: Vec<Candidate>,
    /// The instances selected over them.
    pub selected: Vec<Selected>,
    /// THE ONE LIST OF LISTENERS (boot stage 3f's input): the root's own, then every selected
    /// instance's inbound listener, each with its bind.
    pub inbound: Vec<InboundBind>,
}

impl Stages {
    /// One report line per discovered plugin: its stated facts and whether the configuration uses
    /// it.
    pub fn lines(&self) -> Vec<String> {
        self.candidates
            .iter()
            .enumerate()
            .map(|(i, c)| {
                let used: Vec<&str> = self
                    .selected
                    .iter()
                    .filter(|s| s.candidate == i)
                    .map(|s| s.instance.as_str())
                    .collect();
                let abi = ManifestFacts::read(&c.stated).map_or(0, |f| f.kind_abi);
                let status = if used.is_empty() {
                    "not used by this config".to_string()
                } else {
                    format!("selected as {}", used.join(", "))
                };
                format!(
                    "    plugin: {} ({}, ABI {abi}) — {status}",
                    c.name,
                    kind_word(c.kind)
                )
            })
            .chain(
                self.inbound
                    .iter()
                    .filter(|b| b.owner != BindOwner::Root)
                    .map(|b| {
                        let tls = if b.tls.is_some() { "tls" } else { "clear" };
                        format!(
                            "    listens: {} on {} over {} ({tls}, at most {} connections)",
                            b.at, b.listen, b.transport, b.max_conns
                        )
                    }),
            )
            .collect()
    }
}

fn kind_word(k: KindCode) -> String {
    format!("{k:?}").to_ascii_lowercase()
}

/// `--validate`'s STAGES 0-2 over the configuration at `path` and the dropped-in plugins the
/// preflight admitted: Plan, Discover, Select — see [`stages`]. `root` are the host's own listeners
/// ([`root_binds`]). Nothing is opened.
///
/// # Errors
///
/// The first refusal.
pub fn validate(
    path: &std::path::Path,
    registry: &PluginRegistry,
    root: &RootListens<'_>,
) -> Result<Stages, String> {
    let doc = document(path)
        .map(|d| d.value().clone())
        .unwrap_or_default();
    let root = root_binds(&doc, root);
    stages(&doc, discover(registry)?, root)
}

/// The addresses the host's own listeners take, as the resolved configuration states them.
#[derive(Debug, Clone, Copy)]
pub struct RootListens<'a> {
    /// The data door (`listen`).
    pub listen: &'a str,
    /// The admin surface (`admin_listen`).
    pub admin_listen: &'a str,
}

/// THE ROOT'S OWN LISTENERS AS BINDS, the head of the one list: the data door at `listen` with the
/// raw `tls` block, and the admin surface at `admin_listen` with the raw `admin_tls` block. They
/// keep 1.5.5's bound: no connection cap. An address is a socket address or a name it resolves to
/// (its first address, as 1.5.5's listener bound); one that resolves to none binds nothing here.
#[must_use]
pub fn root_binds(doc: &serde_json::Value, root: &RootListens<'_>) -> Vec<InboundBind> {
    [
        ("listen", root.listen, "tls"),
        ("admin_listen", root.admin_listen, "admin_tls"),
    ]
    .into_iter()
    .filter_map(|(setting, addr, tls)| {
        Some(InboundBind {
            owner: BindOwner::Root,
            transport: String::new(),
            at: setting.to_string(),
            listen: addr
                .parse()
                .ok()
                .or_else(|| std::net::ToSocketAddrs::to_socket_addrs(addr).ok()?.next())?,
            tls: doc.get(tls).filter(|v| !v.is_null()).cloned(),
            max_conns: u64::MAX,
        })
    })
    .collect()
}

/// STAGES 0 and 2 over `doc` and the discovered `candidates`: Select; the one list of listeners,
/// `root` first, then every selected instance's inbound listener read from its settings — two
/// listeners on one address are refused here, before anything binds; and the loader's version refusal for every
/// SELECTED plugin whose Statement states a mechanism or kind ABI version other than this host's,
/// naming the rebuild (BUSBAR-1.6.0.md §11.8).
///
/// # Errors
///
/// The first refusal.
pub fn stages(
    doc: &serde_json::Value,
    candidates: Vec<Candidate>,
    root: Vec<InboundBind>,
) -> Result<Stages, String> {
    let uses = Uses::of(doc);
    let selected = select(&uses, &candidates);
    refuse_inbound(&candidates, &selected)?;
    let inbound = inbound(doc, &candidates, &selected, root)?;
    for s in &selected {
        let c = &candidates[s.candidate];
        let facts =
            ManifestFacts::read(&c.stated).map_err(|e| format!("plugin '{}': {e}", c.name))?;
        let host = facts.kind.abi_version();
        let refusal =
            if facts.mechanism_version != busbar_contract::abi::mechanism::MECHANISM_VERSION {
                Some(LoadError::ManifestMechanism {
                    stated: facts.mechanism_version,
                    host: busbar_contract::abi::mechanism::MECHANISM_VERSION,
                })
            } else if facts.kind_abi != host {
                Some(LoadError::ManifestKindAbi {
                    stated: facts.kind_abi,
                    host,
                })
            } else {
                None
            };
        if let Some(r) = refusal {
            return Err(format!("plugin '{}' ({}): {r}", c.name, s.instance));
        }
    }
    Ok(Stages {
        candidates,
        selected,
        inbound,
    })
}

/// NO ACCEPTED CONNECTION HAS A CONSUMER YET (ARCHITECT ruling 2026-09-30): a selected plugin
/// that declares an inbound need is refused, naming the need, rather than bound and closed. The
/// driver binding that serves an accepted connection removes this refusal.
///
/// # Errors
///
/// The first selected instance with an inbound need.
fn refuse_inbound(candidates: &[Candidate], selected: &[Selected]) -> Result<(), String> {
    use busbar_contract::abi::host::conn::connector::DIRECTION_INBOUND;
    for s in selected {
        let Some(c) = candidates.get(s.candidate) else {
            continue;
        };
        if let Some((i, n)) = c
            .needs
            .iter()
            .enumerate()
            .find(|(_, n)| n.direction == DIRECTION_INBOUND)
        {
            return Err(format!(
                "{} ({}): inbound need {i} over `{}` cannot be served by this build (nothing \
                 serves an accepted connection yet); remove the plugin from the configuration",
                s.instance, c.name, n.transport
            ));
        }
    }
    Ok(())
}

/// BOOT'S HALF OF [`refuse_inbound`]: the configuration at `path` over the dropped-in plugins
/// `registry` admitted, discovered and selected as `--validate` does, refused the same way.
///
/// # Errors
///
/// A Statement that does not read back, or a selected plugin with an inbound need.
pub fn refuse_unserved_inbound(
    path: &std::path::Path,
    registry: &PluginRegistry,
) -> Result<(), String> {
    let doc = document(path)
        .map(|d| d.value().clone())
        .unwrap_or_default();
    let candidates = discover(registry)?;
    refuse_inbound(&candidates, &select(&Uses::of(&doc), &candidates))
}

/// THE PLUGINS DROPPED INTO THE CONFIGURED `plugins.dir`, scanned ONCE before any axis is installed —
/// so before the configuration is parsed, which needs those axes — and kept for the process, whose
/// dropped-in planes and export modules are opened from it. Only the kernel-owned `plugins:` block is
/// read, off the same file and environment interpolation the boot load uses; the trust policy and
/// the persisted first-party floors are resolved as the preflight resolves them. No `plugins:`
/// block, `enabled: false`, or no readable file: `None`, and the directory is not read. A scan the
/// loader refuses is `None` here too — the plugins preflight reads the same directory under the same
/// policy later in boot and refuses it there with every problem named.
///
/// The build's LINKED export sinks ([`Linked::export_doors`], K9b) are registered into the same registry
/// ahead of the directory's rows, through the one admission (`PluginRegistry::link`) — so the export
/// axis holds both doors' rows, and a build that links a sink has an axis with no `plugins:` block.
pub fn dropped_from_config(
    linked: &Linked,
) -> Option<&'static crate::root::loader::PluginRegistry> {
    let rows = linked_exports(linked.export_doors).unwrap_or_else(|refusal| {
        eprintln!("busbar: {refusal}");
        std::process::exit(2);
    });
    let scanned = scan_configured();
    if scanned.is_none() && rows.is_empty() {
        return None;
    }
    let registry = scanned.unwrap_or_else(crate::root::loader::PluginRegistry::empty);
    let registry = registry.link(rows).unwrap_or_else(|refusal| {
        eprintln!("busbar: {refusal}");
        std::process::exit(2);
    });
    // Kept for the process — the export axis and the diagnostics axis read it for as long as it
    // serves — in the one registry slot boot fills.
    Some(REGISTRY.get_or_init(|| registry))
}

/// The one plugin registry [`dropped_from_config`] builds, held for the process.
pub(crate) static REGISTRY: std::sync::OnceLock<crate::root::loader::PluginRegistry> =
    std::sync::OnceLock::new();

/// The plugin registry [`dropped_from_config`] built and kept, once it has (no rescan). The door
/// composition reads it to seal each door-plane member's egress over the dropped-in auth plugins
/// (`root::door_steps::OutboundAuths`).
pub fn dropped_registry() -> Option<&'static crate::root::loader::PluginRegistry> {
    REGISTRY.get()
}

/// The configured `plugins.dir`'s admitted rows (see [`dropped_from_config`]).
fn scan_configured() -> Option<crate::root::loader::PluginRegistry> {
    let path =
        crate::root::cli::resolve_config_path(crate::root::cli::config_path_flag().as_deref());
    let raw = std::fs::read_to_string(path).ok()?;
    let text = busbar_kernel::config::interpolate_env_with(
        &raw,
        busbar_kernel::config::EnvSubst::Lenient,
        &mut Vec::new(),
    )
    .ok()?;
    let doc: serde_yaml::Value = serde_yaml::from_str(&text).ok()?;
    let plugins =
        serde_yaml::from_value::<busbar_kernel::config::PluginsCfg>(doc.get("plugins")?.clone())
            .ok()
            .filter(|p| p.enabled)?;
    let l = &plugins.logs;
    let words = (l.dir.as_deref(), l.level.as_deref(), &l.levels);
    if let Ok(logs) = crate::root::loader::dispatch::PluginLogConfig::from_words(
        words.0,
        words.1,
        words.2,
        l.rotate_mb,
        l.keep,
    ) {
        let _ = LOGS.set(logs);
    }
    plugins.warn_invalid_floors();
    let data_dir = busbar_kernel::preflight::fleet_data_dir();
    let registry =
        crate::root::boot::registry(Vec::new(), Some(&plugins), data_dir.as_deref(), &mut |_| {})
            .ok()?;
    admit_dropped_secrets(&registry).ok()?;
    Some(registry)
}

/// THE PLANES DROPPED INTO `dropped` (see [`dropped_from_config`]) AND THE LINKED PLANE DOORS: every
/// plane that states itself through a door is discovered here and bound by [`load_door_planes`] once
/// the process's dispatcher is built. A trusted plane that will not state itself, or has no door,
/// refuses the boot, as a linked plane's would.
pub fn discover_planes(linked: &Linked, dropped: Option<&crate::root::loader::PluginRegistry>) {
    let set = match dropped {
        Some(registry) => registry.open_planes(linked.plane_doors),
        None => crate::root::loader::PluginRegistry::empty().open_planes(linked.plane_doors),
    };
    let set = set.unwrap_or_else(|refusal| {
        eprintln!("busbar: {refusal}");
        std::process::exit(2);
    });
    let _ = DOOR_CANDIDATES.set(set.doors);
}

/// The declaring sections of the discovered door planes the boot never bound (Law 7: the boot
/// configuration writes none of their sections). Like a bound plane left unopened, each is
/// restart-to-apply (`door_steps::Rules::hold_unopened`); the fallback plane is never one.
#[must_use]
pub fn unbound_sections() -> Vec<&'static str> {
    let bound = door_planes();
    DOOR_CANDIDATES
        .get()
        .map_or(&[][..], Vec::as_slice)
        .iter()
        .filter(|c| !bound.iter().any(|(instance, _)| *instance == c.name))
        .filter_map(|c| c.verbs.first())
        .filter_map(|section| {
            busbar_kernel::plane_driver::registry::plane_decl_for_config_section(section)
        })
        .filter(|decl| !decl.fallback)
        .map(|decl| decl.config_section)
        .collect()
}

/// The `base_url` of every resolved provider (its catalog definition merged with the document's
/// deployment), noted by `main` once the configuration resolves and before the seal opens the
/// dropped-in transports ([`transport_uses`]).
static PROVIDER_URLS: std::sync::OnceLock<Vec<String>> = std::sync::OnceLock::new();

/// Note the resolved providers' `base_url`s (`main`, once, before the seal).
pub fn note_provider_urls(urls: impl IntoIterator<Item = String>) {
    let _ = PROVIDER_URLS.set(urls.into_iter().collect());
}

/// WHAT SELECTS A DROPPED-IN TRANSPORT (Law 7; `BUSBAR-1.6.0.md` §4, "a transport loads iff a
/// configured URL uses a scheme it claims"): the URL schemes the configuration file uses, and those
/// of the resolved providers' `base_url`s, which a catalog definition carries when the document
/// does not. And every scheme a linked transport claims: a dropped-in transport claiming one is a
/// second owner of it, opened so the seal refuses the boot as it refuses a second linked row with
/// that key (two transports claiming one scheme refuse boot).
fn transport_uses() -> Uses {
    let mut uses = plan(&config_path()).reaching(
        PROVIDER_URLS
            .get()
            .map_or(&[][..], Vec::as_slice)
            .iter()
            .map(String::as_str),
    );
    uses.schemes.extend(
        crate::LINKED_TRANSPORT_DOORS
            .iter()
            .filter_map(|(_, door)| Candidate::linked(*door).ok())
            .flat_map(|c| c.schemes),
    );
    uses
}

/// The door planes [`discover_planes`] discovered, waiting for the dispatcher.
pub(crate) static DOOR_CANDIDATES: std::sync::OnceLock<Vec<crate::root::loader::boot::Candidate>> =
    std::sync::OnceLock::new();

/// The door planes [`load_door_planes`] bound, held for the process.
static DOOR_PLANES: std::sync::OnceLock<Vec<(String, DoorPlane)>> = std::sync::OnceLock::new();

/// A plane bound through its door, shared (a `Plugin` is `!Clone`, THE DESIGN C.1): the boot's
/// list, each generation's plane instance and its config-apply holder share the one instance.
pub type DoorPlane = std::sync::Arc<
    crate::root::loader::dispatch::Plugin<crate::root::loader::dispatch::kinds::plane::Plane>,
>;

/// THE DOOR PLANES' ONE LOAD, run once the process's dispatcher is built
/// ([`crate::root::dispatch::boot`]): every plane [`discover_planes`] discovered, linked and
/// dropped alike, bound through the loader's one load on that dispatcher, each to its own log sink
/// under the configured `plugins.logs`, each declaring its needs on the process's one connection
/// table (`root::connector::the()`). A plane that will not bind refuses the boot (exit 2).
///
/// LAW 7: only a plane the configuration uses is bound — one that owns a section among `sections`,
/// the keys the boot composes its door planes over (the document's plane sections and the
/// kernel-owned sections it hands them, `pools` whenever `models` is), so a plane is bound exactly
/// when the composition can open it.
pub fn load_door_planes<'s>(sections: impl IntoIterator<Item = &'s str>) {
    let doors = DOOR_CANDIDATES.get().map_or(&[][..], Vec::as_slice);
    let uses = Uses {
        roots: sections.into_iter().map(str::to_string).collect(),
        ..Uses::default()
    };
    let used = crate::root::loader::boot::used_planes(&uses, doors);
    // The process's ONE connection table: a plane that declares a need is declared on it.
    let conns: std::sync::Arc<dyn busbar_contract::conn::DeclaredConns> =
        crate::root::connector::the().clone();
    let bound = crate::root::loader::boot::load_planes(
        &used,
        plugin_logs(),
        std::sync::Arc::new(crate::root::loader::dispatch::NoSink),
        crate::root::dispatch::dispatcher().adopter(),
        u32::MAX,
        crate::root::loader::dispatch::ConnTable::Host(conns),
    )
    .unwrap_or_else(|refusal| {
        eprintln!("busbar: {refusal}");
        std::process::exit(2);
    })
    .into_iter()
    .map(|(instance, plane)| (instance, std::sync::Arc::new(plane)))
    .collect::<Vec<(String, DoorPlane)>>();
    // Stage 3g: every bound door validates the section dealt to it before anything opens.
    let path =
        crate::root::cli::resolve_config_path(crate::root::cli::config_path_flag().as_deref());
    if let Some(doc) = document(std::path::Path::new(&path)) {
        let seats = doors.iter().map(|c| {
            (
                c.name.as_str(),
                Seat::of(kind_of(c.kind), &c.verbs, &c.name),
            )
        });
        let refused = validate_dealt(&doc, seats, |instance, settings| {
            bound
                .iter()
                .find(|(name, _)| name == instance)
                .map_or(Ok(()), |(_, door)| validate_door(door, settings))
        });
        if let Err(refusal) = refused {
            eprintln!("busbar: {refusal}");
            std::process::exit(2);
        }
    }
    let _ = DOOR_PLANES.set(bound);
}

/// The configured `plugins.logs` ([`scan_configured`] reads it), or its defaults.
static LOGS: std::sync::OnceLock<crate::root::loader::dispatch::PluginLogConfig> =
    std::sync::OnceLock::new();

pub(crate) fn plugin_logs() -> &'static crate::root::loader::dispatch::PluginLogConfig {
    LOGS.get_or_init(|| {
        let none = Default::default();
        crate::root::loader::dispatch::PluginLogConfig::from_words(None, None, &none, None, None)
            .expect("the plugins.logs defaults resolve")
    })
}

/// FOLLOW A CONFIG APPLY'S `plugins.logs` (THE DESIGN §11.2: a plugin's level and its file's
/// rotation change through an apply): `logs`, and every sink opened from it or a clone of it, take
/// the applied words, live sinks at their next line. Words that do not resolve keep the ones in
/// force (the apply's pre-flight refuses them first).
pub(crate) fn follow_plugin_logs(
    logs: &crate::root::loader::dispatch::PluginLogConfig,
    plugins: &busbar_kernel::config::PluginsCfg,
) {
    let l = &plugins.logs;
    match crate::root::loader::dispatch::PluginLogConfig::from_words(
        l.dir.as_deref(),
        l.level.as_deref(),
        &l.levels,
        l.rotate_mb,
        l.keep,
    ) {
        Ok(next) => logs.reconfigure(&next),
        Err(e) => tracing::warn!(error = %e, "plugins.logs kept its words across a config apply"),
    }
}

/// Every plane bound through its door, by instance name (empty until [`load_door_planes`] runs).
pub fn door_planes() -> &'static [(String, DoorPlane)] {
    DOOR_PLANES.get().map_or(&[], Vec::as_slice)
}

/// THE TRANSPORTS DROPPED INTO THE CONFIGURED `plugins.dir` (the registry [`dropped_from_config`]
/// scanned): every `kind: transport` plugin it admitted, loaded ONCE and held for the process, so the
/// boot seal folds them beside the linked wires (`crate::root::registry::compose`) and a wire the
/// data door serves through lives as long as the door. Each image is a memory-ABI door, opened
/// through the one dispatcher and served over the host's sockets (`crate::root::doors`, opened with
/// the deployment's `settings`; the boot's call is the one that loads them). A trusted transport
/// that will not LOAD, or that exports no door, refuses the boot, as a linked plane's would.
pub fn dropped_transports(
    settings: &busbar_contract::transport::TransportSettings,
) -> crate::root::registry::Dropped {
    static WIRES: std::sync::OnceLock<Vec<crate::root::registry::DroppedDoor>> =
        std::sync::OnceLock::new();
    let doors = WIRES.get_or_init(|| {
        let Some(registry) = REGISTRY.get() else {
            return Vec::new();
        };
        let opened = registry
            .open_transport_entries(&crate::root::doors::bind(), &transport_uses(), plugin_logs())
            .and_then(|entries| {
                entries
                    .doors
                    .into_iter()
                    .map(|plugin| {
                        let facts = plugin
                            .context::<crate::root::loader::dispatch::kinds::transport::TransportFacts>()
                            .cloned()
                            .ok_or_else(|| format!("`{}` states no transport tail", plugin.name()))?;
                        let key = facts.claims.first().copied().unwrap_or_default();
                        let claims = facts.claims;
                        let composes_over = facts.composes_over;
                        let offered = facts.offered;
                        let upgrades = facts.upgrades;
                        let (door, wire) = crate::root::doors::served(plugin, settings)?;
                        Ok(crate::root::registry::DroppedDoor {
                            key,
                            claims,
                            composes_over,
                            offered,
                            upgrades,
                            wire,
                            door,
                        })
                    })
                    .collect::<Result<Vec<_>, String>>()
            });
        opened.unwrap_or_else(|refusal| {
            eprintln!("busbar: {refusal}");
            std::process::exit(2);
        })
    });
    crate::root::registry::Dropped { doors }
}

/// THE BOOT BOOK, COMPOSED — the extracted seam [`book`] calls, wired against a store
/// adapter so its behaviour can be proved without a bound listener or a loaded plugin behind it.
///
/// Three decisions, made together here because they are ONE value and a caller that made them
/// separately would have a node whose halves disagree:
///
/// 1. **The journal is KEPT BY THE CONFIGURED STORE** (ARCHITECT 2026-10-07 H3 ruling (a)-(c)): each
///    record goes through `lane`, the host's bounded write-behind lane, to the store's v3
///    `record_put` slot under the journal schema. With no data directory the chain the store kept is
///    READ BACK first and the journal resumes it, so the book, the open holds, the audit records,
///    the dated rate-card history and the amendments are what they were before the restart; with
///    one the disk is the record and the store is catch-up work. See [`super::durability`]'s
///    preamble for what a full lane means.
/// 2. **The ledger dual-writes onto the in-memory reconciliation rows.** That half stays memory: it
///    is the cross-check the reconciliation identity is read from, not the acknowledgement path.
/// 3. **The OPENING IS SEALED, here, before this function returns.** The previous release's rows are
///    read through the same adapter and sealed as the opening figures, with the marker written onto
///    THIS journal rather than the adapter's node-local shim — which could only ever hold it for the
///    life of a process.
///
/// **THE ORDER IS THE WHOLE POINT.** The seal happens before the composed book is handed back, so it
/// is impossible for a caller to reach a settlement path with an unopened book: the first accepted
/// connection can settle, and a settlement posted before the opening was sealed would measure its
/// residual from a checkpoint that did not exist when it happened. An opening sealed after traffic
/// has begun is worse than no opening at all, because it looks authoritative.
///
/// It returns the wired stack, the rows a view reads them back from, and what the migration did.
/// The opening is signed with the audit chain's own key (Q71(3): one keyset); a chain given no key
/// seals it unsigned, which the ledger unit accepts.
///
/// # Errors
///
/// The journal could not be opened (a configured data directory that could not be read), or the
/// opening could not be sealed — the two boot conditions [`super::migration::run`] returns where
/// continuing would be worse than refusing. A store that merely would not answer for some rows is
/// NOT one of them; see that module's preamble.
pub fn compose_book(
    adapter: &super::loader::store_adapter::StoreAdapter,
    lane: super::durability::JournalLane,
    data_dir: Option<std::path::PathBuf>,
    mig: &super::migration::MigrationConfig,
    now: u64,
    token: &busbar_contract::caps::Grant<busbar_contract::caps::DurableWrite>,
) -> Result<
    (
        super::durability::Durability,
        Arc<busbar_kernel_ledger::legacy::SummedRows>,
        super::migration::Migration,
    ),
    String,
> {
    // The dual write's rows as running sums, one per cell: memory bounded by the cells the node
    // settles into, never by how many settlements it makes (the journal is the durable record).
    let rows = Arc::new(busbar_kernel_ledger::legacy::SummedRows::new());
    let mut durability = super::durability::build_on_store(
        &super::durability::DurabilityConfig {
            data_dir: data_dir.clone(),
        },
        mig.node,
        lane,
        Box::new(busbar_kernel_ledger::legacy::SummedRows::clone(&rows)),
        Box::new(|| crate::root::kernel::ROOT_CARD.pin()),
        Some(&crate::root::kernel::ROOT_CARD),
    )
    .map_err(|e| format!("the boot ledger's log could not be opened: {e}"))?;
    // The node amendment journal is rebuilt from the chain before anything can seal onto it, so a
    // corrected count and every recorded content access survive the restart — off the disk, or off
    // the chain the store kept. A chain that will not read back refuses the boot here as it would
    // have at the book's build: taken for an empty one, every signed correction would revert.
    durability.restore_amendments()?;
    // A corrupt journal segment was already logged and counted when the book was built; this puts
    // the durable record of it on the chain. A failed append is logged, never a refusal to boot.
    if let Err(lost) =
        durability.journal_quarantines(token, busbar_contract::caps::StepName::Meter, now)
    {
        tracing::error!(
            step = lost.step().as_str(),
            "the journal could not record the quarantine boot recovery made"
        );
    }
    // THE DEPLOYMENT KEYSET (spec #82(a); BUSBAR-1.6.0.md THE DESIGN, §2, PB-13; architect ruling 2026-09-26),
    // bound BEFORE the opening is sealed so checkpoint 0 is signed with it too. With a data
    // directory the first boot mints it, caches it there (0600) and seals its fingerprint in a
    // `Bootstrap` record; a later boot that cannot produce that fingerprint refuses `KeysetMissing`.
    // Without one it is ephemeral: minted for this process, written nowhere, checked by nothing.
    super::keyset::bind(
        &mut durability,
        data_dir.as_deref(),
        token,
        busbar_contract::caps::StepName::Meter,
        now,
    )
    .map_err(|e| e.to_string())?;
    // The opening is sealed under the identity the journal writes as: the node's stable id, or the
    // one a data directory's chain was written under.
    let mig = &super::migration::MigrationConfig {
        node: durability.journal.node(),
        ..mig.clone()
    };
    let migration = {
        let (mut records, signer) =
            durability.migration_records_signed(token, busbar_contract::caps::StepName::Meter);
        let signer = signer
            .as_ref()
            .map(|s| s as &dyn busbar_kernel_ledger::checkpoint::CheckpointSecret);
        super::migration::run(adapter, &mut records, mig, now, signer)
            .map_err(|e| format!("the boot ledger could not seal its opening balances: {e}"))?
    };
    Ok((durability, rows, migration))
}

/// STAGE 4, BOOK (`BUSBAR-1.6.0.md` §3, the stage table: "open the store, replay the WAL, seal the
/// opening, bind the keyset — at boot only"): THE PROCESS'S ONE BOOK, opened over the deployment's
/// configured store with its balances sealed. Boot calls it once. Reload runs stages 1–3 and 5 and
/// never Book (`BUSBAR-1.6.0.md` §3, and its round-2 ruling "Book stage and store are BOOT-ONLY"): a rebuilt
/// generation carries the store it was handed, so a reload neither reopens the store nor seals a
/// second opening.
///
/// The book's journal is kept by the configured store, `store` by name: its records go to the store's
/// v3 record slots and a boot with no data directory reads them back (ARCHITECT 2026-10-07 H3
/// ruling). The opening is sealed from the rows the previous release left in that store.
///
/// A configuration names its store (Q-STORE = (B), Appendix B 2026-09-27), so a boot that resolved
/// none refuses; and a store that does not offer the record slots cannot keep a journal, so the
/// boot refuses that too, naming the store and the slots.
///
/// The data directory is the one [`busbar_kernel::preflight::fleet_data_dir`] resolves — the SAME
/// accessor the plugin anti-downgrade floor persists under, so the two can never disagree about
/// where this node keeps its own files. Absent, the branch in
/// [`super::durability::build_for_node`] is the unset one and nothing is probed, nothing is opened
/// and no file appears: this wiring gives a node with a CONFIGURED directory somewhere to write, and
/// deliberately does not make writing unconditional.
///
/// # Errors
///
/// No store resolved, the store offers no record slots, its lane could not start, or
/// [`compose_book`] refused.
pub fn book(
    app: &busbar_kernel::state::App,
    store: &str,
) -> Result<super::durability::NodeBook, String> {
    let Some(gov) = app.governance.as_ref() else {
        return Err(
            "the boot book needs the configured store and none resolved; add a store, e.g. \
             `store: {module: memory}`, or run `busbar migrate` (Q-STORE)"
                .to_string(),
        );
    };
    let Some(calls) = gov.store_calls() else {
        return Err(no_record_slots(store));
    };
    let lane = super::durability::JournalLane::start(calls, store)?;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());
    let adapter = super::loader::store_adapter::StoreAdapter::native(gov.store());
    // THIS NODE'S IDENTITY (ARCHITECT 2026-10-07 H3 ruling, follow-up; Q128 root part 12 HIGH 2):
    // with a data directory, the id kept in it (adopting the registry's id for this host on the
    // first boot that has none, and then holding the host name's lease for it); without one, the store registry's id for this host while this
    // process holds the host name's lease, else a fresh id of its own. Its journal records are
    // keyed by it, so two live nodes on one store never write under one identity, whatever their
    // host names. The host name is only a label.
    let data_dir = busbar_kernel::preflight::fleet_data_dir();
    let host = super::durability::host_identity();
    let calls = lane.calls();
    let taken = match data_dir.as_deref() {
        Some(dir) => super::durability::persisted_node(calls.as_ref(), dir, &host),
        None => super::durability::take_node(calls.as_ref(), &host),
    }
    .map_err(|why| format!("this node's identity in the store `{store}`: {why}"))?;
    // THE FIRST-PARTY ANTI-DOWNGRADE FLOOR, held in the store for this host: the scan ran before
    // the store opened, so a dropped-in first-party plugin below the mark the store keeps refuses
    // the boot here, and the marks rise to what loaded.
    super::durability::hold_plugin_floor(
        calls.as_ref(),
        &host,
        app.hook_env.registry.as_ref(),
        &app.plugins_cfg.first_party_floors,
    )?;
    // The lease is held on the lane to the store it is held in, the lane this book keeps: its
    // checkpoint flush tick refreshes it and the clean shutdown releases it.
    if let Some(lease) = taken.lease {
        lane.hold_lease(lease);
    }
    let node = taken.id;
    let mig = super::migration::MigrationConfig {
        node,
        ..super::migration::config_from(&app.cost, now)
    };
    let token = super::kernel::new_kernel().durability_token();
    let (durability, rows, migration) = compose_book(&adapter, lane, data_dir, &mig, now, &token)?;
    // WHAT THE DISASTER-RECOVERY VERBS LEFT (row 187): the chain's operator breaks, read as
    // deliberate.
    super::durability::report_operator_breaks(&durability);
    // THE CALLER REFERENCE OF EVERY VERIFIED PRINCIPAL (row 159 H2): a node that keeps no signing
    // material derives it from the deployment keyset just bound, so no verified principal is lent
    // an empty reference and two principals never share one. A node with neither keeps this
    // boot's random key, so its references differ from every other node's and from its own after
    // a restart: a deployment that meant to bind a keyset reads that here. DEBUG, not INFO: the
    // INFO+ boot lines are pinned by `tests/boot_lines_neutrality.rs`.
    if let Some(material) = durability
        .record
        .derived_secret(super::keyset::CALLER_REF_MATERIAL)
    {
        gov.bind_deployment_caller_ref(material);
    } else {
        tracing::debug!(
            node = mig.node,
            "no deployment keyset is bound: caller references are keyed by this boot's random key \
             unless the node keeps signing material, so they differ per node and per restart"
        );
    }
    // DEBUG, NOT INFO, and that is a neutrality decision rather than a taste one. The
    // boot log's INFO+ line set is part of what "one plane alone ≡ 1.5.5" means — it is pinned
    // by `tests/boot_lines_neutrality.rs` and recorded by the oracle's
    // `hazard|no-data-dir|logs` cell — so a new line here is a user-visible byte change
    // on a surface that must not move. The seal is an internal fact an operator can ask
    // for; it is not news a 1.5.5 deployment ever printed.
    if migration.sealed_now() {
        tracing::debug!(
            node = mig.node,
            rate_card_version = mig.rate_card_version,
            "the boot ledger sealed its opening balances from the configured store"
        );
    }
    // THIS ONE STAYS A WARN, and the asymmetry is deliberate: it fires only when the store
    // would not list its key rows, which means the opening is INCOMPLETE — sealed over the
    // buckets configuration named and missing the ones the store would have. A money fact
    // that degraded silently to keep a log shape would be the wrong trade. It cannot fire
    // on the neutral shape: it takes a store that fails to answer, not a store with
    // nothing in it.
    if let Some(reason) = &migration.key_rows_unreadable {
        tracing::warn!(
            reason = %reason,
            "the boot ledger could not list the store's key rows, so the opening was sealed \
             over the buckets the configuration named"
        );
    }
    let durability = Arc::new(std::sync::Mutex::new(durability));
    // Every amendment sealed from here on goes on the book it was rebuilt from.
    super::durability::bind_amendments(&durability);
    // The disaster-recovery verbs reach this book's journal and the store it is shipped to: one
    // store behind the node, not one per seam (row 113, ruling (B); row 187).
    let verb_store = super::durability::node_verb_store(
        Arc::clone(&durability),
        super::kernel::new_kernel().durability_token(),
        store,
    );
    Ok(super::durability::NodeBook {
        durability,
        rows,
        verb_store,
    })
}

/// The boot's refusal of a store that offers no record slots: it cannot keep the journal.
#[must_use]
pub fn no_record_slots(store: &str) -> String {
    format!(
        "the configured store `{store}` does not offer the record slots ({}) the node's journal is \
         kept in; configure a store that implements store ABI v3",
        super::durability::RECORD_SLOTS
    )
}

#[cfg(test)]
#[path = "tests/boot.rs"]
mod tests;
