// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! `busbar --store-kit` (DES-STOREKIT r2), harness builds only: the kernel's store kit
//! (`busbar_kernel::persistence::store_kit`) run against one store's shipped library.
//!
//! ```text
//! busbar --store-kit --pack <signed.tar.gz> --fixture <store-kit.json> [--out <dir>]
//! ```
//!
//! The pack is loaded through the production path only:
//! 1. `tarball::unpack` and `sign::validate_structure`;
//! 2. `admit::admit_bytes` against the boot's trust policy. With `allow_untrusted` off, only this
//!    harness build's first-party key, `BUSBAR_TEST_HARNESS_FIRST_PARTY_KEY`, can sign it;
//! 3. `ImagesBuilder`, then the bootstrap registry, Needs and kernel seal
//!    ([`super::min3_boot::store_kit::KitStore`]).
//!
//! The fixture is data (strict schema `busbar.store-kit/1`, unknown keys refused, never
//! interpolated by a shell). `{dataset}` names one case's dataset and `{instance}` one opened
//! instance.
//!
//! Every case has a deadline ([`CASE_DEADLINE`]), the run has a total one ([`RUN_DEADLINE`]),
//! and nothing is retried.
//!
//! Exit status: 0 when every case passed; 1 when a case failed or timed out; 2 for a usage,
//! fixture, pack or admission refusal, before any case ran.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use busbar_contract::persistence::PersistenceBackend;
use busbar_kernel::persistence::store_kit::{self, Fixture};

use super::min3_boot::store_kit::KitStore;

/// One kit case's deadline.
pub(crate) const CASE_DEADLINE: Duration = Duration::from_secs(120);
/// The whole run's deadline.
pub(crate) const RUN_DEADLINE: Duration = Duration::from_secs(600);
/// The fixture file's size bound.
const FIXTURE_MAX: u64 = 64 * 1024;
/// The fixture schema this runner reads.
const SCHEMA: &str = "busbar.store-kit/1";
const DATASET: &str = "{dataset}";
const INSTANCE: &str = "{instance}";

const EXIT_PASSED: i32 = 0;
const EXIT_FAILED: i32 = 1;
const EXIT_REFUSED: i32 = 2;

/// `testing/conformance/store-kit.json`.
#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct FixtureFile {
    schema: String,
    config: busbar_contract::json::Value,
    dataset_scope: Scope,
}

/// Where one dataset lives.
#[derive(serde::Deserialize, Clone, Copy, PartialEq, Eq, Debug)]
#[serde(rename_all = "lowercase")]
pub(crate) enum Scope {
    /// Every opened instance over `{dataset}` reaches the same data, as a database, file or key
    /// prefix does.
    Shared,
    /// The data lives inside one opened instance, as the memory store's does: every handle on a
    /// dataset is that dataset's first instance.
    Instance,
}

/// The fixture, read and checked: the store's config as JSON text with its two tokens, and its
/// scope.
#[derive(Debug)]
pub(crate) struct Template {
    config: String,
    scope: Scope,
}

impl Template {
    /// Parse `bytes` against the strict schema.
    ///
    /// # Errors
    /// Malformed JSON, an unknown key, another schema, a config that is not an object, or a shared
    /// config that does not name `{dataset}`.
    pub(crate) fn parse(bytes: &[u8]) -> Result<Self, String> {
        let file: FixtureFile = busbar_contract::json::parse(bytes)
            .map_err(|error| format!("the fixture is not a {SCHEMA} document: {error}"))?;
        if file.schema != SCHEMA {
            return Err(format!(
                "the fixture's schema is `{}`; this runner reads `{SCHEMA}`",
                file.schema
            ));
        }
        if !busbar_contract::json::JsonValueTrait::is_object(&file.config) {
            return Err("the fixture's `config` is not an object".into());
        }
        let config = busbar_contract::json::to_string(&file.config)
            .map_err(|error| format!("the fixture's `config` does not encode: {error}"))?;
        if file.dataset_scope == Scope::Shared && !config.contains(DATASET) {
            return Err(format!(
                "a shared-scope fixture must name {DATASET} in its config, or every case would \
                 share one dataset"
            ));
        }
        Ok(Self {
            config,
            scope: file.dataset_scope,
        })
    }

    /// The config for one instance of one dataset. The tokens are replaced in the JSON text by
    /// lower-case ASCII letters, digits and `-`, so no escaping changes.
    pub(crate) fn config(&self, dataset: &str, instance: &str) -> Vec<u8> {
        self.config
            .replace(DATASET, dataset)
            .replace(INSTANCE, instance)
            .into_bytes()
    }
}

/// How the kit reaches the store: one open per handle it asks for.
pub(crate) trait Opener: Send + Sync {
    fn open<'a>(
        &'a self,
        instance: &'a str,
        config: Vec<u8>,
    ) -> busbar_plugin_abi::host_side::caller::BoxFut<'a, Result<Arc<dyn PersistenceBackend>, String>>;
}

impl Opener for KitStore {
    fn open<'a>(
        &'a self,
        instance: &'a str,
        config: Vec<u8>,
    ) -> busbar_plugin_abi::host_side::caller::BoxFut<'a, Result<Arc<dyn PersistenceBackend>, String>>
    {
        Box::pin(async move { KitStore::open(self, instance, &config).await })
    }
}

/// The kit's [`Fixture`] over an [`Opener`] and a [`Template`].
pub(crate) struct KitFixture<O> {
    opener: O,
    template: Template,
    next: AtomicU64,
}

/// One case's dataset: its token and its first handle, kept open for the case.
pub(crate) struct Dataset {
    token: String,
    first: Arc<dyn PersistenceBackend>,
}

impl<O: Opener> KitFixture<O> {
    pub(crate) fn new(opener: O, template: Template) -> Self {
        Self {
            opener,
            template,
            next: AtomicU64::new(1),
        }
    }

    fn next(&self) -> u64 {
        self.next.fetch_add(1, Ordering::Relaxed)
    }

    async fn instance(&self, dataset: &str) -> Arc<dyn PersistenceBackend> {
        let name = format!("store-kit-{}", self.next());
        let config = self.template.config(dataset, &name);
        self.opener
            .open(&name, config)
            .await
            .unwrap_or_else(|refusal| panic!("{} {refusal}", store_kit::MARK))
    }
}

#[async_trait::async_trait]
impl<O: Opener> Fixture for KitFixture<O> {
    type Dataset = Dataset;

    async fn fresh(&self) -> Dataset {
        let token = format!("kit-{}", self.next());
        let first = self.instance(&token).await;
        Dataset { token, first }
    }

    async fn open(&self, dataset: &Dataset) -> Arc<dyn PersistenceBackend> {
        match self.template.scope {
            Scope::Instance => Arc::clone(&dataset.first),
            Scope::Shared => self.instance(&dataset.token).await,
        }
    }
}

/// Run every kit case over `fixture` on `runtime`, each within `case`, all within `total`. `Err`
/// names the failing case (the kit's own panic text) or the deadline that passed.
pub(crate) fn run_kit<O: Opener>(
    runtime: &tokio::runtime::Runtime,
    fixture: &KitFixture<O>,
    case: Duration,
    total: Duration,
) -> Result<(), String> {
    let ran = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        runtime.block_on(tokio::time::timeout(
            total,
            store_kit::run_within(fixture, case),
        ))
    }));
    match ran {
        Ok(Ok(())) => Ok(()),
        Ok(Err(_)) => Err(format!(
            "{} TIMEOUT the run ({} s)",
            store_kit::MARK,
            total.as_secs()
        )),
        Err(panic) => Err(panic
            .downcast_ref::<String>()
            .cloned()
            .or_else(|| panic.downcast_ref::<&str>().map(|text| (*text).to_owned()))
            .unwrap_or_else(|| "a case failed".to_owned())),
    }
}

/// The command line after `--store-kit`.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Args {
    pub(crate) pack: PathBuf,
    pub(crate) fixture: PathBuf,
    pub(crate) out: Option<PathBuf>,
}

impl Args {
    /// `--pack`, `--fixture` (both required) and `--out`, each once, as `--x v` or `--x=v`.
    ///
    /// # Errors
    /// An unknown, repeated, valueless or missing option.
    pub(crate) fn parse(words: &[String]) -> Result<Self, String> {
        let (mut pack, mut fixture, mut out) = (None, None, None);
        let mut words = words.iter();
        while let Some(word) = words.next() {
            let (name, inline) = match word.split_once('=') {
                Some((name, value)) => (name, Some(value.to_owned())),
                None => (word.as_str(), None),
            };
            let slot = match name {
                "--pack" => &mut pack,
                "--fixture" => &mut fixture,
                "--out" => &mut out,
                other => return Err(format!("--store-kit does not take `{other}`")),
            };
            let value = match inline {
                Some(value) => value,
                None => words
                    .next()
                    .cloned()
                    .ok_or_else(|| format!("{name} needs a value"))?,
            };
            if value.is_empty() || value.starts_with('-') {
                return Err(format!("{name} needs a value"));
            }
            if slot.replace(PathBuf::from(value)).is_some() {
                return Err(format!("{name} is given more than once"));
            }
        }
        Ok(Self {
            pack: pack.ok_or("--store-kit needs --pack <signed pack>")?,
            fixture: fixture.ok_or("--store-kit needs --fixture <store-kit.json>")?,
            out,
        })
    }
}

/// Read at most `cap` bytes of a regular file.
fn read_bounded(path: &Path, cap: u64, what: &str) -> Result<Vec<u8>, String> {
    let meta =
        std::fs::metadata(path).map_err(|error| format!("{what} {}: {error}", path.display()))?;
    if !meta.is_file() || meta.len() > cap {
        return Err(format!(
            "{what} {} is not a regular file of at most {cap} bytes",
            path.display()
        ));
    }
    std::fs::read(path).map_err(|error| format!("{what} {}: {error}", path.display()))
}

/// Unpack and admit the pack: structure, sha256, signature and trust, as the plugins directory
/// admits a dropped-in pack.
fn admit(pack: &Path) -> Result<busbar_plugin_loader::admit::Admitted, String> {
    use busbar_plugin_loader::{sign, supported_abi, tarball};
    if std::env::var(super::boot::HARNESS_FIRST_PARTY_KEY_ENV)
        .ok()
        .filter(|key| !key.trim().is_empty())
        .is_none()
    {
        return Err(format!(
            "{} is unset: the pack is admitted only as first-party to this harness build",
            super::boot::HARNESS_FIRST_PARTY_KEY_ENV
        ));
    }
    let bytes = read_bounded(pack, tarball::MAX_TARBALL_FILE_BYTES, "the pack")?;
    let package = tarball::unpack(&bytes).map_err(|error| format!("the pack: {error}"))?;
    sign::validate_structure(
        &package.manifest,
        &package.lib_bytes,
        &supported_abi,
        sign::HOST_IDENTITY,
    )
    .map_err(|error| format!("the pack's manifest: {error}"))?;
    let policy = super::boot::trust_policy(
        &busbar_kernel::config::PluginsCfg::default(),
        env!("CARGO_PKG_VERSION"),
    )?;
    admit_image(&package, &policy)
}

/// `admit::admit_bytes`: a sealed memfd of exactly the verified bytes, then every admission step.
#[cfg(target_os = "linux")]
fn admit_image(
    package: &busbar_plugin_loader::tarball::UnpackedPlugin,
    policy: &busbar_plugin_loader::admit::TrustConfig,
) -> Result<busbar_plugin_loader::admit::Admitted, String> {
    busbar_plugin_loader::admit::admit_bytes(&package.lib_bytes, &package.manifest, policy)
        .map_err(|refusal| format!("admission refused the pack: {refusal}"))
}

/// Only Linux loads plugin images.
#[cfg(not(target_os = "linux"))]
fn admit_image(
    _: &busbar_plugin_loader::tarball::UnpackedPlugin,
    _: &busbar_plugin_loader::admit::TrustConfig,
) -> Result<busbar_plugin_loader::admit::Admitted, String> {
    Err("only Linux loads plugin images".into())
}

/// `busbar --store-kit …`: the exit status.
pub(crate) fn command(words: &[String]) -> i32 {
    match prepare(words) {
        Err(refusal) => {
            eprintln!("busbar --store-kit: {refusal}");
            EXIT_REFUSED
        }
        Ok(prepared) => {
            let result = run_kit(
                &prepared.runtime,
                &prepared.fixture,
                CASE_DEADLINE,
                RUN_DEADLINE,
            );
            let out = prepared.out;
            let (status, line) = match &result {
                Ok(()) => (
                    EXIT_PASSED,
                    format!("{} passed every case", store_kit::MARK),
                ),
                Err(failure) => (EXIT_FAILED, format!("{} FAILED {failure}", store_kit::MARK)),
            };
            println!("{line}");
            if let Some(out) = out {
                if let Err(error) = std::fs::create_dir_all(&out)
                    .and_then(|()| std::fs::write(out.join("store-kit.txt"), format!("{line}\n")))
                {
                    eprintln!("busbar --store-kit: {}: {error}", out.display());
                    return EXIT_FAILED;
                }
            }
            status
        }
    }
}

/// Everything one run needs, kept alive for it.
struct Prepared {
    runtime: tokio::runtime::Runtime,
    fixture: KitFixture<KitStore>,
    out: Option<PathBuf>,
    /// The plugin process resources the registry's slots and ids come from, as `main` keeps
    /// them for the process.
    _process: Arc<busbar_plugin_loader::process::ProcessResources>,
}

fn prepare(words: &[String]) -> Result<Prepared, String> {
    let args = Args::parse(words)?;
    let template = Template::parse(&read_bounded(&args.fixture, FIXTURE_MAX, "the fixture")?)?;
    let image = admit(&args.pack)?;
    let process = Arc::new(
        busbar_plugin_loader::process::ProcessResources::new()
            .map_err(|error| format!("plugin process resources: {error}"))?,
    );
    let mut builder = busbar_plugin_loader::instance::ImagesBuilder::new(
        &busbar_plugin_abi::host_side::host_vt::HOST,
        Arc::clone(process.slots()),
        busbar_plugin_loader::instance::Ceilings::DEFAULT,
    );
    builder
        .admit(image)
        .map_err(|error| format!("the image: {error}"))?;
    // The store reaches its own backend (a local service in CI) as an operator's deployment with
    // `advanced.block_private_addresses: false` lets it; metadata stays refused.
    let guard = busbar_core_connector::guard::Guard::from_config(
        &busbar_kernel::config::sections::Destinations {
            block_private_addresses: false,
            ..busbar_kernel::config::sections::Destinations::default()
        },
    )?;
    let store = KitStore::new(&process, guard, builder.finish())?;
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|error| format!("a runtime: {error}"))?;
    Ok(Prepared {
        runtime,
        fixture: KitFixture::new(store, template),
        out: args.out,
        _process: process,
    })
}

#[cfg(test)]
#[path = "tests/store_kit_run.rs"]
mod tests;
