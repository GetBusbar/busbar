// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Monotonic host acceptance floors. An audited rollback pin authorizes loading a
//! lower plugin version; it never lowers that plugin's remembered floor or the
//! release-key document floor.
use std::sync::Arc;

use super::{
    boot_identity::{error, BootRecords},
    facade::CoreStore,
    scoped::{Expected, Mutation, Predicate},
};
use busbar_contract::semver::version_at_least;
use busbar_contract::{plugin::valid_semver, Secret};

pub const PLUGIN_FLOOR_SCHEMA: &str = "busbar.plugin_floor.v1";
pub const RELEASE_KEYS_FLOOR_SCHEMA: &str = "busbar.release_keys_floor.v1";

pub struct Candidate<'a> {
    pub name: &'a str,
    pub version: &'a str,
    pub file: &'a str,
    pub first_party: bool,
    pub linked: bool,
    pub rollback_pinned: bool,
}
pub struct PluginFloor {
    core: Arc<CoreStore>,
    records: BootRecords,
}
fn floor_key(host: &str, name: &str) -> Result<Vec<u8>, String> {
    let mut key = Vec::new();
    for part in [host, name] {
        let length = u32::try_from(part.len()).map_err(error)?;
        key.extend_from_slice(&length.to_be_bytes());
        key.extend_from_slice(part.as_bytes());
    }
    Ok(key)
}
/// The `(scope, name)` parts of a [`floor_key`]; anything else is a corrupt row.
fn split_floor_key(key: &[u8]) -> Result<(&[u8], &[u8]), String> {
    let malformed = || "a stored plugin floor key is malformed".to_string();
    let mut rest = key;
    let mut parts: [&[u8]; 2] = [&[], &[]];
    for part in &mut parts {
        let (length, tail) = rest.split_first_chunk::<4>().ok_or_else(malformed)?;
        let length = usize::try_from(u32::from_be_bytes(*length)).map_err(|_| malformed())?;
        let (head, tail) = tail.split_at_checked(length).ok_or_else(malformed)?;
        *part = head;
        rest = tail;
    }
    if !rest.is_empty() {
        return Err(malformed());
    }
    Ok((parts[0], parts[1]))
}
/// The higher of two stored floors of one schema. An unreadable plugin floor already refuses its
/// plugin until an audited rollback, so it is kept over a readable one: carrying never lowers a
/// floor.
fn higher_floor(schema: &str, held: Option<&[u8]>, carried: &[u8]) -> Result<Vec<u8>, String> {
    let Some(held) = held else {
        return Ok(carried.to_vec());
    };
    if schema == RELEASE_KEYS_FLOOR_SCHEMA {
        let highest = decode_keys(Some(held))?.max(decode_keys(Some(carried))?);
        return Ok(highest.to_be_bytes().to_vec());
    }
    let read = |bytes: &[u8]| {
        std::str::from_utf8(bytes)
            .ok()
            .filter(|version| valid_semver(version))
            .map(str::to_owned)
    };
    Ok(match (read(held), read(carried)) {
        (Some(have), Some(other)) if !version_at_least(&have, &other) => carried,
        (Some(_), None) => carried,
        _ => held,
    }
    .to_vec())
}
fn decode_keys(bytes: Option<&[u8]>) -> Result<u64, String> {
    bytes.map_or(Ok(0), |bytes| {
        bytes
            .try_into()
            .map(u64::from_be_bytes)
            .map_err(|_| "the release keys-document floor is malformed".into())
    })
}
/// A first-party candidate whose version does not read: refused with its remedy, never exempt from its
/// floor (DES-359 r3 L11, B-R5).
fn unreadable_version(candidate: &Candidate<'_>) -> String {
    format!(
        "the first-party plugin `{}` declares version `{}`, which is not a MAJOR.MINOR.PATCH version, \
         so its anti-downgrade floor cannot be checked and it does not load; install a release whose \
         manifest version reads as MAJOR.MINOR.PATCH (for example 1.6.0 or 1.6.0-rc.1)",
        candidate.name, candidate.version
    )
}
impl PluginFloor {
    pub fn new(core: Arc<CoreStore>) -> Result<Self, String> {
        Ok(Self {
            core: core.clone(),
            records: BootRecords::new(core, &[PLUGIN_FLOOR_SCHEMA, RELEASE_KEYS_FLOOR_SCHEMA])?,
        })
    }
    /// Obtain the final persistent admission observation after any requested floor
    /// raises are confirmed. Generation rows and both floor values are read together.
    pub async fn prepare_admission(
        &self,
        host: &str,
        candidate: Candidate<'_>,
        release_keys_version: Option<u64>,
        archive_sha256: &str,
    ) -> Result<AdmissionProof, String> {
        use busbar_contract::persistence::{Address, NamespaceId, Read, ReadResult};
        let _gate = self.records.gate.lock().await;
        self.records.resume().await?;
        if archive_sha256.len() != 64 || !archive_sha256.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err("plugin admission requires its exact SHA-256 archive identity".into());
        }
        let plugin = super::scoped::migration_address(
            true,
            super::boot_identity::INSTANCE,
            PLUGIN_FLOOR_SCHEMA,
            &floor_key(host, candidate.name)?,
        )
        .map_err(error)?;
        let keys = super::scoped::migration_address(
            true,
            super::boot_identity::INSTANCE,
            RELEASE_KEYS_FLOOR_SCHEMA,
            &floor_key(host, "busbar-release-keys")?,
        )
        .map_err(error)?;
        let plugin_generation = super::fences::scan_guard(NamespaceId(plugin.namespace), 0).address;
        let keys_generation = super::fences::scan_guard(NamespaceId(keys.namespace), 0).address;
        let addresses: Vec<Address> = vec![plugin, keys, plugin_generation, keys_generation];
        let result = self
            .core
            .backend()
            .read(Arc::new(Read {
                dataset: self.core.info().dataset,
                addresses,
                time: None,
            }))
            .await
            .map_err(error)?;
        let ReadResult::Values {
            observed_at,
            values,
        } = result
        else {
            return Err("plugin floor observation was not coherent".into());
        };
        if observed_at.authority != self.core.info().clock_authority || values.len() != 4 {
            return Err("plugin floor observation authority changed".into());
        }
        let seal = crate::seal::lend();
        let decode_generation = |value: &Option<Secret<Vec<u8>>>| -> Result<u64, String> {
            value.as_ref().map_or(Ok(0), |v| {
                let bytes: [u8; 8] = v.expose(&seal).as_slice().try_into().map_err(error)?;
                let generation = u64::from_le_bytes(bytes);
                if generation == 0 {
                    return Err("invalid explicit zero floor generation".into());
                }
                Ok(generation)
            })
        };
        if candidate.first_party && !candidate.linked && !valid_semver(candidate.version) {
            return Err(unreadable_version(&candidate));
        }
        let plugin_floor = if candidate.first_party && !candidate.linked {
            values[0]
                .as_ref()
                .map(|v| String::from_utf8(v.expose(&seal).clone()).map_err(error))
                .transpose()?
        } else {
            None
        };
        let release_floor = decode_keys(values[1].as_ref().map(|v| v.expose(&seal).as_slice()))?;
        let proof = AdmissionProof {
            host: host.into(),
            name: candidate.name.into(),
            version: candidate.version.into(),
            file: candidate.file.into(),
            first_party: candidate.first_party,
            linked: candidate.linked,
            rollback_pinned: candidate.rollback_pinned,
            release_keys_version,
            archive_sha256: archive_sha256.into(),
            plugin_floor,
            release_floor,
            dataset: self.core.info().dataset,
            _scope_generations: [
                decode_generation(&values[2])?,
                decode_generation(&values[3])?,
            ],
        };
        proof.check(host, candidate, release_keys_version, archive_sha256)?;
        Ok(proof)
    }

    /// UPG-7 (#332) migrate-on-boot: carry every floor row keyed by another scope (a host name,
    /// as 1.6 builds before the deployment key wrote them) into `deployment`'s slot, and delete
    /// it, one exact-predicated commit per row. Several hosts sharing this Store fold into the
    /// highest floor, so no host's floor is lowered. Idempotent: a rerun, or a peer racing it,
    /// finds the rows gone. Returns how many rows were carried.
    pub async fn adopt_host_floors(&self, deployment: &str) -> Result<usize, String> {
        let _gate = self.records.gate.lock().await;
        self.records.resume().await?;
        let mut carried = 0;
        for schema in [PLUGIN_FLOOR_SCHEMA, RELEASE_KEYS_FLOOR_SCHEMA] {
            let mut foreign = Vec::new();
            let mut cursor = None;
            loop {
                let page = self
                    .records
                    .records
                    .page(schema, b"", cursor.as_ref())
                    .await
                    .map_err(error)?;
                for (key, _) in page.rows {
                    let (scope, name) = split_floor_key(&key)?;
                    if scope != deployment.as_bytes() {
                        let name = std::str::from_utf8(name)
                            .map_err(|_| "a stored plugin floor names no plugin".to_string())?;
                        let target = floor_key(deployment, name)?;
                        foreign.push((key, target));
                    }
                }
                match page.next {
                    Some(next) => cursor = Some(next),
                    None => break,
                }
            }
            for (key, target) in foreign {
                loop {
                    let Some(old) = self
                        .records
                        .records
                        .get(schema, &key)
                        .await
                        .map_err(error)?
                    else {
                        break;
                    };
                    let held = self
                        .records
                        .records
                        .get(schema, &target)
                        .await
                        .map_err(error)?;
                    let seal = crate::seal::lend();
                    let merged = higher_floor(
                        schema,
                        held.as_ref().map(|v| v.expose(&seal).as_slice()),
                        old.expose(&seal),
                    )?;
                    let mut mutations = Vec::new();
                    if held.as_ref().map(|v| v.expose(&seal).as_slice()) != Some(merged.as_slice())
                    {
                        mutations.push(Mutation::Put {
                            schema: schema.into(),
                            key: target.clone(),
                            value: Secret::new(merged),
                        });
                    }
                    mutations.push(Mutation::Delete {
                        schema: schema.into(),
                        key: key.clone(),
                    });
                    let predicates = vec![
                        Predicate {
                            schema: schema.into(),
                            key: key.clone(),
                            expected: Expected::Exact(old),
                        },
                        Predicate {
                            schema: schema.into(),
                            key: target.clone(),
                            expected: held.map_or(Expected::Absent, Expected::Exact),
                        },
                    ];
                    if self.records.decide(predicates, mutations).await? {
                        carried += 1;
                        break;
                    }
                }
            }
        }
        Ok(carried)
    }
    pub async fn release_keys_floor(&self, host: &str) -> Result<u64, String> {
        let _gate = self.records.gate.lock().await;
        self.records.resume().await?;
        let key = floor_key(host, "busbar-release-keys")?;
        let held = self
            .records
            .records
            .get(RELEASE_KEYS_FLOOR_SCHEMA, &key)
            .await
            .map_err(error)?;
        decode_keys(
            held.as_ref()
                .map(|v| v.expose(&crate::seal::lend()).as_slice()),
        )
    }
    /// Checks the loaded set against the host's release keys floor and, when `raise`,
    /// lifts the floor to the set's LOWEST keys version.
    /// Raising to the highest member would make a host that loads a mixed set (for
    /// example an enterprise file still sealed at k5 beside public files at k7)
    /// refuse its own unchanged set on the next boot. A uniform set raises the
    /// floor exactly as before.
    pub async fn enforce_release_keys(
        &self,
        host: &str,
        versions: &[u64],
        raise: bool,
    ) -> Result<(), String> {
        let Some(&lowest) = versions.iter().min() else {
            return Ok(());
        };
        let highest = versions.iter().copied().max().unwrap_or(lowest);
        if raise && highest > lowest {
            tracing::warn!(
                code = "KEYS_MIXED",
                host,
                lowest,
                highest,
                "first-party plugins are sealed under mixed release keys versions; the keys floor is held at the lowest ({lowest}) until every file is resealed at {highest}"
            );
        }
        let _gate = self.records.gate.lock().await;
        self.records.resume().await?;
        let key = floor_key(host, "busbar-release-keys")?;
        loop {
            let held = self
                .records
                .records
                .get(RELEASE_KEYS_FLOOR_SCHEMA, &key)
                .await
                .map_err(error)?;
            let floor = decode_keys(
                held.as_ref()
                    .map(|v| v.expose(&crate::seal::lend()).as_slice()),
            )?;
            if lowest < floor {
                return Err(format!("keys-rollback: release keys-document version {lowest} is below {floor}, the highest this host has accepted; no plugin rollback pin or trust opt-in lowers this floor"));
            }
            if !raise || lowest <= floor {
                return Ok(());
            }
            if self
                .records
                .decide(
                    vec![Predicate {
                        schema: RELEASE_KEYS_FLOOR_SCHEMA.into(),
                        key: key.clone(),
                        expected: held.map_or(Expected::Absent, Expected::Exact),
                    }],
                    vec![Mutation::Put {
                        schema: RELEASE_KEYS_FLOOR_SCHEMA.into(),
                        key: key.clone(),
                        value: Secret::new(lowest.to_be_bytes().to_vec()),
                    }],
                )
                .await?
            {
                return Ok(());
            }
        }
    }
    pub async fn enforce_candidate(
        &self,
        host: &str,
        candidate: Candidate<'_>,
        raise: bool,
    ) -> Result<(), String> {
        if !candidate.first_party || candidate.linked {
            return Ok(());
        }
        if !valid_semver(candidate.version) {
            return Err(unreadable_version(&candidate));
        }
        let _gate = self.records.gate.lock().await;
        self.records.resume().await?;
        let key = floor_key(host, candidate.name)?;
        loop {
            let held = self
                .records
                .records
                .get(PLUGIN_FLOOR_SCHEMA, &key)
                .await
                .map_err(error)?;
            let floor = held
                .as_ref()
                .map(|v| {
                    std::str::from_utf8(v.expose(&crate::seal::lend()))
                        .ok()
                        .filter(|v| valid_semver(v))
                        .ok_or_else(|| {
                            format!("the stored first-party floor of `{}` does not read as a version; its anti-downgrade check cannot run, so the plugin does not load. Roll it back on purpose with the audited `POST /api/v1/admin/plugins/rollback`, which pins a readable floor in the overlay's `plugin_versions`", candidate.name)
                        })
                })
                .transpose()?;
            if let Some(floor) = floor {
                if !candidate.rollback_pinned && !version_at_least(candidate.version, floor) {
                    return Err(format!("the first-party plugin `{}` {} is below {floor}, the highest version of it this host has loaded: an old signed release does not load in its place. To roll it back on purpose, call the audited `POST /api/v1/admin/plugins/rollback` with `{{\"file\": \"{}\"}}`; it pins `{}` in the overlay's `plugin_versions`", candidate.name, candidate.version, candidate.file, candidate.name));
                }
                if version_at_least(floor, candidate.version) {
                    return Ok(());
                }
            }
            if !raise {
                return Ok(());
            }
            if self
                .records
                .decide(
                    vec![Predicate {
                        schema: PLUGIN_FLOOR_SCHEMA.into(),
                        key: key.clone(),
                        expected: held.map_or(Expected::Absent, Expected::Exact),
                    }],
                    vec![Mutation::Put {
                        schema: PLUGIN_FLOOR_SCHEMA.into(),
                        key: key.clone(),
                        value: Secret::new(candidate.version.as_bytes().to_vec()),
                    }],
                )
                .await?
            {
                return Ok(());
            }
        }
    }
}

#[cfg(test)]
#[path = "tests/plugin_floor_tests.rs"]
mod tests;

/// A specific admission observation, never an unrestricted cached floor exemption.
/// The host pairs it with the retained library bytes and consumes it in the native
/// load guard immediately after awaited admission for that same archive.
#[derive(Clone)]
pub struct AdmissionProof {
    host: String,
    name: String,
    version: String,
    file: String,
    first_party: bool,
    linked: bool,
    rollback_pinned: bool,
    release_keys_version: Option<u64>,
    archive_sha256: String,
    plugin_floor: Option<String>,
    release_floor: u64,
    dataset: busbar_contract::persistence::DatasetId,
    /// Decoded (and so validated) at admission; read back only by tests.
    _scope_generations: [u64; 2],
}
impl AdmissionProof {
    pub fn release_keys_floor(&self) -> u64 {
        self.release_floor
    }
    pub fn dataset(&self) -> busbar_contract::persistence::DatasetId {
        self.dataset
    }
    #[cfg(test)]
    pub(crate) fn scope_generations(&self) -> [u64; 2] {
        self._scope_generations
    }
    pub fn check(
        &self,
        host: &str,
        candidate: Candidate<'_>,
        release_keys_version: Option<u64>,
        archive_sha256: &str,
    ) -> Result<(), String> {
        if self.host != host
            || self.name != candidate.name
            || self.version != candidate.version
            || self.file != candidate.file
            || self.first_party != candidate.first_party
            || self.linked != candidate.linked
            || self.rollback_pinned != candidate.rollback_pinned
            || self.release_keys_version != release_keys_version
            || self.archive_sha256 != archive_sha256
        {
            return Err("plugin admission proof names another archive or registry decision".into());
        }
        if release_keys_version.is_some_and(|version| version < self.release_floor) {
            return Err(
                "keys-rollback: release keys-document is below the observed host floor".into(),
            );
        }
        if let Some(floor) = &self.plugin_floor {
            if !valid_semver(floor) {
                return Err(format!("the observed floor of `{}` does not read as a version; re-run admission (restart) so the floor is observed again, or roll the plugin back with the audited `POST /api/v1/admin/plugins/rollback`", candidate.name));
            }
            if !candidate.rollback_pinned && !version_at_least(candidate.version, floor) {
                return Err(format!(
                    "plugin {} {} is below observed floor {floor}",
                    candidate.name, candidate.version
                ));
            }
        }
        Ok(())
    }
}
