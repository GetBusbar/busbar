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
fn decode_keys(bytes: Option<&[u8]>) -> Result<u64, String> {
    bytes.map_or(Ok(0), |bytes| {
        bytes
            .try_into()
            .map(u64::from_be_bytes)
            .map_err(|_| "the release keys-document floor is malformed".into())
    })
}
fn version_at_least(have: &str, floor: &str) -> bool {
    if !valid_semver(have) || !valid_semver(floor) {
        return false;
    }
    fn core(value: &str) -> &str {
        value.split(['-', '+']).next().unwrap_or("")
    }
    // Compare decimal strings without narrowing arbitrary semver components to u64.
    for (have, floor) in core(have).split('.').zip(core(floor).split('.')) {
        let have = have.trim_start_matches('0');
        let floor = floor.trim_start_matches('0');
        match have.len().cmp(&floor.len()).then_with(|| have.cmp(floor)) {
            std::cmp::Ordering::Less => return false,
            std::cmp::Ordering::Greater => return true,
            std::cmp::Ordering::Equal => {}
        }
    }
    true
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
        let plugin_floor =
            if candidate.first_party && !candidate.linked && valid_semver(candidate.version) {
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
            scope_generations: [
                decode_generation(&values[2])?,
                decode_generation(&values[3])?,
            ],
        };
        proof.check(host, candidate, release_keys_version, archive_sha256)?;
        Ok(proof)
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
            if !raise || highest <= floor {
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
                        value: Secret::new(highest.to_be_bytes().to_vec()),
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
        if !candidate.first_party || candidate.linked || !valid_semver(candidate.version) {
            return Ok(());
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
                            format!("the first-party floor of `{}` is malformed", candidate.name)
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
mod tests {
    use super::*;
    use crate::persistence::host_records::tests::{attach, Backend};
    use std::sync::atomic::Ordering;

    fn candidate(version: &str, rollback_pinned: bool) -> Candidate<'_> {
        Candidate {
            name: "plugin",
            version,
            file: "plugin.so",
            first_party: true,
            linked: false,
            rollback_pinned,
        }
    }

    #[tokio::test]
    async fn floors_remain_monotonic_and_prepared_admission_names_one_exact_archive() {
        let backend = Arc::new(Backend::default());
        let owner = PluginFloor::new(Arc::new(attach(backend.clone()).await)).unwrap();
        backend.lose_reply.store(true, Ordering::SeqCst);
        owner
            .enforce_candidate("host", candidate("2.0.0", false), true)
            .await
            .unwrap();
        owner
            .enforce_candidate("host", candidate("1.0.0", true), true)
            .await
            .unwrap();
        assert!(owner
            .enforce_candidate("host", candidate("1.0.0", false), false)
            .await
            .is_err());
        owner
            .enforce_release_keys("host", &[42], true)
            .await
            .unwrap();
        assert!(owner
            .enforce_release_keys("host", &[41], false)
            .await
            .is_err());
        let archive = "a".repeat(64);
        let proof = owner
            .prepare_admission("host", candidate("2.0.0", false), Some(42), &archive)
            .await
            .unwrap();
        assert_eq!(proof.release_keys_floor(), 42);
        assert!(proof
            .scope_generations()
            .iter()
            .all(|generation| *generation > 0));
        proof
            .check("host", candidate("2.0.0", false), Some(42), &archive)
            .unwrap();
        assert!(proof
            .check("host", candidate("2.0.0", false), Some(42), &"b".repeat(64))
            .is_err());
        assert!(proof
            .check("host", candidate("1.0.0", true), Some(42), &archive)
            .is_err());
    }

    #[tokio::test]
    async fn cancelled_raise_is_confirmed_before_a_later_lower_candidate_is_checked() {
        let backend = Arc::new(Backend::default());
        let owner = PluginFloor::new(Arc::new(attach(backend.clone()).await)).unwrap();
        backend.hang.store(true, Ordering::SeqCst);
        {
            let write = owner.enforce_candidate("host", candidate("3.0.0", false), true);
            tokio::pin!(write);
            assert!(futures::poll!(&mut write).is_pending());
        }
        backend.hang.store(false, Ordering::SeqCst);
        assert!(owner
            .enforce_candidate("host", candidate("2.0.0", false), true)
            .await
            .is_err());
        owner
            .prepare_admission("host", candidate("3.0.0", false), None, &"a".repeat(64))
            .await
            .unwrap();
    }

    #[test]
    fn decimal_version_order_preserves_large_components_and_legacy_suffix_semantics() {
        assert!(version_at_least(
            "184467440737095516160.0.0",
            "184467440737095516159.9.9"
        ));
        assert!(version_at_least("01.002.0003-beta", "1.2.3+build"));
        assert!(!version_at_least("1.2.2", "1.2.3"));
        assert!(!version_at_least("1.2.3", "malformed"));
    }
}

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
    scope_generations: [u64; 2],
}
impl AdmissionProof {
    pub fn release_keys_floor(&self) -> u64 {
        self.release_floor
    }
    pub fn dataset(&self) -> busbar_contract::persistence::DatasetId {
        self.dataset
    }
    pub fn scope_generations(&self) -> [u64; 2] {
        self.scope_generations
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
                return Err("malformed observed plugin floor".into());
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
