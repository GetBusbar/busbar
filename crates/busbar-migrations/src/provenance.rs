// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use crate::Error;

/// A live native fence observation bound to one retained source and snapshot.
/// Only the startup session can mint it after CheckFence succeeds.
#[derive(Debug, Clone)]
pub struct CheckedNativeFence {
    pub(crate) source: lifecycle::SourceIdentity,
    pub(crate) upgrade: [u8; 16],
    pub(crate) snapshot: [u8; 16],
    pub(crate) enforcement: [u8; 32],
    pub(crate) observation: [u8; 32],
    pub(crate) route: [u8; 32],
}
impl CheckedNativeFence {
    pub fn source(&self) -> &lifecycle::SourceIdentity {
        &self.source
    }
    pub fn upgrade_id(&self) -> [u8; 16] {
        self.upgrade
    }
    pub fn snapshot(&self) -> [u8; 16] {
        self.snapshot
    }
    pub fn enforcement_digest(&self) -> [u8; 32] {
        self.enforcement
    }
    pub fn observation_digest(&self) -> [u8; 32] {
        self.observation
    }
    pub fn route_digest(&self) -> [u8; 32] {
        self.route
    }
}
use busbar_contract::persistence::lifecycle;

/// Released storage semantics admitted by a native inspection. These names
/// describe registered reader profiles, not an inferred product binary version.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReleasedProfile {
    Sqlite6,
    Postgres6,
    Mysql3,
    Valkey6,
    Sqlite7,
    Sqlite8,
    Sqlite9,
    Postgres7,
    Postgres8,
    Postgres9,
    Mysql4,
    Mysql5,
    Mysql7,
    Valkey7,
    Valkey8,
    Valkey9,
}

/// Actual native source identity bound to a compiled released reader profile.
/// Callers cannot construct provenance by asserting a release boolean.
#[derive(Debug, Clone)]
pub struct ReleasedSourceProof {
    source: lifecycle::SourceIdentity,
    profile: ReleasedProfile,
}
impl ReleasedSourceProof {
    pub fn source(&self) -> &lifecycle::SourceIdentity {
        &self.source
    }
    pub fn profile(&self) -> ReleasedProfile {
        self.profile
    }
    /// Physical schemas do not uniquely identify a product release. No exact
    /// release is claimed without separately admitted native release metadata.
    pub fn product_release(&self) -> Option<[u32; 3]> {
        None
    }
    pub(crate) fn inspected(source: &lifecycle::SourceIdentity) -> Result<Option<Self>, Error> {
        let Some(format) = source.format else {
            return Err(Error::UnsupportedPath);
        };
        if !matches!(format.logical, 0 | 1) || format.codec != 1 {
            return Err(Error::UnsupportedPath);
        }
        let profile = match (format.owner, format.physical) {
            (lifecycle::SQLITE_SOURCE_OWNER, 6) => ReleasedProfile::Sqlite6,
            (lifecycle::POSTGRES_SOURCE_OWNER, 6) => ReleasedProfile::Postgres6,
            (lifecycle::MYSQL_SOURCE_OWNER, 3) => ReleasedProfile::Mysql3,
            (lifecycle::VALKEY_SOURCE_OWNER, 6) => ReleasedProfile::Valkey6,
            (lifecycle::SQLITE_SOURCE_OWNER, 7) => ReleasedProfile::Sqlite7,
            (lifecycle::SQLITE_SOURCE_OWNER, 8) => ReleasedProfile::Sqlite8,
            (lifecycle::SQLITE_SOURCE_OWNER, 9) => ReleasedProfile::Sqlite9,
            (lifecycle::POSTGRES_SOURCE_OWNER, 7) => ReleasedProfile::Postgres7,
            (lifecycle::POSTGRES_SOURCE_OWNER, 8) => ReleasedProfile::Postgres8,
            (lifecycle::POSTGRES_SOURCE_OWNER, 9) => ReleasedProfile::Postgres9,
            (lifecycle::MYSQL_SOURCE_OWNER, 4) => ReleasedProfile::Mysql4,
            (lifecycle::MYSQL_SOURCE_OWNER, 5) => ReleasedProfile::Mysql5,
            (lifecycle::MYSQL_SOURCE_OWNER, 7) => ReleasedProfile::Mysql7,
            (lifecycle::VALKEY_SOURCE_OWNER, 7) => ReleasedProfile::Valkey7,
            (lifecycle::VALKEY_SOURCE_OWNER, 8) => ReleasedProfile::Valkey8,
            (lifecycle::VALKEY_SOURCE_OWNER, 9) => ReleasedProfile::Valkey9,
            _ => return Err(Error::UnsupportedPath),
        };
        if source.native_anchor == [0; 32]
            || source.dataset.0 == [0; 16]
            || source.catalogue_digest == [0; 32]
            || source.layout_digest == [0; 32]
        {
            return Err(Error::IdentityMismatch);
        }
        Ok(Some(Self {
            source: source.clone(),
            profile,
        }))
    }
}
