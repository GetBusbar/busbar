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

/// Actual native source identity bound to a compiled released reader profile.
/// Callers cannot construct provenance by asserting a release boolean.
#[derive(Debug, Clone)]
pub struct ReleasedSourceProof {
    source: lifecycle::SourceIdentity,
    reader: lifecycle::SourceReader,
}
impl ReleasedSourceProof {
    pub fn source(&self) -> &lifecycle::SourceIdentity {
        &self.source
    }
    pub fn documents(&self) -> lifecycle::DocumentSemantics {
        self.reader.documents()
    }
    pub fn reader(&self) -> lifecycle::SourceReader {
        self.reader
    }
    /// Physical schemas do not uniquely identify a product release. No exact
    /// release is claimed without separately admitted native release metadata.
    pub fn product_release(&self) -> Option<[u32; 3]> {
        None
    }
    pub(crate) fn inspected(
        source: &lifecycle::SourceIdentity,
        reader: lifecycle::SourceReader,
    ) -> Result<Option<Self>, Error> {
        let Some(format) = source.format else {
            return Err(Error::UnsupportedPath);
        };
        if !matches!(format.logical, 0 | 1) || format.codec != 1 {
            return Err(Error::UnsupportedPath);
        }
        if source.native_anchor == [0; 32]
            || source.dataset.0 == [0; 16]
            || source.catalogue_digest == [0; 32]
            || source.layout_digest == [0; 32]
        {
            return Err(Error::IdentityMismatch);
        }
        Ok(Some(Self {
            source: source.clone(),
            reader,
        }))
    }
}
