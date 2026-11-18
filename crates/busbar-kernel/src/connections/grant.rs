// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors
//! Host grant authority. Plaintext is lent only after durable whole-key mint
//! exclusion. Epochs fence delivery; revisions compare exact grant transitions.
use crate::governance::at_rest::{
    CallerProtectedRecords, CallerRecordContext, CallerRecordError, CallerRecordKind,
};
use busbar_contract::{crypto, secure::SecureVec, Secret};
use std::sync::Arc;

#[path = "grant/owner.rs"]
mod owner;
pub use owner::{
    CallerCredentialAnswer, CallerGrantOwner, ConnectionBinding, DeliveryIdentity, DeliveryPermit,
    GrantEpoch, MintPermit,
};

const HEADER: usize = 37;
const MAGIC: &[u8; 4] = b"BGR1";

#[derive(Clone, PartialEq, Eq, Hash)]
pub struct GrantKey(Vec<u8>);
impl GrantKey {
    /// Called with the actual admitted plane namespace and verified subject.
    pub(crate) fn new(
        plugin: &str,
        name: &str,
        subject: &str,
        upstream: &str,
    ) -> Result<Self, GrantError> {
        if plugin.is_empty() || name.is_empty() || subject.is_empty() || upstream.is_empty() {
            return Err(GrantError::Invalid);
        }
        let subject = crypto::sha256(subject.as_bytes());
        let parts = [
            plugin.as_bytes(),
            name.as_bytes(),
            subject.as_slice(),
            upstream.as_bytes(),
        ];
        let len = parts
            .iter()
            .try_fold(1usize, |n, p| {
                u32::try_from(p.len()).ok()?;
                n.checked_add(4)?.checked_add(p.len())
            })
            .ok_or(GrantError::Budget)?;
        let mut key = Vec::new();
        key.try_reserve_exact(len).map_err(|_| GrantError::Budget)?;
        key.push(1);
        for part in parts {
            key.extend_from_slice(&(part.len() as u32).to_be_bytes());
            key.extend_from_slice(part)
        }
        Ok(Self(key))
    }
    pub fn encoded(&self) -> &[u8] {
        &self.0
    }

    /// Recovery accepts only the canonical complete durable namespace.
    pub fn decode(encoded: &[u8]) -> Result<Self, GrantError> {
        if encoded.first() != Some(&1) {
            return Err(GrantError::Invalid);
        }
        let mut rest = &encoded[1..];
        for field in 0..4 {
            let length = rest.get(..4).ok_or(GrantError::Invalid)?;
            let length =
                u32::from_be_bytes(length.try_into().map_err(|_| GrantError::Invalid)?) as usize;
            rest = &rest[4..];
            let value = rest.get(..length).ok_or(GrantError::Invalid)?;
            if field == 2 {
                if length != 32 {
                    return Err(GrantError::Invalid);
                }
            } else if value.is_empty() || std::str::from_utf8(value).is_err() {
                return Err(GrantError::Invalid);
            }
            rest = &rest[length..];
        }
        if !rest.is_empty() {
            return Err(GrantError::Invalid);
        }
        let mut key = Vec::new();
        key.try_reserve_exact(encoded.len())
            .map_err(|_| GrantError::Budget)?;
        key.extend_from_slice(encoded);
        Ok(Self(key))
    }
}
impl std::fmt::Debug for GrantKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("GrantKey(<private>)")
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum GrantState {
    Live = 1,
    Minting = 2,
    ReconnectRequired = 3,
    Revoked = 4,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GrantVersion {
    pub epoch: u64,
    pub revision: u64,
    pub state: GrantState,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GrantPurpose {
    Install,
    Refresh,
    RevokeCurrent,
    RevokeExplicit,
    Delivery,
    Rewrap,
    MintStart,
    MintFinish,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GrantError {
    Invalid,
    Budget,
    Unavailable,
    ConnectRequired,
    Stale,
    Overflow,
    Custody,
}
impl From<CallerRecordError> for GrantError {
    fn from(error: CallerRecordError) -> Self {
        match error {
            CallerRecordError::Budget => Self::Budget,
            _ => Self::Custody,
        }
    }
}

/// Only the grant state owner creates these checked transitions; persistence
/// consumes their exact encrypted predicates, never arbitrary caller mutations.
pub struct ValidatedGrantChange {
    key: GrantKey,
    purpose: GrantPurpose,
    previous: Option<Secret<Vec<u8>>>,
    successor: Secret<Vec<u8>>,
    before: Option<GrantVersion>,
    after: GrantVersion,
}
impl ValidatedGrantChange {
    pub fn encoded_key(&self) -> &[u8] {
        self.key.encoded()
    }
    pub fn purpose(&self) -> GrantPurpose {
        self.purpose
    }
    pub fn previous(&self) -> Option<&Secret<Vec<u8>>> {
        self.previous.as_ref()
    }
    pub fn successor(&self) -> &Secret<Vec<u8>> {
        &self.successor
    }
    pub fn before(&self) -> Option<GrantVersion> {
        self.before
    }
    pub fn after(&self) -> GrantVersion {
        self.after
    }
}

pub struct GrantSnapshot {
    key: GrantKey,
    version: GrantVersion,
    owner: [u8; 16],
    original: Secret<Vec<u8>>,
    grant: SecureVec,
}
impl GrantSnapshot {
    pub fn version(&self) -> GrantVersion {
        self.version
    }
    pub fn key(&self) -> &GrantKey {
        &self.key
    }
}
impl std::fmt::Debug for GrantSnapshot {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GrantSnapshot")
            .field("version", &self.version)
            .finish_non_exhaustive()
    }
}

/// Concrete authenticated row codec/state transition producer. No method here
/// grants mint or send permission; that requires actual durable Applied custody.
pub struct GrantRecords {
    codec: Arc<CallerProtectedRecords>,
    dataset: [u8; 16],
    domain: [u8; 16],
}
impl GrantRecords {
    pub(crate) fn new(
        codec: Arc<CallerProtectedRecords>,
        dataset: [u8; 16],
        domain: [u8; 16],
    ) -> Result<Self, GrantError> {
        if dataset == [0; 16] || domain == [0; 16] {
            return Err(GrantError::Invalid);
        }
        Ok(Self {
            codec,
            dataset,
            domain,
        })
    }
    pub(crate) fn decode(
        &self,
        key: &GrantKey,
        row: &Secret<Vec<u8>>,
    ) -> Result<GrantSnapshot, GrantError> {
        let seal = crate::seal::lend();
        let bytes = row.expose(&seal);
        if bytes.len() < HEADER || &bytes[..4] != MAGIC {
            return Err(GrantError::Invalid);
        }
        let epoch = u64::from_be_bytes(bytes[4..12].try_into().map_err(|_| GrantError::Invalid)?);
        let revision =
            u64::from_be_bytes(bytes[12..20].try_into().map_err(|_| GrantError::Invalid)?);
        let state = match bytes[20] {
            1 => GrantState::Live,
            2 => GrantState::Minting,
            3 => GrantState::ReconnectRequired,
            4 => GrantState::Revoked,
            _ => return Err(GrantError::Invalid),
        };
        let owner = bytes[21..37].try_into().map_err(|_| GrantError::Invalid)?;
        if epoch == 0 || revision == 0 || (state == GrantState::Minting) == (owner == [0; 16]) {
            return Err(GrantError::Invalid);
        }
        let context = CallerRecordContext::new(
            CallerRecordKind::Grant,
            self.dataset,
            self.domain,
            key.encoded(),
            revision,
            owner,
            &bytes[4..HEADER],
        )?;
        let grant = self.codec.open(&context, &bytes[HEADER..])?;
        if matches!(state, GrantState::ReconnectRequired | GrantState::Revoked) && !grant.is_empty()
        {
            return Err(GrantError::Invalid);
        }
        Ok(GrantSnapshot {
            key: key.clone(),
            version: GrantVersion {
                epoch,
                revision,
                state,
            },
            owner,
            original: row.clone(),
            grant,
        })
    }
    fn change(
        &self,
        key: &GrantKey,
        prior: Option<&GrantSnapshot>,
        transition: (GrantPurpose, GrantState, bool, [u8; 16]),
        grant: &[u8],
    ) -> Result<ValidatedGrantChange, GrantError> {
        let (purpose, state, bump_epoch, owner) = transition;
        if prior.is_some_and(|s| s.key != *key) {
            return Err(GrantError::Invalid);
        }
        let before = prior.map(|s| s.version);
        let revision = before
            .map_or(Some(1), |v| v.revision.checked_add(1))
            .ok_or(GrantError::Overflow)?;
        let epoch = before
            .map_or(Some(1), |v| {
                if bump_epoch {
                    v.epoch.checked_add(1)
                } else {
                    Some(v.epoch)
                }
            })
            .ok_or(GrantError::Overflow)?;
        let after = GrantVersion {
            epoch,
            revision,
            state,
        };
        let mut header = [0u8; HEADER];
        header[..4].copy_from_slice(MAGIC);
        header[4..12].copy_from_slice(&epoch.to_be_bytes());
        header[12..20].copy_from_slice(&revision.to_be_bytes());
        header[20] = state as u8;
        header[21..37].copy_from_slice(&owner);
        let context = CallerRecordContext::new(
            CallerRecordKind::Grant,
            self.dataset,
            self.domain,
            key.encoded(),
            revision,
            owner,
            &header[4..],
        )?;
        let ciphertext = self.codec.seal(&context, grant)?;
        let mut row = SecureVec::with_capacity(
            HEADER
                .checked_add(ciphertext.len())
                .ok_or(GrantError::Budget)?,
        )
        .map_err(|_| GrantError::Budget)?;
        row.extend(&header).map_err(|_| GrantError::Budget)?;
        row.extend(&ciphertext).map_err(|_| GrantError::Budget)?;
        Ok(ValidatedGrantChange {
            key: key.clone(),
            purpose,
            previous: prior.map(|s| s.original.clone()),
            successor: Secret::new(row.into_vec()),
            before,
            after,
        })
    }
    /// Native COMPLETE supplies the original BEGIN snapshot, never a fresh read.
    pub(crate) fn install(
        &self,
        key: &GrantKey,
        prior: Option<&GrantSnapshot>,
        grant: &[u8],
    ) -> Result<ValidatedGrantChange, GrantError> {
        self.change(
            key,
            prior,
            (GrantPurpose::Install, GrantState::Live, true, [0; 16]),
            grant,
        )
    }
    pub(crate) fn start_mint(
        &self,
        prior: &GrantSnapshot,
        owner: [u8; 16],
    ) -> Result<ValidatedGrantChange, GrantError> {
        if prior.version.state != GrantState::Live || owner == [0; 16] {
            return Err(GrantError::Unavailable);
        }
        self.change(
            &prior.key,
            Some(prior),
            (GrantPurpose::MintStart, GrantState::Minting, false, owner),
            &prior.grant,
        )
    }
    fn owns(prior: &GrantSnapshot, owner: [u8; 16]) -> Result<(), GrantError> {
        if prior.version.state != GrantState::Minting || prior.owner != owner || owner == [0; 16] {
            Err(GrantError::Stale)
        } else {
            Ok(())
        }
    }
    pub(crate) fn finish_mint(
        &self,
        prior: &GrantSnapshot,
        owner: [u8; 16],
        replacement: Option<&[u8]>,
    ) -> Result<ValidatedGrantChange, GrantError> {
        Self::owns(prior, owner)?;
        self.change(
            &prior.key,
            Some(prior),
            (GrantPurpose::MintFinish, GrantState::Live, false, [0; 16]),
            replacement.unwrap_or(&prior.grant),
        )
    }
    pub(crate) fn reconnect_required(
        &self,
        prior: &GrantSnapshot,
        owner: [u8; 16],
    ) -> Result<ValidatedGrantChange, GrantError> {
        Self::owns(prior, owner)?;
        self.change(
            &prior.key,
            Some(prior),
            (
                GrantPurpose::MintFinish,
                GrantState::ReconnectRequired,
                true,
                [0; 16],
            ),
            &[],
        )
    }
    pub(crate) fn revoke(
        &self,
        key: &GrantKey,
        prior: Option<&GrantSnapshot>,
    ) -> Result<ValidatedGrantChange, GrantError> {
        self.change(
            key,
            prior,
            (
                GrantPurpose::RevokeExplicit,
                GrantState::Revoked,
                true,
                [0; 16],
            ),
            &[],
        )
    }
    pub(crate) fn delivery(
        &self,
        prior: &GrantSnapshot,
        epoch: u64,
    ) -> Result<ValidatedGrantChange, GrantError> {
        if prior.version.state != GrantState::Live || prior.version.epoch != epoch {
            return Err(GrantError::Stale);
        }
        Ok(ValidatedGrantChange {
            key: prior.key.clone(),
            purpose: GrantPurpose::Delivery,
            previous: Some(prior.original.clone()),
            successor: prior.original.clone(),
            before: Some(prior.version),
            after: prior.version,
        })
    }
}

#[cfg(test)]
#[path = "grant/tests.rs"]
mod tests;
