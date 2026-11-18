// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! SELF-SERVE KEYS (MIGRATE-ON-BOOT §6 (4), r40). A 1.5.5 self-serve key has no `idp_subject`,
//! `idp_provider` or `binding_mode` (v1.5.5 `store.rs:73-117`): 1.5.5 found it by its id alone,
//! derived from the subject and an epoch under the signing key. R0 converts each such row as it
//! writes it, so the subject's next self-serve login resolves the same key, its usage and audit
//! still attributed to the same id.

use busbar_contract::records::VirtualKey;

use super::SelfId;

/// The group prefix of a 1.5.5 self-serve key.
const GROUP_PREFIX: &str = "user:";
/// The name 1.5.5 gave a self-serve key, around its subject.
const NAME_PREFIX: &str = "self-serve key (";
/// The binding mode a verified self-serve key is carried under.
const USER_BOUND: &str = "user-bound";
/// The epochs tried after the key's own marker: 1.5.5's rotate and revoke wrote a random
/// generation (`state.rs:191, 1277`), so the epoch a key was minted under is not always its own.
const EPOCH_PROBE: u64 = 256;

/// What [`convert`] found.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    /// Not a self-serve-looking key: carried unchanged.
    NotSelf,
    /// Converted already (a resumed run): left as is.
    Converted,
    /// Its id is its subject's at some epoch: now `idp_subject` = the subject, `user-bound`.
    Verified,
    /// It looks self-serve but its id is not its subject's (no signing key, a rotated seed, a
    /// random id in a `user:` group, or an epoch past the probe): carried with its 1.5.5 shape and
    /// counted (`self_keys_unverified`).
    Unverified,
}

/// The subject a 1.5.5 key names: its `user:` group, else its `self-serve key (<sub>)` name (an
/// admin's `update_key` changes only `enabled` and `group`, so a moved key still names it).
#[must_use]
pub fn candidate(key: &VirtualKey) -> Option<&str> {
    key.group
        .as_deref()
        .and_then(|group| group.strip_prefix(GROUP_PREFIX))
        .or_else(|| {
            key.name
                .strip_prefix(NAME_PREFIX)
                .and_then(|rest| rest.strip_suffix(')'))
        })
        .filter(|sub| !sub.is_empty())
}

/// The epoch in a `binding:<id>:<e>` marker, when it is the key's own.
fn marker_epoch(key: &VirtualKey) -> Option<u64> {
    let rest = key.generation_hash.strip_prefix("binding:")?;
    let (id, epoch) = rest.rsplit_once(':')?;
    (id == key.id).then(|| epoch.parse().ok()).flatten()
}

/// Convert one KEY row in place. Idempotent: a converted row has `idp_subject`.
pub fn convert(key: &mut VirtualKey, self_id: Option<SelfId<'_>>) -> Verdict {
    if key.idp_subject.is_some() {
        return Verdict::Converted;
    }
    let Some(sub) = candidate(key).map(str::to_owned) else {
        return Verdict::NotSelf;
    };
    let Some(derive) = self_id else {
        return Verdict::Unverified;
    };
    let verified = marker_epoch(key)
        .into_iter()
        .chain(0..=EPOCH_PROBE)
        .any(|epoch| derive(&sub, epoch) == key.id);
    if !verified {
        return Verdict::Unverified;
    }
    key.idp_subject = Some(sub);
    key.binding_mode = Some(USER_BOUND.to_owned());
    key.idp_provider = None;
    Verdict::Verified
}
