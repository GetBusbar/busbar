// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Shared chain rows for unit records and notary certificates. Reading a chain must not filter
//! certificates out: their sequence and predecessor occupy the same chain as the unit lines.

use busbar_contract::caps::MeterClassId;

use crate::notary_key::{notary_key_from_journal_body, NotaryKeyRecord};
use crate::{AuditChain, AuditRecord, Fingerprint};

/// A decoded chain row. Boxing keeps cold read collections compact without enlarging every
/// request-path unit record or changing its journal format.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuditLinkedRecord {
    /// A unit under any supported legacy or link recipe.
    Unit(Box<AuditRecord>),
    /// A Bootstrap-certified per-boot key in the link chain.
    NotaryKey(Box<NotaryKeyRecord>),
}

impl AuditLinkedRecord {
    /// The node whose chain contains the row.
    #[must_use]
    pub fn node(&self) -> u64 {
        match self {
            Self::Unit(record) => record.node,
            Self::NotaryKey(record) => record.node,
        }
    }

    /// The chain sequence, never the WAL position.
    #[must_use]
    pub fn chain_seq(&self) -> u64 {
        match self {
            Self::Unit(record) => record.seq,
            Self::NotaryKey(record) => record.seq,
        }
    }

    /// The link timestamp, zero for legacy unit records without one.
    #[must_use]
    pub fn linked_ms(&self) -> u64 {
        match self {
            Self::Unit(record) => record.linked_ms,
            Self::NotaryKey(record) => record.linked_ms,
        }
    }

    /// Decode the predecessor fingerprint without accepting malformed hex as genesis.
    pub fn prev_link(&self) -> Result<Fingerprint, String> {
        match self {
            Self::Unit(record) => Fingerprint::from_hex(&record.prev_hash)
                .ok_or_else(|| "an audit predecessor is not a fingerprint".into()),
            Self::NotaryKey(record) => Ok(record.prev_link),
        }
    }

    /// Decode the stored fingerprint. An empty stored digest is never a valid record digest.
    pub fn fingerprint(&self) -> Result<Fingerprint, String> {
        match self {
            Self::Unit(record) => {
                if record.hash.is_empty() {
                    return Err("an audit record has no fingerprint".into());
                }
                Fingerprint::from_hex(&record.hash)
                    .ok_or_else(|| "an audit digest is not a fingerprint".into())
            }
            Self::NotaryKey(record) => Ok(record.fingerprint),
        }
    }

    /// Recompute the appropriate recipe's digest. This is chain integrity, not authentication
    /// of a certificate or unit signature and not proof of authority-history completeness.
    pub fn verify_digest(&self) -> Result<(), String> {
        let valid = match self {
            Self::Unit(record) => AuditChain::digest_of(record) == record.hash,
            Self::NotaryKey(record) => record.recompute_fingerprint() == record.fingerprint,
        };
        if valid {
            Ok(())
        } else {
            Err("an audit record digest does not match its content".into())
        }
    }
}

/// Decode every existing unit recipe through its original decoder, or a certificate through
/// its versioned decoder. Recognized malformed rows fail; non-chain rows return None.
pub fn linked_record_from_journal_body(
    bytes: &[u8],
    class: &dyn Fn(&str) -> Option<MeterClassId>,
) -> Result<Option<AuditLinkedRecord>, String> {
    if let Some(record) = notary_key_from_journal_body(bytes)? {
        return Ok(Some(AuditLinkedRecord::NotaryKey(Box::new(record))));
    }
    crate::from_journal_body(bytes, class)
        .map(|record| record.map(|record| AuditLinkedRecord::Unit(Box::new(record))))
}

/// Check a complete chain from genesis, including certificates and legacy unit rows.
pub fn verify_linked_chain(records: &[AuditLinkedRecord]) -> Result<(), String> {
    walk(records, true)
}

/// Check continuity within a window. Its first predecessor is context, not independently
/// authenticated trust; callers must resolve stamp/Bootstrap authority separately.
pub fn verify_linked_window(records: &[AuditLinkedRecord]) -> Result<(), String> {
    walk(records, false)
}

fn walk(records: &[AuditLinkedRecord], genesis: bool) -> Result<(), String> {
    let Some(first) = records.first() else {
        return Ok(());
    };
    let node = first.node();
    let mut seq = if genesis { 1 } else { first.chain_seq() };
    let mut prev = if genesis {
        Fingerprint::ZERO
    } else {
        first.prev_link()?
    };
    for (index, record) in records.iter().enumerate() {
        if record.node() != node
            || record.chain_seq() != seq
            || seq == 0
            || record.prev_link()? != prev
        {
            return Err("an audit chain has a node, sequence or predecessor mismatch".into());
        }
        record.verify_digest()?;
        prev = record.fingerprint()?;
        if index + 1 < records.len() {
            seq = seq
                .checked_add(1)
                .ok_or_else(|| "an audit chain sequence overflowed".to_string())?;
        }
    }
    Ok(())
}
