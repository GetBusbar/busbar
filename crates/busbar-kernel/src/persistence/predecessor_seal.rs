// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE PREDECESSOR SEAL ROWS (SEALING-FIX r20 §3.6.2): what the start-up sealer reads and writes
//! through [`PredecessorFence`], the one kernel object it writes with.
//!
//! - `fenced:<epoch be><writer>`: the FENCE MARK, written by `retire`'s fence in the same
//!   compare-and-set as the permanent fence, never deleted; each seal of one of the writer's nodes
//!   adds that node to its `sealed` list (decision 193).
//! - `sealed:<id be>`: a node's one SEAL ROW, written once by a compare-and-set that needs it absent
//!   (G11): `Clean { through }` (nothing to seal; authenticates nothing), or the signed
//!   `audit.stamp.v1` or `audit.break.v1` body.
//!
//! Both sit in the `busbar.node.v1` schema beside the host, id and lease rows; the node registry
//! and the expired-writer scan skip their prefixes.

use busbar_contract::Secret;
use busbar_kernel_wal::JournalRecord;

use super::{
    error, predicate, put, Assignment, BootRecords, LeaseRow, PredecessorFence, RetireError,
    UndrainedWriter, WriterRetirement, LEASE_TTL_MS, NODE_SCHEMA,
};

const FENCE_MAGIC: &[u8; 8] = b"BBFENCE1";
const SEAL_MAGIC: &[u8; 8] = b"BBSEAL01";

/// The fence mark's row key for one writer.
pub(super) fn fenced_key(epoch: u64, writer: [u8; 16]) -> Vec<u8> {
    [b"fenced:".as_slice(), &epoch.to_be_bytes(), &writer].concat()
}

/// A node's seal row key.
pub(super) fn sealed_key(id: u64) -> Vec<u8> {
    [b"sealed:".as_slice(), &id.to_be_bytes()].concat()
}

/// THE FENCE MARK (r11, r12): the fenced writer's last lease expiry, and the nodes of it sealed
/// since.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FenceMark {
    /// The `expires_ms` of the lease row the fence was guarded on (never plus a grace).
    pub lease_expires_ms: u64,
    /// The writer's nodes sealed so far, ascending.
    pub sealed: Vec<u64>,
}

impl FenceMark {
    /// The row bytes.
    #[must_use]
    pub fn bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(16 + 8 * self.sealed.len());
        out.extend_from_slice(FENCE_MAGIC);
        out.extend_from_slice(&self.lease_expires_ms.to_be_bytes());
        for id in &self.sealed {
            out.extend_from_slice(&id.to_be_bytes());
        }
        out
    }

    /// Read a mark row back; a row that does not decode is an error.
    pub fn parse(bytes: &[u8]) -> Result<Self, String> {
        if bytes.len() < 16 || &bytes[..8] != FENCE_MAGIC || (bytes.len() - 16) % 8 != 0 {
            return Err("malformed fence mark".into());
        }
        let lease_expires_ms = u64::from_be_bytes(bytes[8..16].try_into().map_err(error)?);
        let sealed = bytes[16..]
            .chunks_exact(8)
            .map(|c| c.try_into().map(u64::from_be_bytes).map_err(error))
            .collect::<Result<Vec<u64>, String>>()?;
        if sealed.windows(2).any(|w| w[0] >= w[1]) {
            return Err("fence mark nodes are not ascending".into());
        }
        Ok(Self {
            lease_expires_ms,
            sealed,
        })
    }

    /// Whether the mark is open for node `id` (it does not list it yet).
    #[must_use]
    pub fn is_open_for(&self, id: u64) -> bool {
        self.sealed.binary_search(&id).is_err()
    }

    /// The same mark with `id` added, kept sorted.
    #[must_use]
    pub fn with_sealed(&self, id: u64) -> Self {
        let mut next = self.clone();
        if let Err(at) = next.sealed.binary_search(&id) {
            next.sealed.insert(at, id);
        }
        next
    }
}

/// A node's one seal outcome.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SealOutcome {
    /// Nothing to seal through line `through` (0: the node never wrote a journal record).
    /// Unsigned on purpose: it authenticates nothing.
    Clean {
        /// The node's tail line (chain `seq`).
        through: u64,
    },
    /// A signed `audit.stamp.v1` body (`kind: after_restart`).
    Stamp(Vec<u8>),
    /// A signed `audit.break.v1` body.
    Break(Vec<u8>),
}

/// THE SEAL ROW: who sealed the node, and how.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SealRow {
    /// The successor node that wrote it.
    pub sealer: u64,
    /// The outcome.
    pub outcome: SealOutcome,
}

impl SealRow {
    /// The row bytes: magic, sealer, a tag (0 clean, 1 stamp, 2 break), then `through` or the body.
    #[must_use]
    pub fn bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(32);
        out.extend_from_slice(SEAL_MAGIC);
        out.extend_from_slice(&self.sealer.to_be_bytes());
        match &self.outcome {
            SealOutcome::Clean { through } => {
                out.push(0);
                out.extend_from_slice(&through.to_be_bytes());
            }
            SealOutcome::Stamp(body) => {
                out.push(1);
                out.extend_from_slice(body);
            }
            SealOutcome::Break(body) => {
                out.push(2);
                out.extend_from_slice(body);
            }
        }
        out
    }

    /// Read a seal row back; a row that does not decode is an error (never trusted, never
    /// replaced).
    pub fn parse(bytes: &[u8]) -> Result<Self, String> {
        if bytes.len() < 17 || &bytes[..8] != SEAL_MAGIC {
            return Err("malformed seal row".into());
        }
        let sealer = u64::from_be_bytes(bytes[8..16].try_into().map_err(error)?);
        let rest = &bytes[17..];
        let outcome = match bytes[16] {
            0 if rest.len() == 8 => SealOutcome::Clean {
                through: u64::from_be_bytes(rest.try_into().map_err(error)?),
            },
            1 if !rest.is_empty() => SealOutcome::Stamp(rest.to_vec()),
            2 if !rest.is_empty() => SealOutcome::Break(rest.to_vec()),
            _ => return Err("malformed seal row outcome".into()),
        };
        Ok(Self { sealer, outcome })
    }
}

/// One node registered on this host, other than the caller's own.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostNode {
    /// The node.
    pub id: u64,
    /// Its assignment's writer epoch.
    pub epoch: u64,
    /// Its assignment's writer.
    pub writer: [u8; 16],
    /// Its writer lease row's `expires_ms` when the list was taken; `None` if no row.
    pub lease_expires_ms: Option<u64>,
}

/// A node the host scan refuses (decision 170: fabricated rows are never signed for).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RefusedNode {
    /// The node, when its row names one.
    pub id: Option<u64>,
    /// Why.
    pub reason: &'static str,
}

/// THE HOST SCAN (§3.6.2 "Finding the predecessors"), taken once when the sealer starts.
#[derive(Debug, Clone, Default)]
pub struct HostNodes {
    /// The store clock (ms) the scan's lease reads were made at.
    pub listed_ms: u64,
    /// Every well-formed node on the host but the caller's.
    pub nodes: Vec<HostNode>,
    /// Every node refused, with its reason.
    pub refused: Vec<RefusedNode>,
}

/// What [`PredecessorFence::retire_predecessor`] found.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PredecessorRetire {
    /// The writer's lease has not expired yet.
    Live {
        /// When it will have (store ms).
        retry_at_ms: u64,
    },
    /// The fence attempt is retained; retry.
    Pending,
    /// The writer is permanently closed. `closed_open`: this call's close of a writer that never
    /// retired applied (its record is offered).
    Retired {
        /// Whether this instance closed an open writer.
        closed_open: bool,
    },
}

/// The seal row and the fence mark of one predecessor, as read.
#[derive(Debug, Clone, Default)]
pub struct SealState {
    /// The node's seal row bytes, if present.
    pub row: Option<Vec<u8>>,
    /// The writer's mark row exactly as read (the compare-and-set's predicate).
    mark_raw: Option<Secret<Vec<u8>>>,
    /// The mark, if present and it decodes.
    pub mark: Option<FenceMark>,
}

impl SealState {
    /// Whether a mark row is present at all (decoded or not).
    #[must_use]
    pub fn mark_present(&self) -> bool {
        self.mark_raw.is_some()
    }
}

/// The selected head of a predecessor's journal, as [`PredecessorFence::journal_tail`] reads it.
pub use super::super::journal::TailView;

impl PredecessorFence {
    /// THE HOST SCAN: the `host:<host>` row and every `host:<host>\0…` archive row, each checked
    /// against its `id:` reservation, and each writer's lease row; `own` is left out.
    pub async fn host_nodes(&self, own: u64) -> Result<HostNodes, RetireError> {
        let records = &self.seals.records;
        let host_key = super::host_key(&self.host);
        let mut rows: Vec<(Vec<u8>, Secret<Vec<u8>>)> = Vec::new();
        if let Some(value) = records
            .get(NODE_SCHEMA, &host_key)
            .await
            .map_err(RetireError::from)?
        {
            rows.push((host_key.clone(), value));
        }
        let mut prefix = host_key;
        prefix.push(0);
        let mut cursor = None;
        loop {
            let page = records
                .page(NODE_SCHEMA, &prefix, cursor.as_ref())
                .await
                .map_err(RetireError::from)?;
            rows.extend(page.rows);
            match page.next {
                Some(next) => cursor = Some(next),
                None => break,
            }
        }
        let mut out = HostNodes::default();
        let mut seen = std::collections::BTreeSet::new();
        for (_, value) in rows {
            let bytes = value.expose(&crate::seal::lend());
            let Ok(assignment) = Assignment::parse(bytes) else {
                let id = (bytes.len() == 8)
                    .then(|| bytes.try_into().ok().map(u64::from_be_bytes))
                    .flatten();
                if id != Some(own) {
                    out.refused.push(RefusedNode {
                        id,
                        reason: "assignment",
                    });
                }
                continue;
            };
            if assignment.id == own || !seen.insert(assignment.id) {
                continue;
            }
            let reserved = records
                .get(NODE_SCHEMA, &super::id_key(assignment.id))
                .await
                .map_err(RetireError::from)?;
            if reserved
                .as_ref()
                .map(|v| v.expose(&crate::seal::lend()).to_vec())
                != Some(assignment.bytes())
            {
                out.refused.push(RefusedNode {
                    id: Some(assignment.id),
                    reason: "assignment",
                });
                continue;
            }
            let lease = records
                .get(
                    NODE_SCHEMA,
                    &super::writer_lease_key(assignment.epoch, assignment.writer),
                )
                .await
                .map_err(RetireError::from)?;
            let lease_expires_ms = match lease {
                Some(v) => Some(LeaseRow::parse(v.expose(&crate::seal::lend()))?.expires_ms),
                None => None,
            };
            out.nodes.push(HostNode {
                id: assignment.id,
                epoch: assignment.epoch,
                writer: assignment.writer,
                lease_expires_ms,
            });
        }
        let clock = self
            .core
            .backend()
            .clock(self.core.info().dataset)
            .await
            .map_err(RetireError::from)?;
        if clock.authority != self.core.info().clock_authority {
            return Err("node lease clock authority changed".into());
        }
        out.listed_ms = clock
            .unix_seconds
            .checked_mul(1_000)
            .ok_or("node lease clock overflow")?;
        Ok(out)
    }

    /// STEP 1, THE FENCE: close the predecessor's writer for good through this task's own
    /// retirements (`retire_after(.., 0, seen)`), with the mark in the same compare-and-set.
    pub async fn retire_predecessor(
        &self,
        epoch: u64,
        writer: [u8; 16],
        seen: UndrainedWriter,
    ) -> Result<PredecessorRetire, RetireError> {
        match self
            .retirements
            .retire_after(&self.core, epoch, writer, 0, Some(seen))
            .await?
        {
            WriterRetirement::Live { retry_at_ms } => Ok(PredecessorRetire::Live { retry_at_ms }),
            WriterRetirement::Pending => Ok(PredecessorRetire::Pending),
            WriterRetirement::Retired(_) => Ok(PredecessorRetire::Retired {
                closed_open: self.retirements.take_closed_open(epoch, writer),
            }),
        }
    }

    /// Read node `id`'s seal row and its writer's fence mark (two point reads).
    pub async fn seal_state(
        &self,
        id: u64,
        epoch: u64,
        writer: [u8; 16],
    ) -> Result<SealState, RetireError> {
        let mut values = self
            .seals
            .records
            .read(&[
                (NODE_SCHEMA, &sealed_key(id)),
                (NODE_SCHEMA, &fenced_key(epoch, writer)),
            ])
            .await
            .map_err(RetireError::from)?
            .into_iter();
        let row = values.next().ok_or("seal row observation missing")?;
        let mark_raw = values.next().ok_or("fence mark observation missing")?;
        let mark = mark_raw
            .as_ref()
            .and_then(|v| FenceMark::parse(v.expose(&crate::seal::lend())).ok());
        Ok(SealState {
            row: row.map(|v| v.expose(&crate::seal::lend()).to_vec()),
            mark_raw,
            mark,
        })
    }

    /// STEP 4, WRITE ONCE: one compare-and-set with the seal row absent and the mark exactly as
    /// `state` read it. With `add_to_mark` (the normal path: the mark is open for `id`), the mark
    /// gains `id` in the same write; a break over an `unsealed_fenced` node leaves it unchanged.
    /// `Ok(false)`: the compare-and-set lost (re-read and decide, §3.6.2 "The fence mark").
    pub async fn seal_node(
        &self,
        id: u64,
        epoch: u64,
        writer: [u8; 16],
        row: &SealRow,
        state: &SealState,
        add_to_mark: bool,
    ) -> Result<bool, RetireError> {
        let _gate = self.seals.gate.lock().await;
        self.seals.resume().await?;
        let mark_key = fenced_key(epoch, writer);
        let predicates = vec![
            predicate(NODE_SCHEMA, sealed_key(id), None),
            predicate(NODE_SCHEMA, mark_key.clone(), state.mark_raw.clone()),
        ];
        let mut mutations = vec![put(NODE_SCHEMA, sealed_key(id), row.bytes())];
        if add_to_mark {
            let Some(mark) = state.mark.as_ref().filter(|m| m.is_open_for(id)) else {
                return Err("the fence mark is not open for this node".into());
            };
            mutations.push(put(NODE_SCHEMA, mark_key, mark.with_sealed(id).bytes()));
        }
        self.seals
            .decide(predicates, mutations)
            .await
            .map_err(RetireError::from)
    }

    /// Settle a seal write this task left retained (one round trip on a store that answers).
    pub async fn settle_seal(&self) -> Result<(), String> {
        let _gate = self.seals.gate.lock().await;
        self.seals.resume().await.map(|_| ())
    }

    /// The predecessor's journal head and owner (`None`: it never wrote a record).
    pub async fn journal_tail(&self, node: u64) -> Result<Option<TailView>, RetireError> {
        super::super::journal::StoreJournal::new(&self.core, node)
            .map_err(RetireError::from)?
            .tail_view()
            .await
            .map_err(RetireError::from)
    }

    /// Original frames `from..=to` (ordinals) of the predecessor's journal, oldest first.
    pub async fn journal_records(
        &self,
        node: u64,
        from: u64,
        to: u64,
    ) -> Result<Vec<JournalRecord>, RetireError> {
        super::super::journal::StoreJournal::new(&self.core, node)
            .map_err(RetireError::from)?
            .read_back(from, to)
            .await
            .map_err(RetireError::from)
    }

    /// This host's identity (may be empty).
    #[must_use]
    pub fn host(&self) -> &str {
        &self.host
    }

    /// The lease time-to-live the sibling bound uses.
    #[must_use]
    pub fn lease_ttl_ms(&self) -> u64 {
        LEASE_TTL_MS
    }
}

/// A fresh seal-row owner over `core` (its own gate and retained slot, never the node lease's).
pub(super) fn seal_records(
    core: std::sync::Arc<super::super::facade::CoreStore>,
) -> Result<BootRecords, String> {
    BootRecords::new(core, &[NODE_SCHEMA])
}
