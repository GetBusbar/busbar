// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Incremental predecessor walk. Audit bodies are released after checking their successor;
//! only stamp candidates awaiting their endpoint survive across record batches.

use std::collections::VecDeque;

use super::{span_ms, BreakAt, TailItem, WalkContext, WalkOutcome};
use crate::link::Fingerprint;
use crate::record::{AuditBreakKind, AuditChain};
use crate::sign::SIGNATURE_ALGORITHM;
use crate::stamp::{BreakReason, Stamp, StampKind};

#[derive(Debug, Clone)]
struct Line {
    seq: u64,
    wal: u64,
    hash: String,
    prev: String,
    linked_ms: u64,
}

#[derive(Debug)]
struct Resolved {
    seq: u64,
    first_wal: u64,
    outcome: WalkOutcome,
}

#[derive(Debug)]
struct Pending {
    stamp: Option<Stamp>,
    resolved: Option<Result<Resolved, ()>>,
}

/// A backwards §3.6.0 walk, fed one decoded item at a time, newest first. Its line storage
/// is constant in the length of the journal; unresolved stamp candidates are retained until
/// their endpoint is reached. A caller stops feeding at the first non-`NeedMore` result.
#[derive(Debug, Default)]
pub struct BackwardWalk {
    tail: Option<Line>,
    next: Option<Line>,
    candidates: VecDeque<Pending>,
    failed_stamp: bool,
    saw_candidate: bool,
    failure: Option<BreakAt>,
    unsigned: Option<BreakAt>,
    undecodable: Option<u64>,
    link_lines: bool,
}

impl BackwardWalk {
    /// Number of retained line summaries, independent of how many records have been consumed.
    #[must_use]
    pub fn retained_lines(&self) -> usize {
        usize::from(self.tail.is_some()) + usize::from(self.next.is_some())
    }

    fn at(&self, last_good: u64, wal: u64, reason: BreakReason) -> BreakAt {
        BreakAt {
            last_good,
            unsealed_from: last_good.saturating_add(1),
            unsealed_to: self
                .tail
                .as_ref()
                .map_or(0, |t| t.seq)
                .max(last_good.saturating_add(1)),
            journal_from: wal,
            journal_to: self.tail.as_ref().map_or(0, |t| t.wal),
            reason,
        }
    }

    fn remember_failure(&mut self, at: BreakAt) {
        if self
            .failure
            .as_ref()
            .is_none_or(|previous| at.journal_from <= previous.journal_from)
        {
            self.failure = Some(at);
        }
    }

    fn resolve(&self, seq: u64, stamp: Option<&Stamp>, cx: &WalkContext<'_>) -> Resolved {
        let tail = self.tail.as_ref();
        let first_wal = self.next.as_ref().or(tail).map_or(0, |line| line.wal);
        let mut failure = self.failure;
        if let Some(unsigned) = self.unsigned {
            if failure
                .as_ref()
                .is_none_or(|at| unsigned.journal_from < at.journal_from)
            {
                failure = Some(unsigned);
            }
        }
        let unsealed = |reason| WalkOutcome::Break(self.at(seq, first_wal, reason));
        let outcome = if let Some(at) = failure {
            WalkOutcome::Break(at)
        } else if tail.is_none_or(|tail| tail.seq <= seq) || !self.link_lines {
            WalkOutcome::Nothing {
                through: tail.map_or(0, |line| line.seq),
                through_node_seq: tail.map_or(0, |line| line.wal),
            }
        } else if let (Some(stamp), Some(tail), Some(first)) = (stamp, tail, &self.next) {
            if stamp.host != cx.host {
                WalkOutcome::Foreign {
                    anchor_host: stamp.host.clone(),
                }
            } else if stamp.kind == StampKind::Final {
                unsealed(BreakReason::AfterFinal)
            } else if tail.linked_ms.saturating_sub(first.linked_ms) > span_ms(stamp.every)
                || first.linked_ms.saturating_add(span_ms(stamp.every)) < stamp.stamped_ms
            {
                unsealed(BreakReason::Span)
            } else if let Some(fingerprint) = Fingerprint::from_hex(&tail.hash) {
                WalkOutcome::Clean {
                    from: seq.saturating_add(1),
                    to: tail.seq,
                    from_node_seq: first.wal,
                    fingerprint,
                    to_node_seq: tail.wal,
                    every: stamp.every,
                    down_from_ms: tail.linked_ms,
                }
            } else {
                unsealed(BreakReason::Digest)
            }
        } else {
            unsealed(BreakReason::Unanchored)
        };
        Resolved {
            seq,
            first_wal,
            outcome,
        }
    }

    fn ready(&mut self) -> WalkOutcome {
        while self
            .candidates
            .front()
            .is_some_and(|candidate| candidate.resolved.is_some())
        {
            let Some(candidate) = self.candidates.pop_front() else {
                break;
            };
            match candidate.resolved {
                Some(Ok(resolved)) => {
                    return if self.failed_stamp {
                        WalkOutcome::Break(self.at(
                            resolved.seq,
                            resolved.first_wal,
                            BreakReason::Stamp,
                        ))
                    } else {
                        resolved.outcome
                    };
                }
                Some(Err(())) => self.failed_stamp |= candidate.stamp.is_some(),
                None => {}
            }
        }
        WalkOutcome::NeedMore
    }

    /// Consume the next item from the backwards journal read.
    pub fn push(&mut self, item: &TailItem, cx: &WalkContext<'_>) -> WalkOutcome {
        let (line, node, link_line, digest_valid, legacy_candidate) = match item {
            TailItem::Stamp { stamp, .. } => {
                self.saw_candidate = true;
                self.candidates.push_back(Pending {
                    stamp: Some(stamp.clone()),
                    resolved: None,
                });
                return WalkOutcome::NeedMore;
            }
            TailItem::Undecodable { node_seq } => {
                self.undecodable = Some(*node_seq);
                return WalkOutcome::NeedMore;
            }
            TailItem::Line { record, node_seq } => (
                Line {
                    seq: record.seq,
                    wal: *node_seq,
                    hash: record.hash.clone(),
                    prev: record.prev_hash.clone(),
                    linked_ms: record.linked_ms,
                },
                record.node,
                record.recipe.is_link(),
                AuditChain::digest_of(record) == record.hash,
                (!record.recipe.is_link() && record.signature.is_some())
                    .then(|| AuditChain::verify_signature(record, cx.key).is_ok()),
            ),
            TailItem::Certificate { record, node_seq } => (
                Line {
                    seq: record.seq,
                    wal: *node_seq,
                    hash: record.fingerprint.to_string(),
                    prev: if record.prev_link == Fingerprint::ZERO {
                        String::new()
                    } else {
                        record.prev_link.to_string()
                    },
                    linked_ms: record.linked_ms,
                },
                record.node,
                true,
                record.recompute_fingerprint() == record.fingerprint,
                None,
            ),
        };
        if self.tail.is_none() {
            self.tail = Some(line.clone());
        }

        // Check the successor before considering this line as an anchor. At an anchor the
        // anchor's incoming link is outside the walked tail, but its outgoing link is not.
        if let Some(next) = &self.next {
            if let Some(kind) = crate::record::link_break(
                &next.prev,
                next.seq,
                &line.hash,
                line.seq.saturating_add(1),
            ) {
                let reason = if kind == AuditBreakKind::LinkMismatch {
                    BreakReason::Link
                } else {
                    BreakReason::Sequence
                };
                self.remember_failure(self.at(line.seq, next.wal, reason));
            }
        }
        if let Some(wal) = self.undecodable.take() {
            self.remember_failure(self.at(line.seq, wal, BreakReason::Decode));
        }

        // A stamp remains unresolved only while its endpoint is below this line. Missing
        // endpoints invalidate the candidate, then the search continues to older anchors.
        let mut candidates = std::mem::take(&mut self.candidates);
        for candidate in &mut candidates {
            let Some(stamp) = candidate.stamp.as_ref() else {
                continue;
            };
            if candidate.resolved.is_some() {
                continue;
            }
            if stamp.sig_alg != SIGNATURE_ALGORITHM {
                return WalkOutcome::Unsupported;
            }
            if stamp.to < line.seq {
                continue;
            }
            let result = if stamp.to == line.seq
                && stamp.node == cx.node
                && node == cx.node
                && stamp.key_cert == 0
                && stamp.verify(cx.key).is_ok()
                && digest_valid
                && Fingerprint::from_hex(&line.hash) == Some(stamp.fingerprint)
            {
                Ok(self.resolve(line.seq, Some(stamp), cx))
            } else {
                Err(())
            };
            candidate.resolved = Some(result);
        }
        self.candidates = candidates;
        if let Some(passes) = legacy_candidate {
            self.saw_candidate = true;
            let resolved = if passes {
                Ok(self.resolve(line.seq, None, cx))
            } else {
                Err(())
            };
            self.candidates.push_back(Pending {
                stamp: None,
                resolved: Some(resolved),
            });
        }
        let ready = self.ready();
        if ready != WalkOutcome::NeedMore {
            return ready;
        }

        if node != cx.node {
            self.remember_failure(self.at(line.seq.saturating_sub(1), line.wal, BreakReason::Link));
        } else if !digest_valid {
            self.remember_failure(self.at(
                line.seq.saturating_sub(1),
                line.wal,
                BreakReason::Digest,
            ));
        }
        if link_line {
            self.link_lines = true;
            if let Some(unsigned) = self.unsigned {
                self.remember_failure(unsigned);
            }
        } else {
            self.unsigned =
                Some(self.at(line.seq.saturating_sub(1), line.wal, BreakReason::Unsigned));
        }
        self.next = Some(line);
        WalkOutcome::NeedMore
    }

    /// Complete the walk after reaching genesis. Never call this at an incomplete batch edge.
    pub fn finish(&mut self, cx: &WalkContext<'_>) -> WalkOutcome {
        if self.tail.is_none() {
            return WalkOutcome::Nothing {
                through: 0,
                through_node_seq: 0,
            };
        }
        for candidate in &mut self.candidates {
            if candidate.resolved.is_none() {
                candidate.resolved = Some(Err(()));
            }
        }
        let ready = self.ready();
        if ready != WalkOutcome::NeedMore {
            return ready;
        }
        let first_wal = self.next.as_ref().map_or(0, |line| line.wal);
        if self.failed_stamp {
            return WalkOutcome::Break(self.at(0, first_wal, BreakReason::Stamp));
        }
        if let Some(wal) = self.undecodable.take() {
            self.remember_failure(self.at(0, wal, BreakReason::Decode));
        }
        if let Some(first) = &self.next {
            if let Some(kind) = crate::record::link_break(&first.prev, first.seq, "", 1) {
                let reason = if kind == AuditBreakKind::LinkMismatch {
                    BreakReason::Link
                } else {
                    BreakReason::Sequence
                };
                self.remember_failure(self.at(0, first.wal, reason));
            }
        }
        // With no signed candidate at all, the historical unsigned legacy prefix stays
        // readable. A legacy line after a v7 line was already recorded as a failure above.
        if !self.saw_candidate {
            self.unsigned = None;
        }
        self.resolve(0, None, cx).outcome
    }

    /// The fixed record budget was reached before finding an anchor.
    #[must_use]
    pub fn budget_break(&self) -> WalkOutcome {
        let first = self.next.as_ref();
        WalkOutcome::Break(self.at(
            first.map_or(0, |line| line.seq.saturating_sub(1)),
            first.map_or(0, |line| line.wal),
            BreakReason::Budget,
        ))
    }
}
