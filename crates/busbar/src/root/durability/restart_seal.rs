// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! RESTART SEALING (SEALING-FIX r20 §3.6.0-§3.6.1): the boot phase that seals this node's own crash
//! leftover, and the pieces the predecessor sealer shares with it.
//!
//! A node whose journal already holds lines when it boots (a same-holder re-take) walks them from
//! its last valid stamp to its tail (`busbar_kernel_audit::walk_tail`). A clean, crash-sized tail on
//! this host gets one `after_restart` page; anything else gets a signed break notice, a
//! `restart_findings` entry and an alert, and boot continues. Both are signed on the Bootstrap
//! signer thread through the boot phase's `SignerHandle<Seal>`, never on the control runtime, and
//! staged and confirmed before the notary starts. The notary starts after the tail either way,
//! so a live page never vouches for a line this phase did not seal.

use busbar_kernel_audit::linked_record::{linked_record_from_journal_body, AuditLinkedRecord};
use busbar_kernel_audit::{
    break_body, stamp_body, stamp_from_journal_body, walk_tail, AuditVerifyingKey, BreakAt,
    BreakNotice, Fingerprint, Stamp, StampKind, TailItem, WalkContext, WalkOutcome,
};
use busbar_kernel_wal::{Entry, JournalRecord, RecordClass};

use super::boot_jobs::PendingBootJob;
use super::signer::{Seal, SignFailure, SignerHandle};
use super::Durability;

/// Why a node's records cannot be walked by this build.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct RecipeUnsupported;

/// THE WALK'S INPUT from journal records: every audit line, page stamp and undecodable audit body,
/// in journal order. Any other record (claims, checkpoints, break notices, the Bootstrap record)
/// is left out. A line under a recipe this build cannot compute stops the walk
/// (`AUDIT_RECIPE_UNSUPPORTED`, §3.6.0 step 4).
pub(crate) fn tail_items(records: &[JournalRecord]) -> Result<Vec<TailItem>, RecipeUnsupported> {
    let mut items = Vec::new();
    for record in records {
        if record.class != RecordClass::Transaction {
            continue;
        }
        match linked_record_from_journal_body(
            &record.body,
            &busbar_kernel::Registration::meter_class,
        ) {
            Ok(Some(AuditLinkedRecord::Unit(line))) => items.push(TailItem::Line {
                record: *line,
                node_seq: record.node_seq,
            }),
            Ok(Some(AuditLinkedRecord::NotaryKey(line))) => items.push(TailItem::Certificate {
                record: *line,
                node_seq: record.node_seq,
            }),
            Ok(None) => match stamp_from_journal_body(&record.body) {
                Ok(Some(stamp)) => items.push(TailItem::Stamp {
                    stamp,
                    node_seq: record.node_seq,
                }),
                Ok(None) => {}
                Err(_) => items.push(TailItem::Undecodable {
                    node_seq: record.node_seq,
                }),
            },
            Err(why) if why.starts_with("AUDIT_RECIPE_UNSUPPORTED") => {
                return Err(RecipeUnsupported)
            }
            Err(_) => items.push(TailItem::Undecodable {
                node_seq: record.node_seq,
            }),
        }
    }
    Ok(items)
}

/// A clean tail the walk found (`WalkOutcome::Clean`), as the restart page names it.
#[derive(Debug, Clone, Copy)]
pub(crate) struct CleanTail {
    pub(crate) from: u64,
    pub(crate) to: u64,
    pub(crate) fingerprint: Fingerprint,
    pub(crate) every: u64,
    pub(crate) down_from_ms: u64,
}

/// The unsigned `after_restart` page over a clean tail of `node`, sealed by `sealer` on `host`.
pub(crate) fn restart_page(
    node: u64,
    sealer: u64,
    host: &str,
    tail: CleanTail,
    now_ms: u64,
) -> Stamp {
    Stamp {
        node,
        from: tail.from,
        to: tail.to,
        fingerprint: tail.fingerprint,
        kind: StampKind::AfterRestart,
        sealer,
        host: host.to_owned(),
        every: tail.every,
        stamped_ms: now_ms,
        down_from_ms: tail.down_from_ms.min(now_ms),
        down_to_ms: now_ms,
        crypto: String::new(),
        sig_alg: String::new(),
        key_id: String::new(),
        key_cert: 0,
        signature: Vec::new(),
    }
}

/// The unsigned break notice for `at` over `node`, recorded by `sealer` on `host`.
pub(crate) fn break_notice(
    node: u64,
    sealer: u64,
    host: &str,
    at: &BreakAt,
    now_ms: u64,
) -> BreakNotice {
    BreakNotice {
        node,
        sealer,
        last_good: at.last_good,
        unsealed_from: at.unsealed_from,
        unsealed_to: at.unsealed_to,
        journal_from: at.journal_from,
        journal_to: at.journal_to,
        reason: at.reason,
        detected_ms: now_ms,
        host: host.to_owned(),
        crypto: String::new(),
        sig_alg: String::new(),
        key_id: String::new(),
        signature: Vec::new(),
    }
}

/// What the own-node phase did, for the boot log and its test.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum OwnSeal {
    /// No line was left unstamped (or the node is fresh).
    Nothing,
    /// One `after_restart` page over `from..=to` was staged and confirmed.
    Sealed { from: u64, to: u64 },
    /// A break notice was staged and confirmed; boot continues.
    Broken(BreakAt),
    /// Nothing was written: the reason is in `restart_findings`.
    Refused(String),
}

/// Transfer own-node work to the ordered boot gate before its certificate is signed.
pub(crate) async fn prepare_own_node(
    durability: &mut Durability,
    records: &[JournalRecord],
    handle: &SignerHandle<Seal>,
    key: &AuditVerifyingKey,
    host: &str,
) -> (OwnSeal, Option<PendingBootJob>) {
    let mut pending = None;
    let outcome = seal_own_node(durability, records, handle, key, host, &mut pending).await;
    (outcome, pending)
}

/// THE OWN-NODE RESTART SEAL (`BookPhase::SealAfterRestart`, §3.6.1): walk the records the book read
/// at reopen, sign on the Bootstrap thread through `handle`, stage and confirm. Never fails boot.
async fn seal_own_node(
    durability: &mut Durability,
    records: &[JournalRecord],
    handle: &SignerHandle<Seal>,
    key: &AuditVerifyingKey,
    host: &str,
    pending: &mut Option<PendingBootJob>,
) -> OwnSeal {
    let node = durability.record.node();
    let items = match tail_items(records) {
        Ok(items) => items,
        Err(RecipeUnsupported) => return refuse(
            durability,
            "AUDIT_RECIPE_UNSUPPORTED: the node's own audit lines use a recipe this build cannot \
                 compute; nothing is sealed or recorded"
                .into(),
        ),
    };
    let outcome = walk_tail(
        &items,
        &WalkContext {
            node,
            host,
            key,
            complete: true,
        },
    );
    let now_ms = busbar_kernel::store::now_ms();
    match outcome {
        WalkOutcome::Nothing { .. } | WalkOutcome::NeedMore => OwnSeal::Nothing,
        WalkOutcome::Unsupported => refuse(
            durability,
            "AUDIT_RECIPE_UNSUPPORTED: a stamp of this node names a signature algorithm this build \
             cannot verify; nothing is sealed or recorded"
                .into(),
        ),
        WalkOutcome::Foreign { anchor_host } => {
            busbar_kernel::diag_error!(
                busbar_kernel::diagnostics::AUDIT_PREDECESSOR_REFUSED,
                node,
                reason = "foreign_host",
                anchor_host = %anchor_host,
                "this node's own last stamp names another host; nothing is sealed for it"
            );
            refuse(
                durability,
                format!(
                    "audit restart seal: node {node}: its last stamp names host {anchor_host:?}, \
                     not this host; nothing sealed"
                ),
            )
        }
        WalkOutcome::Clean {
            from,
            to,
            fingerprint,
            every,
            down_from_ms,
            ..
        } => {
            let tail = CleanTail {
                from,
                to,
                fingerprint,
                every,
                down_from_ms,
            };
            let page = restart_page(node, node, host, tail, now_ms);
            *pending = Some(PendingBootJob::Restart(page.clone()));
            match handle.submit_restart(page).await {
                Ok(signed) => match stage_stamp(durability, &signed, pending).await {
                    Ok(()) => {
                        tracing::info!(
                            diag = %busbar_kernel::diagnostics::AUDIT_SEALED_AFTER_RESTART.banner(),
                            node, sealer = node, from, to,
                            down_from_ms = signed.down_from_ms, down_to_ms = signed.down_to_ms,
                            "the node's own unstamped audit tail was sealed after restart"
                        );
                        OwnSeal::Sealed { from, to }
                    }
                    Err(why) => refuse(durability, why),
                },
                Err(failure) => sign_failed(durability, node, failure),
            }
        }
        WalkOutcome::Break(at) => {
            let notice = break_notice(node, node, host, &at, now_ms);
            *pending = Some(PendingBootJob::Break(notice.clone()));
            match handle.submit_break(notice).await {
                Ok(signed) => {
                    let staged = stage_break(durability, &signed, pending).await;
                    let finding = broken_finding(node, &at);
                    durability.restart_findings.push(finding);
                    if let Err(why) = staged {
                        return refuse(durability, why);
                    }
                    busbar_kernel::diag_error!(
                        busbar_kernel::diagnostics::AUDIT_CHAIN_BROKEN_AT_BOOT,
                        node, sealer = node, last_good = at.last_good,
                        unsealed_from = at.unsealed_from, unsealed_to = at.unsealed_to,
                        reason = at.reason.as_str(),
                        "the node's own audit chain is broken after its last valid stamp; recorded, never sealed"
                    );
                    OwnSeal::Broken(at)
                }
                Err(failure) => sign_failed(durability, node, failure),
            }
        }
    }
}

/// The `restart_findings` text for a break.
pub(crate) fn broken_finding(node: u64, at: &BreakAt) -> String {
    format!(
        "audit chain broken after line {} (node {node}, reason {}): lines {}-{} are not sealed",
        at.last_good,
        at.reason.as_str(),
        at.unsealed_from,
        at.unsealed_to
    )
}

fn refuse(durability: &mut Durability, why: String) -> OwnSeal {
    durability.restart_findings.push(why.clone());
    OwnSeal::Refused(why)
}

fn sign_failed(durability: &mut Durability, node: u64, failure: SignFailure) -> OwnSeal {
    busbar_kernel::diag_error!(
        busbar_kernel::diagnostics::AUDIT_STAMP_FAILED,
        node,
        reason = "signer",
        cause = %failure,
        "the restart page or break notice could not be signed; the ordered boot queue retains it before live signing"
    );
    refuse(
        durability,
        format!("audit restart seal: node {node}: the Bootstrap signer failed: {failure}"),
    )
}

async fn stage_stamp(
    durability: &Durability,
    stamp: &Stamp,
    pending: &mut Option<PendingBootJob>,
) -> Result<(), String> {
    let body = stamp_body(stamp).map_err(|_| "a restart page exceeds the journal field bound")?;
    stage_one(
        durability,
        Entry::new(RecordClass::Transaction, body).at(stamp.stamped_ms / 1000, 0),
        pending,
    )
    .await
}

async fn stage_break(
    durability: &Durability,
    notice: &BreakNotice,
    pending: &mut Option<PendingBootJob>,
) -> Result<(), String> {
    let body = break_body(notice).map_err(|_| "a break notice exceeds the journal field bound")?;
    stage_one(
        durability,
        Entry::new(RecordClass::Transaction, body).at(notice.detected_ms / 1000, 0),
        pending,
    )
    .await
}

async fn stage_one(
    durability: &Durability,
    entry: Entry,
    pending: &mut Option<PendingBootJob>,
) -> Result<(), String> {
    let run = durability
        .journal
        .stage_run(&[entry])
        .map_err(|e| format!("audit restart seal: staging refused: {e:?}"))?;
    *pending = Some(PendingBootJob::Staged(run.clone()));
    durability
        .journal
        .confirm(&run)
        .await
        .map_err(|e| format!("audit restart seal: not confirmed: {e:?}"))?;
    *pending = None;
    Ok(())
}

impl Durability {
    /// Take the records read at reopen (once; the own-node restart seal walks them).
    pub(crate) fn take_boot_records(&mut self) -> Vec<JournalRecord> {
        std::mem::take(&mut self.boot_records)
    }
}

#[cfg(test)]
#[path = "../tests/durability_restart_seal.rs"]
mod tests;
