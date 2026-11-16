// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! RECORD COMMIT decode (IF 12.5): the nested `REC_PRED*`, then `REC_PUT*`/`REC_DEL*`, into a stack
//! array of at most `commit::MAX_OPS` operations, no heap. The driver has already bounded the
//! count; this re-checks it, since a handler never trusts a caller's framing.
//!
//! A plugin Need never carries `REC_CALLER` (a caller-bound record is plane-only, and a plugin has
//! no request subject), so the flag is `Invalid` here.

use busbar_kernel::plugin_records::CommitOp;
use busbar_plugin_abi::host_side::needs::NeedErr;
use busbar_plugin_abi::records::{commit, tag, RecDelRec, RecPredRec, RecPutRec, Records};

/// The most operations one commit carries.
pub const MAX_OPS: usize = commit::MAX_OPS as usize;

/// The empty slot the stack array starts from.
pub const EMPTY: CommitOp<'static> = CommitOp::Del {
    key: &[],
    caller: false,
};

/// Decode `recs` into `ops` and return how many were written.
///
/// # Errors
/// `Invalid` for an unknown tag, a bad size, a key longer than its record, a predicate kind
/// outside `PRED_*`, `REC_CALLER`, a predicate after a mutation, no operation at all, or more than
/// `MAX_OPS`.
pub fn decode<'a>(recs: Records<'a>, ops: &mut [CommitOp<'a>; MAX_OPS]) -> Result<usize, NeedErr> {
    let mut n = 0;
    let mut mutating = false;
    for rec in recs {
        let rec = rec.map_err(|_| NeedErr::Invalid)?;
        let slot = ops.get_mut(n).ok_or(NeedErr::Invalid)?;
        *slot = match rec.tag {
            tag::REC_PRED if !mutating => {
                let (head, tail) = rec.pod_tail::<RecPredRec>().map_err(|_| NeedErr::Invalid)?;
                let (key, value) = split(tail, head.key_len)?;
                if head.flags & commit::REC_CALLER != 0 {
                    return Err(NeedErr::Invalid);
                }
                match head.flags & commit::PRED_MASK {
                    commit::PRED_ABSENT if value.is_empty() => {
                        CommitOp::Absent { key, caller: false }
                    }
                    commit::PRED_PRESENT if value.is_empty() => {
                        CommitOp::Present { key, caller: false }
                    }
                    commit::PRED_EQUALS => CommitOp::Equals {
                        key,
                        value,
                        caller: false,
                    },
                    _ => return Err(NeedErr::Invalid),
                }
            }
            tag::REC_PUT => {
                mutating = true;
                let (head, tail) = rec.pod_tail::<RecPutRec>().map_err(|_| NeedErr::Invalid)?;
                let (key, value) = split(tail, head.key_len)?;
                if head.flags & commit::REC_CALLER != 0 {
                    return Err(NeedErr::Invalid);
                }
                CommitOp::Put {
                    key,
                    value,
                    ttl_s: head.ttl_s,
                    caller: false,
                }
            }
            tag::REC_DEL => {
                mutating = true;
                let (head, key) = rec.pod_tail::<RecDelRec>().map_err(|_| NeedErr::Invalid)?;
                if head.flags & commit::REC_CALLER != 0 || head._r != 0 {
                    return Err(NeedErr::Invalid);
                }
                CommitOp::Del { key, caller: false }
            }
            _ => return Err(NeedErr::Invalid),
        };
        n += 1;
    }
    if n == 0 {
        return Err(NeedErr::Invalid);
    }
    Ok(n)
}

fn split(tail: &[u8], key_len: u32) -> Result<(&[u8], &[u8]), NeedErr> {
    let at = usize::try_from(key_len).map_err(|_| NeedErr::Invalid)?;
    tail.split_at_checked(at).ok_or(NeedErr::Invalid)
}
