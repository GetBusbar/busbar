// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Test-only execution of the existing RECORD COMMIT wire format. The parent holds State's
//! mutex across predicate evaluation and publication. Stage every mutation before publication,
//! so malformed input also cannot expose a partial write. TTL is deliberately unsupported here:
//! only TTL=0 commits are accepted, never a silently non-expiring timed write.

use super::State;
use busbar_plugin_abi::host_side::caller::Caller;
use busbar_plugin_abi::host_side::needs::NeedErr;
use busbar_plugin_abi::records::{commit, tag, RecDelRec, RecPredRec, RecPutRec, Records};

impl State {
    pub(super) fn commit_records(
        &mut self,
        cx: &Caller<'_>,
        records: Records<'_>,
    ) -> Result<(u64, u64), NeedErr> {
        let at = |key: &[u8]| (cx.plugin.to_owned(), cx.name.to_owned(), key.to_vec());
        let mut mutations = Vec::new();
        let mut failed = None;
        let mut predicates = 0u32;
        let mut count = 0u32;
        let mut mutating = false;
        for record in records {
            let record = record.map_err(|_| NeedErr::Invalid)?;
            count += 1;
            if count > commit::MAX_OPS {
                return Err(NeedErr::Invalid);
            }
            match record.tag {
                tag::REC_PRED if !mutating => {
                    let (head, tail) = record
                        .pod_tail::<RecPredRec>()
                        .map_err(|_| NeedErr::Invalid)?;
                    if head.flags & !commit::PRED_MASK != 0 {
                        return Err(NeedErr::Invalid);
                    }
                    let (key, value) = split(tail, head.key_len)?;
                    let current = self.records.get(&at(key));
                    let matches = match head.flags {
                        commit::PRED_ABSENT if value.is_empty() => current.is_none(),
                        commit::PRED_PRESENT if value.is_empty() => current.is_some(),
                        commit::PRED_EQUALS => current.is_some_and(|bytes| bytes == value),
                        _ => return Err(NeedErr::Invalid),
                    };
                    if !matches && failed.is_none() {
                        failed = Some(predicates);
                    }
                    predicates += 1;
                }
                tag::REC_PUT => {
                    mutating = true;
                    let (head, tail) = record
                        .pod_tail::<RecPutRec>()
                        .map_err(|_| NeedErr::Invalid)?;
                    if head.flags != 0 || head.ttl_s != 0 {
                        return Err(NeedErr::Invalid);
                    }
                    let (key, value) = split(tail, head.key_len)?;
                    mutations.push((at(key), Some(value.to_vec())));
                }
                tag::REC_DEL => {
                    mutating = true;
                    let (head, key) = record
                        .pod_tail::<RecDelRec>()
                        .map_err(|_| NeedErr::Invalid)?;
                    if head.flags != 0 || head._r != 0 {
                        return Err(NeedErr::Invalid);
                    }
                    mutations.push((at(key), None));
                }
                _ => return Err(NeedErr::Invalid),
            }
        }
        if count == 0 {
            return Err(NeedErr::Invalid);
        }
        if let Some(index) = failed {
            return Ok((u64::from(commit::CONFLICT), u64::from(index)));
        }
        for (key, value) in mutations {
            match value {
                Some(value) => {
                    self.records.insert(key, value);
                }
                None => {
                    self.records.remove(&key);
                }
            }
        }
        Ok((u64::from(commit::APPLIED), 0))
    }
}

fn split(bytes: &[u8], len: u32) -> Result<(&[u8], &[u8]), NeedErr> {
    let len = usize::try_from(len).map_err(|_| NeedErr::Invalid)?;
    bytes.split_at_checked(len).ok_or(NeedErr::Invalid)
}
