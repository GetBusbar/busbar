// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Plane request encoders and describe decoders (IF §8.8). Core builds every plane record it hands a plane here,
//! and reads the plane describe items K6 and K7 need here; the L8 adapter and the K8 serving code call them.

use busbar_plugin_abi::fail::{fact, refused};
use busbar_plugin_abi::plane::{self, tag};
use busbar_plugin_abi::records::{
    tag as generic, Full, Pod, Rec, RecErr, Records, Reply, U32Rec, Writer,
};
use busbar_plugin_abi::types::Pair;
use zeroize::Zeroize;

use crate::ports::plane::{ObservedAnswer, TrustAnswer, WorkAnswer};

/// Round 13: the D_PROVIDER_SCHEMA text (at most one; a second is RecErr), or None.
pub fn decode_provider_schema<'o>(describe: Records<'o>) -> Result<Option<&'o str>, RecErr> {
    let mut schema = None;
    for rec in describe {
        let rec = rec?;
        if rec.tag == tag::D_PROVIDER_SCHEMA && schema.replace(rec.text()?).is_some() {
            return Err(RecErr::Size);
        }
    }
    Ok(schema)
}

/// Round 15: every D_DIALECT_AUTH item as a typed presentation, in describe order. A dialect not among the
/// image's D_DIALECT items, a second row for one dialect, an unknown presentation word, a field that does
/// not belong to the presentation, a missing DA_SIGN_SERVICE/DA_REGION_DEFAULT under PRESENT_SIGN, or a
/// TEXT outside the charset/length of §8.6 is RecErr (the registry refuses DescribeInvalid). Borrowed; the
/// registry copies it once at `add` into `DialectAuthOwned` (cold).
///
/// W1-A10: a misplaced tag is `Unknown(tag)` (a DA_* field outside D_DIALECT_AUTH or under the other
/// presentation, a field record where the head's TEXT belongs, a third record in a DA_FAMILY); a missing,
/// repeated or out-of-grammar value is `Size`; a non-zero reserved word is `Reserved`.
pub fn decode_dialect_auth<'o>(describe: Records<'o>) -> Result<Vec<DialectAuth<'o>>, RecErr> {
    // The image's dialects first: a row may come before the D_DIALECT item it names.
    let mut dialects = Vec::new();
    for rec in describe {
        let rec = rec?;
        match rec.tag {
            tag::D_DIALECT => dialects.push(rec.text()?),
            // Round 15: the DA_* fields are only valid inside a D_DIALECT_AUTH (FAULT UnknownTag elsewhere).
            tag::DA_KEY_HEADER..=tag::DA_REGION_DEFAULT => return Err(RecErr::Unknown(rec.tag)),
            _ => {}
        }
    }
    let mut rows: Vec<DialectAuth<'o>> = Vec::new();
    for rec in describe {
        let rec = rec?;
        if rec.tag != tag::D_DIALECT_AUTH {
            continue;
        }
        let row = dialect_auth_row(rec)?;
        if !dialects.contains(&row.dialect) || rows.iter().any(|seen| seen.dialect == row.dialect) {
            return Err(RecErr::Size);
        }
        rows.push(row);
    }
    Ok(rows)
}

/// Round 15: one D_DIALECT_AUTH row. Core vocabulary only: nothing in it is a plugin settings key.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DialectAuth<'o> {
    pub dialect: &'o str,
    pub present: Presentation<'o>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Presentation<'o> {
    Header {
        key_header: Option<&'o str>,
        own_header: Option<&'o str>,
        passthrough_header: Option<&'o str>,
        families: Vec<(
            &'o str, /* prefix */
            &'o str, /* header, "" = bearer */
            bool,    /* trim_start */
        )>,
    },
    Sign {
        service: &'o str,
        region_after: Vec<&'o str>,
        region_default: &'o str,
    },
}

/// The registry's owned copy (every `&'o str` becomes `Box<str>`; same shape, same field names).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DialectAuthOwned {
    pub dialect: Box<str>,
    pub present: PresentationOwned,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PresentationOwned {
    Header {
        key_header: Option<Box<str>>,
        own_header: Option<Box<str>>,
        passthrough_header: Option<Box<str>>,
        families: Vec<(Box<str>, Box<str>, bool)>,
    },
    Sign {
        service: Box<str>,
        region_after: Vec<Box<str>>,
        region_default: Box<str>,
    },
}

impl DialectAuth<'_> {
    pub fn to_owned(&self) -> DialectAuthOwned {
        let present = match &self.present {
            Presentation::Header {
                key_header,
                own_header,
                passthrough_header,
                families,
            } => {
                let mut owned: Vec<(Box<str>, Box<str>, bool)> = Vec::with_capacity(families.len());
                for &(prefix, header, trim_start) in families {
                    owned.push((Box::from(prefix), Box::from(header), trim_start));
                }
                PresentationOwned::Header {
                    key_header: key_header.map(Box::from),
                    own_header: own_header.map(Box::from),
                    passthrough_header: passthrough_header.map(Box::from),
                    families: owned,
                }
            }
            Presentation::Sign {
                service,
                region_after,
                region_default,
            } => {
                let mut owned: Vec<Box<str>> = Vec::with_capacity(region_after.len());
                for &label in region_after {
                    owned.push(Box::from(label));
                }
                PresentationOwned::Sign {
                    service: Box::from(*service),
                    region_after: owned,
                    region_default: Box::from(*region_default),
                }
            }
        };
        DialectAuthOwned {
            dialect: Box::from(self.dialect),
            present,
        }
    }
}

/// The presentation words of D_DIALECT_AUTH (core vocabulary).
pub const PRESENT_HEADER: &str = "header";
pub const PRESENT_SIGN: &str = "request-signature";

/// §8.6: every D_DIALECT_AUTH TEXT is at most this many bytes.
const DA_TEXT_MAX: usize = 128;
/// §8.6 RefusalRec: the status core chose is clamped into 400..=599, and its text is at most 300 bytes.
const REFUSAL_STATUS_MIN: u16 = 400;
const REFUSAL_STATUS_MAX: u16 = 599;
const REFUSAL_TEXT_MAX: usize = 300;
/// §8.6 TrustAns: the algorithm or critical member a TRUST_VERIFY verdict names, core-cut to 128 bytes.
const TRUST_NAMED_MAX: usize = 128;

/// One D_DIALECT_AUTH item: TEXT dialect, TEXT presentation word, then that presentation's fields.
fn dialect_auth_row(rec: Rec<'_>) -> Result<DialectAuth<'_>, RecErr> {
    let mut fields = rec.nested();
    let dialect = da_text(head_text(&mut fields)?, Case::Any, false)?;
    let present = match head_text(&mut fields)? {
        PRESENT_HEADER => header_fields(fields)?,
        PRESENT_SIGN => sign_fields(fields)?,
        _ => return Err(RecErr::Size),
    };
    Ok(DialectAuth { dialect, present })
}

/// The next record, which must be a generic TEXT.
fn head_text<'o>(fields: &mut Records<'o>) -> Result<&'o str, RecErr> {
    let rec = fields.next().ok_or(RecErr::Size)??;
    if rec.tag != generic::TEXT {
        return Err(RecErr::Unknown(rec.tag));
    }
    rec.text()
}

fn header_fields(fields: Records<'_>) -> Result<Presentation<'_>, RecErr> {
    let (mut key_header, mut own_header, mut passthrough_header) = (None, None, None);
    let mut families = Vec::new();
    for rec in fields {
        let rec = rec?;
        match rec.tag {
            tag::DA_KEY_HEADER => once(&mut key_header, da_text(rec.text()?, Case::Lower, false)?)?,
            tag::DA_OWN_HEADER => once(&mut own_header, da_text(rec.text()?, Case::Lower, false)?)?,
            tag::DA_PASSTHROUGH_HEADER => {
                once(
                    &mut passthrough_header,
                    da_text(rec.text()?, Case::Lower, false)?,
                )?;
            }
            tag::DA_FAMILY => families.push(family(rec)?),
            other => return Err(RecErr::Unknown(other)),
        }
    }
    Ok(Presentation::Header {
        key_header,
        own_header,
        passthrough_header,
        families,
    })
}

fn sign_fields(fields: Records<'_>) -> Result<Presentation<'_>, RecErr> {
    let (mut service, mut region_default) = (None, None);
    let mut region_after = Vec::new();
    for rec in fields {
        let rec = rec?;
        match rec.tag {
            tag::DA_SIGN_SERVICE => once(&mut service, da_text(rec.text()?, Case::Any, false)?)?,
            tag::DA_REGION_AFTER => region_after.push(da_text(rec.text()?, Case::Any, false)?),
            tag::DA_REGION_DEFAULT => {
                once(&mut region_default, da_text(rec.text()?, Case::Any, false)?)?
            }
            other => return Err(RecErr::Unknown(other)),
        }
    }
    Ok(Presentation::Sign {
        service: service.ok_or(RecErr::Size)?,
        region_after,
        region_default: region_default.ok_or(RecErr::Size)?,
    })
}

/// DA_FAMILY: DaFamilyRec, then exactly a nested TEXT key prefix and a TEXT header ("" = bearer).
fn family(rec: Rec<'_>) -> Result<(&str, &str, bool), RecErr> {
    let (head, tail) = rec.pod_tail::<plane::DaFamilyRec>()?;
    if head._r != 0 {
        return Err(RecErr::Reserved);
    }
    let trim_start = match head.trim_start {
        0 => false,
        1 => true,
        _ => return Err(RecErr::Size),
    };
    let mut parts = Records::new(tail);
    let prefix = da_text(head_text(&mut parts)?, Case::Any, false)?;
    let header = da_text(head_text(&mut parts)?, Case::Lower, true)?;
    match parts.next() {
        None => Ok((prefix, header, trim_start)),
        Some(Ok(extra)) => Err(RecErr::Unknown(extra.tag)),
        Some(Err(e)) => Err(e),
    }
}

/// A field stated at most once.
fn once<'o>(slot: &mut Option<&'o str>, value: &'o str) -> Result<(), RecErr> {
    match slot.replace(value) {
        None => Ok(()),
        Some(_) => Err(RecErr::Size),
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Case {
    Any,
    /// Header names: lowercase only.
    Lower,
}

/// §8.6: ≤ 128 bytes of `[A-Za-z0-9._-]` (`[a-z0-9._-]` for a header name); empty only where `empty` allows.
fn da_text(text: &str, case: Case, empty: bool) -> Result<&str, RecErr> {
    let charset = |byte: u8| {
        byte.is_ascii_lowercase()
            || byte.is_ascii_digit()
            || matches!(byte, b'.' | b'_' | b'-')
            || (case == Case::Any && byte.is_ascii_uppercase())
    };
    if text.len() > DA_TEXT_MAX || (text.is_empty() && !empty) || !text.bytes().all(charset) {
        return Err(RecErr::Size);
    }
    Ok(text)
}

/// `text` cut to at most `max` bytes, at a char boundary.
fn cut(text: &str, max: usize) -> &str {
    let mut end = text.len().min(max);
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    &text[..end]
}

/// One record: `head`, then `parts` back to back. The tail is staged in a block of exactly its size (never
/// regrown, so never copied) and wiped before it is freed: plane record values may be credentials.
fn put_head_parts<T: Pod>(
    w: &mut impl Writer,
    tag: u16,
    head: &T,
    parts: &[&[u8]],
) -> Result<(), Full> {
    let len = parts
        .iter()
        .try_fold(0usize, |len, part| len.checked_add(part.len()))
        .ok_or(Full)?;
    let mut tail = Vec::with_capacity(len);
    for part in parts {
        tail.extend_from_slice(part);
    }
    let put = w.put_pod_tail(tag, head, &tail);
    tail.zeroize();
    put
}

/// `code` < 0x100 (generic only, §12.15; a larger code is a core bug: debug_assert, then R_DENIED).
pub fn encode_refusal(w: &mut impl Writer, status: u16, code: u32, text: &str) -> Result<(), Full> {
    debug_assert!(
        code < 0x100,
        "a REFUSAL carries a generic code only (§12.15), got {code:#x}"
    );
    let code = if code < 0x100 {
        code
    } else {
        refused::R_DENIED
    };
    let head = plane::RefusalRec {
        status: u32::from(status.clamp(REFUSAL_STATUS_MIN, REFUSAL_STATUS_MAX)),
        code,
    };
    w.put_pod_tail(tag::REFUSAL, &head, cut(text, REFUSAL_TEXT_MAX).as_bytes())
}

/// FROM_UPSTREAM P_HEAD: H_STATUS, PAIR*, FACT(FACT_TLS_PIN)? and FACT(FACT_TLS_CLIENT_ID)?.
pub fn encode_upstream_head(
    w: &mut impl Writer,
    status: u16,
    headers: &[Pair<'_>],
    pin_ok: Option<bool>,
    client_id: Option<bool>,
) -> Result<(), Full> {
    let status = U32Rec {
        value: u32::from(status),
        _r: 0,
    };
    w.put_pod(generic::H_STATUS, &status)?;
    for pair in headers {
        w.put_pair(generic::PAIR, pair.name.get(), pair.value.get())?;
    }
    if let Some(ok) = pin_ok {
        w.put_fact(fact::FACT_TLS_PIN, u64::from(ok))?;
    }
    if let Some(ok) = client_id {
        w.put_fact(fact::FACT_TLS_CLIENT_ID, u64::from(ok))?;
    }
    Ok(())
}

/// (check, outcome, failed, status) per COMMIT, in answer order.
pub fn encode_committed(w: &mut impl Writer, answers: &[(u32, u32, u32, u32)]) -> Result<(), Full> {
    for &(check, outcome, failed, status) in answers {
        let ans = plane::CommittedRec {
            check,
            outcome,
            failed,
            status,
        };
        w.put_pod(tag::COMMITTED, &ans)?;
    }
    Ok(())
}

/// One TRUST_ANS per TRUST, in intent order. TRUST_STATE: the tail is nested TR_ITEM_STATE* (TrustItemState,
/// name, approved digest if TS_APPROVED, sighted digest if TS_SIGHTED). TRUST_VERIFY: the tail is `named`, cut
/// to 128 bytes. An answer has one or the other (`items` wins); TRUST_SERVES has neither.
pub fn encode_trust_answers(w: &mut impl Writer, answers: &[TrustAnswer<'_>]) -> Result<(), Full> {
    for answer in answers {
        debug_assert!(
            answer.items.is_empty() || answer.named.is_empty(),
            "a TRUST_ANS tail is item states or a named member, never both"
        );
        let ans = plane::TrustAns {
            check: answer.check,
            verdict: answer.verdict,
        };
        if answer.items.is_empty() {
            w.put_pod_tail(
                tag::TRUST_ANS,
                &ans,
                cut(answer.named, TRUST_NAMED_MAX).as_bytes(),
            )?;
            continue;
        }
        let mut states = Reply::new();
        for item in answer.items {
            let mut flags = 0;
            if item.approved.is_some() {
                flags |= plane::TS_APPROVED;
            }
            if item.sighted.is_some() {
                flags |= plane::TS_SIGHTED;
            }
            let state = plane::TrustItemState {
                verdict: item.verdict,
                flags,
                name_len: u32::try_from(item.name.len()).map_err(|_| Full)?,
                _r: 0,
            };
            let approved = item.approved.as_ref().map_or(&[][..], |d| &d[..]);
            let sighted = item.sighted.as_ref().map_or(&[][..], |d| &d[..]);
            put_head_parts(
                &mut states,
                tag::TR_ITEM_STATE,
                &state,
                &[item.name.as_bytes(), approved, sighted],
            )?;
        }
        w.put_pod_tail(tag::TRUST_ANS, &ans, states.as_bytes())?;
    }
    Ok(())
}

/// P_CHANNEL's bytes (§8.6, R6a / #257): exactly one CH_ATTACH record, the `ChanAttach` pod plus the
/// CH_READY tail handed to later attachers.
pub fn encode_chan_attach(
    w: &mut impl Writer,
    generation: u64,
    slot: u64,
    greet: bool,
    ready_tail: &[u8],
) -> Result<(), Full> {
    let attach = plane::ChanAttach {
        generation,
        slot,
        greet: u32::from(greet),
        _r: 0,
    };
    w.put_pod_tail(tag::CH_ATTACH, &attach, ready_tail)
}

/// One CAT_MODEL text per model, in the order core shows them (`render(RENDER_CATALOG)`'s arg).
pub fn encode_catalog(w: &mut impl Writer, models: &[&str]) -> Result<(), Full> {
    for model in models {
        w.put_text(tag::CAT_MODEL, model)?;
    }
    Ok(())
}

/// One LOOKUP_HIT per hit: (lookup index, key, value), body LookupHit + key + value.
pub fn encode_lookup_hits(w: &mut impl Writer, hits: &[(u32, &[u8], &[u8])]) -> Result<(), Full> {
    for &(lookup, key, value) in hits {
        let hit = plane::LookupHit {
            lookup,
            key_len: u32::try_from(key.len()).map_err(|_| Full)?,
        };
        put_head_parts(w, tag::LOOKUP_HIT, &hit, &[key, value])?;
    }
    Ok(())
}

/// Round 12: one CHAIN_STATE after the LOOKUP_HITs of an LK_CHAIN lookup (§8.6).
pub fn encode_chain_state(
    w: &mut impl Writer,
    lookup: u32,
    len: u64,
    broken_at: u64,
) -> Result<(), Full> {
    let state = plane::ChainState {
        lookup,
        _r: 0,
        len,
        broken_at,
    };
    w.put_pod(tag::CHAIN_STATE, &state)
}

/// One ENTITLE_ANS (check, granted 1 or 0) per ENTITLE, in intent order.
pub fn encode_entitle_answers(w: &mut impl Writer, answers: &[(u32, bool)]) -> Result<(), Full> {
    for &(check, granted) in answers {
        let ans = plane::EntitleAns {
            check,
            granted: u32::from(granted),
        };
        w.put_pod(tag::ENTITLE_ANS, &ans)?;
    }
    Ok(())
}

/// Round 16, P_JUDGED: one JUDGE_ANS (check, verdict = DEST_*) per JUDGE, in intent order.
pub fn encode_judged(w: &mut impl Writer, answers: &[(u32, u32)]) -> Result<(), Full> {
    for &(check, verdict) in answers {
        w.put_pod(tag::JUDGE_ANS, &plane::JudgeAns { check, verdict })?;
    }
    Ok(())
}

/// One MINTED per MINT, in intent order: `status` 0 = minted (`ticket` = the client-facing text, opaque to the
/// plane), else a generic REFUSED code (`ticket` is ignored and `expires_at_s` is 0).
pub fn encode_minted(w: &mut impl Writer, answers: &[(u32, u32, u64, &str)]) -> Result<(), Full> {
    for &(check, status, expires_at_s, ticket) in answers {
        let ans = plane::MintedRec {
            check,
            status,
            expires_at_s: if status == 0 { expires_at_s } else { 0 },
        };
        let text = if status == 0 { ticket } else { "" };
        w.put_pod_tail(tag::MINTED, &ans, text.as_bytes())?;
    }
    Ok(())
}

/// One answer to a SIGN, as [`encode_signed`] writes it.
pub enum SignedAnswer<'a> {
    /// SIGN_JWS_COMPACT: the compact JWS is the tail.
    Compact { check: u32, jws: &'a str },
    /// SIGN_JWS_DETACHED: the tail is nested SG_PROTECTED + SG_SIGNATURE.
    Detached {
        check: u32,
        protected: &'a str,
        signature: &'a str,
    },
    /// A REFUSED code (generic, < 0x100); no tail.
    Refused { check: u32, status: u32 },
}

/// One SIGNED per SIGN, in intent order.
pub fn encode_signed(w: &mut impl Writer, answers: &[SignedAnswer<'_>]) -> Result<(), Full> {
    for answer in answers {
        match answer {
            SignedAnswer::Compact { check, jws } => {
                let ans = plane::SignedRec {
                    check: *check,
                    status: 0,
                };
                w.put_pod_tail(tag::SIGNED, &ans, jws.as_bytes())?;
            }
            SignedAnswer::Detached {
                check,
                protected,
                signature,
            } => {
                let ans = plane::SignedRec {
                    check: *check,
                    status: 0,
                };
                let mut nested = Reply::new();
                nested.put_text(tag::SG_PROTECTED, protected)?;
                nested.put_text(tag::SG_SIGNATURE, signature)?;
                w.put_pod_tail(tag::SIGNED, &ans, nested.as_bytes())?;
            }
            SignedAnswer::Refused { check, status } => {
                let ans = plane::SignedRec {
                    check: *check,
                    status: *status,
                };
                w.put_pod(tag::SIGNED, &ans)?;
            }
        }
    }
    Ok(())
}

/// One CONNECT_ANS per CONNECT, in intent order: (check, CONN_* state, the URL for a BEGIN that is READY).
pub fn encode_connect_answers(
    w: &mut impl Writer,
    answers: &[(u32, u32, Option<&str>)],
) -> Result<(), Full> {
    for &(check, state, url) in answers {
        let ans = plane::ConnectAns { check, state };
        w.put_pod_tail(tag::CONNECT_ANS, &ans, url.unwrap_or("").as_bytes())?;
    }
    Ok(())
}

/// P_OBSERVED: OBS_SCOPE_ANS (check, status, scope id) and OBS_RECEIPT (check, status, receipt), in intent order.
pub fn encode_observed(w: &mut impl Writer, answers: &[ObservedAnswer<'_>]) -> Result<(), Full> {
    for answer in answers {
        match answer {
            ObservedAnswer::Scope {
                check,
                status,
                scope,
            } => {
                let ans = plane::ObsScopeAns {
                    check: *check,
                    status: *status,
                };
                let id = scope.as_ref().map_or(&[][..], |id| &id[..]);
                w.put_pod_tail(tag::OBS_SCOPE_ANS, &ans, id)?;
            }
            ObservedAnswer::Receipt {
                check,
                status,
                receipt,
            } => {
                let ans = plane::ObsReceipt {
                    check: *check,
                    status: *status,
                };
                w.put_pod_tail(tag::OBS_RECEIPT, &ans, receipt)?;
            }
        }
    }
    Ok(())
}

/// Round 10, P_WORK: one WORK_ANS per WORK, in intent order (WK_REF for OPEN/FIND, then WK_TARGET for FIND).
/// An empty `reference` or `target` writes no record (`WorkAnswer`: "" when refused, and except for FIND).
pub fn encode_work_answers(w: &mut impl Writer, answers: &[WorkAnswer<'_>]) -> Result<(), Full> {
    for answer in answers {
        let ans = plane::WorkAns {
            check: answer.check,
            status: answer.status,
            state: answer.state,
            _r: 0,
        };
        let mut nested = Reply::new();
        if !answer.reference.is_empty() {
            nested.put_text(tag::WK_REF, answer.reference)?;
        }
        if !answer.target.is_empty() {
            nested.put_text(tag::WK_TARGET, answer.target)?;
        }
        w.put_pod_tail(tag::WORK_ANS, &ans, nested.as_bytes())?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    //! W1-A10: the plane encoders and describe decoders of IF §8.8, read back with the generic reader (§3.1).

    use busbar_plugin_abi::records::{FactRec, Nested, PairRec};
    use busbar_plugin_abi::types::{Bytes, Str};

    use super::*;
    use crate::ports::plane::TrustItem;

    fn recs(bytes: &[u8]) -> Vec<Rec<'_>> {
        Records::new(bytes)
            .collect::<Result<Vec<_>, _>>()
            .expect("the encoder writes well-framed records")
    }

    fn texts<'a>(records: &[Rec<'a>], want: u16) -> Vec<&'a str> {
        records
            .iter()
            .map(|rec| {
                assert_eq!(rec.tag, want);
                rec.text().expect("UTF-8")
            })
            .collect()
    }

    #[test]
    fn a_refusal_is_one_record_with_its_status_code_and_text() {
        let mut w = Reply::new();
        encode_refusal(&mut w, 403, refused::R_DENIED, "denied by policy").expect("fits");
        let records = recs(w.as_bytes());
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].tag, tag::REFUSAL);
        let (head, text) = records[0]
            .pod_tail::<plane::RefusalRec>()
            .expect("RefusalRec");
        assert_eq!((head.status, head.code), (403, refused::R_DENIED));
        assert_eq!(text, b"denied by policy");
    }

    #[test]
    fn a_refusal_status_is_clamped_and_its_text_cut_at_a_char_boundary() {
        let mut long = "a".repeat(299);
        long.push('é'); // bytes 299..301: a 300-byte cut would split it
        let mut w = Reply::new();
        encode_refusal(&mut w, 200, refused::R_INVALID, &long).expect("fits");
        encode_refusal(&mut w, 700, refused::R_INVALID, "").expect("fits");
        let records = recs(w.as_bytes());
        let (low, text) = records[0]
            .pod_tail::<plane::RefusalRec>()
            .expect("RefusalRec");
        assert_eq!(low.status, 400);
        assert_eq!(text, "a".repeat(299).as_bytes());
        let (high, empty) = records[1]
            .pod_tail::<plane::RefusalRec>()
            .expect("RefusalRec");
        assert_eq!(high.status, 599);
        assert!(empty.is_empty());
    }

    #[cfg(debug_assertions)]
    #[test]
    #[should_panic(expected = "generic code")]
    fn a_kind_code_in_a_refusal_is_a_core_bug() {
        let mut w = Reply::new();
        let _ = encode_refusal(&mut w, 403, 0x100, "kind code");
    }

    #[test]
    fn an_upstream_head_is_status_pairs_then_the_tls_facts() {
        let mut w = Reply::new();
        let pairs = [Pair {
            name: Str::EMPTY,
            value: Bytes::EMPTY,
        }];
        encode_upstream_head(&mut w, 201, &pairs, Some(true), Some(false)).expect("fits");
        encode_upstream_head(&mut w, 502, &[], None, None).expect("fits");
        let records = recs(w.as_bytes());
        assert_eq!(records.len(), 5);
        assert_eq!(records[0].tag, generic::H_STATUS);
        assert_eq!(records[0].pod::<U32Rec>().expect("U32Rec").value, 201);
        assert_eq!(records[1].tag, generic::PAIR);
        assert_eq!(records[1].pair().expect("pair shape"), ("", &b""[..]));
        assert_eq!(records[1].body.len(), size_of::<PairRec>());
        let pin = records[2].pod::<FactRec>().expect("FactRec");
        assert_eq!(
            (records[2].tag, pin.key, pin.value),
            (generic::FACT, fact::FACT_TLS_PIN, 1)
        );
        let id = records[3].pod::<FactRec>().expect("FactRec");
        assert_eq!(
            (records[3].tag, id.key, id.value),
            (generic::FACT, fact::FACT_TLS_CLIENT_ID, 0)
        );
        // The second head: no pin and no client identity configured, so no facts.
        assert_eq!(records[4].tag, generic::H_STATUS);
        assert_eq!(records[4].pod::<U32Rec>().expect("U32Rec").value, 502);
    }

    #[test]
    fn committed_answers_are_one_record_each_in_answer_order() {
        let mut w = Reply::new();
        let answers = [
            (1, 1, 0, 0),
            (2, 2, 3, 0),
            (3, 0, 0, refused::R_RATE_LIMITED),
        ];
        encode_committed(&mut w, &answers).expect("fits");
        let records = recs(w.as_bytes());
        assert_eq!(records.len(), 3);
        for (rec, want) in records.iter().zip(answers) {
            assert_eq!(rec.tag, tag::COMMITTED);
            let got = rec.pod::<plane::CommittedRec>().expect("CommittedRec");
            assert_eq!((got.check, got.outcome, got.failed, got.status), want);
        }
    }

    #[test]
    fn trust_answers_carry_item_states_or_the_named_member() {
        let items = [
            TrustItem {
                name: "search",
                verdict: plane::DISTRUST_NONE,
                approved: Some([1; 32]),
                sighted: Some([2; 32]),
            },
            TrustItem {
                name: "fetch",
                verdict: plane::DISTRUST_NOT_APPROVED,
                approved: None,
                sighted: Some([3; 32]),
            },
        ];
        let answers = [
            TrustAnswer {
                check: 7,
                verdict: plane::DISTRUST_CHANGED,
                items: &items,
                named: "",
            },
            TrustAnswer {
                check: 8,
                verdict: plane::SIGNED_ALGORITHM,
                items: &[],
                named: "HS256",
            },
            TrustAnswer {
                check: 9,
                verdict: plane::SIGNED_VERIFIED,
                items: &[],
                named: "",
            },
        ];
        let mut w = Reply::new();
        encode_trust_answers(&mut w, &answers).expect("fits");
        let records = recs(w.as_bytes());
        assert_eq!(records.len(), 3);

        assert_eq!(records[0].tag, tag::TRUST_ANS);
        let (ans, tail) = records[0].pod_tail::<plane::TrustAns>().expect("TrustAns");
        assert_eq!((ans.check, ans.verdict), (7, plane::DISTRUST_CHANGED));
        let states = recs(tail);
        assert_eq!(states.len(), 2);
        assert_eq!(states[0].tag, tag::TR_ITEM_STATE);
        let (first, rest) = states[0]
            .pod_tail::<plane::TrustItemState>()
            .expect("state");
        assert_eq!(
            (first.verdict, first.flags, first.name_len, first._r),
            (
                plane::DISTRUST_NONE,
                plane::TS_APPROVED | plane::TS_SIGHTED,
                6,
                0
            )
        );
        let mut want = b"search".to_vec();
        want.extend_from_slice(&[1; 32]);
        want.extend_from_slice(&[2; 32]);
        assert_eq!(rest, &want[..]);
        let (second, rest) = states[1]
            .pod_tail::<plane::TrustItemState>()
            .expect("state");
        assert_eq!(
            (second.verdict, second.flags, second.name_len),
            (plane::DISTRUST_NOT_APPROVED, plane::TS_SIGHTED, 5)
        );
        let mut want = b"fetch".to_vec();
        want.extend_from_slice(&[3; 32]);
        assert_eq!(rest, &want[..]);

        let (ans, tail) = records[1].pod_tail::<plane::TrustAns>().expect("TrustAns");
        assert_eq!(
            (ans.check, ans.verdict, tail),
            (8, plane::SIGNED_ALGORITHM, &b"HS256"[..])
        );
        let (ans, tail) = records[2].pod_tail::<plane::TrustAns>().expect("TrustAns");
        assert_eq!((ans.check, ans.verdict), (9, plane::SIGNED_VERIFIED));
        assert!(tail.is_empty());
    }

    #[test]
    fn a_named_member_is_cut_to_128_bytes_at_a_char_boundary() {
        let mut named = "x".repeat(127);
        named.push('ü');
        let answers = [TrustAnswer {
            check: 1,
            verdict: plane::SIGNED_CRITICAL,
            items: &[],
            named: &named,
        }];
        let mut w = Reply::new();
        encode_trust_answers(&mut w, &answers).expect("fits");
        let records = recs(w.as_bytes());
        let (_, tail) = records[0].pod_tail::<plane::TrustAns>().expect("TrustAns");
        assert_eq!(tail, "x".repeat(127).as_bytes());
    }

    #[test]
    fn a_catalog_is_one_cat_model_text_per_model() {
        let mut w = Reply::new();
        encode_catalog(&mut w, &["gpt-5", "claude-opus", ""]).expect("fits");
        let records = recs(w.as_bytes());
        assert_eq!(
            texts(&records, tag::CAT_MODEL),
            ["gpt-5", "claude-opus", ""]
        );
    }

    #[test]
    fn lookup_hits_carry_the_lookup_index_then_key_and_value() {
        let mut w = Reply::new();
        let hits: [(u32, &[u8], &[u8]); 2] = [(0, b"task/1", b"{\"s\":1}"), (2, b"k", b"")];
        encode_lookup_hits(&mut w, &hits).expect("fits");
        encode_chain_state(&mut w, 2, 9, 4).expect("fits");
        let records = recs(w.as_bytes());
        assert_eq!(records.len(), 3);
        for (rec, (lookup, key, value)) in records.iter().zip(hits) {
            assert_eq!(rec.tag, tag::LOOKUP_HIT);
            let (hit, tail) = rec.pod_tail::<plane::LookupHit>().expect("LookupHit");
            assert_eq!(hit.lookup, lookup);
            assert_eq!(hit.key_len as usize, key.len());
            let (k, v) = tail.split_at(key.len());
            assert_eq!((k, v), (key, value));
        }
        assert_eq!(records[2].tag, tag::CHAIN_STATE);
        let state = records[2].pod::<plane::ChainState>().expect("ChainState");
        assert_eq!(
            (state.lookup, state._r, state.len, state.broken_at),
            (2, 0, 9, 4)
        );
    }

    #[test]
    fn entitle_and_judge_answers_are_one_record_each() {
        let mut w = Reply::new();
        encode_entitle_answers(&mut w, &[(4, true), (5, false)]).expect("fits");
        encode_judged(
            &mut w,
            &[(6, plane::DEST_ALLOWED), (7, plane::DEST_INTERNAL)],
        )
        .expect("fits");
        let records = recs(w.as_bytes());
        assert_eq!(records.len(), 4);
        let granted: Vec<_> = records[..2]
            .iter()
            .map(|rec| {
                assert_eq!(rec.tag, tag::ENTITLE_ANS);
                let ans = rec.pod::<plane::EntitleAns>().expect("EntitleAns");
                (ans.check, ans.granted)
            })
            .collect();
        assert_eq!(granted, [(4, 1), (5, 0)]);
        let judged: Vec<_> = records[2..]
            .iter()
            .map(|rec| {
                assert_eq!(rec.tag, tag::JUDGE_ANS);
                let ans = rec.pod::<plane::JudgeAns>().expect("JudgeAns");
                (ans.check, ans.verdict)
            })
            .collect();
        assert_eq!(
            judged,
            [(6, plane::DEST_ALLOWED), (7, plane::DEST_INTERNAL)]
        );
    }

    #[test]
    fn observed_answers_keep_intent_order_with_their_tails() {
        let answers = [
            ObservedAnswer::Scope {
                check: 1,
                status: plane::OBS_READY,
                scope: Some([9; 32]),
            },
            ObservedAnswer::Receipt {
                check: 2,
                status: plane::OBS_ACCEPTED,
                receipt: b"receipt-1",
            },
            ObservedAnswer::Scope {
                check: 3,
                status: plane::OBS_REFUSED,
                scope: None,
            },
        ];
        let mut w = Reply::new();
        encode_observed(&mut w, &answers).expect("fits");
        let records = recs(w.as_bytes());
        assert_eq!(records.len(), 3);
        assert_eq!(records[0].tag, tag::OBS_SCOPE_ANS);
        let (ans, tail) = records[0]
            .pod_tail::<plane::ObsScopeAns>()
            .expect("ObsScopeAns");
        assert_eq!(
            (ans.check, ans.status, tail),
            (1, plane::OBS_READY, &[9u8; 32][..])
        );
        assert_eq!(records[1].tag, tag::OBS_RECEIPT);
        let (ans, tail) = records[1]
            .pod_tail::<plane::ObsReceipt>()
            .expect("ObsReceipt");
        assert_eq!(
            (ans.check, ans.status, tail),
            (2, plane::OBS_ACCEPTED, &b"receipt-1"[..])
        );
        assert_eq!(records[2].tag, tag::OBS_SCOPE_ANS);
        let (ans, tail) = records[2]
            .pod_tail::<plane::ObsScopeAns>()
            .expect("ObsScopeAns");
        assert_eq!((ans.check, ans.status), (3, plane::OBS_REFUSED));
        assert!(tail.is_empty());
    }

    #[test]
    fn work_answers_nest_the_reference_then_the_target() {
        let answers = [
            WorkAnswer {
                check: 1,
                status: 0,
                state: plane::WORK_LIVE,
                reference: "wk-1",
                target: "",
            },
            WorkAnswer {
                check: 2,
                status: 0,
                state: plane::WORK_LIVE,
                reference: "wk-1",
                target: "/v1beta/interactions/abc?alt=sse",
            },
            WorkAnswer {
                check: 3,
                status: refused::R_UNSUPPORTED,
                state: 0,
                reference: "",
                target: "",
            },
        ];
        let mut w = Reply::new();
        encode_work_answers(&mut w, &answers).expect("fits");
        let records = recs(w.as_bytes());
        assert_eq!(records.len(), 3);
        let want: [(u32, u32, u32, &[(u16, &str)]); 3] = [
            (1, 0, plane::WORK_LIVE, &[(tag::WK_REF, "wk-1")]),
            (
                2,
                0,
                plane::WORK_LIVE,
                &[
                    (tag::WK_REF, "wk-1"),
                    (tag::WK_TARGET, "/v1beta/interactions/abc?alt=sse"),
                ],
            ),
            (3, refused::R_UNSUPPORTED, 0, &[]),
        ];
        for (rec, (check, status, state, nested)) in records.iter().zip(want) {
            assert_eq!(rec.tag, tag::WORK_ANS);
            let (ans, tail) = rec.pod_tail::<plane::WorkAns>().expect("WorkAns");
            assert_eq!(
                (ans.check, ans.status, ans.state, ans._r),
                (check, status, state, 0)
            );
            let got: Vec<_> = recs(tail)
                .iter()
                .map(|r| (r.tag, r.text().expect("UTF-8")))
                .collect();
            assert_eq!(got, nested);
        }
    }

    #[test]
    fn the_provider_schema_is_at_most_one_text() {
        let mut none = Reply::new();
        none.put_text(tag::D_DIALECT, "anthropic").expect("fits");
        assert_eq!(
            decode_provider_schema(Records::new(none.as_bytes())),
            Ok(None)
        );

        let schema = r#"{"type":"object","properties":{"error_map":{"type":"object"}}}"#;
        let mut one = Reply::new();
        one.put_text(tag::D_DIALECT, "anthropic").expect("fits");
        one.put_text(tag::D_PROVIDER_SCHEMA, schema).expect("fits");
        assert_eq!(
            decode_provider_schema(Records::new(one.as_bytes())),
            Ok(Some(schema))
        );

        let mut two = Reply::new();
        two.put_text(tag::D_PROVIDER_SCHEMA, schema).expect("fits");
        two.put_text(tag::D_PROVIDER_SCHEMA, schema).expect("fits");
        assert_eq!(
            decode_provider_schema(Records::new(two.as_bytes())),
            Err(RecErr::Size)
        );

        let mut bad = Reply::new();
        bad.put(tag::D_PROVIDER_SCHEMA, &[0xff, 0xfe])
            .expect("fits");
        assert_eq!(
            decode_provider_schema(Records::new(bad.as_bytes())),
            Err(RecErr::Utf8)
        );
        // A framing error anywhere in the describe answer is the decoder's error.
        let mut cut = one.as_bytes().to_vec();
        cut.truncate(cut.len() - 8);
        assert_eq!(
            decode_provider_schema(Records::new(&cut)),
            Err(RecErr::Truncated)
        );
    }

    /// One D_DIALECT_AUTH item: TEXT dialect, TEXT presentation, then `fields`.
    fn row(
        w: &mut Reply,
        dialect: &str,
        present: &str,
        fields: impl FnOnce(&mut Nested<'_>) -> Result<(), Full>,
    ) {
        w.put_nested(tag::D_DIALECT_AUTH, |n| {
            n.put_text(generic::TEXT, dialect)?;
            n.put_text(generic::TEXT, present)?;
            fields(n)
        })
        .expect("fits");
    }

    /// One DA_FAMILY: DaFamilyRec, then nested TEXT prefix and TEXT header.
    fn family(n: &mut Nested<'_>, trim_start: u32, prefix: &str, header: &str) -> Result<(), Full> {
        let mut tail = Reply::new();
        tail.put_text(generic::TEXT, prefix)?;
        tail.put_text(generic::TEXT, header)?;
        let head = plane::DaFamilyRec { trim_start, _r: 0 };
        n.put_pod_tail(tag::DA_FAMILY, &head, tail.as_bytes())
    }

    /// plane-llm's six rows as IF §12.18 states them.
    fn plane_llm() -> Reply {
        let mut w = Reply::new();
        for dialect in [
            "anthropic",
            "gemini",
            "openai",
            "responses",
            "cohere",
            "bedrock",
        ] {
            w.put_text(tag::D_DIALECT, dialect).expect("fits");
        }
        w.put_text(tag::D_PROVIDER_SCHEMA, "{}").expect("fits");
        row(&mut w, "anthropic", PRESENT_HEADER, |n| {
            n.put_text(tag::DA_KEY_HEADER, "x-api-key")?;
            n.put_text(tag::DA_OWN_HEADER, "x-api-key")?;
            family(n, 1, "sk-ant-api", "x-api-key")?;
            family(n, 0, "sk-ant-oat", "")
        });
        row(&mut w, "gemini", PRESENT_HEADER, |n| {
            n.put_text(tag::DA_KEY_HEADER, "x-goog-api-key")?;
            n.put_text(tag::DA_OWN_HEADER, "x-goog-api-key")?;
            n.put_text(tag::DA_PASSTHROUGH_HEADER, "x-goog-api-key")
        });
        for dialect in ["openai", "responses", "cohere"] {
            row(&mut w, dialect, PRESENT_HEADER, |_| Ok(()));
        }
        row(&mut w, "bedrock", PRESENT_SIGN, |n| {
            n.put_text(tag::DA_SIGN_SERVICE, "bedrock")?;
            for label in [
                "bedrock-runtime",
                "bedrock-runtime-fips",
                "bedrock",
                "bedrock-fips",
            ] {
                n.put_text(tag::DA_REGION_AFTER, label)?;
            }
            n.put_text(tag::DA_REGION_DEFAULT, "us-east-1")
        });
        w
    }

    fn bearer(dialect: &str) -> DialectAuth<'_> {
        DialectAuth {
            dialect,
            present: Presentation::Header {
                key_header: None,
                own_header: None,
                passthrough_header: None,
                families: Vec::new(),
            },
        }
    }

    #[test]
    fn plane_llm_dialect_auth_rows_decode_typed_in_describe_order() {
        let w = plane_llm();
        let rows = decode_dialect_auth(Records::new(w.as_bytes())).expect("valid rows");
        let want = vec![
            DialectAuth {
                dialect: "anthropic",
                present: Presentation::Header {
                    key_header: Some("x-api-key"),
                    own_header: Some("x-api-key"),
                    passthrough_header: None,
                    families: vec![("sk-ant-api", "x-api-key", true), ("sk-ant-oat", "", false)],
                },
            },
            DialectAuth {
                dialect: "gemini",
                present: Presentation::Header {
                    key_header: Some("x-goog-api-key"),
                    own_header: Some("x-goog-api-key"),
                    passthrough_header: Some("x-goog-api-key"),
                    families: Vec::new(),
                },
            },
            bearer("openai"),
            bearer("responses"),
            bearer("cohere"),
            DialectAuth {
                dialect: "bedrock",
                present: Presentation::Sign {
                    service: "bedrock",
                    region_after: vec![
                        "bedrock-runtime",
                        "bedrock-runtime-fips",
                        "bedrock",
                        "bedrock-fips",
                    ],
                    region_default: "us-east-1",
                },
            },
        ];
        assert_eq!(rows, want);
        // An image that states no row decodes to none.
        let mut empty = Reply::new();
        empty.put_text(tag::D_DIALECT, "openai").expect("fits");
        assert_eq!(
            decode_dialect_auth(Records::new(empty.as_bytes())),
            Ok(Vec::new())
        );
    }

    #[test]
    fn an_owned_row_is_the_same_row_boxed() {
        let w = plane_llm();
        let rows = decode_dialect_auth(Records::new(w.as_bytes())).expect("valid rows");
        let anthropic = rows[0].to_owned();
        assert_eq!(
            anthropic,
            DialectAuthOwned {
                dialect: "anthropic".into(),
                present: PresentationOwned::Header {
                    key_header: Some("x-api-key".into()),
                    own_header: Some("x-api-key".into()),
                    passthrough_header: None,
                    families: vec![
                        ("sk-ant-api".into(), "x-api-key".into(), true),
                        ("sk-ant-oat".into(), "".into(), false),
                    ],
                },
            }
        );
        let bedrock = rows[5].to_owned();
        assert_eq!(
            bedrock,
            DialectAuthOwned {
                dialect: "bedrock".into(),
                present: PresentationOwned::Sign {
                    service: "bedrock".into(),
                    region_after: vec![
                        "bedrock-runtime".into(),
                        "bedrock-runtime-fips".into(),
                        "bedrock".into(),
                        "bedrock-fips".into(),
                    ],
                    region_default: "us-east-1".into(),
                },
            }
        );
    }

    /// A describe answer declaring `openai` with one row built by `build`.
    fn one_row(build: impl FnOnce(&mut Reply)) -> Result<Vec<DialectAuthOwned>, RecErr> {
        let mut w = Reply::new();
        w.put_text(tag::D_DIALECT, "openai").expect("fits");
        build(&mut w);
        decode_dialect_auth(Records::new(w.as_bytes()))
            .map(|rows| rows.iter().map(DialectAuth::to_owned).collect())
    }

    #[test]
    fn a_row_for_an_undeclared_dialect_or_a_second_row_is_refused() {
        assert_eq!(
            one_row(|w| row(w, "anthropic", PRESENT_HEADER, |_| Ok(()))),
            Err(RecErr::Size)
        );
        assert_eq!(
            one_row(|w| {
                row(w, "openai", PRESENT_HEADER, |_| Ok(()));
                row(w, "openai", PRESENT_HEADER, |_| Ok(()));
            }),
            Err(RecErr::Size)
        );
    }

    #[test]
    fn an_unknown_presentation_word_or_a_missing_head_is_refused() {
        assert_eq!(
            one_row(|w| row(w, "openai", "bearer", |_| Ok(()))),
            Err(RecErr::Size)
        );
        // Only the dialect: no presentation.
        assert_eq!(
            one_row(|w| w
                .put_nested(tag::D_DIALECT_AUTH, |n| n.put_text(generic::TEXT, "openai"))
                .expect("fits")),
            Err(RecErr::Size)
        );
        // The head is two TEXT records, not a DA_* field.
        assert_eq!(
            one_row(|w| w
                .put_nested(tag::D_DIALECT_AUTH, |n| {
                    n.put_text(generic::TEXT, "openai")?;
                    n.put_text(tag::DA_KEY_HEADER, "x-api-key")
                })
                .expect("fits")),
            Err(RecErr::Unknown(tag::DA_KEY_HEADER))
        );
    }

    #[test]
    fn a_field_of_the_other_presentation_is_an_unknown_tag() {
        assert_eq!(
            one_row(|w| row(w, "openai", PRESENT_HEADER, |n| n
                .put_text(tag::DA_SIGN_SERVICE, "bedrock"))),
            Err(RecErr::Unknown(tag::DA_SIGN_SERVICE))
        );
        assert_eq!(
            one_row(|w| row(w, "openai", PRESENT_SIGN, |n| {
                n.put_text(tag::DA_SIGN_SERVICE, "bedrock")?;
                n.put_text(tag::DA_REGION_DEFAULT, "us-east-1")?;
                n.put_text(tag::DA_KEY_HEADER, "x-api-key")
            })),
            Err(RecErr::Unknown(tag::DA_KEY_HEADER))
        );
        // A DA_* field outside any D_DIALECT_AUTH.
        assert_eq!(
            one_row(|w| w.put_text(tag::DA_KEY_HEADER, "x-api-key").expect("fits")),
            Err(RecErr::Unknown(tag::DA_KEY_HEADER))
        );
    }

    #[test]
    fn a_sign_row_needs_its_service_and_default_region_once() {
        fn sign(service: &[&str], default: &[&str]) -> Result<Vec<DialectAuthOwned>, RecErr> {
            one_row(|w| {
                row(w, "openai", PRESENT_SIGN, |n| {
                    for s in service {
                        n.put_text(tag::DA_SIGN_SERVICE, s)?;
                    }
                    n.put_text(tag::DA_REGION_AFTER, "bedrock-runtime")?;
                    for d in default {
                        n.put_text(tag::DA_REGION_DEFAULT, d)?;
                    }
                    Ok(())
                })
            })
        }
        assert!(sign(&["bedrock"], &["us-east-1"]).is_ok());
        assert_eq!(sign(&[], &["us-east-1"]), Err(RecErr::Size));
        assert_eq!(sign(&["bedrock"], &[]), Err(RecErr::Size));
        assert_eq!(
            sign(&["bedrock", "bedrock"], &["us-east-1"]),
            Err(RecErr::Size)
        );
        assert_eq!(
            sign(&["bedrock"], &["us-east-1", "eu-west-1"]),
            Err(RecErr::Size)
        );
    }

    #[test]
    fn every_text_keeps_the_charset_and_length_and_header_names_are_lowercase() {
        fn header(name: &str) -> Result<Vec<DialectAuthOwned>, RecErr> {
            one_row(|w| {
                row(w, "openai", PRESENT_HEADER, |n| {
                    n.put_text(tag::DA_KEY_HEADER, name)
                })
            })
        }
        assert!(header("x-api-key").is_ok());
        assert!(header(&"h".repeat(128)).is_ok());
        assert_eq!(header(&"h".repeat(129)), Err(RecErr::Size));
        assert_eq!(header("X-Api-Key"), Err(RecErr::Size));
        assert_eq!(header("x api key"), Err(RecErr::Size));
        assert_eq!(header(""), Err(RecErr::Size));
        assert_eq!(
            one_row(|w| row(w, "openai", PRESENT_HEADER, |n| {
                n.put_text(tag::DA_KEY_HEADER, "x-api-key")?;
                n.put_text(tag::DA_KEY_HEADER, "x-api-key")
            })),
            Err(RecErr::Size)
        );
        // The signing texts are not header names: mixed case is in the charset.
        assert!(one_row(|w| row(w, "openai", PRESENT_SIGN, |n| {
            n.put_text(tag::DA_SIGN_SERVICE, "Bedrock")?;
            n.put_text(tag::DA_REGION_DEFAULT, "us-east-1")
        }))
        .is_ok());
        assert_eq!(
            one_row(|w| row(w, "openai", PRESENT_SIGN, |n| {
                n.put_text(tag::DA_SIGN_SERVICE, "bed/rock")?;
                n.put_text(tag::DA_REGION_DEFAULT, "us-east-1")
            })),
            Err(RecErr::Size)
        );
    }

    #[test]
    fn a_family_is_a_trim_flag_a_prefix_and_a_header_or_bearer() {
        fn fam(trim: u32, prefix: &str, header: &str) -> Result<Vec<DialectAuthOwned>, RecErr> {
            one_row(|w| {
                row(w, "openai", PRESENT_HEADER, |n| {
                    family(n, trim, prefix, header)
                })
            })
        }
        assert!(fam(1, "sk-", "x-api-key").is_ok());
        assert!(fam(0, "sk-", "").is_ok());
        assert_eq!(fam(2, "sk-", ""), Err(RecErr::Size));
        assert_eq!(fam(0, "", "x-api-key"), Err(RecErr::Size));
        assert_eq!(fam(0, "sk-", "X-Api-Key"), Err(RecErr::Size));
        // A third nested record in a family.
        assert_eq!(
            one_row(|w| row(w, "openai", PRESENT_HEADER, |n| {
                let mut tail = Reply::new();
                tail.put_text(generic::TEXT, "sk-")?;
                tail.put_text(generic::TEXT, "")?;
                tail.put_text(generic::TEXT, "extra")?;
                let head = plane::DaFamilyRec {
                    trim_start: 0,
                    _r: 0,
                };
                n.put_pod_tail(tag::DA_FAMILY, &head, tail.as_bytes())
            })),
            Err(RecErr::Unknown(generic::TEXT))
        );
        // A non-zero reserved word.
        assert_eq!(
            one_row(|w| row(w, "openai", PRESENT_HEADER, |n| {
                let mut tail = Reply::new();
                tail.put_text(generic::TEXT, "sk-")?;
                tail.put_text(generic::TEXT, "")?;
                let head = plane::DaFamilyRec {
                    trim_start: 0,
                    _r: 1,
                };
                n.put_pod_tail(tag::DA_FAMILY, &head, tail.as_bytes())
            })),
            Err(RecErr::Reserved)
        );
    }

    #[test]
    fn a_chan_attach_is_one_ch_attach_record_with_the_ready_tail() {
        let mut w = Reply::new();
        encode_chan_attach(&mut w, 7, 9, true, b"tail-bytes").expect("fits");
        let records = recs(w.as_bytes());
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].tag, tag::CH_ATTACH);
        let (head, tail) = records[0]
            .pod_tail::<plane::ChanAttach>()
            .expect("ChanAttach");
        assert_eq!((head.generation, head.slot, head.greet), (7, 9, 1));
        assert_eq!(head._r, 0);
        assert_eq!(tail, b"tail-bytes");

        let mut w = Reply::new();
        encode_chan_attach(&mut w, 1, 2, false, &[]).expect("fits");
        let records = recs(w.as_bytes());
        let (head, tail) = records[0]
            .pod_tail::<plane::ChanAttach>()
            .expect("ChanAttach");
        assert_eq!(head.greet, 0);
        assert!(tail.is_empty());
    }

    #[test]
    fn minted_signed_and_connect_answers_read_back() {
        let mut w = Reply::new();
        encode_minted(&mut w, &[(1, 0, 99, "ek_bbt1.x"), (2, 4, 99, "ignored")]).expect("fits");
        encode_signed(
            &mut w,
            &[
                SignedAnswer::Compact {
                    check: 3,
                    jws: "h.p.s",
                },
                SignedAnswer::Detached {
                    check: 4,
                    protected: "P",
                    signature: "S",
                },
                SignedAnswer::Refused {
                    check: 5,
                    status: refused::R_UNSUPPORTED,
                },
            ],
        )
        .expect("fits");
        encode_connect_answers(&mut w, &[(6, plane::CONN_PENDING, Some("https://x/y"))])
            .expect("fits");
        let records = recs(w.as_bytes());
        assert_eq!(records.len(), 6);
        let (ok, text) = records[0]
            .pod_tail::<plane::MintedRec>()
            .expect("MintedRec");
        assert_eq!(
            (ok.check, ok.status, ok.expires_at_s, text),
            (1, 0, 99, &b"ek_bbt1.x"[..])
        );
        let (no, text) = records[1]
            .pod_tail::<plane::MintedRec>()
            .expect("MintedRec");
        assert_eq!((no.status, no.expires_at_s, text.len()), (4, 0, 0));
        let (compact, tail) = records[2]
            .pod_tail::<plane::SignedRec>()
            .expect("SignedRec");
        assert_eq!((compact.status, tail), (0, &b"h.p.s"[..]));
        let (detached, tail) = records[3]
            .pod_tail::<plane::SignedRec>()
            .expect("SignedRec");
        assert_eq!(detached.status, 0);
        let nested = recs(tail);
        assert_eq!(
            (nested[0].tag, nested[0].text().expect("text")),
            (tag::SG_PROTECTED, "P")
        );
        assert_eq!(
            (nested[1].tag, nested[1].text().expect("text")),
            (tag::SG_SIGNATURE, "S")
        );
        let (refused_ans, tail) = records[4]
            .pod_tail::<plane::SignedRec>()
            .expect("SignedRec");
        assert_eq!(
            (refused_ans.status, tail.len()),
            (refused::R_UNSUPPORTED, 0)
        );
        let (conn, url) = records[5]
            .pod_tail::<plane::ConnectAns>()
            .expect("ConnectAns");
        assert_eq!(
            (conn.check, conn.state, url),
            (6, plane::CONN_PENDING, &b"https://x/y"[..])
        );
    }
}
