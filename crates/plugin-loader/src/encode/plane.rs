// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Plane request encoders and describe decoders (IF §8.8). W0-ABI stub: frozen signatures, `todo!()` bodies;
//! A10 fills it.

use busbar_plugin_abi::records::{Full, RecErr, Records, Writer};
use busbar_plugin_abi::types::Pair;

use crate::ports::plane::{ObservedAnswer, TrustAnswer, WorkAnswer};

/// Round 13: the D_PROVIDER_SCHEMA text (at most one; a second is RecErr), or None.
pub fn decode_provider_schema<'o>(describe: Records<'o>) -> Result<Option<&'o str>, RecErr> {
    let _ = describe;
    todo!()
}

/// Round 15: every D_DIALECT_AUTH item as a typed presentation, in describe order. A dialect not among the
/// image's D_DIALECT items, a second row for one dialect, an unknown presentation word, a field that does
/// not belong to the presentation, a missing DA_SIGN_SERVICE/DA_REGION_DEFAULT under PRESENT_SIGN, or a
/// TEXT outside the charset/length of §8.6 is RecErr (the registry refuses DescribeInvalid). Borrowed; the
/// registry copies it once at `add` into `DialectAuthOwned` (cold).
pub fn decode_dialect_auth<'o>(describe: Records<'o>) -> Result<Vec<DialectAuth<'o>>, RecErr> {
    let _ = describe;
    todo!()
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
        let _ = self;
        todo!()
    }
}

/// The presentation words of D_DIALECT_AUTH (core vocabulary).
pub const PRESENT_HEADER: &str = "header";
pub const PRESENT_SIGN: &str = "request-signature";

/// `code` < 0x100 (generic only, §12.15; a larger code is a core bug: debug_assert, then R_DENIED).
pub fn encode_refusal(w: &mut impl Writer, status: u16, code: u32, text: &str) -> Result<(), Full> {
    let _ = (w, status, code, text);
    todo!()
}

/// FROM_UPSTREAM P_HEAD: H_STATUS, PAIR*, FACT(FACT_TLS_PIN)? and FACT(FACT_TLS_CLIENT_ID)?.
pub fn encode_upstream_head(
    w: &mut impl Writer,
    status: u16,
    headers: &[Pair<'_>],
    pin_ok: Option<bool>,
    client_id: Option<bool>,
) -> Result<(), Full> {
    let _ = (w, status, headers, pin_ok, client_id);
    todo!()
}

/// (check, outcome, failed, status) per COMMIT, in answer order.
pub fn encode_committed(w: &mut impl Writer, answers: &[(u32, u32, u32, u32)]) -> Result<(), Full> {
    let _ = (w, answers);
    todo!()
}

pub fn encode_trust_answers(w: &mut impl Writer, answers: &[TrustAnswer<'_>]) -> Result<(), Full> {
    let _ = (w, answers);
    todo!()
}

pub fn encode_chan_attach(
    w: &mut impl Writer,
    generation: u64,
    slot: u64,
    greet: bool,
    ready_tail: &[u8],
) -> Result<(), Full> {
    let _ = (w, generation, slot, greet, ready_tail);
    todo!()
}

pub fn encode_catalog(w: &mut impl Writer, models: &[&str]) -> Result<(), Full> {
    let _ = (w, models);
    todo!()
}

pub fn encode_lookup_hits(w: &mut impl Writer, hits: &[(u32, &[u8], &[u8])]) -> Result<(), Full> {
    let _ = (w, hits);
    todo!()
}

/// Round 12: one CHAIN_STATE after the LOOKUP_HITs of an LK_CHAIN lookup (§8.6).
pub fn encode_chain_state(
    w: &mut impl Writer,
    lookup: u32,
    len: u64,
    broken_at: u64,
) -> Result<(), Full> {
    let _ = (w, lookup, len, broken_at);
    todo!()
}

pub fn encode_entitle_answers(w: &mut impl Writer, answers: &[(u32, bool)]) -> Result<(), Full> {
    let _ = (w, answers);
    todo!()
}

/// Round 16, P_JUDGED: one JUDGE_ANS (check, verdict = DEST_*) per JUDGE, in intent order.
pub fn encode_judged(w: &mut impl Writer, answers: &[(u32, u32)]) -> Result<(), Full> {
    let _ = (w, answers);
    todo!()
}

/// P_OBSERVED: OBS_SCOPE_ANS (check, status, scope id) and OBS_RECEIPT (check, status, receipt), in intent order.
pub fn encode_observed(w: &mut impl Writer, answers: &[ObservedAnswer<'_>]) -> Result<(), Full> {
    let _ = (w, answers);
    todo!()
}

/// Round 10, P_WORK: one WORK_ANS per WORK, in intent order (WK_REF for OPEN/FIND, then WK_TARGET for FIND).
pub fn encode_work_answers(w: &mut impl Writer, answers: &[WorkAnswer<'_>]) -> Result<(), Full> {
    let _ = (w, answers);
    todo!()
}
