// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE INBOUND FAMILY: `verify` and the `begin_login`/`complete_login` pair, plus the shapes the

use crate::abi::mechanism::call::{AbiStr, OutHead, Span};

/// The HOST buffer an identity is written into (request-path results live in host memory).
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct IdentityBuf {
    /// The bytes every [`Span`] of the answer points into.
    pub buf: *mut u8,
    /// Their capacity.
    pub buf_cap: usize,
    /// The group spans.
    pub groups: *mut Span,
    /// Their capacity.
    pub groups_cap: u32,
    /// Alignment padding.
    pub _reserved: u32,
}

/// An identity, as spans into the host's [`IdentityBuf`].
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct IdentityOut {
    /// The stable subject (required).
    pub subject: Span,
    /// The governance virtual-key id, if any.
    pub key_id: Span,
    /// The governance virtual-key display name, if any.
    pub key_name: Span,
    /// The end-user identifier, if any.
    pub user: Span,
    /// The asserting provider, if any.
    pub provider: Span,
    /// The display name, if any.
    pub name: Span,
    /// The claims blob. The kernel never reads it on the request path.
    pub claims: Span,
    /// The claims' [`Blob::fmt`](crate::abi::mechanism::call::Blob).
    pub claims_fmt: u32,
    /// [`super::IDENTITY_HAS_TTL`]; any other bit is FAULT.
    pub flags: u32,
    /// The suggested cache TTL, seconds (the plugin's cache clamps it; 3600 max, 300 default).
    pub ttl_secs: u64,
    /// How many group spans the plugin wrote into [`IdentityBuf::groups`].
    pub groups_len: u32,
    /// Alignment padding.
    pub _reserved: u32,
    /// A key the kernel must see only ONCE within [`Self::replay_ttl_secs`] (a signed webhook's
    /// message id). After a `verify` identity carrying one, the kernel claims
    /// `<plugin name>/<replay_key>` in its record store for that long, and a key already claimed
    /// refuses the request (replay). Absent or empty = no claim. The plane never sees it. Appended
    /// last (a pre-tag layout edit).
    pub replay_key: Span,
    /// How long the replay claim stands, seconds. A nonzero value requires a present, non-empty
    /// [`Self::replay_key`] (else the answer is a FAULT); zero means no claim.
    pub replay_ttl_secs: u64,
    /// The credential the identity was verified from, as the kernel holds it on the unit for the
    /// `caller-credential` style (THE DESIGN, "Auth points and guest lists", step 4). SECRET:
    /// it goes to the kernel only, never to the transport, never logged, zeroised at the unit's
    /// exit. Only with [`super::VERDICT_IDENTITY`]; absent = `len == 0`. Appended last (a pre-tag
    /// layout edit).
    pub credential: Span,
}

/// `verify`'s and `complete_login`'s `out`.
///
/// SHORT BUFFER: when the identity or the strip names do not fit, the plugin answers `FAILED`
/// with `needed_bytes`, `needed_groups` or `needed_strip` above the capacity it was given and
/// writes nothing else. The host re-issues
/// the op once, as a fresh call (no `FLAG_RESUME`) on the SAME ticket, with buffers at least that
/// large; a second short answer is FAULT. The plugin keeps the identity it reached for that ticket
/// and serves the retry from it, never repeating the work (an authorization code redeems once).
/// `FAILED` with both at `0` is a real failure. A buffer is at most `u32::MAX` bytes ([`Span`]).
///
/// THE ANSWER RULES, enforced by `super::check_identify` and `super::check_complete_login`
/// in `u64` math (any violation is FAULT). On REFUSED or PENDING, every `needed_*` is `0`. On
/// READY, every `needed_*` is `0`; the verdict is in the op's vocabulary; for `verify` the
/// decision is in its vocabulary, `strip_len <= strip_cap`, every strip name is present and in
/// bounds with a known `place`, and a `credential` span is present only with an identity; for
/// `complete_login` the decision, `strip_len` and `credential` are `0`/absent;
/// for an identity, `subject` is present and non-empty, a nonzero `replay_ttl_secs` comes with a
/// present, non-empty `replay_key`, every present [`Span`] has `off + len <= buf_cap`, an
/// absent one ([`super::SPAN_ABSENT`]) has `len == 0`, `groups_len <= groups_cap`, every group
/// span is present and in bounds, and `flags` holds only [`super::IDENTITY_HAS_TTL`]. On FAILED,
/// `needed_bytes <= u32::MAX`, `needed_groups <=` [`super::IDENTITY_GROUPS_HARD_MAX`] and
/// `needed_strip <=` [`super::FIELDS_HARD_MAX`]; all `0` is a real failure; otherwise each reports its FULL size and at least one exceeds its capacity
/// (a fitting dimension's full size is legal; none exceeding is FAULT, a wasted re-call).
///
/// The identity buffer is ALWAYS secret material to the host (claims may carry an identity token):
/// never logged, zeroised after use. No plugin flag says so.
///
/// THE REASON (no layout of its own: it rides `head.error`): on READY with
/// [`super::VERDICT_REJECT`] (`verify`) or a `complete_login` verdict that is not
/// [`super::LOGIN_IDENTITY`], `head.error` may name WHY: the check that failed, or the identity
/// provider's answer to an outage (its status). Operator text, never secret material. The host
/// writes it to the instance's own plugin log and the host log, and NEVER to the client, whose
/// answer is the same refusal whatever the reason. Absent = no reason given.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct IdentifyOut {
    /// The head.
    pub head: OutHead,
    /// `verify`: [`super::VERDICT_IDENTITY`] | [`super::VERDICT_REJECT`] | `super::VERDICT_PASS`.
    /// `complete_login`: [`super::LOGIN_IDENTITY`] | `super::LOGIN_BAD_CREDENTIAL` |
    /// [`super::LOGIN_OUTAGE`] | [`super::LOGIN_SECURITY_CHECK_FAILED`]. `0` is FAULT.
    pub verdict: u32,
    /// Short buffer: the group spans needed.
    pub needed_groups: u32,
    /// Short buffer: the bytes needed.
    pub needed_bytes: u64,
    /// Who, for an identity verdict.
    pub identity: IdentityOut,
    /// `verify` on READY: [`super::DECISION_CONTINUE`] | `super::DECISION_STOP`, what the
    /// transport does with the request. `complete_login`: `0`.
    pub decision: u32,
    /// `verify` on READY: how many `StripName`s the plugin wrote into [`VerifyIn::strip`],
    /// whatever the verdict. `complete_login`: `0`.
    pub strip_len: u32,
    /// Short buffer: the strip names needed.
    pub needed_strip: u32,
    /// Alignment padding.
    pub _reserved: u32,
}

/// One declared credential field of a login form.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct LoginField {
    /// The field name.
    pub name: AbiStr,
    /// Its label.
    pub label: AbiStr,
    /// `super::FORM_TEXT` | `super::FORM_PASSWORD`.
    pub kind: u32,
    /// `1` = required.
    pub required: u32,
}
