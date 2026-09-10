// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! What a bucket is CALLED — the row identity an enforced key charges through.
//!
//! ## Why the ledger owns the name and not the door
//!
//! A bucket id is not a display string. It is the primary key of a durable row: two nodes that
//! spell one group's monthly bucket differently do not disagree cosmetically, they keep two separate
//! balances for one budget and each admits up to the full cap. So the spelling belongs where the
//! rows do, and every producer reaches it here rather than composing a format string of its own.
//! That is the whole of this module's claim — it invents nothing, it is where the invention stops
//! being repeated.
//!
//! ## The key's side of it
//!
//! An enforced key carries no money. Under owner ruling 13:0x (6) it does not even carry the NAME
//! of its pot: the auth unit's resolved key holds identity, scope, expiry and revocation, and the
//! charging pot is the composition root's to resolve from configuration. What the root resolves it
//! to is this: an attribution row named by the key's own id, and then one row per window of the
//! group the key is bound to, and its ancestors'.
//!
//! ## The two shapes, and why the scope suffix is not optional decoration
//!
//! A plain group bucket, `group:<name>@<window>`, accounts every request the group made. A
//! SCOPE-QUALIFIED bucket, `group:<name>@<window>#<kind>:<value>`, is its own row accounting only
//! the traffic dispatched through that scope — a limit written with a `pool:` narrows to one, and
//! folding it back into the plain row would let one pool's spend exhaust another's allowance.
//!
//! ## A group name may contain `@` and `#`
//!
//! Nothing rejects it, and an IdP subject is normally an email, so `group:user:alice@corp.com@total`
//! is the ORDINARY case and not a pathological one. Any reader that ever wants a bucket id back has
//! to match the group name VERBATIM and require a recognised window word after it; splitting on `@`
//! gets the wrong answer for the most common deployment there is. There is no such reader today,
//! which is why there is no such function here.

use crate::totals::BucketId;

/// The prefix every configured group's window bucket is named under.
///
/// The shipped release's literal, unchanged, because these are the same rows: a node that resolved
/// its groups through one projection and a node that resolved them through another must charge the
/// same cell for the same group, or one release's usage reads as another release's silence.
const GROUP_BUCKET_PREFIX: &str = "group:";

/// The row a group charges through in one window.
#[must_use]
pub fn group_bucket(group: &str, window: &str) -> BucketId {
    BucketId::new(format!("{GROUP_BUCKET_PREFIX}{group}@{window}"))
}

/// The row a group charges through in one window, narrowed to one scope.
#[must_use]
pub fn group_bucket_scoped(group: &str, window: &str, kind: &str, value: &str) -> BucketId {
    BucketId::new(format!(
        "{GROUP_BUCKET_PREFIX}{group}@{window}#{kind}:{value}"
    ))
}
