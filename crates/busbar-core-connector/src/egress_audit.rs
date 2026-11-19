// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! EVERY OUTBOUND REFUSAL AND TLS FAILURE, EXPLAINED AND AUDITED.
//!
//! A refused dial (the destination guard, the plaintext rule, the trust store) is one coded
//! BUSBAR-5051 line and one `egress.dial_refused` audit record; a TLS verification failure is one
//! BUSBAR-5047 line and one `egress.tls_verification_failed` audit record carrying the dialled host,
//! the `advanced.tls.destinations` entries that matched and the fingerprints of the operator
//! anchors in force. Lines are rate-limited per (host, reason) so a retry storm writes one line a
//! minute; audit records are written for every refusal the limiter lets through, never with
//! certificate bodies or credentials. The lines, records and limiter are cold
//! (`crate::cold::egress`): they run only when a dial is refused or fails.

use std::sync::{Arc, OnceLock};

use arc_swap::ArcSwapOption;

use crate::tls::store::TrustStore;

static STORE: OnceLock<ArcSwapOption<TrustStore>> = OnceLock::new();

/// The process's trust store for the failure records.
pub(crate) fn store() -> &'static ArcSwapOption<TrustStore> {
    STORE.get_or_init(ArcSwapOption::empty)
}

/// Install the process's trust store for the failure records (the connector selects with its own).
pub fn install_store(s: Arc<TrustStore>) {
    store().store(Some(s));
}

/// The host of a dial target, without userinfo, port or brackets: what a record may name (at most
/// 256 characters of it).
pub(crate) fn shown(target: &str) -> &str {
    let t = target.split_once("://").map_or(target, |(_, r)| r);
    let t = t.rsplit_once('@').map_or(t, |(_, h)| h);
    let t = t.split(['/', '?', '#']).next().unwrap_or(t);
    t.char_indices().nth(256).map_or(t, |(at, _)| &t[..at])
}

/// The verdict name a `dest.judge` verdict number reads as.
#[must_use]
pub fn verdict_name(v: u64) -> &'static str {
    use busbar_contract::services::codes::{
        DEST_INTERNAL, DEST_METADATA, DEST_NO_ADDRESSES, DEST_NO_HOST, DEST_OBFUSCATED,
        DEST_PLAINTEXT, DEST_SCHEME, DEST_UNRESOLVABLE,
    };
    match v {
        DEST_SCHEME => "scheme",
        DEST_NO_HOST => "no-host",
        DEST_METADATA => "metadata",
        DEST_OBFUSCATED => "obfuscated",
        DEST_INTERNAL => "internal",
        DEST_PLAINTEXT => "plaintext",
        DEST_UNRESOLVABLE => "unresolvable",
        DEST_NO_ADDRESSES => "no-addresses",
        _ => "refused",
    }
}

/// A REFUSED DIAL: one BUSBAR-5051 line and one audit record, rate-limited per host and reason.
/// `class` is the need's egress class when known; `owner` names the instance and need. `now` is
/// the op's clock memo: the limiter reads the clock through it, once per op at most.
pub fn dial_refused(
    target: &str,
    class: Option<u32>,
    why: &str,
    owner: Option<(u64, u32)>,
    now: &mut Option<std::time::Instant>,
) {
    crate::cold::egress::dial_refused(shown(target), class, why, owner, now);
}

/// A TLS VERIFICATION FAILURE on a dial of `target`: one BUSBAR-5047 line and one audit record
/// naming the matched `advanced.tls.destinations` entries and the operator anchors in force. `now`
/// is the op's clock memo, as for [`dial_refused`].
pub fn tls_failed(target: &str, why: &str, now: &mut Option<std::time::Instant>) {
    crate::cold::egress::tls_failed(shown(target), why, now);
}

/// Whether a TLS error is a verification failure (certificate or pin), not a transport error.
#[must_use]
pub fn is_verification(e: &rustls::Error) -> bool {
    matches!(
        e,
        rustls::Error::InvalidCertificate(_)
            | rustls::Error::NoCertificatesPresented
            | rustls::Error::General(_)
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cold::egress::due;

    #[test]
    fn a_refusal_names_the_host_never_its_userinfo_and_is_rate_limited() {
        assert_eq!(
            shown("https://user:pw\x40db.internal:5432/x"),
            "db.internal:5432"
        );
        assert!(due("rate.test", "internal", &mut None));
        assert!(
            !due("rate.test", "internal", &mut None),
            "a second line within a minute is held"
        );
        assert!(
            due("rate.test", "plaintext", &mut None),
            "another reason is its own line"
        );
    }

    /// The limiter judges by the op's one reading: refusals of one op share its memo and read the
    /// clock once between them; an op that already read the clock reads it not again.
    #[test]
    fn refusals_of_one_op_read_the_clock_once() {
        use crate::compose::clock_reads;
        let _ = clock_reads::take();
        let mut now = None;
        dial_refused("once.test", None, "internal", None, &mut now);
        dial_refused("once.test", None, "plaintext", None, &mut now);
        tls_failed("once.test", "pin", &mut now);
        assert_eq!(
            clock_reads::take().reads,
            1,
            "one reading for the op's three refusals"
        );
        let mut read = Some(crate::framer::now());
        dial_refused("twice.test", None, "internal", None, &mut read);
        assert_eq!(
            clock_reads::take().reads,
            0,
            "the op's earlier reading is used"
        );
    }
}
