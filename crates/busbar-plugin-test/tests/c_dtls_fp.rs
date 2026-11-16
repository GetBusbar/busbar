// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! C-DTLS-FP (ABI-MIN3-INTERFACE §14): A datagram `begin` gets a non-empty `local_fingerprint`; a mismatching far
//! end gets PATH_REJECTED and no EV_KEYING.
//!
//! The core arm runs in busbar-core-connector over a scripted transport (the media session is crate-private
//! there, and that crate is not a dependency of this one), so it moved to the owner's crate (WBS rule 10):
//!
//! - TEST-VALUE `a_fingerprint_mismatch_is_path_rejected`:
//!   `busbar_core_connector::dtls::session::tests::a_fingerprint_mismatch_is_path_rejected_with_no_keying`
//!   (PATH_REJECTED, no EV_KEYING, one `dtls_fingerprint_mismatch` audit), with the begin half in
//!   `busbar_core_connector::dtls::session::tests::a_datagram_begin_gets_the_host_fingerprint_and_a_dial_gets_its_opening`
//!   (a non-empty `sha-256` local fingerprint on `begin`).
