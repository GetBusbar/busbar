// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE TRANSPORT-LAYER IDENTITY: a peer certificate's SubjectPublicKeyInfo, hashed.
//!
//! An A2A card's signature is OPTIONAL. Where a vendor does not sign, the only authenticity root left
//! is the one the network already established: the certificate the card endpoint proved it held the
//! private key for. Pinning the SPKI rather than the whole certificate is the standard choice and it is
//! the right one here — a certificate is re-issued on every renewal and its bytes change each time,
//! while the key underneath it survives a renewal.
//!
//! ## ONE WALK, LIFTED TO THE NEUTRAL HOST
//!
//! The DER walk this file used to own now lives in [`crate::plane_host::spki`]: when the HOST owns an
//! outbound hop (the egress seam) it must hand the plane the SAME pin string the plane would have
//! computed here, byte for byte, and a second copy of the walk would be a second answer to "what is
//! this key's pin". So the walk lives in ONE neutral place and this module re-exports it — the a2a
//! spelling ([`spki_pin`]) and the host spelling ([`crate::plane_host::spki::pin`]) are the SAME
//! function, which is what makes a host-computed pin and a plane-computed pin identical.
//!
//! The DER handed to [`spki_pin`] is the leaf certificate of a handshake that ALREADY COMPLETED under
//! the ordinary chain-and-name check ([`super::transport`]). This is therefore an OBSERVATION of a
//! connection somebody else already verified, never a substitute for verifying one.

// The walk, the error taxonomy and the pin rendering all live in the neutral host module now; a2a
// re-exports them under their historical names so this plane's tests keep one spelling. Since the
// transport's hop moved onto the egress seam, the HOST computes the observed pin (from the same
// [`crate::plane_host::spki::pin`] this name aliases), so no non-test code reaches `spki_pin` any
// more — the walk, its error taxonomy and the pin rendering are all exercised only by the tests.
#[cfg(test)]
pub(crate) use crate::plane_host::spki::pin as spki_pin;
#[cfg(test)]
pub(crate) use crate::plane_host::spki::{subject_public_key_info, SpkiError};

#[cfg(test)]
#[path = "tests/spki_tests.rs"]
mod spki_tests;
