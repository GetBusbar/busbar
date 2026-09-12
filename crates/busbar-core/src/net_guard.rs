// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Re-export shim. THE NETWORK-ADDRESS JUDGEMENT is the trust unit's — the shipped, stricter copy
//! (the six-name cloud-metadata list, the bare `host:port` fallback) — and every in-core call site
//! keeps naming `crate::net_guard::…` unchanged through this glob.
//!
//! It used to glob the substrate's second copy of the same control, kept honest by an anti-drift
//! parity test. Two copies of a security control is one copy plus a thing that can disagree with
//! it, so the second one is gone and the unit's is what remains. The refusal type is
//! [`AddressRefusal`]; `GuardRefusal` — the name the dead copy used — died with it, and no wire
//! text changes, because the two `Display` impls were byte-identical.
//!
//! WHAT IS NOT HERE: the async resolve-then-pin door. It holds a socket, and a unit holds none, so
//! it lives on the egress seam that owns the socket ([`crate::plane_host::egress`]).

pub use busbar_unit_trust::net::*;
