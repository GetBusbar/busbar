// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Opaque media payload value types. SHAPES: defined in `busbar_contract::media` (DECISIONS #83,
//! SD-2b of the #83a split), where the raw-bytes arm is re-expressed over the contract's own
//! `SlabBytes`; re-exported here under their historical paths.

pub use busbar_contract::media::{
    base64_decode, base64_encode, ImageOutput, MediaBlob, MediaPayload, PcmParams,
};
