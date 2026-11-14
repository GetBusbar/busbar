// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE AUTH `serve` SLOT'S SHAPES (auth v4): the provisioning mount, `/provision/<instance>/*`.

use crate::abi::mechanism::call::{AbiStr, Blob, InHead};

/// `serve`'s `out`: the hook kind's, byte for byte (status, response headers and body under
/// `head.lease` until `release(lease)`, memory class iv).
pub use crate::abi::hook::ServeOut;

/// `serve`'s `in`: one HTTP request to this instance's provisioning mount. The hook kind's
/// `ServeIn` field for field, then [`ServeIn::client`]. Before this call the kernel has capped the
/// body, run this instance's own `verify` over the request head, required IDENTITY, and found the
/// principal in `provisioning.clients`; `Authorization` and the instance's carrier fields never
/// reach `serve`, so no raw credential crosses this slot.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct ServeIn {
    /// The head.
    pub head: InHead,
    /// The HTTP method.
    pub method: AbiStr,
    /// The path AFTER `/provision/<instance>`: `/` when nothing follows.
    pub path: AbiStr,
    /// The raw query string; absent = none.
    pub query: AbiStr,
    /// Header name/value pairs, interleaved (`name`, `value`, …); never `Authorization`.
    pub headers: *const AbiStr,
    /// How many `AbiStr` entries `headers` holds (twice the header count).
    pub headers_len: usize,
    /// The request body; absent = none.
    pub body: Blob,
    /// APPENDED to the hook shape: the client principal the kernel authenticated (this instance's
    /// own `verify` IDENTITY) and found in `provisioning.clients`. Never empty on a real call.
    pub client: AbiStr,
}
