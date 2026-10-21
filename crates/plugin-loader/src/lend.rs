// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE HOST'S LENDING (status row 194): where the loader makes an [`AbiStr`] or a [`Blob`] over
//! runtime memory it lends a plugin for ONE call (settings, a public URL, a request's bytes). The
//! contract keeps their pointer and length private and makes such a value only through its
//! `unsafe` `from_raw_parts`; this module holds that `unsafe` for the loader.
//!
//! SOUNDNESS. The raw lenders ([`str`], [`blob`]) are `pub(crate)`: a value over memory the borrow
//! checker does not tie to it never leaves this crate, so no other crate (a plugin's tests
//! included) can make one. Each caller in the loader builds the call's `in` with it and makes the
//! crossing while still holding the bytes. A crate that may not write `unsafe` (busbar's root)
//! lends through the WHOLE CROSSINGS below instead ([`validate_json`], [`open_json`],
//! [`open_plane`]): each takes the borrowed bytes, builds the `in`, makes the call and returns only
//! the copied answer, so the lent value is born and dies inside the call that borrows its bytes.
//!
//! THE CALL-LENDING CONTRACT the raw lenders' callers keep: the bytes stay alive, unmoved and
//! unwritten until the call whose `in` carries the value returns (for a submitted op, until the op
//! completes: lend memory the op owns), and the value is never handed to data read after that.
//!
//! An empty `bytes` is present and empty (a non-NULL pointer, length `0`), never absent: a caller
//! that lends "none" for empty says so with [`AbiStr::ABSENT`] / [`Blob::ABSENT`].
//!
//! RED (status row 194): no crate but the loader makes a lent string, so none returns one past the
//! bytes it names.
//!
//! ```compile_fail,E0603
//! use busbar_contract::abi::mechanism::call::AbiStr;
//! fn escape() -> AbiStr {
//!     let bytes = String::from("{}");
//!     busbar_plugin_loader::lend::str(bytes.as_bytes())
//! }
//! ```
//!
//! GREEN, its twin: the whole crossing lends the same bytes to its one call and returns the answer.
//!
//! ```
//! use busbar_plugin_loader::dispatch::kinds::plane::Plane;
//! use busbar_plugin_loader::dispatch::{Called, Plugin};
//! fn validate(plugin: &Plugin<Plane>) -> Called {
//!     let bytes = String::from("{}");
//!     busbar_plugin_loader::lend::validate_json(plugin, bytes.as_bytes())
//! }
//! ```

use busbar_contract::abi::mechanism::call::{AbiStr, Blob, OutHead, BLOB_JSON};
use busbar_contract::abi::mechanism::lifecycle::{slot as life, OpenIn, OpenOut, ValidateIn};
use busbar_contract::abi::plane::{PlaneOpenIn, PlaneOpenOut};
use busbar_contract::abi::sdk::door::{blank_in, blank_out};
use busbar_contract::plane_calls::DialectFacts;

use crate::dispatch::kinds::plane::{provider_facts, OwnedSnapshot, Plane};
use crate::dispatch::{in_head, out_head, Called, Frame, Kind, Plugin};

/// `bytes` as a string the loader lends one call, under the call-lending contract (module docs).
#[must_use]
pub(crate) fn str(bytes: &[u8]) -> AbiStr {
    // SAFETY: the call-lending contract: the caller keeps `bytes` alive, unmoved and unwritten
    // for every read of the value, until the call it lends the `in` to returns.
    unsafe { AbiStr::from_raw_parts(bytes.as_ptr(), bytes.len()) }
}

/// `bytes` as a payload of `fmt` (`BLOB_JSON`, `BLOB_OCTETS` ...) the loader lends one call, under
/// the call-lending contract (module docs); flag it with [`Blob::with_flags`].
#[must_use]
pub(crate) fn blob(bytes: &[u8], fmt: u32) -> Blob {
    // SAFETY: as `str`: the call-lending contract.
    unsafe { Blob::from_raw_parts(bytes.as_ptr(), bytes.len(), fmt, 0) }
}

/// The lifecycle `validate` of `plugin` over `settings` (JSON), lent to that one call; the reason a
/// plugin writes lands in a reason buffer the call lends too, and comes back in the answer.
#[must_use]
pub fn validate_json<K: Kind>(plugin: &Plugin<K>, settings: &[u8]) -> Called {
    let mut err = [0_u8; 1024];
    let mut i: ValidateIn = blank_in();
    // `settings` and `err` outlive the call below, the only one this `in` is lent to.
    i.settings = blob(settings, BLOB_JSON);
    i.err_buf = err.as_mut_ptr();
    i.err_cap = err.len();
    let mut f = Frame::new(i, blank_out::<OutHead>());
    plugin.call(life::VALIDATE, &mut f)
}

/// The lifecycle `open` of `plugin` over `settings` (JSON; `None` = absent), lent to that one call.
#[must_use]
pub fn open_json<K: Kind>(plugin: &Plugin<K>, settings: Option<&[u8]>) -> Called {
    let mut i: OpenIn = blank_in();
    // `settings` outlives the call below, the only one this `in` is lent to.
    i.settings = settings.map_or(Blob::ABSENT, |s| blob(s, BLOB_JSON));
    let mut f = Frame::new(i, blank_out::<OpenOut>());
    plugin.call(life::OPEN, &mut f)
}

/// A plane's `open`, generation 1: its `settings` (JSON), the deployment's `public_url` (empty =
/// none stated, absent), its `owned` sections (JSON; empty = absent) and the provider facts of
/// `dialects`, all lent to that one call; the answer and the snapshot it published, copied
/// ([`Plugin::open`]).
#[must_use]
pub fn open_plane(
    plugin: &Plugin<Plane>,
    settings: &[u8],
    public_url: &str,
    owned: &[u8],
    dialects: &[DialectFacts],
) -> (Called, Option<OwnedSnapshot>) {
    // Each points into `dialects`, which outlives the call.
    let providers = provider_facts(dialects);
    // `settings`, `public_url`, `owned` and `providers` outlive the call below, the only one this
    // `in` is lent to.
    let mut frame = Frame::new(
        PlaneOpenIn {
            open: OpenIn {
                head: in_head(),
                host: std::ptr::null(),
                settings: blob(settings, BLOB_JSON),
                secrets: std::ptr::null(),
                secrets_len: 0,
                generation: 1,
                err_buf: std::ptr::null_mut(),
                err_cap: 0,
            },
            // The deployment's public base URL, which a plane states its audience and its claims
            // against (a plane with none fronts nothing).
            public_url: if public_url.is_empty() {
                AbiStr::ABSENT
            } else {
                str(public_url.as_bytes())
            },
            owned: if owned.is_empty() {
                Blob::ABSENT
            } else {
                blob(owned, BLOB_JSON)
            },
            providers: if providers.is_empty() {
                std::ptr::null()
            } else {
                providers.as_ptr()
            },
            providers_len: providers.len(),
        },
        PlaneOpenOut {
            open: OpenOut {
                head: out_head(),
                instance: std::ptr::null_mut(),
                err_len: 0,
            },
            snapshot: std::ptr::null(),
        },
    );
    plugin.open(&mut frame)
}
