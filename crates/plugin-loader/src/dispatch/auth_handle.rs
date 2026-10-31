// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE AUTH HANDLE'S REFS, HOST SIDE (BUSBAR-1.6.0.md Part 2 #74, the untrusted-ABI half, and #65;
//! THE DESIGN, Auth points and guest lists): minting and verifying the two kernel-MAC'd refs a
//! transport hands back on the auth handle's services, [`AuthRef`] and [`UnitRef`].
//!
//! THE PRIMITIVE IS THE INSTANCE HANDLE'S. Both refs are tagged with the same keyed SipHash-2-4,
//! under the same 128-bit key drawn from the OS random source at the loader's boot
//! ([`super::handle::arm`]), that tags every instance handle and permutes every ticket generation;
//! each under its own domain word, so a tag minted for one is never a tag for another. No new
//! crypto and no second key: the key never leaves host memory, and its one residual is the one #75
//! accepts (a native plugin that reads process memory).
//!
//! * An [`AuthRef`]'s `mac` covers (owner, configuration generation, `id`). It is OWNER-SCOPED:
//!   the owner is the calling instance's identity on the instance table, so a ref minted for one
//!   transport and presented by another does not verify; and a ref of an older generation does not
//!   verify against the current one.
//! * A [`UnitRef`]'s `mac` covers (the request's own kernel secret, generation, owner, line, unit):
//!   a unit replayed from another request (another secret), for another line or by another owner
//!   does not verify.
//!
//! Every comparison folds the whole difference before it is judged (constant time), and a refusal
//! names no reason a guesser could steer by beyond "not minted".
//!
//! THE GENERATION. The kernel publishes the configuration generation its guest lists and bindings
//! belong to ([`publish_generation`]); a ref is verified against the published one. Until the
//! kernel publishes one it is `0`.

use std::sync::atomic::{AtomicU64, Ordering};

use busbar_contract::abi::host::service::{AuthRef, UnitRef};

use super::handle::{key, siphash24};

/// Domain separation: an auth ref's tag is never an instance handle's, a ticket's or a unit's.
const DOMAIN_AUTH_REF: u64 = u64::from_le_bytes(*b"bb.aref1");
/// Domain separation: a unit ref's tag is never an auth ref's.
const DOMAIN_UNIT_REF: u64 = u64::from_le_bytes(*b"bb.unit1");

/// The configuration generation the kernel last published.
static GENERATION: AtomicU64 = AtomicU64::new(0);

/// Why a ref was refused. Each has one interned text ([`RefRefused::text`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RefRefused {
    /// The ref names nothing (`id == 0`).
    Absent,
    /// The `mac` is not the one the host mints for this owner, generation and id: a ref of another
    /// owner, of another generation, or forged.
    NotMinted,
    /// The host's key could not be drawn (the boot refuses first; this is the fail-closed arm).
    NoKey,
}

/// The text of [`RefRefused::Absent`].
pub const REF_ABSENT: &str = "the call names no handle";
/// The text of [`RefRefused::NotMinted`].
pub const REF_NOT_MINTED: &str =
    "the handle is not one the host minted for this caller at this generation";
/// The text of [`RefRefused::NoKey`].
pub const REF_NO_KEY: &str = "the host holds no key to verify the handle";

impl RefRefused {
    /// The interned refusal text, valid for the process's life.
    #[must_use]
    pub const fn text(self) -> &'static str {
        match self {
            Self::Absent => REF_ABSENT,
            Self::NotMinted => REF_NOT_MINTED,
            Self::NoKey => REF_NO_KEY,
        }
    }
}

/// Publish the configuration generation refs are verified against. The kernel's, at boot and at
/// each reload, once the generation's guest lists and bindings are built.
pub fn publish_generation(generation: u64) {
    GENERATION.store(generation, Ordering::Release);
}

/// The configuration generation refs are verified against now.
#[must_use]
pub fn generation() -> u64 {
    GENERATION.load(Ordering::Acquire)
}

/// The tag of an auth ref.
fn auth_tag(key: (u64, u64), owner: u64, generation: u64, id: u64) -> u64 {
    siphash24(key, &[DOMAIN_AUTH_REF, owner, generation, id])
}

/// The tag of a unit ref.
fn unit_tag(
    key: (u64, u64),
    secret: [u64; 2],
    generation: u64,
    owner: u64,
    line: u32,
    unit: u64,
) -> u64 {
    siphash24(
        key,
        &[
            DOMAIN_UNIT_REF,
            secret[0],
            secret[1],
            generation,
            owner,
            u64::from(line),
            unit,
        ],
    )
}

/// `want` against `got`, the whole difference folded before it is judged.
fn same(want: u64, got: u64) -> bool {
    std::hint::black_box(want ^ got) == 0
}

/// Mint the ref of line or binding `id` for `owner` (the instance identity of the transport that
/// will present it) at `generation`. `None` for `id == 0` or when the host's key cannot be drawn.
#[must_use]
pub fn mint_auth_ref(owner: u64, generation: u64, id: u64) -> Option<AuthRef> {
    if id == 0 {
        return None;
    }
    let key = key().ok()?;
    Some(AuthRef {
        id,
        mac: auth_tag(key, owner, generation, id),
    })
}

/// Verify a presented auth ref for `owner` (the calling instance) at `generation`; the line or
/// binding id it names.
///
/// # Errors
///
/// [`RefRefused::Absent`] for no ref; [`RefRefused::NotMinted`] for a ref of another owner, of
/// another generation, or with a forged `mac`; [`RefRefused::NoKey`] when the key cannot be drawn.
pub fn verify_auth_ref(owner: u64, generation: u64, r: &AuthRef) -> Result<u64, RefRefused> {
    if r.is_none() {
        return Err(RefRefused::Absent);
    }
    let key = key().map_err(|_| RefRefused::NoKey)?;
    if !same(auth_tag(key, owner, generation, r.id), r.mac) {
        return Err(RefRefused::NotMinted);
    }
    Ok(r.id)
}

/// Mint unit `unit`'s ref for one request: its kernel secret, the generation, the owner (the
/// transport's instance identity) and the line it matched. `None` for `unit == 0` or when the key
/// cannot be drawn.
#[must_use]
pub fn mint_unit_ref(
    secret: [u64; 2],
    generation: u64,
    owner: u64,
    line: u32,
    unit: u64,
) -> Option<UnitRef> {
    if unit == 0 {
        return None;
    }
    let key = key().ok()?;
    Some(UnitRef {
        id: unit,
        mac: unit_tag(key, secret, generation, owner, line, unit),
    })
}

/// Verify a presented unit ref against the request's own secret, the generation, the owner and the
/// line; the unit it names.
///
/// # Errors
///
/// [`RefRefused::Absent`] for no unit; [`RefRefused::NotMinted`] for a unit of another request,
/// generation, owner or line, or a forged `mac`; [`RefRefused::NoKey`] when the key cannot be
/// drawn.
pub fn verify_unit_ref(
    secret: [u64; 2],
    generation: u64,
    owner: u64,
    line: u32,
    r: &UnitRef,
) -> Result<u64, RefRefused> {
    if r.is_none() {
        return Err(RefRefused::Absent);
    }
    let key = key().map_err(|_| RefRefused::NoKey)?;
    if !same(unit_tag(key, secret, generation, owner, line, r.id), r.mac) {
        return Err(RefRefused::NotMinted);
    }
    Ok(r.id)
}

/// THE LINES WHOSE AUTH IS `none`, lent by the host to an accepting transport: `(owner, id)` of
/// each ref [`lend_none_line`] minted. `unit.hand_in` on such a line needs no verdict (the
/// contract, [`busbar_contract::abi::host::service::UnitHandInIn`] item (b)), so the host mints the
/// request's unit there and answers continue.
static NONE_LINES: std::sync::Mutex<Vec<(u64, u64)>> = std::sync::Mutex::new(Vec::new());

/// Units minted for requests on a `none` line, numbered from 1.
static NONE_UNITS: AtomicU64 = AtomicU64::new(0);

/// LEND A `none` LINE to `owner` (the instance identity of the accepting transport): its ref `id`
/// minted at the published generation, and the line recorded as one whose auth is `none`. `None`
/// for `id == 0` or when the host's key cannot be drawn.
#[must_use]
pub fn lend_none_line(owner: u64, id: u64) -> Option<AuthRef> {
    let r = mint_auth_ref(owner, generation(), id)?;
    let mut lines = NONE_LINES
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    if !lines.contains(&(owner, id)) {
        lines.push((owner, id));
    }
    Some(r)
}

/// Whether line ref `id` was lent to `owner` as a `none` line ([`lend_none_line`]).
#[must_use]
pub fn is_none_line(owner: u64, id: u64) -> bool {
    NONE_LINES
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .contains(&(owner, id))
}

/// THE UNIT OF A REQUEST HANDED IN ON A `none` LINE: a fresh unit id, tagged for `owner` and
/// `line` at the published generation under a secret of its own. `None` when the key cannot be
/// drawn.
#[must_use]
pub fn mint_none_unit(owner: u64, line: u32) -> Option<UnitRef> {
    let unit = NONE_UNITS.fetch_add(1, Ordering::Relaxed) + 1;
    let key = key().ok()?;
    let secret = [
        siphash24(key, &[DOMAIN_UNIT_REF, owner, unit, 1]),
        siphash24(key, &[DOMAIN_UNIT_REF, owner, unit, 2]),
    ];
    mint_unit_ref(secret, generation(), owner, line, unit)
}
