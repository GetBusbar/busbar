// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE CORE TEST KIT: what a plugin repo and busbar's own tests run against, at a released core
//! tag. A dev-dependency only: no busbar build links it.
//!
//! * [`conformance`]: the published conformance suite (`conformance_suite!`), linked and dropped
//!   in, through the one loader;
//! * [`tcp_conns`], [`https_conns`]: connection-table doubles with in-process far ends, for a build
//!   that cannot link the process's connector ([`stand_in`]: the facts they stand in for);
//! * [`test_issuer`]: a local token issuer (an ES256 key, its JWKS, signed tokens);
//! * [`root_door_fixtures`]: the composition root's door fixtures.
#![deny(unsafe_code)]

// The loader items the suite drives, at the paths it names them by.
use busbar_plugin_loader::{auth_door, dispatch, plugin_library_filename, sign, store_v3};

pub mod auth_axis;
#[allow(unsafe_code)] // REVIEWED: the published suite drives raw doors and plants faults
pub mod conformance;
pub mod https_conns;
/// The composition root's door fixtures: doors built by the contract's door macro, whose expansion
/// writes `unsafe`, kept here so the `forbid(unsafe_code)` root holds no such expansion.
#[allow(unsafe_code)] // TEST ONLY: plugin_door! fixtures the composition root's tests drive
pub mod root_door_fixtures;
pub mod stand_in;
pub mod tcp_conns;
pub mod test_issuer;
