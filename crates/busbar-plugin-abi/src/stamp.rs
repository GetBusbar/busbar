// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The plugin stamp: struct, flags, `build_id_of`, `target_now` (IF §7.4). W0-ABI stub: frozen signatures, `todo!()` bodies; A4 fills it.

use crate::versions::EngineVersion;

#[repr(C)] // 272 bytes, align 8, little-endian (round 28: was 320)
pub struct Stamp {
    pub magic: [u8; 16],           //   0  b"BUSBAR\0PLUGSTAMP"
    pub format: u32, //  16  2 (round 28: the licence fields are gone; scan refuses format 1)
    pub size: u32,   //  20  272
    pub kind: u32,   //  24  KindCode
    pub kind_abi: u32, //  28  versions::<KIND>
    pub mechanism: u32, //  32  versions::MECHANISM (2)
    pub flags: u32,  //  36  STAMP_*
    pub layout: u64, //  40  <kind>::FP
    pub mechanism_layout: u64, //  48  CORE_FP
    pub semantic: u64, //  56  == layout (docs are hashed inside FP)
    pub mechanism_semantic: u64, //  64  == mechanism_layout
    pub engine_min: EngineVersion, //  72
    pub engine_max: EngineVersion, //  80
    pub name: [u8; 64], //  88  plugin identity (CARGO_PKG_NAME of the logic crate | name: arm | BUSBAR_PLUGIN_NAME)
    pub version: [u8; 32], // 152  CARGO_PKG_VERSION of the logic crate
    pub target: [u8; 32], // 184  <arch>-<os>-<env>
    pub build_id: [u8; 32], // 216  BUSBAR_BUILD_ID (64 hex) or zero with STAMP_LOCAL_BUILD
    pub crypto: [u8; 8], // 248  "host" (Rust plugins), "external" (C header), or a backend name (out_of_process only)
    pub _reserved: [u8; 16], // 256  0
}

// The typed view of busbar-ffi's `StampBytes` (what `Plugin::stamp` points at): same size and alignment.
const _: () = assert!(
    core::mem::size_of::<Stamp>() == busbar_ffi::header::STAMP_SIZE
        && core::mem::size_of::<Stamp>() == core::mem::size_of::<busbar_ffi::StampBytes>()
        && core::mem::align_of::<Stamp>() == core::mem::align_of::<busbar_ffi::StampBytes>()
);
pub const STAMP_MAGIC: [u8; 16] = *b"BUSBAR\0PLUGSTAMP";
pub const STAMP_LOCAL_BUILD: u32 = 1;
// Round 28: bits 2 and 4 are retired, never reused; a stamp setting
// either is StampMalformed (unknown flag). AGREED 289 stays a distribution rule (§16.183), not a stamp bit.
/// New (r4 §3.1): runs only in busbar-plugin-host, network denied (rung 3 / webrtc).
pub const STAMP_OUT_OF_PROCESS: u32 = 8;
pub const STAMP_FLAGS_KNOWN: u32 = 9;
pub const fn build_id_of(hex: Option<&str>) -> ([u8; 32], u32) {
    // const-panics on bad hex (r10)
    let _ = hex;
    todo!()
}
pub const fn target_now() -> [u8; 32] {
    // cfg!-derived canonical target
    todo!()
}
// `scan` (find exactly one stamp in image bytes and validate every field, r10 step 3) lives in the loader's
// `scan.rs` (L1), its only callers being admit and pack: `pub fn stamp(image: &[u8]) -> Result<Stamp, StampScanErr>`.
