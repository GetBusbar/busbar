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

#[cfg(test)]
mod tests {
    use super::*;

    fn spec<'a>(name: &'a str, out_of_process: bool, crypto: &'a str) -> Spec<'a> {
        Spec {
            kind: KindCode::Secret,
            kind_abi: 2,
            layout: 0x0123_4567_89ab_cdef,
            out_of_process,
            engine_min: Some("1.6.2"),
            engine_max: None,
            name,
            version: "1.6.0-rc.1+abc",
            build_id: None,
            crypto,
        }
    }

    /// IF §7.4: every field at its frozen offset, little-endian, and the typed view reads them back.
    #[test]
    fn the_stamp_is_272_bytes_with_every_field_at_its_offset() {
        let bytes = emit(&spec("busbar-secret-env", false, "host")).0;
        assert_eq!(bytes.len(), 272);
        let u32_at = |at: usize| u32::from_le_bytes(bytes[at..at + 4].try_into().expect("4"));
        let u64_at = |at: usize| u64::from_le_bytes(bytes[at..at + 8].try_into().expect("8"));
        assert_eq!(&bytes[..16], b"BUSBAR\0PLUGSTAMP");
        assert_eq!(u32_at(16), 2, "format 2 (round 28)");
        assert_eq!(u32_at(20), 272);
        assert_eq!(u32_at(24), KindCode::Secret as u32);
        assert_eq!(u32_at(28), 2);
        assert_eq!(u32_at(32), MECHANISM);
        assert_eq!(
            u32_at(36),
            STAMP_LOCAL_BUILD,
            "no BUSBAR_BUILD_ID: LOCAL_BUILD"
        );
        assert_eq!(u64_at(40), 0x0123_4567_89ab_cdef);
        assert_eq!(u64_at(48), crate::fp::CORE_FP);
        assert_eq!(u64_at(56), u64_at(40), "semantic == layout");
        assert_eq!(
            u64_at(64),
            u64_at(48),
            "mechanism_semantic == mechanism_layout"
        );
        assert_eq!(&bytes[88..88 + 17], b"busbar-secret-env");
        assert!(bytes[88 + 17..152].iter().all(|&b| b == 0), "NUL-padded");
        assert_eq!(&bytes[152..152 + 14], b"1.6.0-rc.1+abc");
        assert_eq!(&bytes[184..216], &target_now());
        assert!(bytes[216..248].iter().all(|&b| b == 0), "zero build id");
        assert_eq!(&bytes[248..252], b"host");
        assert!(bytes[256..].iter().all(|&b| b == 0), "reserved");

        let stamp = Stamp::read_from_bytes(&bytes[..]).expect("272 bytes");
        assert_eq!(stamp.magic, STAMP_MAGIC);
        assert_eq!(stamp.kind, KindCode::Secret as u32);
        assert_eq!(stamp.engine_min.major, ENGINE.major);
        assert_eq!(stamp.engine_min.minor, ENGINE.minor);
        assert_eq!(stamp.engine_min.patch, 2);
        assert_eq!(
            stamp.engine_max.patch,
            u16::MAX,
            "the line's end by default"
        );
        assert_eq!(stamp.flags & !STAMP_FLAGS_KNOWN, 0);
    }

    /// Round 28: only bits 1 and 8 exist; out_of_process sets 8 and names its backend.
    #[test]
    fn out_of_process_sets_its_flag_and_crypto_name() {
        let stamp = Stamp::read_from_bytes(&emit(&spec("rtc", true, "ring")).0[..]).expect("stamp");
        assert_eq!(stamp.flags, STAMP_LOCAL_BUILD | STAMP_OUT_OF_PROCESS);
        assert_eq!(&stamp.crypto[..5], b"ring\0");
        assert_eq!(STAMP_FLAGS_KNOWN, STAMP_LOCAL_BUILD | STAMP_OUT_OF_PROCESS);
    }

    #[test]
    fn a_build_id_is_64_lowercase_hex() {
        let hex = "00ff".repeat(16);
        let (id, flags) = build_id_of(Some(&hex));
        assert_eq!(flags, 0, "a build id clears LOCAL_BUILD");
        assert_eq!(id[..2], [0x00, 0xff]);
        assert_eq!(build_id_of(None), ([0; 32], STAMP_LOCAL_BUILD));
        assert!(std::panic::catch_unwind(|| build_id_of(Some("00FF"))).is_err());
        assert!(std::panic::catch_unwind(|| build_id_of(Some(&"0F".repeat(32)))).is_err());
    }

    #[test]
    fn the_target_is_arch_os_env() {
        let target = target_now();
        let text =
            core::str::from_utf8(&target[..target.iter().position(|&b| b == 0).unwrap_or(32)])
                .expect("ascii");
        assert_eq!(text.split('-').count(), 3, "{text}");
        assert!(
            text.bytes()
                .all(|b| matches!(b, b'a'..=b'z' | b'0'..=b'9' | b'_' | b'-'))
        );
        assert!(text.starts_with(std::env::consts::ARCH), "{text}");
    }

    #[test]
    fn names_versions_and_crypto_words_follow_r10() {
        assert!(valid_name("busbar-store-sqlite"));
        assert!(!valid_name("-lead") && !valid_name("trail-") && !valid_name("Upper"));
        assert!(!valid_name("") && !valid_name(&"a".repeat(65)));
        assert!(
            valid_version("1.6.0") && valid_version("1.6.0-rc.1") && valid_version("10.0.3+b.7")
        );
        assert!(
            !valid_version("1.6") && !valid_version("1.6.0 ") && !valid_version("1.6.0-\x1b[2J")
        );
        assert!(valid_crypto("host") && valid_crypto("aws-lc"));
        assert!(!valid_crypto("external") && !valid_crypto("") && !valid_crypto("nine-char"));
        assert_eq!(pick_name(Some("arm"), Some("env"), "pkg"), "arm");
        assert_eq!(pick_name(None, Some("env"), "pkg"), "env");
        assert_eq!(pick_name(None, None, "pkg"), "pkg");
        assert_eq!(former_names(None).get(), "");
        assert_eq!(
            former_names(Some("sqlite,busbar-store-sqlite-plugin")).get(),
            "sqlite,busbar-store-sqlite-plugin"
        );
        assert!(std::panic::catch_unwind(|| former_names(Some("ok,,bad"))).is_err());
    }

    #[test]
    fn an_engine_bound_stays_on_the_line() {
        let line = format!("{}.{}.7", ENGINE.major, ENGINE.minor);
        assert_eq!(engine(Some(&line), 0).patch, 7);
        let other = format!("{}.{}.0", ENGINE.major, ENGINE.minor + 1);
        assert!(std::panic::catch_unwind(|| engine(Some(&other), 0)).is_err());
        assert!(std::panic::catch_unwind(|| engine(Some("1.6"), 0)).is_err());
    }
}
