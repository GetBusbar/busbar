// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The plugin stamp: struct, flags, `build_id_of`, `target_now` (IF §7.4), and the const builder `plugin!`
//! writes it with. Every field rule of r10 §2.3.1 step 3 that the builder can know is checked while the
//! static is evaluated, so a bad name, version, crypto word, build id or engine range is a compile error,
//! never a stamp the loader refuses at run time.

use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout};

use crate::types::{KindCode, Str};
use crate::versions::{ENGINE, EngineVersion, MECHANISM};

#[repr(C)] // 272 bytes, align 8, little-endian (round 28: was 320)
#[derive(Clone, Copy, FromBytes, IntoBytes, Immutable, KnownLayout)]
pub struct Stamp {
    pub magic: [u8; 16],           //   0  b"BUSBAR\0PLUGSTAMP"
    pub format: u32,               //  16  2 (scan refuses format 1)
    pub size: u32,                 //  20  272
    pub kind: u32,                 //  24  KindCode
    pub kind_abi: u32,             //  28  versions::<KIND>
    pub mechanism: u32,            //  32  versions::MECHANISM (2)
    pub flags: u32,                //  36  STAMP_*
    pub layout: u64,               //  40  <kind>::FP
    pub mechanism_layout: u64,     //  48  CORE_FP
    pub semantic: u64,             //  56  == layout (docs are hashed inside FP)
    pub mechanism_semantic: u64,   //  64  == mechanism_layout
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
const fn build_id_of(hex: Option<&str>) -> ([u8; 32], u32) {
    // const-panics on bad hex (r10)
    let Some(hex) = hex else {
        return ([0; 32], STAMP_LOCAL_BUILD);
    };
    let digits = hex.as_bytes();
    assert!(
        digits.len() == 64,
        "BUSBAR_BUILD_ID is not 64 lowercase hex characters"
    );
    let mut id = [0u8; 32];
    let mut i = 0;
    while i < 32 {
        id[i] = (nibble(digits[2 * i]) << 4) | nibble(digits[2 * i + 1]);
        i += 1;
    }
    (id, 0)
}
pub const fn target_now() -> [u8; 32] {
    // cfg!-derived canonical target
    let arch = if cfg!(target_arch = "x86_64") {
        "x86_64"
    } else if cfg!(target_arch = "aarch64") {
        "aarch64"
    } else if cfg!(target_arch = "x86") {
        "x86"
    } else if cfg!(target_arch = "arm") {
        "arm"
    } else if cfg!(target_arch = "riscv64") {
        "riscv64"
    } else if cfg!(target_arch = "powerpc64") {
        "powerpc64"
    } else if cfg!(target_arch = "s390x") {
        "s390x"
    } else if cfg!(target_arch = "loongarch64") {
        "loongarch64"
    } else {
        panic!("target_now: an architecture with no canonical stamp spelling")
    };
    let os = if cfg!(target_os = "linux") {
        "linux"
    } else if cfg!(target_os = "macos") {
        "macos"
    } else if cfg!(target_os = "windows") {
        "windows"
    } else if cfg!(target_os = "freebsd") {
        "freebsd"
    } else if cfg!(target_os = "netbsd") {
        "netbsd"
    } else if cfg!(target_os = "openbsd") {
        "openbsd"
    } else if cfg!(target_os = "illumos") {
        "illumos"
    } else if cfg!(target_os = "android") {
        "android"
    } else if cfg!(target_os = "ios") {
        "ios"
    } else {
        panic!("target_now: an operating system with no canonical stamp spelling")
    };
    let env = if cfg!(target_env = "gnu") {
        "gnu"
    } else if cfg!(target_env = "musl") {
        "musl"
    } else if cfg!(target_env = "msvc") {
        "msvc"
    } else if cfg!(target_env = "") {
        "none"
    } else {
        panic!("target_now: a target environment with no canonical stamp spelling")
    };
    let mut target = [0u8; 32];
    let at = put(&mut target, 0, arch.as_bytes());
    let at = put(&mut target, at, b"-");
    let at = put(&mut target, at, os.as_bytes());
    let at = put(&mut target, at, b"-");
    put(&mut target, at, env.as_bytes());
    target
}
// `scan` (find exactly one stamp in image bytes and validate every field, r10 step 3) lives in the loader's
// `scan.rs` (L1), its only callers being admit and pack: `pub fn stamp(image: &[u8]) -> Result<Stamp, StampScanErr>`.

/// What `plugin!` states for one image; `emit` turns it into the 272 stamp bytes.
#[doc(hidden)]
pub struct Spec<'a> {
    pub kind: KindCode,
    pub kind_abi: u32,
    /// `<kind>::FP`: the stamp's `layout` and `semantic`.
    pub layout: u64,
    pub out_of_process: bool,
    /// The `engine_min:`/`engine_max:` arms; None is the SDK line's `x.y.0` / `x.y.65535`.
    pub engine_min: Option<&'a str>,
    pub engine_max: Option<&'a str>,
    pub name: &'a str,
    pub version: &'a str,
    /// `BUSBAR_BUILD_ID` as the build saw it.
    pub build_id: Option<&'a str>,
    /// `"host"`, or the out-of-process host's backend name.
    pub crypto: &'a str,
}

/// The stamp `spec` states, every field checked (a const panic is a compile error in `plugin!`'s static).
#[doc(hidden)]
pub const fn emit(spec: &Spec<'_>) -> busbar_ffi::StampBytes {
    assert!(
        valid_name(spec.name),
        "the plugin name is not [a-z0-9-], 1 to 64 bytes, with no leading or trailing '-'"
    );
    assert!(
        valid_version(spec.version),
        "the plugin version is not a SemVer `x.y.z[-pre][+build]` of at most 32 bytes"
    );
    assert!(
        valid_crypto(spec.crypto),
        "the stamp's crypto name is not 1 to 8 bytes of [a-z0-9-], or is the reserved `external`"
    );
    assert!(
        spec.out_of_process || is(spec.crypto, "host"),
        "only an out_of_process plugin names a crypto backend"
    );
    let engine_min = engine(spec.engine_min, 0);
    let engine_max = engine(spec.engine_max, u16::MAX);
    assert!(
        engine_min.patch <= engine_max.patch,
        "engine_min is above engine_max"
    );
    let (build_id, local) = build_id_of(spec.build_id);
    let flags = local
        | if spec.out_of_process {
            STAMP_OUT_OF_PROCESS
        } else {
            0
        };
    let core = crate::fp::CORE_FP;
    let mut b = [0u8; 272];
    put(&mut b, 0, &STAMP_MAGIC);
    put(&mut b, 16, &2u32.to_le_bytes());
    put(&mut b, 20, &272u32.to_le_bytes());
    put(&mut b, 24, &(spec.kind as u32).to_le_bytes());
    put(&mut b, 28, &spec.kind_abi.to_le_bytes());
    put(&mut b, 32, &MECHANISM.to_le_bytes());
    put(&mut b, 36, &flags.to_le_bytes());
    put(&mut b, 40, &spec.layout.to_le_bytes());
    put(&mut b, 48, &core.to_le_bytes());
    put(&mut b, 56, &spec.layout.to_le_bytes());
    put(&mut b, 64, &core.to_le_bytes());
    put_engine(&mut b, 72, engine_min);
    put_engine(&mut b, 80, engine_max);
    put(&mut b, 88, spec.name.as_bytes());
    put(&mut b, 152, spec.version.as_bytes());
    put(&mut b, 184, &target_now());
    put(&mut b, 216, &build_id);
    put(&mut b, 248, spec.crypto.as_bytes());
    busbar_ffi::StampBytes(b)
}

/// The stamp name by precedence (r10 §2.3.2): the `name:` arm, else `BUSBAR_PLUGIN_NAME`, else the logic
/// crate's `CARGO_PKG_NAME`.
#[doc(hidden)]
pub const fn pick_name<'a>(
    arm: Option<&'a str>,
    env: Option<&'a str>,
    package: &'a str,
) -> &'a str {
    match (arm, env) {
        (Some(name), _) | (None, Some(name)) => name,
        (None, None) => package,
    }
}

/// The header's `former_names` (round 11): comma-separated stamp names, each `valid_name`; none = empty.
#[doc(hidden)]
pub const fn former_names(names: Option<&'static str>) -> Str<'static> {
    let Some(names) = names else {
        return Str::EMPTY;
    };
    let b = names.as_bytes();
    let (mut start, mut i) = (0, 0);
    while i <= b.len() {
        if i == b.len() || b[i] == b',' {
            assert!(
                valid_name_bytes(b, start, i),
                "a former name is not [a-z0-9-], 1 to 64 bytes, with no leading or trailing '-'"
            );
            start = i + 1;
        }
        i += 1;
    }
    Str::new(names)
}

/// r10 `valid_name`: `[a-z0-9-]`, 1..=64 bytes, no leading or trailing `-`.
const fn valid_name(name: &str) -> bool {
    let b = name.as_bytes();
    valid_name_bytes(b, 0, b.len())
}

const fn valid_name_bytes(b: &[u8], start: usize, end: usize) -> bool {
    if end <= start || end - start > 64 || b[start] == b'-' || b[end - 1] == b'-' {
        return false;
    }
    let mut i = start;
    while i < end {
        if !matches!(b[i], b'a'..=b'z' | b'0'..=b'9' | b'-') {
            return false;
        }
        i += 1;
    }
    true
}

/// r10 `valid_semver` plus the step-3 charset: `x.y.z` decimal, then nothing or a `-`/`+` suffix, every
/// byte in `[0-9A-Za-z.+-]`, at most 32 bytes.
const fn valid_version(version: &str) -> bool {
    let b = version.as_bytes();
    if b.is_empty() || b.len() > 32 {
        return false;
    }
    let mut i = 0;
    while i < b.len() {
        if !matches!(b[i], b'0'..=b'9' | b'A'..=b'Z' | b'a'..=b'z' | b'.' | b'+' | b'-') {
            return false;
        }
        i += 1;
    }
    let mut at = 0;
    let mut part = 0;
    while part < 3 {
        let start = at;
        while at < b.len() && b[at].is_ascii_digit() {
            at += 1;
        }
        if at == start {
            return false;
        }
        if part < 2 {
            if at >= b.len() || b[at] != b'.' {
                return false;
            }
            at += 1;
        }
        part += 1;
    }
    at == b.len() || b[at] == b'-' || b[at] == b'+'
}

/// The `crypto` field: 1..=8 bytes of `[a-z0-9-]`, never the C header's reserved `external`.
const fn valid_crypto(crypto: &str) -> bool {
    let b = crypto.as_bytes();
    if b.is_empty() || b.len() > 8 || is(crypto, "external") {
        return false;
    }
    let mut i = 0;
    while i < b.len() {
        if !matches!(b[i], b'a'..=b'z' | b'0'..=b'9' | b'-') {
            return false;
        }
        i += 1;
    }
    true
}

/// An engine bound: `text` (`x.y.z`, inside the SDK's own line), or the line's `x.y.<patch>`.
const fn engine(text: Option<&str>, patch: u16) -> EngineVersion {
    let line = EngineVersion {
        major: ENGINE.major,
        minor: ENGINE.minor,
        patch,
        _reserved: 0,
    };
    let Some(text) = text else {
        return line;
    };
    let b = text.as_bytes();
    let mut parts = [0u16; 3];
    let (mut part, mut at) = (0, 0);
    while part < 3 {
        let start = at;
        let mut value: u32 = 0;
        while at < b.len() && b[at].is_ascii_digit() {
            value = value * 10 + (b[at] - b'0') as u32;
            assert!(
                value <= u16::MAX as u32,
                "an engine bound part is over 65535"
            );
            at += 1;
        }
        assert!(at > start, "an engine bound is not `x.y.z`");
        parts[part] = value as u16;
        part += 1;
        if part < 3 {
            assert!(
                at < b.len() && b[at] == b'.',
                "an engine bound is not `x.y.z`"
            );
            at += 1;
        }
    }
    assert!(at == b.len(), "an engine bound is not `x.y.z`");
    assert!(
        parts[0] == line.major && parts[1] == line.minor,
        "an engine bound leaves the SDK's line"
    );
    EngineVersion {
        major: parts[0],
        minor: parts[1],
        patch: parts[2],
        _reserved: 0,
    }
}

const fn nibble(digit: u8) -> u8 {
    match digit {
        b'0'..=b'9' => digit - b'0',
        b'a'..=b'f' => digit - b'a' + 10,
        _ => panic!("BUSBAR_BUILD_ID is not 64 lowercase hex characters"),
    }
}

const fn is(a: &str, b: &str) -> bool {
    let (a, b) = (a.as_bytes(), b.as_bytes());
    if a.len() != b.len() {
        return false;
    }
    let mut i = 0;
    while i < a.len() {
        if a[i] != b[i] {
            return false;
        }
        i += 1;
    }
    true
}

/// Copy `src` into `dst` at `at`; returns the end.
const fn put(dst: &mut [u8], at: usize, src: &[u8]) -> usize {
    let mut i = 0;
    while i < src.len() {
        dst[at + i] = src[i];
        i += 1;
    }
    at + src.len()
}

const fn put_engine(dst: &mut [u8], at: usize, v: EngineVersion) {
    put(dst, at, &v.major.to_le_bytes());
    put(dst, at + 2, &v.minor.to_le_bytes());
    put(dst, at + 4, &v.patch.to_le_bytes());
}

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
