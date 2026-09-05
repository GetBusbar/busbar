//! Test-only wiring: the shared harness, the codec/µ-law fixture tests, and the purity/determinism
//! and style checks the crate doc comments promise elsewhere (`lib.rs`'s [`crate::VoicePlane`] doc
//! comment cites [`purity`] by name).

pub mod harness;

mod codec;
mod ulaw;

/// Purity and determinism: the properties every plane in the design is held to ("pure over its
/// inputs, no input or output of its own"), checked here rather than merely asserted in prose.
mod purity {
    use crate::VoicePlane;

    /// `VoicePlane` derives `Copy`. Every interior-mutable cell (`Cell`, `RefCell`, `Mutex`,
    /// `OnceLock`, ...) is `!Copy`, so a type that IS `Copy` structurally cannot hold one: this is
    /// a compile-time proof, not a convention, that the plane keeps no mutable state of its own
    /// across calls — everything that varies across a session lives in the kernel-held
    /// `PlaneSessionState` instead (see `session::VoiceSessionState`).
    const fn assert_copy<T: Copy>() {}
    const _: () = assert_copy::<VoicePlane>();

    /// Two planes built from the same upstream list compare equal, and looking up the same dialect
    /// twice gives the same answer — the two are really the same check, since `upstream_for_dialect`
    /// is a pure function of `self.upstreams()` and the argument.
    #[test]
    fn same_configuration_answers_the_same_way_every_time() {
        use crate::claims::Dialect;
        use crate::Upstream;
        use busbar_contract::ids::LaneId;

        static UPSTREAMS: &[Upstream] = &[Upstream {
            lane: LaneId::new("realtime"),
            host: "api.openai.example",
            dialect: Dialect::OpenaiRealtime,
        }];
        let a = VoicePlane::new(UPSTREAMS);
        let b = VoicePlane::new(UPSTREAMS);
        assert_eq!(a, b);
        assert_eq!(
            a.upstream_for_dialect(Dialect::OpenaiRealtime),
            b.upstream_for_dialect(Dialect::OpenaiRealtime)
        );
        assert_eq!(a.upstream_for_dialect(Dialect::GeminiLive), None);
    }

    /// A plane with nothing configured answers every dialect lookup with `None` rather than
    /// panicking or fabricating a host.
    #[test]
    fn empty_plane_names_no_upstream() {
        use crate::claims::Dialect;
        assert!(VoicePlane::EMPTY
            .upstream_for_dialect(Dialect::OpenaiRealtime)
            .is_none());
        assert_eq!(VoicePlane::EMPTY, VoicePlane::default());
    }

    /// The µ-law transform is a pure function: the same byte decodes to the same sample every time,
    /// with no I/O anywhere in the call.
    #[test]
    fn ulaw_decode_is_deterministic() {
        use crate::ulaw::ulaw_byte_to_pcm16;
        for byte in 0u8..=255 {
            assert_eq!(ulaw_byte_to_pcm16(byte), ulaw_byte_to_pcm16(byte));
        }
    }
}

/// Style rules this crate holds itself to, checked rather than merely asserted in prose: no
/// section-sign citation and no parity-binding identifier (a two-letter prefix, a hyphen and
/// digits, e.g. a two-letter code followed by a hyphen and a number) anywhere in this crate's own source — the same hard rule
/// `busbar-contract`'s `feature_invariance` test enforces for its own crate
/// (`crates/busbar-contract/tests/feature_invariance.rs`).
mod style {
    use std::path::{Path, PathBuf};

    fn src_dir() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR")).join("src")
    }

    fn walk(dir: &Path, f: &mut impl FnMut(&Path, &str)) {
        let entries = std::fs::read_dir(dir).expect("the source directory is readable");
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                walk(&path, f);
            } else if path.extension().is_some_and(|e| e == "rs") {
                let text = std::fs::read_to_string(&path).expect("a source file is readable");
                f(&path, &text);
            }
        }
    }

    #[test]
    fn no_section_sign_or_parity_binding_identifier_anywhere_in_source() {
        let mut offenders = Vec::new();
        walk(&src_dir(), &mut |path, text| {
            for (n, line) in text.lines().enumerate() {
                if line.contains('\u{00A7}') {
                    offenders.push(format!("{}:{}: section sign", path.display(), n + 1));
                }
                let bytes = line.as_bytes();
                for i in 0..bytes.len().saturating_sub(4) {
                    if bytes[i] == b'P'
                        && bytes[i + 1] == b'B'
                        && bytes[i + 2] == b'-'
                        && bytes[i + 3].is_ascii_digit()
                    {
                        offenders.push(format!("{}:{}: binding identifier", path.display(), n + 1));
                    }
                }
            }
        });
        assert!(
            offenders.is_empty(),
            "the source cites the design by number rather than in words: {offenders:?}"
        );
    }
}
