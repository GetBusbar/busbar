//! Test-only wiring: the shared harness, the codec/µ-law fixture tests, and the purity/determinism
//! and style checks the crate doc comments promise elsewhere (`lib.rs`'s [`crate::VoicePlane`] doc
//! comment cites [`purity`] by name).

pub mod harness;

mod codec;
mod ulaw;

/// What a request path matches, decided the same way the boot's overlap check decides it.
mod selectors {
    use crate::claims::matches_selector;
    use busbar_contract::grammar::Selector;

    /// A one-level prefix claims the segment below it and nothing else. A sibling whose name merely
    /// starts with the prefix's bytes is a different route, and matching it here would hand a
    /// request to a dialect the boot never proved this plane had claimed.
    #[test]
    fn a_one_level_prefix_stops_at_the_segment_boundary() {
        let s = Selector::PrefixOneLevel("/twilio");
        assert!(matches_selector(&s, "/twilio/inbound"));
        assert!(!matches_selector(&s, "/twiliofoo"));
        assert!(!matches_selector(&s, "/twilio"));
        assert!(!matches_selector(&s, "/twilio/inbound/deeper"));
        assert!(!matches_selector(&s, "/other/inbound"));
    }
}

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

    // The µ-law transform's determinism used to be "asserted" here by comparing one call of a pure
    // function to a second call of the same pure function over the same byte — a statement no
    // implementation of it can falsify, and one that read as coverage the transform did not have.
    // What the transform is actually held to lives in [`super::ulaw`]: the standard's own reference
    // vectors in both directions, and a round trip over all 256 bytes that pins the decoded sample.
}

/// Style rules this crate holds itself to, checked rather than merely asserted in prose: no
/// section-sign citation and no parity-binding identifier (a two-letter prefix, a hyphen and
/// digits, e.g. a two-letter code followed by a hyphen and a number) anywhere in this crate's own source — the same hard rule
/// `busbar-contract`'s `feature_invariance` test enforces for its own crate
/// (`crates/busbar-contract/tests/feature_invariance.rs`).
mod style {
    use std::path::{Path, PathBuf};

    fn crate_dir() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR")).to_path_buf()
    }

    /// Everything this crate SAYS — not only the half of it under `src`.
    ///
    /// The rule is that this crate cites the design in words rather than by number, and a citation
    /// is a citation wherever it is written: the integration tests are this crate's source too, and
    /// the manifest is the first thing a reader of the crate opens. Walking only `src` let both
    /// carry exactly what the rule forbids while a check named for the whole source passed.
    fn checked_files() -> Vec<PathBuf> {
        let root = crate_dir();
        let mut out = vec![root.join("Cargo.toml")];
        for dir in ["src", "tests"] {
            let dir = root.join(dir);
            if dir.is_dir() {
                collect(&dir, &mut out);
            }
        }
        out
    }

    fn collect(dir: &Path, out: &mut Vec<PathBuf>) {
        let entries = std::fs::read_dir(dir).expect("the source directory is readable");
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                collect(&path, out);
            } else if path.extension().is_some_and(|e| e == "rs") {
                out.push(path);
            }
        }
    }

    #[test]
    fn no_section_sign_or_parity_binding_identifier_anywhere_in_source() {
        let mut offenders = Vec::new();
        for path in checked_files() {
            let text = std::fs::read_to_string(&path).expect("a source file is readable");
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
        }
        assert!(
            offenders.is_empty(),
            "the source cites the design by number rather than in words: {offenders:?}"
        );
    }
}
