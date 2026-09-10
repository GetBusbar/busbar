//! Test-only wiring: the shared harness, the codec/µ-law fixture tests, and the purity/determinism
//! and style checks the crate doc comments promise elsewhere (`lib.rs`'s [`crate::VoicePlane`] doc
//! comment cites [`purity`] by name).

pub mod harness;

mod codec;
mod session_params;

/// What a request path matches, decided the same way the boot's overlap check decides it.
mod selectors {
    use crate::claims::matches_selector;
    use busbar_contract::grammar::Selector;

    /// A ONE-LEVEL PREFIX CLAIMS ITS OWN URL AND NO RELATIVE OF IT.
    ///
    /// The form all three duplex legs are claimed in, and every near miss below is a path some other
    /// route of this node serves or could serve; admitting one would hand a request to a dialect the
    /// boot never proved this plane had claimed. The bare base `/v1/realtime` is the sharpest of
    /// them — it is the plane's audience base and the mount the one-shot passes live under, and a
    /// claim that reached it would put a posted document into a session dialect's reader. The
    /// sibling whose name merely STARTS with the prefix's bytes is the other one: a prefix that
    /// stopped at the byte rather than the segment boundary would claim it.
    #[test]
    fn a_one_level_prefix_claims_its_own_url_and_no_relative_of_it() {
        let s = Selector::PrefixOneLevel("/v1/realtime/telephony");
        assert!(matches_selector(&s, "/v1/realtime/telephony/rtc_c0ffee"));
        assert!(!matches_selector(&s, "/v1/realtime/telephony"));
        assert!(!matches_selector(&s, "/v1/realtime/telephony/a/b"));
        assert!(!matches_selector(&s, "/v1/realtime/telephonyfoo/a"));
        assert!(!matches_selector(&s, "/v1/realtime/sideband/rtc_c0ffee"));
        assert!(!matches_selector(&s, "/v1/realtime"));
        assert!(!matches_selector(&s, "/v2/realtime/telephony/rtc_c0ffee"));
    }

    /// THE THREE LEGS ARE ADMITTED SEPARATELY, which is what makes them three dialects.
    ///
    /// A claim on the shared base would admit all three under whichever dialect named it, and the
    /// session would be read by the wrong reader — silently, because every one of the three speaks
    /// JSON over the same wire and a frame of the wrong vocabulary is a decode failure some frames
    /// into an open call rather than a refusal at the door.
    #[test]
    fn each_served_leg_names_its_own_dialect_and_the_base_names_none() {
        use crate::claims::{dialect_for, CARRIER};
        use crate::dialect::{NAME_GEMINI_LIVE, NAME_OPENAI_REALTIME};

        assert_eq!(
            dialect_for("/v1/realtime/sideband/rtc_c0ffee"),
            Some(NAME_OPENAI_REALTIME)
        );
        assert_eq!(
            dialect_for("/v1/realtime/telephony/rtc_c0ffee"),
            Some(CARRIER)
        );
        assert_eq!(
            dialect_for("/v1/realtime/gemini/rtc_c0ffee"),
            Some(NAME_GEMINI_LIVE)
        );
        assert_eq!(dialect_for("/v1/realtime"), None);
        assert_eq!(dialect_for("/twilio/stream"), None);
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
        use crate::dialect;
        use crate::Upstream;
        use busbar_contract::ids::LaneId;

        static UPSTREAMS: &[Upstream] = &[Upstream {
            lane: LaneId::new("realtime"),
            host: "api.openai.example",
            dialect: &dialect::OPENAI_REALTIME,
        }];
        let a = VoicePlane::new(UPSTREAMS);
        let b = VoicePlane::new(UPSTREAMS);
        assert_eq!(a, b);
        assert_eq!(
            a.upstream_for_dialect(&dialect::OPENAI_REALTIME),
            b.upstream_for_dialect(&dialect::OPENAI_REALTIME)
        );
        assert_eq!(a.upstream_for_dialect(&dialect::GEMINI_LIVE), None);
    }

    /// A plane with nothing configured answers every dialect lookup with `None` rather than
    /// panicking or fabricating a host.
    #[test]
    fn empty_plane_names_no_upstream() {
        use crate::dialect;
        assert!(VoicePlane::EMPTY
            .upstream_for_dialect(&dialect::OPENAI_REALTIME)
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
