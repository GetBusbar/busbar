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
        use crate::claims::GEMINI_LIVE as NAME_GEMINI_LIVE;
        use crate::claims::OPENAI_REALTIME as NAME_OPENAI_REALTIME;
        use crate::claims::{dialect_for, CARRIER};

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
            dialect: &super::harness::A_DIALECT,
        }];
        let a = VoicePlane::new(UPSTREAMS);
        let b = VoicePlane::new(UPSTREAMS);
        assert_eq!(a, b);
        assert_eq!(
            a.upstream_for_dialect(&super::harness::A_DIALECT),
            b.upstream_for_dialect(&super::harness::A_DIALECT)
        );
        // A DIALECT THIS UPSTREAM LIST DOES NOT CARRY — and it is a row declared HERE, not a
        // sibling dialect crate's. The assertion is "a list with one dialect answers None for a
        // different one", which needs a different row and never a particular vendor's; reaching for
        // one would be this crate's tests taking the dependency its own direction rule forbids.
        static OTHER: dialect::Dialect = dialect::Dialect {
            name: "other-dialect",
            duplex_upstream: true,
            authenticates_from_session: true,
            meters_own_uplink: false,
            envelope: None,
            locked_session_config: None,
            reader: None,
            writer: None,
            credential_at: None,
        };
        assert_eq!(a.upstream_for_dialect(&OTHER), None);
    }

    /// A plane with nothing configured answers every dialect lookup with `None` rather than
    /// panicking or fabricating a host.
    #[test]
    fn empty_plane_names_no_upstream() {
        assert!(VoicePlane::EMPTY
            .upstream_for_dialect(&super::harness::A_DIALECT)
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

/// THE KIND'S FACE, AND THE INSTANCE DISPATCH THAT USED TO BE BEHIND IT.
///
/// The owner's ruling of 2026-09-10 is that nothing dialect-specific lives in this plane beyond the
/// kind's face, and that every plugin of a kind is identical to every other of its kind. Until the
/// Gemini dialect was cut into its own crate this plane failed both: `reader_for` and `writer_for`
/// were `if dialect.name == <one vendor> { that codec } else { the other }`, so one dialect of the
/// three was privileged by a string comparison at the neutral crate's own altitude and the other
/// two were "the else".
///
/// These cells are RED BEFORE that cut, and red in the strongest way a cell can be: the row fields
/// they read do not exist on the base, so the base does not compile them.
///
/// NO DIALECT IS NAMED HERE, and that is the whole discipline. The reader these cells hand the row
/// is written IN THIS MODULE, three lines of it, precisely so the cell asserts the FACE rather than
/// a particular vendor's codec — reaching for a real one would be this crate's tests taking the
/// dependency its own direction rule forbids, and would put a second instance's vocabulary in the
/// neutral crate's ceiling to buy a test.
mod dialect_face {
    use crate::dialect::{
        DecodeState, Dialect, DuplexReader, DuplexWriter, IrClientEvent, IrServerEvent, WireEvent,
        WireRef,
    };

    /// A dialect's OWN reader/writer, as a test double: it reads nothing and writes nothing, which
    /// is all the cell needs — the question is WHOSE reader the plane reached for, not what it read.
    struct ItsOwn;

    impl DuplexReader for ItsOwn {
        fn read_up_ref(&self, _wire: WireRef<'_>, _st: &mut DecodeState) -> Vec<IrClientEvent> {
            Vec::new()
        }
        fn read_down_ref(&self, _wire: WireRef<'_>, _st: &mut DecodeState) -> Vec<IrServerEvent> {
            Vec::new()
        }
    }

    impl DuplexWriter for ItsOwn {
        fn write_up(&self, _e: IrClientEvent, _st: &mut DecodeState) -> Option<WireEvent> {
            None
        }
        fn write_down(&self, _e: IrServerEvent, _st: &mut DecodeState) -> Option<WireEvent> {
            None
        }
    }

    /// The one server event every dialect of this plane has a frame for — the cell needs an event
    /// the SHARED writer will render, so that "rendered nothing" can only mean the row's own writer
    /// was used.
    fn session_created() -> IrServerEvent {
        IrServerEvent::SessionCreated {
            session: serde_json::json!({}),
        }
    }

    fn own_reader() -> Box<dyn DuplexReader> {
        Box::new(ItsOwn)
    }

    fn own_writer() -> Box<dyn DuplexWriter> {
        Box::new(ItsOwn)
    }

    /// A row that brings its own reader and writer — the shape a dialect crate declares.
    static BRINGS_ITS_OWN: Dialect = Dialect {
        name: "brings-its-own-reader",
        duplex_upstream: true,
        authenticates_from_session: true,
        meters_own_uplink: false,
        envelope: None,
        locked_session_config: None,
        reader: Some(own_reader),
        writer: Some(own_writer),
        credential_at: None,
    };

    /// A row that declares `None` — "the shared IR reads my frames", which is an ANSWER and not a
    /// blank.
    static RIDES_THE_SHARED_IR: Dialect = Dialect {
        name: "rides-the-shared-ir",
        duplex_upstream: true,
        authenticates_from_session: true,
        meters_own_uplink: false,
        envelope: None,
        locked_session_config: None,
        reader: None,
        writer: None,
        credential_at: None,
    };

    /// A DIALECT'S READER IS A FIELD OF ITS ROW, NEVER A TEST ON ITS NAME.
    ///
    /// Two rows that differ ONLY in that field get different readers, and neither row's name appears
    /// anywhere in the crate that chose between them. The old shape could not pass this: a row whose
    /// name is neither of the two vendors fell into the `else` no matter what it declared, so both
    /// rows below would have got the same reader and the field would have been decoration.
    #[test]
    fn a_dialects_reader_comes_off_its_own_row_and_not_off_its_name() {
        let mut st = DecodeState::default();
        let ga = br#"{"type":"session.created","session":{}}"#;

        let brought = crate::plane::reader_for(Some(&BRINGS_ITS_OWN));
        assert!(
            brought.read_down_ref(WireRef(ga), &mut st).is_empty(),
            "the row declared its OWN reader and the plane reached for a different one; a dialect              whose declared reader is ignored is instance dispatch by another name"
        );

        let mut st = DecodeState::default();
        let shared = crate::plane::reader_for(Some(&RIDES_THE_SHARED_IR));
        assert!(
            !shared.read_down_ref(WireRef(ga), &mut st).is_empty(),
            "the row declared `None` — the SHARED IR — and did not get it; `None` is an answer on              this face, not a blank to be filled by whichever vendor was written first"
        );
    }

    /// THE SAME RULE FOR THE WRITER, stated separately because the two fields are separately
    /// declarable: a dialect that reads its own wire and writes the shared one is a shape this face
    /// admits, and one combined field would have decided that for every dialect at once.
    #[test]
    fn a_dialects_writer_comes_off_its_own_row_and_not_off_its_name() {
        let mut st = DecodeState::default();
        let brought = crate::plane::writer_for(Some(&BRINGS_ITS_OWN));
        assert!(
            brought.write_down(session_created(), &mut st).is_none(),
            "the row declared its OWN writer and the plane reached for a different one"
        );

        let mut st = DecodeState::default();
        let shared = crate::plane::writer_for(Some(&RIDES_THE_SHARED_IR));
        assert!(
            shared.write_down(session_created(), &mut st).is_some(),
            "the row declared `None` — the SHARED IR — and did not get it"
        );
    }

    /// THE NEUTRAL PLANE DECLARES NO ROW FOR A DIALECT THAT HAS A CRATE.
    ///
    /// The direction rule's other half, as a cell: a name this plane's claim table carries must
    /// resolve through [`crate::dialect::register`], not through a `&'static` this crate wrote. No
    /// composition root runs in a unit-test process, so the honest assertion is that the table is
    /// SILENT about a cut dialect here — silence that a registration, and only a registration, ends.
    #[test]
    fn a_cut_dialect_has_no_row_this_crate_declared() {
        assert!(
            crate::dialect::dialect(crate::claims::GEMINI_LIVE).is_none(),
            "this crate still declares a row for a dialect that has its own crate; the plane is              naming an instance again"
        );
        assert!(
            crate::dialect::dialect(crate::claims::CARRIER).is_none(),
            "this crate declares a row for the carrier dialect, which has had its own crate since              the carrier was cut"
        );
    }
}
