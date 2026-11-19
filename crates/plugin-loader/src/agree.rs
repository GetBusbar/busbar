// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Agreement at load (DESIGN-interface-revision C.4, C.6, D.1; owner's decisions B1, B6, B12).
//!
//! A contract (the core, or one kind) has a two-part version `first.second`: the first number breaks,
//! the second adds. An image's stamp (format 3) states, for the core and for its own kind, the version
//! it was built for and the fingerprint of exactly that version's wire. The contract crate holds what
//! this engine speaks of each contract and the check of one contract (`versions::Contract::agree`); this
//! module is the loader's half: it reads the stamp's claims, runs the check for the core and then for
//! the kind, keeps what was agreed, and words the refusal.
//!
//! | The image is | Result |
//! |---|---|
//! | of another first number | refused, both versions named |
//! | of a second number above this engine's | refused (a too-new plugin is never loaded), both versions named |
//! | of a released line, with that line's fingerprint | loads; the engine remembers the image's second number and never sends it anything introduced later |
//! | of a version this engine knows, with another fingerprint | refused: built from an unreleased or altered contract |
//! | of the unreleased version at the label | loads on a dev-built engine (`Build::Dev`); refused on an engine built for release, which accepts released lines only |
//!
//! So the two stamp forms need no flag: a released stamp names a released line, a dev stamp names the
//! next unreleased version with the fingerprint at the label, and a dev build cannot reach a customer by
//! accident because a release engine has no line for it.
//!
//! Nothing here names a kind: the tables are data handed in, so a kind change never edits this file.

use busbar_plugin_abi::types::KindCode;
use busbar_plugin_abi::versions::{Build, Contract, Disagree, Version};

use crate::refusal::{Refusal, RefusalCode};

/// What a stamp states about one contract.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Claim {
    pub version: Version,
    pub wire: u64,
}

/// What a stamp states about the interface.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Claims {
    pub core: Claim,
    pub kind: KindCode,
    pub of_kind: Claim,
}

/// An image that agrees: the second numbers it was built for. The engine keeps these with the instance
/// and never sends the image a record, field, position or call introduced after them.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Agreed {
    pub kind: KindCode,
    pub core_second: u32,
    pub kind_second: u32,
}

impl Agreed {
    /// Whether the image knows an element of its kind that arrived in second number `since`.
    pub fn knows(&self, since: u32) -> bool {
        Contract::knows(self.kind_second, since)
    }
    /// Whether the image knows a core element that arrived in core second number `since`.
    pub fn knows_core(&self, since: u32) -> bool {
        Contract::knows(self.core_second, since)
    }
}

/// A refused image: which contract, what the stamp claimed, and why.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Refused {
    /// `core`, or the kind's word.
    pub contract: &'static str,
    pub is_core: bool,
    pub have: Claim,
    pub why: Disagree,
}

impl Refused {
    /// What the image was built for, as the refusal's `have`.
    pub fn have_text(&self) -> String {
        let (name, have) = (self.contract, self.have);
        match self.why {
            Disagree::Fingerprint { .. } => {
                format!("{name} {} wire {:#018x}", have.version, have.wire)
            }
            Disagree::Unreleased { .. } => {
                format!(
                    "built for {name} {}, which is not a released version",
                    have.version
                )
            }
            Disagree::First { .. } | Disagree::Newer { .. } => {
                format!("built for {name} {}", have.version)
            }
        }
    }

    /// What this engine speaks and what to do, as the refusal's `want`.
    pub fn want_text(&self) -> String {
        let name = self.contract;
        match self.why {
            Disagree::First { engine, .. } => format!(
                "this engine speaks {name} {engine}: use the plugin's build for {name} {}",
                engine.first
            ),
            Disagree::Newer { engine, .. } => format!(
                "this engine speaks {name} {engine}: upgrade the engine or use the plugin's build for {name} {engine}"
            ),
            Disagree::Fingerprint { version } => format!(
                "this engine's record of {name} {version}: the plugin was built from an unreleased or altered contract"
            ),
            Disagree::Unreleased { .. } => format!(
                "a released version of {name}: this engine is built for release and loads released builds only"
            ),
        }
    }

    /// The loader's refusal. The codes are the existing ones: a version disagreement is `KindAbi` (kind)
    /// or `Mechanism` (core); a fingerprint disagreement is `Layout`.
    pub fn refusal(&self) -> Refusal {
        let (code, field) = match (self.why, self.is_core) {
            (Disagree::Fingerprint { .. }, true) => (RefusalCode::Layout, "core_layout"),
            (Disagree::Fingerprint { .. }, false) => (RefusalCode::Layout, "layout"),
            (_, true) => (RefusalCode::Mechanism, "core_abi"),
            (_, false) => (RefusalCode::KindAbi, "kind_abi"),
        };
        Refusal::new(code, field, self.have_text(), self.want_text())
    }
}

/// The whole check: the core first, then the image's kind.
pub fn agree(
    build: Build,
    claims: &Claims,
    core: &Contract,
    kind: &Contract,
) -> Result<Agreed, Refused> {
    for (contract, is_core, have) in [(core, true, claims.core), (kind, false, claims.of_kind)] {
        contract
            .agree(build, have.version, have.wire)
            .map_err(|why| Refused {
                contract: contract.name,
                is_core,
                have,
                why,
            })?;
    }
    Ok(Agreed {
        kind: claims.kind,
        core_second: claims.core.version.second,
        kind_second: claims.of_kind.version.second,
    })
}

/// How this engine was built. An engine built for release (`release-engine`) accepts released lines
/// only; any other build is a dev engine and also accepts the unreleased version at the label.
pub const fn build() -> Build {
    if cfg!(feature = "release-engine") {
        Build::Release
    } else {
        Build::Dev
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use busbar_plugin_abi::versions::Line;

    const fn v(first: u32, second: u32) -> Version {
        Version { first, second }
    }

    /// Core 3.1: 3.0 released, 3.1 released.
    const CORE: Contract = Contract {
        name: "core",
        speaks: v(3, 1),
        wire: 0xC1,
        released: &[
            Line {
                version: v(3, 0),
                wire: 0xC0,
            },
            Line {
                version: v(3, 1),
                wire: 0xC1,
            },
        ],
    };

    /// Transport as a release engine speaks it: 2.0 to 2.3 released.
    const TRANSPORT: Contract = Contract {
        name: "transport",
        speaks: v(2, 3),
        wire: 0x73,
        released: &RELEASED,
    };

    /// Transport at the label: 2.4 is the next unreleased version.
    const TRANSPORT_AT_LABEL: Contract = Contract {
        name: "transport",
        speaks: v(2, 4),
        wire: 0x7D,
        released: &RELEASED,
    };

    const RELEASED: [Line; 4] = [
        Line {
            version: v(2, 0),
            wire: 0x70,
        },
        Line {
            version: v(2, 1),
            wire: 0x71,
        },
        Line {
            version: v(2, 2),
            wire: 0x72,
        },
        Line {
            version: v(2, 3),
            wire: 0x73,
        },
    ];

    fn claims(core: (u32, u32, u64), kind: (u32, u32, u64)) -> Claims {
        let claim = |(first, second, wire)| Claim {
            version: v(first, second),
            wire,
        };
        Claims {
            core: claim(core),
            kind: KindCode::Transport,
            of_kind: claim(kind),
        }
    }

    #[test]
    fn an_older_second_number_loads_and_is_remembered() {
        let agreed = agree(
            Build::Release,
            &claims((3, 0, 0xC0), (2, 1, 0x71)),
            &CORE,
            &TRANSPORT,
        )
        .unwrap();
        assert_eq!((agreed.core_second, agreed.kind_second), (0, 1));
        assert!(agreed.knows(1) && !agreed.knows(2));
        assert!(agreed.knows_core(0) && !agreed.knows_core(1));
    }

    #[test]
    fn a_newer_kind_is_refused_naming_both_numbers() {
        let no = agree(
            Build::Release,
            &claims((3, 1, 0xC1), (2, 4, 0x74)),
            &CORE,
            &TRANSPORT,
        )
        .unwrap_err();
        assert!(matches!(no.why, Disagree::Newer { .. }));
        assert_eq!(no.have_text(), "built for transport 2.4");
        assert_eq!(
            no.want_text(),
            "this engine speaks transport 2.3: upgrade the engine or use the plugin's build for transport 2.3"
        );
    }

    #[test]
    fn a_newer_core_is_refused_before_the_kind_is_read() {
        let no = agree(
            Build::Release,
            &claims((3, 2, 0xC2), (9, 9, 0)),
            &CORE,
            &TRANSPORT,
        )
        .unwrap_err();
        assert!(no.is_core);
        assert!(matches!(no.why, Disagree::Newer { .. }));
        assert_eq!(no.have_text(), "built for core 3.2");
        assert!(no.want_text().starts_with("this engine speaks core 3.1"));
    }

    #[test]
    fn another_first_number_is_refused_naming_both_numbers() {
        let no = agree(
            Build::Release,
            &claims((3, 1, 0xC1), (1, 0, 0x10)),
            &CORE,
            &TRANSPORT,
        )
        .unwrap_err();
        assert!(matches!(no.why, Disagree::First { .. }));
        assert_eq!(no.have_text(), "built for transport 1.0");
        assert_eq!(
            no.want_text(),
            "this engine speaks transport 2.3: use the plugin's build for transport 2"
        );
        let no = agree(
            Build::Release,
            &claims((2, 0, 0xB0), (2, 3, 0x73)),
            &CORE,
            &TRANSPORT,
        )
        .unwrap_err();
        assert!(no.is_core);
        assert!(matches!(no.why, Disagree::First { .. }));
    }

    #[test]
    fn a_released_line_with_another_fingerprint_is_an_altered_contract() {
        let no = agree(
            Build::Release,
            &claims((3, 1, 0xC1), (2, 2, 0xBAD)),
            &CORE,
            &TRANSPORT,
        )
        .unwrap_err();
        assert_eq!(no.why, Disagree::Fingerprint { version: v(2, 2) });
        assert!(no.want_text().ends_with("unreleased or altered contract"));
        assert!(no.have_text().starts_with("transport 2.2 wire 0x"));
    }

    #[test]
    fn a_dev_engine_at_the_label_loads_a_dev_stamp() {
        let dev_stamp = claims((3, 1, 0xC1), (2, 4, 0x7D));
        let agreed = agree(Build::Dev, &dev_stamp, &CORE, &TRANSPORT_AT_LABEL).unwrap();
        assert_eq!(agreed.kind_second, 4);
    }

    #[test]
    fn an_engine_built_for_release_refuses_a_dev_stamp() {
        let dev_stamp = claims((3, 1, 0xC1), (2, 4, 0x7D));
        // Built from the same source at the label, but for release: 2.4 has no released line.
        let no = agree(Build::Release, &dev_stamp, &CORE, &TRANSPORT_AT_LABEL).unwrap_err();
        assert_eq!(no.why, Disagree::Unreleased { version: v(2, 4) });
        assert_eq!(
            no.have_text(),
            "built for transport 2.4, which is not a released version"
        );
        // And a release engine one version behind refuses it as too new.
        let no = agree(Build::Release, &dev_stamp, &CORE, &TRANSPORT).unwrap_err();
        assert!(matches!(no.why, Disagree::Newer { .. }));
    }

    #[test]
    fn a_dev_stamp_from_another_label_is_refused_as_altered() {
        let stale = claims((3, 1, 0xC1), (2, 4, 0x7E));
        let no = agree(Build::Dev, &stale, &CORE, &TRANSPORT_AT_LABEL).unwrap_err();
        assert_eq!(no.why, Disagree::Fingerprint { version: v(2, 4) });
    }

    #[test]
    fn a_dev_engine_still_loads_every_released_line() {
        for line in RELEASED {
            let image = claims(
                (3, 0, 0xC0),
                (line.version.first, line.version.second, line.wire),
            );
            assert!(agree(Build::Dev, &image, &CORE, &TRANSPORT_AT_LABEL).is_ok());
        }
    }

    #[test]
    fn the_refusal_keeps_the_existing_codes() {
        let no = agree(
            Build::Release,
            &claims((3, 1, 0xC1), (2, 9, 0)),
            &CORE,
            &TRANSPORT,
        )
        .unwrap_err();
        assert_eq!(no.refusal().code, RefusalCode::KindAbi);
        let no = agree(
            Build::Release,
            &claims((4, 0, 0), (2, 0, 0x70)),
            &CORE,
            &TRANSPORT,
        )
        .unwrap_err();
        assert_eq!(no.refusal().code, RefusalCode::Mechanism);
        let no = agree(
            Build::Release,
            &claims((3, 1, 0xBAD), (2, 0, 0x70)),
            &CORE,
            &TRANSPORT,
        )
        .unwrap_err();
        assert_eq!(no.refusal().code, RefusalCode::Layout);
    }
}
