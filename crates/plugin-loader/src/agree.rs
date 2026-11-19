// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Agreement at load (DESIGN-interface-revision C.4, C.6, D.1; owner's decisions B1, B6, B12).
//!
//! A contract (the core, or one kind) has a two-part version `first.second`: the first number breaks,
//! the second adds. An image's stamp states, for the core and for its own kind, the version it was built
//! for and the fingerprint of exactly that version's wire. The engine knows, for the one first number it
//! speaks of each contract, every released line (second number and fingerprint: the lines of that
//! contract's lock file, compiled in) and, in a dev build only, the one unreleased line at the label.
//!
//! The check, per contract, core first and then the kind:
//!
//! | The image is | Result |
//! |---|---|
//! | of another first number | refused, both versions named |
//! | of a second number above every line this engine knows | refused (a too-new plugin is never loaded), both versions named |
//! | of a line this engine knows, with that line's fingerprint | loads; the engine remembers the image's second number and never sends it anything introduced later |
//! | of a line this engine knows, with another fingerprint | refused: built from an unreleased or altered contract |
//!
//! The two stamp forms need no flag. A released stamp names a released line. A dev stamp names the next
//! unreleased second number and the fingerprint at the label: a dev-built engine at the same label knows
//! that line and loads it; a release-built engine knows released lines only, so the same stamp is "above
//! every line this engine knows" and is refused. A dev build cannot reach a customer by accident.
//!
//! Nothing here reads a kind: the tables are data handed in, so a kind change never edits this file.

use busbar_plugin_abi::types::KindCode;

use crate::refusal::{Refusal, RefusalCode};

/// A two-part contract version.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub struct Version {
    pub first: u32,
    pub second: u32,
}

impl core::fmt::Display for Version {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}.{}", self.first, self.second)
    }
}

/// One line the engine knows of the first number it speaks: a second number and the fingerprint of
/// that version's wire.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Line {
    pub second: u32,
    pub wire: u64,
}

/// What this engine speaks of one contract.
#[derive(Clone, Copy, Debug)]
pub struct Contract {
    /// `core`, or the kind's word (`transport`, `auth`, ...), as refusals name it.
    pub name: &'static str,
    pub first: u32,
    /// The released lines of `first`, ascending by second number: the lock file's lines.
    pub released: &'static [Line],
    /// The unreleased line at the label. Some in a dev build, None in a build for release.
    pub dev: Option<Line>,
}

impl Contract {
    /// The newest line this engine knows: the dev line in a dev build, else the last released line.
    pub fn newest(&self) -> Option<Line> {
        self.dev.or(self.released.last().copied())
    }

    /// The version refusals name as "this engine speaks".
    pub fn speaks(&self) -> Version {
        Version {
            first: self.first,
            second: self.newest().map_or(0, |line| line.second),
        }
    }

    fn line(&self, second: u32) -> Option<(Line, Form)> {
        if let Some(dev) = self.dev.filter(|dev| dev.second == second) {
            return Some((dev, Form::Dev));
        }
        self.released
            .iter()
            .find(|line| line.second == second)
            .map(|line| (*line, Form::Released))
    }
}

/// Which form of stamp an image carried, as the engine's tables resolve it.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Form {
    /// A released line of the lock file.
    Released,
    /// The unreleased line at the label (a dev-built engine only).
    Dev,
}

/// What a stamp states about one contract.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Claim {
    pub version: Version,
    pub wire: u64,
}

/// What a stamp (format 3) states about the interface.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Claims {
    pub core: Claim,
    pub kind: KindCode,
    pub of_kind: Claim,
}

/// Why one contract's claim is not one this engine loads.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Why {
    /// Another first number.
    FirstNumber,
    /// A second number above every line this engine knows.
    TooNew,
    /// A known line with another fingerprint: built from an unreleased or altered contract.
    Altered { want: u64 },
    /// A second number at or below the newest with no line of its own. A lock file is contiguous, so
    /// this is a stamp no build of ours writes.
    NoSuchLine,
}

/// A refused image: which contract, what it claimed, what this engine speaks, why.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Disagree {
    pub contract: &'static str,
    pub is_core: bool,
    pub have: Claim,
    pub speaks: Version,
    pub why: Why,
}

impl Disagree {
    /// What the image was built for, as the refusal's `have`.
    pub fn have_text(&self) -> String {
        match self.why {
            Why::Altered { .. } => format!(
                "{} {} wire {:#018x}",
                self.contract, self.have.version, self.have.wire
            ),
            _ => format!("built for {} {}", self.contract, self.have.version),
        }
    }

    /// What this engine speaks and what to do, as the refusal's `want`.
    pub fn want_text(&self) -> String {
        let (name, speaks) = (self.contract, self.speaks);
        match self.why {
            Why::FirstNumber => format!(
                "this engine speaks {name} {speaks}: use the plugin's build for {name} {}",
                speaks.first
            ),
            Why::TooNew => format!(
                "this engine speaks {name} {speaks}: upgrade the engine or use the plugin's build for {name} {speaks}"
            ),
            Why::Altered { want } => format!(
                "{name} {} wire {want:#018x}: the plugin was built from an unreleased or altered contract",
                self.have.version
            ),
            Why::NoSuchLine => format!(
                "this engine speaks {name} {speaks} and has no record of {name} {}",
                self.have.version
            ),
        }
    }

    /// The loader's refusal. The codes are the existing ones: a version disagreement is `KindAbi` (kind)
    /// or `Mechanism` (core); a fingerprint disagreement is `Layout`.
    pub fn refusal(&self) -> Refusal {
        let (code, field) = match (self.why, self.is_core) {
            (Why::Altered { .. }, true) => (RefusalCode::Layout, "core.wire"),
            (Why::Altered { .. }, false) => (RefusalCode::Layout, "kind.wire"),
            (_, true) => (RefusalCode::Mechanism, "core.version"),
            (_, false) => (RefusalCode::KindAbi, "kind.version"),
        };
        Refusal::new(code, field, self.have_text(), self.want_text())
    }
}

/// An image that agrees: the second numbers it was built for. The engine keeps these with the instance
/// and never sends the image a record, field, position or call introduced after them.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Agreed {
    pub kind: KindCode,
    pub core_second: u32,
    pub kind_second: u32,
    /// Dev when either line resolved to the unreleased line at the label.
    pub form: Form,
}

impl Agreed {
    /// Whether the image knows an element of its kind that arrived in second number `since`.
    pub fn knows(&self, since: u32) -> bool {
        self.kind_second >= since
    }
    /// Whether the image knows a core element that arrived in core second number `since`.
    pub fn knows_core(&self, since: u32) -> bool {
        self.core_second >= since
    }
}

fn one(contract: &Contract, is_core: bool, have: Claim) -> Result<Form, Disagree> {
    let refuse = |why| Disagree {
        contract: contract.name,
        is_core,
        have,
        speaks: contract.speaks(),
        why,
    };
    if have.version.first != contract.first {
        return Err(refuse(Why::FirstNumber));
    }
    let newest = contract.newest().map(|line| line.second);
    if newest.is_none_or(|newest| have.version.second > newest) {
        return Err(refuse(Why::TooNew));
    }
    match contract.line(have.version.second) {
        Some((line, form)) if line.wire == have.wire => Ok(form),
        Some((line, _)) => Err(refuse(Why::Altered { want: line.wire })),
        None => Err(refuse(Why::NoSuchLine)),
    }
}

/// The whole check: the core first, then the image's kind.
pub fn agree(claims: &Claims, core: &Contract, kind: &Contract) -> Result<Agreed, Disagree> {
    let core_form = one(core, true, claims.core)?;
    let kind_form = one(kind, false, claims.of_kind)?;
    Ok(Agreed {
        kind: claims.kind,
        core_second: claims.core.version.second,
        kind_second: claims.of_kind.version.second,
        form: if core_form == Form::Dev || kind_form == Form::Dev {
            Form::Dev
        } else {
            Form::Released
        },
    })
}

/// What this engine speaks: the core and the seven kinds, indexed by kind code.
#[derive(Clone, Copy, Debug)]
pub struct Speaks {
    pub core: Contract,
    /// Index `KindCode as usize - 1`.
    pub kinds: [Contract; 7],
}

impl Speaks {
    pub fn kind(&self, kind: KindCode) -> &Contract {
        &self.kinds[kind as usize - 1]
    }

    /// The check against this engine's tables.
    pub fn agree(&self, claims: &Claims) -> Result<Agreed, Disagree> {
        agree(claims, &self.core, self.kind(claims.kind))
    }

    /// A lock file's lines must ascend by one from 0 and the dev line, when present, must be the next
    /// second number. Checked once at start; a table that fails it is a build fault of the engine.
    pub fn well_formed(&self) -> Result<(), String> {
        for contract in core::iter::once(&self.core).chain(self.kinds.iter()) {
            for (at, line) in contract.released.iter().enumerate() {
                if line.second as usize != at {
                    return Err(format!(
                        "{} {}: released line {at} names second number {}",
                        contract.name, contract.first, line.second
                    ));
                }
            }
            if let Some(dev) = contract.dev {
                if dev.second as usize != contract.released.len() {
                    return Err(format!(
                        "{} {}: the dev line names second number {} after {} released lines",
                        contract.name,
                        contract.first,
                        dev.second,
                        contract.released.len()
                    ));
                }
            }
            if contract.newest().is_none() {
                return Err(format!(
                    "{} {}: no released line and no dev line",
                    contract.name, contract.first
                ));
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const CORE: [Line; 2] = [
        Line {
            second: 0,
            wire: 0xC0,
        },
        Line {
            second: 1,
            wire: 0xC1,
        },
    ];
    const TRANSPORT: [Line; 4] = [
        Line {
            second: 0,
            wire: 0x70,
        },
        Line {
            second: 1,
            wire: 0x71,
        },
        Line {
            second: 2,
            wire: 0x72,
        },
        Line {
            second: 3,
            wire: 0x73,
        },
    ];
    const DEV: Line = Line {
        second: 4,
        wire: 0x7D,
    };

    fn core() -> Contract {
        Contract {
            name: "core",
            first: 3,
            released: &CORE,
            dev: None,
        }
    }

    fn transport(dev: bool) -> Contract {
        Contract {
            name: "transport",
            first: 2,
            released: &TRANSPORT,
            dev: dev.then_some(DEV),
        }
    }

    fn claims(core: (u32, u32, u64), kind: (u32, u32, u64)) -> Claims {
        let claim = |(first, second, wire)| Claim {
            version: Version { first, second },
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
            &claims((3, 0, 0xC0), (2, 1, 0x71)),
            &core(),
            &transport(false),
        )
        .unwrap();
        assert_eq!((agreed.core_second, agreed.kind_second), (0, 1));
        assert_eq!(agreed.form, Form::Released);
        assert!(agreed.knows(1) && !agreed.knows(2));
        assert!(agreed.knows_core(0) && !agreed.knows_core(1));
    }

    #[test]
    fn a_newer_kind_is_refused_naming_both_numbers() {
        let no = agree(
            &claims((3, 1, 0xC1), (2, 4, 0x74)),
            &core(),
            &transport(false),
        )
        .unwrap_err();
        assert_eq!(no.why, Why::TooNew);
        assert_eq!(no.have_text(), "built for transport 2.4");
        assert_eq!(
            no.want_text(),
            "this engine speaks transport 2.3: upgrade the engine or use the plugin's build for transport 2.3"
        );
    }

    #[test]
    fn a_newer_core_is_refused_before_the_kind_is_read() {
        let no = agree(&claims((3, 2, 0xC2), (9, 9, 0)), &core(), &transport(false)).unwrap_err();
        assert!(no.is_core);
        assert_eq!(no.why, Why::TooNew);
        assert_eq!(no.have_text(), "built for core 3.2");
        assert!(no.want_text().starts_with("this engine speaks core 3.1"));
    }

    #[test]
    fn another_first_number_is_refused_naming_both_numbers() {
        let no = agree(
            &claims((3, 1, 0xC1), (1, 0, 0x10)),
            &core(),
            &transport(false),
        )
        .unwrap_err();
        assert_eq!(no.why, Why::FirstNumber);
        assert_eq!(no.have_text(), "built for transport 1.0");
        assert!(no
            .want_text()
            .starts_with("this engine speaks transport 2.3"));
        let no = agree(
            &claims((2, 0, 0xB0), (2, 3, 0x73)),
            &core(),
            &transport(false),
        )
        .unwrap_err();
        assert!(no.is_core);
        assert_eq!(no.why, Why::FirstNumber);
    }

    #[test]
    fn a_known_line_with_another_fingerprint_is_an_altered_contract() {
        let no = agree(
            &claims((3, 1, 0xC1), (2, 2, 0xBAD)),
            &core(),
            &transport(false),
        )
        .unwrap_err();
        assert_eq!(no.why, Why::Altered { want: 0x72 });
        assert!(no.want_text().ends_with("unreleased or altered contract"));
    }

    #[test]
    fn a_release_built_engine_refuses_a_dev_stamp() {
        let dev_stamp = claims((3, 1, 0xC1), (2, 4, 0x7D));
        let no = agree(&dev_stamp, &core(), &transport(false)).unwrap_err();
        assert_eq!(no.why, Why::TooNew);
    }

    #[test]
    fn a_dev_built_engine_at_the_same_label_loads_a_dev_stamp() {
        let dev_stamp = claims((3, 1, 0xC1), (2, 4, 0x7D));
        let agreed = agree(&dev_stamp, &core(), &transport(true)).unwrap();
        assert_eq!(agreed.form, Form::Dev);
        assert_eq!(agreed.kind_second, 4);
    }

    #[test]
    fn a_dev_stamp_from_another_label_is_refused_as_altered() {
        let stale = claims((3, 1, 0xC1), (2, 4, 0x7E));
        let no = agree(&stale, &core(), &transport(true)).unwrap_err();
        assert_eq!(no.why, Why::Altered { want: 0x7D });
    }

    #[test]
    fn a_dev_built_engine_still_loads_every_released_line() {
        for line in TRANSPORT {
            let agreed = agree(
                &claims((3, 0, 0xC0), (2, line.second, line.wire)),
                &core(),
                &transport(true),
            )
            .unwrap();
            assert_eq!(agreed.form, Form::Released);
        }
    }

    #[test]
    fn a_table_with_a_gap_or_a_misplaced_dev_line_is_not_well_formed() {
        let good = Speaks {
            core: core(),
            kinds: [transport(true); 7],
        };
        assert!(good.well_formed().is_ok());
        static GAP: [Line; 2] = [Line { second: 0, wire: 1 }, Line { second: 2, wire: 2 }];
        let mut bad = good;
        bad.kinds[3].released = &GAP;
        bad.kinds[3].dev = None;
        assert!(bad.well_formed().is_err());
        let mut bad = good;
        bad.kinds[0].dev = Some(Line { second: 9, wire: 0 });
        assert!(bad.well_formed().is_err());
    }

    #[test]
    fn the_refusal_keeps_the_existing_codes() {
        let no = agree(&claims((3, 1, 0xC1), (2, 9, 0)), &core(), &transport(false)).unwrap_err();
        assert_eq!(no.refusal().code, RefusalCode::KindAbi);
        let no = agree(&claims((4, 0, 0), (2, 0, 0x70)), &core(), &transport(false)).unwrap_err();
        assert_eq!(no.refusal().code, RefusalCode::Mechanism);
        let no = agree(
            &claims((3, 1, 0xBAD), (2, 0, 0x70)),
            &core(),
            &transport(false),
        )
        .unwrap_err();
        assert_eq!(no.refusal().code, RefusalCode::Layout);
    }
}
