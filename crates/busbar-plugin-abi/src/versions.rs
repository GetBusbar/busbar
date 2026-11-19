// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The contract versions (interface revision C.4) and the engine version.
//!
//! A version is `first.second` per contract: the core contract and each of the seven kind contracts has
//! its own. The first number moves only when something existing is changed or removed (images of that
//! contract are rebuilt); the second moves when something is added (images built earlier keep loading and
//! are never sent what they do not know). There is no shared number: a change to one kind's contract
//! alters nothing an image of another kind carries.

use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout};

use crate::types::KindCode;

/// The core contract's first number: the old "mechanism" 2 plus one (the one call shape).
pub const CORE: u32 = 3;
/// Each kind's first number is its previous value plus one: every kind moves once, with the call shape.
pub const STORE: u32 = 4;
pub const SECRET: u32 = 3;
pub const AUTH: u32 = 4;
pub const HOOK: u32 = 3;
pub const EXPORT: u32 = 4;
pub const PLANE: u32 = 2;
pub const TRANSPORT: u32 = 2;

/// The second number this source speaks, per contract. Until a contract's first line is cut at a qa
/// promotion this is 0 and unreleased: a dev build stamps `first.0` with the fingerprint of the interface
/// it was built from, and an engine built for release, which knows only released lines, refuses it.
pub const CORE_MINOR: u32 = 0;
pub const STORE_MINOR: u32 = 0;
pub const SECRET_MINOR: u32 = 0;
pub const AUTH_MINOR: u32 = 0;
pub const HOOK_MINOR: u32 = 0;
pub const EXPORT_MINOR: u32 = 0;
pub const PLANE_MINOR: u32 = 0;
pub const TRANSPORT_MINOR: u32 = 0;

/// The engine version, which is this crate's package version.
pub const ENGINE: EngineVersion = EngineVersion {
    major: number(env!("CARGO_PKG_VERSION_MAJOR")),
    minor: number(env!("CARGO_PKG_VERSION_MINOR")),
    patch: number(env!("CARGO_PKG_VERSION_PATCH")),
    _reserved: 0,
};
/// The stamp's engine range is a statement a plugin author makes about a known bad engine. Its default is
/// "any": these two bounds. (Before core 3.0 the default was the engine's own minor line, which refused a
/// plugin built for 1.6 on 1.7 even when no contract had changed.)
pub const ENGINE_ANY_MIN: EngineVersion = EngineVersion {
    major: 0,
    minor: 0,
    patch: 0,
    _reserved: 0,
};
pub const ENGINE_ANY_MAX: EngineVersion = EngineVersion {
    major: u16::MAX,
    minor: u16::MAX,
    patch: u16::MAX,
    _reserved: 0,
};

#[repr(C)]
#[derive(
    Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug, FromBytes, IntoBytes, Immutable, KnownLayout,
)]
pub struct EngineVersion {
    pub major: u16,
    pub minor: u16,
    pub patch: u16,
    pub _reserved: u16,
}

/// One contract version, `first.second`.
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

/// One released line of a contract's lock file (`pins/<contract>.pin`, interface revision C.7): the
/// version and the wire fingerprint a stamp of that version carries. A released line is never edited.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Line {
    pub version: Version,
    pub wire: u64,
}

/// What an engine knows of one contract: the version its source speaks, that version's fingerprint, and
/// every released line of the first number it speaks (compiled in from the lock file).
#[derive(Clone, Copy, Debug)]
pub struct Contract {
    /// The lock file's word: `core`, or the kind's manifest word.
    pub name: &'static str,
    pub speaks: Version,
    /// The fingerprint of `speaks` as this source computes it.
    pub wire: u64,
    pub released: &'static [Line],
}

/// Why an image and an engine do not agree on a contract (interface revision C.4). The loader's refusal
/// text names both numbers.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Disagree {
    /// A different first number: "built for transport 1.x; this engine speaks 2.y".
    First { image: Version, engine: Version },
    /// The image is newer than the engine (B6): "built for transport 2.4; this engine speaks 2.3: upgrade
    /// the engine or use the plugin's build for 2.3".
    Newer { image: Version, engine: Version },
    /// The image's fingerprint is not the engine's record of that version: it was built from an
    /// unreleased or altered contract.
    Fingerprint { version: Version },
    /// The image carries a version no released line names, and this engine accepts only released lines
    /// (a dev-built plugin on a release engine).
    Unreleased { version: Version },
}

/// Whether an engine may accept an image stamped with the next unreleased version of a contract.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Build {
    /// A dev engine: the latest interface, released or not (B12: "just latest in dev").
    Dev,
    /// An engine built for release: released lines only.
    Release,
}

impl Contract {
    /// The load check of one contract, in the order of interface revision C.4: first equal; second not
    /// above the engine's; the fingerprint equal to the engine's record of exactly that version.
    pub const fn agree(&self, build: Build, image: Version, wire: u64) -> Result<(), Disagree> {
        if image.first != self.speaks.first {
            return Err(Disagree::First {
                image,
                engine: self.speaks,
            });
        }
        if image.second > self.speaks.second {
            return Err(Disagree::Newer {
                image,
                engine: self.speaks,
            });
        }
        let mut i = 0;
        while i < self.released.len() {
            let line = self.released[i];
            if line.version.first == image.first && line.version.second == image.second {
                return if line.wire == wire {
                    Ok(())
                } else {
                    Err(Disagree::Fingerprint { version: image })
                };
            }
            i += 1;
        }
        // No released line names this version: it is the unreleased one this source speaks, or nothing.
        match build {
            Build::Dev if image.second == self.speaks.second => {
                if wire == self.wire {
                    Ok(())
                } else {
                    Err(Disagree::Fingerprint { version: image })
                }
            }
            _ => Err(Disagree::Unreleased { version: image }),
        }
    }
    /// Whether an image at second number `image_second` knows an element that arrived in `since`: the
    /// engine never sends an older image what it does not know (skip), and refuses a use that needs it.
    pub const fn knows(image_second: u32, since: u32) -> bool {
        since <= image_second
    }
}

/// The core contract as this source speaks it. `released` is filled from `pins/core.pin` at the first qa
/// promotion; until then it is empty and only dev builds agree.
pub const CORE_CONTRACT: Contract = Contract {
    name: "core",
    speaks: Version {
        first: CORE,
        second: CORE_MINOR,
    },
    wire: crate::fp::CORE_FP,
    released: &[],
};

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct AbiVersion {
    pub kind: KindCode,
    pub version: u32,
}
/// The first number of `kind`'s contract.
pub const fn abi_of(kind: KindCode) -> u32 {
    match kind {
        KindCode::Store => STORE,
        KindCode::Secret => SECRET,
        KindCode::Auth => AUTH,
        KindCode::Hook => HOOK,
        KindCode::Export => EXPORT,
        KindCode::Plane => PLANE,
        KindCode::Transport => TRANSPORT,
    }
}
/// The second number of `kind`'s contract as this source speaks it.
pub const fn minor_of(kind: KindCode) -> u32 {
    match kind {
        KindCode::Store => STORE_MINOR,
        KindCode::Secret => SECRET_MINOR,
        KindCode::Auth => AUTH_MINOR,
        KindCode::Hook => HOOK_MINOR,
        KindCode::Export => EXPORT_MINOR,
        KindCode::Plane => PLANE_MINOR,
        KindCode::Transport => TRANSPORT_MINOR,
    }
}
/// `kind`'s contract version as this source speaks it.
pub const fn version_of(kind: KindCode) -> Version {
    Version {
        first: abi_of(kind),
        second: minor_of(kind),
    }
}
/// `kind`'s contract with fingerprint `wire` (`<kind>::FP`) and no released line yet: what the loader
/// checks an image's kind words against. `released` comes from `pins/<kind>.pin` at the first qa promotion.
pub const fn contract_of(kind: KindCode, wire: u64) -> Contract {
    Contract {
        name: kind.word(),
        speaks: version_of(kind),
        wire,
        released: &[],
    }
}
impl AbiVersion {
    pub const fn current(kind: KindCode) -> Self {
        AbiVersion {
            kind,
            version: abi_of(kind),
        }
    }
    /// The first number must be equal; the second is judged by `Contract::agree`.
    pub const fn accepts(self, have: u32) -> bool {
        have == self.version
    }
}

const fn number(digits: &str) -> u16 {
    let bytes = digits.as_bytes();
    assert!(!bytes.is_empty(), "an empty package version component");
    let mut value: u16 = 0;
    let mut i = 0;
    while i < bytes.len() {
        let digit = bytes[i];
        assert!(
            digit.is_ascii_digit(),
            "a package version component is decimal"
        );
        value = value * 10 + (digit - b'0') as u16;
        i += 1;
    }
    value
}

#[cfg(test)]
mod tests {
    use super::*;

    const V20: Version = Version {
        first: 2,
        second: 0,
    };
    const V21: Version = Version {
        first: 2,
        second: 1,
    };
    const ENGINE_21: Contract = Contract {
        name: "transport",
        speaks: V21,
        wire: 0xB,
        released: &[Line {
            version: V20,
            wire: 0xA,
        }],
    };

    #[test]
    fn an_older_second_number_loads_and_a_newer_one_is_refused() {
        assert_eq!(ENGINE_21.agree(Build::Release, V20, 0xA), Ok(()));
        let v22 = Version {
            first: 2,
            second: 2,
        };
        assert_eq!(
            ENGINE_21.agree(Build::Dev, v22, 0xC),
            Err(Disagree::Newer {
                image: v22,
                engine: V21
            })
        );
        let v10 = Version {
            first: 1,
            second: 0,
        };
        assert!(matches!(
            ENGINE_21.agree(Build::Dev, v10, 0xA),
            Err(Disagree::First { .. })
        ));
    }

    #[test]
    fn a_released_line_must_match_and_a_dev_stamp_needs_a_dev_engine() {
        assert_eq!(
            ENGINE_21.agree(Build::Release, V20, 0xF),
            Err(Disagree::Fingerprint { version: V20 })
        );
        assert_eq!(ENGINE_21.agree(Build::Dev, V21, 0xB), Ok(()));
        assert_eq!(
            ENGINE_21.agree(Build::Release, V21, 0xB),
            Err(Disagree::Unreleased { version: V21 })
        );
        assert!(Contract::knows(1, 1) && !Contract::knows(0, 1));
    }
}
