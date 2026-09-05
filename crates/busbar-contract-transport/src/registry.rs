// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The transport kind's ABI generation, the fact keys the kernel reserves, and the boot check that
//! a composed stack is the stack every layer declared.
//!
//! All three are read by transports and by the composition root that wires them, and by nobody who
//! writes a plane. Each of them is a declaration that used to be a comment: a generation nobody
//! compared, a key three planes each guessed at, a layering nothing verified.

use core::fmt;

/// The transport kind's ABI generation.
///
/// Transports are in-tree and never dynamically loaded, so there is no loader window to police —
/// but the ABI-surface scan needs something to compare against, and a constant every transport
/// names is the difference between one generation and each crate having invented its own. It sits
/// beside the store's for the same reason: a kind's ABI is the kind's, not a plugin's.
pub const TRANSPORT_ABI: crate::AbiVersion = crate::AbiVersion(1);

/// The transport fact keys the kernel reserves, spelled once.
///
/// Transport facts are open vocabulary, which is right for a transport's own facts. These six are
/// not a transport's own: they are the structural values the arrival grammar already resolves
/// against, and a plane cannot see a connection, so the request target reaches it as one of these
/// or not at all. With nothing pinning the spelling, three planes each guessed `"path"` and said so
/// in a comment, and the boot check that would have caught a fourth guessing something else had
/// nothing to compare.
///
/// A transport that publishes one of these names the constant. A transport that publishes something
/// of its own names it whatever it likes, and none of this applies.
pub mod facts {
    /// The request target's path.
    pub const PATH: &str = "path";
    /// The request method, where the transport has one.
    pub const METHOD: &str = "method";
    /// The authority the request named.
    pub const AUTHORITY: &str = "authority";
    /// The protocol negotiated during the handshake.
    pub const ALPN: &str = "alpn";
    /// The server name offered during the handshake.
    pub const SNI: &str = "sni";
    /// The peer's source address as the bottom layer saw it.
    pub const PEER: &str = "peer";

    /// Every reserved key, for the registration check and the boot cell that walks them.
    pub const RESERVED: &[&str] = &[PATH, METHOD, AUTHORITY, ALPN, SNI, PEER];

    /// Whether a key is one the kernel reserves.
    #[must_use]
    pub fn is_reserved(key: &str) -> bool {
        RESERVED.contains(&key)
    }

    /// The first reserved key a transport publishes without having declared it.
    ///
    /// Run at registration, over the transport's own `TRANSPORT_FACTS` and the keys it actually
    /// writes. A reserved key published but not declared is a value a plane reads and no boot check
    /// knows about, which is the failure this module exists to make impossible.
    #[must_use]
    pub fn undeclared<'a>(declared: &[&'a str], published: &[&'a str]) -> Option<&'a str> {
        published
            .iter()
            .copied()
            .find(|key| is_reserved(key) && !declared.contains(key))
    }
}

/// One registered transport, as the registry holds it for the boot check.
///
/// The declarations are associated constants, which a trait object cannot read; this is them as
/// data, recorded at registration by the composition root that named the transport. Nothing here is
/// derived — every field is what the crate declared or what the root wired — because a check that
/// re-derived its own inputs would agree with itself for free.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Registered {
    /// The transport's registry key.
    pub key: &'static str,
    /// The layers it declares it can be built over.
    pub composes_over: &'static [&'static str],
    /// The layer it was ACTUALLY built over, where the root composed it over one.
    pub composed_over: Option<&'static str>,
}

/// A composition the registry will not boot on.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CompositionError {
    /// A transport declares it composes over a layer no registered transport provides.
    ///
    /// A declaration nothing checks is the frame-honesty problem one layer up: the stack a node
    /// reports is the stack its declarations describe, and a name that resolves to nothing means
    /// the description was never true.
    UnregisteredLayer {
        /// The transport that declared it.
        transport: &'static str,
        /// The layer it named.
        layer: &'static str,
    },
    /// A transport was composed over a layer it does not declare.
    ///
    /// The other direction of the same rule: a declared composition must be the one actually used,
    /// or the declaration describes a node nobody is running.
    UndeclaredComposition {
        /// The transport that was composed.
        transport: &'static str,
        /// What it was actually built over.
        used: &'static str,
    },
    /// Two transports registered under one key.
    DuplicateKey(&'static str),
}

impl fmt::Display for CompositionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnregisteredLayer { transport, layer } => write!(
                f,
                "transport `{transport}` composes over `{layer}`, which no registered transport \
                 provides"
            ),
            Self::UndeclaredComposition { transport, used } => write!(
                f,
                "transport `{transport}` was composed over `{used}`, which it does not declare"
            ),
            Self::DuplicateKey(key) => {
                write!(f, "two transports registered under the key `{key}`")
            }
        }
    }
}

impl std::error::Error for CompositionError {}

/// The boot check over a registry's transports: every declared layer exists, and every composition
/// that happened was declared.
///
/// Run once, at boot, after configuration is read. Both halves matter and neither implies the
/// other: a transport can declare a layer nobody registered, and a root can compose a transport
/// over a layer it never declared. Before this ran, `COMPOSES_OVER` was a comment with a type.
///
/// # Errors
///
/// Two transports share a key, a declared layer names no registered transport, or a transport was
/// built over a layer it does not declare.
pub fn check_composition(registered: &[Registered]) -> Result<(), CompositionError> {
    for (i, r) in registered.iter().enumerate() {
        if registered[..i].iter().any(|other| other.key == r.key) {
            return Err(CompositionError::DuplicateKey(r.key));
        }
    }
    for r in registered {
        for layer in r.composes_over {
            if !registered.iter().any(|other| other.key == *layer) {
                return Err(CompositionError::UnregisteredLayer {
                    transport: r.key,
                    layer,
                });
            }
        }
        if let Some(used) = r.composed_over {
            if !r.composes_over.contains(&used) {
                return Err(CompositionError::UndeclaredComposition {
                    transport: r.key,
                    used,
                });
            }
        }
    }
    Ok(())
}
