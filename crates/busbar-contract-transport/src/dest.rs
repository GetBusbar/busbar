// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Where a dial lands.
//!
//! The one piece of the destination vocabulary that is the TRANSPORT's rather than the plane's: a
//! plane says which upstream a unit wants, and this is how the family that dials it spells the
//! place. It is here rather than in the contract because reading it is a transport author's job —
//! the certificate name a socket family offers, the argument vector a process family spawns under,
//! the method a call-per-path family declares — and none of those are questions a plane answers.

use core::fmt;

/// Where a dial lands, as the transport family that dials it spells it.
///
/// TWO SHAPES, because there are two genuinely different objects here: a peer you CONNECT to, and a
/// process you SPAWN. Nothing about an argument vector or a spawn environment is a socket's
/// business, and nothing about a certificate name is a child process's, so neither collapses into
/// the other and neither is a key on the other.
///
/// Everything a particular FAMILY needs beside its shape is a key. There was a third arm, `Grpc`,
/// which was a `Socket` plus one `method` field — and because every reader below matches the arms
/// by name rather than falling through a catch-all (deliberately: a catch-all would silently give a
/// new family no program, no arguments and no environment, and the first thing anyone would learn
/// is that it failed to dial), that one field cost six accessors an arm apiece and every reader in
/// the tree an edit. The shape was not new. Only the fact was. So the fact is now a declared entry
/// in [`UpstreamAddress::extras`]'s keyed map, under the same reserved key the arrival grammar
/// already spells a request method with, and a fourth family that needs a fact of its own adds a
/// key and edits nothing.
///
/// The map is CLAIM-DRIVEN in both directions, exactly as the reserved ingress fact keys are. A
/// transport reads the keys it understands through [`UpstreamAddress::extra`] and does not see the
/// rest — a key it has never heard of costs it nothing. A transport that CANNOT dial without a key
/// names it and refuses the destination that does not declare one, through
/// [`UpstreamAddress::missing`]; refusing is the point, because the alternative is substituting a
/// default of its own and dialling somewhere nobody named.
///
/// One opaque `host` string was read three incompatible ways by three transports: as a socket
/// address whose IP doubled as the offered certificate name, as an absolute program path with no
/// argument vector and no environment, and as an address a method name had nowhere to sit beside.
/// Each arm still carries exactly what its SHAPE needs to dial without guessing; what it needs
/// beyond that, it declares.
///
/// The `Program` arm's environment is the one secret-carrying field on this type, so neither the
/// `Debug` nor the serialization is derived: both say which names are set and how long each value
/// was, and neither says a value. The extras are not that: they are declared wire facts — a method
/// path, a stream group — that a transport author's log line is read to check, so they print whole.
/// A transport author's log line and a configuration dump are the two places an upstream address is
/// formatted, and both are outside this tree's reading.
#[derive(Clone, Copy, PartialEq, Eq, serde::Serialize)]
pub enum UpstreamAddress {
    /// A socket the byte-stream families connect to: `tcp`, `tls`, `http`, `ws`, `grpc`.
    ///
    /// `authority` is the dial target as configured (`host:port`, or a URL for the families whose
    /// dial target is one). `sni` is the name a certificate must have been issued for, where the
    /// deployment names one — the reason it is separate from `authority` is that a pinned address
    /// and the name it was resolved from are two facts, and offering the address as the name makes
    /// every certificate issued for a DNS name fail to match.
    Socket {
        /// The dial target as configured.
        authority: &'static str,
        /// The name a presented certificate is checked against, where one is named.
        sni: Option<&'static str>,
        /// What this destination declares beyond the shape, as name/value pairs.
        extras: &'static [(&'static str, &'static str)],
    },
    /// A program `stdio` spawns, with the argument vector and environment it is spawned under.
    ///
    /// The environment is named rather than inherited: a child that inherits the node's environment
    /// inherits its credentials, and an empty list is the posture a transport should default to.
    Program {
        /// The absolute path of the program to spawn.
        path: &'static str,
        /// The argument vector, not counting the program name itself.
        args: &'static [&'static str],
        /// The environment the child is spawned under, as name/value pairs.
        #[serde(serialize_with = "env_names_only")]
        env: &'static [(&'static str, &'static str)],
        /// What this destination declares beyond the shape, as name/value pairs.
        extras: &'static [(&'static str, &'static str)],
    },
}

/// Serialize an environment as the names it sets and nothing else.
///
/// A journal entry that recorded the values would be a credential at rest in a file nothing
/// rotates. The names are what a reader needs to see that the child was spawned with the variables
/// it was configured with.
fn env_names_only<S: serde::Serializer>(
    env: &&'static [(&'static str, &'static str)],
    serializer: S,
) -> Result<S::Ok, S::Error> {
    serializer.collect_seq(env.iter().map(|(name, _)| *name))
}

/// One environment entry as `Debug` may say it: the name, and how many bytes the value was.
struct EnvEntry(&'static str, usize);

impl fmt::Debug for EnvEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} = <{} bytes>", self.0, self.1)
    }
}

/// An environment as `Debug` may say it: every name, with the length of the value beside it.
struct EnvNames<'a>(&'a [(&'static str, &'static str)]);

impl fmt::Debug for EnvNames<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_list()
            .entries(
                self.0
                    .iter()
                    .map(|(name, value)| EnvEntry(name, value.len())),
            )
            .finish()
    }
}

impl fmt::Debug for UpstreamAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Socket {
                authority,
                sni,
                extras,
            } => f
                .debug_struct("Socket")
                .field("authority", authority)
                .field("sni", sni)
                .field("extras", extras)
                .finish(),
            Self::Program {
                path,
                args,
                env,
                extras,
            } => f
                .debug_struct("Program")
                .field("path", path)
                .field("args", args)
                .field("env", &EnvNames(env))
                .field("extras", extras)
                .finish(),
        }
    }
}

impl UpstreamAddress {
    /// The dial target, for the shape that connects to a socket.
    #[must_use]
    pub const fn authority(&self) -> Option<&'static str> {
        match self {
            Self::Socket { authority, .. } => Some(authority),
            Self::Program { .. } => None,
        }
    }

    /// The name a presented certificate is checked against, where the deployment named one.
    ///
    /// `tls` reads this and nothing else: with no name declared it has no honest basis for one, and
    /// offering the pinned address in its place is the mismatch this field exists to stop.
    #[must_use]
    pub const fn sni(&self) -> Option<&'static str> {
        match self {
            Self::Socket { sni, .. } => *sni,
            Self::Program { .. } => None,
        }
    }

    /// The program to spawn, for the shape whose upstream is a process.
    ///
    /// Every arm is named, here and in the accessors around it, rather than answered for by a
    /// catch-all. A catch-all answered for arms that did not exist yet, so adding a SHAPE to this
    /// enum compiled without a word — and the transport whose dial reads one of these would have
    /// taken the silence for an answer. A new shape has to come back here and say what it carries.
    /// What a new FAMILY carries is not a new shape and never reaches this file: it is a key.
    #[must_use]
    pub const fn program(&self) -> Option<&'static str> {
        match self {
            Self::Program { path, .. } => Some(path),
            Self::Socket { .. } => None,
        }
    }

    /// The argument vector the program is spawned with. Empty for a socket.
    #[must_use]
    pub const fn args(&self) -> &'static [&'static str] {
        match self {
            Self::Program { args, .. } => args,
            Self::Socket { .. } => &[],
        }
    }

    /// The environment the program is spawned under. Empty for a socket.
    #[must_use]
    pub const fn env(&self) -> &'static [(&'static str, &'static str)] {
        match self {
            Self::Program { env, .. } => env,
            Self::Socket { .. } => &[],
        }
    }

    /// What this destination declares beyond its shape, whichever shape it is.
    #[must_use]
    pub const fn extras(&self) -> &'static [(&'static str, &'static str)] {
        match self {
            Self::Socket { extras, .. } | Self::Program { extras, .. } => extras,
        }
    }

    /// One declared fact, by key. `None` for a key this destination does not declare.
    ///
    /// The reading half of the negotiation: a transport asks for the keys it understands and never
    /// sees the rest, so a destination declaring a fact for some other family costs it nothing.
    #[must_use]
    pub fn extra(&self, key: &str) -> Option<&'static str> {
        self.extras()
            .iter()
            .find(|(name, _)| *name == key)
            .map(|(_, value)| *value)
    }

    /// The first key a transport requires that this destination does not declare.
    ///
    /// The refusing half, and the same shape as `registry::facts::undeclared` one module over,
    /// because it is the same rule read from the other side. A transport that cannot dial without a
    /// key names it here and refuses; the alternative is a default of its own, which dials
    /// somewhere nobody named and reports success.
    #[must_use]
    pub fn missing<'k>(&self, required: &[&'k str]) -> Option<&'k str> {
        required
            .iter()
            .copied()
            .find(|key| self.extra(key).is_none())
    }

    /// A socket target with no certificate name and nothing declared beyond the shape. The common
    /// case, and the one a configuration that names only `host:port` produces.
    #[must_use]
    pub const fn socket(authority: &'static str) -> Self {
        Self::Socket {
            authority,
            sni: None,
            extras: &[],
        }
    }
}
