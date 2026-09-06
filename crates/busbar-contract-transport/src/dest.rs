// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Where a dial lands.
//!
//! The one piece of the destination vocabulary that is the TRANSPORT's rather than the plane's: a
//! plane says which upstream a unit wants, and this is how the family that dials it spells the
//! place. It is here rather than in the contract because reading it is a transport author's job —
//! the certificate name a socket family offers, the argument vector a process family spawns under,
//! the method a call-per-path family needs — and none of those are questions a plane answers.

use core::fmt;

/// Where a dial lands, as the transport family that dials it spells it.
///
/// Every reader below matches on all three arms by name rather than falling through a catch-all.
/// A fourth family added to this enum has to be answered for at each reader, which is the point of
/// a closed vocabulary: a catch-all would silently give the new family no program, no arguments,
/// no environment and no method, and the first thing anyone would learn is that it failed to dial.
///
/// One opaque `host` string was read three incompatible ways by three transports: as a socket
/// address whose IP doubled as the offered certificate name, as an absolute program path with no
/// argument vector and no environment, and as an address a method name had nowhere to sit beside.
/// The families are genuinely different objects, so they are different arms, and every arm carries
/// exactly what its family needs to dial without guessing.
///
/// The `Program` arm's environment is the one secret-carrying field on this type, so neither the
/// `Debug` nor the serialization is derived: both say which names are set and how long each value
/// was, and neither says a value. A transport author's log line and a configuration dump are the
/// two places an upstream address is formatted, and both are outside this tree's reading.
#[derive(Clone, Copy, PartialEq, Eq, serde::Serialize)]
pub enum UpstreamAddress {
    /// A socket the byte-stream families connect to: `tcp`, `tls`, `http`, `ws`.
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
    },
    /// A gRPC method on a socket: the family whose wire names every call by a path.
    Grpc {
        /// The dial target as configured.
        authority: &'static str,
        /// The name a presented certificate is checked against, where one is named.
        sni: Option<&'static str>,
        /// The fully qualified method, `/package.Service/Method`.
        method: &'static str,
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
            Self::Socket { authority, sni } => f
                .debug_struct("Socket")
                .field("authority", authority)
                .field("sni", sni)
                .finish(),
            Self::Program { path, args, env } => f
                .debug_struct("Program")
                .field("path", path)
                .field("args", args)
                .field("env", &EnvNames(env))
                .finish(),
            Self::Grpc {
                authority,
                sni,
                method,
            } => f
                .debug_struct("Grpc")
                .field("authority", authority)
                .field("sni", sni)
                .field("method", method)
                .finish(),
        }
    }
}

impl UpstreamAddress {
    /// The dial target, for the two families that connect to a socket.
    #[must_use]
    pub const fn authority(&self) -> Option<&'static str> {
        match self {
            Self::Socket { authority, .. } | Self::Grpc { authority, .. } => Some(authority),
            Self::Program { .. } => None,
        }
    }

    /// The name a presented certificate is checked against, where the deployment named one.
    ///
    /// `tls` reads this and nothing else: with no name declared it has no honest basis for one, and
    /// offering the pinned address in its place is the mismatch this arm exists to stop.
    #[must_use]
    pub const fn sni(&self) -> Option<&'static str> {
        match self {
            Self::Socket { sni, .. } | Self::Grpc { sni, .. } => *sni,
            Self::Program { .. } => None,
        }
    }

    /// The program to spawn, for the family whose upstream is a process.
    #[must_use]
    pub const fn program(&self) -> Option<&'static str> {
        match self {
            Self::Program { path, .. } => Some(path),
            Self::Socket { .. } | Self::Grpc { .. } => None,
        }
    }

    /// The argument vector the program is spawned with. Empty for every other family.
    #[must_use]
    pub const fn args(&self) -> &'static [&'static str] {
        match self {
            Self::Program { args, .. } => args,
            Self::Socket { .. } | Self::Grpc { .. } => &[],
        }
    }

    /// The environment the program is spawned under. Empty for every other family.
    #[must_use]
    pub const fn env(&self) -> &'static [(&'static str, &'static str)] {
        match self {
            Self::Program { env, .. } => env,
            Self::Socket { .. } | Self::Grpc { .. } => &[],
        }
    }

    /// The method name, for the family whose wire needs one.
    #[must_use]
    pub const fn method(&self) -> Option<&'static str> {
        match self {
            Self::Grpc { method, .. } => Some(method),
            Self::Socket { .. } | Self::Program { .. } => None,
        }
    }

    /// A socket target with no certificate name declared. The common case, and the one a
    /// configuration that names only `host:port` produces.
    #[must_use]
    pub const fn socket(authority: &'static str) -> Self {
        Self::Socket {
            authority,
            sni: None,
        }
    }
}
