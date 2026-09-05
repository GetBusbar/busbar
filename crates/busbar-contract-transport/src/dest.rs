// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Where a dial lands.
//!
//! The one piece of the destination vocabulary that is the TRANSPORT's rather than the plane's: a
//! plane says which upstream a unit wants, and this is how the family that dials it spells the
//! place. It is here rather than in the contract because reading it is a transport author's job —
//! the certificate name a socket family offers, the argument vector a process family spawns under,
//! the method a call-per-path family needs — and none of those are questions a plane answers.

/// Where a dial lands, as the transport family that dials it spells it.
///
/// One opaque `host` string was read three incompatible ways by three transports: as a socket
/// address whose IP doubled as the offered certificate name, as an absolute program path with no
/// argument vector and no environment, and as an address a method name had nowhere to sit beside.
/// The families are genuinely different objects, so they are different arms, and every arm carries
/// exactly what its family needs to dial without guessing.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize)]
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
            _ => None,
        }
    }

    /// The argument vector the program is spawned with. Empty for every other family.
    #[must_use]
    pub const fn args(&self) -> &'static [&'static str] {
        match self {
            Self::Program { args, .. } => args,
            _ => &[],
        }
    }

    /// The environment the program is spawned under. Empty for every other family.
    #[must_use]
    pub const fn env(&self) -> &'static [(&'static str, &'static str)] {
        match self {
            Self::Program { env, .. } => env,
            _ => &[],
        }
    }

    /// The method name, for the family whose wire needs one.
    #[must_use]
    pub const fn method(&self) -> Option<&'static str> {
        match self {
            Self::Grpc { method, .. } => Some(method),
            _ => None,
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
