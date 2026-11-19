// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE RETIRED CARRIER PLUGINS: `busbar-transport-tcp` and `busbar-transport-stdio` (owner decision 16).
//!
//! In 1.6.0 the engine owns the carrier: it listens, dials, runs child-process servers and frames their lines
//! itself, so the two plugins that used to carry raw TCP and a spawned program's pipes have nothing left to do
//! and are no longer part of the distribution. A deployment may still NAME one of them: an image of it left in
//! the plugins directory is the one place where naming it would otherwise act (an entry of a publisher's
//! `plugins:` scope and an `insecure_transport` acceptance keyed by its instance are lookups that simply never
//! match). The rule is the whole of this module: THE NAME IS ACCEPTED AND IGNORED, with one notice per carrier
//! per boot (`min3_boot::admit_dropped_images`). It is never a refusal (old settings are
//! migrated, never refused), and it is never an instance: nothing is admitted, opened or dealt settings.
//!
//! What a deployment relied on is unchanged, and the notice says so: a `transport: stdio` upstream is served
//! by the engine (its line limit is the engine's fixed 4 MiB, where the plugin's was a setting), and every TCP
//! listener and dial is the engine's own socket.
//!
//! No plugin name is read anywhere else in the root to decide behaviour (ABI-MIN3-INTERFACE §15.8); these two
//! are named here because they name things that no longer exist, which no image can state about itself.

/// A carrier plugin the distribution no longer has.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum Retired {
    /// `busbar-transport-tcp`: raw TCP.
    Tcp,
    /// `busbar-transport-stdio`: a spawned program's pipes.
    Stdio,
}

/// Every spelling a deployment can hold for each: the module word, the transport-qualified word, the
/// repository and logic-crate name, and the dropped-in library's crate name. Compared after [`canonical`].
const NAMES: [(&str, Retired); 8] = [
    ("tcp", Retired::Tcp),
    ("transport-tcp", Retired::Tcp),
    ("busbar-transport-tcp", Retired::Tcp),
    ("busbar-transport-tcp-plugin", Retired::Tcp),
    ("stdio", Retired::Stdio),
    ("transport-stdio", Retired::Stdio),
    ("busbar-transport-stdio", Retired::Stdio),
    ("busbar-transport-stdio-plugin", Retired::Stdio),
];

/// `name` as the table spells names: a library file's `lib` prefix and its extension dropped, `_` read as `-`,
/// ASCII case folded. A path is not a name: only its last component is read.
fn canonical(name: &str) -> String {
    let leaf = name.rsplit(['/', '\\']).next().unwrap_or(name);
    let stem = leaf
        .strip_suffix(".so")
        .or_else(|| leaf.strip_suffix(".dylib"))
        .or_else(|| leaf.strip_suffix(".dll"))
        .unwrap_or(leaf);
    let stem = if stem.len() != leaf.len() {
        stem.strip_prefix("lib").unwrap_or(stem)
    } else {
        stem
    };
    stem.chars()
        .map(|c| {
            if c == '_' {
                '-'
            } else {
                c.to_ascii_lowercase()
            }
        })
        .collect()
}

/// The retired carrier `name` names, in any of its spellings; `None` for every other name.
pub(crate) fn retired(name: &str) -> Option<Retired> {
    let name = canonical(name);
    NAMES
        .iter()
        .find(|(spelled, _)| *spelled == name)
        .map(|(_, carrier)| *carrier)
}

impl Retired {
    /// The repository name, as the notice and the migration note spell it.
    pub(crate) fn plugin(self) -> &'static str {
        match self {
            Retired::Tcp => "busbar-transport-tcp",
            Retired::Stdio => "busbar-transport-stdio",
        }
    }

    /// The one notice for this carrier: where it was named, that it is ignored, and what serves instead.
    pub(crate) fn notice(self, place: &str) -> String {
        let serves = match self {
            Retired::Tcp => {
                "since 1.6.0 the engine itself listens on and dials every TCP socket; nothing changes \
                 for a listener or an upstream"
            }
            Retired::Stdio => {
                "since 1.6.0 the engine itself runs and frames `transport: stdio` child-process \
                 servers; a line may be at most 4 MiB (the plugin's line limit setting is no longer read)"
            }
        };
        format!(
            "`{}` ({place}) is accepted and ignored: {serves}. Remove it at your convenience.",
            self.plugin()
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_spelling_of_the_two_carriers_is_recognised() {
        for name in [
            "tcp",
            "transport-tcp",
            "busbar-transport-tcp",
            "busbar_transport_tcp",
            "busbar-transport-tcp-plugin",
            "libbusbar_transport_tcp_plugin.so",
            "/opt/busbar/plugins/libbusbar_transport_tcp_plugin.so",
            "busbar_transport_tcp_plugin.dll",
            "Busbar-Transport-TCP",
        ] {
            assert_eq!(retired(name), Some(Retired::Tcp), "{name}");
        }
        for name in [
            "stdio",
            "transport-stdio",
            "busbar-transport-stdio",
            "busbar_transport_stdio_plugin",
            "libbusbar_transport_stdio_plugin.dylib",
        ] {
            assert_eq!(retired(name), Some(Retired::Stdio), "{name}");
        }
    }

    #[test]
    fn no_living_plugin_and_no_near_miss_is_retired() {
        for name in [
            "",
            "http",
            "busbar-transport-http",
            "busbar-transport-ws",
            "busbar-transport-grpc",
            "busbar-transport-webrtc",
            "busbar-transport-tcp2",
            "busbar-transport-tcps",
            "tcp-proxy",
            "stdio-bridge",
            "my-tcp",
            "busbar-transport",
            // `lib` is a library file's prefix, not a name's: a plugin called `libtcp` is its own plugin.
            "libtcp",
            "libstdio",
        ] {
            assert_eq!(retired(name), None, "{name}");
        }
    }

    #[test]
    fn the_notice_never_refuses_and_names_what_serves_instead() {
        for carrier in [Retired::Tcp, Retired::Stdio] {
            let notice = carrier.notice("x");
            assert!(notice.contains("accepted and ignored"), "{notice}");
            assert!(notice.contains("the engine itself"), "{notice}");
            for word in ["refus", "error", "fail", "must"] {
                assert!(!notice.contains(word), "{word}: {notice}");
            }
        }
    }
}
