// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Initial native listener suppliers and upgrade targets from one complete serving generation, and the
//! outbound carrier table: which admitted transport carries each dial carrier.

use std::sync::Arc;

use busbar_plugin_abi::plane::{
    CARRIER_DEFAULT, CARRIER_GRPC, CARRIER_HTTP, CARRIER_RTC, CARRIER_STDIO, CARRIER_WEBSOCKET,
};
use busbar_plugin_abi::transport::{FB_CLIENT, FB_DATAGRAM, FB_SERVER};
use busbar_plugin_abi::types::KindCode;

use super::min3_boot::transports::ServedTransport;

/// The four carriers a transport image can be assigned, with the word every printout and the manifest's
/// `[package.metadata.busbar.carriers]` key names each by. `CARRIER_STDIO` is core's own child-process path
/// and `CARRIER_DEFAULT` means "the route's carrier": neither is ever a slot of the table.
const CARRIERS: [(u32, &str); 4] = [
    (CARRIER_HTTP, "http"),
    (CARRIER_GRPC, "grpc"),
    (CARRIER_WEBSOCKET, "websocket"),
    (CARRIER_RTC, "rtc"),
];

/// One carrier the build assigns, generated from `[package.metadata.busbar.carriers]` into `$OUT_DIR/linked.rs`
/// (`LINKED_CARRIERS`, `src/linked_gen.rs`): the carrier number and the admission of the linked row's own header,
/// which states the image's identity. The root's source names no plugin.
pub(crate) struct LinkedCarrier {
    pub(crate) carrier: u32,
    pub(crate) admit: fn() -> Result<
        busbar_plugin_loader::admit::Admitted,
        busbar_plugin_loader::refusal::Refusal,
    >,
}

/// Why a carrier number has no supplier. The number arrives in a plane's own record, so every value is checked
/// before it indexes anything; no value panics.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CarrierRefused {
    /// `CARRIER_DEFAULT` reached the table: the route's carrier was not resolved first (a core fault).
    Unresolved,
    /// `CARRIER_STDIO` reached the table: the child-process carrier is core's, never a framer's (a core fault).
    Stdio,
    /// Not a carrier number at all (a plane fault: the exchange is refused and charged to the plane).
    OutOfRange(u32),
    /// A carrier this build assigns to no image. Configuration validation refuses a route that needs it, so at
    /// request time this is a core fault, never a fallback to another image.
    NoSupplier(u32),
}

impl std::fmt::Display for CarrierRefused {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unresolved => f.write_str(
                "carrier 0 (the route's default) reached the carrier table unresolved: a core fault",
            ),
            Self::Stdio => f.write_str(
                "carrier 5 (a child process) is core's own carrier, never a transport's: a core fault",
            ),
            Self::OutOfRange(carrier) => {
                write!(f, "carrier {carrier} is not a carrier: the plane's exchange is refused")
            }
            Self::NoSupplier(carrier) => write!(
                f,
                "carrier `{}` has no supplying transport in this build",
                word(*carrier)
            ),
        }
    }
}

/// The table slot of a carrier number: the checked read every lookup goes through.
fn slot(carrier: u32) -> Result<usize, CarrierRefused> {
    match carrier {
        CARRIER_DEFAULT => Err(CarrierRefused::Unresolved),
        CARRIER_HTTP => Ok(0),
        CARRIER_GRPC => Ok(1),
        CARRIER_WEBSOCKET => Ok(2),
        CARRIER_RTC => Ok(3),
        CARRIER_STDIO => Err(CarrierRefused::Stdio),
        other => Err(CarrierRefused::OutOfRange(other)),
    }
}

fn word(carrier: u32) -> &'static str {
    CARRIERS
        .iter()
        .find(|(number, _)| *number == carrier)
        .map_or("?", |(_, word)| *word)
}

/// One supplier per carrier, indexed by carrier number minus one (`slot`). Built once at boot and held for the
/// process: transports are opened once, and a reload whose transport images or settings differ is refused
/// (`TransportSources::check`).
#[derive(Clone)]
pub(crate) struct Carriers<T> {
    slots: [Option<T>; 4],
}

impl<T> Carriers<T> {
    fn empty() -> Self {
        Self {
            slots: [None, None, None, None],
        }
    }

    /// The supplier of `carrier`, by a checked read: 0, the child-process carrier, a number out of range and an
    /// unassigned carrier are each refused.
    pub(crate) fn get(&self, carrier: u32) -> Result<&T, CarrierRefused> {
        self.slots
            .get(slot(carrier)?)
            .and_then(Option::as_ref)
            .ok_or(CarrierRefused::NoSupplier(carrier))
    }
}

impl Carriers<Arc<str>> {
    /// The table of image identities from (carrier, identity) pairs. Refused: a pair whose carrier is not one of
    /// the four, a carrier assigned twice, and one image under two carriers (an image frames one carrier: core
    /// cannot tell a framer which carrier a connection is for, and an instance has one client offer and one set
    /// of default head lines).
    fn of(
        pairs: impl IntoIterator<Item = Result<(u32, Arc<str>), String>>,
    ) -> Result<Self, String> {
        let mut table = Self::empty();
        for pair in pairs {
            let (carrier, identity) = pair?;
            let at = slot(carrier).map_err(|why| format!("an assigned carrier: {why}"))?;
            if let Some(held) = table.slots.get(at).and_then(Option::as_ref) {
                return Err(format!(
                    "carrier `{}` is assigned twice, to `{held}` and `{identity}`",
                    word(carrier)
                ));
            }
            if let Some(other) = table
                .slots
                .iter()
                .zip(CARRIERS)
                .find_map(|(held, (number, _))| {
                    held.as_ref()
                        .filter(|held| **held == identity)
                        .map(|_| number)
                })
            {
                return Err(format!(
                    "transport image `{identity}` is assigned two carriers, `{}` and `{}`: one image frames one \
                     carrier",
                    word(other),
                    word(carrier)
                ));
            }
            if let Some(entry) = table.slots.get_mut(at) {
                *entry = Some(identity);
            }
        }
        Ok(table)
    }

    /// Validation on DESCRIBED facts (nothing is opened: `--validate` opens nothing): every assigned image is an
    /// admitted transport with the carrier's role, the client role for HTTP, gRPC and WebSocket and the datagram
    /// role for WebRTC. `described` answers an identity's kind and describe facts, `None` when it is not admitted.
    fn check(&self, described: impl Fn(&str) -> Option<(KindCode, u64)>) -> Result<(), String> {
        for (carrier, word) in CARRIERS {
            let Ok(identity) = self.get(carrier) else {
                continue;
            };
            let (kind, facts) = described(&**identity).ok_or_else(|| {
                format!("carrier `{word}`: its transport image `{identity}` is not admitted")
            })?;
            let role = if carrier == CARRIER_RTC {
                facts & FB_DATAGRAM != 0
            } else {
                facts & FB_CLIENT != 0 && facts & FB_DATAGRAM == 0
            };
            if kind != KindCode::Transport || !role {
                return Err(format!(
                    "carrier `{word}`: image `{identity}` is not a transport with the {} role",
                    if carrier == CARRIER_RTC {
                        "datagram"
                    } else {
                        "stream client"
                    }
                ));
            }
        }
        Ok(())
    }
}

/// The carrier a plane claim's transport word means (the words planes claimed on with the old transports' scheme
/// claims, dial decision v2 section 3.1): `http`, `https` and `sse` ride HTTP; `grpc` gRPC; `ws`, `wss` and
/// `websocket` WebSocket; `webrtc` and `rtc` WebRTC. Any other word names no carrier.
pub(crate) fn carrier_of_claim(word: &str) -> Option<u32> {
    match word.to_ascii_lowercase().as_str() {
        "http" | "https" | "sse" => Some(CARRIER_HTTP),
        "grpc" => Some(CARRIER_GRPC),
        "ws" | "wss" | "websocket" => Some(CARRIER_WEBSOCKET),
        "webrtc" | "rtc" => Some(CARRIER_RTC),
        _ => None,
    }
}

impl<T> Carriers<T> {
    /// Whether this table has a supplier for the carrier a claim's transport `word` means.
    pub(crate) fn serves_claim(&self, word: &str) -> bool {
        carrier_of_claim(word).is_some_and(|carrier| self.get(carrier).is_ok())
    }
}

/// The build's assignment: each generated row admitted (a read of its static header) for its identity.
pub(crate) fn assigned(rows: &[LinkedCarrier]) -> Result<Carriers<Arc<str>>, String> {
    Carriers::of(rows.iter().map(|row| {
        (row.admit)()
            .map(|image| (row.carrier, Arc::from(image.identity())))
            .map_err(|refusal| format!("an assigned carrier's image: {refusal}"))
    }))
}

/// Configuration validation (every config read: boot, reload, admin apply, `--validate`): the build's
/// assignment holds against these admitted images' described facts.
pub(crate) fn validate(images: &busbar_plugin_loader::instance::Images) -> Result<(), String> {
    assigned(crate::LINKED_CARRIERS)?
        .check(|identity| images.described(identity).map(|one| (one.kind, one.facts)))
}

/// `busbar --list-plugins`: each carrier and the image the build assigns it, or `none`.
pub(crate) fn listing() -> Result<Vec<String>, String> {
    let carriers = assigned(crate::LINKED_CARRIERS)?;
    Ok(CARRIERS
        .iter()
        .map(|(carrier, word)| match carriers.get(*carrier) {
            Ok(identity) => format!("  {word:<10} {identity} (assigned by the build)"),
            Err(_) => format!("  {word:<10} none"),
        })
        .collect())
}

/// The already admitted/opened transport table. Connections retain this immutable generation through
/// security preparation and any upgrade; publishing a new table cannot change their selected instance.
#[derive(Clone)]
pub(crate) struct NativeFramers {
    served: Arc<[ServedTransport]>,
    /// Each carrier's supplier, as its index into `served`: a lookup borrows from the generation the
    /// connection already holds, with no reference count taken per exchange.
    carriers: Carriers<usize>,
}

impl NativeFramers {
    /// Consume the boot's complete transport table after its protocol declarations were validated.
    pub(crate) fn new(served: Vec<ServedTransport>) -> Self {
        Self {
            served: served.into(),
            carriers: Carriers::empty(),
        }
    }

    /// Bind each assigned carrier to its opened instance (named by the image identity). An assigned image with
    /// no opened instance refuses the boot.
    pub(crate) fn carrying(mut self, assigned: &Carriers<Arc<str>>) -> Result<Self, String> {
        for (carrier, word) in CARRIERS {
            let Ok(identity) = assigned.get(carrier) else {
                continue;
            };
            let index = self
                .served
                .iter()
                .position(|one| one.instance == *identity)
                .ok_or_else(|| {
                    format!(
                        "carrier `{word}`: its transport image `{identity}` has no opened instance"
                    )
                })?;
            let at = slot(carrier).map_err(|why| why.to_string())?;
            if let Some(entry) = self.carriers.slots.get_mut(at) {
                *entry = Some(index);
            }
        }
        Ok(self)
    }

    /// The instance that carries `carrier`, borrowed from this generation. The number is untrusted (it comes from
    /// a plane's record): 0, the child-process carrier, a number out of range and an unassigned carrier are refused.
    pub(crate) fn for_carrier(&self, carrier: u32) -> Result<&ServedTransport, CarrierRefused> {
        self.served
            .get(*self.carriers.get(carrier)?)
            .ok_or(CarrierRefused::NoSupplier(carrier))
    }

    /// The boot's one line stating the assignment: each carrier's instance, or `none`.
    pub(crate) fn carrier_line(&self) -> String {
        let each: Vec<String> = CARRIERS
            .iter()
            .map(|(carrier, word)| {
                let supplier = self
                    .for_carrier(*carrier)
                    .map_or("none", |one| &*one.instance);
                format!("{word}={supplier}")
            })
            .collect();
        format!(
            "outbound carriers (assigned by the build): {}",
            each.join(" ")
        )
    }

    /// The instance declaring D_PROTOCOL `protocol` (an upgrade target), if one is admitted.
    pub(crate) fn for_protocol(&self, protocol: &str) -> Option<ServedTransport> {
        super::min3_boot::transports::declaring(&self.served, protocol).cloned()
    }

    /// Exactly one instance explicitly declares this configuration slot. Image names, ALPN and
    /// upgrade protocols are never fallback selectors. Unknown declarations create no listeners.
    pub(crate) fn for_slot(&self, slot: &str) -> Result<ServedTransport, String> {
        let mut suppliers = self.served.iter().filter(|one| {
            one.port
                .listener_slots()
                .iter()
                .any(|declared| declared.as_ref() == slot)
        });
        let one = suppliers.next().ok_or_else(|| {
            format!("{slot}: no native transport declares this initial listener slot")
        })?;
        if let Some(other) = suppliers.next() {
            return Err(format!(
                "{slot}: native transport instances `{}` and `{}` both declare this initial listener slot",
                one.instance, other.instance
            ));
        }
        if one.port.facts() & FB_SERVER == 0 || one.port.facts() & FB_DATAGRAM != 0 {
            return Err(format!(
                "{slot}: native transport `{}` is not an accepting stream framer",
                one.instance
            ));
        }
        Ok(one.clone())
    }
}

#[cfg(test)]
#[path = "tests/min3_framers.rs"]
mod tests;
