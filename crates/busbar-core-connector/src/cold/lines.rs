// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The refusal and diagnostic text of the carrier, the host's I/O, the registry view, the
//! destination judge, the dialled association and the wire rule: built only when a refusal or a
//! failure is answered, out of line.

use std::fmt::Display;
use std::io;

use busbar_contract::conn::ConnError;

use crate::registry::ViewRefusal;

/// [`crate::wire::unlayered`]'s refusal of an entry that names a transport it composes over.
#[cold]
pub(crate) fn composes_over(name: &str) -> String {
    format!(
        "transport `{name}` names a transport it composes over; no transport names another \
         (the carrier is the connector's choice from the target's scheme)"
    )
}

/// The sentence of `value`, spelled only when a refusal or failure is answered.
#[cold]
pub(crate) fn display_text(value: &dyn Display) -> String {
    format!("{value}")
}

/// `prefix` and the sentence of `value`, spelled only when a refusal or failure is answered.
#[cold]
pub(crate) fn prefixed(prefix: &str, value: &dyn Display) -> String {
    format!("{prefix}{value}")
}

/// A refusal's borrowed text, owned for the answer that carries it.
#[cold]
pub(crate) fn refusal_text(text: &str) -> String {
    text.to_owned()
}

/// The text of a carrier crossing that did not answer READY ([`crate::carrier::text`]).
#[cold]
pub(crate) fn crossing_text(error: &[u8]) -> String {
    format!("{}", String::from_utf8_lossy(error))
}

/// A failed I/O op's sentence.
#[cold]
pub(crate) fn io_error_text(error: &io::Error) -> String {
    format!("{error}")
}

/// The refusal of a unix-domain dial no socket answers.
#[cfg(unix)]
#[cold]
pub(crate) fn no_socket_listens(path: &str, error: &io::Error) -> String {
    format!("no socket listens at `{path}`: {error}")
}

/// The refusal of a dial to an address that is not an `ip:port`.
#[cold]
pub(crate) fn not_dialable(addr: &str) -> String {
    format!("`{addr}` is not an address the connector dials without resolving a name")
}

/// A failed channel publication of a dialled association.
#[cold]
pub(crate) fn channel_publication_failed(error: ConnError) -> String {
    format!("upstream channel publication failed: {error:?}")
}

/// The registry view's refusal of an entry that states no claim.
#[cold]
pub(crate) fn no_claim(entry: &str) -> ViewRefusal {
    ViewRefusal::NoClaim {
        entry: entry.to_owned(),
    }
}

/// The registry view's refusal of a scheme two entries claim.
#[cold]
pub(crate) fn claimed_twice(scheme: &str, first: &str, second: &str) -> ViewRefusal {
    ViewRefusal::ClaimedTwice {
        scheme: scheme.to_owned(),
        first: first.to_owned(),
        second: second.to_owned(),
    }
}

/// The registry view's refusal of an entry composing over a layer no entry serves.
#[cold]
pub(crate) fn unserved_layer(entry: &str, layer: &str) -> ViewRefusal {
    ViewRefusal::UnservedLayer {
        entry: entry.to_owned(),
        layer: layer.to_owned(),
    }
}
