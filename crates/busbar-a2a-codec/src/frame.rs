// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE ENVELOPE FRAME, and the operator-rewrite seat over it.
//!
//! An A2A message crosses the plane face inside an ENVELOPE: a direction, a set of envelope metadata
//! entries, and the message body the plane will carry. The body is the protocol's and the codec has
//! no opinion about its shape — it is an opaque [`serde_json::Value`] here, exactly as the wire
//! canonicalization treats it — but the ENVELOPE around it is where an operator gets to act: add a
//! routing header, redact one, stamp a correlation id. [`Frame`] is that envelope, named once so the
//! rewrite seat and the plane that applies it spell it the same way.
//!
//! ## Two seats, and the difference is the whole point
//!
//! - A [`Transform`] MAY REWRITE the frame. It is the operator-rewrite seat: it takes the frame and
//!   hands back the frame that carries on, so a chain of them composes left to right and the last
//!   one's output is what the plane sends or receives.
//! - A [`Tap`] MAY ONLY OBSERVE. It is handed the frame by shared reference and returns nothing, so
//!   an audit or a metric can watch what crosses the face without being able to change it. A tap that
//!   could rewrite would be a transform wearing a name that promised it would not, which is exactly
//!   the confusion keeping the two traits apart prevents.
//!
//! Taps run BEFORE the transforms in [`rewrite`], so what they observe is the frame as it ARRIVED,
//! not a rewrite of it — an audit of what an operator's transforms then changed has to see the input
//! they changed it from.
//!
//! ## Why this is codec and not plane
//!
//! The seat names nothing that opens anything — no socket, no HTTP, no store — so it stays on the
//! pure side of the purity seam with the rest of the vocabulary. The plane crate applies these seats
//! to real bytes as they cross the wire; the SHAPE of a frame and the SEAT that rewrites it are a
//! claim about the vocabulary, read from both sides, and so are spelled here.

/// Which way a frame is crossing the plane face.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    /// Arriving at busbar from a caller or an upstream.
    Inbound,
    /// Leaving busbar toward a caller or an upstream.
    Outbound,
}

/// ONE ENVELOPE FRAME at the plane face: the direction, the operator-rewritable metadata, and the
/// opaque message body.
///
/// The metadata is an ordered list of `(key, value)` pairs rather than a map, because the order an
/// operator declared its headers in is the order they are applied and rendered, and a map would
/// hash that away. The body is carried but never inspected here — a frame is an envelope, and the
/// codec's opinions about the body live in the canonicalization module, not the rewrite seat.
#[derive(Debug, Clone, PartialEq)]
pub struct Frame {
    /// Which way this frame is crossing the face.
    pub direction: Direction,
    /// The envelope metadata an operator's transforms may add to, rewrite or drop. Ordered.
    pub metadata: Vec<(String, String)>,
    /// The message body, opaque to this seat.
    pub body: serde_json::Value,
}

impl Frame {
    /// A frame with no metadata, carrying `body` in `direction`.
    #[must_use]
    pub fn new(direction: Direction, body: serde_json::Value) -> Self {
        Frame {
            direction,
            metadata: Vec::new(),
            body,
        }
    }

    /// The first value for `key`, if the envelope carries one. First, not last: a transform that
    /// added a key ahead of an existing one meant its own to win, and the applied order is the
    /// declared order.
    #[must_use]
    pub fn get(&self, key: &str) -> Option<&str> {
        self.metadata
            .iter()
            .find(|(k, _)| k == key)
            .map(|(_, v)| v.as_str())
    }

    /// Set `key` to `value`, replacing the first existing entry for `key` in place, or appending one
    /// when there is none. Replacing in place keeps a rewrite from reordering the envelope.
    pub fn set(&mut self, key: impl Into<String>, value: impl Into<String>) {
        let key = key.into();
        let value = value.into();
        if let Some(entry) = self.metadata.iter_mut().find(|(k, _)| *k == key) {
            entry.1 = value;
        } else {
            self.metadata.push((key, value));
        }
    }

    /// Drop every entry for `key`, returning whether anything was removed — the redaction primitive.
    pub fn remove(&mut self, key: &str) -> bool {
        let before = self.metadata.len();
        self.metadata.retain(|(k, _)| k != key);
        self.metadata.len() != before
    }
}

/// THE OPERATOR-REWRITE SEAT: a thing that may rewrite a frame as it crosses the face.
///
/// It takes the frame BY VALUE and returns the frame that carries on, so a transform owns the frame
/// for the length of its rewrite and a chain of them threads one frame through, each seeing the
/// previous one's output. An implementation that changes nothing returns its argument unchanged,
/// which is a no-op rewrite rather than a special case.
pub trait Transform {
    /// Rewrite `frame`, returning the frame to carry on.
    fn transform(&self, frame: Frame) -> Frame;
}

/// THE OBSERVE-ONLY SEAT: a thing that may look at a frame but never change it.
///
/// It is handed the frame by shared reference and returns nothing, so an audit trail or a metric can
/// watch the face without being able to steer it. That it CANNOT rewrite is the guarantee — a tap is
/// where "watch everything, change nothing" is stated in the type.
pub trait Tap {
    /// Observe `frame`. Returns nothing: a tap changes nothing.
    fn tap(&self, frame: &Frame);
}

/// RUN the seats over one frame: every tap observes the frame as it ARRIVED, then every transform
/// rewrites it in order, and the last transform's output is returned.
///
/// The taps run first and against the input so an observer sees what the operator's transforms then
/// changed it FROM; the transforms run in declaration order so composing them is left to right, the
/// order an operator reading the config would expect.
#[must_use]
pub fn rewrite(frame: Frame, taps: &[&dyn Tap], transforms: &[&dyn Transform]) -> Frame {
    for tap in taps {
        tap.tap(&frame);
    }
    transforms
        .iter()
        .fold(frame, |frame, transform| transform.transform(frame))
}

#[cfg(test)]
#[path = "tests/frame_tests.rs"]
mod frame_tests;
