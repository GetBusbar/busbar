// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! A live stream asks for its policy through the existing operation extension blobs.

use super::check::{check_route_view, MAX_LINES};
use super::route::{RouteView, FIELD_PRESENT, FIELD_VALUE_PREFIX};
use crate::abi::auth::{check_points, POINT_HEAD_BODY};
use crate::abi::host::service::LINE_NONE;
use std::collections::HashSet;

/// A framer reply asks the host to open this stream before route matching or auth.
pub const EXT_GUEST_OPEN: &str = "guest.open";
/// The following call lends the selected generation's policy to the requesting operation.
pub const EXT_GUEST_POLICY: &str = "guest.policy";
const VERSION: u32 = 1;

/// A reply confirming that the stream may use a previously decoded policy identity.
pub const EXT_GUEST_CURRENT: &str = "guest.current";

/// A stream opening, with the policy generation already cached by its framer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Open {
    /// The plugin-local stream, bound by the host to the current framing leg.
    pub stream: u64,
    /// The cached generation, or zero when the framer needs the full policy.
    pub known_generation: u64,
}

impl Open {
    /// Encode an opening without allocation.
    #[must_use]
    pub fn encode(self) -> [u8; size_of::<u32>() + 2 * size_of::<u64>()] {
        let mut out = [0; size_of::<u32>() + 2 * size_of::<u64>()];
        out[..4].copy_from_slice(&VERSION.to_le_bytes());
        out[4..12].copy_from_slice(&self.stream.to_le_bytes());
        out[12..].copy_from_slice(&self.known_generation.to_le_bytes());
        out
    }

    /// Decode an entire opening value.
    pub fn decode(bytes: &[u8]) -> Result<Self, &'static str> {
        let mut reader = Reader(bytes);
        if reader.u32()? != VERSION {
            return Err("the stream-open version is unknown");
        }
        let open = Self {
            stream: reader.u64()?,
            known_generation: reader.u64()?,
        };
        if !reader.0.is_empty() {
            return Err("the stream-open value has trailing bytes");
        }
        Ok(open)
    }
}

/// The identity of an immutable listener policy. Acknowledging it avoids resending route rows.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Identity {
    /// The host-owned listener registration.
    pub listener: u64,
    /// Its configuration generation.
    pub generation: u64,
}

impl Identity {
    /// Encode an acknowledgement without allocation.
    pub fn encode(self) -> Result<[u8; size_of::<u32>() + 2 * size_of::<u64>()], &'static str> {
        if self.listener == 0 || self.generation == 0 {
            return Err("the policy has no listener or generation");
        }
        Ok(Open {
            stream: self.listener,
            known_generation: self.generation,
        }
        .encode())
    }

    /// Decode a whole acknowledgement; the caller still checks it against its cached policy.
    pub fn decode(bytes: &[u8]) -> Result<Self, &'static str> {
        let open = Open::decode(bytes)?;
        let identity = Self {
            listener: open.stream,
            generation: open.known_generation,
        };
        identity.encode()?;
        Ok(identity)
    }
}

/// ONE LINE OF A LISTENER'S GUEST LIST, owned, as the connector lends it to an accepting framer's
/// `begin` (`BeginIn::lines`, one `LineEntry` each; THE DESIGN §6, "Auth points and guest
/// lists", items 3 and 4): the line's id, the points its auth needs, its auth handle (minted for
/// the identity of the transport instance the listener is bound to, at the published generation),
/// the body bound at the body point, and its route in the contract's one vocabulary
/// (`abi::transport::route`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GuestLine {
    /// The line's id, as the kernel numbers it.
    pub line: u32,
    /// The auth points its auth needs (`POINT_*`); `0` for a line whose auth is `none`.
    pub points: u32,
    /// Its auth handle, owner-scoped to the listener's transport.
    pub auth: crate::abi::host::service::AuthRef,
    /// The body bound at the body point; `0` without that point.
    pub body_limit: u64,
    /// `METHOD_*` bits.
    pub methods: u32,
    /// `PATH_*`.
    pub path_form: u32,
    /// The path, in its form's spelling.
    pub path: String,
    /// Its field predicates: `(FIELD_*, lower-case name, value)`.
    pub fields: Vec<(u32, String, Vec<u8>)>,
    /// The claimant's own order among its own lines.
    pub rung: u32,
}

/// A generation's owned policy, decoded only when the generation changes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Policy {
    /// The host-owned listener registration; an instance can serve several listeners.
    pub listener: u64,
    /// The host-selected configuration generation.
    pub generation: u64,
    /// The listener's lines in match order.
    pub lines: Vec<GuestLine>,
}

fn valid(lines: &[GuestLine]) -> Result<(), &'static str> {
    if lines.len() as u64 > MAX_LINES {
        return Err("the policy exceeds the existing guest-list limit");
    }
    let mut ids = HashSet::new();
    for line in lines {
        if line.line == LINE_NONE || !ids.insert(line.line) || line.auth.is_none() {
            return Err("the policy has an absent or repeated line or auth handle");
        }
        check_points(line.points, false).map_err(|_| "the policy has invalid auth points")?;
        if (line.points & POINT_HEAD_BODY != 0) != (line.body_limit != 0) {
            return Err("the policy body limit disagrees with its auth points");
        }
        if line
            .fields
            .iter()
            .any(|(op, _, _)| !matches!(*op, FIELD_PRESENT | FIELD_VALUE_PREFIX))
        {
            return Err("the policy has an unknown field predicate");
        }
        check_route_view(&RouteView {
            methods: line.methods,
            path_form: line.path_form,
            path: &line.path,
            fields: line
                .fields
                .iter()
                .map(|(op, name, value)| (*op, name.as_str(), value.as_slice()))
                .collect(),
            rung: line.rung,
        })
        .map_err(|_| "the policy has an invalid route")?;
    }
    Ok(())
}

fn put_bytes(out: &mut Vec<u8>, bytes: &[u8]) -> Result<(), &'static str> {
    let len =
        u32::try_from(bytes.len()).map_err(|_| "the policy field exceeds its length encoding")?;
    out.extend_from_slice(&len.to_le_bytes());
    out.extend_from_slice(bytes);
    Ok(())
}

/// Encode an extension value once for this listener and generation.
pub fn encode(
    listener: u64,
    generation: u64,
    lines: &[GuestLine],
) -> Result<Vec<u8>, &'static str> {
    if listener == 0 || generation == 0 {
        return Err("the policy has no listener or generation");
    }
    valid(lines)?;
    let mut out = Vec::new();
    out.extend_from_slice(&VERSION.to_le_bytes());
    out.extend_from_slice(&listener.to_le_bytes());
    out.extend_from_slice(&generation.to_le_bytes());
    out.extend_from_slice(&(lines.len() as u32).to_le_bytes());
    for line in lines {
        out.extend_from_slice(&line.line.to_le_bytes());
        out.extend_from_slice(&line.points.to_le_bytes());
        out.extend_from_slice(&line.auth.id.to_le_bytes());
        out.extend_from_slice(&line.auth.mac.to_le_bytes());
        out.extend_from_slice(&line.body_limit.to_le_bytes());
        out.extend_from_slice(&line.methods.to_le_bytes());
        out.extend_from_slice(&line.path_form.to_le_bytes());
        out.extend_from_slice(&line.rung.to_le_bytes());
        put_bytes(&mut out, line.path.as_bytes())?;
        let fields =
            u32::try_from(line.fields.len()).map_err(|_| "too many encoded field predicates")?;
        out.extend_from_slice(&fields.to_le_bytes());
        for (op, name, value) in &line.fields {
            out.extend_from_slice(&op.to_le_bytes());
            put_bytes(&mut out, name.as_bytes())?;
            put_bytes(&mut out, value)?;
        }
    }
    Ok(out)
}

struct Reader<'a>(&'a [u8]);
impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], &'static str> {
        let bytes = self.0.get(..n).ok_or("the policy is truncated")?;
        self.0 = &self.0[n..];
        Ok(bytes)
    }
    fn u32(&mut self) -> Result<u32, &'static str> {
        Ok(u32::from_le_bytes(
            self.take(4)?.try_into().map_err(|_| "invalid u32")?,
        ))
    }
    fn u64(&mut self) -> Result<u64, &'static str> {
        Ok(u64::from_le_bytes(
            self.take(8)?.try_into().map_err(|_| "invalid u64")?,
        ))
    }
    fn bytes(&mut self) -> Result<&'a [u8], &'static str> {
        let len = usize::try_from(self.u32()?).map_err(|_| "the field length does not fit")?;
        self.take(len)
    }
    fn text(&mut self) -> Result<String, &'static str> {
        std::str::from_utf8(self.bytes()?)
            .map(str::to_owned)
            .map_err(|_| "the policy text is not UTF-8")
    }
}

/// Decode a whole policy value. Lengths are checked against the actual input before allocation.
pub fn decode(bytes: &[u8]) -> Result<Policy, &'static str> {
    let mut reader = Reader(bytes);
    if reader.u32()? != VERSION {
        return Err("the policy version is unknown");
    }
    let listener = reader.u64()?;
    let generation = reader.u64()?;
    if listener == 0 || generation == 0 {
        return Err("the policy has no listener or generation");
    }
    let count = reader.u32()?;
    if u64::from(count) > MAX_LINES {
        return Err("the policy exceeds the existing guest-list limit");
    }
    let mut lines = Vec::new();
    for _ in 0..count {
        let line = reader.u32()?;
        let points = reader.u32()?;
        let auth = crate::abi::host::service::AuthRef {
            id: reader.u64()?,
            mac: reader.u64()?,
        };
        let body_limit = reader.u64()?;
        let methods = reader.u32()?;
        let path_form = reader.u32()?;
        let rung = reader.u32()?;
        let path = reader.text()?;
        let count =
            usize::try_from(reader.u32()?).map_err(|_| "the predicate count does not fit")?;

        if count > reader.0.len() / (3 * size_of::<u32>()) {
            return Err("the policy predicates are truncated");
        }
        let mut fields = Vec::new();
        for _ in 0..count {
            fields.push((reader.u32()?, reader.text()?, reader.bytes()?.to_vec()));
        }
        lines.push(GuestLine {
            line,
            points,
            auth,
            body_limit,
            methods,
            path_form,
            path,
            fields,
            rung,
        });
    }
    if !reader.0.is_empty() {
        return Err("the policy has trailing bytes");
    }
    valid(&lines)?;
    Ok(Policy {
        listener,
        generation,
        lines,
    })
}

#[cfg(test)]
#[path = "../tests/guest_policy_tests.rs"]
mod tests;
