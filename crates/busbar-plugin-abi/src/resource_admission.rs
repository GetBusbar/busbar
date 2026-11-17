// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Pure resource selection and immutable forwarding descriptor facts (#408).
//! These records are claims to validate against the retained host inventory, never capabilities.

use crate::plane::{ResourceEchoRec, tag as t};
use crate::records::{Full, Records, U32Rec, Writer};

pub const MAX_SELECTION_BYTES: usize = 16 * 1024;
pub const MAX_SELECTED: usize = 32;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Invalid;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Scope<'a> {
    pub kind: &'a str,
    pub value: &'a str,
}

pub fn valid_kind(s: &str) -> bool {
    (1..=64).contains(&s.len())
        && s.as_bytes()[0].is_ascii_lowercase()
        && s.bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
}

pub fn valid_value(s: &str) -> bool {
    (1..=256).contains(&s.len()) && !s.chars().any(char::is_control)
}

fn text(bytes: &[u8]) -> Result<&str, Invalid> {
    core::str::from_utf8(bytes).map_err(|_| Invalid)
}

pub fn write_selection(out: &mut impl Writer, scopes: &[Scope<'_>]) -> Result<(), Full> {
    for s in scopes {
        out.put_pair(t::RESOURCE_SELECTED, s.kind, s.value.as_bytes())?;
    }
    Ok(())
}

pub fn decode_selection(bytes: &[u8]) -> Result<Vec<Scope<'_>>, Invalid> {
    if bytes.len() > MAX_SELECTION_BYTES {
        return Err(Invalid);
    }
    let mut scopes = Vec::new();
    for rec in Records::new(bytes) {
        let rec = rec.map_err(|_| Invalid)?;
        if rec.tag != t::RESOURCE_SELECTED || scopes.len() == MAX_SELECTED {
            return Err(Invalid);
        }
        let (kind, value) = rec.pair().map_err(|_| Invalid)?;
        let s = Scope {
            kind,
            value: text(value)?,
        };
        if !valid_kind(s.kind) || !valid_value(s.value) || scopes.contains(&s) {
            return Err(Invalid);
        }
        scopes.push(s);
    }
    if scopes.is_empty() {
        return Err(Invalid);
    }
    Ok(scopes)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DescriptorEcho<'a> {
    pub invocation: u64,
    pub generation: u64,
    pub route: u32,
    pub descriptor: u32,
    pub instance: &'a str,
}

pub fn write_echo(out: &mut impl Writer, echo: DescriptorEcho<'_>) -> Result<(), Full> {
    out.put_pod_tail(
        t::RESOURCE_ECHO,
        &ResourceEchoRec {
            invocation: echo.invocation,
            generation: echo.generation,
            route: echo.route,
            descriptor: echo.descriptor,
        },
        echo.instance.as_bytes(),
    )
}

/// Decodes one isolated resource echo. The surrounding admission block can contain other
/// independently validated protocols; callers must extract this record without discarding duplicates.
pub fn decode_echo(bytes: &[u8]) -> Result<DescriptorEcho<'_>, Invalid> {
    let mut records = Records::new(bytes);
    let rec = records.next().ok_or(Invalid)?.map_err(|_| Invalid)?;
    if rec.tag != t::RESOURCE_ECHO || records.next().is_some() {
        return Err(Invalid);
    }
    let (r, tail) = rec.pod_tail::<ResourceEchoRec>().map_err(|_| Invalid)?;
    let instance = text(tail)?;
    if r.invocation == 0 || r.descriptor == 0 || !valid_value(instance) {
        return Err(Invalid);
    }
    Ok(DescriptorEcho {
        invocation: r.invocation,
        generation: r.generation,
        route: r.route,
        descriptor: r.descriptor,
        instance,
    })
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Forward<'a> {
    pub descriptor: u32,
    pub pool: &'a str,
    pub member: &'a str,
    pub upstream: &'a str,
    pub dialect: &'a str,
    pub model: &'a str,
    pub method: &'a str,
    pub target: &'a str,
}

#[derive(Debug, PartialEq, Eq)]
pub struct Resource<'a> {
    pub scope: Scope<'a>,
    pub forwards: Vec<Forward<'a>>,
}

pub fn write_resource(out: &mut impl Writer, resource: &Resource<'_>) -> Result<(), Full> {
    out.put_nested(t::RESOURCE_ENTRY, |out| {
        out.put(t::RESOURCE_KIND, resource.scope.kind.as_bytes())?;
        out.put(t::RESOURCE_VALUE, resource.scope.value.as_bytes())?;
        for f in &resource.forwards {
            out.put_nested(t::RESOURCE_FORWARD, |out| {
                out.put_pod(
                    t::RESOURCE_DESCRIPTOR,
                    &U32Rec {
                        value: f.descriptor,
                        _r: 0,
                    },
                )?;
                for (tag, value) in [
                    (t::RESOURCE_POOL, f.pool),
                    (t::RESOURCE_MEMBER, f.member),
                    (t::RESOURCE_UPSTREAM, f.upstream),
                    (t::RESOURCE_DIALECT, f.dialect),
                    (t::RESOURCE_MODEL, f.model),
                    (crate::records::tag::H_METHOD, f.method),
                    (crate::records::tag::H_PATH, f.target),
                ] {
                    out.put(tag, value.as_bytes())?;
                }
                Ok(())
            })?;
        }
        Ok(())
    })
}

fn forward(bytes: &[u8]) -> Result<Forward<'_>, Invalid> {
    let mut id = None;
    let mut fields = [None; 7];
    for rec in Records::new(bytes) {
        let rec = rec.map_err(|_| Invalid)?;
        if rec.tag == t::RESOURCE_DESCRIPTOR {
            let value = rec.pod::<U32Rec>().map_err(|_| Invalid)?;
            if value._r != 0 || id.replace(value.value).is_some() {
                return Err(Invalid);
            }
            continue;
        }
        let i = match rec.tag {
            t::RESOURCE_POOL => 0,
            t::RESOURCE_MEMBER => 1,
            t::RESOURCE_UPSTREAM => 2,
            t::RESOURCE_DIALECT => 3,
            t::RESOURCE_MODEL => 4,
            crate::records::tag::H_METHOD => 5,
            crate::records::tag::H_PATH => 6,
            _ => return Err(Invalid),
        };
        if fields[i]
            .replace(rec.text().map_err(|_| Invalid)?)
            .is_some()
        {
            return Err(Invalid);
        }
    }
    let [pool, member, upstream, dialect, model, method, target] = fields.map(|s| s.ok_or(Invalid));
    let f = Forward {
        descriptor: id.ok_or(Invalid)?,
        pool: pool?,
        member: member?,
        upstream: upstream?,
        dialect: dialect?,
        model: model?,
        method: method?,
        target: target?,
    };
    if f.descriptor == 0
        || !valid_value(f.pool)
        || f.member.is_empty()
        || f.member.len() > 512
        || !valid_value(f.upstream)
        || f.dialect.len() > 256
        || f.model.len() > 256
        || f.dialect.chars().any(char::is_control)
        || f.model.chars().any(char::is_control)
        || !(1..=32).contains(&f.method.len())
        || !f.method.bytes().all(|b| b.is_ascii_uppercase())
        || f.target.len() > 8192
        || !f.target.starts_with('/')
        || f.target.contains('#')
        || f.target.chars().any(char::is_control)
    {
        return Err(Invalid);
    }
    Ok(f)
}

/// Byte and fact limits are checked before allocating. Host validation must additionally resolve
/// every pool/member against its actual configuration and retain the exact resulting target.
pub fn decode_inventory(bytes: &[u8], byte_limit: usize) -> Result<Vec<Resource<'_>>, Invalid> {
    if bytes.len() > byte_limit {
        return Err(Invalid);
    }
    let mut resources: Vec<Resource<'_>> = Vec::new();
    let mut ids = std::collections::BTreeSet::new();
    let mut scopes = std::collections::BTreeSet::new();
    for rec in Records::new(bytes) {
        let rec = rec.map_err(|_| Invalid)?;
        if rec.tag != t::RESOURCE_ENTRY || resources.len() >= 65_536 {
            return Err(Invalid);
        }
        let mut kind = None;
        let mut value = None;
        let mut forwards = Vec::new();
        for child in Records::new(rec.body) {
            let child = child.map_err(|_| Invalid)?;
            match child.tag {
                t::RESOURCE_KIND if kind.is_none() => {
                    kind = Some(child.text().map_err(|_| Invalid)?)
                }
                t::RESOURCE_VALUE if value.is_none() => {
                    value = Some(child.text().map_err(|_| Invalid)?)
                }
                t::RESOURCE_FORWARD => {
                    if ids.len() >= 65_536 {
                        return Err(Invalid);
                    }
                    let f = forward(child.body)?;
                    if !ids.insert(f.descriptor) {
                        return Err(Invalid);
                    }
                    forwards.push(f);
                }
                _ => return Err(Invalid),
            }
        }
        let scope = Scope {
            kind: kind.ok_or(Invalid)?,
            value: value.ok_or(Invalid)?,
        };
        if !valid_kind(scope.kind)
            || !valid_value(scope.value)
            || forwards.is_empty()
            || !scopes.insert((scope.kind, scope.value))
        {
            return Err(Invalid);
        }
        resources.push(Resource { scope, forwards });
    }
    if resources.is_empty() {
        return Err(Invalid);
    }
    Ok(resources)
}
