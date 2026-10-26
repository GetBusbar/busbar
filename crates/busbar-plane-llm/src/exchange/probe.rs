//! A health probe's far-end request, sans I/O: the smallest request a far end answers with its
//! health (THE DESIGN: a probe is a kernel-originated unit pinned to one member; the plane answers
//! its ATTEMPT with this request, the kernel's breaker classifies the answer as it classifies
//! organic traffic, and the probe bills nothing).
//!
//! 1.5.5's prober, as bytes: the far end's dialect's own probe body for the wire model, POSTed to
//! the provider's fixed path or the dialect's single-answer path, with the head fields a native
//! client sends. A lane under a path base is never probed (its path is the dialect's reshaped one,
//! which a probe cannot name). The credential, the schedule, the timeout and the verdict are the
//! kernel's.

use busbar_contract::protocol::{ProtocolDecl, APPLICATION_JSON, EGRESS_UA_DEFAULT};

use super::attempt::{wire_and_canonical_path, FarRequest};
use super::shaping::Lane;
use crate::codec::DECLS;

fn decl(name: &str) -> Option<&'static ProtocolDecl> {
    DECLS.iter().copied().find(|d| d.name == name)
}

/// The probe body the far end's dialect answers for `wire_model` (empty when it has none).
#[must_use]
pub fn probe_body(
    host: &dyn busbar_contract::codec::CodecHost,
    dialect: &str,
    wire_model: &str,
) -> Vec<u8> {
    decl(dialect)
        .and_then(|d| d.dialect())
        .map(|dc| dc.probe_body(host, wire_model))
        .unwrap_or_default()
}

/// The path a probe of `lane` is sent to, before encoding: the provider's fixed path, else the
/// dialect's single-answer path for the wire model.
#[must_use]
pub fn probe_path(lane: &Lane) -> String {
    lane.path.clone().unwrap_or_else(|| {
        decl(lane.dialect)
            .and_then(|d| d.dialect())
            .map(|dc| dc.upstream_path_for_stream(lane.wire_model(), false))
            .unwrap_or_default()
    })
}

/// THE PROBE REQUEST for `lane`; `None` for a lane under a path base, which is not probed.
#[must_use]
pub fn request(host: &dyn busbar_contract::codec::CodecHost, lane: &Lane) -> Option<FarRequest> {
    if lane.path_base.is_some() {
        return None;
    }
    // A lane over the invoke envelope is probed through it: its target, and its body's edits.
    let path = match &lane.path {
        None if lane.invoke => super::invoke::path(lane.wire_model(), false),
        _ => probe_path(lane),
    };
    let body = probe_body(host, lane.dialect, lane.wire_model());
    let body = if lane.invoke {
        super::invoke::body(&body, &[])?
    } else {
        body
    };
    let (target, _canonical) = wire_and_canonical_path(&path);
    let user_agent = decl(lane.dialect).map_or(EGRESS_UA_DEFAULT, |d| d.egress_user_agent);
    // The lane's declared static fields first, as an organic request of the lane writes them
    // (`attempt::head_fields`): a far end that requires its version field answers a probe that
    // lacks it with a 400, which the breaker would read as the lane's health.
    let mut fields: Vec<(String, Vec<u8>)> = lane
        .statics
        .iter()
        .map(|(n, v)| ((*n).to_string(), v.as_bytes().to_vec()))
        .collect();
    fields.extend([
        (
            "content-type".to_string(),
            APPLICATION_JSON.as_bytes().to_vec(),
        ),
        ("user-agent".to_string(), user_agent.as_bytes().to_vec()),
        ("accept".to_string(), APPLICATION_JSON.as_bytes().to_vec()),
    ]);
    Some(FarRequest {
        verb: "POST",
        target,
        fields,
        body,
        pristine: false,
        dropped_controls: Vec::new(),
    })
}
