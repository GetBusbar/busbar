// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! A TEST BINARY'S PROTOCOL REGISTRATIONS. A test registers a protocol the way the composition root
//! installs one in production; each change of the registered set is published as the process
//! protocol registry ([`crate::ingress::protocols::publish_protocols`]).

use crate::ingress::protocols::{publish_protocols, registry, ProtocolDecl};
use std::sync::Mutex;

/// The protocols registered so far, in registration order.
static REGISTERED: Mutex<Vec<&'static ProtocolDecl>> = Mutex::new(Vec::new());

/// Register a protocol for a test, as production's `install_protocols` does. Idempotent by name; a
/// protocol already installed under the name stands (the boot fold keeps the first).
pub fn register_test_protocol(decl: &'static ProtocolDecl) {
    register_test_protocols(&[decl]);
}

/// [`register_test_protocol`] for each of `decls`, in order.
pub fn register_test_protocols(decls: &[&'static ProtocolDecl]) {
    let mut reg = REGISTERED.lock().unwrap_or_else(|e| e.into_inner());
    let before = reg.len();
    for d in decls {
        if !reg.iter().any(|r| r.name == d.name) {
            reg.push(d);
        }
    }
    if reg.len() != before {
        publish_protocols(&reg);
    }
}

/// Every verb any installed protocol serves, in declaration order, deduped (leaked per call: a
/// test reads it a handful of times).
pub fn declared_verbs() -> &'static [busbar_contract::operation::OpVerb] {
    let mut verbs = Vec::new();
    for d in registry().decls() {
        for v in d.verbs {
            if !verbs.contains(v) {
                verbs.push(*v);
            }
        }
    }
    verbs.leak()
}

/// Canonical dialect names, for tests only: production names no dialect.
pub const PROTO_ANTHROPIC: &str = "anthropic";
pub const PROTO_OPENAI: &str = "openai";
pub const PROTO_GEMINI: &str = "gemini";
pub const PROTO_BEDROCK: &str = "bedrock";
pub const PROTO_COHERE: &str = "cohere";
pub const PROTO_RESPONSES: &str = "responses";
