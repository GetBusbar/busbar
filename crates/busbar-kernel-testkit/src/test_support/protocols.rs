// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use crate::ingress::protocols::{publish_protocols, registry, ProtocolDecl};
use std::sync::Mutex;

static REGISTERED: Mutex<Vec<&'static ProtocolDecl>> = Mutex::new(Vec::new());

pub fn register_test_protocol(decl: &'static ProtocolDecl) {
    register_test_protocols(&[decl]);
}

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

pub const PROTO_ANTHROPIC: &str = "anthropic";
pub const PROTO_OPENAI: &str = "openai";
pub const PROTO_GEMINI: &str = "gemini";
pub const PROTO_BEDROCK: &str = "bedrock";
pub const PROTO_COHERE: &str = "cohere";
pub const PROTO_RESPONSES: &str = "responses";
